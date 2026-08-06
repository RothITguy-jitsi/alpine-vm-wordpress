#!/bin/sh
# 10-security-tooling-and-validation.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Installs Trivy, Lynis, wp-hardening.sh, and runs post-install validation.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Installing Trivy vulnerability scanner"
# Pinned to a specific release, with the release's own checksums file pinned
# by hash. This is not routine hygiene -- Trivy's distribution was compromised
# TWICE in 2026:
#   * 28 Feb 2026 — repository takeover
#   * 19 Mar 2026 — a malicious binary published as v0.69.4 for ~3 hours, and
#                   credential-stealing code injected into trivy-action and
#                   setup-trivy
#   * 22 Mar 2026 — the aquasec/trivy 0.69.5 and 0.69.6 Docker Hub images were
#                   also found to contain the attacker's C2 domain
# A version pin alone would not have helped anyone who happened to pin 0.69.4.
# Verifying the download against a hash recorded here, out of band from the
# download itself, is the control that would have.
TRIVY_VER="v0.72.0"
# SHA-256 of trivy_0.72.0_checksums.txt from the GitHub release. The binary is
# then verified against that file, so this single hash anchors the whole
# download. Re-record it by hand when bumping TRIVY_VER; a stale value fails
# closed, which is the correct direction to fail.
TRIVY_CHECKSUMS_SHA256="ebe9d19a774b950e240b1017a038e9b5a002ea068e02023369ff6d241c10c580"
# Versions known to have shipped attacker-controlled code. Refused no matter
# how they arrived -- including via apk, since a distro package built from a
# poisoned upstream would be just as compromised.
TRIVY_DENYLIST="0.69.4 0.69.5 0.69.6"
TRIVY_CACHE_DIR="/var/cache/trivy"
mkdir -p "${TRIVY_CACHE_DIR}"; chmod 755 "${TRIVY_CACHE_DIR}"

# BUG FIX (v7-13, ChatGPT Finding 13): fallback install.sh fetch is pinned
# to a specific commit hash, not `main`. Same commit aquasecurity's own
# setup-trivy Action pins to. See the identical fix in update.sh's
# setup_trivy() further above for the full rationale (Trivy v0.69.4 supply
# chain compromise, raw.githubusercontent.com serves by content-addressed
# commit hash, etc). Keep both TRIVY_VER and TRIVY_INSTALL_COMMIT updated
# together after auditing any change to contrib/install.sh.
TRIVY_INSTALL_COMMIT="75c4dc0f45c5d7ffd05ae26df1e0c666787bdf2a"

# Try edge/testing first (clean apk) then fall back to commit-pinned installer
if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
     trivy >/dev/null 2>&1; then
  ok "Trivy installed via apk edge/testing"
elif apk add --no-cache wget >/dev/null 2>&1 && \
     wget -qO /tmp/trivy-install.sh \
       "https://raw.githubusercontent.com/aquasecurity/trivy/${TRIVY_INSTALL_COMMIT}/contrib/install.sh" \
       2>/dev/null; then
  sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && ok "Trivy ${TRIVY_VER} installed via official script (commit-pinned)" \
    || warn "Trivy install failed — vulnerability scanning disabled in update.sh"
  rm -f /tmp/trivy-install.sh
else
  warn "Trivy unavailable — update.sh will skip vulnerability scanning"
fi

if command -v trivy >/dev/null 2>&1; then
  ok "Trivy $(trivy --version 2>/dev/null | head -1) ready"
# Refuse a known-compromised build regardless of how it got here. Checked
# after installation rather than only at download time, because the apk path
# does not go through the checksum verification above and a distribution
# package built from a poisoned upstream would carry the same code.
if command -v trivy >/dev/null 2>&1; then
  _tv=$(trivy --version 2>/dev/null | head -1 | sed -n 's/.*[Vv]ersion:* *v\{0,1\}\([0-9.]*\).*/\1/p')
  for _bad in $TRIVY_DENYLIST; do
    if [ "$_tv" = "$_bad" ]; then
      err "Trivy ${_tv} is a KNOWN-COMPROMISED release (March 2026 supply-chain incident) and contains attacker C2 code. Refusing to use it. Remove it and install ${TRIVY_VER}: apk del trivy"
    fi
  done
  [ -n "$_tv" ] && ok "Trivy ${_tv} is not on the known-compromised list"
fi

  ok "  Pre-seeding vulnerability DB (~100 MB, takes 30-90s)..."
  trivy image --cache-dir "${TRIVY_CACHE_DIR}" --download-db-only --quiet 2>/dev/null \
    && ok "  Trivy DB cached at ${TRIVY_CACHE_DIR}" \
    || warn "  Trivy DB pre-seed failed (will download on first update scan)"
fi

# ════════════════════════════════════════════════════════════════════════════
# LYNIS — Security auditing for MSP compliance evidence
# lynis is only in Alpine edge/testing, NOT in stable repos (3.21-3.24).
# Try stable first (may land in community someday), then edge/testing,
# then direct GitHub install as a final fallback — so Lynis is never
# silently absent even if Alpine packaging changes.
# Weekly automated audit; manual: lynis audit system
# Score: grep hardening_index /var/log/lynis-report.dat
# ════════════════════════════════════════════════════════════════════════════
ts "Installing Lynis security auditor"
LYNIS_OK=0

# Try 1: Alpine stable community (might appear in future versions)
apk add --no-cache lynis >/dev/null 2>&1 && LYNIS_OK=1

# Install the profile whichever way lynis arrived. Without it the report is
# dominated by findings that are structurally impossible on this VM —
# separate partitions on a single-qcow2 guest, GRUB on a hypervisor-booted
# system, a host web server when Apache runs in a container. A score built
# from noise gets ignored, and an ignored audit is the same as none.
if [ -f "${PAYLOAD_DIR}/etc/lynis-custom.prf" ]; then
  mkdir -p /etc/lynis
  install -m 0644 "${PAYLOAD_DIR}/etc/lynis-custom.prf" /etc/lynis/custom.prf
  ok "Lynis profile installed — exclusions documented in /etc/lynis/custom.prf"
fi

# Try 2: Alpine edge/testing (where it currently lives as of Alpine 3.24)
if [ "$LYNIS_OK" = "0" ]; then
  apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    lynis >/dev/null 2>&1 && LYNIS_OK=1
fi

# Try 3: Direct install from CISOfy's stable release tarball (no OS dependency)
if [ "$LYNIS_OK" = "0" ]; then
  warn "Lynis not in apk repos — trying GitHub release tarball"
  apk add --no-cache wget >/dev/null 2>&1 || true
  LYNIS_TAG=$(wget -qO- https://api.github.com/repos/CISOfy/lynis/releases/latest 2>/dev/null \
    | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  LYNIS_TAG="${LYNIS_TAG:-3.1.3}"  # pinned fallback if API unavailable
  if wget -qO /tmp/lynis.tar.gz \
       "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_TAG}.tar.gz" 2>/dev/null; then
    tar xzf /tmp/lynis.tar.gz -C /usr/local/lib 2>/dev/null
    ln -sf "/usr/local/lib/lynis-${LYNIS_TAG}/lynis" /usr/local/bin/lynis 2>/dev/null
    rm -f /tmp/lynis.tar.gz
    command -v lynis >/dev/null 2>&1 && LYNIS_OK=1 && ok "Lynis ${LYNIS_TAG} installed from GitHub release"
  fi
fi

if [ "$LYNIS_OK" = "1" ]; then
  ok "Lynis $(lynis --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ready"
cat "${PAYLOAD_DIR}/cron/lynis-audit.cron" >> /etc/crontabs/root
  ok "Lynis: weekly audit Sat 05:00 | manual: wp-hardening.sh lynis"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
else
  warn "Lynis could not be installed — all install methods failed"
  warn "  Manual install: apk add --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing lynis"
  warn "  Or: wget https://github.com/CISOfy/lynis/archive/refs/tags/3.1.3.tar.gz"
fi

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC CONSOLE AUTO-ENROLMENT
# If an enrolment key was provided at provisioning time, enrol now.
# After enrolment: visit https://app.crowdsec.net → Accept the engine.
# Then restart CrowdSec: podman restart crowdsec
# ════════════════════════════════════════════════════════════════════════════
if [ -n "${CROWDSEC_ENROLL_KEY}" ]; then
  ts "CrowdSec console auto-enrolment"
  CS_NAME=$(hostname 2>/dev/null || echo "wordpress-vm")
  if PRUN exec crowdsec cscli console enroll \
       --name "${CS_NAME}" \
       --tags "wordpress,msp,podman,alpine" \
       "${CROWDSEC_ENROLL_KEY}" 2>/dev/null; then
    ok "CrowdSec enrolled as '${CS_NAME}' — accept it at https://app.crowdsec.net"
    ok "  Then restart: podman restart crowdsec"
  else
    warn "CrowdSec enrolment failed — check key at app.crowdsec.net"
    warn "  Manual: podman exec crowdsec cscli console enroll <key>"
  fi
  # Scrub key from disk now that it's been used
  sed -i 's/^CROWDSEC_ENROLL_KEY=.*/CROWDSEC_ENROLL_KEY=""/' \
    /etc/wp-install/vars.sh 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════════
# WP-HARDENING.SH — Toggle security features from Proxmox or SSH
# qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# ════════════════════════════════════════════════════════════════════════════
ts "Installing wp-hardening.sh security toggle"
install -m 0755 "${PAYLOAD_DIR}/bin/wp-hardening.sh" /usr/local/bin/wp-hardening.sh

# ── Malware / integrity scanning ─────────────────────────────────────────────
ts "Installing malware and integrity scanning"
install -m 0755 "${PAYLOAD_DIR}/bin/wp-malware-scan.sh" /usr/local/bin/wp-malware-scan.sh
mkdir -p /etc/wp-install/malware
install -m 0644 "${PAYLOAD_DIR}/malware/wp-malware.yar" /etc/wp-install/malware/wp-malware.yar
mkdir -p /var/lib/wp-quarantine /var/lib/wp-malware-scan
chmod 700 /var/lib/wp-quarantine
ok "wp-malware-scan.sh installed (structural / core / yara / db / clamav)"

# YARA is the backbone of the signature layer and is small, so it is installed
# unconditionally. ClamAV is NOT: its signature database alone is close to a
# gigabyte resident, which is a poor trade on a 4 GB VM also running
# WordPress, MariaDB and CrowdSec -- and its PHP-webshell coverage is weaker
# than the YARA rules. It stays a deliberate, on-demand choice.
if apk add --no-cache yara >/dev/null 2>&1; then
  ok "yara installed — signature scanning active"
else
  warn "yara could not be installed; the YARA layer will be skipped"
  warn "  Install later with: apk add yara"
fi
# ClamAV is installed only if asked for. It is optional for a reason that
# is not primarily memory: it is a general-purpose, signature-driven file
# scanner built largely for email attachments, and its coverage of modern
# obfuscated PHP webshells is weak next to the YARA rules installed above,
# which target exactly that. It also false-positives on some minified
# JavaScript, and a WordPress tree is full of minified plugin assets.
# It earns its place on sites that accept visitor uploads, for non-PHP
# payloads such as dropped ELF binaries, and where a compliance regime
# simply requires an AV product.
if [ "${INSTALL_CLAMAV:-0}" = "1" ]; then
  ts "Installing ClamAV (requested at install time)"
  if apk add --no-cache clamav clamav-libunrar >/dev/null 2>&1; then
    ok "ClamAV installed"
    # Signatures are fetched now so the first scan is not the thing that
    # discovers the database is empty. Non-fatal: a registry or mirror
    # problem should not fail an otherwise-good install.
    if freshclam --quiet >/dev/null 2>&1; then
      ok "  Signature database downloaded"
    else
      warn "  freshclam could not download signatures yet — run 'freshclam' later"
    fi
    # Weekly, not daily: a full ClamAV pass over a WordPress tree takes
    # minutes, and the layers that matter most for WordPress already run daily.
    printf '15 4 * * 0 /usr/local/bin/wp-malware-scan.sh clamav >/dev/null 2>&1 || logger -t wp-malware "weekly ClamAV scan reported findings"\n' >> /etc/crontabs/root
    ok "  Weekly ClamAV scan scheduled (Sunday 04:15 UTC)"
    ok "  On demand: wp-malware-scan.sh clamav"
  else
    warn "ClamAV was requested but could not be installed — other layers unaffected"
  fi
else
  ok "ClamAV not installed (not requested)."
  ok "  Structural, core-integrity, YARA and database layers still run daily."
  ok "  Add later: apk add clamav clamav-libunrar && freshclam"
fi
chmod +x /usr/local/bin/wp-hardening.sh
ok "wp-hardening.sh installed"
ok "  Usage: wp-hardening.sh status"
ok "  Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
ok "  Commands: enable|disable [8g|xmlrpc|uploads-php|debug]  |  trivy-scan  |  lynis"

# ════════════════════════════════════════════════════════════════════════════
# POST-INSTALL VALIDATION SUITE
# Verifies every critical component before declaring the install complete.
# Creates /usr/local/bin/validate-wordpress.sh for ongoing health checks.
# ════════════════════════════════════════════════════════════════════════════
ts "Running post-install validation"

PASS=0; FAIL=0
check() {
  local label="$1"; local result="$2"; local expected="${3:-ok}"
  if [ "$result" = "$expected" ]; then
    ok "  PASS  ${label}"
    PASS=$((PASS+1))
  else
    warn "  FAIL  ${label} (got: ${result}, expected: ${expected})"
    FAIL=$((FAIL+1))
  fi
}

# WordPress container running
check "WordPress container up"   "$(podman inspect wordpress --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB container running
check "MariaDB container up"   "$(podman inspect mariadb --format '{{.State.Status}}' 2>/dev/null)" "running"

# CrowdSec container running
check "CrowdSec container up"   "$(podman inspect crowdsec --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB reachability check — NOT Health.Status. Podman's health-check timer
# frequently never fires on Alpine (no systemd/conmon poller to drive it), so
# .State.Health.Status can sit on "starting" forever even though MariaDB is
# fully up — same finding as the FIX 2 note above the MariaDB wait loop.
# stdout is redirected too, not just stderr: mariadb(d)-admin ping --silent
# still prints "mysqld is alive" on success, which would otherwise leak into
# the captured value and break the "ok" string comparison below.
_DB_PING_CHECK=$(PRUN exec mariadb sh -c 'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' && echo ok || echo fail)
check "MariaDB reachable (exec ping)" "$_DB_PING_CHECK"

# WordPress DB connectivity (PHP mysqli test, runs as www-data via su)
DB_CHECK=$(podman exec --user www-data wordpress php -r   'echo @mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"))?"ok":"fail";'   2>/dev/null || echo "error")
check "WordPress DB connection (www-data)" "$DB_CHECK"

# PRODUCTION SAFETY FIX (v7-6k): the two checks above are narrow (root-only
# ping; a bare mysqli_connect proves a socket opens, not that a query
# succeeds). These two additional checks call the same strengthened
# health-check scripts that gate update.sh's rollback decisions
# (wp-health-check.sh / mariadb-health-check.sh, installed earlier in this
# stage), so install-time validation is exactly as rigorous as update-time
# validation — HTTP + PHP execution + DB name resolution + a real
# WordPress-credential query for WordPress, and root + wpdb-credential
# queries + InnoDB-initialized for MariaDB itself. Added alongside, not
# instead of, the checks above.
_MARIADB_FULL_CHECK=$([ -x /usr/local/bin/mariadb-health-check.sh ] && /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1 && echo ok || echo fail)
check "MariaDB full health (query + InnoDB)" "$_MARIADB_FULL_CHECK"

_WP_FULL_CHECK=$([ -x /usr/local/bin/wp-health-check.sh ] && /usr/local/bin/wp-health-check.sh wordpress 80 >/dev/null 2>&1 && echo ok || echo fail)
check "WordPress full health (HTTP+PHP+DB)" "$_WP_FULL_CHECK"

# Port 80 listening — ss (iproute2) isn't installed on stock Alpine and this
# script never adds it, so this always read "0" regardless of real state.
# Busybox's netstat ships by default and is a drop-in replacement here.
check "Port 80 listening"   "$(netstat -tlnp 2>/dev/null | grep -c ':80 ' | tr -d ' ')" "1"

# WordPress HTTP response (should be 302 redirect to /wp-admin/install.php)
HTTP_CODE=$(podman exec --user www-data wordpress php -r   'error_reporting(0);$r=@file_get_contents("http://127.0.0.1/",false,stream_context_create(["http"=>["timeout"=>5,"method"=>"GET","ignore_errors"=>true]]));$code=preg_match("/HTTP\/[0-9.]+ ([0-9]+)/",$http_response_header[0]??"",$m)?$m[1]:"0";echo($code>=200&&$code<500)?"ok":"fail:".$code;'   2>/dev/null || echo "skip")
[ "$HTTP_CODE" = "skip" ] && ok "  SKIP  WordPress HTTP check (PHP network unavailable)"   || check "WordPress HTTP response (non-error)" "$HTTP_CODE"

# uploads directory writable by www-data
# BUG FIX (v7-5d): ensure the directory exists first — WordPress doesn't
# necessarily create wp-content/uploads until first real media use, and a
# missing directory makes this touch-test fail identically to a real
# permissions problem, even with correct ownership already in place.
podman exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
UPLOADS_CHECK=$(podman exec --user www-data wordpress sh -c   'touch /var/www/html/wp-content/uploads/.write_test && rm /var/www/html/wp-content/uploads/.write_test && echo ok || echo fail'   2>/dev/null || echo "fail")
check "Uploads dir writable (www-data)" "$UPLOADS_CHECK"

# nftables loaded
check "nftables active"   "$(nft list tables 2>/dev/null | grep -c filter | tr -d ' ')" "1"

# CrowdSec bouncer connected
check "CS firewall bouncer"   "$(rc-service cs-firewall-bouncer status 2>/dev/null | grep -c started | tr -d ' ')" "1"

# 8G firewall .htaccess present
_8g=0
[ -f /home/wpuser/wp/htaccess/.htaccess ] && { _8g=$(grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess) || _8g=0; }
check "8G .htaccess installed"   "$_8g" "1"

# Trivy available
check "Trivy scanner"   "$(command -v trivy >/dev/null 2>&1 && echo ok || echo missing)"

# Lynis available
check "Lynis auditor"   "$(command -v lynis >/dev/null 2>&1 && echo ok || echo missing)"

echo ""
if [ "$FAIL" = "0" ]; then
  ok "Validation: ${PASS} checks passed, 0 failed — install is healthy"
else
  warn "Validation: ${PASS} passed, ${FAIL} FAILED — review warnings above"
  warn "  Re-run after fix: /usr/local/bin/validate-wordpress.sh"
fi

# Write the validation script for ongoing use
install -m 0755 "${PAYLOAD_DIR}/bin/validate-wordpress.sh" /usr/local/bin/validate-wordpress.sh
chmod +x /usr/local/bin/validate-wordpress.sh
ln -sf /usr/local/bin/validate-wordpress.sh /usr/local/bin/wp-validate 2>/dev/null || true
ok "validate-wordpress.sh installed (also available as: wp-validate)"
ok "  Full run     : validate-wordpress.sh"
ok "  One area     : validate-wordpress.sh --section security"
ok "  Every failure prints a copy-paste remediation command"

# ── Done ──────────────────────────────────────────────────────────────────────
touch /var/log/wp-install.done
# Retry IP detection — filter out Podman bridges (10.89.x.x) and loopback.
# hostname -I can be empty briefly while DHCP completes, or contain only
# a wp-front/wp-db gateway address which is useless as a published address.
IP=""
for _ip_try in $(seq 1 12); do
  IP=$(hostname -I 2>/dev/null | tr ' ' '\n' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -v '^10\.89\.' \
    | grep -v '^127\.' \
    | head -1)
  [ -n "$IP" ] && break
  sleep 5
done
IP="${IP:-<run: ip addr show eth0 | grep inet>}"

# Build ongoing login/admin URLs from custom slug if configured.
# IMPORTANT: WordPress setup (/wp-admin/install.php) is ALWAYS at the
# default path regardless of custom slug. The slug only applies AFTER
# setup completes — for day-to-day login and admin access.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  LOGIN_URL="http://${IP}/${WP_ADMIN_SLUG}-login"
  ADMIN_URL="http://${IP}/${WP_ADMIN_SLUG}/"
else
  LOGIN_URL="http://${IP}/wp-login.php"
  ADMIN_URL="http://${IP}/wp-admin/"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       WordPress VM Setup Complete!                         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 1 — MUST DO FIRST (standard WP setup URL):       ║"
echo "║     http://${IP}/wp-admin/install.php"
echo "║     ^ This URL is ALWAYS /wp-admin/install.php             ║"
echo "║     ^ Do NOT try /slug/install.php — that will 404         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 2 — After setup, use your custom slug:           ║"
echo "║     Login : ${LOGIN_URL}"
echo "║     Admin : ${ADMIN_URL}"
echo "║  WP         : ${WP_IMAGE}"
echo "║  MariaDB    : ${DB_IMAGE}  (internal wp-db only)"
echo "║  CrowdSec   : ${CROWDSEC_IMAGE}"
echo "║  Digest pin : ${DIGEST_PIN_SUMMARY:-disabled}$([ "${DIGEST_PIN_COUNT:-0}" != "3" ] && [ "${DIGEST_PIN_SUMMARY:-}" != "disabled" ] && echo " — see ${DIGEST_PIN_LOG}")"
echo "║  Kernel     : $(uname -r)"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Credentials  : /root/.wp-credentials (chmod 600)        ║"
if [ "${ADMIN_USER_CREATED:-0}" = "1" ]; then
echo "║  Admin login  : /root/.wp-admin-credentials (chmod 600)  ║"
fi
echo "║  Env file     : /etc/wordpress/env    (chmod 600)        ║"
echo "║  DB backups   : /root/wp-db-backups/ (daily, 7-day keep)║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Security layers active:                                  ║"
echo "║   L1  nftables       default-deny + wp-front/wp-db rules ║"
echo "║   L2  Apache         ADMIN_CIDR + custom slug + 8G WAF   ║"
echo "║   L3  CrowdSec       apache2 + wordpress + appsec-wp     ║"
echo "║   L4  Podman         cap-drop ALL, static IPs, DB=internal║"
echo "║   L5  Kernel         rp_filter=2, syncookies, ip_forward ║"
if [ "${ADMIN_USER_CREATED:-0}" = "1" ]; then
echo "║   L6  SSH            root login disabled — admin: ${ADMIN_USER} (doas for root)"
else
echo "║   L6  SSH            FALLBACK: admin account creation failed —"
echo "║                      root SSH is active instead. Create one by"
echo "║                      hand: adduser, addgroup <user> wheel,"
echo "║                      apk add doas, permit persist :wheel"
fi
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Tooling:                                                 ║"
echo "║   update.sh status    — check + update all components    ║"
echo "║   update.sh trivy     — scan running containers for CVEs ║"
echo "║   wp-hardening.sh     — toggle security features         ║"
echo "║   validate-wordpress.sh — health check all layers        ║"
echo "║   wp-hardening.sh lynis — run Lynis security audit       ║"
echo "╠════════════════════════════════════════════════════════════╣"
[ -n "${CROWDSEC_ENROLL_KEY}" ]   && echo "║  CrowdSec: ENROLLED — accept at https://app.crowdsec.net ║"   || echo "║  CrowdSec: podman exec crowdsec cscli console enroll <k> ║"
echo "║  SSL: put behind NPM  OR  apk add certbot certbot-apache  ║"
echo "╚════════════════════════════════════════════════════════════╝"
