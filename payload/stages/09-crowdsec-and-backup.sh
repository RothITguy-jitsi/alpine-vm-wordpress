#!/bin/sh
# 09-crowdsec-and-backup.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Installs and configures the CrowdSec engine and firewall bouncer, the wp-db-backup.sh script, and the core cron schedule.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "CrowdSec — engine"
mkdir -p /opt/crowdsec/config /opt/crowdsec/data
mkdir -p /home/wpuser/wp/logs; chown 33:33 /home/wpuser/wp/logs 2>/dev/null || true
# Ensure /var/log/messages exists before CrowdSec bind-mounts it.
touch /var/log/messages 2>/dev/null || true

install -m 0644 "${PAYLOAD_DIR}/crowdsec/acquis.yaml" /opt/crowdsec/acquis.yaml
# Custom parser + scenario for WordPress login failures. CrowdSec sees Apache
# access logs already, but a failed and a successful login are both a POST to
# wp-login.php there -- indistinguishable without inspecting the response.
# The mu-plugin logs the outcome explicitly, and these teach CrowdSec to read
# it and ban at the firewall.
# PATH FIX: only /opt/crowdsec/config is mounted into the container (as
# /etc/crowdsec). An earlier revision wrote these to /opt/crowdsec/parsers,
# which the container cannot see -- CrowdSec would have started cleanly and
# simply never loaded them, so login brute-forcing would have gone
# undetected with no error anywhere to say why.
mkdir -p /opt/crowdsec/config/parsers/s01-parse \
         /opt/crowdsec/config/scenarios \
         /opt/crowdsec/config/postoverflows/s01-whitelist
install -m 0644 "${PAYLOAD_DIR}/crowdsec/parsers/wpvm-login.yaml" \
  /opt/crowdsec/config/parsers/s01-parse/wpvm-login.yaml
install -m 0644 "${PAYLOAD_DIR}/crowdsec/scenarios/wpvm-login-bruteforce.yaml" \
  /opt/crowdsec/config/scenarios/wpvm-login-bruteforce.yaml

# ── Operator whitelist ───────────────────────────────────────────────────────
# Written as a POSTOVERFLOW rather than a parser whitelist, deliberately.
# A parser-stage whitelist discards the events before they ever reach a
# scenario, so a whitelisted address becomes completely invisible. At the
# postoverflow stage the bucket still fills and the alert is still raised --
# only the ban is suppressed. So if the operator's own workstation is
# compromised and starts brute-forcing, it shows up in `cscli alerts list`
# instead of silently having free rein. Not locking yourself out and not
# blinding yourself are both achievable; picking the parser stage would have
# quietly traded the second for the first.
if [ -n "${CROWDSEC_WHITELIST:-}" ]; then
  _WL=/opt/crowdsec/config/postoverflows/s01-whitelist/wpvm-operator.yaml
  {
    printf 'name: rothitguy/wpvm-operator-whitelist\n'
    printf 'description: "Addresses the operator declared must never be banned"\n'
    printf 'whitelist:\n'
    printf '  reason: "operator-declared address (install-time)"\n'
  } > "$_WL"
  _ips=""; _cidrs=""
  _oldIFS=$IFS; IFS=','
  for _e in $CROWDSEC_WHITELIST; do
    IFS=$_oldIFS
    case "$_e" in
      */*) _cidrs="${_cidrs} ${_e}" ;;
      ?*)  _ips="${_ips} ${_e}" ;;
    esac
    IFS=','
  done
  IFS=$_oldIFS
  if [ -n "$_ips" ]; then
    printf '  ip:\n' >> "$_WL"
    for _i in $_ips; do printf '    - "%s"\n' "$_i" >> "$_WL"; done
  fi
  if [ -n "$_cidrs" ]; then
    printf '  cidr:\n' >> "$_WL"
    for _c in $_cidrs; do printf '    - "%s"\n' "$_c" >> "$_WL"; done
  fi
  chmod 644 "$_WL"
  ok "CrowdSec whitelist written: ${CROWDSEC_WHITELIST}"
  ok "  Alerts still raised for these — only the ban is suppressed."
else
  warn "No CrowdSec whitelist configured."
  warn "  A banned admin address drops SSH too; recovery is via qm terminal."
  warn "  Add one later: /opt/crowdsec/config/postoverflows/s01-whitelist/"
fi
ok "Login brute-force parser + scenario installed"
# `ok`, not `warn`. These are instructions, not failures — and a warning
# glyph on a to-do sends the operator hunting a problem that does not exist.
# Observed exactly that: a clean install was read as having CrowdSec errors
# because three informational lines carried a warning marker.
ok "  Verify the parser loaded, once the VM is up:"
ok "    doas podman exec crowdsec cscli parsers list | grep wpvm"
ok "    doas podman exec crowdsec cscli scenarios list | grep wpvm"
ok "acquis.yaml: Apache logs + syslog"

podman rm -f crowdsec 2>/dev/null || true
podman run -d \
  --name    crowdsec \
  --restart always \
  --network host \
  --cap-drop ALL \
  --cap-add  DAC_OVERRIDE \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
  --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
  --pids-limit 100 \
  --memory=512m \
  --label io.containers.autoupdate=image \
  -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
  -v /opt/crowdsec/config:/etc/crowdsec:rw \
  -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
  -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
  -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
  -v /var/log/messages:/var/log/host/messages:ro \
  "${CROWDSEC_IMAGE}"

ts "Waiting for CrowdSec LAPI"
LAPI_READY=0
for i in $(seq 1 30); do
  PRUN exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_READY=1; break; }
  sleep 5
done
[ "$LAPI_READY" = "1" ] && ok "LAPI up" || warn "LAPI not confirmed — continuing"

ts "Locking LAPI to 127.0.0.1:8080"
CFG=/opt/crowdsec/config/config.yaml
for i in $(seq 1 12); do [ -f "$CFG" ] && break || sleep 5; done
if [ -f "$CFG" ]; then
  grep -qE '^\s*listen_uri:' "$CFG" \
    && sed -i -E 's|^(\s*listen_uri:).*|\1 127.0.0.1:8080|' "$CFG"
  PRUN restart crowdsec >/dev/null 2>&1; sleep 3
  ok "LAPI → 127.0.0.1:8080"
else
  warn "config.yaml not found — restrict LAPI manually"
fi

ts "Generating bouncer API key"
PRUN exec crowdsec cscli bouncers delete firewall-bouncer >/dev/null 2>&1 || true
BOUNCER_KEY=$(PRUN exec crowdsec cscli bouncers add firewall-bouncer -o raw 2>/dev/null | tail -1)
[ -n "$BOUNCER_KEY" ] && ok "Bouncer key generated" \
  || warn "Could not generate key — check: podman logs crowdsec"

ts "Installing cs-firewall-bouncer"
apk add --no-cache nftables cs-firewall-bouncer cs-firewall-bouncer-openrc >/dev/null 2>&1 \
  || warn "cs-firewall-bouncer not in apk — try edge repo"

if [ -n "$BOUNCER_KEY" ]; then
  mkdir -p /etc/crowdsec/bouncers
sed "s|__BOUNCER_KEY__|${BOUNCER_KEY}|g" \
    "${PAYLOAD_DIR}/templates/crowdsec-firewall-bouncer.yaml.tmpl" > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  rc-update add cs-firewall-bouncer default 2>/dev/null || true
  rc-service cs-firewall-bouncer start 2>/dev/null || true
  # BUG FIX (v7-4): the bouncer's first start frequently loses a race against
  # CrowdSec's LAPI still finishing initialization and comes up "crashed"
  # (confirmed in the field: `rc-service cs-firewall-bouncer status` showed
  # crashed immediately after install, and a plain `restart` — no config
  # change — fixed it instantly). Retry the start a few times instead of
  # accepting the first crash.
  BOUNCER_UP=0
  for attempt in 1 2 3 4 5; do
    if rc-service cs-firewall-bouncer status 2>/dev/null | grep -q started; then
      BOUNCER_UP=1; break
    fi
    warn "cs-firewall-bouncer not started yet (attempt ${attempt}/5) — restarting"
    rc-service cs-firewall-bouncer restart >/dev/null 2>&1 || true
    sleep 5
  done
  [ "$BOUNCER_UP" = "1" ] \
    && ok "cs-firewall-bouncer service running" \
    || warn "cs-firewall-bouncer still not started after retries — run: rc-service cs-firewall-bouncer restart"
  sleep 2
  BOUNCER_REGISTERED=0
  PRUN exec crowdsec cscli bouncers list 2>/dev/null | grep -q firewall-bouncer \
    && { BOUNCER_REGISTERED=1; ok "Bouncer connected to LAPI"; } \
    || warn "Bouncer not yet showing — check rc-service cs-firewall-bouncer status"
else
  BOUNCER_UP=0
  BOUNCER_REGISTERED=0
fi

# FORENSIC FIX (new-audit High finding, confirmed accurate): this used to
# only ever `warn` when the bouncer never came up or never registered —
# unlike the Alpine-image and digest-pinning checks elsewhere in this
# install, which both fail closed under DEPLOYMENT_PROFILE=production.
# CrowdSec's engine only DETECTS and decides bans; the bouncer is what
# actually ENFORCES them via nftables. A "successful" install with the
# engine up but no working bouncer silently downgrades the whole layer to
# detection-only — decisions get made, nothing blocks them — which is a
# materially different security posture than what production mode
# promises. Standard mode keeps the original warn-and-continue (a
# transient LAPI-registration hiccup shouldn't brick a homelab install);
# production mode now matches the fail-closed pattern used everywhere else
# in this codebase for the same class of "did the thing we just installed
# actually come up" question.
if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ] \
   && { [ "$BOUNCER_UP" != "1" ] || [ "$BOUNCER_REGISTERED" != "1" ]; }; then
  err "cs-firewall-bouncer is not running and registered with CrowdSec's LAPI — refusing to continue under DEPLOYMENT_PROFILE=production, since CrowdSec would be detecting bans without enforcing any of them. Check: podman logs crowdsec ; rc-service cs-firewall-bouncer status. Retry once fixed, or re-run under DEPLOYMENT_PROFILE=standard if this is a lab install."
fi

install -m 0755 "${PAYLOAD_DIR}/init.d/crowdsec-container" /etc/init.d/crowdsec-container
chmod +x /etc/init.d/crowdsec-container
rc-update add crowdsec-container default 2>/dev/null || true
ok "crowdsec-container service registered"

# BUG FIX: podman-compose is NOT needed for podman auto-update.
# podman auto-update is a built-in Podman command.
# BUG FIX (v7-13, ChatGPT Finding 7 in the audit): the inline daily backup
# cron used to be `podman exec ... mariadb-dump ... | gzip > file.sql.gz`
# — the exact pipe-to-gzip pattern that #4 in the original audit closed
# inside do_db_update() during v7-9, but that hadn't been folded into this
# cron line because it wasn't inside do_db_update() itself. Same failure
# mode: cron's default shell has no pipefail, so a `mariadb-dump` failure
# was masked by gzip's own successful exit on empty input — producing a
# valid, empty, unrestorable .sql.gz that then aged into the retention
# window while older good backups were rotated out. wp-db-backup.sh
# reuses do_db_update's proven pipeline: write raw SQL first (so its own
# exit status is what's checked, not gzip's), confirm the dump completed
# by looking for mariadb-dump's own trailing marker, gzip and verify with
# gzip -t, and only THEN rotate. If any step fails, the partial file is
# removed and the rotation is skipped, so a bad day never destroys the
# previous good backup.
install -m 0755 "${PAYLOAD_DIR}/bin/wp-db-backup.sh" /usr/local/bin/wp-db-backup.sh
chmod 755 /usr/local/bin/wp-db-backup.sh

cat "${PAYLOAD_DIR}/cron/wordpress-vm.cron" >> /etc/crontabs/root
ok "Cron jobs scheduled:"
ok "  Weekly  : podman auto-update dry-run (Sun 04:00)"
ok "  Every 5m: WordPress system cron (replaces WP-Cron)"
ok "  Daily   : MariaDB backup to /root/wp-db-backups/ (verified, 7-day retention)"

# ════════════════════════════════════════════════════════════════════════════
# 8G FIREWALL v1.4 — Apache .htaccess WAF, runs before PHP (fast)
# Sourced: perishablepress.com/8g-firewall (free for all use, credit intact)
# WordPress only rewrites between # BEGIN/END WordPress markers —
# our 8G rules placed ABOVE that block survive any WordPress .htaccess flush.
# DIVI: visual builder (admin-ajax, REST API) unaffected by these rules.
# Toggle: wp-hardening.sh disable 8g  or  wp-hardening.sh enable 8g
# ════════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════════
# TRIVY — Container vulnerability scanner (gates updates in update.sh)
# Latest: v0.71.2 (June 2026). Cache at /var/cache/trivy persists reboots.
# First scan downloads the DB (~100-200 MB); subsequent scans use cache (<15s).
# ════════════════════════════════════════════════════════════════════════════
