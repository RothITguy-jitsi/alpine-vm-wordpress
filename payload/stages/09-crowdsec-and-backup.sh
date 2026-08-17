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

# ── Egress proxy ─────────────────────────────────────────────────────────────
if [ "${EGRESS_PROXY:-0}" = "1" ]; then
  ts "Starting the egress proxy"
  mkdir -p /opt/squid/config /opt/squid/logs
  for _f in squid.conf hard-deny.txt allowlist-runtime.txt threat-deny.txt allowlist-maintenance.txt; do
    [ -f "${PAYLOAD_DIR}/squid/${_f}" ] && install -m 0644 "${PAYLOAD_DIR}/squid/${_f}" "/opt/squid/config/${_f}"
  done
  # Substitute the resolvers Squid should use. VM_DNS is what the operator
  # chose at install; fall back to Quad9, which is the installer's default.
  _sq_dns="${VM_DNS:-9.9.9.9 149.112.112.112}"
  sed -i "s|WASP_DNS_SERVERS_PLACEHOLDER|${_sq_dns}|" /opt/squid/config/squid.conf 2>/dev/null || true
  if grep -q "WASP_DNS_SERVERS_PLACEHOLDER" /opt/squid/config/squid.conf 2>/dev/null; then
    warn "Squid resolver placeholder not substituted — Squid will not resolve names"
  else
    ok "  Squid resolvers: ${_sq_dns}"
  fi
  # Append the page-builder domains the operator selected. Nothing is added
  # unless it was asked for, so a site running Divi does not carry Elementor's
  # licence server as a reachable destination.
  if [ -n "${PAGE_BUILDER_DOMAINS:-}" ]; then
    {
      echo ""
      echo "# Selected at install time (page builders / commercial themes)."
      echo "# Remove one with:  doas wasp-egress.sh deny <domain>"
      for _pbd in ${PAGE_BUILDER_DOMAINS}; do
        # Only ever a domain, never a path or a scheme -- this file feeds a
        # dstdomain ACL and a malformed entry makes Squid refuse the whole list.
        case "$_pbd" in
          *[!a-zA-Z0-9.-]*|'') warn "  Skipping malformed builder domain: ${_pbd}" ;;
          *) echo "$_pbd" ;;
        esac
      done
    } >> /opt/squid/config/allowlist-runtime.txt
    ok "  Builder domains allowed: ${PAGE_BUILDER_DOMAINS}"
  fi
  touch /opt/squid/config/allowlist-maintenance.txt
  chmod 0644 /opt/squid/config/*.txt
  # The log directory must be writable by the user squid runs as INSIDE the
  # container. This was 100:101 -- Alpine's squid uid:gid -- left behind when
  # the container was switched from `alpine + apk add squid` to Canonical's
  # ubuntu/squid, which runs as `proxy` (13:13 on Debian/Ubuntu). Squid could
  # not create cache.log, exited immediately, and --restart=always turned that
  # into a silent crash loop: `podman ps` showed "Up Less than a second"
  # forever while nothing worked.
  #
  # Rather than swap one magic number for another, ask the image who it runs
  # as. Falling back to 13 only if the query fails, so a future base-image
  # change does not reintroduce exactly this bug.
  _squid_uid=$(PRUN run --rm "${SQUID_IMAGE}" id -u proxy 2>/dev/null | tr -dc '0-9')
  _squid_gid=$(PRUN run --rm "${SQUID_IMAGE}" id -g proxy 2>/dev/null | tr -dc '0-9')
  [ -n "$_squid_uid" ] || _squid_uid=13
  [ -n "$_squid_gid" ] || _squid_gid=13
  chown -R "${_squid_uid}:${_squid_gid}" /opt/squid/logs 2>/dev/null || true
  chmod 0755 /opt/squid/logs 2>/dev/null || true
  ok "  Squid log dir owned by ${_squid_uid}:${_squid_gid} (queried from the image)"

  # A fixed address, because the firewall rule names it. A proxy whose address
  # moves is a firewall rule that stops matching, and the failure is silent:
  # egress simply starts being denied for the wrong reason.
  # ── Squid image: a real, pinnable image, not `apk add` at container start ──
  # Canonical's ubuntu/squid is the maintained option and, crucially, its
  # DIGEST represents a known Squid version -- which the previous
  # "alpine + apk add squid" approach could not, because the binary was
  # fetched at container start and was therefore whatever the repo served that
  # minute. That made Squid the one container update.sh could not check, scan
  # or pin. It now follows the same digest model as WordPress, MariaDB and
  # CrowdSec, and pinned.env carries SQUID_DIGEST the same way.
  # `latest` deliberately, not a pinned version tag. Canonical's scheme is
  # <squid>-<ubuntu>_<channel> (e.g. 6.6-24.04_edge) and the set of published
  # combinations is not guessable -- an earlier version of this file invented
  # "6.13-24.04_stable", which does not exist, and Squid silently fell back to
  # an unpinned tag on a real install. `latest` is guaranteed to exist, and the
  # DIGEST resolved at install is what actually pins us, so nothing is lost.
  SQUID_IMAGE="${SQUID_IMAGE:-docker.io/ubuntu/squid:latest}"
  SQUID_RUN_IMAGE="$SQUID_IMAGE"
  if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
    [ -n "${SQUID_DIGEST:-}" ] && SQUID_RUN_IMAGE="docker.io/ubuntu/squid@${SQUID_DIGEST}"
  fi

  PRUN run -d --name squid --restart=always \
    --network wp-front --ip 10.89.10.2 \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges \
    --memory 256m --pids-limit 100 \
    -v /opt/squid/config/squid.conf:/etc/squid/squid.conf:ro \
    -v /opt/squid/config/hard-deny.txt:/etc/squid/hard-deny.txt:ro \
    -v /opt/squid/config/allowlist-runtime.txt:/etc/squid/allowlist-runtime.txt:ro \
    -v /opt/squid/config/allowlist-maintenance.txt:/etc/squid/allowlist-maintenance.txt:ro \
    -v /opt/squid/config/threat-deny.txt:/etc/squid/threat-deny.txt:ro \
    -v /opt/squid/logs:/var/log/squid:rw \
    "${SQUID_RUN_IMAGE}" \
    >/dev/null 2>&1 && ok "Squid running on 10.89.10.2:3128" \
    || _squid_start_failed=1
  if [ "${_squid_start_failed:-0}" = "1" ]; then
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      block_production "Squid did not start (EGRESS_PROXY=1). Egress fails closed, so ALL WordPress web access (updates, plugin/theme APIs, licence checks) is broken -- completing the install would ship a site that cannot reach the internet at all. Refusing. Check: podman logs squid. Retry once fixed, or re-run under DEPLOYMENT_PROFILE=standard if this is a lab install where a dead proxy is acceptable."
    fi
    warn "Squid failed to start — WordPress web egress will be denied (fails closed)"
  fi

  # Verify it parses before declaring success. A proxy that started but whose
  # policy was rejected is worse than one that did not start: the firewall
  # sends traffic to it and it does not filter.
  sleep 3
  # Report the Squid version for the record. CVE-2025-62168 (CVSS 10.0,
  # credential disclosure via error pages) is the one that needed a code fix,
  # not just the `email_err_data off` policy workaround. Canonical BACKPORTS
  # that fix into the 6.x line (fixed in the 6.13-1ubuntu1.2 package), so the
  # right check here is not "is this >= 7.2" -- it is "is the image current",
  # which the digest pin plus `update.sh squid` keeps true. The policy
  # workaround remains as defence in depth regardless of package version.
  _sqv=$(PRUN exec squid squid -v 2>/dev/null | sed -n 's/.*Version \([0-9.]*\).*/\1/p' | head -1)
  [ -n "$_sqv" ] && ok "  Squid ${_sqv} (Canonical image; keep current via: update.sh squid)"
  # A check that says "this failed" without saying WHY costs a whole
  # redeploy cycle to diagnose. On a real install this printed "rejected its
  # own policy" and nothing else, and the operator had no way to know whether
  # it was a bad directive, an unreadable include, or the container dying
  # under it. Capture the actual parser output and the container's own log,
  # print the useful part inline, and keep the full text on disk.
  _squid_diag=/var/log/wasp-squid-parse.log
  # `squid -k parse` needs a RUNNING container. When the policy is bad, squid
  # exits immediately and podman answers "can only start exec sessions when
  # their container is running" -- which tells you nothing. On the install that
  # found this, the container's OWN LOG carried the real answer (a FATAL naming
  # the offending line) while the exec output was useless. So read the log
  # first, and treat exec as the optional extra.
  _sq_log=$(PRUN logs --tail 80 squid 2>&1)
  if _sq_parse=$(PRUN exec squid squid -k parse 2>&1); then
    ok "  Egress policy parsed and loaded"
  else
    {
      echo "=== squid -k parse output ($(date -u +%Y-%m-%dT%H:%M:%SZ)) ==="
      printf '%s\n' "$_sq_parse"
      echo ""
      echo "=== podman logs squid (last 80) — usually the real answer ==="
      printf '%s\n' "$_sq_log"
      echo ""
      echo "=== container state ==="
      PRUN ps -a --filter 'name=^squid$' --format '{{.Names}} {{.Status}} {{.Image}}' 2>&1
      echo ""
      echo "=== /opt/squid/logs ownership (squid must be able to write here) ==="
      ls -ln /opt/squid/logs 2>&1
      stat -c '%n owner=%u:%g mode=%a' /opt/squid/logs 2>&1
    } > "$_squid_diag" 2>&1
    chmod 600 "$_squid_diag" 2>/dev/null || true

    warn "  Squid rejected the policy. From its own log:"
    # FATAL/ERROR lines from the container log are the ones that name the
    # offending directive; they are what actually diagnoses this.
    printf '%s\n' "$_sq_log" | grep -E 'FATAL|ERROR' | head -8 | sed 's/^/      /'
    printf '%s\n' "$_sq_log" | grep -qE 'FATAL|ERROR' \
      || printf '%s\n' "$_sq_log" | tail -8 | sed 's/^/      /'
    warn "  Full log + parser output + log-dir ownership: ${_squid_diag}"

    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      block_production "Squid started but rejected its own policy (squid -k parse failed). A running proxy with a broken policy is worse than one that did not start: the firewall directs traffic to it and it does not filter. Diagnostics captured at ${_squid_diag}."
    fi
  fi
  ok "  Prove the boundary holds:  wasp-egress test"
else
  ok "Egress proxy not enabled (WordPress may reach any host on permitted ports)"
fi

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
