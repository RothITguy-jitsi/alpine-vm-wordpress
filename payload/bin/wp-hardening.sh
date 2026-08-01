#!/bin/sh
# WordPress VM Security Feature Toggle
# Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp]
# From Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# Features: 8g  xmlrpc  uploads-php  author-enum  debug
set -e
# v7-16: auto-elevate via doas instead of hard-failing (see update.sh for the
# full rationale) — the admin can only copy/paste over SSH as the unprivileged
# wheel user, so re-exec through doas so this works over SSH. "$@" is intact
# here (dispatch is later), so it survives the exec.
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then
    exec doas "$0" "$@"
  fi
  echo "Run as root (or install doas and run as a wheel user)" >&2
  exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
PRUN() {
  podman "$@"
}

HTACCESS="/home/wpuser/wp/htaccess/.htaccess"
APACHE_CONF="/home/wpuser/wp/apache-conf/wp-security.conf"
TRIVY_CACHE_DIR="/var/cache/trivy"
# FORENSIC FIX (new-audit High finding, confirmed accurate): "enable
# uploads-php" (i.e. open the PHP-execution block) had no automatic
# expiration — a real risk since wp-content/uploads is exactly where an
# attacker who can get a file onto the server would want PHP to execute.
# Left open and forgotten, it's a standing hole with no timer on it. This
# marker file's mtime is the timer: written when opened, checked by a cron
# entry (see payload/cron/wordpress-vm.cron) that re-blocks automatically
# after UPLOADS_PHP_MAX_OPEN_SECS, and removed by any re-block (manual or
# automatic) so the timer can't double-fire. Persistent under
# /etc/wp-install/ (not /var/run) so a reboot while open doesn't reset the
# clock — the whole point is a bound on how long this stays open.
UPLOADS_PHP_MARKER="/etc/wp-install/uploads-php-opened-at"
EGRESS_EXTRA_FILE="/etc/wp-install/egress-extra.nft"
UPLOADS_PHP_MAX_OPEN_SECS=3600

restart_wp() { PRUN restart wordpress >/dev/null 2>&1 && echo "  ✔  WordPress restarted" || true; }

feature_state() {
  case "$1" in
    8g)          grep -q '^# 8G DISABLED' "$HTACCESS" 2>/dev/null && echo DISABLED || echo ENABLED ;;
    xmlrpc)      grep -q 'xmlrpc.php.*Require all denied' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    uploads-php) grep -q 'wp-content/uploads' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    debug)       PRUN exec wordpress php -r 'echo (defined("WP_DEBUG") && WP_DEBUG)?"ON":"OFF";' 2>/dev/null || echo UNKNOWN ;;
  esac
}

show_status() {
  echo ""
  echo "WordPress VM — Security Features"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  %-18s %s\n" "8G Firewall:"    "$(feature_state 8g)"
  printf "  %-18s %s\n" "xmlrpc.php:"     "$(feature_state xmlrpc)"
  printf "  %-18s %s\n" "uploads PHP:"    "$(feature_state uploads-php)"
  printf "  %-18s %s\n" "WP_DEBUG:"       "$(feature_state debug)"
  echo ""
  echo "Containers:"
  PRUN ps --format "  {{.Names}}: {{.Status}}" 2>/dev/null | head -5
  echo ""
  echo "Trivy cache: $(du -sh ${TRIVY_CACHE_DIR} 2>/dev/null | cut -f1 || echo 'not installed')"
  echo "Lynis last:  $(stat -c '%y' /var/log/lynis-report.dat 2>/dev/null | cut -d. -f1 || echo 'not run yet')"
  echo ""
  echo "Commands: enable|disable [8g|xmlrpc|uploads-php|debug|author-enum]"
  echo "          egress-list | egress-allow <port> [tcp|udp] | egress-deny <port>"
  echo "          geoip-test [ip] | proxy-check"
  echo "          crowdsec-whitelist [list|add <ip>|remove <ip>]"
  echo "Proxmox:  qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
}

enable_feature() {
  case "$1" in
    8g)
      sed -i 's/^# 8G DISABLED //' "$HTACCESS" 2>/dev/null || true
      echo "✔ 8G Firewall enabled"; restart_wp ;;
    xmlrpc)
      sed -i '/<Files "xmlrpc\.php">/,/<\/Files>/d' "$APACHE_CONF" 2>/dev/null
      echo "✔ xmlrpc.php unblocked (Jetpack etc. can now use it)"
      echo "  ⚠ Monitor with: podman exec crowdsec cscli decisions list"
      restart_wp ;;
    uploads-php)
      sed -i '/<DirectoryMatch.*uploads/,/<\/DirectoryMatch>/d' "$APACHE_CONF" 2>/dev/null
      mkdir -p "$(dirname "$UPLOADS_PHP_MARKER")"
      date +%s > "$UPLOADS_PHP_MARKER"
      echo "✔ PHP in uploads unblocked  ⚠ security risk — auto re-blocks in $((UPLOADS_PHP_MAX_OPEN_SECS/60)) min (or run: wp-hardening.sh disable uploads-php)"
      restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",false)/define(\"WP_DEBUG\",true)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG ON  ⚠ DISABLE after troubleshooting — exposes internals" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

disable_feature() {
  case "$1" in
    8g)
      sed -i 's/^  RewriteEngine On$/# 8G DISABLED   RewriteEngine On/g;s/^  RewriteCond /# 8G DISABLED   RewriteCond /g;s/^  RewriteRule /# 8G DISABLED   RewriteRule /g' \
        "$HTACCESS" 2>/dev/null
      echo "✔ 8G Firewall disabled  |  re-enable: wp-hardening.sh enable 8g"
      restart_wp ;;
    xmlrpc)
      grep -q 'xmlrpc' "$APACHE_CONF" \
        || printf '\n<Files "xmlrpc.php">\n    Require all denied\n</Files>\n' >> "$APACHE_CONF"
      echo "✔ xmlrpc.php blocked"; restart_wp ;;
    uploads-php)
      grep -q 'wp-content/uploads' "$APACHE_CONF" \
        || cat >> "$APACHE_CONF" << 'B'

<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
B
      rm -f "$UPLOADS_PHP_MARKER"
      echo "✔ PHP in uploads blocked"; restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",true)/define(\"WP_DEBUG\",false)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG OFF" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

case "${1:-status}" in
  status)      show_status ;;
  enable)      [ -n "$2" ] && enable_feature "$2"  || echo "Usage: wp-hardening.sh enable <feature>" ;;
  disable)     [ -n "$2" ] && disable_feature "$2" || echo "Usage: wp-hardening.sh disable <feature>" ;;
  restart-wp)  restart_wp ;;
  crowdsec-whitelist)
    _WL=/opt/crowdsec/config/postoverflows/s01-whitelist/wpvm-operator.yaml
    _act="${2:-list}"; _ip="${3:-}"
    case "$_act" in
      list|"")
        echo ""
        echo "CrowdSec whitelist — addresses that are never banned"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [ -r "$_WL" ]; then
          sed -n 's/^    - "\(.*\)"/  • \1/p' "$_WL" | grep . || echo "  (file exists but lists nothing)"
        else
          echo "  (no whitelist configured)"
          echo ""
          echo "  A ban applies at nftables and drops SSH as well as HTTP, so an"
          echo "  admin address getting banned locks you out of the VM until you"
          echo "  use the Proxmox console."
        fi
        echo ""
        echo "  Currently banned addresses:"
        podman exec crowdsec cscli decisions list -o raw 2>/dev/null \
          | tail -n +2 | head -20 | sed 's/^/    /' || echo "    (none, or cscli unavailable)"
        echo ""
        echo "  Add:     wp-hardening.sh crowdsec-whitelist add <ip|cidr>"
        echo "  Remove:  wp-hardening.sh crowdsec-whitelist remove <ip|cidr>"
        echo "  Unban now (does not whitelist): podman exec crowdsec cscli decisions delete --ip <ip>" ;;
      add|remove)
        [ -n "$_ip" ] || { echo "Usage: wp-hardening.sh crowdsec-whitelist ${_act} <ip|cidr>" >&2; exit 1; }
        printf '%s' "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' \
          || { echo "✗ '${_ip}' is not a valid IPv4 address or CIDR." >&2; exit 1; }
        mkdir -p "$(dirname "$_WL")"
        if [ ! -f "$_WL" ]; then
          {
            printf 'name: rothitguy/wpvm-operator-whitelist\n'
            printf 'description: "Addresses the operator declared must never be banned"\n'
            printf 'whitelist:\n'
            printf '  reason: "operator-declared address"\n'
          } > "$_WL"
        fi
        case "$_ip" in */*) _key="cidr" ;; *) _key="ip" ;; esac
        if [ "$_act" = "add" ]; then
          grep -q "\"${_ip}\"" "$_WL" && { echo "Already whitelisted: ${_ip}"; exit 0; }
          grep -q "^  ${_key}:" "$_WL" || printf '  %s:\n' "$_key" >> "$_WL"
          # Insert directly under the right key so ip: and cidr: lists stay
          # separate -- CrowdSec validates the shape and silently ignores the
          # whole file if a CIDR turns up under ip:.
          awk -v k="  ${_key}:" -v v="    - \"${_ip}\"" \
            '{print} $0==k && !d {print v; d=1}' "$_WL" > "${_WL}.tmp" && mv -f "${_WL}.tmp" "$_WL"
          echo "✔ Whitelisted ${_ip}"
          echo "  ⚠ Anything at that address can now brute-force this site without being banned."
        else
          grep -v -- "- \"${_ip}\"" "$_WL" > "${_WL}.tmp" && mv -f "${_WL}.tmp" "$_WL"
          echo "✔ Removed ${_ip} from the whitelist"
        fi
        chmod 644 "$_WL"
        # The engine reads these at start; a reload is what makes the change real.
        if podman exec crowdsec kill -HUP 1 2>/dev/null || podman restart crowdsec >/dev/null 2>&1; then
          echo "  CrowdSec reloaded — change is live."
        else
          echo "  ⚠ Could not reload CrowdSec. Apply with: podman restart crowdsec"
        fi ;;
      *) echo "Usage: wp-hardening.sh crowdsec-whitelist [list|add <ip>|remove <ip>]" >&2; exit 1 ;;
    esac ;;

  proxy-check)
    # Answers the one question that decides every "works on the LAN IP but
    # not through the domain" report: what address does Apache believe the
    # client is? Everything else (slug, wp-admin restriction, CSP) keys off
    # that, so guessing at those first wastes time.
    . /etc/wp-install/vars.sh 2>/dev/null || true
    DBG=/home/wpuser/wp/logs/remoteip-debug.log
    echo ""
    echo "Reverse-proxy / client IP diagnosis"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ -z "${PROXY_IP:-}" ]; then
      echo "  No PROXY_IP configured — mod_remoteip is not loaded."
      echo "  Apache uses the raw connection address as the client IP."
      exit 0
    fi
    echo "  Trusted proxy (RemoteIPTrustedProxy) : ${PROXY_IP}"
    echo "  wp-admin allowed                     : ${ADMIN_CIDR:-none} ${ALLOWED_ADMIN_IP:-}"
    echo ""
    if [ ! -s "$DBG" ]; then
      echo "  ${DBG} is empty."
      echo "  Make one request through the domain, then re-run this."
      exit 0
    fi
    echo "  Last 15 requests (peer = who connected, interpreted = who Apache thinks it is):"
    tail -15 "$DBG" | sed 's/^/    /'
    echo ""
    # The decisive comparison: if peer never equals the configured proxy,
    # mod_remoteip cannot trust anything and the X-Forwarded-For header is
    # ignored regardless of whether the proxy sent one.
    _peers=$(sed -n 's/.*peer=\([^ ]*\).*/\1/p' "$DBG" | sort -u | head -8)
    echo "  Distinct peers seen: $(printf '%s' "$_peers" | tr '\n' ' ')"
    if printf '%s\n' "$_peers" | grep -qx "$PROXY_IP"; then
      echo "  ✔ ${PROXY_IP} does connect — mod_remoteip will trust its header."
      _bad=$(grep "peer=${PROXY_IP} " "$DBG" | sed -n 's/.*interpreted=\([^ ]*\).*/\1/p' \
             | grep -x "$PROXY_IP" | head -1)
      if [ -n "$_bad" ]; then
        echo "  ✗ But interpreted is ALSO ${PROXY_IP} on some requests, which means the"
        echo "    proxy did not send a usable X-Forwarded-For. Apache then treats the"
        echo "    proxy as the client, and the wp-admin rules reject it."
        echo "    Fix in the proxy, not here: enable X-Forwarded-For on that host."
      else
        echo "  ✔ interpreted differs from the peer — the header is being honoured."
        echo "    If wp-admin still 403s, compare the interpreted value above against"
        echo "    the allowed list at the top: that address must appear in it."
      fi
    else
      echo "  ✗ Nothing has connected from ${PROXY_IP}."
      echo "    The proxy reaches this VM from a DIFFERENT address than configured"
      echo "    — common when the proxy runs in a container or has several"
      echo "    interfaces, so its management IP is not its egress IP."
      echo "    Use one of the peers listed above as the trusted proxy:"
      echo "      edit PROXY_IP in /etc/wp-install/vars.sh, then re-run"
      echo "      wp-geoip-setup.sh or recreate the container to regenerate config."
    fi
    echo ""
    echo "  Status codes are the last field of each line; 403 on a /wp-login.php"
    echo "  or /wp-admin request means the interpreted address was not allowed." ;;

  geoip-test)
    # Functional test of country filtering. validate-wordpress.sh only checks
    # that mod_maxminddb is LOADED, which says nothing about whether the
    # database resolves addresses correctly or whether your allow/block list
    # does what you think it does.
    _ip="${2:-}"
    GEOIP_DB=/home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb
    echo ""
    echo "GeoIP filtering — functional test"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [ "${GEOIP_ENABLED:-0}" != "1" ]; then
      echo "  GeoIP is not enabled on this VM. Nothing to test."
      echo "  Enable it with:  doas /usr/local/bin/wp-geoip-setup.sh"
      exit 0
    fi

    # 1. Module actually loaded in the running Apache.
    if podman exec wordpress apache2ctl -M 2>/dev/null | grep -qi maxminddb; then
      echo "  ✔  mod_maxminddb is loaded in the running Apache"
    else
      echo "  ✗  mod_maxminddb is NOT loaded — filtering is inactive right now"
      echo "     doas podman logs --tail 30 wordpress"
      exit 1
    fi

    # 2. Database present, and FRESH. GeoLite2 is republished weekly and IP
    #    allocations move; a database left to rot quietly misclassifies real
    #    visitors, which looks like random 403s rather than a stale file.
    if [ -s "$GEOIP_DB" ]; then
      _age_days=$(( ( $(date +%s) - $(stat -c %Y "$GEOIP_DB" 2>/dev/null || echo 0) ) / 86400 ))
      _size=$(du -h "$GEOIP_DB" | cut -f1)
      if [ "$_age_days" -gt 60 ]; then
        echo "  ⚠  Database present (${_size}) but ${_age_days} days old — refresh it:"
        echo "     doas /usr/local/bin/wp-geoip-setup.sh"
      else
        echo "  ✔  Database present (${_size}, ${_age_days} days old)"
      fi
    else
      echo "  ✗  Database missing at ${GEOIP_DB}"
      exit 1
    fi

    # 3. Configured policy, read from the live config rather than from vars.sh
    #    -- the running Apache is what actually decides.
    _conf=/home/wpuser/wp/apache-conf/geoip.conf
    _mode=$(grep -o 'AllowCountry\|BlockCountry' "$_conf" 2>/dev/null | head -1)
    _list=$(sed -n 's/.*MM_COUNTRY_CODE "\^(\([^)]*\))\$".*/\1/p' "$_conf" 2>/dev/null | head -1)
    case "$_mode" in
      AllowCountry) echo "  ℹ  Policy: WHITELIST — only [${_list}] may reach the site" ;;
      BlockCountry) echo "  ℹ  Policy: BLOCKLIST — [${_list}] is denied, everyone else allowed" ;;
      *)            echo "  ⚠  Could not read the policy from ${_conf}" ;;
    esac
    echo "  ℹ  Private/loopback addresses are always exempt (your LAN is never blocked)"

    # 4. Resolve a specific address, if one was given.
    if [ -n "$_ip" ]; then
      echo ""
      echo "  Looking up ${_ip}…"
      if command -v mmdblookup >/dev/null 2>&1; then
        _cc=$(mmdblookup --file "$GEOIP_DB" --ip "$_ip" country iso_code 2>/dev/null \
              | sed -n 's/.*"\([A-Z][A-Z]\)".*/\1/p' | head -1)
        if [ -z "$_cc" ]; then
          echo "  ⚠  No country for ${_ip} in the database."
          echo "     Private, reserved and some newly-allocated ranges have no entry."
          echo "     Under a WHITELIST that means DENIED unless the address is"
          echo "     private (private is exempt); under a BLOCKLIST it means allowed."
        else
          echo "  ℹ  ${_ip} → ${_cc}"
          case "$_mode" in
            AllowCountry)
              if echo "$_list" | tr '|' ' ' | grep -qw "$_cc"; then
                echo "  ✔  Expected verdict: ALLOWED (${_cc} is in the whitelist)"
              else
                echo "  ✔  Expected verdict: BLOCKED (${_cc} is not in the whitelist)"
              fi ;;
            BlockCountry)
              if echo "$_list" | tr '|' ' ' | grep -qw "$_cc"; then
                echo "  ✔  Expected verdict: BLOCKED (${_cc} is in the blocklist)"
              else
                echo "  ✔  Expected verdict: ALLOWED (${_cc} is not in the blocklist)"
              fi ;;
          esac
        fi
      else
        echo "  ⚠  mmdblookup is not installed, so the address cannot be resolved here."
        echo "     It is a small package and does not touch the containers:"
        echo "       doas apk add libmaxminddb"
      fi
    else
      echo ""
      echo "  Resolve a specific address:  wp-hardening.sh geoip-test 8.8.8.8"
    fi

    # 5. Be honest about what this proved.
    echo ""
    echo "  What this checked: the module is live, the database is present and"
    echo "  fresh, the policy is what you think it is, and how a given address"
    echo "  resolves. That is the configuration."
    echo ""
    echo "  What it CANNOT check from inside the VM: Apache's actual verdict on"
    echo "  a real foreign request. Every request originating here comes from a"
    echo "  private address, which is exempt by design, so it will always be"
    echo "  allowed no matter what the policy says."
    echo ""
    echo "  The only true end-to-end test is from outside:"
    echo "    • From a host in a blocked country (a cheap VPS, or a VPN exit):"
    echo "        curl -o /dev/null -w '%{http_code}\\n' http://<your-site>/"
    echo "        expect 403 when blocked, 200 when allowed"
    echo "    • Or, if a reverse proxy fronts this VM, from the proxy itself:"
    echo "        curl -o /dev/null -w '%{http_code}\\n' \\"
    echo "             -H 'X-Forwarded-For: <foreign-ip>' http://<vm-ip>/"
    echo "      (only the configured proxy IP is trusted for that header, so"
    echo "       this cannot be forged from anywhere else)" ;;

  egress-list)
    # Show what the LIVE ruleset permits, not what a config file says it
    # should -- the two diverge the moment someone edits by hand.
    echo ""
    echo "Outbound (egress) policy"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━"
    if nft list chain inet filter output 2>/dev/null | grep -q "nft-egress-drop"; then
      echo "  Mode: RESTRICTED — anything not listed below is dropped and logged."
    else
      echo "  Mode: UNRESTRICTED — only the hypervisor management ports are blocked."
      echo "        (Enable at install time, or add rules by hand.)"
    fi
    echo ""
    echo "  Always allowed:  53 DNS · 123 NTP · 67/68 DHCP · 80 HTTP · 443 HTTPS"
    echo "                   25/465/587 mail (connection-rate-limited)"
    echo ""
    echo "  Operator-added TCP ports:"
    nft list set inet filter egress_extra_tcp 2>/dev/null \
      | sed -n 's/.*elements = {\(.*\)}.*/    \1/p' | grep . || echo "    (none)"
    echo "  Operator-added UDP ports:"
    nft list set inet filter egress_extra_udp 2>/dev/null \
      | sed -n 's/.*elements = {\(.*\)}.*/    \1/p' | grep . || echo "    (none)"
    echo ""
    echo "  Recent drops (last 10):"
    grep "nft-egress-drop" /var/log/messages 2>/dev/null | tail -10 | sed 's/^/    /' \
      || echo "    (none logged)"
    echo ""
    echo "  Open a port:   wp-hardening.sh egress-allow <port> [tcp|udp]"
    echo "  Close it:      wp-hardening.sh egress-deny  <port> [tcp|udp]" ;;

  egress-allow|egress-deny)
    _act="$1"; _port="${2:-}"; _proto="${3:-tcp}"
    case "$_port" in
      ''|*[!0-9]*) echo "Usage: wp-hardening.sh ${_act} <port> [tcp|udp]" >&2; exit 1 ;;
    esac
    [ "$_port" -ge 1 ] && [ "$_port" -le 65535 ] || { echo "Port must be 1-65535" >&2; exit 1; }
    case "$_proto" in tcp|udp) : ;; *) echo "Protocol must be tcp or udp" >&2; exit 1 ;; esac
    _set="egress_extra_${_proto}"
    # Applied to the running ruleset AND written to the persistence file that
    # the main ruleset includes. Doing only the first is lost on reboot;
    # doing only the second is a change that appears to have had no effect.
    mkdir -p "$(dirname "$EGRESS_EXTRA_FILE")"
    [ -f "$EGRESS_EXTRA_FILE" ] || {
      printf '# Operator-added egress ports (wp-hardening.sh egress-allow).\n' > "$EGRESS_EXTRA_FILE"
      printf '# Included by /etc/nftables.nft — do not delete; empty is valid.\n' >> "$EGRESS_EXTRA_FILE"
      chmod 644 "$EGRESS_EXTRA_FILE"
    }
    _line="add element inet filter ${_set} { ${_port} }"
    if [ "$_act" = "egress-allow" ]; then
      nft add element inet filter "$_set" "{ ${_port} }" 2>/dev/null \
        || { echo "✗ Could not add to the live ruleset — is nftables loaded?" >&2; exit 1; }
      grep -qxF "$_line" "$EGRESS_EXTRA_FILE" 2>/dev/null || echo "$_line" >> "$EGRESS_EXTRA_FILE"
      echo "✔ ${_proto}/${_port} allowed outbound (live now, and persisted)"
      echo "  ⚠ Every port opened here is one more way out for a compromised site."
      echo "    Review periodically:  wp-hardening.sh egress-list"
    else
      nft delete element inet filter "$_set" "{ ${_port} }" 2>/dev/null || true
      if [ -f "$EGRESS_EXTRA_FILE" ]; then
        grep -vxF "$_line" "$EGRESS_EXTRA_FILE" > "${EGRESS_EXTRA_FILE}.tmp" 2>/dev/null \
          && mv -f "${EGRESS_EXTRA_FILE}.tmp" "$EGRESS_EXTRA_FILE"
      fi
      echo "✔ ${_proto}/${_port} no longer allowed outbound"
    fi ;;

  check-expiry)
    # Called every 15 min from cron (payload/cron/wordpress-vm.cron). Not a
    # user-facing command, but harmless if run by hand. No-ops silently
    # unless the marker exists AND is older than UPLOADS_PHP_MAX_OPEN_SECS —
    # both the common "not open" case and "open but still within budget"
    # case produce no output, so this doesn't spam cron's mail/log output
    # every 15 minutes for the entire life of the VM.
    if [ -f "$UPLOADS_PHP_MARKER" ]; then
      opened_at=$(cat "$UPLOADS_PHP_MARKER" 2>/dev/null || echo 0)
      now=$(date +%s)
      case "$opened_at" in ''|*[!0-9]*) opened_at=0 ;; esac
      age=$((now - opened_at))
      if [ "$age" -ge "$UPLOADS_PHP_MAX_OPEN_SECS" ]; then
        echo "wp-hardening: uploads-php was open ${age}s (limit ${UPLOADS_PHP_MAX_OPEN_SECS}s) — auto re-blocking" | logger -t wp-hardening
        disable_feature uploads-php >/dev/null 2>&1 || true
      fi
    fi ;;
  trivy-scan)
    echo "Scanning running containers for vulnerabilities..."
    for img in $(PRUN ps --format "{{.Image}}"); do
      echo "  → Scanning ${img}"
      trivy image --cache-dir "${TRIVY_CACHE_DIR}" --severity HIGH,CRITICAL --quiet "${img}" 2>/dev/null \
        && echo "  ✔  Clean" || echo "  ⚠  Vulnerabilities found — run: update.sh"
    done ;;
  lynis)
    echo "Running Lynis audit (2-5 min)..."
    lynis audit system --quiet \
      --logfile /var/log/lynis.log \
      --report-file /var/log/lynis-report.dat 2>&1 | logger -t lynis-manual
    echo "✔  Done. Score: $(grep hardening_index /var/log/lynis-report.dat | cut -d= -f2)" ;;
  *)
    echo "Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp|trivy-scan|lynis]"
    ;;
esac
