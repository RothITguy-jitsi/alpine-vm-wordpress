#!/bin/sh
# WordPress VM Security Feature Toggle
# Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp]   f: 8g xmlrpc uploads-php debug file-mods
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
    # Multi-line aware. The old form was a single-line grep for
    # 'xmlrpc.php.*Require all denied', but the directive spans three lines:
    #   <Files "xmlrpc.php">
    #       Require all denied
    #   </Files>
    # so it never matched and reported OPEN on a file that had been blocked
    # since install. A status check that under-reports protection is worse
    # than none: it prompts an operator to "fix" something already correct,
    # which is how a duplicate block gets appended.
    xmlrpc)      awk '/<Files[^>]*xmlrpc\.php/{f=1} f&&/Require all denied/{print "BLOCKED"; exit} /<\/Files>/{f=0} END{if(!f)exit}' \
                   "$APACHE_CONF" 2>/dev/null | grep -q BLOCKED && echo BLOCKED || echo OPEN ;;
    uploads-php) grep -q 'wp-content/uploads' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    debug)       PRUN exec wordpress php -r 'echo (defined("WP_DEBUG") && WP_DEBUG)?"ON":"OFF";' 2>/dev/null || echo UNKNOWN ;;
    file-mods)   PRUN exec wordpress php -r 'echo (defined("DISALLOW_FILE_MODS") && DISALLOW_FILE_MODS)?"BLOCKED":"ALLOWED";' 2>/dev/null || echo UNKNOWN ;;
    php-exec)    PRUN exec wordpress php -r 'echo function_exists("system")?"ALLOWED":"BLOCKED";' 2>/dev/null || echo UNKNOWN ;;
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
  echo "          geoip-test [ip] | proxy-check | nginx-snippet"
  echo "          exceptions | exceptions-check"
  echo "          admin-rule [show|strict|simple] | security-txt <contact>"
  echo "          web-list | web-allow <ip> | web-deny <ip>"
  echo "          cti [ip|--status] | cti-key <key> [budget] | cti-watch"
  echo "          lynis [run] | disk | disk-check | tls [domain]"
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
    php-exec)
      # Edit the HOST file. The in-container copy is a READ-ONLY bind mount
      # (/usr/local/etc/php/conf.d/wp-security.ini), so sed inside the
      # container fails silently -- which would have made this toggle report
      # success while changing nothing.
      sed -i 's|^;*disable_functions.*|disable_functions = exec,passthru,shell_exec,system,proc_open,popen,proc_nice,proc_terminate,proc_get_status,proc_close,pcntl_exec,dl|' \
        /home/wpuser/wp/php-conf/security.ini 2>/dev/null || true
      echo "  ✔  Process-execution functions BLOCKED. Restarting WordPress…"
      restart_wp ;;
    file-mods)
      # "enable file-mods" means ENABLE THE RESTRICTION, i.e. block installs.
      PRUN exec wordpress sh -c \
        "grep -q 'DISALLOW_FILE_MODS' /var/www/html/wp-config.php || \
         sed -i \"s|/\\* That's all, stop editing|define('DISALLOW_FILE_MODS',true);\\n/* That's all, stop editing|\" /var/www/html/wp-config.php" 2>/dev/null || true
      PRUN exec wordpress sh -c \
        "sed -i \"s|define('DISALLOW_FILE_MODS',false)|define('DISALLOW_FILE_MODS',true)|;s|define(\\\"DISALLOW_FILE_MODS\\\",false)|define(\\\"DISALLOW_FILE_MODS\\\",true)|\" /var/www/html/wp-config.php" 2>/dev/null || true
      echo "  ✔  Plugin/theme installs and updates are BLOCKED in wp-admin."
      echo "     Install from the console instead, which is logged:"
      echo "       doas wp-plugins.sh install <slug> --activate"
      ;;
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
    php-exec)
      sed -i 's|^disable_functions.*|;disable_functions = (disabled by wp-hardening.sh)|' \
        /home/wpuser/wp/php-conf/security.ini 2>/dev/null || true
      echo "✔ PHP can call system(), shell_exec() and exec() again."
      echo ""
      echo "  ⚠  This is the control that breaks commodity PHP webshells. Nearly"
      echo "     every one dropped through a vulnerable plugin calls system() or"
      echo "     shell_exec() in its first few lines. With this off, they work."
      echo ""
      echo "  Only leave it off if a plugin genuinely needs to shell out, and"
      echo "  consider whether that plugin is worth the exposure. Restore with:"
      echo "     doas wp-hardening.sh enable php-exec"
      restart_wp ;;
    file-mods)
      # "disable file-mods" means DISABLE THE RESTRICTION, i.e. allow installs.
      #
      # Why this toggle exists: DISALLOW_FILE_MODS is set automatically under
      # DEPLOYMENT_PROFILE=production, and it removes Plugins → Add New,
      # Appearance → Themes → Add New, and the theme/plugin UPLOAD form
      # entirely. That is the intent -- a hijacked admin session cannot install
      # arbitrary PHP -- but it also means an operator cannot upload a
      # commercial theme like Divi or Elementor, which is a normal, legitimate
      # thing to need to do. Reported from a real install: "I do not see the
      # theme upload section".
      #
      # The honest trade: turn it off, upload what you need, turn it back on.
      # Leaving it off is a real reduction in hardening, not a cosmetic one.
      PRUN exec wordpress sh -c \
        "sed -i \"s|define('DISALLOW_FILE_MODS',true)|define('DISALLOW_FILE_MODS',false)|;s|define(\\\"DISALLOW_FILE_MODS\\\",true)|define(\\\"DISALLOW_FILE_MODS\\\",false)|\" /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ Plugin/theme installs and uploads are ALLOWED in wp-admin again."
      echo ""
      echo "  ⚠  This is a real reduction in hardening while it is off: anyone"
      echo "     with an admin session -- including one that has been stolen --"
      echo "     can now install arbitrary PHP through the upload form."
      echo ""
      echo "  Turn it back on the moment you are finished:"
      echo "     doas wp-hardening.sh enable file-mods"
      ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug file-mods php-exec" ;;
  esac
}

case "${1:-status}" in
  smtp-repin)
    # Re-resolve the relay and rewrite the SMTP destination rule. Needed when a
    # hosted relay changes IP, which silently breaks mail until re-run -- the
    # known cost of pinning the destination rather than allowing any host on
    # port 587.
    _h=$(sed -n 's/^SMTP_HOST=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
    [ -n "$_h" ] || { echo "No SMTP relay configured." >&2; exit 1; }
    _ips=$(getent ahostsv4 "$_h" 2>/dev/null | awk '{print $1}' | sort -u | head -8 | tr '\n' ',' | sed 's/,$//')
    [ -n "$_ips" ] || { echo "✗  Could not resolve ${_h}. Check DNS before re-pinning." >&2; exit 1; }
    echo "  ${_h} now resolves to: ${_ips}"
    if nft -c -f /etc/nftables.nft 2>/dev/null; then
      sed -i "s|ip daddr { [0-9.,]* } tcp dport|ip daddr { ${_ips} } tcp dport|" /etc/nftables.nft
      if nft -c -f /etc/nftables.nft 2>/dev/null && nft -f /etc/nftables.nft 2>/dev/null; then
        echo "  ✔  SMTP destination re-pinned and the ruleset reloaded."
        echo "     Verify:  doas wp-mail.sh doctor"
      else
        echo "✗  The edited ruleset did not validate — nothing was loaded." >&2
        echo "   Inspect /etc/nftables.nft before retrying." >&2
        exit 1
      fi
    else
      echo "✗  The current ruleset does not validate; refusing to edit it." >&2
      exit 1
    fi ;;

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

  security-txt)
    # RFC 9116. A one-line file that tells a researcher who finds something
    # where to send it. Without one they either give up, post publicly, or
    # try the WHOIS address -- none of which is how you want to learn about a
    # vulnerability in a client's site.
    #
    # Flagged as missing by an external scan of a live deployment.
    . /etc/wp-install/vars.sh 2>/dev/null || true
    _c="${2:-${WP_ADMIN_EMAIL:-}}"
    if [ -z "$_c" ]; then
      echo "Usage: wp-hardening.sh security-txt <contact-email-or-url>" >&2
      echo "  e.g. wp-hardening.sh security-txt security@example.com" >&2
      exit 1
    fi
    case "$_c" in
      https://*|mailto:*) _uri="$_c" ;;
      *@*)                _uri="mailto:${_c}" ;;
      *)                  echo "✗ Give an email address or an https:// URL" >&2; exit 1 ;;
    esac
    # Expires is required by RFC 9116 and is the field everyone forgets. A
    # stale security.txt is worse than none: it tells a researcher the contact
    # is current when it may not be.
    _exp=$(date -u -d "+1 year" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null) || \
      _exp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    _dir=/home/wpuser/wp/html/.well-known
    mkdir -p "$_dir"
    {
      printf 'Contact: %s\n' "$_uri"
      printf 'Expires: %s\n' "$_exp"
      printf 'Preferred-Languages: en\n'
      [ -n "${WP_DOMAIN:-}" ] && printf 'Canonical: https://%s/.well-known/security.txt\n' "$WP_DOMAIN"
    } > "$_dir/security.txt"
    chown -R 33:33 "$_dir" 2>/dev/null || true
    chmod 644 "$_dir/security.txt"
    echo "✔ Written to ${_dir}/security.txt"
    echo "  Contact : ${_uri}"
    echo "  Expires : ${_exp}  (RFC 9116 requires this; re-run before it lapses)"
    echo ""
    echo "  Confirm it is reachable:"
    echo "    curl -s https://${WP_DOMAIN:-your-domain}/.well-known/security.txt"
    echo ""
    echo "  If it 404s, the .well-known path may be blocked by the dotfile"
    echo "  deny rule at the proxy. Add an exception ABOVE that rule:"
    echo "    location ^~ /.well-known/ { allow all; proxy_pass http://VM-IP:80; }" ;;

  nginx-snippet)
    # Prints proxy-side configuration filled in with THIS VM's actual values.
    # Generated rather than documented because the useful version needs the
    # admin CIDR, the extra allowed IP, the login slug and the VM's address --
    # and a snippet transcribed by hand with one of those wrong is worse than
    # none, since it looks configured.
    . /etc/wp-install/vars.sh 2>/dev/null || true
    _vmip=$(ip -4 addr show scope global 2>/dev/null \
            | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1)
    _slug="${WP_ADMIN_SLUG:-}"
    # Written out rather than as ${_slug:-a}${_slug:+b}. That form is correct
    # here, but it is the same shape as a bug fixed earlier in this project --
    # where ${V:+X}${V:-Y} was mistaken for if/else and silently appended the
    # variable. Anything requiring a reader to reason about expansion
    # semantics to confirm a display string is not worth the two saved lines.
    if [ -n "$_slug" ]; then _loginpath="/${_slug}"; else _loginpath="/wp-login.php"; fi
    cat <<SNIPPET

═══════════════════════════════════════════════════════════════════
 Nginx Proxy Manager configuration for this VM
═══════════════════════════════════════════════════════════════════

  VM address        : ${_vmip:-<unknown>}
  Admin CIDR        : ${ADMIN_CIDR:-<none>}
  Extra allowed IP  : ${ALLOWED_ADMIN_IP:-<none>}
  Login path        : ${_loginpath}
  Trusted proxy     : ${PROXY_IP:-<none configured>}

───────────────────────────────────────────────────────────────────
 1. PROXY HOST -> Advanced tab   (the important one)
───────────────────────────────────────────────────────────────────

 Why this beats the Apache-side rule: nginx is the edge, so \$remote_addr
 IS the client. There is no header to trust and no substitution step to
 fail. The Apache rule stays as a second, independent layer.

SNIPPET
    printf 'location ~* ^/(wp-admin/|wp-login\\.php'
    [ -n "$_slug" ] && printf '|%s' "$_slug"
    printf ') {\n'
    [ -n "${ADMIN_CIDR:-}" ]       && printf '    allow %s;\n' "$ADMIN_CIDR"
    [ -n "${ALLOWED_ADMIN_IP:-}" ] && printf '    allow %s;\n' "$ALLOWED_ADMIN_IP"
    printf '    deny all;\n\n'
    printf '    # Rate limiting is SAFE here now: the zone keys on POST only,\n'
    printf '    # so the assets this page loads are never counted. Requires the\n'
    printf '    # map + limit_req_zone from section 1 to exist first.\n'
    printf '    limit_req zone=wplogin burst=5 nodelay;\n'
    printf '    # 429, not the default 503. A rate-limited client should be told\n'
    printf '    # to slow down, not that the service is broken.\n'
    printf '    limit_req_status 429;\n\n'
    printf '    proxy_pass http://%s:80;\n' "${_vmip:-VM_IP}"
    printf '    proxy_set_header Host              \$host;\n'
    printf '    proxy_set_header X-Real-IP         \$remote_addr;\n'
    printf '    # REPLACE, not append. NPM defaults to\n'
    printf '    #   \$proxy_add_x_forwarded_for\n'
    printf '    # which appends to whatever the CLIENT sent, so a forged header\n'
    printf '    # arrives as "<forged>, <real>". mod_remoteip should still pick\n'
    printf '    # the right one, but only if RemoteIPTrustedProxy is exactly\n'
    printf '    # right. Replacing it states the truth and removes the class.\n'
    printf '    proxy_set_header X-Forwarded-For   \$remote_addr;\n'
    printf '    proxy_set_header X-Forwarded-Proto \$scheme;\n'
    printf '}\n\n'
    printf 'location = /xmlrpc.php { deny all; }\n\n'
    printf '# ── Security headers, set at the EDGE ──────────────────────────\n'
    printf '# The VM already sets these in Apache. An external scan of a live\n'
    printf '# deployment found NONE of them reaching the internet — only HSTS,\n'
    printf '# which the proxy adds itself. Headers that protect the visitor are\n'
    printf '# worth nothing if they die at the proxy, and whether they survive\n'
    printf '# depends on proxy configuration the VM cannot see or control.\n'
    printf '#\n'
    printf '# proxy_hide_header first, then add_header: without hiding, nginx\n'
    printf '# appends rather than replaces and the client receives the header\n'
    printf '# twice, which some browsers resolve by taking the STRICTER value\n'
    printf '# and others by taking the first. Deterministic beats lucky.\n'
    printf '#\n'
    printf '# always: send these on error responses too. A 403 or 500 page is\n'
    printf '# still a page a browser renders.\n'
    printf 'proxy_hide_header X-Frame-Options;\n'
    printf 'proxy_hide_header X-Content-Type-Options;\n'
    printf 'proxy_hide_header Referrer-Policy;\n'
    printf 'proxy_hide_header Permissions-Policy;\n'
    printf 'add_header X-Frame-Options        \"SAMEORIGIN\" always;\n'
    printf 'add_header X-Content-Type-Options \"nosniff\" always;\n'
    printf 'add_header Referrer-Policy        \"strict-origin-when-cross-origin\" always;\n'
    printf 'add_header Permissions-Policy     \"camera=(), microphone=(), geolocation=(), payment=()\" always;\n'
    printf '\n'
    printf '# includeSubDomains added. The scan found \"max-age=63072000; preload\"\n'
    printf '# WITHOUT it — which is not merely weaker, it is INVALID for the HSTS\n'
    printf '# preload list. A preload submission is rejected without\n'
    printf '# includeSubDomains, so the directive was doing nothing.\n'
    printf '# Only add this once you are certain EVERY subdomain serves HTTPS.\n'
    printf 'add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n'
    printf '\n'
    printf '# CSP is deliberately NOT set here. The VM tailors it per-path --\n'
    printf '# wp-admin needs unsafe-eval, the public site does not -- and a\n'
    printf '# single blanket policy at the edge would either break the admin\n'
    printf '# interface or weaken the public site to match it. Check the VM is\n'
    printf '# emitting it, and that the proxy forwards it:\n'
    printf '#   curl -sI https://YOUR-DOMAIN/ | grep -i content-security\n'
    cat <<'SNIPPET2'

───────────────────────────────────────────────────────────────────
 2. NPM HOST -> /data/nginx/custom/http_top.conf
───────────────────────────────────────────────────────────────────

 limit_req_zone lives in the http block, which the Advanced tab cannot
 reach. Create the file if it does not exist, then restart NPM.

# Keyed on POST only. An empty key is not rate limited, so GETs — every
# CSS, JS and image the login page pulls — pass freely.
#
# The earlier version keyed on $binary_remote_addr and the location
# matched the whole admin tree. A single login page load is a dozen or
# more requests, so the budget was spent by the page loading itself and
# nginx answered 503 — its DEFAULT status for limit_req — for everything
# after. The front page kept working because it did not match.
map $request_method $wplogin_limit_key {
    POST    $binary_remote_addr;
    default "";
}
limit_req_zone $wplogin_limit_key zone=wplogin:10m rate=6r/m;

───────────────────────────────────────────────────────────────────
 3. Verify, in this order
───────────────────────────────────────────────────────────────────

 a) From an ALLOWED address, load the login page. It must still work.
    Locking yourself out is the likeliest way this goes wrong.

 b) From a phone on mobile data (wifi OFF):
       expect 403 from nginx — it should not reach this VM at all

 c) Back on this VM, confirm what Apache now sees:
       wp-hardening.sh proxy-check
    interpreted= should show the REAL client, never the proxy.

 d) Rate limit, from an allowed address:
       for i in $(seq 1 10); do curl -o /dev/null -s -w "%{http_code} "          https://YOUR-DOMAIN/YOUR-LOGIN-PATH; done; echo
    Expect a few 200s then 429s.

───────────────────────────────────────────────────────────────────
 What this does NOT fix
───────────────────────────────────────────────────────────────────

 Restricting at nginx protects the admin paths. The login rate limiter,
 CrowdSec and GeoIP on the VM still identify clients from
 X-Forwarded-For, so they still depend on mod_remoteip working. Section 1
 makes that header trustworthy; it does not remove the dependency.

 The edge rate limit is the exception — it works on $remote_addr directly
 and holds even if everything downstream is misconfigured. That is why it
 is worth adding even though the VM already rate-limits logins.

SNIPPET2
    ;;

  exceptions)
    # A reader for the exception log. Without one the log is write-only: a
    # governance process that records decisions and never surfaces them again
    # is a filing cabinet, not oversight. This is what a periodic review reads.
    _log=/var/log/wasp-vuln-exceptions.log
    _today=$(date -u +%Y-%m-%d)
    echo ""
    echo "Vulnerability exceptions"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━"
    if [ ! -s "$_log" ]; then
      echo "  None recorded. Every HIGH/CRITICAL finding has either been fixed"
      echo "  by an update or has blocked one — which is the intended state."
      exit 0
    fi
    _act=0; _exp=0; _soon=0
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      _when=$(printf '%s' "$line" | awk -F' \\| ' '{print $1}')
      _who=$(printf  '%s' "$line" | sed -n 's/.*who=\([^|]*\).*/\1/p' | sed 's/ *$//')
      _dig=$(printf  '%s' "$line" | sed -n 's/.*digest=\([^|]*\).*/\1/p' | sed 's/ *$//')
      _unt=$(printf  '%s' "$line" | sed -n 's/.*until=\([^|]*\).*/\1/p' | sed 's/ *$//')
      _cve=$(printf  '%s' "$line" | sed -n 's/.*cves=\([^|]*\).*/\1/p' | sed 's/ *$//')
      _rsn=$(printf  '%s' "$line" | sed -n 's/.*reason=//p')
      if [ "$_today" \> "$_unt" ]; then
        _st="EXPIRED"; _exp=$((_exp+1))
      else
        _st="active"; _act=$((_act+1))
        # 14 days is enough notice to re-argue an exception before the next
        # update run is blocked by it.
        _warn=$(date -u -d "+14 days" +%Y-%m-%d 2>/dev/null || echo "$_today")
        [ "$_warn" \> "$_unt" ] && { _st="EXPIRING SOON"; _soon=$((_soon+1)); }
      fi
      echo ""
      printf '  [%s]  accepted %s by %s\n' "$_st" "${_when%T*}" "${_who:-unknown}"
      printf '    image digest : %s\n' "${_dig:-?}"
      printf '    expires      : %s\n' "${_unt:-?}"
      printf '    CVEs         : %s\n' "${_cve:-not recorded}"
      printf '    reason       : %s\n' "${_rsn:-none given}"
    done < "$_log"
    echo ""
    echo "  ────────────────────────────────────────────────────────"
    printf '  %s active, %s expiring within 14 days, %s expired\n' "$_act" "$_soon" "$_exp"
    echo ""
    echo "  An EXPIRED entry does not block anything by itself — it means the"
    echo "  next update touching that image will ask for the decision again."
    echo "  That is the intended behaviour: an exception nobody re-argues"
    echo "  should lapse rather than quietly become permanent policy."
    if [ "$_soon" -gt 0 ]; then
      echo ""
      echo "  ${_soon} exception(s) lapse within 14 days. Re-review them now,"
      echo "  rather than at the moment an update is blocked." >&2
    fi ;;

  exceptions-check)
    # Cron entry point. Silent unless something needs attention, so a weekly
    # job does not train the operator to ignore it.
    _log=/var/log/wasp-vuln-exceptions.log
    [ -s "$_log" ] || exit 0
    _today=$(date -u +%Y-%m-%d)
    _warn=$(date -u -d "+14 days" +%Y-%m-%d 2>/dev/null || echo "$_today")
    _due=$(mktemp)
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      _unt=$(printf '%s' "$line" | sed -n 's/.*until=\([^|]*\).*/\1/p' | sed 's/ *$//')
      [ -n "$_unt" ] || continue
      [ "$_today" \> "$_unt" ] && continue          # already lapsed; not news
      if [ "$_warn" \> "$_unt" ]; then
        printf '  expires %s : %s\n' "$_unt" \
          "$(printf '%s' "$line" | sed -n 's/.*reason=//p')" >> "$_due"
      fi
    done < "$_log"
    if [ -s "$_due" ]; then
      _n=$(grep -c . "$_due") || _n=0
      logger -t wasp-exceptions "${_n} vulnerability exception(s) lapse within 14 days"
      if [ -x /usr/local/bin/wp-notify.sh ]; then
        _b=$(mktemp)
        {
          printf 'Vulnerability exceptions on %s lapse within 14 days.\n\n' "$(hostname)"
          cat "$_due"
          printf '\nWhen one lapses, the next update touching that image asks for the\n'
          printf 'decision again. Re-review now rather than at the moment an update\n'
          printf 'is blocked.\n\n'
          printf 'Full detail:  wp-hardening.sh exceptions\n'
        } > "$_b"
        /usr/local/bin/wp-notify.sh wasp-vuln-exception \
          "${_n} vulnerability exception(s) expiring on $(hostname)" "$_b"
        rm -f "$_b"
      fi
    fi
    rm -f "$_due" ;;

  tls|tls-check)
    # TLS terminates at the reverse proxy, so this VM never sees its own
    # certificate — an openssl check against 127.0.0.1 would test nothing.
    # It has to go out to the public endpoint, which means it is also
    # verifying that the domain resolves and the proxy is answering.
    #
    # Worth having because a broken renewal is otherwise invisible until a
    # visitor's browser warns them, and by then it has been broken for days.
    . /etc/wp-install/vars.sh 2>/dev/null || true
    _d="${2:-${WP_DOMAIN:-}}"
    [ -n "$_d" ] || { echo "Usage: wp-hardening.sh tls <domain>" >&2; exit 1; }
    command -v openssl >/dev/null 2>&1 || { echo "✗ openssl not installed: apk add openssl" >&2; exit 1; }

    _end=$(echo | openssl s_client -servername "$_d" -connect "${_d}:443" 2>/dev/null \
           | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    if [ -z "$_end" ]; then
      _quiet="${3:-}"
      [ "$_quiet" = "--quiet" ] || {
        echo ""
        echo "✗ Could not retrieve a certificate for ${_d}."
        echo "  Either the name does not resolve, the proxy is not answering on"
        echo "  443, or egress to that host is blocked from this VM."
        echo "    wp-hardening.sh egress-list"
      }
      exit 1
    fi
    _es=$(date -u -d "$_end" +%s 2>/dev/null) || _es=""
    _days=$(( ( ${_es:-0} - $(date -u +%s) ) / 86400 ))
    _iss=$(echo | openssl s_client -servername "$_d" -connect "${_d}:443" 2>/dev/null \
           | openssl x509 -noout -issuer 2>/dev/null | sed 's/.*CN *= *//')

    if [ "${1}" = "tls-check" ]; then
      # Cron path: silent unless it actually matters. Let's Encrypt renews at
      # 30 days, so warning at 30 would fire on every healthy certificate.
      [ "$_days" -le 14 ] || exit 0
      logger -t wasp-tls "certificate for ${_d} expires in ${_days} day(s)"
      [ -x /usr/local/bin/wp-notify.sh ] || exit 0
      _b=$(mktemp)
      {
        printf 'The TLS certificate for %s expires in %s day(s).\n\n' "$_d" "$_days"
        printf '  Expires : %s\n  Issuer  : %s\n\n' "$_end" "${_iss:-unknown}"
        printf 'Renewal happens at the reverse proxy, not on this VM. Automatic\n'
        printf 'renewal has had time to run and has not — check the proxy.\n\n'
        printf 'A common cause is an ACME HTTP-01 challenge blocked by a\n'
        printf 'rule denying dotfile paths: /.well-known/ begins with a dot.\n'
        printf 'Confirm it is reachable:\n'
        printf '  curl -sI https://%s/.well-known/acme-challenge/test\n' "$_d"
      } > "$_b"
      NOTIFY_COOLDOWN_HOURS=72 /usr/local/bin/wp-notify.sh wasp-tls \
        "TLS certificate for ${_d} expires in ${_days} days" "$_b"
      rm -f "$_b"
      exit 0
    fi

    echo ""
    echo "TLS — ${_d}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf '  Expires : %s\n' "$_end"
    printf '  Issuer  : %s\n' "${_iss:-unknown}"
    if   [ "$_days" -lt 0 ]  ; then echo "  ✗ EXPIRED ${_days#-} day(s) ago."; exit 2
    elif [ "$_days" -le 7 ]  ; then echo "  ✗ ${_days} day(s) left — renewal has failed."; exit 2
    elif [ "$_days" -le 14 ] ; then echo "  ⚠ ${_days} day(s) left. Let's Encrypt renews at 30, so this is late."; exit 1
    else                            echo "  ✔ ${_days} day(s) remaining."
    fi
    echo ""
    echo "  Renewal is the proxy's job — this VM only observes the result." ;;

  disk)
    # Disk exhaustion is the classic "site stopped working overnight for no
    # apparent reason". MariaDB refuses writes, backups fail, logs stop, and
    # none of it names the disk as the cause. validate-wordpress.sh reports a
    # percentage; this shows what is actually consuming it and what can safely
    # be reclaimed.
    echo ""
    echo "Disk usage"
    echo "━━━━━━━━━━"
    df -h / | sed 's/^/  /'
    _pct=$(df -P / | awk 'NR==2{gsub("%","",$5); print $5}')
    echo ""
    echo "  Largest consumers:"
    for _d in /var/lib/containers /root/wp-db-backups /home/wpuser/wp/logs \
              /var/cache/wp-vulns /var/lib/wp-quarantine /var/log; do
      [ -d "$_d" ] && printf '    %-28s %s\n' "$_d" "$(du -sh "$_d" 2>/dev/null | cut -f1)"
    done
    echo ""
    echo "  Reclaimable:"
    _dang=$(podman images -f dangling=true -q 2>/dev/null | grep -c .) || _dang=0
    printf '    %-28s %s image(s)\n' "unreferenced container images" "$_dang"
    [ "${_dang:-0}" -gt 0 ] && printf '      doas podman image prune -f --filter dangling=true\n'
    _oldq=$(find /var/lib/wp-quarantine -maxdepth 1 -type f -mtime +30 2>/dev/null | grep -c .) || _oldq=0
    [ "${_oldq:-0}" -gt 0 ] && printf '    %-28s %s file(s)  →  wp-malware-scan.sh purge\n' "quarantine over 30 days" "$_oldq"
    echo ""
    if [ "${_pct:-0}" -ge 90 ]; then
      echo "  ✗ CRITICAL at ${_pct}%. MariaDB will refuse writes before the disk is"
      echo "    actually full, and the resulting errors will not mention disk."
      exit 2
    elif [ "${_pct:-0}" -ge 75 ]; then
      echo "  ⚠ ${_pct}% used. Act now rather than at 95% — a full disk during a"
      echo "    backup leaves you with neither space nor a backup."
      exit 1
    fi
    echo "  ${_pct}% used — healthy." ;;

  disk-check)
    # Cron entry point. Silent below the threshold; emails once above it.
    _pct=$(df -P / | awk 'NR==2{gsub("%","",$5); print $5}')
    [ "${_pct:-0}" -ge 80 ] || exit 0
    logger -t wasp-disk "root filesystem at ${_pct}%"
    [ -x /usr/local/bin/wp-notify.sh ] || exit 0
    _b=$(mktemp)
    {
      printf 'Root filesystem on %s is at %s%%.\n\n' "$(hostname)" "$_pct"
      df -h / | sed 's/^/  /'
      printf '\nWhat is using it:\n'
      for _d in /var/lib/containers /root/wp-db-backups /home/wpuser/wp/logs /var/cache/wp-vulns; do
        [ -d "$_d" ] && printf '  %-28s %s\n' "$_d" "$(du -sh "$_d" 2>/dev/null | cut -f1)"
      done
      printf '\nUsually reclaimable:\n'
      printf '  doas podman image prune -f --filter dangling=true   # old images after updates\n'
      printf '  wp-malware-scan.sh purge                       # quarantined samples\n'
      printf '  wp-hardening.sh disk                           # full breakdown\n\n'
      printf 'Acting at 80%% rather than 95%% matters: MariaDB refuses writes before\n'
      printf 'the disk is full, and a backup that runs out of space leaves you with\n'
      printf 'neither the space nor the backup.\n'
    } > "$_b"
    NOTIFY_COOLDOWN_HOURS=48 /usr/local/bin/wp-notify.sh wasp-disk \
      "Disk at ${_pct}% on $(hostname)" "$_b"
    rm -f "$_b" ;;

  lynis)
    # Reads the last audit rather than running one — a full audit takes
    # minutes and already runs weekly from cron. `lynis run` forces a fresh
    # one when that matters.
    _rep=/var/log/lynis-report.dat
    if [ "${2:-}" = "run" ]; then
      command -v lynis >/dev/null 2>&1 || { echo "✗ lynis is not installed" >&2; exit 1; }
      echo "Running an audit (this takes a few minutes)…"
      lynis audit system --quiet --logfile /var/log/lynis.log --report-file "$_rep" >/dev/null 2>&1
    fi
    [ -r "$_rep" ] || { echo "No Lynis report yet. Run: wp-hardening.sh lynis run" >&2; exit 1; }
    echo ""
    echo "Lynis audit"
    echo "━━━━━━━━━━━"
    printf '  Report age : %s day(s)\n' "$(( ( $(date +%s) - $(stat -c %Y "$_rep") ) / 86400 ))"
    _idx=$(sed -n 's/^hardening_index=//p' "$_rep" | head -1)
    printf '  Hardening index : %s / 100\n' "${_idx:-unknown}"
    echo ""
    echo "  The index is a comparison against a general-purpose server profile."
    echo "  It is a trend to watch, not a target to chase: several controls that"
    echo "  matter here — digest pinning, the internal database network, the"
    echo "  signed manifest — are invisible to it, and some of what it wants"
    echo "  would be actively wrong on a single-purpose container host."
    echo ""
    _w=$(sed -n 's/^warning\[\]=//p' "$_rep" | head -12)
    if [ -n "$_w" ]; then
      echo "  Warnings:"
      printf '%s\n' "$_w" | sed 's/^/    /'
    else
      echo "  No warnings recorded."
    fi
    echo ""
    _s=$(sed -n 's/^suggestion\[\]=//p' "$_rep" | grep -c .) || _s=0
    printf '  %s suggestion(s). Full detail: %s\n' "$_s" "$_rep"
    echo "  Exclusions and why: /etc/lynis/custom.prf" ;;

  cti-lookup)
    # Machine-readable single lookup, for other tools. Same cache and same
    # budget guard as the interactive command -- a second code path with its
    # own accounting is how a quota gets spent twice over.
    # Prints: reputation|noise|as_name|country|behaviours|false_positive
    _ip="${2:-}"
    CTI_CONF=/etc/wp-install/cti.conf
    CTI_CACHE=/var/cache/wp-cti
    [ -r "$CTI_CONF" ] && . "$CTI_CONF"
    CTI_MONTHLY_BUDGET="${CTI_MONTHLY_BUDGET:-120}"
    [ -n "${CTI_API_KEY:-}" ] || exit 2
    command -v jq >/dev/null 2>&1 || exit 2
    printf '%s' "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || exit 2
    mkdir -p "$CTI_CACHE" 2>/dev/null; chmod 700 "$CTI_CACHE" 2>/dev/null

    _cf="${CTI_CACHE}/${_ip}.json"
    _need=1
    if [ -f "$_cf" ]; then
      _age=$(( ( $(date +%s) - $(stat -c %Y "$_cf") ) / 86400 ))
      [ "$_age" -lt 7 ] && _need=0
    fi
    if [ "$_need" = 1 ]; then
      _m=$(date -u +%Y-%m); _uf="${CTI_CACHE}/.used-${_m}"
      _used=$(cat "$_uf" 2>/dev/null || echo 0)
      [ "${_used:-0}" -ge "$CTI_MONTHLY_BUDGET" ] && exit 3   # budget spent
      _t=$(mktemp)
      _c=$(curl -sS --max-time 15 -w '%{http_code}' -H "x-api-key: ${CTI_API_KEY}" \
             -o "$_t" "https://cti.api.crowdsec.net/v2/smoke/${_ip}" 2>/dev/null || echo 000)
      echo $(( _used + 1 )) > "$_uf"
      case "$_c" in
        200) mv -f "$_t" "$_cf"; chmod 600 "$_cf" ;;
        404) rm -f "$_t"; printf 'unknown|-|-|-|not seen in CrowdSec network|no\n'; exit 0 ;;
        *)   rm -f "$_t"; exit 4 ;;
      esac
    fi
    jq -r '[
      (.reputation // "unknown"),
      ((.background_noise_score // "?") | tostring),
      (.as_name // "?"),
      (.location.country // "?"),
      ((.behaviors // []) | map(.label) | join(", ") | if . == "" then "none recorded" else . end),
      (if ((.false_positives // []) | length) > 0 then "YES" else "no" end)
    ] | join("|")' "$_cf" 2>/dev/null || exit 4 ;;

  cti-watch)
    # Cron entry point. Enriches NEW login-guard bans only, and only when the
    # operator opted in -- because at the free tier's 40/month this would
    # otherwise consume the entire budget on commodity scanners within a day.
    #
    # Login-guard bans specifically, not every CrowdSec decision: an address
    # that reached the login form and failed repeatedly is targeting THIS
    # site. An http-probing ban is background noise hitting everyone.
    CTI_CONF=/etc/wp-install/cti.conf
    CTI_CACHE=/var/cache/wp-cti
    [ -r "$CTI_CONF" ] && . "$CTI_CONF"
    [ "${CTI_ENRICH_BANS:-0}" = "1" ] || exit 0
    [ -n "${CTI_API_KEY:-}" ] || exit 0
    mkdir -p "$CTI_CACHE"; _seen="${CTI_CACHE}/.notified"
    touch "$_seen"; chmod 600 "$_seen"

    podman exec crowdsec cscli decisions list -o raw 2>/dev/null | tail -n +2 | \
    while IFS=, read -r _id _src _val _scen _rest; do
      case "$_val" in Ip:*) _ip="${_val#Ip:}" ;; *) continue ;; esac
      case "$_scen" in *wpvm-login*) : ;; *) continue ;; esac
      grep -qxF "$_ip" "$_seen" 2>/dev/null && continue
      printf '%s\n' "$_ip" >> "$_seen"

      _cti=$("$0" cti-lookup "$_ip" 2>/dev/null) || _cti=""
      _b=$(mktemp)
      {
        printf 'An address was banned for repeated failed logins.\n\n'
        printf '  IP       : %s\n' "$_ip"
        printf '  Scenario : %s\n' "$_scen"
        printf '  Host     : %s\n\n' "$(hostname)"
        if [ -n "$_cti" ]; then
          printf 'CrowdSec threat intelligence:\n'
          printf '%s' "$_cti" | awk -F'|' '{
            printf "  Reputation : %s\n  Noise      : %s / 10\n  Network    : %s (%s)\n  Behaviours : %s\n  False pos. : %s\n",
              $1,$2,$3,$4,$5,$6 }'
          case "$_cti" in
            *"|YES") printf '\n  ⚠ FLAGGED AS A POSSIBLE FALSE POSITIVE — a crawler, monitor or\n'
                     printf '    CDN. Confirm before treating this as an attack.\n' ;;
          esac
        else
          printf '(No CTI data — no key, quota spent, or lookup failed.)\n'
        fi
        printf '\nWhat it did HERE, which CTI cannot tell you:\n'
        printf '  wp-forensics.sh timeline --hours 48 | grep %s\n' "$_ip"
        printf '  wp-hardening.sh crowdsec-whitelist list\n'
      } > "$_b"
      [ -x /usr/local/bin/wp-notify.sh ] && \
        /usr/local/bin/wp-notify.sh wp-cti-ban "Login brute-force ban: ${_ip}" "$_b"
      rm -f "$_b"
    done
    # Keep the seen-list bounded; a ban expiring and recurring is worth
    # hearing about again eventually.
    tail -500 "$_seen" > "${_seen}.tmp" 2>/dev/null && mv -f "${_seen}.tmp" "$_seen" ;;

  cti)
    # CrowdSec CTI lookup — what is this address known for globally?
    #
    # QUOTA IS THE DESIGN CONSTRAINT. The free Community key allows
    # **40 lookups per MONTH**, and unused quota does not roll over. That is
    # roughly 1.3 per day. Older documentation and blog posts say 50 per day;
    # that figure is out of date and building against it would exhaust a
    # month of quota in an afternoon on a site with normal scanner traffic.
    #
    # So this is deliberately NOT wired into ban notifications by default. A
    # busy WordPress site bans dozens of addresses a day and every one of them
    # is a scanner; spending the entire monthly budget confirming that is a
    # poor trade. It is an operator command, used when an address actually
    # matters — the one in a malware timeline, or a repeat offender that
    # reached the login form.
    #
    # Answers are cached for 7 days. CTI describes weeks of observed
    # behaviour, so a same-week repeat lookup buys nothing and costs quota.
    _ip="${2:-}"
    CTI_CONF=/etc/wp-install/cti.conf
    CTI_CACHE=/var/cache/wp-cti
    [ -r "$CTI_CONF" ] && . "$CTI_CONF"
    CTI_MONTHLY_BUDGET="${CTI_MONTHLY_BUDGET:-120}"
    mkdir -p "$CTI_CACHE" 2>/dev/null || true
    chmod 700 "$CTI_CACHE" 2>/dev/null || true

    case "$_ip" in
      ""|--status)
        echo ""
        echo "CrowdSec CTI"
        echo "━━━━━━━━━━━━"
        if [ -z "${CTI_API_KEY:-}" ]; then
          echo "  Not configured."
          echo ""
          echo "  A free Community key gives 40 lookups per MONTH (not per day —"
          echo "  older docs say otherwise). Enough for investigating addresses"
          echo "  that matter; not enough to enrich routine bans, which is why"
          echo "  nothing here does that automatically."
          echo ""
          echo "  Generate one in the CrowdSec Console under Settings -> CTI API"
          echo "  Keys, then:  wp-hardening.sh cti-key <key>"
          exit 0
        fi
        _m=$(date -u +%Y-%m)
        _used=$(cat "${CTI_CACHE}/.used-${_m}" 2>/dev/null || echo 0)
        printf '  Key        : configured (%s chars)\n' "${#CTI_API_KEY}"
        printf '  This month : %s of %s lookups used\n' "$_used" "$CTI_MONTHLY_BUDGET"
          _cached=$(ls -1 "$CTI_CACHE"/*.json 2>/dev/null | grep -c .) || _cached=0
          printf '  Cached     : %s address(es), 7-day life\n' "$_cached"
        echo ""
        echo "  Look one up:  wp-hardening.sh cti <ip>"
        exit 0 ;;
    esac

    printf '%s' "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
      || { echo "✗ '${_ip}' is not an IPv4 address" >&2; exit 1; }
    [ -n "${CTI_API_KEY:-}" ] || { echo "✗ No CTI key. wp-hardening.sh cti-key <key>" >&2; exit 1; }
    command -v jq >/dev/null 2>&1 || { echo "✗ jq required: apk add jq" >&2; exit 1; }

    _cf="${CTI_CACHE}/${_ip}.json"
    _fresh=0
    if [ -f "$_cf" ]; then
      _age=$(( ( $(date +%s) - $(stat -c %Y "$_cf") ) / 86400 ))
      [ "$_age" -lt 7 ] && _fresh=1
    fi

    if [ "$_fresh" = 0 ]; then
      _m=$(date -u +%Y-%m)
      _uf="${CTI_CACHE}/.used-${_m}"
      _used=$(cat "$_uf" 2>/dev/null || echo 0)
      # Refuse rather than exhaust. Discovering the budget is gone at the
      # moment an address actually matters is the failure worth avoiding.
      if [ "${_used:-0}" -ge "$CTI_MONTHLY_BUDGET" ]; then
        echo "✗ Monthly CTI budget spent (${_used}/${CTI_MONTHLY_BUDGET})." >&2
        echo "  It resets on the 1st and does not roll over." >&2
        [ -f "$_cf" ] && echo "  A cached answer from $(date -u -d "@$(stat -c %Y "$_cf")" '+%Y-%m-%d') exists — showing it." >&2
        [ -f "$_cf" ] || exit 1
      else
        _tmp=$(mktemp)
        _code=$(curl -sS --max-time 20 -w '%{http_code}' \
                  -H "x-api-key: ${CTI_API_KEY}" \
                  -o "$_tmp" "https://cti.api.crowdsec.net/v2/smoke/${_ip}" 2>/dev/null || echo 000)
        case "$_code" in
          200) mv -f "$_tmp" "$_cf"; chmod 600 "$_cf"
               echo $(( _used + 1 )) > "$_uf"
               _used=$(( _used + 1 )) ;;
          404) rm -f "$_tmp"
               echo "  ${_ip} is not in CrowdSec's database."
               echo "  That is meaningful: it has not been seen attacking anyone in"
               echo "  their network. Not proof of innocence, but it does mean this"
               echo "  is not a known mass-scanner."
               echo $(( _used + 1 )) > "$_uf"
               exit 0 ;;
          429) rm -f "$_tmp"; echo "✗ CrowdSec rate-limited the request (429). Quota may be exhausted." >&2; exit 1 ;;
          403|401) rm -f "$_tmp"; echo "✗ Key rejected (HTTP ${_code}). Check it in the Console." >&2; exit 1 ;;
          *)   rm -f "$_tmp"; echo "✗ Lookup failed (HTTP ${_code})." >&2; exit 1 ;;
        esac
      fi
    fi

    [ -s "$_cf" ] || { echo "✗ No data for ${_ip}" >&2; exit 1; }
    echo ""
    echo "CTI — ${_ip}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    [ "$_fresh" = 1 ] && echo "  (cached $(date -u -d "@$(stat -c %Y "$_cf")" '+%Y-%m-%d') — no quota used)"
    jq -r '
      "  Reputation   : \(.reputation // "unknown")",
      "  Confidence   : \(.confidence // "unknown")",
      "  Network      : \(.as_name // "?") (\(.location.country // "?"))",
      "  Range        : \(.ip_range // "?")  range score \(.ip_range_score // "?")",
      "  Noise score  : \(.background_noise_score // "?") / 10   (10 = hits everyone constantly)",
      "  First seen   : \(.history.first_seen // "?")",
      "  Last seen    : \(.history.last_seen // "?")",
      "",
      "  Behaviours   : \((.behaviors // []) | map(.label) | join(", ") | if . == "" then "none recorded" else . end)",
      "  Top attacks  : \((.attack_details // []) | map(.name) | .[0:6] | join(", ") | if . == "" then "none recorded" else . end)",
      "  Targets      : \((.target_countries // {}) | to_entries | sort_by(-.value) | .[0:5] | map("\(.key) \(.value)%") | join(", "))",
      "  False pos.   : \((.false_positives // []) | join(", ") | if . == "" then "none flagged" else . end)"
    ' "$_cf" 2>/dev/null || { echo "  Could not parse the response."; exit 1; }
    echo ""
    _fp=$(jq -r '(.false_positives // []) | length' "$_cf" 2>/dev/null || echo 0)
    if [ "${_fp:-0}" -gt 0 ]; then
      echo "  ⚠ Flagged as a possible FALSE POSITIVE — a search engine crawler,"
      echo "    monitoring service or CDN. Check before banning it permanently."
    fi
    echo "  This describes what the address does GLOBALLY, across CrowdSec's"
    echo "  network. It does not tell you what it did to this site — for that:"
    echo "    wp-forensics.sh timeline --hours 48 | grep ${_ip}" ;;

  cti-key)
    _k="${2:-}"
    [ -n "$_k" ] || { echo "Usage: wp-hardening.sh cti-key <key>" >&2; exit 1; }
    mkdir -p /etc/wp-install
    { printf 'CTI_API_KEY=%s\n' "$_k"
      printf 'CTI_MONTHLY_BUDGET=%s\n' "${3:-40}"; } > /etc/wp-install/cti.conf
    chmod 600 /etc/wp-install/cti.conf
    echo "✔ CTI key stored (0600, root-only)"
    echo "  Budget set to ${3:-40} lookups/month — the Community free tier."
    echo "  If you have a paid key, pass the real figure:"
    echo "    wp-hardening.sh cti-key <key> 5000"
    echo ""
    echo "  Test it:  wp-hardening.sh cti 45.148.10.62" ;;

  web-list|web-allow|web-deny)
    # WEB_CIDR restricts who may open a TCP connection to 80/443 at all.
    # It is deliberately separate from the wp-admin rule, which decides who
    # may reach the admin PATHS once connected.
    #
    # The useful configuration is both: the proxy, so external visitors are
    # funnelled through it, PLUS the operator's own addresses, so admin work
    # can go direct to the VM. Direct access has no proxy in the path, so it
    # does not depend on mod_remoteip substituting anything — which is the
    # fragile part, and the one that produces a 403 when it breaks.
    . /etc/wp-install/vars.sh 2>/dev/null || true
    _act="${1}"; _ip="${2:-}"
    _nft=/etc/nftables.nft

    case "$_act" in
      web-list)
        echo ""
        echo "Who may connect to ports 80/443"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if [ -z "${WEB_CIDR:-}" ]; then
          echo "  ANY source. External visitors can reach this VM directly,"
          echo "  bypassing the proxy and whatever it enforces."
        else
          printf '%s' "$WEB_CIDR" | tr ',' '\n' | sed 's/^/  • /'
          echo ""
          printf '  Proxy configured : %s\n' "${PROXY_IP:-none}"
          case ",${WEB_CIDR}," in
            *",${PROXY_IP:-__none__},"*) echo "  ✔ The proxy is allowed — normal visitors can reach the site." ;;
            *) echo "  ✗ The proxy (${PROXY_IP:-?}) is NOT in this list. Visitors cannot" ;;
          esac
          echo ""
          echo "  wp-admin additionally requires the CLIENT address to match:"
          printf '    %s %s\n' "${ADMIN_CIDR:-none}" "${ALLOWED_ADMIN_IP:-}"
          echo "    Reaching the VM directly from one of those is the reliable"
          echo "    way in: no proxy means no X-Forwarded-For to get wrong."
        fi
        echo ""
        echo "  Live rule:"
        nft list ruleset 2>/dev/null | grep -E "tcp dport \{ 80, 443 \}" | sed 's/^/    /'
        echo ""
        echo "  Add:  wp-hardening.sh web-allow <ip|cidr>"
        echo "  Drop: wp-hardening.sh web-deny  <ip|cidr>" ;;

      web-allow|web-deny)
        [ -n "$_ip" ] || { echo "Usage: wp-hardening.sh ${_act} <ip|cidr>" >&2; exit 1; }
        printf '%s' "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' \
          || { echo "✗ '${_ip}' is not a valid IPv4 address or CIDR." >&2; exit 1; }
        [ -w "$_nft" ] || { echo "✗ Cannot write ${_nft}" >&2; exit 1; }

        _new="$WEB_CIDR"
        if [ "$_act" = "web-allow" ]; then
          case ",${WEB_CIDR}," in
            *",${_ip},"*) echo "Already allowed: ${_ip}"; exit 0 ;;
          esac
          _new="${WEB_CIDR:+${WEB_CIDR},}${_ip}"
        else
          # Removing the proxy would take the site offline for every visitor.
          if [ "$_ip" = "${PROXY_IP:-}" ]; then
            echo "✗ That is the reverse proxy address. Removing it stops every" >&2
            echo "  visitor reaching the site, not just you." >&2
            exit 1
          fi
          _new=$(printf '%s' "$WEB_CIDR" | tr ',' '\n' | grep -vxF "$_ip" | paste -sd, -)
        fi

        # mktemp, not a fixed /tmp name: this runs as root and a predictable
        # path is one a local user can pre-create as a symlink.
        _NFTERR=$(mktemp) || exit 1
        cp "$_nft" "${_nft}.bak-$(date -u +%Y%m%d%H%M%S)"
        # Both places: the input rule and the forward rule. Editing only one
        # leaves the two disagreeing, and the forward rule is the one that
        # actually decides for a published container port.
        sed -i "s|ip saddr { ${WEB_CIDR} } tcp dport { 80, 443 }|ip saddr { ${_new} } tcp dport { 80, 443 }|g" "$_nft"
        sed -i "s|ip saddr != { ${WEB_CIDR}, 127.0.0.0/8, 10.89.0.0/16 }|ip saddr != { ${_new}, 127.0.0.0/8, 10.89.0.0/16 }|g" "$_nft"
        sed -i "s|^WEB_CIDR=.*|WEB_CIDR='${_new}'|" /etc/wp-install/vars.sh 2>/dev/null || true

        if nft -c -f "$_nft" 2>"$_NFTERR"; then
          nft -f "$_nft" && echo "✔ Web access now: ${_new}"
          echo "  Rule reloaded. Verify: wp-hardening.sh web-list"
        else
          echo "✗ The edited ruleset does NOT parse — nothing was applied." >&2
          sed 's/^/    /' "$_NFTERR" >&2
          cp "$(ls -1t ${_nft}.bak-* | head -1)" "$_nft"
          echo "  Restored the previous ruleset." >&2
          exit 1
        fi
        rm -f "$_NFTERR" ;;
    esac ;;

  admin-rule)
    # Switch the wp-admin/wp-login authorization rule between two forms,
    # live, without reinstalling. Exists because the fail-closed form uses
    # `Require not ip`, and if that turns out to be what returns 503 on this
    # Apache build there needs to be a way back that does not involve
    # rebuilding the VM.
    _conf=/home/wpuser/wp/apache-conf/wp-security.conf
    . /etc/wp-install/vars.sh 2>/dev/null || true
    _mode="${2:-show}"
    [ -r "$_conf" ] || { echo "✗ ${_conf} not found" >&2; exit 1; }

    case "$_mode" in
      show|"")
        echo ""
        echo "wp-admin authorization rule"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        if grep -q "Require not ip" "$_conf"; then
          echo "  Mode: STRICT (fail-closed)"
          echo "    Denies the proxy's own address, so a mod_remoteip failure"
          echo "    produces 403 instead of allowing everyone."
        else
          echo "  Mode: SIMPLE (allow-list only)"
          echo "    ⚠ If ${PROXY_IP:-the proxy} is inside ${ADMIN_CIDR:-the admin range},"
          echo "      a mod_remoteip failure would ALLOW every request rather than"
          echo "      deny them — silently."
        fi
        echo ""
        sed -n '/<Files "wp-login.php">/,/<\/Files>/p' "$_conf" | sed 's/^/    /'
        echo ""
        echo "  Switch:  wp-hardening.sh admin-rule strict|simple"
        echo "  Then:    podman restart wordpress" ;;

      simple)
        # Strip the RequireAll wrapper, leaving the positive allow-list.
        cp "$_conf" "${_conf}.bak-$(date -u +%Y%m%d%H%M%S)"
        awk '
          /<RequireAll>/     { inall=1; next }
          /<\/RequireAll>/   { inall=0; next }
          /Require not ip/   { next }
          /<RequireAny>/     { if (inall) next }
          /<\/RequireAny>/   { if (inall) next }
          { print }
        ' "$_conf" > "${_conf}.new" && mv -f "${_conf}.new" "$_conf"
        echo "✔ Switched to SIMPLE. Backup kept alongside the original."
        echo "  ⚠ This restores the fail-OPEN behaviour: if mod_remoteip stops"
        echo "    substituting the client address and your proxy sits inside the"
        echo "    admin range, everyone is allowed. Use it to isolate a 503, not"
        echo "    as a resting state."
        echo "  doas podman restart wordpress" ;;

      strict)
        grep -q "Require not ip" "$_conf" && { echo "Already strict."; exit 0; }
        [ -n "${PROXY_IP:-}" ] || { echo "✗ No PROXY_IP configured; strict mode has nothing to deny." >&2; exit 1; }
        cp "$_conf" "${_conf}.bak-$(date -u +%Y%m%d%H%M%S)"
        awk -v proxy="$PROXY_IP" '
          /Require ip/ && !done {
            print "    <RequireAll>"
            print "        Require not ip " proxy
            print "        <RequireAny>"
            buf = 1
          }
          /Require ip/ { print "    " $0; next }
          buf && !/Require ip/ {
            print "        </RequireAny>"
            print "    </RequireAll>"
            buf = 0; done = 1
          }
          { print }
        ' "$_conf" > "${_conf}.new" && mv -f "${_conf}.new" "$_conf"
        echo "✔ Switched to STRICT. Backup kept alongside the original."
        echo "  doas podman exec wordpress apache2ctl configtest   # check BEFORE restarting"
        echo "  doas podman restart wordpress" ;;

      *) echo "Usage: wp-hardening.sh admin-rule [show|strict|simple]" >&2; exit 1 ;;
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
    # The check that matters most, done directly rather than inferred: does
    # the live config actually deny the proxy's own address?
    echo ""
    if grep -q "Require not ip ${PROXY_IP}" /home/wpuser/wp/apache-conf/wp-security.conf 2>/dev/null; then
      echo "  ✔ wp-admin rules deny the proxy's own address, so a mod_remoteip"
      echo "    failure produces 403 rather than allowing everyone."
    else
      echo "  ✗ wp-admin rules do NOT deny ${PROXY_IP}."
      if printf '%s' "${ADMIN_CIDR:-}" | grep -q '/'; then
        echo "    Your admin range is ${ADMIN_CIDR}. If the proxy is inside it,"
        echo "    then any mod_remoteip failure ALLOWS EVERY REQUEST rather than"
        echo "    denying them — and nothing looks wrong."
        echo "    Test it: browse to the login page from a phone on mobile data."
        echo "    You should get 403. If you get the login form, this is live."
      fi
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
        # Offer to install it rather than just reporting its absence. A
        # diagnostic that stops to tell you to go and install a diagnostic is
        # a poor trade for ~100 KB.
        echo "  ⚠  mmdblookup is not installed, so the address cannot be resolved."
        printf "     Install it now (~100 KB, does not touch the containers)? [Y/n] : "
        read -r _mi
        case "${_mi:-y}" in
          n|N) echo "     Skipped.  doas apk add libmaxminddb" ;;
          *)
            if apk add --no-cache libmaxminddb >/dev/null 2>&1; then
              echo "     ✔ Installed — re-run: wp-hardening.sh geoip-test ${_ip}"
            else
              echo "     ✗ Could not install. Try by hand: apk add libmaxminddb"
            fi ;;
        esac
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
