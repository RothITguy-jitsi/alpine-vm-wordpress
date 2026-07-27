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
