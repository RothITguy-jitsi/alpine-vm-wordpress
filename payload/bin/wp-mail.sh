#!/bin/sh
# =============================================================================
# wp-mail.sh — outbound email status, testing, and (re)configuration
# =============================================================================
# WordPress mail fails silently by default on this VM: the official container
# has no sendmail binary, so PHP's mail() has nothing to hand a message to,
# and wp_mail() returns without a visible error. This tool exists because
# "did that actually send?" is otherwise unanswerable without reading logs.
#
#   wp-mail.sh status              what is configured (password redacted)
#   wp-mail.sh test you@example.com  send a real message and report the result
#   wp-mail.sh setup               (re)configure the relay interactively
#   wp-mail.sh log                 recent mail failures from the PHP error log
#   wp-mail.sh doctor              config + mount + mu-plugin + DNS checks
# =============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or install doas and run as a wheel user)" >&2
  exit 1
fi
[ -r /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

SECRETS_DIR="/home/wpuser/wp/secrets"
SMTP_FILE="${SECRETS_DIR}/smtp.php"
MU_PLUGIN="/home/wpuser/wp/html/wp-content/mu-plugins/01-wpvm-smtp.php"
WP_LOG_DIR="/home/wpuser/wp/logs"
WPCLI_IMAGE="${WPCLI_IMAGE:-docker.io/library/wordpress:cli}"

_wp() {
  if ! podman ps --filter 'name=^wordpress$' --filter status=running --format '{{.Names}}' \
       | grep -qx wordpress; then
    echo "✗  The 'wordpress' container is not running: rc-service wp-container start" >&2
    exit 1
  fi
  # shellcheck disable=SC2086 -- WPCLI_ENV is a deliberate word-split list
  podman run --rm --network "container:wordpress" --user 33:33 \
    ${WPCLI_ENV} \
    -v /home/wpuser/wp/html:/var/www/html \
    -v "${SECRETS_DIR}:/var/www/private:ro" \
    "$WPCLI_IMAGE" "$@"
}

# Read one value out of the generated PHP config without executing it —
# a plain grep/sed, so `status` works even if the file is malformed (which
# is exactly when you most want to look at it).
_cfg() {
  [ -r "$SMTP_FILE" ] || return 1
  sed -n "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'\{0,1\}\([^',]*\)'\{0,1\},.*/\1/p" "$SMTP_FILE" | head -1
}

_configured() { [ -r "$SMTP_FILE" ] && [ -n "$(_cfg host)" ]; }

show_status() {
  echo ""
  echo "Outbound email status"
  echo "━━━━━━━━━━━━━━━━━━━━━"
  if ! _configured; then
    echo "  ✗  NOT CONFIGURED — WordPress cannot send mail."
    echo ""
    echo "     Password resets, new-user notifications, comment alerts and"
    echo "     WooCommerce receipts are all failing silently right now."
    echo "     Configure with:  wp-mail.sh setup"
    return
  fi
  printf "  %-14s %s\n" "Relay:"     "$(_cfg host):$(_cfg port)"
  printf "  %-14s %s\n" "Encryption:" "$(_cfg encryption)"
  printf "  %-14s %s\n" "Username:"  "$(_cfg user)"
  printf "  %-14s %s\n" "Password:"  "(set — redacted)"
  printf "  %-14s %s\n" "From:"      "$(_cfg from) <$(_cfg from_name)>"
  echo ""
  # Permissions are part of the status, not a separate audit: a
  # world-readable credentials file is the failure worth catching early.
  _perm=$(stat -c '%a %U:%G' "$SMTP_FILE" 2>/dev/null || echo "?")
  case "$_perm" in
    "400 "*) printf "  %-14s %s\n" "File mode:" "$_perm  ✔" ;;
    *)       printf "  %-14s %s\n" "File mode:" "$_perm  ⚠ expected 400, owned by uid 33" ;;
  esac
  [ -r "$MU_PLUGIN" ] \
    && printf "  %-14s %s\n" "mu-plugin:" "present ✔" \
    || printf "  %-14s %s\n" "mu-plugin:" "MISSING ⚠ — mail will fall back to PHP mail() and fail"
  echo ""
  echo "  Verify delivery end-to-end:  wp-mail.sh test you@example.com"
}

do_test() {
  _to="$1"
  [ -n "$_to" ] || { echo "Usage: wp-mail.sh test <recipient@example.com>" >&2; exit 1; }
  # Reject anything that is not plausibly an address before it reaches a
  # shell word-split list or the container environment.
  case "$_to" in
    *[!A-Za-z0-9._%+@-]*|*@*@*|@*|*@) 
      echo "✗  '${_to}' does not look like an email address." >&2; exit 1 ;;
    *@*.*) : ;;
    *) echo "✗  '${_to}' does not look like an email address." >&2; exit 1 ;;
  esac
  _configured || { echo "✗  No relay configured — run: wp-mail.sh setup" >&2; exit 1; }
  echo "Sending a test message to ${_to} via $(_cfg host):$(_cfg port)…"
  # wp_mail()'s own return value is the ground truth — it is what every
  # plugin and core feature calls. Testing the relay with something else
  # (swaks, openssl s_client) would prove the relay works while saying
  # nothing about whether WordPress can actually use it, which is the
  # question being asked.
  # BUG FIX (found on a live VM): this passed the recipient as a second
  # positional argument to `wp eval`, which accepts exactly one (the code) and
  # has no $argv passthrough -- that is `wp eval-file`. wp-cli rejected the
  # call outright with "Too many positional arguments", so the send never even
  # reached the relay, and the failure looked like a mail problem when the
  # relay was fine. Passed through the environment instead: no quoting to get
  # wrong, and the address never becomes part of the PHP source, so an odd
  # character in it cannot alter the code being evaluated.
  WPCLI_ENV="-e WPMAIL_TO=${_to}"
  _out=$(_wp eval '
    $to = getenv("WPMAIL_TO");
    $ok = wp_mail($to, "wp-mail.sh test message",
        "If you are reading this, WordPress on this VM can send mail.\n\n" .
        "Relay, credentials, TLS, and the SMTP mu-plugin are all working.\n" .
        "Sent: " . gmdate("c") . " UTC\n");
    echo $ok ? "SENT" : "FAILED";
  ' 2>&1) || true
  WPCLI_ENV=""
  case "$_out" in
    *SENT*)
      echo "✔  wp_mail() reported success — check ${_to} (including spam)."
      echo "   If it does not arrive, the relay accepted it but something"
      echo "   downstream dropped it: check SPF/DKIM alignment for $(_cfg from)"
      echo "   and your relay's own outbound log." ;;
    *)
      echo "✗  Send failed. Output:" >&2
      printf '%s\n' "$_out" >&2
      echo "" >&2
      echo "   Next: wp-mail.sh doctor   (checks DNS, port reachability, config)" >&2
      exit 1 ;;
  esac
}

do_setup() {
  echo ""
  echo "Configure the outbound SMTP relay"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "Use a DEDICATED mailbox or app password for this site — it is stored"
  echo "on this VM, and if the site is compromised you want to revoke exactly"
  echo "one credential without disturbing anything else that sends mail."
  echo ""
  printf "  SMTP server hostname : "; read -r _h
  [ -n "$_h" ] || { echo "Hostname is required." >&2; exit 1; }
  printf "  Port [587] : "; read -r _p; _p="${_p:-587}"
  case "$_p" in 465) _enc="ssl" ;; *) _enc="tls" ;; esac
  printf "  Username (full mailbox address) : "; read -r _u
  printf "  Password / app password : "
  stty -echo 2>/dev/null; read -r _pw; stty echo 2>/dev/null; echo
  [ -n "$_pw" ] || { echo "Password is required." >&2; exit 1; }
  printf "  From address [%s] : " "$_u"; read -r _f; _f="${_f:-$_u}"
  printf "  From name [WordPress] : "; read -r _fn; _fn="${_fn:-WordPress}"

  _php_q() { printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g"; }
  mkdir -p "$SECRETS_DIR"; chmod 0700 "$SECRETS_DIR"
  install -m 0600 -o 33 -g 33 /dev/null "$SMTP_FILE"
  cat > "$SMTP_FILE" << PHPEOF
<?php
// Written by wp-mail.sh setup. Mounted read-only into the container at
// /var/www/private/smtp.php — outside the web root on purpose.
return array(
    'host'       => '$(_php_q "$_h")',
    'port'       => $(printf '%d' "$_p" 2>/dev/null || echo 587),
    'user'       => '$(_php_q "$_u")',
    'pass'       => '$(_php_q "$_pw")',
    'from'       => '$(_php_q "$_f")',
    'from_name'  => '$(_php_q "$_fn")',
    'encryption' => '$_enc',
    'timeout'    => 10,
);
PHPEOF
  chmod 0400 "$SMTP_FILE"; chown 33:33 "$SMTP_FILE"
  echo "✔  Written to ${SMTP_FILE} (0400, uid 33)"
  # The mount is read-only and already in place, and PHP reads the file per
  # request, so no container restart is needed — but opcache can hold a
  # compiled copy, so nudge it.
  podman exec wordpress sh -c 'command -v php >/dev/null && php -r "opcache_reset();" 2>/dev/null' >/dev/null 2>&1 || true
  echo "   Test it:  wp-mail.sh test you@example.com"
}

show_log() {
  echo "Recent wp_mail failures (from the PHP error log):"
  if [ -d "$WP_LOG_DIR" ]; then
    grep -h "wpvm-smtp" "$WP_LOG_DIR"/*.log 2>/dev/null | tail -25 \
      || echo "  (none — no logged mail failures)"
  else
    echo "  ${WP_LOG_DIR} not found"
  fi
}

do_doctor() {
  echo "Mail diagnostics"
  echo "━━━━━━━━━━━━━━━━"
  _configured && echo "  config      : present" || { echo "  config      : MISSING (wp-mail.sh setup)"; exit 1; }
  _h=$(_cfg host); _p=$(_cfg port)
  echo "  relay       : ${_h}:${_p}"
  [ -r "$MU_PLUGIN" ] && echo "  mu-plugin   : present" || echo "  mu-plugin   : MISSING"
  printf "  mount       : "
  _m=$(podman inspect wordpress --format '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' 2>/dev/null \
       | tr ' ' '\n' | grep '/var/www/private')
  case "$_m" in
    *=false) echo "/var/www/private mounted READ-ONLY (correct)" ;;
    *=true)  echo "/var/www/private mounted WRITABLE — should be :ro" ;;
    *)       echo "/var/www/private NOT MOUNTED — wp_mail cannot read the relay settings" ;;
  esac
  printf "  DNS         : "
  podman exec wordpress sh -c "getent hosts ${_h} >/dev/null 2>&1" \
    && echo "${_h} resolves from the container" \
    || echo "${_h} does NOT resolve from the container ⚠"
  printf "  TCP ${_p}     : "
  # nc is not guaranteed in the container; use PHP, which definitely is.
  podman exec wordpress php -r "
    \$e=null;\$s=@fsockopen('${_h}',${_p},\$n,\$e,5);
    echo \$s?'reachable':'UNREACHABLE ('.\$e.')';
    if(\$s)fclose(\$s);" 2>/dev/null || echo "check failed"
  echo ""
  echo "  Firewall note: outbound submission is rate limited to 30 new"
  echo "  connections/hour (burst 10). Hitting that logs 'nft-smtp-ratelimit'"
  echo "  to the system log — check there if sends start failing in bulk."
}

case "${1:-status}" in
  status) show_status ;;
  test)   do_test "${2:-}" ;;
  setup)  do_setup ;;
  log)    show_log ;;
  doctor) do_doctor ;;
  *)
    echo "Usage: wp-mail.sh [status|setup|doctor|log]"
    echo "       wp-mail.sh test <recipient@example.com>" ;;
esac
