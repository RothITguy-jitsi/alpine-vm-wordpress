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
# INI, not PHP. The credentials file is data now, so reading it cannot
# execute anything -- see the note in 01-wpvm-smtp.php for why that changed.
# Legacy smtp.php is still read if present so an existing VM keeps working
# until `setup` migrates it.
SMTP_FILE="${SECRETS_DIR}/smtp.ini"
SMTP_FILE_LEGACY="${SECRETS_DIR}/smtp.php"
_cfg() {
  if [ -r "$SMTP_FILE" ]; then
    if [ "$1" = "pass" ]; then
      sed -n 's/^[[:space:]]*pass_b64[[:space:]]*=[[:space:]]*//p' "$SMTP_FILE" | head -1 | base64 -d 2>/dev/null
    else
      sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$SMTP_FILE" | head -1
    fi
    return 0
  fi
  [ -r "$SMTP_FILE_LEGACY" ] || return 1
  sed -n "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'\{0,1\}\([^',]*\)'\{0,1\},.*/\1/p" "$SMTP_FILE_LEGACY" | head -1
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
  # Numeric, not names. GID 33 is www-data on Debian but has NO name on
  # Alpine, so `stat %G` returns "UNKNOWN" and a name comparison can never
  # match — reporting a permission fault on a perfectly correct file. The
  # container is Debian; this host is Alpine. Numbers mean the same on both.
  _perm=$(stat -c '%a %u:%g' "$SMTP_FILE" 2>/dev/null || echo "?")
  case "$_perm" in
    "440 0:33") printf "  %-14s %s\n" "File mode:" "${_perm} (root:uid33)  ✔" ;;
    *) printf "  %-14s %s\n" "File mode:" "$_perm  ⚠ expected 440 0:33 (root, group 33)" ;;
  esac
  # MU_PLUGIN was never assigned, so this tested `[ -r "" ]` and always
  # printed MISSING — on a VM where the validator confirmed the file present
  # and parsing. A status screen that reports a fault which is not there is
  # worse than one that says nothing: it sends the operator to fix something
  # that works, in the middle of a real problem elsewhere.
  _mu=/home/wpuser/wp/html/wp-content/mu-plugins/01-wpvm-smtp.php
  if [ -r "$_mu" ]; then
    # Present is not the same as loading. Ask PHP whether the hook is live.
    if podman exec wordpress php -l /var/www/html/wp-content/mu-plugins/01-wpvm-smtp.php >/dev/null 2>&1; then
      printf "  %-14s %s\n" "mu-plugin:" "present and parses ✔"
    else
      printf "  %-14s %s\n" "mu-plugin:" "present but has a PHP SYNTAX ERROR ⚠ — mail will fail"
    fi
  else
    printf "  %-14s %s\n" "mu-plugin:" "MISSING ⚠ — mail will fall back to PHP mail() and fail"
  fi
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
  # Check the name resolves before sending. Without this the failure surfaces
  # as PHPMailer's "Could not instantiate mail function", which points at the
  # mail system when the actual problem is a typo in the hostname.
  _h=$(_cfg host)
  if ! podman exec wordpress getent hosts "$_h" >/dev/null 2>&1; then
    echo "✗  ${_h} does not resolve from inside the container." >&2
    echo "   Nothing was sent. This is a DNS or hostname problem, not a mail one." >&2
    echo "   Check the spelling:  wp-mail.sh doctor" >&2
    echo "   Reconfigure:         wp-mail.sh setup" >&2
    exit 1
  fi
  echo "Sending a test message to ${_to} via ${_h}:$(_cfg port)…"
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
    *"Error establishing a database connection"*|*"database connection"*)
      echo "✗  wp-cli could not reach the database, so the message was never sent." >&2
      echo "   This is NOT a mail problem — the relay was never contacted." >&2
      printf '   %s\n' "$_out" >&2
      echo "   Check:  wp-plugins.sh doctor   (same wp-cli path)" >&2
      exit 1 ;;
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

  # INI, not PHP: the config is data, so it can never be executed. Password
  # base64-encoded so quotes/semicolons/'=' cannot interact with INI parsing.
  mkdir -p "$SECRETS_DIR"
  chown root:33 "$SECRETS_DIR" 2>/dev/null || true
  chmod 0750 "$SECRETS_DIR"
  install -m 0600 -o 0 -g 33 /dev/null "$SMTP_FILE"
  {
    printf '; WASP SMTP relay settings. Data, not code -- never include() this.\n'
    printf 'host = %s\n'       "$_h"
    printf 'port = %s\n'       "$_p"
    printf 'user = %s\n'       "$_u"
    printf 'pass_b64 = %s\n'   "$(printf '%s' "$_pw" | base64 | tr -d '\n')"
    printf 'from = %s\n'       "$_f"
    printf 'from_name = %s\n'  "$_fn"
    printf 'encryption = %s\n' "$_enc"
    printf 'timeout = 10\n'
  } > "$SMTP_FILE"
  chmod 0440 "$SMTP_FILE"; chown root:33 "$SMTP_FILE"
  # Retire the executable form if this VM predates the change.
  [ -f "$SMTP_FILE_LEGACY" ] && { rm -f "$SMTP_FILE_LEGACY"; echo "  Removed legacy executable smtp.php"; }
  echo "✔  Written to ${SMTP_FILE} (INI, non-executable, root:33 0440, dir 0750)"
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
