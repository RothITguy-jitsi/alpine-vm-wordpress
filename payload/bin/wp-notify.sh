#!/bin/sh
# =============================================================================
# wp-notify.sh — send an operational alert by email
# =============================================================================
#   wp-notify.sh <tag> <subject> [body-file]
#   wp-notify.sh --test
#   wp-notify.sh --status
#
# Used by the scheduled scans. Existing as one script rather than a snippet
# repeated in each of them matters for a reason this project has been bitten
# by repeatedly: anything implemented in several places drifts, and the copy
# nobody remembered to update fails silently.
#
# CREDENTIALS: read from /home/wpuser/wp/secrets/smtp.php, the same single
# file the WordPress mu-plugin uses. Nothing is duplicated into a second
# config, so there is no second place to forget when the relay changes.
#
# TRANSPORT: msmtp, invoked entirely from the command line -- no msmtprc is
# written, so the relay password never lands in a second file on disk. The
# password reaches msmtp through --passwordeval, which runs a command to
# fetch it, rather than through the process arguments where `ps` would show
# it to any local user.
#
# WHY NOT wp_mail: it would reuse the WordPress mail path exactly, which is
# tempting. But these alerts fire when something is wrong, and "WordPress or
# MariaDB is down" is precisely when an alert matters most and when wp_mail
# cannot run. Host-side sending works whether or not the site does.
#
# DEDUPLICATION is a deliberate feature, not an optimisation. A daily scan
# that emails the same unpatched plugin every morning becomes a filter rule
# within a week, and the operator stops reading it before the finding that
# matters arrives. The same alert is therefore sent at most once per
# NOTIFY_COOLDOWN_HOURS unless its content changes.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

SMTP_FILE="/home/wpuser/wp/secrets/smtp.php"
STATE="/var/lib/wp-notify"
NOTIFY_COOLDOWN_HOURS="${NOTIFY_COOLDOWN_HOURS:-24}"
mkdir -p "$STATE" 2>/dev/null || true
chmod 700 "$STATE" 2>/dev/null || true

# Same parser wp-mail.sh uses: read the value without executing the file.
_cfg() {
  [ -r "$SMTP_FILE" ] || return 1
  sed -n "s/^[[:space:]]*'$1'[[:space:]]*=>[[:space:]]*'\{0,1\}\([^',]*\)'\{0,1\},.*/\1/p" "$SMTP_FILE" | head -1
}

_recipient() {
  # Explicit override first, then the admin address given at install, then
  # the relay account itself -- which is always a real mailbox, so alerts
  # have somewhere to go even if nobody configured a destination.
  if [ -n "${NOTIFY_EMAIL:-}" ]; then printf '%s' "$NOTIFY_EMAIL"; return; fi
  if [ -n "${WP_ADMIN_EMAIL:-}" ]; then printf '%s' "$WP_ADMIN_EMAIL"; return; fi
  _cfg user
}

_configured() { [ -r "$SMTP_FILE" ] && [ -n "$(_cfg host)" ] && [ -n "$(_recipient)" ]; }

send_mail() {
  _tag="$1"; _subject="$2"; _bodyfile="${3:-}"
  _to=$(_recipient)
  _host=$(_cfg host); _port=$(_cfg port); _user=$(_cfg user)
  _from=$(_cfg from); [ -n "$_from" ] || _from="$_user"
  _enc=$(_cfg encryption)

  if ! command -v msmtp >/dev/null 2>&1; then
    logger -t wp-notify "msmtp not installed; alert not emailed: ${_subject}"
    echo "✗ msmtp is not installed — install with: apk add msmtp" >&2
    return 1
  fi

  # --passwordeval keeps the secret out of the argument list. Passing it as
  # --password would expose it in `ps` output to every local account for the
  # lifetime of the process.
  _pwcmd="sed -n \"s/^[[:space:]]*'pass'[[:space:]]*=>[[:space:]]*'\\(.*\\)',.*/\\1/p\" ${SMTP_FILE} | head -1"

  case "$_enc" in
    ssl) _tlsargs="--tls=on --tls-starttls=off" ;;
    *)   _tlsargs="--tls=on --tls-starttls=on" ;;
  esac

  {
    printf 'From: %s\n' "$_from"
    printf 'To: %s\n' "$_to"
    printf 'Subject: [%s] %s\n' "${HOSTNAME:-wordpress-vm}" "$_subject"
    printf 'X-WPVM-Tag: %s\n' "$_tag"
    printf 'Content-Type: text/plain; charset=UTF-8\n'
    printf '\n'
    printf 'Host    : %s\n' "${HOSTNAME:-unknown}"
    printf 'Time    : %s UTC\n' "$(date -u '+%Y-%m-%d %H:%M:%S')"
    printf 'Source  : %s\n\n' "$_tag"
    if [ -n "$_bodyfile" ] && [ -r "$_bodyfile" ]; then
      cat "$_bodyfile"
    else
      printf '(no detail supplied)\n'
    fi
    printf '\n--\nSent by wp-notify.sh on %s\n' "${HOSTNAME:-this VM}"
    printf 'Silence this class of alert: NOTIFY_COOLDOWN_HOURS in /etc/wp-install/vars.sh\n'
  } | msmtp --host="$_host" --port="${_port:-587}" --auth=on $_tlsargs \
            --user="$_user" --from="$_from" \
            --passwordeval="$_pwcmd" \
            --read-envelope-from=off \
            "$_to" 2>"$STATE/last-error" \
    && { logger -t wp-notify "sent: ${_subject} -> ${_to}"; return 0; } \
    || { logger -t wp-notify "SEND FAILED: ${_subject} ($(head -1 "$STATE/last-error" 2>/dev/null))"; return 1; }
}

case "${1:-}" in
  --test)
    _configured || { echo "✗ No SMTP relay configured. Run: wp-mail.sh setup" >&2; exit 1; }
    _t=$(mktemp)
    printf 'This is a test alert from wp-notify.sh.\n\nIf you received it, scheduled scans can reach you.\n' > "$_t"
    send_mail "test" "wp-notify test message" "$_t" && echo "✔ Test alert sent to $(_recipient)"
    rm -f "$_t" ;;
  --status)
    echo ""
    echo "Alert notifications"
    echo "━━━━━━━━━━━━━━━━━━━"
    if _configured; then
      echo "  Relay      : $(_cfg host):$(_cfg port)"
      echo "  Recipient  : $(_recipient)"
      echo "  Cooldown   : ${NOTIFY_COOLDOWN_HOURS}h per identical alert"
      command -v msmtp >/dev/null 2>&1 \
        && echo "  Transport  : msmtp (works even if WordPress is down)" \
        || echo "  Transport  : MISSING — apk add msmtp"
    else
      echo "  NOT CONFIGURED — scans will log to syslog only."
      echo "  Configure the relay: wp-mail.sh setup"
    fi
    echo ""
    echo "  Recently sent:"
    ls -1t "$STATE"/sent-* 2>/dev/null | head -5 | while read -r f; do
      printf '    %s  %s\n' "$(date -u -d "@$(stat -c %Y "$f")" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')" "$(basename "$f" | sed 's/^sent-//;s/\.[a-f0-9]*$//')"
    done || true
    echo ""
    echo "  Send a test:  wp-notify.sh --test" ;;
  "")
    echo "Usage: wp-notify.sh <tag> <subject> [body-file]" >&2
    echo "       wp-notify.sh --test | --status" >&2
    exit 1 ;;
  *)
    _tag="$1"; _subject="${2:-alert}"; _body="${3:-}"
    # Always record to syslog, whether or not mail works. Email can fail;
    # the local record should not depend on it.
    logger -t "$_tag" "${_subject}"
    _configured || exit 0

    # Dedupe on the CONTENT of the finding, not the subject line. A subject
    # like "3 findings" is identical two days running even when the findings
    # changed completely, and hashing that would suppress a genuinely new
    # alert.
    if [ -n "$_body" ] && [ -r "$_body" ]; then
      _hash=$(md5sum "$_body" | awk '{print $1}')
    else
      _hash=$(printf '%s' "$_subject" | md5sum | awk '{print $1}')
    fi
    _marker="$STATE/sent-${_tag}.${_hash}"
    if [ -f "$_marker" ]; then
      _age_h=$(( ( $(date +%s) - $(stat -c %Y "$_marker" 2>/dev/null || echo 0) ) / 3600 ))
      if [ "$_age_h" -lt "$NOTIFY_COOLDOWN_HOURS" ]; then
        logger -t wp-notify "suppressed (identical alert sent ${_age_h}h ago): ${_subject}"
        exit 0
      fi
    fi
    # Only this tag's stale markers are cleared, so an unrelated alert's
    # cooldown is never reset as a side effect.
    find "$STATE" -name "sent-${_tag}.*" -type f -delete 2>/dev/null || true
    if send_mail "$_tag" "$_subject" "$_body"; then
      : > "$_marker"; chmod 600 "$_marker"
    fi ;;
esac
