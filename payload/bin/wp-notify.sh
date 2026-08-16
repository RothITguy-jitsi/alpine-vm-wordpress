#!/bin/sh
# =============================================================================
# wp-notify.sh — send an operational alert by email
# =============================================================================
#   wp-notify.sh <tag> <subject> [body-file]
#   wp-notify.sh --test
#   wp-notify.sh --heartbeat-url <url>   external dead-man's-switch
#   wp-notify.sh --heartbeat             ping it (cron)
#   wp-notify.sh --status
#
# Used by the scheduled scans. Existing as one script rather than a snippet
# repeated in each of them matters for a reason this project has been bitten
# by repeatedly: anything implemented in several places drifts, and the copy
# nobody remembered to update fails silently.
#
# CREDENTIALS: read from /home/wpuser/wp/secrets/smtp.ini, the same single
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

# INI, not PHP. The credentials file is data now, so reading it cannot
# execute anything -- see the note in 01-wpvm-smtp.php for why that changed.
# Legacy smtp.php is still read if present so an existing VM keeps working
# until `setup` migrates it.
# Defined here rather than inherited: this script does not source wp-mail.sh,
# and the _cfg() helper was copied across from it complete with a reference to
# a variable that only exists there. Every notification path failed with
# "SECRETS_DIR: parameter not set".
# Restored: this default was removed by an earlier edit that replaced the
# _cfg() helper, and under `set -u` every path referencing it then died with
# "NOTIFY_COOLDOWN_HOURS: parameter not set" — including --status, which is
# the command an operator runs to check that notifications work.
NOTIFY_COOLDOWN_HOURS="${NOTIFY_COOLDOWN_HOURS:-24}"
SECRETS_DIR="${SECRETS_DIR:-/home/wpuser/wp/secrets}"
# THIRD instance of this same bug (SECRETS_DIR, then NOTIFY_COOLDOWN_HOURS, now
# STATE). Reported from a live VM:
#     doas wp-db-backup.sh
#     /usr/local/bin/wp-notify.sh: line 269: STATE: parameter not set
# STATE holds the dedup markers and the last-error file. It is referenced in six
# places and was never assigned, so under `set -u` EVERY notification path died
# before sending anything -- backup-failure email, malware findings, vulnerability
# findings, and the heartbeat that is the only thing detecting a VM being gone.
#
# A monitoring system that cannot report is worse than not having one, because
# its silence is indistinguishable from "all clear". That is precisely the
# failure this script exists to prevent, and it had it.
STATE="${STATE:-/var/lib/wasp-notify}"
mkdir -p "$STATE" 2>/dev/null || true
chmod 0700 "$STATE" 2>/dev/null || true
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

_recipient() {
  # Vulnerability exceptions go to the governance mailbox when one is set --
  # deliberately a different destination from operational alerts, so a risk
  # acceptance is not filed alongside disk-space warnings.
  if [ "${1:-}" = "wasp-vuln-exception" ] && [ -n "${GOVERNANCE_EMAIL:-}" ]; then
    printf '%s' "$GOVERNANCE_EMAIL"; return
  fi
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
  _to=$(_recipient "$_tag")
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
    # The && form meant a failed send printed NOTHING AT ALL -- observed in
    # the field: `wp-notify.sh --test` returned to the prompt with no output,
    # which reads like success. A test command that is silent on failure is
    # worse than no test command.
    if send_mail "test" "wp-notify test message" "$_t"; then
      echo "✔ Test alert sent to $(_recipient)"
      echo "  If it does not arrive, the relay accepted it and something"
      echo "  downstream dropped it — check SPF/DKIM for $(_cfg from)."
    else
      echo "✗ Test alert FAILED to send." >&2
      if [ -s "$STATE/last-error" ]; then
        echo "  msmtp said:" >&2
        sed 's/^/    /' "$STATE/last-error" >&2
      else
        echo "  No error output captured. Is msmtp installed? (apk add msmtp)" >&2
      fi
      echo "  Check the relay settings:  wp-mail.sh doctor" >&2
      rm -f "$_t"
      exit 1
    fi
    rm -f "$_t" ;;
  --heartbeat)
    # Ping an external dead-man's-switch (healthchecks.io, Uptime Kuma,
    # Better Stack — anything that alerts on ABSENCE).
    #
    # This closes the one gap nothing else here can: every other check runs
    # ON this VM, so a VM that is powered off, unreachable, or on a dead
    # hypervisor reports nothing at all. Silence looks identical to health.
    #
    # The signal is the absence of a ping, which is why it must be an
    # external service — a check that lives on the thing being checked cannot
    # detect the thing being gone.
    #
    # Deliberately checks that WordPress actually SERVES before pinging.
    # A heartbeat that only proves cron is running would keep reporting
    # healthy through a completely broken site, which is worse than none: it
    # converts a real outage into a false assurance.
    _url="${HEARTBEAT_URL:-}"
    [ -n "$_url" ] || _url=$(sed -n 's/^HEARTBEAT_URL=//p' /etc/wp-install/heartbeat.conf 2>/dev/null | tr -d "'\"")
    if [ -z "$_url" ]; then
      echo "No heartbeat URL configured." >&2
      echo "  Create a check at healthchecks.io (free) or your own Uptime Kuma," >&2
      echo "  then:  wp-notify.sh --heartbeat-url <url>" >&2
      exit 1
    fi
    _ok=1
    podman exec wordpress php -r '
      $c=stream_context_create(["http"=>["timeout"=>8,"ignore_errors"=>true,
        "header"=>"User-Agent: wasp-heartbeat/1.0\r\n"]]);
      @file_get_contents("http://127.0.0.1/",false,$c);
      preg_match("#HTTP/[0-9.]+ ([0-9]{3})#",$http_response_header[0]??"",$m);
      exit((($m[1]??0)>=200 && ($m[1]??0)<400)?0:1);' 2>/dev/null || _ok=0
    podman exec mariadb sh -c \
      'mariadb-admin ping --silent -uroot -p"$MARIADB_ROOT_PASSWORD" 2>/dev/null' >/dev/null 2>&1 || _ok=0

    if [ "$_ok" = "1" ]; then
      curl -fsS -m 15 "$_url" >/dev/null 2>&1 && exit 0
      logger -t wasp-heartbeat "site healthy but the heartbeat could not be sent"
      exit 1
    fi
    # Signal failure explicitly where the endpoint supports it; otherwise stay
    # silent and let the missed ping speak.
    curl -fsS -m 15 "${_url}/fail" >/dev/null 2>&1 || true
    logger -t wasp-heartbeat "health check FAILED — heartbeat withheld"
    exit 1 ;;

  --heartbeat-url)
    _u="${2:-}"
    case "$_u" in
      https://*|http://*) : ;;
      *) echo "Usage: wp-notify.sh --heartbeat-url https://hc-ping.com/<uuid>" >&2; exit 1 ;;
    esac
    mkdir -p /etc/wp-install
    printf 'HEARTBEAT_URL=%s\n' "$_u" > /etc/wp-install/heartbeat.conf
    chmod 600 /etc/wp-install/heartbeat.conf
    echo "✔ Heartbeat URL stored"
    echo "  Set the check's period to 15 minutes with a 30-minute grace at the"
    echo "  other end — cron pings every 10, so two consecutive failures alert"
    echo "  rather than one slow run."
    echo ""
    echo "  Test it now:  wp-notify.sh --heartbeat" ;;

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
