#!/bin/sh
# =============================================================================
# wasp-capture.sh — record what you did and produce one shareable bundle
# =============================================================================
#   wasp-capture.sh start [label]     begin recording a working session
#   wasp-capture.sh stop              end it, gather diagnostics, bundle, redact
#   wasp-capture.sh report            just gather diagnostics now (no session)
#   wasp-capture.sh oneshot -- CMD…   record a single command and bundle it
#
# WHAT THIS IS FOR
#
# When something on the VM needs a second pair of eyes -- a failed install, a
# control that is not behaving, a question about what a command did -- the most
# useful thing you can hand over is not a description, it is exactly what you
# ran and exactly what came back, plus the machine's own view of its state. This
# records your session, runs the full diagnostic report, and packages both into
# a single file you can attach in a browser (a chat, an email, an issue).
#
# HOW IT WORKS
#
# It wraps `script` (util-linux, already on the VM -- no new dependency) to
# capture the terminal transcript, then runs wasp-testreport.sh for the
# structured state. It is NOT asciinema and does not upload anywhere: the
# bundle is a local file and you decide where it goes.
#
# WHY REDACTION IS NOT OPTIONAL HERE
#
# A raw session transcript on a WASP VM contains client IPs, hostnames, and
# whatever scrolled past -- which under GDPR and similar law is personal data
# the moment it leaves the machine. Public recording services (asciinema.org
# and the like) are explicitly the wrong place for it. So this scrubs, BY
# VALUE, every secret the installer knows about (passwords, API keys, the age
# recipient) from BOTH the transcript and the report before bundling, and warns
# you to read the result before sending. Redaction that misses something is a
# bug to report, not a surprise to discover -- but you are the last check, so
# skim the bundle. Secrets are replaced with a typed placeholder like
# «REDACTED:SMTP_PASS» so the structure stays readable.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi

VARS=/etc/wp-install/vars.sh
WORKDIR=/var/tmp/wasp-capture
STATE="${WORKDIR}/.active"
TESTREPORT=/usr/local/bin/wasp-testreport.sh

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' "$1"; }

mkdir -p "$WORKDIR"; chmod 700 "$WORKDIR"

# ── Redaction ────────────────────────────────────────────────────────────────
# Build a sed script that replaces each KNOWN secret VALUE with a typed marker.
# By value, not by variable name: the transcript shows the value, not "SMTP_PASS
# =", so we have to know the actual strings. We read them from vars.sh and the
# secrets files, escape them for sed, and only redact values long enough to be
# real secrets (>= 6 chars) so we do not blank out every short token.
# Strip one leading and one trailing quote (single OR double) from $1, using
# character variables so there is never a literal quote-inside-quote construct
# for a POSIX shell parser to mishandle.
_sq=$(printf '\047'); _dq=$(printf '\042')
_unquote() {
  _u="$1"
  case "$_u" in "$_dq"*) _u="${_u#$_dq}" ;; esac
  case "$_u" in *"$_dq") _u="${_u%$_dq}" ;; esac
  case "$_u" in "$_sq"*) _u="${_u#$_sq}" ;; esac
  case "$_u" in *"$_sq") _u="${_u%$_sq}" ;; esac
  printf '%s' "$_u"
}

_build_redactor() {
  _sed="${WORKDIR}/.redact.sed"; : > "$_sed"
  _add() { # name, value
    _v="$2"
    [ -n "$_v" ] || return 0
    [ "${#_v}" -ge 6 ] || return 0
    # escape sed metacharacters in the value
    _e=$(printf '%s' "$_v" | sed -e 's/[\/&|.*^$[]/\\&/g')
    printf 's|%s|«REDACTED:%s»|g\n' "$_e" "$1" >> "$_sed"
  }
  if [ -r "$VARS" ]; then
    # Pull each sensitive assignment value out of vars.sh without sourcing it.
    for _k in ADMIN_PASS ROOT_PASS DB_ROOT_PASS DB_WP_PASS SMTP_PASS \
              CTI_API_KEY WORDFENCE_API_KEY MAXMIND_LICENSE_KEY \
              CROWDSEC_ENROLL_KEY OFFSITE_AGE_RECIPIENT; do
      _val=$(sed -n "s/^${_k}=//p" "$VARS" 2>/dev/null | head -1)
      _val=$(_unquote "$_val")
      _add "$_k" "$_val"
    done
  fi
  # SMTP password from the ini too, in case it differs from vars.sh
  if [ -r /home/wpuser/wp/secrets/smtp.ini ]; then
    _val=$(sed -n 's/^password=//p;s/^AuthPass=//p' /home/wpuser/wp/secrets/smtp.ini 2>/dev/null | head -1)
    _add SMTP_PASS "$_val"
  fi
  # age SECRET keys and rclone secrets, if any ever land in a transcript.
  printf 's|AGE-SECRET-KEY-[A-Z0-9]*|«REDACTED:AGE_SECRET_KEY»|g\n' >> "$_sed"
  printf 's|\\(aws_secret_access_key *= *\\).*|\\1«REDACTED:R2_SECRET»|g\n' >> "$_sed"
  printf 's|\\(password *= *\\).*|\\1«REDACTED:PASSWORD»|g\n' >> "$_sed"
  # A generic AGE-SECRET-KEY line the operator might paste during a restore.
  echo "$_sed"
}

_redact_file() { # infile, outfile
  _r=$(_build_redactor)
  if [ -s "$_r" ]; then
    LC_ALL=C sed -f "$_r" "$1" > "$2" 2>/dev/null || cp "$1" "$2"
  else
    cp "$1" "$2"
  fi
}

# ── Environment context ──────────────────────────────────────────────────────
# A short, non-sensitive snapshot that answers "what is this VM" without
# needing the operator to describe it.
_env_context() {
  echo "# WASP capture — environment context"
  echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "hostname  : $(hostname 2>/dev/null)"
  if [ -r "$VARS" ]; then
    _bv=$(_unquote "$(sed -n 's/^WASP_VERSION=//p' "$VARS" 2>/dev/null | head -1)")
    _pf=$(_unquote "$(sed -n 's/^DEPLOYMENT_PROFILE=//p' "$VARS" 2>/dev/null | head -1)")
    _eg=$(_unquote "$(sed -n 's/^EGRESS_PROXY=//p' "$VARS" 2>/dev/null | head -1)")
    echo "build     : ${_bv}"
    echo "profile   : ${_pf}"
    echo "egress    : ${_eg}"
  fi
  echo "alpine    : $(cat /etc/alpine-release 2>/dev/null)"
  echo "kernel    : $(uname -r 2>/dev/null)"
  echo ""
  echo "# containers"
  podman ps -a --format '  {{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null | LC_ALL=C sed 's|@sha256:[0-9a-f]*||' || echo "  (podman unavailable)"
  echo ""
  echo "# unverified-install marker"
  [ -f /etc/wp-install/UNVERIFIED ] && cat /etc/wp-install/UNVERIFIED || echo "  none (build was verified, or standard/lab)"
}

# ── Bundle assembly ──────────────────────────────────────────────────────────
_bundle() { # session_transcript_or_empty, label
  _sess="$1"; _label="$2"
  _stamp=$(date -u +%Y%m%d-%H%M%S)
  _base="wasp-capture-${_label:-session}-${_stamp}"
  _dir="${WORKDIR}/${_base}"; mkdir -p "$_dir"

  _hdr "Gathering diagnostics"
  # 1. environment context
  _env_context > "${_dir}/00-environment.txt"
  _ok "environment snapshot"

  # 2. full structured report (already redacts secrets to lengths). Capture it
  #    to a file, then run it through the value-redactor too as a second pass.
  if [ -x "$TESTREPORT" ]; then
    _raw="${WORKDIR}/.report.raw"
    "$TESTREPORT" > "$_raw" 2>&1 || true
    # wasp-testreport writes its own file too; prefer capturing our run.
    _redact_file "$_raw" "${_dir}/10-testreport.txt"; rm -f "$_raw"
    _ok "diagnostic report (redacted)"
  else
    echo "wasp-testreport.sh not found" > "${_dir}/10-testreport.txt"
    _warn "wasp-testreport.sh not found — report section is empty"
  fi

  # 3. the session transcript, redacted, if there was one
  if [ -n "$_sess" ] && [ -f "$_sess" ]; then
    _redact_file "$_sess" "${_dir}/20-session.txt"
    _ok "session transcript (redacted)"
  fi

  # 4. recent, low-sensitivity logs that help correlate. Egress denials and
  #    firewall drops are exactly the evidence a reviewer wants, and they are
  #    about destinations, not secrets -- but they still pass through the
  #    redactor in case a hostname is sensitive.
  {
    echo "# recent WASP-relevant log lines (redacted)"
    echo "## nftables drops / egress bypass"
    dmesg 2>/dev/null | grep -iE 'nft-|egress' | tail -40
    echo ""
    echo "## squid denials (if egress proxy on)"
    tail -40 /opt/squid/logs/access.log 2>/dev/null | grep -i denied
    echo ""
    echo "## crowdsec decisions"
    podman exec crowdsec cscli decisions list 2>/dev/null | head -20
  } > "${WORKDIR}/.logs.raw" 2>/dev/null
  _redact_file "${WORKDIR}/.logs.raw" "${_dir}/30-logs.txt"; rm -f "${WORKDIR}/.logs.raw"
  _ok "correlated logs (redacted)"

  # 5. a short README so whoever opens the bundle knows what each file is.
  #    Built with printf rather than a heredoc: the explanatory text contains
  #    em-dashes and guillemets, and a stray one confusing heredoc delimiter
  #    detection is not worth the risk in a POSIX sh script.
  {
    printf 'WASP capture bundle\n'
    printf '===================\n'
    printf '00-environment.txt  What this VM is: build, profile, containers, markers.\n'
    printf '10-testreport.txt   Full diagnostic report - the machine view of its state.\n'
    printf '20-session.txt      What you actually typed and saw (if a session was recorded).\n'
    printf '30-logs.txt         Recent firewall/egress/CrowdSec lines for correlation.\n'
    printf '\n'
    printf 'All files are redacted BY VALUE for known secrets (passwords, API keys,\n'
    printf 'the age recipient, pasted private keys), replaced with REDACTED markers.\n'
    printf 'Skim before sharing anyway - you are the last check.\n'
  } > "${_dir}/README.txt"

  # 6. tar it up.
  _out="/var/tmp/${_base}.tar.gz"
  tar -czf "$_out" -C "$WORKDIR" "$_base" 2>/dev/null
  rm -rf "$_dir"
  chmod 600 "$_out"

  _hdr "Bundle ready"
  _ok "$_out"
  _sz=$(du -h "$_out" | cut -f1)
  _note "size: ${_sz}"
  echo ""
  _note "It is redacted, but SKIM IT before sending — you are the last check:"
  _note "  tar -xzOf \"$_out\" ${_base}/20-session.txt | less"
  echo ""
  _note "Then attach ${_out} in your browser (chat, email, or issue)."
  _note "To pull it to your workstation:"
  _note "  scp admin@$(hostname):${_out} ."
}

# ── Commands ─────────────────────────────────────────────────────────────────
case "${1:-}" in

  start)
    _label=$(printf '%s' "${2:-session}" | tr -c 'a-zA-Z0-9._-' '_')
    if [ -f "$STATE" ]; then
      _warn "A capture is already active. Stop it first: wasp-capture.sh stop"
      exit 1
    fi
    command -v script >/dev/null 2>&1 || { echo "util-linux 'script' is required" >&2; exit 1; }
    _tr="${WORKDIR}/session-${_label}-$(date -u +%Y%m%d-%H%M%S).raw"
    printf '%s\n' "$_tr" > "$STATE"; printf '%s\n' "$_label" >> "$STATE"
    _hdr "Recording started"
    _note "Everything in the shell that opens is being recorded to a transcript."
    _note "Do the work you want captured. When finished, type 'exit' to leave the"
    _note "recorded shell, then run:  wasp-capture.sh stop"
    echo ""
    # script's -q quiets its own banner; -f flushes so a crash still leaves data.
    script -q -f "$_tr"
    _note "Recorded shell closed. Now run:  wasp-capture.sh stop"
    ;;

  stop)
    [ -f "$STATE" ] || { _warn "No active capture. Start one with: wasp-capture.sh start"; exit 1; }
    _tr=$(sed -n '1p' "$STATE"); _label=$(sed -n '2p' "$STATE")
    rm -f "$STATE"
    [ -f "$_tr" ] || { _warn "Transcript not found (${_tr}); bundling report only."; _tr=""; }
    _bundle "$_tr" "$_label"
    [ -n "$_tr" ] && rm -f "$_tr"
    ;;

  report)
    # No session, just the machine's state + logs. Useful when the operator
    # only needs "here is what the VM looks like right now".
    _bundle "" "report"
    ;;

  oneshot)
    shift 2>/dev/null || true
    [ "${1:-}" = "--" ] && shift
    [ $# -gt 0 ] || { echo "Usage: wasp-capture.sh oneshot -- <command> [args…]" >&2; exit 1; }
    _tr="${WORKDIR}/oneshot-$(date -u +%Y%m%d-%H%M%S).raw"
    _hdr "Recording a single command"
    _note "\$ $*"
    script -q -f -c "$*" "$_tr" || true
    _bundle "$_tr" "oneshot"
    rm -f "$_tr"
    ;;

  *)
    sed -n '4,9p' "$0"
    ;;
esac
