#!/bin/sh
# Installs the Two Factor plugin once WordPress core setup has been completed.
# Runs from cron; removes its own schedule after a successful install.
set -u
LOG=/var/log/wasp-mfa-deferred.log
STAMP=/etc/wp-install/.mfa-plugin-installed

# --now forces a run: ignores the completion stamp, prints to the terminal as
# well as the log, and reports what it found. Added because the automatic path
# failed once with no way to retry it by hand -- the operator had to dig the
# install command out of an old log.
_FORCE=0
case "${1:-}" in
  --now|now|--force) _FORCE=1 ;;
  --status)
    echo "Deferred Two Factor installer"
    echo "  script  : /usr/local/bin/wasp-mfa-deferred.sh"
    if grep -q wasp-mfa-deferred /etc/crontabs/root 2>/dev/null; then
      echo "  schedule: $(grep wasp-mfa-deferred /etc/crontabs/root)"
    else
      echo "  schedule: NOT SCHEDULED — that is why it never ran."
      echo "            Fix: echo '*/10 * * * * /usr/local/bin/wasp-mfa-deferred.sh >/dev/null 2>&1' >> /etc/crontabs/root"
    fi
    echo "  crond   : $(rc-service crond status 2>/dev/null | tail -1)"
    if [ -f "$STAMP" ]; then echo "  state   : DONE (installed $(cat "$STAMP" 2>/dev/null))"
    else echo "  state   : still waiting"; fi
    echo "  log     :"
    tail -12 "$LOG" 2>/dev/null | sed 's/^/    /' || echo "    (no log yet — it has never run)"
    exit 0 ;;
esac

if [ "$_FORCE" = "0" ] && [ -f "$STAMP" ]; then exit 0; fi

_log() {
  printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG"
  [ "${_FORCE:-0}" = "1" ] && printf '  %s\n' "$*"
  return 0
}

# Is the site actually installed yet? `wp core is-installed` is the exact
# question, and it is cheap.
# LEAVE EVIDENCE ON EVERY RUN, including the waiting ones.
#
# This used to `exit 0` silently while waiting for the setup wizard. That made
# an empty log indistinguishable from cron never firing at all -- which is
# exactly the situation an operator hit: waited twenty minutes, saw nothing,
# and had no way to tell whether the hook was alive, broken, or never
# scheduled. A heartbeat line costs nothing and answers that in one look.
_log "run: checking whether WordPress setup is complete"
if ! _probe=$(/usr/local/bin/wp-plugins.sh is-site-installed 2>&1); then
  _log "  not yet -- wizard not finished, or wp-cli cannot reach WordPress"
  [ -n "$_probe" ] && _log "  wp-cli said: $(printf '%s' "$_probe" | head -3 | tr '\n' ' ')"
  exit 0
fi

_log "WordPress setup detected — installing Two Factor"
_rc=0
  _out=$(/usr/local/bin/wp-plugins.sh install two-factor --activate 2>&1) || _rc=$?
  printf '%s\n' "$_out" >> "$LOG"
  if [ "$_rc" -eq 0 ]; then
  _log "Two Factor installed and activated"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$STAMP"
  # Clear the production blocker this was responsible for, if it is the only one.
  if [ -f /etc/wp-install/PRODUCTION-BLOCKERS ]; then
    grep -v 'Two Factor plugin is not active' /etc/wp-install/PRODUCTION-BLOCKERS \
      > /etc/wp-install/PRODUCTION-BLOCKERS.tmp 2>/dev/null || true
    if [ -s /etc/wp-install/PRODUCTION-BLOCKERS.tmp ]; then
      mv -f /etc/wp-install/PRODUCTION-BLOCKERS.tmp /etc/wp-install/PRODUCTION-BLOCKERS
      _log "MFA blocker cleared; other blockers remain"
    else
      rm -f /etc/wp-install/PRODUCTION-BLOCKERS.tmp /etc/wp-install/PRODUCTION-BLOCKERS
      _log "MFA blocker cleared; no blockers remain"
    fi
  fi
  logger -t wasp-mfa "Two Factor plugin installed and activated after WordPress setup"
else
  _log "Install attempt FAILED — will retry"
  # Show wp-cli's ACTUAL output. This used to log only "FAILED", which is the
  # one thing the operator already knows. Diagnosing it then meant re-running
  # the underlying command by hand -- and a tool whose whole purpose is making
  # a silent failure visible should not itself be the thing hiding it.
  if [ -n "${_out:-}" ]; then
    _log "  wp-cli said:"
    printf '%s\n' "$_out" | tail -12 | while IFS= read -r _l; do _log "    ${_l}"; done
  fi
  _log "  If this says 'unexpected error ... server configuration', check that"
  _log "  wp-config.php has WP_PROXY_HOST when the egress proxy is enabled:"
  _log "    doas grep WP_PROXY /home/wpuser/wp/html/wp-config.php"
fi
