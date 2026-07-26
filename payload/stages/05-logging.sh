#!/bin/sh
# 05-logging.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Enables syslog and configures log rotation.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Enabling syslog"
rc-update add syslog boot 2>/dev/null || true
rc-service syslog status >/dev/null 2>&1 || rc-service syslog start 2>/dev/null || true
ok "syslog active"

# ── Log rotation ────────────────────────────────────────────────────────────
# BUG FIX (v7-14) — LOGS GREW WITHOUT BOUND AND EVENTUALLY FILLED THE DISK.
# Nothing in any previous version rotated anything. Four separate writers
# all appended forever to the same VM disk:
#   • /home/wpuser/wp/logs/access.log       — every HTTP request, combined format
#   • /home/wpuser/wp/logs/error.log        — Apache errors + PHP warnings
#   • /home/wpuser/wp/logs/remoteip-debug.log — a SECOND line per request
#   • /var/log/crowdsec/*.log               — decisions, parser output
# On a site getting even modest bot traffic that's easily hundreds of MB a
# month, and the failure mode when the disk finally fills is nasty and
# non-obvious: MariaDB can corrupt its data directory mid-write, the daily
# backup script fails (and its own error output has nowhere to go), Apache
# stops serving, and the first symptom an operator sees is "the site is
# down" with no clue that a log file is the cause.
#
# copytruncate is REQUIRED here, not a preference: Apache runs inside a
# container and holds an open file descriptor on the bind-mounted log.
# A normal rotate (rename + create new) would leave Apache writing to the
# now-unlinked inode forever — the new file would stay empty and the old
# one would keep growing invisibly, which is worse than not rotating at
# all. copytruncate copies then truncates in place, so the container's
# existing fd keeps working. The small window where lines can be lost
# between copy and truncate is an acceptable trade for access logs.
#
# Both a size trigger and a time trigger are set: `daily` bounds how old
# a log can get, `maxsize` bounds how big it gets — but maxsize is only
# evaluated when logrotate runs, so the cron entry runs HOURLY (see the
# scheduling note below) to make the 50M cap real rather than cosmetic.
ts "Configuring log rotation"
apk add --no-cache logrotate >/dev/null 2>&1 || warn "logrotate install failed — logs will NOT be rotated; check disk usage manually"

mkdir -p /etc/logrotate.d
install -m 0644 "${PAYLOAD_DIR}/etc/logrotate.d/wordpress-vm" /etc/logrotate.d/wordpress-vm
chmod 644 /etc/logrotate.d/wordpress-vm

# Alpine's logrotate package drops a hook in /etc/periodic/daily, but that
# only runs if the stock busybox crontab entries that call run-parts are
# still present — and this script appends its own entries to
# /etc/crontabs/root, so relying on that is a silent single point of
# failure. An explicit entry is scheduled instead.
# v7-15 (audit #4): run HOURLY, not daily. `maxsize 50M` is only evaluated
# when logrotate actually runs, so a once-daily invocation lets a traffic
# spike or log-flooding attack grow a file to gigabytes before the cap is
# ever checked — the cap was effectively cosmetic. Running hourly makes
# maxsize meaningful (a log can exceed 50M for at most ~an hour), while the
# `daily` directive inside the config still limits low-volume logs to one
# rotation a day. Minute 17 chosen to avoid the top-of-hour cron pile-up;
# still comfortably after the 02:00 backup on the daily overlap.
if ! grep -q 'logrotate.*wordpress-vm\|/usr/sbin/logrotate /etc/logrotate.conf' /etc/crontabs/root 2>/dev/null; then
  echo '17 * * * * /usr/sbin/logrotate /etc/logrotate.conf 2>&1 | logger -t logrotate' >> /etc/crontabs/root
fi

# logrotate.conf must exist and must include logrotate.d — Alpine's package
# ships one, but create a minimal fallback if it somehow isn't there so the
# cron entry above is never a no-op.
if [ ! -f /etc/logrotate.conf ]; then
  cat > /etc/logrotate.conf << 'LRCONF'
weekly
rotate 4
create
compress
include /etc/logrotate.d
LRCONF
  chmod 644 /etc/logrotate.conf
fi

if command -v logrotate >/dev/null 2>&1; then
  # --debug parses the config without touching anything: catches a syntax
  # error now, at install time, instead of silently never rotating. Validate
  # OUR file specifically (via a tiny wrapper conf) rather than the whole
  # /etc/logrotate.conf tree, which may pull in distro-shipped fragments we
  # don't control and whose errors would be misattributed to us. Capture the
  # actual error so the operator gets something actionable, not just "did
  # not validate".
  _lr_probe=$(mktemp)
  printf 'include /etc/logrotate.d/wordpress-vm\n' > "$_lr_probe"
  _lr_err=$(logrotate --debug "$_lr_probe" 2>&1 >/dev/null)
  if [ -z "$_lr_err" ]; then
    ok "Log rotation active (daily + 50M cap, 14 days retained, copytruncate)"
  else
    warn "logrotate config validation reported:"
    printf '%s\n' "$_lr_err" | sed 's/^/       /' | head -5
    warn "  Logs will still be written; rotation may not run until this is resolved."
    warn "  Reproduce with: logrotate --debug /etc/logrotate.d/wordpress-vm"
  fi
  rm -f "$_lr_probe"
else
  warn "logrotate not available — logs are NOT bounded. Monitor: du -sh /home/wpuser/wp/logs"
fi



