#!/bin/sh
# WordPress system cron — runs wp-cron.php inside the WordPress container.
# FORENSIC FIX (new-audit Low finding, confirmed reasonable): this was a
# bare one-line wrapper with no overlap protection and no failure signal —
# fine for the happy path, but a slow run (e.g. a plugin's scheduled job
# stalling) could overlap with the next 5-minute cron tick, and a failure
# was silently invisible (cron only mails non-empty stdout, not a nonzero
# exit). Locking mirrors update.sh's own lock exactly (mkdir is atomic on
# every storage backend this runs on, no flock binary dependency, and a
# lock left behind by a crashed run is detected via the recorded PID and
# `kill -0` rather than wedging every future tick) rather than introducing
# a second, different locking convention into the same codebase.
LOCK_DIR="/run/lock/wp-cron-run.lock"
mkdir -p /run/lock
if mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
else
  lock_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)
  if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
    # A previous run is still actually going (rare: wp-cron.php stalled
    # past the 5-minute tick) -- skip this tick rather than pile up a
    # second concurrent run against the same site.
    exit 0
  fi
  # Stale lock from a crashed/killed previous run -- clear it and proceed.
  rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR" 2>/dev/null && printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
fi

podman exec wordpress php /var/www/html/wp-cron.php
rc=$?
[ "$rc" -eq 0 ] || echo "wp-cron-run: wp-cron.php exited ${rc}" | logger -t wp-cron-run
exit "$rc"
