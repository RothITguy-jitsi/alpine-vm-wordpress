#!/bin/sh
# wp-db-backup.sh — verified daily MariaDB backup. Called from cron.
# Design mirrors do_db_update()'s in-flight backup step in update.sh.
# Auto-elevate. Every other operator tool in this suite does this, and the
# inconsistency was found the hard way: running this as the admin user printed
# "install: can't create directory '/root/wp-db-backups': Permission denied",
# which reads like a broken path rather than "you need doas".
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "This must run as root (or via doas)." >&2; exit 1
fi
set -eu

# Per-run, not a fixed path. A predictable file under /tmp that a root process
# writes to is CWE-377: any local user can pre-create it as a symlink and have
# root truncate whatever it points at. Dot-prefixing hid it from `ls` and from
# nothing else.
_OFFLOG=$(mktemp) || exit 1
trap 'rm -f "$_OFFLOG"' EXIT INT TERM
# FORENSIC FIX (new-audit Medium finding, confirmed reasonable): no lock
# existed, so a manual run while the scheduled 2am run was still going (or
# any other double-invocation) could overlap two mariadb-dump processes
# against the same instance. Same mkdir-based convention as update.sh and
# wp-cron-run.sh's own locks -- not a new pattern, the third use of the
# same one. A concurrent run just skips (exit 0): yesterday's good backup
# is still safe either way, and the next scheduled run will simply try again.
LOCK_DIR="/run/lock/wp-db-backup.lock"
mkdir -p /run/lock
if mkdir "$LOCK_DIR" 2>/dev/null; then
  printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null || true
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
else
  _lock_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || echo "")
  if [ -n "$_lock_pid" ] && kill -0 "$_lock_pid" 2>/dev/null; then
    logger -t wp-db-backup "skipped — another backup (pid ${_lock_pid}) is still running"
    exit 0
  fi
  rm -rf "$LOCK_DIR"
  mkdir "$LOCK_DIR" 2>/dev/null && printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null || true
  trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
fi
BACKUP_DIR="/root/wp-db-backups"
# v7-15 (audit #14): timestamp includes time, not just date — a manual run
# on the same day as the scheduled one no longer overwrites it.
STAMP=$(date -u +%Y%m%d-%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/wp-db-${STAMP}.sql.gz"
# v8-1 (ChatGPT v8 finding 19): stage the dump and the compressed archive to
# HIDDEN temp files in the same directory, then publish the verified archive
# with a single atomic rename. A crash mid-dump or mid-gzip can then never leave
# a truncated wp-db-*.sql.gz that looks complete to an operator, the rotation
# below, or an external backup sync arriving before the next run.
BACKUP_RAW="${BACKUP_DIR}/.wp-db-${STAMP}.sql.part"
BACKUP_GZ_TMP="${BACKUP_DIR}/.wp-db-${STAMP}.sql.gz.part"

install -d -m 0700 "${BACKUP_DIR}"
BACKUP_OK=0

# Step 1: dump to a plain .sql file so mariadb-dump's own exit status is
# what gets checked (gzip on the end of a pipe would mask the failure).
# v7-15 (audit #14): --routines --events --triggers so stored procedures,
# functions, scheduled events, and triggers are included — without them a
# restore rebuilds tables but silently drops the logic that operates on
# them. --single-transaction gives a consistent snapshot without locking
# the whole database for the duration of the dump.
if (umask 077; podman exec mariadb sh -c \
     'exec mariadb-dump --all-databases --routines --events --triggers --single-transaction --quick --hex-blob -uroot -p"$MARIADB_ROOT_PASSWORD"' \
     > "${BACKUP_RAW}" 2> "${BACKUP_RAW}.err"); then
  # Step 2: confirm mariadb-dump actually finished (non-empty + trailing marker).
  # An interrupted dump can still exit 0 in some connection-drop scenarios.
  if [ -s "${BACKUP_RAW}" ] && tail -c 200 "${BACKUP_RAW}" | grep -q "Dump completed"; then
    # Step 3: compress to a temp file, integrity-check it, set perms, then
    # atomically rename it into place as the final archive (see note above).
    if gzip -c "${BACKUP_RAW}" > "${BACKUP_GZ_TMP}" && gzip -t "${BACKUP_GZ_TMP}" 2>/dev/null; then
      chmod 600 "${BACKUP_GZ_TMP}" 2>/dev/null || true
      if mv -f "${BACKUP_GZ_TMP}" "${BACKUP_FILE}"; then
        BACKUP_OK=1
      else
        logger -t wp-db-backup "FAILED — could not publish ${BACKUP_FILE}"
      fi
    else
      logger -t wp-db-backup "FAILED — gzip compress/verify of the staged archive"
    fi
  else
    logger -t wp-db-backup "FAILED — dump looks incomplete (empty or missing completion marker)"
  fi
else
  logger -t wp-db-backup "FAILED — mariadb-dump exited nonzero"
fi

if [ "${BACKUP_OK}" != "1" ]; then
  # Preserve stderr from the failed run for diagnosis, but remove the
  # broken .sql/.sql.gz so it can't be mistaken for a good backup by
  # anything (a monitoring script, an operator, or the rotation below).
  [ -s "${BACKUP_RAW}.err" ] && \
    logger -t wp-db-backup "stderr: $(head -c 500 "${BACKUP_RAW}.err")"

  # SAY IT ON THE TERMINAL TOO. This used to go only to syslog and email, so an
  # operator running the tool by hand -- or a self-test running it on their
  # behalf -- got silence and exit 1 with no reason. On a real VM the
  # commission check reported "a backup could not be taken" and there was
  # nothing anywhere to say why. The whole point of the .err file is diagnosis;
  # it should reach whoever is standing there.
  {
    printf '\n✗  Backup FAILED.\n'
    if [ -s "${BACKUP_RAW}.err" ]; then
      printf '   mariadb-dump said:\n'
      head -c 1200 "${BACKUP_RAW}.err" | sed 's/^/     /'
      printf '\n'
    else
      printf '   No stderr was captured, which usually means the dump never started.\n'
    fi
    printf '   Common causes, in the order worth checking:\n'
    printf '     df -h /                          # a full disk is the most common\n'
    printf '     doas podman ps --filter name=mariadb  # is the database running?\n'
    printf '     doas podman logs --tail 30 mariadb\n'
  } >&2
  # Email on failure. A backup that has been failing silently for months is
  # the single most common way people discover they have no backups -- at the
  # exact moment they need one. This is the alert most worth having: it is
  # rare, it is unambiguous, and there is nothing else that would tell you.
  if [ -x /usr/local/bin/wp-notify.sh ]; then
    _bb=$(mktemp)
    {
      printf 'The nightly database backup FAILED. Yesterday'"'"'s backup was kept.\n\n'
      [ -s "${BACKUP_RAW}.err" ] && { printf 'Error output:\n'; head -c 1000 "${BACKUP_RAW}.err"; printf '\n\n'; }
      printf 'Check:\n'
      printf '  wp-db-backup.sh            # run one now\n'
      printf '  validate-wordpress.sh --section backups\n'
      printf '  doas podman logs --tail 30 mariadb\n'
      printf '  df -h /                    # a full disk is a common cause\n'
    } > "$_bb"
    # Deliberately NOT deduplicated by content: a repeated failure is the
    # thing you most need to keep hearing about, and each night the error
    # text is likely identical.
    NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wp-db-backup \
      "Database backup FAILED" "$_bb"
    rm -f "$_bb"
  fi
  rm -f "${BACKUP_RAW}" "${BACKUP_RAW}.err" "${BACKUP_GZ_TMP}" "${BACKUP_FILE}" 2>/dev/null || true
  # DELIBERATE: no rotation on failure. Yesterday's good backup stays.
  exit 1
fi

rm -f "${BACKUP_RAW}" "${BACKUP_RAW}.err" 2>/dev/null || true
logger -t wp-db-backup "OK — ${BACKUP_FILE} ($(du -sh "${BACKUP_FILE}" | cut -f1))"

# Replicate off this VM. Deliberately AFTER the local backup is verified and
# rotation has run: a copy of a backup that failed verification is not worth
# sending, and a push failure must not prevent a good local backup from being
# kept. A failure here is reported and does not fail the local backup.
if [ -x /usr/local/bin/wasp-offsite-backup.sh ]; then
  # NOTE the path. This block used to write to "$_OFFLOG" and then read from a
  # hardcoded /tmp/.offsite.log -- two different files. So on a real VM the
  # push failed, the error was captured, and the line meant to report it read
  # an empty path and logged nothing. The operator saw "Newest backup is NOT
  # present off-VM" with no reason anywhere.
  _LAST_OFF_ERR=/etc/wp-install/offsite-last-error
  if /usr/local/bin/wasp-offsite-backup.sh push "${BACKUP_FILE}" >"$_OFFLOG" 2>&1; then
    logger -t wp-db-backup "off-VM copy sent and size-verified"
    rm -f "$_LAST_OFF_ERR"
    # Timestamp of the last SUCCESSFUL off-site copy. Its age is the only
    # signal that survives a silently-failing push -- an expired token keeps
    # failing identically forever, so "when did this last work" is the question
    # that actually detects it.
    date +%s > /etc/wp-install/offsite-last-ok 2>/dev/null || true
  else
    logger -t wp-db-backup "OFF-VM COPY FAILED — the local backup is fine, the remote copy is not"
    sed 's/^/  /' "$_OFFLOG" 2>/dev/null | logger -t wp-db-backup

    # PERSIST the reason. "The backup is not off-VM" is a symptom; the operator
    # needs the cause, and syslog rotates. Everything that reports offsite
    # health reads this file, so the answer is in the same place as the
    # complaint.
    mkdir -p /etc/wp-install 2>/dev/null || true
    {
      printf 'at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      printf 'file=%s\n' "$(basename "${BACKUP_FILE}")"
      echo '--- push output ---'
      tail -30 "$_OFFLOG" 2>/dev/null
    } > "$_LAST_OFF_ERR" 2>/dev/null || true
    chmod 600 "$_LAST_OFF_ERR" 2>/dev/null || true

    # And say it on the terminal, for anyone who ran this by hand.
    {
      echo ""
      echo "⚠  The local backup is fine. The OFF-VM copy failed:"
      tail -12 "$_OFFLOG" 2>/dev/null | sed 's/^/     /'
      echo "   Full reason kept at ${_LAST_OFF_ERR}"
      echo "   Check the destination and credentials:  doas wasp-offsite-backup.sh status"
    } >&2

    if [ -x /usr/local/bin/wp-notify.sh ]; then
      # No cooldown: an offsite copy that has been quietly failing is the same
      # class of problem as a backup that has been quietly failing.
      NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wasp-offsite \
        "Off-VM backup copy FAILED" "$_OFFLOG"
    fi
  fi
fi

# Step 4: rotate ONLY after a new backup passed all three verification
# gates. If any earlier step failed, we exited above and yesterday's
# good backup is safe.
find "${BACKUP_DIR}" -type f -name 'wp-db-*.sql.gz' -mtime +7 -delete 2>&1 \
  | logger -t wp-db-backup
