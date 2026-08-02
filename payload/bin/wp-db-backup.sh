#!/bin/sh
# wp-db-backup.sh — verified daily MariaDB backup. Called from cron.
# Design mirrors do_db_update()'s in-flight backup step in update.sh.
set -eu
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
      printf '  podman logs --tail 30 mariadb\n'
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
  if /usr/local/bin/wasp-offsite-backup.sh push "${BACKUP_FILE}" >/tmp/.offsite.log 2>&1; then
    logger -t wp-db-backup "off-VM copy sent and size-verified"
  else
    logger -t wp-db-backup "OFF-VM COPY FAILED — the local backup is fine, the remote copy is not"
    sed 's/^/  /' /tmp/.offsite.log 2>/dev/null | logger -t wp-db-backup
    if [ -x /usr/local/bin/wp-notify.sh ]; then
      # No cooldown: an offsite copy that has been quietly failing is the same
      # class of problem as a backup that has been quietly failing.
      NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wasp-offsite \
        "Off-VM backup copy FAILED" /tmp/.offsite.log
    fi
  fi
  rm -f /tmp/.offsite.log
fi

# Step 4: rotate ONLY after a new backup passed all three verification
# gates. If any earlier step failed, we exited above and yesterday's
# good backup is safe.
find "${BACKUP_DIR}" -type f -name 'wp-db-*.sql.gz' -mtime +7 -delete 2>&1 \
  | logger -t wp-db-backup
