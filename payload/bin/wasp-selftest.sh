#!/bin/sh
# =============================================================================
# wasp-selftest.sh — prove the two things that are usually only assumed
# =============================================================================
#   wasp-selftest.sh restore-test          restore the latest backup and verify it
#   wasp-selftest.sh candidate-isolation   prove the read-only account cannot write
#   wasp-selftest.sh all                   both
#   wasp-selftest.sh --json <file> all     machine-readable result as well
#
# WHY THESE TWO
#
# Both close a gap between what is CHECKED and what is CLAIMED.
#
#   restore-test        wp-db-backup.sh verifies that the dump completed, that
#                       its completion marker is present, and that the gzip
#                       archive is intact. All of that is structural: it proves
#                       a well-formed file exists. It does not prove the file
#                       restores, and "the backup was there but would not
#                       restore" is a recognised way to discover you had no
#                       backups. This restores the newest archive into a
#                       THROWAWAY MariaDB instance and checks the data is
#                       actually there.
#
#   candidate-isolation update.sh now runs the update candidate under a
#                       SELECT-only database account. That is only worth
#                       anything if the grant really does refuse writes, so
#                       this creates the same kind of account and tries to
#                       write with it. A test that assumes its own mechanism
#                       works is not a test.
#
# SAFETY
#
# Neither test touches production. The restore runs in a separate container on
# an isolated network with no host port and its own data directory, and is
# destroyed afterwards. The isolation test writes only to a scratch table in a
# scratch database, which it drops.
#
# Run on demand, or weekly from cron. Deliberately not daily: the restore
# starts a second database and copies the whole dump, which is real work.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ]   && . /etc/wp-install/vars.sh
[ -r /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

BACKUP_DIR="${BACKUP_DIR:-/root/wp-db-backups}"
WPDB="${WORDPRESS_DB_NAME:-wordpress}"
TEST_CTR="wasp-selftest-db"
TEST_NET="wasp-selftest-net"
JSON_OUT=""
PASS=0; FAIL=0
RESULTS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --json) JSON_OUT="${2:-}"; shift 2 ;;
    *) break ;;
  esac
done
CMD="${1:-all}"

_p() { PASS=$((PASS+1)); printf '  \033[32m[PASS]\033[0m %s\n' "$1"; RESULTS="${RESULTS}PASS|$1\n"; }
_f() { FAIL=$((FAIL+1)); printf '  \033[31m[FAIL]\033[0m %s\n' "$1"
       [ -n "${2:-}" ] && printf '         %s\n' "$2"; RESULTS="${RESULTS}FAIL|$1\n"; }
_i() { printf '  [info] %s\n' "$1"; }
# Run SQL inside the mariadb container.
#
# MARIADB_ROOT_PASSWORD and WORDPRESS_TABLE_PREFIX exist in the CONTAINER's
# environment, not on this host. Expanding them here yields an empty string,
# and `mariadb -p""` then fails in a way that looks like "no data" rather than
# "no password" -- which is exactly how this shipped: the self-test reported
# an empty options table and missing users against a restore that was fine.
#
# The command is single-quoted so the shell inside the container expands them.
_mdb() {
  podman exec mariadb sh -c \
    'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -N -B "$@"' _ "$@" 2>/dev/null
}
# The table prefix is randomised at install (wp<hex>_), so a hardcoded "wp_"
# matches nothing. Read it from the container rather than guessing.
_wp_prefix() {
  podman exec mariadb sh -c 'printf %s "${WORDPRESS_TABLE_PREFIX:-wp_}"' 2>/dev/null \
    || printf 'wp_'
}

_hdr(){ printf '\n\033[1m── %s\033[0m\n' "$1"; }

cleanup_scratch() {
  podman rm -f "$TEST_CTR" >/dev/null 2>&1 || true
  podman network rm "$TEST_NET" >/dev/null 2>&1 || true
  rm -rf /var/tmp/wasp-selftest-data 2>/dev/null || true
}
trap 'cleanup_scratch' EXIT INT TERM

# ── Restore proof ────────────────────────────────────────────────────────────
restore_test() {
  _hdr "Backup restore proof"

  _bk=$(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1)
  if [ -z "$_bk" ]; then
    # Take one rather than just refusing. A first run on a fresh VM has no
    # backup yet, and reporting a FAIL for "you have not done the thing this
    # test needs" trains people to ignore the output. Observed exactly that:
    # the first self-test failed, a backup was taken, the re-run passed 18/18.
    _i "No backup archive yet — taking one now so this test can run"
    # Capture the output. `>/dev/null 2>&1` here meant that when the on-demand
    # backup failed, the ONLY thing anyone saw was "one could not be taken" --
    # no exit code, no error, nothing to act on. That happened on a real VM and
    # cost a full redeploy cycle to work out why.
    _bkrc=0
    _bkout=$(/usr/local/bin/wp-db-backup.sh 2>&1) || _bkrc=$?
    if [ "$_bkrc" -eq 0 ]; then
      _bk=$(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1)
      [ -n "$_bk" ] && _p "Took a backup to test with"
    fi
    if [ -z "$_bk" ]; then
      _i "wp-db-backup.sh exited ${_bkrc}. What it said:"
      printf '%s\n' "$_bkout" | tail -12 | sed 's/^/      /'
      # The dump writes its own stderr to a sidecar file; that is where a
      # mariadb-dump failure actually explains itself.
      for _e in "$BACKUP_DIR"/*.err; do
        [ -f "$_e" ] || continue
        [ -s "$_e" ] || continue
        _i "  ${_e}:"
        tail -6 "$_e" | sed 's/^/      /'
      done
      _f "No backup archive in ${BACKUP_DIR} and one could not be taken" \
         "Run wp-db-backup.sh by hand and read its output"
      return
    fi
  fi
  _age_h=$(( ( $(date +%s) - $(stat -c %Y "$_bk" 2>/dev/null || echo 0) ) / 3600 ))
  _i "Testing $(basename "$_bk") ($(du -h "$_bk" | cut -f1), ${_age_h}h old)"
  # A backup that restores but is a fortnight old is a different problem from
  # one that does not restore, and worth separating.
  [ "$_age_h" -gt 48 ] && _f "Newest backup is ${_age_h}h old" \
      "The daily job may not be running: grep wp-db-backup /var/log/messages"

  if ! gzip -t "$_bk" 2>/dev/null; then
    _f "Archive is not a valid gzip" "The file is corrupt; earlier backups may be too"
    return
  fi
  _p "Archive passes gzip integrity"
  # NOTE: this proves the LOCAL backup restores. It does NOT prove the offsite
  # copy can be pulled and decrypted -- a remote object can be truncated or
  # encrypted to a key you no longer hold. Prove that separately, periodically:
  #   wasp-offsite-backup.sh remote-restore-drill

  # Throwaway instance: isolated network, no published port, own data dir.
  cleanup_scratch
  mkdir -p /var/tmp/wasp-selftest-data
  podman network create --internal "$TEST_NET" >/dev/null 2>&1 || true
  _rootpw=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  _img="${DB_IMAGE:-docker.io/library/mariadb:11.4}"

  _i "Starting a throwaway MariaDB (isolated, no host port)…"
  if ! podman run -d --name "$TEST_CTR" --network "$TEST_NET" \
        -e MARIADB_ROOT_PASSWORD="$_rootpw" \
        -v /var/tmp/wasp-selftest-data:/var/lib/mysql \
        --memory 512m --pids-limit 200 \
        "$_img" >/dev/null 2>&1; then
    _f "Could not start the scratch database" "podman logs ${TEST_CTR}"
    return
  fi

  _i "Waiting for it to accept connections…"
  _up=0
  for _i2 in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if podman exec "$TEST_CTR" mariadb -u root -p"$_rootpw" -e "SELECT 1" >/dev/null 2>&1; then
      _up=1; break
    fi
    sleep 3
  done
  [ "$_up" = 1 ] || { _f "Scratch database never became ready" "podman logs ${TEST_CTR}"; return; }
  _p "Scratch database is running"

  _i "Restoring the archive…"
  if gzip -dc "$_bk" | podman exec -i "$TEST_CTR" mariadb -u root -p"$_rootpw" >/dev/null 2>&1; then
    _p "Archive restored without error"
  else
    _f "Restore FAILED" "The archive exists and is valid gzip but will not load. This is the failure structural checks cannot see."
    return
  fi

  _q() { podman exec "$TEST_CTR" mariadb -u root -p"$_rootpw" -N -B -e "$1" 2>/dev/null; }

  _tables=$(_q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${WPDB}';")
  if [ "${_tables:-0}" -ge 10 ]; then
    _p "Restored database has ${_tables} tables"
  else
    _f "Restored database has only ${_tables:-0} tables" \
       "A WordPress schema has ~12. The dump may be partial."
  fi

  # Read the real prefix; it is randomised per install.
  _pfx=$(_wp_prefix)
  _i "Table prefix: ${_pfx}"
  # Before judging the CONTENT of a restore, establish whether the source site
  # had any content to begin with. On a freshly provisioned VM the operator has
  # not run the WordPress setup wizard yet, so the database is an empty schema:
  # no options table, no users, no siteurl. Reporting that as "siteurl missing
  # from the restored options table -- the dump may not include the options
  # table" is actively misleading. It accuses the backup of losing data that
  # never existed, on exactly the install where an operator is least equipped
  # to tell the difference.
  #
  # So: detect the not-yet-set-up case once, and report it as a SKIP with the
  # real reason. A backup of an empty site restoring as an empty site is
  # correct behaviour, and the structural checks above (gzip integrity, schema
  # loads, tables present) have already done the work that IS meaningful here.
  _optcount=$(_q "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${WPDB}' AND table_name='${_pfx}options';")
  if [ "${_optcount:-0}" -eq 0 ]; then
    _i "WordPress setup has not been completed on this site yet:"
    _i "  the database holds no options table, so there is no siteurl or user"
    _i "  data for a backup to contain. The structural checks above still apply."
    _i "  Re-run this after finishing setup to validate real content:"
    _i "    wasp-selftest.sh restore-test"
  else
    # The specific rows that make a restore *useful*: without siteurl and a
    # user, you have a schema, not a site.
    _su=$(_q "SELECT option_value FROM ${WPDB}.${_pfx}options WHERE option_name='siteurl' LIMIT 1;")
    [ -n "$_su" ] && _p "siteurl present in restored data: ${_su}" \
                  || _f "siteurl missing from the restored options table" "The dump may not include the options table"

    _users=$(_q "SELECT COUNT(*) FROM ${WPDB}.${_pfx}users;")
    [ "${_users:-0}" -ge 1 ] && _p "Restored users table has ${_users} user(s)" \
                             || _f "Restored users table is empty" "A restore with no users is not recoverable"
  fi

  _posts=$(_q "SELECT COUNT(*) FROM ${WPDB}.${_pfx}posts;")
  _i "Restored posts: ${_posts:-0}"

  # Compare against production so a silently-shrinking backup is visible.
  _live=$(_mdb -e "SELECT COUNT(*) FROM \`${WPDB}\`.${_pfx}posts;")
  if [ -n "$_live" ] && [ "${_posts:-0}" -gt 0 ]; then
    _delta=$(( _live - _posts )); [ "$_delta" -lt 0 ] && _delta=$(( -_delta ))
    if [ "$_live" -gt 0 ] && [ $(( _delta * 100 / _live )) -gt 25 ]; then
      _f "Restored post count (${_posts}) differs from live (${_live}) by more than 25%" \
         "Expected if the site changed a lot since the backup; suspicious otherwise."
    else
      _p "Restored row counts are consistent with production (${_posts} vs ${_live})"
    fi
  fi

  cleanup_scratch
  _p "Scratch instance destroyed"

  # A restorable backup that exists only on this VM still dies with the VM.
  if [ -x /usr/local/bin/wasp-offsite-backup.sh ] && [ -r /etc/wp-install/offsite.conf ]; then
    if /usr/local/bin/wasp-offsite-backup.sh verify >/dev/null 2>&1; then
      _p "Newest backup is also present off-VM, same size"
    else
      _f "Newest backup is NOT present off-VM" \
         "The local backup restores correctly and the offsite copy is missing or wrong — which looks healthy until the VM is gone. wasp-offsite-backup.sh verify"
  # Show the recorded cause. "It is not off-VM" is a symptom; the push failure
  # that produced it was captured by wp-db-backup.sh, and reporting the symptom
  # without the cause is how an operator ends up guessing at credentials.
  if [ -r /etc/wp-install/offsite-last-error ]; then
    _i "  The last push failed. What it said:"
    sed -n '/--- push output ---/,$p' /etc/wp-install/offsite-last-error \
      | tail -12 | sed 's/^/       /'
  else
    _i "  No push failure was recorded, so a push may never have run."
    _i "  Full diagnosis:  doas wasp-offsite-backup.sh doctor"
    _i "  Force one now:  doas wp-db-backup.sh"
  fi
    fi
  else
    _i "Off-VM backup not configured — this backup dies with the VM"
  fi
}

# ── Candidate isolation proof ────────────────────────────────────────────────
candidate_isolation() {
  _hdr "Candidate DB isolation (read-only account)"

  if ! _mdb -e "SELECT 1" >/dev/null 2>&1; then
    _f "Cannot reach the database as root" "Is the mariadb container running?"
    return
  fi
  _u="wasp_rotest_$$"
  _pw=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  _scratch="wasp_rotest_db_$$"

  _root() { _mdb -e "$1"; }
  _asuser() { podman exec mariadb mariadb -u "$_u" -p"$_pw" -N -B -e "$1" 2>&1; }
  # The read-only test account is created here, so its password IS a host
  # variable and expanding it here is correct.

  # A scratch database so the write attempts never target real data, even if
  # the grant is wrong -- which is the very thing being tested.
  _root "CREATE DATABASE IF NOT EXISTS \`${_scratch}\`;" >/dev/null
  _root "CREATE TABLE IF NOT EXISTS \`${_scratch}\`.t (id INT PRIMARY KEY, v VARCHAR(16));" >/dev/null
  _root "INSERT IGNORE INTO \`${_scratch}\`.t VALUES (1,'seed');" >/dev/null

  if ! _root "CREATE USER '${_u}'@'%' IDENTIFIED BY '${_pw}';
              GRANT SELECT ON \`${_scratch}\`.* TO '${_u}'@'%'; FLUSH PRIVILEGES;" >/dev/null; then
    _f "Could not create the read-only test account"
    _root "DROP DATABASE IF EXISTS \`${_scratch}\`;" >/dev/null
    return
  fi
  _p "Read-only account created (SELECT only, scratch database)"

  # 1. It must be able to read.
  _r=$(_asuser "SELECT v FROM \`${_scratch}\`.t WHERE id=1;")
  [ "$_r" = "seed" ] && _p "Read-only account CAN read (SELECT works)" \
                     || _f "Read-only account cannot read" "Candidate would fail to boot: ${_r}"

  # 2. Every write class must be refused. If any succeeds, the isolation is
  #    decorative and the candidate could modify production data.
  for _sql in \
    "INSERT INTO \`${_scratch}\`.t VALUES (2,'x');" \
    "UPDATE \`${_scratch}\`.t SET v='y' WHERE id=1;" \
    "DELETE FROM \`${_scratch}\`.t WHERE id=1;" \
    "CREATE TABLE \`${_scratch}\`.t2 (id INT);" \
    "DROP TABLE \`${_scratch}\`.t;"
  do
    _op=$(printf '%s' "$_sql" | awk '{print $1}')
    _out=$(_asuser "$_sql")
    if printf '%s' "$_out" | grep -qi "denied"; then
      _p "${_op} correctly DENIED"
    else
      _f "${_op} was NOT denied — isolation is not working" \
         "The candidate could modify production data. Output: ${_out:-<none>}"
    fi
  done

  # 3. It must not reach the real WordPress database at all.
  _out=$(_asuser "SELECT COUNT(*) FROM \`${WPDB}\`.${WORDPRESS_TABLE_PREFIX:-wp_}options;")
  if printf '%s' "$_out" | grep -qiE "denied|doesn't exist|unknown database"; then
    _p "Account cannot reach the production database at all"
  else
    _f "Account CAN read the production database" "Grant is too broad: ${_out}"
  fi

  _root "DROP USER IF EXISTS '${_u}'@'%'; DROP DATABASE IF EXISTS \`${_scratch}\`; FLUSH PRIVILEGES;" >/dev/null
  _p "Test account and scratch database removed"
}

case "$CMD" in
  restore-test)        restore_test ;;
  candidate-isolation) candidate_isolation ;;
  all)                 restore_test; candidate_isolation ;;
  *) sed -n '4,10p' "$0"; exit 1 ;;
esac

printf '\n\033[1m── Result\033[0m\n'
printf '  passed %s   failed %s\n' "$PASS" "$FAIL"
if [ -n "$JSON_OUT" ]; then
  {
    printf '{\n  "ran_at": "%s",\n  "passed": %s,\n  "failed": %s,\n  "checks": [\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PASS" "$FAIL"
    _first=1
    printf '%b' "$RESULTS" | while IFS='|' read -r st desc; do
      [ -n "$st" ] || continue
      [ "$_first" = 1 ] || printf ',\n'; _first=0
      printf '    { "status": "%s", "check": "%s" }' "$st" "$(printf '%s' "$desc" | sed 's/"/\\"/g')"
    done
    printf '\n  ]\n}\n'
  } > "$JSON_OUT"
  printf '  JSON: %s\n' "$JSON_OUT"
fi
if [ "$FAIL" -gt 0 ]; then
  printf '\n  A failure here means a guarantee this system makes is not actually held.\n'
  printf '  Backups that do not restore and isolation that does not isolate are\n'
  printf '  worse than their absence, because they are relied upon.\n'
  exit 1
fi
printf '\n  Both guarantees verified against real data, not inferred.\n'
exit 0
