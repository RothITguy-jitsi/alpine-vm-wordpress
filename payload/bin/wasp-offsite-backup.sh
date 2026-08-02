#!/bin/sh
# =============================================================================
# wasp-offsite-backup.sh — copy database backups off this VM
# =============================================================================
#   wasp-offsite-backup.sh push [file]   send a backup (newest if omitted)
#   wasp-offsite-backup.sh verify        confirm the newest local backup is there
#   wasp-offsite-backup.sh list          what is stored remotely
#   wasp-offsite-backup.sh test          prove the destination works, end to end
#   wasp-offsite-backup.sh prune         apply remote retention
#   wasp-offsite-backup.sh status        configuration summary
#
# WHY THIS EXISTS
#
# A backup on the same VM as the thing it protects is not a backup. It shares
# the disk, the hypervisor, and the attacker. The single most common
# ransomware pattern against small hosting is: encrypt the site, then delete
# the backups sitting next to it — and the operator discovers both at once.
#
# THE PART THAT MATTERS MORE THAN THE TRANSPORT
#
# Whatever method is used, this VM holds a credential that can reach the
# backup destination. An attacker with root here can therefore reach it too.
# Copying backups off the VM does not, on its own, protect them from that
# attacker — it protects them from disk failure and from losing the VM.
#
# What closes the gap is making the destination APPEND-ONLY, so the credential
# stored here can add backups but cannot delete or overwrite them:
#
#   SSH/rsync : give the key a forced command in authorized_keys, e.g.
#               command="rrsync -no-del /srv/backups/wasp",restrict ssh-ed25519 ...
#               so the key cannot run arbitrary commands or delete anything.
#   S3        : an IAM policy granting s3:PutObject and s3:ListBucket but NOT
#               s3:DeleteObject, with Versioning and Object Lock enabled on
#               the bucket. Object Lock in compliance mode cannot be removed
#               even by the account root during the retention window.
#
# Without that, an attacker who owns this VM owns the backups as well, and the
# offsite copy is protection against accident rather than against malice. Both
# are worth having; they are not the same thing, and it should be a decision
# rather than an assumption. `status` says which one you have.
#
# CREDENTIALS live under /etc/wp-install, root-owned and 0400/0600. WordPress
# runs as uid 33 and cannot read them, so a compromise of the web application
# alone does not reach the backup destination — only a root compromise does.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi

CONF=/etc/wp-install/offsite.conf
SSH_KEY=/etc/wp-install/offsite-key
RCLONE_CONF=/etc/wp-install/rclone.conf
BACKUP_DIR="${BACKUP_DIR:-/root/wp-db-backups}"
OFFSITE_RETAIN="${OFFSITE_RETAIN:-14}"
AGE_RECIPIENT="${OFFSITE_AGE_RECIPIENT:-}"

# ── Encryption before it leaves the VM ───────────────────────────────────────
# A database dump is not an opaque blob. It contains password hashes, every
# user's email and real name, private and draft post content, and whatever
# plugins have written into wp_options -- API keys, form submissions, order
# records. Handing that to a storage provider in plaintext gives them, and
# anyone who reaches the bucket, all of it.
#
# age is used in PUBLIC-KEY mode, and that choice is the point rather than a
# detail: this VM holds only the RECIPIENT (public) key. It can encrypt
# backups and cannot decrypt them -- not the ones it sends, and not the ones
# already at the destination. So an attacker with root here cannot read the
# backups even though they can create them.
#
# That composes with an append-only destination: they cannot delete what is
# there and cannot read it either.
#
# THE COST, and it is real: if the private key is lost, every encrypted backup
# is permanently unrecoverable. An encrypted backup nobody can decrypt is not
# a backup. The private key belongs somewhere that is neither this VM nor the
# storage bucket.
#
# The LOCAL backup is deliberately left unencrypted. It never leaves the host,
# it is already behind the VM boundary, and keeping it readable is what allows
# wasp-selftest.sh to prove a restore actually works. Encrypting the copy that
# leaves your control while keeping the one that does not is the split that
# preserves both properties.
_encrypt_for_upload() {
  _src="$1"
  [ -n "$AGE_RECIPIENT" ] || { printf '%s' "$_src"; return 0; }
  if ! command -v age >/dev/null 2>&1; then
    _bad "Encryption is configured but 'age' is not installed — refusing to upload in plaintext"
    _note "  apk add age"
    return 1
  fi
  _enc="/tmp/$(basename "$_src").age"
  if age -r "$AGE_RECIPIENT" -o "$_enc" "$_src" 2>/tmp/.age.err; then
    printf '%s' "$_enc"; return 0
  fi
  _bad "Encryption FAILED — not uploading. $(head -c 160 /tmp/.age.err 2>/dev/null)"
  rm -f "$_enc" /tmp/.age.err
  return 1
}

[ -r "$CONF" ] && . "$CONF"
OFFSITE_METHOD="${OFFSITE_METHOD:-none}"

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_note() { printf '  %s\n' "$1"; }

_configured() { [ "$OFFSITE_METHOD" != "none" ] && [ -n "${OFFSITE_DEST:-}" ]; }

_ssh_opts() {
  # BatchMode so a missing/rejected key fails immediately instead of hanging a
  # cron job on a password prompt. StrictHostKeyChecking=yes with a known_hosts
  # captured at setup: accept-new would let a MITM substitute the destination
  # on first contact, which for a backup target means silently sending every
  # database dump somewhere else.
  printf '%s' "-i ${SSH_KEY} -o BatchMode=yes -o StrictHostKeyChecking=yes \
-o UserKnownHostsFile=/etc/wp-install/offsite-known_hosts -o ConnectTimeout=20"
}

push_one() {
  _f="${1:-}"
  [ -n "$_f" ] || _f=$(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1)
  [ -n "$_f" ] && [ -r "$_f" ] || { _bad "No backup file to send"; return 1; }
  # Encrypt first when configured, then send and verify THAT artifact -- the
  # ciphertext is a different size from the plaintext, so comparing the remote
  # copy against the local dump would always mismatch.
  _plain="$_f"
  _f=$(_encrypt_for_upload "$_f") || return 1
  _b=$(basename "$_f")
  _sz=$(stat -c %s "$_f")
  [ "$_f" != "$_plain" ] && _note "Encrypted to $(basename "$_f") before upload"

  case "$OFFSITE_METHOD" in
    scp)
      scp $(_ssh_opts) -q "$_f" "${OFFSITE_DEST}/${_b}" 2>/tmp/.offsite.err ;;
    rsync)
      # --partial so an interrupted transfer resumes rather than restarting;
      # a nightly dump over a slow link should not have to be perfect first time.
      rsync -q --partial --timeout=300 -e "ssh $(_ssh_opts)" \
            "$_f" "${OFFSITE_DEST}/" 2>/tmp/.offsite.err ;;
    rclone)
      rclone --config "$RCLONE_CONF" copyto --quiet \
             "$_f" "${OFFSITE_DEST}/${_b}" 2>/tmp/.offsite.err ;;
    *)
      _bad "Unknown method '${OFFSITE_METHOD}'"; return 1 ;;
  esac
  _rc=$?
  if [ "$_rc" -ne 0 ]; then
    _bad "Upload FAILED (${OFFSITE_METHOD}) — $(head -c 200 /tmp/.offsite.err 2>/dev/null)"
    rm -f /tmp/.offsite.err
    return 1
  fi
  rm -f /tmp/.offsite.err

  # Confirm the remote copy is the right SIZE rather than assuming the
  # transport told the truth. A silently truncated upload is the failure this
  # catches, and it is the one that looks fine until a restore.
  _rsz=$(remote_size "$_b")
  if [ -n "$_rsz" ] && [ "$_rsz" = "$_sz" ]; then
    _ok "Sent ${_b} ($(du -h "$_f" | cut -f1)) and confirmed its size remotely"
    [ "$_f" != "$_plain" ] && rm -f "$_f"
    return 0
  fi
  [ "$_f" != "$_plain" ] && rm -f "$_f"
  if [ -z "$_rsz" ]; then
    _bad "Uploaded ${_b} but could not read it back to confirm — treat as unverified"
    return 1
  fi
  _bad "Size mismatch after upload: local ${_sz}, remote ${_rsz}"
  return 1
}

remote_size() {
  _n="$1"
  case "$OFFSITE_METHOD" in
    scp|rsync)
      ssh $(_ssh_opts) "${OFFSITE_DEST%%:*}" \
        "stat -c %s '${OFFSITE_DEST#*:}/${_n}' 2>/dev/null" 2>/dev/null | tr -d '\r' ;;
    rclone)
      rclone --config "$RCLONE_CONF" size --json "${OFFSITE_DEST}/${_n}" 2>/dev/null \
        | sed -n 's/.*"bytes":[[:space:]]*\([0-9]*\).*/\1/p' ;;
  esac
}

list_remote() {
  case "$OFFSITE_METHOD" in
    scp|rsync)
      ssh $(_ssh_opts) "${OFFSITE_DEST%%:*}" \
        "ls -lh '${OFFSITE_DEST#*:}' 2>/dev/null" 2>/dev/null ;;
    rclone)
      rclone --config "$RCLONE_CONF" lsl "${OFFSITE_DEST}" 2>/dev/null ;;
  esac
}

case "${1:-status}" in
  status)
    echo ""
    echo "Off-VM backup"
    echo "━━━━━━━━━━━━━"
    if ! _configured; then
      echo "  NOT CONFIGURED — backups exist only on this VM."
      echo "  A backup on the same disk, hypervisor and attacker as the thing"
      echo "  it protects survives disk failure and nothing else."
      echo "  Configure: wasp-offsite-backup.sh setup   (or re-run the installer)"
      exit 0
    fi
    printf '  Method      : %s\n' "$OFFSITE_METHOD"
    printf '  Destination : %s\n' "$OFFSITE_DEST"
    printf '  Retention   : %s copies\n' "$OFFSITE_RETAIN"
    case "$OFFSITE_METHOD" in
      scp|rsync) [ -r "$SSH_KEY" ] && printf '  Key         : %s (%s)\n' "$SSH_KEY" "$(stat -c '%a %U' "$SSH_KEY")" ;;
      rclone)    [ -r "$RCLONE_CONF" ] && printf '  rclone conf : %s (%s)\n' "$RCLONE_CONF" "$(stat -c '%a %U' "$RCLONE_CONF")" ;;
    esac
    echo ""
    if [ -n "$AGE_RECIPIENT" ]; then
      printf '  Encryption : age, recipient %s…\n' "$(printf '%s' "$AGE_RECIPIENT" | cut -c1-20)"
      echo "               This VM holds only the public key: it can encrypt"
      echo "               backups and cannot read them, including the ones"
      echo "               already at the destination."
      echo "               Restore instructions: wasp-offsite-backup.sh restore-help"
    else
      echo "  Encryption : NONE — dumps leave this VM in plaintext."
      echo "               They contain password hashes, user emails, private"
      echo "               post content and whatever plugins put in wp_options."
    fi
    echo ""
    if [ "${OFFSITE_APPEND_ONLY:-unknown}" = "yes" ]; then
      echo "  Destination declared APPEND-ONLY — a root compromise here should"
      echo "  not be able to delete what has already been sent."
    else
      echo "  ⚠ Destination is NOT declared append-only."
      echo "    This VM holds a credential that can reach it, so an attacker"
      echo "    with root here can delete the backups too. That makes this"
      echo "    protection against disk failure, not against ransomware."
      echo "    SSH  : command=\"rrsync -no-del <path>\",restrict in authorized_keys"
      echo "    S3   : deny s3:DeleteObject; enable Versioning + Object Lock"
    fi ;;

  push)   _configured || { _bad "Off-VM backup is not configured"; exit 1; }
          push_one "${2:-}" ;;

  verify)
    _configured || { _bad "Off-VM backup is not configured"; exit 1; }
    _f=$(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1)
    [ -n "$_f" ] || { _bad "No local backup to compare against"; exit 1; }
    _b=$(basename "$_f")
    # When encryption is on, what was uploaded is the .age artifact, so that
    # is the name to look for. Size is not compared here because the
    # ciphertext is not retained locally after a successful push.
    [ -n "$AGE_RECIPIENT" ] && _b="${_b}.age"
    _sz=$(stat -c %s "$_f"); _rsz=$(remote_size "$_b")
    if [ -z "$_rsz" ]; then
      _bad "Newest local backup ${_b} is NOT present at the destination"
      _note "The local backup succeeded and the copy did not — which is the"
      _note "state that looks healthy right up until you need the offsite copy."
      exit 1
    fi
    if [ -n "$AGE_RECIPIENT" ]; then
      _ok "Newest backup is present remotely as ${_b} (${_rsz} bytes, encrypted)"
    elif [ "$_rsz" = "$_sz" ]; then
      _ok "Newest backup ${_b} is present remotely, same size"
    else
      _bad "Remote ${_b} is ${_rsz} bytes, local is ${_sz}"; exit 1
    fi ;;

  list)   _configured || { _bad "Not configured"; exit 1; }
          echo ""; echo "Remote backups:"; list_remote | sed 's/^/  /' ;;

  test)
    _configured || { _bad "Not configured"; exit 1; }
    echo "Testing the destination end to end…"
    _t=$(mktemp -d)/wasp-offsite-test-$(date -u +%s).txt
    mkdir -p "$(dirname "$_t")"
    printf 'WASP offsite connectivity test %s\n' "$(date -u)" > "$_t"
    if push_one "$_t"; then
      _ok "Write and read-back both work"
      _note "Note: this proves the destination ACCEPTS data. It does not prove"
      _note "the credential is restricted — check that separately, because a"
      _note "key that can also delete is the difference between a backup and a"
      _note "hostage."
    else
      _bad "Test upload failed — see the error above"; rm -f "$_t"; exit 1
    fi
    rm -f "$_t" ;;

  prune)
    _configured || { _bad "Not configured"; exit 1; }
    # Deliberately not automatic after every push. If the destination is
    # append-only -- which is the configuration worth having -- pruning will
    # fail, and that failure is correct rather than a fault to be fixed by
    # granting delete rights.
    echo "Applying remote retention (keep ${OFFSITE_RETAIN})…"
    case "$OFFSITE_METHOD" in
      scp|rsync)
        ssh $(_ssh_opts) "${OFFSITE_DEST%%:*}" \
          "ls -1t '${OFFSITE_DEST#*:}'/*.sql.gz 2>/dev/null | tail -n +$((OFFSITE_RETAIN+1)) | xargs -r rm -f" \
          2>&1 | sed 's/^/  /' ;;
      rclone)
        rclone --config "$RCLONE_CONF" delete --min-age "${OFFSITE_RETAIN}d" \
               "${OFFSITE_DEST}" 2>&1 | sed 's/^/  /' ;;
    esac
    echo "  (A failure here is expected and correct on an append-only destination.)" ;;

  restore-help)
    echo ""
    echo "Restoring an encrypted off-VM backup"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Not done on this VM. It holds only the public key by design and"
    echo "  cannot decrypt anything — which is the property that makes a root"
    echo "  compromise here unable to read your backups."
    echo ""
    echo "  On a machine that has the PRIVATE key:"
    echo "    1. Fetch the archive from the destination"
    echo "    2. age -d -i /path/to/age-key.txt -o backup.sql.gz backup.sql.gz.age"
    echo "    3. gzip -t backup.sql.gz            # confirm it is intact"
    echo "    4. gzip -dc backup.sql.gz | mariadb -u root -p wordpress"
    echo ""
    echo "  Do step 2 and 3 NOW, once, against a real backup — before you need"
    echo "  it. An encrypted backup whose key is lost or wrong is not a backup,"
    echo "  and the moment you discover that should not be an incident."
    echo ""
    echo "  The private key belongs somewhere that is neither this VM nor the"
    echo "  storage bucket. Both are things an attacker may already hold." ;;

  *) sed -n '4,10p' "$0" ;;
esac
