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
# Read AFTER the config is sourced. It was previously assigned above the
# `. "$CONF"` line, so it was ALWAYS empty: an operator who configured
# encryption at install got plaintext uploads, and `status` truthfully
# reported "Encryption : NONE" — which reads as "you did not set it up"
# rather than "the setting is being ignored".
#
# Found on a live VM whose vars.sh held a valid age1 recipient while every
# archive in the bucket was an unencrypted .sql.gz.
AGE_RECIPIENT="${OFFSITE_AGE_RECIPIENT:-}"

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
    s3|rclone)
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
    s3|rclone)
      rclone --config "$RCLONE_CONF" size --json "${OFFSITE_DEST}/${_n}" 2>/dev/null \
        | sed -n 's/.*"bytes":[[:space:]]*\([0-9]*\).*/\1/p' ;;
  esac
}

list_remote() {
  case "$OFFSITE_METHOD" in
    scp|rsync)
      ssh $(_ssh_opts) "${OFFSITE_DEST%%:*}" \
        "ls -lh '${OFFSITE_DEST#*:}' 2>/dev/null" 2>/dev/null ;;
    s3|rclone)
      rclone --config "$RCLONE_CONF" lsl "${OFFSITE_DEST}" 2>/dev/null ;;
  esac
}

# ── Setup ────────────────────────────────────────────────────────────────────
do_init() {
  echo ""
  echo "Off-VM backup setup"
  echo "━━━━━━━━━━━━━━━━━━━"
  mkdir -p /etc/wp-install; chmod 755 /etc/wp-install

  # ── SSH key ────────────────────────────────────────────────────────────────
  # Generated HERE rather than copied in. A key made on this host and never
  # transmitted has no window in which it existed somewhere else, and the
  # public half is the only part that needs to travel.
  if [ -f "$SSH_KEY" ]; then
    echo "  SSH key already exists at ${SSH_KEY} — keeping it."
  else
    printf "  Generate an SSH key for backup transport? [Y/n] : "
    read -r _a
    case "${_a:-y}" in
      n|N) : ;;
      *)
        ssh-keygen -t ed25519 -N "" -C "wasp-backup-$(hostname)" -f "$SSH_KEY" >/dev/null 2>&1 \
          || { _bad "ssh-keygen failed"; return 1; }
        chmod 400 "$SSH_KEY"; chmod 444 "${SSH_KEY}.pub"
        echo "  ✔ Key generated (private key is 0400 root-only)"
        ;;
    esac
  fi
  if [ -f "${SSH_KEY}.pub" ]; then
    echo ""
    echo "  ── Install this on the BACKUP HOST ──────────────────────────────"
    echo ""
    echo "  Append to ~/.ssh/authorized_keys there, WITH the forced command:"
    echo ""
    printf '    command="rrsync -no-del /srv/backups/wasp",restrict %s\n' "$(cat "${SSH_KEY}.pub")"
    echo ""
    echo "  The command= prefix is the part that matters. Without it this key"
    echo "  can run anything, and anyone who takes root on this VM can delete"
    echo "  every backup it ever sent. With it, the key can add files and"
    echo "  nothing else — which is what makes the copy survive a compromise"
    echo "  here rather than merely surviving a disk failure."
    echo ""
    echo "  rrsync ships with rsync; on Debian it is at"
    echo "  /usr/share/doc/rsync/scripts/rrsync (may need chmod +x)."
    echo ""
  fi

  # ── age encryption ─────────────────────────────────────────────────────────
  echo "  ── Encryption ───────────────────────────────────────────────────"
  if [ -n "${AGE_RECIPIENT:-}" ]; then
    echo "  Already configured for: ${AGE_RECIPIENT}"
    echo "  Re-running would orphan every backup already encrypted to the old key."
  else
    echo "  This VM must NOT hold the private key. That is the whole property:"
    echo "  holding only the public half means an attacker with root here can"
    echo "  create backups and cannot read any of them — not the ones it sends,"
    echo "  and not the ones already stored."
    echo ""
    echo "  Generate the keypair on YOUR machine and paste the PUBLIC line here."
    echo "  Platform-by-platform instructions are in the README under"
    echo "  \"Off-VM Backup -> Creating the encryption key\"."
    echo ""
    echo "    age-keygen -o wasp-backup-key.txt"
    echo ""
    echo "  That prints a line starting 'Public key: age1...'. Paste that."
    echo "  Keep wasp-backup-key.txt somewhere that is neither this VM nor the"
    echo "  backup destination — an attacker may already hold both."
    echo ""
    while :; do
      printf "  age public key (age1..., blank = no encryption) : "
      read -r _pk
      [ -z "$_pk" ] && { echo "  No encryption — backups leave this VM in plaintext."; break; }
      case "$_pk" in
        AGE-SECRET-KEY*)
          # Refused, not accepted-with-a-warning. Storing the private key here
          # would silently discard the only reason this design is worth
          # anything, while appearing to work perfectly.
          _bad "That is a PRIVATE key. It must never be on this VM."
          _note "Paste the line beginning 'age1', not the one beginning AGE-SECRET-KEY."
          continue ;;
      esac
      if printf '%s' "$_pk" | grep -qE '^age1[0-9a-z]{50,}$'; then
        AGE_RECIPIENT="$_pk"
        echo "  ✔ Backups will be encrypted to ${_pk}"
        echo "    Verify you can DECRYPT with the matching private key before"
        echo "    relying on this:  wasp-offsite-backup.sh restore --file <name> --to-file /tmp/t.sql.gz"
        break
      fi
      _bad "Doesn't look like an age public key (expected age1...)."
    done
  fi
  # ── Destination ────────────────────────────────────────────────────────────
  echo ""
  echo "  ── Destination ──────────────────────────────────────────────────"
  printf "  Method [scp/rsync/rclone] (blank = keep %s) : " "${OFFSITE_METHOD:-none}"
  read -r _m
  case "$_m" in scp|rsync|rclone) OFFSITE_METHOD="$_m" ;; esac
  if [ "${OFFSITE_METHOD:-none}" != "none" ]; then
    printf "  Destination (blank = keep '%s') : " "${OFFSITE_DEST:-unset}"
    read -r _d
    [ -n "$_d" ] && OFFSITE_DEST="$_d"
  fi

  # Pin the destination host key now, so transfers use
  # StrictHostKeyChecking=yes. For a backup target, accept-new would let a
  # machine-in-the-middle receive every database dump on first contact.
  case "${OFFSITE_METHOD:-none}" in
    scp|rsync)
      _h="${OFFSITE_DEST#*@}"; _h="${_h%%:*}"
      if [ -n "$_h" ] && ssh-keyscan -T 10 "$_h" > /etc/wp-install/offsite-known_hosts 2>/dev/null \
         && [ -s /etc/wp-install/offsite-known_hosts ]; then
        chmod 644 /etc/wp-install/offsite-known_hosts
        echo "  ✔ Host key pinned for ${_h}"
      else
        _bad "Could not reach ${_h:-the destination} to capture its host key"
        _note "Transfers will fail until: ssh-keyscan ${_h} >> /etc/wp-install/offsite-known_hosts"
      fi ;;
  esac

  {
    printf 'OFFSITE_METHOD=%s\n'        "${OFFSITE_METHOD:-none}"
    printf 'OFFSITE_DEST=%s\n'          "${OFFSITE_DEST:-}"
    printf 'OFFSITE_RETAIN=%s\n'        "${OFFSITE_RETAIN:-14}"
    printf 'OFFSITE_APPEND_ONLY=%s\n'   "${OFFSITE_APPEND_ONLY:-unknown}"
    printf 'OFFSITE_AGE_RECIPIENT=%s\n' "${AGE_RECIPIENT:-}"
  } > "$CONF"
  chmod 600 "$CONF"
  echo ""
  echo "  ✔ Written to ${CONF}"
  echo ""
  echo "  Next, in this order:"
  echo "    1. Install the SSH key on the backup host (above)"
  echo "    2. wasp-offsite-backup.sh test        — prove it accepts data"
  echo "    3. wp-db-backup.sh                    — take one"
  echo "    4. wasp-offsite-backup.sh restore --list"
  echo "    5. Decrypt one NOW, before you need it:"
  echo "       wasp-offsite-backup.sh restore --file <name> --to-file /tmp/t.sql.gz"
}

# ── Restore ──────────────────────────────────────────────────────────────────
# The VM cannot decrypt on its own -- that is the point of public-key mode --
# so the private key has to be supplied for this one operation. It is read
# into a variable, used, and dropped; it is never written to this VM's disk.
do_restore() {
  _file=""; _keyfile=""; _tofile=""; _todb=0; _list=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --list)        _list=1; shift ;;
      --file)        _file="${2:-}"; shift 2 ;;
      --key-file)    _keyfile="${2:-}"; shift 2 ;;
      --to-file)     _tofile="${2:-}"; shift 2 ;;
      --to-database) _todb=1; shift ;;
      *) shift ;;
    esac
  done

  if [ "$_list" = "1" ] || [ -z "$_file" ]; then
    echo ""
    echo "Available backups"
    echo "━━━━━━━━━━━━━━━━━"
    echo "  Local (unencrypted, on this VM):"
    ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -10 | sed 's|.*/|    |' || echo "    (none)"
    if _configured; then
      echo "  Remote:"
      list_remote 2>/dev/null | sed 's/^/    /' | head -15 || echo "    (unreadable)"
    fi
    echo ""
    echo "  Restore:  wasp-offsite-backup.sh restore --file <name> --to-file /tmp/out.sql.gz"
    echo "            add --to-database to load it (destructive — see below)"
    return 0
  fi

  _work=$(mktemp -d) || return 1
  trap 'rm -rf "$_work"' RETURN 2>/dev/null || true
  _local="${BACKUP_DIR}/${_file}"

  if [ -f "$_local" ]; then
    cp "$_local" "$_work/$_file"
    _note "Using the local copy of ${_file}"
  else
    _configured || { _bad "No local copy and no destination configured"; rm -rf "$_work"; return 1; }
    _note "Fetching ${_file} from the destination…"
    case "$OFFSITE_METHOD" in
      scp|rsync) scp $(_ssh_opts) -q "${OFFSITE_DEST}/${_file}" "$_work/$_file" ;;
      s3|rclone) rclone --config "$RCLONE_CONF" copyto --quiet "${OFFSITE_DEST}/${_file}" "$_work/$_file" ;;
    esac || { _bad "Could not fetch ${_file}"; rm -rf "$_work"; return 1; }
  fi

  _src="$_work/$_file"
  case "$_file" in
    *.age)
      command -v age >/dev/null 2>&1 || { _bad "age is not installed (apk add age)"; rm -rf "$_work"; return 1; }
      if [ -n "$_keyfile" ]; then
        [ -r "$_keyfile" ] || { _bad "Cannot read ${_keyfile}"; rm -rf "$_work"; return 1; }
        age -d -i "$_keyfile" -o "${_src%.age}" "$_src" 2>/tmp/.age.err \
          || { _bad "Decryption failed — wrong key? $(head -c 160 /tmp/.age.err)"; rm -rf "$_work"; return 1; }
      else
        echo ""
        echo "  ${_file} is encrypted. This VM holds only the public key and"
        echo "  cannot decrypt it — which is the property that stops an attacker"
        echo "  here reading your backups."
        echo ""
        echo "  Paste the AGE-SECRET-KEY line. It is used for this restore and"
        echo "  not written to this VM's disk."
        printf "  Private key: "
        stty -echo 2>/dev/null; read -r _sk; stty echo 2>/dev/null; echo
        case "$_sk" in
          AGE-SECRET-KEY*) : ;;
          *) _bad "That does not look like an age private key"; _sk=""; rm -rf "$_work"; return 1 ;;
        esac
        _kf="$_work/k"; printf '%s\n' "$_sk" > "$_kf"; chmod 600 "$_kf"; _sk=""
        age -d -i "$_kf" -o "${_src%.age}" "$_src" 2>/tmp/.age.err \
          || { _bad "Decryption failed — wrong key? $(head -c 160 /tmp/.age.err)"; rm -rf "$_work"; return 1; }
        rm -f "$_kf"
      fi
      rm -f /tmp/.age.err
      _src="${_src%.age}"
      _ok "Decrypted"
      ;;
  esac

  gzip -t "$_src" 2>/dev/null && _ok "Archive integrity verified" \
    || { _bad "Decrypted file is not valid gzip"; rm -rf "$_work"; return 1; }

  if [ -n "$_tofile" ]; then
    cp "$_src" "$_tofile" && _ok "Written to ${_tofile}"
    _note "Inspect it: gzip -dc '${_tofile}' | head -20"
    rm -rf "$_work"; return 0
  fi

  if [ "$_todb" = "1" ]; then
    echo ""
    echo "  ⚠  This REPLACES the live database. Everything since this backup"
    echo "     was taken is lost."
    echo ""
    # A backup of the current state first, unprompted. Restoring the wrong
    # archive is a recoverable mistake only if the thing being overwritten
    # still exists somewhere.
    _note "Taking a safety backup of the CURRENT database first…"
    if /usr/local/bin/wp-db-backup.sh >/dev/null 2>&1; then
      _ok "Current state backed up to ${BACKUP_DIR}"
    else
      _bad "Could not back up the current database. Refusing to overwrite it."
      rm -rf "$_work"; return 1
    fi
    printf "  Type REPLACE to load %s into the live database: " "$_file"
    read -r _c
    [ "$_c" = "REPLACE" ] || { echo "  Cancelled — nothing changed."; rm -rf "$_work"; return 0; }
    if gzip -dc "$_src" | podman exec -i mariadb mariadb -u root -p"${MARIADB_ROOT_PASSWORD:-}" 2>/dev/null; then
      _ok "Restored into the live database"
      _note "Verify now: validate-wordpress.sh --section database"
      _note "If the site misbehaves, the pre-restore backup is the newest file"
      _note "in ${BACKUP_DIR}."
    else
      _bad "Restore FAILED — the database may be in a partial state"
      _note "The pre-restore backup is the newest file in ${BACKUP_DIR}"
      rm -rf "$_work"; return 1
    fi
    rm -rf "$_work"; return 0
  fi

  _note "Decrypted and verified but not written anywhere."
  _note "Add --to-file <path> or --to-database."
  rm -rf "$_work"
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
      s3|rclone) [ -r "$RCLONE_CONF" ] && printf '  rclone conf : %s (%s)\n' "$RCLONE_CONF" "$(stat -c '%a %U' "$RCLONE_CONF")" ;;
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

  init|setup) do_init ;;
  restore)    shift 2>/dev/null || true; do_restore "$@" ;;
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
      s3|rclone)
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
