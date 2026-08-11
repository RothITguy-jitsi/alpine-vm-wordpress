#!/bin/sh
# =============================================================================
# wp-rotate-secrets.sh — rotate credentials across every place they live
# =============================================================================
#   wp-rotate-secrets.sh status         what can be rotated, and from here
#   wp-rotate-secrets.sh salts          WordPress salts only (fast, safe)
#   wp-rotate-secrets.sh db             database application password
#   wp-rotate-secrets.sh smtp <pass>    SMTP password (you supply the new one)
#   wp-rotate-secrets.sh all            salts + db (NOT smtp — needs the relay's)
#
# WHY THIS EXISTS
#
# The incident playbook says "rotate every credential." Until now it provided
# no way to do it, so the one moment rotation matters most — just after a
# compromise — is the moment an operator is hand-editing config files under
# pressure, across the several places each secret is stored, hoping they
# caught them all. A missed copy means either a broken site or a credential
# the attacker still holds.
#
# THE HARD PART IS THAT A SECRET LIVES IN MORE THAN ONE PLACE
#
# The database password is in /etc/wordpress/env (the container environment),
# in the MariaDB user's grant, and is read by WordPress from the environment.
# Rotating it means changing MariaDB and the environment IN THE RIGHT ORDER,
# or the running WordPress loses its database mid-request. This does that in an
# order that keeps the site up, verifies the new credential works before
# committing, and puts the old one back if it does not.
#
# WHAT IT DELIBERATELY WILL NOT ROTATE
#
# The age backup key. Rotating it makes every existing encrypted backup
# permanently unreadable, because they were encrypted to the old public key.
# That is not a rotation, it is throwing away your history, and it needs a
# re-encryption workflow this script does not pretend to provide. `status`
# explains it; nothing here touches it.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

ENVF=/etc/wordpress/env
SECRETS=/home/wpuser/wp/secrets
BACKUP_DIR=/root/.rotate-backups

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' "$1"; }

# Strong, shell-safe password: no quotes, backslashes or characters that need
# escaping in an env file or a SQL statement. 32 chars from a safe alphabet.
_newpass() {
  tr -dc 'A-Za-z0-9_.-' < /dev/urandom | head -c 32
  echo
}

_mdb() { # run SQL as root inside the container
  podman exec -i mariadb sh -c \
    'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" "$@"' _ "$@"
}

# wp-cli runs in its OWN container: the official wordpress:*-apache image does
# NOT ship wp-cli, so `podman exec wordpress wp ...` fails with "wp: not found".
# This shares the running container's network and env-file so wp-config resolves
# exactly as it does for the site itself.
_wpcli_image() {
  _wi=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
  [ -n "$_wi" ] || _wi="docker.io/library/wordpress:cli"
  printf '%s' "$_wi"
}
_wp() {
  podman run --rm \
    --network "container:wordpress" \
    --user 33:33 \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -v /home/wpuser/wp/html:/var/www/html \
    "$(_wpcli_image)" wp --path=/var/www/html "$@" 2>/dev/null
}

_snapshot() {
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  _ts=$(date -u +%Y%m%d-%H%M%S)
  [ -f "$ENVF" ] && cp "$ENVF" "${BACKUP_DIR}/env.${_ts}"
  [ -f "${SECRETS}/smtp.ini" ] && cp "${SECRETS}/smtp.ini" "${BACKUP_DIR}/smtp.ini.${_ts}"
  echo "$_ts"
}

case "${1:-status}" in

status)
  _hdr "Credential rotation"
  echo "  Rotatable from here:"
  _ok "WordPress salts     — wp-rotate-secrets.sh salts   (instant, logs everyone out)"
  _ok "Database password   — wp-rotate-secrets.sh db      (kept in sync across env + MariaDB)"
  _ok "SMTP password       — wp-rotate-secrets.sh smtp <new>  (after you change it at the relay)"
  echo ""
  echo "  Rotate at the PROVIDER, then update here:"
  _note "CTI / Wordfence keys — regenerate in their console, then re-run the"
  _note "  set-key command. They are external; this VM only holds a copy."
  echo ""
  _warn "NOT rotatable without re-encrypting your backups:"
  _note "The age backup key. Every off-VM backup was encrypted to the current"
  _note "public key; a new key cannot read them. Rotating it discards your"
  _note "backup history. If you must, generate a new key, KEEP THE OLD ONE to"
  _note "read old backups, and switch new backups to the new recipient by hand."
  echo ""
  echo "  After a compromise, the right order is:"
  _note "1. wp-rotate-secrets.sh all      (salts + database)"
  _note "2. wp-rotate-secrets.sh smtp <new>  (change at the relay first)"
  _note "3. Reset every WordPress admin password:  wp-forensics.sh admins"
  _note "4. Regenerate provider API keys in their consoles"
  ;;

salts)
  _hdr "Rotating WordPress salts"
  # The cheap, always-safe one. Invalidates every session, which after a
  # compromise is exactly what you want -- a stolen auth cookie stops working.
  if _wp config shuffle-salts >/dev/null 2>&1; then
    _ok "Salts regenerated"
    _note "Every logged-in session is now invalid, including any an attacker held."
    _note "Legitimate users simply log in again."
  else
    _bad "Could not shuffle salts — is wp-config.php writable by the container?"
    exit 1
  fi
  ;;

db)
  _hdr "Rotating the database password"
  [ -f "$ENVF" ] || { _bad "No ${ENVF} — cannot locate the credential"; exit 1; }
  _user=$(sed -n 's/^WORDPRESS_DB_USER=//p' "$ENVF" | head -1)
  _name=$(sed -n 's/^WORDPRESS_DB_NAME=//p' "$ENVF" | head -1)
  [ -n "$_user" ] || { _bad "Could not read WORDPRESS_DB_USER from ${ENVF}"; exit 1; }

  _new=$(_newpass)
  _ts=$(_snapshot)
  _note "Rotating password for DB user '${_user}'. Snapshot: ${_ts}"

  # ORDER MATTERS. Change MariaDB first, then the environment, then restart
  # WordPress so it picks up the new value. Between the grant and the restart,
  # the running WordPress still holds a live connection with the OLD password
  # (MySQL does not drop existing connections on password change), so the site
  # keeps serving until the clean restart.
  if _mdb -e "ALTER USER '${_user}'@'%' IDENTIFIED BY '${_new}'; FLUSH PRIVILEGES;" 2>/dev/null; then
    _ok "MariaDB password changed"
  else
    _bad "Could not change the MariaDB password. Nothing else was touched."
    exit 1
  fi

  # Update the environment file atomically.
  _tmp=$(mktemp)
  sed "s#^WORDPRESS_DB_PASSWORD=.*#WORDPRESS_DB_PASSWORD=${_new}#; s#^MARIADB_PASSWORD=.*#MARIADB_PASSWORD=${_new}#" \
    "$ENVF" > "$_tmp" && cat "$_tmp" > "$ENVF" && rm -f "$_tmp"
  _ok "Environment file updated"

  # Verify BEFORE declaring success: can a fresh connection authenticate with
  # the new password? If not, roll everything back.
  _check=$(podman exec -i mariadb sh -c \
    "mariadb -u '${_user}' -p'${_new}' -e 'SELECT 1;' '${_name}' 2>/dev/null && echo OK" 2>/dev/null)
  if [ "$_check" != "OK" ] && ! printf '%s' "$_check" | grep -q OK; then
    _bad "The new password does not authenticate. Rolling back."
    cp "${BACKUP_DIR}/env.${_ts}" "$ENVF"
    _old=$(sed -n 's/^WORDPRESS_DB_PASSWORD=//p' "$ENVF" | head -1)
    _mdb -e "ALTER USER '${_user}'@'%' IDENTIFIED BY '${_old}'; FLUSH PRIVILEGES;" 2>/dev/null
    _note "Restored the previous password in both places."
    exit 1
  fi
  _ok "New password authenticates"

  _note "Restarting WordPress to pick up the new credential…"
  podman restart wordpress >/dev/null 2>&1
  sleep 5
  # Confirm the site actually serves after the restart.
  if _wp option get siteurl >/dev/null 2>&1; then
    _ok "WordPress reconnected with the new password"
  else
    _warn "WordPress restarted but did not respond in 5s — check: podman logs --tail 30 wordpress"
  fi
  echo ""
  _ok "Database password rotated. Old snapshot kept at ${BACKUP_DIR}/env.${_ts}"
  logger -t wasp-rotate "database password rotated"
  ;;

smtp)
  _hdr "Rotating the SMTP password"
  _new="${2:-}"
  # SMTP is different: the password is owned by the mail relay, not by this VM.
  # We cannot generate it -- the operator changes it at the provider and gives
  # us the new value to store. Generating one here would just break mail.
  if [ -z "$_new" ]; then
    _bad "Supply the new password: wp-rotate-secrets.sh smtp '<new-password>'"
    _note "Change it at your mail relay FIRST, then pass the new value here."
    _note "Unlike the database password, this one is owned by the relay, not"
    _note "by this VM — so it cannot be generated locally."
    exit 1
  fi
  [ -f "${SECRETS}/smtp.ini" ] || { _bad "No ${SECRETS}/smtp.ini"; exit 1; }
  _ts=$(_snapshot)
  _tmp=$(mktemp)
  # msmtp/PHPMailer ini: replace the password line, leave the rest.
  sed "s#^password=.*#password=${_new}#; s#^AuthPass=.*#AuthPass=${_new}#" \
    "${SECRETS}/smtp.ini" > "$_tmp" && cat "$_tmp" > "${SECRETS}/smtp.ini" && rm -f "$_tmp"
  chmod 440 "${SECRETS}/smtp.ini"
  chown root:33 "${SECRETS}/smtp.ini" 2>/dev/null || chown root:www-data "${SECRETS}/smtp.ini" 2>/dev/null || true
  _ok "SMTP password updated (snapshot ${_ts})"
  _note "Verify delivery end to end — a wrong password fails silently:"
  _note "  wp-mail.sh test you@example.com"
  logger -t wasp-rotate "SMTP password rotated"
  ;;

all)
  "$0" salts
  "$0" db
  echo ""
  _warn "SMTP was NOT rotated — it needs the new value from your relay."
  _note "  wp-rotate-secrets.sh smtp '<new>'"
  _warn "WordPress admin passwords were NOT rotated — do those in wp-admin, or:"
  _note "  wp-forensics.sh admins   # then reset each"
  ;;

*) sed -n '4,10p' "$0" ;;
esac
