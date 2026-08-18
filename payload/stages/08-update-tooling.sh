#!/bin/sh
# 08-update-tooling.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Installs wp-cron-run.sh and the update.sh update/upgrade utility.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Installing update script"
install -m 0755 "${PAYLOAD_DIR}/bin/update.sh" /usr/local/bin/update.sh
chmod +x /usr/local/bin/update.sh
ok "update.sh installed (wp / db / crowdsec / os / digest-check / all)"
ok "  Concurrent runs are now blocked by an exclusive lock at /run/lock/wordpress-update.lock"
ok "  Container swaps (wp/db/crowdsec) now check every rename/start instead of discarding the result — a silent failure here used to be able to delete a still-healthy container"
ok "  WordPress updates now validate the pulled image on a loopback candidate (127.0.0.1:18080) before cutting production over on :80"
ok "  MariaDB updates now verify the backup dump itself, snapshot the data directory before the swap, and confirm WordPress can use the new database before mariadb-old is ever deleted"
ok "  MariaDB updates now also check mariadb-upgrade's own exit status and roll back instead of continuing past a failure"
ok "  pinned.env is now written atomically (temp file + rename) and re-validated on load — a truncated or hand-edited file can no longer feed an unvalidated image reference into a pull or run"


# ── WordPress-level update visibility (NEW) ──────────────────────────────────
# update.sh above covers the CONTAINER IMAGE. Plugins and themes live in the
# mounted wp-content volume and are untouched by an image update -- and they
# are where roughly 91% of WordPress vulnerabilities are found (Patchstack,
# "State of WordPress Security in 2026": ~11,334 disclosed in 2025, ~91% in
# plugins, ~9% in themes, about six in core). wp-plugins.sh is the visibility
# for that layer.
ts "Installing WordPress plugin/theme update visibility"
install -m 0755 "${PAYLOAD_DIR}/bin/wp-plugins.sh" /usr/local/bin/wp-plugins.sh

cat > /etc/motd << 'MOTD'

  WASP — WordPress Alpine Security Platform
  Type  wasp-menu  for a task-grouped menu of all the operator tooling,
  or run any tool in /usr/local/bin directly (wp-*, wasp-*, update, ...).

MOTD

# The inbox is group-writable by the admin user so SFTP drops a file in
# without a permissions fight -- the most common reason a non-technical
# handover stalls. Not world-readable: a client's backup contains their
# database.
mkdir -p /var/lib/wasp-import/incoming
if [ -n "${ADMIN_USER:-}" ]; then
  chown "root:${ADMIN_USER}" /var/lib/wasp-import/incoming 2>/dev/null || true
  chmod 2770 /var/lib/wasp-import/incoming
else
  chmod 750 /var/lib/wasp-import/incoming
fi
ok "Import inbox ready: /var/lib/wasp-import/incoming"
ok "  How to get a backup there: wp-import.sh where"
# Only install what the chosen method needs. rclone is ~50 MB, so it is not
# pulled onto a VM that will never use it.
# age is installed only when encryption was actually configured -- and if it
# cannot be installed, the backup script REFUSES to upload rather than falling
# back to plaintext. A silent downgrade from "encrypted offsite backup" to
# "the whole database in someone else's bucket" is not an acceptable failure.
if [ -n "${OFFSITE_AGE_RECIPIENT:-}" ]; then
  apk add --no-cache age >/dev/null 2>&1 \
    && ok "age installed — off-VM backups will be encrypted" \
    || warn "age could not be installed; encrypted off-VM backup will REFUSE to upload rather than send plaintext"
fi
case "${OFFSITE_METHOD:-none}" in
  rsync)  apk add --no-cache rsync openssh-client >/dev/null 2>&1 \
            && ok "rsync + ssh installed for off-VM backup" ;;
  scp)    apk add --no-cache openssh-client >/dev/null 2>&1 \
            && ok "ssh client installed for off-VM backup" ;;
  s3|rclone) apk add --no-cache rclone >/dev/null 2>&1 \
            && ok "rclone installed for off-VM backup" \
            || warn "rclone could not be installed — off-VM backup will not work" ;;
esac
# msmtp sends host-side, so alerts still go out when WordPress or MariaDB is
# down -- which is exactly when an alert matters. Credentials are read from
# the same smtp.ini the mu-plugin uses; no second config file is written.
apk add --no-cache msmtp >/dev/null 2>&1 \
  && ok "msmtp installed — scan alerts can be emailed" \
  || warn "msmtp not installed; scans will log to syslog only (apk add msmtp)"
mkdir -p /var/lib/wp-notify && chmod 700 /var/lib/wp-notify
# jq parses the Wordfence feed; without it `wp-plugins.sh vulns` cannot run.
apk add --no-cache jq >/dev/null 2>&1 && ok "jq installed (vulnerability feed parsing)" \
  || warn "jq not installed — 'wp-plugins.sh vulns' will not work until: apk add jq"
mkdir -p /var/cache/wp-vulns && chmod 755 /var/cache/wp-vulns
# The token collected at install has to reach the file wp-plugins.sh reads at
# runtime. vars.sh already carries it, but that file is sourced by several
# tools and is not the place for a per-source credential; vuln-sources.conf is
# the single location the vulnerability code looks at.
if [ -n "${WORDFENCE_API_KEY:-}" ]; then
  install -m 0600 /dev/null /etc/wp-install/vuln-sources.conf
  printf 'WORDFENCE_API_KEY=%s\n' "$WORDFENCE_API_KEY" > /etc/wp-install/vuln-sources.conf
  # Feed choice lives beside the token: both are read by the same code, and
  # splitting them would create a second place to look when scanning misbehaves.
  printf 'WORDFENCE_FEED=%s\n' "${WORDFENCE_FEED:-scanner}" >> /etc/wp-install/vuln-sources.conf
  chmod 600 /etc/wp-install/vuln-sources.conf
  ok "Wordfence token stored (0600) — daily vulnerability scans active"
else
  warn "No Wordfence token — plugin vulnerability scanning is unavailable"
  warn "  Free token: https://www.wordfence.com/products/wordfence-intelligence/"
  warn "  Then:       wp-plugins.sh set-key wordfence <token>"
fi
install -m 0755 "${PAYLOAD_DIR}/bin/wp-mail.sh" /usr/local/bin/wp-mail.sh

# Pull the official wp-cli image now, so the tool works on a VM that later
# has no registry access, and so its digest is recorded alongside the other
# three images rather than being resolved at first use. Non-fatal: a
# registry hiccup here should not fail an otherwise-good install, and
# wp-plugins.sh degrades to a clear error rather than misbehaving.
WPCLI_IMAGE_REF="docker.io/library/wordpress:cli"
if podman pull "$WPCLI_IMAGE_REF" >/dev/null 2>&1; then
  if [ "${USE_DIGEST_PINNING:-1}" = "1" ] && command -v skopeo >/dev/null 2>&1; then
    _wpcli_dig=$(skopeo inspect --format '{{.Digest}}' "docker://${WPCLI_IMAGE_REF}" 2>/dev/null || echo "")
    case "$_wpcli_dig" in
      sha256:*) WPCLI_IMAGE_REF="docker.io/library/wordpress@${_wpcli_dig}"
                ok "wp-cli image pinned to ${_wpcli_dig}" ;;
      *)        warn "wp-cli image digest lookup failed — using the floating tag" ;;
    esac
  fi
  printf 'WPCLI_IMAGE=%s\n' "$WPCLI_IMAGE_REF" >> /etc/wp-install/pinned.env
  ok "wp-plugins.sh installed (status / check / update-plugins / update-themes)"
  ok "  Vulnerability scanning: wp-plugins.sh vulns  (Wordfence Intelligence, free)"
  ok "  Optional extra sources: wp-plugins.sh vuln-sources"
  ok "wp-mail.sh installed (status / test / setup / doctor / log)"
  ok "  Reports by default, never auto-updates: ~46% of disclosed plugin CVEs have no patch"
  ok "  at disclosure, and plugin auto-update has itself been a supply-chain vector."
else
  warn "Could not pull ${WPCLI_IMAGE_REF} — wp-plugins.sh is installed but will not run"
  warn "  until the image is available: podman pull ${WPCLI_IMAGE_REF}"
fi

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC
# ════════════════════════════════════════════════════════════════════════════

install -m 0755 "${PAYLOAD_DIR}/bin/wp-vuln-cron.sh" /usr/local/bin/wp-vuln-cron.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wp-notify.sh" /usr/local/bin/wp-notify.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-selftest.sh" /usr/local/bin/wasp-selftest.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-verify-integrity.sh" /usr/local/bin/wasp-verify-integrity.sh
[ -f "${PAYLOAD_DIR}/bin/wasp-testreport.sh" ] && \
  install -m 0755 "${PAYLOAD_DIR}/bin/wasp-testreport.sh" /usr/local/bin/wasp-testreport.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-offsite-backup.sh" /usr/local/bin/wasp-offsite-backup.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wp-forensics.sh" /usr/local/bin/wp-forensics.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wp-import.sh" /usr/local/bin/wp-import.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-egress.sh" /usr/local/bin/wasp-egress.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wp-rotate-secrets.sh" /usr/local/bin/wp-rotate-secrets.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-capture.sh" /usr/local/bin/wasp-capture.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-menu.sh" /usr/local/bin/wasp-menu.sh
install -m 0755 "${PAYLOAD_DIR}/bin/wasp-triage.sh" /usr/local/bin/wasp-triage.sh

# A login hint so operators discover the menu. Written to /etc/motd (shown on
# interactive login over SSH and on the console) rather than a shell rc, so it
# does not run code on every shell -- it is just a printed line. The menu is
# the recommended entry point; the individual tools remain available for anyone
# who prefers them.


# ── Bare-name aliases (after every tool is installed) ────────────────────────
# ORDERING BUG FIXED. This loop symlinks /usr/local/bin/*.sh to bare names, but
# it used to run near the TOP of the stage -- at which point only update.sh and
# wp-plugins.sh existed. It dutifully reported "Bare-name aliases created" and
# had created two, so `wasp-menu` and a dozen others were still "not found"
# while the log said the aliases were done. A loop over a directory has to run
# after the directory is populated.
# The tools install with a .sh suffix, but everything an operator reads --
# these installer prompts, the runbooks, the README, the motd -- refers to them
# by bare name: `wasp-egress test`, `wasp-menu`, `update.sh check`. On the first
# real install an operator typed `wasp-egress status` exactly as the installer
# had told them to, and got "not found".
#
# Rather than rewrite every reference to add .sh (and have the mismatch come
# back the next time someone writes a doc from memory), both spellings now
# work. Symlinks, so `ls -l` shows plainly what they point at.
for _t in /usr/local/bin/*.sh; do
  [ -e "$_t" ] || continue
  _bare="${_t%.sh}"
  # Never clobber a real binary that happens to share the name.
  if [ ! -e "$_bare" ]; then
    ln -sf "$_t" "$_bare" 2>/dev/null || true
  fi
done
ok "Bare-name aliases created (wasp-egress and wasp-egress.sh both work)"

# NOTE: the Two Factor plugin install used to live here. It moved to stage 10,
# because it needs the INTERNET and the egress proxy does not exist yet at this
# point -- see the comment at its new home for the full reasoning.
