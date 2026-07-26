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

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC
# ════════════════════════════════════════════════════════════════════════════
