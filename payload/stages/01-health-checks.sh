#!/bin/sh
# 01-health-checks.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Installs wp-health-check.sh and mariadb-health-check.sh (real functional health checks, not just a socket check).
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

# ── wp-health-check.sh — real WordPress health validation ────────────────────
# BUG FIX (v7-6g, item #6 from the 7-6f review): every prior "is WordPress
# ready?" gate in this script (initial install, GeoIP rebuild, and
# update.sh's rollback decision) was a bare `wget -qO- http://127.0.0.1/`
# treating any non-500 HTTP response as success. That proves Apache answered
# a socket — nothing more. It happily passes on "Error establishing a
# database connection", a PHP fatal-error page, a WordPress maintenance
# page, a partially initialized site, or the Apache default page — every one
# of which returns 200/302 while WordPress itself is broken. This is
# especially dangerous in update.sh's do_wp_update(): a health check that
# lies "healthy" is exactly the case that skips rollback and leaves a broken
# site live.
#
# Installed once, here, before MariaDB/WordPress ever start, so it's
# available to every later health-check call site in this file (initial
# install, wp-geoip-setup.sh, and update.sh) without duplicating the logic
# three times and letting the copies drift.
#
# Checks, in order, each independently gating pass/fail:
#   1. HTTP response      — sanity check only; proves a socket answers.
#   2. PHP execution      — proves PHP itself runs inside the container,
#                            not just that Apache is up.
#   3. MariaDB DNS         — `getent hosts mariadb` proves Aardvark DNS /
#                            the wp-db network path resolves the hostname,
#                            independent of credentials.
#   4+5. MariaDB auth + real WordPress DB query — one PHP mysqli call using
#        WordPress's own WORDPRESS_DB_HOST/USER/PASSWORD/NAME env vars (the
#        exact values Apache/PHP itself uses) that opens a connection AND
#        runs `SELECT 1`. This is the check that actually proves "WordPress
#        can talk to its database", not just "MariaDB's TCP port is open".
# Recent container logs are also grepped for fatal/uncaught/segfault/
# permission-denied lines and printed for a human to review — informational
# only, since some of these can be transient noise during first boot, so it
# never gates pass/fail on its own.
ts "Installing wp-health-check.sh (real health validation, not just HTTP)"
install -m 0755 "${PAYLOAD_DIR}/bin/wp-health-check.sh" /usr/local/bin/wp-health-check.sh
chmod +x /usr/local/bin/wp-health-check.sh
ok "wp-health-check.sh installed — HTTP + PHP + DB-DNS + DB-auth + real query"
ok "  Manual use: wp-health-check.sh [container] [port]"

# ── mariadb-health-check.sh — real MariaDB health validation ─────────────────
# PRODUCTION SAFETY FIX (v7-6k, "Strengthen service health checks" from the
# 7-6f review): wp-health-check.sh (above) closed this gap for WordPress,
# but every MariaDB readiness gate in this script — the wait loop just
# below (before either container even exists yet) AND update.sh's
# do_db_update() rollback decision — was still a bare
# `mariadbd-admin ping`. A ping only proves the server accepts a TCP
# connection and that ROOT authenticates; it proves nothing about InnoDB
# actually being usable, and nothing about whether WordPress's OWN
# database/user (MARIADB_DATABASE/MARIADB_USER, not root) can run a query.
# That is the identical blind spot the old `wget -qO-` WordPress check had
# — a shallow protocol-level success coexisting with a broken
# application-level path (see the long comment above the wp-health-check.sh
# heredoc). It matters most inside do_db_update(): DB_READY there directly
# decides whether the new MariaDB container is kept or rolled back to
# mariadb-old, and at that point in the update WordPress is deliberately
# stopped, so wp-health-check.sh — which needs a running WordPress
# container to test through — cannot be used to validate the new database.
# A MariaDB-only check is the only way to test it there.
#
# Installed once, here, before either container starts, so it's available
# to every later call site (the wait loop just below, and update.sh)
# without duplicating the query logic and letting copies drift.
ts "Installing mariadb-health-check.sh (real health validation, not just ping)"
install -m 0755 "${PAYLOAD_DIR}/bin/mariadb-health-check.sh" /usr/local/bin/mariadb-health-check.sh
chmod +x /usr/local/bin/mariadb-health-check.sh
ok "mariadb-health-check.sh installed — ping + root query + wpdb query + InnoDB"
ok "  Manual use: mariadb-health-check.sh [container]"

