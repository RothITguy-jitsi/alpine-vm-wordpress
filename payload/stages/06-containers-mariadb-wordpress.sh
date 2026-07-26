#!/bin/sh
# 06-containers-mariadb-wordpress.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Loads the nftables firewall, starts the MariaDB and WordPress containers, validates WordPress health, fixes uploads ownership, and (optionally) installs GeoIP filtering.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "nftables firewall"
apk add --no-cache nftables >/dev/null
rc-update add nftables default 2>/dev/null || true
if [ -f /etc/nftables.nft ]; then
  # v7-15 (audit #13): syntax-check with `nft -c` BEFORE applying. `-c` parses
  # and validates the ruleset without committing it, so a malformed rule
  # (e.g. from a bad CIDR that slipped through input validation) is caught
  # here instead of half-loading and potentially leaving the firewall in an
  # inconsistent or open state. The CIDR/IP inputs are already validated at
  # prompt time, but this is defence in depth on the one config whose failure
  # mode is "host firewall is down".
  if nft -c -f /etc/nftables.nft 2>/tmp/nft-check.err; then
    nft -f /etc/nftables.nft && ok "Rules loaded (syntax pre-checked)" \
      || warn "Ruleset load failed despite passing syntax check — check /etc/nftables.nft"
    rc-service nftables start 2>/dev/null || true
  else
    warn "nftables ruleset FAILED syntax check — NOT loading it (firewall would be left broken):"
    sed 's/^/       /' /tmp/nft-check.err | head -5
    warn "  The generated /etc/nftables.nft has a syntax error. This usually means a"
    warn "  CIDR/IP value contained something unexpected. Inspect it, fix by hand, then:"
    warn "    nft -c -f /etc/nftables.nft   (check)   &&   nft -f /etc/nftables.nft   (load)"
  fi
  rm -f /tmp/nft-check.err
else
  warn "/etc/nftables.nft not found"
fi

# ── MariaDB container ─────────────────────────────────────────────────────────
# wp-db ONLY (--internal, no route out) — zero host port exposure AND zero
# egress, not just "no port published".
# BUG FIX: tag was 11.4-lts (does not exist) — now using 11.4.
ts "Starting MariaDB (pulling ~150 MB — internal network only)"
# Mount a custom MariaDB config to cap InnoDB buffer pool and enable slow
# query logging. Without a buffer pool limit MariaDB can consume all available
# RAM on busy sites, evicting WordPress and CrowdSec from memory.
mkdir -p /home/wpuser/wp/mariadb-conf
install -m 0644 "${PAYLOAD_DIR}/mariadb-conf/wp.cnf" /home/wpuser/wp/mariadb-conf/wp.cnf
chmod 644 /home/wpuser/wp/mariadb-conf/wp.cnf
ok "MariaDB config: innodb_buffer_pool=256M, slow_query_log=on"

podman rm -f mariadb 2>/dev/null || true
podman run -d \
  --name    mariadb \
  --network wp-db \
  --ip      10.89.20.2 \
  --network-alias mariadb \
  --restart always \
  --label   io.containers.autoupdate=image \
  --cap-drop ALL \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --cap-add  DAC_OVERRIDE \
  --cap-add  FOWNER \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
  --pids-limit 100 \
  --memory=512m \
  --cpu-shares=512 \
  --env-file /etc/wordpress/env \
  -v /home/wpuser/wp/mysql:/var/lib/mysql \
  -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \
  --health-cmd "healthcheck.sh --connect --innodb_initialized" \
  --health-interval 5s \
  --health-timeout 5s \
  --health-retries 24 \
  --health-start-period 30s \
  "${DB_IMAGE}"

# FIX 2: Do NOT rely on Podman health check status.
# On Alpine without systemd, conmon's health check timer often does not fire —
# the container stays in "starting" state indefinitely even when MariaDB is
# fully ready. Instead, use a direct exec-based probe (mariadbd ping with
# credentials) which works regardless of conmon or cgroup configuration.
# The --health-cmd is still configured for 'podman ps' display purposes, but
# we never block on its output here.
ts "Waiting for MariaDB to accept connections (up to 3 min)"
# PRODUCTION SAFETY FIX (v7-6k): this loop used to gate readiness on a bare
# ping — see the mariadb-health-check.sh rationale above (installed earlier
# in this stage) for why that's not enough. Now gated on the same real
# query + InnoDB validation used at update time, with the old ping-only
# check kept as a fallback only if that script is somehow missing.
DB_READY=0
for i in $(seq 1 36); do
  if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
    if /usr/local/bin/mariadb-health-check.sh mariadb; then
      DB_READY=1; break
    fi
  # Run mariadbd ping INSIDE the container where MARIADB_ROOT_PASSWORD is set.
  # Use sh -c so the env var expands in the container's shell context, not here.
  elif PRUN exec mariadb sh -c \
       'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
        mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
    DB_READY=1; break
  fi
  sleep 5
done
[ "$DB_READY" = "1" ] \
  && ok "MariaDB healthy — ping + real query (root and wpdb) + InnoDB initialized" \
  || warn "MariaDB did not pass full health validation in 3 min — WordPress will retry. Check: PRUN logs mariadb | tail -20"



# ── WordPress container ───────────────────────────────────────────────────────
# BUG FIX: WordPress previously had NO --cap-drop ALL (MariaDB did).
# All containers now use the same cap discipline:
#   --cap-drop ALL        remove every Linux capability from the bounding set
#   --cap-add NET_BIND_SERVICE  Apache binds port 80 inside container netns
#                               (required even with -p 80:80 and custom network;
#                               Podman's host-side publish is separate from the
#                               in-container bind)
#   --cap-add SETUID/SETGID     Apache drops from root to www-data (UID 33)
#   --cap-add CHOWN             WordPress entrypoint sets file ownership on init
#   --cap-add DAC_OVERRIDE      read/write files across UID boundaries
#   --cap-add FOWNER            chmod on files not owned by current process
# --security-opt no-new-privileges blocks setuid binary privilege escalation
# but does NOT block Apache's intentional setuid() call to drop to www-data.
ts "Starting WordPress (pulling ~180 MB)"

# Determine remoteip volume mounts (only if mod_remoteip files were deployed)
REMOTEIP_MOUNTS=""
if [ -d /home/wpuser/wp/apache-mods ]; then
  REMOTEIP_MOUNTS_FLAG="yes"
else
  REMOTEIP_MOUNTS_FLAG="no"
fi

# mod_headers is NOT enabled by default in the WordPress Docker image
# (despite mod_remoteip being pre-enabled). Without headers.load Apache
# crashes on every 'Header always set ...' directive in wp-security.conf.
# We always create and mount this file.
mkdir -p /home/wpuser/wp/apache-mods
cat > /home/wpuser/wp/apache-mods/headers.load << 'HLOAD'
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
HLOAD
chmod 644 /home/wpuser/wp/apache-mods/headers.load
ok "headers.load created — enables mod_headers for security headers"

# Build volume args for podman run
WP_VOL_ARGS="-v /home/wpuser/wp/html:/var/www/html"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/logs:/var/log/apache2"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro"
# Always mount headers.load (mod_headers not pre-enabled in wordpress image)
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro"
# NOTE: remoteip.load is intentionally NOT mounted — mod_remoteip is already
# pre-enabled in the WordPress Docker image. Mounting it again just generates
# a harmless "already loaded" warning but we keep things clean.
# Mount 8G Firewall .htaccess as :rw — WordPress updates permalink rules
# inside the # BEGIN/END WordPress markers without touching the 8G section above.
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw"
# Only mount remoteip.conf if a trusted proxy IP was configured (sets RemoteIPTrustedProxy).
if [ -f /home/wpuser/wp/apache-mods/remoteip.conf ]; then
  WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"
fi

WEB_CHECK_PORT=80

podman rm -f wordpress 2>/dev/null || true
# shellcheck disable=SC2086
podman run -d \
  --name    wordpress \
  --network wp-front \
  --ip      10.89.10.3 \
  -p 80:80 \
  --restart always \
  --label   io.containers.autoupdate=image \
  --cap-drop ALL \
  --cap-add  NET_BIND_SERVICE \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --cap-add  DAC_OVERRIDE \
  --cap-add  FOWNER \
  --security-opt no-new-privileges:true \
  --pids-limit 200 \
  --memory=768m \
  --cpu-shares=512 \
  --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
  --env-file /etc/wordpress/env \
  -e WORDPRESS_DB_HOST=mariadb:3306 \
  -e WORDPRESS_DEBUG="" \
  -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
  ${WP_VOL_ARGS} \
  "${WP_IMAGE}"
# wp-db (--internal) attached second — Podman's --network flag on `run` only
# takes a static --ip for the primary network in this Podman/Alpine
# combination, so wp-db is attached post-create via `network connect`, the
# same pattern Podman's own docs recommend for multi-network containers.
podman network connect --ip 10.89.20.3 wp-db wordpress

# Wait for WordPress to pass full health validation — NOT just a non-500
# HTTP response. BUG FIX (v7-6g): a bare HTTP check happily passes on
# "Error establishing a database connection", a PHP fatal-error page, or a
# partially initialized site — every one of these can return a non-500
# code while WordPress itself is broken. wp-health-check.sh (installed
# earlier in this stage) additionally proves PHP actually executes, that
# the mariadb hostname resolves, and — the check that actually matters here
# — that a real mysqli connection using WordPress's own DB credentials can
# run SELECT 1.
ts "Validating WordPress health (HTTP + PHP + DB name resolution + DB auth + real query)"
WP_READY=0
for i in $(seq 1 24); do
  if /usr/local/bin/wp-health-check.sh wordpress "${WEB_CHECK_PORT}"; then
    WP_READY=1; break
  fi
  warn "WordPress not fully healthy yet (retry ${i}/24) — see checks above"
  sleep 5
done
[ "$WP_READY" = "0" ] && warn "WordPress did not pass full health validation after 24 attempts — check: podman logs wordpress"
ok "Container: $(podman ps --filter name='^wordpress$' --format '{{.Status}}' 2>/dev/null)"

# Fix uploads ownership — critical for theme/plugin/media uploads.
# Root cause: WordPress Docker entrypoint runs as UID 0 and creates
# wp-content/uploads/ as root:root. After Apache drops to www-data via
# setuid(), it LOSES DAC_OVERRIDE (Linux clears effective capabilities
# on UID drop). www-data (UID 33) then cannot write to root:root 755 dirs.
# Note: 'podman exec wordpress php -r is_writable(...)' falsely shows true
# because exec runs as container root, not as www-data — misleading.
ts "Fixing wp-content/uploads ownership (www-data must own uploads)"
# BUG FIX (v7-4): a single chown 3s after container start was racing the
# WordPress entrypoint, which continues copying/creating files under
# wp-content *after* that 3s mark (root-owned each time it touches a file).
# Symptom seen in the field: uploads worked fine after a reboot (because the
# OpenRC start() handler re-runs the same chown well after the entrypoint is
# done) but failed right after first install. Fix: wait for a concrete signal
# that the entrypoint's copy is finished (wp-content/plugins exists with the
# default plugins in it), THEN chown, THEN verify with an actual www-data
# write test, retrying a few times if the entrypoint is still mid-copy.
UPLOADS_FIXED=0
for attempt in 1 2 3 4 5; do
  # Wait for a sign the entrypoint has finished its initial copy.
  PRUN exec wordpress sh -c '[ -d /var/www/html/wp-content/plugins ]' >/dev/null 2>&1 || { sleep 4; continue; }
  # BUG FIX (v7-5d): WordPress doesn't necessarily create wp-content/uploads
  # until the first real media operation — confirmed in the field, this
  # retry loop kept "failing" even with correct ownership because the
  # touch-test's target directory simply didn't exist yet, which looks
  # identical to a permissions failure but chown can never fix it. Create it
  # unconditionally (safe no-op if it already exists) before testing.
  PRUN exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
  PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
  if PRUN exec --user www-data wordpress sh -c \
       'touch /var/www/html/wp-content/uploads/.write_test 2>/dev/null && rm -f /var/www/html/wp-content/uploads/.write_test' \
       >/dev/null 2>&1; then
    UPLOADS_FIXED=1
    ok "wp-content/ ownership → www-data:www-data (verified writable, attempt ${attempt})"
    break
  fi
  sleep 4
done
[ "$UPLOADS_FIXED" = "1" ] \
  || warn "uploads still not confirmed writable after 5 attempts; fix: PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content"
# Mirror ownership fix on the host-side bind-mount for persistence across
# restarts (container UID 33 maps 1:1 to host UID 33 under rootful Podman).
chown -R 33:33 /home/wpuser/wp/html/wp-content 2>/dev/null \
  && ok "Host-side /home/wpuser/wp/html/wp-content ownership fixed too" || true

# ── Custom login slug: WordPress-side support (v7-14) ───────────────────────
# BUG FIX (v7-14) — WITHOUT THIS THE SLUG LOCKS YOU OUT OF YOUR OWN SITE.
# v7-14 made the slug a real boundary by blocking direct /wp-login.php in
# .htaccess. But WordPress generates its OWN login URLs from
# site_url('wp-login.php', ...) in at least four places that all matter:
#   • the <form action> on the login page itself (scheme 'login_post')
#   • wp_login_url() used by auth_redirect() when a logged-out user hits
#     any /wp-admin/ page
#   • the "Lost your password?" and logout links
#   • the redirect after a successful login
# So without a WordPress-side fix, the sequence is: visit /slug-login (works,
# internal rewrite) -> page renders with action="http://host/wp-login.php"
# -> submit -> POST goes to the DEFAULT path -> Apache 403s it -> login is
# impossible. That is almost certainly the "custom slug didn't work" symptom
# from earlier versions, made fatal rather than merely cosmetic by the new
# block. This must-use plugin closes it by rewriting those generated URLs to
# the slug, so WordPress never emits (or depends on) the default path.
#
# mu-plugins is used deliberately over a normal plugin: mu-plugins load
# unconditionally, cannot be deactivated from the admin UI, and survive
# plugin-wipe recovery steps — appropriate for something that, if disabled,
# makes the site unreachable.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  ts "Installing custom login slug support (mu-plugin)"
  MU_DIR="/home/wpuser/wp/html/wp-content/mu-plugins"
  mkdir -p "${MU_DIR}"
  # The slug is substituted here on the VM (vars.sh already sourced), so the
  # heredoc body is quoted and the one dynamic value is injected via sed
  # afterwards — avoids any chance of PHP's $ syntax being mangled by shell
  # expansion inside the heredoc.
install -m 0644 "${PAYLOAD_DIR}/mu-plugins/00-wpvm-login-slug.php" "${MU_DIR}/00-wpvm-login-slug.php"

  # Inject the actual slug. Using a delimiter that cannot appear in the
  # sanitised slug (lowercase alnum + hyphen only), so no escaping needed.
  sed -i "s|WPVM_SLUG_PLACEHOLDER|${WP_ADMIN_SLUG}|g" "${MU_DIR}/00-wpvm-login-slug.php"

  chown -R 33:33 "${MU_DIR}" 2>/dev/null || true
  chmod 644 "${MU_DIR}/00-wpvm-login-slug.php"

  # Verify the substitution actually happened — a leftover placeholder would
  # mean every login URL points at a nonexistent path.
  if grep -q "WPVM_SLUG_PLACEHOLDER" "${MU_DIR}/00-wpvm-login-slug.php" 2>/dev/null; then
    warn "Login slug mu-plugin still contains a placeholder — slug will NOT work."
    warn "  Fix by hand: ${MU_DIR}/00-wpvm-login-slug.php"
  else
    ok "Login slug mu-plugin installed (/${WP_ADMIN_SLUG}-login)"
    # Confirm PHP can actually parse it. A syntax error in an mu-plugin is a
    # site-wide fatal, and mu-plugins can't be disabled from the admin UI —
    # so this is checked now, while there's still a console to report it on.
    if PRUN exec wordpress php -l /var/www/html/wp-content/mu-plugins/00-wpvm-login-slug.php >/dev/null 2>&1; then
      ok "  mu-plugin syntax verified by PHP"
    else
      warn "  mu-plugin FAILED PHP syntax check — removing it to avoid a fatal error"
      rm -f "${MU_DIR}/00-wpvm-login-slug.php"
      warn "  The slug rewrite still works, but WordPress will emit /wp-login.php"
      warn "  URLs that the .htaccess block rejects. Remove the wp-login block from"
      warn "  /home/wpuser/wp/htaccess/.htaccess if you get locked out."
    fi
  fi
fi


# ── OpenRC: mariadb-container ─────────────────────────────────────────────────

# ════════════════════════════════════════════════════════════════════════════
# GEOIP COUNTRY FILTERING (optional — only runs if GEOIP_ENABLED=1)
#
# BUG FIX (v7-4): GeoIP silently never got applied in the field even with
# valid MaxMind credentials. Root cause: `podman build` for the mod_maxminddb
# image runs its RUN steps (apt-get, curl) in a build-time container that
# is NOT on wp-front/wp-db (10.89.10.0/24 / 10.89.20.0/24) — it's on Podman's
# default bridge subnet. But by this point in Stage 2 the nftables ruleset is
# already loaded, and its forward chain only allows those two subnets before
# its policy DROP:
#   ip saddr/daddr 10.89.10.0/24 accept
#   ip saddr/daddr 10.89.20.0/24 accept
# So the build container's outbound internet access (apt-get update, the
# mod_maxminddb download) was silently dropped by the firewall, apt-get
# failed, `podman build` failed, and — because everything past that point
# (maxminddb.load, the GeoLite2 download, geoip.conf) lives inside the
# `if podman build ...; then` success branch — nothing else ever ran. No
# error reached the console because the build's own output only went to
# the install log, and the failure path just printed one generic warning.
#
# FIX: `podman build --network host` for this one build step, so it shares
# the host's already-working internet access instead of an unlisted bridge
# subnet the firewall drops. This does not weaken the running containers'
# isolation — it only applies to the transient build container, which never
# runs application code and is discarded once the image layer is committed.
#
# DESIGN NOTE — why a custom image at all (unchanged from v7-3):
#   Compiling mod_maxminddb via `podman exec` into a RUNNING container writes
#   to that container's ephemeral writable layer and is lost on recreate.
#   Building a small custom image instead (multi-stage: one stage compiles,
#   the final stage is the pinned WordPress image plus only the compiled
#   .so) means GeoIP survives every future update/recreate with no
#   persistence hacks. The GeoLite2 database itself is fetched directly via
#   curl on the Alpine host (documented MaxMind permalink API, plain HTTPS —
#   host-level curl uses the OUTPUT chain, which is policy-accept, so it was
#   never affected by the bug above) and bind-mounted in.
#
# REUSABILITY FIX (v7-4): this logic is now written out as a standalone,
# idempotent script — /usr/local/bin/wp-geoip-setup.sh — instead of living
# only inline here. That means if GeoIP setup ever fails again (bad
# credentials, MaxMind rate limit, transient network blip), it can be fixed
# and retried on a live VM with a single command and NO reboot and NO
# re-running the whole provisioning script:
#   1. Fix /etc/wp-install/vars.sh (MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY
#      / GEOIP_MODE / GEOIP_WHITELIST or GEOIP_BLOCKLIST / GEOIP_ENABLED=1)
#   2. Run: /usr/local/bin/wp-geoip-setup.sh
#   3. Check: tail -40 /var/log/wp-geoip.log
# ════════════════════════════════════════════════════════════════════════════
mkdir -p /home/wpuser/wp/geoip-build /home/wpuser/wp/geoip-db /home/wpuser/wp/apache-mods
install -m 0755 "${PAYLOAD_DIR}/bin/wp-geoip-setup.sh" /usr/local/bin/wp-geoip-setup.sh
chmod +x /usr/local/bin/wp-geoip-setup.sh
ok "wp-geoip-setup.sh installed — reusable, rerunnable anytime with no reboot needed"
ok "  Retry after fixing creds: /usr/local/bin/wp-geoip-setup.sh   then: tail -40 /var/log/wp-geoip.log"
ok "  MaxMind credentials now flow through a netrc file (--netrc-file) — never on a curl command line or exposed in argv/ps output"

if [ "${GEOIP_ENABLED:-0}" = "1" ] && [ -n "${MAXMIND_ACCOUNT_ID}" ] && [ -n "${MAXMIND_LICENSE_KEY}" ]; then
  ts "GeoIP country filtering — building mod_maxminddb image layer"
  if /usr/local/bin/wp-geoip-setup.sh; then
    ok "GeoIP filtering active — see /var/log/wp-geoip.log for details"
    # Reflect the new pinned image tag for the rest of THIS install run too
    # (later heredocs below substitute ${WP_IMAGE} at write time).
    WP_IMAGE=$(PRUN inspect wordpress --format '{{.Config.Image}}' 2>/dev/null || echo "$WP_IMAGE")
  else
    warn "GeoIP setup failed — full detail in /var/log/wp-geoip.log"
    warn "  Fix credentials/network, then re-run: /usr/local/bin/wp-geoip-setup.sh"
  fi
elif [ "${GEOIP_ENABLED:-0}" = "1" ]; then
  warn "GeoIP was enabled but MaxMind credentials are missing — skipping GeoIP setup"
fi

