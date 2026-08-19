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
    if nft -f /etc/nftables.nft; then
      ok "Rules loaded (syntax pre-checked)"
    else
      warn "Ruleset load failed despite passing syntax check — check /etc/nftables.nft"
      [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ] && \
        block_production "The nftables ruleset passed its syntax check but failed to LOAD, so this VM has no host firewall. Check: doas nft -f /etc/nftables.nft"
    fi
    rc-service nftables start 2>/dev/null || true
  else
    warn "nftables ruleset FAILED syntax check — NOT loading it (firewall would be left broken):"
    sed 's/^/       /' /tmp/nft-check.err | head -5
    warn "  The generated /etc/nftables.nft has a syntax error. This usually means a"
    warn "  CIDR/IP value contained something unexpected. Inspect it, fix by hand, then:"
    warn "    doas nft -c -f /etc/nftables.nft   (check)   &&   doas nft -f /etc/nftables.nft   (load)"

    # A VM with NO FIREWALL must never be certified. On a real install a
    # generated rule expanded with an empty variable, nft rejected the whole
    # file, and the VM came up with no filter table at all -- no L1 packet
    # filter, no egress boundary, nothing. The install printed this warning and
    # then reported success, and only `wasp-egress test` two screens later said
    # "the boundary is NOT holding".
    #
    # Every other fail-closed control here blocks production. This -- the one
    # whose failure means there is no perimeter -- did not, which was an
    # oversight rather than a decision.
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      block_production "The nftables ruleset FAILED to load, so this VM has NO host firewall: no L1 packet filter, no admin-IP restriction, and no egress boundary. Everything else that reports 'enabled' is describing rules that are not in the kernel. Inspect /etc/nftables.nft, fix it, then: doas nft -c -f /etc/nftables.nft && doas nft -f /etc/nftables.nft"
    fi
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
# Intermediate polls are SILENCED. mariadb-health-check.sh is written to be run
# against a database that should already be up, so it reports every failed sub-
# check loudly -- correct there, badly wrong here, where "not ready yet" is the
# expected state for the first few polls. On the first real hardware install
# this printed two full blocks of red "✗ MariaDB health: ONE OR MORE CRITICAL
# CHECKS FAILED" before succeeding on the third poll, which reads like a
# disaster in the log and sends an operator debugging a database that was
# simply still starting. Output is captured and only shown if we run out of
# attempts -- at which point it is genuinely diagnostic.
_db_last_out=""
for i in $(seq 1 36); do
  if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
    if _db_last_out=$(/usr/local/bin/mariadb-health-check.sh mariadb 2>&1); then
      DB_READY=1; break
    fi
  # Run mariadbd ping INSIDE the container where MARIADB_ROOT_PASSWORD is set.
  # Use sh -c so the env var expands in the container's shell context, not here.
  elif PRUN exec mariadb sh -c \
       'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
        mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
    DB_READY=1; break
  fi
  # A progress note every 30s, so a genuinely stuck database is still visible
  # without a wall of failed sub-checks.
  [ $(( i % 6 )) -eq 0 ] && echo "     still waiting for MariaDB ($(( i * 5 ))s)…"
  sleep 5
done
if [ "$DB_READY" = "0" ] && [ -n "$_db_last_out" ]; then
  warn "MariaDB never became healthy — last check output:"
  printf '%s\n' "$_db_last_out" | sed 's/^/    /'
fi
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

# ── Build wp-config.php extras (NEW: site address + proxy awareness) ─────────
# Base hardening constants -- unchanged from before, just no longer a single
# hardcoded string, because the site-address handling below is conditional.
WP_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);'

# DISALLOW_FILE_MODS under production, from an external evaluation and it is a
# fair point. DISALLOW_FILE_EDIT above only removes the theme/plugin CODE
# EDITOR; an administrator (or anyone who has taken over an admin session) can
# still install a plugin from wp-admin, which is a far more direct route to
# running arbitrary PHP than the editor ever was. DISALLOW_FILE_MODS closes
# installs, updates and deletes for plugins and themes together.
#
# It is deliberately NOT the default for standard/lab installs: it makes the
# admin UI meaningfully less useful, and someone running this for a personal
# site should not have that forced on them. Under production -- the profile
# that already refuses unverified releases and fails closed on Squid -- the
# trade lands the other way, and plugins are installed deliberately from the
# console with `wp-plugins.sh install`, which is auditable and logged.
if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
  WP_CONFIG_EXTRA="${WP_CONFIG_EXTRA}define(\"DISALLOW_FILE_MODS\",true);"
  # Verified: WP-CLI is NOT affected by this constant (the sole documented
  # exception is `wp core language install`), so wp-plugins.sh keeps working.
  # That is precisely the split we want -- blocked in the admin UI where a
  # hijacked session lives, available from the console path that is logged.
  # It also happens to make the site immune to CVE-2024-31210, whose advisory
  # states sites with DISALLOW_FILE_MODS set are not affected.
  ok "  DISALLOW_FILE_MODS enabled (production): plugin/theme installs and"
  ok "  updates from wp-admin are blocked. Use: wp-plugins.sh install <slug>"
fi

# ── Proxy configuration for WordPress ────────────────────────────────────────
# The FIREWALL enforces the egress boundary; this is what makes well-behaved
# code take the sanctioned path rather than being dropped at it. Without
# these defines, core updates and the plugin API fail at the firewall instead
# of being proxied, and the site looks broken rather than restricted.
#
# WP_PROXY_BYPASS_HOSTS keeps loopback and the container networks direct:
# mariadb, the health checks and wp-cli must not try to reach each other
# through a web proxy.
if [ "${EGRESS_PROXY:-0}" = "1" ]; then
  WP_CONFIG_EXTRA="${WP_CONFIG_EXTRA}"'define("WP_PROXY_HOST","10.89.10.2");define("WP_PROXY_PORT","3128");define("WP_PROXY_BYPASS_HOSTS","localhost,127.0.0.1,10.89.10.0/24,10.89.20.0/24,mariadb");'
fi

if [ -n "${WP_DOMAIN:-}" ]; then
  _WP_URL="${WP_SCHEME:-http}://${WP_DOMAIN}"

  # BOTH WP_HOME and WP_SITEURL are set, deliberately and always together.
  # Setting only WP_HOME is a documented WordPress misconfiguration, not
  # merely an incomplete one: with WP_SITEURL still resolving from the
  # database's stale value, wp-login.php?action=logout&redirect_to=... can
  # be used to disclose that old value (typically the raw VM IP), and the
  # site ends up emitting two different origins depending on which code
  # path builds the URL. Constants also take precedence over the database
  # copy, so the site never needs a search-replace migration to move
  # domains -- change these two and restart.
  WP_CONFIG_EXTRA="${WP_CONFIG_EXTRA}define(\"WP_HOME\",\"${_WP_URL}\");define(\"WP_SITEURL\",\"${_WP_URL}\");"

  if [ "${WP_SCHEME:-http}" = "https" ]; then
    # TLS is terminated upstream (nothing in this VM serves 443), so PHP
    # sees a plain HTTP request and is_ssl() returns false. Left alone
    # that produces the classic redirect loop: WordPress wants https,
    # sends a redirect, the proxy forwards the next request as http
    # again, repeat until the browser gives up.
    #
    # The fix is to honor X-Forwarded-Proto -- but ONLY when a trusted
    # proxy was actually configured. That header is just a request header:
    # anything that can reach port 80 directly can set it. Trusting it
    # unconditionally would let a direct caller assert "this was https"
    # and flip FORCE_SSL_ADMIN's protection off for their own session.
    # PROXY_IP is the same trust signal Apache's mod_remoteip already
    # uses for X-Forwarded-For (see RemoteIPTrustedProxy in the generated
    # Apache config), so the two stay consistent: header trust is granted
    # in exactly one place, for exactly one configured proxy.
    if [ -n "${PROXY_IP:-}" ]; then
      # The header can legitimately be a comma-separated list when a
      # request crossed more than one proxy; the LEFTMOST value is the
      # original client's scheme, so take that rather than substring-
      # matching the whole list (which would read "https,http" -- client
      # on http through an https-fronted hop -- as https).
      WP_CONFIG_EXTRA="${WP_CONFIG_EXTRA}"'if(isset($_SERVER["HTTP_X_FORWARDED_PROTO"])){$xfp=explode(",",$_SERVER["HTTP_X_FORWARDED_PROTO"]);if(strtolower(trim($xfp[0]))==="https"){$_SERVER["HTTPS"]="on";}}'
      WP_CONFIG_EXTRA="${WP_CONFIG_EXTRA}define(\"FORCE_SSL_ADMIN\",true);"
      ok "Site address: ${_WP_URL} (X-Forwarded-Proto trusted from ${PROXY_IP}, admin forced to SSL)"
    else
      # https requested with no trusted proxy: set the URLs so links are
      # correct, but do NOT enable header-based scheme detection (nothing
      # is trusted to set it) and do NOT force SSL admin, which without a
      # working https path in front would lock the operator out of
      # wp-admin entirely rather than protect anything.
      warn "Site address: ${_WP_URL}, but no reverse proxy IP is set."
      warn "  X-Forwarded-Proto will NOT be trusted (any direct caller could forge it)"
      warn "  and FORCE_SSL_ADMIN is left off so wp-admin stays reachable."
      warn "  Set a proxy IP and re-run if TLS is terminated upstream."
    fi
  else
    ok "Site address: ${_WP_URL}"
  fi
  unset _WP_URL
else
  # No domain given: leave WP_HOME/WP_SITEURL unset so WordPress falls back
  # to its normal behavior (deriving from the request, then persisting
  # whatever the first setup visit used). Correct for a throwaway lab VM
  # reached by IP; see README for why it's the wrong default for a real site.
  ok "No site domain configured — WordPress will derive its URL from the request"
fi

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
# ── SMTP credentials (NEW) ────────────────────────────────────────────────────
# Written OUTSIDE the docroot and mounted read-only. See the reasoning in
# payload/mu-plugins/01-wpvm-smtp.php -- short version: a secret inside
# /var/www/html becomes HTTP-readable the moment PHP execution breaks, and a
# secret in the container environment is printed by `podman inspect`.
#
# This is an intentionally unquoted heredoc (values must expand). Every value
# is escaped for PHP single-quoted string context first -- backslash before
# quote, so an app password containing either survives intact rather than
# breaking out of the string. This is the same category as vars.sh: config
# generation with substitution, not a literal script body.
if [ -n "${SMTP_HOST:-}" ]; then
  # PERMISSIONS FIX (found on a live VM): this directory was root:root 0700,
  # which meant www-data could not TRAVERSE it -- so PHP could never open the
  # file inside, regardless of that file's own mode. The symptoms looked
  # contradictory: `wp-mail.sh doctor` read the config fine (it runs as root
  # via doas) while the mu-plugin silently fell back to mail(), because
  # is_readable() was false for uid 33. sendmail then tried 127.0.0.1 and was
  # refused.
  #
  # root:33 0750 lets the PHP worker traverse and read while nothing else on
  # the system can. The file below is root-owned and group-readable rather
  # than owned by 33, so a compromised PHP process can read the relay
  # credentials (unavoidable -- it must, to send mail) but cannot rewrite
  # them to point at a server it controls.
  mkdir -p /home/wpuser/wp/secrets
  chown root:33 /home/wpuser/wp/secrets 2>/dev/null || true
  chmod 0750 /home/wpuser/wp/secrets
  _php_q() { printf '%s' "$1" | sed "s/\\\\/\\\\\\\\/g; s/'/\\\\'/g"; }
  # Pre-create with restrictive mode so the file never exists world-readable,
  # even briefly: `cat >` truncates but preserves an existing file's mode.
  # Written as INI, not PHP. A .php credentials file is code -- it gets
  # include()d, so a flaw in the escaping below, or any future write access to
  # the file, would be code execution rather than a bad password. INI is data:
  # the worst a malformed value can do is fail to parse.
  #
  # The password is base64-encoded so that quotes, semicolons, '=' and
  # whitespace cannot interact with INI parsing at all. That is encoding for
  # robustness, NOT secrecy -- file permissions remain what protects it.
  install -m 0600 -o 0 -g 33 /dev/null /home/wpuser/wp/secrets/smtp.ini
  {
    printf '; WASP SMTP relay settings. Data, not code -- never include() this.\n'
    printf '; Managed by wp-mail.sh setup. Mounted read-only into the container.\n'
    printf 'host = %s\n'       "$SMTP_HOST"
    printf 'port = %s\n'       "${SMTP_PORT:-587}"
    printf 'user = %s\n'       "$SMTP_USER"
    printf 'pass_b64 = %s\n'   "$(printf '%s' "$SMTP_PASS" | base64 | tr -d '\n')"
    printf 'from = %s\n'       "$SMTP_FROM"
    printf 'from_name = %s\n'  "$SMTP_FROM_NAME"
    printf 'encryption = %s\n' "${SMTP_ENCRYPTION:-tls}"
    printf 'timeout = 10\n'
  } > /home/wpuser/wp/secrets/smtp.ini
  chmod 0440 /home/wpuser/wp/secrets/smtp.ini
  chown root:33 /home/wpuser/wp/secrets/smtp.ini
  # Remove any pre-existing executable config so it cannot be the one used.
  rm -f /home/wpuser/wp/secrets/smtp.php
  ok "SMTP credentials written as INI (root:33 0440, non-executable, outside the web root)"
else
  # Create the directory regardless so the read-only mount below always has
  # a source -- podman would otherwise create it root-owned at run time.
  mkdir -p /home/wpuser/wp/secrets
  chown root:33 /home/wpuser/wp/secrets 2>/dev/null || true
  chmod 0750 /home/wpuser/wp/secrets
  warn "No SMTP relay configured — WordPress cannot send mail (silently)."
  warn "  Configure later on the VM with: wp-mail.sh setup"
fi

WP_VOL_ARGS="-v /home/wpuser/wp/html:/var/www/html"
# ── SMTP transport mu-plugin (NEW) ───────────────────────────────────────────
# REGRESSION FIX (caught by the new mail validation section on a real
# install): this was originally installed inside the `if [ -n "$WP_ADMIN_SLUG" ]`
# block further down, because that is where the other mu-plugin lives and
# where MU_DIR is defined. With no custom slug -- the default -- that whole
# block is skipped, so the SMTP transport was never installed and wp_mail()
# silently fell back to PHP mail() with no sendmail present. Mail transport
# has nothing to do with the login slug, so it gets its own unconditional
# block with its own MU_DIR.
#
# Installed even when no relay is configured: the mu-plugin checks for its
# config file and returns early if absent, so it is inert until
# `wp-mail.sh setup` writes one -- which means enabling mail later needs no
# container rebuild.
SMTP_MU_DIR="/home/wpuser/wp/html/wp-content/mu-plugins"
mkdir -p "${SMTP_MU_DIR}"
install -m 0644 "${PAYLOAD_DIR}/mu-plugins/01-wpvm-smtp.php" "${SMTP_MU_DIR}/01-wpvm-smtp.php"
# Login rate-limiting. Unconditional and in the same block as the SMTP
# transport, for the same reason: it has nothing to do with the custom-slug
# prompt, and burying it in that conditional is exactly how the SMTP plugin
# went missing on every install that kept the default slug.
install -m 0644 "${PAYLOAD_DIR}/mu-plugins/02-wpvm-login-guard.php" "${SMTP_MU_DIR}/02-wpvm-login-guard.php"
chown 33:33 "${SMTP_MU_DIR}/02-wpvm-login-guard.php" 2>/dev/null || true
chown 33:33 "${SMTP_MU_DIR}/01-wpvm-smtp.php" 2>/dev/null || true
# Verify rather than assume -- this is the exact failure that shipped.
if [ -r "${SMTP_MU_DIR}/01-wpvm-smtp.php" ]; then
  ok "SMTP transport mu-plugin installed"
else
  warn "SMTP transport mu-plugin FAILED to install — wp_mail() will fail silently"
fi

# MFA enforcement. Unconditional install (the mu-plugin is a no-op when
# WPVM_MFA_ENFORCE is 0), same block as the others for the same reason.
# Enforcement and grace are substituted from the install-time answers; the
# mu-plugin holds them as constants so a compromised admin session cannot
# widen the grace window to defeat the control.
install -m 0644 "${PAYLOAD_DIR}/mu-plugins/03-wpvm-mfa-enforce.php" "${SMTP_MU_DIR}/03-wpvm-mfa-enforce.php"
sed -i \
  -e "s|WPVM_MFA_ENFORCE_PLACEHOLDER|${MFA_ENFORCE:-0}|g" \
  -e "s|WPVM_MFA_GRACE_PLACEHOLDER|${MFA_GRACE_DAYS:-7}|g" \
  "${SMTP_MU_DIR}/03-wpvm-mfa-enforce.php"
chown 33:33 "${SMTP_MU_DIR}/03-wpvm-mfa-enforce.php" 2>/dev/null || true
# A leftover placeholder would be a PHP parse error -> site-wide fatal, and an
# mu-plugin cannot be disabled from wp-admin, so this is checked now while a
# console still exists to fix it.
#
# BUG FIX (found on the first real hardware install): this used to verify with
# `PRUN exec wordpress php -l ...`, but at THIS point in the stage the
# WordPress container has not been created yet -- it is pulled and started
# below. So the exec always failed, and every install reported
# "MFA mu-plugin failed php -l — NOT enforcing", regardless of whether the file
# was fine. A check whose failure mode is "always warn" trains people to ignore
# it, and here it also silently disabled a security control that was working.
#
# The placeholder check below needs no container, so it stays here. The real
# php -l is deferred to _verify_mfa_mu_plugin, called after WordPress is up.
if grep -q "WPVM_MFA_.*_PLACEHOLDER" "${SMTP_MU_DIR}/03-wpvm-mfa-enforce.php" 2>/dev/null; then
  warn "MFA mu-plugin still has a placeholder — enforcement will fatal. Fix by hand."
else
  ok "MFA enforcement mu-plugin written (php -l verified once WordPress is up)"
fi

# Verify the mu-plugin parses, once there is a container able to parse it.
# Called after the WordPress container is confirmed running.
_verify_mfa_mu_plugin() {
  [ -f "${SMTP_MU_DIR}/03-wpvm-mfa-enforce.php" ] || return 0
  if PRUN exec wordpress php -l /var/www/html/wp-content/mu-plugins/03-wpvm-mfa-enforce.php >/dev/null 2>&1; then
    if [ "${MFA_ENFORCE:-0}" = "1" ]; then
      ok "MFA enforcement active (required for admins, ${MFA_GRACE_DAYS:-7}-day grace)"
    else
      ok "MFA enforcement mu-plugin verified (present, enforcement OFF)"
    fi
  else
    warn "MFA mu-plugin failed php -l — NOT enforcing. Inspect:"
    warn "  doas podman exec wordpress php -l /var/www/html/wp-content/mu-plugins/03-wpvm-mfa-enforce.php"
  fi
}

# NOTE: the Two Factor PLUGIN (the TOTP/backup-code machinery this mu-plugin
# enforces) is installed in stage 08, after wp-plugins.sh exists to install it.
# The mu-plugin above is a safe no-op until the plugin is present -- it detects
# absence and shows an admin notice rather than locking anyone out.

# The mu-plugin needs to know the proxy's address to notice when it has
# become the apparent client -- the symptom of mod_remoteip not applying.
# Written next to the SMTP config because that directory is already mounted
# read-only into the container; it is not a secret, just a fact PHP needs.
if [ -n "${PROXY_IP:-}" ]; then
  printf '%s\n' "$PROXY_IP" > /home/wpuser/wp/secrets/proxy.txt
  chmod 0444 /home/wpuser/wp/secrets/proxy.txt
  chown root:33 /home/wpuser/wp/secrets/proxy.txt 2>/dev/null || true
fi

WP_EXTRA_VOLS="-v /home/wpuser/wp/secrets:/var/www/private:ro"
WP_VOL_ARGS="${WP_VOL_ARGS} ${WP_EXTRA_VOLS}"

# REGRESSION FIX (found in a real deployment): wp-geoip-setup.sh rebuilds
# the WordPress container from scratch with its OWN hardcoded env and volume
# list. Anything added here and not mirrored there is silently discarded the
# moment GeoIP runs -- which is exactly what happened to the site-address
# config (WP_HOME/WP_SITEURL/proxy) and the SMTP credential mount. Rather
# than duplicate them into a second place and create the same trap again,
# write them once here and have wp-geoip-setup.sh source this file. One
# definition, so the two paths cannot drift apart.
mkdir -p /etc/wp-install
{
  printf 'WP_CONFIG_EXTRA=%s\n' "$(printf '%s' "$WP_CONFIG_EXTRA" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/")"
  printf 'WP_EXTRA_VOLS=%s\n'   "$(printf '%s' "${WP_EXTRA_VOLS:-}" | sed "s/'/'\\\\''/g; s/^/'/; s/$/'/")"
} > /etc/wp-install/wp-run-extra.env
chmod 600 /etc/wp-install/wp-run-extra.env

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
  -e WORDPRESS_CONFIG_EXTRA="${WP_CONFIG_EXTRA}" \
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

# ── Verify wp-config.php actually received WORDPRESS_CONFIG_EXTRA ────────────
# The official image writes wp-config.php ONLY on first run. Once the file
# exists, WORDPRESS_CONFIG_EXTRA is ignored entirely -- so any later recreation
# of the container (the GeoIP rebuild does exactly this) cannot add defines,
# and passing the variable correctly is not the same as the defines arriving.
#
# Found on a live VM: WP_PROXY_HOST was absent from wp-config.php while the
# egress proxy was enabled. WordPress's HTTP API therefore had no proxy, and
# `wp plugin install` failed with "An unexpected error occurred. Something may
# be wrong with WordPress.org or this server's configuration" -- WITHOUT ever
# opening a connection, which Squid's access log confirmed by showing nothing
# at all for those attempts. Two sessions were spent on egress theories for a
# proxy that was working perfectly; the request never reached it.
#
# So verify the file rather than trusting the variable, and repair it in place.
_WPCFG=/home/wpuser/wp/html/wp-config.php
if [ -f "$_WPCFG" ] && [ -n "${WP_CONFIG_EXTRA:-}" ]; then
  _missing=0
  for _need in WP_PROXY_HOST DISALLOW_FILE_MODS WP_HOME; do
    case "$WP_CONFIG_EXTRA" in
      *"$_need"*)
        grep -q "$_need" "$_WPCFG" 2>/dev/null || _missing=1 ;;
    esac
  done
  if [ "$_missing" = 1 ]; then
    warn "wp-config.php is missing defines that were passed to the container."
    warn "  The image writes that file only on first run, so a later rebuild"
    warn "  cannot add them. Injecting them now."
    cp -a "$_WPCFG" "${_WPCFG}.pre-inject" 2>/dev/null || true
    # Insert before the marker the image itself writes.
    _tmp=$(mktemp) || _tmp=""
    if [ -n "$_tmp" ]; then
      awk -v extra="$WP_CONFIG_EXTRA" '
        /That.s all, stop editing/ && !done { print extra; done=1 }
        { print }
      ' "$_WPCFG" > "$_tmp" && mv -f "$_tmp" "$_WPCFG"
      chown 33:33 "$_WPCFG" 2>/dev/null || true
      chmod 640 "$_WPCFG" 2>/dev/null || true
      if grep -q WP_PROXY_HOST "$_WPCFG" 2>/dev/null || [ "${EGRESS_PROXY:-0}" != "1" ]; then
        ok "  wp-config.php repaired (backup at ${_WPCFG}.pre-inject)"
        podman restart wordpress >/dev/null 2>&1 || true
      else
        warn "  Injection did not take — inspect ${_WPCFG} by hand."
      fi
    fi
  else
    ok "  wp-config.php contains the expected defines"
  fi
fi

# ── Re-assert the mu-plugins now that WordPress has finished unpacking ───────
# These were written BEFORE the container's first start, which is too early.
# The official image's entrypoint extracts WordPress core into the docroot when
# index.php is absent -- precisely the state at that moment -- and that
# extraction brings its own wp-content, which can displace what we just put
# there. On a real VM the result was `wp-mail.sh doctor` reporting
# "mu-plugin: MISSING" while validate-wordpress.sh reported it installed: the
# two ran either side of validate-wordpress silently reinstalling it.
#
# Relying on a later tool to repair this is not a design, it is a coincidence
# that happened to work. Re-install here, idempotently, at the first moment the
# docroot is settled.
for _mu in 01-wpvm-smtp.php 03-wpvm-mfa-enforce.php; do
  [ -f "${PAYLOAD_DIR}/mu-plugins/${_mu}" ] || continue
  if [ ! -f "${SMTP_MU_DIR}/${_mu}" ]; then
    install -m 0644 "${PAYLOAD_DIR}/mu-plugins/${_mu}" "${SMTP_MU_DIR}/${_mu}"
    # The MFA one carries placeholders that must be substituted again.
    if [ "$_mu" = "03-wpvm-mfa-enforce.php" ]; then
      sed -i \
        -e "s|WPVM_MFA_ENFORCE_PLACEHOLDER|${MFA_ENFORCE:-0}|g" \
        -e "s|WPVM_MFA_GRACE_PLACEHOLDER|${MFA_GRACE_DAYS:-7}|g" \
        "${SMTP_MU_DIR}/${_mu}"
    fi
    chown 33:33 "${SMTP_MU_DIR}/${_mu}" 2>/dev/null || true
    warn "  Re-installed ${_mu} — the container's first-run extraction had removed it"
  fi
done
mkdir -p "${SMTP_MU_DIR}" 2>/dev/null || true
chown 33:33 "${SMTP_MU_DIR}" 2>/dev/null || true

# Now that a WordPress container exists, it can parse the mu-plugin. This was
# attempted far too early in an earlier version and always failed.
_verify_mfa_mu_plugin

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
# So without a WordPress-side fix, the sequence is: visit the slug (works,
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
    ok "Login slug mu-plugin installed (login at /${WP_ADMIN_SLUG})"
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
    # The rebuild replaces the running WordPress container, so a failure here
    # can leave the site down rather than merely leaving GeoIP off. Report
    # that plainly instead of continuing as if only a feature were missing.
    if ! PRUN ps --filter 'name=^wordpress$' --filter status=running --format '{{.Names}}' 2>/dev/null | grep -qx wordpress; then
      warn "  WordPress is NOT running after the GeoIP rebuild — the site is DOWN."
      warn "  Check: podman logs --tail 50 wordpress"
    fi
    # Same fail-closed rule this profile already applies to image
    # verification, digest pinning, the CrowdSec bouncer and sysctls: a
    # requested security control that did not actually take effect is a
    # failed production install, not a warning. Country filtering silently
    # inactive means every request is being allowed through -- precisely the
    # false sense of protection this profile exists to prevent.
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      err "GeoIP country filtering was requested but is not active, and the WordPress container may be unhealthy. Refusing to finish under DEPLOYMENT_PROFILE=production. See /var/log/wp-geoip.log and 'podman logs wordpress'. Re-run under standard if an install without country filtering is acceptable."
    fi
  fi
elif [ "${GEOIP_ENABLED:-0}" = "1" ]; then
  warn "GeoIP was enabled but MaxMind credentials are missing — skipping GeoIP setup"
fi

