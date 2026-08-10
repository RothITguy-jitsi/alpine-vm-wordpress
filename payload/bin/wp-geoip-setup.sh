#!/bin/sh
# wp-geoip-setup.sh — (Re)apply MaxMind GeoIP country filtering.
# Safe to re-run anytime on a live VM: no reboot, no full reinstall needed.
# Reads credentials/mode from /etc/wp-install/vars.sh, written at
# provisioning time (edit that file to fix bad credentials, then re-run
# this script). Exit code 0 = applied, 1 = failed (see the log below).
LOG=/var/log/wp-geoip.log
exec >> "$LOG" 2>&1
echo ""
echo "=== [$(date '+%Y-%m-%d %H:%M:%S')] wp-geoip-setup.sh starting ==="

[ "$(id -u)" -eq 0 ] || { echo "FATAL: must run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
PRUN() {
  podman "$@"
}

if [ "${GEOIP_ENABLED:-0}" != "1" ]; then
  echo "GEOIP_ENABLED is not 1 in /etc/wp-install/vars.sh — nothing to do."
  echo "Set GEOIP_ENABLED=1, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, GEOIP_MODE"
  echo "(whitelist|blocklist), and GEOIP_WHITELIST or GEOIP_BLOCKLIST there, then re-run."
  exit 0
fi
if [ -z "${MAXMIND_ACCOUNT_ID:-}" ] || [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "FATAL: MaxMind Account ID / License Key missing from /etc/wp-install/vars.sh"
  exit 1
fi

# BUG FIX (v7-12, #11): credentials to a netrc file, never on a curl
# command line. `curl -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY"` (the
# previous form, used both here and in the weekly refresh cron job below)
# puts the license key directly into that process's own argv — visible to
# anything on this VM that can read /proc/<pid>/cmdline (or run `ps aux`)
# for as long as the download takes. The cron line had it worse: the same
# credentials sat spelled out in plain text in /etc/crontabs/root itself,
# in addition to reappearing in argv every Wednesday when cron actually
# ran it. A netrc file holds the same credentials at rest — chmod 600,
# root-owned, the same protection level /etc/wordpress/env and
# /root/.wp-credentials already get elsewhere in this script — and both
# this script's own download and the cron job it writes now reference it
# by PATH ONLY via --netrc-file. The credentials themselves never sit on a
# command line again. Rewritten every run (built with printf, one value
# per line, rather than a heredoc — nothing to reason about regarding
# expansion rules for a file that's about to hold this VM's most sensitive
# external credential) so an updated vars.sh — this script's own
# documented way to fix a bad MaxMind credential — is always picked up.
MAXMIND_NETRC="/etc/wp-install/.maxmind-netrc"
mkdir -p /etc/wp-install
{
  printf 'machine download.maxmind.com\n'
  printf 'login %s\n' "$MAXMIND_ACCOUNT_ID"
  printf 'password %s\n' "$MAXMIND_LICENSE_KEY"
} > "$MAXMIND_NETRC"
chmod 600 "$MAXMIND_NETRC"

# Defensive (spotted while fixing #11): curl is used below for MaxMind's
# HTTP Basic Auth download API — wget, used elsewhere in this script for
# the mod_maxminddb release lookup, has no --netrc-file equivalent, so the
# fix above depends on curl specifically. Nothing in this script's Alpine
# provisioning actually installs curl on the VM (it's only ever apt-get
# installed inside the transient, Debian-based mod_maxminddb build
# container below — a completely different context) — install it here if
# missing so this script stays genuinely standalone/rerunnable per its own
# header, instead of silently depending on curl having arrived some other
# way.
command -v curl >/dev/null 2>&1 || apk add --no-cache curl >/dev/null 2>&1 \
  || { echo "FATAL: curl is unavailable and 'apk add curl' failed — cannot fetch GeoLite2-Country"; exit 1; }

CURRENT_WP_IMAGE=$(PRUN inspect wordpress --format '{{.Config.Image}}' 2>/dev/null)
[ -z "$CURRENT_WP_IMAGE" ] && CURRENT_WP_IMAGE="docker.io/wordpress:6.9.6-php8.4-apache"
# Derive a human-friendly tag for naming the local GeoIP image.
# BUG FIX (v7-6f): the Skopeo rewrite of digest pinning dropped the "does
# this Podman accept a combined tag+digest reference" test — every pinned
# reference is now digest-only (repo@sha256:..., no tag at all), ALWAYS,
# not just on the subset of hosts where the combined form used to fail.
# That leaves CURRENT_WP_IMAGE's own string with no tag to parse out once
# pinning is on, so the old heuristic here (parse a tag out of the image
# string, only falling back to a short digest fragment when none was
# present) would now hit that fallback on every single run — every GeoIP
# rebuild producing a digest-fragment tag (wordpress-geoip:a1b2c3d4e5f6)
# instead of a readable one (wordpress-geoip:6.9.6-php8.4-apache).
# /etc/wp-install/pinned.env carries the tag separately from the image
# reference for exactly this reason (see the installer's PERSIST comment) —
# read WP_TAG from there first. Only fall back to parsing CURRENT_WP_IMAGE
# itself when pinned.env has no tag to offer (digest pinning disabled, or
# the file is missing/not yet written).
WP_TAG_FROM_PIN=""
[ -f /etc/wp-install/pinned.env ] && WP_TAG_FROM_PIN=$(. /etc/wp-install/pinned.env; echo "$WP_TAG")
if [ -n "$WP_TAG_FROM_PIN" ]; then
  WP_TAG_PORTION="$WP_TAG_FROM_PIN"
else
  WP_BASE_NO_DIGEST=$(echo "${CURRENT_WP_IMAGE}" | sed 's|@sha256:.*||')
  case "$WP_BASE_NO_DIGEST" in
    *:*) WP_TAG_PORTION="${WP_BASE_NO_DIGEST##*:}" ;;
    *)   WP_TAG_PORTION=$(echo "${CURRENT_WP_IMAGE}" | grep -oE 'sha256:[0-9a-f]{12}' | sed 's|sha256:||' || true)
         [ -z "$WP_TAG_PORTION" ] && WP_TAG_PORTION="latest"
         ;;
  esac
fi
WP_TAG_PORTION=$(echo "$WP_TAG_PORTION" | sed 's|^geoip-||')
GEOIP_IMG_TAG="localhost/wordpress-geoip:${WP_TAG_PORTION}"
echo "Base image: ${CURRENT_WP_IMAGE}  ->  Target: ${GEOIP_IMG_TAG}"

mkdir -p /home/wpuser/wp/geoip-build /home/wpuser/wp/geoip-db /home/wpuser/wp/apache-mods

MMDB_ASSET_URL=$(wget -qO- https://api.github.com/repos/maxmind/mod_maxminddb/releases/latest 2>/dev/null \
  | grep -oE '"browser_download_url":\s*"[^"]*mod_maxminddb-[0-9.]+\.tar\.gz"' \
  | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')
if [ -z "$MMDB_ASSET_URL" ]; then
  MMDB_ASSET_URL="https://github.com/maxmind/mod_maxminddb/releases/download/1.2.0/mod_maxminddb-1.2.0.tar.gz"
  echo "GitHub API lookup failed — using pinned mod_maxminddb 1.2.0"
else
  echo "Latest mod_maxminddb release: $(basename "$MMDB_ASSET_URL")"
fi

cat > /home/wpuser/wp/geoip-build/Containerfile << CONTAINERFILE
FROM ${CURRENT_WP_IMAGE} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2-dev libmaxminddb-dev build-essential curl ca-certificates \
    && curl -fsSL -o /tmp/mod_maxminddb.tar.gz "${MMDB_ASSET_URL}" \
    && mkdir -p /tmp/build && tar xzf /tmp/mod_maxminddb.tar.gz -C /tmp/build --strip-components=1 \
    && cd /tmp/build && ./configure --with-apxs=/usr/bin/apxs && make \
    && find /tmp/build -name 'mod_maxminddb.so' -exec cp {} /tmp/mod_maxminddb.so \; \
    && test -s /tmp/mod_maxminddb.so || { echo "FATAL: mod_maxminddb.so not found anywhere under /tmp/build after make — the mod_maxminddb build layout may have changed upstream" >&2; exit 1; } \
    && mkdir -p /tmp/deps \
    && find /usr/lib -name 'libmaxminddb.so.0*' -exec cp -L {} /tmp/deps/ \; \
    && ls /tmp/deps/libmaxminddb.so.0 >/dev/null 2>&1 || { echo 'FATAL: libmaxminddb.so.0 not found in the builder - it must be carried into the final image or Apache cannot load the module' >&2; exit 1; }

FROM ${CURRENT_WP_IMAGE}
COPY --from=builder /tmp/mod_maxminddb.so /etc/apache2/maxminddb-module/mod_maxminddb.so
# ROOT-CAUSE FIX (found in a real deployment): mod_maxminddb.so is linked
# against libmaxminddb (see '-lmaxminddb' in the build output). The builder
# stage gets libmaxminddb0 as a dependency of libmaxminddb-dev, but THIS
# stage starts fresh from the base WordPress image, which does not ship it.
# Copying only the module produced a .so with an unsatisfiable runtime
# dependency: Apache's LoadModule dlopen() failed with
# "libmaxminddb.so.0: cannot open shared object file", Apache refused to
# start, and the container exited instantly -- after the working container
# had already been destroyed. The build itself SUCCEEDED, which is what
# made this so quiet. /usr/local/lib is on Debian's default ld.so search
# path, so ldconfig is all that is needed to make it resolvable.
COPY --from=builder /tmp/deps/ /usr/local/lib/
# Fail the BUILD rather than the site if anything is still unresolved --
# the check whose absence let a structurally broken image reach production.
RUN ldconfig && if ldd /etc/apache2/maxminddb-module/mod_maxminddb.so | grep 'not found'; then echo 'FATAL: mod_maxminddb.so has unresolved shared library dependencies - loading it would make Apache refuse to start' >&2; exit 1; fi
CONTAINERFILE

echo "Building ${GEOIP_IMG_TAG} — using --network host (the wp-front/wp-db-only nftables"
echo "forward rule otherwise drops this build container's internet access, which"
echo "was the actual cause of GeoIP silently failing to apply)…"
if ! podman build --network host -t "${GEOIP_IMG_TAG}" -f /home/wpuser/wp/geoip-build/Containerfile /home/wpuser/wp/geoip-build; then
  echo "FATAL: podman build failed — the output directly above is the real apt-get/curl/make error."
  exit 1
fi
echo "Custom image built: ${GEOIP_IMG_TAG}"

cat > /home/wpuser/wp/apache-mods/maxminddb.load << 'MMLOAD'
LoadModule maxminddb_module /etc/apache2/maxminddb-module/mod_maxminddb.so
MMLOAD
chmod 644 /home/wpuser/wp/apache-mods/maxminddb.load

echo "Fetching GeoLite2-Country database…"
# v7-16: -L is REQUIRED. MaxMind's download endpoint returns a 302 redirect
# to a pre-signed CDN URL (S3/CloudFront); without -L curl stops at the 302,
# writes the tiny redirect body to the output file instead of the database,
# and the "!= 200" check below fails with 302 — the exact field failure
# ("GeoLite2 download failed — HTTP 302"). curl does not resend the netrc
# credentials across the redirect to the CDN host, which is correct: the
# redirect URL is already pre-signed, so no credentials are needed there.
# With -L, %{http_code} reports the FINAL response (200 from the CDN). The
# weekly refresh cron already uses -fsSL; this makes the initial fetch match.
HTTP_CODE=$(curl -sSL -o /tmp/geolite2-country.tar.gz -w '%{http_code}' \
  --netrc-file "$MAXMIND_NETRC" \
  'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz')
if [ "$HTTP_CODE" != "200" ]; then
  echo "FATAL: GeoLite2 download failed — HTTP ${HTTP_CODE}."
  case "$HTTP_CODE" in
    401) echo "  401 = wrong MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY." ;;
    403) echo "  403 = credentials valid, but this key isn't permitted to download GeoLite2." ;;
    *)   echo "  Check outbound access to download.maxmind.com from this host." ;;
  esac
  rm -f /tmp/geolite2-country.tar.gz
  exit 1
fi
mkdir -p /tmp/geolite-extract
tar xzf /tmp/geolite2-country.tar.gz -C /tmp/geolite-extract --strip-components=1
# mmdblookup ships in libmaxminddb and is what makes `wp-hardening.sh
# geoip-test <ip>` able to resolve an address. Installing GeoIP without it
# gives an operator a test command that reports "mmdblookup is not installed"
# — telling them to go and install something in order to check the thing they
# just enabled. It is ~100 KB and touches nothing in the containers.
apk add --no-cache libmaxminddb >/dev/null 2>&1 \
  && echo "  mmdblookup installed (geoip-test can resolve addresses)" \
  || echo "  note: libmaxminddb not installed; geoip-test cannot resolve IPs"
find /tmp/geolite-extract -name '*.mmdb' -exec cp {} /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb \;
rm -rf /tmp/geolite-extract /tmp/geolite2-country.tar.gz
if [ ! -s /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb ]; then
  echo "FATAL: download succeeded but no .mmdb file was extracted."
  exit 1
fi
chmod 644 /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb
echo "GeoLite2-Country.mmdb ready ($(du -h /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb | cut -f1))"

if [ "${GEOIP_MODE}" = "whitelist" ]; then
  GEOIP_CC_PATTERN=$(echo "${GEOIP_WHITELIST}" | tr -d ' ' | tr ',' '|')
  GEOIP_REQUIRE_LINE="    Require env AllowCountry"
  GEOIP_SETENV_LINE="SetEnvIf MM_COUNTRY_CODE \"^(${GEOIP_CC_PATTERN})\$\" AllowCountry"
else
  GEOIP_CC_PATTERN=$(echo "${GEOIP_BLOCKLIST}" | tr -d ' ' | tr ',' '|')
  GEOIP_REQUIRE_LINE="    Require not env BlockCountry"
  GEOIP_SETENV_LINE="SetEnvIf MM_COUNTRY_CODE \"^(${GEOIP_CC_PATTERN})\$\" BlockCountry"
fi

cat > /home/wpuser/wp/apache-conf/geoip.conf << GEOIPCONF
# GeoIP country filtering — generated by wp-geoip-setup.sh
# Mode: ${GEOIP_MODE}   Countries: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}
# Database refreshed weekly via host cron (Wed 06:00 UTC).
<IfModule maxminddb_module>
    MaxMindDBEnable On
    MaxMindDBFile COUNTRY_DB /usr/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBEnv MM_COUNTRY_CODE COUNTRY_DB/country/iso_code

    ${GEOIP_SETENV_LINE}

    # FIX 1: <RequireAll> is an authorization container and Apache only
    # permits it in DIRECTORY context (<Directory>, <Location>, <Files>,
    # .htaccess). This file is dropped into conf-enabled/, which is SERVER
    # context, so an unwrapped <RequireAll> here is rejected outright with
    # "AH00526: <RequireAll not allowed here" and Apache refuses to start --
    # taking the whole site down, not just country filtering. <Location />
    # is the correct wrapper for a site-wide rule: it is valid context and
    # it matches every URL, including ones with no filesystem mapping.
    <Location />
        <RequireAny>
            # FIX 2: private and loopback addresses have NO country in the
            # GeoLite2 database, so they can never satisfy the country test
            # below. Without these exemptions a whitelist install 403s:
            #   - the in-container health check (127.0.0.1), so the install
            #     can never see WordPress as healthy;
            #   - the operator's own LAN access to wp-admin;
            #   - anything else reaching the site from an RFC1918 address.
            # This does not weaken the filter for real visitors: when a
            # reverse proxy is in front, mod_remoteip has already replaced
            # the connection address with the real client IP from
            # X-Forwarded-For before authorization runs, so a remote visitor
            # is still matched on their own address, not the proxy's.
            Require ip 127.0.0.1
            Require ip ::1
            Require ip 10.0.0.0/8
            Require ip 172.16.0.0/12
            Require ip 192.168.0.0/16
            <RequireAll>
                Require env MM_COUNTRY_CODE
${GEOIP_REQUIRE_LINE}
            </RequireAll>
        </RequireAny>
    </Location>
</IfModule>
GEOIPCONF
chmod 644 /home/wpuser/wp/apache-conf/geoip.conf
echo "geoip.conf written (${GEOIP_MODE}: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})"

WEB_CHECK_PORT=80

# REGRESSION FIX: this block rebuilds the container from scratch, so it must
# use the SAME wp-config extras and extra mounts stage 06 used -- otherwise
# enabling GeoIP silently strips the site address (WP_HOME/WP_SITEURL, the
# reverse-proxy scheme handling) and the SMTP credential mount, turning off
# outbound mail with no error anywhere. Sourced rather than re-derived so
# there is exactly one definition of them.
WP_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);'
WP_EXTRA_VOLS=""
if [ -r /etc/wp-install/wp-run-extra.env ]; then
  . /etc/wp-install/wp-run-extra.env
  echo "Reusing wp-config extras and extra mounts recorded at install time"
else
  echo "WARNING: /etc/wp-install/wp-run-extra.env missing — falling back to base"
  echo "  wp-config extras. If a site domain or SMTP relay was configured, they"
  echo "  will NOT survive this rebuild. Re-run install or re-add them by hand."
fi

echo "Recreating WordPress container with GeoIP module + database mounted…"
# SYSTEMIC FIX: the next line destroys the running WordPress container. If
# the freshly built image cannot start, the working site is already gone --
# exactly what happened in the field. Every other risky swap in this project
# validates a candidate before cutting over (update.sh's loopback-candidate
# pattern); this one did not. Prove the image can load its modules and parse
# its config first, with Apache's own configtest, in a throwaway container
# that touches nothing.
echo "Smoke-testing the new image before touching the running container..."
# The smoke test must mount EVERY file the real container mounts, or it
# validates a container that does not exist. Maintaining a second hand-written
# list is how that goes wrong: the first version mounted only maxminddb.load
# and passed an invalid geoip.conf; the second added geoip.conf and
# wp-security.conf but omitted headers.load, so configtest failed on
# "Invalid command 'Header'" -- a mod_headers directive with the module not
# enabled. Both were faults in the TEST, not the image.
#
# So the list is built once, here, and used for both the smoke test and the
# real run below. Optional files are added only when present, exactly as the
# real run does.
GEOIP_VOL_ARGS="-v /home/wpuser/wp/html:/var/www/html"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/logs:/var/log/apache2"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/apache-conf/geoip.conf:/etc/apache2/conf-enabled/geoip.conf:ro"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/maxminddb.load:/etc/apache2/mods-enabled/maxminddb.load:ro"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw"
GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/geoip-db:/usr/share/GeoIP:ro"
# mod_remoteip config is only present when a reverse proxy was configured.
[ -f /home/wpuser/wp/apache-mods/remoteip.conf ] && \
  GEOIP_VOL_ARGS="${GEOIP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"

_SMOKE=$(podman run --rm ${GEOIP_VOL_ARGS} ${WP_EXTRA_VOLS} \
  --entrypoint apache2ctl "${GEOIP_IMG_TAG}" configtest 2>&1) || true
case "$_SMOKE" in
  *"Syntax OK"*)
    echo "Smoke test passed - Apache loads mod_maxminddb in the new image" ;;
  *)
    echo "FATAL: the new GeoIP image fails Apache's own config test, so it would"
    echo "  exit immediately on start. The RUNNING WordPress container has NOT"
    echo "  been touched - the site is still up and still serving."
    echo ""
    echo "  apache2ctl configtest said:"
    printf '    %s\n' "$_SMOKE"
    echo ""
    echo "  Nothing was changed. Fix the build issue, then re-run:"
    echo "    /usr/local/bin/wp-geoip-setup.sh"
    exit 1 ;;
esac

podman rm -f wordpress >/dev/null 2>&1 || true
podman run -d \
  --name wordpress --network wp-front --ip 10.89.10.3 -p 80:80 --restart always \
  --label io.containers.autoupdate=image \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
  --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --pids-limit 200 --memory=768m --cpu-shares=512 \
  --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
  --env-file /etc/wordpress/env \
  -e WORDPRESS_DB_HOST=mariadb:3306 \
  -e WORDPRESS_DEBUG="" \
  -e WORDPRESS_CONFIG_EXTRA="${WP_CONFIG_EXTRA}" \
  ${WP_EXTRA_VOLS} \
  ${GEOIP_VOL_ARGS} \
  "${GEOIP_IMG_TAG}"
podman network connect --ip 10.89.20.3 wp-db wordpress
sed -i "s|WP_IMAGE=.*|WP_IMAGE=\"${GEOIP_IMG_TAG}\"|" /etc/init.d/wp-container 2>/dev/null || true
sed -i "s|^PINNED_WP_VER=.*|PINNED_WP_VER=\"geoip-$(echo "${GEOIP_IMG_TAG}" | sed 's|.*:||')\"|" /usr/local/bin/update.sh 2>/dev/null || true

sleep 5
PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
# BUG FIX (v7-6g): this used to be a bare `wget -qO-` check, which passes on
# a DB-connection-error page or a PHP fatal-error page just as readily as on
# a working site — meaningless right after swapping to a newly-built GeoIP
# image, exactly the moment a broken mod_maxminddb build or a bad mount is
# most likely to surface. Use the same full health check (HTTP + PHP + DB
# name resolution + DB auth + a real SELECT 1) as the rest of the script,
# falling back to the old bare check only if wp-health-check.sh is somehow
# missing (e.g. this script run standalone on a VM provisioned before v7-6g).
echo "Validating GeoIP-enabled WordPress health (HTTP + PHP + DB name resolution + DB auth + real query)…"
GEOIP_WP_READY=0
for i in $(seq 1 12); do
  if [ -x /usr/local/bin/wp-health-check.sh ]; then
    if /usr/local/bin/wp-health-check.sh wordpress "${WEB_CHECK_PORT}"; then
      GEOIP_WP_READY=1; break
    fi
  else
    wget -qO- -U "wp-health-check/1.0" "http://127.0.0.1:${WEB_CHECK_PORT}/" >/dev/null 2>&1 && { GEOIP_WP_READY=1; break; }
  fi
  sleep 5
done
if [ "$GEOIP_WP_READY" = "1" ]; then
  echo "WordPress responding and healthy with GeoIP active"
else
  # REGRESSION FIX (found in a real deployment): this used to print a warning
  # and then fall through to a normal exit 0. The caller in stage 06 tests
  # this script's exit status, so a zero here made the installer report
  # "GeoIP filtering active" while the container it had just rebuilt was
  # exiting on startup and mod_maxminddb was not loaded at all -- the site
  # was down and the install still declared success. A rebuild that leaves
  # WordPress unhealthy is a failure and now exits non-zero to say so.
  #
  # No automatic rollback to the pre-GeoIP container: reconstructing that
  # run command here is exactly the duplication that caused the config-drift
  # bug fixed above, and getting it subtly wrong would swap one broken
  # container for a differently broken one. The operator gets the state and
  # the commands instead.
  echo "ERROR: WordPress did not pass health validation after the GeoIP rebuild."
  echo "  The site is very likely DOWN right now. Most common cause is that"
  echo "  Apache cannot load mod_maxminddb, which makes it refuse to start."
  echo ""
  echo "  Diagnose:  podman logs --tail 50 wordpress"
  echo "             podman exec wordpress apache2ctl -M 2>&1 | grep -i maxmind"
  echo "             tail -40 /var/log/wp-geoip.log"
  echo ""
  echo "  Recover without GeoIP (restores a working site):"
  echo "             sed -i 's/^GEOIP_ENABLED=.*/GEOIP_ENABLED=0/' /etc/wp-install/vars.sh"
  echo "             rc-service wp-container restart"
  echo ""
  echo "  Then re-enable once the build issue is understood:"
  echo "             /usr/local/bin/wp-geoip-setup.sh"
  exit 1
fi

grep -q "GeoLite2-Country database refresh" /etc/crontabs/root 2>/dev/null || cat >> /etc/crontabs/root << GEOCRON
# Weekly GeoLite2-Country database refresh (Wednesday 06:00 UTC)
# Credentials read from ${MAXMIND_NETRC} (chmod 600, root-owned) via
# --netrc-file — never placed on this line, so they never sit in
# /etc/crontabs/root itself or reappear in argv/ps output while cron runs it.
0 6 * * 3 curl -fsSL --netrc-file ${MAXMIND_NETRC} 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz' -o /tmp/geolite-refresh.tar.gz && mkdir -p /tmp/geolite-refresh && tar xzf /tmp/geolite-refresh.tar.gz -C /tmp/geolite-refresh --strip-components=1 && find /tmp/geolite-refresh -name '*.mmdb' -exec cp {} /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb \; && rm -rf /tmp/geolite-refresh /tmp/geolite-refresh.tar.gz && logger -t geoip-update "GeoLite2-Country refreshed"
GEOCRON

echo "=== wp-geoip-setup.sh done — GeoIP ${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}) active ==="
