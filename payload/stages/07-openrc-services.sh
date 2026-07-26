#!/bin/sh
# 07-openrc-services.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Creates the mariadb-container and wp-container OpenRC service definitions.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Creating mariadb-container service"
# v8 (production fail-closed toggle): choose the nftables dependency strength
# by deployment profile. standard = "use" (soft): ordering is enforced when
# both are enabled, but a firewall problem can't stop the DB from coming up —
# availability first, matching lab/staging expectations. production = "need"
# (hard): if nftables fails to start, MariaDB does not start, and because
# wp-container needs mariadb-container and crowdsec needs wp-container, the
# whole publicly-exposed stack stays down rather than running unprotected —
# fail-closed security. DEPLOYMENT_PROFILE was sourced from vars.sh near the
# top of this installer. Only this service needs the toggle; the dependency
# propagates transitively to wp-container and crowdsec-container.
if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
  NFT_SVC_DEP="need nftables"
else
  NFT_SVC_DEP="use nftables"
fi
sed -e "s|__DB_IMAGE__|${DB_IMAGE}|g" -e "s|__NFT_SVC_DEP__|${NFT_SVC_DEP}|g" \
  "${PAYLOAD_DIR}/templates/init.d-mariadb-container.tmpl" > /etc/init.d/mariadb-container
chmod +x /etc/init.d/mariadb-container
rc-update add mariadb-container default 2>/dev/null || true
ok "mariadb-container service registered"

# ── OpenRC: wp-container ──────────────────────────────────────────────────────
ts "Creating wp-container service"
# Determine remoteip volume mounts for the service script
# headers.load is always mounted (mod_headers not pre-enabled in WP image).
# remoteip.load is NOT mounted (already pre-enabled in WP image — would warn).
# remoteip.conf only mounted if a trusted proxy was configured (file exists).
SVC_HEADERS_VOL='-v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw'
SVC_REMOTEIP_VOLS=''
if [ -f /home/wpuser/wp/apache-mods/remoteip.conf ]; then
  SVC_REMOTEIP_VOLS='\\
      -v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro'
fi

cat > /etc/init.d/wp-container << ORCSVC_WP
#!/sbin/openrc-run
name="wp-container"
description="WordPress Apache (rootful Podman, wp-front, port 80)"
# Install-time snapshot — used only as a fallback if /etc/wp-install/
# pinned.env can't be read when this service needs to recreate the
# container from scratch (see start(), below).
WP_IMAGE="${WP_IMAGE}"

depend() {
  need net mariadb-container
  after sysfs mariadb-container
}

start() {
  ebegin "Starting WordPress"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  lsmod | grep -q '^overlay' || modprobe overlay 2>/dev/null || true
  lsmod | grep -q '^fuse'    || modprobe fuse    2>/dev/null || true
  if [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \\
     && [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  if podman container exists wordpress 2>/dev/null; then
    podman start wordpress >/dev/null 2>&1
    # Fix uploads ownership after every start (entrypoint creates dirs as root)
    sleep 3 && podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
  else
    podman rm -f wordpress 2>/dev/null || true
    # Prefer the live pin over the install-time WP_IMAGE snapshot above —
    # same rationale as mariadb-container — but ONLY when WP_IMAGE isn't
    # already a locally-built GeoIP image (localhost/wordpress-geoip:...):
    # a GeoIP layer has no upstream registry digest of its own to
    # reconstruct from pinned.env (WP_DIGEST there is always the upstream
    # wordpress image, not the local GeoIP build). Recreating from the
    # existing GeoIP tag as-is is still correct here; re-run
    # wp-geoip-setup.sh afterwards if you want it rebuilt on a newer base.
    _WP_RUN_IMAGE="\$WP_IMAGE"
    case "\$WP_IMAGE" in
      localhost/wordpress-geoip:*) : ;;
      *)
        if [ -f /etc/wp-install/pinned.env ]; then
          . /etc/wp-install/pinned.env
          [ -n "\$WP_DIGEST" ] && _WP_RUN_IMAGE="docker.io/wordpress@\${WP_DIGEST}"
        fi
        ;;
    esac
    podman run -d --name wordpress --network wp-front --ip 10.89.10.3 -p 80:80 --restart always \\
      --label io.containers.autoupdate=image \\
      --cap-drop ALL --cap-add NET_BIND_SERVICE \\
      --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add DAC_OVERRIDE --cap-add FOWNER \\
      --security-opt no-new-privileges:true \\
      --pids-limit 200 --memory=768m --cpu-shares=512 \\
      --tmpfs /tmp:size=64M,noexec,nosuid,nodev \\
      --env-file /etc/wordpress/env \\
      -e WORDPRESS_DB_HOST=mariadb:3306 \\
      -e WORDPRESS_DEBUG="" \\
      -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \\
      -v /home/wpuser/wp/html:/var/www/html \\
      -v /home/wpuser/wp/logs:/var/log/apache2 \\
      -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \\
      -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \\
      ${SVC_HEADERS_VOL}${SVC_REMOTEIP_VOLS} \\
      "\$_WP_RUN_IMAGE" >/dev/null 2>&1
    podman network connect --ip 10.89.20.3 wp-db wordpress >/dev/null 2>&1 || true
  fi
  eend \$?
}

stop() {
  ebegin "Stopping WordPress"
  podman stop wordpress >/dev/null 2>&1
  eend \$?
}
ORCSVC_WP
chmod +x /etc/init.d/wp-container
rc-update add wp-container default 2>/dev/null || true
ok "wp-container service registered"

# ── WP-Cron runner ─────────────────────────────────────────────────────────────
install -m 0755 "${PAYLOAD_DIR}/bin/wp-cron-run.sh" /usr/local/bin/wp-cron-run.sh
chmod +x /usr/local/bin/wp-cron-run.sh
ok "wp-cron-run.sh installed"

# ── Update script ─────────────────────────────────────────────────────────────
