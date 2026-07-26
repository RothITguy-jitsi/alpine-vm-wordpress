#!/bin/sh
# 03-wordpress-user-and-secrets.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Creates the wpuser account, generates database credentials, and creates the Podman wp-front/wp-db networks.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Creating wpuser account"
apk add --no-cache shadow >/dev/null
id wpuser >/dev/null 2>&1 || adduser -D -s /sbin/nologin wpuser
ok "wpuser ready (file layout only — not used for container UID)"

ts "Generating database credentials"
apk add --no-cache openssl >/dev/null 2>&1 || true
DB_ROOT_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)
DB_WP_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)
WP_TABLE_PREFIX="wp$(openssl rand -hex 3)_"

mkdir -p /etc/wordpress
cat > /etc/wordpress/env << WPCREDS
MARIADB_ROOT_PASSWORD=${DB_ROOT_PASS}
MARIADB_DATABASE=wordpress
MARIADB_USER=wpdb
MARIADB_PASSWORD=${DB_WP_PASS}
WORDPRESS_DB_HOST=mariadb:3306
WORDPRESS_DB_USER=wpdb
WORDPRESS_DB_PASSWORD=${DB_WP_PASS}
WORDPRESS_DB_NAME=wordpress
WORDPRESS_TABLE_PREFIX=${WP_TABLE_PREFIX}
WPCREDS
chmod 600 /etc/wordpress/env
ok "/etc/wordpress/env written (chmod 600)"

cat > /root/.wp-credentials << WPCREDSINFO
# ============================================================
# WordPress VM Credentials — $(date '+%Y-%m-%d %H:%M:%S')
# chmod 600 /root/.wp-credentials
# ============================================================
# MariaDB root password  : ${DB_ROOT_PASS}
# MariaDB DB             : wordpress
# MariaDB WP user        : wpdb
# MariaDB WP password    : ${DB_WP_PASS}
# WordPress table prefix : ${WP_TABLE_PREFIX}
#
# WordPress Admin: http://<VM-IP>/wp-admin/install.php
#   (the 5-minute install — do this before anyone else finds your site)
#
# Machine env file: /etc/wordpress/env  (chmod 600)
# ============================================================
WPCREDSINFO
chmod 600 /root/.wp-credentials
ok "/root/.wp-credentials written (chmod 600)"

ts "Creating Podman wp-front / wp-db networks"
# Explicit subnets keep the nftables forward chain rules exact:
#   ip saddr/daddr 10.89.10.0/24 accept   (wp-front, in /etc/nftables.nft)
#   ip saddr/daddr 10.89.20.0/24 accept   (wp-db,    in /etc/nftables.nft)
# Without fixed subnets, netavark assigns them dynamically and the forward
# rules could stop matching after a network recreate.
#
# wp-front: WordPress only. Has normal egress (plugin/theme installs, WP-Cron
# remote requests, update checks) and is where the published host port lands.
PRUN network exists wp-front 2>/dev/null \
  || PRUN network create --subnet 10.89.10.0/24 --gateway 10.89.10.1 wp-front
ok "wp-front: 10.89.10.0/24 — WordPress egress + published port"
#
# wp-db: WordPress + MariaDB only, --internal. netavark never configures a
# route out of an --internal network, so MariaDB has no path to the internet
# regardless of nftables state — a real isolation boundary, not just "no
# host port".
PRUN network exists wp-db 2>/dev/null \
  || PRUN network create --internal --subnet 10.89.20.0/24 --gateway 10.89.20.1 wp-db
ok "wp-db: 10.89.20.0/24 — internal (no egress), no host port for MariaDB"

