#!/bin/sh
# WordPress installer — runs via /etc/local.d on every boot until complete.
# Self-bootstraps bash. Two stages: 1=kernel switch, 2=containers.

if [ -z "${BASH_VERSION:-}" ]; then
  apk add --no-cache bash >/dev/null 2>&1 \
    || { echo "FATAL: apk failed — networking up?"; exit 1; }
  exec bash "$0" "$@"; exit 1
fi

set -e
LOG=/var/log/wp-install.log
exec >> "$LOG" 2>&1

ts()   { echo; echo "=== [$(date '+%H:%M:%S')] $* ==="; }
ok()   { echo "  ✔  $*"; }
warn() { echo "  ⚠  $*"; }

# ── Pinned image versions ─────────────────────────────────────────────────────
# BUG FIX: mariadb:11.4-lts does NOT exist on Docker Hub.
# Correct tags: mariadb:11.4 (branch), mariadb:lts (always current LTS).
# wordpress:6.7.2-php8.3-apache (full semver) is more stable than 6.7.
WP_IMAGE="docker.io/wordpress:6.9.4-php8.3-apache"
DB_IMAGE="docker.io/mariadb:11.4"
# BUG FIX (v7-5): v1.7.6 → v1.7.8. v1.7.8 (2026-05-11) is a security release
# patching CVE-2026-44982 (a HIGH-impact partial WAF bypass in the AppSec
# datasource — chunked-encoding/HTTP2-no-Content-Length requests were
# evaluated against an empty body, silently bypassing any WAF rule targeting
# body content; this directly affects the crowdsecurity/appsec-wordpress
# collection this script enables) and CVE-2026-44981 (a LAPI DoS via
# unbounded gzip decompression — lower impact here since LAPI is bound to
# 127.0.0.1 only, but still worth the patch).
CROWDSEC_IMAGE="docker.io/crowdsecurity/crowdsec:v1.7.8"

STAGE_FILE=/var/lib/wp-install-stage
STAGE=$(cat "$STAGE_FILE" 2>/dev/null || echo 1)

echo "=================================================="
echo "  WordPress Installer — $(date)  [stage ${STAGE}]"
echo "  Alpine $(cat /etc/alpine-release 2>/dev/null)  Kernel $(uname -r)"
echo "  WordPress : ${WP_IMAGE}"
echo "  MariaDB   : ${DB_IMAGE}"
echo "  CrowdSec  : ${CROWDSEC_IMAGE}"
echo "=================================================="

# ════════════════════════════════════════════════════════════════════════════
# STAGE 1 — filesystem, updates, kernel switch
# ════════════════════════════════════════════════════════════════════════════
if [ "$STAGE" = "1" ]; then

  ts "Expanding root filesystem"
  apk add --no-cache e2fsprogs >/dev/null 2>&1 || true
  ROOT_DEV=$(df / | awk 'NR==2{print $1}')
  resize2fs "$ROOT_DEV" 2>/dev/null && ok "$(df -h / | awk 'NR==2{print $2}') total" \
    || ok "Already at full size"

  ts "Updating Alpine"
  VER=$(cut -d. -f1,2 /etc/alpine-release)
  cat > /etc/apk/repositories << REPOS
https://dl-cdn.alpinelinux.org/alpine/v${VER}/main
https://dl-cdn.alpinelinux.org/alpine/v${VER}/community
REPOS
  apk update  >/dev/null 2>&1
  apk upgrade --no-cache >/dev/null 2>&1
  ok "Alpine ${VER} up to date"

  ts "Enabling nightly security updates (crond)"
  apk add --no-cache busybox-openrc >/dev/null 2>&1 || true
  rc-update add crond default 2>/dev/null || true
  rc-service crond start 2>/dev/null || true
  echo "0 3 * * * apk update -q && apk upgrade --no-cache -q && logger -t alpine-autoupdate done" \
    >> /etc/crontabs/root
  ok "Nightly apk upgrade @ 03:00 UTC"

  ts "QEMU Guest Agent"
  apk add --no-cache qemu-guest-agent >/dev/null
  rc-update add qemu-guest-agent default 2>/dev/null || true
  rc-service qemu-guest-agent start      2>/dev/null || true
  ok "Agent running"

  ts "Admin account doas (redundant safety net)"
  # The admin account, its wheel-group membership, and doas.conf normally
  # already exist by this point — created host-side before first boot in
  # create-wordpress-vm.sh's pre-boot chroot (see ADMIN_USER_CREATED in
  # /etc/wp-install/vars.sh). That chroot only needs local filesystem
  # writes for the account/group itself, so it's virtually guaranteed to
  # succeed regardless of network — but installing the `doas` PACKAGE from
  # that same chroot did depend on the PROXMOX HOST reaching Alpine's CDN
  # at provisioning time. This VM now has its own real networking (Stage 1
  # already ran a full apk update/upgrade above), so retry here — cheap,
  # fully idempotent, and closes the one plausible network-dependent gap
  # in an otherwise network-independent setup.
  command -v doas >/dev/null 2>&1 || apk add --no-cache doas >/dev/null 2>&1 || true
  if command -v doas >/dev/null 2>&1; then
    ok "doas present"
  else
    warn "doas still unavailable — install manually: apk add doas"
  fi

  ts "Clock sync"
  apk add --no-cache chrony >/dev/null
  for s in pool.ntp.org time.cloudflare.com time.google.com; do
    chronyd -q "server $s iburst maxsamples 4" >/dev/null 2>&1 && break || true
  done
  hwclock --systohc 2>/dev/null || true
  rc-update add chronyd default 2>/dev/null || true
  rc-service chronyd start      2>/dev/null || true
  ok "$(date '+%Y-%m-%d %H:%M:%S %Z')"

  ts "Kernel check — switching to linux-lts if needed"
  CURRENT_FLAVOR=$(uname -r | grep -oE '[a-z]+$')
  KERNEL_SWITCH_OK=0
  if [ "$CURRENT_FLAVOR" = "lts" ]; then
    ok "Already linux-lts ($(uname -r))"
  else
    warn "Running linux-${CURRENT_FLAVOR} — installing linux-lts"
    apk add --no-cache linux-lts >/dev/null 2>&1 || warn "linux-lts install failed"
    if [ -f /boot/vmlinuz-lts ]; then
      apk add --no-cache syslinux >/dev/null 2>&1 || true
      if [ -f /etc/update-extlinux.conf ]; then
        grep -qE '^[# ]*default=' /etc/update-extlinux.conf \
          && sed -i -E 's|^[# ]*default=.*|default=lts|' /etc/update-extlinux.conf \
          || echo 'default=lts' >> /etc/update-extlinux.conf
        update-extlinux 2>&1 | sed 's/^/    /'
        grep -q 'vmlinuz-lts' /boot/extlinux.conf 2>/dev/null \
          && { ok "Bootloader → linux-lts"; KERNEL_SWITCH_OK=1; } \
          || warn "extlinux.conf has no vmlinuz-lts — staying on current kernel"
      else
        warn "/etc/update-extlinux.conf not found"
      fi
    else
      warn "/boot/vmlinuz-lts missing after install"
    fi
  fi

  echo 2 > "$STAGE_FILE"
  if [ "$KERNEL_SWITCH_OK" = "1" ]; then
    ts "Rebooting into linux-lts"
    sync; sleep 2; reboot; exit 0
  fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STAGE 2 — Podman, MariaDB, WordPress, CrowdSec
# ════════════════════════════════════════════════════════════════════════════
ts "Stage 2 — kernel: $(uname -r)"

# ── Source installer variables (slug, CS key, GeoIP, network) ────────────────
# These were injected at provisioning time into /etc/wp-install/vars.sh
# because the INSTALLER_EOF heredoc is single-quoted (no host var expansion).
if [ -f /etc/wp-install/vars.sh ]; then
  . /etc/wp-install/vars.sh
  ok "Installer vars loaded: slug=${WP_ADMIN_SLUG:-default}, cs-enroll=${CROWDSEC_ENROLL_KEY:+provided}, net=${NET_MODE:-dhcp}, geoip=${GEOIP_ENABLED:-0}"
else
  WP_ADMIN_SLUG=""
  CROWDSEC_ENROLL_KEY=""
  NET_MODE="dhcp"
  VM_STATIC_IP=""
  GEOIP_ENABLED="0"
  GEOIP_MODE=""
  GEOIP_WHITELIST=""
  GEOIP_BLOCKLIST=""
  MAXMIND_ACCOUNT_ID=""
  MAXMIND_LICENSE_KEY=""
  ADMIN_USER=""
  ADMIN_USER_CREATED="0"
  warn "/etc/wp-install/vars.sh not found — new features default off"
fi
# Defensive defaults in case vars.sh exists but is missing newer keys
# (e.g. a VM re-provisioned from an older version of this script's injection)
GEOIP_ENABLED="${GEOIP_ENABLED:-0}"
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_USER_CREATED="${ADMIN_USER_CREATED:-0}"

# ── PRUN: podman dispatch wrapper ─────────────────────────────────────────────
# BUG FIX (v7-6d): PRUN used to have a rootless branch that rebuilt the whole
# command as a single string — su -s /bin/sh wpuser -c "podman $*" — and "$*"
# joins every argument on IFS, discarding the argument boundaries "$@" would
# have preserved. That string was then RE-PARSED by the inner `sh -c`, so any
# argument containing shell metacharacters (spaces, quotes, ;, $()) got
# reinterpreted instead of passed through intact — exactly what happens to
# WORDPRESS_CONFIG_EXTRA's 'define("WP_DEBUG",false);define(...);...' value.
# Now that this script is rootful-only, that dispatch — and the vulnerable
# reconstruction it required — is gone. PRUN is kept as a thin wrapper (so
# every "PRUN <cmd>" call site elsewhere in this installer, update.sh,
# wp-hardening.sh, and validate-wordpress.sh needs no changes), but it now
# ALWAYS calls podman directly with "$@", which preserves argument
# boundaries exactly.
PRUN() {
  podman "$@"
}


# ── Payload + stage locations (populated by create-wordpress-vm.sh) ──────────
PAYLOAD_DIR=/etc/wp-install/payload
STAGE_DIR=/etc/wp-install/stages

# ── Run stages 01-10 in order, in THIS shell (so every variable and function
#    defined above -- and by each stage in turn -- stays in scope for every
#    later stage, exactly as it would in one unsplit script). ─────────────────
. "${STAGE_DIR}/01-health-checks.sh"
. "${STAGE_DIR}/02-kernel-and-runtime.sh"
. "${STAGE_DIR}/03-wordpress-user-and-secrets.sh"
. "${STAGE_DIR}/04-apache-hardening.sh"
. "${STAGE_DIR}/05-logging.sh"
. "${STAGE_DIR}/06-containers-mariadb-wordpress.sh"
. "${STAGE_DIR}/07-openrc-services.sh"
. "${STAGE_DIR}/08-update-tooling.sh"
. "${STAGE_DIR}/09-crowdsec-and-backup.sh"
. "${STAGE_DIR}/10-security-tooling-and-validation.sh"
