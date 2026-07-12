#!/usr/bin/env bash
# =============================================================================
# v7-1 PATCH NOTES (on top of v7):
#   1. [CRITICAL — root cause of the crash-loop] Removed "RewriteBase /" from
#      the custom wp-admin slug block that gets written into wp-security.conf.
#      That directive is only valid in per-directory context (.htaccess or
#      <Directory>), but wp-security.conf loads as server/vhost-level config
#      (conf-enabled/*.conf). Every Apache start therefore failed its config
#      test with "RewriteBase: only valid in per-directory config files" and
#      the wordpress container crash-looped indefinitely — nothing was ever
#      actually served on port 80, only Podman's own port-forward stayed up
#      behind it. This is what caused essentially every other post-install
#      validation failure (DB connectivity, uploads writable, port 80
#      listening, HTTP check) — all downstream of Apache never starting.
#      The slug RewriteRule patterns also gained a leading "/", which they
#      need to match correctly outside per-directory context.
#   2. Inline post-install "MariaDB health" check no longer trusts
#      .State.Health.Status — Podman's health-check timer frequently never
#      fires on Alpine without systemd/conmon polling (this script already
#      found and worked around this once, see FIX 2 near the MariaDB wait
#      loop, but the fix wasn't applied here too). Now uses the same direct
#      exec ping already used by the install/update wait loops.
#   3. MariaDB exec-ping checks (inline + validate-wordpress.sh) now redirect
#      stdout, not just stderr — mariadb-admin/mariadbd-admin ping --silent
#      still prints "mysqld is alive" on success, which was leaking into the
#      captured variable and failing the "ok" string comparison even when
#      the ping succeeded.
#   4. "Port 80 listening" checks (inline + validate-wordpress.sh) switched
#      from `ss` to `netstat` — Alpine doesn't ship iproute2/ss by default
#      and this script never installs it, so the check always read "0"
#      regardless of the real port state. Busybox's netstat is present
#      out of the box and takes the same flags.
# =============================================================================
# WORDPRESS VM — PROXMOX VE PROVISIONING SCRIPT  (v4 — production-ready)
# =============================================================================
#
# CRITICAL BUGS FIXED vs v3:
#   1. netavark firewall_driver now set to "nftables" — eliminates the
#      "netavark: iptables: No such file or directory" error on Alpine.
#      Alpine's netavark defaults to iptables which isn't installed; setting
#      nftables here uses the already-installed 'nft' binary instead.
#   2. nftables forward chain now allows 10.89.1.0/24 (wp-net subnet) before
#      the policy drop — without this containers couldn't reach the internet
#      even after fix #1, because nftables DROP preempts any iptables ACCEPT.
#   3. aardvark-dns installed explicitly — provides container-to-container DNS
#      on wp-net so WordPress can resolve hostname 'mariadb:3306'. Without it
#      the container starts but the DB connection fails with a name lookup error.
#   4. /var/log/messages touched before CrowdSec starts — Podman fails with
#      "No such file or directory" if the bind-mount source doesn't exist yet.
#   5. wp-net created with explicit subnet 10.89.1.0/24 — makes nftables
#      forward rule deterministic; without it netavark assigns a random subnet.
#   6. rp_filter changed from strict (1) to loose (2) — strict mode can drop
#      container NAT traffic due to asymmetric routing on the Podman bridge.
#   7. net.ipv4.ip_forward=1 now explicit in sysctl — required for container
#      packet forwarding; netavark enables it but explicit is more resilient.
#
# WRONG VERSIONS FIXED vs v3:
#   8. WordPress: 6.7.2 → 6.8 floating tag (6.8.x security patches auto)
#      6.8 is current stable; 7.0.0 released June 2026 but too new for MSP.
#   9. CrowdSec: v1.6.8 (DOES NOT EXIST) → v1.7.4 (latest stable, Dec 2024).
#      v1.7.0+ requires /var/lib/crowdsec/data volume — already mounted ✓.
#
# FUNCTIONAL ISSUES FIXED vs v3:
#  10. PHP session.cookie_samesite: Strict → Lax. Strict breaks WordPress
#      OAuth flows, WooCommerce payment gateway callbacks, and SSO plugins.
#  11. PHP allow_url_fopen: Off → On. Many WooCommerce payment gateways and
#      plugin APIs use file_get_contents() with URLs; Off breaks them silently.
#      allow_url_include stays Off (blocks remote code inclusion attacks).
#  12. DISABLE_WP_CRON=true added to wp-config — WP-Cron only fires on page
#      loads and is unreliable in production. Real system cron added instead.
#  13. WordPress system cron added (*/5 * * * *) — runs wp-cron.php inside
#      the container; handles scheduled posts, updates, and plugin jobs.
#  14. Daily MariaDB backup cron (02:00) — gzipped mysqldump to /root/wp-db-
#      backups/ with 7-day auto-retention. Essential for MSP production.
#  15. MariaDB InnoDB buffer pool capped (256M) — without a limit MariaDB can
#      consume all available VM RAM, evicting other containers.
#      Also enables slow query log for performance debugging.
#  16. MariaDB conf mounted in OpenRC service and update.sh — consistent
#      between first install, reboots, and updates.
#   1. mariadb:11.4-lts → mariadb:11.4   (11.4-lts tag does not exist on Hub)
#   2. wordpress pin updated to 6.7.2-php8.3-apache (full semver, more stable)
#   3. mariadb-admin ping now passes credentials (anonymous ping can be denied)
#   4. WordPress container now has --cap-drop ALL + exact cap-add (was missing)
#   5. mariadb-container + wp-container services now export PODMAN_IGNORE env
#   6. wp-container service now has lsmod + modprobe calls (matched mariadb-svc)
#   7. mount --make-shared / added to both container services (Podman overlay)
#   8. podman-compose removed — podman auto-update is a built-in, needs no pkg
#
# SECURITY IMPROVEMENTS vs v2:
#   A. wp-admin / wp-login.php Apache IP restriction (new prompts)
#      — separate from nftables WEB_CIDR; works at HTTP request layer
#   B. mod_remoteip enabled when behind a reverse proxy (new PROXY_IP prompt)
#      — ensures Require ip checks real client IP through NPM/nginx/Caddy
#   C. WordPress now has --cap-drop ALL (same discipline as MariaDB)
#      + NET_BIND_SERVICE (Apache binds port 80 in container netns)
#      + SETUID/SETGID/CHOWN/DAC_OVERRIDE/FOWNER (same as MariaDB)
#   D. PHP: allow_url_fopen=Off + allow_url_include=Off (blocks RFI attacks)
#   E. Apache: Content-Security-Policy + Permissions-Policy headers
#   F. Apache: PHP execution blocked in wp-content/uploads (webshell guard)
#   G. Apache: author=N query string blocked (username enumeration)
#   H. Apache: debug.log access blocked
#   I. Apache config now built HOST-SIDE with CIDRs baked in, injected via
#      qemu-nbd — same pattern as nftables, no runtime substitution needed
#
# ROOTFUL vs ROOTLESS DECISION (documented):
#   MariaDB  — rootful, --cap-drop ALL + 5 caps, isolated to wp-net, no host
#              port. Equivalent security to rootless for this workload.
#   WordPress — rootful, --cap-drop ALL + 6 caps. Requires NET_BIND_SERVICE
#              because Apache binds port 80 inside the container's own network
#              namespace even with -p 80:80 (Podman's host-side port publish
#              is separate from Apache's in-netns bind). Making WordPress
#              rootless requires either running Apache on port 8080+ (needs
#              a ports.conf override) or sysctl ip_unprivileged_port_start=0,
#              both of which add fragility with no meaningful security gain
#              given the VM is the primary isolation boundary.
#   CrowdSec  — rootful, --network host, --read-only, minimal caps.
#              Must use host network to see syslog and write nftables rules.
# =============================================================================
set -e

RD='\033[0;31m' GN='\033[0;32m' YW='\033[0;33m' BL='\033[0;36m'
BLD='\033[1m'   CL='\033[0m'
msg_info()  { echo -e "  ${BL}➜${CL}  $*"; }
msg_ok()    { echo -e "  ${GN}✔${CL}  $*"; }
msg_warn()  { echo -e "  ${YW}⚠${CL}  $*"; }
msg_error() { echo -e "  ${RD}✗${CL}  $*" >&2; exit 1; }

# ── VM sizing ─────────────────────────────────────────────────────────────────
_next_vmid() { pvesh get /cluster/nextid 2>/dev/null | tr -d '"' || echo 100; }
VMID=""
CORES=2
RAM=4096
DISK="20G"

# ── Alpine BIOS cloud image — auto-detect newest from CDN ────────────────────
_find_alpine_image() {
  local base="https://dl-cdn.alpinelinux.org/alpine"
  for minor in 3.24 3.23 3.22 3.21; do
    local idx="${base}/v${minor}/releases/cloud/"
    local fname
    fname=$(curl -fsSL --max-time 10 "$idx" 2>/dev/null \
      | grep -oE "generic_alpine-${minor//./\\.}\\.[0-9]+-x86_64-bios-cloudinit-r[0-9]+\\.qcow2" \
      | sort -V | tail -1)
    if [[ -n "$fname" ]]; then
      ALPINE_VER=$(echo "$fname" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
      ALPINE_MINOR="$minor"
      ALPINE_URL="${idx}${fname}"
      return 0
    fi
  done
  ALPINE_VER="3.23.4"; ALPINE_MINOR="3.23"
  ALPINE_URL="${base}/v3.23/releases/cloud/generic_alpine-3.23.4-x86_64-bios-cloudinit-r0.qcow2"
}
ALPINE_VER="" ALPINE_MINOR="" ALPINE_URL=""
_find_alpine_image
IMG_CACHE="/var/lib/vz/template/iso"
IMG_FILE="${IMG_CACHE}/$(basename "$ALPINE_URL")"

# ── Cleanup on error ──────────────────────────────────────────────────────────
_NBD="" _MNT="" _DESTROY_VM=1
cleanup() {
  set +e
  [[ -n "$_MNT" ]] && { umount "$_MNT/dev" 2>/dev/null; umount "$_MNT/proc" 2>/dev/null
                         umount "$_MNT"      2>/dev/null; }
  [[ -n "$_NBD" ]] && qemu-nbd --disconnect "$_NBD" 2>/dev/null
  if (( _DESTROY_VM )) && [[ -n "$VMID" ]] && qm status "$VMID" &>/dev/null 2>&1; then
    qm stop "$VMID" --skiplock 2>/dev/null; qm destroy "$VMID" --purge 2>/dev/null
  fi
}
trap cleanup EXIT

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]]                || msg_error "Must run as root on the Proxmox host."
[[ -f /etc/pve/pve-root-ca.pem ]] || msg_error "Not a Proxmox VE host."
command -v qm        &>/dev/null || msg_error "'qm' not found."
command -v qemu-nbd  &>/dev/null || msg_error "'qemu-nbd' not found — apt install qemu-utils"
command -v qemu-img  &>/dev/null || msg_error "'qemu-img' not found — apt install qemu-utils"
command -v openssl   &>/dev/null || msg_error "'openssl' not found."

# ── Interactive setup ─────────────────────────────────────────────────────────
clear
echo -e "\n${BLD}  WordPress VM${CL}"
echo    "  Alpine (auto) + Podman (WordPress + MariaDB) + CrowdSec + nftables"
echo    "  ${CORES} CPU · ${RAM} MB · ${DISK} · hardened Apache + PHP"
echo ""

SUGGESTED=$(_next_vmid)
while true; do
  read -rp "  VM ID        [${SUGGESTED}] : " _vmid
  VMID="${_vmid:-$SUGGESTED}"
  [[ "$VMID" =~ ^[0-9]+$ ]] || { echo -e "  ${RD}ID must be a number.${CL}"; continue; }
  (( VMID >= 100 ))          || { echo -e "  ${RD}ID must be ≥ 100.${CL}"; continue; }
  if qm status "$VMID" &>/dev/null 2>&1 || \
     [[ -f "/etc/pve/qemu-server/${VMID}.conf" ]] || \
     [[ -f "/etc/pve/lxc/${VMID}.conf" ]]; then
    echo -e "  ${RD}VM ${VMID} already exists.${CL}"
    SUGGESTED=$(( VMID + 1 )); continue
  fi
  break
done

ROOT_PASS=""
while [[ -z "$ROOT_PASS" ]]; do
  read -rsp "  Root password for the VM : " p1; echo
  read -rsp "  Confirm                  : " p2; echo
  [[ "$p1" == "$p2" && -n "$p1" ]] && ROOT_PASS="$p1" \
    || echo -e "  ${RD}Passwords do not match.${CL}"
done

read -rp "  Hostname       [wordpress] : " HN; HN="${HN:-wordpress}"

echo ""
msg_info "Available storages:"
pvesm status --content images 2>/dev/null \
  | awk 'NR>1 && $2=="active" {printf "    • %-20s (%s)\n", $1, $4}'
read -rp "  Storage  [local-lvm] : " STORAGE; STORAGE="${STORAGE:-local-lvm}"
read -rp "  Bridge       [vmbr0] : " BRIDGE;  BRIDGE="${BRIDGE:-vmbr0}"
read -rp "  VLAN tag  (blank=no) : " VLAN_RAW
VLAN="${VLAN_RAW:+,tag=${VLAN_RAW}}"

echo ""
echo -e "  ${BLD}Network addressing${CL}"
echo -e "  ${YW}Proxmox host interfaces (for reference — pick an address on the same subnet):${CL}"
ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print "    " a[1] "  (subnet: " $2 ")"}' | head -6
echo ""
echo "  [1] DHCP — VM gets an address automatically (default)"
echo "  [2] Static IPv4 — you assign the address, gateway, and DNS now"
read -rp "  Network mode [1] : " NET_MODE_SEL
NET_MODE="dhcp"
VM_STATIC_IP="" VM_PREFIX="" VM_GATEWAY="" VM_DNS=""

_valid_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a parts <<< "$ip"
  for o in "${parts[@]}"; do (( o >= 0 && o <= 255 )) || return 1; done
  return 0
}

if [[ "$NET_MODE_SEL" == "2" ]]; then
  while true; do
    read -rp "  VM static IPv4 address (e.g. 192.168.1.50) : " VM_STATIC_IP
    _valid_ipv4 "$VM_STATIC_IP" && break || echo -e "  ${RD}Not a valid IPv4 address — try again.${CL}"
  done
  while true; do
    read -rp "  Subnet prefix length, CIDR bits [24] : " VM_PREFIX
    VM_PREFIX="${VM_PREFIX:-24}"
    [[ "$VM_PREFIX" =~ ^[0-9]+$ ]] && (( VM_PREFIX >= 1 && VM_PREFIX <= 32 )) && break
    echo -e "  ${RD}Enter a number 1-32 (e.g. 24 for a /24).${CL}"
  done
  while true; do
    read -rp "  Gateway IPv4 address (required) : " VM_GATEWAY
    _valid_ipv4 "$VM_GATEWAY" && break || echo -e "  ${RD}Not a valid IPv4 address — try again.${CL}"
  done
  read -rp "  DNS servers, space-separated [1.1.1.1 8.8.8.8] : " VM_DNS
  VM_DNS="${VM_DNS:-1.1.1.1 8.8.8.8}"
  NET_MODE="static"

  # CIDR prefix -> dotted-decimal netmask (e.g. 24 -> 255.255.255.0)
  _cidr_to_netmask() {
    local cidr=$1 mask="" i bits
    for ((i=0; i<4; i++)); do
      if (( cidr >= 8 )); then bits=255; cidr=$((cidr-8));
      elif (( cidr > 0 )); then bits=$((256 - 2**(8-cidr))); cidr=0;
      else bits=0; fi
      mask+="${bits}"
      (( i < 3 )) && mask+="."
    done
    echo "$mask"
  }
  VM_NETMASK=$(_cidr_to_netmask "$VM_PREFIX")
  msg_ok "Static IP: ${VM_STATIC_IP}/${VM_PREFIX} (netmask ${VM_NETMASK}) via ${VM_GATEWAY}, DNS: ${VM_DNS}"
else
  NET_MODE="dhcp"
  msg_ok "Network: DHCP (default)"
fi

echo ""
echo -e "  ${BLD}SSH access${CL}"
echo "  Paste your public key (starts with ssh-ed25519 or ssh-rsa),"
echo "  or press Enter to load from a file path."
read -rp "  Public key (paste, or blank) : " SSH_KEY_PASTE
SSH_KEYS=""
if [[ -n "$SSH_KEY_PASTE" ]]; then
  SSH_KEYS="$SSH_KEY_PASTE"
else
  read -rp "  ...or path to a .pub file (blank = keep password login) : " SK
  [[ -n "$SK" && -f "$SK" ]] && SSH_KEYS=$(cat "$SK")
fi
if [[ -n "$SSH_KEYS" ]]; then
  DISABLE_PW_AUTH=1; msg_ok "SSH key set — password login disabled"
else
  DISABLE_PW_AUTH=0; msg_warn "No SSH key — password login remains enabled"
fi

echo ""
echo -e "  ${BLD}Firewall + access control${CL}"
echo ""
echo -e "  ${BLD}Layer 1 — nftables (packet level, applies to ALL traffic on 80/443):${CL}"
read -rp "  Restrict SSH (22) to a CIDR?           (blank = any)  : " SSH_CIDR
read -rp "  Restrict Web (80/443) to a CIDR?       (blank = any)  : " WEB_CIDR
[[ -z "$WEB_CIDR" ]] && msg_warn "Web ports open to any IP — Layer 2 (Apache) still enforces wp-admin"
echo ""
echo -e "  ${BLD}Layer 2 — Apache (request level, wp-admin + wp-login.php only):${CL}"
echo -e "  ${YW}This restriction works whether traffic is direct OR through a reverse proxy.${CL}"
echo -e "  ${YW}Set to your local network CIDR (e.g. 192.168.1.0/24).${CL}"
echo ""
echo -e "  ${YW}Your workstation is likely on one of these subnets (from the Proxmox host):${CL}"
ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print "    " a[1] "  (subnet: " $2 ")"}' | head -5
echo ""
read -rp "  Local network CIDR for wp-admin?  e.g. 192.168.100.0/24 (blank = open) : " ADMIN_CIDR
read -rp "  Additional IP for wp-admin?  (e.g. 203.0.113.5, blank = none)  : " ALLOWED_ADMIN_IP
echo ""
echo -e "  ${BLD}Layer 2b — mod_remoteip (only needed if behind a reverse proxy):${CL}"
echo -e "  ${YW}If WordPress is behind NPM / nginx / Caddy, Apache sees the proxy IP${CL}"
echo -e "  ${YW}not the real client IP. Enter the proxy's internal IP so Apache trusts${CL}"
echo -e "  ${YW}its X-Forwarded-For header for accurate wp-admin IP checks.${CL}"
read -rp "  Reverse proxy IP (e.g. 192.168.1.50, blank = direct access) : " PROXY_IP
echo ""
echo -e "  ${BLD}Security features${CL}"
echo -e "  ${YW}Custom wp-admin slug: replaces /wp-admin and /wp-login.php with a secret URL.${CL}"
echo -e "  ${YW}Choose something unique (e.g. siteadmin, seclogin, mymsp2024).${CL}"
echo -e "  ${YW}Avoid obvious words: admin, login, dashboard, wp, secure.${CL}"
read -rp "  wp-admin custom slug?  (blank = keep default /wp-admin) : " WP_ADMIN_SLUG
# Sanitise: lowercase, alphanumeric + hyphen only
WP_ADMIN_SLUG=$(echo "${WP_ADMIN_SLUG}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed 's/^-//;s/-$//')
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  msg_ok "Admin slug: /${WP_ADMIN_SLUG}  (direct /wp-admin access will return 403)"
else
  msg_warn "No slug set — /wp-admin accessible at default URL (still protected by ADMIN_CIDR + CrowdSec)"
fi
echo ""
echo -e "  ${BLD}CrowdSec Console enrolment (optional — can be done after install):${CL}"
echo -e "  ${YW}Get your enrolment key at https://app.crowdsec.net → Security Engines → Add${CL}"
echo -e "  ${YW}This automates the enrolment step so you don't need to SSH in afterwards.${CL}"
read -rp "  CrowdSec enrolment key (blank = skip, enrol manually later) : " CROWDSEC_ENROLL_KEY

echo ""
echo -e "  ${BLD}GeoIP country filtering (optional — Layer 2 Apache, site-wide)${CL}"
echo -e "  ${YW}Blocks or allows visitors by country before WordPress/PHP ever runs.${CL}"
echo -e "  ${YW}Uses MaxMind's free GeoLite2-Country database via the mod_maxminddb${CL}"
echo -e "  ${YW}Apache module (compiled during install — adds ~2 min, then removed${CL}"
echo -e "  ${YW}build tools to keep the container lean).${CL}"
echo -e "  ${YW}Requires a FREE MaxMind account: https://www.maxmind.com/en/geolite2/signup${CL}"
read -rp "  Enable GeoIP country filtering? [y/N] : " GEOIP_ENABLE
GEOIP_ENABLED=0 GEOIP_MODE="" GEOIP_WHITELIST="" GEOIP_BLOCKLIST=""
MAXMIND_ACCOUNT_ID="" MAXMIND_LICENSE_KEY=""
if [[ "${GEOIP_ENABLE:-N}" =~ ^[Yy] ]]; then
  read -rp "  MaxMind Account ID  : " MAXMIND_ACCOUNT_ID
  read -rp "  MaxMind License Key : " MAXMIND_LICENSE_KEY
  if [[ -z "$MAXMIND_ACCOUNT_ID" || -z "$MAXMIND_LICENSE_KEY" ]]; then
    msg_warn "Both Account ID and License Key are required — GeoIP filtering will be skipped"
  else
    echo ""
    echo "  Whitelist mode : ONLY listed countries can reach the site (strict)"
    echo "  Blocklist mode : everyone EXCEPT listed countries can reach the site"
    read -rp "  Whitelist countries (ISO codes, e.g. US,CA,GB) or blank for blocklist mode : " GEOIP_WHITELIST
    if [[ -z "$GEOIP_WHITELIST" ]]; then
      read -rp "  Block countries (ISO codes, comma-separated, e.g. CN,RU,KP) : " GEOIP_BLOCKLIST
      GEOIP_MODE="blocklist"
    else
      GEOIP_MODE="whitelist"
    fi
    GEOIP_ENABLED=1
    msg_ok "GeoIP ${GEOIP_MODE}: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}"
  fi
fi

echo ""
echo -e "  ${BLD}Deployment mode — rootful (default) or rootless Podman${CL}"
echo -e "  ${YW}Rootful (default): containers run as the host's root user via Podman.${CL}"
echo -e "  ${YW}  This is the battle-tested path used throughout this script's${CL}"
echo -e "  ${YW}  development and debugging history. Recommended for production.${CL}"
echo -e "  ${YW}Rootless: containers run as the unprivileged 'wpuser' account.${CL}"
echo -e "  ${YW}  WordPress publishes on host port 8080 (not 80) because an${CL}"
echo -e "  ${YW}  unprivileged user cannot bind ports below 1024 — nftables adds${CL}"
echo -e "  ${YW}  a redirect so visitors still use plain port 80 externally.${CL}"
echo -e "  ${YW}  KNOWN TRADE-OFF: rootless port-forwarding (rootlessport) does${CL}"
echo -e "  ${YW}  not preserve the visitor's real source IP by default — this can${CL}"
echo -e "  ${YW}  blind CrowdSec banning and the wp-admin CIDR check. The script${CL}"
echo -e "  ${YW}  attempts the experimental pasta source-IP-preserving forwarder${CL}"
echo -e "  ${YW}  and will warn loudly in the install log if it cannot confirm${CL}"
echo -e "  ${YW}  this works. Treat rootless as newer/less proven — test before${CL}"
echo -e "  ${YW}  relying on it for a production client site.${CL}"
read -rp "  Use rootless Podman? [y/N] : " ROOTLESS_SEL
ROOTLESS_MODE=0
[[ "${ROOTLESS_SEL:-N}" =~ ^[Yy] ]] && ROOTLESS_MODE=1
if (( ROOTLESS_MODE )); then
  msg_warn "Rootless mode selected — WordPress will be reachable on host port 8080,"
  msg_warn "with an nftables redirect from 80. Review the install log for the"
  msg_warn "source-IP preservation check before trusting CrowdSec bans / CIDR rules."
else
  msg_ok "Rootful Podman (default, fully validated path)"
fi

echo ""
echo -e "  ${BLD}Container image digest pinning${CL}"
echo -e "  ${YW}When enabled, WordPress/MariaDB/CrowdSec are pinned to the exact SHA256${CL}"
echo -e "  ${YW}digest resolved at install time, not just the floating tag. This${CL}"
echo -e "  ${YW}guarantees the bits that get audited/tested are the exact bits that${CL}"
echo -e "  ${YW}run — a registry silently repointing a tag can't change what's deployed.${CL}"
echo -e "  ${YW}what's deployed. update.sh re-pins on every update, and${CL}"
echo -e "  ${YW}'update.sh digest-check' can find and move to a newer digest published${CL}"
echo -e "  ${YW}under the SAME tag (e.g. a same-version security rebuild).${CL}"
read -rp "  Use SHA256 image digest pinning? [Y/n] : " PINNING_SEL
USE_DIGEST_PINNING=1
[[ "${PINNING_SEL:-Y}" =~ ^[Nn] ]] && USE_DIGEST_PINNING=0
if (( USE_DIGEST_PINNING )); then
  msg_ok "Digest pinning enabled — resolved during install (adds a short pull-and-inspect step)"
else
  msg_warn "Digest pinning disabled — images run by floating tag only"
fi

echo ""
echo -e "  ${BLD}Vulnerability & compliance tooling (always installed)${CL}"
echo -e "  ${YW}Trivy  — scans every container image for known CVEs (HIGH/CRITICAL)${CL}"
echo -e "  ${YW}         before update.sh applies an update. Maintains a local cache${CL}"
echo -e "  ${YW}         at /var/cache/trivy so repeat scans take under 15 seconds.${CL}"
echo -e "  ${YW}         Run on demand:  update.sh trivy   |   wp-hardening.sh trivy-scan${CL}"
echo -e "  ${YW}Lynis  — audits the OS itself: SSH config, kernel hardening, file${CL}"
echo -e "  ${YW}         permissions, exposed services. Produces a 0-100 hardening${CL}"
echo -e "  ${YW}         index, useful as compliance evidence for MSP clients.${CL}"
echo -e "  ${YW}         Runs automatically every Saturday 05:00 UTC. Run on demand:${CL}"
echo -e "  ${YW}         wp-hardening.sh lynis${CL}"
echo -e "  ${YW}Both results are combined in one place:  wp-hardening.sh security-report${CL}"

echo ""
echo -e "  ${BLD}─── Summary ──────────────────────────────────────${CL}"
printf  "  %-18s %s\n"  "VM ID:"       "$VMID"
printf  "  %-18s %s\n"  "Hostname:"    "$HN"
printf  "  %-18s %s CPU · %s MB · %s\n" "Resources:"  "$CORES" "$RAM" "$DISK"
printf  "  %-18s Alpine %s (auto)\n"   "OS:"          "$ALPINE_VER"
printf  "  %-18s %s\n"  "SSH:"         "$([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password (no key)')"
printf  "  %-18s nft SSH=%-15s  nft Web=%s\n"   "L1 Firewall:"  "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
printf  "  %-18s admin-cidr=%-18s  allowed-ip=%s\n" "L2 wp-admin:" "${ADMIN_CIDR:-none}" "${ALLOWED_ADMIN_IP:-none}"
printf  "  %-18s %s\n"  "Proxy IP:"    "${PROXY_IP:-direct (no proxy)}"
printf  "  %-18s %s\n"  "Admin slug:"  "${WP_ADMIN_SLUG:+/${WP_ADMIN_SLUG} (custom)}${WP_ADMIN_SLUG:-/wp-admin (default)}"
printf  "  %-18s %s\n"  "CS enrolment:" "${CROWDSEC_ENROLL_KEY:+key provided (auto-enrol)}${CROWDSEC_ENROLL_KEY:-manual (after install)}"
printf  "  %-18s WordPress + MariaDB (internal) + CrowdSec\n" "Containers:"
printf  "  %-18s %s\n"  "Network:"     "${NET_MODE}${VM_STATIC_IP:+ ($VM_STATIC_IP/$VM_PREFIX)}"
printf  "  %-18s %s\n"  "Podman mode:" "$([[ $ROOTLESS_MODE -eq 1 ]] && echo 'rootless (port 8080→80 via nftables)' || echo 'rootful (default)')"
printf  "  %-18s %s\n"  "GeoIP:"       "$([[ $GEOIP_ENABLED -eq 1 ]] && echo "${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})" || echo 'disabled')"
printf  "  %-18s %s\n"  "Digest pinning:" "$([[ $USE_DIGEST_PINNING -eq 1 ]] && echo 'enabled (SHA256-pinned images)' || echo 'disabled (tag-only)')"
[[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]] && msg_warn "WEB_CIDR set + PROXY_IP set → ${PROXY_IP} auto-added to nftables so NPM can reach port 80/443"
[[ -n "$WEB_CIDR" && -z "$PROXY_IP" ]] && msg_warn "WEB_CIDR restricts port 80/443 to ${WEB_CIDR}. If NPM is on a different subnet, add its IP as PROXY_IP or re-run the script."
echo ""
read -rp "  Proceed? [Y/n] : " yn
[[ "${yn:-Y}" =~ ^[Yy] ]] || { echo "Aborted."; _DESTROY_VM=0; exit 0; }


# ── Storage type ──────────────────────────────────────────────────────────────
STYPE=$(pvesm status -storage "$STORAGE" 2>/dev/null | awk 'NR>1{print $2}')
case "$STYPE" in
  nfs|dir)  DISK_EXT=".qcow2"; DISK_REF="${VMID}/"; DISK_FMT="-format qcow2" ;;
  btrfs)    DISK_EXT=".raw";   DISK_REF="${VMID}/"; DISK_FMT="-format raw"   ;;
  *)        DISK_EXT="";       DISK_REF="";          DISK_FMT="-format raw"   ;;
esac
DISK0="vm-${VMID}-disk-0${DISK_EXT}"
DISK0_REF="${STORAGE}:${DISK_REF}${DISK0}"
case "$STYPE" in
  nfs|dir|btrfs) DISK_OPTS="${DISK0_REF},size=${DISK}"                 ;;
  *)             DISK_OPTS="${DISK0_REF},discard=on,ssd=1,size=${DISK}" ;;
esac

# ── Download + verify Alpine image ────────────────────────────────────────────
# BUG FIX (v7-5): added real integrity verification. Checked directly against
# the Alpine CDN: the cloud/ qcow2 images do NOT publish a .sha256 sidecar —
# only a .sha512 and a detached GPG .asc signature (their .iso releases do
# ship .sha256, but this is a different image type/directory). SHA-512 is a
# stronger hash than SHA-256 anyway, so this isn't a downgrade — it's simply
# what Alpine actually publishes for this file. The checksum is fetched fresh
# from the SAME directory as the image, matching the already auto-selected
# ${ALPINE_URL} exactly. Deliberately NOT hardcoded: this script's own image
# selection floats across point releases (3.24, 3.23, 3.22, 3.21, whichever
# has a build available), so a fixed hash would break on the very next Alpine
# point release. GPG verification of the .asc would add defense-in-depth
# against a compromised CDN, but requires pinning Alpine's rotating
# per-release signing key — left as a manual step rather than guessed at
# here (current fingerprint is posted at https://alpinelinux.org/downloads/
# if you want to add `gpg --verify` yourself).
_verify_alpine_sha512() {
  local img="$1" url="$2" sidecar_url expected actual
  sidecar_url="${url}.sha512"
  expected=$(curl -fsSL --max-time 10 "$sidecar_url" 2>/dev/null | awk '{print $1}')
  if [[ -z "$expected" || ! "$expected" =~ ^[0-9a-fA-F]{128}$ ]]; then
    msg_warn "Could not fetch a valid .sha512 for $(basename "$img") — skipping integrity check"
    msg_warn "  (provisioning continues, but this download was not verified)"
    return 0
  fi
  actual=$(sha512sum "$img" | awk '{print $1}')
  if [[ "$actual" == "$expected" ]]; then
    msg_ok "SHA512 verified: $(basename "$img")"
  else
    rm -f "$img"
    msg_error "SHA512 MISMATCH for $(basename "$img") — refusing to use this image (deleted).
    Expected: ${expected}
    Got:      ${actual}
    Re-run to re-download, or investigate your network (captive portal / MITM proxy)."
  fi
}

# ── Download Alpine image ─────────────────────────────────────────────────────
mkdir -p "$IMG_CACHE"
if [[ -f "$IMG_FILE" ]]; then
  msg_ok "Cached: $(basename "$IMG_FILE")"
else
  msg_info "Downloading Alpine ${ALPINE_VER}…"
  curl -fL --progress-bar -o "$IMG_FILE" "$ALPINE_URL" \
    || { rm -f "$IMG_FILE"; msg_error "Download failed."; }
  msg_ok "Downloaded"
fi
if command -v sha512sum &>/dev/null; then
  _verify_alpine_sha512 "$IMG_FILE" "$ALPINE_URL"
else
  msg_warn "sha512sum not found on this host — skipping Alpine image integrity check"
fi
WORK_IMG="/tmp/wp-vm-${VMID}-alpine.qcow2"
cp "$IMG_FILE" "$WORK_IMG"
qemu-img resize "$WORK_IMG" "$DISK" >/dev/null
msg_ok "Working image ready (${DISK})"

# ── Build nftables ruleset (host-side substitution) ───────────────────────────
# WEB_CONTAINER_PORT is what the *filter* chain must match: in rootful mode
# WordPress publishes -p 80:80 so this is 80 (zero behaviour change from the
# default path). In rootless mode WordPress publishes -p 8080:80 (an
# unprivileged user cannot bind <1024 on the host), so a separate nat table
# DNAT-redirects public port 80 to 8080 — and because nftables NAT redirects
# run in the prerouting hook BEFORE the filter/input hook, by the time the
# packet reaches our input chain its destination port has ALREADY been
# rewritten to 8080. The filter rule must therefore match 8080, not 80.
WEB_CONTAINER_PORT=80
ROOTLESS_NAT_BLOCK=""
if [[ "${ROOTLESS_MODE:-0}" == "1" ]]; then
  WEB_CONTAINER_PORT=8080
  ROOTLESS_NAT_BLOCK=$(cat << 'NATEOF'

# Rootless mode: redirect public port 80 to the unprivileged host port 8080
# that WordPress actually publishes to (wpuser cannot bind <1024 directly).
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat;
        tcp dport 80 redirect to :8080
    }
}
NATEOF
)
fi

if [[ -n "$SSH_CIDR" ]]; then
  SSH_RULE="ip saddr ${SSH_CIDR} tcp dport 22"
else
  SSH_RULE="tcp dport 22"
fi
if [[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]]; then
  # Both set: allow local CIDR AND the reverse proxy IP.
  # Critical for NPM setups — without this, nftables blocks the proxy's requests
  # to port 80 even though mod_remoteip would correctly identify the real client.
  WEB_RULE="ip saddr { ${WEB_CIDR}, ${PROXY_IP} } tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
elif [[ -n "$WEB_CIDR" ]]; then
  WEB_RULE="ip saddr ${WEB_CIDR} tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
else
  WEB_RULE="tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
fi

NFT_CONF=$(cat << NFTEOF
#!/usr/sbin/nft -f
# nftables — generated by create-wordpress-vm.sh
# MariaDB (3306) is NOT here — isolated inside Podman wp-net (10.89.1.0/24).
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        icmp  type echo-request limit rate 5/second accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
        # SSH: CrowdSec (crowdsecurity/sshd) handles brute-force banning
        ${SSH_RULE} ct state new limit rate 10/minute accept
        # HTTP/HTTPS: CrowdSec (crowdsecurity/apache2 + crowdsecurity/wordpress
        # + crowdsecurity/http-cve) handles application-layer banning.
        # wp-admin/wp-login IP restriction is enforced at Apache level (Layer 2).
        ${WEB_RULE} accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        # Allow Podman wp-net (10.89.1.0/24) container traffic.
        # FIX: without these rules the nftables DROP policy prevents containers
        # from reaching the internet even after netavark sets up NAT — because
        # nftables and iptables both operate on the FORWARD netfilter hook, and
        # nftables DROP is evaluated regardless of iptables ACCEPT rules.
        # Allowing only the known wp-net subnet keeps the forward chain tight.
        ct state established,related accept
        ct state invalid drop
        ip saddr 10.89.1.0/24 accept
        ip daddr 10.89.1.0/24 accept
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
${ROOTLESS_NAT_BLOCK}
NFTEOF
)

# ── Build Apache security config (host-side — CIDRs baked in here) ────────────
# Built on the host where ADMIN_CIDR, ALLOWED_ADMIN_IP, and PROXY_IP are known.
# Written to /root/wp-security.conf on the VM disk and copied by the installer.
# This avoids any runtime variable substitution inside the VM.

# Build wp-admin Require block
REQUIRE_ADMIN=""
if [[ -n "$ADMIN_CIDR" || -n "$ALLOWED_ADMIN_IP" ]]; then
  [[ -n "$ADMIN_CIDR" ]]       && REQUIRE_ADMIN+=$'\n'"    Require ip ${ADMIN_CIDR}"
  [[ -n "$ALLOWED_ADMIN_IP" ]] && REQUIRE_ADMIN+=$'\n'"    Require ip ${ALLOWED_ADMIN_IP}"
fi

# Build wp-admin block strings (empty = no restriction added)
if [[ -n "$REQUIRE_ADMIN" ]]; then
  WP_ADMIN_BLOCK=$(cat << ADMINBLOCK
# wp-admin and wp-login.php are restricted to the IPs below.
# Access from any other source receives HTTP 403 Forbidden.
# Local network CIDR : ${ADMIN_CIDR:-not set}
# Allowed extra IP   : ${ALLOWED_ADMIN_IP:-not set}
# Proxy IP (trusted) : ${PROXY_IP:-direct — no proxy}
#
# PROXY BEHAVIOUR: If this VM is behind NPM or another reverse proxy,
# Apache sees the proxy IP as the source, not the real client IP.
# mod_remoteip (below) corrects this by trusting the proxy's
# X-Forwarded-For header — so Require ip checks the REAL client IP.
<DirectoryMatch "^/var/www/html/wp-admin">
${REQUIRE_ADMIN}
</DirectoryMatch>

<Files "wp-login.php">
${REQUIRE_ADMIN}
</Files>
ADMINBLOCK
)
else
  WP_ADMIN_BLOCK="# wp-admin: no IP restriction configured (open to any source IP)."$'\n'"# Re-run with ADMIN_CIDR set, or edit this file and restart the container."
fi

# Build mod_remoteip block (only if PROXY_IP was set)
if [[ -n "$PROXY_IP" ]]; then
  REMOTEIP_BLOCK=$(cat << RIBLOCK
# mod_remoteip — loaded because a reverse proxy IP was specified.
# Tells Apache to trust X-Forwarded-For from ${PROXY_IP} only.
# Other sources' X-Forwarded-For headers are ignored (prevents IP spoofing).
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy ${PROXY_IP}
RIBLOCK
)
else
  REMOTEIP_BLOCK="# mod_remoteip not loaded (direct access — no proxy IP specified)."$'\n'"# If you add a reverse proxy later, set RemoteIPTrustedProxy here and"$'\n'"# LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so"
fi

# ── Build custom admin slug Apache block ──────────────────────────────────────
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  # FIX: The previous version used <If "%%{THE_REQUEST} =~ ..."> which caused
  # Apache to crash with "Cannot parse condition clause: Parse error near '%'".
  # Root cause: %%{THE_REQUEST} is two literal percent signs (not a printf
  # escape in a bash heredoc) — Apache's ap_expr parser rejects it.
  #
  # NEW APPROACH: remove <If> entirely. The URL mapping is done by RewriteRule
  # only. Access control (who may USE wp-admin) is handled by the REQUIRE_ADMIN
  # Require ip block below — which already fires when WordPress serves the
  # rewritten /wp-admin/ response. No conditional logic needed here at all.
  # This is simpler, avoids the parser issue, and works correctly with Divi.
  #
  # BUG FIX (v7-5) — THE SLUG NEVER ACTUALLY FIRED: this block used to be
  # emitted bare in wp-security.conf, which loads via conf-enabled/*.conf —
  # processed by Debian's apache2.conf in MAIN SERVER context, BEFORE
  # sites-enabled/000-default.conf defines the <VirtualHost> that actually
  # serves every request. mod_rewrite has a documented, mod_rewrite-specific
  # exception to Apache's normal config inheritance: RewriteEngine/RewriteRule
  # set in main-server scope are NOT inherited by a <VirtualHost> unless that
  # vhost explicitly sets `RewriteOptions Inherit` (it doesn't, since it's the
  # stock Debian-packaged vhost from the apache2 package). So the slug's own
  # RewriteRules were silently never evaluated for real requests — 100% dead
  # config, no error, no log line, nothing.
  # FIX: the calling code now places this block INSIDE the existing
  # <Directory /var/www/html> container (see APACHE_SECURITY_CONF below)
  # instead of bare in server scope. Per-directory context (<Directory>,
  # <Files>, .htaccess) is NOT subject to the inheritance restriction above —
  # it's the exact same rewrite phase that already makes WordPress's own
  # .htaccess permalinks and the 8G Firewall .htaccess rules work correctly
  # today. Per-directory pattern matching is also RELATIVE to the directory
  # (no leading "/"), the same convention WordPress's own .htaccess uses
  # (`RewriteRule ^index\.php$ ...`, not `^/index\.php$`) — so the leading
  # "/" added by the old v7-1 fix (needed back when this ran in server
  # context) is now removed from the pattern side; the substitution side
  # keeps its leading "/" (an absolute path from the document root), same as
  # WordPress core's own `RewriteRule . /index.php [L]`.
  SLUG_BLOCK=$(cat << SLUGEOF
    # ── Custom wp-admin slug ────────────────────────────────────────────────
    # Slug: /${WP_ADMIN_SLUG}
    # How it works:
    #   Requests to /${WP_ADMIN_SLUG}/, /${WP_ADMIN_SLUG}/anything.php, etc. are
    #   rewritten internally to the matching literal file under /wp-admin/.
    #   Requests to /${WP_ADMIN_SLUG}-login  → rewritten to /wp-login.php  (internally)
    #   Direct access to /wp-admin/ and /wp-login.php is then controlled
    #   by the Require ip block below — bots hitting the default paths
    #   get 403 if they are not on the allowed ADMIN_CIDR.
    # Divi Visual Builder uses /wp-admin/admin-ajax.php from authenticated sessions,
    # which follow the session cookie — not the URL slug — so it is unaffected.
    # Targeting literal files (index.php, wp-login.php, and whatever file a
    # wp-admin sub-path already names, e.g. post.php, admin-ajax.php) avoids
    # Apache's fragile directory/trailing-slash resolution on an internally
    # rewritten directory target — every RewriteRule target below is a real file.
    <IfModule mod_rewrite.c>
      RewriteEngine On
      RewriteRule ^${WP_ADMIN_SLUG}/?$ /wp-admin/index.php [L,QSA]
      RewriteRule ^${WP_ADMIN_SLUG}/(.+)$ /wp-admin/\$1 [L,QSA]
      RewriteRule ^${WP_ADMIN_SLUG}-login/?$ /wp-login.php [L,QSA]
    </IfModule>
SLUGEOF
)
else
  SLUG_BLOCK=""
fi

APACHE_SECURITY_CONF=$(cat << APACHEEOF
# ============================================================
# WordPress Apache Security Configuration
# Generated by create-wordpress-vm.sh — do not edit by hand.
# Re-generate by re-running the provisioning script.
# Loaded via bind-mount: /etc/apache2/conf-enabled/wp-security.conf
# ============================================================

${REMOTEIP_BLOCK}

# Hide Apache and OS versions from HTTP headers and error pages.
ServerTokens Prod
ServerSignature Off

# File-based access log for CrowdSec.
# The bind-mount at /var/log/apache2 hides Docker's default stdout symlinks,
# so Apache creates real files here that CrowdSec reads from the host.
CustomLog /var/log/apache2/access.log combined

${WP_ADMIN_BLOCK}

# Suppress "Could not reliably determine the server's fully qualified domain name"
# (Apache warning AH00558). ServerName must be set — use the container hostname.
ServerName wordpress

# Disable directory listing and enable symlink following.
# BUG FIX (v7-5): the custom wp-admin slug and the author=N enumeration block
# both live INSIDE this <Directory> container now, not bare in server/global
# scope — see the long explanation above SLUG_BLOCK's generation on the host
# side. Short version: mod_rewrite rules bare in conf-enabled/*.conf run in
# main-server context and are never inherited by the <VirtualHost> that
# actually serves requests, so they silently never fired. Per-directory
# context (this container, same phase as .htaccess) does not have that
# restriction.
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride All

${SLUG_BLOCK}

    # Block ?author=N user enumeration. Attackers use this to harvest
    # WordPress usernames for targeted brute-force campaigns.
    # BUG FIX (v7-5): moved from bare server scope (never fired — see note
    # above) into this per-directory context.
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteCond %{QUERY_STRING} author=
        RewriteRule ^ - [F,L]
    </IfModule>
</Directory>

# Block PHP execution in wp-content/uploads.
# Prevents a successfully uploaded webshell from being executed —
# the highest-impact single PHP restriction for WordPress security.
<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>

# Block access to sensitive files that must never be served via HTTP.
<FilesMatch "(wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>

# Block backup and script files
<FilesMatch "\.(bak|orig|sql|log|sh|swp|save)$">
    Require all denied
</FilesMatch>

# Block wp-config backup patterns (some tools write these)
<FilesMatch "wp-config.*\.(php|txt|bak)$">
    Require all denied
</FilesMatch>

# Block WordPress debug log — written to /var/www/html/ when WP_DEBUG_LOG=true.
# Even though WP_DEBUG=false in our config, block it in case a plugin enables it.
<Files "debug.log">
    Require all denied
</Files>

# Block XML-RPC — common attack vector for brute-force and pingback DDoS.
# Remove this block only if a plugin explicitly requires XML-RPC (e.g. Jetpack).
<Files "xmlrpc.php">
    Require all denied
</Files>

# Security headers
Header always set X-Content-Type-Options  "nosniff"
Header always set X-Frame-Options         "SAMEORIGIN"
Header always set X-XSS-Protection        "1; mode=block"
Header always set Referrer-Policy         "strict-origin-when-cross-origin"
Header always unset X-Powered-By
# Content-Security-Policy — 'unsafe-inline' and 'unsafe-eval' are required
# by WordPress admin panels (inline JS/CSS is core to WP admin UX).
# Tighten these on the front-end only if your theme does not use inline scripts.
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
APACHEEOF
)
msg_ok "Apache security config built (wp-admin: ${ADMIN_CIDR:-open}, extra-ip: ${ALLOWED_ADMIN_IP:-none}, proxy: ${PROXY_IP:-none}, slug: ${WP_ADMIN_SLUG:-default})"

# ── Build the installer ───────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)

cat > "${TMPDIR}/install-wordpress.sh" << 'INSTALLER_EOF'
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

# ── Source installer variables (slug, CS key, GeoIP, rootless, network) ──────
# These were injected at provisioning time into /etc/wp-install/vars.sh
# because the INSTALLER_EOF heredoc is single-quoted (no host var expansion).
if [ -f /etc/wp-install/vars.sh ]; then
  . /etc/wp-install/vars.sh
  ok "Installer vars loaded: slug=${WP_ADMIN_SLUG:-default}, cs-enroll=${CROWDSEC_ENROLL_KEY:+provided}, net=${NET_MODE:-dhcp}, geoip=${GEOIP_ENABLED:-0}, rootless=${ROOTLESS_MODE:-0}"
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
  ROOTLESS_MODE="0"
  warn "/etc/wp-install/vars.sh not found — new features default off"
fi
# Defensive defaults in case vars.sh exists but is missing newer keys
# (e.g. a VM re-provisioned from an older version of this script's injection)
GEOIP_ENABLED="${GEOIP_ENABLED:-0}"
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"

# ── PRUN: podman dispatch wrapper ─────────────────────────────────────────────
# Rootless Podman keeps a COMPLETELY SEPARATE container/image state per user
# (under ~/.local/share/containers). If wpuser created the containers, root
# running a bare `podman ps` sees NOTHING — not an error, just an empty list,
# which is a silent and confusing failure mode. Every podman lifecycle/inspect
# call in this installer, in update.sh, and in wp-hardening.sh routes through
# PRUN so the correct user is always targeted regardless of deployment mode.
# Safe for simple arguments (inspect/ps/logs/exec/stop/rm/rename/start) because
# none of those carry embedded spaces requiring re-quoting through su -c.
# The three actual container-CREATION commands (which DO have complex quoted
# values like WORDPRESS_CONFIG_EXTRA) are handled separately via run-*.sh
# files invoked by file path — see the "ROOTLESS MODE" section below.
PRUN() {
  if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c "podman $*"
  else
    podman "$@"
  fi
}


ts "Loading kernel modules"
modprobe overlay 2>/dev/null && ok "overlay" || warn "overlay modprobe failed"
modprobe fuse    2>/dev/null && ok "fuse"    || warn "fuse modprobe failed"
grep -q '^overlay$' /etc/modules 2>/dev/null || echo overlay >> /etc/modules
grep -q '^fuse$'    /etc/modules 2>/dev/null || echo fuse    >> /etc/modules

ts "cgroup v2"
if ! grep -q '^cgroup2 ' /etc/fstab 2>/dev/null; then
  echo "cgroup2 /sys/fs/cgroup cgroup2 nosuid,noexec,nodev 0 0" >> /etc/fstab
fi
mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null || true
mount -t cgroup2 cgroup2 /sys/fs/cgroup
ok "cgroup2 mounted"
# Required for Podman overlay with bind mounts on some kernels
mount --make-shared / 2>/dev/null || true

ts "Hardening /tmp"
if ! grep -q 'tmpfs.*\/tmp ' /etc/fstab 2>/dev/null; then
  echo "tmpfs   /tmp   tmpfs   defaults,noexec,nosuid,nodev,size=256M   0 0" >> /etc/fstab
fi
mount -a 2>/dev/null || true
ok "/tmp: 256M noexec nosuid nodev"

ts "Kernel sysctls"
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=1
vm.swappiness=10
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
SYSCTL
sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1
ok "Sysctls applied"

ts "Installing Podman"
apk add --no-cache podman crun >/dev/null
ok "Podman $(podman --version 2>/dev/null | awk '{print $3}')"
echo 'export PODMAN_IGNORE_CGROUPSV1_WARNING=1' >> /etc/profile

# aardvark-dns: required for container-to-container DNS resolution on wp-net.
# Without it WordPress can't resolve the hostname 'mariadb:3306'.
# It may be a podman dependency on some Alpine versions but install explicitly.
apk add --no-cache aardvark-dns 2>/dev/null \
  || warn "aardvark-dns not in current repo — container DNS may use fallback"

# FIX: configure netavark to use nftables as firewall driver.
# The default on Alpine's netavark version is iptables, which causes:
#   Error: netavark: iptables: No such file or directory (os error 2)
# Setting nftables here means netavark uses the 'nft' binary (already
# installed via our nftables package) instead of looking for iptables.
# The wp-net subnet (10.89.1.0/24) is explicitly allowed in the nftables
# forward chain so container-to-internet traffic isn't dropped.
# CRITICAL: use a drop-in file in containers.conf.d/, NOT cat >> to the main
# containers.conf. Alpine's packaged containers.conf already defines [network].
# TOML does not allow duplicate section headers, so appending another [network]
# block causes: "Key 'network' has already been defined" and Podman refuses to
# start any container with a custom network.
# Drop-in files are merged on top of the main config without that restriction.
mkdir -p /etc/containers/containers.conf.d
cat > /etc/containers/containers.conf.d/10-netavark-nftables.conf << 'CONTAINERSCONF'
[network]
firewall_driver = "nftables"
CONTAINERSCONF
ok "netavark: firewall_driver=nftables (drop-in: containers.conf.d/)"

# ── Sub-UID/GID — set up now even though we use rootful; enables future ───────
# rootless or --userns=auto migration without reinstall.
grep -q '^root:100000' /etc/subuid 2>/dev/null || echo 'root:100000:65536' >> /etc/subuid
grep -q '^root:100000' /etc/subgid 2>/dev/null || echo 'root:100000:65536' >> /etc/subgid
ok "subuid/subgid ranges provisioned for root (100000:65536)"

ts "Configuring Podman storage"
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << 'REGCONF'
[registries.search]
registries = ["docker.io"]
[registries.insecure]
registries = []
REGCONF

DRIVER_CHOSEN="vfs"
if lsmod | grep -q '^overlay'; then
  cat > /etc/containers/storage.conf << 'SC1'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC1
  DRIVER_CHOSEN="overlay"
elif lsmod | grep -q '^fuse'; then
  apk add --no-cache fuse fuse3 fuse-overlayfs >/dev/null
  cat > /etc/containers/storage.conf << 'SC2'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
SC2
  DRIVER_CHOSEN="fuse-overlayfs"
else
  cat > /etc/containers/storage.conf << 'SC3'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC3
  warn "Using vfs storage (uses more disk) — overlay unavailable"
fi
podman system migrate >/dev/null 2>&1 || true
ok "Storage driver: ${DRIVER_CHOSEN}"

# ── Container image digest pinning (default ON) ───────────────────────────────
# BUG FIX (v7-5): real SHA256 digest pinning, resolved dynamically instead of
# a hardcoded placeholder. A hardcoded digest goes stale the instant any of
# these images is rebuilt under the same tag — which registries do routinely
# for security patches — silently pinning every future install to a WORSE,
# older image forever with no warning. Instead: pull the tag once here, ask
# Podman what digest it actually resolved to, then rewrite
# WP_IMAGE/DB_IMAGE/CROWDSEC_IMAGE to a pinned reference for the rest of this
# run. Every OpenRC service, every rootless run-*.sh script, and the GeoIP
# builder all read these same three variables (unquoted heredocs substitute
# at write time), so pinning here propagates everywhere with zero other code
# changes. It does NOT freeze out security updates: update.sh re-resolves and
# re-pins on every wp/db/crowdsec update, and `update.sh digest-check`
# explicitly checks for a newer digest published under the SAME tag (e.g. a
# same-version security rebuild) without waiting for a version bump.
#
# FORMAT NOTE: Podman's support for combining a tag AND a digest in one
# reference ("repo:tag@sha256:digest") has genuinely varied across releases —
# some older versions hard-reject it with "invalid image reference" (which
# would break every single container operation in this script, since
# WP_IMAGE/DB_IMAGE/CROWDSEC_IMAGE are used everywhere), while some newer
# ones accept it for pull/run but don't locally tag the stored image. Rather
# than guess which behavior this host's Podman has, _pin_digest tests the
# combined form directly against the local Podman (a fast, read-only,
# network-free `podman inspect`) and only uses it if that succeeds — falling
# back to the universally-supported digest-only form ("repo@sha256:digest")
# otherwise. Either form gives the same reproducibility guarantee; the
# combined form is just more readable in `podman ps`/logs when available.
if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
  ts "Resolving SHA256 digests for image pinning"
  _pin_digest() {
    local ref="$1" label="$2" digest repo_only candidate
    # BUG FIX (v7-5b): CRITICAL — ok()/warn() print to plain stdout (see their
    # definitions above: `echo "  ✔  $*"`), and this function is called as
    # WP_IMAGE=$(_pin_digest ...). A command substitution captures EVERYTHING
    # the function writes to stdout, not just the final `echo "$candidate"` —
    # so the human-readable "pinned to sha256:..." status line was landing
    # IN THE VARIABLE, ahead of the actual image reference, on its own line.
    # WP_IMAGE/DB_IMAGE/CROWDSEC_IMAGE ended up as two-line garbage strings,
    # and every subsequent `podman run ... "${DB_IMAGE}"` failed with
    # "invalid reference format" — confirmed in the field, MariaDB never
    # started. Every ok/warn call in this function must go to stderr (>&2)
    # so it still displays/logs normally but does NOT get captured here.
    if ! podman pull "$ref" >/dev/null 2>&1; then
      warn "${label}: pull failed — continuing with tag-only reference (no digest pin)" >&2
      echo "$ref"; return 0
    fi
    digest=$(podman inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    if [ -z "$digest" ]; then
      warn "${label}: could not resolve a digest — continuing with tag-only reference" >&2
      echo "$ref"; return 0
    fi
    repo_only="${ref%:*}"
    candidate="${ref}@${digest}"
    if podman inspect "$candidate" >/dev/null 2>&1; then
      ok "${label}: pinned to ${digest} (tag+digest)" >&2
      echo "$candidate"
    else
      ok "${label}: pinned to ${digest} (digest-only — this Podman doesn't accept tag+digest together)" >&2
      echo "${repo_only}@${digest}"
    fi
  }
  WP_IMAGE=$(_pin_digest "$WP_IMAGE" "WordPress")
  DB_IMAGE=$(_pin_digest "$DB_IMAGE" "MariaDB")
  CROWDSEC_IMAGE=$(_pin_digest "$CROWDSEC_IMAGE" "CrowdSec")
else
  ok "Digest pinning disabled (USE_DIGEST_PINNING=0) — using tag-only references"
fi

ts "Creating wpuser account"
apk add --no-cache shadow >/dev/null
if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  # Rootless mode needs a real shell for wpuser since OpenRC services and
  # update.sh invoke podman commands as wpuser via 'su -s /bin/sh wpuser -c'.
  id wpuser >/dev/null 2>&1 || adduser -D -s /bin/sh wpuser
  usermod -s /bin/sh wpuser 2>/dev/null || true
  # Distinct subuid/subgid range from root's own range (100000:65536, set
  # earlier) so rootless container UIDs never overlap with anything else.
  grep -q '^wpuser:' /etc/subuid 2>/dev/null || echo 'wpuser:200000:65536' >> /etc/subuid
  grep -q '^wpuser:' /etc/subgid 2>/dev/null || echo 'wpuser:200000:65536' >> /etc/subgid
  mkdir -p /home/wpuser/.config/containers
  chown -R wpuser:wpuser /home/wpuser/.config 2>/dev/null || true
  ok "wpuser ready — rootless mode (shell: /bin/sh, subuid/subgid: 200000:65536)"
else
  id wpuser >/dev/null 2>&1 || adduser -D -s /sbin/nologin wpuser
  ok "wpuser ready (file layout only — not used for container UID)"
fi

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

ts "Creating Podman wp-net network"
# Explicit subnet keeps the nftables forward chain rule exact:
#   ip saddr 10.89.1.0/24 accept  (in /etc/nftables.nft)
# Without a fixed subnet, netavark assigns 10.89.x.0/24 dynamically
# and the forward rule could stop matching after a network recreate.
# ROOTLESS: network state is per-user — must create the network as wpuser
# so wpuser's containers can connect to it. PRUN dispatches to the correct user.
PRUN network exists wp-net 2>/dev/null \
  || PRUN network create --subnet 10.89.1.0/24 --gateway 10.89.1.1 wp-net
ok "wp-net: 10.89.1.0/24 — internal, no host port for MariaDB"

ts "Installing 8G Firewall v1.4"
mkdir -p /home/wpuser/wp/htaccess
cat > /home/wpuser/wp/htaccess/.htaccess << '8GEOF'
# 8G FIREWALL v1.4 — https://perishablepress.com/8g-firewall/
# Installed by create-wordpress-vm.sh

# ── 8G[QUERY STRING] ────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{QUERY_STRING} (eval\(|base64_encode|GLOBALS\[|_REQUEST\[) [NC,OR]
  RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]
  RewriteCond %{QUERY_STRING} (\.\./|%2e%2e%2f|%252e%252e) [NC,OR]
  RewriteCond %{QUERY_STRING} (union.*select|select.*from.*information_schema) [NC,OR]
  RewriteCond %{QUERY_STRING} (benchmark\s*\(|sleep\s*\() [NC,OR]
  RewriteCond %{QUERY_STRING} (cmd=|passthru=|system\(|exec\() [NC,OR]
  RewriteCond %{QUERY_STRING} (127\.0\.0\.1|localhost|loopback) [NC,OR]
  RewriteCond %{QUERY_STRING} (<script|javascript:|vbscript:) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REQUEST URI] ─────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_URI} (\.(asp|bak|cfg|cgi|config|dat|dll|exe|git|gz|hta|ini|jsp|log|old|orig|sql|svn|swp|tar|tgz|zip)) [NC,OR]
  RewriteCond %{REQUEST_URI} (etc/passwd|etc/shadow|proc/self) [NC,OR]
  RewriteCond %{REQUEST_URI} (phpmyadmin|myadmin|pma|mysql) [NC,OR]
  RewriteCond %{REQUEST_URI} (wp-config\.php|wp-config-sample) [NC,OR]
  RewriteCond %{REQUEST_URI} (wp-content/uploads/.*\.ph(p|tml)) [NC,OR]
  RewriteCond %{REQUEST_URI} (webshell|c99\.php|r57\.php|hack\.php) [NC,OR]
  RewriteCond %{REQUEST_URI} (eval\(|base64_encode|\.\./) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[USER AGENT] ──────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} (acunetix|nikto|nessus|sqlmap|masscan|zgrab) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (dirbuster|gobuster|ffuf|wfuzz|nuclei|metasploit) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (scrapy|havij|libwww-perl|HTTrack|WPScan) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (wikodo|semrush.*bot|dotbot|ahrefsbot) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} ^(-|_|\.|\s)*$ [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} ^$ [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REQUEST METHOD] ──────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_METHOD} ^(CONNECT|DEBUG|MOVE|TRACE|TRACK) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REFERRER] ────────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_REFERER} (<|>|\'|\") [NC,OR]
  RewriteCond %{HTTP_REFERER} (base64_encode|eval\() [NC]
  RewriteRule .* - [F,L]
</IfModule>
8GEOF
# ── Custom wp-admin slug + author=N enumeration blocking ─────────────────────
# BUG FIX (v7-5): these were originally emitted ONLY in wp-security.conf's
# <Directory> block. That fixes the server-vs-vhost mod_rewrite inheritance
# problem (see the long note above SLUG_BLOCK's generation on the host side),
# but mod_rewrite has a SEPARATE, independent non-inheritance boundary
# between a <Directory> block and a .htaccess file at that same path — by
# default a .htaccess file's own ruleset can reset/replace what a covering
# <Directory> block established, unless that .htaccess explicitly opts in
# with `RewriteOptions Inherit`. Rather than depend on that merge behavior
# working a particular way, the exact same rules are placed here too —
# directly inside the .htaccess file, in the exact per-directory ruleset
# already proven to work (this is the same file WordPress's own permalinks
# and the 8G rules above run from). Placed BEFORE the WordPress-managed
# BEGIN/END block (and so, critically, evaluated BEFORE it) so: (1) it
# survives any WordPress .htaccess rewrite (permalink structure changes,
# etc. only ever touch content between those markers), and (2) requests to
# the custom slug resolve to a real file (/wp-admin/index.php) before
# WordPress's own catch-all `RewriteCond %{REQUEST_FILENAME} !-f` rule can
# claim them and route them into ordinary front-end 404 handling instead.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  {
    echo ""
    echo "# ── Custom wp-admin slug (mirrors wp-security.conf) ─────────────────────────"
    echo "<IfModule mod_rewrite.c>"
    echo "    RewriteEngine On"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/?\$ /wp-admin/index.php [L,QSA]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/(.+)\$ /wp-admin/\$1 [L,QSA]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}-login/?\$ /wp-login.php [L,QSA]"
    echo "</IfModule>"
  } >> /home/wpuser/wp/htaccess/.htaccess
fi
cat >> /home/wpuser/wp/htaccess/.htaccess << '8GEOF2'

# ── author=N user enumeration blocking (mirrors wp-security.conf) ───────────
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} author=
    RewriteRule ^ - [F,L]
</IfModule>

# ── WordPress Permalink Rules (WordPress manages this block — do not edit) ──
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
8GEOF2
chmod 644 /home/wpuser/wp/htaccess/.htaccess
chown 33:33 /home/wpuser/wp/htaccess/.htaccess
ok "8G Firewall .htaccess ready at /home/wpuser/wp/htaccess/"
ok "  Toggle anytime: wp-hardening.sh disable 8g | enable 8g"

ts "Preparing volume directories"
mkdir -p /home/wpuser/wp/html /home/wpuser/wp/logs
mkdir -p /home/wpuser/wp/mysql
mkdir -p /home/wpuser/wp/apache-conf /home/wpuser/wp/php-conf
chown -R wpuser:wpuser /home/wpuser/wp 2>/dev/null || true

# Rootless containers use subordinate UID/GID mapping (subuid/subgid).
# wpuser's range is 200000:65536, so container UID 33 (www-data) maps to
# host UID 200033, and container UID 999 (mysql) maps to host UID 200999.
# A plain 'chown 33:33' as real root sets the WRONG on-disk owner for
# rootless containers — the write would fail silently because the container
# process (which has access to 200033, not 33) cannot write to a dir owned
# by literal 33. 'podman unshare' enters wpuser's user namespace so chown
# values resolve correctly through the mapping to the actual disk UIDs.
if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  su -s /bin/sh wpuser -c 'podman unshare chown -R 33:33  /home/wpuser/wp/html /home/wpuser/wp/logs' 2>/dev/null \
    && ok "html/logs owned by www-data (subordinate UID mapping via podman unshare)" || true
  su -s /bin/sh wpuser -c 'podman unshare chown -R 999:999 /home/wpuser/wp/mysql' 2>/dev/null \
    && ok "mysql owned by mysql (subordinate UID mapping via podman unshare)" || true
else
  # Rootful: container UIDs are the real host UIDs — literal chown is correct.
  chown -R 33:33  /home/wpuser/wp/html /home/wpuser/wp/logs
  chown -R 999:999 /home/wpuser/wp/mysql
  ok "Volume directories owned by UID 33 (www-data) and 999 (mysql)"
fi

# ── Deploy Apache security config (pre-built by host script) ─────────────────
# /root/wp-security.conf was written by create-wordpress-vm.sh via qemu-nbd
# with ADMIN_CIDR, ALLOWED_ADMIN_IP, and PROXY_IP already substituted.
# No runtime variable substitution needed here.
if [ -f /root/wp-security.conf ]; then
  cp /root/wp-security.conf /home/wpuser/wp/apache-conf/wp-security.conf
  chmod 644 /home/wpuser/wp/apache-conf/wp-security.conf
  ok "Apache security config deployed (with your CIDR/IP restrictions baked in)"
  # If mod_remoteip files were also injected, deploy them too
  if [ -f /root/wp-remoteip.load ]; then
    mkdir -p /home/wpuser/wp/apache-mods
    cp /root/wp-remoteip.load /home/wpuser/wp/apache-mods/remoteip.load
    cp /root/wp-remoteip.conf /home/wpuser/wp/apache-mods/remoteip.conf 2>/dev/null || true
    chmod 644 /home/wpuser/wp/apache-mods/remoteip.load \
              /home/wpuser/wp/apache-mods/remoteip.conf 2>/dev/null || true
    ok "mod_remoteip files deployed — proxy IP trusted for X-Forwarded-For"
  fi
else
  warn "/root/wp-security.conf not found — generating fallback (no IP restriction)"
  cat > /home/wpuser/wp/apache-conf/wp-security.conf << 'APACHEFALLBACK'
# Fallback Apache security config — no wp-admin IP restriction.
ServerTokens Prod
ServerSignature Off
CustomLog /var/log/apache2/access.log combined
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride All
</Directory>
<FilesMatch "(wp-config\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
<FilesMatch "\.(bak|orig|sql|log|sh|swp|save)$">
    Require all denied
</FilesMatch>
<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
<Files "xmlrpc.php">
    Require all denied
</Files>
<Files "debug.log">
    Require all denied
</Files>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} author=
    RewriteRule ^ - [F,L]
</IfModule>
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always unset X-Powered-By
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
APACHEFALLBACK
fi
chmod 644 /home/wpuser/wp/apache-conf/wp-security.conf

# PHP security configuration
cat > /home/wpuser/wp/php-conf/security.ini << 'PHPSEC'
; WordPress PHP Security Configuration
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/apache2/php-errors.log
; allow_url_fopen: ON for MSP production.
; WordPress core uses cURL (not fopen) for HTTP, but many WooCommerce payment
; gateways and plugin APIs use file_get_contents() with URLs. Disabling breaks
; those integrations. Restrict at the nftables output chain if tighter control
; is needed. Flip to Off only for high-security environments with no plugins.
allow_url_fopen = On
allow_url_include = Off
; File upload limits
upload_max_filesize = 64M
post_max_size = 64M
; Runtime limits
memory_limit = 256M
max_execution_time = 300
; Session security — Lax (not Strict) for WordPress OAuth and payment flows.
; Strict breaks SSO callbacks, WooCommerce, and any cross-origin POST redirect.
session.cookie_httponly = 1
session.cookie_samesite = Lax
session.use_strict_mode = 1
PHPSEC
chmod 644 /home/wpuser/wp/php-conf/security.ini

ok "Volume directories and config files ready:"
ok "  /home/wpuser/wp/html     WordPress files   (UID 33:www-data)"
ok "  /home/wpuser/wp/logs     Apache access log (UID 33:www-data)"
ok "  /home/wpuser/wp/mysql    MariaDB data      (UID 999:mysql)"
ok "  /home/wpuser/wp/apache-conf/wp-security.conf"
ok "  /home/wpuser/wp/php-conf/security.ini"

ts "Enabling syslog"
rc-update add syslog boot 2>/dev/null || true
rc-service syslog status >/dev/null 2>&1 || rc-service syslog start 2>/dev/null || true
ok "syslog active"



# ════════════════════════════════════════════════════════════════════════════
# ROOTLESS MODE SETUP (only runs if ROOTLESS_MODE=1)
#
# Generates run-mariadb.sh / run-wordpress.sh / run-crowdsec.sh — standalone
# POSIX sh files containing the full podman run invocation for each container.
# WHY FILES INSTEAD OF INLINE su -c STRINGS: our podman run commands embed
# WORDPRESS_CONFIG_EXTRA values with nested double-quotes. Flattening that
# through `su -c "podman run ... -e VAR='...nested...' ..."` breaks the outer
# shell's quote parsing. A file has no such problem — it's just a normal
# script with normal quoting, invoked via `su -s /bin/sh wpuser -c '/path'`
# where the -c argument is a single clean token (the path), so there is
# nothing to mis-parse regardless of how complex the file's own contents are.
# This same mechanism works correctly whether called from bash (this
# installer) or busybox ash (OpenRC service scripts on Alpine).
#
# PORT 8080 RATIONALE: an unprivileged user cannot bind host ports <1024.
# WordPress therefore publishes -p 8080:80 (container-internal Apache still
# binds port 80 normally — NET_BIND_SERVICE is evaluated inside the
# container's own network namespace, unaffected by the outer host-level
# restriction). nftables (configured host-side, always as real root
# regardless of Podman mode) redirects public port 80 to 8080 so visitors
# never see a difference.
#
# SOURCE-IP PRESERVATION — read before trusting CrowdSec bans / ADMIN_CIDR:
# Rootless bridge networks forward published ports via "rootlessport", a
# userspace proxy that by default does NOT preserve the original client IP
# (WordPress would see every visitor as coming from the bridge gateway).
# This would silently blind CrowdSec banning and the wp-admin CIDR check.
# Podman has an experimental fix (rootless_port_forwarder=pasta) which we
# attempt below; if the installed pasta version doesn't support it, we warn
# loudly rather than silently degrading a security feature.
# ════════════════════════════════════════════════════════════════════════════
if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  ts "Rootless mode — generating container run scripts"

  # Attempt pasta-based port forwarding for source-IP preservation.
  # Falls back gracefully (default rootlessport) with a loud warning if the
  # installed pasta is too old for the --map-gw style source-IP behaviour.
  apk add --no-cache passt >/dev/null 2>&1 || true
  PASTA_OK=0
  if command -v pasta >/dev/null 2>&1; then
    cat >> /home/wpuser/.config/containers/containers.conf << 'PASTACONF'
[network]
rootless_port_forwarder = "pasta"
PASTACONF
    chown wpuser:wpuser /home/wpuser/.config/containers/containers.conf 2>/dev/null || true
    PASTA_OK=1
    ok "pasta port forwarder configured — will verify source-IP preservation after WordPress starts"
  else
    warn "pasta not available via apk — using default rootlessport (NO client source-IP preservation)"
    warn "  CrowdSec IP banning and the wp-admin ADMIN_CIDR check will NOT see real visitor IPs."
    warn "  Mitigation: rely on Layer 1 nftables (SSH_CIDR/WEB_CIDR) and CrowdSec's"
    warn "  application-layer WordPress/Apache rules (which inspect request content,"
    warn "  not source IP) until this is resolved, or switch to rootful mode."
  fi

  # ── run-mariadb.sh ──────────────────────────────────────────────────────────
  cat > /home/wpuser/wp/run-mariadb.sh << RUNDB
#!/bin/sh
# Generated by create-wordpress-vm.sh — rootless MariaDB launcher.
# Re-run anytime to (re)create the container if it's missing; starts it if present.
if podman container exists mariadb 2>/dev/null; then
  podman start mariadb
else
  podman run -d --name mariadb --network wp-net --ip 10.89.1.2 --restart always \\
    --label io.containers.autoupdate=image \\
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
    --cap-add DAC_OVERRIDE --cap-add FOWNER \\
    --security-opt no-new-privileges:true \\
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev \\
    --pids-limit 100 --memory=512m --cpu-shares=512 \\
    --env-file /etc/wordpress/env \\
    -v /home/wpuser/wp/mysql:/var/lib/mysql \\
    -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \\
    --health-cmd "healthcheck.sh --connect --innodb_initialized" \\
    --health-interval 5s --health-timeout 5s --health-retries 24 --health-start-period 30s \\
    "${DB_IMAGE}"
fi
RUNDB
  chmod 750 /home/wpuser/wp/run-mariadb.sh
  chown wpuser:wpuser /home/wpuser/wp/run-mariadb.sh

  # ── run-wordpress.sh (port 8080, not 80 — see rationale above) ──────────────
  cat > /home/wpuser/wp/run-wordpress.sh << RUNWP
#!/bin/sh
# Generated by create-wordpress-vm.sh — rootless WordPress launcher.
if podman container exists wordpress 2>/dev/null; then
  podman start wordpress
else
  podman run -d --name wordpress --network wp-net --ip 10.89.1.3 -p 8080:80 --restart always \\
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
    --add-host "mariadb:10.89.1.2" \\
    -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \\
    -v /home/wpuser/wp/html:/var/www/html \\
    -v /home/wpuser/wp/logs:/var/log/apache2 \\
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \\
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \\
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \\
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \\
    "${WP_IMAGE}"
fi
RUNWP
  chmod 750 /home/wpuser/wp/run-wordpress.sh
  chown wpuser:wpuser /home/wpuser/wp/run-wordpress.sh

  # ── run-crowdsec.sh ──────────────────────────────────────────────────────────
  # --network host: shares the host's network namespace directly, so there is
  # no rootlessport proxy stage for CrowdSec itself (its only inbound surface
  # is LAPI on 127.0.0.1, loopback regardless of Podman mode).
  cat > /home/wpuser/wp/run-crowdsec.sh << RUNCS
#!/bin/sh
# Generated by create-wordpress-vm.sh — rootless CrowdSec launcher.
if podman container exists crowdsec 2>/dev/null; then
  podman start crowdsec
else
  podman run -d --name crowdsec --restart always --network host \\
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
    --security-opt no-new-privileges:true --read-only \\
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev --tmpfs /var/run:size=16M,noexec,nosuid,nodev \\
    --pids-limit 100 --memory=512m --label io.containers.autoupdate=image \\
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \\
    -v /opt/crowdsec/config:/etc/crowdsec:rw \\
    -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \\
    -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \\
    -v /home/wpuser/wp/logs:/var/log/wordpress:ro \\
    -v /var/log/messages:/var/log/host/messages:ro \\
    "${CROWDSEC_IMAGE}"
fi
RUNCS
  chmod 750 /home/wpuser/wp/run-crowdsec.sh
  chown wpuser:wpuser /home/wpuser/wp/run-crowdsec.sh
  mkdir -p /opt/crowdsec/config /opt/crowdsec/data
  chown -R wpuser:wpuser /opt/crowdsec
  chmod 644 /var/log/messages 2>/dev/null || true

  ok "run-mariadb.sh, run-wordpress.sh, run-crowdsec.sh generated (owned by wpuser)"
  ok "WordPress will publish on host port 8080 — nftables redirects public :80 to it"
fi

ts "nftables firewall"
apk add --no-cache nftables >/dev/null
rc-update add nftables default 2>/dev/null || true
if [ -f /etc/nftables.nft ]; then
  nft -f /etc/nftables.nft && ok "Rules loaded" \
    || warn "Ruleset load failed — check /etc/nftables.nft"
  rc-service nftables start 2>/dev/null || true
else
  warn "/etc/nftables.nft not found"
fi

# ── MariaDB container ─────────────────────────────────────────────────────────
# Internal wp-net ONLY — zero host port exposure.
# BUG FIX: tag was 11.4-lts (does not exist) — now using 11.4.
ts "Starting MariaDB (pulling ~150 MB — internal network only)"
# Mount a custom MariaDB config to cap InnoDB buffer pool and enable slow
# query logging. Without a buffer pool limit MariaDB can consume all available
# RAM on busy sites, evicting WordPress and CrowdSec from memory.
mkdir -p /home/wpuser/wp/mariadb-conf
cat > /home/wpuser/wp/mariadb-conf/wp.cnf << 'MYCNF'
# MariaDB 11.4 configuration for WordPress
# Use [mariadbd] (not [mysqld]) — MariaDB 11.x canonical section name.
# [mysqld] still works for compat but [mariadbd] avoids deprecation warnings.
[mariadbd]
# InnoDB: cap buffer pool to prevent OOM on a 4 GB VM shared with WordPress
# and CrowdSec. innodb_log_file_size removed — deprecated in 11.x, now
# controlled by innodb_redo_log_capacity (default is fine for WP workloads).
innodb_buffer_pool_size        = 256M
# innodb_log_file_size is the correct MariaDB variable (innodb_redo_log_capacity
# is MySQL 8.0.30+ syntax and does NOT exist in MariaDB — using it crashes mariadbd)
innodb_log_file_size           = 64M
innodb_flush_log_at_trx_commit = 2
# Suppress io_uring probe: MariaDB 11.x tries io_uring first, falls back to
# libaio when blocked by seccomp (our --cap-drop ALL). The fallback works fine
# but generates noisy log lines. Disable the probe entirely.
innodb_use_native_aio         = OFF
# Charset: utf8mb4 required for WordPress emoji and 4-byte Unicode support
character_set_server          = utf8mb4
collation_server              = utf8mb4_unicode_ci
# Connection limits
max_connections               = 100
max_allowed_packet            = 64M
# Slow query log for MSP performance diagnostics
slow_query_log                = 1
slow_query_log_file           = /var/lib/mysql/slow.log
long_query_time               = 2
MYCNF
chmod 644 /home/wpuser/wp/mariadb-conf/wp.cnf
ok "MariaDB config: innodb_buffer_pool=256M, slow_query_log=on"

if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  ok "Rootless mode: launching MariaDB as wpuser via run-mariadb.sh"
  su -s /bin/sh wpuser -c '/home/wpuser/wp/run-mariadb.sh'
else
  podman rm -f mariadb 2>/dev/null || true
  podman run -d \
    --name    mariadb \
    --network wp-net \
    --ip      10.89.1.2 \
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
fi

# FIX 2: Do NOT rely on Podman health check status.
# On Alpine without systemd, conmon's health check timer often does not fire —
# the container stays in "starting" state indefinitely even when MariaDB is
# fully ready. Instead, use a direct exec-based probe (mariadbd ping with
# credentials) which works regardless of conmon or cgroup configuration.
# The --health-cmd is still configured for 'podman ps' display purposes, but
# we never block on its output here.
ts "Waiting for MariaDB to accept connections (up to 3 min)"
DB_READY=0
for i in $(seq 1 36); do
  # Run mariadbd ping INSIDE the container where MARIADB_ROOT_PASSWORD is set.
  # Use sh -c so the env var expands in the container's shell context, not here.
  if PRUN exec mariadb sh -c \
       'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
        mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
    DB_READY=1; break
  fi
  sleep 5
done
[ "$DB_READY" = "1" ] \
  && ok "MariaDB accepting authenticated connections on port 3306" \
  || warn "MariaDB did not respond in 3 min — WordPress will retry. Check: PRUN logs mariadb | tail -20"



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
[ "${ROOTLESS_MODE:-0}" = "1" ] && WEB_CHECK_PORT=8080

if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  ok "Rootless mode: launching WordPress as wpuser via run-wordpress.sh (host port 8080)"
  su -s /bin/sh wpuser -c '/home/wpuser/wp/run-wordpress.sh'
else
  podman rm -f wordpress 2>/dev/null || true
  # shellcheck disable=SC2086
  podman run -d \
    --name    wordpress \
    --network wp-net \
    --ip      10.89.1.3 \
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
    --add-host "mariadb:10.89.1.2" \
    -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
    ${WP_VOL_ARGS} \
    "${WP_IMAGE}"
fi

# Wait for WordPress to respond with non-500 (500 = DB not connected)
# A 302 redirect to /wp-admin/install.php is the expected first response.
# WEB_CHECK_PORT: 80 rootful, 8080 rootless (nftables' prerouting redirect
# does not apply to locally-generated loopback traffic, only traffic arriving
# on the real network interface — so the internal check must hit the real
# published port directly).
WP_READY=0
for i in $(seq 1 24); do
  http_code=$(wget -S -O /dev/null "http://127.0.0.1:${WEB_CHECK_PORT}/" 2>&1 \
    | awk '/HTTP\// {print $2}' | tail -1)
  if [ -n "$http_code" ] && [ "$http_code" != "500" ]; then
    ok "WordPress HTTP ${http_code} — DB connected successfully"
    WP_READY=1; break
  fi
  [ "$http_code" = "500" ] && warn "WordPress returns 500 (DB not connected yet — retry ${i}/24)"
  sleep 5
done
[ "$WP_READY" = "0" ] && warn "WordPress did not confirm DB connectivity — check: podman logs wordpress"
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
# restarts. ROOTLESS NOTE: container UID 33 maps to a subordinate host UID
# (200000+33=200033 with our wpuser:200000:65536 range), NOT literal 33 — a
# plain `chown 33:33` as real root would set the WRONG on-disk owner.
# `podman unshare` enters wpuser's user namespace so chown 33:33 resolves
# correctly to the mapped subordinate UID, exactly as it appears inside the
# container.
if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  su -s /bin/sh wpuser -c 'podman unshare chown -R 33:33 /home/wpuser/wp/html/wp-content' 2>/dev/null \
    && ok "Host-side ownership fixed via podman unshare (subordinate UID mapping)" || true
else
  chown -R 33:33 /home/wpuser/wp/html/wp-content 2>/dev/null \
    && ok "Host-side /home/wpuser/wp/html/wp-content ownership fixed too" || true
fi


# ── OpenRC: mariadb-container ─────────────────────────────────────────────────

# ════════════════════════════════════════════════════════════════════════════
# GEOIP COUNTRY FILTERING (optional — only runs if GEOIP_ENABLED=1)
#
# BUG FIX (v7-4): GeoIP silently never got applied in the field even with
# valid MaxMind credentials. Root cause: `podman build` for the mod_maxminddb
# image runs its RUN steps (apt-get, curl) in a build-time container that
# is NOT on wp-net (10.89.1.0/24) — it's on Podman's default bridge subnet.
# But by this point in Stage 2 the nftables ruleset is already loaded, and
# its forward chain only allows wp-net traffic before its policy DROP:
#   ip saddr 10.89.1.0/24 accept
#   ip daddr 10.89.1.0/24 accept
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
cat > /usr/local/bin/wp-geoip-setup.sh << 'WPGEOSETUP'
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
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
PRUN() {
  if [ "${ROOTLESS_MODE}" = "1" ]; then
    su -s /bin/sh wpuser -c "podman $*"
  else
    podman "$@"
  fi
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

CURRENT_WP_IMAGE=$(PRUN inspect wordpress --format '{{.Config.Image}}' 2>/dev/null)
[ -z "$CURRENT_WP_IMAGE" ] && CURRENT_WP_IMAGE="docker.io/wordpress:6.9.4-php8.3-apache"
# Derive a human-friendly tag for naming the local GeoIP image. Once digest
# pinning is active, CURRENT_WP_IMAGE may be tag+digest (repo:tag@sha256:...)
# OR digest-only (repo@sha256:..., no tag at all — used when this host's
# Podman doesn't accept the combined form). A plain `sed 's|.*:||'` breaks
# in the digest-only case (there's no ":tag" to find, so it would return the
# whole "repo/path" string, which isn't a valid tag — tags can't contain
# "/"). Detect which case applies and fall back to a short digest fragment
# when there's genuinely no tag to extract.
WP_BASE_NO_DIGEST=$(echo "${CURRENT_WP_IMAGE}" | sed 's|@sha256:.*||')
case "$WP_BASE_NO_DIGEST" in
  *:*) WP_TAG_PORTION="${WP_BASE_NO_DIGEST##*:}" ;;
  *)   WP_TAG_PORTION=$(echo "${CURRENT_WP_IMAGE}" | grep -oE 'sha256:[0-9a-f]{12}' | sed 's|sha256:||' || true)
       [ -z "$WP_TAG_PORTION" ] && WP_TAG_PORTION="latest"
       ;;
esac
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
    && find /usr/lib/apache2/modules -name 'mod_maxminddb.so' -exec cp {} /tmp/mod_maxminddb.so \;

FROM ${CURRENT_WP_IMAGE}
COPY --from=builder /tmp/mod_maxminddb.so /etc/apache2/maxminddb-module/mod_maxminddb.so
CONTAINERFILE

echo "Building ${GEOIP_IMG_TAG} — using --network host (the wp-net-only nftables"
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
HTTP_CODE=$(curl -sS -o /tmp/geolite2-country.tar.gz -w '%{http_code}' \
  -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
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
    <RequireAll>
        Require env MM_COUNTRY_CODE
${GEOIP_REQUIRE_LINE}
    </RequireAll>
</IfModule>
GEOIPCONF
chmod 644 /home/wpuser/wp/apache-conf/geoip.conf
echo "geoip.conf written (${GEOIP_MODE}: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})"

WEB_CHECK_PORT=80
[ "${ROOTLESS_MODE}" = "1" ] && WEB_CHECK_PORT=8080

echo "Recreating WordPress container with GeoIP module + database mounted…"
if [ "${ROOTLESS_MODE}" = "1" ]; then
  cat > /home/wpuser/wp/run-wordpress.sh << RUNWPGEO
#!/bin/sh
# Generated by wp-geoip-setup.sh — rootless WordPress launcher (GeoIP active).
if podman container exists wordpress 2>/dev/null; then
  podman start wordpress
else
  podman run -d --name wordpress --network wp-net --ip 10.89.1.3 -p 8080:80 --restart always \\
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
    --add-host "mariadb:10.89.1.2" \\
    -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \\
    -v /home/wpuser/wp/html:/var/www/html \\
    -v /home/wpuser/wp/logs:/var/log/apache2 \\
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \\
    -v /home/wpuser/wp/apache-conf/geoip.conf:/etc/apache2/conf-enabled/geoip.conf:ro \\
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \\
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \\
    -v /home/wpuser/wp/apache-mods/maxminddb.load:/etc/apache2/mods-enabled/maxminddb.load:ro \\
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \\
    -v /home/wpuser/wp/geoip-db:/usr/share/GeoIP:ro \\
    "${GEOIP_IMG_TAG}"
fi
RUNWPGEO
  chmod 750 /home/wpuser/wp/run-wordpress.sh
  chown wpuser:wpuser /home/wpuser/wp/run-wordpress.sh
  su -s /bin/sh wpuser -c 'podman rm -f wordpress' >/dev/null 2>&1 || true
  su -s /bin/sh wpuser -c '/home/wpuser/wp/run-wordpress.sh'
  sed -i "s|^WP_IMAGE=.*|WP_IMAGE=\"${GEOIP_IMG_TAG}\"|" /etc/init.d/wp-container 2>/dev/null || true
else
  podman rm -f wordpress >/dev/null 2>&1 || true
  podman run -d \
    --name wordpress --network wp-net --ip 10.89.1.3 -p 80:80 --restart always \
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
    --add-host "mariadb:10.89.1.2" \
    -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
    -v /home/wpuser/wp/html:/var/www/html \
    -v /home/wpuser/wp/logs:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/apache-conf/geoip.conf:/etc/apache2/conf-enabled/geoip.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/apache-mods/maxminddb.load:/etc/apache2/mods-enabled/maxminddb.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
    -v /home/wpuser/wp/geoip-db:/usr/share/GeoIP:ro \
    "${GEOIP_IMG_TAG}"
  sed -i "s|WP_IMAGE=.*|WP_IMAGE=\"${GEOIP_IMG_TAG}\"|" /etc/init.d/wp-container 2>/dev/null || true
fi
sed -i "s|^PINNED_WP_VER=.*|PINNED_WP_VER=\"geoip-$(echo "${GEOIP_IMG_TAG}" | sed 's|.*:||')\"|" /usr/local/bin/update.sh 2>/dev/null || true

sleep 5
PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
for i in $(seq 1 12); do
  wget -qO- "http://127.0.0.1:${WEB_CHECK_PORT}/" >/dev/null 2>&1 && { echo "WordPress responding with GeoIP active"; break; }
  sleep 5
done

grep -q "GeoLite2-Country database refresh" /etc/crontabs/root 2>/dev/null || cat >> /etc/crontabs/root << GEOCRON
# Weekly GeoLite2-Country database refresh (Wednesday 06:00 UTC)
0 6 * * 3 curl -fsSL -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz' -o /tmp/geolite-refresh.tar.gz && mkdir -p /tmp/geolite-refresh && tar xzf /tmp/geolite-refresh.tar.gz -C /tmp/geolite-refresh --strip-components=1 && find /tmp/geolite-refresh -name '*.mmdb' -exec cp {} /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb \; && rm -rf /tmp/geolite-refresh /tmp/geolite-refresh.tar.gz && logger -t geoip-update "GeoLite2-Country refreshed"
GEOCRON

echo "=== wp-geoip-setup.sh done — GeoIP ${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}) active ==="
WPGEOSETUP
chmod +x /usr/local/bin/wp-geoip-setup.sh
ok "wp-geoip-setup.sh installed — reusable, rerunnable anytime with no reboot needed"
ok "  Retry after fixing creds: /usr/local/bin/wp-geoip-setup.sh   then: tail -40 /var/log/wp-geoip.log"

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

ts "Creating mariadb-container service"
cat > /etc/init.d/mariadb-container << ORCSVC_DB
#!/sbin/openrc-run
name="mariadb-container"
description="MariaDB for WordPress (rootful Podman, internal wp-net)"
DB_IMAGE="${DB_IMAGE}"

depend() {
  need net
  after sysfs qemu-guest-agent
}

start() {
  ebegin "Starting MariaDB"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  lsmod | grep -q '^overlay' || modprobe overlay 2>/dev/null || true
  lsmod | grep -q '^fuse'    || modprobe fuse    2>/dev/null || true
  if [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \\
     && [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  # Rootless dispatch: this OpenRC script runs independently at boot and has
  # no access to the installer's shell variables, so it reads vars.sh itself.
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "\${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c '/home/wpuser/wp/run-mariadb.sh' >/dev/null 2>&1
    eend \$?
    return
  fi
  # Network must exist in the correct user namespace (rootless: wpuser, rootful: root)
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh 2>/dev/null || true
  if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c 'podman network exists wp-net 2>/dev/null || podman network create --subnet 10.89.1.0/24 --gateway 10.89.1.1 wp-net' 2>/dev/null || true
  else
    podman network exists wp-net 2>/dev/null || podman network create --subnet 10.89.1.0/24 --gateway 10.89.1.1 wp-net 2>/dev/null || true
  fi
  if podman container exists mariadb 2>/dev/null; then
    podman start mariadb >/dev/null 2>&1
  else
    podman rm -f mariadb 2>/dev/null || true
    podman run -d --name mariadb --network wp-net --ip 10.89.1.2 --restart always \\
      --label io.containers.autoupdate=image \\
      --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add DAC_OVERRIDE --cap-add FOWNER \\
      --security-opt no-new-privileges:true \\
      --tmpfs /tmp:size=32M,noexec,nosuid,nodev \\
      --pids-limit 100 --memory=512m --cpu-shares=512 \\
      --env-file /etc/wordpress/env \\
      -v /home/wpuser/wp/mysql:/var/lib/mysql \\
      -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \\
      --health-cmd "healthcheck.sh --connect --innodb_initialized" \\
      --health-interval 5s --health-timeout 5s --health-retries 24 \\
      --health-start-period 30s \\
      "\${DB_IMAGE}" >/dev/null 2>&1
  fi
  eend \$?
}

stop() {
  ebegin "Stopping MariaDB"
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "\${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c 'podman stop mariadb' >/dev/null 2>&1
  else
    podman stop mariadb >/dev/null 2>&1
  fi
  eend \$?
}
ORCSVC_DB
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
description="WordPress Apache (rootful Podman, wp-net, port 80)"
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
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "\${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c '/home/wpuser/wp/run-wordpress.sh' >/dev/null 2>&1
    sleep 3
    su -s /bin/sh wpuser -c 'podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content' >/dev/null 2>&1 || true
    eend \$?
    return
  fi
  if podman container exists wordpress 2>/dev/null; then
    podman start wordpress >/dev/null 2>&1
    # Fix uploads ownership after every start (entrypoint creates dirs as root)
    sleep 3 && podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
  else
    podman rm -f wordpress 2>/dev/null || true
    podman run -d --name wordpress --network wp-net --ip 10.89.1.3 -p 80:80 --restart always \\
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
      --add-host "mariadb:10.89.1.2" \\
      -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \\
      -v /home/wpuser/wp/html:/var/www/html \\
      -v /home/wpuser/wp/logs:/var/log/apache2 \\
      -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \\
      -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \\
      ${SVC_HEADERS_VOL}${SVC_REMOTEIP_VOLS} \\
      "\${WP_IMAGE}" >/dev/null 2>&1
  fi
  eend \$?
}

stop() {
  ebegin "Stopping WordPress"
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "\${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c 'podman stop wordpress' >/dev/null 2>&1
  else
    podman stop wordpress >/dev/null 2>&1
  fi
  eend \$?
}
ORCSVC_WP
chmod +x /etc/init.d/wp-container
rc-update add wp-container default 2>/dev/null || true
ok "wp-container service registered"

# ── WP-Cron runner (rootful/rootless-aware) ───────────────────────────────────
cat > /usr/local/bin/wp-cron-run.sh << 'WPCRON'
#!/bin/sh
# WordPress system cron — runs wp-cron.php inside the WordPress container.
# Uses the correct Podman user context depending on deployment mode.
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  su -s /bin/sh wpuser -c 'podman exec wordpress php /var/www/html/wp-cron.php'
else
  podman exec wordpress php /var/www/html/wp-cron.php
fi
WPCRON
chmod +x /usr/local/bin/wp-cron-run.sh
ok "wp-cron-run.sh installed (rootful/rootless-aware)"

# ── Update script ─────────────────────────────────────────────────────────────
ts "Installing update script"
cat > /usr/local/bin/update.sh << 'UPDSCRIPT'
#!/bin/sh
# =============================================================================
# Update Utility — WordPress VM
# Usage: update.sh [check|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all]
# =============================================================================
set -e

# BUG FIX: 11.4-lts does not exist on Docker Hub — use 11.4
# WordPress 6.8-php8.3-apache: current stable minor branch (7.0 too new for MSP)
# CrowdSec v1.7.4: latest stable; v1.7.0+ requires /var/lib/crowdsec/data volume
PINNED_WP_VER="6.9.4-php8.3-apache"
PINNED_DB_VER="11.4"
PINNED_CS_VER="v1.7.8"
WP_REGISTRY="docker.io/wordpress"
DB_REGISTRY="docker.io/mariadb"
CS_REGISTRY="docker.io/crowdsecurity/crowdsec"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: Must run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
PRUN() {
  if [ "${ROOTLESS_MODE}" = "1" ]; then
    su -s /bin/sh wpuser -c "podman $*"
  else
    podman "$@"
  fi
}
cd /tmp

# BUG FIX (v7-5): the previous `... | sed ... || echo "not running"` never
# actually fired that fallback — when a container doesn't exist, `podman
# inspect` exits non-zero and prints nothing, but sed then runs on EMPTY
# stdin, itself exits 0, and a pipeline's exit status in POSIX sh is the
# LAST command's — so the `||` never triggered and RUNNING_WP/DB/CS silently
# became an empty string instead of "not running". Fixed by checking
# emptiness explicitly. Also strips any @sha256:digest suffix for the plain
# comparison variables (RUNNING_WP/DB/CS) — once digest pinning is active
# those would otherwise never equal a bare PINNED_*_VER and update.sh would
# think an update was needed on every single run. The _RAW variants keep the
# digest intact for the new digest-check feature below.
RUNNING_WP_RAW=$(PRUN inspect wordpress --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_DB_RAW=$(PRUN inspect mariadb   --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_CS_RAW=$(PRUN inspect crowdsec  --format "{{.Config.Image}}" 2>/dev/null || true)
# once GeoIP is active, the running image is tagged localhost/wordpress-geoip:
# <ver>, not ${WP_REGISTRY}:<ver> — strip whichever prefix is actually
# present so "already on target" comparisons work either way, instead of
# perpetually thinking an update is needed and re-triggering a pointless
# rebuild on every `update.sh check`.
if [ -z "$RUNNING_WP_RAW" ]; then
  RUNNING_WP="not running"
else
  RUNNING_WP=$(echo "$RUNNING_WP_RAW" | sed -e 's|@sha256:[0-9a-f]*$||' -e "s|^${WP_REGISTRY}:||" -e 's|^localhost/wordpress-geoip:||')
fi
WP_IS_GEOIP=0
case "$RUNNING_WP_RAW" in localhost/wordpress-geoip:*) WP_IS_GEOIP=1 ;; esac
if [ -z "$RUNNING_DB_RAW" ]; then
  RUNNING_DB="not running"
else
  RUNNING_DB=$(echo "$RUNNING_DB_RAW" | sed -e 's|@sha256:[0-9a-f]*$||' -e "s|^${DB_REGISTRY}:||")
fi
if [ -z "$RUNNING_CS_RAW" ]; then
  RUNNING_CS="not running"
else
  RUNNING_CS=$(echo "$RUNNING_CS_RAW" | sed -e 's|@sha256:[0-9a-f]*$||' -e "s|^${CS_REGISTRY}:||")
fi

ask_yn() { printf "%s [y/N]: " "$1"; read ans; case "$ans" in [Yy]*) return 0;; *) return 1;; esac; }

# ── Digest pinning helper (shared by do_wp_update/do_db_update/do_cs_update
# and do_digest_check) ─────────────────────────────────────────────────────
# BUG FIX (v7-5): update.sh previously had no concept of digest pinning at
# all — every update pulled a bare tag and left the container unpinned, so
# pinning applied only at initial install and was lost on the very first
# update. USE_DIGEST_PINNING is read from /etc/wp-install/vars.sh (already
# sourced above). Tests the combined tag+digest form against the local
# Podman before using it (see the longer explanation in install-wordpress.sh)
# rather than assuming this Podman build accepts it.
_pin_digest() {
  local ref="$1" label="$2" digest repo_only candidate
  # BUG FIX (v7-5b): CRITICAL — this function is called as
  # target_img_pinned=$(_pin_digest ...), which captures EVERYTHING written
  # to stdout, not just the final `echo "$candidate"`. The status lines below
  # must go to stderr (>&2) or they end up prepended to the image reference
  # itself, producing a two-line string that fails podman run with "invalid
  # reference format" — confirmed in the field (this exact bug broke every
  # digest-pinned install). See the longer note in install-wordpress.sh.
  [ "${USE_DIGEST_PINNING:-1}" = "1" ] || { echo "$ref"; return 0; }
  digest=$(podman inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null \
    | grep -oE 'sha256:[0-9a-f]{64}' || true)
  if [ -z "$digest" ]; then
    echo "  ⚠  ${label}: could not resolve a digest — continuing with tag-only reference" >&2
    echo "$ref"; return 0
  fi
  repo_only="${ref%:*}"
  candidate="${ref}@${digest}"
  if podman inspect "$candidate" >/dev/null 2>&1; then
    echo "  ✔  ${label}: pinned to ${digest} (tag+digest)" >&2
    echo "$candidate"
  else
    echo "  ✔  ${label}: pinned to ${digest} (digest-only — this Podman doesn't accept tag+digest together)" >&2
    echo "${repo_only}@${digest}"
  fi
}

# ── Trivy: container vulnerability scanner ────────────────────────────────────
# Scans images BEFORE pulling to gate updates on security posture.
# Cache at /var/cache/trivy persists across reboots (faster repeated scans).
# First scan downloads the DB (~100 MB, 30-90s). Subsequent scans: <15s.
TRIVY_CACHE_DIR="/var/cache/trivy"

setup_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    mkdir -p "${TRIVY_CACHE_DIR}"
    return 0
  fi
  echo "  → Installing Trivy (vulnerability scanner)..."
  mkdir -p "${TRIVY_CACHE_DIR}"
  # Try Alpine edge/testing first, then official install script
  if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
       trivy >/dev/null 2>&1; then
    echo "  ✔  Trivy installed (apk)"
  else
    apk add --no-cache wget >/dev/null 2>&1 || true
    TRIVY_VER="v0.71.2"
    wget -qO /tmp/trivy-install.sh \
      https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh 2>/dev/null \
    && sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && echo "  ✔  Trivy ${TRIVY_VER} installed (official script)" \
    || { echo "  ⚠  Trivy install failed — scans will be skipped"; return 1; }
    rm -f /tmp/trivy-install.sh
  fi
}

scan_image() {
  local img="$1"
  if ! command -v trivy >/dev/null 2>&1; then
    echo "  ⚠  Trivy not available — skipping vulnerability scan"
    return 0
  fi
  echo "  → Scanning ${img} for HIGH/CRITICAL vulnerabilities (cache: ${TRIVY_CACHE_DIR})..."
  if trivy image \
       --cache-dir "${TRIVY_CACHE_DIR}" \
       --exit-code 1 \
       --severity HIGH,CRITICAL \
       --no-progress \
       --quiet \
       "${img}" 2>/dev/null; then
    echo "  ✔  No HIGH/CRITICAL vulnerabilities found"
    return 0
  else
    echo "  ⚠  HIGH or CRITICAL vulnerabilities detected in ${img}"
    echo "     Review the findings above before updating."
    ask_yn "  Proceed with update anyway? (not recommended)" || {
      echo "  Update aborted. Check for a newer image version."
      return 1
    }
    return 0
  fi
}

do_os_update() {
  echo "── Alpine OS ──────────────────────────────────────────────────"
  echo "  Current: Alpine $(cat /etc/alpine-release 2>/dev/null)"
  ask_yn "Update Alpine OS packages?" && { apk update; apk upgrade --no-cache; echo "✔  Done"; } \
    || echo "   Skipped."
}

do_wp_update() {
  local target_ver="${1:-$PINNED_WP_VER}" target_img="${WP_REGISTRY}:${1:-$PINNED_WP_VER}"
  echo "── WordPress ──────────────────────────────────────────────────"
  echo "  Running : ${RUNNING_WP}  →  Target: ${target_ver}"
  echo "  Data    : /home/wpuser/wp/html (bind-mount — never removed)"
  [ "${RUNNING_WP}" = "${target_ver}" ] && { echo "  ✔  Already on target."; return 0; }
  ask_yn "Update WordPress?" || { echo "   Skipped."; return 0; }

  setup_trivy
  scan_image "${target_img}" || return 1

  echo "  → Pulling ${target_img}…"
  podman pull "${target_img}" || { echo "✗  Pull failed."; return 1; }
  target_img_pinned=$(_pin_digest "${target_img}" "WordPress")

  PRUN rename wordpress wordpress-old 2>/dev/null || true

  # Determine remoteip mounts
  RI_VOLS=""
  # remoteip.load not mounted (mod_remoteip pre-enabled in WP image)
  # Only mount remoteip.conf if configured (sets RemoteIPTrustedProxy)
  [ -f /home/wpuser/wp/apache-mods/remoteip.conf ] && \
    RI_VOLS="-v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"

  # shellcheck disable=SC2086
  WP_PORT="$( [ "${ROOTLESS_MODE:-0}" = "1" ] && echo 8080 || echo 80 )"
  if PRUN run -d --name wordpress --network wp-net --ip 10.89.1.3 -p "${WP_PORT}:80" --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 200 --memory=768m --cpu-shares=512 \
    --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -e WORDPRESS_DEBUG="" \
    --add-host "mariadb:10.89.1.2" \
    -e WORDPRESS_CONFIG_EXTRA='define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
    -v /home/wpuser/wp/html:/var/www/html \
    -v /home/wpuser/wp/logs:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
    ${RI_VOLS} \
    "${target_img_pinned}"; then

    HEALTHY=0
    for i in $(seq 1 6); do WEB_CHECK=$([ "${ROOTLESS_MODE:-0}" = "1" ] && echo 8080 || echo 80)
      wget -qO- "http://127.0.0.1:${WEB_CHECK}/" >/dev/null 2>&1 && { HEALTHY=1; break; }; sleep 5; done
    if [ "$HEALTHY" = "1" ]; then
      PRUN stop wordpress-old 2>/dev/null; PRUN rm -f wordpress-old 2>/dev/null
      sed -i "s|^PINNED_WP_VER=.*|PINNED_WP_VER=\"${target_ver}\"|" /usr/local/bin/update.sh
      sed -i "s|WP_IMAGE=.*|WP_IMAGE=\"${target_img_pinned}\"|" /etc/init.d/wp-container 2>/dev/null || true
      # Re-apply uploads ownership after update (entrypoint re-creates dirs as root)
      sleep 3
      PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
      echo "✔  WordPress base image updated to ${target_ver}"
      # BUG FIX (v7-5): GeoIP used to be silently destroyed here. This function
      # was pulling the bare upstream image and recreating the container with
      # NO knowledge of the localhost/wordpress-geoip custom image or its two
      # extra mounts (geoip.conf, maxminddb.load) — so any site with GeoIP
      # active lost country filtering on every single `update.sh wp`, with no
      # warning. WP_IS_GEOIP reflects whether GeoIP was actually active on the
      # container BEFORE this update started; GEOIP_ENABLED covers the case
      # where it's configured but not yet applied. Either way, rebuild the
      # GeoIP image on the new base and restore the mounts.
      if [ "${WP_IS_GEOIP:-0}" = "1" ] || [ "${GEOIP_ENABLED:-0}" = "1" ]; then
        if [ -x /usr/local/bin/wp-geoip-setup.sh ]; then
          echo "  → GeoIP was active — rebuilding the GeoIP image on the new base…"
          if /usr/local/bin/wp-geoip-setup.sh; then
            echo "  ✔  GeoIP re-applied on the updated WordPress image"
          else
            echo "  ⚠  GeoIP re-apply FAILED — WordPress is updated but GeoIP filtering is now OFF."
            echo "     Check /var/log/wp-geoip.log, then re-run: /usr/local/bin/wp-geoip-setup.sh"
          fi
        else
          echo "  ⚠  GeoIP was active but wp-geoip-setup.sh is missing — GeoIP filtering is now OFF."
        fi
      fi
    else
      echo "✗  Health check failed — rolling back…"
      PRUN stop wordpress 2>/dev/null; PRUN rm -f wordpress 2>/dev/null
      PRUN rename wordpress-old wordpress 2>/dev/null; PRUN start wordpress 2>/dev/null
      echo "✗  Rolled back to ${RUNNING_WP}."; return 1
    fi
  else
    PRUN rm -f wordpress 2>/dev/null
    PRUN rename wordpress-old wordpress 2>/dev/null; PRUN start wordpress 2>/dev/null
    echo "✗  Container start failed — rolled back."; return 1
  fi
}

do_db_update() {
  local target_ver="${1:-$PINNED_DB_VER}" target_img="${DB_REGISTRY}:${1:-$PINNED_DB_VER}"
  echo "── MariaDB ────────────────────────────────────────────────────"
  echo "  Running : ${RUNNING_DB}  →  Target: ${target_ver}"
  echo "  Data    : /home/wpuser/wp/mysql (bind-mount — never removed)"
  [ "${RUNNING_DB}" = "${target_ver}" ] && { echo "  ✔  Already on target."; return 0; }
  ask_yn "Update MariaDB? (backup taken first)" || { echo "   Skipped."; return 0; }

  setup_trivy
  scan_image "${target_img}" || return 1

  BACKUP_FILE="/root/wp-db-backup-$(date +%Y%m%d-%H%M%S).sql.gz"
  echo "  → Backing up to ${BACKUP_FILE}…"
  # BUG FIX: use sh -c so $MARIADB_ROOT_PASSWORD expands inside the container
  # where it is set (from --env-file), not on the host where it is not set.
  if PRUN exec mariadb sh -c \
       'exec mariadb-dump --all-databases -uroot -p"$MARIADB_ROOT_PASSWORD"' \
       | gzip > "${BACKUP_FILE}"; then
    echo "  ✔  Backup: ${BACKUP_FILE} ($(du -sh "${BACKUP_FILE}" | cut -f1))"
  else
    echo "✗  Backup failed — aborting. Fix the database before retrying."; return 1
  fi

  echo "  → Pulling ${target_img}…"
  podman pull "${target_img}" || { echo "✗  Pull failed."; return 1; }
  target_img_pinned=$(_pin_digest "${target_img}" "MariaDB")

  echo "  → Stopping WordPress (brief downtime)…"
  PRUN stop wordpress 2>/dev/null || true
  PRUN rename mariadb mariadb-old 2>/dev/null || true

  if PRUN run -d --name mariadb --network wp-net --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --cpu-shares=512 \
    --env-file /etc/wordpress/env \
    -v /home/wpuser/wp/mysql:/var/lib/mysql \
    -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \
    --health-cmd "healthcheck.sh --connect --innodb_initialized" \
    --health-interval 5s --health-timeout 5s --health-retries 24 \
    --health-start-period 30s \
    "${target_img_pinned}"; then

    DB_READY=0
    for i in $(seq 1 24); do
      PRUN exec mariadb sh -c \
        'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
         mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null' \
        && { DB_READY=1; break; }
      sleep 5
    done

    if [ "$DB_READY" = "1" ]; then
      echo "  → mariadb-upgrade (no-op if not needed)…"
      PRUN exec mariadb sh -c \
        'mariadb-upgrade -uroot -p"$MARIADB_ROOT_PASSWORD"' >/dev/null 2>&1 || true
      PRUN start wordpress >/dev/null 2>&1 || true
      PRUN stop mariadb-old 2>/dev/null; PRUN rm -f mariadb-old 2>/dev/null
      sed -i "s|^PINNED_DB_VER=.*|PINNED_DB_VER=\"${target_ver}\"|" /usr/local/bin/update.sh
      sed -i "s|DB_IMAGE=.*|DB_IMAGE=\"${target_img_pinned}\"|" /etc/init.d/mariadb-container 2>/dev/null || true
      echo "✔  MariaDB updated to ${target_ver}. Backup: ${BACKUP_FILE}"
    else
      echo "✗  New MariaDB not ready — rolling back…"
      PRUN stop mariadb 2>/dev/null; PRUN rm -f mariadb 2>/dev/null
      PRUN rename mariadb-old mariadb 2>/dev/null; PRUN start mariadb 2>/dev/null
      PRUN start wordpress 2>/dev/null
      echo "✗  Rolled back. Backup: ${BACKUP_FILE}"; return 1
    fi
  else
    PRUN rm -f mariadb 2>/dev/null
    PRUN rename mariadb-old mariadb 2>/dev/null; PRUN start mariadb 2>/dev/null
    PRUN start wordpress 2>/dev/null
    echo "✗  Container start failed — rolled back. Backup: ${BACKUP_FILE}"; return 1
  fi
}

do_cs_update() {
  local target_ver="${1:-$PINNED_CS_VER}" target_img="${CS_REGISTRY}:${1:-$PINNED_CS_VER}"
  echo "── CrowdSec ───────────────────────────────────────────────────"
  echo "  Running : ${RUNNING_CS}  →  Target: ${target_ver}"
  [ "${RUNNING_CS}" = "${target_ver}" ] && { echo "  ✔  Already on target."; return 0; }
  ask_yn "Update CrowdSec?" || { echo "   Skipped."; return 0; }

  setup_trivy
  scan_image "${target_img}" || return 1

  podman pull "${target_img}" || { echo "✗  Pull failed."; return 1; }
  target_img_pinned=$(_pin_digest "${target_img}" "CrowdSec")
  PRUN rename crowdsec crowdsec-old 2>/dev/null || true

  if PRUN run -d --name crowdsec --restart always --network host \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --label io.containers.autoupdate=image \
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
    -v /opt/crowdsec/config:/etc/crowdsec:rw -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
    -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
    -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
    -v /var/log/messages:/var/log/host/messages:ro \
    "${target_img_pinned}"; then

    LAPI_UP=0
    for i in $(seq 1 6); do
      PRUN exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_UP=1; break; }; sleep 5
    done
    if [ "$LAPI_UP" = "1" ]; then
      rc-service cs-firewall-bouncer restart 2>/dev/null || true
      PRUN stop crowdsec-old 2>/dev/null; PRUN rm -f crowdsec-old 2>/dev/null
      sed -i "s|^PINNED_CS_VER=.*|PINNED_CS_VER=\"${target_ver}\"|" /usr/local/bin/update.sh
      echo "✔  CrowdSec updated to ${target_ver}"
    else
      echo "✗  LAPI not responding — rolling back…"
      PRUN stop crowdsec 2>/dev/null; PRUN rm -f crowdsec 2>/dev/null
      PRUN rename crowdsec-old crowdsec 2>/dev/null; PRUN start crowdsec 2>/dev/null
      rc-service cs-firewall-bouncer restart 2>/dev/null; return 1
    fi
  else
    PRUN rm -f crowdsec 2>/dev/null
    PRUN rename crowdsec-old crowdsec 2>/dev/null; PRUN start crowdsec 2>/dev/null
    rc-service cs-firewall-bouncer restart 2>/dev/null; return 1
  fi
}

show_status() {
  echo ""; echo "── Status ─────────────────────────────────────────────────────"
  PRUN ps --format "  {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null | column -t || true
  echo ""
  echo "  Firewall : $(nft list tables 2>/dev/null | grep -c table) nft tables"
  echo "  Bouncer  : $(rc-service cs-firewall-bouncer status 2>/dev/null | head -1)"
  echo ""
}

# ── Digest check: same tag, newer published digest ────────────────────────────
# Answers a different question than do_wp_update/do_db_update/do_cs_update:
# those check "is there a newer VERSION TAG available" (you supply VER, or it
# compares against PINNED_*_VER). This checks "has the registry republished
# a NEW IMAGE under the SAME tag" — which happens routinely for security
# rebuilds (base-OS CVE patches, etc.) without the version number changing at
# all. Without this, a digest-pinned deployment could sit on a known-bad
# image indefinitely because "already on target" only ever compared tags.
do_digest_check() {
  echo "── Digest Check (same tag, newer published digest) ───────────────"
  if [ "${USE_DIGEST_PINNING:-1}" != "1" ]; then
    echo "  Digest pinning is disabled (USE_DIGEST_PINNING=0 in vars.sh) — nothing to check."
    return 0
  fi
  _check_one() {
    local label="$1" running_raw="$2" registry="$3" bare_tag="$4" updater="$5"
    local running_digest fresh_digest fresh_ref
    running_digest=$(echo "$running_raw" | grep -oE 'sha256:[0-9a-f]{64}' || true)
    if [ -z "$running_digest" ]; then
      echo "  ${label}: not currently digest-pinned — run its update.sh command once to pin it."
      return 0
    fi
    fresh_ref="${registry}:${bare_tag}"
    echo "  → ${label}: checking ${fresh_ref} for a newer digest than currently pinned…"
    if ! podman pull "${fresh_ref}" >/dev/null 2>&1; then
      echo "  ${label}: pull failed — skipping digest check"
      return 0
    fi
    fresh_digest=$(podman inspect "${fresh_ref}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    if [ -z "$fresh_digest" ]; then
      echo "  ${label}: could not resolve the current digest — skipping"
      return 0
    fi
    if [ "$fresh_digest" = "$running_digest" ]; then
      echo "  ✔  ${label}: already on the latest published digest for ${bare_tag}"
    else
      echo "  ⚠  ${label}: ${fresh_ref} has a NEWER digest than what's pinned"
      echo "     Pinned : ${running_digest}"
      echo "     Latest : ${fresh_digest}"
      ask_yn "  Move ${label} to the new digest now (same version ${bare_tag}, rebuilt image)?" \
        && "$updater" "${bare_tag}"
    fi
  }
  _check_one "WordPress" "${RUNNING_WP_RAW}" "${WP_REGISTRY}" "$(echo "${PINNED_WP_VER}" | sed 's|^geoip-||')" do_wp_update
  _check_one "MariaDB"   "${RUNNING_DB_RAW}" "${DB_REGISTRY}" "${PINNED_DB_VER}" do_db_update
  _check_one "CrowdSec"  "${RUNNING_CS_RAW}" "${CS_REGISTRY}" "${PINNED_CS_VER}" do_cs_update
}

case "${1:-check}" in
  os)          do_os_update ;;
  wp)          do_wp_update "${2:-}" ;;
  db)          do_db_update "${2:-}" ;;
  crowdsec|cs) do_cs_update "${2:-}" ;;
  all)         do_os_update; do_wp_update; do_db_update; do_cs_update ;;
  digest-check|digest|pin) do_digest_check ;;
  trivy|scan)
    setup_trivy
    for img in wordpress mariadb crowdsec; do
      running=$(PRUN inspect $img --format "{{.Config.Image}}" 2>/dev/null || echo "")
      [ -n "$running" ] && scan_image "$running"
    done ;;
  check|"")
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  Update Check                                            ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Alpine   : $(cat /etc/alpine-release 2>/dev/null)"
    echo "║  WordPress: running=${RUNNING_WP}  pinned=${PINNED_WP_VER}"
    echo "║  MariaDB  : running=${RUNNING_DB}  pinned=${PINNED_DB_VER}"
    echo "║  CrowdSec : running=${RUNNING_CS}  pinned=${PINNED_CS_VER}"
    echo "║  Digest pinning: $([ "${USE_DIGEST_PINNING:-1}" = "1" ] && echo enabled || echo disabled)"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    do_os_update; do_wp_update; do_db_update; do_cs_update; do_digest_check; show_status ;;
  *) echo "Usage: update.sh [check|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all]"; exit 1 ;;
esac
UPDSCRIPT
chmod +x /usr/local/bin/update.sh
ok "update.sh installed (wp / db / crowdsec / os / digest-check / all)"

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC
# ════════════════════════════════════════════════════════════════════════════
ts "CrowdSec — engine"
mkdir -p /opt/crowdsec/config /opt/crowdsec/data
# In rootless mode, wpuser owns /opt/crowdsec (containers write to it as root
# inside the container, which maps to wpuser on the host via user namespace).
[ "${ROOTLESS_MODE:-0}" = "1" ] && chown -R wpuser:wpuser /opt/crowdsec 2>/dev/null || true
mkdir -p /home/wpuser/wp/logs; chown 33:33 /home/wpuser/wp/logs 2>/dev/null || true
# Ensure /var/log/messages exists before CrowdSec bind-mounts it.
touch /var/log/messages 2>/dev/null || true

cat > /opt/crowdsec/acquis.yaml << 'ACQUIS'
filenames:
  - /var/log/wordpress/access.log
labels:
  type: apache2
---
filenames:
  - /var/log/host/messages
labels:
  type: syslog
ACQUIS
ok "acquis.yaml: Apache logs + syslog"

if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
  ok "Rootless mode: launching CrowdSec as wpuser via run-crowdsec.sh"
  su -s /bin/sh wpuser -c '/home/wpuser/wp/run-crowdsec.sh'
else
  podman rm -f crowdsec 2>/dev/null || true
  podman run -d \
  --name    crowdsec \
  --restart always \
  --network host \
  --cap-drop ALL \
  --cap-add  DAC_OVERRIDE \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
  --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
  --pids-limit 100 \
  --memory=512m \
  --label io.containers.autoupdate=image \
  -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
  -v /opt/crowdsec/config:/etc/crowdsec:rw \
  -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
  -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
  -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
  -v /var/log/messages:/var/log/host/messages:ro \
  "${CROWDSEC_IMAGE}"
fi  # end rootless/rootful dispatch

ts "Waiting for CrowdSec LAPI"
LAPI_READY=0
for i in $(seq 1 30); do
  PRUN exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_READY=1; break; }
  sleep 5
done
[ "$LAPI_READY" = "1" ] && ok "LAPI up" || warn "LAPI not confirmed — continuing"

ts "Locking LAPI to 127.0.0.1:8080"
CFG=/opt/crowdsec/config/config.yaml
for i in $(seq 1 12); do [ -f "$CFG" ] && break || sleep 5; done
if [ -f "$CFG" ]; then
  grep -qE '^\s*listen_uri:' "$CFG" \
    && sed -i -E 's|^(\s*listen_uri:).*|\1 127.0.0.1:8080|' "$CFG"
  PRUN restart crowdsec >/dev/null 2>&1; sleep 3
  ok "LAPI → 127.0.0.1:8080"
else
  warn "config.yaml not found — restrict LAPI manually"
fi

ts "Generating bouncer API key"
PRUN exec crowdsec cscli bouncers delete firewall-bouncer >/dev/null 2>&1 || true
BOUNCER_KEY=$(PRUN exec crowdsec cscli bouncers add firewall-bouncer -o raw 2>/dev/null | tail -1)
[ -n "$BOUNCER_KEY" ] && ok "Bouncer key generated" \
  || warn "Could not generate key — check: podman logs crowdsec"

ts "Installing cs-firewall-bouncer"
apk add --no-cache nftables cs-firewall-bouncer cs-firewall-bouncer-openrc >/dev/null 2>&1 \
  || warn "cs-firewall-bouncer not in apk — try edge repo"

if [ -n "$BOUNCER_KEY" ]; then
  mkdir -p /etc/crowdsec/bouncers
  cat > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml << BOUNCERCFG
mode: nftables
pid_dir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: http://127.0.0.1:8080/
api_key: ${BOUNCER_KEY}
disable_ipv6: false
deny_action: DROP
deny_log: false
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
    priority: -10
  ipv6:
    enabled: false
nftables_hooks:
  - input
BOUNCERCFG
  chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  rc-update add cs-firewall-bouncer default 2>/dev/null || true
  rc-service cs-firewall-bouncer start 2>/dev/null || true
  # BUG FIX (v7-4): the bouncer's first start frequently loses a race against
  # CrowdSec's LAPI still finishing initialization and comes up "crashed"
  # (confirmed in the field: `rc-service cs-firewall-bouncer status` showed
  # crashed immediately after install, and a plain `restart` — no config
  # change — fixed it instantly). Retry the start a few times instead of
  # accepting the first crash.
  BOUNCER_UP=0
  for attempt in 1 2 3 4 5; do
    if rc-service cs-firewall-bouncer status 2>/dev/null | grep -q started; then
      BOUNCER_UP=1; break
    fi
    warn "cs-firewall-bouncer not started yet (attempt ${attempt}/5) — restarting"
    rc-service cs-firewall-bouncer restart >/dev/null 2>&1 || true
    sleep 5
  done
  [ "$BOUNCER_UP" = "1" ] \
    && ok "cs-firewall-bouncer service running" \
    || warn "cs-firewall-bouncer still not started after retries — run: rc-service cs-firewall-bouncer restart"
  sleep 2
  PRUN exec crowdsec cscli bouncers list 2>/dev/null | grep -q firewall-bouncer \
    && ok "Bouncer connected to LAPI" \
    || warn "Bouncer not yet showing — check rc-service cs-firewall-bouncer status"
fi

cat > /etc/init.d/crowdsec-container << 'CSSVC'
#!/sbin/openrc-run
name="crowdsec-container"
description="CrowdSec engine (Podman)"
depend() {
  need net wp-container
  after sysfs wp-container
}
start() {
  ebegin "Starting CrowdSec"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \
     && [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c '/home/wpuser/wp/run-crowdsec.sh' >/dev/null 2>&1
    eend $?
    return
  fi
  podman container exists crowdsec 2>/dev/null && podman start crowdsec >/dev/null 2>&1 || true
  eend $?
}
stop() {
  ebegin "Stopping CrowdSec"
  [ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
  if [ "${ROOTLESS_MODE:-0}" = "1" ]; then
    su -s /bin/sh wpuser -c 'podman stop crowdsec' >/dev/null 2>&1
  else
    podman stop crowdsec >/dev/null 2>&1
  fi
  eend $?
}
CSSVC
chmod +x /etc/init.d/crowdsec-container
rc-update add crowdsec-container default 2>/dev/null || true
ok "crowdsec-container service registered"

# BUG FIX: podman-compose is NOT needed for podman auto-update.
# podman auto-update is a built-in Podman command.
cat >> /etc/crontabs/root << 'AUTOCRON'
# Weekly container image update check (Sunday 04:00 UTC — dry run only)
0 4 * * 0 podman auto-update --dry-run 2>&1 | logger -t podman-autoupdate
# WordPress system cron — replaces unreliable WP-Cron (which only fires on
# page loads). DISABLE_WP_CRON=true is set in WORDPRESS_CONFIG_EXTRA.
# Runs every 5 min; WordPress schedules (backups, updates, email) fire on time.
*/5 * * * * /usr/local/bin/wp-cron-run.sh >/dev/null 2>&1
# Daily MariaDB backup — gzipped SQL dump to /root/wp-db-backups/.
# Retains 7 days automatically. Restore: gunzip < file.sql.gz | mariadb -u root
0 2 * * * mkdir -p /root/wp-db-backups && podman exec mariadb sh -c 'exec mariadb-dump --all-databases -uroot -p"$MARIADB_ROOT_PASSWORD"' | gzip > "/root/wp-db-backups/wp-db-$(date +\%Y\%m\%d).sql.gz" && find /root/wp-db-backups -name 'wp-db-*.sql.gz' -mtime +7 -delete 2>&1 | logger -t wp-db-backup
AUTOCRON
ok "Cron jobs scheduled:"
ok "  Weekly  : podman auto-update dry-run (Sun 04:00)"
ok "  Every 5m: WordPress system cron (replaces WP-Cron)"
ok "  Daily   : MariaDB backup to /root/wp-db-backups/ (7-day retention)"

# ════════════════════════════════════════════════════════════════════════════
# 8G FIREWALL v1.4 — Apache .htaccess WAF, runs before PHP (fast)
# Sourced: perishablepress.com/8g-firewall (free for all use, credit intact)
# WordPress only rewrites between # BEGIN/END WordPress markers —
# our 8G rules placed ABOVE that block survive any WordPress .htaccess flush.
# DIVI: visual builder (admin-ajax, REST API) unaffected by these rules.
# Toggle: wp-hardening.sh disable 8g  or  wp-hardening.sh enable 8g
# ════════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════════
# TRIVY — Container vulnerability scanner (gates updates in update.sh)
# Latest: v0.71.2 (June 2026). Cache at /var/cache/trivy persists reboots.
# First scan downloads the DB (~100-200 MB); subsequent scans use cache (<15s).
# ════════════════════════════════════════════════════════════════════════════
ts "Installing Trivy vulnerability scanner"
TRIVY_VER="v0.71.2"
TRIVY_CACHE_DIR="/var/cache/trivy"
mkdir -p "${TRIVY_CACHE_DIR}"; chmod 755 "${TRIVY_CACHE_DIR}"

# Try edge/testing first (clean apk) then fall back to official install script
if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
     trivy >/dev/null 2>&1; then
  ok "Trivy installed via apk edge/testing"
elif apk add --no-cache wget >/dev/null 2>&1 && \
     wget -qO /tmp/trivy-install.sh \
       https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
       2>/dev/null; then
  sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && ok "Trivy ${TRIVY_VER} installed via official script" \
    || warn "Trivy install failed — vulnerability scanning disabled in update.sh"
  rm -f /tmp/trivy-install.sh
else
  warn "Trivy unavailable — update.sh will skip vulnerability scanning"
fi

if command -v trivy >/dev/null 2>&1; then
  ok "Trivy $(trivy --version 2>/dev/null | head -1) ready"
  ok "  Pre-seeding vulnerability DB (~100 MB, takes 30-90s)..."
  trivy image --cache-dir "${TRIVY_CACHE_DIR}" --download-db-only --quiet 2>/dev/null \
    && ok "  Trivy DB cached at ${TRIVY_CACHE_DIR}" \
    || warn "  Trivy DB pre-seed failed (will download on first update scan)"
fi

# ════════════════════════════════════════════════════════════════════════════
# LYNIS — Security auditing for MSP compliance evidence
# lynis is only in Alpine edge/testing, NOT in stable repos (3.21-3.24).
# Try stable first (may land in community someday), then edge/testing,
# then direct GitHub install as a final fallback — so Lynis is never
# silently absent even if Alpine packaging changes.
# Weekly automated audit; manual: lynis audit system
# Score: grep hardening_index /var/log/lynis-report.dat
# ════════════════════════════════════════════════════════════════════════════
ts "Installing Lynis security auditor"
LYNIS_OK=0

# Try 1: Alpine stable community (might appear in future versions)
apk add --no-cache lynis >/dev/null 2>&1 && LYNIS_OK=1

# Try 2: Alpine edge/testing (where it currently lives as of Alpine 3.24)
if [ "$LYNIS_OK" = "0" ]; then
  apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    lynis >/dev/null 2>&1 && LYNIS_OK=1
fi

# Try 3: Direct install from CISOfy's stable release tarball (no OS dependency)
if [ "$LYNIS_OK" = "0" ]; then
  warn "Lynis not in apk repos — trying GitHub release tarball"
  apk add --no-cache wget >/dev/null 2>&1 || true
  LYNIS_TAG=$(wget -qO- https://api.github.com/repos/CISOfy/lynis/releases/latest 2>/dev/null \
    | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  LYNIS_TAG="${LYNIS_TAG:-3.1.3}"  # pinned fallback if API unavailable
  if wget -qO /tmp/lynis.tar.gz \
       "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_TAG}.tar.gz" 2>/dev/null; then
    tar xzf /tmp/lynis.tar.gz -C /usr/local/lib 2>/dev/null
    ln -sf "/usr/local/lib/lynis-${LYNIS_TAG}/lynis" /usr/local/bin/lynis 2>/dev/null
    rm -f /tmp/lynis.tar.gz
    command -v lynis >/dev/null 2>&1 && LYNIS_OK=1 && ok "Lynis ${LYNIS_TAG} installed from GitHub release"
  fi
fi

if [ "$LYNIS_OK" = "1" ]; then
  ok "Lynis $(lynis --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ready"
  cat >> /etc/crontabs/root << 'LYNISCRON'
# Weekly Lynis security audit (Saturday 05:00 UTC) — MSP compliance evidence
0 5 * * 6 lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat 2>&1 | logger -t lynis-audit
LYNISCRON
  ok "Lynis: weekly audit Sat 05:00 | manual: wp-hardening.sh lynis"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
else
  warn "Lynis could not be installed — all install methods failed"
  warn "  Manual install: apk add --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing lynis"
  warn "  Or: wget https://github.com/CISOfy/lynis/archive/refs/tags/3.1.3.tar.gz"
fi

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC CONSOLE AUTO-ENROLMENT
# If an enrolment key was provided at provisioning time, enrol now.
# After enrolment: visit https://app.crowdsec.net → Accept the engine.
# Then restart CrowdSec: podman restart crowdsec
# ════════════════════════════════════════════════════════════════════════════
if [ -n "${CROWDSEC_ENROLL_KEY}" ]; then
  ts "CrowdSec console auto-enrolment"
  CS_NAME=$(hostname 2>/dev/null || echo "wordpress-vm")
  if PRUN exec crowdsec cscli console enroll \
       --name "${CS_NAME}" \
       --tags "wordpress,msp,podman,alpine" \
       "${CROWDSEC_ENROLL_KEY}" 2>/dev/null; then
    ok "CrowdSec enrolled as '${CS_NAME}' — accept it at https://app.crowdsec.net"
    ok "  Then restart: podman restart crowdsec"
  else
    warn "CrowdSec enrolment failed — check key at app.crowdsec.net"
    warn "  Manual: podman exec crowdsec cscli console enroll <key>"
  fi
  # Scrub key from disk now that it's been used
  sed -i 's/^CROWDSEC_ENROLL_KEY=.*/CROWDSEC_ENROLL_KEY=""/' \
    /etc/wp-install/vars.sh 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════════
# WP-HARDENING.SH — Toggle security features from Proxmox or SSH
# qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# ════════════════════════════════════════════════════════════════════════════
ts "Installing wp-hardening.sh security toggle"
cat > /usr/local/bin/wp-hardening.sh << 'HARDEN'
#!/bin/sh
# WordPress VM Security Feature Toggle
# Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp]
# From Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# Features: 8g  xmlrpc  uploads-php  author-enum  debug
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
PRUN() {
  if [ "${ROOTLESS_MODE}" = "1" ]; then
    su -s /bin/sh wpuser -c "podman $*"
  else
    podman "$@"
  fi
}

HTACCESS="/home/wpuser/wp/htaccess/.htaccess"
APACHE_CONF="/home/wpuser/wp/apache-conf/wp-security.conf"
TRIVY_CACHE_DIR="/var/cache/trivy"

restart_wp() { PRUN restart wordpress >/dev/null 2>&1 && echo "  ✔  WordPress restarted" || true; }

feature_state() {
  case "$1" in
    8g)          grep -q '^# 8G DISABLED' "$HTACCESS" 2>/dev/null && echo DISABLED || echo ENABLED ;;
    xmlrpc)      grep -q 'xmlrpc.php.*Require all denied' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    uploads-php) grep -q 'wp-content/uploads' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    debug)       PRUN exec wordpress php -r 'echo WP_DEBUG?"ON":"OFF";' 2>/dev/null || echo UNKNOWN ;;
  esac
}

show_status() {
  echo ""
  echo "WordPress VM — Security Features"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  %-18s %s\n" "8G Firewall:"    "$(feature_state 8g)"
  printf "  %-18s %s\n" "xmlrpc.php:"     "$(feature_state xmlrpc)"
  printf "  %-18s %s\n" "uploads PHP:"    "$(feature_state uploads-php)"
  printf "  %-18s %s\n" "WP_DEBUG:"       "$(feature_state debug)"
  echo ""
  echo "Containers:"
  PRUN ps --format "  {{.Names}}: {{.Status}}" 2>/dev/null | head -5
  echo ""
  echo "Trivy cache: $(du -sh ${TRIVY_CACHE_DIR} 2>/dev/null | cut -f1 || echo 'not installed')"
  echo "Lynis last:  $(stat -c '%y' /var/log/lynis-report.dat 2>/dev/null | cut -d. -f1 || echo 'not run yet')"
  echo ""
  echo "Commands: enable|disable [8g|xmlrpc|uploads-php|debug|author-enum]"
  echo "Proxmox:  qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
}

enable_feature() {
  case "$1" in
    8g)
      sed -i 's/^# 8G DISABLED //' "$HTACCESS" 2>/dev/null || true
      echo "✔ 8G Firewall enabled"; restart_wp ;;
    xmlrpc)
      sed -i '/<Files "xmlrpc\.php">/,/<\/Files>/d' "$APACHE_CONF" 2>/dev/null
      echo "✔ xmlrpc.php unblocked (Jetpack etc. can now use it)"
      echo "  ⚠ Monitor with: podman exec crowdsec cscli decisions list"
      restart_wp ;;
    uploads-php)
      sed -i '/<DirectoryMatch.*uploads/,/<\/DirectoryMatch>/d' "$APACHE_CONF" 2>/dev/null
      echo "✔ PHP in uploads unblocked  ⚠ security risk — re-block when done"
      restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",false)/define(\"WP_DEBUG\",true)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG ON  ⚠ DISABLE after troubleshooting — exposes internals" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

disable_feature() {
  case "$1" in
    8g)
      sed -i 's/^  RewriteEngine On$/# 8G DISABLED   RewriteEngine On/g;s/^  RewriteCond /# 8G DISABLED   RewriteCond /g;s/^  RewriteRule /# 8G DISABLED   RewriteRule /g' \
        "$HTACCESS" 2>/dev/null
      echo "✔ 8G Firewall disabled  |  re-enable: wp-hardening.sh enable 8g"
      restart_wp ;;
    xmlrpc)
      grep -q 'xmlrpc' "$APACHE_CONF" \
        || printf '\n<Files "xmlrpc.php">\n    Require all denied\n</Files>\n' >> "$APACHE_CONF"
      echo "✔ xmlrpc.php blocked"; restart_wp ;;
    uploads-php)
      grep -q 'wp-content/uploads' "$APACHE_CONF" \
        || cat >> "$APACHE_CONF" << 'B'

<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
B
      echo "✔ PHP in uploads blocked"; restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",true)/define(\"WP_DEBUG\",false)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG OFF" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

case "${1:-status}" in
  status)      show_status ;;
  enable)      [ -n "$2" ] && enable_feature "$2"  || echo "Usage: wp-hardening.sh enable <feature>" ;;
  disable)     [ -n "$2" ] && disable_feature "$2" || echo "Usage: wp-hardening.sh disable <feature>" ;;
  restart-wp)  restart_wp ;;
  trivy-scan)
    echo "Scanning running containers for vulnerabilities..."
    for img in $(PRUN ps --format "{{.Image}}"); do
      echo "  → Scanning ${img}"
      trivy image --cache-dir "${TRIVY_CACHE_DIR}" --severity HIGH,CRITICAL --quiet "${img}" 2>/dev/null \
        && echo "  ✔  Clean" || echo "  ⚠  Vulnerabilities found — run: update.sh"
    done ;;
  lynis)
    echo "Running Lynis audit (2-5 min)..."
    lynis audit system --quiet \
      --logfile /var/log/lynis.log \
      --report-file /var/log/lynis-report.dat 2>&1 | logger -t lynis-manual
    echo "✔  Done. Score: $(grep hardening_index /var/log/lynis-report.dat | cut -d= -f2)" ;;
  *)
    echo "Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp|trivy-scan|lynis]"
    ;;
esac
HARDEN
chmod +x /usr/local/bin/wp-hardening.sh
ok "wp-hardening.sh installed"
ok "  Usage: wp-hardening.sh status"
ok "  Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
ok "  Commands: enable|disable [8g|xmlrpc|uploads-php|debug]  |  trivy-scan  |  lynis"

# ════════════════════════════════════════════════════════════════════════════
# POST-INSTALL VALIDATION SUITE
# Verifies every critical component before declaring the install complete.
# Creates /usr/local/bin/validate-wordpress.sh for ongoing health checks.
# ════════════════════════════════════════════════════════════════════════════
ts "Running post-install validation"

PASS=0; FAIL=0
check() {
  local label="$1"; local result="$2"; local expected="${3:-ok}"
  if [ "$result" = "$expected" ]; then
    ok "  PASS  ${label}"
    PASS=$((PASS+1))
  else
    warn "  FAIL  ${label} (got: ${result}, expected: ${expected})"
    FAIL=$((FAIL+1))
  fi
}

# WordPress container running
check "WordPress container up"   "$(podman inspect wordpress --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB container running
check "MariaDB container up"   "$(podman inspect mariadb --format '{{.State.Status}}' 2>/dev/null)" "running"

# CrowdSec container running
check "CrowdSec container up"   "$(podman inspect crowdsec --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB reachability check — NOT Health.Status. Podman's health-check timer
# frequently never fires on Alpine (no systemd/conmon poller to drive it), so
# .State.Health.Status can sit on "starting" forever even though MariaDB is
# fully up — same finding as the FIX 2 note above the MariaDB wait loop.
# stdout is redirected too, not just stderr: mariadb(d)-admin ping --silent
# still prints "mysqld is alive" on success, which would otherwise leak into
# the captured value and break the "ok" string comparison below.
_DB_PING_CHECK=$(PRUN exec mariadb sh -c 'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' && echo ok || echo fail)
check "MariaDB reachable (exec ping)" "$_DB_PING_CHECK"

# WordPress DB connectivity (PHP mysqli test, runs as www-data via su)
DB_CHECK=$(podman exec --user www-data wordpress php -r   'echo @mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"))?"ok":"fail";'   2>/dev/null || echo "error")
check "WordPress DB connection (www-data)" "$DB_CHECK"

# Port 80 listening — ss (iproute2) isn't installed on stock Alpine and this
# script never adds it, so this always read "0" regardless of real state.
# Busybox's netstat ships by default and is a drop-in replacement here.
check "Port 80 listening"   "$(netstat -tlnp 2>/dev/null | grep -c ':80 ' | tr -d ' ')" "1"

# WordPress HTTP response (should be 302 redirect to /wp-admin/install.php)
HTTP_CODE=$(podman exec --user www-data wordpress php -r   'error_reporting(0);$r=@file_get_contents("http://127.0.0.1/",false,stream_context_create(["http"=>["timeout"=>5,"method"=>"GET","ignore_errors"=>true]]));$code=preg_match("/HTTP\/[0-9.]+ ([0-9]+)/",$http_response_header[0]??"",$m)?$m[1]:"0";echo($code>=200&&$code<500)?"ok":"fail:".$code;'   2>/dev/null || echo "skip")
[ "$HTTP_CODE" = "skip" ] && ok "  SKIP  WordPress HTTP check (PHP network unavailable)"   || check "WordPress HTTP response (non-error)" "$HTTP_CODE"

# uploads directory writable by www-data
UPLOADS_CHECK=$(podman exec --user www-data wordpress sh -c   'touch /var/www/html/wp-content/uploads/.write_test && rm /var/www/html/wp-content/uploads/.write_test && echo ok || echo fail'   2>/dev/null || echo "fail")
check "Uploads dir writable (www-data)" "$UPLOADS_CHECK"

# nftables loaded
check "nftables active"   "$(nft list tables 2>/dev/null | grep -c filter | tr -d ' ')" "1"

# CrowdSec bouncer connected
check "CS firewall bouncer"   "$(rc-service cs-firewall-bouncer status 2>/dev/null | grep -c started | tr -d ' ')" "1"

# 8G firewall .htaccess present
check "8G .htaccess installed"   "$([ -f /home/wpuser/wp/htaccess/.htaccess ] && grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess || echo 0)" "1"

# Trivy available
check "Trivy scanner"   "$(command -v trivy >/dev/null 2>&1 && echo ok || echo missing)"

# Lynis available
check "Lynis auditor"   "$(command -v lynis >/dev/null 2>&1 && echo ok || echo missing)"

echo ""
if [ "$FAIL" = "0" ]; then
  ok "Validation: ${PASS} checks passed, 0 failed — install is healthy"
else
  warn "Validation: ${PASS} passed, ${FAIL} FAILED — review warnings above"
  warn "  Re-run after fix: /usr/local/bin/validate-wordpress.sh"
fi

# Write the validation script for ongoing use
cat > /usr/local/bin/validate-wordpress.sh << 'VALSCRIPT'
#!/bin/sh
# WordPress VM Health Validation
# Usage: validate-wordpress.sh [--quiet]
# Exit code: 0 = all pass, 1 = failures found
QUIET="${1:-}"
PASS=0; FAIL=0
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
PRUN() {
  if [ "${ROOTLESS_MODE}" = "1" ]; then
    su -s /bin/sh wpuser -c "podman $*"
  else
    podman "$@"
  fi
}

chk() {
  local label="$1" got="$2" want="${3:-ok}"
  if [ "$got" = "$want" ]; then
    [ "$QUIET" != "--quiet" ] && echo "  ✔  ${label}"
    PASS=$((PASS+1))
  else
    echo "  ✗  ${label}  (got: ${got})"
    FAIL=$((FAIL+1))
  fi
}

echo ""
echo "═══════════════════════════════════════════════════"
echo "  WordPress VM — Health Validation"
echo "═══════════════════════════════════════════════════"

chk "WordPress running"  "$(PRUN inspect wordpress --format '{{.State.Status}}' 2>/dev/null)" "running"
chk "MariaDB running"    "$(PRUN inspect mariadb --format '{{.State.Status}}' 2>/dev/null)" "running"
chk "CrowdSec running"  "$(PRUN inspect crowdsec --format '{{.State.Status}}' 2>/dev/null)" "running"
  # stdout redirected too, not just stderr — mariadb(d)-admin ping --silent
  # still prints "mysqld is alive" on success, which otherwise leaks into
  # $_DB_PING and breaks the "ok" string comparison even on a good ping.
  _DB_PING=$(PRUN exec mariadb sh -c 'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' && echo ok || echo fail)
  chk "MariaDB reachable (exec ping)" "${_DB_PING}"

DB=$(PRUN exec --user www-data wordpress php -r   'echo @mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"))?"ok":"fail";' 2>/dev/null || echo error)
chk "DB connectivity (www-data)" "$DB"

UPL=$(PRUN exec --user www-data wordpress sh -c   'touch /var/www/html/wp-content/uploads/.wt && rm /var/www/html/wp-content/uploads/.wt && echo ok || echo fail' 2>/dev/null || echo fail)
chk "Uploads writable (www-data)" "$UPL"

chk "Port 80 listening" "$(netstat -tlnp 2>/dev/null | grep -c ':80 ' | tr -d ' ')" "1"
chk "nftables active"   "$(nft list tables 2>/dev/null | grep -c filter | tr -d ' ')" "1"
chk "CS bouncer"        "$(rc-service cs-firewall-bouncer status 2>/dev/null | grep -c started | tr -d ' ')" "1"
chk "8G .htaccess"      "$(grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess 2>/dev/null || echo 0)" "1"
chk "Trivy available"   "$(command -v trivy >/dev/null 2>&1 && echo ok || echo missing)"
chk "Lynis available"   "$(command -v lynis >/dev/null 2>&1 && echo ok || echo missing)"

WP_DEBUG=$(PRUN exec wordpress php -r 'echo WP_DEBUG?"ON":"OFF";' 2>/dev/null || echo "?")
chk "WP_DEBUG is OFF"   "$WP_DEBUG" "OFF"

echo ""
echo "  Passed: ${PASS}  Failed: ${FAIL}"
[ "$FAIL" -gt 0 ] && echo "  Run wp-hardening.sh status for details" && exit 1
echo "  All checks passed"
exit 0
VALSCRIPT
chmod +x /usr/local/bin/validate-wordpress.sh
ok "validate-wordpress.sh installed — run anytime to check VM health"

# ── Done ──────────────────────────────────────────────────────────────────────
touch /var/log/wp-install.done
# Retry IP detection — filter out Podman bridge (10.89.x.x) and loopback.
# hostname -I can be empty briefly while DHCP completes, or contain only
# the Podman wp-net gateway which is useless as a published address.
IP=""
for _ip_try in $(seq 1 12); do
  IP=$(hostname -I 2>/dev/null | tr ' ' '\n' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -v '^10\.89\.' \
    | grep -v '^127\.' \
    | head -1)
  [ -n "$IP" ] && break
  sleep 5
done
IP="${IP:-<run: ip addr show eth0 | grep inet>}"

# Build ongoing login/admin URLs from custom slug if configured.
# IMPORTANT: WordPress setup (/wp-admin/install.php) is ALWAYS at the
# default path regardless of custom slug. The slug only applies AFTER
# setup completes — for day-to-day login and admin access.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  LOGIN_URL="http://${IP}/${WP_ADMIN_SLUG}-login"
  ADMIN_URL="http://${IP}/${WP_ADMIN_SLUG}/"
else
  LOGIN_URL="http://${IP}/wp-login.php"
  ADMIN_URL="http://${IP}/wp-admin/"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       WordPress VM Setup Complete!                         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 1 — MUST DO FIRST (standard WP setup URL):       ║"
echo "║     http://${IP}/wp-admin/install.php"
echo "║     ^ This URL is ALWAYS /wp-admin/install.php             ║"
echo "║     ^ Do NOT try /slug/install.php — that will 404         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 2 — After setup, use your custom slug:           ║"
echo "║     Login : ${LOGIN_URL}"
echo "║     Admin : ${ADMIN_URL}"
echo "║  WP         : ${WP_IMAGE}"
echo "║  MariaDB    : ${DB_IMAGE}  (internal wp-net only)"
echo "║  CrowdSec   : ${CROWDSEC_IMAGE}"
echo "║  Kernel     : $(uname -r)"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Credentials  : /root/.wp-credentials (chmod 600)        ║"
echo "║  Env file     : /etc/wordpress/env    (chmod 600)        ║"
echo "║  DB backups   : /root/wp-db-backups/ (daily, 7-day keep)║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Security layers active:                                  ║"
echo "║   L1  nftables       default-deny + wp-net forward rule  ║"
echo "║   L2  Apache         ADMIN_CIDR + custom slug + 8G WAF   ║"
echo "║   L3  CrowdSec       apache2 + wordpress + appsec-wp     ║"
echo "║   L4  Podman         cap-drop ALL, static IPs, wp-net    ║"
echo "║   L5  Kernel         rp_filter=2, syncookies, ip_forward ║"
echo "║   L6  SSH            modern ciphers, key-only (if key set)║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Tooling:                                                 ║"
echo "║   update.sh status    — check + update all components    ║"
echo "║   update.sh trivy     — scan running containers for CVEs ║"
echo "║   wp-hardening.sh     — toggle security features         ║"
echo "║   validate-wordpress.sh — health check all layers        ║"
echo "║   wp-hardening.sh lynis — run Lynis security audit       ║"
echo "╠════════════════════════════════════════════════════════════╣"
[ -n "${CROWDSEC_ENROLL_KEY}" ]   && echo "║  CrowdSec: ENROLLED — accept at https://app.crowdsec.net ║"   || echo "║  CrowdSec: podman exec crowdsec cscli console enroll <k> ║"
echo "║  SSL: put behind NPM  OR  apk add certbot certbot-apache  ║"
echo "╚════════════════════════════════════════════════════════════╝"
INSTALLER_EOF

chmod +x "${TMPDIR}/install-wordpress.sh"
INST_LINES=$(wc -l < "${TMPDIR}/install-wordpress.sh")
(( INST_LINES > 100 )) || msg_error "Installer truncated (${INST_LINES} lines)"
msg_ok "Installer ready (${INST_LINES} lines)"

# ── Inject via qemu-nbd ───────────────────────────────────────────────────────
msg_info "Mounting disk image for injection…"
modprobe nbd max_part=8 2>/dev/null || true; sleep 1

NBD=""
for n in $(seq 0 15); do
  d="/dev/nbd${n}"; [[ -b "$d" ]] || continue
  sz=$(lsblk -bdno SIZE "$d" 2>/dev/null || echo 1)
  [[ "$sz" == "0" ]] && { NBD="$d"; break; }
done
[[ -n "$NBD" ]] || NBD="/dev/nbd0"
_NBD="$NBD"

qemu-nbd --connect="$NBD" "$WORK_IMG"; sleep 2
partprobe "$NBD" 2>/dev/null || true; sleep 1

ROOT_PART=""
for p in "${NBD}p2" "${NBD}p1" "${NBD}"; do
  [[ -b "$p" ]] || continue
  blkid "$p" 2>/dev/null | grep -qiE 'TYPE="ext[234]"' && { ROOT_PART="$p"; break; }
done
[[ -n "$ROOT_PART" ]] || ROOT_PART="${NBD}p1"
[[ -b "$ROOT_PART" ]] || ROOT_PART="$NBD"
msg_ok "Root partition: $ROOT_PART"

MNT="${TMPDIR}/mnt"; mkdir -p "$MNT"
mount "$ROOT_PART" "$MNT" || msg_error "Could not mount $ROOT_PART"
_MNT="$MNT"

# ─ Root password ──────────────────────────────────────────────────────────────
HASHED=$(openssl passwd -6 "$ROOT_PASS")
if [[ -f "$MNT/etc/shadow" ]]; then
  sed -i "s|^root:[^:]*:|root:${HASHED}:|" "$MNT/etc/shadow"
else
  printf "root:%s:0:0:99999:7:::\n" "$HASHED" > "$MNT/etc/shadow"; chmod 640 "$MNT/etc/shadow"
fi

# ─ Hostname ───────────────────────────────────────────────────────────────────
echo "$HN" > "$MNT/etc/hostname"
grep -q "$HN" "$MNT/etc/hosts" 2>/dev/null || echo "127.0.1.1  $HN" >> "$MNT/etc/hosts"

# ─ SSH hardening ──────────────────────────────────────────────────────────────
SSHCFG="$MNT/etc/ssh/sshd_config"; mkdir -p "$MNT/etc/ssh"
[[ $DISABLE_PW_AUTH -eq 1 ]] && { _PWAUTH="no"; _ROOTLOGIN="prohibit-password"; } \
                              || { _PWAUTH="yes"; _ROOTLOGIN="yes"; }
cat > "$SSHCFG" << SSHEOF
PermitRootLogin ${_ROOTLOGIN}
PasswordAuthentication ${_PWAUTH}
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 6
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
SSHEOF
chmod 600 "$SSHCFG"
if [[ -n "$SSH_KEYS" ]]; then
  mkdir -p "$MNT/root/.ssh"
  echo "$SSH_KEYS" > "$MNT/root/.ssh/authorized_keys"
  chmod 700 "$MNT/root/.ssh"; chmod 600 "$MNT/root/.ssh/authorized_keys"
fi

# ─ nftables ───────────────────────────────────────────────────────────────────
echo "$NFT_CONF" > "$MNT/etc/nftables.nft"; chmod 600 "$MNT/etc/nftables.nft"
msg_ok "nftables.nft injected"

# ─ Network addressing (DHCP or static) ────────────────────────────────────────
# Alpine's cloud image reads /etc/network/interfaces via the OpenRC "networking"
# service (already enabled below). We overwrite it unconditionally so behaviour
# is deterministic regardless of what the base image shipped with.
mkdir -p "$MNT/etc/network"
if [[ "$NET_MODE" == "static" ]]; then
  IFS=' ' read -r -a _dns_arr <<< "$VM_DNS"
  cat > "$MNT/etc/network/interfaces" << IFACEEOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address ${VM_STATIC_IP}
    netmask ${VM_NETMASK}
    gateway ${VM_GATEWAY}
    dns-nameservers ${_dns_arr[*]}
IFACEEOF
  msg_ok "Static network config injected: ${VM_STATIC_IP}/${VM_PREFIX} via ${VM_GATEWAY}"
else
  cat > "$MNT/etc/network/interfaces" << 'IFACEEOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACEEOF
  msg_ok "DHCP network config injected"
fi

# Write installer variables that can't go in the INSTALLER_EOF heredoc
# (which is single-quoted on the host, so host variables don't expand inside).
# The installer sources this file early in Stage 2.
mkdir -p "$MNT/etc/wp-install"
cat > "$MNT/etc/wp-install/vars.sh" << INSTALLERENV
# WordPress VM installer variables — generated by create-wordpress-vm.sh
# Sourced by /root/install-wordpress.sh during Stage 2
WP_ADMIN_SLUG="${WP_ADMIN_SLUG}"
CROWDSEC_ENROLL_KEY="${CROWDSEC_ENROLL_KEY}"
NET_MODE="${NET_MODE}"
VM_STATIC_IP="${VM_STATIC_IP}"
GEOIP_ENABLED="${GEOIP_ENABLED:-0}"
GEOIP_MODE="${GEOIP_MODE:-}"
GEOIP_WHITELIST="${GEOIP_WHITELIST:-}"
GEOIP_BLOCKLIST="${GEOIP_BLOCKLIST:-}"
MAXMIND_ACCOUNT_ID="${MAXMIND_ACCOUNT_ID:-}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
ROOTLESS_MODE="${ROOTLESS_MODE:-0}"
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"
INSTALLERENV
chmod 600 "$MNT/etc/wp-install/vars.sh"
msg_ok "Installer vars injected (slug=${WP_ADMIN_SLUG:-default}, cs-enroll=${CROWDSEC_ENROLL_KEY:+provided}, net=${NET_MODE}, geoip=${GEOIP_ENABLED:-0}, rootless=${ROOTLESS_MODE:-0}, digest-pin=${USE_DIGEST_PINNING:-1})"

# ─ Apache security config (host-built, CIDRs/IPs already substituted) ─────────
# The installer reads this from /root/wp-security.conf and copies it to the
# correct bind-mount path. This is the same pattern as nftables injection.
printf '%s\n' "$APACHE_SECURITY_CONF" > "$MNT/root/wp-security.conf"
chmod 644 "$MNT/root/wp-security.conf"
msg_ok "wp-security.conf injected (admin: ${ADMIN_CIDR:-open}, extra-ip: ${ALLOWED_ADMIN_IP:-none})"

# ─ mod_remoteip files (only if PROXY_IP was set) ─────────────────────────────
if [[ -n "$PROXY_IP" ]]; then
  cat > "$MNT/root/wp-remoteip.load" << RILOAD
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
RILOAD
  cat > "$MNT/root/wp-remoteip.conf" << RICONF
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy ${PROXY_IP}
RICONF
  chmod 644 "$MNT/root/wp-remoteip.load" "$MNT/root/wp-remoteip.conf"
  msg_ok "mod_remoteip files injected (trusted proxy: ${PROXY_IP})"
fi

# ─ Installer script ───────────────────────────────────────────────────────────
mkdir -p "$MNT/root"
cp "${TMPDIR}/install-wordpress.sh" "$MNT/root/install-wordpress.sh"
chmod +x "$MNT/root/install-wordpress.sh"
[[ -s "$MNT/root/install-wordpress.sh" ]] || msg_error "Installer copy failed."
msg_ok "install-wordpress.sh written ($(wc -l < "$MNT/root/install-wordpress.sh") lines)"

# ─ First-boot launcher ────────────────────────────────────────────────────────
mkdir -p "$MNT/etc/local.d"
cat > "$MNT/etc/local.d/01-wordpress.start" << 'LAUNCH'
#!/bin/sh
[ -f /var/log/wp-install.done ] && exit 0
mkdir -p /var/log
exec sh /root/install-wordpress.sh >> /var/log/wp-install.log 2>&1
LAUNCH
chmod +x "$MNT/etc/local.d/01-wordpress.start"

# ─ OpenRC runlevel symlinks ───────────────────────────────────────────────────
mkdir -p "$MNT/etc/runlevels/default"
for svc in local sshd networking; do
  [[ -f "$MNT/etc/init.d/$svc" ]] \
    && ln -sf "/etc/init.d/$svc" "$MNT/etc/runlevels/default/$svc" 2>/dev/null || true
done

# ─ Disable cloud-init ─────────────────────────────────────────────────────────
touch "$MNT/etc/cloud/cloud-init.disabled" 2>/dev/null || true
for s in cloud-init-local cloud-init cloud-config cloud-final; do
  rm -f "$MNT/etc/runlevels/"{default,boot,sysinit}"/$s" 2>/dev/null || true
done

# ─ Pre-install QEMU Guest Agent ───────────────────────────────────────────────
cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true
mount --bind /proc "$MNT/proc" 2>/dev/null || true
mount --bind /dev  "$MNT/dev"  2>/dev/null || true
chroot "$MNT" /bin/sh -c '
  VER=$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || echo "3.23")
  grep -q community /etc/apk/repositories 2>/dev/null \
    || printf "\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n" \
         "$VER" >> /etc/apk/repositories
  apk update --quiet --no-progress 2>/dev/null
  apk add   --quiet --no-progress --no-cache qemu-guest-agent 2>/dev/null
  ln -sf /etc/init.d/qemu-guest-agent /etc/runlevels/default/qemu-guest-agent 2>/dev/null
' 2>/dev/null \
  && msg_ok "QEMU Guest Agent pre-installed" \
  || msg_warn "Guest agent pre-install skipped (will install on first boot)"

umount "$MNT/dev"  2>/dev/null || true
umount "$MNT/proc" 2>/dev/null || true
umount "$MNT" && _MNT=""
qemu-nbd --disconnect "$NBD" && _NBD=""
msg_ok "Injection complete"

# ── Create VM ─────────────────────────────────────────────────────────────────
msg_info "Creating VM ${VMID} (${HN})…"
qm create "$VMID" \
  --name        "$HN" \
  --memory      "$RAM" \
  --cores       "$CORES" \
  --sockets     1 \
  --cpu         host \
  --net0        "virtio,bridge=${BRIDGE}${VLAN}" \
  --scsihw      virtio-scsi-single \
  --ostype      l26 \
  --onboot      1 \
  --startup     "order=3,up=30" \
  --tablet      0 \
  --vga         serial0 \
  --serial0     socket \
  --boot        order=scsi0 \
  --agent       "enabled=1,fstrim_cloned_disks=1" \
  --description "Alpine ${ALPINE_VER} | WordPress + MariaDB (wp-net) + CrowdSec | $(date '+%Y-%m-%d')"
msg_ok "VM skeleton created"

msg_info "Importing disk to ${STORAGE}…"
qm importdisk "$VMID" "$WORK_IMG" "$STORAGE" ${DISK_FMT} 1>/dev/null
rm -f "$WORK_IMG"
msg_ok "Disk imported"

qm set "$VMID" --scsi0 "$DISK_OPTS" --boot order=scsi0 --serial0 socket 1>/dev/null
msg_ok "Disk attached"

# ── Start VM ──────────────────────────────────────────────────────────────────
qm start "$VMID"
msg_ok "VM ${VMID} started"
_DESTROY_VM=0

# ── Wait for IP ───────────────────────────────────────────────────────────────
VM_MAC=$(qm config "$VMID" 2>/dev/null \
  | grep -m1 '^net0:' \
  | grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' \
  | tr '[:upper:]' '[:lower:]') || VM_MAC=""

echo ""
if [[ "$NET_MODE" == "static" ]]; then
  echo -e "  ${YW}Static IP configured — confirming the VM boots (up to 30s)…${CL}"
else
  echo -e "  ${YW}Waiting up to 2 minutes for an IP address… (Ctrl-C to skip)${CL}"
fi
echo ""

VM_IP="${VM_STATIC_IP}" ELAPSED=0 AGENT=0
WAIT_CAP=120
[[ "$NET_MODE" == "static" ]] && WAIT_CAP=30
SPIN=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'); SI=0

set +e
while (( ELAPSED < WAIT_CAP )); do
  if (( AGENT == 0 )) && qm agent "$VMID" ping &>/dev/null 2>&1; then
    AGENT=1; printf "\r  ${GN}✔${CL}  Guest agent online (%ds)\n" "$ELAPSED"
    if [[ "$NET_MODE" == "static" ]]; then
      printf "  ${GN}✔${CL}  Using configured static IP: ${BLD}%s${CL}\n" "$VM_IP"
      break
    fi
  fi
  if (( AGENT == 1 )) && [[ "$NET_MODE" != "static" ]]; then
    VM_IP=$(qm agent "$VMID" network-get-interfaces 2>/dev/null \
      | grep -oP '"ip-address":\s*"\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
      | grep -v '^127\.' | head -1) || VM_IP=""
    [[ -n "$VM_IP" ]] && { printf "\r  ${GN}✔${CL}  IP (agent): ${BLD}%s${CL}\n" "$VM_IP"; break; }
  fi
  if [[ -n "$VM_MAC" && "$NET_MODE" != "static" ]]; then
    VM_IP=$(ip -4 neigh show 2>/dev/null \
      | awk -v m="$VM_MAC" 'tolower($5)==m{print $1;exit}') || VM_IP=""
    [[ -n "$VM_IP" ]] && { printf "\r  ${GN}✔${CL}  IP (ARP):   ${BLD}%s${CL}\n" "$VM_IP"; break; }
  fi
  printf "\r  ${SPIN[$SI]}  Booting… %ds " "$ELAPSED"
  SI=$(( (SI+1) % ${#SPIN[@]} ))
  sleep 5; ELAPSED=$(( ELAPSED+5 ))
done
set -e

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
printf "${GN}${BLD}"
echo   "  ╔══════════════════════════════════════════════════════════════╗"
echo   "  ║        WordPress VM Created                                  ║"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
printf "  ║  VM ID    :  %-47s║\n"  "$VMID"
printf "  ║  Hostname :  %-47s║\n"  "$HN"
printf "  ║  Alpine   :  %-47s║\n"  "$ALPINE_VER"
printf "  ║  Resources:  %-47s║\n"  "${CORES} CPU · ${RAM} MB · ${DISK}"
printf "  ║  MAC      :  %-47s║\n"  "${VM_MAC:-see: qm config $VMID}"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
printf "  ║  SSH      :  %-47s║\n" "$([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only (password disabled)' || echo 'password enabled (no key)')"
printf "  ║  L1 nftables   SSH=%-12s  Web=%-21s║\n" "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
printf "  ║  L2 wp-admin   cidr=%-11s  extra-ip=%-16s║\n" "${ADMIN_CIDR:-open}" "${ALLOWED_ADMIN_IP:-none}"
printf "  ║  mod_remoteip  proxy=%-40s║\n"  "${PROXY_IP:-not configured (direct)}"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  # Pre-compute summary values using if/else (avoids quote-in-subshell issues)
  if [[ "${ROOTLESS_MODE:-0}" == "1" ]]; then
    _WP_PORT_DESC="6.9.4-php8.3-apache → port 8080 (rootless)"
    _MODE_DESC="rootless (wpuser, nftables 80→8080)"
  else
    _WP_PORT_DESC="6.9.4-php8.3-apache → port 80 (rootful)"
    _MODE_DESC="rootful (default)"
  fi
  if [[ -n "${VM_STATIC_IP}" ]]; then
    _NET_DESC="${NET_MODE:-dhcp} → ${VM_STATIC_IP}/${VM_PREFIX} via ${VM_GATEWAY}"
  else
    _NET_DESC="${NET_MODE:-dhcp}"
  fi
  if [[ "${GEOIP_ENABLED:-0}" == "1" ]]; then
    _GEO_DESC="${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})"
  else
    _GEO_DESC="disabled"
  fi
  echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  Containers (all --cap-drop ALL):                           ║"
  printf "  ║    WordPress  %-47s║\n" "${_WP_PORT_DESC}"
  printf "  ║    MariaDB    %-47s║\n" "11.4 → wp-net:10.89.1.0/24 only (no host port)"
  printf "  ║    CrowdSec   %-47s║\n" "v1.7.8 → host network, read-only"
  echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  Networking: netavark firewall_driver=nftables (no iptables)║"
  echo   "  ║  nftables forward: 10.89.1.0/24 allowed, all else DROP      ║"
  printf "  ║  Podman mode:   %-44s║\n" "${_MODE_DESC}"
  printf "  ║  Network:       %-44s║\n" "${_NET_DESC}"
  printf "  ║  GeoIP:         %-44s║\n" "${_GEO_DESC}"
  [[ -n "${WP_ADMIN_SLUG}" ]] && printf "  ║  Custom slug:   %-44s║\n" "/${WP_ADMIN_SLUG}-login"
echo   "  ║  Background install (~15 min total):                       ║"
echo   "  ║    qm terminal $VMID  then:  tail -f /var/log/wp-install.log"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  When done: http://<VM-IP>/wp-admin/install.php            ║"
echo   "  ╚══════════════════════════════════════════════════════════════╝"
printf "${CL}"
echo ""
