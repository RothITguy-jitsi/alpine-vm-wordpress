#!/usr/bin/env bash
# 01-interactive-setup.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# All interactive prompts: VM ID, root password, hostname, storage/bridge/VLAN, network mode, SSH key/admin account, firewall CIDRs, admin slug, CrowdSec enrolment, GeoIP, digest pinning, deployment profile, and the final confirmation summary.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

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
echo -e "  ${YW}Root SSH login is always disabled on this VM. A dedicated admin account${CL}"
echo -e "  ${YW}is created instead, in the 'wheel' group, with doas configured for root${CL}"
echo -e "  ${YW}access after login (root still has a local console password for${CL}"
echo -e "  ${YW}'qm terminal' access — that's separate from SSH).${CL}"
echo "  Paste your public key (starts with ssh-ed25519 or ssh-rsa),"
echo "  or press Enter to load from a file path."
read -rp "  Public key (paste, or blank) : " SSH_KEY_PASTE
SSH_KEYS=""
if [[ -n "$SSH_KEY_PASTE" ]]; then
  SSH_KEYS="$SSH_KEY_PASTE"
else
  read -rp "  ...or path to a .pub file (blank = set an admin password instead) : " SK
  [[ -n "$SK" && -f "$SK" ]] && SSH_KEYS=$(cat "$SK")
fi

# Sanitise: lowercase, alnum + underscore/hyphen, must start with a letter
# (POSIX username rules) — same sanitisation style as WP_ADMIN_SLUG below,
# plus an explicit leading-character check that a URL slug doesn't need.
read -rp "  Admin account username [wpadmin] : " ADMIN_USER_RAW
ADMIN_USER=$(echo "${ADMIN_USER_RAW:-wpadmin}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9_-' '-' | sed 's/^-//;s/-$//')
[[ "$ADMIN_USER" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || ADMIN_USER="wpadmin"
# Reserved names: root (this whole feature's point), wpuser (already used
# for file/volume ownership — see wpuser creation later — colliding would
# make adduser fail and trip the ADMIN_USER_CREATED fallback further down).
[[ "$ADMIN_USER" == "root" || "$ADMIN_USER" == "wpuser" ]] && ADMIN_USER="wpadmin"

ADMIN_PASS=""
if [[ -n "$SSH_KEYS" ]]; then
  DISABLE_PW_AUTH=1
  # Password auth is off session-wide, so this account's password is never
  # typed over SSH — it exists purely so doas has something to authenticate
  # against once logged in. Generated the same way the DB passwords are
  # (openssl rand, unknown to the operator, written to a credentials file
  # on disk) rather than asked for, since nobody needs to remember it.
  ADMIN_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 24)
  msg_ok "SSH key set — password login disabled. Admin account: ${ADMIN_USER}"
else
  DISABLE_PW_AUTH=0
  msg_warn "No SSH key — ${ADMIN_USER} will use password login (root SSH stays disabled either way)"
  while [[ -z "$ADMIN_PASS" ]]; do
    read -rsp "  Password for ${ADMIN_USER} : " ap1; echo
    read -rsp "  Confirm                  : " ap2; echo
    [[ "$ap1" == "$ap2" && -n "$ap1" ]] && ADMIN_PASS="$ap1" \
      || echo -e "  ${RD}Passwords do not match.${CL}"
  done
fi

echo ""
echo -e "  ${BLD}Firewall + access control${CL}"
echo ""

# BUG FIX (v7-15, audit #13): validate every CIDR/IP before it's accepted.
# These values are inserted verbatim into root-owned security config —
# nftables rules (`ip saddr ${SSH_CIDR} ...`) and Apache directives
# (`Require ip ${ADMIN_CIDR}`, `RemoteIPTrustedProxy ${PROXY_IP}`). A
# malformed value doesn't just get ignored: it makes nftables fail to load
# (potentially leaving the firewall down) or Apache fail to start
# (potentially leaving the site down), and a stray token could weaken the
# very restriction it's meant to express. Validated here at input time so a
# typo is caught immediately, with a re-prompt, instead of surfacing as a
# baffling service failure 10 minutes into a background install.
#
# _valid_octet: 0-255. _valid_ipv4: four dotted octets. _valid_cidr:
# IPv4 or IPv4/prefix (prefix 0-32).
_v15_valid_ipv4() {
  case "$1" in
    *[!0-9.]*) return 1 ;;
  esac
  local IFS=. o count=0
  set -- $1
  [ $# -eq 4 ] || return 1
  for o in "$@"; do
    [ -n "$o" ] || return 1
    case "$o" in *[!0-9]*) return 1 ;; esac
    [ "$o" -le 255 ] 2>/dev/null || return 1
    # reject leading-zero forms like 01 / 001 (ambiguous, octal-looking)
    [ "$o" = "0" ] || [ "${o#0}" = "$o" ] || return 1
    count=$((count+1))
  done
  [ "$count" -eq 4 ]
}
_v15_valid_cidr() {
  case "$1" in
    */*)
      local addr="${1%/*}" pfx="${1#*/}"
      case "$pfx" in
        ''|*[!0-9]*) return 1 ;;
      esac
      [ "$pfx" -le 32 ] 2>/dev/null || return 1
      _v15_valid_ipv4 "$addr"
      ;;
    *)
      _v15_valid_ipv4 "$1"
      ;;
  esac
}
# Prompt for a CIDR-or-blank value, re-asking until valid.
_ask_cidr() {  # $1 prompt text ; echoes validated value (may be empty)
  local _p="$1" _v
  while :; do
    printf '%s' "$_p" >&2
    IFS= read -r _v
    [ -z "$_v" ] && { printf '' ; return 0; }
    if _v15_valid_cidr "$_v"; then printf '%s' "$_v"; return 0; fi
    echo -e "  ${RD}Not a valid IPv4 address or CIDR (e.g. 192.168.1.0/24 or 192.168.1.5). Try again or leave blank.${CL}" >&2
  done
}
_ask_single_ip() {  # $1 prompt text ; echoes validated single IPv4 (may be empty)
  local _p="$1" _v
  while :; do
    printf '%s' "$_p" >&2
    IFS= read -r _v
    [ -z "$_v" ] && { printf '' ; return 0; }
    case "$_v" in
      */*|*[!0-9.]*) echo -e "  ${RD}Enter a single IPv4 address (no CIDR, no list). Try again or leave blank.${CL}" >&2; continue ;;
    esac
    if _v15_valid_ipv4 "$_v"; then printf '%s' "$_v"; return 0; fi
    echo -e "  ${RD}Not a valid IPv4 address. Try again or leave blank.${CL}" >&2
  done
}

echo -e "  ${BLD}Layer 1 — nftables (packet level, applies to ALL traffic on 80/443):${CL}"
SSH_CIDR=$(_ask_cidr "  Restrict SSH (22) to a CIDR?           (blank = any)  : ")
WEB_CIDR=$(_ask_cidr "  Restrict Web (80/443) to a CIDR?       (blank = any)  : ")
[[ -z "$WEB_CIDR" ]] && msg_warn "Web ports open to any IP — Layer 2 (Apache) still enforces wp-admin"
echo ""
echo -e "  ${BLD}Layer 2 — Apache (request level, wp-admin + wp-login.php only):${CL}"
echo -e "  ${YW}This restriction works whether traffic is direct OR through a reverse proxy.${CL}"
echo -e "  ${YW}Set to your local network CIDR (e.g. 192.168.1.0/24).${CL}"
echo ""
echo -e "  ${YW}Your workstation is likely on one of these subnets (from the Proxmox host):${CL}"
ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print "    " a[1] "  (subnet: " $2 ")"}' | head -5
echo ""
ADMIN_CIDR=$(_ask_cidr "  Local network CIDR for wp-admin?  e.g. 192.168.100.0/24 (blank = open) : ")
ALLOWED_ADMIN_IP=$(_ask_single_ip "  Additional IP for wp-admin?  (e.g. 203.0.113.5, blank = none)  : ")
echo ""
echo -e "  ${BLD}Layer 2b — mod_remoteip (only needed if behind a reverse proxy):${CL}"
echo -e "  ${YW}If WordPress is behind NPM / nginx / Caddy, Apache sees the proxy IP${CL}"
echo -e "  ${YW}not the real client IP. Enter the proxy's internal IP so Apache trusts${CL}"
echo -e "  ${YW}its X-Forwarded-For header for accurate wp-admin IP checks.${CL}"
PROXY_IP=$(_ask_single_ip "  Reverse proxy IP (e.g. 192.168.1.50, blank = direct access) : ")
echo ""
echo -e "  ${BLD}Security features${CL}"
echo -e "  ${YW}Custom wp-admin slug: moves the login page to a secret URL and blocks${CL}"
echo -e "  ${YW}the default /wp-login.php, so credential-stuffing bots hitting the${CL}"
echo -e "  ${YW}standard path get 403 before WordPress or PHP is ever reached.${CL}"
echo -e "  ${YW}Choose something unique (e.g. siteadmin, seclogin, mymsp2024).${CL}"
echo -e "  ${YW}Avoid obvious words: admin, login, dashboard, wp, secure.${CL}"
read -rp "  wp-admin custom slug?  (blank = keep default /wp-admin) : " WP_ADMIN_SLUG
# Sanitise: lowercase, alphanumeric + hyphen only
WP_ADMIN_SLUG=$(echo "${WP_ADMIN_SLUG}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed 's/^-//;s/-$//')
# BUG FIX (v7-14): reject slugs that collide with a real WordPress path.
# A slug of "wp-content", "wp-admin", "wp-includes" or similar would have
# its RewriteRule shadow (or be shadowed by) the real directory, producing
# a site that half-works in ways that are extremely hard to diagnose — the
# rewrite fires for some paths and the real directory wins for others.
case "$WP_ADMIN_SLUG" in
  wp-admin|wp-includes|wp-content|wp-login|wp-json|index|xmlrpc|feed|admin-ajax)
    msg_warn "Slug '${WP_ADMIN_SLUG}' collides with a real WordPress path — ignoring it."
    msg_warn "  Re-run and pick something that isn't a WordPress reserved path."
    WP_ADMIN_SLUG=""
    ;;
esac
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  msg_ok "Admin slug: /${WP_ADMIN_SLUG}-login  (default /wp-login.php will return 403)"
  msg_info "  A must-use plugin makes WordPress emit the slug in its own login links,"
  msg_info "  so the default path is never advertised. Recovery instructions if you"
  msg_info "  ever lock yourself out are printed at the end of the install."
else
  msg_warn "No slug set — /wp-login.php accessible at default URL (still protected by ADMIN_CIDR + CrowdSec)"
fi
echo ""
echo -e "  ${BLD}CrowdSec Console enrolment (optional — can be done after install):${CL}"
echo -e "  ${YW}Get your enrolment key at https://app.crowdsec.net → Security Engines → Add${CL}"
echo -e "  ${YW}This automates the enrolment step so you don't need to SSH in afterwards.${CL}"
read -rsp "  CrowdSec enrolment key (blank = skip, enrol manually later) : " CROWDSEC_ENROLL_KEY; echo

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
  read -rsp "  MaxMind License Key : " MAXMIND_LICENSE_KEY; echo
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


echo -e "  ${YW}When enabled, WordPress/MariaDB/CrowdSec are pinned to the exact SHA256${CL}"
echo -e "  ${YW}digest resolved at install time, not just the floating tag. This${CL}"
echo -e "  ${YW}guarantees the bits that get audited/tested are the exact bits that${CL}"
echo -e "  ${YW}run — a registry silently repointing a tag can't change what's deployed.${CL}"
echo -e "  ${YW}Digests are resolved via Skopeo (a registry manifest query, a few KB —${CL}"
echo -e "  ${YW}no image is pulled just to check), so this stays cheap on every check.${CL}"
echo -e "  ${YW}update.sh re-pins on every update, and${CL}"
echo -e "  ${YW}'update.sh digest-check' can find and move to a newer digest published${CL}"
echo -e "  ${YW}under the SAME tag (e.g. a same-version security rebuild).${CL}"
read -rp "  Use SHA256 image digest pinning? [Y/n] : " PINNING_SEL
USE_DIGEST_PINNING=1
[[ "${PINNING_SEL:-Y}" =~ ^[Nn] ]] && USE_DIGEST_PINNING=0
if (( USE_DIGEST_PINNING )); then
  msg_ok "Digest pinning enabled — resolved during install via Skopeo (manifest query, not a full pull)"
else
  msg_warn "Digest pinning disabled — images run by floating tag only"
fi

# BUG FIX (v7-13, ChatGPT Findings 8+9 in the audit): DEPLOYMENT_PROFILE
# controls how this script behaves when its OWN security verifications
# can't complete. Older versions had two separate, independently
# fail-open code paths: _verify_alpine_sha512() would msg_warn and
# return success if the .sha512 sidecar was missing/malformed or if
# sha512sum itself wasn't installed on the Proxmox host, and _pin_digest()
# would silently fall back to a tag-only reference every time its Skopeo
# lookup or its podman pull failed — so an install could complete claiming
# "digest pinning enabled" while running as few as 0/3 pinned images.
# Both are correct defaults for a homelab (an admin diagnosing a bad
# Alpine mirror doesn't want the script to abort mid-provision), but they
# leave an MSP client with no way to INSIST on those verifications
# succeeding — no toggle that turns "warn and continue" into "abort".
# DEPLOYMENT_PROFILE is that toggle:
#   • standard (default) — keeps the v7-12 behavior EXACTLY. Verifications
#     are attempted; a failure is loudly warned but not fatal. Chosen so
#     existing installs and repeat runs behave identically to before, and
#     so admins in a bad-network situation can still get a working VM.
#   • production          — the audit-graded behavior. If sha512sum isn't
#     installed on the Proxmox host, if the Alpine .sha512 sidecar can't
#     be fetched or is malformed, if fewer than 3/3 container images
#     resolve to a real @sha256: digest — any one of these aborts the
#     install instead of silently continuing. Chosen when an operator
#     needs to be able to promise a compliance auditor that the base OS
#     image and all container images actually WERE verified against
#     upstream, not merely attempted.
# Not enabled by default because the loud warnings in "standard" already
# make a failure visible to any operator who's watching the install
# output; production mode is opt-in for the operators who need to
# GUARANTEE that visibility rather than depend on it.
echo ""
echo -e "  ${BLD}Deployment profile — what happens when a verification fails${CL}"
echo -e "  ${YW}standard   — warn and continue (default). Alpine SHA-512 mismatch or a${CL}"
echo -e "  ${YW}             registry blip during digest pinning is loudly reported but${CL}"
echo -e "  ${YW}             does not abort the install. Right for lab/staging installs${CL}"
echo -e "  ${YW}             and for repeat runs on a network where the sha512 sidecar${CL}"
echo -e "  ${YW}             is sometimes flaky. Matches the v7-11/v7-12 behavior exactly.${CL}"
echo -e "  ${YW}production — treat verification failure as fatal. If sha512sum is missing${CL}"
echo -e "  ${YW}             on this host, if Alpine's .sha512 sidecar can't be fetched or${CL}"
echo -e "  ${YW}             validated, or if fewer than 3/3 container images resolve to a${CL}"
echo -e "  ${YW}             real digest, the install ABORTS instead of continuing under${CL}"
echo -e "  ${YW}             unverified state. Right for MSP-graded deployments that need${CL}"
echo -e "  ${YW}             to demonstrate the verifications actually succeeded.${CL}"
read -rp "  Deployment profile? [standard/production] (default: standard) : " DEPLOY_SEL
case "${DEPLOY_SEL:-standard}" in
  production|prod|p) DEPLOYMENT_PROFILE="production" ;;
  *)                 DEPLOYMENT_PROFILE="standard"   ;;
esac
if [ "$DEPLOYMENT_PROFILE" = "production" ]; then
  msg_ok "Deployment profile: production — verification failures will abort the install"
  # Force digest pinning ON under production — a "digest pinning disabled"
  # install can't satisfy the production-mode 3/3 requirement below, so
  # it makes no sense to offer both toggles as independently answerable.
  if [ "$USE_DIGEST_PINNING" != "1" ]; then
    msg_warn "  Digest pinning was answered [n] but production profile requires it — enabling."
    USE_DIGEST_PINNING=1
  fi
else
  msg_ok "Deployment profile: standard — verification failures will warn but not abort"
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
printf  "  %-18s %s\n"  "SSH:"         "${ADMIN_USER} — $([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password')  (root SSH disabled)"
printf  "  %-18s nft SSH=%-15s  nft Web=%s\n"   "L1 Firewall:"  "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
printf  "  %-18s admin-cidr=%-18s  allowed-ip=%s\n" "L2 wp-admin:" "${ADMIN_CIDR:-none}" "${ALLOWED_ADMIN_IP:-none}"
printf  "  %-18s %s\n"  "Proxy IP:"    "${PROXY_IP:-direct (no proxy)}"
printf  "  %-18s %s\n"  "Admin slug:"  "${WP_ADMIN_SLUG:+/${WP_ADMIN_SLUG} (custom)}${WP_ADMIN_SLUG:-/wp-admin (default)}"
printf  "  %-18s %s\n"  "CS enrolment:" "${CROWDSEC_ENROLL_KEY:+key provided (auto-enrol)}${CROWDSEC_ENROLL_KEY:-manual (after install)}"
printf  "  %-18s WordPress + MariaDB (internal) + CrowdSec\n" "Containers:"
printf  "  %-18s %s\n"  "Network:"     "${NET_MODE}${VM_STATIC_IP:+ ($VM_STATIC_IP/$VM_PREFIX)}"
printf  "  %-18s %s\n"  "GeoIP:"       "$([[ $GEOIP_ENABLED -eq 1 ]] && echo "${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})" || echo 'disabled')"
printf  "  %-18s %s\n"  "Digest pinning:" "$([[ $USE_DIGEST_PINNING -eq 1 ]] && echo 'enabled (SHA256-pinned images)' || echo 'disabled (tag-only)')"
[[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]] && msg_warn "WEB_CIDR set + PROXY_IP set → ${PROXY_IP} auto-added to nftables so NPM can reach port 80/443"
[[ -n "$WEB_CIDR" && -z "$PROXY_IP" ]] && msg_warn "WEB_CIDR restricts port 80/443 to ${WEB_CIDR}. If NPM is on a different subnet, add its IP as PROXY_IP or re-run the script."
echo ""
read -rp "  Proceed? [Y/n] : " yn
[[ "${yn:-Y}" =~ ^[Yy] ]] || { echo "Aborted."; _DESTROY_VM=0; exit 0; }


