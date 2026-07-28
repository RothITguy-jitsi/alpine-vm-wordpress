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
# ── Introduction ─────────────────────────────────────────────────────────────
# Shown once, before the first prompt. The intent is to explain what is
# actually different here, in terms someone can verify afterwards, and to say
# what this is NOT so nobody finishes the install with a wrong mental model of
# what they are protected against. Claims that cannot be checked against the
# running VM do not belong in it.
echo -e "  ${BLD}Why this installer${CL}"
echo -e "  ${YW}Most WordPress install scripts get you a running site. This one${CL}"
echo -e "  ${YW}assumes the site will eventually be attacked, and that you will${CL}"
echo -e "  ${YW}still have to run it in six months. The differences follow from${CL}"
echo -e "  ${YW}that:${CL}"
echo ""
echo -e "  ${BL}  Segmented, not just firewalled.${CL}${YW} MariaDB sits on its own${CL}"
echo -e "  ${YW}    internal network with no host port and no route to the${CL}"
echo -e "  ${YW}    internet. A compromised WordPress cannot reach past it, and${CL}"
echo -e "  ${YW}    the database is not exposed even if the firewall is wrong.${CL}"
echo ""
echo -e "  ${BL}  Updates are tested before they are applied.${CL}${YW} A candidate${CL}"
echo -e "  ${YW}    container is started, scanned for CVEs, and health-checked${CL}"
echo -e "  ${YW}    while production keeps serving. Only then is the swap made,${CL}"
echo -e "  ${YW}    and it rolls back automatically if the new one fails.${CL}"
echo ""
echo -e "  ${BL}  Images are pinned to digests, not tags.${CL}${YW} What was scanned${CL}"
echo -e "  ${YW}    and tested is exactly what runs. A registry moving a tag${CL}"
echo -e "  ${YW}    cannot change your deployment underneath you.${CL}"
echo ""
echo -e "  ${BL}  Backups are verified, not assumed.${CL}${YW} The dump's exit status,${CL}"
echo -e "  ${YW}    its completion marker and the archive itself are all checked${CL}"
echo -e "  ${YW}    before any old backup is rotated away.${CL}"
echo ""
echo -e "  ${BL}  It tells you when it is wrong.${CL}${YW} Post-install validation${CL}"
echo -e "  ${YW}    runs ~45 checks and prints the exact command to fix each${CL}"
echo -e "  ${YW}    failure. Day-2 tooling ships with it: update.sh,${CL}"
echo -e "  ${YW}    validate-wordpress.sh, wp-hardening.sh, wp-mail.sh,${CL}"
echo -e "  ${YW}    wp-plugins.sh — including plugin CVE visibility, which is${CL}"
echo -e "  ${YW}    where ~91% of WordPress vulnerabilities actually live and${CL}"
echo -e "  ${YW}    which container scanning does not cover.${CL}"
echo ""
echo -e "  ${BL}  Every control tells you its limits.${CL}${YW} Where a setting is${CL}"
echo -e "  ${YW}    noise reduction rather than a boundary, the prompt says so.${CL}"
echo -e "  ${YW}    Nothing here is oversold — a control you over-trust is worse${CL}"
echo -e "  ${YW}    than one you know the edges of.${CL}"
echo ""
echo -e "  ${YW}What this is not: a managed service, a substitute for backups you${CL}"
echo -e "  ${YW}keep somewhere else, or protection against someone specifically${CL}"
echo -e "  ${YW}targeting you. It raises the floor considerably and is honest${CL}"
echo -e "  ${YW}about the ceiling.${CL}"
echo ""
echo -e "  ${BL}                                                  by RothITguy${CL}"
echo ""
# Closing line. Deliberately says "looks there too" rather than "scans your
# plugins for CVEs": wp-plugins.sh surfaces what is out of date via the
# WordPress.org update API, which is the practical remediation path, but it
# is not a CVE-matching scanner. Overstating that here would be the exact
# thing the rest of this installer refuses to do.
echo -e "  ${BLD}  \"~91% of WordPress vulnerabilities live in plugins —${CL}"
echo -e "  ${BLD}   where most hardening never looks. This one does.\"${CL}"
echo -e "  ${YW}     figure: Patchstack, State of WordPress Security 2026${CL}"
echo ""
echo -e "  ${YW}  Press Enter to begin.${CL}"
read -r _INTRO_ACK
unset _INTRO_ACK
echo ""
# ── Security-reasoning blocks ────────────────────────────────────────────────
# Several prompts below carry a short "what this does and does not buy you"
# note. These exist because the failure mode of a security control is rarely
# that it breaks -- it is that someone believes it excludes a class of
# attacker it does not. The bound on a control belongs in front of the person
# choosing whether to rely on it, not only in a README they may never read.
#
# _sec_note prints the attribution so it is clear these are this project's
# considered judgements rather than generic vendor boilerplate.
_sec_note() { echo -e "  ${BL}— RothITguy${CL}"; echo ""; }
_sec_head() { echo -e "  ${BLD}What this does and does not buy you:${CL}"; }


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

_sec_head
echo -e "  ${YW}  Root SSH is disabled unconditionally, so this password is only ever${CL}"
echo -e "  ${YW}  usable from the Proxmox console (qm terminal). That is deliberate: it${CL}"
echo -e "  ${YW}  guarantees a recovery path that does not depend on the network, on${CL}"
echo -e "  ${YW}  SSH, or on the admin account having been created successfully.${CL}"
echo -e "  ${YW}  It is not decorative. Anyone who can reach the Proxmox web UI can${CL}"
echo -e "  ${YW}  open that console, so this password is only as meaningful as your${CL}"
echo -e "  ${YW}  hypervisor login — treat it as a hypervisor-tier secret, not a${CL}"
echo -e "  ${YW}  throwaway you will never type again.${CL}"
_sec_note
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
_sec_head
echo -e "  ${YW}  This is a security choice, not just a networking one. Several${CL}"
echo -e "  ${YW}  controls here are keyed to addresses: the SSH and wp-admin${CL}"
echo -e "  ${YW}  restrictions, the reverse-proxy trust for X-Forwarded-For, and any${CL}"
echo -e "  ${YW}  firewall rule elsewhere that names this VM.${CL}"
echo -e "  ${YW}  With DHCP, a lease change moves this host out from under those rules${CL}"
echo -e "  ${YW}  silently — nothing errors, access simply starts being denied or,${CL}"
echo -e "  ${YW}  worse, a rule that named the old address now names something else.${CL}"
echo -e "  ${YW}  Static addressing is the safer default for anything you will write${CL}"
echo -e "  ${YW}  firewall rules about. DHCP is fine for a lab VM you will rebuild.${CL}"
_sec_note
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
_sec_head
echo -e "  ${YW}  Restricting SSH by source address is the single highest-value control${CL}"
echo -e "  ${YW}  here: it removes this host from the constant background of internet${CL}"
echo -e "  ${YW}  SSH brute-forcing entirely, rather than merely surviving it.${CL}"
echo -e "  ${YW}  It trusts the network. Anything inside the allowed range — a${CL}"
echo -e "  ${YW}  compromised workstation, a guest VLAN that can route here — is${CL}"
echo -e "  ${YW}  unaffected by it. Narrow the range to what you actually administer${CL}"
echo -e "  ${YW}  from, not to the whole LAN because that is easier.${CL}"
echo -e "  ${YW}  Leaving it blank is defensible only if something in front of this VM${CL}"
echo -e "  ${YW}  is already doing the same job.${CL}"
_sec_note
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

# ── Outbound (egress) firewall ────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Restrict outbound traffic?${CL}"
echo -e "  ${YW}By default this VM may connect OUT to anything; only the Proxmox${CL}"
echo -e "  ${YW}management ports are blocked. Restricting egress limits what a${CL}"
echo -e "  ${YW}compromised WordPress can reach.${CL}"
echo ""
echo -e "  ${YW}Allowed automatically, because every feature here needs them:${CL}"
echo -e "  ${YW}    53   DNS            123  NTP (time sync)${CL}"
echo -e "  ${YW}    80   HTTP           443  HTTPS${CL}"
echo -e "  ${YW}    67/68 DHCP          25/465/587  outbound mail${CL}"
echo -e "  ${YW}  That covers Alpine packages, container registries, WordPress${CL}"
echo -e "  ${YW}  and plugin updates, CrowdSec, MaxMind, Trivy, and SMTP.${CL}"
echo ""
echo -e "  ${YW}Ports can be opened later without a reinstall:${CL}"
echo -e "  ${YW}    wp-hardening.sh egress-allow 8443${CL}"
echo ""
# The limitation goes LAST, immediately before the question, and is as
# concrete as the benefit. An earlier version put the memorable examples
# (6667, 4444) in the selling paragraph and left the caveat vague and buried
# under reassurance text -- which is how a feature gets over-trusted. If the
# honest bound on a security control is worth writing in the README, it is
# worth putting in front of the person choosing whether to rely on it.
_sec_head
echo -e "  ${YW}  It removes the easy options — C2 on an odd port, a reverse${CL}"
echo -e "  ${YW}  shell on 4444, IRC botnet traffic on 6667, bulk exfiltration${CL}"
echo -e "  ${YW}  over a random high port.${CL}"
echo -e "  ${YW}  It is NOT containment against a determined attacker. 443 has${CL}"
echo -e "  ${YW}  to stay open — nothing here works without it — and anyone${CL}"
echo -e "  ${YW}  wanting a covert channel will simply use 443.${CL}"
echo -e "  ${YW}  Worth having. Not worth over-trusting.${CL}"
_sec_note
read -rp "  Restrict outbound traffic to the ports above? [y/N] : " _EGR
case "${_EGR}" in
  y|Y|yes|YES)
    RESTRICT_EGRESS=1
    msg_ok "Egress restricted — everything except the listed ports is dropped and logged"
    msg_info "  Open more later:  wp-hardening.sh egress-allow <port> [tcp|udp]"
    msg_info "  See what is open:  wp-hardening.sh egress-list"
    ;;
  *)
    msg_ok "Egress unrestricted (default) — only Proxmox management ports are blocked"
    ;;
esac
unset _EGR

# ── Outbound email / SMTP relay (NEW) ─────────────────────────────────────────
echo ""
echo -e "  ${BLD}Outbound email (SMTP relay)${CL}"
echo -e "  ${YW}WordPress cannot send mail on this VM without this. The official${CL}"
echo -e "  ${YW}WordPress container has no sendmail binary, so PHP's mail() has${CL}"
echo -e "  ${YW}nothing to hand messages to. Every password reset, new-user${CL}"
echo -e "  ${YW}notification, comment alert, contact-form submission and${CL}"
echo -e "  ${YW}WooCommerce receipt then fails SILENTLY -- WordPress reports${CL}"
echo -e "  ${YW}success in the UI and nothing is written to any log. Locked-out${CL}"
echo -e "  ${YW}admins with no reset email is the usual way people find out.${CL}"
echo ""
echo -e "  ${YW}Use a DEDICATED mailbox or app password for this site, not your${CL}"
echo -e "  ${YW}normal account: it is stored on the VM (0400, root-owned, mounted${CL}"
echo -e "  ${YW}read-only into the container, outside the web root), and if the${CL}"
echo -e "  ${YW}site is ever compromised you want to revoke exactly one${CL}"
echo -e "  ${YW}credential without disturbing anything else that sends mail.${CL}"
echo ""
echo -e "  ${YW}Outbound sends are rate-limited by the firewall (30 new${CL}"
echo -e "  ${YW}connections/hour, burst 10). A compromised site spamming through${CL}"
echo -e "  ${YW}an authenticated relay damages your sending domain's reputation,${CL}"
echo -e "  ${YW}and that outlasts the compromise itself.${CL}"
echo ""
SMTP_HOST=""; SMTP_PORT="587"; SMTP_USER=""; SMTP_PASS=""
SMTP_FROM=""; SMTP_FROM_NAME=""; SMTP_ENCRYPTION="tls"
read -rp "  Configure outbound email now? [y/N] : " _WANT_SMTP
case "${_WANT_SMTP}" in
  y|Y|yes|YES)
    while :; do
      read -rp "  SMTP server hostname (e.g. mail.example.com) : " SMTP_HOST
      SMTP_HOST=$(printf '%s' "$SMTP_HOST" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
      [ -n "$SMTP_HOST" ] && break
      msg_warn "  A hostname is required (or answer N to skip email entirely)."
    done
    echo -e "  ${YW}587 = submission with STARTTLS (the standard, and the default).${CL}"
    echo -e "  ${YW}465 = implicit TLS, encrypted from connect. Both are fine.${CL}"
    echo -e "  ${YW}25 is deliberately not offered: it is for server-to-server${CL}"
    echo -e "  ${YW}relay, is widely blocked outbound, and is unauthenticated.${CL}"
    read -rp "  SMTP port [587] : " _SP
    case "${_SP:-587}" in
      465) SMTP_PORT="465"; SMTP_ENCRYPTION="ssl" ;;
      *)   SMTP_PORT="587"; SMTP_ENCRYPTION="tls" ;;
    esac
    read -rp "  SMTP username (the full mailbox address) : " SMTP_USER
    while :; do
      read -rsp "  SMTP password / app password : " SMTP_PASS; echo
      [ -n "$SMTP_PASS" ] && break
      msg_warn "  Password cannot be empty — authenticated submission is required."
    done
    echo -e "  ${YW}The From address matters more than it looks. WordPress otherwise${CL}"
    echo -e "  ${YW}sends as wordpress@<your-domain>, which is usually not a real${CL}"
    echo -e "  ${YW}mailbox and usually not a sender your SPF record authorizes --${CL}"
    echo -e "  ${YW}under a DMARC policy of quarantine or reject that means silent${CL}"
    echo -e "  ${YW}non-delivery, which is the same invisible failure again. Use an${CL}"
    echo -e "  ${YW}address on a domain whose SPF/DKIM covers this relay.${CL}"
    read -rp "  From address [${SMTP_USER}] : " SMTP_FROM
    SMTP_FROM="${SMTP_FROM:-$SMTP_USER}"
    read -rp "  From name [${WP_SITE_TITLE:-WordPress}] : " SMTP_FROM_NAME
    SMTP_FROM_NAME="${SMTP_FROM_NAME:-${WP_SITE_TITLE:-WordPress}}"
    msg_ok "SMTP: ${SMTP_USER}@${SMTP_HOST}:${SMTP_PORT} (${SMTP_ENCRYPTION}), from ${SMTP_FROM}"
    msg_info "  Verify delivery after install with:  wp-mail.sh test you@example.com"
    ;;
  *)
    msg_warn "Outbound email not configured — WordPress will be UNABLE to send mail."
    msg_warn "  Password resets and notifications will fail silently. Configure later:"
    msg_warn "  wp-mail.sh setup   (on the VM, after install)"
    ;;
esac
unset _WANT_SMTP _SP

# ── WordPress site identity (NEW) ─────────────────────────────────────────────
# Why this is asked at install time rather than left to the browser wizard:
# WordPress stores its canonical URL in the DATABASE (wp_options.siteurl and
# .home) the moment you first complete setup. If that first visit is to the
# VM's raw IP, the IP becomes the site's identity -- baked into permalinks,
# emails, password-reset links, and (worst) into serialized PHP arrays in
# plugin/theme options, where a naive SQL find-and-replace corrupts the data
# because it doesn't fix the embedded string lengths. Moving to the real
# domain afterwards then needs wp-cli search-replace or a migration plugin.
#
# Setting WP_HOME/WP_SITEURL as constants avoids the whole problem: constants
# take precedence over the database values, so the site is born knowing its
# own name and the DB copy never matters. It also makes the URL a
# config-file change (one restart) rather than a database migration if the
# domain ever moves.
echo ""
echo -e "  ${BLD}WordPress site address${CL}"
echo -e "  ${YW}The domain this site will actually be served on. Set it now and${CL}"
echo -e "  ${YW}WordPress is configured with it from first boot -- no browser setup${CL}"
echo -e "  ${YW}wizard writing the VM's IP into the database as the permanent site${CL}"
echo -e "  ${YW}URL, and no search-replace migration later to undo that.${CL}"
echo -e "  ${YW}Leave blank to use the VM's IP address (fine for a lab/test VM).${CL}"
WP_DOMAIN=""
while :; do
  read -rp "  Site domain (e.g. example.com, blank = use IP) : " _WPD
  # Trim leading/trailing whitespace only -- deliberately NOT `tr -d` on all
  # whitespace, which would silently turn a fat-fingered "exa mple.com" into
  # the valid-but-different "example.com" and deploy the site under a domain
  # the operator never typed. Internal whitespace fails the pattern below
  # and gets a re-prompt, which is the correct outcome for a typo.
  _WPD=$(printf '%s' "${_WPD}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')
  # Strip anything the operator pasted that isn't the hostname itself --
  # a scheme, a trailing slash, or a path. Asking for "just the domain"
  # and then silently accepting "https://example.com/" would produce
  # "https://https://example.com//" in the constants below.
  _WPD=${_WPD#http://}; _WPD=${_WPD#https://}; _WPD=${_WPD%%/*}
  [ -z "$_WPD" ] && { msg_info "No domain set — WordPress will use the VM's IP address."; break; }
  # RFC 1123 hostname: labels of alphanumerics and hyphens, not starting or
  # ending with a hyphen, at least one dot (a bare label like "wordpress"
  # is a valid hostname but never a usable public site address, and is far
  # more likely to be a typo than intent).
  if printf '%s' "$_WPD" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'; then
    WP_DOMAIN="$_WPD"; msg_ok "Site domain: ${WP_DOMAIN}"; break
  fi
  msg_warn "  '${_WPD}' doesn't look like a domain name (expected something like example.com)."
done
unset _WPD

WP_SCHEME="http"
if [[ -n "$WP_DOMAIN" ]]; then
  # Default to https when a reverse proxy was configured, since that's the
  # overwhelmingly common arrangement (NPM/Caddy/nginx terminating TLS and
  # forwarding plain HTTP inward) and getting it wrong causes either mixed
  # content or a redirect loop. Direct-access installs default to http
  # because nothing in this VM terminates TLS on its own.
  if [[ -n "$PROXY_IP" ]]; then
    echo -e "  ${YW}A reverse proxy is configured, so TLS is presumably terminated there${CL}"
    echo -e "  ${YW}and visitors reach the site over https.${CL}"
    read -rp "  Site scheme? [https/http] (default: https) : " _WPS
    case "${_WPS:-https}" in http|HTTP) WP_SCHEME="http" ;; *) WP_SCHEME="https" ;; esac
  else
    echo -e "  ${YW}No reverse proxy was configured. Nothing in this VM terminates TLS,${CL}"
    echo -e "  ${YW}so choose https only if something in front of it will.${CL}"
    read -rp "  Site scheme? [http/https] (default: http) : " _WPS
    case "${_WPS:-http}" in https|HTTPS) WP_SCHEME="https" ;; *) WP_SCHEME="http" ;; esac
  fi
  unset _WPS
  msg_ok "Site address: ${WP_SCHEME}://${WP_DOMAIN}"
  if [[ "$WP_SCHEME" = "https" && -z "$PROXY_IP" ]]; then
    msg_warn "  https with no reverse proxy IP set: WordPress will build https:// URLs,"
    msg_warn "  but this VM only serves plain HTTP on port 80. Make sure whatever"
    msg_warn "  fronts it terminates TLS, or the site will not load correctly."
  fi
fi

# Site title and admin email are cosmetic-but-annoying-to-change-later
# details that the browser wizard would otherwise ask for. Collected here
# only when a domain was given, since an IP-addressed lab VM is usually
# throwaway and doesn't benefit from the extra prompts.
WP_SITE_TITLE=""
WP_ADMIN_EMAIL=""
if [[ -n "$WP_DOMAIN" ]]; then
  read -rp "  Site title [${WP_DOMAIN}] : " WP_SITE_TITLE
  WP_SITE_TITLE="${WP_SITE_TITLE:-$WP_DOMAIN}"
  while :; do
    read -rp "  Admin email for WordPress (recovery/notifications, blank = skip) : " WP_ADMIN_EMAIL
    [ -z "$WP_ADMIN_EMAIL" ] && break
    # Deliberately permissive: enough to catch a typo like a missing @ or a
    # stray space, without pretending to implement RFC 5322.
    if printf '%s' "$WP_ADMIN_EMAIL" | grep -qE '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'; then
      break
    fi
    msg_warn "  '${WP_ADMIN_EMAIL}' doesn't look like an email address."
  done
fi

echo ""
echo -e "  ${BLD}Security features${CL}"
echo -e "  ${YW}Custom wp-admin slug: moves the login page to a secret URL and blocks${CL}"
echo -e "  ${YW}the default /wp-login.php, so credential-stuffing bots hitting the${CL}"
echo -e "  ${YW}standard path get 403 before WordPress or PHP is ever reached.${CL}"
echo -e "  ${YW}Choose something unique (e.g. siteadmin, seclogin, mymsp2024).${CL}"
echo -e "  ${YW}Avoid obvious words: admin, login, dashboard, wp, secure.${CL}"
_sec_head
echo -e "  ${YW}  This is obscurity, and obscurity is worth having here: the${CL}"
echo -e "  ${YW}  overwhelming majority of login attacks are bots that only ever try${CL}"
echo -e "  ${YW}  /wp-login.php. Moving the door means they hit a 403 before PHP or${CL}"
echo -e "  ${YW}  WordPress is reached, so they cost you nothing and never appear in${CL}"
echo -e "  ${YW}  your auth logs as attempts.${CL}"
echo -e "  ${YW}  It stops none of the following: anyone who can read a password-reset${CL}"
echo -e "  ${YW}  email, a leaked link, a plugin that prints the login URL, or the${CL}"
echo -e "  ${YW}  REST API. It is not a secret, it is a filter.${CL}"
echo -e "  ${YW}  Treat it as noise reduction stacked on top of the IP restriction and${CL}"
echo -e "  ${YW}  CrowdSec — never as the thing protecting the account.${CL}"
_sec_note
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
_sec_head
echo -e "  ${YW}  Enrolling links this engine to CrowdSec's console: you get the${CL}"
echo -e "  ${YW}  shared blocklist (addresses already attacking other people) and a${CL}"
echo -e "  ${YW}  dashboard, which is a genuine gain — most attacking IPs hit many${CL}"
echo -e "  ${YW}  sites before yours.${CL}"
echo -e "  ${YW}  It also means signals about attacks on this VM leave it. That is the${CL}"
echo -e "  ${YW}  trade being made, and it is a reasonable one, but it should be a${CL}"
echo -e "  ${YW}  decision rather than a default you did not notice.${CL}"
echo -e "  ${YW}  Skipping loses only the console and the shared blocklist. Local${CL}"
echo -e "  ${YW}  detection and the firewall bouncer work exactly the same either way.${CL}"
_sec_note
read -rsp "  CrowdSec enrolment key (blank = skip, enrol manually later) : " CROWDSEC_ENROLL_KEY; echo

echo ""
echo -e "  ${BLD}GeoIP country filtering (optional — Layer 2 Apache, site-wide)${CL}"
echo -e "  ${YW}Blocks or allows visitors by country before WordPress/PHP ever runs.${CL}"
echo -e "  ${YW}Uses MaxMind's free GeoLite2-Country database via the mod_maxminddb${CL}"
echo -e "  ${YW}Apache module (compiled during install — adds ~2 min, then removed${CL}"
echo -e "  ${YW}build tools to keep the container lean).${CL}"
echo -e "  ${YW}Requires a FREE MaxMind account: https://www.maxmind.com/en/geolite2/signup${CL}"
echo ""
# Same standard as the egress prompt: state the honest bound of the control
# immediately before the person decides whether to rely on it. Country
# filtering looks stronger than it is, and the failure mode of over-trusting
# it is believing a whole class of attacker has been excluded when they have
# not been.
_sec_head
echo -e "  ${YW}  It is very effective against bulk, opportunistic traffic —${CL}"
echo -e "  ${YW}  credential-stuffing and vulnerability-scanning bots — which is${CL}"
echo -e "  ${YW}  most of what reaches a WordPress site. Blocking runs in Apache${CL}"
echo -e "  ${YW}  before PHP starts, so it costs almost nothing.${CL}"
echo -e "  ${YW}  It is trivially bypassed by anyone who chooses to: a VPN, proxy${CL}"
echo -e "  ${YW}  or Tor exit in an allowed country defeats it in seconds. It is${CL}"
echo -e "  ${YW}  a noise filter, not a boundary.${CL}"
echo -e "  ${YW}  It will also block legitimate visitors travelling abroad or on${CL}"
echo -e "  ${YW}  a VPN, and GeoLite2 country data is good but not perfect.${CL}"
echo -e "  ${YW}  Your own LAN and loopback are always exempt, so this cannot${CL}"
echo -e "  ${YW}  lock you out of wp-admin from inside the network.${CL}"
_sec_note
read -rp "  Enable GeoIP country filtering? [y/N] : " GEOIP_ENABLE
GEOIP_ENABLED=0 GEOIP_MODE="" GEOIP_WHITELIST="" GEOIP_BLOCKLIST=""
MAXMIND_ACCOUNT_ID="" MAXMIND_LICENSE_KEY=""
if [[ "${GEOIP_ENABLE:-N}" =~ ^[Yy] ]]; then
  # UX FIX (from a field install): the License Key prompt is a no-echo read,
  # so a paste that silently failed to register looks exactly like typing it
  # correctly. Previously a blank key printed one warning and moved straight
  # on into the digest-pinning explainer, which scrolled it off screen -- the
  # operator answered "y" to GeoIP, saw the summary say "disabled", and had
  # no obvious way to tell why. Re-prompt instead of degrading silently, the
  # same way the production profile re-prompts for a missing SSH key, and
  # make declining an explicit choice rather than an accident.
  while :; do
    read -rp  "  MaxMind Account ID  : " MAXMIND_ACCOUNT_ID
    read -rsp "  MaxMind License Key : " MAXMIND_LICENSE_KEY; echo
    if [[ -n "$MAXMIND_ACCOUNT_ID" && -n "$MAXMIND_LICENSE_KEY" ]]; then
      # Confirm what was actually captured -- length only, never the value.
      msg_ok "  Credentials captured (account ${MAXMIND_ACCOUNT_ID}, key ${#MAXMIND_LICENSE_KEY} chars)"
      break
    fi
    echo ""
    if [[ -z "$MAXMIND_ACCOUNT_ID" && -z "$MAXMIND_LICENSE_KEY" ]]; then
      msg_warn "  Neither value was entered."
    elif [[ -z "$MAXMIND_LICENSE_KEY" ]]; then
      msg_warn "  The License Key came back EMPTY. That prompt does not echo, so a"
      msg_warn "  paste that did not register looks identical to typing it correctly."
    else
      msg_warn "  The Account ID came back empty."
    fi
    msg_warn "  Get both at: https://www.maxmind.com/en/accounts/current/license-key"
    read -rp "  Try again? [Y/n] (n = continue without GeoIP filtering) : " _GEO_RETRY
    if [[ "${_GEO_RETRY:-Y}" =~ ^[Nn] ]]; then
      MAXMIND_ACCOUNT_ID="" MAXMIND_LICENSE_KEY=""
      break
    fi
  done
  unset _GEO_RETRY
  if [[ -z "$MAXMIND_ACCOUNT_ID" || -z "$MAXMIND_LICENSE_KEY" ]]; then
    msg_warn "GeoIP filtering will be SKIPPED — no MaxMind credentials."
    msg_warn "  You can enable it later on the VM, no reinstall needed:"
    msg_warn "    doas /usr/local/bin/wp-geoip-setup.sh"
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
_sec_head
echo -e "  ${YW}  A tag is a moving pointer. Pinning to a digest means the bits you${CL}"
echo -e "  ${YW}  scanned and tested are exactly the bits that run, and that a registry${CL}"
echo -e "  ${YW}  silently repointing a tag cannot change what is deployed under you.${CL}"
echo -e "  ${YW}  It guarantees IDENTITY, not SAFETY. A pinned image with a critical${CL}"
echo -e "  ${YW}  CVE stays pinned to that vulnerable image — pinning is what makes${CL}"
echo -e "  ${YW}  Trivy's verdict meaningful, not a substitute for it.${CL}"
echo -e "  ${YW}  It also means updates are deliberate. That is the point, and it is${CL}"
echo -e "  ${YW}  why 'update.sh digest-check' exists to move you forward on purpose.${CL}"
_sec_note
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
  # FORENSIC FIX (new-audit Medium finding, confirmed reasonable): the same
  # logic applies to SSH. Root login is unconditionally disabled either
  # way, but a production box with no admin SSH key falls back to
  # password auth on that account -- exposed to credential stuffing and
  # online guessing exactly where SSH_CIDR determines how broad that
  # exposure is. Same pattern as digest pinning above: re-ask rather than
  # silently degrade, since the operator already answered this before
  # they'd chosen a profile.
  if [ "$DISABLE_PW_AUTH" != "1" ]; then
    msg_warn "  No SSH key was set, but production profile requires key-only SSH."
    while [ "$DISABLE_PW_AUTH" != "1" ]; do
      echo "  Paste your public key (starts with ssh-ed25519 or ssh-rsa),"
      read -rp "  or a path to a .pub file (required for production) : " _PROD_KEY_INPUT
      if [ -n "$_PROD_KEY_INPUT" ]; then
        if [ -f "$_PROD_KEY_INPUT" ]; then
          SSH_KEYS=$(cat "$_PROD_KEY_INPUT")
        else
          SSH_KEYS="$_PROD_KEY_INPUT"
        fi
      fi
      if [ -n "$SSH_KEYS" ]; then
        DISABLE_PW_AUTH=1
        ADMIN_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 24)
        msg_ok "  SSH key set — password login disabled for ${ADMIN_USER}."
      else
        msg_warn "  Still no key. Production profile can't proceed with password-only SSH."
      fi
    done
  fi
  unset _PROD_KEY_INPUT
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
printf  "  %-18s %s\n"  "Site address:" "$([[ -n "$WP_DOMAIN" ]] && echo "${WP_SCHEME}://${WP_DOMAIN}" || echo "(none — will use the VM IP)")"
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


