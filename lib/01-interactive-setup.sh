#!/usr/bin/env bash
# 01-interactive-setup.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# All interactive prompts: VM ID, root password, hostname, storage/bridge/VLAN, network mode, SSH key/admin account, firewall CIDRs, admin slug, CrowdSec enrolment, GeoIP, digest pinning, deployment profile, and the final confirmation summary.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

# ── Interactive setup ─────────────────────────────────────────────────────────
clear
echo -e "\n${BLD}  WASP — WordPress Alpine Security Platform${CL}"
echo -e "  ${YW}  build ${WASP_VERSION:-unknown}${CL}"
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
echo -e "  ${YW}still have to run it in six months.${CL}"
echo ""
echo -e "  ${BLD}  Who this is for${CL}"
echo -e "  ${YW}  An MSP or consultant hosting client sites, where a compromise${CL}"
echo -e "  ${YW}  is a phone call at 2am and a reputational problem rather than${CL}"
echo -e "  ${YW}  an inconvenience. Anyone running WordPress on their own${CL}"
echo -e "  ${YW}  hardware who would rather not become an incident responder.${CL}"
echo -e "  ${YW}  Anyone who has to show a client what protects their site.${CL}"
echo ""
echo -e "  ${BLD}  Who it is NOT for${CL}"
echo -e "  ${YW}  A throwaway test site — the prompts ahead assume you care${CL}"
echo -e "  ${YW}  about the answers. Shared hosting, where you control none of${CL}"
echo -e "  ${YW}  this. Anyone wanting a one-click install with no decisions:${CL}"
echo -e "  ${YW}  several questions here have consequences worth reading.${CL}"
echo ""
echo -e "  ${YW}The differences follow from that:${CL}"
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
# ── ITEM 1: what you need BEFORE you start ───────────────────────────────────
# Requested after a real install: an operator got several prompts deep before
# discovering they needed an account they did not have, and had to abandon the
# run. Everything optional is marked as such, but knowing which tab or
# password-manager entry to open first is the difference between one sitting
# and three.
echo ""
echo -e "  ${BLD}Before you start — what you will be asked for${CL}"
echo ""
echo -e "  ${BLD}Required${CL}"
echo -e "    • An SSH public key ${YW}(or the installer will show you how to make one)${CL}"
echo -e "    • A VM ID, hostname, and the IP/gateway if you want a static address"
echo -e "    • The CIDR or addresses allowed to reach wp-admin"
echo -e "      ${YW}your own public IP:  curl -s ifconfig.me${CL}"
echo ""
echo -e "  ${BLD}Optional — have these open if you want them${CL}"
echo -e "    • ${BLD}SMTP relay${CL}  host, port, username, password"
echo -e "      ${YW}without it there are no alert emails at all${CL}"
echo -e "    • ${BLD}CrowdSec Console${CL}  https://app.crowdsec.net"
echo -e "      ${YW}enrolment key (Security Engines → Enroll) and, separately,${CL}"
echo -e "      ${YW}a CTI API key + its quota (Settings → CTI API Keys)${CL}"
echo -e "    • ${BLD}Wordfence Intelligence${CL}  https://www.wordfence.com/threat-intel/"
echo -e "      ${YW}free API token for plugin CVE data${CL}"
echo -e "    • ${BLD}MaxMind${CL}  https://www.maxmind.com/en/geolite2/signup"
echo -e "      ${YW}free account ID + licence key, only if you want GeoIP filtering${CL}"
echo -e "    • ${BLD}Which page builder you use${CL}  Elementor, Divi, Kadence…"
echo -e "      ${YW}so its licence server can be allowed through the egress proxy${CL}"
echo -e "    • ${BLD}Off-site backup${CL}  an S3/R2 bucket, or an SSH target"
echo -e "      ${YW}Cloudflare R2 and Backblaze B2 both have usable free tiers${CL}"
echo ""
echo -e "  ${YW}  Every optional item can be added later; none of them blocks the${CL}"
echo -e "  ${YW}  install. But each one you skip is a control that is not running.${CL}"
echo ""
echo -e "  ${YW}  Budget 15-20 minutes of prompts, then ~15 minutes unattended.${CL}"
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
  # ── Resolver choice ────────────────────────────────────────────────────────
  # The default used to be 1.1.1.1 + 8.8.8.8. Both are fast and reliable, and
  # both are the wrong default for this product: Cloudflare and Google are US
  # (Five Eyes) operators whose business is not DNS, and on a box built to
  # minimise what leaks, every domain this VM ever looks up is exactly the kind
  # of metadata worth not handing over by default.
  #
  # Quad9 is the default instead, and the reason is not only privacy. It
  # BLOCKS KNOWN-MALICIOUS DOMAINS using threat intelligence, which is a real
  # security layer on a WordPress host: a compromised plugin phoning home to a
  # known C2 domain fails at resolution, before Squid, before nftables. It does
  # not log client IPs, is GDPR-compliant, validates DNSSEC, and answers from
  # 200+ locations across 90 countries, so it performs acceptably wherever the
  # Proxmox host happens to be.
  #
  # Everything offered below serves PLAIN DNS on port 53, because that is what
  # /etc/resolv.conf needs. This rules out several otherwise-excellent
  # providers, and the exclusion is not a judgement on them:
  #
  #   * Mullvad          DoH/DoT ONLY. Its own documentation is explicit that
  #                      the IPs "can only be used with DNS resolvers that
  #                      support DoH or DoT, not with DNS over UDP/53 or
  #                      TCP/53". Offering it here would have produced a VM
  #                      with no working DNS at all.
  #   * Applied Privacy  DoH/DoT only.
  #   * Wikimedia DNS    DoH/DoT only.
  #
  # If this VM ever grows a local DoH/DoT stub resolver, they become viable and
  # should be revisited. Until then, do not add them back.
  echo ""
  echo -e "  ${BLD}DNS resolver for this VM${CL}"
  echo -e "  ${YW}Every domain this VM resolves is visible to whoever runs the${CL}"
  echo -e "  ${YW}resolver. A resolver that also blocks known-malicious domains${CL}"
  echo -e "  ${YW}stops a compromised plugin reaching its C2 before any other${CL}"
  echo -e "  ${YW}control in this stack gets involved.${CL}"
  echo ""
  echo -e "  ${BLD}Global${CL} — pick these unless you have a reason not to"
  echo "    1) Quad9              9.9.9.9  149.112.112.112   (recommended)"
  echo "         blocks malicious domains, no IP logging, DNSSEC, 90 countries"
  echo "         Swiss-based non-profit — outside Five/Nine/Fourteen Eyes"
  echo "    2) AdGuard DNS        94.140.14.14  94.140.15.15"
  echo "         also blocks ads and trackers; 15+ locations"
  echo "    3) Control D          76.76.2.0  76.76.10.0"
  echo "         free tier keeps no logs or timestamps; anycast"
  echo "    4) DNS.SB             185.222.222.222  45.11.45.11"
  echo "         no logging, no filtering, 30 locations, yearly transparency report"
  echo ""
  echo -e "  ${BLD}Europe${CL} — lower latency if the Proxmox host is in the EU"
  echo "    5) DNS4EU             86.54.11.100  86.54.11.200"
  echo "         EU-funded, GDPR, IPs anonymised; 1-2ms in Europe"
  echo "    6) FFMUC              5.1.66.255  185.150.99.255"
  echo "         non-profit, no logging, no tracking"
  echo "    7) UncensoredDNS      91.239.100.100  89.233.43.71"
  echo "         zero logging, warrant canary (Denmark)"
  echo ""
  echo -e "  ${BLD}Regional${CL}"
  echo "    8) CIRA Shield        149.112.121.10  149.112.122.10"
  echo "         malware/phishing blocking (Canada; slow elsewhere)"
  echo ""
  echo "    9) Enter your own"
  echo ""
  echo -e "  ${YW}Not offered: 1.1.1.1 and 8.8.8.8. Both are US Five-Eyes${CL}"
  echo -e "  ${YW}operators; choose 9 if you specifically need them.${CL}"
  echo ""
  read -rp "  Resolver [1] : " _DNSC
  case "${_DNSC:-1}" in
    1)  VM_DNS="9.9.9.9 149.112.112.112" ;;
    2)  VM_DNS="94.140.14.14 94.140.15.15" ;;
    3)  VM_DNS="76.76.2.0 76.76.10.0" ;;
    4)  VM_DNS="185.222.222.222 45.11.45.11" ;;
    5)  VM_DNS="86.54.11.100 86.54.11.200" ;;
    6)  VM_DNS="5.1.66.255 185.150.99.255" ;;
    7)  VM_DNS="91.239.100.100 89.233.43.71" ;;
    8)  VM_DNS="149.112.121.10 149.112.122.10" ;;
    9)
      while true; do
        read -rp "  DNS servers, space-separated : " VM_DNS
        VM_DNS="${VM_DNS:-9.9.9.9 149.112.112.112}"
        _dns_bad=0
        for _d in $VM_DNS; do
          _valid_ipv4 "$_d" || { _dns_bad=1; echo -e "  ${RD}'${_d}' is not a valid IPv4 address.${CL}"; }
        done
        [ "$_dns_bad" = "0" ] && break
      done
      case "$VM_DNS" in
        *1.1.1.1*|*8.8.8.8*|*8.8.4.4*|*1.0.0.1*)
          msg_warn "  Cloudflare/Google chosen deliberately — noted." ;;
      esac ;;
    *)  VM_DNS="9.9.9.9 149.112.112.112"
        msg_warn "  Unrecognised choice — using Quad9." ;;
  esac
  unset _DNSC _dns_bad _d
  msg_ok "DNS: ${VM_DNS}"
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
echo ""
echo -e "  ${BLD}Don't have a key yet?${CL} Generate one on the machine you will connect FROM"
echo -e "  ${YW}(not on this Proxmox host). It takes about ten seconds.${CL}"
echo ""
echo -e "  ${BLD}Linux / macOS${CL} — terminal:"
echo "      ssh-keygen -t ed25519 -C \"\$(whoami)@\$(hostname)-wasp\" -f ~/.ssh/wasp_ed25519"
echo "      cat ~/.ssh/wasp_ed25519.pub          # copy this whole line"
echo ""
echo -e "  ${BLD}Windows 10/11${CL} — PowerShell (OpenSSH is built in):"
echo "      ssh-keygen -t ed25519 -C \"\$env:USERNAME@\$env:COMPUTERNAME-wasp\" -f \$env:USERPROFILE\\.ssh\\wasp_ed25519"
echo "      Get-Content \$env:USERPROFILE\\.ssh\\wasp_ed25519.pub | Set-Clipboard"
echo ""
echo -e "  ${YW}Naming it (-f …/wasp_ed25519) rather than overwriting the default${CL}"
echo -e "  ${YW}id_ed25519 keeps this VM's access separate from every other host${CL}"
echo -e "  ${YW}you reach — you can revoke it without breaking anything else. Give${CL}"
echo -e "  ${YW}it a passphrase when prompted; a stolen laptop should not be a${CL}"
echo -e "  ${YW}stolen server.${CL}"
echo ""
echo -e "  ${YW}Paste the .pub line (public, safe to share). NEVER paste the file${CL}"
echo -e "  ${YW}without .pub — that is the private half and must never leave the${CL}"
echo -e "  ${YW}machine that generated it.${CL}"
echo ""
echo -e "  ${YW}Then connect with:  ssh -i ~/.ssh/wasp_ed25519 <admin>@<this-vm-ip>${CL}"
echo ""
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
_ask_ip_list() {  # $1 prompt ; echoes SPACE-separated validated IPv4s (may be empty)
  # Apache's `Require ip` takes a space-separated list natively, so several
  # addresses cost nothing structurally -- the previous single-IP limit was
  # arbitrary, and an MSP realistically has an office IP, a home IP, and one
  # per travelling admin. Commas are accepted because that is how people
  # naturally type a list; they are normalised to spaces.
  local _p="$1" _v _one _bad _out
  while :; do
    printf '%s' "$_p" >&2
    IFS= read -r _v
    [ -z "$_v" ] && { printf ''; return 0; }
    _v=$(printf '%s' "$_v" | tr ',;' '  ')
    _bad=0; _out=""
    for _one in $_v; do
      case "$_one" in
        */*) echo -e "  ${RD}'${_one}' looks like a CIDR range. This field takes single addresses; use the CIDR question above for a range.${CL}" >&2; _bad=1; continue ;;
      esac
      if _v15_valid_ipv4 "$_one"; then
        _out="${_out:+$_out }$_one"
      else
        echo -e "  ${RD}'${_one}' is not a valid IPv4 address.${CL}" >&2; _bad=1
      fi
    done
    if [ "$_bad" = "0" ] && [ -n "$_out" ]; then printf '%s' "$_out"; return 0; fi
    echo -e "  ${YW}Try again, or leave blank for none.${CL}" >&2
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
_sec_head
echo -e "  ${YW}  Almost every site should leave this BLANK. A public website that${CL}"
echo -e "  ${YW}  only answers a single network is not a public website — visitors,${CL}"
echo -e "  ${YW}  search engines and uptime monitors all get dropped at the packet${CL}"
echo -e "  ${YW}  level, silently, with no error page to explain it.${CL}"
echo -e "  ${YW}  It is the right answer for a staging or internal site that genuinely${CL}"
echo -e "  ${YW}  should not be reachable from the internet, and for a site behind a${CL}"
echo -e "  ${YW}  reverse proxy where you can restrict this to the proxy's address${CL}"
echo -e "  ${YW}  alone — then nothing can bypass the proxy by hitting the VM directly.${CL}"
echo -e "  ${YW}  Note this is Layer 1 and blocks EVERYTHING, including the front page.${CL}"
echo -e "  ${YW}  It is not the wp-admin restriction — that is asked separately below and${CL}"
echo -e "  ${YW}  is what protects the login page while leaving the site public.${CL}"
echo -e "  ${YW}  Leaving it blank is not 'no protection': CrowdSec, the 8G firewall,${CL}"
echo -e "  ${YW}  the wp-admin IP rules and the login rate limiter all still apply.${CL}"
_sec_note
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
echo ""
echo -e "  ${YW}  Additional individual addresses that may reach wp-admin, on top of${CL}"
echo -e "  ${YW}  the CIDR above. Typical entries:${CL}"
echo -e "  ${YW}    • your own public IP, so you can administer from outside the LAN${CL}"
echo -e "  ${YW}      (find it with: curl -s ifconfig.me)${CL}"
echo -e "  ${YW}    • a colleague or client admin working from a different office${CL}"
echo -e "  ${YW}    • a static VPN exit address your team connects through${CL}"
echo -e "  ${YW}  Several are fine — separate them with commas or spaces:${CL}"
echo -e "  ${YW}    203.0.113.5, 198.51.100.20, 192.0.2.44${CL}"
echo -e "  ${YW}  Leave blank if the CIDR above already covers everyone. Anything${CL}"
echo -e "  ${YW}  not listed gets a 403 on wp-admin, so a dynamic home IP is worth${CL}"
echo -e "  ${YW}  thinking about — you can add more later with:${CL}"
echo -e "  ${YW}    wp-hardening.sh admin-rule${CL}"
ALLOWED_ADMIN_IP=$(_ask_ip_list "  Additional IP(s) for wp-admin (blank = none) : ")
echo ""
echo -e "  ${BLD}Layer 2b — mod_remoteip (only needed if behind a reverse proxy):${CL}"
echo -e "  ${YW}If WordPress is behind NPM / nginx / Caddy, Apache sees the proxy IP${CL}"
echo -e "  ${YW}not the real client IP. Enter the proxy's internal IP so Apache trusts${CL}"
echo -e "  ${YW}its X-Forwarded-For header for accurate wp-admin IP checks.${CL}"
PROXY_IP=$(_ask_single_ip "  Reverse proxy IP (e.g. 192.168.1.50, blank = direct access) : ")

# Flag the combination that turns a mod_remoteip failure into "allow everyone".
# A proxy on the LAN is normally inside the operator's own admin CIDR, and when
# that is true the wp-admin restriction cannot fail safely on its own -- if the
# real client address is not substituted, every request looks like it came from
# an allowed address. lib/03 now emits a `Require not ip <proxy>` rule that
# makes it fail closed; this says so, because a control that silently stopped
# applying is worth knowing about even when it is handled.
if [[ -n "$PROXY_IP" && -n "$ADMIN_CIDR" ]]; then
  _pi=$(printf '%s' "$PROXY_IP" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')
  _net="${ADMIN_CIDR%%/*}"; _bits="${ADMIN_CIDR##*/}"
  case "$ADMIN_CIDR" in */*) : ;; *) _bits=32 ;; esac
  _ni=$(printf '%s' "$_net" | awk -F. '{printf "%d", ($1*16777216)+($2*65536)+($3*256)+$4}')
  if [[ "$_bits" -ge 0 && "$_bits" -le 32 ]]; then
    _mask=$(( _bits == 0 ? 0 : (0xFFFFFFFF << (32 - _bits)) & 0xFFFFFFFF ))
    if [[ $(( _pi & _mask )) -eq $(( _ni & _mask )) ]]; then
      echo ""
      msg_warn "The proxy (${PROXY_IP}) is inside your wp-admin range (${ADMIN_CIDR})."
      msg_warn "  That matters: if mod_remoteip ever stops substituting the real"
      msg_warn "  client address, every request would look like it came from the"
      msg_warn "  proxy — which is an allowed address. The restriction would"
      msg_warn "  silently permit everyone rather than deny everyone, so nothing"
      msg_warn "  would look wrong."
      msg_ok  "  Handled: the generated rules deny the proxy's own address, so"
      msg_ok  "  that failure produces 403 instead. You cannot administer"
      msg_ok  "  WordPress from a shell on the proxy host itself."
      msg_info "  Verify after install:  wp-hardening.sh proxy-check"
    fi
  fi
  unset _pi _net _bits _ni _mask
fi

# Offer to lock port 80/443 to the proxy now that its address is known.
# The Web CIDR question is asked earlier, before this answer exists, so
# without this the operator has to already know the proxy IP at that point --
# and the single best answer to that question is exactly this address.
if [[ -n "$PROXY_IP" && -z "$WEB_CIDR" ]]; then
  echo ""
  echo -e "  ${BLD}Restrict web traffic to this proxy only?${CL}"
  echo -e "  ${YW}You said earlier that ports 80/443 accept any source. Now that${CL}"
  echo -e "  ${YW}the proxy address is known, they can be narrowed to it alone.${CL}"
  _sec_head
  echo -e "  ${YW}  It stops anyone reaching the site by its IP and bypassing the${CL}"
  echo -e "  ${YW}  proxy entirely — which also bypasses whatever the proxy does:${CL}"
  echo -e "  ${YW}  TLS termination, its own rate limits, its access rules, and${CL}"
  echo -e "  ${YW}  the X-Forwarded-For header this VM relies on to see real${CL}"
  echo -e "  ${YW}  client addresses. Without it, the proxy is the front door and${CL}"
  echo -e "  ${YW}  the VM's own IP is an unlocked side door.${CL}"
  echo -e "  ${YW}  Two consequences worth knowing before you say yes:${CL}"
  echo -e "  ${YW}    • You can no longer test by browsing to the VM's IP. Every${CL}"
  echo -e "  ${YW}      check has to go through the domain.${CL}"
  echo -e "  ${YW}    • If the proxy's address ever changes, the site goes dark${CL}"
  echo -e "  ${YW}      until this rule is updated — the failure is silent, at${CL}"
  echo -e "  ${YW}      the packet level, with no error page to explain it.${CL}"
  echo -e "  ${YW}  Fix either from the console: wp-hardening.sh (or edit${CL}"
  echo -e "  ${YW}  /etc/nftables.nft and reload).${CL}"
  _sec_note
  read -rp "  Restrict 80/443 to ${PROXY_IP} only? [y/N] : " _WLOCK
  case "${_WLOCK}" in
    y|Y|yes|YES)
      WEB_CIDR="${PROXY_IP}"
      # Offer to keep a direct path for admin work. Restricting to the proxy
      # ALONE means every admin request depends on mod_remoteip substituting
      # the real client address from X-Forwarded-For — and when that stops
      # working the result is a 403 with no obvious cause, from a VM that
      # serves the public site perfectly.
      #
      # Allowing the operator's own addresses directly removes that
      # dependency for admin work entirely: no proxy in the path means
      # nothing to substitute. External visitors are still funnelled through
      # the proxy, because their addresses are not in the list.
      _extra=""
      [[ -n "$ADMIN_CIDR" && "$ADMIN_CIDR" != "$PROXY_IP" ]] && _extra="$ADMIN_CIDR"
      [[ -n "$ALLOWED_ADMIN_IP" ]] && _extra="${_extra:+$_extra,}$ALLOWED_ADMIN_IP"
      if [[ -n "$_extra" ]]; then
        echo ""
        echo -e "  ${YW}  Also allow direct access from your admin addresses?${CL}"
        echo -e "  ${YW}    ${_extra}${CL}"
        echo -e "  ${YW}  External visitors still have to come through the proxy —${CL}"
        echo -e "  ${YW}  their addresses are not on this list. What it buys you is a${CL}"
        echo -e "  ${YW}  path to wp-admin that does NOT depend on the proxy passing${CL}"
        echo -e "  ${YW}  X-Forwarded-For correctly. If that ever breaks, you get a${CL}"
        echo -e "  ${YW}  403 on a site that otherwise looks completely healthy, and${CL}"
        echo -e "  ${YW}  this is the way back in.${CL}"
        echo -e "  ${YW}  Saying no is defensible if nothing should ever reach the VM${CL}"
        echo -e "  ${YW}  except the proxy — keep the Proxmox console to hand.${CL}"
        read -rp "  Allow direct admin access too? [Y/n] : " _WADM
        case "${_WADM:-y}" in
          n|N) msg_ok "Web ports restricted to ${PROXY_IP} only" ;;
          *)   WEB_CIDR="${PROXY_IP},${_extra}"
               msg_ok "Web ports allow: ${WEB_CIDR}"
               msg_info "  Visitors funnel through the proxy; you can also reach the VM directly." ;;
        esac
        unset _WADM
      else
        msg_ok "Web ports restricted to ${PROXY_IP} — the VM's IP is no longer directly reachable"
      fi
      unset _extra ;;
    *) msg_ok "Web ports remain open to any source (the proxy is the intended path, not the enforced one)" ;;
  esac
  unset _WLOCK
fi

# ── CrowdSec whitelist ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}CrowdSec whitelist — addresses that must never be banned${CL}"
echo -e "  ${YW}CrowdSec does not just block a login form. It bans at nftables,${CL}"
echo -e "  ${YW}which drops EVERY packet from that address — HTTP, and SSH with${CL}"
echo -e "  ${YW}it. Mistype an admin password five times from your workstation${CL}"
echo -e "  ${YW}and you are locked out of the VM entirely, recoverable only from${CL}"
echo -e "  ${YW}the Proxmox console.${CL}"
echo ""
if [[ -n "$PROXY_IP" ]]; then
  echo -e "  ${RD}  You configured a reverse proxy at ${PROXY_IP}.${CL}"
  echo -e "  ${YW}  If that address is ever banned, the site goes down for EVERY${CL}"
  echo -e "  ${YW}  visitor at once, because all traffic arrives from it. Including${CL}"
  echo -e "  ${YW}  it here is strongly advised.${CL}"
  echo ""
fi
echo -e "  ${YW}From what you have already told this installer:${CL}"
[[ -n "$PROXY_IP" ]]          && echo -e "  ${YW}    reverse proxy   : ${PROXY_IP}${CL}"
[[ -n "$SSH_CIDR" ]]          && echo -e "  ${YW}    SSH allowed from: ${SSH_CIDR}${CL}"
[[ -n "$ALLOWED_ADMIN_IP" ]]  && echo -e "  ${YW}    wp-admin extra IP: ${ALLOWED_ADMIN_IP}${CL}"
[[ -n "$ADMIN_CIDR" ]]        && echo -e "  ${YW}    wp-admin network : ${ADMIN_CIDR}${CL}"
echo ""
_sec_head
echo -e "  ${YW}  It prevents you locking yourself out. That is its purpose, and${CL}"
echo -e "  ${YW}  it is a real one — this is the most likely way to lose access${CL}"
echo -e "  ${YW}  to a working VM.${CL}"
echo -e "  ${YW}  It also means anything at those addresses can brute-force this${CL}"
echo -e "  ${YW}  site indefinitely without being blocked. Whitelisting a whole${CL}"
echo -e "  ${YW}  /24 trusts every device on it, including the laptop that gets${CL}"
echo -e "  ${YW}  malware. Prefer single addresses over ranges where you can.${CL}"
echo -e "  ${YW}  Alerts are still raised for whitelisted addresses — only the${CL}"
echo -e "  ${YW}  ban is suppressed — so a compromised machine of your own is${CL}"
echo -e "  ${YW}  still visible in 'cscli alerts list'.${CL}"
_sec_note
_CS_DEFAULT=""
[[ -n "$PROXY_IP" ]] && _CS_DEFAULT="$PROXY_IP"
[[ -n "$ALLOWED_ADMIN_IP" ]] && _CS_DEFAULT="${_CS_DEFAULT:+$_CS_DEFAULT,}$ALLOWED_ADMIN_IP"
CROWDSEC_WHITELIST=""
while :; do
  if [[ -n "$_CS_DEFAULT" ]]; then
    read -rp "  Never-ban addresses, comma-separated [${_CS_DEFAULT}] : " _CSW
    _CSW="${_CSW:-$_CS_DEFAULT}"
  else
    read -rp "  Never-ban addresses, comma-separated (blank = none) : " _CSW
  fi
  [[ -z "$_CSW" ]] && { msg_warn "No whitelist — a banned admin address locks you out until you use the console."; break; }
  _bad=""
  _clean=""
  _oldIFS="$IFS"; IFS=','
  for _e in $_CSW; do
    IFS="$_oldIFS"
    _e=$(printf '%s' "$_e" | tr -d '[:space:]')
    [[ -z "$_e" ]] && continue
    # Accept a bare IPv4 or an IPv4/CIDR. Anything else is a typo, and a typo
    # here fails silently later: CrowdSec loads the file, ignores the bad
    # entry, and the address you thought was protected simply is not.
    if printf '%s' "$_e" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
      _clean="${_clean:+$_clean,}$_e"
    else
      _bad="${_bad:+$_bad, }$_e"
    fi
    IFS=','
  done
  IFS="$_oldIFS"
  if [[ -n "$_bad" ]]; then
    msg_warn "  Not a valid IPv4 address or CIDR: ${_bad}"
    continue
  fi
  CROWDSEC_WHITELIST="$_clean"
  msg_ok "CrowdSec will never ban: ${CROWDSEC_WHITELIST}"
  break
done
unset _CSW _CS_DEFAULT _bad _clean _e _oldIFS

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
    # ── Collect, then REVIEW ────────────────────────────────────────────────
    # Reported from a real install: a typo in the username ("...@rothitguy-pro"
    # instead of ".pro") could not be corrected, because a linear prompt flow
    # has no way back and the only escape was to abort the whole installer.
    # This section has the most fields and the most typo-prone ones, so it now
    # ends in a review step: everything is shown back, and any single field can
    # be re-entered by number without touching the others. Answering blank
    # accepts and moves on, so the fast path is unchanged for anyone who typed
    # it correctly the first time.
    _smtp_collect_all=1
    while :; do
      if [ "$_smtp_collect_all" = "1" ]; then
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
        _smtp_collect_all=0
      fi

      echo ""
      echo -e "  ${BLD}Check these before continuing:${CL}"
      printf "    1) Server      %s\n"  "$SMTP_HOST"
      printf "    2) Port        %s (%s)\n" "$SMTP_PORT" "$SMTP_ENCRYPTION"
      printf "    3) Username    %s\n"  "$SMTP_USER"
      printf "    4) Password    %s\n"  "$(printf '%*s' "${#SMTP_PASS}" '' | tr ' ' '*')"
      printf "    5) From        %s\n"  "$SMTP_FROM"
      printf "    6) From name   %s\n"  "$SMTP_FROM_NAME"
      echo ""
      read -rp "  Enter a number to change it, or press Enter to accept : " _SFIX
      case "${_SFIX}" in
        '') break ;;
        1) while :; do
             read -rp "  SMTP server hostname : " SMTP_HOST
             SMTP_HOST=$(printf '%s' "$SMTP_HOST" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
             [ -n "$SMTP_HOST" ] && break
             msg_warn "  A hostname is required."
           done ;;
        2) read -rp "  SMTP port [587/465] : " _SP
           case "${_SP:-587}" in
             465) SMTP_PORT="465"; SMTP_ENCRYPTION="ssl" ;;
             *)   SMTP_PORT="587"; SMTP_ENCRYPTION="tls" ;;
           esac ;;
        3) read -rp "  SMTP username (full mailbox address) : " SMTP_USER
           # The From address usually tracks the username; offer to follow it
           # rather than leave a stale value behind after a correction.
           if [ -n "$SMTP_USER" ] && [ "$SMTP_FROM" != "$SMTP_USER" ]; then
             read -rp "  Set From address to ${SMTP_USER} too? [Y/n] : " _SF
             case "${_SF}" in n|N|no|NO) : ;; *) SMTP_FROM="$SMTP_USER" ;; esac
           fi ;;
        4) while :; do
             read -rsp "  SMTP password / app password : " SMTP_PASS; echo
             [ -n "$SMTP_PASS" ] && break
             msg_warn "  Password cannot be empty."
           done ;;
        5) read -rp "  From address [${SMTP_USER}] : " SMTP_FROM
           SMTP_FROM="${SMTP_FROM:-$SMTP_USER}" ;;
        6) read -rp "  From name [${WP_SITE_TITLE:-WordPress}] : " SMTP_FROM_NAME
           SMTP_FROM_NAME="${SMTP_FROM_NAME:-${WP_SITE_TITLE:-WordPress}}" ;;
        *) msg_warn "  Enter 1-6, or press Enter to accept." ;;
      esac
    done
    unset _SFIX _SP _SF _smtp_collect_all
    # `${SMTP_USER}@${SMTP_HOST}` produced "contact@rothitguy.pro@mail.example.com"
    # on a real install, because the username IS an email address. The config
    # itself was correct (user and host are separate keys in the msmtp file) --
    # this was display only, but a summary line that looks malformed makes an
    # operator doubt the config it is summarising.
    msg_ok "SMTP: ${SMTP_USER} via ${SMTP_HOST}:${SMTP_PORT} (${SMTP_ENCRYPTION}), from ${SMTP_FROM}"
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

# The SITE TITLE prompt used to be here and has been removed. It claimed to
# save you retyping it in the browser wizard, but nothing ever applied it --
# WordPress asked again anyway, so it was pure duplicate typing. (Reported
# from a real install: "what is the point if I have to retype that during
# WordPress setup?" -- a fair question with no good answer.) The From-name
# for outbound mail now defaults from the domain instead.
WP_SITE_TITLE="${WP_DOMAIN:-WordPress}"
WP_ADMIN_EMAIL=""
if [[ -n "$WP_DOMAIN" ]]; then
  # NOT the WordPress admin email. This one is genuinely different and is not
  # duplicate typing: it is where THE VM ITSELF sends operational alerts --
  # backup failures, malware findings, vulnerability reports, the heartbeat.
  # For an MSP that is usually your address, not the client's, and it must
  # keep working even when WordPress is down, which is why it is host-side
  # and separate from anything configured inside WordPress.
  echo ""
  echo -e "  ${BLD}Where should this VM send its own alerts?${CL}"
  echo -e "  ${YW}This is NOT the WordPress admin email you will set in the setup${CL}"
  echo -e "  ${YW}wizard. It is the operator address for backup failures, malware${CL}"
  echo -e "  ${YW}findings and the heartbeat -- alerts that must arrive even when${CL}"
  echo -e "  ${YW}WordPress itself is broken. For an MSP this is usually you, not${CL}"
  echo -e "  ${YW}the client.${CL}"
  while :; do
    read -rp "  Operator alert email (blank = syslog only) : " WP_ADMIN_EMAIL
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
# Wrapped in a loop so a rejected slug re-prompts. Previously a collision
# silently cleared the answer and carried on with no slug at all -- the
# operator asked for one, was told it was ignored, and the install proceeded
# with the default path. Asking again is the obviously right behaviour and
# was simply missing.
while :; do
read -rp "  Custom login slug?  (blank = keep default /wp-login.php) : " WP_ADMIN_SLUG
# Sanitise: lowercase, alphanumeric + hyphen only
WP_ADMIN_SLUG=$(echo "${WP_ADMIN_SLUG}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed 's/^-//;s/-$//')
[[ -z "$WP_ADMIN_SLUG" ]] && break
# BUG FIX (v7-14): reject slugs that collide with a real WordPress path.
# A slug of "wp-content", "wp-admin", "wp-includes" or similar would have
# its RewriteRule shadow (or be shadowed by) the real directory, producing
# a site that half-works in ways that are extremely hard to diagnose — the
# rewrite fires for some paths and the real directory wins for others.
case "$WP_ADMIN_SLUG" in
  # Reject anything containing a word a scanner would glob for. A slug like
  # "edith-login" or "myadmin" is found by the same wordlist that finds
  # wp-login.php, so it hides the page from nobody -- which is the entire
  # point of choosing one. Checked as a substring, not an exact match.
  *login*|*admin*|*signin*|*log-in*|*wp-*|*auth*|*dashboard*|*panel*)
    msg_warn "  '${WP_ADMIN_SLUG}' contains a word scanners look for."
    msg_warn "  A slug is only worth having if it is not in the wordlist that"
    msg_warn "  finds wp-login.php in the first place. Anything matching"
    msg_warn "  *login*, *admin*, *auth*, *panel* or *dashboard* is."
    msg_warn "  Pick an unrelated word: a place, a colour, an inside joke."
    WP_ADMIN_SLUG=""
    continue ;;
  wp-includes|wp-content|wp-json|index|xmlrpc|feed)
    msg_warn "  '${WP_ADMIN_SLUG}' collides with a real WordPress path."
    msg_warn "  Its rewrite would shadow, or be shadowed by, the real directory —"
    msg_warn "  producing a site that half-works in ways that are hard to trace."
    WP_ADMIN_SLUG=""
    continue ;;
esac
break
done
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  msg_ok "Login URL: /${WP_ADMIN_SLUG}   (wp-admin at /${WP_ADMIN_SLUG}/...)"
  msg_ok "  /wp-login.php now returns 403"
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
echo -e "  ${YW}  You will be asked for a SECOND CrowdSec value later in this run --${CL}"
echo -e "  ${YW}  a CTI API key, for enriching bans with reputation data. Both come${CL}"
echo -e "  ${YW}  from the same console, so copy both now and you will not have to${CL}"
echo -e "  ${YW}  go back to it:${CL}"
echo -e "  ${YW}    enrolment key : Security Engines → Enroll${CL}"
echo -e "  ${YW}    CTI API key   : Settings → CTI API Keys  (note its quota too)${CL}"
read -rsp "  CrowdSec enrolment key (blank = skip, enrol manually later) : " CROWDSEC_ENROLL_KEY; echo

# ── ClamAV (optional malware signature layer) ────────────────────────────────
echo ""
echo -e "  ${BLD}Install ClamAV?${CL}"
echo -e "  ${YW}This VM already scans for malware without it: PHP in the uploads${CL}"
echo -e "  ${YW}directory, WordPress core compared byte-for-byte against the${CL}"
echo -e "  ${YW}pinned image, YARA webshell rules, and database analysis.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  ClamAV is not the backbone of WordPress malware detection, and${CL}"
echo -e "  ${YW}  that is the real reason it is optional rather than the memory${CL}"
echo -e "  ${YW}  cost. It is a general-purpose, signature-driven file scanner${CL}"
echo -e "  ${YW}  built largely for email attachments. Its coverage of modern,${CL}"
echo -e "  ${YW}  obfuscated PHP webshells is weak next to the YARA rules here,${CL}"
echo -e "  ${YW}  which were written specifically for that shape of threat.${CL}"
echo -e "  ${YW}  It also false-positives on some minified JavaScript, and a${CL}"
echo -e "  ${YW}  WordPress site is full of minified plugin assets — noise you${CL}"
echo -e "  ${YW}  have to triage is how a scanner stops being read.${CL}"
echo -e "  ${YW}  Its signatures need refreshing (freshclam) to stay meaningful;${CL}"
echo -e "  ${YW}  a stale AV database is worse than none, because it looks like${CL}"
echo -e "  ${YW}  coverage.${CL}"
echo ""
echo -e "  ${YW}  Where it genuinely earns its place: sites that accept file${CL}"
echo -e "  ${YW}  uploads from visitors, where a user might post a real malware${CL}"
echo -e "  ${YW}  binary rather than a PHP shell; catching non-PHP payloads such${CL}"
echo -e "  ${YW}  as dropped ELF binaries, which YARA rules here do not target;${CL}"
echo -e "  ${YW}  and compliance regimes that simply require an AV product.${CL}"
echo -e "  ${YW}  Costs roughly 1 GB resident for the signature database, and a${CL}"
echo -e "  ${YW}  full scan takes minutes — so it is on-demand and weekly, never${CL}"
echo -e "  ${YW}  part of the daily job.${CL}"
_sec_note
INSTALL_CLAMAV=0
read -rp "  Install ClamAV? [y/N] : " _CLAM
case "${_CLAM}" in
  y|Y|yes|YES) INSTALL_CLAMAV=1
    msg_ok "ClamAV will be installed (signatures fetched on first run)"
    msg_info "  Scan on demand: wp-malware-scan.sh clamav" ;;
  *) msg_ok "ClamAV skipped — structural, core-integrity, YARA and database layers still run" ;;
esac
unset _CLAM

# ── Off-VM backup ────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Copy backups off this VM?${CL}"
echo -e "  ${YW}Nightly database backups are written to this VM's own disk. That${CL}"
echo -e "  ${YW}covers a bad update or a dropped table. It does not cover losing${CL}"
echo -e "  ${YW}the VM, the disk, or the hypervisor — and it does not cover${CL}"
echo -e "  ${YW}someone deleting the backups along with everything else.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  Sending a copy elsewhere protects against disk failure, a lost${CL}"
echo -e "  ${YW}  VM, and a bad restore. That alone is worth doing.${CL}"
echo -e "  ${YW}  It does NOT by itself protect against an attacker who gets root${CL}"
echo -e "  ${YW}  here, because this VM must hold a credential that can reach the${CL}"
echo -e "  ${YW}  destination — so they can reach it too. Encrypting the site and${CL}"
echo -e "  ${YW}  then wiping the backups is the standard pattern, not an exotic${CL}"
echo -e "  ${YW}  one.${CL}"
echo -e "  ${YW}  What closes that gap is an APPEND-ONLY destination: a key that${CL}"
echo -e "  ${YW}  can add files but not delete them.${CL}"
echo -e "  ${YW}    SSH : command=\"rrsync -no-del /path\",restrict in authorized_keys${CL}"
echo -e "  ${YW}    S3  : deny s3:DeleteObject, enable Versioning + Object Lock${CL}"
echo -e "  ${YW}  You are asked below whether you have done that. Answering${CL}"
echo -e "  ${YW}  honestly matters more than answering yes — the status output${CL}"
echo -e "  ${YW}  tells you which kind of protection you actually have.${CL}"
echo -e "  ${YW}  The credential is stored root-only, so WordPress (uid 33)${CL}"
echo -e "  ${YW}  cannot read it. A web-app compromise alone does not reach it.${CL}"
_sec_note
OFFSITE_METHOD="none"; OFFSITE_DEST=""; OFFSITE_KEY_PATH=""
OFFSITE_RCLONE_CONF=""; OFFSITE_APPEND_ONLY="unknown"; OFFSITE_RETAIN="14"
read -rp "  Copy backups off this VM? [y/N] : " _OFF
case "${_OFF}" in
  y|Y|yes|YES)
    echo ""
    echo -e "  ${YW}  scp     simplest. Needs only an SSH key and a remote path.${CL}"
    echo -e "  ${YW}  rsync   same transport, resumes interrupted transfers.${CL}"
    echo -e "  ${YW}          Better over a slow or unreliable link.${CL}"
    echo -e "  ${YW}  s3      Object storage via an S3-compatible API — Cloudflare R2,${CL}"
    echo -e "  ${YW}          Backblaze B2, Wasabi, MinIO, AWS. Guided setup here;${CL}"
    echo -e "  ${YW}          no rclone config needed in advance.${CL}"
    echo -e "  ${YW}  rclone  Any of rclone's ~40 backends, using a config file you${CL}"
    echo -e "  ${YW}          have already created and tested elsewhere.${CL}"
    read -rp "  Method? [scp/rsync/s3/rclone] : " _OM
    case "${_OM}" in
      rsync)  OFFSITE_METHOD="rsync" ;;
      rclone) OFFSITE_METHOD="rclone" ;;
      s3|S3)  OFFSITE_METHOD="s3" ;;
      scp)    OFFSITE_METHOD="scp" ;;
      *)      OFFSITE_METHOD="none"; msg_warn "  Unrecognised method — off-VM backup skipped." ;;
    esac
    if [[ "$OFFSITE_METHOD" == "scp" || "$OFFSITE_METHOD" == "rsync" ]]; then
      echo -e "  ${YW}  Destination as user@host:/path — the remote directory must${CL}"
      echo -e "  ${YW}  already exist and be writable by that user.${CL}"
      read -rp "  Destination (user@host:/path) : " OFFSITE_DEST
      echo -e "  ${YW}  Path to a private key THIS host will use. It is copied onto${CL}"
      echo -e "  ${YW}  the VM as 0400 root-only. Use a key dedicated to backups,${CL}"
      echo -e "  ${YW}  not your admin key — this one lives on a machine that${CL}"
      echo -e "  ${YW}  faces the internet.${CL}"
      read -rp "  SSH private key path on THIS Proxmox host : " OFFSITE_KEY_PATH
      [[ -r "$OFFSITE_KEY_PATH" ]] || { msg_warn "  Cannot read ${OFFSITE_KEY_PATH} — off-VM backup skipped."; OFFSITE_METHOD="none"; }
    elif [[ "$OFFSITE_METHOD" == "s3" ]]; then
      # Generates the rclone config rather than asking for one. S3-compatible
      # providers differ only in endpoint and provider hint, so the operator
      # supplies the four things they actually have from the provider console.
      echo ""
      echo -e "  ${YW}  Which provider?${CL}"
      echo -e "  ${YW}    1  Cloudflare R2      2  Backblaze B2 (S3 API)${CL}"
      echo -e "  ${YW}    3  Wasabi             4  AWS S3${CL}"
      echo -e "  ${YW}    5  Other S3-compatible (MinIO, Ceph, …)${CL}"
      read -rp "  Provider [1] : " _S3P
      case "${_S3P:-1}" in
        1) S3_PROVIDER="Cloudflare"
           echo -e "  ${YW}  Your R2 account ID is in the Cloudflare dashboard URL, and on${CL}"
           echo -e "  ${YW}  the R2 overview page as part of the S3 API endpoint.${CL}"
           read -rp "  Cloudflare account ID : " _S3ACC
           S3_ENDPOINT="https://${_S3ACC}.r2.cloudflarestorage.com"
           S3_REGION="auto" ;;
        2) S3_PROVIDER="Backblaze"
           read -rp "  B2 S3 endpoint (e.g. s3.us-west-004.backblazeb2.com) : " _S3EP
           S3_ENDPOINT="https://${_S3EP#https://}"; S3_REGION="" ;;
        3) S3_PROVIDER="Wasabi"
           read -rp "  Wasabi endpoint (e.g. s3.eu-central-1.wasabisys.com) : " _S3EP
           S3_ENDPOINT="https://${_S3EP#https://}"; S3_REGION="" ;;
        4) S3_PROVIDER="AWS"; S3_ENDPOINT=""
           read -rp "  AWS region (e.g. eu-west-2) : " S3_REGION ;;
        *) S3_PROVIDER="Other"
           read -rp "  S3 endpoint URL : " _S3EP
           S3_ENDPOINT="https://${_S3EP#https://}"
           read -rp "  Region (blank if none) : " S3_REGION ;;
      esac
      echo ""
      echo -e "  ${YW}  Create the credential with WRITE but NOT DELETE permission if${CL}"
      echo -e "  ${YW}  your provider allows it. On R2 that is an API token scoped to${CL}"
      echo -e "  ${YW}  'Object Read & Write' on one bucket; on AWS, an IAM policy${CL}"
      echo -e "  ${YW}  granting s3:PutObject and s3:ListBucket but denying${CL}"
      echo -e "  ${YW}  s3:DeleteObject. That is what stops an attacker with root on${CL}"
      echo -e "  ${YW}  this VM deleting the backups as well as encrypting the site.${CL}"
      read -rp "  Access key ID : " S3_KEY
      read -rsp "  Secret access key : " S3_SECRET; echo
      read -rp "  Bucket name : " S3_BUCKET
      read -rp "  Path inside the bucket [wasp/$(hostname -s 2>/dev/null || echo vm)] : " _S3PATH
      _S3PATH="${_S3PATH:-wasp/$(hostname -s 2>/dev/null || echo vm)}"
      OFFSITE_DEST="wasp-s3:${S3_BUCKET}/${_S3PATH}"
      if [[ -z "$S3_KEY" || -z "$S3_SECRET" || -z "$S3_BUCKET" ]]; then
        msg_warn "  Incomplete S3 details — off-VM backup skipped."
        OFFSITE_METHOD="none"
      else
        msg_ok "S3 destination: ${OFFSITE_DEST}"
        msg_info "  Config is written on the VM at /etc/wp-install/rclone.conf (0600)"
      fi
    elif [[ "$OFFSITE_METHOD" == "rclone" ]]; then
      echo -e "  ${YW}  Destination as remote:bucket/path, using a remote name from${CL}"
      echo -e "  ${YW}  your rclone config.${CL}"
      read -rp "  Destination (remote:bucket/path) : " OFFSITE_DEST
      read -rp "  rclone.conf path on THIS Proxmox host : " OFFSITE_RCLONE_CONF
      [[ -r "$OFFSITE_RCLONE_CONF" ]] || { msg_warn "  Cannot read ${OFFSITE_RCLONE_CONF} — off-VM backup skipped."; OFFSITE_METHOD="none"; }
    fi
    if [[ "$OFFSITE_METHOD" != "none" ]]; then
      read -rp "  Remote copies to keep [14] : " _OR
      case "${_OR}" in ''|*[!0-9]*) OFFSITE_RETAIN=14 ;; *) OFFSITE_RETAIN="$_OR" ;; esac
      echo ""
      echo -e "  ${YW}  Is the destination append-only — can this key ADD backups${CL}"
      echo -e "  ${YW}  but NOT delete or overwrite them? Answer no if unsure; it${CL}"
      echo -e "  ${YW}  only changes what the status output claims, and claiming${CL}"
      echo -e "  ${YW}  protection you do not have is the failure worth avoiding.${CL}"
      echo ""
      echo -e "  ${BLD}Encrypt backups before they leave this VM?${CL}"
      echo -e "  ${YW}A database dump is not an opaque blob. It contains every${CL}"
      echo -e "  ${YW}user's password hash, email and real name, private and draft${CL}"
      echo -e "  ${YW}post content, and whatever plugins have written into${CL}"
      echo -e "  ${YW}wp_options — API keys, form submissions, order records.${CL}"
      echo -e "  ${YW}Unencrypted, your storage provider has all of it, and so${CL}"
      echo -e "  ${YW}does anyone who reaches that bucket.${CL}"
      echo ""
      _sec_head
      echo -e "  ${YW}  Encryption uses age in PUBLIC-KEY mode, and that is the${CL}"
      echo -e "  ${YW}  point rather than a detail: this VM holds only the public${CL}"
      echo -e "  ${YW}  half. It can encrypt backups and cannot read them — not${CL}"
      echo -e "  ${YW}  the ones it sends, and not the ones already stored. An${CL}"
      echo -e "  ${YW}  attacker with root here cannot read your backups even${CL}"
      echo -e "  ${YW}  though they can create them.${CL}"
      echo -e "  ${YW}  With an append-only destination they can neither read${CL}"
      echo -e "  ${YW}  what is there nor delete it.${CL}"
      echo -e "  ${RD}  THE COST IS REAL: lose the private key and every encrypted${CL}"
      echo -e "  ${RD}  backup is gone for good. An encrypted backup nobody can${CL}"
      echo -e "  ${RD}  decrypt is not a backup. Keep the private key somewhere${CL}"
      echo -e "  ${RD}  that is neither this VM nor the storage bucket, and test${CL}"
      echo -e "  ${RD}  a decrypt NOW rather than during an incident.${CL}"
      echo -e "  ${YW}  The LOCAL backup stays unencrypted on purpose: it never${CL}"
      echo -e "  ${YW}  leaves the host, and keeping it readable is what lets the${CL}"
      echo -e "  ${YW}  weekly self-test prove a restore actually works.${CL}"
      echo -e "  ${YW}  Generate a key on your workstation, not here:${CL}"
      echo -e "  ${YW}    age-keygen -o wasp-backup-key.txt${CL}"
      echo -e "  ${YW}  Paste the 'Public key: age1...' line below.${CL}"
      _sec_note
      OFFSITE_AGE_RECIPIENT=""
      while :; do
        read -rp "  age public key (age1..., blank = no encryption) : " OFFSITE_AGE_RECIPIENT
        [[ -z "$OFFSITE_AGE_RECIPIENT" ]] && {
          msg_warn "  Backups will leave this VM UNENCRYPTED."
          msg_warn "  Acceptable only if the destination is hardware you control."
          break; }
        # An age recipient is age1 followed by bech32. Checking the shape stops
        # a private key or a truncated paste being accepted as a recipient --
        # which would fail at 02:00 rather than here.
        if printf '%s' "$OFFSITE_AGE_RECIPIENT" | grep -qE '^age1[0-9a-z]{50,}$'; then
          msg_ok "Off-VM backups will be encrypted to ${OFFSITE_AGE_RECIPIENT:0:16}…"
          msg_warn "  Verify you can decrypt with the matching private key BEFORE relying on this."
          break
        fi
        if printf '%s' "$OFFSITE_AGE_RECIPIENT" | grep -q 'AGE-SECRET-KEY'; then
          msg_warn "  That is a PRIVATE key. Never put it on this VM — the whole"
          msg_warn "  point is that a compromise here cannot read your backups."
          msg_warn "  Paste the 'Public key: age1...' line instead."
        else
          msg_warn "  Doesn't look like an age public key (expected age1...)."
        fi
      done
      read -rp "  Destination is append-only? [y/N] : " _OAO
      case "${_OAO}" in y|Y|yes|YES) OFFSITE_APPEND_ONLY="yes" ;; *) OFFSITE_APPEND_ONLY="no" ;; esac
      msg_ok "Off-VM backup: ${OFFSITE_METHOD} -> ${OFFSITE_DEST} (keep ${OFFSITE_RETAIN})"
      [[ "$OFFSITE_APPEND_ONLY" == "no" ]] && \
        msg_warn "  Not append-only: this protects against loss, not against an attacker with root here."
      msg_info "  Test it after install:  wasp-offsite-backup.sh test"
    fi ;;
  *) msg_warn "Backups stay on this VM only — they will not survive losing it." ;;
esac
unset _OFF _OM _OR _OAO

# ── Governance / compliance address ──────────────────────────────────────────
echo ""
echo -e "  ${BLD}Governance email (vulnerability exception notices)${CL}"
echo -e "  ${YW}Accepting a HIGH or CRITICAL vulnerability finding in order to${CL}"
echo -e "  ${YW}update is sometimes the right call — the fix may not exist yet.${CL}"
echo -e "  ${YW}What must not happen is that it is a private decision nobody${CL}"
echo -e "  ${YW}else ever sees.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  Accepting a finding requires a written justification, which is${CL}"
echo -e "  ${YW}  recorded on the VM and emailed here. The exception is tied to${CL}"
echo -e "  ${YW}  the exact image digest and expires — by default after 90 days${CL}"
echo -e "  ${YW}  — so it cannot quietly become permanent policy.${CL}"
echo -e "  ${YW}  Send it somewhere OTHER than the operator who accepts them,${CL}"
echo -e "  ${YW}  where possible. A record that only the person making the${CL}"
echo -e "  ${YW}  decision receives is a diary, not oversight.${CL}"
echo -e "  ${YW}  The local log is the record; the email is a copy. Mail can${CL}"
echo -e "  ${YW}  fail, and an audit trail that depends on delivery is not one.${CL}"
_sec_note
GOVERNANCE_EMAIL=""
_gov_default="${WP_ADMIN_EMAIL:-}"
while :; do
  if [[ -n "$_gov_default" ]]; then
    read -rp "  Governance email [${_gov_default}] : " GOVERNANCE_EMAIL
    GOVERNANCE_EMAIL="${GOVERNANCE_EMAIL:-$_gov_default}"
  else
    read -rp "  Governance email (blank = local log only) : " GOVERNANCE_EMAIL
  fi
  [[ -z "$GOVERNANCE_EMAIL" ]] && {
    msg_warn "No governance address — exceptions are logged on the VM only."
    msg_warn "  /var/log/wasp-vuln-exceptions.log"
    break; }
  if printf '%s' "$GOVERNANCE_EMAIL" | grep -qE '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'; then
    msg_ok "Exception notices go to: ${GOVERNANCE_EMAIL}"
    [[ "$GOVERNANCE_EMAIL" == "${WP_ADMIN_EMAIL:-}" ]] && \
      msg_warn "  Same as the admin address — consider a separate mailbox so the"
    [[ "$GOVERNANCE_EMAIL" == "${WP_ADMIN_EMAIL:-}" ]] && \
      msg_warn "  person accepting a risk is not the only person told about it."
    break
  fi
  msg_warn "  '${GOVERNANCE_EMAIL}' doesn't look like an email address."
done
unset _gov_default

# ── Egress proxy (Squid) ─────────────────────────────────────────────────────
echo ""
echo -e "  ${BLD}Force WordPress web traffic through a filtering proxy?${CL}"
echo -e "  ${YW}The outbound firewall you were offered earlier restricts which${CL}"
echo -e "  ${YW}PORTS WordPress may use. This restricts which DESTINATIONS —${CL}"
echo -e "  ${YW}443 is open either way, and 443 is where exfiltration goes.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  A compromised WordPress cannot reach an attacker's server${CL}"
echo -e "  ${YW}  unless that server is on the allowlist. It cannot reach cloud${CL}"
echo -e "  ${YW}  metadata, the LAN, or a bare IP address. SSRF in a plugin${CL}"
echo -e "  ${YW}  stops being a route into your internal network.${CL}"
echo -e "  ${YW}  The firewall enforces it, not WordPress's own settings — a${CL}"
echo -e "  ${YW}  plugin calling fsockopen() ignores those completely, which is${CL}"
echo -e "  ${YW}  precisely the traffic worth stopping.${CL}"
echo -e "  ${YW}  No TLS interception: filtering is on the destination name in${CL}"
echo -e "  ${YW}  the CONNECT request, which is plaintext. Nothing is decrypted${CL}"
echo -e "  ${YW}  and no certificate authority is installed.${CL}"
echo ""
echo -e "  ${RD}  THE COST IS REAL. Plugins that call an unlisted service will${CL}"
echo -e "  ${RD}  break — payment gateways, mapping, fonts, licence checks.${CL}"
echo -e "  ${RD}  They break visibly and the log names what was blocked, but${CL}"
echo -e "  ${RD}  they do break. Expect to spend time on the allowlist.${CL}"
echo -e "  ${YW}  Start allowed: wordpress.org, and what WASP itself needs${CL}"
echo -e "  ${YW}  (Wordfence, CrowdSec, MaxMind, Alpine, registries).${CL}"
echo -e "  ${YW}  Find what a site actually needs:  wasp-egress discovery${CL}"
echo -e "  ${YW}  Add one:                          wasp-egress allow <domain>${CL}"
echo -e "  ${YW}  Temporary window:                 wasp-egress maintenance enable${CL}"
_sec_note
EGRESS_PROXY=0
read -rp "  Force web egress through the proxy? [y/N] : " _EP
case "${_EP}" in
  y|Y|yes|YES) EGRESS_PROXY=1
    msg_ok "Egress proxy enabled — WordPress reaches approved destinations only"
    msg_warn "  Verify enforcement after install:  wasp-egress test"
    msg_warn "  If a plugin misbehaves, check what was blocked before assuming"
    msg_warn "  the plugin is at fault:            wasp-egress discovery" ;;
  *) msg_ok "No egress proxy — WordPress may reach any host on permitted ports" ;;
esac
unset _EP

# ── Page builders / commercial themes ────────────────────────────────────────
# Only asked when the egress proxy is on, because without it the allowlist is
# not enforcing anything and this question has no consequence.
#
# These used to be baked into the shipped allowlist -- all nine of them. That
# was backwards: the allowlist is the set of destinations a COMPROMISED
# WordPress may still reach, so shipping Elementor's licence server to a site
# that runs Divi is pure surface for no benefit. Now nothing is allowed unless
# it is asked for.
PAGE_BUILDER_DOMAINS=""
if [[ "${EGRESS_PROXY:-0}" == "1" ]]; then
  echo ""
  echo -e "  ${BLD}Commercial themes or page builders?${CL}"
  echo -e "  ${YW}A paid theme that cannot reach its licence server installs fine${CL}"
  echo -e "  ${YW}and then never updates -- which for a page builder means it${CL}"
  echo -e "  ${YW}silently stops receiving security fixes. If you use one, allow${CL}"
  echo -e "  ${YW}it here.${CL}"
  echo ""
  echo -e "  ${YW}Pick ONLY what this site will actually run. Each one you add is a${CL}"
  echo -e "  ${YW}destination a compromised WordPress may reach; you can add more${CL}"
  echo -e "  ${YW}later with:  doas wasp-egress.sh allow <domain>${CL}"
  echo ""
  echo "    1) Elementor            .elementor.com"
  echo "    2) Divi / Elegant Themes .elegantthemes.com"
  echo "    3) WPBakery             .wpbakery.com"
  echo "    4) Beaver Builder       .beaverbuilder.com"
  echo "    5) Kadence              .kadencewp.com"
  echo "    6) Astra                .wpastra.com"
  echo "    7) GeneratePress        .generatepress.com"
  echo "    8) OceanWP              .oceanwp.org"
  echo "    9) ThemeIsle            .themeisle.com"
  echo ""
  read -rp "  Numbers, comma or space separated (blank = none) : " _PB
  for _n in $(printf '%s' "${_PB}" | tr ',;' '  '); do
    case "$_n" in
      1) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .elementor.com" ;;
      2) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .elegantthemes.com" ;;
      3) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .wpbakery.com" ;;
      4) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .beaverbuilder.com" ;;
      5) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .kadencewp.com" ;;
      6) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .wpastra.com" ;;
      7) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .generatepress.com" ;;
      8) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .oceanwp.org" ;;
      9) PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS} .themeisle.com" ;;
      '') : ;;
      *) msg_warn "  Ignoring '${_n}' — not one of the listed numbers." ;;
    esac
  done
  PAGE_BUILDER_DOMAINS="${PAGE_BUILDER_DOMAINS# }"
  if [[ -n "$PAGE_BUILDER_DOMAINS" ]]; then
    msg_ok "Builder domains allowed: ${PAGE_BUILDER_DOMAINS}"
  else
    msg_ok "No builder domains allowed — add later with: doas wasp-egress.sh allow <domain>"
  fi
  unset _PB _n
fi

# ── Multi-factor authentication for admins ───────────────────────────────────
echo ""
echo -e "  ${BLD}Require two-factor authentication for administrators?${CL}"
echo -e "  ${YW}A stolen or phished admin password is the most common way a${CL}"
echo -e "  ${YW}WordPress site is taken over. A second factor means the password${CL}"
echo -e "  ${YW}alone is not enough, even if the login page is reached.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  Installs the WordPress core team's Two Factor plugin (TOTP,${CL}"
echo -e "  ${YW}  backup codes, and passkeys) and REQUIRES administrators to${CL}"
echo -e "  ${YW}  enrol. Non-admins are unaffected. It composes with the custom${CL}"
echo -e "  ${YW}  login slug, the brute-force guard and the IP restriction${CL}"
echo -e "  ${YW}  already in place -- they are sequential stages, not conflicts.${CL}"
echo -e "  ${YW}  It also closes the REST/app-password side doors so the second${CL}"
echo -e "  ${YW}  factor cannot be walked around via an API.${CL}"
echo ""
echo -e "  ${RD}  LOCKOUT SAFETY. Enforcement is built around recovery: a new or${CL}"
echo -e "  ${RD}  promoted admin gets a grace window to enrol (not blocked${CL}"
echo -e "  ${RD}  instantly), backup codes count as a factor so any device works,${CL}"
echo -e "  ${RD}  and 2FA for one user can be reset from the VM console if every${CL}"
echo -e "  ${RD}  factor is lost. Tell your admins to PRINT THE BACKUP CODES.${CL}"
_sec_note
MFA_ENFORCE=0
MFA_GRACE_DAYS=7
read -rp "  Require 2FA for administrators? [Y/n] : " _MFA
case "${_MFA}" in
  n|N|no|NO)
    msg_ok "MFA not enforced — admins may still opt in from their profile if the plugin is added later" ;;
  *)
    MFA_ENFORCE=1
    read -rp "  Grace period for admins to enrol, in days [7] : " _MFG
    case "${_MFG}" in
      ''|*[!0-9]*) MFA_GRACE_DAYS=7 ;;
      *) MFA_GRACE_DAYS="${_MFG}" ;;
    esac
    # A grace window measured in months is an open door with a timer; cap it.
    [ "${MFA_GRACE_DAYS}" -gt 30 ] && { MFA_GRACE_DAYS=30; msg_warn "  Grace capped at 30 days."; }
    msg_ok "2FA required for administrators (${MFA_GRACE_DAYS}-day grace to enrol)"
    msg_warn "  After install: log in, go to your profile, enable an authenticator app,"
    msg_warn "  and PRINT the backup codes. Without them a lost phone needs console recovery." ;;
esac
unset _MFA _MFG

# ── CrowdSec threat intelligence (CTI) ───────────────────────────────────────
echo ""
echo -e "  ${BLD}CrowdSec threat intelligence (optional)${CL}"
echo -e "  ${YW}Turns \"an address was banned\" into \"this is a Dutch-hosted HTTP${CL}"
echo -e "  ${YW}scanner that has been brute-forcing WordPress across five${CL}"
echo -e "  ${YW}countries since June\" — behaviour, not just reputation.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  Useful when deciding whether a ban is a targeted attempt or${CL}"
echo -e "  ${YW}  background noise, and whether an address is actually a crawler${CL}"
echo -e "  ${YW}  you have just blocked by mistake.${CL}"
echo -e "  ${RD}  THE QUOTA IS SMALL. The free Community key allows 40 lookups${CL}"
echo -e "  ${RD}  per MONTH — not per day. Unused quota does not roll over.${CL}"
echo -e "  ${YW}  That is enough to investigate addresses that matter, and not${CL}"
echo -e "  ${YW}  nearly enough to enrich every ban: this VM will ban dozens a${CL}"
echo -e "  ${YW}  day and almost all of them are commodity scanners.${CL}"
echo -e "  ${YW}  Lookups are cached for 7 days and a local counter refuses at${CL}"
echo -e "  ${YW}  the budget rather than letting you discover it is gone during${CL}"
echo -e "  ${YW}  an incident.${CL}"
echo -e "  ${YW}  Get a free key in the CrowdSec Console under Settings →${CL}"
echo -e "  ${YW}  CTI API Keys. Skipping costs nothing else.${CL}"
_sec_note
CTI_API_KEY=""; CTI_MONTHLY_BUDGET="120"; CTI_ENRICH_BANS="0"
echo -e "  ${YW}  This is the second CrowdSec value (Settings → CTI API Keys).${CL}"
read -rsp "  CrowdSec CTI key (blank = skip) : " CTI_API_KEY; echo
if [[ -n "$CTI_API_KEY" ]]; then
  msg_ok "CTI key captured (${#CTI_API_KEY} chars)"
  # There are TWO free keys and they have different quotas, which is why this
  # asks rather than assuming: a Community-plan account's free key is 40
  # lookups/month, while a Premium-plan account's INCLUDED free key is 120.
  # Both are "the free key" depending on who you ask. The budget matters
  # because exhausting it mid-month silently stops enrichment.
  echo ""
  echo -e "  ${YW}  READ YOUR OWN QUOTA — do not trust a number from anywhere else,${CL}"
  echo -e "  ${YW}  including this installer. CrowdSec's own documentation${CL}"
  echo -e "  ${YW}  contradicts itself: the CTI API Keys page says a Community free${CL}"
  echo -e "  ${YW}  key is 40/month, while the Premium Upgrade page lists Community${CL}"
  echo -e "  ${YW}  as 120 calls/month. A free Community account has been observed${CL}"
  echo -e "  ${YW}  reporting 120, so that is the default here.${CL}"
  echo -e "  ${YW}${CL}"
  echo -e "  ${YW}  Your console shows the real figure:${CL}"
  echo -e "  ${YW}    Settings → CTI API Keys  (next to the key itself)${CL}"
  echo -e "  ${YW}  Unused quota does NOT roll over. Paid keys start at 5,000/month.${CL}"
  echo -e "  ${YW}  Setting this too HIGH is the risk: the budget is what stops${CL}"
  echo -e "  ${YW}  enrichment burning the month's quota in a single busy day.${CL}"
  read -rp "  Monthly lookup budget [120] : " _CTB
  case "${_CTB}" in ''|*[!0-9]*) CTI_MONTHLY_BUDGET=120 ;; *) CTI_MONTHLY_BUDGET="$_CTB" ;; esac
  echo ""
  echo -e "  ${BLD}Automatically enrich login brute-force bans?${CL}"
  echo -e "  ${YW}Only bans from the login-guard scenario — an address that${CL}"
  echo -e "  ${YW}reached your login form and failed repeatedly is targeting THIS${CL}"
  echo -e "  ${YW}site. Generic http-probing bans are noise hitting everyone and${CL}"
  echo -e "  ${YW}are never enriched.${CL}"
  if [[ "$CTI_MONTHLY_BUDGET" -le 100 ]]; then
    echo -e "  ${RD}  At ${CTI_MONTHLY_BUDGET}/month this is likely to exhaust the budget.${CL}"
    echo -e "  ${RD}  Recommended only with a purchased key (5k+/month).${CL}"
    echo -e "  ${YW}  Say no and look addresses up on demand instead:${CL}"
    echo -e "  ${YW}    wp-hardening.sh cti <ip>${CL}"
    echo -e "  ${YW}    wp-forensics.sh timeline --around <file> --enrich${CL}"
    _CTD="N"
  else
    echo -e "  ${YW}  Your budget (${CTI_MONTHLY_BUDGET}/month) can support this.${CL}"
    _CTD="Y"
  fi
  read -rp "  Enrich login brute-force bans automatically? [y/N] : " _CTE
  case "${_CTE:-$_CTD}" in
    y|Y|yes|YES) CTI_ENRICH_BANS="1"
      msg_ok "Login brute-force bans will be enriched and emailed"
      [[ "$CTI_MONTHLY_BUDGET" -le 100 ]] && \
        msg_warn "  With a small budget this may stop working mid-month. The counter" && \
        msg_warn "  refuses rather than failing loudly, so check: wp-hardening.sh cti --status" ;;
    *) msg_ok "On-demand lookups only — wp-hardening.sh cti <ip>" ;;
  esac
  unset _CTB _CTE _CTD
else
  msg_ok "CTI skipped — bans are still enforced, just without global context"
fi

# ── Wordfence Intelligence API key ───────────────────────────────────────────
echo ""
echo -e "  ${BLD}Wordfence Intelligence API token (plugin vulnerability data)${CL}"
echo -e "  ${YW}This is what lets the VM tell you a plugin you have installed has a${CL}"
echo -e "  ${YW}known vulnerability — as opposed to merely being out of date.${CL}"
echo ""
echo -e "  ${YW}Free, for personal and commercial use. It needs a free Wordfence${CL}"
echo -e "  ${YW}account; generate the token under Integrations in the account${CL}"
echo -e "  ${YW}dashboard:  https://www.wordfence.com/products/wordfence-intelligence/${CL}"
echo -e "  ${YW}The v2 feed was open with no key and has been retired, so a token${CL}"
echo -e "  ${YW}is now required to read the database at all.${CL}"
echo ""
_sec_head
echo -e "  ${YW}  It covers the layer container scanning cannot see. Trivy and${CL}"
echo -e "  ${YW}  digest pinning secure the IMAGE; plugins and themes live in a${CL}"
echo -e "  ${YW}  mounted volume that an image update never touches — and that is${CL}"
echo -e "  ${YW}  where roughly 91% of WordPress vulnerabilities are found.${CL}"
echo -e "  ${YW}  The feed is downloaded whole and matched on this VM, so your${CL}"
echo -e "  ${YW}  plugin list is never sent to anyone. Skipping it costs you that${CL}"
echo -e "  ${YW}  visibility and nothing else — everything else still works.${CL}"
echo -e "  ${YW}  It reports DISCLOSED issues. Roughly 46% of plugin${CL}"
echo -e "  ${YW}  vulnerabilities have no patch when they are disclosed, and a${CL}"
echo -e "  ${YW}  plugin nobody has audited has no CVEs by definition.${CL}"
_sec_note
WORDFENCE_FEED="scanner"
read -rsp "  Wordfence API token (blank = skip, add later with wp-plugins.sh) : " WORDFENCE_API_KEY; echo
if [[ -n "$WORDFENCE_API_KEY" ]]; then
  msg_ok "Wordfence token captured (${#WORDFENCE_API_KEY} chars) — daily vulnerability scans enabled"
  echo ""
  echo -e "  ${BLD}Which Wordfence feed?${CL}"
  echo -e "  ${YW}Two feeds exist, and the difference is NOT simply that one is${CL}"
  echo -e "  ${YW}bigger. They contain different things.${CL}"
  echo ""
  echo -e "  ${YW}  scanner    Minimal detection format. Contains newly discovered${CL}"
  echo -e "  ${YW}             vulnerabilities that are still being researched and${CL}"
  echo -e "  ${YW}             are NOT yet in the production feed. So it detects${CL}"
  echo -e "  ${YW}             MORE, and detects it EARLIER — which matters,${CL}"
  echo -e "  ${YW}             because a freshly disclosed plugin flaw is the one${CL}"
  echo -e "  ${YW}             most likely to be under active exploitation.${CL}"
  echo -e "  ${YW}             ~10 MB. This is the default.${CL}"
  echo ""
  echo -e "  ${YW}  production Fully analysed records: descriptions, CVSS vectors,${CL}"
  echo -e "  ${YW}             references, patched versions, researcher credit.${CL}"
  echo -e "  ${YW}             Better for DECIDING what to do about a finding, and${CL}"
  echo -e "  ${YW}             for evidence you can hand a client. But a record${CL}"
  echo -e "  ${YW}             only appears once analysis is complete, so on its${CL}"
  echo -e "  ${YW}             own it can MISS the newest issues. Over 100 MB.${CL}"
  echo ""
  echo -e "  ${YW}  both       Scanner for detection coverage, production for the${CL}"
  echo -e "  ${YW}             detail on whatever it finds. Two downloads, most${CL}"
  echo -e "  ${YW}             RAM during parsing, and the most complete picture.${CL}"
  echo ""
  _sec_head
  echo -e "  ${YW}  Production is optional and not the default for a security${CL}"
  echo -e "  ${YW}  reason before a resource one: using it ALONE narrows what you${CL}"
  echo -e "  ${YW}  detect. Richer records about issues you already know of are${CL}"
  echo -e "  ${YW}  worth less than knowing about the issue that landed today.${CL}"
  echo -e "  ${YW}  'both' has no coverage blind spot, but it is NOT free: Wordfence${CL}"
  echo -e "  ${YW}  rate-limits by REQUEST, not by bytes, so asking for two feeds in${CL}"
  echo -e "  ${YW}  one run can get the second refused with a 429. Observed in the${CL}"
  echo -e "  ${YW}  field: two refusals and two pointless 20-second waits back to${CL}"
  echo -e "  ${YW}  back. The tool now skips the production feed when the scanner${CL}"
  echo -e "  ${YW}  request was refused, and waits 60s between them when it was not,${CL}"
  echo -e "  ${YW}  so 'both' works -- it is just slower and more fragile.${CL}"
  echo ""
  echo -e "  ${YW}  Recommendation: stay on 'scanner' unless you have a specific${CL}"
  echo -e "  ${YW}  reason. It carries the vulnerabilities still under research,${CL}"
  echo -e "  ${YW}  which is the half that matters for early warning, and it is one${CL}"
  echo -e "  ${YW}  small request rather than one small and one 100 MB.${CL}"
  _sec_note
  echo "    1) scanner     — early warning, small request (recommended)"
  echo "    2) production  — richer records, no early warning"
  echo "    3) both        — no blind spot, but rate-limit prone"
  read -rp "  Feed? [1] : " _WFF
  case "${_WFF:-1}" in
    2|production|prod) WORDFENCE_FEED="production" ;;
    3|both|all)        WORDFENCE_FEED="both" ;;
    *)                 WORDFENCE_FEED="scanner" ;;
  esac
  unset _WFF
  msg_ok "Wordfence feed: ${WORDFENCE_FEED}"
  [ "$WORDFENCE_FEED" = "production" ] && \
    msg_warn "  Production alone will not see vulnerabilities still under research."
  [ "$WORDFENCE_FEED" = "both" ] && {
    msg_warn "  'both' makes two feed requests per refresh, and the production feed"
    msg_warn "  is 100 MB+. Wordfence rate-limits, so the first run may report 429"
    msg_warn "  on the second feed; the scan still runs on whichever arrived."
    msg_warn "  Feeds are cached 12h to stay well under the limit."
  }
else
  msg_warn "No Wordfence token — plugin vulnerability scanning will be unavailable."
  msg_warn "  Update visibility (wp-plugins.sh status) still works without it."
  msg_warn "  Add later:  wp-plugins.sh set-key wordfence <token>"
fi

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
echo ""
echo "    1) standard    — warns on verification failures, continues (default)"
echo "    2) production  — verification failures ABORT the install"
read -rp "  Deployment profile? [1] : " DEPLOY_SEL
case "${DEPLOY_SEL:-1}" in
  2|production|prod|p) DEPLOYMENT_PROFILE="production" ;;
  1|standard|std|s|'') DEPLOYMENT_PROFILE="standard"   ;;
  *) DEPLOYMENT_PROFILE="standard"
     msg_warn "  Unrecognised choice — using standard." ;;
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
# Was: "${WP_ADMIN_SLUG:+/${WP_ADMIN_SLUG} (custom)}${WP_ADMIN_SLUG:-/wp-admin (default)}"
# Two bugs in one line. `${V:+X}${V:-Y}` looks like an if/else but is not:
# when V is set, `:+` yields X *and* `:-` yields V itself, so the value got
# appended -- "/edith (custom)edith". It read correctly when no slug was set,
# which is why it survived until someone used the feature. It also showed
# "/edith" while the URL actually served is "/edith-login".
printf  "  %-18s %s\n"  "Login URL:"  "$([ -n "$WP_ADMIN_SLUG" ] && printf '/%s (custom)' "$WP_ADMIN_SLUG" || printf '/wp-login.php (default)')"
# Same ${V:+}${V:-} mistake as the slug line, and worse here: when a key WAS
# supplied, both halves expanded and the ENROLMENT KEY ITSELF was printed into
# the summary and the install log. It never surfaced because the key was left
# blank in testing, which is the only branch that reads correctly.
printf  "  %-18s %s\n"  "CS enrolment:" "$([ -n "$CROWDSEC_ENROLL_KEY" ] && printf 'key provided (auto-enrol)' || printf 'manual (after install)')"
printf  "  %-18s WordPress + MariaDB (internal) + CrowdSec\n" "Containers:"
printf  "  %-18s %s\n"  "Network:"     "${NET_MODE}${VM_STATIC_IP:+ ($VM_STATIC_IP/$VM_PREFIX)}"
printf  "  %-18s %s\n"  "GeoIP:"       "$([[ $GEOIP_ENABLED -eq 1 ]] && echo "${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})" || echo 'disabled')"
printf  "  %-18s %s\n"  "Digest pinning:" "$([[ $USE_DIGEST_PINNING -eq 1 ]] && echo 'enabled (SHA256-pinned images)' || echo 'disabled (tag-only)')"
[[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]] && msg_warn "WEB_CIDR set + PROXY_IP set → ${PROXY_IP} auto-added to nftables so NPM can reach port 80/443"
[[ -n "$WEB_CIDR" && -z "$PROXY_IP" ]] && msg_warn "WEB_CIDR restricts port 80/443 to ${WEB_CIDR}. If NPM is on a different subnet, add its IP as PROXY_IP or re-run the script."
echo ""
read -rp "  Proceed? [Y/n] : " yn
[[ "${yn:-Y}" =~ ^[Yy] ]] || { echo "Aborted."; _DESTROY_VM=0; exit 0; }


