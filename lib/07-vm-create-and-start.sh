#!/usr/bin/env bash
# 07-vm-create-and-start.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Enables OpenRC runlevels, disables cloud-init, unmounts the disk, creates and starts the Proxmox VM, waits for an IP, and prints the summary.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.


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

# ─ Unmount ────────────────────────────────────────────────────────────────────
# /proc and /dev were bind-mounted much earlier (right after the root
# password block) for the combined admin-account/doas/QEMU-agent chroot —
# see the comment there for why the mounts were left in place since then
# instead of being torn down and remounted a second time.
umount "$MNT/dev"  2>/dev/null || true
umount "$MNT/proc" 2>/dev/null || true
umount "$MNT" && _MNT=""
qemu-nbd --disconnect "$NBD" && _NBD=""
msg_ok "Injection complete"

# ── Create VM ─────────────────────────────────────────────────────────────────
msg_info "Creating VM ${VMID} (${HN})…"
# ── VM Notes ─────────────────────────────────────────────────────────────────
# Proxmox renders this field as Markdown, so it is the first thing anyone sees
# on the VM summary page — the right place for what an operator needs in the
# first five minutes and would otherwise go hunting for.
#
# The login URL especially: a VM once served "/<slug>-login" while the
# operator was visiting "/<slug>", and nothing on screen said which build was
# installed. That cost hours.
#
# QUOTED heredoc plus placeholder substitution, deliberately. This document is
# full of shell syntax — backticks for Markdown code spans, ${...} in example
# commands — and an unquoted heredoc would EXECUTE every backticked command on
# the Proxmox host while building the description. The first draft of this did
# exactly that; test/check-heredoc-backticks.py flagged 27 of them. Quoting the
# delimiter makes the whole block inert, and the values are substituted
# afterwards where nothing can be interpreted.
_wasp_vm_notes() {
  local _login
  if [[ -n "${WP_ADMIN_SLUG:-}" ]]; then _login="/${WP_ADMIN_SLUG}"; else _login="/wp-login.php"; fi

  cat <<'NOTES' | sed \
    -e "s|@@LOGIN@@|${WP_SCHEME:-https}://${WP_DOMAIN:-<vm-ip>}${_login}|g" \
    -e "s|@@VMID@@|${VMID}|g" \
    -e "s|@@BUILD@@|${WASP_VERSION:-unknown}|g" \
    -e "s|@@NOTE@@|${WASP_VERSION_NOTE:-}|g" \
    -e "s|@@ALPINE@@|${ALPINE_VER}|g" \
    -e "s|@@DATE@@|$(date '+%Y-%m-%d')|g" \
    -e "s|@@ADMINIP@@|${ADMIN_CIDR:-any} ${ALLOWED_ADMIN_IP:-}|g" \
    -e "s|@@PROXY@@|${PROXY_IP:-not configured}|g"
<div align="center">
  <a href="https://github.com/RothITguy-jitsi/alpine-vm-wordpress" target="_blank">
    <img src="https://raw.githubusercontent.com/RothITguy-jitsi/alpine-vm-wordpress/main/docs/wasp-logo.png" width="220"/>
  </a>
</div>

# WASP — WordPress Alpine Security Platform

**build @@BUILD@@** · Alpine @@ALPINE@@ · installed @@DATE@@
_@@NOTE@@_

WordPress + MariaDB (internal network, no host port) + CrowdSec
rootful Podman · nftables · hardened Apache

---

## Access

| | |
|---|---|
| **Login URL** | @@LOGIN@@ |
| wp-admin allowed from | @@ADMINIP@@ |
| Reverse proxy | @@PROXY@@ |
| Console (always works) | `qm terminal @@VMID@@` |

`/wp-login.php` returns **403** by design. The Login URL above is the way in.

---

## Do these five things first

1. **Finish WordPress setup** — open the Login URL above and complete the installer.
2. **Verify the VM** — `doas validate-wordpress.sh`
3. **Prove backups restore** — `doas wasp-selftest.sh all` (~3 min, starts a throwaway DB)
4. **Send a test alert** — `doas wp-notify.sh --test`, so you know failures will reach you
5. **Snapshot** — `qm snapshot @@VMID@@ post-install`, before adding plugins

---

## Cheat sheet

| Command | What it does |
|---|---|
| `validate-wordpress.sh` | ~50 checks, each with the command to fix it |
| `wasp-testreport.sh` | One full report to read or send on |
| `update.sh versions` | What image tags are available |
| `update.sh wp <tag>` | Candidate → CVE scan → health check → cutover, auto-rollback |
| `wp-plugins.sh vulns` | Installed plugins vs known vulnerabilities |
| `wp-malware-scan.sh full` | Uploads, core integrity, YARA, database |
| `wp-hardening.sh status` | Feature toggles and their state |
| `wp-hardening.sh proxy-check` | What Apache thinks the client IP is |
| `wp-hardening.sh nginx-snippet` | Proxy config, filled in for this VM |
| `wp-db-backup.sh` | Verified dump now |
| `wasp-offsite-backup.sh status` | Off-VM copies: where, encrypted, append-only |
| `wp-mail.sh test <addr>` | Prove outbound mail works |
| `wasp-verify-integrity.sh` | Has the tooling changed since install |

---

## If you are locked out

| Symptom | Cause | Fix |
|---|---|---|
| **403** on admin | Your IP is not allowed, or mod_remoteip is not substituting it | `wp-hardening.sh proxy-check` |
| **503** on admin | nginx `limit_req` — its default status is 503 | Remove `limit_req` from the NPM Advanced tab |
| **502** | Proxy cannot reach the VM, or a redirect loop | `podman logs --tail 40 wordpress` |
| SSH refused | CrowdSec banned you | `podman exec crowdsec cscli decisions delete --ip <ip>` |

Console via `qm terminal @@VMID@@` always works — root SSH is disabled, the console is not.

---

<div align="center">
  <a href="https://github.com/RothITguy-jitsi/alpine-vm-wordpress">Documentation &amp; issues</a> · by RothITguy
</div>
NOTES
}

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
  --description "$(_wasp_vm_notes)"
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
if [[ "${ADMIN_USER_CREATED:-0}" -eq 1 ]]; then
  _SSH_DESC="${ADMIN_USER} — $([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password'), root SSH disabled"
else
  _SSH_DESC="NO SSH LOGIN — root SSH stays disabled, use: qm terminal ${VMID}"
fi
if [[ -n "${WP_DOMAIN:-}" ]]; then
  printf "  ║  Site URL :  %-47s║\n" "${WP_SCHEME}://${WP_DOMAIN}"
else
  printf "  ║  Site URL :  %-47s║\n" "http://<vm-ip>/  (no domain configured)"
fi
printf "  ║  SSH      :  %-47s║\n" "$_SSH_DESC"
[[ "${ADMIN_USER_CREATED:-0}" -eq 0 ]] && printf "  ║  ${RD}⚠ Admin account was NOT created — see install log, create by hand${CL}  ║\n"
printf "  ║  L1 nftables   SSH=%-12s  Web=%-21s║\n" "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
# extra-ip can now be a LIST, which would blow out this fixed-width box. Show
# the addresses when they fit and a count when they do not, so the summary
# stays readable and the border stays aligned.
_xip="${ALLOWED_ADMIN_IP:-none}"
if [ "${#_xip}" -gt 16 ]; then
  _xip="$(printf '%s' "$ALLOWED_ADMIN_IP" | wc -w | tr -d ' ') addresses"
fi
printf "  ║  L2 wp-admin   cidr=%-11s  extra-ip=%-16s║\n" "${ADMIN_CIDR:-open}" "$_xip"
printf "  ║  mod_remoteip  proxy=%-40s║\n"  "${PROXY_IP:-not configured (direct)}"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  # Pre-compute summary values (avoids quote-in-subshell issues)
  _WP_PORT_DESC="7.0.2-php8.4-apache → port 80"
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
  printf "  ║    MariaDB    %-47s║\n" "11.4 → wp-db:10.89.20.0/24 internal (no host port)"
  printf "  ║    CrowdSec   %-47s║\n" "v1.7.8 → host network, read-only"
  echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  Networking: netavark firewall_driver=nftables (no iptables)║"
  echo   "  ║  nftables forward: wp-front 10.89.10.0/24 + wp-db 10.89.20.0/24,║"
  echo   "  ║  all else DROP. wp-db is --internal (MariaDB has no egress) ║"
  printf "  ║  Network:       %-44s║\n" "${_NET_DESC}"
  printf "  ║  GeoIP:         %-44s║\n" "${_GEO_DESC}"
  [[ -n "${WP_ADMIN_SLUG}" ]] && printf "  ║  Custom slug:   %-44s║\n" "/${WP_ADMIN_SLUG}"
echo   "  ║  Background install (~15 min total):                       ║"
echo   "  ║    qm terminal $VMID  then:  tail -800 /var/log/wp-install.log"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  When done: http://<VM-IP>/wp-admin/install.php            ║"
echo   "  ╚══════════════════════════════════════════════════════════════╝"
printf "${CL}"
echo ""

