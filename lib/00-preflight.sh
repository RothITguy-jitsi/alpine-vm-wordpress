#!/usr/bin/env bash
# 00-preflight.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Colors/logging helpers, VMID lookup, Alpine image auto-detect, cleanup trap, and Proxmox host preflight checks.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

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
  # Self-bootstrap cleanup (install.sh, run standalone): remove the
  # temp-extracted repo copy on every exit path, success or failure alike
  # -- nothing from a curl-one-liner run is meant to persist on the host.
  # Never touches a real git clone: _WPVM_BOOTSTRAP_DIR is only ever set
  # when install.sh had to fetch the repo itself in the first place.
  [[ -n "${_WPVM_BOOTSTRAP_DIR:-}" ]] && rm -rf "$_WPVM_BOOTSTRAP_DIR"
}
trap cleanup EXIT

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]]                || msg_error "Must run as root on the Proxmox host."
[[ -f /etc/pve/pve-root-ca.pem ]] || msg_error "Not a Proxmox VE host."
command -v qm        &>/dev/null || msg_error "'qm' not found."
command -v qemu-nbd  &>/dev/null || msg_error "'qemu-nbd' not found — apt install qemu-utils"
command -v qemu-img  &>/dev/null || msg_error "'qemu-img' not found — apt install qemu-utils"
command -v openssl   &>/dev/null || msg_error "'openssl' not found."
