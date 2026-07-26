#!/usr/bin/env bash
# 02-image-and-disk.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Storage type detection and the Alpine cloud image download, SHA-512 verification, and working-copy resize.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

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
    # BUG FIX (v7-13, ChatGPT Finding 8): under DEPLOYMENT_PROFILE=production
    # a missing or malformed .sha512 sidecar is now fatal instead of a warn.
    # Rationale: an install that CAN'T verify the base OS image but still
    # deploys can't be handed to an auditor as "the image was verified."
    # Under DEPLOYMENT_PROFILE=standard (the default), behavior is
    # unchanged from v7-12 — warn and continue, so a bad-mirror day doesn't
    # brick a homelab install.
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      msg_error "Could not fetch a valid .sha512 for $(basename "$img") — refusing to continue under DEPLOYMENT_PROFILE=production. Retry once the mirror recovers, or re-run under DEPLOYMENT_PROFILE=standard if this is a lab install."
    fi
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
  # BUG FIX (v7-13, ChatGPT Finding 8): under DEPLOYMENT_PROFILE=production
  # a Proxmox host missing sha512sum is now an abort instead of a warn.
  # Same reasoning as the sidecar-missing branch inside
  # _verify_alpine_sha512: an install that CAN'T check the base image
  # isn't a verified install, and production mode is opting in to failing
  # rather than silently downgrading.
  if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
    msg_error "sha512sum not found on this Proxmox host — refusing to continue under DEPLOYMENT_PROFILE=production. Install coreutils on the Proxmox host (apt install coreutils), or re-run under DEPLOYMENT_PROFILE=standard."
  fi
  msg_warn "sha512sum not found on this host — skipping Alpine image integrity check"
fi
WORK_IMG="/tmp/wp-vm-${VMID}-alpine.qcow2"
cp "$IMG_FILE" "$WORK_IMG"
qemu-img resize "$WORK_IMG" "$DISK" >/dev/null
msg_ok "Working image ready (${DISK})"

# ── Build nftables ruleset (host-side substitution) ───────────────────────────
