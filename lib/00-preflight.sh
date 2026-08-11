#!/usr/bin/env bash
# 00-preflight.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Colors/logging helpers, VMID lookup, Alpine image auto-detect, cleanup trap, and Proxmox host preflight checks.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

# =============================================================================
set -e

# FORENSIC FIX (new-audit Medium finding, confirmed reasonable): everything
# from here on runs as root and does destructive disk/VM operations, so a
# few cheap, standard hardening steps close off avoidable ways that context
# could go wrong before anything privileged happens:
#   - PATH fixed to the standard Debian/Proxmox system directories, so a
#     malicious or accidental PATH entry earlier in the environment can't
#     get a lookalike binary run instead of the real qm/qemu-nbd/curl/etc.
#   - umask tightened from Debian's default 022 to 027: anything this
#     script or a sourced module creates without its own explicit chmod
#     (most security-sensitive files already set one explicitly -- see
#     vars.sh, credentials, SSH keys -- this is the floor under everything
#     else) is non-world-readable by default instead of world-readable.
#   - LC_ALL=C so string comparisons, sorts, and regexes in every later
#     file behave identically regardless of the operator's shell locale.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
umask 027
export LC_ALL=C

# Refuse to source anything from a group- or world-writable checkout: if
# another local account (or a misconfigured shared directory) could have
# modified lib/ or payload/ before this ran, that's a real, cheap-to-catch
# problem given everything below sources these files as root. This is not
# the same guarantee as verifying the content is the code you expect (a
# release manifest, still tracked as a bigger open item in TODO.md) -- it
# only catches "something else on this box could have changed these files
# since you fetched them," which costs nothing to check.
for _d in "${REPO_DIR}" "${REPO_DIR}/lib" "${REPO_DIR}/payload"; do
  if [[ -n "$(find "$_d" -maxdepth 0 -perm -go+w 2>/dev/null)" ]]; then
    echo "FATAL: ${_d} is group- or world-writable -- refusing to source or copy from it." >&2
    echo "  Fix with: chmod go-w '${_d}'" >&2
    exit 1
  fi
done
unset _d

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

# ── Container tags must actually exist ───────────────────────────────────────
# LEARNED FROM A REAL FAILED INSTALL. The WordPress tag was set to
# 6.9.6-php8.4-apache by reasoning from the WordPress *release* history --
# but the Docker library only builds a specific set of version+variant
# combinations, so that tag never existed. Nothing noticed until the in-VM
# stages had been running for fifteen minutes and podman finally said
# "manifest unknown", by which point a VM had been created, a disk imported,
# and the operator had been waiting for a site that was never going to come up.
#
# Checking the tag resolves is a two-second HTTP request. Doing it here turns
# that fifteen-minute mystery into an immediate, specific error naming the tag.
#
# It fails CLOSED on a definite 404 (the tag really is not there) and only
# WARNS if the registry is unreachable or rate-limits us -- an install should
# not be blocked because Docker Hub is having a bad day, or because this host
# reaches the registry through a proxy this check does not know about.
_tag_exists() {   # namespace repo tag  ->  0 ok, 1 definitely missing, 2 unknown
  local ns="$1" repo="$2" tag="$3" code
  code=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 8 \
    "https://hub.docker.com/v2/repositories/${ns}/${repo}/tags/${tag}/" 2>/dev/null) || code="000"
  case "$code" in
    200) return 0 ;;
    404) return 1 ;;
    *)   return 2 ;;
  esac
}

_check_image_tags() {
  local payload_wp payload_squid unknown=0
  payload_wp=$(sed -n 's|^WP_IMAGE="docker.io/wordpress:\(.*\)"|\1|p' \
    "${SCRIPT_DIR:-.}/payload/install-wordpress.sh" 2>/dev/null | head -1)
  payload_squid=$(sed -n 's|.*docker.io/ubuntu/squid:\([a-zA-Z0-9._-]*\).*|\1|p' \
    "${SCRIPT_DIR:-.}/payload/stages/09-crowdsec-and-backup.sh" 2>/dev/null | head -1)

  if [[ -n "$payload_wp" ]]; then
    _tag_exists library wordpress "$payload_wp"
    case $? in
      0) msg_ok "Image tag verified: wordpress:${payload_wp}" ;;
      1) msg_error "wordpress:${payload_wp} does not exist in the registry. The install would fail ~15 minutes in with 'manifest unknown'. Check https://hub.docker.com/_/wordpress/tags for a real tag and correct WP_IMAGE in payload/install-wordpress.sh." ;;
      2) unknown=1 ;;
    esac
  fi

  if [[ -n "$payload_squid" ]]; then
    _tag_exists ubuntu squid "$payload_squid"
    case $? in
      0) msg_ok "Image tag verified: ubuntu/squid:${payload_squid}" ;;
      1) msg_error "ubuntu/squid:${payload_squid} does not exist. Canonical's scheme is <squid>-<ubuntu>_<channel> (e.g. 6.6-24.04_edge) or plain 'latest'. Correct SQUID_IMAGE in payload/stages/09-crowdsec-and-backup.sh." ;;
      2) unknown=1 ;;
    esac
  fi

  [[ $unknown -eq 1 ]] && msg_warn "Could not reach the registry to verify image tags — continuing. If the install later dies with 'manifest unknown', a pinned tag is wrong."
  return 0
}
_check_image_tags

