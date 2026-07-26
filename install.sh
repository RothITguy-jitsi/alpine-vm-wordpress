#!/usr/bin/env bash
# =============================================================================
# install.sh — WordPress VM provisioning entry point (Proxmox VE host)
# =============================================================================
# Run this ON THE PROXMOX HOST as root. It builds a hardened Alpine +
# Podman (WordPress + MariaDB) + CrowdSec VM: downloads and verifies the
# Alpine cloud image, injects configuration and the in-VM installer directly
# onto the disk image (no network dependency inside the VM for the initial
# file layout), then creates and starts the Proxmox VM.
#
# This used to be one 8,694-line script. It is now this thin entry point
# plus lib/*.sh (sourced below, in order) and payload/ (files copied onto
# the VM disk for the in-VM installer to use). See README.md for the full
# repository layout and CHANGELOG.md for what changed and why.
#
# USAGE — two supported ways to run this, both fully supported, not one
# "real" way and one fallback:
#
#   1. Single command, no git required (Proxmox does not ship git by
#      default, and this avoids installing it just to fetch a script):
#        curl -fsSL -O https://raw.githubusercontent.com/RothITguy-jitsi/alpine-vm-wordpress/refs/heads/main/install.sh
#        chmod +x install.sh
#        sudo ./install.sh
#      install.sh notices it's running standalone (no sibling lib/ or
#      payload/) and fetches the rest of the repository itself -- see
#      "Self-bootstrap" below for exactly what that does and why.
#
#   2. A full clone, if you already have git or want the whole history:
#        git clone https://github.com/RothITguy-jitsi/alpine-vm-wordpress.git
#        cd alpine-vm-wordpress
#        sudo ./install.sh
#      install.sh finds lib/ and payload/ right next to itself and skips
#      the self-bootstrap step entirely -- nothing is downloaded twice.
#
# Every prompt, default, generated file, and VM setting is unchanged from
# v8-1 -- this is a reorganization, not a rewrite. See CHANGELOG.md.
# =============================================================================
set -e

# ── Self-bootstrap ────────────────────────────────────────────────────────────
# Added for the curl-one-liner usage above. install.sh on its own is not
# enough to build the VM -- lib/*.sh has to run somewhere, and payload/ has
# to physically exist somewhere to be copied onto the VM disk. When a full
# checkout isn't there already, this fetches ONLY what's missing: the
# GitHub-generated tarball of the whole repo (no git needed -- it's a plain
# HTTPS download GitHub builds on request), into a temp directory that is
# deleted again when this script exits, by the SAME cleanup() trap that
# already tears down every other temp resource this install creates (see
# lib/00-preflight.sh) -- "minimize what's loaded onto the Proxmox host"
# means during the ~15-minute run, not permanently, and this doesn't touch
# a real git clone (REPO_DIR then points at YOUR directory, never deleted).
#
# Verifying what you run: this downloads over HTTPS (TLS already rules out
# tampering in transit) from whatever WPVM_REPO_REF names -- "main" by
# default, i.e. whatever is on the branch right now. That is the right
# default for "always get the latest fixes" but it is a materially weaker
# integrity story than pinning to a specific commit: a floating branch
# means a future compromise of the repo is fetched by every install run
# from that point on, with nothing here to catch it. If you want a fixed,
# reviewable reference instead of "whatever main is today," set
# WPVM_REPO_REF to a specific commit SHA (from this repo's own commit
# history) before running:
#   WPVM_REPO_REF=<40-char-sha> sudo -E ./install.sh
# This is the same trade-off, and the same trust model, as any single-file
# "curl | bash" installer (Docker's, rustup's, Homebrew's) -- no download-
# time checksum can substitute for that, since a checksum published in the
# same repo it's meant to verify is checking the repo against itself, not
# against an independent source. What a checksum-of-this-download CAN
# catch -- truncation, a corrupted transfer, a wrong URL -- it does; see
# the size and structure checks below.
REPO_OWNER="RothITguy-jitsi"
REPO_NAME="alpine-vm-wordpress"
REPO_REF="${WPVM_REPO_REF:-main}"

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_WPVM_BOOTSTRAP_DIR=""   # set below only if a fetch actually happens; read by
                         # lib/00-preflight.sh's cleanup() trap

if [[ -d "${SELF_DIR}/lib" && -d "${SELF_DIR}/payload" ]]; then
  REPO_DIR="$SELF_DIR"
else
  echo "install.sh is running standalone (no sibling lib/ or payload/) —"
  echo "fetching ${REPO_OWNER}/${REPO_NAME}@${REPO_REF}..."
  command -v curl >/dev/null 2>&1 || { echo "FATAL: curl not found." >&2; exit 1; }
  command -v tar  >/dev/null 2>&1 || { echo "FATAL: tar not found."  >&2; exit 1; }

  _WPVM_BOOTSTRAP_DIR=$(mktemp -d /tmp/wpvm-bootstrap.XXXXXX) \
    || { echo "FATAL: could not create a temp directory." >&2; exit 1; }

  # Commit SHAs (7-40 hex chars) use a bare .../archive/<sha>.tar.gz;
  # anything else is treated as a branch name, needing the refs/heads/
  # prefix. (Tags aren't auto-detected here -- pass a commit SHA if you
  # want a fixed reference; branches cover the floating-default case.)
  if [[ "$REPO_REF" =~ ^[0-9a-f]{7,40}$ ]]; then
    TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/${REPO_REF}.tar.gz"
  else
    TARBALL_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/${REPO_REF}.tar.gz"
  fi

  ARCHIVE="${_WPVM_BOOTSTRAP_DIR}/src.tar.gz"
  curl -fsSL "$TARBALL_URL" -o "$ARCHIVE" || {
    echo "FATAL: could not download ${TARBALL_URL}" >&2
    echo "  Check network access from this host, and that '${REPO_REF}' is a real branch or commit." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  }

  # Sanity check, not a security check (see the note above): a 404/error
  # page saved as if it were the archive is a few hundred bytes; the real
  # thing is not. Catches a wrong URL or an unexpected redirect target,
  # not a deliberately-crafted malicious archive of a plausible size.
  ARCHIVE_SIZE=$(wc -c < "$ARCHIVE" 2>/dev/null || echo 0)
  if (( ARCHIVE_SIZE < 10000 )); then
    echo "FATAL: downloaded archive is only ${ARCHIVE_SIZE} bytes — that's not a real repository archive." >&2
    echo "  URL was: ${TARBALL_URL}" >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  fi

  tar -xzf "$ARCHIVE" -C "$_WPVM_BOOTSTRAP_DIR" || {
    echo "FATAL: downloaded file is not a valid .tar.gz archive." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  }
  rm -f "$ARCHIVE"

  # GitHub names the extracted top-level directory "<repo>-<ref>" (with
  # slashes in the ref sanitized) -- rather than hardcode that naming, just
  # take whatever single top-level directory the archive produced.
  REPO_DIR=$(find "$_WPVM_BOOTSTRAP_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
  if [[ -z "$REPO_DIR" || ! -d "${REPO_DIR}/lib" || ! -d "${REPO_DIR}/payload" ]]; then
    echo "FATAL: extracted archive doesn't look like ${REPO_NAME} (no lib/ or payload/ inside)." >&2
    rm -rf "$_WPVM_BOOTSTRAP_DIR"
    exit 1
  fi
  echo "Fetched $(find "$REPO_DIR" -type f | wc -l) files into a temp directory (removed when this script exits)."
fi

LIB_DIR="${REPO_DIR}/lib"

# ── Run each phase in order, in THIS shell (so every variable set by one ────
#    phase -- VMID, ROOT_PASS, ALPINE_URL, MNT, and so on -- stays in scope
#    for every later phase, exactly as it would in one unsplit script). ──────
. "${LIB_DIR}/00-preflight.sh"
. "${LIB_DIR}/01-interactive-setup.sh"
. "${LIB_DIR}/02-image-and-disk.sh"
. "${LIB_DIR}/03-dynamic-configs.sh"
. "${LIB_DIR}/04-nbd-mount-and-chroot.sh"
. "${LIB_DIR}/05-ssh-and-network-inject.sh"
. "${LIB_DIR}/06-vars-and-payload-inject.sh"
. "${LIB_DIR}/07-vm-create-and-start.sh"
