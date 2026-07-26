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
# Usage:
#   git clone <this repo's URL>
#   cd <repo>
#   sudo ./install.sh
#
# Every prompt, default, generated file, and VM setting is unchanged from
# v8-1 -- this is a reorganization, not a rewrite. See CHANGELOG.md.
# =============================================================================
set -e

# REPO_DIR: the directory this script lives in, resolved to an absolute path
# regardless of the caller's current directory or how install.sh was
# invoked (`./install.sh`, `bash install.sh`, a symlink, etc.). Every lib
# file and the payload/ copy step below reads from here.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${REPO_DIR}/lib"

if [[ ! -d "${REPO_DIR}/payload" || ! -d "${LIB_DIR}" ]]; then
  echo "FATAL: payload/ or lib/ not found next to install.sh." >&2
  echo "  Run this from a full clone of the repository, not a single" >&2
  echo "  downloaded file -- install.sh needs its sibling lib/ and" >&2
  echo "  payload/ directories to build the VM." >&2
  exit 1
fi

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
