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

# ── Release signature verification ────────────────────────────────────────────
# The public key is embedded here rather than fetched, because a key fetched
# alongside the thing it verifies proves nothing. Publish this fingerprint
# somewhere that is NOT this repository -- a project site, a release
# announcement -- so it can be checked against an independent source once.
# After that, a repository compromise cannot go unnoticed: the attacker would
# have to change this line too, and anyone who recorded the key sees it.
#
# Honest scope: for a first-time user who fetches install.sh and the release
# from the same place, this is not a root of trust. It is tamper-evidence
# with a short, checkable identifier -- which is meaningfully better than an
# unsigned curl|bash, and is not the same as a trusted supply chain.
WASP_PUBKEY="${WASP_PUBKEY:-RWSi+SUZQWeFKd9yTC3Q7xAEADUph345WdgwOOlxK+dV40GHEqMsFTPc}"    # set to the release key; empty = unsigned build

# Where the key fingerprint is published independently of this repository.
# The point of a second location is DIFFERENT CREDENTIALS, not merely a
# different URL: a Gist or a Pages site on the same GitHub account falls to
# exactly the compromise this is meant to make visible. A DNS record is held
# at the registrar, which is a separate account entirely.
WASP_KEY_DNS="${WASP_KEY_DNS:-minisign._wasp.rothitguy.pro}"

# Cross-check the embedded key against that DNS record.
#
# HONEST SCOPE, because this is easy to overstate: plain DNS is spoofable by
# anyone on the network path, so this is CORROBORATION, not a second root of
# trust. It answers "does the key baked into this file match the one published
# under separate credentials?" -- which catches a repository compromise that
# swapped both the release and the embedded key, and catches nothing at all
# against an attacker who also controls your resolver. With DNSSEC on the zone
# it is meaningfully stronger. Treat a mismatch as serious and a match as
# reassuring rather than conclusive.
verify_key_dns() {
  [[ -n "$WASP_PUBKEY" ]] || return 0
  [[ "${WASP_SKIP_KEY_DNS:-0}" == "1" ]] && return 0
  command -v dig >/dev/null 2>&1 || command -v host >/dev/null 2>&1 || {
    echo "  (dig/host not present — skipping the DNS key cross-check)"; return 0; }

  local published=""
  if command -v dig >/dev/null 2>&1; then
    published=$(dig +short +timeout=5 +tries=2 TXT "$WASP_KEY_DNS" 2>/dev/null \
                | tr -d '"' | tr -d '\r' | grep -E '^RW' | head -1)
  else
    published=$(host -t TXT "$WASP_KEY_DNS" 2>/dev/null \
                | sed -n 's/.*"\(RW[^"]*\)".*/\1/p' | head -1)
  fi

  if [[ -z "$published" ]]; then
    # Not fatal: the record may not be published yet, DNS may be filtered, or
    # the host may have no outbound resolver. Saying so is more useful than
    # failing on an absence that has many innocent causes.
    echo "  No key record at ${WASP_KEY_DNS} — cross-check skipped."
    return 0
  fi
  if [[ "$published" == "$WASP_PUBKEY" ]]; then
    echo "  ✔ Embedded key matches the one published at ${WASP_KEY_DNS}"
    return 0
  fi
  echo "" >&2
  echo "  ✗ KEY MISMATCH." >&2
  echo "      embedded in install.sh : ${WASP_PUBKEY}" >&2
  echo "      published in DNS       : ${published}" >&2
  echo "" >&2
  echo "  These should be identical. Either the release key was rotated and" >&2
  echo "  this copy of install.sh is stale, or this copy of install.sh did not" >&2
  echo "  come from the project. Do not proceed until you know which." >&2
  echo "  Check independently: https://rothitguy.pro/wasp-signing-key/" >&2
  if [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]]; then
    echo "  FATAL: WASP_REQUIRE_SIGNATURE=1." >&2; exit 1
  fi
  # Not fatal by default: a stale checkout after a legitimate key rotation
  # would otherwise brick every install, and the signature check below is the
  # control that actually decides whether these files are authentic.
  printf "  Continue anyway? [y/N] : " >&2
  read -r _kc
  [[ "${_kc}" =~ ^[Yy] ]] || { echo "  Aborted." >&2; exit 1; }
}

verify_release() {
  local dir="$1"
  local man="${dir}/MANIFEST.sha256"
  local sig="${man}.minisig"

  if [[ -z "$WASP_PUBKEY" ]]; then
    echo "NOTE: this build is unsigned (no release key configured)." >&2
    echo "  Files were fetched over HTTPS but their contents are not verified." >&2
    [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]] && {
      echo "FATAL: WASP_REQUIRE_SIGNATURE=1 and there is no key to verify with." >&2; exit 1; }
    return 0
  fi
  if [[ ! -f "$man" || ! -f "$sig" ]]; then
    echo "WARNING: no signed manifest in this release." >&2
    echo "  Expected MANIFEST.sha256 and MANIFEST.sha256.minisig." >&2
    [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]] && { echo "FATAL: signature required." >&2; exit 1; }
    return 0
  fi
  if ! command -v minisign >/dev/null 2>&1; then
    # Deliberately not silently downgraded to "hashes only": hashes from an
    # unverified manifest catch corruption, not tampering, and reporting that
    # as verification would be worse than reporting nothing.
    echo "WARNING: minisign is not installed, so the release SIGNATURE cannot be checked." >&2
    echo "  Install it and re-run to verify:  apt install minisign" >&2
    [[ "${WASP_REQUIRE_SIGNATURE:-0}" == "1" ]] && { echo "FATAL: signature required." >&2; exit 1; }
    return 0
  fi

  verify_key_dns
  echo "Verifying release signature…"
  local out
  if ! out=$(minisign -Vm "$man" -P "$WASP_PUBKEY" 2>&1); then
    echo "FATAL: the release manifest signature is NOT valid." >&2
    echo "  ${out}" >&2
    echo "  Either this release was not signed with the expected key, or the" >&2
    echo "  files were altered after signing. Not proceeding." >&2
    exit 1
  fi
  # The trusted comment is covered by the signature, so the version it names
  # cannot be forged without the secret key.
  echo "  ${out}" | grep -i "trusted comment" || true

  echo "Verifying file hashes against the signed manifest…"
  local bad=0
  ( cd "$dir" && sha256sum -c --quiet MANIFEST.sha256 ) || bad=1
  if [[ $bad -ne 0 ]]; then
    echo "FATAL: a file does not match the signed manifest." >&2
    echo "  The signature was valid, so the manifest itself is authentic —" >&2
    echo "  which means a shipped file was modified after signing." >&2
    exit 1
  fi
  echo "  All files match the signed manifest."
}
verify_release "$REPO_DIR"

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
