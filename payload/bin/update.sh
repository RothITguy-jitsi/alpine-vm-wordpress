#!/bin/sh
# =============================================================================
# update.sh — WordPress VM update utility
# Usage: update.sh [check|status|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all|trivy]
#
# INTEGRATION NOTES (read before dropping this in):
#  - Rootful only. No ROOTLESS_MODE, no PRUN dispatch wrapper — every call is
#    a plain `podman ...`. If your install script still writes ROOTLESS_MODE
#    into /etc/wp-install/vars.sh that's harmless; it's just never read here.
#  - Assumes container names wordpress / mariadb / crowdsec, and the
#    network-segmented layout from the v7-6/v7-6c line: wp-front (public,
#    WordPress's egress + published port) and wp-db (--internal,
#    WordPress+MariaDB only). MariaDB is addressed purely by DNS name
#    ("mariadb", via aardvark-dns + an explicit --network-alias on wp-db)
#    rather than a fixed IP baked into WordPress — v7-11 removed the old
#    --add-host "mariadb:10.89.20.2" entries that used to shadow this (see
#    that patch note for why a static entry was actively wrong, not just
#    redundant, and why removing it doesn't touch wp-db's own isolation).
#    If your main script still uses a single flat wp-net, wp-front/wp-db
#    is the only naming assumption left to adjust to match.
#  - Reads /etc/wp-install/vars.sh for USE_DIGEST_PINNING and GEOIP_ENABLED
#    (same file your installer already writes) and reads/writes a new
#    /etc/wp-install/pinned.env for per-component pinned tag+digest — see
#    the PINNED STATE note below. Pair this file with the companion
#    installer-side snippet (digest-pinning + Skopeo block) so pinned.env
#    exists from first boot; if it doesn't exist yet, this script bootstraps
#    it from whatever's currently running the first time it's invoked.
#  - Container-recreation commands (the actual `podman run ...` blocks in
#    do_wp_update/do_db_update/do_cs_update) mirror the flags your install
#    script should already be using to create these containers the first
#    time (caps, mounts, env-file, etc.). If your install script customizes
#    any of that, mirror the same customization here or the recreated
#    container will drift from the original.
#  - `update.sh wp` validates a freshly pulled WordPress image on a
#    throwaway "wordpress-candidate" container bound to 127.0.0.1:18080
#    (WP_CANDIDATE_PORT, defined below) — using the same wp-health-check.sh
#    depth as every other health-check site in this script — before it
#    ever touches the production container on :80. Production is only
#    renamed and stopped once that candidate passes. Needs 127.0.0.1:18080
#    free on the VM; change WP_CANDIDATE_PORT if that's already in use for
#    something else.
#
# WHAT CHANGED FROM THE PRE-SKOPEO VERSION OF THIS SCRIPT:
#  - `digest-check` (and therefore a bare `update.sh`/`update.sh check`)
#    used to `podman pull` WordPress, MariaDB, AND CrowdSec on every single
#    invocation just to see whether the registry had republished anything
#    under the same tag — 500 MB-1 GB+ downloaded to answer "did anything
#    change?", every time, even when the answer was no. Skopeo's
#    `inspect docker://ref` asks the registry's manifest endpoint directly
#    (a few KB, no layer data) and reports the digest currently published
#    for a tag without pulling anything. Every digest check below tries
#    Skopeo first; a `podman pull` only happens once a digest is actually
#    going to be used — because it's new, or because Skopeo itself failed,
#    in which case this falls back to pulling by tag and asking Podman what
#    it resolved (the old method — still correct, just back to the old
#    bandwidth cost for that one check).
#  - The old version derived "what tag/digest is currently pinned" by
#    sed-parsing it back out of the running container's own
#    `{{.Config.Image}}` string, which only worked because a pinned
#    reference still had a visible tag in it (`repo:tag@sha256:digest`) —
#    itself dependent on a runtime test of whether this Podman accepted a
#    combined tag+digest reference at all. Every pull below is now a plain
#    `repo@sha256:digest` (no tag, no ambiguity, no version-dependent
#    combined-reference test needed), and the tag is tracked explicitly in
#    /etc/wp-install/pinned.env instead of being re-derived from a string
#    that may no longer contain it.
#  - A bare `update.sh` / `update.sh check` / `update.sh status` is now
#    READ-ONLY: it reports what's running, what's pinned, and whether the
#    registry has anything newer (Skopeo only — no pulls, no prompts).
#    `update.sh all` is the explicit "update everything" command (unchanged
#    otherwise — each component still asks before touching anything).
#    `update.sh digest-check` still exists as a shortcut for "refresh
#    wp/db/crowdsec if the registry has anything newer, skip the OS package
#    prompt" — it now shares the same Skopeo-first check the wp/db/crowdsec
#    update paths use directly, instead of a separate implementation that
#    used to re-pull everything just to compare.
# =============================================================================
set -e

# Fallback target tags — used only if /etc/wp-install/pinned.env doesn't
# exist yet, or is missing an entry for a component (fresh VM never
# updated through this script, or the file was lost). Once pinned.env has
# a value for a component, THAT value is authoritative, not this constant.
PINNED_WP_VER="6.9.4-php8.3-apache"
PINNED_DB_VER="11.4"
PINNED_CS_VER="v1.7.8"
WP_REGISTRY="docker.io/wordpress"
DB_REGISTRY="docker.io/mariadb"
CS_REGISTRY="docker.io/crowdsecurity/crowdsec"

# Loopback-only port do_wp_update() uses to validate a freshly pulled
# WordPress image BEFORE the production container on host port 80 is ever
# touched — see the main script's WORDPRESS UPDATE CUTOVER header note
# (item 40) for the full rationale. Change this only if something else on
# the VM already binds it.
WP_CANDIDATE_PORT="18080"

# MariaDB's bind-mounted data directory, and where do_db_update() keeps a
# pre-update filesystem snapshot of it before the new image ever touches
# the real thing — see the v7-9 header notes (item 41b) for the full
# rationale. Both live on the VM's single root filesystem, same as
# everything else this script writes.
DB_DATA_DIR="/home/wpuser/wp/mysql"
DB_SNAPSHOT_DIR="/home/wpuser/wp/mysql-preupdate-snapshot"

# v7-16: auto-elevate via doas rather than hard-failing. update.sh needs root
# (reads pinned.env, swaps containers, edits the firewall). But the admin can
# only copy/paste over SSH as the unprivileged wheel user — the root console
# via `qm terminal` can't paste — so demanding root made gathering output
# painful. Re-exec through doas so it "just works" over SSH: doas prompts for
# the admin password once (permit persist :wheel), then everything runs as
# root with output in the copyable SSH session. Args are still intact here
# (the subcommand dispatch runs at the end of this script), so "$@" survives
# the exec. If doas isn't present, fall back to the original hard error.
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then
    exec doas "$0" "$@"
  fi
  echo "ERROR: must run as root (or install doas and run as a wheel user)" >&2
  exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
# REGRESSION FIX: update.sh rebuilds the WordPress container twice (candidate,
# then production cutover) and used to hardcode its own copy of the wp-config
# extras and volume list. That made it the fourth and fifth places
# constructing the same container -- so running `update.sh wp` silently
# dropped the site address (WP_HOME/WP_SITEURL) and the SMTP credential
# mount, exactly like enabling GeoIP and rebooting did. All of them now read
# the record stage 06 writes. The literal below is the historical value, kept
# only as a fallback for a VM provisioned before that record existed.
WP_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);'
WP_EXTRA_VOLS=""
[ -r /etc/wp-install/wp-run-extra.env ] && . /etc/wp-install/wp-run-extra.env
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"

# ── Image reference validation (v7-6d, carried forward) ────────────────────
# validate_image_tag: closes a gap flagged in review — the VER argument to
# `update.sh wp|db|crowdsec [VER]` used to flow straight into an image
# reference with no validation of its own, relying entirely on podman's own
# parser to reject anything malformed. Grammar matches Docker/OCI tag rules:
# starts with [A-Za-z0-9_], then up to 127 more of [A-Za-z0-9_.-].
validate_image_tag() {
  _vit_tag="$1"
  if [ -z "$_vit_tag" ]; then
    echo "ERROR: empty version/tag supplied" >&2
    return 1
  fi
  if [ "${#_vit_tag}" -gt 128 ]; then
    echo "ERROR: '${_vit_tag}' exceeds the 128-character tag limit" >&2
    return 1
  fi
  case "$_vit_tag" in
    [A-Za-z0-9_]*) ;;
    *) echo "ERROR: '${_vit_tag}' must start with a letter, digit, or underscore" >&2; return 1 ;;
  esac
  case "$_vit_tag" in
    *[!A-Za-z0-9._-]*)
      echo "ERROR: '${_vit_tag}' contains characters other than A-Z a-z 0-9 . _ -" >&2
      return 1 ;;
  esac
  return 0
}

# validate_digest_ref: sanity-checks a "sha256:<64 lowercase hex>" digest, or
# a full "repo[:tag]@sha256:<64 hex>" reference, before anything trusts it.
validate_digest_ref() {
  _vdr_ref="$1"
  case "$_vdr_ref" in
    *@sha256:*) _vdr_digest="${_vdr_ref##*@sha256:}" ;;
    sha256:*)   _vdr_digest="${_vdr_ref#sha256:}" ;;
    *) echo "ERROR: '${_vdr_ref}' has no sha256: digest" >&2; return 1 ;;
  esac
  if [ "${#_vdr_digest}" -ne 64 ]; then
    echo "ERROR: '${_vdr_ref}' digest is not 64 characters" >&2
    return 1
  fi
  case "$_vdr_digest" in
    *[!0-9a-f]*)
      echo "ERROR: '${_vdr_ref}' digest is not lowercase hex" >&2
      return 1 ;;
  esac
  return 0
}

cd /tmp

DIGEST_PIN_LOG="/var/log/wp-digest-pinning.log"

# ── PINNED STATE ────────────────────────────────────────────────────────────
# /etc/wp-install/pinned.env is the single source of truth for "what tag and
# digest are we currently pinned to" per component — written by the
# installer-side Skopeo/digest-pinning snippet at install time, and kept
# current here after every successful update. Deliberately NOT re-derived
# from the running container's image string on every run (see header note).
WP_TAG="" WP_DIGEST="" DB_TAG="" DB_DIGEST="" CS_TAG="" CS_DIGEST=""
# shellcheck disable=SC1091
[ -f /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

# BUG FIX (v7-12, #9): validate what was just loaded before trusting it.
# The operator-supplied [VER] argument to `update.sh wp|db|crowdsec [VER]`
# has gone through validate_image_tag()/validate_digest_ref() (defined
# above) since v7-6d (item 24) before it's used in an image reference —
# but WP_TAG/WP_DIGEST/DB_TAG/DB_DIGEST/CS_TAG/CS_DIGEST, loaded from
# pinned.env by a plain `. /etc/wp-install/pinned.env`, took a completely
# separate, unvalidated path into the exact same kind of reference. This
# should never actually fire against a pinned.env this version of
# update.sh wrote itself (see the atomic _save_pinned() below), but is a
# safety net for a pinned.env inherited from an older update.sh, a manual
# edit, or a file that predates that atomic-write fix. A value that fails
# validation is discarded (reset to empty), which the rest of this script
# already treats as "not pinned yet" — falling back to the PINNED_*_VER
# constants above, or triggering a fresh bootstrap/resolve just below —
# rather than ever reaching a `podman pull`/`podman run` with an
# unvalidated string. Six explicit checks rather than a loop over dynamic
# variable names: every value here is used directly, by its own name, for
# the rest of this script, and spelling each one out avoids reaching for
# eval to touch them programmatically.
if [ -n "$WP_TAG" ] && ! validate_image_tag "$WP_TAG" 2>/dev/null; then
  echo "  ⚠  pinned.env: WP_TAG '${WP_TAG}' failed validation — ignoring, will re-resolve" >&2
  WP_TAG=""
fi
if [ -n "$WP_DIGEST" ] && ! validate_digest_ref "$WP_DIGEST" 2>/dev/null; then
  echo "  ⚠  pinned.env: WP_DIGEST '${WP_DIGEST}' failed validation — ignoring, will re-resolve" >&2
  WP_DIGEST=""
fi
if [ -n "$DB_TAG" ] && ! validate_image_tag "$DB_TAG" 2>/dev/null; then
  echo "  ⚠  pinned.env: DB_TAG '${DB_TAG}' failed validation — ignoring, will re-resolve" >&2
  DB_TAG=""
fi
if [ -n "$DB_DIGEST" ] && ! validate_digest_ref "$DB_DIGEST" 2>/dev/null; then
  echo "  ⚠  pinned.env: DB_DIGEST '${DB_DIGEST}' failed validation — ignoring, will re-resolve" >&2
  DB_DIGEST=""
fi
if [ -n "$CS_TAG" ] && ! validate_image_tag "$CS_TAG" 2>/dev/null; then
  echo "  ⚠  pinned.env: CS_TAG '${CS_TAG}' failed validation — ignoring, will re-resolve" >&2
  CS_TAG=""
fi
if [ -n "$CS_DIGEST" ] && ! validate_digest_ref "$CS_DIGEST" 2>/dev/null; then
  echo "  ⚠  pinned.env: CS_DIGEST '${CS_DIGEST}' failed validation — ignoring, will re-resolve" >&2
  CS_DIGEST=""
fi

_save_pinned() {
  # BUG FIX (v7-12, #8): temp-file + mv instead of a direct `cat >`. A
  # direct `cat > pinned.env << EOF` truncates the target the instant the
  # shell opens it for writing, before a single byte of the heredoc body
  # lands — so anything reading pinned.env in that exact window (this
  # function runs after every successful wp/db/crowdsec update, and
  # wp-geoip-setup.sh reads this file independently of update.sh's own
  # update-lock, which only guards state-changing update.sh subcommands
  # against each other, not an unrelated reader) could see a truncated or
  # empty file instead of the old value or the new one. mv within the
  # same directory is a single rename(2) — POSIX-atomic — so a reader
  # always sees either the complete previous file or the complete new one.
  mkdir -p /etc/wp-install
  local _tmp="/etc/wp-install/pinned.env.tmp.$$"
  cat > "$_tmp" << PINNEDENV
# WordPress VM — pinned image tag + digest per component.
# Written by the installer's digest-pinning snippet; kept current by
# update.sh after every successful update. Do not edit by hand while
# update.sh might be running.
WP_TAG="${WP_TAG}"
WP_DIGEST="${WP_DIGEST}"
DB_TAG="${DB_TAG}"
DB_DIGEST="${DB_DIGEST}"
CS_TAG="${CS_TAG}"
CS_DIGEST="${CS_DIGEST}"
PINNEDENV
  chmod 600 "$_tmp" 2>/dev/null || true
  mv -f "$_tmp" /etc/wp-install/pinned.env 2>/dev/null || true
}

# Running-container inspection — status display and GeoIP detection only.
# NOT used for version comparisons (see PINNED STATE above).
RUNNING_WP_RAW=$(podman inspect wordpress --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_DB_RAW=$(podman inspect mariadb   --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_CS_RAW=$(podman inspect crowdsec  --format "{{.Config.Image}}" 2>/dev/null || true)
WP_IS_GEOIP=0
case "$RUNNING_WP_RAW" in localhost/wordpress-geoip:*) WP_IS_GEOIP=1 ;; esac

# Bootstrap pinned.env the first time this script runs on a VM that doesn't
# have one yet (upgraded from an older update.sh, or the file was lost):
# best-effort reconstruct tag/digest from whatever's actually running right
# now, then persist it so every run after this one uses the fast path.
_bootstrap_one() {
  local raw="$1" registry="$2"
  echo "$raw" | sed -e 's|^localhost/wordpress-geoip:||' -e "s|^${registry}:||" -e 's|@sha256:.*||'
}
_BOOTSTRAPPED=0
if [ -z "$WP_TAG" ] && [ -z "$WP_DIGEST" ] && [ -n "$RUNNING_WP_RAW" ]; then
  WP_TAG=$(_bootstrap_one "$RUNNING_WP_RAW" "$WP_REGISTRY")
  WP_DIGEST=$(echo "$RUNNING_WP_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$WP_TAG" ] && _BOOTSTRAPPED=1
fi
if [ -z "$DB_TAG" ] && [ -z "$DB_DIGEST" ] && [ -n "$RUNNING_DB_RAW" ]; then
  DB_TAG=$(_bootstrap_one "$RUNNING_DB_RAW" "$DB_REGISTRY")
  DB_DIGEST=$(echo "$RUNNING_DB_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$DB_TAG" ] && _BOOTSTRAPPED=1
fi
if [ -z "$CS_TAG" ] && [ -z "$CS_DIGEST" ] && [ -n "$RUNNING_CS_RAW" ]; then
  CS_TAG=$(_bootstrap_one "$RUNNING_CS_RAW" "$CS_REGISTRY")
  CS_DIGEST=$(echo "$RUNNING_CS_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$CS_TAG" ] && _BOOTSTRAPPED=1
fi
[ "$_BOOTSTRAPPED" = "1" ] && _save_pinned

ask_yn() { printf "%s [y/N]: " "$1"; read ans; case "$ans" in [Yy]*) return 0;; *) return 1;; esac; }

# ── Container-state preflight — stop suppressing critical Podman errors ────
# PRODUCTION SAFETY FIX (v7-6k): every "swap in a replacement container"
# path in this script hid its `podman rename <live> <live>-old` behind
# `2>/dev/null || true` (WordPress's forward swap), and every rollback swap
# (`podman rename <live>-old <live>` for WordPress, MariaDB, AND CrowdSec)
# discarded its result the same way. That meant a rename failure — source
# container missing, a stale *-old container left over from a previous
# crashed/interrupted update, or Podman itself in an inconsistent state —
# was silently swallowed and the script carried on as if nothing had
# happened.
#
# The concrete failure this caused in do_wp_update(): if
# `podman rename wordpress wordpress-old` silently failed, "wordpress" kept
# its original name, so the following `podman run -d --name wordpress ...`
# then failed too (a name collision) — a failure that WAS checked, so
# control fell into the "container start failed — rolled back" branch.
# That branch's first line was `podman rm -f wordpress`, deleting the
# still-good, still-running ORIGINAL WordPress container in the mistaken
# belief it was cleaning up a failed new attempt. One suppressed error
# cascaded into deleting a healthy production container.
#
# require_clean_container_state() closes the forward half of this by
# verifying the rename's own preconditions up front instead of discovering
# them via a cascading failure two steps later. Every rename call site below
# — forward swap and rollback swap, across WordPress, MariaDB, and CrowdSec
# — now also checks the rename/start result directly instead of discarding
# it, and prints exactly what needs manual attention when a rollback itself
# fails, since that's the one moment silence is most dangerous: it means the
# site (or the database, or CrowdSec) is down right now and nobody has been
# told.
require_clean_container_state() {
  local current="$1" old_name="$2"
  podman container exists "$current" || {
    echo "✗  Required container '${current}' does not exist — nothing to update. Aborting; nothing was changed." >&2
    return 1
  }
  if podman container exists "$old_name"; then
    echo "✗  Stale container '${old_name}' already exists, left over from a previous" >&2
    echo "   update that didn't finish cleanly (crashed, interrupted, or aborted mid-way)." >&2
    echo "   Refusing to rename over it. Inspect it first, then either restore from it" >&2
    echo "   or remove it once you're sure it's not needed:" >&2
    echo "     podman inspect ${old_name}" >&2
    echo "     podman rm -f ${old_name}" >&2
    return 1
  fi
  return 0
}

# ── Skopeo: remote digest lookup, no image pull ────────────────────────────
# $1 = full tag reference, e.g. docker.io/wordpress:6.9.4-php8.3-apache
# stdout: sha256:<64 hex> on success. Returns 1 on any failure (Skopeo
# missing, network error, unparseable output) — every caller treats that as
# "fall back to the old method", never as fatal.
#
# BUG FIX (v7-14) — THIS RETURNED A MULTI-LINE VALUE AND SILENTLY BROKE
# DIGEST PINNING AND digest-check. `skopeo inspect` emits a top-level
# "Digest" (the image manifest digest — the one we want) AND a "LayersData"
# array in which EVERY ENTRY also has its own "Digest" field. The old
# extraction was:
#     grep -oE '"Digest"...' | grep -oE 'sha256:[0-9a-f]{64}'
# with no head/limit, so for a typical WordPress image it returned the
# manifest digest followed by 10-20 layer digests, one per line. Two
# concrete failures resulted, both silent:
#   1. _pin_digest() built candidate="${repo}@${digest}" from that
#      multi-line value, producing a syntactically invalid image reference.
#      `podman pull` rejected it every time, burned all 3 retry attempts
#      with 4-second sleeps, logged a scary "Skopeo resolved a digest but
#      pulling it failed" warning, then fell through to the tag-pull
#      fallback — meaning the entire "resolve cheaply via Skopeo without
#      pulling" design never actually took effect, and every install did
#      full pulls anyway.
#   2. Worse: show_check_summary()'s _report_one() and do_digest_check()
#      compare the resolved remote digest against the stored single-line
#      digest from pinned.env. A multi-line value can never equal a
#      single-line one, so EVERY `update.sh check` reported "NEWER DIGEST
#      AVAILABLE under this tag" for all three components on every run,
#      forever, and `update.sh digest-check` re-pulled and re-deployed all
#      three components every single time it ran even when nothing had
#      changed upstream.
# FIX: ask Skopeo for exactly the one field via its Go-template --format
# (unambiguous, no parsing), fall back to the grep path with an explicit
# `head -1` for older Skopeo builds that lack --format, and validate the
# final value is exactly one well-formed sha256 line before returning it.
# Set by _skopeo_digest so callers can distinguish "the registry says this
# tag does not exist" (fatal — no point pulling or scanning) from "the lookup
# failed" (transient — falling back to a tag comparison is reasonable).
# Previously stderr went to /dev/null, so that distinction was unavailable and
# a mistyped tag became a multi-minute detour through a misleading
# "scanner-side failure / unknown security state" message.
_SKOPEO_ERR=""
_skopeo_digest() {
  local ref="$1" out digest _errf
  command -v skopeo >/dev/null 2>&1 || return 1
  _SKOPEO_ERR=""
  _errf=$(mktemp) || _errf=""

  # Preferred: let Skopeo emit just the manifest digest. No JSON parsing,
  # so LayersData can't contaminate the result no matter how it's shaped.
  if [ -n "$_errf" ]; then
    digest=$(skopeo inspect --format '{{.Digest}}' "docker://${ref}" 2>"$_errf" | head -1) || digest=""
    _SKOPEO_ERR=$(cat "$_errf" 2>/dev/null)
    rm -f "$_errf"
  else
    digest=$(skopeo inspect --format '{{.Digest}}' "docker://${ref}" 2>/dev/null | head -1) || digest=""
  fi

  # Fallback for Skopeo builds without --format support: parse the JSON.
  # v7-15 (audit #2): prefer jq, which extracts .Digest by KEY — no reliance
  # on the manifest digest appearing before LayersData in field order, which
  # is not a stable contract. Only if jq is unavailable does it drop to a
  # grep+head-1 that does assume that ordering. The validation below is the
  # real backstop either way: a wrong pick fails closed to "no digest" and
  # the caller falls back to a tag pull rather than using garbage.
  if [ -z "$digest" ]; then
    out=$(skopeo inspect "docker://${ref}" 2>/dev/null) || return 1
    if command -v jq >/dev/null 2>&1; then
      digest=$(printf '%s' "$out" | jq -r '.Digest // empty' 2>/dev/null | head -1)
    fi
    if [ -z "$digest" ]; then
      digest=$(printf '%s' "$out" \
        | grep -oE '"Digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]{64}"' \
        | grep -oE 'sha256:[0-9a-f]{64}' \
        | head -1)
    fi
  fi

  # Validate: exactly one line, exactly the sha256:<64 hex> shape. Anything
  # else (empty, multi-line, truncated, wrong prefix) is treated as a
  # failed lookup so the caller falls back cleanly instead of building an
  # invalid image reference out of it.
  [ -n "$digest" ] || return 1
  [ "$(printf '%s\n' "$digest" | wc -l | tr -d ' ')" = "1" ] || return 1
  case "$digest" in
    sha256:*) ;;
    *) return 1 ;;
  esac
  printf '%s' "$digest" | grep -qE '^sha256:[0-9a-f]{64}$' || return 1
  printf '%s\n' "$digest"
}
_resolve_digest() {
  local ref="$1" attempt digest
  for attempt in 1 2 3; do
    digest=$(_skopeo_digest "$ref") && [ -n "$digest" ] && { printf '%s\n' "$digest"; return 0; }
    [ "$attempt" -lt 3 ] && sleep 2
  done
  return 1
}

# ── Trivy: container vulnerability scanner ────────────────────────────────
TRIVY_CACHE_DIR="/var/cache/trivy"

setup_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    mkdir -p "${TRIVY_CACHE_DIR}"
    return 0
  fi
  echo "  → Installing Trivy (vulnerability scanner)..."
  mkdir -p "${TRIVY_CACHE_DIR}"
  if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
       trivy >/dev/null 2>&1; then
    echo "  ✔  Trivy installed (apk)"
  else
    apk add --no-cache wget >/dev/null 2>&1 || true
    TRIVY_VER="v0.71.2"
    # BUG FIX (v7-13, ChatGPT Finding 13): install.sh is now fetched at a
    # specific COMMIT HASH, not off the mutable `main` branch. Same commit
    # aquasecurity's OWN setup-trivy GitHub Action pins to (per their PR
    # #28, "Pin Trivy install script checkout to a specific commit"), so
    # what's fetched here is byte-identical to what their supply-chain-
    # hardened workflow fetches. This matters concretely: aquasecurity/
    # trivy's main branch was compromised in the real v0.69.4 supply chain
    # attack (StepSecurity's public writeup — the malicious release
    # exfiltrated data to scan.aquasecurtiy.org via an RSA-encrypted C2
    # channel and dropped a tpcp-docs backdoor repo on every runner's
    # GitHub account). raw.githubusercontent.com serves files by commit
    # hash content-addressably — a compromise of main cannot change what
    # THIS URL returns. To update: after auditing any change to trivy's
    # contrib/install.sh, update TRIVY_INSTALL_COMMIT to the newer commit.
    TRIVY_INSTALL_COMMIT="75c4dc0f45c5d7ffd05ae26df1e0c666787bdf2a"
    wget -qO /tmp/trivy-install.sh \
      "https://raw.githubusercontent.com/aquasecurity/trivy/${TRIVY_INSTALL_COMMIT}/contrib/install.sh" 2>/dev/null \
    && sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && echo "  ✔  Trivy ${TRIVY_VER} installed (official script, commit-pinned)" \
    || { echo "  ⚠  Trivy install failed — scans will be skipped"; return 1; }
    rm -f /tmp/trivy-install.sh
  fi
}

# ── Vulnerability exception governance ───────────────────────────────────────
# Replaces a bare y/N. A yes/no leaves no record of WHO accepted WHAT, WHY, or
# WHEN it should be revisited -- so an accepted CVE silently becomes permanent
# and nobody can later reconstruct the decision.
#
# The design goes slightly beyond "type a reason and email it", at no extra
# cost to the operator, because a reason alone still has two gaps:
#
#   SCOPE   The exception records the exact IMAGE DIGEST and is only honoured
#           for that digest. Accepting a finding on one image must not silently
#           carry over to the next image, which will have a different set of
#           vulnerabilities. A blanket "yes" that outlives its subject is how
#           exceptions become policy by accident.
#   EXPIRY  Exceptions expire (default 90 days) and then have to be re-argued.
#           Without this, the first person to type a reason decides forever.
#
# The record is append-only and root-owned; the email is a copy, not the
# record, because mail can fail and an audit trail that depends on delivery is
# not an audit trail.
trivy_exception() {
  local img="$1"
  local log=/var/log/wasp-vuln-exceptions.log
  local digest who reason days until existing

  digest=$(printf '%s' "$img" | sed -n 's/.*@\(sha256:[0-9a-f]*\).*/\1/p')
  [ -n "$digest" ] || digest="$img"

  # An unexpired exception for THIS exact digest is honoured without asking
  # again -- re-prompting for a decision already made and recorded is how
  # people learn to type anything to get past the prompt.
  if [ -r "$log" ]; then
    existing=$(grep -F "digest=${digest}" "$log" 2>/dev/null | tail -1)
    if [ -n "$existing" ]; then
      until=$(printf '%s' "$existing" | sed -n 's/.*until=\([0-9-]*\).*/\1/p')
      if [ -n "$until" ] && [ "$(date -u +%Y-%m-%d)" \< "$until" ]; then
        echo "  ℹ  An accepted exception already covers this exact image digest,"
        echo "     valid until ${until}:"
        printf '     %s\n' "$(printf '%s' "$existing" | sed 's/.*reason=//')"
        return 0
      fi
      echo "  ⚠  A previous exception for this digest EXPIRED on ${until}."
      echo "     It has to be re-argued rather than silently renewed."
    fi
  fi

  echo ""
  echo "  Accepting this requires a written justification. It is recorded to"
  echo "  ${log} and emailed to the governance address."
  echo "  Leave the reason empty to abort the update instead."
  echo ""
  printf "  Reason for accepting these findings: "
  read -r reason
  # A reason nobody can act on later is the same as no reason. This is a low
  # bar deliberately -- it stops "ok" and "asdf", not someone determined.
  if [ ${#reason} -lt 15 ]; then
    echo "  ✗ No usable justification given — update aborted." >&2
    echo "    (A recorded exception has to mean something to whoever reads it" >&2
    echo "     in six months, including you.)" >&2
    return 1
  fi

  printf "  Days until this expires and must be re-reviewed [90]: "
  read -r days
  case "$days" in ''|*[!0-9]*) days=90 ;; esac
  [ "$days" -gt 365 ] && { days=365; echo "  (capped at 365)"; }
  until=$(date -u -d "+${days} days" +%Y-%m-%d 2>/dev/null || date -u +%Y-%m-%d)

  who="${SUDO_USER:-${DOAS_USER:-${USER:-unknown}}}"
  printf "  Accepted by [%s]: " "$who"
  read -r _w; [ -n "$_w" ] && who="$_w"

  mkdir -p "$(dirname "$log")"
  # Record WHICH vulnerabilities are being accepted, not merely that some
  # were. Without it the record says a decision happened and not what was
  # decided -- so a later reviewer cannot tell whether the reason still
  # applies, which is the only question a review asks. Trivy's cache makes
  # this second pass cheap.
  _cves=""
  if command -v trivy >/dev/null 2>&1; then
    _cves=$(trivy image --quiet --no-progress --scanners vuln \
              --severity HIGH,CRITICAL --format json "$img" 2>/dev/null \
            | sed -n 's/.*"VulnerabilityID": *"\([^"]*\)".*/\1/p' \
            | sort -u | head -40 | tr '\n' ' ')
  fi
  [ -n "$_cves" ] || _cves="(could not enumerate — see the scan output above)"

  printf '%s | who=%s | image=%s | digest=%s | until=%s | cves=%s | reason=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$who" "$img" "$digest" "$until" "$_cves" "$reason" >> "$log"
  chmod 600 "$log" 2>/dev/null || true
  echo "  ✔ Exception recorded (expires ${until})"

  if [ -x /usr/local/bin/wp-notify.sh ]; then
    _eb=$(mktemp)
    {
      printf 'A HIGH/CRITICAL vulnerability finding was ACCEPTED on this host.\n\n'
      printf '  Host    : %s\n' "$(hostname)"
      printf '  Image   : %s\n' "$img"
      printf '  Digest  : %s\n' "$digest"
      printf '  By      : %s\n' "$who"
      printf '  Expires : %s\n\n' "$until"
      printf 'Accepted vulnerabilities:\n'
      printf '%s' "$_cves" | tr ' ' '\n' | sed 's/^/  /' | grep . || printf '  (none enumerated)\n'
      printf '\n'
      printf 'Stated reason:\n  %s\n\n' "$reason"
      printf 'The exception applies ONLY to this image digest and lapses on the\n'
      printf 'date above, after which it must be re-argued.\n\n'
      printf 'Review every active exception on this host:\n'
      printf '  wp-hardening.sh exceptions\n\n'
      printf 'Full record: %s\n' "$log"
    } > "$_eb"
    # No cooldown: every acceptance is a separate governance event, and
    # de-duplicating them would hide exactly the pattern worth seeing.
    NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wasp-vuln-exception \
      "Vulnerability exception accepted on $(hostname)" "$_eb" \
      || echo "  ⚠ Exception recorded locally but the notification failed to send." >&2
    rm -f "$_eb"
  fi
  return 0
}

scan_image() {
  local img="$1" rc
  if ! command -v trivy >/dev/null 2>&1; then
    # v8 production fail-closed toggle: standard profile skips the scan and
    # proceeds (availability first); production refuses to update at all
    # without a working scanner, rather than apply an image whose security
    # state is unknown.
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      echo "  ✗  Trivy is not available, and DEPLOYMENT_PROFILE=production requires a" >&2
      echo "     completed vulnerability scan before any image is applied. Refusing to" >&2
      echo "     update. Install Trivy (apk add trivy, or see setup_trivy) and retry," >&2
      echo "     or re-run under DEPLOYMENT_PROFILE=standard for a lab install." >&2
      return 1
    fi
    echo "  ⚠  Trivy not available — skipping vulnerability scan"
    return 0
  fi
  echo "  → Scanning ${img} for HIGH/CRITICAL vulnerabilities (cache: ${TRIVY_CACHE_DIR})..."
  # BUG FIX (v7-13, ChatGPT Finding 14 in the audit): the old scan used
  # `--exit-code 1`, then treated ANY nonzero return as
  # "vulnerabilities detected". But Trivy exits nonzero for many reasons
  # that aren't findings — DB download failure, registry timeout, corrupt
  # cache, invalid image reference, scanner-init failure. An operator who
  # got "HIGH or CRITICAL vulnerabilities detected" after a scanner
  # outage would either wave the update through (thinking it's a normal
  # CVE prompt) or panic-block a clean image. Worse, 2>/dev/null was
  # throwing away the diagnostic stderr that would have distinguished the
  # two cases. Fixed here by using `--exit-code 10` (deliberately reserved
  # for "findings" per Trivy's own convention — 0=no findings, 10=findings,
  # anything else=scanner problem), sending stderr to a temp file so it
  # can be surfaced when the scan itself failed, and branching on the
  # actual return code rather than a boolean "success or not".
  local _trivy_err
  _trivy_err=$(mktemp)
  set +e
  trivy image \
       --cache-dir "${TRIVY_CACHE_DIR}" \
       --exit-code 10 \
       --severity HIGH,CRITICAL \
       --no-progress \
       --quiet \
       "${img}" 2>"${_trivy_err}"
  rc=$?
  set -e
  case "$rc" in
    0)
      rm -f "${_trivy_err}"
      echo "  ✔  No HIGH/CRITICAL vulnerabilities found"
      return 0
      ;;
    10)
      rm -f "${_trivy_err}"
      echo "  ⚠  HIGH or CRITICAL vulnerabilities detected in ${img}"
      echo "     Review the findings above before updating."
      trivy_exception "$img" || {
        echo "  Update aborted. Check for a newer image version."
        return 1
      }
      return 0
      ;;
    *)
      # UX FIX (from a real cutover attempt): a tag that simply does not exist
      # produced the generic "scanner-side failure ... unknown security state"
      # message, sending the operator to investigate Trivy, its cache and the
      # registry -- when the actual cause was a typo'''d version. Trivy reports
      # four errors for this case and three are irrelevant noise (no docker
      # socket, no containerd socket, no podman socket); the real one,
      # MANIFEST_UNKNOWN, is last and easily missed. Detect it and say so
      # plainly, because the remedy is completely different: pick a tag that
      # exists, rather than debug the scanner.
      if grep -qiE "MANIFEST_UNKNOWN|manifest unknown|unknown tag|not found|NAME_UNKNOWN" "${_trivy_err}" 2>/dev/null; then
        echo "  ✗  The image tag does not exist in the registry:" >&2
        echo "       ${img}" >&2
        echo "     This is NOT a scanner problem and NOT a vulnerability finding —" >&2
        echo "     there is simply no such tag to scan." >&2
        echo "" >&2
        echo "     List the tags that DO exist:" >&2
        echo "       skopeo list-tags docker://${img%%:*} | grep '\''${WP_TAG##*-}'\''" >&2
        echo "     Or take the exact command from:  update.sh versions" >&2
        rm -f "${_trivy_err}"
        return 1
      fi
      echo "  ✗  Trivy scan DID NOT COMPLETE for ${img} (rc=${rc}) — this is NOT" >&2
      echo "     a clean scan and NOT a vulnerability finding. Scanner-side" >&2
      echo "     failures (DB download, registry timeout, corrupt cache) look" >&2
      echo "     like this — treat as unknown security state." >&2
      if [ -s "${_trivy_err}" ]; then
        echo "     Trivy stderr:" >&2
        sed 's/^/       /' "${_trivy_err}" >&2 || true
      fi
      rm -f "${_trivy_err}"
      # v8 production fail-closed toggle: in production an incomplete scan is
      # not an operator judgement call — the update is refused. Standard
      # profile keeps the prompt so a lab install isn't blocked by a scanner
      # outage.
      if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
        echo "  ✗  DEPLOYMENT_PROFILE=production requires a COMPLETED scan. Refusing to" >&2
        echo "     update on an unknown security state. Investigate the scanner failure" >&2
        echo "     above and retry." >&2
        return 1
      fi
      ask_yn "  Proceed with update WITHOUT a completed scan? (not recommended)" || {
        echo "  Update aborted. Investigate the scanner failure and retry."
        return 1
      }
      return 0
      ;;
  esac
}

do_os_update() {
  echo "── Alpine OS ──────────────────────────────────────────────────"
  echo "  Current: Alpine $(cat /etc/alpine-release 2>/dev/null)"
  ask_yn "Update Alpine OS packages?" && { apk update; apk upgrade --no-cache; echo "✔  Done"; } \
    || echo "   Skipped."
}

# ── Shared digest-aware check ───────────────────────────────────────────────
# Resolves the target's current digest via Skopeo BEFORE deciding whether
# there's anything to do. Sets three variables the caller reads immediately
# after: _UPD_ACTION (skip|refresh|bump), _UPD_PULL_REF (what to pull),
# _UPD_DIGEST (resolved digest, or empty if Skopeo couldn't resolve one —
# in which case the caller falls back to comparing tags only).
_check_component() {
  local registry="$1" running_tag="$2" running_digest="$3" target_ver="$4"
  local target_img="${registry}:${target_ver}"
  _UPD_PULL_REF="$target_img"
  _UPD_DIGEST=""
  if [ "${USE_DIGEST_PINNING}" = "1" ]; then
    echo "  → Checking ${target_img} against the registry (Skopeo, no download)…"
    _UPD_DIGEST=$(_resolve_digest "$target_img") || _UPD_DIGEST=""
    if [ -n "$_UPD_DIGEST" ]; then
      _UPD_PULL_REF="${registry}@${_UPD_DIGEST}"
      if [ "$target_ver" = "$running_tag" ] && [ "$_UPD_DIGEST" = "$running_digest" ]; then
        _UPD_ACTION="skip"; return 0
      fi
      if [ "$target_ver" = "$running_tag" ]; then _UPD_ACTION="refresh"; else _UPD_ACTION="bump"; fi
      return 0
    fi
    # UX FIX: Skopeo is the FIRST thing that touches the registry, so a
    # nonexistent tag surfaces here -- several minutes before the pull and
    # scan that will fail for the same reason. Distinguish "the registry
    # says there is no such tag" (fatal, and the operator needs to pick a
    # different one) from "the lookup itself failed" (transient; carrying on
    # with a tag comparison is reasonable). Checking here turns a confusing
    # multi-minute detour into an immediate, accurate message.
    if printf '%s' "${_SKOPEO_ERR:-}" | grep -qiE "MANIFEST_UNKNOWN|manifest unknown|unknown tag|NAME_UNKNOWN"; then
      echo "  ✗  The registry has no such tag: ${_probe_ref:-${registry}:${target_ver}}" >&2
      echo "     Nothing was pulled and nothing was changed." >&2
      echo "     Use the exact command printed by:  update.sh versions" >&2
      _UPD_ACTION="notag"
      return 1
    fi
    echo "  ⚠  Skopeo digest lookup failed — comparing by tag only this run."
  fi
  if [ "$target_ver" = "$running_tag" ]; then _UPD_ACTION="skip"; else _UPD_ACTION="bump"; fi
  # Explicit: this function's exit status is now load-bearing (callers use
  # `|| return 1` to stop on a nonexistent tag), so it must not depend on
  # whichever statement happens to be last.
  return 0
}

do_wp_update() {
  local target_ver="${1:-${WP_TAG:-$PINNED_WP_VER}}"
  echo "── WordPress ──────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${WP_TAG:-none}  digest=${WP_DIGEST:-none}"
  echo "  Target  : ${WP_REGISTRY}:${target_ver}"
  echo "  Data    : /home/wpuser/wp/html (bind-mount — never removed)"

  # A nonexistent tag is fatal here: there is nothing to pull or scan, so
  # stop now with the accurate message rather than falling through to a
  # pull and a Trivy run that will both fail for the same reason.
  _check_component "$WP_REGISTRY" "$WP_TAG" "$WP_DIGEST" "$target_ver" || return 1
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it?" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update WordPress to ${target_ver}?" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 40): fail fast, before the pull + candidate-boot +
  # candidate-validate sequence below even begins, if wordpress-old already
  # exists (a stale leftover from an update that crashed/was interrupted
  # before cleanup) or wordpress itself is missing. Same rationale item 39
  # gives for MariaDB/CrowdSec: this used not to apply here (nothing
  # substantial happened before do_wp_update()'s one rename point), but the
  # candidate step below now means a full image pull plus a candidate
  # container boot/validate cycle happens first — worth not wasting if the
  # rename was always going to be refused. The check immediately before the
  # actual cutover rename, further down, stays in place too, catching state
  # that changed during the pull/candidate window — an operator manually
  # intervening mid-update, for instance.
  require_clean_container_state wordpress wordpress-old || return 1

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${WP_REGISTRY}@${_UPD_DIGEST}"
  fi

  RI_VOLS=""
  [ -f /home/wpuser/wp/apache-mods/remoteip.conf ] && \
    RI_VOLS="-v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"

  # ── CANDIDATE: prove the pulled image works BEFORE production is touched
  # (item 40 — merged in from a third parallel line off v7-6f). See the
  # WORDPRESS UPDATE CUTOVER header note for the full history: starting the
  # new "wordpress" straight on -p 80:80 while the old one was merely
  # renamed (still running, still holding port 80) was a structural
  # guarantee of failure, not an occasional race. The pulled image is
  # proven out here instead, on a throwaway container bound ONLY to
  # loopback:WP_CANDIDATE_PORT, with production left completely alone.
  #
  # BUG FIX (v7-13, ChatGPT Finding 3 in the audit): the candidate used to
  # bind-mount PRODUCTION's /home/wpuser/wp/html rw, /home/wpuser/wp/logs
  # rw, and /home/wpuser/wp/htaccess/.htaccess rw — so a plugin
  # write-on-init code path in the candidate image (cache seeding,
  # transient files under wp-content/uploads, a first-request
  # optimization that touches a marker file) could pollute the live
  # production docroot BEFORE the candidate had even been declared
  # healthy. Candidate failure then left production storage with
  # candidate-authored artifacts that outlived the throwaway container.
  # Mitigated here by three changes to the mount surface, none of which
  # break the health check itself (HTTP GET / + PHP exec + DB DNS + real
  # DB query — none require write access to any of these paths):
  #   • /home/wpuser/wp/html mounted :ro (read-only). The candidate can
  #     serve every file production serves, but cannot write to any of
  #     them. If the new image's WordPress ships a plugin that writes on
  #     init, the write itself will EACCES — which is the CORRECT signal:
  #     that plugin behavior would corrupt production either way, catching
  #     it against a throwaway is far cheaper than catching it live.
  #   • /var/log/apache2 bind-mounted to its own logs-candidate directory,
  #     owned 33:33 like production's (a tmpfs here is root-owned and Apache
  #     runs as www-data, so it could not create error.log at all)
  #     the candidate, and there's nothing to clean up after — the tmpfs
  #     disappears with the container.
  #   • The production .htaccess is mounted :ro rather than :rw. v7-13
  #     dropped this mount entirely, which removed the write path but also
  #     meant the candidate ran with NO .htaccess at all — no 8G firewall,
  #     no slug rules, no WordPress permalink rules — so it was no longer
  #     testing the configuration production actually serves. Read-only
  #     restores that fidelity while keeping the write path closed.
  # WP_ENVIRONMENT_TYPE=staging is also set as a hint to well-behaved
  # plugins to skip write-on-init side effects; WordPress core itself
  # respects this env var per the WordPress developer docs.
  #
  # RESIDUAL RISK (ChatGPT Finding 4 in the audit — Deliberately NOT fixed
  # here): the candidate still authenticates to the LIVE production
  # database with production credentials. ChatGPT's suggested full fix
  # (spin up a temporary MariaDB, restore the daily dump into it, create
  # temporary WordPress credentials, run the candidate against that copy,
  # tear it all down) would double disk usage during every update, add
  # minutes-per-GB of dump restore time to every image refresh, and
  # introduce a new class of failure modes (temporary-DB startup, dump
  # restore integrity, credential lifecycle) that themselves need careful
  # rollback handling. That trade-off doesn't make sense for THIS
  # script's purpose — the candidate's DB interactions are limited to
  # what a health check needs (getent hosts mariadb, PHP mysqli connect,
  # SELECT 1, plus whatever a GET / for an anonymous user triggers with
  # DISABLE_WP_CRON=true, WP_ENVIRONMENT_TYPE=staging, and now a RO
  # docroot). WordPress schema migrations are triggered by wp-admin/
  # upgrade.php loaded WHILE authenticated, not by anonymous requests, so
  # a version-mismatched candidate cannot silently migrate the live DB.
  # The remaining exposure — an anonymous plugin init routine that
  # opportunistically writes an options-table row on first request — is
  # bounded, benign, and would happen against production on first real
  # traffic anyway. Documented here rather than half-solved: an operator
  # who needs full DB isolation for their compliance regime can bolt it
  # on with a dump/restore step wrapping this function, but the base
  # script does not pay that cost by default.
  local WP_CANDIDATE="wordpress-candidate"
  local candidate_ok=0 i
  podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true

  # ── Candidate DB isolation (read-only user) ────────────────────────────────
  # The lighter half of the isolation problem, and the half worth paying for.
  # A temporary SELECT-only account is created for the candidate and dropped
  # again afterwards, so the candidate can read everything it needs to render
  # a page and boot WordPress, while any write it attempts fails at the
  # database rather than landing in production.
  #
  # BE CLEAR ABOUT WHAT THIS DOES NOT DO. It does not test the migration. A
  # read-only candidate cannot run schema upgrades, so this proves "the new
  # image boots and can read this database", not "upgrading this database
  # will succeed". Proving the latter needs a dump restored into a throwaway
  # instance -- that is what wasp-selftest.sh restore-test does, separately
  # and on its own schedule, rather than adding minutes to every update.
  #
  # Write failures in the candidate's log during this window are EXPECTED and
  # are the mechanism working, not a fault.
  local CAND_DB_USER="" CAND_DB_PASS="" CAND_DB_ARGS=""
  # Reachability is the real precondition, not a host variable that does not
  # exist -- checking the latter silently disabled this feature entirely.
  if [ "${CANDIDATE_DB_READONLY:-1}" = "1" ] \
     && podman exec mariadb sh -c 'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -e "SELECT 1"' >/dev/null 2>&1; then
    CAND_DB_USER="wp_cand_$$"
    CAND_DB_PASS=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if podman exec mariadb sh -c 'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -e "$1"' _ "
          CREATE USER '${CAND_DB_USER}'@'%' IDENTIFIED BY '${CAND_DB_PASS}';
          GRANT SELECT ON \`${WORDPRESS_DB_NAME:-wordpress}\`.* TO '${CAND_DB_USER}'@'%';
          FLUSH PRIVILEGES;" >/dev/null 2>&1; then
      CAND_DB_ARGS="-e WORDPRESS_DB_USER=${CAND_DB_USER} -e WORDPRESS_DB_PASSWORD=${CAND_DB_PASS}"
      echo "  → Candidate will use a temporary SELECT-only database account"
      echo "    (production data cannot be modified by the candidate)"
    else
      echo "  ⚠ Could not create the read-only candidate account — falling back to"
      echo "    production credentials for the candidate, as before. Set"
      echo "    CANDIDATE_DB_READONLY=0 to silence this." >&2
      CAND_DB_USER=""
    fi
  fi
  # Dropped on every exit path, including a failed candidate or Ctrl-C. A
  # leftover account would be a standing credential nobody knows about.
  _drop_cand_user() {
    [ -n "$CAND_DB_USER" ] || return 0
    podman exec mariadb sh -c 'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -e "$1"' _ \
      "DROP USER IF EXISTS '${CAND_DB_USER}'@'%'; FLUSH PRIVILEGES;" >/dev/null 2>&1 || \
      echo "  ⚠ Could not drop temporary DB user ${CAND_DB_USER} — remove it by hand" >&2
    CAND_DB_USER=""
  }
  trap '_drop_cand_user' EXIT INT TERM

  # FIX (first real `update.sh` run): the candidate used a bare
  #     --tmpfs /var/log/apache2:size=32M,noexec,nosuid,nodev
  # and Apache died on startup with
  #     (13)Permission denied: AH00091: could not open error log file
  # Apache in this image runs as www-data, not root -- which is precisely why
  # the candidate has to be granted NET_BIND_SERVICE to bind :80 at all -- so
  # it cannot create error.log in a root-owned tmpfs. Production has always
  # worked because it bind-mounts /home/wpuser/wp/logs, which stage 04 chowns
  # to 33:33. The candidate now mirrors that known-good arrangement with its
  # own directory rather than relying on tmpfs ownership semantics.
  #
  # A bind mount is also strictly better here for a second reason: a tmpfs is
  # destroyed with the container, so `podman rm -f` on a failed candidate
  # deleted the very log explaining the failure. That is why this took a real
  # deployment to surface. The log now survives and is printed below.
  mkdir -p /home/wpuser/wp/logs-candidate
  chown 33:33 /home/wpuser/wp/logs-candidate 2>/dev/null || true
  chmod 750 /home/wpuser/wp/logs-candidate 2>/dev/null || true
  rm -f /home/wpuser/wp/logs-candidate/*.log 2>/dev/null || true

  echo "  → Starting a validation candidate on 127.0.0.1:${WP_CANDIDATE_PORT} (production stays up on :80)…"
  # No --ip on wp-front (or on the wp-db connect below): production's own
  # wordpress container is still fully up and may hold a fixed address on
  # either network — the candidate must not contend for it. netavark
  # assigns the candidate a free address on both instead.
  # shellcheck disable=SC2086
  if podman run -d --name "$WP_CANDIDATE" --network wp-front \
    -p "127.0.0.1:${WP_CANDIDATE_PORT}:80" --restart no \
    --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 200 --memory=768m --cpu-shares=512 \
    --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -e WORDPRESS_DEBUG="" \
    -e WP_ENVIRONMENT_TYPE=staging \
    -e WORDPRESS_CONFIG_EXTRA="${WP_CONFIG_EXTRA}" \
    ${CAND_DB_ARGS} \
    -v /home/wpuser/wp/html:/var/www/html:ro \
    -v /home/wpuser/wp/logs-candidate:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:ro \
    ${RI_VOLS} \
    "${_UPD_PULL_REF}"; then
    podman network connect wp-db "$WP_CANDIDATE" >/dev/null 2>&1 || true
  else
    echo "✗  Candidate failed to start — production WordPress was never touched."
    # Surface the reason rather than making the operator go hunting. Both
    # sources matter: podman logs catches an entrypoint/exec failure, and the
    # Apache error log catches a config or permissions failure inside it.
    echo "   ── podman logs (candidate) ─────────────────────────────"
    podman logs --tail 25 "$WP_CANDIDATE" 2>&1 | sed 's/^/   /' || true
    if [ -s /home/wpuser/wp/logs-candidate/error.log ]; then
      echo "   ── candidate Apache error.log ──────────────────────────"
      tail -25 /home/wpuser/wp/logs-candidate/error.log 2>/dev/null | sed 's/^/   /'
    fi
    echo "   ────────────────────────────────────────────────────────"
    podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true
    _drop_cand_user
    return 1
  fi

  # PRODUCTION SAFETY (item 40): the candidate is validated with the same
  # wp-health-check.sh depth (HTTP + PHP execution + mariadb DNS + a real
  # WordPress-credential SELECT 1) used at the final cutover check below and
  # every other health-check call site in this script, instead of a bare
  # HTTP-plus-raw-mysqli check — a candidate that merely answers HTTP but
  # can't actually run PHP or reach the database would otherwise be waved
  # through here. Falls back to the older bare check only if
  # wp-health-check.sh is somehow missing.
  echo "  → Validating candidate (HTTP + PHP + DB name resolution + DB auth + real query)…"
  for i in $(seq 1 12); do
    if [ -x /usr/local/bin/wp-health-check.sh ]; then
      # PORT NAMESPACE (bug fixed here): WP_CANDIDATE_PORT is the HOST-side
      # published port from `-p 127.0.0.1:18080:80`. wp-health-check.sh does
      # `podman exec` INTO the container and probes 127.0.0.1 from in there,
      # where Apache listens on 80 and nothing is bound to 18080 -- so passing
      # the published port made the HTTP probe fail with "none" on a candidate
      # that was actually healthy (PHP, DNS and the database all passed). The
      # in-container port is always 80; the published port is only correct for
      # the host-side wget fallback below.
      if /usr/local/bin/wp-health-check.sh "$WP_CANDIDATE" 80; then
        candidate_ok=1; break
      fi
    else
      if wget -qO- -U "wp-health-check/1.0" "http://127.0.0.1:${WP_CANDIDATE_PORT}/" >/dev/null 2>&1; then
        podman exec --user www-data "$WP_CANDIDATE" php -r \
          '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"));exit($c?0:1);' \
          >/dev/null 2>&1 && { candidate_ok=1; break; }
      fi
    fi
    sleep 5
  done

  if [ "$candidate_ok" != "1" ]; then
    echo "✗  Candidate failed validation — production WordPress was never touched."
    echo "   Left running for inspection: podman logs ${WP_CANDIDATE}   (remove with: podman rm -f ${WP_CANDIDATE})"
    return 1
  fi
  podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true
  echo "  ✔  Candidate healthy (HTTP + PHP + DB confirmed) — swapping production to the new image now (brief downtime)…"

  # ── CUTOVER: production is only ever touched from this point on ────────
  # Merges the production-safety line's checked rename/rollback (item 36)
  # with the candidate/cutover line's actual STOP of wordpress-old (item
  # 40) — the piece that was missing before this merge. Renaming alone only
  # frees the NAME "wordpress"; it does not stop the container or release
  # its published port, which is what let the pre-merge code try to start a
  # second container on -p 80:80 while the first was still holding that
  # port, guaranteeing every update attempt would fail (see the WORDPRESS
  # UPDATE CUTOVER header note above for the full history).
  require_clean_container_state wordpress wordpress-old || return 1
  if ! podman rename wordpress wordpress-old >/dev/null; then
    echo "✗  Unable to rename wordpress → wordpress-old — Podman error above. Aborting; production is untouched." >&2
    return 1
  fi
  if ! podman stop --time 15 wordpress-old >/dev/null; then
    echo "✗  wordpress-old would not stop — attempting to restore the 'wordpress' name…" >&2
    if podman rename wordpress-old wordpress >/dev/null; then
      echo "   Restored. The site is NOT down — it's still running as 'wordpress', just" >&2
      echo "   on the previous image. The update did not proceed; investigate why the" >&2
      echo "   container wouldn't stop, then retry." >&2
    else
      echo "✗✗ Could not restore the 'wordpress' name either. The production container" >&2
      echo "   is still running and still serving traffic, but currently named" >&2
      echo "   'wordpress-old'. The site is NOT down, but fix the name before the next" >&2
      echo "   update attempt:" >&2
      echo "     podman rename wordpress-old wordpress" >&2
    fi
    return 1
  fi
  sleep 2

  # No --ip on wp-front: wordpress-old (stopped above, but not yet removed)
  # still holds that address until it's removed below (after the health
  # check passes) — Podman ties an IP reservation to the container's
  # existence, not whether it's currently running. netavark assigns the
  # new container a free address instead.
  # shellcheck disable=SC2086
  if podman run -d --name wordpress --network wp-front -p 80:80 --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 200 --memory=768m --cpu-shares=512 \
    --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -e WORDPRESS_DEBUG="" \
    -e WORDPRESS_CONFIG_EXTRA="${WP_CONFIG_EXTRA}" \
    ${WP_EXTRA_VOLS} \
    -v /home/wpuser/wp/html:/var/www/html \
    -v /home/wpuser/wp/logs:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
    ${RI_VOLS} \
    "${_UPD_PULL_REF}"; then

    podman network connect wp-db wordpress 2>/dev/null || true
    # BUG FIX (v7-6g): this was a bare `wget -qO-` check — the single most
    # dangerous place in the whole script for that, since HEALTHY directly
    # gates whether do_wp_update() keeps the new container or rolls back to
    # wordpress-old. A DB-connection-error page or a PHP fatal-error page
    # returns a perfectly normal HTTP response, so the old check could mark
    # a broken update "healthy" and delete the last-known-good container
    # right after. Use the same wp-health-check.sh (HTTP + PHP execution +
    # mariadb DNS + MariaDB auth + a real SELECT 1 through WordPress's own
    # DB env vars) installed by the main provisioning script, with the old
    # bare check only as a last-resort fallback if it's somehow missing.
    HEALTHY=0
    echo "  → Validating new WordPress container health (HTTP + PHP + DB name resolution + DB auth + real query)…"
    for i in $(seq 1 6); do
      if [ -x /usr/local/bin/wp-health-check.sh ]; then
        if /usr/local/bin/wp-health-check.sh wordpress 80; then
          HEALTHY=1; break
        fi
      else
        wget -qO- -U "wp-health-check/1.0" "http://127.0.0.1:80/" >/dev/null 2>&1 && { HEALTHY=1; break; }
      fi
      sleep 5
    done
    if [ "$HEALTHY" = "1" ]; then
      podman stop wordpress-old 2>/dev/null; podman rm -f wordpress-old 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): a leftover wordpress-old here isn't
      # fatal to THIS update (it already succeeded above), but it now
      # blocks the NEXT one — require_clean_container_state() refuses to
      # rename over a stale *-old container. Surface that now instead of
      # letting the next admin discover it as a confusing abort.
      podman container exists wordpress-old 2>/dev/null \
        && echo "  ⚠  wordpress-old could not be fully removed — clean it up before the next update: podman rm -f wordpress-old" >&2
      sleep 3
      podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
      echo "✔  WordPress base image updated to ${target_ver}"
      WP_TAG="$target_ver"; WP_DIGEST="${_UPD_DIGEST}"
      _save_pinned
      # GeoIP is a locally-built image layered on top of whatever WordPress
      # base is currently running — it has no registry digest of its own to
      # check, so it just gets rebuilt on the new base whenever that base
      # changes. WP_IS_GEOIP reflects whether GeoIP was active BEFORE this
      # update started; GEOIP_ENABLED covers "configured but not yet applied".
      if [ "${WP_IS_GEOIP:-0}" = "1" ] || [ "${GEOIP_ENABLED:-0}" = "1" ]; then
        if [ -x /usr/local/bin/wp-geoip-setup.sh ]; then
          echo "  → GeoIP was active — rebuilding the GeoIP image on the new base…"
          if /usr/local/bin/wp-geoip-setup.sh; then
            echo "  ✔  GeoIP re-applied on the updated WordPress image"
          else
            echo "  ⚠  GeoIP re-apply FAILED — WordPress is updated but GeoIP filtering is now OFF."
            echo "     Check /var/log/wp-geoip.log, then re-run: /usr/local/bin/wp-geoip-setup.sh"
          fi
        else
          echo "  ⚠  GeoIP was active but wp-geoip-setup.sh is missing — GeoIP filtering is now OFF."
        fi
      fi
    else
      echo "✗  Health check failed — rolling back…"
      podman stop wordpress 2>/dev/null; podman rm -f wordpress 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): was `2>/dev/null` on both the rename
      # and the start, discarding the one result that matters most here —
      # this IS the rollback; if it silently fails the site is down with no
      # indication why. Check it and say so loudly.
      if podman rename wordpress-old wordpress && podman start wordpress >/dev/null 2>&1; then
        echo "✗  Rolled back to ${WP_TAG:-previous}."
      else
        echo "✗✗ ROLLBACK FAILED — wordpress-old could not be restored to 'wordpress'" >&2
        echo "   and/or started. The site is DOWN. Manual recovery needed now:" >&2
        echo "     podman ps -a --filter name=wordpress" >&2
        echo "     podman rename wordpress-old wordpress && podman start wordpress" >&2
      fi
      return 1
    fi
  else
    echo "✗  Production container failed to start on :80 — rolling back…"
    podman rm -f wordpress 2>/dev/null
    if podman rename wordpress-old wordpress && podman start wordpress >/dev/null 2>&1; then
      echo "✗  Container start failed — rolled back."
    else
      echo "✗✗ ROLLBACK FAILED — wordpress-old could not be restored to 'wordpress'" >&2
      echo "   and/or started. The site is DOWN. Manual recovery needed now:" >&2
      echo "     podman ps -a --filter name=wordpress" >&2
      echo "     podman rename wordpress-old wordpress && podman start wordpress" >&2
    fi
    return 1
  fi
}

# ── v7-9: MariaDB data-directory snapshot helpers (items 41a/41b/41c) ──────
# Shared by do_db_update() so its normal-failure and rollback paths all use
# the exact same restore logic instead of three near-identical copies — the
# kind of drift item 7/36 already had to clean up once for this same
# function's rename/start error handling.

# _snapshot_space_ok: true if there's enough free space on the filesystem
# backing DB_DATA_DIR to hold a full copy of it. Sized off a live `du` of
# the current data directory, plus 10% and a fixed ~350MB floor that covers
# both copy overhead and the MariaDB image this same update is about to
# pull — both draw on the same VM disk. Checked BEFORE anything is stopped,
# so a too-full disk aborts loudly with zero downtime instead of leaving
# WordPress/MariaDB stopped partway through an update.
_snapshot_space_ok() {
  local data_kb avail_kb need_kb
  data_kb=$(du -sk "$DB_DATA_DIR" 2>/dev/null | awk '{print $1}' || true)
  avail_kb=$(df -Pk "$DB_DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}' || true)
  [ -n "$data_kb" ] && [ -n "$avail_kb" ] || return 1
  need_kb=$(( data_kb + data_kb / 10 + 358400 ))
  [ "$avail_kb" -ge "$need_kb" ]
}

# _data_dir_looks_valid: true if DB_DATA_DIR looks like a real, non-empty
# MariaDB data directory. Exists purely so _db_rollback() never starts
# mariadb-old against a directory that's missing or empty — the official
# MariaDB image auto-initializes a brand-new EMPTY database the instant it
# sees an empty /var/lib/mysql, which would make catastrophic data loss
# look exactly like a clean, healthy rollback.
_data_dir_looks_valid() {
  [ -d "$DB_DATA_DIR" ] || return 1
  [ -d "${DB_DATA_DIR}/mysql" ] || return 1
  [ -n "$(ls -A "$DB_DATA_DIR" 2>/dev/null)" ]
}

# _restore_snapshot: restores DB_DATA_DIR from DB_SNAPSHOT_DIR. Must only be
# called with no container mounting DB_DATA_DIR — do_db_update() always
# stops+removes the failed new "mariadb" before calling this. Uses `mv` (a
# same-filesystem rename), not a copy, so this is fast regardless of
# database size. The failed update's own data is kept alongside
# (timestamped), not deleted, in case it's ever needed for forensics.
_restore_snapshot() {
  if [ ! -d "$DB_SNAPSHOT_DIR" ]; then
    echo "✗✗ No pre-update snapshot found at ${DB_SNAPSHOT_DIR} — nothing to" >&2
    echo "   restore from. ${DB_DATA_DIR} is left exactly as the failed" >&2
    echo "   update left it." >&2
    return 1
  fi
  local failed_dir="${DB_DATA_DIR}.failed-$(date +%Y%m%d-%H%M%S)"
  if ! mv "$DB_DATA_DIR" "$failed_dir" 2>/dev/null; then
    echo "✗✗ Could not move ${DB_DATA_DIR} aside — restore aborted, left untouched." >&2
    return 1
  fi
  if mv "$DB_SNAPSHOT_DIR" "$DB_DATA_DIR" 2>/dev/null; then
    echo "  ✔  Data directory restored from the pre-update snapshot." >&2
    echo "     The failed update's own data was kept for inspection at:" >&2
    echo "       ${failed_dir}" >&2
    echo "     Remove it once you're satisfied it's not needed: rm -rf ${failed_dir}" >&2
    return 0
  fi
  echo "✗✗ Could not move the snapshot into place. Restoring the pre-restore" >&2
  echo "   directory instead so there's SOMETHING there, but this is the" >&2
  echo "   UN-rolled-back state — investigate by hand:" >&2
  echo "     ${DB_DATA_DIR} (put back)  /  snapshot still at ${DB_SNAPSHOT_DIR}  /  also see ${failed_dir}" >&2
  mv "$failed_dir" "$DB_DATA_DIR" 2>/dev/null || true
  return 1
}

# _db_rollback: shared rollback path for do_db_update(), used whether the
# new MariaDB never started, started but failed its own health check, or
# looked healthy but WordPress couldn't actually use it. Tears down the
# failed new "mariadb" (if any), restores the data directory from the
# pre-update snapshot — the new engine may have mutated on-disk state even
# without ever reporting healthy — then restores and restarts mariadb-old
# under the original name, restarts WordPress, and reports the outcome.
# $1 = human-readable reason, used in the opening status line.
#
# Every bare call into this function elsewhere in do_db_update() MUST be
# guarded with `|| true` (e.g. `_db_rollback "reason" || true`) — this
# function always returns 1, and update.sh runs under `set -e`, under which
# an unguarded function call returning non-zero aborts the ENTIRE script
# immediately (confirmed empirically, not assumed), which would skip the
# `return 1` that follows and, from do_digest_check()/`update.sh all`,
# would prevent CrowdSec from ever being checked after a MariaDB failure.
_db_rollback() {
  local reason="$1"
  echo "✗  ${reason} — rolling back…" >&2
  podman stop wordpress >/dev/null 2>&1 || true
  podman stop mariadb   >/dev/null 2>&1 || true
  podman rm -f mariadb  >/dev/null 2>&1 || true
  _restore_snapshot || true
  if ! _data_dir_looks_valid; then
    echo "✗✗ CRITICAL: ${DB_DATA_DIR} does not look like a valid MariaDB data" >&2
    echo "   directory after the restore attempt — refusing to start MariaDB" >&2
    echo "   against it (an empty/missing directory would make the container" >&2
    echo "   silently initialize a brand-new EMPTY database instead of failing" >&2
    echo "   loudly). Manual recovery needed now — inspect before doing anything:" >&2
    echo "     ls -la ${DB_DATA_DIR}" >&2
    echo "     ls -la ${DB_SNAPSHOT_DIR} 2>/dev/null   (pre-update snapshot, if still present)" >&2
    echo "   Logical backup: ${BACKUP_FILE}" >&2
    return 1
  fi
  if podman rename mariadb-old mariadb && podman start mariadb >/dev/null 2>&1; then
    local rb_db_ok=0
    for i in $(seq 1 12); do
      if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
        /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1 && { rb_db_ok=1; break; }
      elif podman exec mariadb sh -c \
        'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
         mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
        rb_db_ok=1; break
      fi
      sleep 5
    done
    if podman start wordpress >/dev/null 2>&1; then
      if [ "$rb_db_ok" = "1" ]; then
        echo "✗  Rolled back to ${DB_TAG:-previous} — data directory restored from the pre-update snapshot." >&2
      else
        echo "✗  Rolled back to ${DB_TAG:-previous}, but the restored MariaDB failed its" >&2
        echo "   own health check — investigate now: mariadb-health-check.sh mariadb" >&2
      fi
    else
      echo "  ⚠  Rolled back to ${DB_TAG:-previous} but WordPress did not restart — start it manually: podman start wordpress" >&2
    fi
    echo "✗  Logical backup: ${BACKUP_FILE}" >&2
    return 1
  fi
  echo "✗✗ ROLLBACK FAILED — mariadb-old could not be restored to 'mariadb'" >&2
  echo "   and/or started. The database is DOWN. Manual recovery needed now:" >&2
  echo "     podman ps -a --filter name=mariadb" >&2
  echo "     podman rename mariadb-old mariadb && podman start mariadb && podman start wordpress" >&2
  echo "   Logical backup: ${BACKUP_FILE}" >&2
  return 1
}

do_db_update() {
  local target_ver="${1:-${DB_TAG:-$PINNED_DB_VER}}"
  echo "── MariaDB ────────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${DB_TAG:-none}  digest=${DB_DIGEST:-none}"
  echo "  Target  : ${DB_REGISTRY}:${target_ver}"
  echo "  Data    : ${DB_DATA_DIR} (bind-mount — never removed)"
  echo "  Rollback: snapshotted to ${DB_SNAPSHOT_DIR} before the swap, removed after a verified success"

  # A nonexistent tag is fatal here: there is nothing to pull or scan, so
  # stop now with the accurate message rather than falling through to a
  # pull and a Trivy run that will both fail for the same reason.
  _check_component "$DB_REGISTRY" "$DB_TAG" "$DB_DIGEST" "$target_ver" || return 1
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it? (backup + data-directory snapshot taken first)" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update MariaDB to ${target_ver}? (backup + data-directory snapshot taken first)" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 39): fail fast, before the backup/pull/stop sequence below
  # even begins, if mariadb-old already exists (a stale leftover from an
  # update that was interrupted before cleanup) or mariadb itself is
  # missing. Without this, that problem is only discovered much further
  # down, right at the actual rename — by which point a full backup has
  # been taken, the new image pulled, and WordPress AND MariaDB have both
  # already been stopped for nothing. The require_clean_container_state()
  # call right before the rename further down stays in place too, as a
  # second, belt-and-suspenders guard against state changing in the window
  # between this early check and the actual rename attempt.
  require_clean_container_state mariadb mariadb-old || return 1

  # v7-9 (item 41a): mariadb-dump no longer pipes straight into gzip — see
  # the header note for the full rationale. It writes to a plain .sql file
  # first (so its OWN exit status, not gzip's, is what gets checked), the
  # result is checked for size and mariadb-dump's own trailing completion
  # marker, and only THEN is it compressed and the archive integrity-
  # checked with gzip -t.
  BACKUP_FILE="/root/wp-db-backup-$(date +%Y%m%d-%H%M%S).sql.gz"
  BACKUP_RAW="${BACKUP_FILE%.gz}"
  echo "  → Backing up to ${BACKUP_FILE}…"
  BACKUP_OK=0
  if ( umask 077; podman exec mariadb sh -c \
       'exec mariadb-dump --all-databases --routines --events --triggers --single-transaction --quick --hex-blob -uroot -p"$MARIADB_ROOT_PASSWORD"' \
       > "${BACKUP_RAW}" 2> "${BACKUP_RAW}.err" ); then
    if [ -s "${BACKUP_RAW}" ] && tail -c 200 "${BACKUP_RAW}" | grep -q "Dump completed"; then
      if gzip -f "${BACKUP_RAW}" && gzip -t "${BACKUP_FILE}" 2>/dev/null; then
        chmod 600 "${BACKUP_FILE}" 2>/dev/null || true
        BACKUP_OK=1
      else
        echo "✗  Compressing or verifying the backup archive failed." >&2
      fi
    else
      echo "✗  mariadb-dump's output looks incomplete (empty, or missing its own" >&2
      echo "   trailing completion marker) — treating this as a failed backup even" >&2
      echo "   though the command itself exited 0." >&2
    fi
  else
    echo "✗  mariadb-dump exited with an error." >&2
  fi
  if [ "$BACKUP_OK" != "1" ]; then
    if [ -s "${BACKUP_RAW}.err" ]; then
      echo "   mariadb-dump stderr:" >&2
      sed 's/^/     /' "${BACKUP_RAW}.err" >&2 || true
    fi
    rm -f "${BACKUP_RAW}" "${BACKUP_RAW}.err" "${BACKUP_FILE}" 2>/dev/null || true
    echo "✗  Backup failed — aborting. Fix the database before retrying."
    return 1
  fi
  rm -f "${BACKUP_RAW}.err" 2>/dev/null || true
  echo "  ✔  Backup verified (dump completed + archive integrity OK): ${BACKUP_FILE} ($(du -sh "${BACKUP_FILE}" | cut -f1))"

  # v7-9 (item 41b): fail fast — before anything is stopped — if there
  # isn't room for the pre-update data-directory snapshot taken further
  # below. See _snapshot_space_ok()'s own comment for the headroom math.
  echo "  → Checking free disk space for a pre-update data-directory snapshot…"
  if ! _snapshot_space_ok; then
    echo "✗  Not enough free disk space to safely snapshot ${DB_DATA_DIR} before" >&2
    echo "   this update — aborting before touching any running container. Free" >&2
    echo "   up space (or grow the VM disk) and retry. The logical backup above" >&2
    echo "   is still on disk and valid: ${BACKUP_FILE}" >&2
    return 1
  fi

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${DB_REGISTRY}@${_UPD_DIGEST}"
  fi

  echo "  → Stopping WordPress (brief downtime)…"
  if ! podman stop --time 30 wordpress; then
    echo "✗  Unable to stop WordPress — aborting before touching MariaDB."
    return 1
  fi

  # BUG FIX (missing-item #2 — MariaDB old container remains running during
  # replacement): this used to rename mariadb -> mariadb-old WITHOUT
  # stopping it first. `podman rename` does not stop a container, so the
  # old mariadbd process stayed live against /home/wpuser/wp/mysql at the
  # same moment the replacement container below mounts that same directory
  # — two InnoDB instances against one data directory, risking redo-log
  # corruption, data-dictionary corruption, and unrecoverable damage.
  # MariaDB is now stopped cleanly (a longer timeout than WordPress, since
  # InnoDB needs time to flush the buffer pool) before the rename, and the
  # old container's stopped state is verified explicitly afterward rather
  # than assumed.
  echo "  → Stopping MariaDB cleanly before replacement…"
  if ! podman stop --time 60 mariadb; then
    echo "✗  MariaDB did not stop cleanly — aborting update."
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  # PRODUCTION SAFETY FIX (v7-6k): preflight the rename's own preconditions
  # (see require_clean_container_state() above) before attempting it, so a
  # stale mariadb-old from a previous crashed update is reported clearly
  # instead of surfacing as a generic rename failure below.
  require_clean_container_state mariadb mariadb-old || {
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  }

  # v7-9 (item 41b): the actual pre-update snapshot — taken only once
  # MariaDB is confirmed stopped (so it's crash-consistent) and BEFORE the
  # new image is ever started against the real data directory. Every
  # rollback path (_db_rollback(), via _restore_snapshot()) restores from
  # this with a same-filesystem `mv`, not a second slow copy.
  echo "  → Snapshotting the data directory (rollback safety net)…"
  rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
  if ! cp -a "$DB_DATA_DIR" "$DB_SNAPSHOT_DIR"; then
    echo "✗  Could not snapshot ${DB_DATA_DIR} — aborting before the new MariaDB" >&2
    echo "   image ever touches it. Restarting the existing database untouched." >&2
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi
  echo "  ✔  Snapshot ready: ${DB_SNAPSHOT_DIR} ($(du -sh "$DB_SNAPSHOT_DIR" 2>/dev/null | cut -f1))"

  if ! podman rename mariadb mariadb-old; then
    echo "✗  Unable to prepare MariaDB rollback container — aborting."
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  DB_OLD_RUNNING="$(podman inspect mariadb-old --format '{{.State.Running}}' 2>/dev/null)"
  if [ "$DB_OLD_RUNNING" != "false" ]; then
    echo "✗  mariadb-old is still running — refusing to start a second MariaDB"
    echo "   instance against the same data directory. Update aborted."
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  # No --ip here either — mariadb-old still holds its wp-db address until
  # removed below, so netavark assigns this replacement whatever address is
  # free instead. WordPress finds it purely via aardvark-dns now (v7-11
  # removed the static --add-host "mariadb:10.89.20.2" entry this comment
  # used to describe as a "fallback" — it wasn't one: glibc's default
  # files-before-dns resolution order meant that entry pre-empted DNS
  # rather than backing it up, and it was wrong for the entire span this
  # container runs without a fixed .2, i.e. essentially every update, not
  # an edge case — see the v7-11 patch note for the full failure chain).
  # --network-alias mariadb below makes the DNS-only discovery explicit
  # rather than implicit; it changes nothing about wp-db's own isolation
  # (still --internal, still no published port, still only reachable from
  # containers already on wp-db).
  if podman run -d --name mariadb --network wp-db --network-alias mariadb --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --cpu-shares=512 \
    --env-file /etc/wordpress/env \
    -v /home/wpuser/wp/mysql:/var/lib/mysql \
    -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \
    --health-cmd "healthcheck.sh --connect --innodb_initialized" \
    --health-interval 5s --health-timeout 5s --health-retries 24 \
    --health-start-period 30s \
    "${_UPD_PULL_REF}"; then

    # PRODUCTION SAFETY FIX (v7-6k): DB_READY used to gate this rollback
    # decision on a bare ping. This is the highest-stakes place a shallow
    # check could bite — DB_READY directly decides whether do_db_update()
    # keeps the new MariaDB container or rolls back to mariadb-old, and a
    # ping can report healthy while the wpdb user/database or InnoDB itself
    # are still broken. WordPress is also stopped at this point in the
    # update, so wp-health-check.sh (which needs a running WordPress
    # container to test through) can't be used here — mariadb-health-check.sh
    # (installed by the main provisioning script; see its rationale there)
    # is the real equivalent for MariaDB itself. The old ping-only check is
    # kept as a fallback only if that script is somehow missing (e.g. a VM
    # provisioned before v7-6k).
    DB_READY=0
    for i in $(seq 1 24); do
      if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
        /usr/local/bin/mariadb-health-check.sh mariadb && { DB_READY=1; break; }
      elif podman exec mariadb sh -c \
        'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
         mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
        DB_READY=1; break
      fi
      sleep 5
    done

    if [ "$DB_READY" = "1" ]; then
      echo "  → mariadb-upgrade (no-op if not needed)…"
      # v7-10 (closes open finding #5): mariadb-upgrade's own exit status is
      # now checked instead of being discarded with `|| true`. DB_READY
      # above only proves the new server accepts connections and InnoDB is
      # initialized (mariadb-health-check.sh) — it says nothing about
      # mariadb-upgrade's own outcome, since that command hasn't run yet at
      # that point. A non-zero exit means mariadb-upgrade hit something it
      # couldn't reconcile on its own (an unrepairable table, a permission
      # problem, a dropped connection mid-run); continuing silently past
      # that risked handing WordPress a database that only LOOKED ready.
      # Combined stdout+stderr is captured to a variable rather than a temp
      # file — mariadb-upgrade prints even on a clean run ("already
      # upgraded"-style lines), so this is captured purely for diagnostics
      # on failure, never used as the pass/fail signal itself — and shown
      # only if the command actually failed. That failure now routes
      # through the same _db_rollback() helper item 41 built for this
      # function's other failure paths, instead of being swallowed. The
      # WordPress-reconnect gate right below is unchanged and still runs
      # either way: mariadb-upgrade's own exit code isn't necessarily
      # exhaustive, so a schema issue that slips past it but still breaks a
      # real WordPress query is caught there, same safety net as before.
      if MARIADB_UPGRADE_OUTPUT=$(podman exec mariadb sh -c \
        'mariadb-upgrade -uroot -p"$MARIADB_ROOT_PASSWORD"' 2>&1); then
        echo "  ✔  mariadb-upgrade completed"
      else
        echo "✗  mariadb-upgrade failed:" >&2
        echo "$MARIADB_UPGRADE_OUTPUT" | sed 's/^/     /' >&2
        _db_rollback "mariadb-upgrade failed" || true
        return 1
      fi

      # v7-9 (item 41c): mariadb-old and the pre-update snapshot used to be
      # deleted right after `podman start wordpress ... || true` — WordPress's
      # own restart failure was swallowed, and nothing confirmed WordPress
      # could actually USE the new database before the only way back was
      # removed. WordPress is now validated with the same wp-health-check.sh
      # depth (HTTP + PHP + DB name resolution + a real WordPress-credential
      # query) used at every other health-check site in this script.
      WP_RECONNECT_OK=0
      if podman start wordpress >/dev/null 2>&1; then
        echo "  → Confirming WordPress can actually use the updated database before removing the rollback container…"
        for i in $(seq 1 6); do
          if [ -x /usr/local/bin/wp-health-check.sh ]; then
            if /usr/local/bin/wp-health-check.sh wordpress 80; then
              WP_RECONNECT_OK=1; break
            fi
          else
            if wget -qO- -U "wp-health-check/1.0" "http://127.0.0.1:80/" >/dev/null 2>&1; then
              podman exec --user www-data wordpress php -r \
                '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"));exit($c?0:1);' \
                >/dev/null 2>&1 && { WP_RECONNECT_OK=1; break; }
            fi
          fi
          sleep 5
        done
      else
        echo "✗  WordPress failed to restart after the MariaDB swap." >&2
      fi

      if [ "$WP_RECONNECT_OK" = "1" ]; then
        podman stop mariadb-old 2>/dev/null; podman rm -f mariadb-old 2>/dev/null
        # PRODUCTION SAFETY FIX (v7-6k): flag a leftover mariadb-old now — it
        # will otherwise silently block the next update's preflight check.
        podman container exists mariadb-old 2>/dev/null \
          && echo "  ⚠  mariadb-old could not be fully removed — clean it up before the next update: podman rm -f mariadb-old" >&2
        rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
        echo "✔  MariaDB updated to ${target_ver} — WordPress confirmed healthy against it. Backup: ${BACKUP_FILE}"
        DB_TAG="$target_ver"; DB_DIGEST="${_UPD_DIGEST}"
        _save_pinned
      else
        _db_rollback "WordPress did not come back healthy against the updated database" || true
        return 1
      fi
    else
      _db_rollback "New MariaDB did not pass health validation" || true
      return 1
    fi
  else
    _db_rollback "MariaDB container failed to start" || true
    return 1
  fi
}

do_cs_update() {
  local target_ver="${1:-${CS_TAG:-$PINNED_CS_VER}}"
  echo "── CrowdSec ───────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${CS_TAG:-none}  digest=${CS_DIGEST:-none}"
  echo "  Target  : ${CS_REGISTRY}:${target_ver}"

  # A nonexistent tag is fatal here: there is nothing to pull or scan, so
  # stop now with the accurate message rather than falling through to a
  # pull and a Trivy run that will both fail for the same reason.
  _check_component "$CS_REGISTRY" "$CS_TAG" "$CS_DIGEST" "$target_ver" || return 1
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it?" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update CrowdSec to ${target_ver}?" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 39): fail fast, before the pull/stop sequence below, if
  # crowdsec-old already exists (a stale leftover from an update that was
  # interrupted before cleanup) or crowdsec itself is missing. Without
  # this, that problem is only discovered much further down, right at the
  # actual rename. The require_clean_container_state() call right before
  # the rename further down stays in place too, as a second,
  # belt-and-suspenders guard — same rationale as do_db_update() above.
  require_clean_container_state crowdsec crowdsec-old || return 1

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${CS_REGISTRY}@${_UPD_DIGEST}"
  fi

  # BUG FIX (missing-item #7 — CrowdSec old and new containers may compete
  # on host networking): this used to rename crowdsec -> crowdsec-old
  # WITHOUT stopping it first. `podman rename` does not stop a container,
  # and CrowdSec runs --network host (the host's own network namespace,
  # not an isolated Podman network like wp-front/wp-db) — so the still-
  # running renamed engine and the new container started below would both
  # be live on the HOST network at once, competing for the same LAPI port
  # (127.0.0.1:8080, locked down earlier in the installer), any AppSec
  # listener, and the same bind-mounted /opt/crowdsec/config and
  # /opt/crowdsec/data. Same class of bug already fixed for MariaDB above
  # (two engines against one set of persistent state/ports) — same fix:
  # stop cleanly first, verify the old container actually stopped, THEN
  # rename, so there is never a moment with two CrowdSec engines both
  # live on the host network.
  echo "  → Stopping CrowdSec cleanly before replacement…"
  if ! podman stop --time 30 crowdsec; then
    echo "✗  CrowdSec did not stop cleanly — aborting update."
    return 1
  fi

  # PRODUCTION SAFETY FIX (v7-6k): preflight the rename's own preconditions
  # (see require_clean_container_state() above) before attempting it, so a
  # stale crowdsec-old from a previous crashed update is reported clearly
  # instead of surfacing as a generic rename failure below.
  require_clean_container_state crowdsec crowdsec-old || {
    podman start crowdsec >/dev/null 2>&1 || true
    return 1
  }
  if ! podman rename crowdsec crowdsec-old; then
    echo "✗  Unable to prepare CrowdSec rollback container — aborting."
    podman start crowdsec >/dev/null 2>&1 || true
    return 1
  fi

  CS_OLD_RUNNING="$(podman inspect crowdsec-old --format '{{.State.Running}}' 2>/dev/null)"
  if [ "$CS_OLD_RUNNING" != "false" ]; then
    echo "✗  crowdsec-old is still running — refusing to start a second CrowdSec"
    echo "   engine against the same host-network ports and data. Update aborted."
    return 1
  fi

  if podman run -d --name crowdsec --restart always --network host \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --label io.containers.autoupdate=image \
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
    -v /opt/crowdsec/config:/etc/crowdsec:rw -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
    -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
    -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
    -v /var/log/messages:/var/log/host/messages:ro \
    "${_UPD_PULL_REF}"; then

    LAPI_UP=0
    for i in $(seq 1 6); do
      podman exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_UP=1; break; }; sleep 5
    done
    if [ "$LAPI_UP" = "1" ]; then
      rc-service cs-firewall-bouncer restart 2>/dev/null || true
      podman stop crowdsec-old 2>/dev/null; podman rm -f crowdsec-old 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): flag a leftover crowdsec-old now — it
      # will otherwise silently block the next update's preflight check.
      podman container exists crowdsec-old 2>/dev/null \
        && echo "  ⚠  crowdsec-old could not be fully removed — clean it up before the next update: podman rm -f crowdsec-old" >&2
      echo "✔  CrowdSec updated to ${target_ver}"
      CS_TAG="$target_ver"; CS_DIGEST="${_UPD_DIGEST}"
      _save_pinned
    else
      echo "✗  LAPI not responding — rolling back…"
      podman stop crowdsec 2>/dev/null; podman rm -f crowdsec 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): was `2>/dev/null` on the rename and
      # start, discarding the one result that matters most — this IS the
      # rollback. Check it and say so loudly if it doesn't work.
      if podman rename crowdsec-old crowdsec && podman start crowdsec >/dev/null 2>&1; then
        rc-service cs-firewall-bouncer restart 2>/dev/null || true
      else
        echo "✗✗ ROLLBACK FAILED — crowdsec-old could not be restored to 'crowdsec'" >&2
        echo "   and/or started. Intrusion protection is DOWN. Manual recovery needed now:" >&2
        echo "     podman ps -a --filter name=crowdsec" >&2
        echo "     podman rename crowdsec-old crowdsec && podman start crowdsec" >&2
      fi
      return 1
    fi
  else
    podman rm -f crowdsec 2>/dev/null
    if podman rename crowdsec-old crowdsec && podman start crowdsec >/dev/null 2>&1; then
      rc-service cs-firewall-bouncer restart 2>/dev/null || true
    else
      echo "✗✗ ROLLBACK FAILED — crowdsec-old could not be restored to 'crowdsec'" >&2
      echo "   and/or started. Intrusion protection is DOWN. Manual recovery needed now:" >&2
      echo "     podman ps -a --filter name=crowdsec" >&2
      echo "     podman rename crowdsec-old crowdsec && podman start crowdsec" >&2
    fi
    return 1
  fi
}

show_status() {
  echo ""; echo "── Status ─────────────────────────────────────────────────────"
  # v7-16: was piped through `column -t`, but `column` (util-linux) isn't on
  # stock Alpine — it printed "column: not found" and dropped the alignment.
  # podman's own `table` format directive aligns the columns natively with no
  # external tool; sed just re-indents to match the rest of this block.
  podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null | sed 's/^/  /' || true
  echo ""
  echo "  Firewall : $(nft list tables 2>/dev/null | grep -c table) nft tables"
  echo "  Bouncer  : $(rc-service cs-firewall-bouncer status 2>/dev/null | head -1)"
  echo ""
}

# ── Digest-only refresh (no OS, no version bump — just "is the currently
# pinned tag's digest still current everywhere?") ─────────────────────────
do_digest_check() {
  echo "── Digest Check (Skopeo manifest query only — pulls happen only if something actually changed) ──"
  if [ "${USE_DIGEST_PINNING}" != "1" ]; then
    echo "  Digest pinning is disabled (USE_DIGEST_PINNING=0 in vars.sh) — nothing to check."
    return 0
  fi
  # BUG FIX (v7-13, ChatGPT Findings 5+6 in the audit): this function and the
  # `all` dispatch below used to call do_wp_update / do_db_update /
  # do_cs_update as unguarded bare statements. update.sh runs under set -e
  # (imposed at the top of this file), so the moment the first component
  # failed, the entire process aborted — leaving the later components
  # unchecked and unrun. Concrete symptom: an intermittent WordPress
  # registry blip during `update.sh digest-check` would leave the MariaDB
  # and CrowdSec digests silently unverified, and `update.sh all` would
  # skip the CrowdSec image update entirely if MariaDB rolled back for any
  # reason. Fixed here by capturing each component's exit status with `||
  # rc=$?` (which set -e does not treat as an error) and then reporting a
  # per-component summary at the end, so an operator sees exactly which
  # components succeeded, which rolled back, and which weren't reached.
  # Return status is nonzero if any single component failed, so cron / a
  # calling script still sees the aggregate as a failure.
  local wp_rc=0 db_rc=0 cs_rc=0
  do_wp_update "${WP_TAG:-$PINNED_WP_VER}" || wp_rc=$?
  do_db_update "${DB_TAG:-$PINNED_DB_VER}" || db_rc=$?
  do_cs_update "${CS_TAG:-$PINNED_CS_VER}" || cs_rc=$?
  echo ""
  echo "── Digest Check Summary ──"
  _fmt_rc() { case "$1" in 0) echo "OK" ;; *) echo "FAILED (rc=$1)" ;; esac; }
  printf "  WordPress: %s\n" "$(_fmt_rc "$wp_rc")"
  printf "  MariaDB:   %s\n" "$(_fmt_rc "$db_rc")"
  printf "  CrowdSec:  %s\n" "$(_fmt_rc "$cs_rc")"
  [ "$wp_rc" -eq 0 ] && [ "$db_rc" -eq 0 ] && [ "$cs_rc" -eq 0 ] && return 0
  return 1
}

# BUG FIX (v7-13, ChatGPT Finding 5): same fix for `update.sh all`. The old
# `all)` dispatch line was `do_os_update; do_wp_update; do_db_update;
# do_cs_update` — same set -e trap, same silently-skipped-later-components
# failure mode, but with an extra step (do_os_update) at the front. Now
# each component's exit status is captured and a summary printed, so
# operators see "OS updated, WordPress rolled back, MariaDB up to date,
# CrowdSec skipped due to WordPress failure" clearly instead of just
# "process exited nonzero somewhere."
do_all_updates() {
  local os_rc=0 wp_rc=0 db_rc=0 cs_rc=0
  do_os_update || os_rc=$?
  do_wp_update || wp_rc=$?
  do_db_update || db_rc=$?
  do_cs_update || cs_rc=$?
  echo ""
  echo "── Update Summary ──"
  _fmt_rc() { case "$1" in 0) echo "OK" ;; *) echo "FAILED (rc=$1)" ;; esac; }
  printf "  Alpine OS: %s\n" "$(_fmt_rc "$os_rc")"
  printf "  WordPress: %s\n" "$(_fmt_rc "$wp_rc")"
  printf "  MariaDB:   %s\n" "$(_fmt_rc "$db_rc")"
  printf "  CrowdSec:  %s\n" "$(_fmt_rc "$cs_rc")"
  [ "$os_rc" -eq 0 ] && [ "$wp_rc" -eq 0 ] && [ "$db_rc" -eq 0 ] && [ "$cs_rc" -eq 0 ] && return 0
  return 1
}

# ── Read-only summary (default action) ─────────────────────────────────────
# Reports; changes nothing. Every remote lookup here is a Skopeo manifest
# query (a few KB) — no `podman pull` happens in this code path at all.
show_check_summary() {
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  WordPress VM — Status (read-only, no downloads)          ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  Alpine   : $(cat /etc/alpine-release 2>/dev/null)"
  _report_one() {
    local label="$1" registry="$2" tag="$3" digest="$4" note remote
    if [ "${USE_DIGEST_PINNING}" = "1" ]; then
      remote=$(_resolve_digest "${registry}:${tag}") || remote=""
      if [ -z "$remote" ]; then
        note="tag=${tag}  (couldn't reach registry to check digest)"
      elif [ -z "$digest" ]; then
        note="tag=${tag}  not pinned yet — current registry digest: ${remote}"
      elif [ "$remote" = "$digest" ]; then
        note="tag=${tag}  digest up to date"
      else
        note="tag=${tag}  NEWER DIGEST AVAILABLE under this tag"
      fi
    else
      note="tag=${tag}  (digest pinning disabled)"
    fi
    printf "║  %-9s %s\n" "${label}:" "$note"
  }
  _report_one "WordPress" "$WP_REGISTRY" "${WP_TAG:-$PINNED_WP_VER}" "$WP_DIGEST"
  _report_one "MariaDB"   "$DB_REGISTRY" "${DB_TAG:-$PINNED_DB_VER}" "$DB_DIGEST"
  _report_one "CrowdSec"  "$CS_REGISTRY" "${CS_TAG:-$PINNED_CS_VER}" "$CS_DIGEST"
  if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
    _PIN_COUNT=0
    [ -n "$WP_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    [ -n "$DB_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    [ -n "$CS_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    echo "║  Digest pinning: enabled — ${_PIN_COUNT}/3 currently pinned"
  else
    echo "║  Digest pinning: disabled"
  fi
  echo "╚══════════════════════════════════════════════════════════╝"
  echo ""
  echo "  update.sh all                  — update everything (asks before each change)"
  echo "  update.sh versions             — check the registry for newer RELEASES"
  echo "  update.sh upgrade              — guided move to newer releases (all components)"
  echo "  update.sh wp|db|crowdsec [VER] — update one component (asks first)"
  echo "  update.sh digest-check         — refresh any component whose tag got rebuilt"
  echo "  update.sh os                   — Alpine package updates"
  echo "  update.sh trivy                — CVE scan of the images actually running"
  echo ""
  echo "  Two different questions this tool answers:"
  echo "   • 'all' / 'digest-check' track newer DIGESTS under the tag you're already"
  echo "     on (e.g. a same-version security rebuild of ${PINNED_WP_VER:-the current tag}). They never"
  echo "     jump to a new version on their own, so an unattended update can't swap in"
  echo "     a new major WordPress or a new MariaDB line."
  echo "   • 'versions' / 'upgrade' find and move to newer RELEASES (e.g. WordPress"
  echo "     6.9.4 -> 6.9.5 for a CVE fix). Run 'update.sh versions' to see what's out,"
  echo "     then 'update.sh upgrade' (guided, with candidate-test + rollback) or name"
  echo "     one directly: update.sh wp <version>."
  show_status
}

# ═══════════════════════════════════════════════════════════════════════════
# VERSION DISCOVERY (v8) — find newer RELEASES, not just rebuilt digests.
# ═══════════════════════════════════════════════════════════════════════════
# digest-check answers "has the tag I'm on been rebuilt?" (same version, new
# digest). This answers a different question: "has a newer VERSION been
# published?" — e.g. you're pinned to WordPress 6.9.4 and 6.9.5 is out with a
# security fix. It lists available tags from the registry (Skopeo list-tags),
# filters to the real release tags for each image, and compares versions so
# you can SEE a newer release and choose to move the pin to it. `upgrade` then
# walks all three components and, for each newer release, runs the ordinary
# update path (candidate test on loopback, digest re-pin, rollback on
# failure, GeoIP layer rebuilt if it was active) — so version bumps get the
# exact same safety as a normal update.

# _ver_cmp A B — compare dotted numeric versions. Echoes 1 if A>B, -1 if A<B,
# 0 if equal. Missing trailing fields count as 0 (so 6.9 == 6.9.0). Pure
# POSIX; does not rely on `sort -V`, which BusyBox sort may not support.
_ver_cmp() {
  _a="$1"; _b="$2"
  while [ -n "$_a" ] || [ -n "$_b" ]; do
    _af="${_a%%.*}"; _bf="${_b%%.*}"
    case "$_a" in *.*) _a="${_a#*.}" ;; *) _a="" ;; esac
    case "$_b" in *.*) _b="${_b#*.}" ;; *) _b="" ;; esac
    [ -n "$_af" ] || _af=0
    [ -n "$_bf" ] || _bf=0
    case "$_af" in *[!0-9]*) _af=0 ;; esac
    case "$_bf" in *[!0-9]*) _bf=0 ;; esac
    if [ "$_af" -gt "$_bf" ]; then echo 1; return; fi
    if [ "$_af" -lt "$_bf" ]; then echo -1; return; fi
  done
  echo 0
}

# _max_version — reads version strings on stdin (one per line), echoes the
# numerically largest using _ver_cmp (not lexical sort). Empty in → empty out.
_max_version() {
  _mv_best=""
  while IFS= read -r _mv_v; do
    [ -n "$_mv_v" ] || continue
    if [ -z "$_mv_best" ] || [ "$(_ver_cmp "$_mv_v" "$_mv_best")" = "1" ]; then
      _mv_best="$_mv_v"
    fi
  done
  [ -n "$_mv_best" ] && printf '%s' "$_mv_best"
}

# _registry_tags REF — echo every tag for a registry repo, one per line.
# Uses Skopeo list-tags + jq (jq is installed at provisioning time); falls
# back to a crude JSON scrape if jq is somehow absent. Returns 1 (and echoes
# nothing) if the registry can't be reached — callers treat that as "unknown".
_registry_tags() {
  _rt_ref="$1"
  command -v skopeo >/dev/null 2>&1 || return 1
  _rt_json=$(skopeo list-tags "docker://${_rt_ref}" 2>/dev/null) || return 1
  [ -n "$_rt_json" ] || return 1
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$_rt_json" | jq -r '.Tags[]?' 2>/dev/null
  else
    # jq-free safety net: isolate the content of the "Tags":[ ... ] array
    # first (so the "Repository" value can't leak in as a bogus tag), then
    # split on commas and strip quotes.
    printf '%s' "$_rt_json" \
      | tr -d '\n' \
      | sed 's/.*"Tags"[[:space:]]*:[[:space:]]*\[//; s/\].*//' \
      | tr ',' '\n' \
      | grep -oE '"[^"]*"' | tr -d '"'
  fi
}

# _wp_latest_stable VARIANT — newest stable WordPress X.Y.Z for the given
# variant suffix (e.g. php8.3-apache). Beta/RC/cli tags are excluded by the
# strict ^X.Y.Z-variant$ shape (they don't start with a bare version number).
_wp_latest_stable() {
  _wls_re=$(printf '%s' "$1" | sed 's/[.]/\\./g')
  _registry_tags "$WP_REGISTRY" \
    | grep -E "^[0-9]+\.[0-9]+\.[0-9]+-${_wls_re}$" \
    | sed "s/-${_wls_re}\$//" \
    | _max_version
}

# _cs_latest_stable — newest stable CrowdSec vX.Y.Z (echoed WITHOUT the v).
# latest/slim/debian/-rc tags are excluded by the strict ^vX.Y.Z$ shape.
_cs_latest_stable() {
  _registry_tags "$CS_REGISTRY" \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | sed 's/^v//' \
    | _max_version
}

# Recognized MariaDB LTS lines, as EXPLICIT maintained allowlists.
# CRITICAL: MariaDB version number alone does NOT indicate support status.
# Rolling releases (11.5/11.6/11.7, 12.0/12.1/12.2, …) carry a SHORTER support
# window than the LTS they follow — 12.2 reached EOL while 10.11 LTS is still
# supported. So a production database must track LTS lines, not "highest number".
#
# v8-1 (ChatGPT v8 findings 7 & 8): these were previously a single allowlist
# {10.6,10.11,11.4,11.8} PLUS an inference that every future major.3 (13.3,
# 14.3, …) is LTS. Two problems: (a) predicting release policy from a number
# pattern is unsafe — an unannounced or preview .3 tag would be offered as a
# production upgrade the moment it appeared; (b) 10.6 was labelled a current
# LTS even though its community maintenance ended 2026-07-06. Both are now
# explicit lists with a supported/EOL split. Update them ONLY after checking
# MariaDB's official lifecycle page: https://mariadb.org/mariadb/all-releases/
# (verified against the May 2026 release set: 12.3/11.8/11.4/10.11 supported,
# 10.6 EOL 2026-07-06).
MARIADB_LTS_SUPPORTED="10.11 11.4 11.8 12.3"
MARIADB_LTS_EOL="10.6"

# _db_lts_state MAJOR.MINOR — echoes: supported | eol | rolling
_db_lts_state() {
  for _l in $MARIADB_LTS_SUPPORTED; do [ "$1" = "$_l" ] && { echo supported; return; }; done
  for _l in $MARIADB_LTS_EOL;       do [ "$1" = "$_l" ] && { echo eol;       return; }; done
  echo rolling
}

# _db_is_lts MAJOR.MINOR — true (0) only for a SUPPORTED LTS line. EOL LTS
# lines are deliberately NOT treated as valid upgrade targets, so version
# discovery never offers a move onto an out-of-support branch.
_db_is_lts() {
  [ "$(_db_lts_state "$1")" = "supported" ]
}

# _db_next_documented_lts CURRENT — echoes the ONE documented next LTS step for
# a recognized LTS source, or nothing. v8-1 (ChatGPT v8 finding 9): the guided
# upgrade uses this instead of picking the numerically-oldest newer LTS, so it
# only ever offers a transition MariaDB actually documents an upgrade guide for.
# An unrecognized/rolling source returns nothing → the guided path refuses to
# infer a jump. Keep in step with MARIADB_LTS_SUPPORTED and MariaDB's upgrade
# docs (10.6→10.11→11.4→11.8→12.3).
_db_next_documented_lts() {
  case "$1" in
    10.6)  echo "10.11" ;;
    10.11) echo "11.4"  ;;
    11.4)  echo "11.8"  ;;
    11.8)  echo "12.3"  ;;
    *)     : ;;
  esac
}

# _db_newer_lts_list CURRENT — echo every LTS MAJOR.MINOR line available in
# the registry that is strictly newer than CURRENT, oldest first (so head -1
# is the safe next step, tail -1 is the newest LTS).
_db_newer_lts_list() {
  _dnl_cur="$1"
  _registry_tags "$DB_REGISTRY" | grep -E '^[0-9]+\.[0-9]+$' | sort -u | while IFS= read -r _dnl_t; do
    _db_is_lts "$_dnl_t" || continue
    [ "$(_ver_cmp "$_dnl_t" "$_dnl_cur")" = "1" ] && echo "$_dnl_t"
  done | (
    # oldest-first order without relying on `sort -V`: bubble via _ver_cmp
    _sorted=""
    while IFS= read -r _line; do
      [ -n "$_line" ] || continue
      if [ -z "$_sorted" ]; then _sorted="$_line"; continue; fi
      _new=""; _placed=0
      for _e in $_sorted; do
        if [ "$_placed" = "0" ] && [ "$(_ver_cmp "$_line" "$_e")" = "-1" ]; then
          _new="$_new $_line"; _placed=1
        fi
        _new="$_new $_e"
      done
      [ "$_placed" = "0" ] && _new="$_new $_line"
      _sorted="${_new# }"
    done
    for _e in $_sorted; do echo "$_e"; done
  )
}

# do_versions — READ-ONLY discovery report. Queries the registry and shows,
# per component, the pinned version vs the newest available release, plus the
# exact command to move to it. Changes nothing.
do_versions() {
  echo "── Available versions (registry query — no download, nothing changed) ──"
  if ! command -v skopeo >/dev/null 2>&1; then
    echo "  skopeo is not installed — cannot query the registry for tags."
    return 1
  fi
  echo "  Querying Docker Hub… (images with many tags can take up to a minute)"
  echo ""

  # ── WordPress ──
  _cur_wp="${WP_TAG:-$PINNED_WP_VER}"
  _wp_ver="${_cur_wp%%-*}"; _wp_variant="${_cur_wp#*-}"
  echo "  WordPress   (variant: ${_wp_variant})"
  echo "    pinned : ${_wp_ver}"
  _newest_wp=$(_wp_latest_stable "$_wp_variant")
  if [ -z "$_newest_wp" ]; then
    echo "    latest : (couldn't reach the registry, or no matching tags)"
  elif [ "$(_ver_cmp "$_newest_wp" "$_wp_ver")" = "1" ]; then
    echo "    latest : ${_newest_wp}   <-- NEWER RELEASE AVAILABLE"
    echo "     move  : update.sh wp ${_newest_wp}-${_wp_variant}"
  else
    echo "    latest : ${_newest_wp}   (up to date)"
  fi
  echo ""

  # ── MariaDB (LTS-aware) ──
  _cur_db="${DB_TAG:-$PINNED_DB_VER}"
  case "$(_db_lts_state "$_cur_db")" in
    supported) _db_note="(LTS, supported)" ;;
    eol)       _db_note="(LTS, END OF LIFE)" ;;
    *)         _db_note="(NOT an LTS line — rolling / short-support)" ;;
  esac
  echo "  MariaDB     (LTS-aware — rolling releases are intentionally excluded)"
  echo "    pinned : ${_cur_db}  ${_db_note}"
  if [ "$(_db_lts_state "$_cur_db")" = "eol" ]; then
    echo "    ⚠ EOL  : MariaDB ${_cur_db} has reached community end-of-life and no"
    echo "             longer receives security fixes. Moving to a supported LTS line"
    echo "             below should be treated as urgent, not optional."
  fi
  _newer_lts=$(_db_newer_lts_list "$_cur_db")
  if [ -z "$_newer_lts" ]; then
    echo "    latest : you are on the newest recognized LTS line"
  else
    _next_lts=$(printf '%s\n' "$_newer_lts" | head -1)
    _top_lts=$(printf '%s\n' "$_newer_lts" | tail -1)
    echo "    newer LTS lines: $(printf '%s' "$_newer_lts" | tr '\n' ' ')"
    echo "     move  : update.sh db ${_next_lts}   (recommended — one LTS at a time)"
    [ "$_next_lts" != "$_top_lts" ] && \
      echo "             update.sh db ${_top_lts}   (newest LTS — a bigger jump; test first)"
    echo "     note  : a higher MariaDB number is NOT always more supported — rolling"
    echo "             releases (e.g. 11.5/11.6/11.7, 12.0/12.1/12.2) reach EOL sooner"
    echo "             than the LTS they follow, so this stays on LTS lines only."
  fi
  echo ""

  # ── CrowdSec ──
  _cur_cs="${CS_TAG:-$PINNED_CS_VER}"; _cs_ver="${_cur_cs#v}"
  echo "  CrowdSec"
  echo "    pinned : v${_cs_ver}"
  _newest_cs=$(_cs_latest_stable)
  if [ -z "$_newest_cs" ]; then
    echo "    latest : (couldn't reach the registry, or no matching tags)"
  elif [ "$(_ver_cmp "$_newest_cs" "$_cs_ver")" = "1" ]; then
    echo "    latest : v${_newest_cs}   <-- NEWER RELEASE AVAILABLE"
    echo "     move  : update.sh crowdsec v${_newest_cs}"
  else
    echo "    latest : v${_newest_cs}   (up to date)"
  fi
  echo ""
  echo "  This is a VERSION check (is a newer release published?), separate from"
  echo "  digest-check (has the CURRENT tag been rebuilt?). To move everything that"
  echo "  has a newer release in one guided pass, with candidate-test + rollback:"
  echo "      update.sh upgrade"
  echo ""
}

# do_upgrade — guided cross-component version bump. For each component with a
# newer release, offers to move the pin to it, then runs the ordinary update
# path for that component (do_*_update): candidate test, digest re-pin, and
# rollback on failure. MariaDB is offered the NEXT LTS line (one step), never
# a rolling release. Each component is confirmed separately.
do_upgrade() {
  echo "── Guided upgrade — move pinned versions to newer releases ──"
  echo "  Each component you accept goes through the normal update path:"
  echo "  a throwaway candidate is tested on loopback first, the new digest is"
  echo "  pinned, and a failure rolls back to the current version. You confirm"
  echo "  each one. Nothing is touched until you say yes."
  echo ""
  if ! command -v skopeo >/dev/null 2>&1; then
    echo "  skopeo is not installed — cannot query the registry for tags."
    return 1
  fi
  echo "  Querying Docker Hub for newer releases…"
  echo ""
  _upg_any=0
  _upg_rc=0
  _sum_wp="no newer release found"
  _sum_db="no newer release found"
  _sum_cs="no newer release found"

  # WordPress
  _cur_wp="${WP_TAG:-$PINNED_WP_VER}"; _wp_ver="${_cur_wp%%-*}"; _wp_variant="${_cur_wp#*-}"
  _newest_wp=$(_wp_latest_stable "$_wp_variant")
  if [ -n "$_newest_wp" ] && [ "$(_ver_cmp "$_newest_wp" "$_wp_ver")" = "1" ]; then
    _upg_any=1
    echo "  WordPress: ${_wp_ver} -> ${_newest_wp}   (${_wp_variant})"
    if ask_yn "  Upgrade WordPress to ${_newest_wp}?"; then
      if do_wp_update "${_newest_wp}-${_wp_variant}"; then
        _sum_wp="upgraded ${_wp_ver} -> ${_newest_wp}"
      else
        _sum_wp="FAILED — left on ${_wp_ver} (see above)"
        _upg_rc=1
        echo "  ⚠  WordPress upgrade did not complete — production left on ${_wp_ver} (see above)."
      fi
    else
      _sum_wp="skipped (${_newest_wp} was available)"
      echo "  Skipped WordPress."
    fi
    echo ""
  fi

  # MariaDB — offer the DOCUMENTED next LTS step only (never an inferred jump)
  _cur_db="${DB_TAG:-$PINNED_DB_VER}"
  _next_lts=$(_db_next_documented_lts "$_cur_db")
  _newer_any=$(_db_newer_lts_list "$_cur_db" | head -1)
  if [ -z "$_next_lts" ] && [ -n "$_newer_any" ]; then
    # Newer supported LTS lines exist, but the current line has no documented
    # single-step path (e.g. a rolling/short-support source). Refuse to infer.
    _upg_any=1
    _sum_db="not offered — no documented single-step path from ${_cur_db}"
    echo "  MariaDB: ${_cur_db} is not a recognized LTS line with a documented"
    echo "           single-step upgrade path, so the guided upgrade will not infer"
    echo "           one. Newer supported LTS lines exist — review 'update.sh versions',"
    echo "           then move deliberately after checking MariaDB's upgrade guide:"
    echo "               update.sh db <supported-LTS-line>"
    echo ""
  fi
  if [ -n "$_next_lts" ]; then
    _upg_any=1
    echo "  MariaDB: ${_cur_db} -> ${_next_lts}   (documented next LTS step)"
    echo "    A MariaDB version bump changes the on-disk format. The update path"
    echo "    snapshots the data directory and runs mariadb-upgrade, rolling back"
    echo "    if WordPress can't use the new database — but for a major jump, take"
    echo "    a manual backup first (update.sh has just verified backups exist)."
    if ask_yn "  Upgrade MariaDB to ${_next_lts} (LTS)?"; then
      if do_db_update "${_next_lts}"; then
        _sum_db="upgraded ${_cur_db} -> ${_next_lts}"
      else
        _sum_db="FAILED — rolled back to ${_cur_db} (see above)"
        _upg_rc=1
        echo "  ⚠  MariaDB upgrade did not complete — rolled back to ${_cur_db} (see above)."
      fi
    else
      _sum_db="skipped (${_next_lts} was available)"
      echo "  Skipped MariaDB."
    fi
    echo ""
  fi

  # CrowdSec
  _cur_cs="${CS_TAG:-$PINNED_CS_VER}"; _cs_ver="${_cur_cs#v}"
  _newest_cs=$(_cs_latest_stable)
  if [ -n "$_newest_cs" ] && [ "$(_ver_cmp "$_newest_cs" "$_cs_ver")" = "1" ]; then
    _upg_any=1
    echo "  CrowdSec: v${_cs_ver} -> v${_newest_cs}"
    if ask_yn "  Upgrade CrowdSec to v${_newest_cs}?"; then
      if do_cs_update "v${_newest_cs}"; then
        _sum_cs="upgraded v${_cs_ver} -> v${_newest_cs}"
      else
        _sum_cs="FAILED (see above)"
        _upg_rc=1
        echo "  ⚠  CrowdSec upgrade did not complete (see above)."
      fi
    else
      _sum_cs="skipped (v${_newest_cs} was available)"
      echo "  Skipped CrowdSec."
    fi
    echo ""
  fi

  if [ "$_upg_any" = "0" ]; then
    echo "  Everything is already on the newest recognized release. Nothing to do."
    echo "  (Run 'update.sh digest-check' to catch same-version security rebuilds.)"
    return 0
  fi

  # v8-1 fix (ChatGPT v8 finding 10): aggregate per-component results and return
  # non-zero if ANY accepted upgrade failed. Previously each failure was
  # swallowed by '|| echo' and do_upgrade fell through returning the last
  # command's status (usually 0), so cron or a monitoring wrapper could record
  # a guided upgrade as fully successful when a component had actually failed
  # and rolled back — the same defect already fixed for 'all' and 'digest-check'.
  echo "── Upgrade summary ──"
  echo "  WordPress : ${_sum_wp}"
  echo "  MariaDB   : ${_sum_db}"
  echo "  CrowdSec  : ${_sum_cs}"
  if [ "$_upg_rc" -ne 0 ]; then
    echo "  Overall   : FAILED — one or more accepted upgrades did not complete." >&2
  else
    echo "  Overall   : OK"
  fi
  return "$_upg_rc"
}

# ── Update lock — prevents concurrent update.sh invocations from stepping
# on each other ─────────────────────────────────────────────────────────
# PRODUCTION SAFETY FIX (v7-6j): nothing previously stopped two update.sh
# invocations from running at the same time — e.g. an admin running
# `update.sh wp` while a cron-triggered `update.sh digest-check` is already
# mid-run, or two admins each updating a different component. Concrete
# failure modes this allowed: two processes racing to rename the same
# container to *-old (the loser's rename fails, or worse, a second update
# removes/renames a rollback container the first update still depends on);
# two processes writing /etc/wp-install/pinned.env around the same time;
# overlapping MariaDB dumps against the same data directory; one process
# restarting a service while another process's health check is mid-poll
# against it.
#
# A plain mkdir-based lock closes this: mkdir is atomic on every storage
# backend this script runs on (overlay/vfs/fuse-overlayfs), so exactly one
# invocation can ever hold the lock directory at a time — no flock/
# lockfile binary dependency required. The holder's PID is recorded inside
# the lock so a stale lock left behind by a crashed update (OOM-killed, VM
# rebooted mid-update, etc.) is detected via `kill -0` and cleared
# automatically instead of wedging every future update permanently.
#
# Only the state-changing subcommands below (os/wp/db/crowdsec/all/
# digest-check) take the lock — check/status/trivy stay lock-free since
# they're read-only (no container renames, no pinned.env writes) and are
# meant to stay safe to run anytime, including while an update is already
# in progress (see "bare update.sh is read-only" under WHAT CHANGED above).
LOCK_DIR="/run/lock/wordpress-update.lock"
acquire_lock() {
  local lock_pid
  mkdir -p /run/lock
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
    trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
    return 0
  fi
  # Lock dir already exists: either a live update holds it, or a previous
  # run crashed without cleaning up. Only trust the recorded PID if that
  # process is actually still alive.
  if [ -f "${LOCK_DIR}/pid" ]; then
    lock_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)
    if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
      echo "  ⚠  Clearing a stale update lock left by dead process ${lock_pid}…" >&2
      rm -rf "$LOCK_DIR"
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
        trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
        return 0
      fi
    fi
  fi
  echo "✗  Another update.sh is already running (PID ${lock_pid:-unknown})." >&2
  echo "   Lock: ${LOCK_DIR} — wait for it to finish, or if you're certain" >&2
  echo "   nothing is actually running, clear it with: rm -rf ${LOCK_DIR}" >&2
  return 1
}

case "${1:-check}" in
  os)          acquire_lock || exit 1; do_os_update ;;
  wp)          acquire_lock || exit 1; do_wp_update "${2:-}" ;;
  db)          acquire_lock || exit 1; do_db_update "${2:-}" ;;
  crowdsec|cs) acquire_lock || exit 1; do_cs_update "${2:-}" ;;
  all)         acquire_lock || exit 1; do_all_updates ;;
  digest-check|digest|pin) acquire_lock || exit 1; do_digest_check ;;
  versions|check-versions|ver) do_versions ;;
  upgrade|upgrade-all)         acquire_lock || exit 1; do_upgrade ;;
  trivy|scan)
    setup_trivy
    for img in wordpress mariadb crowdsec; do
      running=$(podman inspect "$img" --format "{{.Config.Image}}" 2>/dev/null || echo "")
      [ -n "$running" ] && scan_image "$running"
    done ;;
  check|status|"") show_check_summary ;;
  *) echo "Usage: update.sh [check|status|versions|upgrade|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all|trivy]"; exit 1 ;;
esac
