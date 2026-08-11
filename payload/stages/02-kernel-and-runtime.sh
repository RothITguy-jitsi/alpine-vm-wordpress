#!/bin/sh
# 02-kernel-and-runtime.sh — part of install-wordpress.sh (Stage 2 on the VM).
# Kernel modules, cgroup v2, /tmp hardening, sysctls, Podman + Skopeo install, storage driver selection, and container image digest pinning.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

ts "Loading kernel modules"
modprobe overlay 2>/dev/null && ok "overlay" || warn "overlay modprobe failed"
modprobe fuse    2>/dev/null && ok "fuse"    || warn "fuse modprobe failed"
grep -q '^overlay$' /etc/modules 2>/dev/null || echo overlay >> /etc/modules
grep -q '^fuse$'    /etc/modules 2>/dev/null || echo fuse    >> /etc/modules

ts "cgroup v2"
if ! grep -q '^cgroup2 ' /etc/fstab 2>/dev/null; then
  echo "cgroup2 /sys/fs/cgroup cgroup2 nosuid,noexec,nodev 0 0" >> /etc/fstab
fi
mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null || true
mount -t cgroup2 cgroup2 /sys/fs/cgroup
ok "cgroup2 mounted"
# Required for Podman overlay with bind mounts on some kernels
mount --make-shared / 2>/dev/null || true

ts "Hardening /tmp"
if ! grep -q 'tmpfs.*\/tmp ' /etc/fstab 2>/dev/null; then
  echo "tmpfs   /tmp   tmpfs   defaults,noexec,nosuid,nodev,size=256M   0 0" >> /etc/fstab
fi
mount -a 2>/dev/null || true
ok "/tmp: 256M noexec nosuid nodev"

ts "Kernel sysctls"
install -m 0644 "${PAYLOAD_DIR}/etc/sysctl.d/99-hardening.conf" /etc/sysctl.d/99-hardening.conf
sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1
# FORENSIC FIX (new-audit Low finding, confirmed accurate and worth fixing):
# this used to discard sysctl's own output AND its exit status, then print
# "Sysctls applied" unconditionally -- so a key rejected by this kernel
# (not all of these exist on every kernel config, and container networking
# can affect a couple) reported success anyway. That is the exact
# "silent application failure creates a false sense of protection" shape
# this project has fixed elsewhere. Now every key in the file is read back
# and compared to the value that was asked for, rather than trusting that
# writing the file was the same thing as the setting taking effect.
# Keys are parsed from the file itself rather than hardcoded here, so this
# can't drift out of sync when 99-hardening.conf changes.
SYSCTL_BAD=""
SYSCTL_OK_N=0
while IFS= read -r _line; do
  case "$_line" in ''|'#'*) continue ;; esac
  _key=$(printf '%s' "$_line" | cut -d= -f1 | tr -d '[:space:]')
  _want=$(printf '%s' "$_line" | cut -d= -f2- | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
  [ -n "$_key" ] || continue
  _got=$(sysctl -n "$_key" 2>/dev/null | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')
  if [ -z "$_got" ]; then
    SYSCTL_BAD="${SYSCTL_BAD}\n    ${_key} — not available on this kernel"
  elif [ "$_got" != "$_want" ]; then
    SYSCTL_BAD="${SYSCTL_BAD}\n    ${_key} — wanted '${_want}', got '${_got}'"
  else
    SYSCTL_OK_N=$((SYSCTL_OK_N + 1))
  fi
done < /etc/sysctl.d/99-hardening.conf
if [ -z "$SYSCTL_BAD" ]; then
  ok "Sysctls applied and verified (${SYSCTL_OK_N}/${SYSCTL_OK_N} keys read back with the expected value)"
elif [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
  # Same fail-closed rule this profile already applies to image verification,
  # digest pinning, and the CrowdSec bouncer: in production, a hardening
  # control that didn't actually take effect is a failed install, not a note.
  err "$(printf 'Kernel hardening sysctls did not all take effect:%b\n  Refusing to continue under DEPLOYMENT_PROFILE=production. Re-run under standard if this kernel genuinely cannot support these keys and that is acceptable for this deployment.' "$SYSCTL_BAD")"
else
  warn "$(printf '%s of the kernel hardening sysctls did not take effect:%b' "some" "$SYSCTL_BAD")"
  warn "  ${SYSCTL_OK_N} key(s) verified OK. Continuing under DEPLOYMENT_PROFILE=standard."
fi

ts "Installing Podman"
apk add --no-cache podman crun >/dev/null
ok "Podman $(podman --version 2>/dev/null | awk '{print $3}')"
echo 'export PODMAN_IGNORE_CGROUPSV1_WARNING=1' >> /etc/profile

# Skopeo: registry manifest inspection — lets digest pinning (below) and
# update.sh ask "what digest does this tag point to right now" by querying
# the registry's manifest endpoint directly (a few KB) instead of pulling
# the full image just to find out. Lives in Alpine's standard repos, built
# on the same containers/image library as podman/buildah — plain apk add,
# no edge/testing repo needed. Never fatal if it fails: every digest lookup
# that uses it falls back to the older pull-then-inspect method on its own.
ts "Installing Skopeo (registry manifest inspection — powers cheap digest checks)"
if apk add --no-cache skopeo >/dev/null 2>&1; then
  ok "Skopeo $(skopeo --version 2>/dev/null | awk '{print $NF}') ready"
else
  warn "Skopeo install failed — digest pinning/checks will fall back to the"
  warn "  slower pull-then-inspect method (still correct, just heavier)"
fi

# aardvark-dns: required for container-to-container DNS resolution on wp-db.
# Without it WordPress can't resolve the hostname 'mariadb:3306'.
# It may be a podman dependency on some Alpine versions but install explicitly.
apk add --no-cache aardvark-dns 2>/dev/null \
  || warn "aardvark-dns not in current repo — container DNS may use fallback"

# jq: used by the Skopeo digest fallback parser (audit #2 on v7-14). The
# preferred path uses `skopeo inspect --format '{{.Digest}}'`, but on older
# Skopeo builds without --format the fallback parses raw JSON — jq extracts
# .Digest by key rather than relying on the top-level digest appearing
# before the LayersData array in field order, which is not a stable
# contract. A grep+head-1 path remains as a last resort if jq is somehow
# unavailable.
apk add --no-cache jq 2>/dev/null \
  || warn "jq not available — Skopeo JSON fallback will use a less robust parser"

# FIX: configure netavark to use nftables as firewall driver.
# The default on Alpine's netavark version is iptables, which causes:
#   Error: netavark: iptables: No such file or directory (os error 2)
# Setting nftables here means netavark uses the 'nft' binary (already
# installed via our nftables package) instead of looking for iptables.
# The wp-front and wp-db subnets (10.89.10.0/24, 10.89.20.0/24) are explicitly
# allowed in the nftables forward chain so container-to-internet traffic
# isn't dropped.
# CRITICAL: use a drop-in file in containers.conf.d/, NOT cat >> to the main
# containers.conf. Alpine's packaged containers.conf already defines [network].
# TOML does not allow duplicate section headers, so appending another [network]
# block causes: "Key 'network' has already been defined" and Podman refuses to
# start any container with a custom network.
# Drop-in files are merged on top of the main config without that restriction.
mkdir -p /etc/containers/containers.conf.d
cat > /etc/containers/containers.conf.d/10-netavark-nftables.conf << 'CONTAINERSCONF'
[network]
firewall_driver = "nftables"
CONTAINERSCONF
ok "netavark: firewall_driver=nftables (drop-in: containers.conf.d/)"

# BUG FIX (v7-14): cap Podman's own container log files. Separate from the
# Apache file logs that logrotate handles — this is the container stdout/
# stderr stream Podman itself writes under
# /var/lib/containers/storage/.../ctr.log, which has NO size limit by
# default. MariaDB and CrowdSec are both chatty on stdout (every
# connection error, every decision), so this grows continuously and
# invisibly: `du -sh /home/wpuser/wp/logs` looks fine while the real
# consumer is container storage. Set globally via a drop-in for the same
# TOML duplicate-section-header reason explained for the netavark drop-in
# above. 50MB per container is enough to debug a recent failure without
# being able to fill the disk on its own.
cat > /etc/containers/containers.conf.d/20-log-limits.conf << 'CONTAINERSLOG'
[containers]
log_size_max = 52428800
CONTAINERSLOG
ok "Podman container logs capped at 50MB each (drop-in: containers.conf.d/)"

ts "Configuring Podman storage"
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << 'REGCONF'
[registries.search]
registries = ["docker.io"]
[registries.insecure]
registries = []
REGCONF

DRIVER_CHOSEN="vfs"
if lsmod | grep -q '^overlay'; then
  cat > /etc/containers/storage.conf << 'SC1'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC1
  DRIVER_CHOSEN="overlay"
elif lsmod | grep -q '^fuse'; then
  apk add --no-cache fuse fuse3 fuse-overlayfs >/dev/null
  cat > /etc/containers/storage.conf << 'SC2'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
SC2
  DRIVER_CHOSEN="fuse-overlayfs"
else
  cat > /etc/containers/storage.conf << 'SC3'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC3
  warn "Using vfs storage (uses more disk) — overlay unavailable"
fi
podman system migrate >/dev/null 2>&1 || true
ok "Storage driver: ${DRIVER_CHOSEN}"

# ── Container image digest pinning (default ON) ───────────────────────────────
# BUG FIX (v7-5): real SHA256 digest pinning, resolved dynamically instead of
# a hardcoded placeholder. A hardcoded digest goes stale the instant any of
# these images is rebuilt under the same tag — which registries do routinely
# for security patches — silently pinning every future install to a WORSE,
# older image forever with no warning.
#
# SKOPEO REWRITE (v7-6f): resolving "what digest does this tag point to right
# now" used to mean a full `podman pull` (150-200+ MB each for WordPress/
# MariaDB) just to ask Podman what it downloaded. Skopeo's `inspect
# docker://ref` asks the registry's manifest endpoint directly — a few KB, no
# layer data — so the digest is known before anything is pulled. A `podman
# pull` still happens here (the image needs to actually land locally to run
# it), but only once, against the exact `repo@sha256:digest` reference that's
# actually going to be pinned — not as a separate discovery pull first. If
# Skopeo is missing or a lookup fails, _pin_digest falls back to the
# pre-v7-6f method (pull by tag, ask Podman what it resolved) automatically
# — never fatal, just the old bandwidth cost for that one image. update.sh
# uses this same Skopeo-first approach for its own checks, where the payoff
# is bigger: a routine `update.sh check` no longer pulls anything at all.
#
# FORMAT NOTE (v7-6f): the old "does this Podman accept a combined
# repo:tag@sha256:digest reference" compatibility test is gone. Every pinned
# reference is now the universally-supported digest-only form
# (`repo@sha256:digest`); the tag is tracked separately in the new
# /etc/wp-install/pinned.env instead of inside the image reference itself —
# see the PERSIST block below. update.sh's `check`/`status` output is the
# place to see tag info now, not `podman ps`. wp-geoip-setup.sh's tag
# derivation was updated to match — it now reads pinned.env directly instead
# of trying to sed the tag back out of a reference that may no longer
# contain one (see that script for details).
#
# RETRY + DIAGNOSTICS (v7-5c, carried forward unchanged): both the pull and
# the digest-resolution step retry up to 3 times, and any final failure
# writes the ACTUAL error text (not just "failed") to
# /var/log/wp-digest-pinning.log for later diagnosis, plus a short pointer
# to that log in the normal warn() output. A pin-count summary is also
# printed once all three images are resolved.
DIGEST_PIN_LOG="/var/log/wp-digest-pinning.log"

_skopeo_digest() {
  # $1 = full tag reference, e.g. docker.io/wordpress:7.0.2-php8.4-apache
  # stdout: sha256:<64 hex> on success. Returns 1 on any failure (Skopeo
  # missing, network error, unparseable output) — treated as "fall back",
  # never as fatal.
  #
  # BUG FIX (v7-14): this used to return a MULTI-LINE value. `skopeo
  # inspect` emits the top-level image manifest "Digest" AND a "LayersData"
  # array whose every element also carries a "Digest" field, so an
  # unbounded grep returned the manifest digest plus every layer digest.
  # _pin_digest() then built "${repo}@${digest}" out of that, producing an
  # invalid reference that `podman pull` rejected on all 3 attempts before
  # falling through to a full tag pull — so the whole point of resolving
  # via Skopeo (cheap manifest query, no pull) never actually happened.
  # See the fuller note on the matching function inside update.sh.
  # FIX: use Skopeo's --format to ask for exactly that one field, fall back
  # to jq (v7-15, audit #2) then a head-1'd grep on older Skopeo, and
  # validate single-line sha256 shape before returning.
  local ref="$1" out digest
  command -v skopeo >/dev/null 2>&1 || return 1

  digest=$(skopeo inspect --format '{{.Digest}}' "docker://${ref}" 2>/dev/null | head -1) || digest=""

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

  [ -n "$digest" ] || return 1
  [ "$(printf '%s\n' "$digest" | wc -l | tr -d ' ')" = "1" ] || return 1
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

if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
  ts "Resolving image digests (Skopeo registry query — no image pulled yet)"

  _pin_digest() {
    # $1 = tag reference   $2 = label (for logs)
    # stdout: repo@sha256:digest if a digest was resolved (the common case),
    # or the original tag reference if resolution failed outright (that one
    # image falls back to tag-only, same graceful-degradation behavior as
    # USE_DIGEST_PINNING=0 for just that image).
    # BUG FIX (v7-5b, still applies): ok()/warn() print to plain stdout, and
    # this function is called as WP_IMAGE=$(_pin_digest ...) — a command
    # substitution captures EVERYTHING written to stdout, not just the final
    # `echo`. Every ok/warn call in this function must go to stderr (>&2).
    local ref="$1" label="$2" repo tag digest candidate attempt pull_ok pull_output
    repo="${ref%:*}"; tag="${ref##*:}"

    # Preferred path: Skopeo resolves the digest with no image pull at all.
    digest=""
    if command -v skopeo >/dev/null 2>&1; then
      digest=$(_resolve_digest "$ref") || digest=""
    fi

    if [ -n "$digest" ]; then
      candidate="${repo}@${digest}"
      pull_ok=0
      for attempt in 1 2 3; do
        if pull_output=$(podman pull "$candidate" 2>&1); then pull_ok=1; break; fi
        warn "${label}: pull attempt ${attempt}/3 failed, retrying…" >&2
        [ "$attempt" -lt 3 ] && sleep 4
      done
      if [ "$pull_ok" = "1" ]; then
        ok "${label}: pinned to ${digest} (Skopeo — no full pull needed just to check)" >&2
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PINNED (skopeo) — ${candidate}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
        echo "$candidate"
        return 0
      fi
      warn "${label}: Skopeo resolved a digest but pulling it failed after 3 attempts — trying a plain tag pull instead. Detail: ${DIGEST_PIN_LOG}" >&2
      {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: DIGEST PULL FAILED after 3 attempts — ref=${candidate}"
        echo "${pull_output}" | sed 's/^/    /'
      } >> "$DIGEST_PIN_LOG" 2>/dev/null || true
    else
      warn "${label}: Skopeo digest lookup unavailable or failed — falling back to tag pull + local inspect" >&2
    fi

    # Fallback: pull by tag, then ask Podman what digest it resolved to.
    pull_ok=0
    for attempt in 1 2 3; do
      if pull_output=$(podman pull "$ref" 2>&1); then pull_ok=1; break; fi
      warn "${label}: pull attempt ${attempt}/3 failed, retrying…" >&2
      [ "$attempt" -lt 3 ] && sleep 4
    done
    if [ "$pull_ok" != "1" ]; then
      warn "${label}: pull failed after 3 attempts — continuing with tag-only reference (no digest pin). Detail: ${DIGEST_PIN_LOG}" >&2
      {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PULL FAILED after 3 attempts — ref=${ref}"
        echo "${pull_output}" | sed 's/^/    /'
      } >> "$DIGEST_PIN_LOG" 2>/dev/null || true
      echo "$ref"; return 0
    fi
    digest=$(podman inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    if [ -z "$digest" ]; then
      warn "${label}: could not resolve a digest after pulling — continuing with tag-only reference. Detail: ${DIGEST_PIN_LOG}" >&2
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: DIGEST RESOLUTION FAILED (post-pull) — ref=${ref}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
      echo "$ref"; return 0
    fi
    ok "${label}: pinned to ${digest} (tag pull + local inspect — Skopeo path unavailable)" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PINNED (fallback) — ${repo}@${digest}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
    echo "${repo}@${digest}"
  }

  WP_TAG_INIT="${WP_IMAGE##*:}"
  DB_TAG_INIT="${DB_IMAGE##*:}"
  CS_TAG_INIT="${CROWDSEC_IMAGE##*:}"
  WP_IMAGE=$(_pin_digest "$WP_IMAGE" "WordPress")
  DB_IMAGE=$(_pin_digest "$DB_IMAGE" "MariaDB")
  CROWDSEC_IMAGE=$(_pin_digest "$CROWDSEC_IMAGE" "CrowdSec")
  # Squid only exists when egress filtering is enabled. Pin it on the same
  # footing as the rest so update.sh can check/scan/bump it -- a filtering
  # proxy that cannot be updated is a proxy that silently ages on exactly the
  # axis (CVEs) that made us add mitigations for it in the first place.
  if [ "${EGRESS_PROXY:-0}" = "1" ]; then
    SQUID_IMAGE="${SQUID_IMAGE:-docker.io/ubuntu/squid:latest}"
    SQUID_IMAGE=$(_pin_digest "$SQUID_IMAGE" "Squid")
    SQUID_TAG_INIT="${SQUID_IMAGE##*:}"
    case "$SQUID_IMAGE" in *@sha256:*) SQUID_TAG_INIT="latest" ;; esac
  fi

  # ── Visibility: pin-count summary, captured now before GeoIP can later
  # reassign WP_IMAGE to a locally-built (never digest-pinned) image, which
  # would otherwise make a successfully-pinned upstream pull look like a
  # failure in any summary computed after that point. ──────────────────────
  DIGEST_PIN_COUNT=0
  case "$WP_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  case "$DB_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  case "$CROWDSEC_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  DIGEST_PIN_SUMMARY="${DIGEST_PIN_COUNT}/3 pinned"
  if [ "$DIGEST_PIN_COUNT" = "3" ]; then
    ok "Digest pinning: ${DIGEST_PIN_SUMMARY}"
  else
    # BUG FIX (v7-13, ChatGPT Finding 9): under DEPLOYMENT_PROFILE=production
    # anything less than 3/3 pinned aborts the install. Under
    # DEPLOYMENT_PROFILE=standard (default) it stays a warning — the same
    # silent-degradation behavior v7-12 had, deliberately preserved so a
    # temporary registry outage doesn't brick a homelab install. See
    # DEPLOYMENT_PROFILE's own definition at prompt time for the full
    # rationale on why this is a per-install choice, not a hardcoded policy.
    if [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
      err "Digest pinning: ${DIGEST_PIN_SUMMARY} — refusing to continue under DEPLOYMENT_PROFILE=production. Every image must resolve to a real @sha256: digest before the install proceeds. See ${DIGEST_PIN_LOG} for exactly which lookups failed and why. Retry once registry access recovers, or re-run under DEPLOYMENT_PROFILE=standard if this is a lab install where tag-only fallback is acceptable."
    fi
    warn "Digest pinning: ${DIGEST_PIN_SUMMARY} — see ${DIGEST_PIN_LOG} for exactly why the rest fell back to tag-only"
  fi
else
  WP_TAG_INIT="${WP_IMAGE##*:}"
  DB_TAG_INIT="${DB_IMAGE##*:}"
  CS_TAG_INIT="${CROWDSEC_IMAGE##*:}"
  DIGEST_PIN_SUMMARY="disabled"
  ok "Digest pinning disabled (USE_DIGEST_PINNING=0) — using tag-only references"
fi

# ── Persist pinned tag+digest — the source of truth update.sh reads ────────
# BUG FIX (v7-6f): previously there was no persisted record of this at all —
# "what tag/digest is pinned" had to be re-derived later by sed-parsing it
# back out of the running container's own image string, which only worked
# because a pinned reference still had a visible tag in it
# (repo:tag@sha256:digest). Now that every pinned reference is digest-only
# (see FORMAT NOTE above), that string has no tag left in it to parse out.
# /etc/wp-install/pinned.env is the fix: written here at install time, kept
# current by update.sh (see its _save_pinned()) after every successful
# wp/db/crowdsec update, and read by both update.sh and wp-geoip-setup.sh.
WP_PIN_DIGEST=""; case "$WP_IMAGE" in *@sha256:*) WP_PIN_DIGEST="${WP_IMAGE#*@}" ;; esac
DB_PIN_DIGEST=""; case "$DB_IMAGE" in *@sha256:*) DB_PIN_DIGEST="${DB_IMAGE#*@}" ;; esac
CS_PIN_DIGEST=""; case "$CROWDSEC_IMAGE" in *@sha256:*) CS_PIN_DIGEST="${CROWDSEC_IMAGE#*@}" ;; esac
SQUID_PIN_DIGEST=""; case "${SQUID_IMAGE:-}" in *@sha256:*) SQUID_PIN_DIGEST="${SQUID_IMAGE#*@}" ;; esac
mkdir -p /etc/wp-install
# BUG FIX (v7-12, #8): write via temp-file + mv instead of a direct `cat >`.
# A direct `cat > pinned.env << EOF` truncates the target the instant the
# shell opens it for writing — before a single byte of the heredoc body
# lands — so anything reading pinned.env in that exact window (a crash
# mid-write, or wp-geoip-setup.sh reading this same file later in this
# very install run) could see a truncated or empty file, not the old
# value and not the new one. mv within the same directory is a single
# rename(2) — POSIX-atomic — so a reader always sees either the complete
# previous file or the complete new one, never a partial write.
_PINNEDENV_TMP="/etc/wp-install/pinned.env.tmp.$$"
cat > "$_PINNEDENV_TMP" << PINNEDENV
# WordPress VM — pinned image tag + digest per component.
# Written by the installer; kept current by update.sh after every
# successful update. update.sh treats this file as authoritative for
# "what is currently pinned" instead of parsing tags back out of the
# running container's image reference. Do not edit by hand while update.sh
# might be running.
WP_TAG="${WP_TAG_INIT}"
WP_DIGEST="${WP_PIN_DIGEST}"
DB_TAG="${DB_TAG_INIT}"
DB_DIGEST="${DB_PIN_DIGEST}"
CS_TAG="${CS_TAG_INIT}"
CS_DIGEST="${CS_PIN_DIGEST}"
SQUID_TAG="${SQUID_TAG_INIT:-}"
SQUID_DIGEST="${SQUID_PIN_DIGEST:-}"
PINNEDENV
chmod 600 "$_PINNEDENV_TMP"
mv -f "$_PINNEDENV_TMP" /etc/wp-install/pinned.env
ok "pinned.env written — WordPress ${WP_TAG_INIT}, MariaDB ${DB_TAG_INIT}, CrowdSec ${CS_TAG_INIT}"

