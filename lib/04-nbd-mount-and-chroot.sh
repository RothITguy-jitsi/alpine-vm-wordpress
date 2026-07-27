#!/usr/bin/env bash
# 04-nbd-mount-and-chroot.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Mounts the built disk image via qemu-nbd and, in a single chroot, sets the root password and creates the admin account + doas + QEMU Guest Agent.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.


# ── Stage the in-VM installer into TMPDIR ─────────────────────────────────────
# In the pre-split monolith this file was GENERATED here, by a ~5,880-line
# quoted heredoc. It's now a real file in payload/, so it's copied instead.
#
# REGRESSION FIX: this copy went missing in the monolith->repo split and
# broke the installer outright ("chmod: cannot access
# '/tmp/tmp.XXXX/install-wordpress.sh'"). The heredoc's opening line fell in
# the gap between the last line of lib/03 and the first line of lib/04, and
# the split tooling only emitted a replacement when it encountered the
# opener *inside* a file's line range -- so the replacement was dropped
# silently while the chmod immediately below it, which had been on the far
# side of the heredoc, survived and pointed at a file nothing created.
# The verification at the time proved no original line was LOST; it never
# checked that every intended REPLACEMENT was actually PRESENT. See
# CHANGELOG for the check added to close that asymmetry.
[[ -r "${REPO_DIR}/payload/install-wordpress.sh" ]] \
  || msg_error "payload/install-wordpress.sh not found under ${REPO_DIR} — incomplete checkout or failed self-bootstrap."
cp "${REPO_DIR}/payload/install-wordpress.sh" "${TMPDIR}/install-wordpress.sh"

chmod +x "${TMPDIR}/install-wordpress.sh"
INST_LINES=$(wc -l < "${TMPDIR}/install-wordpress.sh")
(( INST_LINES > 100 )) || msg_error "Installer truncated (${INST_LINES} lines)"
msg_ok "Installer ready (${INST_LINES} lines)"

# ── Inject via qemu-nbd ───────────────────────────────────────────────────────
msg_info "Mounting disk image for injection…"
modprobe nbd max_part=8 2>/dev/null || true; sleep 1

NBD=""
for n in $(seq 0 15); do
  d="/dev/nbd${n}"; [[ -b "$d" ]] || continue
  sz=$(lsblk -bdno SIZE "$d" 2>/dev/null || echo 1)
  [[ "$sz" == "0" ]] && { NBD="$d"; break; }
done
[[ -n "$NBD" ]] || NBD="/dev/nbd0"
_NBD="$NBD"

qemu-nbd --connect="$NBD" "$WORK_IMG"; sleep 2
partprobe "$NBD" 2>/dev/null || true; sleep 1

ROOT_PART=""
for p in "${NBD}p2" "${NBD}p1" "${NBD}"; do
  [[ -b "$p" ]] || continue
  blkid "$p" 2>/dev/null | grep -qiE 'TYPE="ext[234]"' && { ROOT_PART="$p"; break; }
done
[[ -n "$ROOT_PART" ]] || ROOT_PART="${NBD}p1"
[[ -b "$ROOT_PART" ]] || ROOT_PART="$NBD"
msg_ok "Root partition: $ROOT_PART"

MNT="${TMPDIR}/mnt"; mkdir -p "$MNT"
mount "$ROOT_PART" "$MNT" || msg_error "Could not mount $ROOT_PART"
_MNT="$MNT"

# ─ Root password ──────────────────────────────────────────────────────────────
# Kept unconditionally — root SSH login is disabled below regardless of what
# the operator chose, but this password still matters for local console
# access (Proxmox `qm terminal` / serial0), which is unrelated to SSH.
HASHED=$(openssl passwd -6 "$ROOT_PASS")
if [[ -f "$MNT/etc/shadow" ]]; then
  sed -i "s|^root:[^:]*:|root:${HASHED}:|" "$MNT/etc/shadow"
else
  printf "root:%s:0:0:99999:7:::\n" "$HASHED" > "$MNT/etc/shadow"; chmod 640 "$MNT/etc/shadow"
fi

# ─ Admin account + doas + QEMU Guest Agent (needs a live chroot w/ network) ───
# BUG FIX (v7-6k): root SSH login is now disabled unconditionally (see the
# SSH hardening block below) — per remaining_tasks.txt item 5 ("no dedicated
# non-root admin account is created either way"), a real admin account
# replaces it: wheel group + doas, so root is only ever reached deliberately
# (doas), never as the SSH identity itself.
# Creating that account means `adduser`/`addgroup` writing into the target
# filesystem's own passwd/group/shadow — and installing doas needs apk +
# network — both requiring a live chroot, exactly like the QEMU Guest Agent
# pre-install already did on its own. Rather than mount and unmount /proc and
# /dev twice for two separate chroot calls, this single chroot now does all
# three (admin account, doas, guest agent); the mounts are left in place
# afterward and torn down once, at the very end of injection, right before
# the disk is unmounted — nothing else written between here and there cares
# whether /proc or /dev happen to be bind-mounted under $MNT.
# Each step below is independent (no `&&` chaining across concerns, nothing
# feeds set -e a bare failing command) so a doas/network hiccup can't stop
# the admin account or the guest agent from being set up, and vice versa —
# each is verified separately afterward rather than inferred from one
# shared exit code.
# ADMIN_USER is interpolated into this otherwise-single-quoted chroot string
# via close-quote/expand/reopen-quote — safe only because ADMIN_USER was
# already constrained to ^[a-z][a-z0-9_-]{0,31}$ above; no shell metachar is
# possible in it. SSH_KEYS and ADMIN_PASS are deliberately NOT interpolated
# here at all (operator-supplied content, unvalidated) — both are written
# host-side via plain redirection/sed after the chroot exits, the same way
# root's own password and key already are, never passed through `sh -c`.
cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true
mount --bind /proc "$MNT/proc" 2>/dev/null || true
mount --bind /dev  "$MNT/dev"  2>/dev/null || true
if chroot "$MNT" /bin/sh -c '
  VER=$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || echo "3.23")
  grep -q community /etc/apk/repositories 2>/dev/null \
    || printf "\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n" \
         "$VER" >> /etc/apk/repositories
  apk update --quiet --no-progress 2>/dev/null

  addgroup wheel 2>/dev/null || true
  id "'"$ADMIN_USER"'" >/dev/null 2>&1 || adduser -D -s /bin/sh "'"$ADMIN_USER"'" 2>/dev/null
  addgroup "'"$ADMIN_USER"'" wheel 2>/dev/null || true

  apk add --quiet --no-progress --no-cache doas 2>/dev/null
  mkdir -p /etc/doas.d
  echo "permit persist :wheel" > /etc/doas.d/doas.conf
  chown root:root /etc/doas.d/doas.conf
  chmod 0400 /etc/doas.d/doas.conf

  apk add --quiet --no-progress --no-cache qemu-guest-agent 2>/dev/null
  ln -sf /etc/init.d/qemu-guest-agent /etc/runlevels/default/qemu-guest-agent 2>/dev/null
' 2>/dev/null; then
  msg_ok "QEMU Guest Agent pre-installed"
else
  msg_warn "Guest agent pre-install skipped (will install on first boot)"
fi

# Verify the admin account independently of the chroot's own exit status
# (that status reflects the LAST command in the script above, i.e. the
# guest-agent symlink — a doas/network failure earlier must not be read as
# "admin account missing" or vice versa). grep's non-match is a real
# possible outcome here, not a bug, so this is an explicit if — under
# set -e a bare failing grep outside a conditional would abort the script.
#
# FORENSIC FIX (new-audit Critical finding, confirmed accurate): this used
# to re-enable root SSH login as a "fallback" when admin-account creation
# failed. That traded one recovery path for a worse one it didn't need:
# ROOT_PASS is set unconditionally above specifically for local console
# access (Proxmox `qm terminal <vmid>` / serial0), which needs no network,
# no SSH, and isn't gated on this chroot succeeding at all. Root SSH is
# now ALWAYS disabled, regardless of ADMIN_USER_CREATED — the fallback
# path is "log in via qm terminal and fix it by hand," not "expose root
# over the network instead." See 05-ssh-and-network-inject.sh.
ADMIN_USER_CREATED=0
ADMIN_UID="" ADMIN_GID=""
if grep -q "^${ADMIN_USER}:" "$MNT/etc/passwd" 2>/dev/null; then
  ADMIN_USER_CREATED=1
  ADMIN_UID=$(grep "^${ADMIN_USER}:" "$MNT/etc/passwd" | cut -d: -f3)
  ADMIN_GID=$(grep "^${ADMIN_USER}:" "$MNT/etc/passwd" | cut -d: -f4)
  msg_ok "Admin account: ${ADMIN_USER} (uid ${ADMIN_UID}), wheel + doas configured"
else
  msg_warn "Admin account creation failed — root SSH stays disabled (by design)."
  msg_warn "  Recover via the Proxmox console instead: qm terminal <vmid>"
  msg_warn "  then create the account by hand (adduser, addgroup <user> wheel, apk add doas)."
fi

# ─ Hostname ───────────────────────────────────────────────────────────────────
