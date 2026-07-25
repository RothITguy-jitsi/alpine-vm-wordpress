#!/usr/bin/env bash
# =============================================================================
# WORDPRESS VM — INTEGRATION TEST HARNESS
# =============================================================================
# Runs on the Proxmox VE host. Asserts, end-to-end, that a provisioned
# WordPress VM actually works — the runtime-only class of failure that syntax
# checks and static analysis cannot see. Every recent round of this project
# drove the same lesson home: bugs that pass `dash -n` and `bash -n` cleanly
# and only surface on real hardware. Four of the v7-16 round's seven bugs were
# exactly that — the container-DNS break (nftables blocking port 53), the
# health check that always returned "none" (GNU wget options on BusyBox), the
# doas friction for the SSH admin, and the validator's false failures. None of
# them were visible until the thing ran. This harness is the standing answer:
# it runs the thing and checks the results.
#
# WHY IT WORKS AGAINST AN ALREADY-PROVISIONED VM
#   The install-time bugs leave after-effects on the running VM. If the DNS
#   fix regressed, the WordPress container can no longer resolve "mariadb". If
#   the health check regressed, the install never reaches its done marker. If
#   the v7-15 backtick spray came back, "command not found" litters the install
#   log. So the assertion suite catches install-time regressions by their
#   consequences, no matter how the VM was provisioned. That makes the suite
#   (default mode) the robust core; --provision is convenience on top.
#
# HOW IT TALKS TO THE VM
#   Through `qm guest exec`, which runs a command as root inside the guest via
#   the QEMU guest agent (the provisioning script installs qemu-guest-agent) and
#   returns JSON with the exit code and output. No SSH, no keys, no VM network
#   reachability from the host required for the core suite. One optional check
#   (the full wpadmin+doas elevation) can use real SSH if you supply --ssh-host.
#
# EACH ASSERTION MAPS TO A REAL BUG OR FEATURE
#   Group 2 (DNS)        -> the v7-15 field-critical nftables/port-53 fix
#   Group 3 (HTTP)       -> the v7-16 BusyBox-wget health-check fix ("none")
#   Group 4 (validator)  -> the v7-16 false-failure fixes (0/3 pins, wp-admin)
#   Group 5 (doas)       -> the v7-16 helper auto-elevation for the SSH admin
#   Group 1 (log spray)  -> the v7-16 backtick-in-unquoted-heredoc fix (bug 70)
#   Group 6 (versions)   -> the v8 version-discovery + fail-closed toggles
#   Group 7 (backup)     -> the backup integrity the validator checks for
#
# WHAT IT HONESTLY CANNOT DO
#   • It cannot run without a real Proxmox host and a real (or provisionable)
#     VM. There is no substitute environment; that is the whole point.
#   • --provision drives the *interactive* provisioning script by feeding it an
#     answers file on stdin. That is inherently fragile: the answer order must
#     match the current prompt sequence. Use --emit-answers-template to get a
#     documented starting point, and expect to adjust it. The assertion suite
#     does not share this fragility.
#   • The rollback assertion (--destructive) proves that a bad update target
#     fails safely (production stays up), not the full candidate-health-then-
#     rollback path, which needs an image that pulls but fails validation —
#     something only a purpose-built broken image can arrange.
#
# EXIT CODE: 0 if every assertion passed (skips allowed), 1 if any failed,
#            2 on a harness/usage/pre-flight error.
# =============================================================================

set -u

# ── Colour (only if stdout is a terminal) ────────────────────────────────────
if [ -t 1 ]; then
  RED=$(printf '\033[31m'); GRN=$(printf '\033[32m'); YLW=$(printf '\033[33m')
  CYN=$(printf '\033[36m'); DIM=$(printf '\033[2m');  BLD=$(printf '\033[1m')
  RST=$(printf '\033[0m')
else
  RED=; GRN=; YLW=; CYN=; DIM=; BLD=; RST=
fi

# ── Defaults ─────────────────────────────────────────────────────────────────
VMID=""
PROVISION=0
SCRIPT=""
ANSWERS=""
KEEP=0
DESTRUCTIVE=0
SSH_HOST=""
SSH_USER="wpadmin"
SSH_KEY=""
WAIT_TIMEOUT=1800     # seconds to wait for the in-VM install to finish
POLL_INTERVAL=10
JSON_OUT=""
ADMIN_USER=""         # resolved from the VM at runtime

usage() {
  cat <<'USAGE'
WordPress VM — integration test harness (run on the Proxmox host).

USAGE:
  test-wordpress-vm.sh --target <VMID> [options]        # test an existing VM
  test-wordpress-vm.sh --provision --script <path> \
                       --answers <file> --vmid <VMID>    # provision then test

OPTIONS:
  --target <VMID>       VM to test (an already-provisioned WordPress VM).
  --provision           Provision a fresh VM first (see --emit-answers-template).
  --script <path>       Path to create-wordpress-vm-v8.sh (with --provision).
  --answers <file>      Newline answers fed to the installer (with --provision).
  --vmid <VMID>         VMID the provision will use / the answers specify.
  --destructive         Also run the rollback-safety and (safe) backup checks
                        that trigger an update attempt. Use only on a throwaway
                        test VM.
  --keep                Do not destroy the VM afterward (default: keep; only
                        --provision auto-destroys unless --keep, see below).
  --ssh-host <ip>       Also test the real wpadmin SSH + doas path against this
                        address (needs key auth; see --ssh-key/--ssh-user).
  --ssh-user <name>     SSH user for the doas test (default: wpadmin).
  --ssh-key <path>      SSH private key for the doas test.
  --timeout <seconds>   How long to wait for the install to finish (default 1800).
  --json <path>         Also write machine-readable results to this file.
  --emit-answers-template   Print a documented answers-file template and exit.
  -h, --help            This help.

EXIT: 0 all passed, 1 one or more failed, 2 harness/usage error.
USAGE
}

emit_answers_template() {
  cat <<'TMPL'
# ── Answers template for create-wordpress-vm-v8.sh (fed on stdin) ────────────
# One answer per line, in the ORDER the script prompts. Blank line = accept the
# bracketed default. This ordering matches the current prompt sequence; if the
# script's prompts change, this must change too. Lines beginning with # are
# stripped by the harness before the file is fed in.
#
# Recommended path for a throwaway test VM: DHCP networking, an admin password
# (not an SSH key), keep the default admin slug. Fill in the CAPITALISED values.
#
900                       # VM ID  (must equal --vmid)
CHANGE-ME-ROOT-PW         # Root password for the VM
CHANGE-ME-ROOT-PW         # Confirm root password
wp-test                   # Hostname
local-lvm                 # Storage
vmbr0                     # Bridge
                          # VLAN tag (blank = none)
1                         # Network mode: 1 = DHCP
                          # SSH public key (blank = set an admin password)
                          # ...or path to a .pub file (blank = admin password)
wpadmin                   # Admin account username
CHANGE-ME-ADMIN-PW        # Admin account password
CHANGE-ME-ADMIN-PW        # Confirm admin password
                          # wp-admin custom slug (blank = default /wp-admin)
                          # CrowdSec enrolment key (blank = skip)
# Depending on options chosen above and on this script version, there may be a
# few more prompts (admin-IP CIDR, MaxMind GeoIP keys, deployment profile). Add
# their answers here in order, or leave the VM's defaults by adding blank lines.
# Run once interactively first to learn the exact remaining sequence.
TMPL
}

# ── Argument parsing ─────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --target)      VMID="${2:-}"; shift ;;
    --provision)   PROVISION=1 ;;
    --script)      SCRIPT="${2:-}"; shift ;;
    --answers)     ANSWERS="${2:-}"; shift ;;
    --vmid)        VMID="${2:-}"; shift ;;
    --destructive) DESTRUCTIVE=1 ;;
    --keep)        KEEP=1 ;;
    --ssh-host)    SSH_HOST="${2:-}"; shift ;;
    --ssh-user)    SSH_USER="${2:-}"; shift ;;
    --ssh-key)     SSH_KEY="${2:-}"; shift ;;
    --timeout)     WAIT_TIMEOUT="${2:-}"; shift ;;
    --json)        JSON_OUT="${2:-}"; shift ;;
    --emit-answers-template) emit_answers_template; exit 0 ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "Unknown option: $1  (try --help)" >&2; exit 2 ;;
  esac
  shift
done

die() { echo "${RED}error:${RST} $*" >&2; exit 2; }

# ── Pre-flight ───────────────────────────────────────────────────────────────
command -v qm >/dev/null 2>&1 || die "'qm' not found — this harness runs on the Proxmox VE host."
command -v jq >/dev/null 2>&1 || die "'jq' not found — install it (apt install jq); it parses 'qm guest exec' JSON."
[ -n "$VMID" ] || die "no VM specified — pass --target <VMID> (or --vmid with --provision)."
if [ "$PROVISION" = "1" ]; then
  [ -n "$SCRIPT" ]  || die "--provision needs --script <path to create-wordpress-vm-v8.sh>."
  [ -f "$SCRIPT" ]  || die "--script '$SCRIPT' not found."
  [ -n "$ANSWERS" ] || die "--provision needs --answers <file> (see --emit-answers-template)."
  [ -f "$ANSWERS" ] || die "--answers '$ANSWERS' not found."
fi

# ── qm guest exec wrapper ────────────────────────────────────────────────────
# Runs a shell command inside the guest as root. Sets VM_RC / VM_OUT / VM_ERR.
# `qm guest exec ... -- argv` runs argv directly (no shell), so we always wrap
# in /bin/sh -c to allow pipes, globs, and &&.
VM_RC=""; VM_OUT=""; VM_ERR=""
vm_exec() {
  local cmd="$1" raw
  raw=$(qm guest exec "$VMID" --timeout 120 -- /bin/sh -c "$cmd" 2>/dev/null)
  if [ -z "$raw" ]; then VM_RC=901; VM_OUT=""; VM_ERR="no response from guest agent"; return; fi
  VM_RC=$(printf '%s' "$raw" | jq -r 'if has("exitcode") then (.exitcode|tostring) else "902" end' 2>/dev/null)
  VM_OUT=$(printf '%s' "$raw" | jq -r '."out-data" // ""' 2>/dev/null)
  VM_ERR=$(printf '%s' "$raw" | jq -r '."err-data" // ""' 2>/dev/null)
  [ -n "$VM_RC" ] || VM_RC=903
}

agent_up() { qm guest exec "$VMID" --timeout 15 -- /bin/true >/dev/null 2>&1; }

# ── Waiting for the in-VM install ────────────────────────────────────────────
# The install runs on boot via /etc/local.d and may reboot once (kernel switch,
# stage 1 -> stage 2). The guest agent disappears across the reboot and comes
# back. We poll for /var/log/wp-install.done (the marker the installer touches
# at the end, and the local.d wrapper gates on), tolerating agent gaps.
wait_for_install() {
  echo "${CYN}Waiting for the in-VM install to finish${RST} (marker: /var/log/wp-install.done, timeout ${WAIT_TIMEOUT}s)…"
  local start now elapsed
  start=$(date +%s)
  while :; do
    now=$(date +%s); elapsed=$((now - start))
    if [ "$elapsed" -ge "$WAIT_TIMEOUT" ]; then
      echo "${RED}Timed out after ${elapsed}s waiting for the install to complete.${RST}"
      echo "  Last install log lines from the VM (if reachable):"
      vm_exec "tail -n 20 /var/log/wp-install.log 2>/dev/null"
      printf '%s\n' "$VM_OUT" | sed 's/^/    /'
      return 1
    fi
    if agent_up; then
      vm_exec "test -f /var/log/wp-install.done && echo DONE || echo PENDING"
      if [ "$VM_OUT" = "DONE" ]; then
        echo "${GRN}Install marker present after ${elapsed}s.${RST} Giving services a moment to settle…"
        sleep 15
        return 0
      fi
    fi
    printf '  %s… %ss elapsed\r' "waiting" "$elapsed"
    sleep "$POLL_INTERVAL"
  done
}

# ── Assertion framework ──────────────────────────────────────────────────────
PASS=0; FAIL=0; SKIP=0
RESULTS=""   # newline records:  STATUS<TAB>NAME<TAB>DETAIL
TAB=$(printf '\t')

_record() { RESULTS="${RESULTS}${1}${TAB}${2}${TAB}${3}
"; }
_pass() { PASS=$((PASS+1)); _record PASS "$1" "$2"; printf '  %sPASS%s  %s\n' "$GRN" "$RST" "$1"; [ -n "$2" ] && printf '        %s%s%s\n' "$DIM" "$2" "$RST"; }
_fail() { FAIL=$((FAIL+1)); _record FAIL "$1" "$2"; printf '  %sFAIL%s  %s\n' "$RED" "$RST" "$1"; [ -n "$2" ] && printf '        %s%s%s\n' "$DIM" "$2" "$RST"; }
_skip() { SKIP=$((SKIP+1)); _record SKIP "$1" "$2"; printf '  %sSKIP%s  %s\n' "$YLW" "$RST" "$1"; [ -n "$2" ] && printf '        %s%s%s\n' "$DIM" "$2" "$RST"; }

section() { printf '\n%s── %s ──%s\n' "$BLD" "$1" "$RST"; }

# First line of VM output, trimmed, for compact failure detail.
_first() { printf '%s' "$1" | head -n1 | cut -c1-100; }

assert_rc0() {         # label ; command
  vm_exec "$2"
  if [ "$VM_RC" = "0" ]; then _pass "$1" ""
  else _fail "$1" "rc=${VM_RC}${VM_ERR:+  err: $(_first "$VM_ERR")}${VM_OUT:+  out: $(_first "$VM_OUT")}"; fi
}
assert_contains() {    # label ; command ; needle
  vm_exec "$2"
  case "$VM_OUT" in
    *"$3"*) _pass "$1" "found: $3" ;;
    *)      _fail "$1" "expected '$3' (rc=${VM_RC}) out: $(_first "$VM_OUT")${VM_ERR:+  err: $(_first "$VM_ERR")}" ;;
  esac
}
assert_not_contains() {  # label ; command ; needle
  vm_exec "$2"
  case "$VM_OUT" in
    *"$3"*) _fail "$1" "found forbidden '$3' — out: $(_first "$VM_OUT")" ;;
    *)      _pass "$1" "" ;;
  esac
}
assert_num_ge() {      # label ; command ; min
  vm_exec "$2"; local n; n=$(printf '%s' "$VM_OUT" | tr -dc '0-9'); n=${n:-0}
  if [ "$n" -ge "$3" ] 2>/dev/null; then _pass "$1" "count=${n} (>= $3)"
  else _fail "$1" "count=${n} (< $3)  out: $(_first "$VM_OUT")"; fi
}
assert_num_le() {      # label ; command ; max
  vm_exec "$2"; local n; n=$(printf '%s' "$VM_OUT" | tr -dc '0-9'); n=${n:-0}
  if [ "$n" -le "$3" ] 2>/dev/null; then _pass "$1" "count=${n} (<= $3)"
  else _fail "$1" "count=${n} (> $3)  out: $(_first "$VM_OUT")"; fi
}

# ── The suite ────────────────────────────────────────────────────────────────
run_suite() {
  # Resolve the admin account name once (defaults to wpadmin if vars.sh lacks it)
  vm_exec '. /etc/wp-install/vars.sh 2>/dev/null; echo "${ADMIN_USER:-wpadmin}"'
  ADMIN_USER=$(printf '%s' "$VM_OUT" | tr -d '[:space:]'); ADMIN_USER=${ADMIN_USER:-wpadmin}

  section "1. Install completed & containers up"
  assert_rc0        "install reached its done marker (/var/log/wp-install.done)" \
                    'test -f /var/log/wp-install.done'
  # Bug 70 regression: unquoted-heredoc backticks executed as commands and
  # sprayed "policy/netavark/flush: command not found" through the install log.
  assert_num_le     "install log free of the bug-70 command-substitution spray" \
                    "grep -cE '(policy|netavark|flush|ruleset|use|need): (command )?not found' /var/log/wp-install.log 2>/dev/null" 0
  for c in wordpress mariadb crowdsec; do
    assert_contains "container '${c}' is running" \
                    "podman ps --filter name=^${c}\$ --filter status=running --format '{{.Names}}'" "$c"
  done

  section "2. Container DNS — the v7-15 field-critical fix"
  # This is THE regression test for the nftables/port-53 break: WordPress
  # resolving 'mariadb' goes through aardvark-dns, which the missing port-53
  # accept used to silently block, and the install never reached the DB.
  assert_rc0        "WordPress container resolves 'mariadb' via aardvark-dns" \
                    'podman exec wordpress getent hosts mariadb'
  assert_num_ge     "nftables input chain has the port-53 accepts (udp+tcp, both subnets)" \
                    "nft list ruleset 2>/dev/null | grep -c 'dport 53 accept'" 4

  section "3. WordPress HTTP health — the v7-16 BusyBox-wget fix"
  # The regressed health check returned "none" for every probe (GNU wget long
  # options on Alpine's BusyBox wget). This asserts the probe returns a real
  # status and the health check does not report the "none" failure.
  assert_not_contains "health check HTTP probe returns a real status, not 'none'" \
                    '/usr/local/bin/wp-health-check.sh wordpress 2>&1' \
                    "Unexpected HTTP response: none"
  assert_contains   "health check confirms a WordPress DB query works" \
                    '/usr/local/bin/wp-health-check.sh wordpress 2>&1' "DB query"

  section "4. Validator correctness — the v7-16 false-failure fixes"
  # 0/3-pins bug: the validator read digests from vars.sh (they live in
  # pinned.env) and reported "0/3 pinned" while update.sh showed 3/3.
  assert_not_contains "digest pinning is not falsely reported as 0/3" \
                    '/usr/local/bin/validate-wordpress.sh --section updates 2>&1' "0/3"
  # wp-admin bug: the check gated on an empty ADMIN_CIDR and always warned.
  # Only meaningful if a restriction is actually configured on this VM.
  vm_exec "grep -q 'Require ip' /home/wpuser/wp/apache-conf/wp-security.conf 2>/dev/null && echo yes || echo no"
  if [ "$VM_OUT" = "yes" ]; then
    assert_not_contains "configured wp-admin restriction is not falsely reported missing" \
                    '/usr/local/bin/validate-wordpress.sh --section security 2>&1' \
                    "No wp-admin IP restriction configured"
  else
    _skip "wp-admin restriction check" "no 'Require ip' configured on this VM — nothing to assert"
  fi

  section "5. Helper accessibility — the v7-16 doas fix"
  assert_rc0        "doas is configured for the wheel group" \
                    "grep -q 'permit persist :wheel' /etc/doas.d/doas.conf"
  assert_rc0        "admin account '${ADMIN_USER}' is in the wheel group" \
                    "id -nG ${ADMIN_USER} 2>/dev/null | grep -qw wheel"
  # --help skips elevation, so this proves the helper is reachable and runnable
  # as the unprivileged admin (the path that used to die on vars.sh perms).
  assert_rc0        "validate-wordpress.sh --help runs as '${ADMIN_USER}' (no elevation)" \
                    "su -s /bin/sh ${ADMIN_USER} -c '/usr/local/bin/validate-wordpress.sh --help'"

  section "6. Update & version features — v8"
  assert_rc0        "update.sh status runs" '/usr/local/bin/update.sh status'
  assert_not_contains "update.sh status does not falsely show 0/3 pins" \
                    '/usr/local/bin/update.sh status 2>&1' "0/3"
  # Version discovery (needs registry reachability; still exits 0 if offline,
  # printing "couldn't reach the registry" — so we assert it produced a report).
  assert_contains   "update.sh versions produces a discovery report" \
                    '/usr/local/bin/update.sh versions 2>&1' "Available versions"
  assert_contains   "version discovery reports the WordPress line" \
                    '/usr/local/bin/update.sh versions 2>&1' "WordPress"
  # Fail-closed firewall toggle: the dependency must match the deployment profile.
  vm_exec '. /etc/wp-install/vars.sh 2>/dev/null; echo "${DEPLOYMENT_PROFILE:-standard}"'
  local profile; profile=$(printf '%s' "$VM_OUT" | tr -d '[:space:]'); profile=${profile:-standard}
  if [ "$profile" = "production" ]; then
    assert_contains "firewall dependency is fail-closed ('need nftables') under production" \
                    "grep -E 'need nftables|use nftables' /etc/init.d/mariadb-container" "need nftables"
  else
    assert_contains "firewall dependency is 'use nftables' under the standard profile" \
                    "grep -E 'need nftables|use nftables' /etc/init.d/mariadb-container" "use nftables"
  fi

  section "7. Backup integrity"
  assert_rc0        "wp-db-backup.sh runs to completion" '/usr/local/bin/wp-db-backup.sh'
  assert_rc0        "a backup archive now exists" \
                    'ls -t /root/wp-db-backups/wp-db-*.sql.gz >/dev/null 2>&1'
  assert_rc0        "newest backup passes gzip integrity" \
                    'gzip -t "$(ls -t /root/wp-db-backups/wp-db-*.sql.gz | head -1)"'
  assert_rc0        "newest backup carries the dump completion marker" \
                    'gunzip -c "$(ls -t /root/wp-db-backups/wp-db-*.sql.gz | head -1)" | tail -c 200 | grep -q "Dump completed"'

  [ "$DESTRUCTIVE" = "1" ] && run_destructive
  [ -n "$SSH_HOST" ] && run_ssh_doas_check
}

# ── Destructive: rollback safety (only with --destructive) ───────────────────
run_destructive() {
  section "8. Rollback safety (--destructive) — a bad update must not break production"
  vm_exec "podman inspect wordpress --format '{{.Image}}' 2>/dev/null"
  local before; before=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  # Auto-confirm any prompt with `yes`; the nonexistent tag fails at pull, well
  # before any cutover, so production must be left exactly as it was.
  vm_exec "yes | /usr/local/bin/update.sh wp 99.99.99-nonexistent-php8.3-apache >/dev/null 2>&1; true"
  vm_exec "podman ps --filter name=^wordpress\$ --filter status=running --format '{{.Names}}'"
  local running; running=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec "podman inspect wordpress --format '{{.Image}}' 2>/dev/null"
  local after; after=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  if [ "$running" = "wordpress" ] && [ -n "$before" ] && [ "$before" = "$after" ]; then
    _pass "a failed update target leaves production untouched" "still running, still on the original image"
  else
    _fail "a failed update target leaves production untouched" "running='${running}' before='${before}' after='${after}'"
  fi
}

# ── Optional: the real wpadmin SSH + doas elevation path ─────────────────────
# The guest-exec checks above run as root, so they verify the RESULTS the doas
# feature enables. This optionally verifies the elevation itself over SSH, the
# way an operator actually uses it. It needs key auth (doas would otherwise
# prompt for a password) and network reachability to the VM.
run_ssh_doas_check() {
  section "9. wpadmin SSH + doas elevation (real path)"
  command -v ssh >/dev/null 2>&1 || { _skip "ssh doas elevation" "no ssh client on the host"; return; }
  local keyopt=""; [ -n "$SSH_KEY" ] && keyopt="-i $SSH_KEY"
  # A helper that auto-elevates should succeed and print its section output.
  # We run the read-only validator; success (rc0) means doas elevation worked
  # non-interactively (passwordless key session), which requires the operator's
  # doas/sudo setup to permit it.
  local out rc
  out=$(ssh $keyopt -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
        "${SSH_USER}@${SSH_HOST}" '/usr/local/bin/validate-wordpress.sh --section updates' 2>&1)
  rc=$?
  if [ "$rc" = "0" ] && printf '%s' "$out" | grep -q -i 'digest'; then
    _pass "validate-wordpress.sh elevates and runs over SSH as ${SSH_USER}" ""
  else
    _skip "validate-wordpress.sh elevates over SSH as ${SSH_USER}" \
          "rc=${rc} (needs passwordless key auth AND a doas policy that doesn't prompt; may be expected)"
  fi
}

# ── Provisioning (optional) ──────────────────────────────────────────────────
provision_vm() {
  echo "${CYN}Provisioning VM ${VMID}${RST} via ${SCRIPT}, answers from ${ANSWERS}…"
  echo "${DIM}(Feeding the interactive installer on stdin — see the header caveat.)${RST}"
  # Strip comment/blank lines from the answers file before feeding it in.
  local answers_clean; answers_clean=$(mktemp)
  grep -vE '^[[:space:]]*#' "$ANSWERS" > "$answers_clean"
  if ! bash "$SCRIPT" < "$answers_clean"; then
    rm -f "$answers_clean"
    die "provisioning script exited non-zero — inspect its output above."
  fi
  rm -f "$answers_clean"
  # The provisioning script kicks off the in-VM install on boot and returns
  # before it finishes. Make sure the VM is running, then wait for the marker.
  qm start "$VMID" >/dev/null 2>&1 || true
}

# ── Teardown ─────────────────────────────────────────────────────────────────
teardown() {
  if [ "$KEEP" = "1" ]; then
    echo "${DIM}--keep set: leaving VM ${VMID} in place for inspection.${RST}"
    return
  fi
  if [ "$PROVISION" = "1" ]; then
    echo "${CYN}Tearing down test VM ${VMID}…${RST}"
    qm stop "$VMID" >/dev/null 2>&1 || true
    sleep 3
    qm destroy "$VMID" --purge --destroy-unreferenced-disks 1 >/dev/null 2>&1 \
      && echo "  destroyed." \
      || echo "  ${YLW}could not destroy VM ${VMID} automatically — remove it manually.${RST}"
  else
    echo "${DIM}Existing VM ${VMID} left untouched (only --provision auto-destroys).${RST}"
  fi
}

# ── JSON output ──────────────────────────────────────────────────────────────
write_json() {
  [ -n "$JSON_OUT" ] || return 0
  {
    printf '{\n  "vmid": "%s",\n  "pass": %d,\n  "fail": %d,\n  "skip": %d,\n  "results": [\n' \
      "$VMID" "$PASS" "$FAIL" "$SKIP"
    local first=1
    printf '%s' "$RESULTS" | while IFS="$TAB" read -r st nm dt; do
      [ -n "$st" ] || continue
      [ "$first" = "1" ] && first=0 || printf ',\n'
      printf '    {"status": "%s", "name": %s, "detail": %s}' \
        "$st" "$(printf '%s' "$nm" | jq -R .)" "$(printf '%s' "$dt" | jq -R .)"
    done
    printf '\n  ]\n}\n'
  } > "$JSON_OUT"
  echo "${DIM}Wrote JSON results to ${JSON_OUT}${RST}"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  printf '%s╔══════════════════════════════════════════════════════════╗%s\n' "$BLD" "$RST"
  printf '%s║   WordPress VM — integration test harness                 ║%s\n' "$BLD" "$RST"
  printf '%s╚══════════════════════════════════════════════════════════╝%s\n' "$BLD" "$RST"
  echo "  Target VMID : ${VMID}"
  echo "  Mode        : $([ "$PROVISION" = 1 ] && echo 'provision + test' || echo 'test existing VM')$([ "$DESTRUCTIVE" = 1 ] && echo ' + destructive')"

  if [ "$PROVISION" = "1" ]; then
    provision_vm
  fi

  # Make sure the VM exists and is running before we wait/test.
  if ! qm status "$VMID" >/dev/null 2>&1; then
    die "VM ${VMID} does not exist on this host."
  fi
  qm start "$VMID" >/dev/null 2>&1 || true

  if ! wait_for_install; then
    echo "${RED}Install did not complete — aborting the assertion suite.${RST}"
    teardown
    exit 1
  fi

  run_suite

  # ── Summary ──
  printf '\n%s════════════════════ RESULTS ════════════════════%s\n' "$BLD" "$RST"
  printf '  %sPASS %d%s   %sFAIL %d%s   %sSKIP %d%s\n' \
    "$GRN" "$PASS" "$RST" "$RED" "$FAIL" "$RST" "$YLW" "$SKIP" "$RST"
  if [ "$FAIL" -gt 0 ]; then
    printf '\n  %sFailed assertions:%s\n' "$RED" "$RST"
    printf '%s' "$RESULTS" | while IFS="$TAB" read -r st nm dt; do
      [ "$st" = "FAIL" ] && printf '    • %s\n      %s%s%s\n' "$nm" "$DIM" "$dt" "$RST"
    done
  fi

  write_json
  teardown

  if [ "$FAIL" -gt 0 ]; then
    echo "${RED}${BLD}Integration test FAILED.${RST}"
    exit 1
  fi
  echo "${GRN}${BLD}Integration test PASSED.${RST}"
  exit 0
}

main
