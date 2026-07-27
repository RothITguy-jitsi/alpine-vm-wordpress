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
STRICT=0              # --strict: treat any SKIP as a failure for the exit code
# FORENSIC FIX (new-audit High finding): the guest-agent SSH host-key
# cross-check added in the last round only ever warned on a mismatch or on
# being unable to check at all, then proceeded anyway with plain
# network-path TOFU regardless. The evaluator's own remediation was to
# gate the connection on this, not just report it: "retrieve the guest
# key... and THEN use StrictHostKeyChecking=yes." Default is now fail
# closed — no independent host-key verification, no SSH connection, full
# stop — with this flag as an explicit, named opt-out for lab use (a
# throwaway VM you're iterating on locally, where you already trust the
# network path because it's localhost/your own LAN).
ALLOW_UNVERIFIED_SSHID=0
ADMIN_USER=""         # resolved from the VM at runtime
CLEANUP_REQUIRED=0    # set to 1 once a provision may have created the VM
CLEANUP_RUNNING=0     # guards teardown against re-entry from the EXIT trap
STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
# v2 (ChatGPT harness finding 23): environment/build metadata for the JSON report.
META_PROFILE=""; META_WP=""; META_DB=""; META_CS=""; META_ALPINE=""; META_PODMAN=""
CLEANUP_REQUIRED=0    # set to 1 once a provision may have created the VM
CLEANUP_RUNNING=0     # guards teardown against re-entry from the EXIT trap

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
  --script <path>       Path to install.sh (with --provision). Run from a full
                        clone -- install.sh needs its sibling lib/ and payload/
                        directories.
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
  --strict              Treat SKIP as failure for the exit code (release gate):
                        exit non-zero if any check was skipped. Default: skips
                        are allowed.
  --allow-unverified-sshid   Proceed with the SSH-dependent checks even if the
                        network-observed host key can't be independently
                        confirmed via the guest agent (see test/README.md).
                        Default: fail closed and skip SSH-dependent checks
                        rather than trust an unverified key. Use only for a
                        throwaway VM on a network path you already trust.
  --emit-answers-template   Print a documented answers-file template and exit.
  -h, --help            This help.

EXIT: 0 all passed, 1 one or more failed, 2 harness/usage error.
USAGE
}

emit_answers_template() {
  cat <<'TMPL'
# ── Answers template for install.sh (fed on stdin) ────────────────────────────
# One answer per line, in the ORDER the script prompts. A blank line accepts the
# bracketed default. This ordering matches the current prompt sequence; if the
# script's prompts change, this must change too.
#
# IMPORTANT (v2 fix): the answer lines below contain ONLY the value — no inline
# comments. The harness strips whole-line "#" comments (like these) before
# feeding the file in, but it does NOT strip text after a value, so a line like
# "900  # VM ID" would reach the installer verbatim and fail. Each value's
# meaning is documented in this comment block instead, by line number:
#
#   Line 1   VM ID (must equal --vmid)
#   Line 2   Root password for the VM
#   Line 3   Confirm root password
#   Line 4   Hostname
#   Line 5   Storage (e.g. local-lvm)
#   Line 6   Bridge (e.g. vmbr0)
#   Line 7   VLAN tag            (blank = none)
#   Line 8   Network mode: 1 = DHCP
#   Line 9   SSH public key      (blank = set an admin password instead)
#   Line 10  ...or path to a .pub file (blank = admin password)
#   Line 11  Admin account username
#   Line 12  Admin account password
#   Line 13  Confirm admin password
#   Line 14  wp-admin custom slug (blank = default /wp-admin)
#   Line 15  CrowdSec enrolment key (blank = skip)
#
# Recommended for a throwaway test VM: DHCP networking, an admin password (not an
# SSH key), the default admin slug. Replace every CHANGE-ME value below. The
# blank lines are intentional answers (accept-default) and must be kept.
900
CHANGE-ME-ROOT-PW
CHANGE-ME-ROOT-PW
wp-test
local-lvm
vmbr0

1


wpadmin
CHANGE-ME-ADMIN-PW
CHANGE-ME-ADMIN-PW


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
    --strict)      STRICT=1 ;;
    --allow-unverified-sshid) ALLOW_UNVERIFIED_SSHID=1 ;;
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
  [ -n "$SCRIPT" ]  || die "--provision needs --script <path to install.sh>."
  [ -f "$SCRIPT" ]  || die "--script '$SCRIPT' not found."
  [ -n "$ANSWERS" ] || die "--provision needs --answers <file> (see --emit-answers-template)."
  [ -f "$ANSWERS" ] || die "--answers '$ANSWERS' not found."
fi

# v2 (ChatGPT harness finding 18): validate numeric inputs and bound the timeout.
# VMID is passed to qm; the timings are used in arithmetic. A malformed value
# should fail here with a clear message, not target the wrong VM or misbehave.
case "$VMID" in ''|*[!0-9]*) die "VMID must be numeric (got '${VMID}')." ;; esac
case "$WAIT_TIMEOUT" in ''|*[!0-9]*) die "--timeout must be a whole number of seconds (got '${WAIT_TIMEOUT}')." ;; esac
case "$POLL_INTERVAL" in ''|*[!0-9]*) die "internal: POLL_INTERVAL must be numeric." ;; esac
[ "$WAIT_TIMEOUT" -ge 60 ]    || die "--timeout must be at least 60 seconds."
[ "$WAIT_TIMEOUT" -le 21600 ] || die "--timeout exceeds the supported maximum (21600s / 6h)."
[ "$POLL_INTERVAL" -ge 1 ]    || die "internal: POLL_INTERVAL must be >= 1."

# ── qm guest exec wrapper ────────────────────────────────────────────────────
# Runs a shell command inside the guest as root. Sets VM_RC / VM_OUT / VM_ERR.
# `qm guest exec ... -- argv` runs argv directly (no shell), so we always wrap
# in /bin/sh -c to allow pipes, globs, and &&.
VM_RC=""; VM_OUT=""; VM_ERR=""
vm_exec() {
  local cmd="$1" raw host_err ef
  ef=$(mktemp 2>/dev/null || printf '/tmp/vmexec.%s' "$$")
  # v2 (ChatGPT harness finding 6): keep qm's own stderr so a guest-agent-disabled,
  # VM-locked, not-running, or bad-VMID host error is reported, not swallowed.
  raw=$(qm guest exec "$VMID" --timeout 120 -- /bin/sh -c "$cmd" 2>"$ef")
  host_err=$(cat "$ef" 2>/dev/null); rm -f "$ef" 2>/dev/null || true
  if [ -z "$raw" ]; then
    VM_RC=901; VM_OUT=""
    VM_ERR="no response from guest agent${host_err:+ — qm: $(printf '%s' "$host_err" | head -n1 | cut -c1-160)}"
    return
  fi
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

assert_rc0() {         # label ; command   — command must succeed
  vm_exec "$2"
  if [ "$VM_RC" = "0" ]; then _pass "$1" ""
  else _fail "$1" "rc=${VM_RC}${VM_ERR:+  err: $(_first "$VM_ERR")}${VM_OUT:+  out: $(_first "$VM_OUT")}"; fi
}

# v2 (ChatGPT harness findings 2, 3, 8): every normal assertion now requires the
# guest command to SUCCEED before its output is judged. Previously a command
# that failed to execute (missing script, permission denied, rc=901 no agent)
# produced empty output and silently PASSED a negative assertion — a false green
# that undermined the whole suite's credibility. Expected-failure cases use the
# explicit assert_rc_nonzero helper below.
_rc_guard() {          # internal: label — _fail + return 1 when the guest cmd failed
  if [ "$VM_RC" != "0" ]; then
    _fail "$1" "guest command failed: rc=${VM_RC}${VM_ERR:+  err: $(_first "$VM_ERR")}${VM_OUT:+  out: $(_first "$VM_OUT")}"
    return 1
  fi
  return 0
}
assert_contains() {    # label ; command ; needle   — cmd must succeed AND output contains needle
  vm_exec "$2"; _rc_guard "$1" || return
  case "$VM_OUT" in
    *"$3"*) _pass "$1" "found: $3" ;;
    *)      _fail "$1" "expected '$3' (rc=0) out: $(_first "$VM_OUT")${VM_ERR:+  err: $(_first "$VM_ERR")}" ;;
  esac
}
assert_not_contains() {  # label ; command ; needle   — cmd must succeed AND output lacks needle
  vm_exec "$2"; _rc_guard "$1" || return
  case "$VM_OUT" in
    *"$3"*) _fail "$1" "found forbidden '$3' — out: $(_first "$VM_OUT")" ;;
    *)      _pass "$1" "" ;;
  esac
}
assert_rc_nonzero() {  # label ; command   — command is EXPECTED to fail (rc != 0)
  vm_exec "$2"
  case "$VM_RC" in
    0)          _fail "$1" "expected a non-zero exit, but the command succeeded (rc=0) out: $(_first "$VM_OUT")" ;;
    901|902|903) _fail "$1" "no usable result from the guest agent (rc=${VM_RC}) — cannot confirm the command failed for the right reason" ;;
    *)          _pass "$1" "command failed as expected (rc=${VM_RC})" ;;
  esac
}
# Numeric assertions require a clean single integer on line 1. A command that
# fails to execute yields empty or non-numeric output and is rejected here; we
# deliberately do NOT gate on rc, because `grep -c` exits 1 when it finds zero
# matches while still printing "0" — a legitimate count we must accept.
_num_read() {          # internal: echoes the integer on line 1, or empty if not a clean integer
  _nr=$(printf '%s\n' "$VM_OUT" | sed -n '1p' | tr -d '[:space:]')
  case "$_nr" in ''|*[!0-9]*) printf '' ;; *) printf '%s' "$_nr" ;; esac
}
assert_num_ge() {      # label ; command ; min
  vm_exec "$2"; local n; n=$(_num_read)
  if [ -z "$n" ]; then _fail "$1" "expected one integer on line 1 (rc=${VM_RC}); got: $(_first "$VM_OUT")"; return; fi
  if [ "$n" -ge "$3" ]; then _pass "$1" "count=${n} (>= $3)"
  else _fail "$1" "count=${n} (< $3)  out: $(_first "$VM_OUT")"; fi
}
assert_num_le() {      # label ; command ; max
  vm_exec "$2"; local n; n=$(_num_read)
  if [ -z "$n" ]; then _fail "$1" "expected one integer on line 1 (rc=${VM_RC}); got: $(_first "$VM_OUT")"; return; fi
  if [ "$n" -le "$3" ]; then _pass "$1" "count=${n} (<= $3)"
  else _fail "$1" "count=${n} (> $3)  out: $(_first "$VM_OUT")"; fi
}

# ── The suite ────────────────────────────────────────────────────────────────
run_suite() {
  # Resolve the admin account name once (defaults to wpadmin if vars.sh lacks it)
  vm_exec '. /etc/wp-install/vars.sh 2>/dev/null; echo "${ADMIN_USER:-wpadmin}"'
  ADMIN_USER=$(printf '%s' "$VM_OUT" | tr -d '[:space:]'); ADMIN_USER=${ADMIN_USER:-wpadmin}
  # v2 (ChatGPT harness finding 17): the account name comes from the VM under
  # test, which may itself be defective. Reject anything outside a strict
  # username charset before it is interpolated into su/id commands run as root
  # through the guest agent.
  case "$ADMIN_USER" in
    ''|*[!a-zA-Z0-9_-]*)
      _fail "admin account name is well-formed" "guest returned an invalid ADMIN_USER ('$(_first "$ADMIN_USER")') — skipping the account-specific checks"
      ADMIN_USER="" ;;
  esac

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
  # v2 (ChatGPT harness finding 7): prove the FOUR specific DNS accepts exist —
  # each backend subnet (wp-front 10.89.10.0/24, wp-db 10.89.20.0/24) for BOTH
  # udp and tcp — rather than counting any four 'dport 53 accept' lines, which a
  # count can satisfy with unrelated or wrong-subnet rules.
  for _sub in 10.89.10.0/24 10.89.20.0/24; do
    for _proto in udp tcp; do
      assert_rc0    "nftables DNS accept present: ${_sub} ${_proto}/53" \
                    "nft list ruleset 2>/dev/null | grep -Eq 'saddr ${_sub}.*${_proto} dport 53 accept'"
    done
  done

  section "3. WordPress HTTP health — the v7-16 BusyBox-wget fix"
  # v2 (ChatGPT harness finding 8): run the health checker ONCE and make its EXIT
  # STATUS the primary verdict; the output strings are supplementary evidence,
  # checked against that single result. The regressed probe returned "none" for
  # every request (GNU wget long options on Alpine's BusyBox wget). Running it
  # twice for adjacent assertions was wasteful and could pass on partial output
  # without the script actually succeeding.
  vm_exec '/usr/local/bin/wp-health-check.sh wordpress 2>&1'
  local _hc_rc="$VM_RC" _hc_out="$VM_OUT"
  if [ "$_hc_rc" != "0" ]; then
    _fail "wp-health-check.sh exits 0 (overall health OK)" "rc=${_hc_rc} — out: $(_first "$_hc_out")"
  else
    _pass "wp-health-check.sh exits 0 (overall health OK)" ""
    case "$_hc_out" in
      *"Unexpected HTTP response: none"*)
        _fail "health check HTTP probe returns a real status, not 'none'" "probe still reports 'none'" ;;
      *) _pass "health check HTTP probe returns a real status, not 'none'" "" ;;
    esac
    case "$_hc_out" in
      *"DB query"*) _pass "health check confirms a WordPress DB query works" "" ;;
      *) _fail "health check confirms a WordPress DB query works" "no 'DB query' line in the health output" ;;
    esac
  fi

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
  if [ -n "$ADMIN_USER" ]; then
    assert_rc0        "admin account '${ADMIN_USER}' is in the wheel group" \
                      "id -nG ${ADMIN_USER} 2>/dev/null | grep -qw wheel"
    # --help skips elevation, so this proves the helper is reachable and runnable
    # as the unprivileged admin (the path that used to die on vars.sh perms).
    assert_rc0        "validate-wordpress.sh --help runs as '${ADMIN_USER}' (no elevation)" \
                      "su -s /bin/sh ${ADMIN_USER} -c '/usr/local/bin/validate-wordpress.sh --help'"
    # v2 (ChatGPT harness finding 15): --help intentionally bypasses elevation, so
    # it does not prove doas works. Probe non-interactive elevation explicitly.
    # doas -n never prompts: it succeeds under a passwordless/persist policy and
    # fails when a password would be required — which is a legitimate policy, so
    # a non-zero result is a SKIP (elevation needs a password), not a FAIL.
    vm_exec "su -s /bin/sh ${ADMIN_USER} -c 'doas -n /usr/local/bin/validate-wordpress.sh --section updates >/dev/null 2>&1'"
    if [ "$VM_RC" = "0" ]; then
      _pass "non-interactive doas elevation works for '${ADMIN_USER}'" "doas -n ran the validator without a password prompt"
    else
      _skip "non-interactive doas elevation for '${ADMIN_USER}'" \
            "doas -n returned rc=${VM_RC} — expected if the doas policy requires a password (test the SSH path with --ssh-host for the interactive case)"
    fi
  else
    _skip "admin account checks" "ADMIN_USER was rejected as malformed — see above"
  fi

  section "6. Update & version features — v8"
  assert_rc0        "update.sh status runs" '/usr/local/bin/update.sh status'
  assert_not_contains "update.sh status does not falsely show 0/3 pins" \
                    '/usr/local/bin/update.sh status 2>&1' "0/3"
  # v2 (ChatGPT harness finding 9): version discovery needs registry reachability
  # and still exits 0 offline (printing that it couldn't reach the registry). A
  # report shell alone doesn't prove discovery ran, so: capture once, require the
  # command to succeed, and if it says the registry was unreachable, SKIP (we
  # can't verify discovery offline) instead of passing. Otherwise require it to
  # actually name the WordPress line.
  vm_exec '/usr/local/bin/update.sh versions 2>&1'
  if [ "$VM_RC" != "0" ]; then
    _fail "update.sh versions runs" "rc=${VM_RC} — out: $(_first "$VM_OUT")"
  else
    case "$VM_OUT" in
      *"couldn't reach the registry"*|*"could not reach"*|*"couldn't reach Docker Hub"*)
        _skip "version discovery reached the registry" \
              "update.sh versions reports the registry was unreachable — can't verify discovery from this host/offline" ;;
      *"WordPress"*)
        _pass "version discovery reached the registry and reported the WordPress line" "" ;;
      *)
        _fail "version discovery reported the WordPress line" "no WordPress line and no unreachable notice — out: $(_first "$VM_OUT")" ;;
    esac
  fi
  # Fail-closed firewall toggle: the dependency must match the deployment profile.
  # v2 (ChatGPT harness finding 7): inspect the OpenRC depend() block specifically
  # — not any line or comment — and require the expected directive as a real
  # need/use token AND the wrong one to be absent, so a phrase in a comment or
  # both directives appearing can't pass it.
  vm_exec '. /etc/wp-install/vars.sh 2>/dev/null; echo "${DEPLOYMENT_PROFILE:-standard}"'
  local profile; profile=$(printf '%s' "$VM_OUT" | tr -d '[:space:]'); profile=${profile:-standard}
  # Extract just the depend() function body from the init script.
  vm_exec "awk '/^depend\\(\\)/{f=1} f{print} f&&/}/{exit}' /etc/init.d/mariadb-container"
  local _dep="$VM_OUT" _dep_rc="$VM_RC"
  if [ "$_dep_rc" != "0" ] || [ -z "$_dep" ]; then
    _fail "mariadb-container has a depend() block" "could not read depend() (rc=${_dep_rc})"
  elif [ "$profile" = "production" ]; then
    case "$_dep" in
      *"need nftables"*) case "$_dep" in
                           *"use nftables"*) _fail "production firewall dependency is exactly 'need nftables'" "depend() also contains 'use nftables'" ;;
                           *) _pass "production firewall dependency is fail-closed ('need nftables')" "" ;;
                         esac ;;
      *) _fail "production firewall dependency is fail-closed ('need nftables')" "depend() has no 'need nftables': $(_first "$_dep")" ;;
    esac
  else
    case "$_dep" in
      *"use nftables"*) case "$_dep" in
                          *"need nftables"*) _fail "standard firewall dependency is exactly 'use nftables'" "depend() also contains 'need nftables'" ;;
                          *) _pass "standard firewall dependency is 'use nftables'" "" ;;
                        esac ;;
      *) _fail "standard firewall dependency is 'use nftables'" "depend() has no 'use nftables': $(_first "$_dep")" ;;
    esac
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
  # Derive the invalid target from the CURRENT variant so this doesn't rot when
  # the deployed PHP/Apache variant changes (ChatGPT harness finding 11).
  vm_exec '. /etc/wp-install/pinned.env 2>/dev/null; echo "${WP_TAG:-6.9.4-php8.3-apache}"'
  local wptag; wptag=$(printf '%s' "$VM_OUT" | tr -d '[:space:]'); wptag=${wptag:-6.9.4-php8.3-apache}
  local variant="${wptag#*-}"; [ "$variant" = "$wptag" ] && variant="php8.3-apache"
  local bad="99.99.99-nonexistent-${variant}"

  vm_exec "podman inspect wordpress --format '{{.Image}}' 2>/dev/null"
  local before; before=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')

  # v2 (ChatGPT harness finding 11): capture the update's exit status and REQUIRE
  # it to be non-zero — a nonexistent tag must be rejected, not silently succeed.
  # The old test discarded the status with '; true', so a defective update path
  # that returned 0 on a bad target would have passed.
  assert_rc_nonzero "a nonexistent update target is rejected (non-zero exit)" \
                    "yes | /usr/local/bin/update.sh wp ${bad} >/dev/null 2>&1"

  # Independently verify production is untouched and no half-swapped state remains.
  vm_exec "podman ps --filter name=^wordpress\$ --filter status=running --format '{{.Names}}'"
  local running; running=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec "podman inspect wordpress --format '{{.Image}}' 2>/dev/null"
  local after; after=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  if [ "$running" = "wordpress" ] && [ -n "$before" ] && [ "$before" = "$after" ]; then
    _pass "production WordPress is unchanged after the failed update" "still running, still on the original image"
  else
    _fail "production WordPress is unchanged after the failed update" "running='${running}' before='${before}' after='${after}'"
  fi
  assert_num_le     "no orphaned wordpress-old / wordpress-candidate container remains" \
                    "podman ps -a --format '{{.Names}}' | grep -cE '^wordpress-(old|candidate)\$'" 0
  # test -d returns 0 while the lock dir EXISTS; we want it GONE (released), so a
  # non-zero exit is the pass here.
  assert_rc_nonzero "the update lock was released after the failed update" \
                    "test -d /run/lock/wordpress-update.lock"
}

# ── Optional: the real wpadmin SSH + doas elevation path ─────────────────────
# The guest-exec checks above run as root, so they verify the RESULTS the doas
# feature enables. This optionally verifies the elevation itself over SSH, the
# way an operator actually uses it. It needs key auth (doas would otherwise
# prompt for a password) and network reachability to the VM.
run_ssh_doas_check() {
  section "9. Outbound email configuration"
  # Config/permission checks only -- deliberately NOT a live send. Every
  # other check here is contained to this VM; a real message leaves it and
  # lands in someone's mailbox, which is a side effect a test suite should
  # not have by default. `wp-mail.sh test <addr>` is the live check, run
  # deliberately by a human. What IS verified here is everything that can be
  # wrong without sending: whether mail is configured at all, whether the
  # credential file is protected, whether the mu-plugin that does the work is
  # present, and whether its mount is read-only.
  if vm_exec 'test -r /home/wpuser/wp/secrets/smtp.php'; then
    _pass "SMTP relay is configured"

    # 0400 owned by uid 33: readable by the PHP worker, nothing else.
    vm_exec "stat -c '%a %u' /home/wpuser/wp/secrets/smtp.php 2>/dev/null"
    case "$VM_OUT" in
      400\ 33*) _pass "Credential file is 0400, owned by uid 33" ;;
      *)        _fail "Credential file mode/owner" \
                      "got '${VM_OUT}', expected '400 33' — the relay password may be readable by other accounts on this VM" ;;
    esac

    # A secret under the docroot becomes HTTP-readable the moment PHP
    # execution breaks, which is exactly when nobody is watching.
    assert_rc0 "credential file is outside the web root" \
               '! test -e /home/wpuser/wp/html/smtp.php && ! test -e /home/wpuser/wp/html/wp-content/smtp.php'

    assert_rc0 "SMTP mu-plugin is installed" \
               'test -r /home/wpuser/wp/html/wp-content/mu-plugins/01-wpvm-smtp.php'

    # Read-only mount: a compromised PHP process must not be able to rewrite
    # the relay config to point at a server it controls.
    vm_exec "podman inspect wordpress --format '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' 2>/dev/null | tr ' ' '\\n' | grep /var/www/private"
    case "$VM_OUT" in
      *=false*) _pass "Credential mount is read-only inside the container" ;;
      *=true*)  _fail "Credential mount is writable inside the container" "expected :ro" ;;
      *)        _skip "Credential mount state" "could not determine it from podman inspect" ;;
    esac

    # The throttle is what bounds reputational damage to the sending domain
    # if these credentials are ever used to send spam.
    assert_rc0 "outbound SMTP rate limit is in the live ruleset" \
               'nft list ruleset 2>/dev/null | grep -q nft-smtp-ratelimit'
  else
    _skip "Outbound email" "no SMTP relay configured — WordPress cannot send mail, so password resets and notifications fail silently. Configure with: wp-mail.sh setup"
  fi

  section "9. wpadmin SSH + doas elevation (real path)"
  command -v ssh >/dev/null 2>&1 || { _skip "ssh doas elevation" "no ssh client on the host"; return; }
  # v2 (ChatGPT harness finding 14): validate the key file before use.
  if [ -n "$SSH_KEY" ]; then
    if [ ! -f "$SSH_KEY" ]; then _skip "ssh doas elevation" "--ssh-key '$SSH_KEY' is not a regular file"; return; fi
    local perm; perm=$(stat -c '%a' "$SSH_KEY" 2>/dev/null || echo "")
    case "$perm" in
      *[2367]|*[2367]?|*[2367]??) : ;;  # (informational; ssh itself enforces strictness)
    esac
    if [ -r "$SSH_KEY" ] && [ "$(stat -c '%U' "$SSH_KEY" 2>/dev/null)" != "$(id -un)" ]; then
      _skip "ssh doas elevation" "--ssh-key '$SSH_KEY' is not owned by $(id -un) — refusing to use it"; return
    fi
  fi
  # FORENSIC FIX (new-audit High finding, confirmed accurate): the previous
  # round added a guest-agent cross-check but only ever warned on a
  # mismatch or on being unable to check, then proceeded anyway with plain
  # network-path TOFU regardless of the result — the evaluator's own
  # remediation was to gate the connection on this, not just report it:
  # "retrieve the guest key... and THEN use StrictHostKeyChecking=yes."
  # This now does exactly that. ssh-keyscan alone is trust-on-first-use
  # over the same network path an attacker would need to control to
  # matter, so accept-new on its output can't detect a MITM'd *first*
  # connection, only a *later* key change. Guest-exec goes over QEMU's own
  # guest-agent channel, not the network path SSH uses, so cross-checking
  # against it closes that gap: an attacker able to intercept the TCP path
  # to $SSH_HOST does not thereby gain the guest-agent channel too.
  local kh; kh=$(mktemp)
  ssh-keyscan -T 10 "$SSH_HOST" >"$kh" 2>/dev/null || true
  local sshid_verified=0
  if [ -s "$kh" ] && agent_up; then
    local scanned_fps guest_fps match=0
    scanned_fps=$(ssh-keygen -lf "$kh" 2>/dev/null | awk '{print $2}')
    vm_exec 'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f" 2>/dev/null; done'
    guest_fps=$(printf '%s' "$VM_OUT" | awk '{print $2}')
    if [ -n "$scanned_fps" ] && [ -n "$guest_fps" ]; then
      while IFS= read -r sfp; do
        [ -n "$sfp" ] || continue
        printf '%s\n' "$guest_fps" | grep -qxF "$sfp" && { match=1; break; }
      done <<EOF
$scanned_fps
EOF
      if [ "$match" = "1" ]; then
        sshid_verified=1
        ok "SSH host key matches the guest-agent-reported fingerprint (not just network TOFU)"
      fi
    fi
  fi
  if [ "$sshid_verified" != "1" ]; then
    if [ "$ALLOW_UNVERIFIED_SSHID" = "1" ]; then
      warn "SSH host key could not be independently verified via the guest agent — proceeding anyway per --allow-unverified-sshid, with plain network TOFU. Treat this VM's SSH as unverified."
    else
      rm -f "$kh" 2>/dev/null || true
      _skip "ssh doas elevation" "SSH host key not independently verified via the guest agent (mismatch, or agent unreachable) — refusing to trust it. Pass --allow-unverified-sshid to proceed anyway on a network path you already trust (e.g. a local lab VM)."
      return
    fi
  fi
  # v2 (ChatGPT harness finding 14): assemble ssh args as an array — a key path
  # with spaces or a leading '-' can no longer split or be read as an option.
  # When the host key was independently verified above, use a REAL
  # StrictHostKeyChecking=yes against a known_hosts file containing only
  # that verified key (built from the guest-agent-confirmed fingerprint
  # match, not just the earlier network scan) -- this also closes a
  # narrower TOCTOU gap accept-new never covered: a MITM appearing between
  # the scan above and this connection, a moment later. Falls back to
  # accept-new only in the explicit --allow-unverified-sshid lab path.
  local ssh_args
  if [ "$sshid_verified" = "1" ]; then
    ssh_args=(-o BatchMode=yes -o StrictHostKeyChecking=yes
              -o "UserKnownHostsFile=$kh" -o ConnectTimeout=15)
  else
    ssh_args=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new
              -o "UserKnownHostsFile=$kh" -o ConnectTimeout=15)
  fi
  [ -n "$SSH_KEY" ] && ssh_args+=(-i "$SSH_KEY")
  # The read-only validator auto-elevates via doas; rc0 means elevation worked
  # non-interactively (passwordless key session + a doas policy that doesn't
  # prompt) and it produced digest output.
  local out rc
  out=$(ssh "${ssh_args[@]}" "${SSH_USER}@${SSH_HOST}" \
        '/usr/local/bin/validate-wordpress.sh --section updates' 2>&1)
  rc=$?
  rm -f "$kh" 2>/dev/null || true
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
  # From here on a VM may exist — the EXIT trap must clean it up on interruption.
  CLEANUP_REQUIRED=1
  # Strip WHOLE-LINE comments and keep everything else (values and intentional
  # blank-line answers). We deliberately do NOT strip inline "# ..." text: a
  # password can legitimately contain " #", so the template (see
  # --emit-answers-template) is comment-free on value lines by design.
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
  [ "$CLEANUP_RUNNING" = "1" ] && return 0
  CLEANUP_RUNNING=1
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

# v2 (ChatGPT harness finding 5): signal-safe cleanup. Without a trap, an
# interrupted run (Ctrl-C, SIGTERM, terminal loss, CI cancel, an unexpected
# error under set -u) left a provisioned test VM running, holding a VMID, disk,
# and test credentials — even though the default for --provision is to destroy
# it. This tears down only a VM this run may have created, and only when --keep
# is not set. teardown is idempotent, so an explicit call plus the trap is safe.
cleanup_on_exit() {
  local rc=$?
  if [ "$PROVISION" = "1" ] && [ "$KEEP" != "1" ] && [ "$CLEANUP_REQUIRED" = "1" ]; then
    teardown
  fi
  exit "$rc"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ── JSON output ──────────────────────────────────────────────────────────────
# v2 (ChatGPT harness finding 23): gather build/environment metadata from the VM.
collect_metadata() {
  vm_exec '. /etc/wp-install/vars.sh 2>/dev/null; printf "%s" "${DEPLOYMENT_PROFILE:-standard}"'
  META_PROFILE=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec '. /etc/wp-install/pinned.env 2>/dev/null; printf "%s" "${WP_DIGEST:-}"'; META_WP=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec '. /etc/wp-install/pinned.env 2>/dev/null; printf "%s" "${DB_DIGEST:-}"'; META_DB=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec '. /etc/wp-install/pinned.env 2>/dev/null; printf "%s" "${CS_DIGEST:-}"'; META_CS=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec 'cat /etc/alpine-release 2>/dev/null'; META_ALPINE=$(printf '%s' "$VM_OUT" | tr -d '[:space:]')
  vm_exec 'podman --version 2>/dev/null'; META_PODMAN=$(printf '%s' "$VM_OUT" | head -n1)
}

_jstr() { printf '%s' "${1:-}" | jq -R .; }   # JSON-encode a string safely

# Hashes $1 (install.sh) plus every file under its sibling lib/ and payload/
# directories, if present -- so provisioner_sha256 still identifies the
# EXACT code that ran, now that it's install.sh + lib/*.sh + payload/**
# instead of one monolithic file. Sorted by path RELATIVE to $1's directory
# (not absolute), so the result is identical across clones regardless of
# where the repo happens to be checked out. Falls back to hashing $1 alone
# for a single-file script with no lib/payload siblings (old layout).
_provisioner_sha256() {
  local entry="$1" dir name
  [ -n "$entry" ] && [ -f "$entry" ] || { printf ''; return; }
  dir=$(cd "$(dirname "$entry")" 2>/dev/null && pwd) || { sha256sum "$entry" 2>/dev/null | awk '{print $1}'; return; }
  name=$(basename "$entry")
  if [ -d "$dir/lib" ] || [ -d "$dir/payload" ]; then
    ( cd "$dir" && {
        sha256sum "$name" 2>/dev/null
        [ -d lib ]     && find lib     -type f | LC_ALL=C sort | xargs -r sha256sum 2>/dev/null
        [ -d payload ] && find payload -type f | LC_ALL=C sort | xargs -r sha256sum 2>/dev/null
      } | LC_ALL=C sort | sha256sum | awk '{print $1}' )
  else
    sha256sum "$entry" 2>/dev/null | awk '{print $1}'
  fi
}

write_json() {
  [ -n "$JSON_OUT" ] || return 0
  local completed; completed=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  # finding 20: refuse to write through a symlink or onto an existing non-regular
  # file, and require the parent directory to exist.
  local jdir jbase; jdir=$(dirname "$JSON_OUT"); jbase=$(basename "$JSON_OUT")
  [ -d "$jdir" ] || die "--json directory '$jdir' does not exist."
  [ -L "$JSON_OUT" ] && die "--json target '$JSON_OUT' is a symlink — refusing to write through it."
  { [ -e "$JSON_OUT" ] && [ ! -f "$JSON_OUT" ]; } && die "--json target '$JSON_OUT' exists and is not a regular file."
  local harness_sha prov_sha="" prov_layout="single-file"
  harness_sha=$(sha256sum "$0" 2>/dev/null | awk '{print $1}')
  if [ -n "$SCRIPT" ]; then
    prov_sha=$(_provisioner_sha256 "$SCRIPT")
    { [ -d "$(dirname "$SCRIPT")/lib" ] || [ -d "$(dirname "$SCRIPT")/payload" ]; } && prov_layout="install.sh+lib+payload"
  fi
  # finding 19: write atomically — a temp file in the same dir, then rename.
  local jtmp; jtmp=$(mktemp "${jdir}/.${jbase}.XXXXXX") || die "cannot create JSON temp file in '$jdir'."
  if ! {
    printf '{\n'
    printf '  "metadata": {\n'
    printf '    "started_at": %s,\n'         "$(_jstr "$STARTED_AT")"
    printf '    "completed_at": %s,\n'       "$(_jstr "$completed")"
    printf '    "vmid": %s,\n'               "$(_jstr "$VMID")"
    printf '    "deployment_profile": %s,\n' "$(_jstr "${META_PROFILE:-unknown}")"
    printf '    "provisioned": %s,\n'        "$([ "$PROVISION" = 1 ] && echo true || echo false)"
    printf '    "destructive": %s,\n'        "$([ "$DESTRUCTIVE" = 1 ] && echo true || echo false)"
    printf '    "ssh_test": %s,\n'           "$([ -n "$SSH_HOST" ] && echo true || echo false)"
    printf '    "harness_sha256": %s,\n'     "$(_jstr "${harness_sha:-}")"
    printf '    "provisioner_sha256": %s,\n' "$(_jstr "${prov_sha:-}")"
    printf '    "provisioner_layout": %s,\n' "$(_jstr "${prov_layout}")"
    printf '    "alpine_version": %s,\n'     "$(_jstr "${META_ALPINE:-}")"
    printf '    "podman_version": %s,\n'     "$(_jstr "${META_PODMAN:-}")"
    printf '    "images": { "wordpress": %s, "mariadb": %s, "crowdsec": %s }\n' \
      "$(_jstr "${META_WP:-}")" "$(_jstr "${META_DB:-}")" "$(_jstr "${META_CS:-}")"
    printf '  },\n'
    printf '  "pass": %d,\n  "fail": %d,\n  "skip": %d,\n  "results": [\n' "$PASS" "$FAIL" "$SKIP"
    local first=1
    printf '%s' "$RESULTS" | while IFS="$TAB" read -r st nm dt; do
      [ -n "$st" ] || continue
      [ "$first" = "1" ] && first=0 || printf ',\n'
      printf '    {"status": "%s", "name": %s, "detail": %s}' "$st" "$(_jstr "$nm")" "$(_jstr "$dt")"
    done
    printf '\n  ]\n}\n'
  } > "$jtmp"; then
    rm -f "$jtmp"; die "failed to generate JSON results."
  fi
  chmod 0600 "$jtmp" 2>/dev/null || true
  mv -f "$jtmp" "$JSON_OUT" || { rm -f "$jtmp"; die "failed to publish JSON results to '$JSON_OUT'."; }
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
    # finding 21: record the phase failure and still emit JSON if requested.
    _fail "install completed within the ${WAIT_TIMEOUT}s timeout" "the /var/log/wp-install.done marker never appeared"
    collect_metadata 2>/dev/null || true
    write_json
    teardown
    exit 1
  fi

  collect_metadata 2>/dev/null || true
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
  if [ "$STRICT" = "1" ] && [ "$SKIP" -gt 0 ]; then
    echo "${YLW}${BLD}Integration test INCOMPLETE under --strict: ${SKIP} check(s) skipped.${RST}"
    exit 1
  fi
  echo "${GRN}${BLD}Integration test PASSED.${RST}"
  exit 0
}

main
