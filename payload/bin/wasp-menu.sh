#!/bin/sh
# =============================================================================
# wasp-menu.sh — one front door to the WASP tooling
# =============================================================================
# A task-grouped menu over the ~20 operator tools, so nobody has to remember
# which flag does what. Built for the way this box is actually operated:
#
#   - Pure POSIX sh, ZERO new packages. It runs in the `qm terminal` console
#     (where root operates and CANNOT paste) and over SSH for admins, on any
#     terminal, with no whiptail/dialog/ncurses dependency to add to a hardened
#     VM. Adding a TUI toolkit or a web UI for a menu would spend the
#     minimal-surface budget this whole project is built to protect.
#
#   - It is a teaching tool as much as a launcher: EVERY action prints the exact
#     command it is about to run before running it. A tech learns the command by
#     watching; an engineer confirms nothing surprising happens and can skip the
#     menu next time. Nothing here does anything you could not do by typing the
#     command yourself — it just means you do not have to remember it.
#
#   - Guardrails match the audience without splitting into two programs:
#     destructive or high-impact actions (rotate, update, restore, purge) are
#     marked [!] and require typing 'yes'. Everything else runs on a keystroke.
#
# This launches the tools; it does not reimplement them. If a tool changes, its
# entry here keeps working because it just calls the tool.
# =============================================================================
set -u

BIN=/usr/local/bin
IS_TTY=0; [ -t 0 ] && [ -t 1 ] && IS_TTY=1

# ── colours, only if the terminal supports them ─────────────────────────────
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  B=$(printf '\033[1m'); DIM=$(printf '\033[2m'); R=$(printf '\033[0m')
  GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); RED=$(printf '\033[31m')
  CYN=$(printf '\033[36m')
else
  B=''; DIM=''; R=''; GRN=''; YEL=''; RED=''; CYN=''
fi

# ── privilege: most tools need root; elevate once via doas if available ──────
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "wasp-menu must run as root (or via doas)." >&2
  exit 1
fi

# ── a run helper: show the command, (confirm if destructive), then run ──────
# usage: run "<label>" "<danger 0|1>" <tool> arg arg...
# The <tool> is a bare script name; run() resolves it under $BIN so the menu
# does not depend on $BIN being in PATH (it often is not in a bare console).
run() {
  _label="$1"; _danger="$2"; _tool="$3"; shift 3
  # Resolve to an absolute path if it is one of our tools; otherwise run as-is.
  if [ -x "$BIN/$_tool" ]; then _exe="$BIN/$_tool"; else _exe="$_tool"; fi
  echo ""
  printf '%s%s%s\n' "$B" "$_label" "$R"
  printf '%s$ %s %s%s\n' "$DIM" "$_tool" "$*" "$R"
  if [ "$_danger" = "1" ]; then
    printf '%s[!] This changes state or is high-impact.%s Type %syes%s to run: ' \
      "$RED" "$R" "$B" "$R"
    read -r _c
    case "$_c" in
      yes|YES) : ;;
      *) echo "    Skipped."; _pause; return 0 ;;
    esac
  fi
  echo "$DIM----------------------------------------$R"
  # shellcheck disable=SC2068
  "$_exe" "$@"
  _rc=$?
  echo "$DIM----------------------------------------$R"
  [ "$_rc" -eq 0 ] && printf '%s[ok] done%s\n' "$GRN" "$R" \
                   || printf '%s[!!] exited %s%s\n' "$YEL" "$_rc" "$R"
  _pause
}

# Prompt for one argument. Returns non-zero (and prints nothing) if left blank,
# so a caller can abort cleanly rather than run a tool with a missing operand.
ask() { # prompt varname
  printf '  %s: ' "$1"
  read -r _ans
  [ -n "$_ans" ] || { echo "    (nothing entered — cancelled)"; return 1; }
  eval "$2=\$_ans"
  return 0
}

_pause() { [ "$IS_TTY" = 1 ] && { printf '\n%spress Enter%s' "$DIM" "$R"; read -r _; }; }

_missing() { # tool
  printf '%s  %s is not installed on this VM.%s\n' "$YEL" "$1" "$R"
  _pause
}

_have() { [ -x "$BIN/$1" ]; }

# ── headers ─────────────────────────────────────────────────────────────────
_banner() {
  clear 2>/dev/null || true
  _ver="unknown"
  # Strip surrounding quotes with sed, not `tr -d` with nested shell quotes:
  # the concatenated `tr` form can degrade into an invalid character range.
  [ -r /etc/wp-install/vars.sh ] && _ver=$(sed -n 's/^WASP_VERSION=//p' /etc/wp-install/vars.sh | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | head -1)
  _prof=$(sed -n 's/^DEPLOYMENT_PROFILE=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'\'']//' -e 's/["'\'']$//' | head -1)
  printf '%s┌────────────────────────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '%s│%s  %sWASP operator menu%s   build %s  %s%s\n' "$CYN" "$R" "$B" "$R" "${_ver}" "${_prof:-standard}" ""
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  # A one-line health pulse at the top so the operator sees state before acting.
  if _have validate-wordpress.sh; then
    _h=$(validate-wordpress.sh --check 2>/dev/null | head -1)
    case "$_h" in
      *OK*|*ok*)     printf '  health: %s%s%s\n' "$GRN" "$_h" "$R" ;;
      *WARN*|*warn*) printf '  health: %s%s%s\n' "$YEL" "$_h" "$R" ;;
      *CRIT*|*crit*) printf '  health: %s%s%s\n' "$RED" "$_h" "$R" ;;
      *)             [ -n "$_h" ] && printf '  health: %s\n' "$_h" ;;
    esac
  fi
}

# =============================================================================
#  SUBMENUS — grouped by the task an operator actually has in mind
# =============================================================================

menu_health() {
  while :; do
    _banner
    cat <<EOF

  ${B}Health & status${R}
    1) Quick health check            ${DIM}validate-wordpress.sh --check${R}
    2) Full validation (~45 checks)  ${DIM}validate-wordpress.sh${R}
    3) Full test report (send-able)  ${DIM}wasp-testreport.sh${R}
    4) Container / WordPress health  ${DIM}wp-health-check.sh${R}
    5) Database health               ${DIM}mariadb-health-check.sh${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) _have validate-wordpress.sh && run "Quick health check" 0 validate-wordpress.sh --check || _missing validate-wordpress.sh ;;
      2) _have validate-wordpress.sh && run "Full validation" 0 validate-wordpress.sh || _missing validate-wordpress.sh ;;
      3) _have wasp-testreport.sh && run "Full test report" 0 wasp-testreport.sh || _missing wasp-testreport.sh ;;
      4) _have wp-health-check.sh && run "WordPress health" 0 wp-health-check.sh || _missing wp-health-check.sh ;;
      5) _have mariadb-health-check.sh && run "Database health" 0 mariadb-health-check.sh || _missing mariadb-health-check.sh ;;
      b|B) return ;;
    esac
  done
}

menu_backup() {
  while :; do
    _banner
    cat <<EOF

  ${B}Backup & restore${R}
    1) Run a backup now              ${DIM}wp-db-backup.sh${R}
    2) Off-site backup status        ${DIM}wasp-offsite-backup.sh status${R}
    7) Why is nothing off-VM?        ${DIM}wasp-offsite-backup.sh doctor${R}
    8) Replace storage credentials   ${DIM}wasp-offsite-backup.sh set-credentials${R}
    9) Change backup destination     ${DIM}wasp-offsite-backup.sh set-destination${R}
    3) List off-site backups         ${DIM}wasp-offsite-backup.sh list${R}
    4) ${RED}[!]${R} Prove offsite recovery      ${DIM}wasp-offsite-backup.sh remote-restore-drill${R}
    5) ${RED}[!]${R} Restore from backup          ${DIM}wasp-offsite-backup.sh restore${R}
    6) Self-test (local restore)     ${DIM}wasp-selftest.sh restore-test${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) _have wp-db-backup.sh && run "Run a backup" 0 wp-db-backup.sh || _missing wp-db-backup.sh ;;
      2) _have wasp-offsite-backup.sh && run "Off-site status" 0 wasp-offsite-backup.sh status || _missing wasp-offsite-backup.sh ;;
      7) _have wasp-offsite-backup.sh && run "Off-site diagnosis" 0 wasp-offsite-backup.sh doctor || _missing wasp-offsite-backup.sh ;;
      8) _have wasp-offsite-backup.sh && run "Replace storage credentials" 1 wasp-offsite-backup.sh set-credentials || _missing wasp-offsite-backup.sh ;;
      9) _have wasp-offsite-backup.sh && run "Change backup destination" 1 wasp-offsite-backup.sh set-destination || _missing wasp-offsite-backup.sh ;;
      3) _have wasp-offsite-backup.sh && run "List off-site" 0 wasp-offsite-backup.sh list || _missing wasp-offsite-backup.sh ;;
      4) _have wasp-offsite-backup.sh && run "Remote restore drill" 1 wasp-offsite-backup.sh remote-restore-drill || _missing wasp-offsite-backup.sh ;;
      5) _have wasp-offsite-backup.sh && run "Restore from backup" 1 wasp-offsite-backup.sh restore || _missing wasp-offsite-backup.sh ;;
      6) _have wasp-selftest.sh && run "Self-test restore" 0 wasp-selftest.sh restore-test || _missing wasp-selftest.sh ;;
      b|B) return ;;
    esac
  done
}

menu_security() {
  while :; do
    _banner
    cat <<EOF

  ${B}Security & hardening${R}
    1) Hardening status              ${DIM}wp-hardening.sh status${R}
    2) Egress (proxy) status         ${DIM}wasp-egress.sh status${R}
    3) Test egress is enforced       ${DIM}wasp-egress.sh test${R}
    4) CrowdSec whitelist            ${DIM}wp-hardening.sh crowdsec-whitelist list${R}
   17) Is CrowdSec actually blocking? ${DIM}wp-hardening.sh crowdsec-doctor${R}
    5) Plugin vulnerability scan     ${DIM}wp-plugins.sh vulns${R}
    6) Malware scan (quick)          ${DIM}wp-malware-scan.sh quick${R}
    7) Malware scan (full)           ${DIM}wp-malware-scan.sh full${R}
    8) Verify tooling integrity      ${DIM}wasp-verify-integrity.sh${R}
   10) Theme/plugin uploads: ALLOW  ${DIM}wp-hardening.sh disable file-mods${R}
   11) Theme/plugin uploads: BLOCK  ${DIM}wp-hardening.sh enable file-mods${R}
   12) Install a theme/plugin ZIP   ${DIM}wp-plugins.sh install-file <path>${R}
   13) PHP shell functions: BLOCK   ${DIM}wp-hardening.sh enable php-exec${R}
   14) PHP shell functions: ALLOW   ${DIM}wp-hardening.sh disable php-exec${R}
    9) ${RED}[!]${R} Rotate a secret              ${DIM}wp-rotate-secrets.sh ...${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) _have wp-hardening.sh && run "Hardening status" 0 wp-hardening.sh status || _missing wp-hardening.sh ;;
      2) _have wasp-egress.sh && run "Egress status" 0 wasp-egress.sh status || _missing wasp-egress.sh ;;
      3) _have wasp-egress.sh && run "Egress enforcement test" 0 wasp-egress.sh test || _missing wasp-egress.sh ;;
      4) _have wp-hardening.sh && run "CrowdSec whitelist" 0 wp-hardening.sh crowdsec-whitelist list || _missing wp-hardening.sh ;;
      17) _have wp-hardening.sh && run "CrowdSec remediation chain (live test)" 0 wp-hardening.sh crowdsec-doctor || _missing wp-hardening.sh ;;
      5) _have wp-plugins.sh && run "Plugin vulnerabilities" 0 wp-plugins.sh vulns || _missing wp-plugins.sh ;;
      6) _have wp-malware-scan.sh && run "Malware quick scan" 0 wp-malware-scan.sh quick || _missing wp-malware-scan.sh ;;
      7) _have wp-malware-scan.sh && run "Malware full scan" 0 wp-malware-scan.sh full || _missing wp-malware-scan.sh ;;
      8) _have wasp-verify-integrity.sh && run "Integrity check" 0 wasp-verify-integrity.sh || _missing wasp-verify-integrity.sh ;;
      10) _have wp-hardening.sh && run "Allow theme/plugin uploads (reduces hardening)" 1 wp-hardening.sh disable file-mods || _missing wp-hardening.sh ;;
      11) _have wp-hardening.sh && run "Block theme/plugin uploads (restore hardening)" 0 wp-hardening.sh enable file-mods || _missing wp-hardening.sh ;;
      12) if _have wp-plugins.sh; then
            echo ""
            echo "  Copy the zip to the VM first, e.g.:"
            echo "    scp divi.zip admin@$(hostname):/var/lib/wasp-import/incoming/"
            if ask "Path to the .zip" _z; then
              run "Install from file" 1 wp-plugins.sh install-file "$_z" --activate
            fi
          else _missing wp-plugins.sh; fi ;;
      13) _have wp-hardening.sh && run "Block PHP shell functions (restore hardening)" 0 wp-hardening.sh enable php-exec || _missing wp-hardening.sh ;;
      14) _have wp-hardening.sh && run "Allow PHP shell functions (reduces hardening)" 1 wp-hardening.sh disable php-exec || _missing wp-hardening.sh ;;
      9) menu_rotate ;;
      b|B) return ;;
    esac
  done
}

menu_rotate() {
  _banner
  cat <<EOF

  ${B}Rotate a secret${R}  ${DIM}(each verifies before committing, rolls back on failure)${R}
    1) ${RED}[!]${R} Salts                         ${DIM}wp-rotate-secrets.sh salts${R}
    2) ${RED}[!]${R} Database password             ${DIM}wp-rotate-secrets.sh db${R}
    3) ${RED}[!]${R} SMTP relay password           ${DIM}wp-rotate-secrets.sh smtp <pass>${R}
    4) ${RED}[!]${R} Everything                    ${DIM}wp-rotate-secrets.sh all${R}
    b) back
EOF
  printf '\n  select: '; read -r c
  _have wp-rotate-secrets.sh || { _missing wp-rotate-secrets.sh; return; }
  case "$c" in
    1) run "Rotate salts" 1 wp-rotate-secrets.sh salts ;;
    2) run "Rotate DB password" 1 wp-rotate-secrets.sh db ;;
    3) if ask "New SMTP password" _p; then run "Rotate SMTP password" 1 wp-rotate-secrets.sh smtp "$_p"; fi ;;
    4) run "Rotate everything" 1 wp-rotate-secrets.sh all ;;
    b|B) return ;;
  esac
}

menu_updates() {
  while :; do
    _banner
    cat <<EOF

  ${B}Updates${R}  ${DIM}(each scans for CVEs and can roll back)${R}
    1) Check what's available        ${DIM}update.sh check${R}
    2) Current versions / status     ${DIM}update.sh status${R}
    3) ${RED}[!]${R} Update everything            ${DIM}update.sh all${R}
    4) ${RED}[!]${R} Update WordPress             ${DIM}update.sh wp${R}
    5) ${RED}[!]${R} Update database              ${DIM}update.sh db${R}
    6) ${RED}[!]${R} Update CrowdSec              ${DIM}update.sh crowdsec${R}
    7) ${RED}[!]${R} Update Squid (egress proxy)  ${DIM}update.sh squid${R}
    8) ${RED}[!]${R} Update Alpine OS packages    ${DIM}update.sh os${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    _have update.sh || { _missing update.sh; return; }
    case "$c" in
      1) run "Update check" 0 update.sh check ;;
      2) run "Update status" 0 update.sh status ;;
      3) run "Update everything" 1 update.sh all ;;
      4) run "Update WordPress" 1 update.sh wp ;;
      5) run "Update database" 1 update.sh db ;;
      6) run "Update CrowdSec" 1 update.sh crowdsec ;;
      7) run "Update Squid" 1 update.sh squid ;;
      8) run "Update OS packages" 1 update.sh os ;;
      b|B) return ;;
    esac
  done
}

menu_import() {
  while :; do
    _banner
    cat <<EOF

  ${B}Import a site${R}  ${DIM}(inspect and scan BEFORE anything is applied)${R}
    1) How to get a backup here      ${DIM}wp-import.sh where${R}
    2) Inspect an archive            ${DIM}wp-import.sh inspect <file>${R}
    3) Extract (bounded staging)     ${DIM}wp-import.sh extract <file>${R}
    4) Scan staged content           ${DIM}wp-import.sh scan${R}
    5) ${RED}[!]${R} Apply the import             ${DIM}wp-import.sh apply${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    _have wp-import.sh || { _missing wp-import.sh; return; }
    case "$c" in
      1) run "Import: where" 0 wp-import.sh where ;;
      2) if ask "Path to archive" _f; then run "Inspect archive" 0 wp-import.sh inspect "$_f"; fi ;;
      3) if ask "Path to archive" _f; then run "Extract archive" 0 wp-import.sh extract "$_f"; fi ;;
      4) run "Scan staged" 0 wp-import.sh scan ;;
      5) run "Apply import" 1 wp-import.sh apply ;;
      b|B) return ;;
    esac
  done
}

menu_testing() {
  while :; do
    _banner
    cat <<EOF

  ${B}Testing & validation${R}  ${DIM}(prove it works — nothing here changes the site)${R}
    1) ${GRN}Commission check (guided)${R}      ${DIM}runs the full sequence below${R}
   20) ${GRN}Known-defect triage${R}            ${DIM}wasp-triage.sh${R}
   21) Re-test production blockers   ${DIM}wasp-triage.sh --recheck-blockers${R}
    ---
    2) Quick health (exit code)      ${DIM}validate-wordpress.sh --check${R}
    3) Full validation               ${DIM}validate-wordpress.sh${R}
    4) Self-test: everything         ${DIM}wasp-selftest.sh all${R}
    5) Self-test: local restore      ${DIM}wasp-selftest.sh restore-test${R}
    6) Self-test: candidate isolated ${DIM}wasp-selftest.sh candidate-isolation${R}
    7) Egress is really enforced     ${DIM}wasp-egress.sh test${R}
    8) Tooling integrity vs manifest ${DIM}wasp-verify-integrity.sh${R}
   16) WordPress file integrity      ${DIM}wp-plugins.sh verify${R}
    9) Updates available (no change) ${DIM}update.sh check${R}
   10) Image CVE scan (no change)    ${DIM}update.sh trivy${R}
   11) Mail path works               ${DIM}wp-mail.sh doctor${R}
   12) wp-cli can reach the site     ${DIM}wp-plugins.sh doctor${R}
   14) MFA / Two Factor status       ${DIM}wp-plugins.sh status${R}
   18) Install Two Factor NOW        ${DIM}wasp-mfa-deferred.sh --now${R}
   19) Why hasn't MFA installed?     ${DIM}wasp-mfa-deferred.sh --status${R}
   15) WordPress core version        ${DIM}wp-plugins.sh core-version${R}
   13) ${RED}[!]${R} Prove OFFSITE recovery      ${DIM}wasp-offsite-backup.sh remote-restore-drill${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) commission_check ;;
      20) _have wasp-triage.sh && run "Known-defect triage" 0 wasp-triage.sh || _missing wasp-triage.sh ;;
      21) _have wasp-triage.sh && run "Re-test production blockers" 0 wasp-triage.sh --recheck-blockers || _missing wasp-triage.sh ;;
      2) _have validate-wordpress.sh && run "Quick health" 0 validate-wordpress.sh --check || _missing validate-wordpress.sh ;;
      3) _have validate-wordpress.sh && run "Full validation" 0 validate-wordpress.sh || _missing validate-wordpress.sh ;;
      4) _have wasp-selftest.sh && run "Self-test: all" 0 wasp-selftest.sh all || _missing wasp-selftest.sh ;;
      5) _have wasp-selftest.sh && run "Self-test: restore" 0 wasp-selftest.sh restore-test || _missing wasp-selftest.sh ;;
      6) _have wasp-selftest.sh && run "Self-test: candidate isolation" 0 wasp-selftest.sh candidate-isolation || _missing wasp-selftest.sh ;;
      7) _have wasp-egress.sh && run "Egress enforcement" 0 wasp-egress.sh test || _missing wasp-egress.sh ;;
      8) _have wasp-verify-integrity.sh && run "Tooling integrity" 0 wasp-verify-integrity.sh || _missing wasp-verify-integrity.sh ;;
      9) _have update.sh && run "Updates available" 0 update.sh check || _missing update.sh ;;
      10) _have update.sh && run "Image CVE scan" 0 update.sh trivy || _missing update.sh ;;
      11) _have wp-mail.sh && run "Mail doctor" 0 wp-mail.sh doctor || _missing wp-mail.sh ;;
      12) _have wp-plugins.sh && run "wp-cli doctor" 0 wp-plugins.sh doctor || _missing wp-plugins.sh ;;
      14) _have wp-plugins.sh && run "Plugin / MFA status" 0 wp-plugins.sh status || _missing wp-plugins.sh ;;
      18) _have wasp-mfa-deferred.sh && run "Install Two Factor now" 0 wasp-mfa-deferred.sh --now || _missing wasp-mfa-deferred.sh ;;
      19) _have wasp-mfa-deferred.sh && run "Deferred MFA installer status" 0 wasp-mfa-deferred.sh --status || _missing wasp-mfa-deferred.sh ;;
      15) _have wp-plugins.sh && run "WordPress core version (files vs image)" 0 wp-plugins.sh core-version || _missing wp-plugins.sh ;;
      16) _have wp-plugins.sh && run "WordPress file integrity (checksums)" 0 wp-plugins.sh verify || _missing wp-plugins.sh ;;
      13) _have wasp-offsite-backup.sh && run "Remote restore drill" 1 wasp-offsite-backup.sh remote-restore-drill || _missing wasp-offsite-backup.sh ;;
      b|B) return ;;
    esac
  done
}

# ── Commission check ─────────────────────────────────────────────────────────
# The sequence you actually want on a fresh VM, in the order that makes sense:
# does it work, is it hardened, can it recover. Each step is read-only or
# self-contained, reports pass/fail, and does NOT stop the run on a failure --
# a commissioning pass should tell you everything that is wrong in one go,
# rather than making you fix one thing and re-run to discover the next.
commission_check() {
  clear 2>/dev/null || true
  printf '%s┌────────────────────────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '%s│%s  %sCommission check%s — is this VM fit to hand over?\n' "$CYN" "$R" "$B" "$R"
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  cat <<EOF

  Runs the read-only validation suite end to end. Nothing here changes the
  site. It does NOT stop at the first failure — you get the whole picture in
  one pass, so you can fix everything before re-running.

  The one thing it cannot do for you is prove OFFSITE recovery: that pulls a
  real encrypted object and needs your recovery key, so it stays a separate,
  deliberate step (option 13). Until you have run it, offsite recovery is an
  assumption, not evidence.

EOF
  printf '  Run the commission check now? [y/N] : '
  read -r _go
  case "$_go" in y|Y|yes|YES) : ;; *) echo "  Cancelled."; _pause; return 0 ;; esac

  _cc_pass=0; _cc_fail=0; _cc_skip=0
  _step() { # label tool args...
    _l="$1"; _t="$2"; shift 2
    printf '\n%s── %s%s\n' "$B" "$_l" "$R"
    if [ ! -x "$BIN/$_t" ]; then
      printf '   %sSKIP%s  %s is not installed\n' "$YEL" "$R" "$_t"
      _cc_skip=$((_cc_skip+1)); return 0
    fi
    printf '%s   $ %s %s%s\n' "$DIM" "$_t" "$*" "$R"
    _cc_log="/var/log/wasp-commission-${_t%.sh}.log"
    if "$BIN/$_t" "$@" >"$_cc_log" 2>&1; then
      printf '   %sPASS%s\n' "$GRN" "$R"
      _cc_pass=$((_cc_pass+1))
      rm -f "$_cc_log"
    else
      _rc=$?
      printf '   %sFAIL%s (exit %s)\n' "$RED" "$R" "$_rc"
      # Show the lines that actually SAY something. A blind `tail` gave six
      # lines of summary boilerplate ("Result: FAILED") and hid the one line
      # naming the failing probe -- on a real commission run that made two of
      # four failures undiagnosable without re-running the tool by hand.
      # Prefer explicit failure markers; fall back to the tail only if none
      # are found.
      if grep -qE '✗|FAIL|failed|not holding|Unknown option' "$_cc_log" 2>/dev/null; then
        grep -E '✗|\[FAIL\]|not holding|Unknown option' "$_cc_log" \
          | grep -vE 'CHECKS FAILED|Result: FAILED|failed [0-9]+$|silently for a week' \
          | head -8 | sed 's/^/       /'
      else
        tail -8 "$_cc_log" | sed 's/^/       /'
      fi
      printf '       %sfull output: %s%s\n' "$DIM" "$_cc_log" "$R"
      _cc_fail=$((_cc_fail+1))
    fi
  }

  _step "Health — does it work at all"        validate-wordpress.sh --check
  _step "Full validation — ~45 checks"        validate-wordpress.sh
  _step "Self-test — restore, isolation"      wasp-selftest.sh all
  _step "Egress — is the proxy enforced"      wasp-egress.sh test
  _step "Integrity — tooling vs manifest"     wasp-verify-integrity.sh
  _step "Updates — anything outstanding"      update.sh check
  _step "Mail — can it actually send"         wp-mail.sh doctor
  _step "wp-cli — can it reach the site"      wp-plugins.sh doctor
  _step "File integrity — core + plugins"     wp-plugins.sh verify
  _step "CrowdSec — is it actually blocking"  wp-hardening.sh crowdsec-doctor

  echo ""
  printf '%s┌─ Commission result ────────────────────────────────┐%s\n' "$CYN" "$R"
  printf '   %sPASS %s%s   %sFAIL %s%s   %sSKIP %s%s\n' \
    "$GRN" "$_cc_pass" "$R" "$RED" "$_cc_fail" "$R" "$YEL" "$_cc_skip" "$R"
  if [ "$_cc_fail" -eq 0 ]; then
    printf '   %sNothing failed.%s Still owed before you call it proven:\n' "$GRN" "$R"
    echo "     - the offsite restore drill (option 13) — the only real"
    echo "       evidence that recovery works"
    echo "     - if MFA is enforced: lock out a test admin and confirm the"
    echo "       console recovery brings them back (SUPPORT-RUNBOOK.md)"
  else
    printf '   %sFix the failures above, then re-run.%s Each tool prints the\n' "$YEL" "$R"
    echo "   command to fix what it found."
  fi
  printf '%s└────────────────────────────────────────────────────┘%s\n' "$CYN" "$R"
  _pause
}

menu_diagnostics() {
  while :; do
    _banner
    cat <<EOF

  ${B}Diagnostics & forensics${R}
    1) Capture a session for review  ${DIM}wasp-capture.sh start${R}
    2) Capture current state only    ${DIM}wasp-capture.sh report${R}
    3) Forensics: unexpected admins  ${DIM}wp-forensics.sh admins${R}
    4) Forensics: change timeline    ${DIM}wp-forensics.sh timeline${R}
    5) Mail: status                  ${DIM}wp-mail.sh status${R}
    6) Mail: send a test             ${DIM}wp-mail.sh test <addr>${R}
    7) Self-test (full)              ${DIM}wasp-selftest.sh all${R}
    b) back
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) _have wasp-capture.sh && run "Start session capture" 0 wasp-capture.sh start || _missing wasp-capture.sh ;;
      2) _have wasp-capture.sh && run "Capture state" 0 wasp-capture.sh report || _missing wasp-capture.sh ;;
      3) _have wp-forensics.sh && run "Forensics: admins" 0 wp-forensics.sh admins || _missing wp-forensics.sh ;;
      4) _have wp-forensics.sh && run "Forensics: timeline" 0 wp-forensics.sh timeline || _missing wp-forensics.sh ;;
      5) _have wp-mail.sh && run "Mail status" 0 wp-mail.sh status || _missing wp-mail.sh ;;
      6) _have wp-mail.sh && { if ask "Send test to" _a; then run "Mail test" 0 wp-mail.sh test "$_a"; fi; } || _missing wp-mail.sh ;;
      7) _have wasp-selftest.sh && run "Full self-test" 0 wasp-selftest.sh all || _missing wasp-selftest.sh ;;
      b|B) return ;;
    esac
  done
}

# =============================================================================
#  MAIN MENU
# =============================================================================
main() {
  while :; do
    _banner
    cat <<EOF

  ${B}What do you need?${R}
    1) Health & status
    2) Backup & restore
    3) Security & hardening
    4) Updates
    5) Import a site
    6) Diagnostics & forensics
    7) Testing & validation

    ${DIM}Every action shows the command before it runs. Destructive ones${R}
    ${DIM}are marked ${R}${RED}[!]${R}${DIM} and ask you to type 'yes'.${R}

    q) quit
EOF
    printf '\n  select: '; read -r c
    case "$c" in
      1) menu_health ;;
      2) menu_backup ;;
      3) menu_security ;;
      4) menu_updates ;;
      5) menu_import ;;
      6) menu_diagnostics ;;
      7) menu_testing ;;
      q|Q) clear 2>/dev/null || true; exit 0 ;;
    esac
  done
}

# If not on a TTY, a menu is meaningless — point the caller at the tools.
if [ "$IS_TTY" -ne 1 ]; then
  echo "wasp-menu is interactive; run it in a terminal."
  echo "The tools it launches are all in ${BIN} and can be run directly."
  exit 1
fi

main
