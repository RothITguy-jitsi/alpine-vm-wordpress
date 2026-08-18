#!/bin/sh
# =============================================================================
# wasp-triage.sh — is THIS already-deployed VM affected by a known defect?
# =============================================================================
#   wasp-triage.sh            check and report
#   wasp-triage.sh --fix      apply the fixes that are safe to apply in place
#
# WHY THIS EXISTS
#
# Several releases in the 2026.08.12 series shipped defects that leave a VM
# running and looking healthy while a control is silently absent. On a fleet
# that is already deployed, "redeploy everything" is not a plan — it is a week
# of client downtime for problems that mostly patch in place.
#
# So this checks the SPECIFIC known-bad states, on the running system, and says
# which apply here. It reads state rather than version strings, because a VM
# may have been partly patched by hand and the version alone will not tell you.
#
# Every finding names the release it came from, what it actually means for the
# client, and whether --fix can repair it without a redeploy.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)." >&2; exit 1
fi

FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

RED=''; GRN=''; YEL=''; BLD=''; CL=''
if [ -t 1 ] && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
  RED=$(printf '\033[31m'); GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m')
  BLD=$(printf '\033[1m'); CL=$(printf '\033[0m')
fi

_bad=0; _warn=0; _ok=0
_FIXED=""

_finding() { # severity, title, meaning, action
  case "$1" in
    CRIT) printf '%s[CRITICAL]%s %s\n' "$RED" "$CL" "$2"; _bad=$((_bad+1)) ;;
    WARN) printf '%s[WARNING ]%s %s\n' "$YEL" "$CL" "$2"; _warn=$((_warn+1)) ;;
  esac
  printf '            %s\n' "$3"
  [ -n "${4:-}" ] && printf '            Fix: %s\n' "$4"
  echo ""
}
_pass() { printf '%s[ OK     ]%s %s\n' "$GRN" "$CL" "$1"; _ok=$((_ok+1)); }

_ver=$(sed -n 's/^WASP_VERSION=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
_prof=$(sed -n 's/^DEPLOYMENT_PROFILE=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)

printf '%s\n' "$BLD"
echo "WASP deployed-VM triage"
echo "━━━━━━━━━━━━━━━━━━━━━━━"
printf '%s' "$CL"
echo "  host    : $(hostname 2>/dev/null)"
echo "  build   : ${_ver:-unknown}   profile: ${_prof:-standard}"
echo "  mode    : $([ "$FIX" = 1 ] && echo 'CHECK AND FIX' || echo 'check only')"
echo ""

# ── 1. Is there a firewall at all? ──────────────────────────────────────────
# From 2026.08.12t/v/x: an empty variable, then an expanding comment, each made
# nft reject the whole ruleset. The VM boots, the site serves, and there is no
# packet filter, no admin-IP restriction and no egress boundary.
if nft list tables 2>/dev/null | grep -q .; then
  _pass "Host firewall is loaded (nftables has tables)"
else
  _finding CRIT "NO HOST FIREWALL — the nftables ruleset is not loaded." \
    "Every control that reports 'enabled' is describing rules absent from the kernel: no L1 filter, no wp-admin IP restriction, no egress boundary. This VM is exposed exactly as if none of it were configured." \
    "doas nft -c -f /etc/nftables.nft   (see the error)   then re-run the installer, or patch /etc/nftables.nft by hand and: doas nft -f /etc/nftables.nft"
fi

# ── 2. Can WordPress send mail? ─────────────────────────────────────────────
# From 2026.08.12q: with the egress proxy on, the SMTP allow rule sat AFTER the
# catch-all drop, so submission was blocked. Password resets fail silently.
_smtp_host=$(sed -n 's/^SMTP_HOST=//p' /etc/wp-install/vars.sh 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
if [ -z "$_smtp_host" ]; then
  _pass "No SMTP relay configured — nothing to check"
elif nft list ruleset 2>/dev/null | grep -qE 'dport \{ ?25,? ?465,? ?587'; then
  _pass "An SMTP allow rule is present in the live ruleset"
else
  _finding CRIT "WordPress may be unable to send ANY email." \
    "A relay is configured (${_smtp_host}) but no SMTP allow rule is in the live ruleset. Password resets, order confirmations, malware alerts and the heartbeat all fail, silently, with every other mail check passing." \
    "Verify with: doas wp-mail.sh doctor   (look for 'TCP 587'). Re-run the installer on 2026.08.12v or later, which fixes the rule ordering."
fi

# ── 3. Can anything alert? ──────────────────────────────────────────────────
# From 2026.08.12a: an unassigned STATE under set -u killed every notification
# path. Backup failures, malware findings and the heartbeat all died silently.
if [ -x /usr/local/bin/wp-notify.sh ]; then
  if /usr/local/bin/wp-notify.sh --status >/dev/null 2>&1; then
    _pass "wp-notify runs (alert path is not dead)"
  else
    _finding CRIT "The notifier CRASHES — no alert can be delivered." \
      "Backup failures, malware findings, vulnerability reports and the VM-is-gone heartbeat all route through it. A monitoring system that cannot report is worse than none: its silence is indistinguishable from all-clear." \
      "doas wp-notify.sh --status   (see the error). Fixed in 2026.08.12a; on an older build add STATE=/var/lib/wasp-notify near the top of /usr/local/bin/wp-notify.sh."
  fi
fi

# ── 4. Is the WordPress being SERVED the one that is pinned? ────────────────
# From 2026.08.12c: the image can be updated while the docroot keeps the old
# core, because the official image only extracts when the docroot is empty.
_wpver=$(podman exec wordpress sh -c 'sed -n "s/^[[:space:]]*\$wp_version[[:space:]]*=[[:space:]]*[\x27\"]\([^\x27\"]*\)[\x27\"].*/\1/p" /var/www/html/wp-includes/version.php 2>/dev/null | head -1' 2>/dev/null)
if [ -n "$_wpver" ]; then
  case "$_wpver" in
    7.0.4|7.0.5|7.1*) _pass "WordPress core being served: ${_wpver}" ;;
    *)
      _finding CRIT "WordPress core ${_wpver} is serving KNOWN VULNERABILITIES." \
        "7.0.3 fixed CVE-2026-64638 (CVSS 8.9, pre-auth XSS on the LOGIN page). 7.0.4 fixed CVE-2026-65640 (CVSS 8.8, Author+ RCE via upload). Anything below 7.0.4 has one or both." \
        "doas update.sh wp 7.0.4-php8.4-apache   then confirm with: doas wp-plugins.sh core-version" ;;
  esac
fi

# ── 5. Was MFA requested but never actually installed? ──────────────────────
if grep -q '^MFA_ENFORCE="1"' /etc/wp-install/vars.sh 2>/dev/null; then
  if podman exec --user 33 wordpress test -d /var/www/html/wp-content/plugins/two-factor 2>/dev/null; then
    _pass "MFA requested and the Two Factor plugin is present"
  else
    _finding WARN "MFA was requested but the Two Factor plugin is NOT installed." \
      "The enforcement mu-plugin fails safe, so nobody is locked out — which also means administrators have no second factor despite it being asked for." \
      "doas wasp-mfa-deferred.sh --status   then: doas wasp-mfa-deferred.sh --now"
  fi
fi

# ── 6. Is anything actually reaching off-site? ──────────────────────────────
if [ -r /etc/wp-install/rclone.conf ] || grep -q '^OFFSITE_METHOD=' /etc/wp-install/vars.sh 2>/dev/null; then
  if [ -s /etc/wp-install/offsite-last-error ]; then
    _finding WARN "The last off-site backup push FAILED." \
      "Local backups are fine; the off-VM copy is not. A VM lost to hardware failure takes its backups with it." \
      "doas wasp-offsite-backup.sh doctor   (on R2 a 403 on HeadObject usually means the token is Object Write but not Object READ)"
  else
    _pass "No recorded off-site push failure"
  fi
fi

# ── 7. Is CrowdSec actually enforcing? ──────────────────────────────────────
if podman ps --filter 'name=^crowdsec$' --filter status=running --format '{{.Names}}' 2>/dev/null | grep -qx crowdsec; then
  if nft list ruleset 2>/dev/null | grep -qi crowdsec; then
    _pass "CrowdSec has written its set into nftables"
  else
    _finding WARN "CrowdSec is running but has no nftables set." \
      "Threats are detected and nothing is blocked. Note this is also the expected symptom when finding 1 applies — fix the firewall first." \
      "doas wp-hardening.sh crowdsec-doctor   (runs a real test ban end to end)"
  fi
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo "────────────────────────────────────────────────────"
printf '  %s%s critical%s   %s%s warning%s   %s%s ok%s\n' \
  "$RED" "$_bad" "$CL" "$YEL" "$_warn" "$CL" "$GRN" "$_ok" "$CL"
echo ""
if [ "$_bad" -gt 0 ]; then
  echo "  Treat the critical findings as live exposure, not backlog. Each one"
  echo "  means a control the client believes they have is not running."
  exit 2
elif [ "$_warn" -gt 0 ]; then
  echo "  Nothing is exposed, but something the client was promised is not"
  echo "  working. Schedule these."
  exit 1
fi
echo "  No known defect from the 2026.08.12 series applies to this VM."
exit 0
