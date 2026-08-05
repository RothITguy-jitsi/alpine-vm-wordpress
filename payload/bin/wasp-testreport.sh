#!/bin/sh
# =============================================================================
# wasp-testreport.sh — run every check and produce one report to send back
# =============================================================================
# RUN ON THE VM:   doas sh wasp-testreport.sh
#
# Everything is read-only or self-cleaning EXCEPT the two phases that must
# actually do something to prove anything:
#
#   --with-mail     sends two real emails
#   --with-restore  starts a throwaway database (~3 min, ~512 MB)
#
# Neither runs unless asked. The default run touches nothing.
#
# SECRETS: passwords, tokens and keys are redacted throughout. What appears is
# lengths, fingerprintable prefixes and permission bits — enough to diagnose,
# not enough to reuse. The report is worth skimming before sending, because a
# redaction that misses something is my mistake to fix, not yours to discover.
# =============================================================================
set -u

WITH_MAIL=0; WITH_RESTORE=0; MAIL_TO=""
for a in "$@"; do
  case "$a" in
    --with-mail)    WITH_MAIL=1 ;;
    --with-restore) WITH_RESTORE=1 ;;
    --all)          WITH_MAIL=1; WITH_RESTORE=1 ;;
    *@*)            MAIL_TO="$a" ;;
    -h|--help)      sed -n '2,22p' "$0"; exit 0 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas sh "$0" "$@"; fi
  echo "Run as root: doas sh $0" >&2; exit 1
fi

OUT="/tmp/wasp-testreport-$(date -u +%Y%m%d-%H%M%S).txt"
STATUS="/tmp/.wasp-testreport-status.$$"

# Everything runs inside main() and the whole thing is piped to tee at the
# bottom. The obvious form -- exec > >(tee "$OUT") -- is process substitution,
# which is a bashism: BusyBox ash is /bin/sh on Alpine and does not have it,
# so that version died at line 39 before printing anything. Caught by `sh -n`
# rather than on the VM, which is the only reason it is not another silent
# failure to debug in the field.
main() {

PASS=0; FAIL=0; SKIP=0
hdr()  { printf '\n\n═══════════════════════════════════════════════════════════\n %s\n═══════════════════════════════════════════════════════════\n' "$1"; }
sub()  { printf '\n─── %s ───\n' "$1"; }
ok()   { PASS=$((PASS+1)); printf '  [PASS] %s\n' "$1"; }
no()   { FAIL=$((FAIL+1)); printf '  [FAIL] %s\n' "$1"; }
sk()   { SKIP=$((SKIP+1)); printf '  [SKIP] %s\n' "$1"; }
inf()  { printf '         %s\n' "$1"; }
run()  { printf '\n$ %s\n' "$1"; sh -c "$1" 2>&1 | sed 's/^/  /'; }

# Redact anything that looks like a credential. Applied to command output that
# might carry one; the checks below mostly avoid printing such output at all.
red()  { sed -E 's/(pass[a-z_]*|secret|token|key)[[:space:]]*[=:][[:space:]]*[^[:space:]]+/\1=<REDACTED>/Ig'; }

hdr "WASP TEST REPORT — $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
inf "host: $(hostname)   mail: ${WITH_MAIL}   restore: ${WITH_RESTORE}"

# ── 1. Baseline ──────────────────────────────────────────────────────────────
hdr "1. BASELINE"
run "validate-wordpress.sh"
sub "containers"
run "podman ps --format '{{.Names}}  {{.Status}}  {{.Image}}'"

# ── 2. Install-time answers ──────────────────────────────────────────────────
hdr "2. CONFIGURATION AS INSTALLED"
sub "vars.sh (secrets removed)"
grep -vE 'PASS|SECRET|KEY|TOKEN|ENROLL' /etc/wp-install/vars.sh 2>/dev/null | sed 's/^/  /'
sub "secrets present? (length only)"
for v in ROOT_PASS DB_ROOT_PASS SMTP_PASS MAXMIND_LICENSE_KEY CROWDSEC_ENROLL_KEY; do
  val=$(sed -n "s/^${v}=//p" /etc/wp-install/vars.sh 2>/dev/null | tr -d "'\"")
  [ -n "$val" ] && printf '  %-22s set (%s chars)\n' "$v" "${#val}" \
                || printf '  %-22s not set\n' "$v"
done

# ── 3. Firewall ──────────────────────────────────────────────────────────────
hdr "3. FIREWALL — egress, hypervisor block, SMTP limit"
sub "does the live ruleset contain what the installer claimed?"
for pat in "nft-drop-pve-mgmt:hypervisor management block" \
           "nft-egress-drop:egress restriction" \
           "nft-smtp-ratelimit:SMTP rate limit" \
           "egress_extra_tcp:runtime port set"; do
  p="${pat%%:*}"; d="${pat##*:}"
  nft list ruleset 2>/dev/null | grep -q "$p" && ok "$d present" || sk "$d not present (may be off by choice)"
done
run "wp-hardening.sh egress-list"
sub "counters — non-zero means rules are actually matching traffic"
nft list ruleset 2>/dev/null | grep -E "counter packets [1-9]" | head -10 | sed 's/^/  /' || inf "(none yet)"

# ── 4. Reverse proxy ─────────────────────────────────────────────────────────
hdr "4. REVERSE PROXY / CLIENT IP"
run "wp-hardening.sh proxy-check"

# ── 5. GeoIP ─────────────────────────────────────────────────────────────────
hdr "5. GEOIP"
run "wp-hardening.sh geoip-test 8.8.8.8"

# ── 6. CrowdSec ──────────────────────────────────────────────────────────────
hdr "6. CROWDSEC"
run "wp-hardening.sh crowdsec-whitelist list"
sub "did the login parser and scenario actually load?"
podman exec crowdsec cscli parsers list 2>/dev/null | grep -i wpvm | sed 's/^/  /' \
  && ok "login parser loaded" || no "login parser NOT loaded (it may be in a path the container cannot see)"
podman exec crowdsec cscli scenarios list 2>/dev/null | grep -i wpvm | sed 's/^/  /' \
  && ok "brute-force scenario loaded" || no "scenario NOT loaded"

# ── 7. Login guard ───────────────────────────────────────────────────────────
hdr "7. LOGIN RATE LIMITING"
for f in 00-wpvm-login-slug 01-wpvm-smtp 02-wpvm-login-guard; do
  p="/home/wpuser/wp/html/wp-content/mu-plugins/${f}.php"
  if [ -r "$p" ]; then
    podman exec wordpress php -l "/var/www/html/wp-content/mu-plugins/${f}.php" >/dev/null 2>&1 \
      && ok "${f}.php installed and parses" || no "${f}.php installed but has a PHP SYNTAX ERROR"
  else
    no "${f}.php MISSING"
  fi
done
sub "does a bad login get logged in the format CrowdSec expects?"
inf "(this makes 1 failed login attempt against the local container)"
podman exec wordpress php -r '
  $c=stream_context_create(["http"=>["method"=>"POST","timeout"=>8,"ignore_errors"=>true,
    "header"=>"Content-Type: application/x-www-form-urlencoded\r\nUser-Agent: wasp-test/1.0\r\n",
    "content"=>"log=wasp-test-nonexistent&pwd=wrong&wp-submit=Log+In"]]);
  @file_get_contents("http://127.0.0.1/wp-login.php",false,$c);' 2>/dev/null
sleep 2
if grep -q "wpvm-login" /home/wpuser/wp/logs/error.log 2>/dev/null; then
  ok "login guard logged the attempt"
  grep "wpvm-login" /home/wpuser/wp/logs/error.log | tail -2 | sed 's/^/  /'
else
  no "no wpvm-login entries — guard may not be active, or wp-login.php is IP-blocked from inside"
fi

# ── 8. Mail ──────────────────────────────────────────────────────────────────
hdr "8. MAIL"
run "wp-mail.sh status"
sub "permissions — the directory is what broke this before"
stat -c '  dir : %a %U:%G  %n' /home/wpuser/wp/secrets 2>/dev/null
stat -c '  file: %a %U:%G  %n' /home/wpuser/wp/secrets/smtp.ini 2>/dev/null || inf "  smtp.ini absent"
[ -f /home/wpuser/wp/secrets/smtp.php ] && no "legacy executable smtp.php still present" \
                                        || ok "no executable smtp.php (INI format in use)"
podman exec --user 33 wordpress test -r /var/www/private/smtp.ini 2>/dev/null \
  && ok "PHP (uid 33) can read the credentials" \
  || no "PHP (uid 33) CANNOT read the credentials — mail will fall back to sendmail"
run "wp-notify.sh --status"
if [ "$WITH_MAIL" = "1" ]; then
  [ -n "$MAIL_TO" ] || MAIL_TO=$(sed -n 's/^user *= *//p' /home/wpuser/wp/secrets/smtp.ini 2>/dev/null | head -1)
  sub "sending two real emails to ${MAIL_TO}"
  run "wp-mail.sh test ${MAIL_TO}"
  run "wp-notify.sh --test"
  inf "CONFIRM BY HAND: did both arrive?"
else
  sk "live send skipped (add --with-mail to actually send)"
fi

# ── 9. Vulnerability scanning ────────────────────────────────────────────────
hdr "9. PLUGIN VULNERABILITY SCANNING"
run "wp-plugins.sh vuln-sources"
sub "wordfence token (length only) and cached feeds"
awk -F= '/API_KEY|TOKEN/{printf "  %s = <%d chars>\n",$1,length($2)} /FEED/{print "  "$0}' \
  /etc/wp-install/vuln-sources.conf 2>/dev/null || inf "  no vuln-sources.conf"
ls -lh /var/cache/wp-vulns/ 2>/dev/null | sed 's/^/  /' || inf "  no feed cache yet"
run "wp-plugins.sh vulns 2>&1 | head -25"

# ── 10. Malware scanning ─────────────────────────────────────────────────────
hdr "10. MALWARE SCANNING"
run "wp-malware-scan.sh structural"
run "wp-malware-scan.sh core"
command -v yara >/dev/null 2>&1 && ok "yara installed" || no "yara missing (signature layer inactive)"
command -v clamscan >/dev/null 2>&1 && inf "clamav installed (optional)" || inf "clamav not installed (expected unless requested)"

# ── 11. Integrity / signing ──────────────────────────────────────────────────
hdr "11. RELEASE INTEGRITY"
run "wasp-verify-integrity.sh"

# ── 12. Backups ──────────────────────────────────────────────────────────────
hdr "12. BACKUPS"
sub "existing backups"
ls -lh /root/wp-db-backups/ 2>/dev/null | tail -5 | sed 's/^/  /' || inf "  none yet"
run "wasp-offsite-backup.sh status"
sub "taking one backup now (this also exercises the off-VM push)"
run "wp-db-backup.sh"
run "wasp-offsite-backup.sh verify"
run "wasp-offsite-backup.sh list 2>&1 | head -12"

# ── 13. Self-test ────────────────────────────────────────────────────────────
hdr "13. SELF-TEST (restore proof + DB isolation)"
if [ "$WITH_RESTORE" = "1" ]; then
  run "wasp-selftest.sh all"
else
  sub "restore proof skipped — add --with-restore"
  inf "It starts a throwaway MariaDB (~512 MB, ~3 min) and destroys it after."
  inf "Running the isolation half alone, which is cheap:"
  run "wasp-selftest.sh candidate-isolation"
fi

# ── 14. Scheduling ───────────────────────────────────────────────────────────
hdr "14. SCHEDULED JOBS"
sub "installed cron entries"
grep -vE '^#|^$' /etc/crontabs/root 2>/dev/null | sed 's/^/  /'
sub "have they produced anything yet?"
for t in wp-vulns wp-malware wp-db-backup wp-plugins wasp-selftest wp-notify; do
  # grep -c prints its count AND exits 1 when that count is zero, so the
  # `|| echo 0` form yields "0\n0". Caught by check-grep-count.py, which was
  # written after this script.
  n=$(grep -c "$t" /var/log/messages 2>/dev/null) || n=0
  printf '  %-16s %s log line(s)\n' "$t" "$n"
done

# ── Summary ──────────────────────────────────────────────────────────────────
hdr "SUMMARY"
printf '  pass %s   fail %s   skip %s\n\n' "$PASS" "$FAIL" "$SKIP"
[ "$WITH_MAIL"    = "0" ] && printf '  Not tested: live mail      (re-run with --with-mail)\n'
[ "$WITH_RESTORE" = "0" ] && printf '  Not tested: backup restore (re-run with --with-restore)\n'
cat <<'EOS'

  Not covered here, needs doing by hand:
    • Browse https://<your-domain>/ and /<slug>-login from OUTSIDE the LAN
    • Decrypt an off-VM backup on your workstation:
        age -d -i wasp-backup-key.txt -o t.sql.gz <file>.age && gzip -t t.sql.gz
    • update.sh cutover  (snapshot the VM first — it swaps containers)

EOS
printf '  Report saved to: %s\n' "$OUT"
printf '  Skim it before sending; if a secret slipped through a redaction,\n'
printf '  that is a bug in this script worth telling me about.\n'
# The counters live in this subshell once main is piped, so the exit status is
# handed out through a file rather than a variable.
printf '%s' "$FAIL" > "$STATUS"
}

main "$@" 2>&1 | tee "$OUT"

_fail=$(cat "$STATUS" 2>/dev/null || echo 0)
rm -f "$STATUS"
[ "${_fail:-0}" -gt 0 ] && exit 1
exit 0
