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
#   --perimeter <url>  ALSO run the external validation harness against <url>,
#                      testing the controls as an outside client sees them.
#                      Best run from a DIFFERENT machine too (see note in the
#                      section), since from the VM you are on the LAN.
#
# Neither runs unless asked. The default run touches nothing.
#
# SECRETS: passwords, tokens and keys are redacted throughout. What appears is
# lengths, fingerprintable prefixes and permission bits — enough to diagnose,
# not enough to reuse. The report is worth skimming before sending, because a
# redaction that misses something is my mistake to fix, not yours to discover.
# =============================================================================
# Auto-elevate. Every other operator tool in this suite does this, and the
# inconsistency was found the hard way: running this as the admin user printed
# "install: can't create directory '/root/wp-db-backups': Permission denied",
# which reads like a broken path rather than "you need doas".
if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "This must run as root (or via doas)." >&2; exit 1
fi
set -u

WITH_MAIL=0; WITH_RESTORE=0; MAIL_TO=""; PERIMETER=""
_prev=""
for a in "$@"; do
  case "$_prev" in --perimeter) PERIMETER="$a"; _prev=""; continue ;; esac
  case "$a" in
    --with-mail)    WITH_MAIL=1 ;;
    --with-restore) WITH_RESTORE=1 ;;
    --all)          WITH_MAIL=1; WITH_RESTORE=1 ;;
    --perimeter)    _prev="--perimeter" ;;
    http://*|https://*) PERIMETER="$a" ;;
    *@*)            MAIL_TO="$a" ;;
    -h|--help)      sed -n '2,24p' "$0"; exit 0 ;;
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

hdr "WASP TEST REPORT — $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
. /etc/wp-install/vars.sh 2>/dev/null || true
inf "host: $(hostname)   build: ${WASP_VERSION:-unknown}"
[ -n "${WASP_VERSION_NOTE:-}" ] && inf "${WASP_VERSION_NOTE}"
inf "mail: ${WITH_MAIL}   restore: ${WITH_RESTORE}"
# Stated up front so anyone reading this report knows which build produced it
# before interpreting anything below.
inf "login URL: $([ -n "${WP_ADMIN_SLUG:-}" ] && printf '/%s' "$WP_ADMIN_SLUG" || printf '/wp-login.php')"

# ── 1. Baseline ──────────────────────────────────────────────────────────────
# Unverified-install banner: the most important provenance fact, placed right
# after the report title rather than buried in a section.
if [ -s /etc/wp-install/PRODUCTION-BLOCKERS ]; then
  no "THIS VM WAS NOT CERTIFIED PRODUCTION-READY AT INSTALL"
  while IFS= read -r _b; do inf "  ${_b}"; done < /etc/wp-install/PRODUCTION-BLOCKERS
  inf "  Resolve, then remove /etc/wp-install/PRODUCTION-BLOCKERS."
fi
if [ -f /etc/wp-install/UNVERIFIED ]; then
  . /etc/wp-install/UNVERIFIED 2>/dev/null || true
  no "THIS BUILD WAS INSTALLED UNVERIFIED (${UNVERIFIED_REASON:-reason unrecorded})"
  inf "  at ${UNVERIFIED_AT:-unknown time}. Signature verification did not pass."
  inf "  A production/MSP deployment must be reinstalled from a signed build."
fi

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
sub "is the login guard actually loaded and functioning?"
# Was: POST to http://127.0.0.1/wp-login.php from inside the container, then
# look for the log line. That cannot work — wp-login.php is IP-restricted, the
# request originates from the container's own address, and Apache returns 403
# before PHP runs. The guard never executes, and the test reported FAIL for a
# guard that was fine.
#
# A test that has to defeat a protection in order to check something else is
# testing the wrong thing. Ask WordPress directly instead.
_lg=$(podman exec --user 33 wordpress php -r '
  define("WP_USE_THEMES", false);
  require "/var/www/html/wp-load.php";
  $f = ["wpvm_login_client_ip","wpvm_login_attempts","wpvm_login_key"];
  $missing = [];
  foreach ($f as $fn) { if (!function_exists($fn)) $missing[] = $fn; }
  echo $missing ? "MISSING: ".implode(",", $missing) : "LOADED";
  echo has_action("wp_login_failed") ? " hook=yes" : " hook=NO";
' 2>/dev/null)
case "$_lg" in
  LOADED*hook=yes) ok "Login guard is loaded and hooked (${_lg})" ;;
  LOADED*)         no "Login guard loaded but its wp_login_failed hook is not registered" ;;
  MISSING*)        no "Login guard functions absent: ${_lg}" ;;
  *)               sk "Could not query WordPress for the login guard (${_lg:-no output})" ;;
esac

sub "have any real login events been recorded yet?"
_n=$(grep -c "wpvm-login" /home/wpuser/wp/logs/error.log 2>/dev/null) || _n=0
if [ "${_n:-0}" -gt 0 ]; then
  ok "${_n} login event(s) logged — CrowdSec has data to work with"
  grep "wpvm-login" /home/wpuser/wp/logs/error.log | tail -3 | sed 's/^/         /'
else
  inf "No login events yet. Expected until someone actually reaches the login"
  inf "form; the guard only logs on a real authentication attempt."
  inf "To prove the CrowdSec parser matches without one, feed it a sample:"
  inf "  printf '[Wed Aug 05 12:00:00.000000 2026] [php:notice] [pid 1] [wpvm-login] event=failed ip=203.0.113.9 user=admin\\n' > /home/wpuser/wp/logs/parsertest.log"
  inf "  podman exec crowdsec cscli explain --file /var/log/wordpress/parsertest.log --type wpvm-login"
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
hdr "ACTIVE VULNERABILITY EXCEPTIONS"
# The evaluator's #5: exceptions are already digest-scoped with expiry (see
# trivy_exception in update.sh). This surfaces every ACTIVE one so weekly
# review sees what has been accepted, against which digest, and when it lapses
# -- an accepted CVE that nobody is looking at is how an exception quietly
# becomes permanent policy.
_vex=/var/log/wasp-vuln-exceptions.log
if [ -f "$_vex" ]; then
  _now=$(date -u +%s); _active=0
  # Records carry an expiry; show any whose expiry is in the future.
  while IFS= read -r _line; do
    case "$_line" in
      *ACCEPTED*|*expires*|*until*)
        _exp=$(printf '%s' "$_line" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' | tail -1)
        [ -n "$_exp" ] || continue
        _es=$(date -u -d "$_exp" +%s 2>/dev/null || echo 0)
        if [ "$_es" -gt "$_now" ]; then
          _active=$((_active+1)); no "ACTIVE exception (expires ${_exp}): ${_line}"
        fi ;;
    esac
  done < "$_vex"
  [ "$_active" = 0 ] && inf "No active vulnerability exceptions"
  [ "$_active" -gt 0 ] && no "${_active} active exception(s) — confirm each is still justified"
else
  inf "No vulnerability exceptions have ever been recorded"
fi

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

# ── 15. Perimeter (external validation) ──────────────────────────────────────
if [ -n "$PERIMETER" ]; then
  section "15. PERIMETER — controls as an outside client sees them"
  _ph=$(command -v wasp-pentest.sh 2>/dev/null || echo /usr/local/bin/wasp-pentest.sh)
  if [ ! -x "$_ph" ]; then
    ok "The external harness is NOT on this VM — which is correct."
    inf "It lives in tools/wasp-pentest.sh, deliberately outside the payload, so"
    inf "a compromised VM does not hand an attacker a ready-made scanner. And"
    inf "the test that matters is from an address NOT on your admin allow list,"
    inf "which this VM is not. Run it from your Kali box instead:"
    inf "  scp tools/wasp-pentest.sh kali:~/ && ssh kali"
    inf "  ./wasp-pentest.sh ${PERIMETER}"
    inf "  ./wasp-pentest.sh --ip <this-vm-ip> ${PERIMETER}   # also tests WEB_CIDR"
  else
    # Running from the VM answers "are the controls working" but NOT "are they
    # working against an unauthorised source" -- this host is on the LAN and
    # very likely allow-listed, so admin endpoints will answer here and be
    # refused elsewhere. Say so plainly rather than let a green result mislead.
    inf "Running the external harness from THIS VM against ${PERIMETER}."
    inf "Caveat: this host is on the LAN and probably allow-listed, so admin"
    inf "endpoints may answer here that an outside attacker cannot reach. For"
    inf "the real access-control test, run wasp-pentest.sh from off-LAN too."
    echo ""
    # Non-interactive: the harness normally asks for "I OWN THIS"; feed it,
    # because running your own testreport against your own VM IS the
    # authorisation, and a report should not block on a prompt.
    printf 'I OWN THIS\n' | "$_ph" "$PERIMETER" 2>&1 | sed 's/^/  /' || true
  fi
  echo ""
fi

  Not covered here, needs doing by hand:
    • Browse https://<your-domain>/ and /<slug> from OUTSIDE the LAN (the slug IS the login URL now)
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
