#!/bin/sh
# ============================================================================
# validate-wordpress.sh — live validation and self-service diagnostics
# ============================================================================
# Rewritten in v7-14. The previous version reported WHAT failed but never HOW
# to fix it, and most of its checks only confirmed a container was in state
# "running" — which says nothing about whether the site actually works. An
# operator hitting a problem after install had no path from "✗ something"
# to a resolution without reading the 6000-line provisioning script.
#
# This version:
#   • runs LIVE functional tests (real HTTP fetches, a real DB query through
#     WordPress's own credentials, a real gzip integrity check on the newest
#     backup, a real Skopeo digest resolution) rather than status lookups
#   • attaches a concrete remediation command to every single failure and
#     reprints them all in one block at the end, so fixing is copy-paste
#   • separates FAIL (something is broken) from WARN (works, but will bite
#     you later — disk filling, backup aging, verification degraded)
#   • can be scoped to one area while debugging, instead of all-or-nothing
#
# Usage:
#   validate-wordpress.sh                  run everything
#   validate-wordpress.sh --section web    run one section
#   validate-wordpress.sh --list           show section names
#   validate-wordpress.sh --quiet          only output failures/warnings
#   validate-wordpress.sh --quick          skip slow checks (network, backups)
#   validate-wordpress.sh --send-test-mail <addr>   also deliver a real test email
#
# Exit: 0 = all passed, 1 = one or more failures, 2 = warnings only
# ============================================================================

# v7-16: auto-elevate via doas. This tool reads /etc/wp-install/vars.sh (root-
# only, 0600) and pinned.env, and inspects containers and the firewall — all
# need root. Run as the unprivileged admin over SSH (the session where
# copy/paste actually works; the root console via `qm terminal` can't paste)
# it used to fail immediately with "can't open /etc/wp-install/vars.sh:
# Permission denied", and every check that reads a vars.sh value then saw an
# empty string and reported a FALSE result — "Digest pinning: 0/3 pinned"
# while `update.sh` correctly showed 3/3, and "No wp-admin IP restriction
# configured" when ADMIN_CIDR was in fact set. Re-exec through doas so the
# tool "just works" over SSH: doas prompts for the admin password once (permit
# persist :wheel), then everything runs as root with output in the copyable
# SSH session. --help/--list need no privileges, so they skip elevation.
_vwp_needs_root=1
case " $* " in
  *" --help "*|*" -h "*|*" --list "*|*" -l "*) _vwp_needs_root=0 ;;
esac
if [ "$_vwp_needs_root" = "1" ] && [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then
    exec doas "$0" "$@"
  fi
  echo "This tool needs root to read vars.sh and inspect the system." >&2
  echo "Run it as root, or as a wheel user with doas installed." >&2
  exit 1
fi

QUIET=0
QUICK=0
SEND_TEST_MAIL=""
ONLY=""

# --check / --check --prom are intercepted BEFORE the option loop below.
#
# BUG FIXED (found by the commission check on a live VM): the loop rejected
# --check with "Unknown option" and exited 2, so the machine-readable health
# path was unreachable -- and even without the rejection, the loop shifts every
# argument away, leaving $1 empty by the time the handler tested it. Both the
# monitoring integration and the menu's first health entry were broken by this,
# and nothing noticed because no test invoked the flag.
CHECK_MODE=0; CHECK_PROM=0
case "${1:-}" in
  --check)
    CHECK_MODE=1
    [ "${2:-}" = "--prom" ] && CHECK_PROM=1
    set -- ;;
esac

while [ $# -gt 0 ]; do
  case "$1" in
    --quiet|-q)   QUIET=1 ;;
    --quick)      QUICK=1 ;;
    --send-test-mail) SEND_TEST_MAIL="${2:-}"; shift ;;
    --section|-s) shift; ONLY="$1" ;;
    --list|-l)
      echo "Sections: containers database web security updates logs backups mail"
      exit 0 ;;
    --help|-h)
      sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Unknown option: $1  (try --help)" >&2; exit 2 ;;
  esac
  shift
done

[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
# v7-16: also source pinned.env — the image digests (WP_DIGEST/DB_DIGEST/
# CS_DIGEST) live HERE, not in vars.sh. Without this the digest-pinning check
# below saw three empty strings and reported "0/3 pinned" as a FALSE failure,
# while update.sh (which sources pinned.env) correctly showed 3/3. Both files
# are 0600 root-only, so this depends on the auto-doas elevation at the top.
[ -r /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

# --- Machine-readable health for external monitoring (Nagios/Zabbix/cron) ---
# --check exits 0 (healthy), 1 (degraded), or 2 (critical) after one line, so a
# poller that only needs a number never parses the human report below. Kept
# deliberately cheap -- containers up, database answering, disk < 90%, newest
# backup < 26h -- because those are the conditions worth paging on; the rest of
# this script is diagnosis, not alerting, and mixing the two makes a check too
# chatty to alert on. See docs/FLEET.md (Layer 2) and SUPPORT-RUNBOOK.md.
if [ "$CHECK_MODE" = "1" ]; then
  _p=0; _msg=""; _age=9999
  for c in wordpress mariadb; do
    podman ps --format '{{.Names}}' 2>/dev/null | grep -qx "$c" || { _p=2; _msg="${_msg}${c}-down "; }
  done
  podman exec mariadb sh -c 'mariadb-admin ping --silent -uroot -p"$MARIADB_ROOT_PASSWORD"' >/dev/null 2>&1 \
    || { _p=2; _msg="${_msg}db-unreachable "; }
  _disk=$(df -P / | awk 'NR==2{gsub("%","",$5);print $5}')
  [ "${_disk:-0}" -ge 90 ] && { [ "$_p" -lt 2 ] && _p=2; _msg="${_msg}disk-${_disk}% "; }
  _newest=$(ls -t /root/wp-db-backups/*.sql.gz 2>/dev/null | head -1)
  if [ -n "$_newest" ]; then
    _age=$(( ( $(date +%s) - $(stat -c %Y "$_newest") ) / 3600 ))
    [ "$_age" -ge 26 ] && { [ "$_p" -lt 1 ] && _p=1; _msg="${_msg}backup-${_age}h-old "; }
  else
    [ "$_p" -lt 1 ] && _p=1; _msg="${_msg}no-backup "
  fi
  # An unverified install is a governance finding that should never be silent:
  # surface it in the machine-readable health so a fleet monitor flags it.
  [ -f /etc/wp-install/UNVERIFIED ] && { [ "$_p" -lt 1 ] && _p=1; _msg="${_msg}UNVERIFIED-build "; }
  # A production blocker means a fail-closed control did not pass at install.
  # CRITICAL, not warning: the VM completed its build but was explicitly not
  # certified, and that must not fade quietly into a green dashboard.
  [ -s /etc/wp-install/PRODUCTION-BLOCKERS ] && { _p=2; _msg="${_msg}PRODUCTION-BLOCKER "; }

  # --check --prom : same signal as Prometheus text for a textfile collector or
  # scrape endpoint (docs/FLEET.md Layer C). Stable metric names so a Grafana
  # panel built against them keeps working.
  if [ "$CHECK_PROM" = "1" ]; then
    printf '# HELP wasp_health Overall WASP health (0 ok 1 warn 2 critical)\n# TYPE wasp_health gauge\nwasp_health %s\n' "$_p"
    printf '# HELP wasp_disk_percent Root filesystem usage percent\n# TYPE wasp_disk_percent gauge\nwasp_disk_percent %s\n' "${_disk:-0}"
    printf '# HELP wasp_backup_age_hours Age of the newest local backup\n# TYPE wasp_backup_age_hours gauge\nwasp_backup_age_hours %s\n' "${_age:-9999}"
    for c in wordpress mariadb crowdsec; do
      _u=0; podman ps --format '{{.Names}}' 2>/dev/null | grep -qx "$c" && _u=1
      printf 'wasp_container_up{name="%s"} %s\n' "$c" "$_u"
    done
    exit "$_p"
  fi
  case "$_p" in
    0) echo "OK - containers up, db answering, disk ${_disk}%, backup fresh" ;;
    1) echo "WARNING - ${_msg}" ;;
    2) echo "CRITICAL - ${_msg}" ;;
  esac
  exit "$_p"
fi

PASS=0; FAIL=0; WARN=0
REMEDIES=""
CUR_SECTION=""

# ── output helpers ─────────────────────────────────────────────────────────
_c_ok=""; _c_bad=""; _c_warn=""; _c_dim=""; _c_off=""
if [ -t 1 ]; then
  _c_ok=$(printf '\033[32m'); _c_bad=$(printf '\033[31m')
  _c_warn=$(printf '\033[33m'); _c_dim=$(printf '\033[2m'); _c_off=$(printf '\033[0m')
fi

section() {
  CUR_SECTION="$1"
  [ "$QUIET" = "1" ] && return 0
  echo ""
  echo "── $2 ──────────────────────────────────────────"
}

# want_section: should this section run?
want_section() {
  [ -z "$ONLY" ] && return 0
  [ "$ONLY" = "$1" ] && return 0
  return 1
}

# Defined alongside the other reporters. It was previously declared far
# below its first use, so `note` was 'not found' at runtime while bash -n
# passed -- shell functions must exist before the line that calls them runs.
note() { printf "     %s\n" "$1"; }
pass() {
  PASS=$((PASS+1))
  [ "$QUIET" = "1" ] && return 0
  printf '  %s✔%s  %s\n' "$_c_ok" "$_c_off" "$1"
}

# fail <label> <detail> <remedy>
fail() {
  FAIL=$((FAIL+1))
  printf '  %s✗%s  %s\n' "$_c_bad" "$_c_off" "$1"
  [ -n "$2" ] && printf '     %s%s%s\n' "$_c_dim" "$2" "$_c_off"
  REMEDIES="${REMEDIES}
[FAIL] ${1}
       ${3}"
}

# warn <label> <detail> <remedy>
warn() {
  WARN=$((WARN+1))
  printf '  %s!%s  %s\n' "$_c_warn" "$_c_off" "$1"
  [ -n "$2" ] && printf '     %s%s%s\n' "$_c_dim" "$2" "$_c_off"
  REMEDIES="${REMEDIES}
[WARN] ${1}
       ${3}"
}

info() {
  [ "$QUIET" = "1" ] && return 0
  printf '     %s%s%s\n' "$_c_dim" "$1" "$_c_off"
}

# ── shared probes ──────────────────────────────────────────────────────────

# _http_code <url> — this server's own status, no redirect following.
# v8-1 fix (ChatGPT v8 finding 16): BusyBox wget on Alpine does NOT accept the
# GNU --max-redirect/--tries/--timeout options, so the old probe errored out
# and returned an empty code here — producing false "no response"/"blocked"
# results even while wp-health-check.sh passed. This now uses the identical
# PHP-from-container method as the health checker and the post-install
# validator: follow_location=0 pins the result to the server's OWN first
# response and ignore_errors=true lets 3xx/4xx come back as a status line
# instead of throwing. $1 is a full 127.0.0.1 URL; we probe its path against
# the container's own :80. The source address is the container loopback, which
# — like the old host-published probe — is not in ADMIN_CIDR, so the login
# paths still return 403 and the section's "cannot verify from this host"
# warning fires exactly as before.
_http_code() {
  _u_path="${1#http://127.0.0.1}"
  case "$_u_path" in ""|http*|"$1") _u_path="/" ;; esac
  podman exec --user www-data wordpress php -r '
    error_reporting(0);
    $ctx = stream_context_create(["http" => [
      "method"         => "GET",
      "timeout"        => 8,
      "follow_location"=> 0,
      "ignore_errors"  => true,
    "header"         => "User-Agent: wp-health-check/1.0\r\n",
    ]]);
    @file_get_contents("http://127.0.0.1:80'"${_u_path}"'", false, $ctx);
    $code = "none";
    if (isset($http_response_header[0]) &&
        preg_match("#HTTP/[0-9.]+ ([0-9]{3})#", $http_response_header[0], $m)) {
      $code = $m[1];
    }
    echo $code;
  ' 2>/dev/null
}

_running() {
  podman inspect "$1" --format '{{.State.Status}}' 2>/dev/null
}

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  WordPress VM — Validation & Diagnostics"
echo "  $(date '+%Y-%m-%d %H:%M:%S')   build=${WASP_VERSION:-unknown}   profile=${DEPLOYMENT_PROFILE:-standard}"
# The build line is not cosmetic. Behaviour that an operator interacts with
# has changed between builds -- most visibly the login slug moving from
# "/<slug>-login" to the bare "/<slug>" -- and a diagnostic that does not say
# which build produced it cannot be reasoned about. Several hours were spent
# on an imagined fault because of exactly that.
[ -n "${WASP_VERSION_NOTE:-}" ] && echo "  ${WASP_VERSION_NOTE}"
echo "═══════════════════════════════════════════════════════════"

# ── CONTAINERS ─────────────────────────────────────────────────────────────
if want_section containers; then
section containers "Containers"

for c in wordpress mariadb crowdsec; do
  st=$(_running "$c")
  case "$st" in
    running) pass "${c} is running" ;;
    "")      fail "${c} does not exist" \
                  "No container by that name — it was never created, or was removed." \
                  "podman ps -a | grep ${c}   # then recreate:  rc-service ${c}-container start" ;;
    *)       fail "${c} is '${st}', not running" \
                  "Container exists but is stopped or exited." \
                  "podman logs --tail 50 ${c}   # find the cause, then:  podman start ${c}" ;;
  esac
done

# Stale *-old containers mean a previous update was interrupted. Left in
# place they block the NEXT update outright (require_clean_container_state
# refuses to rename over them), so this is worth surfacing before someone
# hits it mid-update.
for c in wordpress-old mariadb-old crowdsec-old; do
  if podman container exists "$c" 2>/dev/null; then
    warn "Stale rollback container '${c}' present" \
         "Left by an update that did not finish. It will block the next update." \
         "podman inspect ${c}    # confirm it is not needed, then:  podman rm -f ${c}"
  fi
done

# A lock held by a dead PID wedges every future update until cleared.
if [ -d /run/lock/wordpress-update.lock ]; then
  lp=$(cat /run/lock/wordpress-update.lock/pid 2>/dev/null)
  if [ -n "$lp" ] && kill -0 "$lp" 2>/dev/null; then
    info "An update is currently running (PID ${lp}) — some checks may be transient"
  else
    warn "Stale update lock held by dead PID ${lp:-unknown}" \
         "update.sh will refuse to run until this is cleared." \
         "rm -rf /run/lock/wordpress-update.lock"
  fi
fi
fi

# ── DATABASE ───────────────────────────────────────────────────────────────
if want_section database; then
section database "Database"

if [ "$(_running mariadb)" = "running" ]; then
  if podman exec mariadb sh -c \
       'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 \
        || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' \
       >/dev/null 2>&1; then
    pass "MariaDB responds to ping"
  else
    fail "MariaDB is running but not answering ping" \
         "The daemon is up but not accepting admin connections — often mid-crash-recovery." \
         "podman logs --tail 80 mariadb    # look for InnoDB recovery or a corrupt tablespace"
  fi

  if [ -x /usr/local/bin/mariadb-health-check.sh ] \
     && /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1; then
    pass "MariaDB deep health (real query + InnoDB engine active)"
  else
    fail "MariaDB deep health check failed" \
         "Ping succeeded but a real query or the InnoDB engine check did not." \
         "/usr/local/bin/mariadb-health-check.sh mariadb    # run it directly to see which gate failed"
  fi
else
  fail "MariaDB not running — database checks skipped" \
       "" \
       "podman logs --tail 50 mariadb ; podman start mariadb"
fi

# The query that matters: WordPress's OWN credentials, from inside the
# WordPress container, over the wp-db network. This is what a page load does.
if [ "$(_running wordpress)" = "running" ]; then
  # First: can WordPress even RESOLVE the mariadb hostname? This is the exact
  # failure seen in the field (v7-15) — MariaDB fully healthy, but WordPress
  # couldn't find it because the nftables input chain was dropping the
  # container's DNS query to the gateway. Checking resolution separately from
  # connection turns "database connection failed" (ambiguous) into "DNS is
  # broken, here's the specific firewall rule to check".
  if podman exec wordpress getent hosts mariadb >/dev/null 2>&1; then
    pass "WordPress resolves the 'mariadb' hostname (Aardvark DNS working)"
  else
    fail "WordPress cannot resolve the 'mariadb' hostname" \
         "Container DNS is broken. Aardvark-dns runs on the network gateway; the nftables input chain must allow the container subnet to reach the gateway on port 53. This is the classic 'MariaDB is healthy but WordPress can't find it' failure." \
         "nft list chain inet filter input | grep 'dport 53'   # must show accepts for 10.89.10.0/24 and 10.89.20.0/24 to their gateways; if absent, the ruleset predates the v7-15 DNS fix"
  fi
  dbq=$(podman exec --user www-data wordpress php -r '
    $db = @new mysqli(getenv("WORDPRESS_DB_HOST"), getenv("WORDPRESS_DB_USER"),
                      getenv("WORDPRESS_DB_PASSWORD"), getenv("WORDPRESS_DB_NAME"));
    if ($db->connect_errno) { echo "connect_fail"; exit(0); }
    $r = $db->query("SELECT 1");
    echo $r ? "ok" : "query_fail";' 2>/dev/null)
  case "$dbq" in
    ok) pass "WordPress can query the database with its own credentials" ;;
    connect_fail)
      fail "WordPress cannot connect to MariaDB" \
           "DNS, credentials, or the wp-db network path is broken (see the DNS check just above — if that failed, fix it first)." \
           "podman exec wordpress getent hosts mariadb   # if this fails it is DNS/network, not credentials" ;;
    query_fail)
      fail "WordPress connected but SELECT 1 failed" \
           "Authentication worked; the database itself rejected a trivial query." \
           "podman exec mariadb mariadb -uroot -p\"\$MARIADB_ROOT_PASSWORD\" -e 'SHOW DATABASES;'" ;;
    *)
      fail "WordPress DB check did not run" \
           "PHP or mysqli is unavailable inside the container." \
           "podman exec wordpress php -m | grep -i mysqli" ;;
  esac
fi
fi

# ── WEB ────────────────────────────────────────────────────────────────────
if want_section web; then
section web "Web server"

code=$(_http_code "http://127.0.0.1/")
case "$code" in
  200|301|302) pass "Site responds on :80 (HTTP ${code})" ;;
  403) warn "Site returns 403 on :80" \
            "Expected if WEB_CIDR or GeoIP filtering excludes this host's own address." \
            "Test from an allowed client IP. To inspect: tail -20 /home/wpuser/wp/logs/access.log" ;;
  "")  fail "No HTTP response on :80" \
            "Apache is not answering at all." \
            "doas podman logs --tail 50 wordpress ; netstat -tlnp | grep ':80 '" ;;
  *)   fail "Unexpected HTTP ${code} on :80" \
            "A working WordPress front page returns 200, 301, or 302." \
            "doas podman logs --tail 50 wordpress ; tail -30 /home/wpuser/wp/logs/error.log" ;;
esac

if [ "$(_running wordpress)" = "running" ]; then
  if [ "$(podman exec wordpress php -r 'echo "ok";' 2>/dev/null)" = "ok" ]; then
    pass "PHP executes inside the container"
  else
    fail "PHP does not execute" \
         "The container is up but the PHP binary is not usable." \
         "doas podman logs --tail 50 wordpress"
  fi

  # Apache's own config parser is the authority on whether wp-security.conf
  # and the .htaccess-adjacent config are valid. A syntax error here means
  # Apache fell back to defaults or refused to reload.
  if podman exec wordpress apachectl -t >/dev/null 2>&1; then
    pass "Apache configuration parses cleanly"
  else
    fail "Apache configuration has a syntax error" \
         "Apache is running on an older config or failed to reload." \
         "podman exec wordpress apachectl -t    # prints the offending file and line"
  fi

  podman exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
  if podman exec --user www-data wordpress sh -c \
       'touch /var/www/html/wp-content/uploads/.vtest && rm -f /var/www/html/wp-content/uploads/.vtest' \
       >/dev/null 2>&1; then
    pass "Uploads directory is writable by www-data"
  else
    fail "Uploads directory is not writable by www-data" \
         "Media uploads and plugin installs will fail with a permissions error." \
         "podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content && chown -R 33:33 /home/wpuser/wp/html/wp-content"
  fi
fi

if [ -f /home/wpuser/wp/htaccess/.htaccess ] \
   && grep -q '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess 2>/dev/null; then
  pass ".htaccess present with 8G firewall rules"
else
  fail ".htaccess missing or missing its 8G rules" \
       "The request-filtering layer that runs before PHP is not in place." \
       "ls -l /home/wpuser/wp/htaccess/.htaccess ; grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess"
fi
fi

# ── SECURITY ───────────────────────────────────────────────────────────────
if want_section security; then
section security "Security"

# --- Custom login slug: the end-to-end test this script never had ---
if [ -n "${WP_ADMIN_SLUG}" ]; then
  # The BARE slug is the login URL. The "-login" suffix was removed because a
  # path matching *login* is found by the same wordlist that finds
  # wp-login.php, so it hid the page from nobody. This probe was not updated
  # at the time and kept testing the old path — meaning on a current build it
  # would have reported a 404 for a slug that works, and on an older build it
  # printed a URL that no longer exists. Both are how an operator ends up
  # locked out of a working site.
  slug_code=$(_http_code "http://127.0.0.1/${WP_ADMIN_SLUG}")
  dflt_code=$(_http_code "http://127.0.0.1/wp-login.php")

  if [ "$slug_code" = "403" ] && [ "$dflt_code" = "403" ] \
     && { [ -n "${ADMIN_CIDR}" ] || [ -n "${ALLOWED_ADMIN_IP}" ]; }; then
    warn "Login slug cannot be verified from this host" \
         "Both paths return 403 because ADMIN_CIDR/ALLOWED_ADMIN_IP excludes this host's own source address. That is correct behaviour, not a fault." \
         "Re-test from an allowed client:  curl -o /dev/null -w '%{http_code}\\n' http://<vm-ip>/${WP_ADMIN_SLUG}"
  else
    case "$slug_code" in
      200|302) pass "Login slug /${WP_ADMIN_SLUG} serves the login page (HTTP ${slug_code})" ;;
      404)     fail "Login slug /${WP_ADMIN_SLUG} returns 404" \
                    "The rewrite is not firing. Usually AllowOverride, a missing .htaccess mount, or mod_rewrite disabled." \
                    "grep -A6 'Custom wp-admin slug' /home/wpuser/wp/htaccess/.htaccess ; podman exec wordpress apachectl -M | grep rewrite" ;;
      "")      fail "Login slug /${WP_ADMIN_SLUG} gave no response" "" \
                    "podman logs --tail 30 wordpress" ;;
      *)       fail "Login slug returned unexpected HTTP ${slug_code}" "" \
                    "tail -20 /home/wpuser/wp/logs/error.log" ;;
    esac

    case "$dflt_code" in
      403) pass "Default /wp-login.php is blocked (HTTP 403)" ;;
      200) fail "Default /wp-login.php is NOT blocked (HTTP 200)" \
                "The slug is decorative — bots hitting the standard path reach the real login form." \
                "grep -A5 'wp-login' /home/wpuser/wp/htaccess/.htaccess    # the RewriteCond block should be present" ;;
      *)   warn "Default /wp-login.php returned HTTP ${dflt_code:-none}" \
                "Expected 403 when a slug is configured." \
                "grep -A5 'wp-login' /home/wpuser/wp/htaccess/.htaccess" ;;
    esac
  fi

  # Without the mu-plugin, WordPress emits /wp-login.php in the login form
  # action — which the block above rejects — and login becomes impossible.
  MU=/home/wpuser/wp/html/wp-content/mu-plugins/00-wpvm-login-slug.php
  if [ -f "$MU" ]; then
    if grep -q "WPVM_SLUG_PLACEHOLDER" "$MU" 2>/dev/null; then
      fail "Login slug mu-plugin still contains an unsubstituted placeholder" \
           "WordPress will generate login URLs pointing at a path that does not exist." \
           "sed -i 's|WPVM_SLUG_PLACEHOLDER|${WP_ADMIN_SLUG}|g' ${MU}"
    elif podman exec wordpress php -l /var/www/html/wp-content/mu-plugins/00-wpvm-login-slug.php >/dev/null 2>&1; then
      pass "Login slug mu-plugin installed and parses"
    else
      fail "Login slug mu-plugin has a PHP syntax error" \
           "An mu-plugin fatal takes the whole site down and cannot be disabled from the admin UI." \
           "rm -f ${MU}    # removes the fatal; then also remove the wp-login block from .htaccess or you will be locked out"
    fi
  else
    fail "Login slug configured but mu-plugin is missing" \
         "The login form will POST to the blocked default path — login will fail." \
         "Remove the wp-login block from /home/wpuser/wp/htaccess/.htaccess to restore access, then re-run provisioning"
  fi
else
  info "No custom login slug configured (default /wp-login.php in use)"
fi

# --- WordPress core version actually being served ---
# The image tag and the core files on disk can disagree, because the official
# WordPress image only extracts core when the docroot is empty. An image update
# alone leaves the OLD core in place, so a VM can report a patched tag while
# serving a version with a known login-page CVE. Read the files, not the tag.
_wpver=$(podman exec wordpress sh -c 'grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" /var/www/html/wp-includes/version.php 2>/dev/null | head -1' 2>/dev/null)
_wptag=$(sed -n 's/^WP_TAG=//p' /etc/wp-install/pinned.env 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
if [ -n "$_wpver" ] && [ -n "$_wptag" ]; then
  case "$_wptag" in
    "${_wpver}"*) pass "WordPress core ${_wpver} matches the pinned image" ;;
    *) fail "WordPress core files (${_wpver}) do not match the pinned image (${_wptag})" \
            "The image was updated but core was not, so the site is serving the OLDER version. Any CVE fixed in the newer release is still exploitable here." \
            "update.sh wp ${_wptag}" ;;
  esac
elif [ -n "$_wpver" ]; then
  info "WordPress core ${_wpver} (no pinned tag recorded to compare against)"
fi

# --- MFA enforcement (mu-plugin + Two Factor plugin) ---
# Three things can be wrong and each matters: the mu-plugin could have a syntax
# error (site-wide fatal), enforcement could be ON while the Two Factor plugin
# is absent (every admin blocked with no way to enrol -> lockout), or it could
# be present and healthy. Distinguish them.
MU_MFA=/home/wpuser/wp/html/wp-content/mu-plugins/03-wpvm-mfa-enforce.php
if [ -f "$MU_MFA" ]; then
  if grep -q "WPVM_MFA_.*_PLACEHOLDER" "$MU_MFA" 2>/dev/null; then
    fail "MFA mu-plugin has an unsubstituted placeholder" \
         "It will PHP-fatal and take the site down." \
         "Re-run provisioning or set the constants by hand in ${MU_MFA}"
  elif ! podman exec wordpress php -l /var/www/html/wp-content/mu-plugins/03-wpvm-mfa-enforce.php >/dev/null 2>&1; then
    fail "MFA mu-plugin has a PHP syntax error" \
         "An mu-plugin fatal takes the whole site down and cannot be disabled from the admin UI." \
         "rm -f ${MU_MFA} from the console to restore the site, then re-provision"
  else
    # Is enforcement actually turned on in the installed copy?
    if grep -q "define( 'WPVM_MFA_ENFORCE', 1 )" "$MU_MFA" 2>/dev/null; then
      # Enforcement ON -> the Two Factor plugin MUST be active or admins lock out.
      # via the wp-cli CONTAINER: the wordpress image has no wp binary.
      _wpcli_img=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
      [ -n "$_wpcli_img" ] || _wpcli_img="docker.io/library/wordpress:cli"
      if podman run --rm --network "container:wordpress" --user 33:33 \
           --env-file /etc/wordpress/env -e WORDPRESS_DB_HOST=mariadb:3306 \
           -v /home/wpuser/wp/html:/var/www/html \
           "$_wpcli_img" wp --path=/var/www/html plugin is-active two-factor >/dev/null 2>&1; then
        pass "MFA enforced for admins and the Two Factor plugin is active"
      else
        fail "MFA is ENFORCED but the Two Factor plugin is not active" \
             "Admins past their grace window cannot enrol and will be locked out." \
             "wp-plugins.sh install two-factor --activate"
      fi
    else
      pass "MFA mu-plugin installed and parses (enforcement is off)"
    fi
  fi
else
  info "MFA enforcement mu-plugin not installed"
fi

# --- wp-admin IP restriction ---
# v7-16: check the Apache config as the SOURCE OF TRUTH, not the ADMIN_CIDR
# variable. The old logic only looked for 'Require ip' when ${ADMIN_CIDR} was
# non-empty — but ADMIN_CIDR was never written to vars.sh, so it was always
# empty and this always fell through to the WARN, reporting "No wp-admin IP
# restriction configured" even on installs that HAD one (the exact false
# warning from the field). The enforcement lives in the Apache config, so
# that's what we test; the variable (now also in vars.sh) is only for display.
APACHE_CONF=/home/wpuser/wp/apache-conf/wp-security.conf
if grep -q 'Require ip' "$APACHE_CONF" 2>/dev/null; then
  # Pull the actual value(s) from the config so the message is accurate even
  # when the variable isn't set in this shell.
  # DEDUPLICATE. The same allow list appears in more than one <Directory>
  # block (wp-admin and the custom login slug), and an allow list can now hold
  # several addresses, so a naive concatenation printed
  # "192.168.100.0/24 72.208.112.108 192.168.100.0/24 72.208.112.108" and read
  # like a config bug when the config was correct. Split on whitespace, keep
  # first occurrences, and strip any trailing comment the sed picked up.
  _cfg_ips=$(grep 'Require ip' "$APACHE_CONF" 2>/dev/null \
             | sed 's/#.*$//' | sed 's/.*Require ip//' \
             | tr -s ' \t' '\n' | grep -v '^$' \
             | awk '!seen[$0]++' | tr '\n' ' ' | sed 's/ *$//')
  pass "wp-admin IP restriction present (${_cfg_ips:-see ${APACHE_CONF}})"
elif [ -n "${ADMIN_CIDR}${ALLOWED_ADMIN_IP}" ]; then
  # Variable says one was requested, but the config doesn't have it — a real
  # inconsistency worth failing on.
  fail "ADMIN_CIDR is set but no 'Require ip' rule is in the Apache config" \
       "wp-admin is reachable from any source IP despite a restriction being configured." \
       "grep -n 'Require ip' ${APACHE_CONF}    # re-run provisioning if absent"
else
  warn "No wp-admin IP restriction configured" \
       "wp-admin is reachable from any source address that can reach port 80." \
       "Re-run provisioning with an ADMIN_CIDR, or add a 'Require ip' block to ${APACHE_CONF}"
fi

for pat in 'xmlrpc.php' 'wp-config' 'wp-content/uploads'; do
  if grep -q "$pat" "$APACHE_CONF" 2>/dev/null; then
    pass "Hardening rule present for ${pat}"
  else
    warn "No hardening rule for ${pat}" "" \
         "grep -n '${pat}' ${APACHE_CONF}    # re-run provisioning to regenerate"
  fi
done

if nft list tables 2>/dev/null | grep -q filter; then
  pass "nftables ruleset loaded"
  # v7-15: confirm the container-DNS accept rules are present. Their absence
  # is exactly the field failure — WordPress can't resolve 'mariadb' because
  # its DNS query to the gateway is dropped by the input chain's drop policy.
  if nft list chain inet filter input 2>/dev/null | grep -q 'dport 53'; then
    pass "nftables permits container DNS to the gateway (port 53 accept present)"
  else
    fail "nftables input chain has no port-53 accept for container DNS" \
         "Containers can't reach Aardvark-dns on the gateway, so WordPress can't resolve 'mariadb'. This ruleset predates the v7-15 DNS fix." \
         "Re-run provisioning, or add to the input chain: ip saddr 10.89.20.0/24 ip daddr 10.89.20.1 udp dport 53 accept (and tcp, and the same for 10.89.10.0/24)"
  fi
else
  fail "nftables has no filter table" \
       "The host firewall is not active — all ports are exposed." \
       "rc-service nftables restart ; nft list ruleset | head -40"
fi

if rc-service cs-firewall-bouncer status 2>/dev/null | grep -q started; then
  pass "CrowdSec firewall bouncer running"
else
  warn "CrowdSec firewall bouncer is not running" \
       "Detections are logged but bans are never enforced at the firewall." \
       "rc-service cs-firewall-bouncer restart ; tail -30 /var/log/crowdsec/crowdsec.log"
fi

if [ "${GEOIP_ENABLED:-0}" = "1" ]; then
  if podman exec wordpress apachectl -M 2>/dev/null | grep -q maxminddb; then
    pass "GeoIP: mod_maxminddb loaded in Apache"
  else
    fail "GeoIP enabled but mod_maxminddb is not loaded" \
         "Country filtering is silently inactive — all traffic is being allowed through." \
         "/usr/local/bin/wp-geoip-setup.sh ; tail -40 /var/log/wp-geoip.log"
  fi
fi
fi

# ── UPDATES ────────────────────────────────────────────────────────────────
if want_section updates; then
section updates "Update machinery"

if [ -x /usr/local/bin/update.sh ]; then
  pass "update.sh present and executable"
else
  fail "update.sh is missing or not executable" \
       "No supported path to update WordPress, MariaDB, or CrowdSec." \
       "ls -l /usr/local/bin/update.sh ; chmod +x /usr/local/bin/update.sh"
fi

if [ -f /etc/wp-install/pinned.env ]; then
  perm=$(stat -c '%a' /etc/wp-install/pinned.env 2>/dev/null)
  if [ "$perm" = "600" ]; then
    pass "pinned.env present with 0600 permissions"
  else
    warn "pinned.env permissions are ${perm}, expected 600" \
         "Image state is readable by non-root users." \
         "chmod 600 /etc/wp-install/pinned.env"
  fi
else
  warn "pinned.env not present" \
       "update.sh will rebuild it from the running containers on next run." \
       "update.sh check    # regenerates it"
fi

if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
  pinned=0
  for v in WP_DIGEST DB_DIGEST CS_DIGEST; do
    eval "d=\${$v}"
    case "$d" in sha256:*) pinned=$((pinned+1)) ;; esac
  done
  if [ "$pinned" = "3" ]; then
    pass "Digest pinning: 3/3 images pinned"
  elif [ "${DEPLOYMENT_PROFILE:-standard}" = "production" ]; then
    fail "Digest pinning: only ${pinned}/3 pinned under production profile" \
         "Production profile requires all three images pinned to a digest." \
         "cat /var/log/wp-digest-pinning.log    # shows which lookup failed and why"
  else
    warn "Digest pinning: only ${pinned}/3 images pinned" \
         "The unpinned images run from a mutable tag." \
         "update.sh digest-check    # re-resolves and re-pins"
  fi

  # Live test of the Skopeo path itself. This is what silently regressed in
  # every version before v7-14: the digest parser returned a multi-line value
  # (manifest digest plus every layer digest), which made digest-check report
  # "newer digest available" forever and forced a full pull on every install.
  if [ "$QUICK" = "0" ] && command -v skopeo >/dev/null 2>&1; then
    probe=$(skopeo inspect --format '{{.Digest}}' \
              "docker://docker.io/library/wordpress:latest" 2>/dev/null | head -1)
    if [ -z "$probe" ]; then
      warn "Skopeo could not reach the registry" \
           "Digest checks will fall back to a full image pull." \
           "skopeo inspect docker://docker.io/library/wordpress:latest    # check egress/DNS"
    elif [ "$(printf '%s\n' "$probe" | wc -l | tr -d ' ')" = "1" ] \
         && printf '%s' "$probe" | grep -qE '^sha256:[0-9a-f]{64}$'; then
      pass "Skopeo resolves a single well-formed digest"
    else
      fail "Skopeo returned a malformed digest" \
           "Digest comparison will never match, so every check reports a false update." \
           "skopeo inspect --format '{{.Digest}}' docker://docker.io/library/wordpress:latest"
    fi
  fi
else
  info "Digest pinning disabled (USE_DIGEST_PINNING=0)"
fi

if command -v trivy >/dev/null 2>&1; then
  pass "Trivy available for image scanning"
else
  warn "Trivy is not installed" \
       "Updates proceed without a CVE scan of the new image." \
       "update.sh trivy    # attempts install, or: apk add trivy"
fi

for job in wp-db-backup.sh wp-cron-run.sh logrotate; do
  if grep -q "$job" /etc/crontabs/root 2>/dev/null; then
    pass "Cron entry present: ${job}"
  else
    fail "No cron entry for ${job}" \
         "That scheduled task will never run." \
         "crontab -l -u root    # then add the missing line, or re-run provisioning"
  fi
done
fi

# ── LOGS ───────────────────────────────────────────────────────────────────
if want_section logs; then
section logs "Logging and disk"

if command -v logrotate >/dev/null 2>&1; then
  pass "logrotate installed"
  if [ -f /etc/logrotate.d/wordpress-vm ]; then
    # Validate OUR file specifically (via a wrapper), not the whole
    # /etc/logrotate.conf tree which may include distro fragments we don't
    # control — same approach the installer uses.
    _v_lr=$(mktemp)
    printf 'include /etc/logrotate.d/wordpress-vm\n' > "$_v_lr"
    if logrotate --debug "$_v_lr" >/dev/null 2>&1; then
      pass "logrotate configuration validates"
    else
      fail "logrotate configuration has an error" \
           "Nothing is being rotated — logs will grow until the disk fills." \
           "logrotate --debug /etc/logrotate.d/wordpress-vm    # prints the offending directive"
    fi
    rm -f "$_v_lr"
    if grep -q copytruncate /etc/logrotate.d/wordpress-vm 2>/dev/null; then
      pass "logrotate uses copytruncate (required for containerised Apache)"
    else
      fail "logrotate config is missing copytruncate" \
           "Apache holds an open fd on these files; without copytruncate it keeps writing to the unlinked inode and the rotated file stays empty forever." \
           "Add 'copytruncate' to /etc/logrotate.d/wordpress-vm"
    fi
  else
    fail "No logrotate config for this VM's logs" \
         "Apache and CrowdSec logs grow without bound until the disk fills." \
         "Re-run provisioning, or create /etc/logrotate.d/wordpress-vm"
  fi
else
  fail "logrotate is not installed" \
       "Nothing bounds log growth. A busy site will fill the disk and corrupt MariaDB." \
       "apk add --no-cache logrotate    # then re-run provisioning to install the config"
fi

# Actual on-disk sizes — config can be perfect and a log still be huge if
# rotation was added after the log had already grown.
for lf in /home/wpuser/wp/logs/access.log /home/wpuser/wp/logs/error.log; do
  [ -f "$lf" ] || continue
  sz=$(du -m "$lf" 2>/dev/null | awk '{print $1}')
  [ -z "$sz" ] && continue
  if [ "$sz" -ge 200 ]; then
    warn "$(basename "$lf") is ${sz}MB" \
         "Larger than one rotation cycle should allow." \
         "logrotate -f /etc/logrotate.conf    # force a rotation now"
  else
    pass "$(basename "$lf") size OK (${sz}MB)"
  fi
done

use=$(df -P / 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
if [ -n "$use" ]; then
  if [ "$use" -ge 90 ]; then
    fail "Root filesystem is ${use}% full" \
         "At 100% MariaDB can corrupt its data directory and backups will fail." \
         "du -sh /home/wpuser/wp/logs /root/wp-db-backups /var/lib/containers | sort -h"
  elif [ "$use" -ge 75 ]; then
    warn "Root filesystem is ${use}% full" "" \
         "du -sh /home/wpuser/wp/logs /root/wp-db-backups /var/lib/containers | sort -h"
  else
    pass "Disk usage healthy (${use}%)"
  fi
fi
fi

# ── BACKUPS ────────────────────────────────────────────────────────────────
# CrowdSec whitelist visibility. A ban applies at nftables and drops SSH as
# well as HTTP, so "am I about to lock myself out" is a question the validator
# should answer rather than leave to be discovered the hard way.
# ── Is mod_remoteip actually substituting the real client address? ──────────
# One root cause with four symptoms, so it is checked once, explicitly, rather
# than left to be inferred from four separate oddities:
#   wp-admin restriction — would allow everyone if the proxy is inside the
#                          admin CIDR (now fails closed, but still wrong)
#   login rate limiting  — every visitor shares one counter; five failures
#                          from anyone lock out everyone
#   CrowdSec             — bans the proxy (site-wide outage) or, if the proxy
#                          is whitelisted, detects nothing at all
#   GeoIP                — sees an RFC1918 address and exempts it, so country
#                          filtering does nothing
# ── Is WEB_CIDR actually enforced, or merely present? ────────────────────────
# Checked in the FORWARD chain specifically. Podman DNATs a published port
# before the filter input hook, so an input-chain rule on dport 80 matches
# nothing — verified on a live VM where a host outside WEB_CIDR connected
# while the input rule claimed to allow only the proxy.
#
# This is why the check looks for the rule in the chain that traffic actually
# traverses rather than anywhere in the ruleset: "present somewhere" was
# exactly the evidence that made the broken version look correct.
if [ -n "${WEB_CIDR:-}" ]; then
  if nft list chain inet filter forward 2>/dev/null | grep -q "nft-web-cidr-drop"; then
    pass "WEB_CIDR enforced in the forward chain (where published ports pass)"
  elif nft list chain inet filter input 2>/dev/null | grep -q "tcp dport { 80, 443 }"; then
    fail "WEB_CIDR is configured but only enforced in the INPUT chain" \
         "Published container ports are DNAT'd and traverse FORWARD, so an input-chain rule never matches them. Any host on the LAN can reach the site despite the restriction." \
         "Re-run the installer, or add the forward-chain rule by hand — see lib/03-dynamic-configs.sh"
  else
    note "WEB_CIDR is set to ${WEB_CIDR} but no matching rule was found in the live ruleset"
  fi
fi

if [ -n "${PROXY_IP:-}" ]; then
  _dbg=/home/wpuser/wp/logs/remoteip-debug.log
  if [ -s "$_dbg" ]; then
    # Anchored with ( |$) rather than a bare trailing space: the space is
    # present in this log format today, but relying on it means a format
    # change silently turns this check into "always passes". The alternation
    # also stops 192.168.100.11 matching 192.168.100.112.
    _tot=$(grep -cE "peer=${PROXY_IP}( |\$)" "$_dbg" 2>/dev/null) || _tot=0
    _bad=$(grep -E "peer=${PROXY_IP}( |\$)" "$_dbg" 2>/dev/null | grep -cE "interpreted=${PROXY_IP}( |\$)") || _bad=0
    if [ "${_tot:-0}" -eq 0 ]; then
      note "No requests seen from the configured proxy ${PROXY_IP} yet — browse the site through the domain, then re-run"
    elif [ "${_bad:-0}" -gt 0 ]; then
      fail "mod_remoteip is NOT substituting the client address on ${_bad} of ${_tot} proxied requests" \
           "Every visitor then appears to be the proxy. That defeats the wp-admin restriction, the login rate limiter, CrowdSec and GeoIP simultaneously — all four key off this address." \
           "wp-hardening.sh proxy-check   # then enable X-Forwarded-For on the proxy"
    else
      pass "mod_remoteip is substituting real client addresses (${_tot} proxied requests checked)"
    fi
  else
    note "remoteip-debug.log is empty — cannot confirm client-IP handling yet"
  fi
  if grep -q "REMOTEIP-BROKEN" /home/wpuser/wp/logs/error.log 2>/dev/null; then
    fail "The login guard has logged REMOTEIP-BROKEN" \
         "PHP saw the proxy as the client. Rate limiting is counting every visitor as one." \
         "grep REMOTEIP-BROKEN /home/wpuser/wp/logs/error.log | tail -5"
  fi
fi

_CSWL=/opt/crowdsec/config/postoverflows/s01-whitelist/wpvm-operator.yaml
if [ -r "$_CSWL" ]; then
  _n=$(grep -c '^    - "' "$_CSWL" 2>/dev/null) || _n=0
  pass "CrowdSec whitelist present (${_n} address(es) never banned)"
else
  warn "No CrowdSec whitelist configured" \
       "CrowdSec bans at nftables, which drops SSH too. A mistyped admin password five times can lock you out of the VM entirely; recovery is via the Proxmox console." \
       "wp-hardening.sh crowdsec-whitelist add <your-admin-ip>"
fi
_CSBAN=$(podman exec crowdsec cscli decisions list -o raw 2>/dev/null | tail -n +2 | grep -c .) || _CSBAN=0
if [ "${_CSBAN:-0}" -gt 0 ]; then
  note "CrowdSec is currently banning ${_CSBAN} address(es) — wp-hardening.sh crowdsec-whitelist list"
fi

if want_section mail; then
section mail "Outbound email"

# Config and wiring checks run every time -- they are free and catch the
# failure modes that matter. A LIVE send is opt-in via --send-test-mail
# because it leaves this VM and lands in a real mailbox: a validation command
# someone runs repeatedly should not mail a person each time.
SMTP_FILE=/home/wpuser/wp/secrets/smtp.ini
MU_SMTP=/home/wpuser/wp/html/wp-content/mu-plugins/01-wpvm-smtp.php
if [ -r "$SMTP_FILE" ]; then
  pass "SMTP relay is configured"

  _pm=$(stat -c '%a %u %g' "$SMTP_FILE" 2>/dev/null)
  case "$_pm" in
    "440 0 33") pass "Credential file is 0440 root:www-data" ;;
    *) fail "Credential file is '${_pm}', expected '440 0 33'" \
            "Too open exposes the relay password; too closed and PHP cannot read it." \
            "chown root:33 ${SMTP_FILE} ; chmod 440 ${SMTP_FILE}" ;;
  esac
  # The DIRECTORY is what actually broke this in the field: root:root 0700
  # meant the PHP worker could not traverse it, so the file's own mode was
  # irrelevant and mail silently fell back to sendmail. Checked explicitly,
  # because the failure it causes points nowhere near permissions.
  _dm=$(stat -c '%a %u %g' "$(dirname "$SMTP_FILE")" 2>/dev/null)
  case "$_dm" in
    "750 0 33") pass "Credential directory is 0750 root:www-data (PHP can traverse)" ;;
    *) fail "Credential directory is '${_dm}', expected '750 0 33'" \
            "If www-data cannot traverse this directory, wp_mail() silently falls back to sendmail and every message fails." \
            "chown root:33 $(dirname "$SMTP_FILE") ; chmod 750 $(dirname "$SMTP_FILE")" ;;
  esac
  # Prove it end to end rather than inferring from modes: ask PHP, as the
  # user it actually runs as, whether it can read the file.
  if [ -f /home/wpuser/wp/secrets/smtp.php ]; then
    warn "An executable smtp.php credentials file is still present" \
         "A .php config is include()d, so any write access to it becomes code execution. The INI form removes that entirely." \
         "wp-mail.sh setup   # rewrites as INI and removes the .php"
  fi
  if podman exec --user 33 wordpress test -r /var/www/private/smtp.ini 2>/dev/null; then
    pass "PHP (uid 33) can actually read the credential file"
  else
    fail "PHP (uid 33) CANNOT read /var/www/private/smtp.php" \
         "This is the condition that makes wp_mail() fall back to sendmail and fail. Modes may look right while directory traversal is denied." \
         "chown root:33 /home/wpuser/wp/secrets ; chmod 750 /home/wpuser/wp/secrets"
  fi

  if [ -e /home/wpuser/wp/html/smtp.php ]; then
    fail "A copy of smtp.php exists inside the web root" \
         "A secret under the docroot is HTTP-readable the moment PHP execution breaks." \
         "rm -f /home/wpuser/wp/html/smtp.php"
  else
    pass "Credential file is outside the web root"
  fi

  if [ -r "$MU_SMTP" ]; then
    pass "SMTP mu-plugin is installed"
  else
    fail "SMTP mu-plugin is missing" \
         "wp_mail() falls back to PHP mail(), which has no sendmail in this image, so every message fails SILENTLY." \
         "install -m 0644 -o 33 -g 33 /etc/wp-install/payload/mu-plugins/01-wpvm-smtp.php ${MU_SMTP}"
  fi

  _mnt=$(podman inspect wordpress --format '{{range .Mounts}}{{.Destination}}={{.RW}} {{end}}' 2>/dev/null | tr ' ' '\n' | grep /var/www/private)
  case "$_mnt" in
    *=false) pass "Credential mount is read-only in the container" ;;
    *=true)  fail "Credential mount is WRITABLE in the container" \
                  "A compromised PHP process could repoint the relay at a server it controls." \
                  "Recreate the container with :ro on the /var/www/private mount" ;;
    *)       warn "Credential mount not found on the wordpress container" \
                  "wp_mail() cannot read the relay settings, so mail will fail." \
                  "rc-service wp-container restart" ;;
  esac

  if nft list ruleset 2>/dev/null | grep -q nft-smtp-ratelimit; then
    pass "Outbound SMTP rate limit is in the live ruleset"
  else
    warn "Outbound SMTP rate limit is not in the live ruleset" \
         "A compromised site could send unbounded mail through your relay, harming the sending domain's reputation." \
         "rc-service nftables restart"
  fi

  if [ "$SEND_TEST_MAIL" != "" ]; then
    # The live check goes through wp_mail() itself, which is what every plugin
    # and core feature calls -- testing the relay any other way would prove the
    # relay works while saying nothing about whether WordPress can use it.
    if /usr/local/bin/wp-mail.sh test "$SEND_TEST_MAIL" >/dev/null 2>&1; then
      pass "Live test message accepted by the relay (sent to ${SEND_TEST_MAIL})"
    else
      fail "Live test message was NOT accepted by the relay" \
           "Credentials, TLS, DNS or reachability. Delivery beyond the relay is a separate question (SPF/DKIM)." \
           "wp-mail.sh doctor ; wp-mail.sh test ${SEND_TEST_MAIL}"
    fi
  else
    note "Live send not attempted — add --send-test-mail <addr> to actually deliver one"
  fi
else
  warn "No SMTP relay configured — WordPress cannot send mail" \
       "Password resets, new-user notices and WooCommerce receipts fail SILENTLY: the UI reports success and nothing is logged." \
       "wp-mail.sh setup"
fi

fi

if want_section backups; then
section backups "Backups"

BK=/root/wp-db-backups
if [ -x /usr/local/bin/wp-db-backup.sh ]; then
  pass "Backup script present"
else
  fail "wp-db-backup.sh is missing" \
       "The daily backup cron has nothing to run." \
       "ls -l /usr/local/bin/wp-db-backup.sh    # re-run provisioning to reinstall"
fi

if [ -d "$BK" ]; then
  newest=$(ls -t "$BK"/wp-db-*.sql.gz 2>/dev/null | head -1)
  if [ -z "$newest" ]; then
    # v7-16: WARN, not FAIL. The directory exists but is empty — normal on a
    # VM that hasn't reached its first scheduled 02:00 backup. A truly broken
    # backup system surfaces as a FAIL via the >48h staleness check below once
    # a backup exists, so this stays a WARN to avoid a false alarm on fresh
    # installs while still prompting the operator to verify.
    warn "No backups exist yet in ${BK}" \
         "Expected on a fresh VM — the backup runs daily at 02:00. Not yet verified end-to-end." \
         "/usr/local/bin/wp-db-backup.sh    # run one now and watch for errors"
  else
    age_h=$(( ( $(date +%s) - $(date -r "$newest" +%s 2>/dev/null || echo 0) ) / 3600 ))
    if [ "$age_h" -le 48 ]; then
      pass "Most recent backup is ${age_h}h old"
    else
      fail "Most recent backup is ${age_h}h old" \
           "The daily backup has not succeeded in over two days." \
           "/usr/local/bin/wp-db-backup.sh ; logger -t check 'manual run' ; tail -50 /var/log/messages | grep wp-db-backup"
    fi

    if [ "$QUICK" = "0" ]; then
      # A backup that exists but does not restore is worse than no backup,
      # because it produces false confidence. Verify the archive and the
      # dump's own completion marker, exactly as the backup script does.
      if gzip -t "$newest" 2>/dev/null; then
        pass "Newest backup passes gzip integrity check"
        if gunzip -c "$newest" 2>/dev/null | tail -c 200 | grep -q "Dump completed"; then
          pass "Newest backup contains mariadb-dump's completion marker"
        else
          fail "Newest backup has no completion marker" \
               "The dump was truncated — it will not restore cleanly." \
               "/usr/local/bin/wp-db-backup.sh    # take a fresh one and verify"
        fi
      else
        fail "Newest backup fails gzip integrity check" \
             "The archive is corrupt and cannot be restored." \
             "rm -f ${newest} ; /usr/local/bin/wp-db-backup.sh"
      fi
    fi

    cnt=$(ls "$BK"/wp-db-*.sql.gz 2>/dev/null | wc -l | tr -d ' ')
    info "${cnt} backup(s) retained in ${BK}"
  fi
else
  # v7-16: WARN, not FAIL — same fresh-install reasoning as above. The daily
  # backup creates this directory on its first run (02:00); its absence on a
  # brand-new VM is expected, not a fault. If the backup script itself is
  # missing that's caught as a FAIL by the "Backup script present" check above.
  warn "Backup directory ${BK} does not exist yet" \
       "Expected on a fresh VM — it's created by the first scheduled backup (daily 02:00)." \
       "/usr/local/bin/wp-db-backup.sh    # run one now to create it and verify"
fi
fi

# ── SUMMARY ────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
printf '  Passed: %s%d%s   Warnings: %s%d%s   Failed: %s%d%s\n' \
  "$_c_ok" "$PASS" "$_c_off" "$_c_warn" "$WARN" "$_c_off" "$_c_bad" "$FAIL" "$_c_off"
echo "═══════════════════════════════════════════════════════════"

if [ -n "$REMEDIES" ]; then
  echo ""
  echo "  HOW TO FIX WHAT WAS FLAGGED"
  echo "  ─────────────────────────────────────────────────────────"
  printf '%s\n' "$REMEDIES"
  echo ""
  echo "  Re-run a single area while fixing:  validate-wordpress.sh --section <name>"
  echo "  Sections: containers database web security updates logs backups mail"
fi

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "  Result: FAILED — ${FAIL} issue(s) need attention."
  exit 1
fi
if [ "$WARN" -gt 0 ]; then
  echo ""
  echo "  Result: PASSED WITH WARNINGS — nothing is broken, but see above."
  exit 2
fi
echo ""
echo "  Result: ALL CHECKS PASSED"
exit 0
