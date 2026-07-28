#!/bin/sh
# wp-health-check.sh — proves WordPress is actually functional, not just
# that Apache answers a socket. See the long comment above this heredoc in
# create-wordpress-vm.sh for the full rationale.
# Usage: wp-health-check.sh [container_name] [http_port]
# Exit 0 = all critical checks passed. Exit 1 = one or more failed.
CONTAINER="${1:-wordpress}"
# $2 is the port Apache listens on INSIDE the container (80 here), not a
# host-published port -- every check below runs via `podman exec`, so the
# host's port mappings do not exist in that namespace.
HTTP_PORT="${2:-80}"
FAIL=0

_pass() { echo "  ✔  $*"; }
_fail() { echo "  ✗  $*" >&2; FAIL=1; }

# 1) HTTP response — sanity check only, proves nothing about WordPress
# itself (a DB-error page or PHP fatal page can still answer 200/302).
# BUG FIX (v7-13, ChatGPT Finding 15 in the audit): the old check accepted
# ANY code that wasn't 500 or 000 as healthy — which quietly waved through
# 401/403/404/429/502/503/504 as "OK", the exact list of "something is
# actually broken" codes a WordPress front page should never legitimately
# return on GET /. A permission-denied Apache config error (403), a Basic-
# Auth wall that the health check can't authenticate against (401), or a
# reverse-proxy backend failure (502/504) would all look healthy under the
# old check. Fixed to an explicit allowlist: only 200 OK (front page
# serving), 301 Moved Permanently (HTTPS/canonical URL redirect), and 302
# Found (temporary redirect, common on WP session/login flows) count as
# healthy for a GET / on a working WordPress. Any other status is a real
# failure signal worth investigating, not something to silently accept.
#
# BUG FIX (v7-16): the v7-14 attempt to harden this used GNU wget long
# options — --max-redirect, --tries, --timeout — but this runs on Alpine,
# where wget is BusyBox wget, which does NOT support any of those long
# options. BusyBox wget rejected the unrecognized option, printed nothing
# parseable, and awk extracted an empty string, so EVERY health check
# reported "Unexpected HTTP response: none" — blocking the install from
# ever reaching a healthy state through all 24 retries even though PHP,
# DNS, and the DB query all passed. (This is the exact failure in the
# field log: PHP/DNS/DB all ✔, HTTP ✗ none, 24/24 retries exhausted.)
# FIX: do the request from inside the container with PHP, which is always
# present in the WordPress image and needs no external HTTP client. This is
# the same method the post-install validator already uses successfully.
# follow_location=0 pins the result to the server's OWN first response —
# achieving exactly what the v7-14 --max-redirect=0 was reaching for (don't
# grade an offsite canonical-redirect target) but in a way that actually
# works here. ignore_errors=true makes PHP return the status line for 3xx
# and 4xx responses instead of throwing, so we can classify them. timeout=8
# bounds a hung socket so a half-open connection can't stall an update.
# ROOT CAUSE OF THE PERSISTENT 403 (found from field logs): the 8G firewall
# this project installs contains, by design,
#     RewriteCond %{HTTP_USER_AGENT} ^$ [NC]
# which 403s any request with an empty User-Agent -- a good rule, since that
# is a common scanner signature. But PHP HTTP stream wrapper sends the
# "user_agent" ini value, which is EMPTY by default in the official WordPress
# image, so this health check was tripping the site own WAF on every request:
# PHP, DNS and the database all passed while HTTP returned 403 forever and
# the install could never reach a healthy state. The probe now identifies
# itself, which is both the fix and better practice -- these requests are now
# distinguishable in the access log instead of looking like an anonymous bot.
#
# NOTE FOR FUTURE EDITS: the PHP program below is passed to the interpreter
# as a SINGLE-QUOTED shell string. An apostrophe anywhere inside it -- even
# in a comment, even in ordinary prose like the possessive form of a noun --
# silently terminates that string, and everything after it is executed as
# shell instead. That is exactly how an earlier version of this very comment
# shipped broken, producing "line 54: //: Permission denied" at runtime while
# passing sh -n cleanly. Keep all prose up here in shell comments, where
# apostrophes are harmless. See test/check-embedded-quotes.py.
HTTP_CODE=$(podman exec --user www-data "$CONTAINER" php -r '
  error_reporting(0);
  $ctx = stream_context_create(["http" => [
    "method"         => "GET",
    "timeout"        => 8,
    "follow_location"=> 0,
    "ignore_errors"  => true,
    "header"         => "User-Agent: wp-health-check/1.0\r\n",
  ]]);
  @file_get_contents("http://127.0.0.1:'"${HTTP_PORT}"'/", false, $ctx);
  $code = "none";
  if (isset($http_response_header[0]) &&
      preg_match("#HTTP/[0-9.]+ ([0-9]{3})#", $http_response_header[0], $m)) {
    $code = $m[1];
  }
  echo $code;
' 2>/dev/null)
case "$HTTP_CODE" in
  200|301|302) _pass "HTTP response: ${HTTP_CODE}" ;;
  none|"")
    # "none" means the request never got a response line at all -- refused or
    # timed out -- as opposed to a real HTTP error code. By far the most
    # common cause is a port-namespace mistake, so say so rather than leaving
    # the operator to work out why PHP and the database pass while HTTP does
    # not.
    _fail "No HTTP response on 127.0.0.1:${HTTP_PORT} inside ${CONTAINER}"
    echo "        This probe runs INSIDE the container, so the port must be the one" >&2
    echo "        Apache listens on there (80) — NOT a host-published port such as" >&2
    echo "        the 18080 in '-p 127.0.0.1:18080:80'. Nothing is bound to a" >&2
    echo "        published port from inside the container." >&2
    echo "        Listening sockets seen inside ${CONTAINER}:" >&2
    podman exec "$CONTAINER" sh -c \
      "netstat -tln 2>/dev/null || ss -tln 2>/dev/null || echo '(no netstat/ss in image)'" \
      2>/dev/null | sed 's/^/          /' >&2 || true
    ;;
  *) _fail "Unexpected HTTP response: ${HTTP_CODE} (expected 200, 301, or 302)" ;;
esac

# 2) PHP actually executes inside the container.
PHP_OK=$(podman exec "$CONTAINER" php -r 'echo "ok";' 2>/dev/null)
if [ "$PHP_OK" = "ok" ]; then
  _pass "PHP executes"
else
  _fail "PHP did not execute inside ${CONTAINER}"
fi

# 3) MariaDB name resolution via Aardvark DNS — proves the wp-db network
# path is up, independent of credentials.
if podman exec "$CONTAINER" getent hosts mariadb >/dev/null 2>&1; then
  _pass "mariadb hostname resolves"
else
  _fail "mariadb hostname does not resolve (Aardvark DNS / wp-db network issue)"
fi

# 4+5) MariaDB authentication AND a real WordPress DB query — using
# WordPress's own WORDPRESS_DB_* env vars (the exact values Apache/PHP
# itself uses), proving both that MariaDB accepts these credentials and
# that a real query succeeds — not just that a TCP socket opens.
DB_CHECK=$(podman exec "$CONTAINER" php -r '
$host = getenv("WORDPRESS_DB_HOST");
$user = getenv("WORDPRESS_DB_USER");
$pass = getenv("WORDPRESS_DB_PASSWORD");
$name = getenv("WORDPRESS_DB_NAME");
$db = @new mysqli($host, $user, $pass, $name);
if ($db->connect_errno) {
    fwrite(STDERR, $db->connect_error . PHP_EOL);
    echo "connect_fail";
    exit(0);
}
$result = $db->query("SELECT 1");
echo $result ? "ok" : "query_fail";
' 2>/dev/null)
case "$DB_CHECK" in
  ok) _pass "MariaDB auth + WordPress DB query (SELECT 1)" ;;
  connect_fail) _fail "MariaDB connection failed (auth/DNS/credentials) — see: podman logs ${CONTAINER}" ;;
  query_fail) _fail "MariaDB connected but SELECT 1 failed" ;;
  *) _fail "DB check did not run (PHP/mysqli unavailable in ${CONTAINER}?)" ;;
esac

# Informational only — recent fatal/uncaught/segfault/permission lines from
# the container's own logs, surfaced for a human. Never gates pass/fail by
# itself: some of these can be transient noise during first boot (e.g. a
# plugin autoloader race), and the checks above are what actually decide
# health.
RECENT_ERRORS=$(podman logs --since 2m "$CONTAINER" 2>&1 \
  | grep -Ei 'fatal|uncaught|segmentation|permission denied' | tail -5)
if [ -n "$RECENT_ERRORS" ]; then
  echo "  ⚠  Recent log lines worth reviewing (informational, not fatal):"
  echo "$RECENT_ERRORS" | sed 's/^/       /'
fi

if [ "$FAIL" = "0" ]; then
  echo "  ✔  WordPress health: ALL CRITICAL CHECKS PASSED"
  exit 0
fi
echo "  ✗  WordPress health: ONE OR MORE CRITICAL CHECKS FAILED"
exit 1
