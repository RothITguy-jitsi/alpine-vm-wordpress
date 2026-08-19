#!/bin/sh
# =============================================================================
# wasp-egress.sh — manage and prove the egress boundary
# =============================================================================
#   wasp-egress status              current mode, allowlist, recent denies
#   wasp-egress test                PROVE the boundary holds (see below)
#   wasp-egress discovery report    what was denied, classified for review
#   wasp-egress maintenance enable --duration N --reason "..." [--host X]
#   wasp-egress maintenance status | disable
#   wasp-egress allow <domain>      add to the runtime allowlist
#   wasp-egress deny <domain>       remove from it
#
# THE BOUNDARY
#
#   wp-front  ──:3128──►  Squid  ──80/443──►  approved destinations only
#   wp-front  ──X──────►  the internet directly
#   wp-db     ──X──────►  anything
#
# Two independent controls, and both matter:
#
#   Squid decides WHERE traffic may go — by destination, from the plaintext
#   CONNECT hostname, without decrypting anything.
#
#   nftables decides that WordPress CANNOT GO ROUND IT. Without that, the
#   proxy is a suggestion: a plugin calling fsockopen() or curl with
#   CURLOPT_PROXY unset simply ignores WordPress's proxy settings.
#
# `test` exists because a control nobody has verified is a claim. The most
# important case it covers is removing WordPress's proxy configuration and
# confirming egress STILL fails — that is what distinguishes a firewall
# enforcing a boundary from an application politely observing one.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

SQ=/opt/squid
CONF="${SQ}/config"
LOGS="${SQ}/logs"
RUNTIME="${CONF}/allowlist-runtime.txt"
MAINT="${CONF}/allowlist-maintenance.txt"
MAINT_META="${CONF}/.maintenance"
PROXY_HOST=10.89.10.2
PROXY_PORT=3128

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1"; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' "$1"; }

_mode() {
  # The placeholder entry exists only to stop Squid warning about an empty ACL
  # (see the header of allowlist-maintenance.txt). It is NOT a maintenance
  # window, and treating it as one would have left every VM permanently
  # reporting MAINTENANCE.
  if [ -s "$MAINT" ] && grep -vE '^\s*(#|$)|^wasp-placeholder\.invalid$' "$MAINT" 2>/dev/null | grep -q .; then echo MAINTENANCE
  else echo STRICT; fi
}

# Expire a maintenance window if its time has passed. Called by every command
# so an expired window cannot outlive its duration merely because nobody ran
# the cron job -- the expiry is a property of the state, not of a timer.
_expire_maint() {
  [ -r "$MAINT_META" ] || return 0
  _until=$(sed -n 's/^until=//p' "$MAINT_META" 2>/dev/null)
  [ -n "$_until" ] || return 0
  if [ "$(date -u +%s)" -ge "$_until" ]; then
    # Restore the placeholder rather than truncating to nothing, or Squid
    # starts warning about an empty ACL again the moment a window expires.
    printf 'wasp-placeholder.invalid\n' > "$MAINT"
    _why=$(sed -n 's/^reason=//p' "$MAINT_META" 2>/dev/null)
    rm -f "$MAINT_META"
    podman exec squid squid -k reconfigure 2>/dev/null || podman restart squid >/dev/null 2>&1
    logger -t wasp-egress "maintenance window expired, returned to STRICT (${_why})"
    return 1
  fi
  return 0
}

case "${1:-status}" in

status)
  _expire_maint && _exp=0 || _exp=1
  _hdr "Egress control"
  _m=$(_mode)
  printf '  Mode : %s\n' "$_m"
  [ "$_exp" = 1 ] && _note "(a maintenance window expired just now and was closed)"

  # Ask podman with a FILTER rather than grepping its formatted output, and
  # confirm the proxy is actually SERVING rather than merely present.
  #
  # Reported from a live VM: this said "Squid is NOT running" while Squid's own
  # access log showed it tunnelling to api.wordpress.org and correctly refusing
  # example.com in the same second. A false negative here is expensive -- it
  # sent an investigation after a working proxy and made every downstream
  # failure look like a consequence of it.
  if podman ps --filter 'name=^squid$' --filter status=running \
       --format '{{.Names}}' 2>/dev/null | grep -qx squid; then
    _ok "Squid is running"
    # Running is not the same as answering. One probe settles it.
    if podman exec squid squid -k check >/dev/null 2>&1; then
      _ok "  and responding to its own control interface"
    else
      _note "  (control check did not answer; see: doas podman logs --tail 30 squid)"
    fi
  else
    _bad "Squid is NOT running"
    _note "  If Squid's access log shows recent traffic, this check is wrong,"
    _note "  not Squid. Confirm directly:"
    _note "    doas podman ps -a --filter name=squid"
    _note "    doas podman logs --tail 20 squid"
    _note "WordPress web egress is therefore failing — which is the intended"
    _note "behaviour, not a secondary fault. The boundary fails closed."
    _note "  doas podman logs --tail 30 squid"
  fi

  echo ""
  _n=$(grep -cvE '^\s*(#|$)' "$RUNTIME" 2>/dev/null) || _n=0
  printf '  Runtime allowlist (%s):\n' "$_n"
  grep -vE '^\s*(#|$)' "$RUNTIME" 2>/dev/null | sed 's/^/    /'

  if [ "$_m" = "MAINTENANCE" ]; then
    echo ""
    _warn "MAINTENANCE window open:"
    sed 's/^/    /' "$MAINT_META" 2>/dev/null
    grep -vE '^\s*(#|$)|^wasp-placeholder\.invalid$' "$MAINT" 2>/dev/null | sed 's/^/    + /'
  fi

  echo ""
  echo "  Recent denials (what WordPress tried and could not reach):"
  grep -E 'TCP_DENIED|DENIED' "${LOGS}/access.log" 2>/dev/null | tail -8 \
    | awk '{print "    "$4" "$7}' | sort -u || echo "    (none)"
  echo ""
  _note "Prove the boundary actually holds:  wasp-egress test"
  ;;

# ── Proof, not configuration review ─────────────────────────────────────────
test)
  _hdr "Egress boundary — enforcement test"
  _pass=0; _fail=0
  # Takes the command as ARGUMENTS, not as a string to eval. The earlier
  # version eval'd, which meant every test containing a nested quote had to be
  # escaped correctly twice -- and one of them was not. A test harness whose
  # own quoting can silently change what it runs is not a test harness.
  _t() { # expected(allow|deny), description, command...
    _e="$1"; _d="$2"; shift 2
    if "$@" >/dev/null 2>&1; then _r=allow; else _r=deny; fi
    if [ "$_r" = "$_e" ]; then _pass=$((_pass+1)); printf '  \033[32m✔\033[0m  %-52s %s\n' "$_d" "$_r"
    else _fail=$((_fail+1)); printf '  \033[31m✗\033[0m  %-52s got %s, expected %s\n' "$_d" "$_r" "$_e"; fi
  }

  # A pass/fail probe that only asks "did curl exit zero" cannot tell a POLICY
  # denial from a connectivity failure, and those need completely different
  # fixes. On a real VM this reported "api.wordpress.org: got deny" and the
  # operator had no way to know whether Squid had refused it, DNS was broken,
  # or the URL simply 404s. Capture the HTTP status instead and classify:
  #
  #   200-399  reached it            -> allow
  #   403      Squid refused it      -> deny BY POLICY (the allowlist)
  #   407      proxy auth demanded   -> misconfiguration
  #   503      Squid could not resolve or connect upstream
  #   000      never reached Squid   -> firewall, or Squid is down
  #
  # Note the removal of `-f`: with it, any 4xx from the DESTINATION also makes
  # curl exit nonzero, so an allowlisted host that returns 404 for the probed
  # path looks identical to a blocked one. That is exactly the trap the old
  # probe fell into by requesting `https://api.wordpress.org/`, whose root path
  # is not a 200.
  _code() { # description, url  -> echoes the classification
    _u="$2"
    # Values go through the ENVIRONMENT, never interpolated into the PHP
    # source, so a URL containing a quote cannot alter the code being run.
    export WASP_PROBE_URL="$_u" WASP_PROBE_PROXY="${_PX_FOR_PROBE:-}"
    # curl's %{http_code} ALREADY prints 000 when it never got a response, so
    # a `|| echo 000` fallback concatenates a second one and yields "000000",
    # which then matched no case arm and printed as a nonsense status.
    # Probe with PHP, not curl. The official WordPress image is minimal -- it
    # has no netstat, no ss, and curl is not guaranteed either. When curl is
    # absent, `podman exec wordpress curl ...` produces no output at all, the
    # status comes back empty, and the test reports "000 / no response" for
    # what is actually a missing binary. That sent a real investigation after
    # a firewall that was working.
    #
    # PHP is guaranteed present, and it is a BETTER probe: it exercises the
    # exact runtime and proxy path WordPress itself uses to reach the network,
    # so a pass here means the thing we care about works, not merely that some
    # tool in the container could reach the internet.
    _hc=$(podman exec -e WASP_PROBE_URL -e WASP_PROBE_PROXY wordpress php -r '
        $u = getenv("WASP_PROBE_URL"); $p = getenv("WASP_PROBE_PROXY");
        $o = ["http" => ["method"=>"GET","timeout"=>12,"ignore_errors"=>true]];
        if ($p !== false && $p !== "") {
          $o["http"]["proxy"] = str_replace("http://","tcp://",$p);
          $o["http"]["request_fulluri"] = true;
        }
        $c = stream_context_create($o);
        $f = @file_get_contents($u, false, $c);
        $code = "000";
        if (isset($http_response_header[0]) &&
            preg_match("~ (\d{3}) ~x", $http_response_header[0], $m)) { $code = $m[1]; }
        echo $code;
      ' 2>/dev/null)
    case "$_hc" in
      ''|*[!0-9]*) _hc=000 ;;
      ???) : ;;
      *) _hc=000 ;;   # anything not exactly three digits is not a status
    esac
    printf '%s' "$_hc"
  }
  _tc() { # expected(allow|deny), description, url
    _e="$1"; _d="$2"; _u="$3"
    _PX_FOR_PROBE="$_PX"
    _hc=$(_code "$_d" "$_u")
    case "$_hc" in
      2*|3*)  _r=allow; _why="HTTP ${_hc}" ;;
      403)    _r=deny;  _why="403 — refused by the proxy policy" ;;
      407)    _r=deny;  _why="407 — proxy demanded auth (misconfigured)" ;;
      503)    _r=deny;  _why="503 — Squid could not resolve or reach it" ;;
      000)    _r=deny;  _why="no response — Squid unreachable or blocked by the firewall" ;;
      *)      _r=deny;  _why="HTTP ${_hc}" ;;
    esac
    if [ "$_r" = "$_e" ]; then
      _pass=$((_pass+1)); printf '  \033[32m✔\033[0m  %-52s %s\n' "$_d" "$_why"
    else
      _fail=$((_fail+1)); printf '  \033[31m✗\033[0m  %-52s %s (expected %s)\n' "$_d" "$_why" "$_e"
      # A 503 or 000 on a line that should ALLOW is a connectivity problem, not
      # an allowlist problem, and saying so saves an afternoon of editing a
      # file that was never wrong.
      case "${_e}:${_hc}" in
        allow:503) printf '       %s\n' "Squid reached, but it could not resolve/connect. Check Squid's DNS:" ;;
        allow:000) printf '       %s\n' "Nothing answered. Is Squid running? podman ps --filter name=squid" ;;
        allow:403) printf '       %s\n' "Squid refused it. Confirm the host is in allowlist-runtime.txt." ;;
      esac
    fi
  }
  _PX="http://${PROXY_HOST}:${PROXY_PORT}"

  echo "  Through the proxy — allowlisted destination should work:"
  # The core version-check endpoint, which returns 200 and is what WordPress
  # itself calls. The bare root of api.wordpress.org does not return 200, so
  # probing it made a working proxy look broken.
  # NOTE the http:// scheme, deliberately. PHP's stream wrapper cannot perform
  # a CONNECT tunnel, so an https:// URL through a proxy returns nothing at all
  # and the probe reports "no response" for a proxy that is answering fine --
  # which happened on a live VM while Squid's own log showed a clean
  # TCP_DENIED/403. A plain http:// request goes through the same ACL chain
  # (source, method, destination allowlist), which is what this test is for.
  # Real HTTPS reachability is proven separately by the plugin install itself.
  _tc allow "api.wordpress.org via proxy" \
     "http://api.wordpress.org/core/version-check/1.7/"

  echo ""
  echo "  Through the proxy — everything else should be refused:"
  _t deny "example.com via proxy (not allowlisted)" \
     podman exec wordpress curl -sf -m 12 -x "$_PX" https://example.com/ -o /dev/null
  _t deny "cloud metadata 169.254.169.254 via proxy" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" http://169.254.169.254/ -o /dev/null
  _t deny "bare IP literal via proxy" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" https://1.1.1.1/ -o /dev/null
  _t deny "CONNECT to a non-443 port (tunnel attempt)" \
     podman exec wordpress curl -sf -m 8 -x "$_PX" https://api.wordpress.org:22/ -o /dev/null

  echo ""
  echo "  BYPASSING the proxy entirely — the test that matters:"
  _note "If any of these succeed, the proxy is a suggestion rather than a"
  _note "boundary. A plugin using fsockopen() or curl without CURLOPT_PROXY"
  _note "ignores WordPress's proxy settings completely."
  _t deny "direct HTTPS to an ALLOWLISTED host, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" https://api.wordpress.org/ -o /dev/null
  _t deny "direct HTTPS to any host, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" https://example.com/ -o /dev/null
  _t deny "direct HTTP on port 80, no proxy" \
     podman exec wordpress curl -sf -m 8 --noproxy "*" http://example.com/ -o /dev/null
  # A plugin opening its own socket is the case the firewall exists for.
  _t deny "raw socket to 1.1.1.1:443 (simulating fsockopen)" \
     podman exec wordpress php -r "exit(@fsockopen('1.1.1.1',443,\$e,\$s,5)?0:1);"

  echo ""
  echo "  Database container — should reach nothing:"
  _t deny "mariadb direct to the internet" \
     podman exec mariadb timeout 6 bash -c "exec 3<>/dev/tcp/1.1.1.1/443"

  _hdr "Result"
  printf '  passed %s   failed %s\n\n' "$_pass" "$_fail"
  if [ "$_fail" -gt 0 ]; then
    _bad "The boundary is NOT holding."
    _note "A failure on a 'no proxy' line means the firewall is not enforcing"
    _note "the restriction and only WordPress's own settings are. Any plugin"
    _note "that opens its own socket walks straight past it."
    _note "  doas nft list ruleset | grep -A6 'wp-front egress'"
    exit 1
  fi
  _ok "WordPress can reach approved destinations only, and cannot go round the proxy."
  _note "This proves WHERE traffic may go. It does not inspect what it carries:"
  _note "an approved destination that is itself compromised is still reachable."
  ;;

# ── Discovery ───────────────────────────────────────────────────────────────
discovery)
  _hdr "Discovery — what was denied"
  _note "Denied destinations are NEVER promoted automatically. Classify each,"
  _note "then add only what is genuinely required. An allowlist grown by"
  _note "accepting whatever asked is not an allowlist."
  echo ""
  _d=$(grep -E 'TCP_DENIED|DENIED' "${LOGS}/access.log" 2>/dev/null \
       | awk '{print $7}' | sed 's|^https\?://||; s|[:/].*||' | sort | uniq -c | sort -rn | head -30)
  if [ -z "$_d" ]; then
    echo "  Nothing denied since the log was last rotated."
    echo "  Either the allowlist already covers this site, or nothing has run"
    echo "  yet — exercise updates, cron and admin workflows first."
    exit 0
  fi
  printf '  %-8s %s\n' "HITS" "DESTINATION"
  printf '%s\n' "$_d" | sed 's/^/  /'
  echo ""
  echo "  Classify each as:"
  echo "    REQUIRED     the site genuinely does not work without it"
  echo "    MAINTENANCE  needed occasionally, not at runtime  -> maintenance window"
  echo "    UNNECESSARY  a plugin phoning home, a font CDN, telemetry"
  echo "    SUSPICIOUS   you cannot account for it            -> investigate"
  echo ""
  echo "  Then:  wasp-egress allow <domain>"
  echo ""
  _warn "A destination you cannot explain is a finding, not an allowlist entry."
  ;;

# ── Maintenance ─────────────────────────────────────────────────────────────
maintenance)
  _sub="${2:-status}"
  case "$_sub" in
    status)
      _expire_maint >/dev/null
      if [ "$(_mode)" = "MAINTENANCE" ]; then
        _hdr "Maintenance window OPEN"
        sed 's/^/  /' "$MAINT_META" 2>/dev/null
        _u=$(sed -n 's/^until=//p' "$MAINT_META" 2>/dev/null)
        [ -n "$_u" ] && printf '  closes in %s minute(s)\n' "$(( (_u - $(date -u +%s)) / 60 ))"
        echo ""; grep -vE '^\s*(#|$)' "$MAINT" | sed 's/^/  + /'
      else
        echo ""; echo "  STRICT — no maintenance window open."
      fi ;;

    enable)
      shift 2
      _dur=60; _reason=""; _hosts=""
      while [ $# -gt 0 ]; do
        case "$1" in
          --duration) _dur="${2:-60}"; shift 2 ;;
          --reason)   _reason="${2:-}"; shift 2 ;;
          --host)     _hosts="${_hosts} ${2:-}"; shift 2 ;;
          *) shift ;;
        esac
      done
      case "$_dur" in ''|*[!0-9]*) _dur=60 ;; esac
      # 120 minutes is the documented ceiling. A window long enough to forget
      # about is a permanent open mode with extra steps.
      [ "$_dur" -gt 120 ] && { _dur=120; _warn "Capped at 120 minutes."; }
      [ ${#_reason} -ge 10 ] || {
        _bad "A reason of at least 10 characters is required."
        _note "It is recorded and emailed. \"testing\" tells a reviewer nothing."
        exit 1; }
      [ -n "$_hosts" ] || { _bad "Give at least one --host"; exit 1; }

      _until=$(( $(date -u +%s) + _dur * 60 ))
      : > "$MAINT"
      for _h in $_hosts; do printf '%s\n' "$_h" >> "$MAINT"; done
      {
        printf 'reason=%s\n' "$_reason"
        printf 'by=%s\n' "${SUDO_USER:-${DOAS_USER:-${USER:-unknown}}}"
        printf 'opened=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'until=%s\n' "$_until"
        printf 'expires=%s\n' "$(date -u -d "@${_until}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
        printf 'hosts=%s\n' "$_hosts"
      } > "$MAINT_META"
      chmod 600 "$MAINT_META"
      podman exec squid squid -k reconfigure 2>/dev/null || podman restart squid >/dev/null 2>&1

      _hdr "MAINTENANCE window open"
      printf '  Hosts   :%s\n  Duration: %s minutes\n  Closes  : %s\n' \
        "$_hosts" "$_dur" "$(date -u -d "@${_until}" +%H:%M 2>/dev/null) UTC"
      _note "Closes automatically. Nothing needs to remember to close it."
      logger -t wasp-egress "maintenance opened for${_hosts} (${_dur}m): ${_reason}"
      if [ -x /usr/local/bin/wp-notify.sh ]; then
        _b=$(mktemp)
        { printf 'An egress maintenance window was opened on %s.\n\n' "$(hostname)"
          sed 's/^/  /' "$MAINT_META"
          printf '\nIt closes automatically. Egress returns to STRICT with no action.\n'
        } > "$_b"
        NOTIFY_COOLDOWN_HOURS=0 /usr/local/bin/wp-notify.sh wasp-egress \
          "Egress maintenance opened on $(hostname)" "$_b"
        rm -f "$_b"
      fi ;;

    disable)
      : > "$MAINT"; rm -f "$MAINT_META"
      podman exec squid squid -k reconfigure 2>/dev/null || podman restart squid >/dev/null 2>&1
      _ok "Closed. Back to STRICT."
      logger -t wasp-egress "maintenance closed manually" ;;
  esac ;;

# ── Allowlist ───────────────────────────────────────────────────────────────
allow|deny)
  _act="$1"; _dom="${2:-}"
  [ -n "$_dom" ] || { echo "Usage: wasp-egress ${_act} <domain>" >&2; exit 1; }
  printf '%s' "$_dom" | grep -qE '^\.?[a-z0-9.-]+$' \
    || { _bad "'${_dom}' does not look like a domain"; exit 1; }
  # A bare TLD or an over-broad wildcard defeats the point of the list.
  case "$_dom" in
    .com|.net|.org|.io|.*.*) : ;;
    .*) [ "$(printf '%s' "$_dom" | tr -cd . | wc -c)" -lt 2 ] && {
          _bad "'${_dom}' is too broad — that is most of a TLD."
          _note "Allowlist the specific host you need."; exit 1; } ;;
  esac
  cp "$RUNTIME" "${RUNTIME}.bak-$(date -u +%s)"
  if [ "$_act" = "allow" ]; then
    grep -qxF "$_dom" "$RUNTIME" && { echo "Already allowed: ${_dom}"; exit 0; }
    printf '%s\n' "$_dom" >> "$RUNTIME"
    _ok "Allowed: ${_dom}"
    _warn "Every entry is a route out for a compromised site. Review periodically."
  else
    grep -vxF "$_dom" "$RUNTIME" > "${RUNTIME}.tmp" && mv -f "${RUNTIME}.tmp" "$RUNTIME"
    _ok "Removed: ${_dom}"
  fi
  podman exec squid squid -k parse 2>/dev/null && podman exec squid squid -k reconfigure 2>/dev/null \
    && _ok "Squid reloaded" \
    || { _bad "Squid rejected the configuration — restoring the previous list"
         cp "$(ls -1t ${RUNTIME}.bak-* | head -1)" "$RUNTIME"; exit 1; } ;;

*) sed -n '4,12p' "$0" ;;
esac
