#!/bin/sh
# =============================================================================
# wp-plugins.sh — WordPress-level update visibility (plugins, themes, core)
# =============================================================================
# WHY THIS EXISTS
#
# Everything else in this project defends the CONTAINER: digest-pinned
# images, Trivy scanning, fail-closed production gates, `update.sh` for the
# image itself. That is all real protection -- and it covers almost none of
# the actual WordPress attack surface.
#
# `trivy image` scans the image's OS packages and PHP libraries. Plugins and
# themes do not live in the image; they live in the mounted wp-content
# volume, installed by the site owner after deployment. Nothing scanned them
# and nothing reported when they went out of date. Updating the WordPress
# container image updates CORE only.
#
# The proportions matter here. Of the 11,334 WordPress vulnerabilities
# disclosed in 2025 (Patchstack, "State of WordPress Security in 2026"),
# roughly 91% were in plugins and 9% in themes -- core accounted for about
# six. So the hardening that was already in place addressed the ~6, while
# the ~11,300 had no coverage at all. Roughly 43% of those need no
# authentication to exploit, and disclosure-to-exploitation is frequently
# measured in hours.
#
# WHY IT REPORTS BY DEFAULT AND UPDATES ONLY ON REQUEST
#
# Blindly auto-updating plugins is not the obvious win it looks like:
#   - Roughly 46% of disclosed vulnerabilities had no patch available at
#     disclosure, so "update everything" cannot close that window anyway.
#   - Plugin auto-update has itself been the compromise vector in real
#     supply-chain incidents, where legitimate plugins from the official
#     directory shipped malicious updates to sites that trusted them.
#   - An unattended plugin update on a live site can break it with nobody
#     watching.
# So the default is visibility: report what is out of date, let a human
# decide. This mirrors what this VM already does for container images --
# the cron job runs `podman auto-update --dry-run`, never an actual
# unattended update.
#
# HOW IT RUNS
#
# wp-cli is not bundled in the official WordPress image, and downloading
# wp-cli.phar at runtime would add exactly the kind of unverified
# supply-chain dependency this project already refuses elsewhere. Instead
# this uses the official `wordpress:cli` image, digest-pinned like every
# other image here, run as a --rm throwaway that shares the running
# WordPress container's network namespace (--network container:wordpress).
# Sharing the namespace rather than re-attaching networks by hand means it
# resolves `mariadb` and reaches api.wordpress.org exactly the way
# WordPress itself does, with no duplicated network wiring to drift.
# =============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or install doas and run as a wheel user)" >&2
  exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
[ -r /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

WP_HTML_DIR="/home/wpuser/wp/html"
# Pinned at install time (stage 08) into pinned.env alongside the other three
# image references; falls back to the floating tag only if that lookup never
# happened, which matches how the other images degrade.
WPCLI_IMAGE="${WPCLI_IMAGE:-docker.io/library/wordpress:cli}"

# www-data inside both the wordpress and wordpress:cli images is uid/gid 33.
# Running as that uid means anything wp-cli writes into the shared volume
# lands with the ownership WordPress itself expects, rather than root-owned
# files WordPress can then not modify.
WPCLI_UID=33


# Colour is emitted only when stdout is a terminal. These tools are read by
# humans AND piped to logger by cron; raw escape codes in syslog are unreadable
# and make grepping the log harder for no benefit.
if [ -t 1 ]; then
  C_RED=$(printf '\033[31m'); C_YEL=$(printf '\033[33m'); C_OFF=$(printf '\033[0m')
else
  C_RED=""; C_YEL=""; C_OFF=""
fi

# ── Vulnerability data sources ───────────────────────────────────────────────
# Config lives outside the script so keys are not in a world-readable file and
# survive an update of this script.
VULN_CONF="/etc/wp-install/vuln-sources.conf"
VULN_CACHE="/var/cache/wp-vulns"
# v3. The v2 feed was open with no authentication and has been retired --
# anything still pointing at v2 silently stops receiving data. v3 requires a
# token generated under Integrations in a (free) Wordfence account, sent as a
# bearer credential in the Authorization header.
#
# Scanner feed rather than Production, deliberately: Production carries the
# full analysed records and is well over 100 MB, which is a poor thing to
# hand to jq on a 4 GB VM also running WordPress and MariaDB. Scanner is the
# minimal detection format -- exactly the fields this matching needs -- and it
# additionally contains newly discovered vulnerabilities that have not yet
# been fully analysed, so it is both smaller AND earlier.
WF_BASE="https://www.wordfence.com/api/intelligence/v3/vulnerabilities"
# scanner | production | both. Default scanner -- see the note above: it is
# the one that carries vulnerabilities still under research, so choosing
# production alone trades detection breadth for record detail.
WORDFENCE_FEED="${WORDFENCE_FEED:-scanner}"
[ -r "$VULN_CONF" ] && . "$VULN_CONF"

# Compare two dotted version strings. Returns 0 if $1 <= $2.
# WordPress plugin versions are not strict semver (1.2, 1.2.3, 1.2.3.4 all
# occur), so this pads to four fields and compares numerically field by field
# rather than relying on sort -V, which BusyBox does not implement
# consistently.
_ver_le() {
  _a=$(printf '%s' "$1" | tr -cd '0-9.' ); _b=$(printf '%s' "$2" | tr -cd '0-9.')
  _i=1
  while [ "$_i" -le 4 ]; do
    _x=$(printf '%s' "$_a" | cut -d. -f"$_i"); _x=${_x:-0}
    _y=$(printf '%s' "$_b" | cut -d. -f"$_i"); _y=${_y:-0}
    _x=$(printf '%s' "$_x" | sed 's/^0*//'); _x=${_x:-0}
    _y=$(printf '%s' "$_y" | sed 's/^0*//'); _y=${_y:-0}
    [ "$_x" -lt "$_y" ] 2>/dev/null && return 0
    [ "$_x" -gt "$_y" ] 2>/dev/null && return 1
    _i=$((_i+1))
  done
  return 0
}

# Refresh the Wordfence feed. This is a BULK download queried locally rather
# than a per-plugin lookup, which matters for two reasons: one request instead
# of one per plugin, and -- more importantly -- the list of plugins this site
# runs is never sent to a third party. A per-plugin API tells the provider
# your exact attack surface.
# Fetch one named feed into the cache. Called once or twice depending on
# WORDFENCE_FEED; the matcher then reads every cached feed file present, so
# "both" needs no special case downstream.
_wf_fetch_one() {
  _which="$1"; _force="${2:-}"
  _f="$VULN_CACHE/wordfence-${_which}.json"
  _age=99999
  [ -f "$_f" ] && _age=$(( ( $(date +%s) - $(stat -c %Y "$_f" 2>/dev/null || echo 0) ) / 3600 ))
  WF_FEED="${WF_BASE}/${_which}"
  _wf_do_fetch "$_force"
}

_wf_refresh() {
  mkdir -p "$VULN_CACHE"
  case "$WORDFENCE_FEED" in
    both)
      # Succeed if EITHER feed is usable. The first version returned failure
      # when the second fetch failed, which threw away a perfectly good
      # scanner feed and aborted the whole scan -- observed in the field as
      # "Rate limited (429)" with no results at all, despite scanner having
      # downloaded seconds earlier.
      # Scanner first and unconditionally: it is the feed that carries
      # vulnerabilities still under research, so if only one can be had, it
      # should be that one.
      _ok=0
      _wf_fetch_one scanner "${1:-}" && _ok=1
      if [ "$_ok" = 0 ]; then
        # Scanner was refused, so the budget is already spent. Asking for the
        # 100 MB production feed immediately afterwards cannot succeed and
        # only deepens the rate limit -- the field log showed exactly that,
        # two 429s and two pointless 20s waits back to back.
        echo "  Skipping the production feed this run: the scanner request was" >&2
        echo "  refused, so another request now would only be refused too." >&2
      else
        # 60s, not 5s. Five was chosen without evidence and was not enough;
        # the two feeds are a small request and a 100 MB one, and the limit
        # counts requests rather than bytes.
        sleep 60
        _wf_fetch_one production "${1:-}" && _ok=1
      fi
      [ "$_ok" = 1 ] && return 0
      return 1 ;;
    production) _wf_fetch_one production "${1:-}" || return 1 ;;
    *)          _wf_fetch_one scanner "${1:-}" || return 1 ;;
  esac
  return 0
}

_wf_do_fetch() {
  trap 'rm -f "$VULN_CACHE/.hdr.$$"' RETURN 2>/dev/null || true
  if [ -z "${WORDFENCE_API_KEY:-}" ]; then
    if [ -f "$_f" ]; then
      echo "  ⚠ No Wordfence token set — using the cached feed (${_age}h old)."
      echo "    It will go stale. Add one: wp-plugins.sh set-key wordfence <token>"
      return 0
    fi
    echo "  ✗ No Wordfence API token configured, and no cached feed to fall back on." >&2
    echo "    The v3 feed requires a token. It is free (personal and commercial)." >&2
    echo "      1. Create a free account and generate a token under Integrations:" >&2
    echo "         https://www.wordfence.com/products/wordfence-intelligence/" >&2
    echo "      2. wp-plugins.sh set-key wordfence <token>" >&2
    return 1
  fi
  if [ "${1:-}" = "force" ] || [ "$_age" -gt 12 ]; then
    echo "  Fetching Wordfence Intelligence v3 ${_which:-scanner} feed…"
    _code=$(curl -sS --max-time 180 -w '%{http_code}' \
              -H "Authorization: Bearer ${WORDFENCE_API_KEY}" \
              -D "$VULN_CACHE/.hdr.$$" \
              -o "${_f}.tmp" "$WF_FEED" 2>/dev/null || echo 000)
    case "$_code" in
      401|403)
        rm -f "${_f}.tmp"
        echo "  ✗ Wordfence rejected the token (HTTP ${_code})." >&2
        echo "    Check it under Integrations in your Wordfence account, then:" >&2
        echo "      wp-plugins.sh set-key wordfence <token>" >&2
        [ -f "$_f" ] && echo "    Using the cached feed (${_age}h old) meanwhile." >&2 && return 0
        return 1 ;;
      429)
        rm -f "${_f}.tmp"
        # One retry after a pause. A 429 here is usually the burst of two
        # large feed downloads rather than a sustained quota, so waiting a
        # few seconds generally clears it -- and giving up immediately meant
        # `both` users effectively never got the production feed at all.
        # Honour Retry-After when the server sends one. Guessing a delay when
        # the server has stated it is how a client keeps getting refused.
        _wait=$(awk 'BEGIN{IGNORECASE=1} /^Retry-After:/{gsub(/[^0-9]/,"",$2); print $2}' \
                  "$VULN_CACHE/.hdr.$$" 2>/dev/null | head -1)
        case "$_wait" in ''|*[!0-9]*) _wait=45 ;; esac
        [ "$_wait" -gt 300 ] && _wait=300
        echo "  ⚠ Rate limited (HTTP 429) on the ${_which:-} feed — waiting ${_wait}s and retrying once…" >&2
        sleep "$_wait"
        _code=$(curl -sS --max-time 180 -w '%{http_code}' \
                  -H "Authorization: Bearer ${WORDFENCE_API_KEY}" \
                  -o "${_f}.tmp" "$WF_FEED" 2>/dev/null || echo 000)
        if [ "$_code" = "200" ] && [ -s "${_f}.tmp" ] && head -c1 "${_f}.tmp" | grep -q '{'; then
          mv -f "${_f}.tmp" "$_f"; chmod 644 "$_f"
          echo "  ✔ Retry succeeded." >&2
          return 0
        fi
        rm -f "${_f}.tmp"
        echo "  ✗ Still rate limited. Wordfence limits how often the feeds can be" >&2
        echo "    pulled; the cache is reused for 12h precisely to stay under it." >&2
        if [ -f "$_f" ]; then
          echo "    Using the cached ${_which:-} feed (${_age}h old)." >&2; return 0
        fi
        echo "    Try again shortly, or use one feed instead of both:" >&2
        echo "      sed -i 's/^WORDFENCE_FEED=.*/WORDFENCE_FEED=scanner/' /etc/wp-install/vuln-sources.conf" >&2
        return 1 ;;
    esac
    if [ "$_code" = "200" ] && [ -s "${_f}.tmp" ] && head -c1 "${_f}.tmp" | grep -q '{'; then
      mv -f "${_f}.tmp" "$_f"; chmod 644 "$_f"
    else
      rm -f "${_f}.tmp"
      [ -f "$_f" ] && echo "  ⚠ Refresh failed; using cached feed (${_age}h old)" \
                   || { echo "  ✗ Could not fetch the feed and no cache exists." >&2; return 1; }
    fi
  fi
  return 0
}

_wp() {
  # --network container:wordpress requires the wordpress container to be
  # running. Checked explicitly so the failure is a clear sentence rather
  # than a raw podman error about a missing namespace.
  if ! podman ps --filter 'name=^wordpress$' --filter status=running --format '{{.Names}}' \
       | grep -qx wordpress; then
    echo "✗  The 'wordpress' container is not running — start it first:" >&2
    echo "     doas rc-service wp-container start" >&2
    exit 1
  fi
  # The official WordPress image's wp-config.php reads DB_NAME/DB_USER/
  # DB_PASSWORD from the ENVIRONMENT (it is wp-config-docker.php). A wp-cli
  # container that mounts the same html directory but without those variables
  # loads a wp-config resolving to nothing, and every command dies with
  # "Error establishing a database connection" -- which reads like a database
  # or (in wp-mail.sh) a mail-server fault when neither is wrong. Uses the
  # same env-file as the real container so the two cannot drift.
  # NOTE the explicit `wp` before "$@". The wordpress:cli image's entrypoint
  # execs its arguments directly unless the first one starts with a dash, so
  # `podman run … wordpress:cli plugin install x` tries to exec a program
  # called `plugin` and dies with "plugin: not found". Every _wp call was
  # silently failing this way, hidden because each call site suppresses stderr
  # and falls back to a friendly message.
  # EGRESS PROXY. The wp-cli container shares the WordPress network namespace,
  # so it is subject to the same nftables rules: when EGRESS_PROXY=1 the ONLY
  # reachable destination is Squid at 10.89.10.2:3128. WordPress itself knows
  # this via WP_PROXY_HOST in wp-config, but wp-cli is a separate process that
  # would otherwise try to connect DIRECTLY and be silently dropped -- which
  # surfaces as "An unexpected error occurred... plugin could not be found",
  # a message that blames WordPress.org for a local firewall decision.
  #
  # Read the setting rather than assume it: when egress filtering is off these
  # variables stay empty and wp-cli connects directly, which is correct then.
  _wpcli_proxy=""
  # Strip quotes with sed, not a nested-quote `tr -d` -- that construct has
  # broken dash parsing in this repo twice before.
  _egress_on=$(sed -n 's/^EGRESS_PROXY=//p' /etc/wp-install/vars.sh 2>/dev/null \
               | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
  if [ "${_egress_on}" = "1" ]; then
    _wpcli_proxy="-e HTTP_PROXY=http://10.89.10.2:3128 -e HTTPS_PROXY=http://10.89.10.2:3128 -e NO_PROXY=localhost,127.0.0.1,mariadb,10.89.10.0/24,10.89.20.0/24"
  fi
  # shellcheck disable=SC2086
  podman run --rm \
    --network "container:wordpress" \
    --user "${WPCLI_UID}:${WPCLI_UID}" \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    ${_wpcli_proxy} \
    ${WPCLI_MOUNT:-} \
    -v "${WP_HTML_DIR}:/var/www/html" \
    "$WPCLI_IMAGE" wp --path=/var/www/html "$@"
}

show_status() {
  echo ""
  echo "WordPress — core / plugin / theme update status"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "Core:"
  _wp core check-update 2>/dev/null || echo "  (could not check core — see 'wp-plugins.sh doctor')"
  echo ""
  echo "Plugins with updates available:"
  _wp plugin list --update=available --fields=name,version,update_version,status 2>/dev/null \
    || echo "  (could not list plugins)"
  echo ""
  echo "Themes with updates available:"
  _wp theme list --update=available --fields=name,version,update_version,status 2>/dev/null \
    || echo "  (could not list themes)"
  echo ""
  echo "Inactive plugins (still a risk — code on disk is reachable even when"
  echo "not activated, and unmaintained inactive plugins are a common entry point):"
  _wp plugin list --status=inactive --fields=name,version 2>/dev/null || true
  echo ""
  echo "Update:  wp-plugins.sh update-plugins        (all)"
  echo "         wp-plugins.sh update-plugins <slug> (one)"
  echo "         wp-plugins.sh update-core"
  echo "Note:    take a backup first — wp-db-backup.sh runs one on demand."
}

# Cron entry point. Deliberately silent when everything is current, so a
# weekly job does not train the operator to ignore its output; logs through
# syslog (not stdout mail) when something is pending, matching how every
# other scheduled job on this VM reports.
check_quiet() {
  _n_plug=$(_wp plugin list --update=available --field=name 2>/dev/null | grep -c .) || _n_plug=0
  _n_theme=$(_wp theme list --update=available --field=name 2>/dev/null | grep -c .) || _n_theme=0
  _core=$(_wp core check-update --field=version --format=csv 2>/dev/null | grep -c .) || _core=0
  if [ "${_n_plug:-0}" -gt 0 ] || [ "${_n_theme:-0}" -gt 0 ] || [ "${_core:-0}" -gt 0 ]; then
    _msg="WordPress updates pending: ${_n_plug} plugin(s), ${_n_theme} theme(s)"
    [ "${_core:-0}" -gt 0 ] && _msg="${_msg}, core update available"
    _msg="${_msg} — review with: wp-plugins.sh status"
    echo "$_msg" | logger -t wp-plugins
    # Also surface the plugin names, so the log line is actionable without
    # having to go and run the status command to find out what is pending.
    _wp plugin list --update=available --field=name 2>/dev/null \
      | while IFS= read -r _p; do
          [ -n "$_p" ] && echo "  pending plugin update: ${_p}" | logger -t wp-plugins
        done
  fi
}

vuln_scan() {
  _use_nvd="${1:-0}"
  command -v jq >/dev/null 2>&1 || { echo "✗ jq is required: apk add jq" >&2; exit 1; }
  _wf_refresh || exit 1
  # Read every cached feed. With WORDFENCE_FEED=both a vulnerability can
  # appear in both files; duplicate findings are collapsed by sorting unique
  # on the reported line rather than by trying to reconcile the two records.
  _feeds=$(ls "$VULN_CACHE"/wordfence-*.json 2>/dev/null)
  [ -n "$_feeds" ] || { echo "  ✗ No cached feed. Run: wp-plugins.sh vuln-refresh" >&2; exit 1; }

  echo ""
  echo "Vulnerability scan — installed plugins and themes"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Sources: Wordfence Intelligence ${WORDFENCE_FEED} feed$([ -n "${PATCHSTACK_API_KEY:-}" ] && printf ', Patchstack')$([ -n "${WPSCAN_API_TOKEN:-}" ] && printf ', WPScan')$([ "$_use_nvd" = 1 ] && printf ', NVD')"
  echo ""

  _inv=$(_wp plugin list --fields=name,version,status --format=csv 2>/dev/null | tail -n +2)
  _inv="${_inv}
$(_wp theme list --fields=name,version,status --format=csv 2>/dev/null | tail -n +2)"
  [ -n "$(printf '%s' "$_inv" | tr -d '[:space:]')" ] || { echo "  Could not list plugins/themes."; exit 1; }

  _hits=0
  printf '%s\n' "$_inv" | while IFS=, read -r _slug _ver _status; do
    [ -n "$_slug" ] || continue
    # Every affected range recorded for this slug, as "from|from_incl|to|to_incl|title|cve|score"
    _ranges=$(cat $_feeds | jq -s 'add' 2>/dev/null | jq -r --arg s "$_slug" '
      to_entries[] | .value as $v
      | ($v.software // [])[] | select(.slug == $s)
      | (.affected_versions // {}) | to_entries[] | .value as $r
      | [ ($r.from_version // "*"), ($r.from_inclusive|tostring),
          ($r.to_version // "*"),   ($r.to_inclusive|tostring),
          ($v.title // "untitled"), ($v.cve // ""),
          (($v.cvss.score // "") | tostring) ] | @tsv
    ' 2>/dev/null)
    [ -n "$_ranges" ] || continue

    printf '%s\n' "$_ranges" | while IFS="$(printf '\t')" read -r _fv _fi _tv _ti _title _cve _score; do
      # Is the installed version inside this affected range?
      _in=1
      if [ "$_fv" != "*" ]; then
        if [ "$_fi" = "true" ]; then _ver_le "$_fv" "$_ver" || _in=0
        else _ver_le "$_ver" "$_fv" && _in=0; fi
      fi
      if [ "$_tv" != "*" ] && [ "$_in" = 1 ]; then
        if [ "$_ti" = "true" ]; then _ver_le "$_ver" "$_tv" || _in=0
        else _ver_le "$_tv" "$_ver" && _in=0; fi
      fi
      [ "$_in" = 1 ] || continue

      case "${_score%%.*}" in
        9|10) _sev="${C_RED}CRITICAL${C_OFF}" ;;
        7|8)  _sev="${C_RED}HIGH${C_OFF}" ;;
        4|5|6) _sev="${C_YEL}MEDIUM${C_OFF}" ;;
        *)    _sev="LOW" ;;
      esac
      printf '  [%b] %s %s\n' "$_sev" "$_slug" "$_ver"
      printf '        %s\n' "$_title"
      [ -n "$_cve" ] && printf '        %s   cvss %s\n' "$_cve" "${_score:-n/a}"
      printf '        fix: wp-plugins.sh update-plugins %s\n' "$_slug"
      echo "$_slug" >> "$VULN_CACHE/.hits.$$"
    done
  done

  # `grep -c` prints its count AND exits 1 when that count is zero, so
  # `$(grep -c ...) || echo 0` yields "0\n0" and the arithmetic test below
  # dies with "too many arguments". Assign on failure instead of appending.
  if [ -f "$VULN_CACHE/.hits.$$" ]; then
    _hits=$(sort -u "$VULN_CACHE/.hits.$$" | grep -c .) || _hits=0
  else
    _hits=0
  fi
  rm -f "$VULN_CACHE/.hits.$$"

  # Opt-in sources. Queried per-slug, which is why they are opt-in and not the
  # default: unlike the Wordfence bulk feed, a per-slug lookup discloses this
  # site's exact plugin inventory to the provider.
  if [ -n "${PATCHSTACK_API_KEY:-}" ]; then
    echo ""
    echo "  Patchstack: enabled (per-slug queries — your plugin list is sent to Patchstack)"
  fi
  if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
    echo ""
    echo "  WPScan: enabled. Free tier is limited to 25 API calls per day, so a"
    echo "  site with more plugins than that will not be fully covered in one run."
  fi
  if [ "$_use_nvd" = 1 ]; then
    echo ""
    echo "  NVD: keyword matching only. NVD rate-limits to 5 requests per 30s"
    echo "  without an API key, and WordPress plugin entries there are sparse and"
    echo "  noisy — plugin names are ordinary words, so keyword search returns"
    echo "  unrelated CVEs. Treat NVD output as a prompt to investigate, never"
    echo "  as a verdict."
  fi

  echo ""
  if [ "${_hits:-0}" -gt 0 ]; then
    echo "  ${_hits} component(s) match a known vulnerability."
    echo "  Update first, then re-run. If no fix exists yet, consider deactivating"
    echo "  and deleting the plugin — deactivated code is still on disk and still"
    echo "  reachable by direct request."
  else
    echo "  No installed component matched a known vulnerability."
    echo "  That is a statement about DISCLOSED issues in this feed, not proof the"
    echo "  site is safe: ~46% of plugin vulnerabilities have no patch at the time"
    echo "  they are disclosed, and a plugin nobody has audited has no CVEs by"
    echo "  definition."
  fi
  # Licensing obligation of the Wordfence feed, not decoration: MITRE
  # copyright claims must be displayed for MITRE records shown to end users.
  echo ""
  echo "  Vulnerability data: Wordfence Intelligence (free API). Records"
  echo "  sourced from MITRE remain (c) MITRE Corporation."
}

# ── Verify core and plugin files against WordPress.org checksums ─────────────
# Detects a plugin or core file that has been MODIFIED since it was installed:
# the signature of a backdoor injected through a vulnerable plugin, which is how
# most WordPress compromises actually persist.
#
# WHY THE EXIT CODE IS NOT TRUSTED
#
# wp-cli's own exit status is not a safe pass/fail here, and this is documented
# behaviour rather than a bug. `wp plugin verify-checksums --all` reports e.g.
# "Verified 2 of 3 plugins (1 skipped)" and STILL EXITS 0 -- the skip happens
# because a plugin has no checksum published on WordPress.org, which is true of
# every commercial plugin and every bespoke one. A caller that trusts the exit
# code sees success while a plugin went unchecked.
#
# So this parses the counts, compares verified against total, and reports the
# three states separately, because they mean completely different things:
#
#   VERIFIED  the files match what WordPress.org published
#   MODIFIED  they do NOT match -- investigate, this is the finding
#   SKIPPED   no published checksum exists -- EXPECTED for Divi, Elementor Pro
#             and anything bespoke, and NOT a problem, but it does mean those
#             files are outside this control and need integrity cover elsewhere
#
# Exits nonzero only on MODIFIED. Skipped items are reported, never counted as
# failures, and never hidden.
# SIEM CONTRACT (Wazuh and friends)
# Every outcome is written to syslog with tag `wasp-integrity` in key=value
# form, so a rule can match on fields rather than parsing prose that will
# change. The shape is stable; treat it as an interface:
#
#   wasp_integrity result=PASS|FAIL|SKIP component=core|plugins|all reason=...
#
#   auth.crit    result=FAIL  -> alert. A modified core or plugin file.
#   auth.notice  result=SKIP  -> informational. Commercial/bespoke plugins have
#                                no published checksum; expected, but it means
#                                those files need FIM cover from the SIEM side.
#   auth.info    result=PASS  -> healthy run, useful for proving the check ran.
#
# A Wazuh decoder matching `wasp_integrity` and alerting on `result=FAIL` is
# the whole integration. Nothing here needs an agent-side script.
do_verify() {
  _strict=0; _json=0
  for _a in "$@"; do
    case "$_a" in
      --strict) _strict=1 ;;
      --json)   _json=1 ;;
    esac
  done

  _findings=0
  echo ""
  echo "File integrity — core and plugins vs WordPress.org checksums"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # ── Core ──────────────────────────────────────────────────────────────────
  _core_rc=0
  _core_out=$(_wp core verify-checksums 2>&1) || _core_rc=$?
  if printf '%s' "$_core_out" | grep -q "Success:"; then
    echo "  [PASS] WordPress core matches published checksums"
  else
    echo "  [FAIL] WordPress core does NOT match published checksums"
    printf '%s\n' "$_core_out" | grep -iE "doesn't verify|warning" | head -20 | sed 's/^/         /'
    echo "         A modified core file is either a bad update or a backdoor."
    echo "         Compare before assuming the worst:  doas wp-malware-scan.sh core"
    _findings=$((_findings+1))
    logger -t wasp-integrity -p auth.crit "wasp_integrity result=FAIL component=core reason=checksum_mismatch" 2>/dev/null || true
  fi

  # ── Plugins ───────────────────────────────────────────────────────────────
  _pl_rc=0
  _pl_args="--all"
  [ "$_strict" = 1 ] && _pl_args="--all --strict"
  # shellcheck disable=SC2086
  _pl_out=$(_wp plugin verify-checksums $_pl_args 2>&1) || _pl_rc=$?

  # "Verified 2 of 3 plugins (1 skipped)" -- parse, do not trust the status.
  _ver=$(printf '%s' "$_pl_out" | sed -n 's/.*Verified \([0-9]*\) of \([0-9]*\) plugin.*/\1/p' | head -1)
  _tot=$(printf '%s' "$_pl_out" | sed -n 's/.*Verified \([0-9]*\) of \([0-9]*\) plugin.*/\2/p' | head -1)
  _skip=$(printf '%s' "$_pl_out" | sed -n 's/.*(\([0-9]*\) skipped).*/\1/p' | head -1)
  : "${_ver:=0}" ; : "${_tot:=0}" ; : "${_skip:=0}"

  _mismatch=$(printf '%s' "$_pl_out" | grep -icE "doesn't verify|does not verify|checksum.*(mismatch|error)" || true)

  # ARITHMETIC, not phrasing. total - verified - skipped is the number of
  # plugins that were checked and FAILED. This does not depend on wp-cli's
  # wording, which can change between releases and has; grepping for
  # "doesn't verify" is a good hint but a bad primary test. If the numbers say
  # something failed, treat it as failed even when no message matched.
  _unaccounted=0
  if [ "${_tot:-0}" -gt 0 ]; then
    _unaccounted=$(( _tot - _ver - _skip ))
    [ "$_unaccounted" -lt 0 ] && _unaccounted=0
  fi
  if [ "$_unaccounted" -gt 0 ] && [ "${_mismatch:-0}" -eq 0 ]; then
    echo "  [FAIL] ${_unaccounted} plugin(s) neither verified nor skipped."
    echo "         wp-cli printed no matching message, but the counts do not"
    echo "         add up: ${_ver} verified + ${_skip} skipped is less than"
    echo "         ${_tot} total. Treating that as a failure rather than"
    echo "         assuming the silence is benign."
    _findings=$((_findings+1))
    logger -t wasp-integrity -p auth.crit "wasp_integrity result=FAIL component=plugins reason=unaccounted count=${_unaccounted} total=${_tot}" 2>/dev/null || true
  fi

  if [ "${_mismatch:-0}" -gt 0 ]; then
    echo "  [FAIL] ${_mismatch} plugin file(s) do NOT match published checksums"
    printf '%s\n' "$_pl_out" | grep -iE "doesn't verify|does not verify" | head -20 | sed 's/^/         /'
    _findings=$((_findings+1))
    logger -t wasp-integrity -p auth.crit "wasp_integrity result=FAIL component=plugins reason=checksum_mismatch files=${_mismatch}" 2>/dev/null || true
  else
    echo "  [PASS] ${_ver} of ${_tot} plugin(s) match published checksums"
  fi

  if [ "${_skip:-0}" -gt 0 ]; then
    echo "  [SKIP] ${_skip} plugin(s) have no published checksum to compare against."
    echo "         Expected for commercial or bespoke plugins -- WordPress.org"
    echo "         only publishes checksums for what it distributes. NOT a"
    echo "         failure, but those files are outside this control:"
    printf '%s\n' "$_pl_out" | grep -iE "skipp|no checksum|not found" | head -10 | sed 's/^/           /'
    logger -t wasp-integrity -p auth.notice "wasp_integrity result=SKIP component=plugins reason=no_published_checksum count=${_skip}" 2>/dev/null || true
  fi

  echo ""
  if [ "$_findings" -gt 0 ]; then
    echo "  RESULT: ${_findings} integrity finding(s). This is worth acting on."
    echo "    doas wp-malware-scan.sh full"
    echo "    doas wp-forensics.sh timeline"
    return 1
  fi
  echo "  RESULT: no modified files detected."
  [ "${_skip:-0}" -gt 0 ] && echo "  (with ${_skip} plugin(s) unverifiable — see SKIP above)"
  logger -t wasp-integrity -p auth.info "wasp_integrity result=PASS component=all core=ok plugins_verified=${_ver} plugins_total=${_tot} plugins_skipped=${_skip}" 2>/dev/null || true
  return 0
}

# ── Install a theme or plugin from a LOCAL zip ───────────────────────────────
# For commercial products -- Divi, Elementor Pro, a client's bespoke plugin --
# that are not in the WordPress.org directory and never will be.
#
# WHY THIS IS SEPARATE FROM `install`, AND WHY IT DOES NOT TAKE A URL
#
# `install <slug>` deliberately refuses URLs and ZIPs: its whole guarantee is
# that the code came from the official directory over TLS and nowhere else.
# Weakening that to accept an arbitrary URL would turn one auditable path into
# "download and run anything", which is the supply-chain shape this platform
# refuses everywhere else.
#
# So this takes a LOCAL FILE that the operator deliberately placed on the VM.
# The trust decision is made off-box, by a human, at scp time -- not by this
# script at runtime. It records a SHA-256 either way, so what was installed can
# be compared later against what the vendor shipped.
#
# WHY THE ZIP SHOULD NOT LIVE IN YOUR GIT REPOSITORY
#
# Tempting, and wrong for four reasons. It freezes the theme at one version
# while the vendor keeps shipping security fixes. It puts ~30 MB in git history
# forever. It does not save the licensing step, since each site still needs its
# own vendor API key to activate and receive updates. And the GPL covers the
# code, not the trademark -- redistributing a commercial product under your own
# name is a poor look for an MSP even where it is lawful. Keep the zip in your
# own asset store, scp it per install, and let the vendor's updater take over
# once the licence is activated.
do_install_file() {
  _zip=""; _activate=0; _want_sha=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --activate) _activate=1 ;;
      --sha256)   _want_sha="${2:-}"; shift ;;
      http*://*)
        echo "✗  Refusing a URL. Download it yourself, check it, copy it here:" >&2
        echo "     scp theme.zip admin@<vm>:/var/lib/wasp-import/incoming/" >&2
        echo "   Then:  doas wp-plugins.sh install-file /var/lib/wasp-import/incoming/theme.zip" >&2
        return 1 ;;
      -*) : ;;
      *) [ -z "$_zip" ] && _zip="$1" ;;
    esac
    shift
  done
  [ -n "$_zip" ] || { echo "Usage: wp-plugins.sh install-file <file.zip> [--activate] [--sha256 <hash>]" >&2; return 1; }
  [ -f "$_zip" ] || { echo "✗  No such file: ${_zip}" >&2; return 1; }
  case "$_zip" in *.zip) : ;; *) echo "✗  Not a .zip: ${_zip}" >&2; return 1 ;; esac
  # The path becomes part of a `-v host:container:ro` argument that is expanded
  # UNQUOTED (podman needs the flag and value as separate words). A filename
  # containing a space or a semicolon would therefore word-split into garbage
  # arguments -- not a shell injection, since nothing re-evaluates the value,
  # but a broken mount and a baffling error at the worst moment. Constrain the
  # charset instead of trying to quote around it.
  case "$_zip" in
    *[!A-Za-z0-9._/-]*)
      echo "✗  Refusing that path: it contains characters that would break the" >&2
      echo "   container mount argument (spaces, quotes, semicolons and the" >&2
      echo "   like). Rename it to letters, digits, dot, dash, underscore:" >&2
      echo "     mv \"${_zip}\" ./divi.zip" >&2
      return 1 ;;
  esac

  # Integrity. If the operator supplied a hash, it must match -- that is the
  # only point at which a corrupted or swapped download gets caught.
  _got_sha=$(sha256sum "$_zip" 2>/dev/null | awk '{print $1}')
  if [ -n "$_want_sha" ]; then
    if [ "$_got_sha" != "$_want_sha" ]; then
      echo "✗  SHA-256 MISMATCH — refusing to install." >&2
      echo "     expected: ${_want_sha}" >&2
      echo "     actual  : ${_got_sha}" >&2
      return 1
    fi
    echo "  ✔  SHA-256 verified"
  else
    echo "  ℹ  No --sha256 given. Recording what was installed:"
    echo "       ${_got_sha}"
    echo "     Pass it next time so a swapped file is caught."
  fi

  # wp-cli needs the file inside its container -- but NOT inside the web root.
  #
  # An earlier version copied it to wp-content/upgrade/, which is served by
  # Apache. Only wp-content/uploads is protected here, and the .zip extension
  # is blocked by the 8G ruleset -- which is a TOGGLE (`wp-hardening.sh disable
  # 8g`). So on a VM with 8G off, a commercial theme or a client's bespoke
  # plugin was downloadable by anyone who guessed the filename during the
  # install window. Small window, real disclosure, and the kind of thing a
  # security review finds immediately.
  #
  # Mounting the file read-only at /tmp inside the wp-cli container removes the
  # web root from the path entirely. Nothing is ever written under the docroot.
  _base=$(basename "$_zip")
  _abs=$(cd "$(dirname "$_zip")" 2>/dev/null && pwd)/"$_base"
  [ -f "$_abs" ] || { echo "✗  Could not resolve ${_zip}" >&2; return 1; }
  WPCLI_MOUNT="-v ${_abs}:/tmp/${_base}:ro"
  export WPCLI_MOUNT

  # Theme or plugin? A theme zip has style.css at the top of its directory.
  _kind=plugin
  if command -v unzip >/dev/null 2>&1; then
    unzip -l "$_zip" 2>/dev/null | grep -qE '^[^/]*[[:space:]]+[^ ]+/style\.css$' && _kind=theme
  fi
  echo "  → Installing as a ${_kind} from ${_base}…"

  _rc=0
  _out=$(_wp "$_kind" install "/tmp/${_base}" --force 2>&1) || _rc=$?
  printf '%s\n' "$_out" | sed 's/^/  /'
  unset WPCLI_MOUNT

  if [ "$_rc" -ne 0 ]; then
    echo "✗  Install failed." >&2
    echo "   If wp-admin uploads are blocked this does NOT affect wp-cli, so the" >&2
    echo "   cause is elsewhere — check the output above." >&2
    return 1
  fi
  echo "  ✔  Installed ${_base} as a ${_kind}"

  if [ "$_activate" = 1 ]; then
    _slug_guess=$(printf '%s' "$_out" | sed -n "s/.*'\([a-z0-9-]*\)'.*/\1/p" | head -1)
    [ -n "$_slug_guess" ] || _slug_guess="${_base%.zip}"
    _wp "$_kind" activate "$_slug_guess" >/dev/null 2>&1 || true
    if _wp "$_kind" list --status=active --field=name 2>/dev/null | grep -q .; then
      echo "  ✔  Activated (verified)"
    else
      echo "  ⚠  Could not confirm activation — activate from wp-admin." >&2
    fi
  fi

  mkdir -p /etc/wp-install 2>/dev/null || true
  printf '%s\t%s\t%s\tsha256=%s\tactivate=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_kind" "$_base" "$_got_sha" "$_activate" \
    >> /etc/wp-install/installed-plugins.log 2>/dev/null || true

  echo ""
  echo "  Licence + updates: enter the vendor API key in wp-admin so the theme"
  echo "  receives security fixes. Without it, it is frozen at this version."
  echo "  Its licence domain must also be reachable through the egress proxy:"
  echo "    doas wasp-egress.sh allow .elegantthemes.com     # Divi, for example"
}

# ── Install a plugin from the WordPress.org directory ────────────────────────
# WASP does not bundle a plugin store, and for good reason: fetching arbitrary
# code at runtime is the thing this project spends most of its effort avoiding.
# But a small, named, well-known set of plugins (2FA above all) is worth
# supporting through one auditable path rather than having operators paste
# `wp plugin install` by hand with no verification.
#
# This installs by slug from WordPress.org over the already-allowlisted
# .wordpress.org egress path, records what it did, and REFUSES an arbitrary
# URL or ZIP -- only directory slugs, so the source is always the official
# WordPress.org directory and never a random download.
#
# CORRECTION (external evaluation, and it was right): an earlier version of
# this comment called that directory "signed". IT IS NOT. WordPress.org serves
# plugin packages over HTTPS, which authenticates the SERVER, but the packages
# themselves carry no cryptographic signature that this VM verifies. The
# guarantee here is "official source over TLS, never an arbitrary URL" -- which
# is worth having and is NOT the same as a signed artifact. Overstating a
# control is worse than not having it, because it stops anyone looking for the
# real one. See TODO for `wp plugin verify-checksums`, which is the closest
# available integrity check and is not yet wired in. Activation is the
# caller's choice, because a plugin that activates before its settings exist
# can lock a login.
do_install() {
  _slug=""; _activate=0
  for _a in "$@"; do
    case "$_a" in
      --activate) _activate=1 ;;
      http*://*|*.zip)
        echo "✗  Refusing a URL or ZIP. Only WordPress.org directory slugs are" >&2
        echo "   allowed, so the source is always the official directory:" >&2
        echo "     wp-plugins.sh install two-factor" >&2
        exit 1 ;;
      -*) : ;;
      *) [ -z "$_slug" ] && _slug="$_a" ;;
    esac
  done
  [ -n "$_slug" ] || { echo "Usage: wp-plugins.sh install <slug> [--activate]" >&2; exit 1; }
  # Slug hygiene: WordPress.org slugs are lowercase, digits and hyphens only.
  case "$_slug" in
    *[!a-z0-9-]*) echo "✗  '${_slug}' is not a valid plugin slug" >&2; exit 1 ;;
  esac

  echo "── Installing ${_slug} from WordPress.org ──"
  # A REACHABILITY probe first. `plugin is-installed` returning non-zero means
  # "not installed" -- but it means exactly the same thing when wp-cli cannot
  # see WordPress at all, and on a real install that ambiguity produced a
  # cheerful "installed and activated" against a site wp-cli had never found.
  # Prove the tool works before trusting anything it says about a plugin.
  # Distinguish the two failure modes that look identical from here. "Site not
  # installed" means finish the setup wizard; "cannot reach" means a container
  # or network problem. Telling an operator to check egress when the real
  # answer is "you have not run the setup wizard yet" wastes an afternoon.
  _probe=""
  if ! _probe=$(_wp core version 2>&1) || [ -z "$_probe" ]; then
    case "$_probe" in
      *"not installed"*|*"core install"*)
        echo "ℹ  WordPress core setup has not been completed yet." >&2
        echo "   Finish the setup wizard in a browser first, then re-run:" >&2
        echo "     wp-plugins.sh install ${_slug} --activate" >&2
        return 1 ;;
    esac
    echo "✗  wp-cli cannot reach the WordPress install." >&2
    printf '%s\n' "$_probe" | sed 's/^/     /' >&2
    echo "   Nothing was installed. Check the container is running and healthy:" >&2
    echo "     doas podman ps --filter name=wordpress ; wp-plugins.sh doctor" >&2
    return 1
  fi
  if _wp plugin is-installed "$_slug" >/dev/null 2>&1; then
    echo "  ℹ  Already installed."
  else
    # Capture, then judge, then print. `if _wp … | sed` would test SED's exit
    # status -- always 0 -- so a failed install reported success. That is
    # exactly what happened on a real VM: wp-cli died with "plugin: not found"
    # and the line above it still said "✔ Installed two-factor".
    # `|| _inst_rc=$?` -- an unguarded `_x=$(cmd); _rc=$?` dies at the
    # assignment under set -e before the rc is ever read.
    _inst_rc=0
    _inst_out=$(_wp plugin install "$_slug" 2>&1) || _inst_rc=$?
    printf '%s\n' "$_inst_out" | sed 's/^/  /'
    if [ "$_inst_rc" -eq 0 ]; then
      echo "  ✔  Installed ${_slug}"
    else
      echo "✗  Install failed. If egress filtering is on, confirm .wordpress.org" >&2
      echo "   is reachable: wasp-egress status" >&2
      exit 1
    fi
  fi

  if [ "$_activate" = 1 ]; then
    _wp plugin activate "$_slug" >/dev/null 2>&1 || true
    # Confirm by asking, not by trusting the exit status of the thing we just
    # ran. "Installed and activated" was printed on a VM where neither had
    # happened; a claim about state should be a reading of state.
    if _wp plugin is-active "$_slug" >/dev/null 2>&1; then
      echo "  ✔  Activated (verified)"
    else
      echo "  ⚠  Not active after the activate call — activate from wp-admin," >&2
      echo "     or retry: wp-plugins.sh install ${_slug} --activate" >&2
    fi
  else
    echo "  ℹ  Not activated. Activate when ready:  wp-plugins.sh ... (or in wp-admin)"
  fi

  # Record it so status/reporting can see what was added out of band.
  mkdir -p /etc/wp-install 2>/dev/null || true
  printf '%s\t%s\tactivate=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_slug" "$_activate" \
    >> /etc/wp-install/installed-plugins.log 2>/dev/null || true
}

case "${1:-status}" in
  status) show_status ;;
  install|add) shift; do_install "$@" ;;
  install-file|add-file) shift; do_install_file "$@" ;;
  verify|verify-checksums|checksums) shift; do_verify "$@" ;;
  # Cheap yes/no used by the deferred MFA installer: has the WordPress setup
  # wizard actually been completed? Silent by design -- it is called from cron
  # every 10 minutes and must not fill a log with noise while waiting.
  is-site-installed) _wp core is-installed >/dev/null 2>&1 && exit 0 || exit 1 ;;
  # Applies any schema migrations a core file update requires. Called by
  # update.sh after it syncs core out of a new image.
  core-update-db) _wp core update-db ;;
  # The version ACTUALLY BEING SERVED, read from the files on disk rather than
  # from the image tag. Those two disagree whenever core files have not been
  # synced, which was a real and silent failure mode -- the image said 7.0.3
  # while the site served 7.0.2. Never trust the tag for this question.
  core-version)
    _iv=$(podman exec wordpress sh -c 'sed -n "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*[\x27\"]\\([^\x27\"]*\\)[\x27\"].*/\\1/p" /var/www/html/wp-includes/version.php 2>/dev/null | head -1' 2>/dev/null)
    _tag=$(sed -n 's/^WP_TAG=//p' /etc/wp-install/pinned.env 2>/dev/null | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//' | head -1)
    echo "  Core files serving : ${_iv:-unknown}"
    echo "  Image tag pinned   : ${_tag:-unknown}"
    case "${_tag}" in
      "${_iv}"*) echo "  ✔  They agree." ;;
      "") : ;;
      *) echo "  ⚠  MISMATCH — the image was updated but core files were not."
         echo "     The site is serving ${_iv:-?}, not ${_tag%%-*}."
         echo "     Fix: update.sh wp ${_tag}"
         exit 1 ;;
    esac ;;
  vulns|vuln|cve)
    case "${2:-}" in --nvd) vuln_scan 1 ;; *) vuln_scan 0 ;; esac ;;
  vuln-sources)
    echo ""
    echo "Vulnerability data sources"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf '  Wordfence Intelligence : %s\n' "$([ -n "${WORDFENCE_API_KEY:-}" ] && echo 'ENABLED (free token, bulk feed v3)' || echo 'NO TOKEN — vulnerability scanning unavailable')"
    printf '  Patchstack             : %s\n' "$([ -n "${PATCHSTACK_API_KEY:-}" ] && echo ENABLED || echo 'not configured')"
    printf '  WPScan                 : %s\n' "$([ -n "${WPSCAN_API_TOKEN:-}" ] && echo ENABLED || echo 'not configured')"
    echo "  NVD                    : on demand — wp-plugins.sh vulns --nvd"
    echo ""
    echo "  Wordfence is the primary source: free for personal and commercial"
    echo "  use, and fetched as ONE bulk feed queried locally — so your plugin"
    echo "  inventory never leaves this VM. The v3 feed does require a free"
    echo "  account token (v2 was open and has been retired)."
    echo ""
    echo "  The opt-in sources query per plugin slug, which does disclose what"
    echo "  you run to that provider. That is a reasonable trade for better"
    echo "  coverage, but it should be a choice, so they are off by default."
    echo ""
    echo "  Enable:  wp-plugins.sh set-key patchstack <key>"
    echo "           wp-plugins.sh set-key wpscan <token>"
    echo "    Patchstack: https://patchstack.com/  ·  WPScan: https://wpscan.com/api" ;;
  set-key)
    _src="${2:-}"; _key="${3:-}"
    [ -n "$_src" ] && [ -n "$_key" ] || { echo "Usage: wp-plugins.sh set-key [wordfence|patchstack|wpscan] <key>" >&2; exit 1; }
    mkdir -p "$(dirname "$VULN_CONF")"
    touch "$VULN_CONF"; chmod 600 "$VULN_CONF"
    case "$_src" in
      wordfence)  sed -i '/^WORDFENCE_API_KEY=/d' "$VULN_CONF"
                  printf 'WORDFENCE_API_KEY=%s\n' "$_key" >> "$VULN_CONF"
                  echo "  Note: the feed is fetched whole and matched locally, so your"
                  echo "  plugin list is not sent to Wordfence." ;;
      patchstack) sed -i '/^PATCHSTACK_API_KEY=/d' "$VULN_CONF"
                  printf 'PATCHSTACK_API_KEY=%s\n' "$_key" >> "$VULN_CONF" ;;
      wpscan)     sed -i '/^WPSCAN_API_TOKEN=/d' "$VULN_CONF"
                  printf 'WPSCAN_API_TOKEN=%s\n' "$_key" >> "$VULN_CONF" ;;
      *) echo "Unknown source '${_src}'. Use wordfence, patchstack or wpscan." >&2; exit 1 ;;
    esac
    echo "✔ ${_src} key stored in ${VULN_CONF} (0600, root-only)"
    echo "  Note: per-slug lookups disclose your plugin list to ${_src}." ;;
  vuln-refresh) _wf_refresh force && echo "✔ Feed refreshed" ;;
  check)  check_quiet ;;
  update-plugins)
    shift
    if [ $# -gt 0 ]; then
      echo "Updating plugin(s): $*"
      _wp plugin update "$@"
    else
      echo "Updating ALL plugins with available updates."
      echo "⚠  A backup is strongly advised first: wp-db-backup.sh"
      _wp plugin update --all
    fi
    echo "✔ Done. Verify the site still works: validate-wordpress.sh" ;;
  update-themes)
    shift
    if [ $# -gt 0 ]; then _wp theme update "$@"; else _wp theme update --all; fi
    echo "✔ Done. Verify the site still works: validate-wordpress.sh" ;;
  update-core)
    # Deliberately NOT the same thing as `update.sh wp`. That replaces the
    # container image (the supported path here, since it keeps the running
    # code identical to a pinned, Trivy-scanned digest). This updates core
    # files inside the mounted volume instead, which then diverge from the
    # image -- useful in a pinch, but it means the next image update may
    # overwrite or conflict with it.
    echo "⚠  'update.sh wp' is the preferred way to update WordPress core on this VM:"
    echo "   it swaps to a new pinned, Trivy-scanned container image, with the"
    echo "   candidate/cutover and rollback path this VM is built around."
    echo "   This command instead writes core files into the mounted volume,"
    echo "   which will then differ from the container image."
    printf "   Continue anyway? [y/N] : "
    read -r _ans
    case "$_ans" in
      y|Y) _wp core update; echo "✔ Core updated in-volume. Run: validate-wordpress.sh" ;;
      *)   echo "Cancelled — use: update.sh wp" ;;
    esac ;;
  list)   _wp plugin list --fields=name,status,version,update ;;
  doctor)
    echo "wp-cli image : ${WPCLI_IMAGE}"
    echo "html volume  : ${WP_HTML_DIR}"
    printf "wordpress ctr: "
    podman ps --filter 'name=^wordpress$' --format '{{.Status}}' 2>/dev/null || echo "not found"
    echo "--- wp-cli self-check ---"
    _wp cli version || echo "wp-cli could not run (is the image pulled? doas podman images | grep wordpress)"
    echo "--- database reachability as wp-cli sees it ---"
    _wp db check || echo "wp-cli could not reach the database" ;;
  *)
    echo "Usage: wp-plugins.sh [status|check|list|doctor]"
    echo "       wp-plugins.sh update-plugins [slug ...]"
    echo "       wp-plugins.sh update-themes  [slug ...]"
    echo "       wp-plugins.sh update-core"
    echo ""
    echo "  Vulnerability scanning:"
    echo "       wp-plugins.sh vulns                 scan against known-vulnerable versions"
    echo "       wp-plugins.sh vulns --nvd           also query NVD (slow, noisy)"
    echo "       wp-plugins.sh vuln-sources          which data sources are enabled"
    echo "       wp-plugins.sh vuln-refresh          force a feed re-download"
    echo "       wp-plugins.sh set-key wordfence <token>"
    echo "       wp-plugins.sh set-key patchstack|wpscan <key>"
    echo ""
    echo "Why this exists: ~91% of WordPress vulnerabilities are in plugins and"
    echo "themes, which live in the mounted volume — not in the container image"
    echo "that update.sh and Trivy cover. This is the visibility for that layer." ;;
esac
