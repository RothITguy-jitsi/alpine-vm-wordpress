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
WF_FEED="https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner"
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
_wf_refresh() {
  mkdir -p "$VULN_CACHE"
  _f="$VULN_CACHE/wordfence-scanner.json"
  _age=99999
  [ -f "$_f" ] && _age=$(( ( $(date +%s) - $(stat -c %Y "$_f" 2>/dev/null || echo 0) ) / 3600 ))
  if [ "${1:-}" = "force" ] || [ "$_age" -gt 12 ]; then
    echo "  Fetching Wordfence Intelligence feed (free, no key required)…"
    if curl -fsSL --max-time 120 -o "${_f}.tmp" "$WF_FEED" 2>/dev/null \
       && [ -s "${_f}.tmp" ] && head -c1 "${_f}.tmp" | grep -q '{'; then
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
    echo "     rc-service wp-container start" >&2
    exit 1
  fi
  # The official WordPress image's wp-config.php reads DB_NAME/DB_USER/
  # DB_PASSWORD from the ENVIRONMENT (it is wp-config-docker.php). A wp-cli
  # container that mounts the same html directory but without those variables
  # loads a wp-config resolving to nothing, and every command dies with
  # "Error establishing a database connection" -- which reads like a database
  # or (in wp-mail.sh) a mail-server fault when neither is wrong. Uses the
  # same env-file as the real container so the two cannot drift.
  podman run --rm \
    --network "container:wordpress" \
    --user "${WPCLI_UID}:${WPCLI_UID}" \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -v "${WP_HTML_DIR}:/var/www/html" \
    "$WPCLI_IMAGE" "$@"
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
  _n_plug=$(_wp plugin list --update=available --field=name 2>/dev/null | grep -c . || echo 0)
  _n_theme=$(_wp theme list --update=available --field=name 2>/dev/null | grep -c . || echo 0)
  _core=$(_wp core check-update --field=version --format=csv 2>/dev/null | grep -c . || echo 0)
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
  _feed="$VULN_CACHE/wordfence-scanner.json"

  echo ""
  echo "Vulnerability scan — installed plugins and themes"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Sources: Wordfence Intelligence (free)$([ -n "${PATCHSTACK_API_KEY:-}" ] && printf ', Patchstack')$([ -n "${WPSCAN_API_TOKEN:-}" ] && printf ', WPScan')$([ "$_use_nvd" = 1 ] && printf ', NVD')"
  echo ""

  _inv=$(_wp plugin list --fields=name,version,status --format=csv 2>/dev/null | tail -n +2)
  _inv="${_inv}
$(_wp theme list --fields=name,version,status --format=csv 2>/dev/null | tail -n +2)"
  [ -n "$(printf '%s' "$_inv" | tr -d '[:space:]')" ] || { echo "  Could not list plugins/themes."; exit 1; }

  _hits=0
  printf '%s\n' "$_inv" | while IFS=, read -r _slug _ver _status; do
    [ -n "$_slug" ] || continue
    # Every affected range recorded for this slug, as "from|from_incl|to|to_incl|title|cve|score"
    _ranges=$(jq -r --arg s "$_slug" '
      to_entries[] | .value as $v
      | ($v.software // [])[] | select(.slug == $s)
      | (.affected_versions // {}) | to_entries[] | .value as $r
      | [ ($r.from_version // "*"), ($r.from_inclusive|tostring),
          ($r.to_version // "*"),   ($r.to_inclusive|tostring),
          ($v.title // "untitled"), ($v.cve // ""),
          (($v.cvss.score // "") | tostring) ] | @tsv
    ' "$_feed" 2>/dev/null)
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

  _hits=$( [ -f "$VULN_CACHE/.hits.$$" ] && sort -u "$VULN_CACHE/.hits.$$" | grep -c . || echo 0 )
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

case "${1:-status}" in
  status) show_status ;;
  vulns|vuln|cve)
    case "${2:-}" in --nvd) vuln_scan 1 ;; *) vuln_scan 0 ;; esac ;;
  vuln-sources)
    echo ""
    echo "Vulnerability data sources"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Wordfence Intelligence : ENABLED (free, no key, bulk feed)"
    printf '  Patchstack             : %s\n' "$([ -n "${PATCHSTACK_API_KEY:-}" ] && echo ENABLED || echo 'not configured')"
    printf '  WPScan                 : %s\n' "$([ -n "${WPSCAN_API_TOKEN:-}" ] && echo ENABLED || echo 'not configured')"
    echo "  NVD                    : on demand — wp-plugins.sh vulns --nvd"
    echo ""
    echo "  Wordfence is the default because it is free for commercial use, needs"
    echo "  no key, and is fetched as ONE bulk feed queried locally — so your"
    echo "  plugin inventory never leaves this VM."
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
    [ -n "$_src" ] && [ -n "$_key" ] || { echo "Usage: wp-plugins.sh set-key [patchstack|wpscan] <key>" >&2; exit 1; }
    mkdir -p "$(dirname "$VULN_CONF")"
    touch "$VULN_CONF"; chmod 600 "$VULN_CONF"
    case "$_src" in
      patchstack) sed -i '/^PATCHSTACK_API_KEY=/d' "$VULN_CONF"
                  printf 'PATCHSTACK_API_KEY=%s\n' "$_key" >> "$VULN_CONF" ;;
      wpscan)     sed -i '/^WPSCAN_API_TOKEN=/d' "$VULN_CONF"
                  printf 'WPSCAN_API_TOKEN=%s\n' "$_key" >> "$VULN_CONF" ;;
      *) echo "Unknown source '${_src}'. Use patchstack or wpscan." >&2; exit 1 ;;
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
    echo "Why this exists: ~91% of WordPress vulnerabilities are in plugins and"
    echo "themes, which live in the mounted volume — not in the container image"
    echo "that update.sh and Trivy cover. This is the visibility for that layer." ;;
esac
