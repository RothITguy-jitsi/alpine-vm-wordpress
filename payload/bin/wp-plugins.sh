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
  podman run --rm \
    --network "container:wordpress" \
    --user "${WPCLI_UID}:${WPCLI_UID}" \
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

case "${1:-status}" in
  status) show_status ;;
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
    _wp cli version || echo "wp-cli could not run (is the image pulled? podman images | grep wordpress)"
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
