#!/bin/sh
# =============================================================================
# wp-forensics.sh — assemble a timeline around a finding
# =============================================================================
#   wp-forensics.sh timeline [--hours N] [--around <file>] [--json <out>] [--enrich]
#   wp-forensics.sh since-backup      what changed since the last good backup
#   wp-forensics.sh entry-class       walk the "how did this get in" decision tree
#   wp-forensics.sh admins            accounts, roles, and when they appeared
#
# WHAT THIS IS
#
# A merge of sources already on this VM, ordered by time. It answers the
# question the malware scanner cannot: *when did this appear, and what was
# happening then*. A CRITICAL finding tells you a file is there; this tells you
# what else happened in the same ten minutes.
#
# Sources, all local, none fetched:
#   - wp-malware-scan findings and the quarantine manifest
#   - file mtimes under the WordPress root, uploads and plugins first
#   - Apache access and error logs around those times
#   - login-guard events and CrowdSec decisions
#   - backup timestamps, as "last known clean"
#
# WHAT THIS IS NOT
#
# Not a patient-zero report. It does not prove a file came from a particular
# request; it puts them side by side and leaves the inference to you. That is
# a real limit, not modesty: correlation in a ten-minute window is suggestive
# and routinely wrong, and a tool that stated a conclusion here would be
# confidently wrong on exactly the occasions that matter.
#
# It is also bounded by log retention. Logs rotate hourly and are kept for a
# limited window, so an intrusion older than that leaves file mtimes and
# database timestamps but no HTTP context. `timeline` says when its evidence
# runs out rather than presenting a shorter window as a complete one.
#
# WHY IT ONLY READS
#
# Nothing here modifies, deletes or quarantines. Deciding what happened and
# acting on it are separate steps, and merging them is how evidence gets
# destroyed by someone in a hurry. Use wp-malware-scan.sh quarantine when you
# have decided.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

WP_ROOT=/home/wpuser/wp/html
LOGS=/home/wpuser/wp/logs
SCAN_STATE=/var/lib/wp-malware-scan
QUARANTINE=/var/lib/wp-quarantine
BACKUP_DIR="${BACKUP_DIR:-/root/wp-db-backups}"

HOURS=48
AROUND=""
JSON=""
ENRICH=0
CMD=""

while [ $# -gt 0 ]; do
  case "$1" in
    --hours)  HOURS="${2:-48}"; shift 2 ;;
    --around) AROUND="${2:-}"; shift 2 ;;
    --json)   JSON="${2:-}"; shift 2 ;;
    --enrich) ENRICH=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) [ -z "$CMD" ] && CMD="$1"; shift ;;
  esac
done
CMD="${CMD:-timeline}"

_hdr() { printf '\n\033[1m── %s\033[0m\n' "$1"; }
_row() { printf '  %-20s %-11s %s\n' "$1" "$2" "$3"; }
_note(){ printf '     %s\n' "$1"; }

TL=$(mktemp) || exit 1
trap 'rm -f "$TL" "$TL".*' EXIT INT TERM

# Every source writes: epoch <TAB> kind <TAB> detail
_add() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$TL"; }

# ── Window ───────────────────────────────────────────────────────────────────
_now=$(date +%s)
if [ -n "$AROUND" ] && [ -e "$AROUND" ]; then
    _centre=$(stat -c %Y "$AROUND")
    _from=$(( _centre - 3600 )); _to=$(( _centre + 3600 ))
    _wdesc="±1h around $(basename "$AROUND") ($(date -u -d "@${_centre}" '+%Y-%m-%d %H:%M' 2>/dev/null))"
else
    _from=$(( _now - HOURS * 3600 )); _to=$_now
    _wdesc="last ${HOURS}h"
fi

collect() {
  # ── Malware findings ──────────────────────────────────────────────────────
  if [ -r "$SCAN_STATE/last-scan.tsv" ]; then
    _st=$(stat -c %Y "$SCAN_STATE/last-scan.tsv")
    while IFS="$(printf '\t')" read -r sev title _; do
      [ -n "$sev" ] || continue
      _add "$_st" "scan-${sev}" "$title"
    done < "$SCAN_STATE/last-scan.tsv"
  fi

  # ── Quarantine manifest ───────────────────────────────────────────────────
  if [ -r "$QUARANTINE/manifest.tsv" ]; then
    while IFS="$(printf '\t')" read -r dest orig; do
      [ -n "$dest" ] || continue
      [ -e "$dest" ] && _add "$(stat -c %Y "$dest")" "quarantined" "$orig"
    done < "$QUARANTINE/manifest.tsv"
  fi

  # ── File modifications, riskiest paths first ──────────────────────────────
  # uploads and mu-plugins lead because a change there is almost never
  # legitimate; plugins and themes change on every update, so they are noisier.
  for _p in "wp-content/uploads" "wp-content/mu-plugins" "wp-content/plugins" \
            "wp-content/themes" "wp-includes" "."; do
    [ -d "${WP_ROOT}/${_p}" ] || continue
    find "${WP_ROOT}/${_p}" -maxdepth 4 -type f \
         -newermt "@${_from}" ! -newermt "@${_to}" 2>/dev/null | head -40 | \
    while IFS= read -r f; do
      _add "$(stat -c %Y "$f")" "file-changed" "${f#${WP_ROOT}/}"
    done
    [ "$_p" = "." ] && break
  done

  # ── Login-guard events ────────────────────────────────────────────────────
  if [ -r "$LOGS/error.log" ]; then
    grep "wpvm-login" "$LOGS/error.log" 2>/dev/null | tail -200 | \
    while IFS= read -r line; do
      _ts=$(printf '%s' "$line" | sed -n 's/^\[\([^]]*\)\].*/\1/p')
      _e=$(date -u -d "$_ts" +%s 2>/dev/null) || _e=""
      [ -n "$_e" ] || continue
      _add "$_e" "auth" "$(printf '%s' "$line" | sed -n 's/.*\[wpvm-login\] //p')"
    done
  fi

  # ── Apache denials: what was being probed ─────────────────────────────────
  if [ -r "$LOGS/error.log" ]; then
    grep "AH01630" "$LOGS/error.log" 2>/dev/null | tail -100 | \
    while IFS= read -r line; do
      _ts=$(printf '%s' "$line" | sed -n 's/^\[\([^]]*\)\].*/\1/p')
      _e=$(date -u -d "$_ts" +%s 2>/dev/null) || _e=""
      [ -n "$_e" ] || continue
      _ip=$(printf '%s' "$line" | sed -n 's/.*\[client \([^:]*\).*/\1/p')
      _pa=$(printf '%s' "$line" | sed -n 's/.*server configuration: \([^,]*\).*/\1/p')
      _add "$_e" "denied" "${_ip} -> ${_pa}"
    done
  fi

  # ── POST requests: how content usually arrives ────────────────────────────
  if [ -r "$LOGS/access.log" ]; then
    grep '"POST ' "$LOGS/access.log" 2>/dev/null | tail -150 | \
    while IFS= read -r line; do
      _ts=$(printf '%s' "$line" | sed -n 's/.*\[\([^]]*\)\].*/\1/p' | tr '/' ' ' | sed 's/:/ /')
      _e=$(date -u -d "$(printf '%s' "$line" | sed -n 's/.*\[\([^:]*\):\([^ ]*\).*/\1 \2/p' | tr '/' ' ')" +%s 2>/dev/null) || _e=""
      [ -n "$_e" ] || continue
      _add "$_e" "POST" "$(printf '%s' "$line" | awk '{print $1" "$7" "$9}')"
    done
  fi

  # ── CrowdSec decisions ────────────────────────────────────────────────────
  podman exec crowdsec cscli decisions list -o raw 2>/dev/null | tail -n +2 | \
  while IFS=, read -r _id _src _val _scen _type _country _as _events _dur _rest; do
    [ -n "$_val" ] || continue
    _add "$_now" "crowdsec-ban" "${_val} ${_scen} (${_country:-?}) ${_dur}"
  done

  # ── Backups: the "last known clean" anchor ────────────────────────────────
  for b in $(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -5); do
    _add "$(stat -c %Y "$b")" "backup" "$(basename "$b")"
  done
}

case "$CMD" in
  timeline)
    _hdr "Forensic timeline — ${_wdesc}"
    printf '  %-20s %-11s %s\n' "WHEN (UTC)" "WHAT" "DETAIL"
    printf '  %-20s %-11s %s\n' "────────────────────" "───────────" "──────────────────────────"
    collect
    _shown=0
    sort -n "$TL" | while IFS="$(printf '\t')" read -r e k d; do
      [ -n "$e" ] || continue
      [ "$e" -lt "$_from" ] && continue
      [ "$e" -gt "$_to" ] && continue
      _row "$(date -u -d "@${e}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" "$k" "$d"
    done
    _shown=$(sort -n "$TL" | awk -F'\t' -v a="$_from" -v b="$_to" '$1>=a && $1<=b' | grep -c .) || _shown=0
    echo ""
    _note "${_shown} event(s) in window."

    # State the evidence boundary rather than letting a short window look complete.
    if [ -r "$LOGS/access.log" ]; then
      _oldest=$(head -1 "$LOGS/access.log" 2>/dev/null | sed -n 's/.*\[\([^:]*\).*/\1/p')
      [ -n "$_oldest" ] && _note "Access log reaches back to ${_oldest}. Anything earlier has file"
      [ -n "$_oldest" ] && _note "and database timestamps but NO HTTP context — logs rotate hourly."
    fi
    echo ""
    _note "Correlation in a window is suggestive, not proof. Two things happening"
    _note "close together is where an investigation starts, not where it ends."

    # Enrichment is opt-in per run, not automatic. Each distinct address costs
    # a CTI lookup, and the free tier allows 40 a MONTH -- a timeline with a
    # dozen scanner IPs in it would spend a quarter of the budget answering a
    # question nobody asked.
    if [ "${ENRICH:-0}" = "1" ]; then
      _hdr "Threat intelligence for addresses in this window"
      _ips=$(sort -n "$TL" | awk -F'\t' -v a="$_from" -v b="$_to" '$1>=a && $1<=b {print $3}' \
             | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
             | grep -vE '^(127\.|10\.89\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
             | sort -u)
      if [ -z "$_ips" ]; then
        _note "No public addresses in the window."
      else
        _n=$(printf '%s\n' "$_ips" | grep -c .) || _n=0
        _note "${_n} distinct public address(es). Each uncached one costs a lookup."
        echo ""
        for _i in $_ips; do
          _rc=0
          _r=$(wp-hardening.sh cti-lookup "$_i" 2>/dev/null) || _rc=$?
          case "$_rc" in
            0) printf '  %-16s %s\n' "$_i" \
                 "$(printf '%s' "$_r" | awk -F'|' '{printf "%s · noise %s/10 · %s (%s) · %s", $1,$2,$3,$4,$5}')"
               case "$_r" in *"|YES") printf '  %-16s ⚠ possible FALSE POSITIVE — crawler/monitor/CDN\n' "" ;; esac ;;
            3) printf '  %-16s (monthly CTI budget spent — no lookup made)\n' "$_i" ;;
            2) printf '  %-16s (CTI not configured — wp-hardening.sh cti-key <key>)\n' "$_i"; break ;;
            *) printf '  %-16s (lookup failed)\n' "$_i" ;;
          esac
        done
        echo ""
        _note "CTI describes GLOBAL behaviour. The timeline above is what this"
        _note "address did HERE. The two answer different questions."
      fi
    fi
    if [ -n "$JSON" ]; then
      {
        printf '{\n  "generated": "%s",\n  "window": "%s",\n  "events": [\n' \
          "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_wdesc"
        _f=1
        sort -n "$TL" | awk -F'\t' -v a="$_from" -v b="$_to" '$1>=a && $1<=b' | \
        while IFS="$(printf '\t')" read -r e k d; do
          [ "$_f" = 1 ] || printf ',\n'; _f=0
          printf '    {"at":"%s","kind":"%s","detail":"%s"}' \
            "$(date -u -d "@${e}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" "$k" \
            "$(printf '%s' "$d" | sed 's/\\/\\\\/g; s/"/\\"/g')"
        done
        printf '\n  ]\n}\n'
      } > "$JSON"
      _note "JSON written to ${JSON}"
    fi ;;

  since-backup)
    _hdr "Changed since the last backup"
    _bk=$(ls -1t "$BACKUP_DIR"/*.sql.gz 2>/dev/null | head -1)
    [ -n "$_bk" ] || { echo "  No backup to compare against."; exit 1; }
    _bt=$(stat -c %Y "$_bk")
    _note "Reference: $(basename "$_bk") — $(date -u -d "@${_bt}" '+%Y-%m-%d %H:%M') UTC"
    _note "Anything below post-dates the newest known-good copy."
    echo ""
    for _p in "wp-content/uploads" "wp-content/mu-plugins" "wp-content/plugins" "wp-content/themes"; do
      [ -d "${WP_ROOT}/${_p}" ] || continue
      _n=$(find "${WP_ROOT}/${_p}" -type f -newermt "@${_bt}" 2>/dev/null | grep -c .) || _n=0
      printf '  %-28s %s file(s)\n' "$_p" "$_n"
      [ "${_n:-0}" -gt 0 ] && find "${WP_ROOT}/${_p}" -type f -newermt "@${_bt}" 2>/dev/null \
        | head -15 | sed "s|${WP_ROOT}/|      |"
    done
    echo ""
    _note "Plugin and theme changes are expected after an update. Uploads and"
    _note "mu-plugins are not — a new file in either is worth explaining." ;;

  admins)
    _hdr "WordPress accounts"
    _pfx=$(podman exec mariadb sh -c 'printf %s "${WORDPRESS_TABLE_PREFIX:-wp_}"' 2>/dev/null || printf 'wp_')
    podman exec mariadb sh -c \
      'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -N -B "${WORDPRESS_DB_NAME:-wordpress}" -e "$1"' _ \
      "SELECT u.user_login, u.user_email, u.user_registered,
              SUBSTRING(m.meta_value,1,60)
       FROM ${_pfx}users u
       JOIN ${_pfx}usermeta m ON u.ID=m.user_id
       WHERE m.meta_key='${_pfx}capabilities'
       ORDER BY u.user_registered DESC;" 2>/dev/null \
      | sed 's/^/  /' || echo "  Could not query the database."
    echo ""
    _note "An administrator you did not create is persistence: it survives"
    _note "cleaning the file that created it. Check registration dates against"
    _note "the timeline — an account appearing minutes after a suspicious file"
    _note "is the same event, not two." ;;

  entry-class)
    _hdr "How did this get in? — decision tree"
    cat <<'TREE'
  Work down. The first that matches is usually it; more than one can be true.

  A. UPLOADS WEBSHELL
     PHP in wp-content/uploads.
       wp-malware-scan.sh structural
       wp-forensics.sh timeline --around <the file>
       wp-plugins.sh vulns
     Most upload shells arrive through a known plugin vulnerability, not a
     guessed password. Look for a POST to a plugin endpoint near the mtime.

  B. PLUGIN OR THEME BACKDOOR
     YARA or integrity hit under plugins/ or themes/.
       wp-plugins.sh status ; wp-plugins.sh vulns
       wp-forensics.sh since-backup
     Was it installed or updated just before the file date? With no matching
     CVE, suspect a nulled or pirated package.

  C. COMPROMISED ADMIN
     Rogue account, or broad changes with no plugin CVE to explain them.
       wp-forensics.sh admins
       wp-forensics.sh timeline --hours 168
       podman exec crowdsec cscli alerts list
     Look for a successful login from an unfamiliar address before the change.

  D. CORE FILE CHANGE
     wp-malware-scan.sh core reports a mismatch against the pinned image.
     Rarely random — usually filesystem access, a bad plugin, or supply chain.
     Restore core from the pinned image rather than editing by hand:
       update.sh wp <same-tag>

  THEN: fix the CAUSE, not the symptom. A cleaned site with the original
  vulnerability is compromised again, usually within days.
TREE
    ;;

  *) sed -n '4,12p' "$0" ;;
esac
