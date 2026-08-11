#!/bin/sh
# =============================================================================
# wp-import.sh — get a site backup onto this VM, and see what is in it
# =============================================================================
#   wp-import.sh where                 how to get an archive here
#   wp-import.sh fetch s3 <path>       pull from your object storage
#   wp-import.sh fetch url <url> [sha256]
#   wp-import.sh list                  what has arrived
#   wp-import.sh inspect <file>        what is inside it — NOTHING is extracted
#   wp-import.sh extract <file>        unpack to staging, outside the docroot
#   wp-import.sh scan [id]             scan staged files AND the dump
#   wp-import.sh staged                what is currently staged
#   wp-import.sh apply [id]            normalise, import, re-harden
#
# This is steps 1 and 2 of docs/IMPORT-DESIGN.md: get the archive here, and
# report what it contains. It does not extract, import, or modify anything.
#
# `inspect` is deliberately the first thing built. "Tell me what is in this
# backup before I touch it" is useful on its own, and it is the only part of
# the import pipeline with no destructive failure mode. Everything after it
# writes to disk; this only reads.
#
# WHY INSPECT NEVER EXTRACTS
#
# Reading an archive's index is safe. Extracting is where path traversal,
# symlink escapes and decompression bombs happen. Those are checked HERE,
# against the listing, so a hostile archive is refused before any of its
# contents exist on disk.
# =============================================================================
set -u

if [ "$(id -u)" -ne 0 ]; then
  if command -v doas >/dev/null 2>&1; then exec doas "$0" "$@"; fi
  echo "Run as root (or via doas)" >&2; exit 1
fi
[ -r /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh

INBOX=/var/lib/wasp-import/incoming
STAGING=/var/lib/wasp-import/staging
WP_ROOT=/home/wpuser/wp/html
RCLONE_CONF=/etc/wp-install/rclone.conf
mkdir -p "$INBOX" "$STAGING" 2>/dev/null || true
chmod 700 "$STAGING" 2>/dev/null || true
chmod 750 "$INBOX" 2>/dev/null || true

_ok()   { printf '  \033[32m✔\033[0m  %s\n' "$1"; }
_bad()  { printf '  \033[31m✗\033[0m  %s\n' "$1" >&2; }
_warn() { printf '  \033[33m⚠\033[0m  %s\n' "$1"; }
_note() { printf '     %s\n' "$1"; }
_hdr()  { printf '\n\033[1m%s\033[0m\n%s\n' "$1" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

case "${1:-where}" in

# ── How to get a file here ───────────────────────────────────────────────────
where)
  cat <<INSTRUCTIONS

Getting a backup onto this VM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Everything lands in ${INBOX}

  Pick whichever is least effort. They are equivalent afterwards.

  1. OBJECT STORAGE — easiest if you already configured off-VM backups
  ─────────────────────────────────────────────────────────────────────
     The same credentials already work; nothing new to set up.

       Upload the file to your bucket from any machine, then:
         wp-import.sh fetch s3 <bucket>/<path>/backup.zip

     No object storage? Cloudflare R2's free tier is 10 GB, which is
     more than most WordPress sites, and a browser upload avoids the
     command line entirely.

  2. SFTP — familiar, works from FileZilla/WinSCP/Cyberduck
  ─────────────────────────────────────────────────────────
       Host      : $(hostname) (${VM_STATIC_IP:-this VM's address})
       Port      : 22
       User      : ${ADMIN_USER:-<your admin user>}
       Directory : ${INBOX}

     Drag the file in. SSH here only accepts a key, so use the same key
     you use for the terminal.

     From a command line instead:
       scp backup.zip ${ADMIN_USER:-admin}@${VM_STATIC_IP:-vm-ip}:${INBOX}/

  3. DIRECT LINK — Dropbox, Drive, WeTransfer, anywhere with a URL
  ────────────────────────────────────────────────────────────────
       wp-import.sh fetch url 'https://…/backup.zip'

     Use the DIRECT download link, not the share page — a share page
     downloads an HTML file that looks like a backup and is not one.
     Most services offer "copy download link" separately.

  4. FROM THE PROXMOX HOST — if the file is already there
  ───────────────────────────────────────────────────────
       scp /path/to/backup.zip root@${VM_STATIC_IP:-vm-ip}:${INBOX}/

  ── Then ──────────────────────────────────────────────────────────
       wp-import.sh list
       wp-import.sh inspect <file>

  Inspect only reads. It will not extract or install anything, so it is
  safe to run on a backup you do not trust — which is the point.

  ── Space ─────────────────────────────────────────────────────────
       $(df -h / | awk 'NR==2{print "  "$4" free of "$2}')

  Allow roughly three times the archive size: the file, its extraction,
  and working room. Running out mid-import leaves a broken site and no
  import, so this is checked before anything starts.

INSTRUCTIONS
  ;;

# ── Fetch ────────────────────────────────────────────────────────────────────
fetch)
  _m="${2:-}"; _src="${3:-}"; _sum="${4:-}"
  [ -n "$_src" ] || { echo "Usage: wp-import.sh fetch [s3|url] <source> [sha256]" >&2; exit 1; }

  # Refuse early rather than filling the disk. A failed import that also took
  # the live site down with it is the worst outcome available here.
  _free=$(df -Pk / | awk 'NR==2{print $4}')
  [ "${_free:-0}" -lt 2097152 ] && {
    _bad "Less than 2 GB free. Fetching could fill the disk and take the site down."
    _note "wp-hardening.sh disk"
    exit 1; }

  case "$_m" in
    s3|rclone)
      command -v rclone >/dev/null 2>&1 || { _bad "rclone not installed: apk add rclone"; exit 1; }
      [ -r "$RCLONE_CONF" ] || {
        _bad "No rclone configuration at ${RCLONE_CONF}"
        _note "Off-VM backup sets this up. Configure it, or use: wp-import.sh fetch url <url>"
        exit 1; }
      # Reuse the remote already configured for backups. A second set of
      # credentials for the same bucket is a second thing to rotate and
      # forget.
      _rem=$(sed -n 's/^\[\(.*\)\]$/\1/p' "$RCLONE_CONF" | head -1)
      case "$_src" in *:*) _full="$_src" ;; *) _full="${_rem}:${_src}" ;; esac
      _note "Fetching ${_full} …"
      rclone --config "$RCLONE_CONF" copy --progress "$_full" "$INBOX/" || {
        _bad "Fetch failed."
        _note "List what is there:  rclone --config ${RCLONE_CONF} ls ${_rem}:"
        exit 1; }
      ;;
    url)
      case "$_src" in https://*|http://*) : ;; *) _bad "Give a http(s) URL"; exit 1 ;; esac
      _name=$(basename "${_src%%\?*}")
      case "$_name" in ''|*/*) _name="import-$(date -u +%Y%m%d-%H%M%S).bin" ;; esac
      _note "Downloading to ${INBOX}/${_name} …"
      curl -fL --progress-bar -o "${INBOX}/${_name}" "$_src" || { _bad "Download failed."; exit 1; }
      # A share page returns HTML that is the right shape and the wrong thing.
      # Catching it here saves a confusing failure three steps later.
      if head -c 512 "${INBOX}/${_name}" | grep -qi '<!doctype html\|<html'; then
        _bad "That downloaded an HTML page, not an archive."
        _note "You probably used the share link. Look for 'copy download link' instead."
        rm -f "${INBOX}/${_name}"; exit 1
      fi
      if [ -n "$_sum" ]; then
        _got=$(sha256sum "${INBOX}/${_name}" | awk '{print $1}')
        [ "$_got" = "$_sum" ] && _ok "Checksum matches" || {
          _bad "CHECKSUM MISMATCH — the file is not what you expected."
          _note "expected ${_sum}"; _note "got      ${_got}"
          rm -f "${INBOX}/${_name}"; exit 1; }
      else
        _warn "No checksum given. The download is unverified."
        _note "If you have one:  wp-import.sh fetch url <url> <sha256>"
      fi
      ;;
    *) echo "Usage: wp-import.sh fetch [s3|url] <source> [sha256]" >&2; exit 1 ;;
  esac
  chmod 640 "$INBOX"/* 2>/dev/null || true
  _ok "Done. Next:  wp-import.sh list"
  ;;

# ── List ─────────────────────────────────────────────────────────────────────
list)
  _hdr "Archives in ${INBOX}"
  if [ -z "$(ls -A "$INBOX" 2>/dev/null)" ]; then
    echo "  (empty)"
    echo ""
    echo "  How to get one here:  wp-import.sh where"
    exit 0
  fi
  ls -lh "$INBOX" | tail -n +2 | awk '{printf "  %-46s %8s  %s %s\n", $9, $5, $6, $7}'
  echo ""
  echo "  Inspect one:  wp-import.sh inspect <name>"
  df -h / | awk 'NR==2{printf "  Disk: %s free of %s\n", $4, $2}'
  ;;

# ── Inspect ──────────────────────────────────────────────────────────────────
inspect)
  _f="${2:-}"
  [ -n "$_f" ] || { echo "Usage: wp-import.sh inspect <file>" >&2; exit 1; }
  [ -f "$_f" ] || _f="${INBOX}/${_f}"
  [ -f "$_f" ] || { _bad "Not found: ${2}"; _note "wp-import.sh list"; exit 1; }

  _hdr "Inspecting $(basename "$_f")"
  _sz=$(stat -c %s "$_f"); _szh=$(du -h "$_f" | cut -f1)
  printf '  Size : %s\n  Type : %s\n\n' "$_szh" "$(file -b "$_f" 2>/dev/null || echo unknown)"

  # ── Format ────────────────────────────────────────────────────────────────
  _fmt="unknown"; _listing=""
  case "$(basename "$_f")" in
    *.wpress)
      _fmt="All-in-One WP Migration (.wpress)"
      _warn "Custom binary format — not a standard archive."
      _note "Extract it on your workstation first with a .wpress extractor,"
      _note "then bring the resulting folder here. Native support is planned."
      echo ""; exit 0 ;;
    backup_*-db.gz|backup_*.gz) _fmt="UpdraftPlus (database part)" ;;
    backup_*.zip)               _fmt="UpdraftPlus (files part)" ;;
  esac

  if tar -tzf "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="tar.gz"
    _listing=$(tar -tzf "$_f" 2>/dev/null)
  elif unzip -l "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="zip"
    _listing=$(unzip -Z1 "$_f" 2>/dev/null)
  elif gzip -t "$_f" >/dev/null 2>&1; then
    [ "$_fmt" = "unknown" ] && _fmt="gzip (probably a SQL dump)"
  fi
  printf '  Format : %s\n' "$_fmt"

  # ── Hostile members — checked BEFORE anything is extracted ────────────────
  # This is the reason inspect exists as a separate step. Every item here is
  # something that does damage at extraction time, so it has to be caught
  # while the contents are still only names in an index.
  if [ -n "$_listing" ]; then
    _n=$(printf '%s\n' "$_listing" | grep -c .) || _n=0
    printf '  Members: %s\n\n' "$_n"

    _hostile=0
    _trav=$(printf '%s\n' "$_listing" | grep -c '\.\./') || _trav=0
    [ "${_trav:-0}" -gt 0 ] && { _bad "${_trav} member(s) contain '../' — path traversal"
      _note "Extraction would write OUTSIDE the target directory."
      _hostile=$(( _hostile + _trav )); }
    _abs=$(printf '%s\n' "$_listing" | grep -c '^/') || _abs=0
    [ "${_abs:-0}" -gt 0 ] && { _bad "${_abs} member(s) use absolute paths"; _hostile=$(( _hostile + _abs )); }
    if tar -tzvf "$_f" >/dev/null 2>&1; then
      _lnk=$(tar -tzvf "$_f" 2>/dev/null | grep -c '^l') || _lnk=0
      [ "${_lnk:-0}" -gt 0 ] && { _bad "${_lnk} symlink(s)"
        _note "A backup does not need symlinks. They can point outside the target."
        _hostile=$(( _hostile + _lnk )); }
    fi
    [ "$_hostile" -eq 0 ] && _ok "No path traversal, absolute paths or symlinks"

    # ── Content the operator should know about ──────────────────────────────
    echo ""
    _dup=$(printf '%s\n' "$_listing" | grep -c 'installer\.php$') || _dup=0
    [ "${_dup:-0}" -gt 0 ] && { _bad "Contains Duplicator's installer.php"
      _note "This is a documented site-takeover vector. It will be deleted,"
      _note "never executed — do not run it yourself either."; }

    _php=$(printf '%s\n' "$_listing" | grep -cE 'wp-content/uploads/.*\.(php|phtml|phar)$') || _php=0
    [ "${_php:-0}" -gt 0 ] && { _bad "${_php} executable PHP file(s) inside uploads"
      _note "Nothing legitimate puts PHP there. This is the single strongest"
      _note "indicator that the source site was compromised."; }
    [ "${_php:-0}" -eq 0 ] && _ok "No PHP in uploads"

    _mu=$(printf '%s\n' "$_listing" | grep -c 'wp-content/mu-plugins/') || _mu=0
    [ "${_mu:-0}" -gt 0 ] && _warn "${_mu} must-use plugin file(s) — active on arrival, no activation step"

    _cfg=$(printf '%s\n' "$_listing" | grep -c 'wp-config\.php$') || _cfg=0
    [ "${_cfg:-0}" -gt 0 ] && _note "Contains wp-config.php — will be discarded; this VM's own config wins"

    _core=$(printf '%s\n' "$_listing" | grep -c '^\(\./\)\?wp-includes/') || _core=0
    [ "${_core:-0}" -gt 0 ] && _note "Contains WordPress core — will be discarded in favour of the pinned image"

    _plug=$(printf '%s\n' "$_listing" | grep -oE 'wp-content/plugins/[^/]+' | sort -u | grep -c .) || _plug=0
    _thm=$(printf '%s\n' "$_listing" | grep -oE 'wp-content/themes/[^/]+' | sort -u | grep -c .) || _thm=0
    echo ""
    printf '  Plugins: %s   Themes: %s\n' "$_plug" "$_thm"

    # ── Expansion ratio ─────────────────────────────────────────────────────
    _un=$(tar -tzvf "$_f" 2>/dev/null | awk '{s+=$3} END{print s+0}')
    if [ "${_un:-0}" -gt 0 ]; then
      _ratio=$(( _un / (_sz > 0 ? _sz : 1) ))
      printf '  Expands to roughly %s (ratio %sx)\n' "$(numfmt --to=iec "$_un" 2>/dev/null || echo "${_un}B")" "$_ratio"
      [ "$_ratio" -gt 100 ] && _warn "Very high compression ratio — possible decompression bomb"
      _need=$(( _un / 1024 * 3 ))
      _free=$(df -Pk / | awk 'NR==2{print $4}')
      [ "${_free:-0}" -lt "$_need" ] && _bad "Not enough disk: needs ~$(( _need / 1048576 ))GB free, have $(( _free / 1048576 ))GB"
    fi

    echo ""
    if [ "$_hostile" -gt 0 ]; then
      _bad "REFUSED: this archive contains members that would write outside"
      _bad "the extraction directory. There is no legitimate reason for that."
      exit 2
    fi
    if [ "${_php:-0}" -gt 0 ] || [ "${_dup:-0}" -gt 0 ]; then
      _warn "Findings above. Importable, but treat the source as compromised:"
      _note "the flagged files will be quarantined rather than installed."
      exit 1
    fi
    _ok "Nothing structurally hostile found."
    _note "This is an index check, not a malware scan — a backdoored plugin"
    _note "looks exactly like a normal one from here. The full scan runs on"
    _note "the extracted contents, before anything is imported."
  else
    _note "Could not read an index. If this is a SQL dump, that is expected."
    printf '  First lines:\n'
    { gzip -dc "$_f" 2>/dev/null || cat "$_f"; } | head -5 | sed 's/^/    /'
  fi
  ;;

# ── Extract ──────────────────────────────────────────────────────────────────
extract)
  _f="${2:-}"
  [ -n "$_f" ] || { echo "Usage: wp-import.sh extract <file>" >&2; exit 1; }
  [ -f "$_f" ] || _f="${INBOX}/${_f}"
  [ -f "$_f" ] || { _bad "Not found: ${2}"; exit 1; }

  # Re-run the hostile-member checks. inspect already did this, but extraction
  # must not depend on the operator having run inspect first -- a security
  # check that only fires when someone remembers to ask for it is not a
  # control.
  _listing=""
  tar -tzf "$_f" >/dev/null 2>&1 && _listing=$(tar -tzf "$_f" 2>/dev/null)
  [ -z "$_listing" ] && unzip -l "$_f" >/dev/null 2>&1 && _listing=$(unzip -Z1 "$_f" 2>/dev/null)
  if [ -n "$_listing" ]; then
    _h=0
    printf '%s\n' "$_listing" | grep -q '\.\./' && { _bad "Path traversal in archive members"; _h=1; }
    printf '%s\n' "$_listing" | grep -q '^/'      && { _bad "Absolute paths in archive members"; _h=1; }
    tar -tzvf "$_f" 2>/dev/null | grep -q '^l'     && { _bad "Symlinks in archive"; _h=1; }
    [ "$_h" = 1 ] && { _bad "Refusing to extract. Nothing legitimate needs these."; exit 2; }
  fi

  _id="$(date -u +%Y%m%d-%H%M%S)-$(basename "$_f" | tr -c 'a-zA-Z0-9._-' '_' | cut -c1-32)"
  _st="${STAGING}/${_id}"
  mkdir -p "${_st}/files" "${_st}/db"
  chmod 700 "$_st"

  # Space check before writing, not after. Running out mid-extract leaves a
  # half-populated staging directory and a disk too full for the live site to
  # write its own logs or backups.
  _un=$(tar -tzvf "$_f" 2>/dev/null | awk '{s+=$3} END{print s+0}')
  if [ "${_un:-0}" -gt 0 ]; then
    _needk=$(( _un / 1024 + 524288 ))
    _freek=$(df -Pk / | awk 'NR==2{print $4}')
    [ "${_freek:-0}" -lt "$_needk" ] && {
      _bad "Not enough disk: needs ~$(( _needk / 1048576 ))GB, have $(( _freek / 1048576 ))GB"
      rm -rf "$_st"; exit 1; }
  fi

  _note "Extracting to ${_st}/files …"
  # --no-same-owner / --no-same-permissions: never honour ownership or mode
  # bits from an untrusted archive. A setuid binary or a root-owned file
  # inside a client's backup is not something to reproduce faithfully.
  if tar -tzf "$_f" >/dev/null 2>&1; then
    tar -xzf "$_f" -C "${_st}/files" --no-same-owner --no-same-permissions 2>/dev/null \
      || { _bad "Extraction failed"; rm -rf "$_st"; exit 1; }
  elif unzip -l "$_f" >/dev/null 2>&1; then
    unzip -q -o "$_f" -d "${_st}/files" 2>/dev/null \
      || { _bad "Extraction failed"; rm -rf "$_st"; exit 1; }
  elif gzip -t "$_f" >/dev/null 2>&1; then
    cp "$_f" "${_st}/db/$(basename "$_f")"
    _note "Gzip input treated as a database dump"
  else
    _bad "Unrecognised archive format"; rm -rf "$_st"; exit 1
  fi

  # Nothing extracted is executable. The staging directory is not served and
  # nothing here should be run, so removing the bit costs nothing and removes
  # a whole class of accident -- including an operator or a script invoking
  # something from the archive without meaning to.
  find "${_st}/files" -type f -exec chmod a-x {} + 2>/dev/null || true
  find "${_st}/files" -type d -exec chmod 700 {} + 2>/dev/null || true

  # Duplicator's installer is removed immediately, not at import. It is a
  # documented takeover vector and there is no stage at which keeping it is
  # useful.
  _dupn=$(find "${_st}/files" -name 'installer.php' -o -name 'installer-backup.php' 2>/dev/null | grep -c .) || _dupn=0
  if [ "${_dupn:-0}" -gt 0 ]; then
    find "${_st}/files" \( -name 'installer.php' -o -name 'installer-backup.php' \) -delete 2>/dev/null
    _warn "Removed ${_dupn} Duplicator installer file(s) — never executed"
  fi

  # Collect any SQL dumps into db/ so the scan knows where to look.
  find "${_st}/files" -maxdepth 3 \( -name '*.sql' -o -name '*.sql.gz' -o -name '*-db.gz' \) \
    -exec mv {} "${_st}/db/" \; 2>/dev/null || true

  _nf=$(find "${_st}/files" -type f 2>/dev/null | grep -c .) || _nf=0
  _nd=$(ls -1 "${_st}/db" 2>/dev/null | grep -c .) || _nd=0
  printf '%s\n' "$_id" > "${STAGING}/.latest"
  echo ""
  _ok "Extracted: ${_nf} file(s), ${_nd} database dump(s)"
  _note "Staging: ${_st}"
  _note "Nothing is executable and nothing is web-reachable."
  echo ""
  _note "Next:  wp-import.sh scan ${_id}"
  ;;

# ── Scan ─────────────────────────────────────────────────────────────────────
scan)
  _id="${2:-}"
  [ -n "$_id" ] || _id=$(cat "${STAGING}/.latest" 2>/dev/null)
  [ -n "$_id" ] || { echo "Usage: wp-import.sh scan <id>   (wp-import.sh staged)" >&2; exit 1; }
  _st="${STAGING}/${_id}"
  [ -d "$_st" ] || { _bad "No staging directory ${_id}"; exit 1; }

  _hdr "Scanning ${_id}"
  _crit=0; _high=0

  # ── Files: reuse the existing scanner against the staged tree ────────────
  if [ -x /usr/local/bin/wp-malware-scan.sh ]; then
    _note "File scan (structural + signatures) …"
    /usr/local/bin/wp-malware-scan.sh --path "${_st}/files" structural 2>&1 | sed 's/^/  /'
    _c=$(/usr/local/bin/wp-malware-scan.sh --path "${_st}/files" structural 2>/dev/null \
         | grep -c 'CRITICAL') || _c=0
    _crit=$(( _crit + _c ))
  else
    _warn "wp-malware-scan.sh not available — file scan skipped"
  fi

  # ── Database dump: scanned as a FILE, before it is ever loaded ───────────
  # This is the point of the exercise. Loading a dump and then querying it is
  # the same mistake as extracting into the docroot: by the time you look, the
  # thing you were checking for has already happened.
  _hdr "Database dump"
  _dumps=$(ls -1 "${_st}/db"/* 2>/dev/null)
  if [ -z "$_dumps" ]; then
    _warn "No SQL dump found. A files-only backup imports content but no site."
  else
    for _d in $_dumps; do
      printf '  %s (%s)\n' "$(basename "$_d")" "$(du -h "$_d" | cut -f1)"
      _rd() { case "$_d" in *.gz) gzip -dc "$_d" 2>/dev/null ;; *) cat "$_d" ;; esac; }

      # Autoloaded options are the highest-value target: they run on every
      # page load, are invisible in the filesystem, and survive any file clean.
      _ao=$(_rd | grep -ciE "INSERT INTO \`?wp[a-z0-9_]*options\`?.*(eval\(|base64_decode|<\?php|gzinflate|assert\()") || _ao=0
      if [ "${_ao:-0}" -gt 0 ]; then
        _bad "${_ao} option row(s) contain code"
        _note "Autoloaded options run on EVERY page load and survive a file clean."
        _crit=$(( _crit + _ao ))
      else _ok "No code in option rows"; fi

      # Scheduled events. A backdoor here re-creates files after you clean
      # them, and the operator concludes the malware "came back".
      # Quote-agnostic: mysqldump emits single quotes, but exports from
      # phpMyAdmin, Adminer and several backup plugins use double. A pattern
      # matching only one style silently passes the dumps produced by the
      # other -- and this check exists for the persistence mechanism most
      # likely to be missed, so failing quietly is the worst outcome.
      _cr=$(_rd | grep -ciE "['\"]cron['\"].*(eval|base64_decode|https?://)") || _cr=0
      if [ "${_cr:-0}" -gt 0 ]; then
        _bad "Scheduled-task (cron) option looks suspicious"
        _note "This is the persistence mechanism that makes malware appear to"
        _note "return after cleaning. The cron option is cleared at import."
        _high=$(( _high + 1 ))
      else _ok "Scheduled tasks look ordinary"; fi

      _ad=$(_rd | grep -c "administrator") || _ad=0
      printf '     %s row(s) mention administrator — review after import:\n' "$_ad"
      _note "wp-forensics.sh admins"

      _sp=$(_rd | grep -ciE "<script[^>]*>(eval|document\.write|atob)") || _sp=0
      [ "${_sp:-0}" -gt 0 ] && { _warn "${_sp} row(s) contain inline script — often injected SEO spam"
                                 _high=$(( _high + 1 )); } \
                            || _ok "No obvious injected script in content"

      _su=$(_rd | grep -oE "'siteurl','[^']*'" | head -1 | sed "s/.*,'//;s/'//")
      [ -n "$_su" ] && _note "Source siteurl: ${_su}  (rewritten at import)"
    done
  fi

  # ── Verdict ──────────────────────────────────────────────────────────────
  _hdr "Verdict"
  printf '  critical %s   high %s\n\n' "$_crit" "$_high"
  {
    printf '%s  id=%s critical=%s high=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_id" "$_crit" "$_high"
  } >> "${STAGING}/scan-log.txt"

  if [ "$_crit" -gt 0 ]; then
    _bad "CRITICAL findings. Import would carry a live compromise across."
    _note "Flagged files are quarantined rather than imported, but the source"
    _note "site should be treated as compromised: whatever put them there may"
    _note "also be in a plugin, a theme, or the database."
    _note ""
    _note "  wp-import.sh report ${_id}      full detail"
    _note "  wp-plugins.sh vulns             which plugin was the likely door"
    exit 2
  fi
  if [ "$_high" -gt 0 ]; then
    _warn "Findings worth reading before importing."
    exit 1
  fi
  _ok "Nothing critical found in the staged content."
  _note "That is a statement about what the scanners detect, not proof the"
  _note "site is clean. A backdoored plugin looks like a working plugin."
  ;;

# ── Staged ───────────────────────────────────────────────────────────────────
staged)
  _hdr "Staged imports"
  if [ -z "$(ls -A "$STAGING" 2>/dev/null | grep -v '^\.' )" ]; then
    echo "  (none)"; exit 0
  fi
  for _d in "$STAGING"/*/; do
    [ -d "$_d" ] || continue
    _fc=$(find "$_d/files" -type f 2>/dev/null | grep -c .) || _fc=0
    printf '  %-40s %8s  %s file(s)\n' "$(basename "$_d")" \
      "$(du -sh "$_d" 2>/dev/null | cut -f1)" "$_fc"
  done
  echo ""
  echo "  Scan:   wp-import.sh scan <id>"
  echo "  Remove: rm -rf ${STAGING}/<id>"
  [ -s "${STAGING}/scan-log.txt" ] && { echo ""; echo "  Scan history:"; tail -5 "${STAGING}/scan-log.txt" | sed 's/^/    /'; }
  ;;

# ── Apply ────────────────────────────────────────────────────────────────────
apply)
  _id="${2:-}"; shift 2 2>/dev/null || shift $# 
  [ -n "$_id" ] || _id=$(cat "${STAGING}/.latest" 2>/dev/null)
  _force=0; _accept=0
  for _a in "$@"; do
    case "$_a" in --force) _force=1 ;; --accept-findings) _accept=1 ;; esac
  done
  _st="${STAGING}/${_id}"
  [ -d "$_st" ] || { _bad "No staging directory ${_id}"; _note "wp-import.sh staged"; exit 1; }

  _hdr "Import ${_id}"

  # ── Gate ─────────────────────────────────────────────────────────────────
  # Refusing outright is wrong: people import compromised sites deliberately,
  # in order to clean them. Proceeding silently defeats the tool. So the gate
  # is graded, and every override is recorded.
  _last=$(grep "id=${_id}" "${STAGING}/scan-log.txt" 2>/dev/null | tail -1)
  if [ -z "$_last" ]; then
    _bad "This staging set has not been scanned."
    _note "wp-import.sh scan ${_id}"
    exit 1
  fi
  _c=$(printf '%s' "$_last" | sed -n 's/.*critical=\([0-9]*\).*/\1/p')
  _h=$(printf '%s' "$_last" | sed -n 's/.*high=\([0-9]*\).*/\1/p')
  printf '  Last scan: %s critical, %s high\n\n' "${_c:-?}" "${_h:-?}"
  if [ "${_c:-0}" -gt 0 ] && [ "$_force" != 1 ]; then
    _bad "CRITICAL findings. Refusing without --force."
    _note "Flagged files are quarantined rather than imported, but whatever put"
    _note "them there may also be in a plugin, a theme, or the database."
    _note "  wp-import.sh scan ${_id}"
    exit 2
  fi
  if [ "${_h:-0}" -gt 0 ] && [ "$_accept" != 1 ] && [ "$_force" != 1 ]; then
    _bad "HIGH findings. Re-run with --accept-findings to proceed."
    exit 1
  fi

  # ── Safety backup, mandatory ─────────────────────────────────────────────
  # Before anything is replaced. An import that goes wrong without this leaves
  # neither the old site nor a working new one.
  _note "Backing up the CURRENT site before replacing anything…"
  if ! /usr/local/bin/wp-db-backup.sh >/dev/null 2>&1; then
    _bad "Could not back up the current database. Refusing to import."
    _note "An import without a way back is not an import, it is a replacement."
    exit 1
  fi
  _ok "Current database backed up"

  echo ""
  _warn "This REPLACES the site's content, plugins, themes and database."
  _note "Core, wp-config.php, .htaccess and mu-plugins are NOT imported —"
  _note "this VM's own are kept, because those are exactly where a compromised"
  _note "source hides things that survive a content clean."
  printf "  Type IMPORT to proceed: "
  read -r _cf
  [ "$_cf" = "IMPORT" ] || { echo "  Cancelled — nothing changed."; exit 0; }

  # ── Normalise ────────────────────────────────────────────────────────────
  _hdr "Normalising"
  _q="${_st}/quarantined"; mkdir -p "$_q"
  _src="${_st}/files"
  # Some archives nest the site one level down.
  [ -d "${_src}/wp-content" ] || {
    _cand=$(find "$_src" -maxdepth 2 -type d -name wp-content 2>/dev/null | head -1)
    [ -n "$_cand" ] && _src=$(dirname "$_cand") && _note "Site root: ${_src#${_st}/}"; }

  for _drop in wp-config.php wp-config-sample.php .htaccess .user.ini; do
    [ -e "${_src}/${_drop}" ] && { mv "${_src}/${_drop}" "$_q/" 2>/dev/null
      _note "Withheld ${_drop} — this VM's own is authoritative"; }
  done
  for _cd in wp-admin wp-includes; do
    [ -d "${_src}/${_cd}" ] && { rm -rf "${_src:?}/${_cd}"
      _note "Discarded ${_cd} — core comes from the pinned image"; }
  done
  find "$_src" -maxdepth 1 -name 'wp-*.php' ! -name 'wp-config.php' -delete 2>/dev/null
  if [ -d "${_src}/wp-content/mu-plugins" ]; then
    mv "${_src}/wp-content/mu-plugins" "$_q/mu-plugins" 2>/dev/null
    _warn "Withheld mu-plugins — they activate on arrival with no opt-in"
  fi
  # Anything executable in uploads. Quarantined, not deleted: it is evidence.
  _qp=0
  find "${_src}/wp-content/uploads" -type f \
       \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) \
       2>/dev/null | while IFS= read -r _bf; do
    mkdir -p "$_q/uploads"; mv "$_bf" "$_q/uploads/" 2>/dev/null
  done
  _qp=$(find "$_q/uploads" -type f 2>/dev/null | grep -c .) || _qp=0
  [ "${_qp:-0}" -gt 0 ] && _warn "Quarantined ${_qp} executable file(s) from uploads"

  # ── Files ────────────────────────────────────────────────────────────────
  _hdr "Importing content"
  for _d in uploads plugins themes; do
    [ -d "${_src}/wp-content/${_d}" ] || continue
    mkdir -p "${WP_ROOT}/wp-content/${_d}"
    cp -a "${_src}/wp-content/${_d}/." "${WP_ROOT}/wp-content/${_d}/" 2>/dev/null
    _n=$(find "${_src}/wp-content/${_d}" -type f 2>/dev/null | grep -c .) || _n=0
    _ok "${_d}: ${_n} file(s)"
  done
  chown -R 33:33 "${WP_ROOT}/wp-content" 2>/dev/null || true
  find "${WP_ROOT}/wp-content/uploads" -type f -exec chmod 644 {} + 2>/dev/null || true

  # ── Database ─────────────────────────────────────────────────────────────
  _hdr "Importing database"
  _dump=$(ls -1 "${_st}/db"/* 2>/dev/null | head -1)
  if [ -z "$_dump" ]; then
    _warn "No dump — files imported, database unchanged."
  else
    _ourpfx=$(podman exec mariadb sh -c 'printf %s "${WORDPRESS_TABLE_PREFIX:-wp_}"' 2>/dev/null || printf 'wp_')
    _rd() { case "$_dump" in *.gz) gzip -dc "$_dump" ;; *) cat "$_dump" ;; esac; }
    _theirpfx=$(_rd | grep -oiE "INSERT INTO [\`\"']?[a-z0-9_]+options[\`\"']?" | head -1 \
                | grep -oE '[a-z0-9_]+options' | sed 's/options$//')
    [ -n "$_theirpfx" ] || _theirpfx="wp_"
    printf '  Source prefix: %s   This VM: %s\n' "$_theirpfx" "$_ourpfx"

    _sql="${_st}/db/normalised.sql"
    if [ "$_theirpfx" != "$_ourpfx" ]; then
      # Rewriting the prefix is NOT just table names. wp_capabilities,
      # wp_user_level and wp_user_roles are stored as meta_key / option_name
      # VALUES and carry the prefix too. Rewriting tables alone is the classic
      # "changed the prefix and lost admin access" — the user rows import
      # fine and nobody has any capabilities.
      _note "Rewriting prefix, including capability keys…"
      # Quote-agnostic on the meta keys. mysqldump emits single quotes;
      # phpMyAdmin, Adminer and several backup plugins emit double. Matching
      # only one style rewrites the table names and leaves the capability
      # keys alone -- which imports every user with NO capabilities and locks
      # the administrator out of the site that was just imported. That is the
      # classic "changed the prefix and lost admin access", and it presents as
      # a successful import.
      _rd | sed -E \
        -e "s/\`${_theirpfx}/\`${_ourpfx}/g" \
        -e "s/(['\"])${_theirpfx}(capabilities|user_level|user_roles|user-settings|user-settings-time|dashboard_quick_press_last_post_id)\\1/\\1${_ourpfx}\\2\\1/g" \
        > "$_sql"
    else
      _rd > "$_sql"
    fi

    if podman exec -i mariadb sh -c \
         'exec mariadb -u root -p"$MARIADB_ROOT_PASSWORD" "${WORDPRESS_DB_NAME:-wordpress}"' \
         < "$_sql" 2>/dev/null; then
      _ok "Database imported"
    else
      _bad "Database import FAILED. Files were copied; the database is unchanged"
      _bad "or partially loaded. The pre-import backup is the newest file in"
      _bad "/root/wp-db-backups."
      exit 1
    fi
    rm -f "$_sql"
  fi

  # ── Re-harden ────────────────────────────────────────────────────────────
  # An import undoes hardening: it carries the source site's URLs, users,
  # salts and scheduled tasks. Skipping this leaves a site configured for
  # somewhere else, with credentials someone else may know.
  _hdr "Re-hardening"
  # wp-cli runs in its OWN container: the official wordpress:*-apache image does
  # NOT ship wp-cli, so `podman exec wordpress wp ...` fails with "wp: not found".
  # This shares the running container's network and env-file so wp-config resolves
  # exactly as it does for the site itself.
  _wpcli_image() {
    _wi=$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env 2>/dev/null | tr -d '"' | head -1)
    [ -n "$_wi" ] || _wi="docker.io/library/wordpress:cli"
    printf '%s' "$_wi"
  }
  _wp() {
    podman run --rm \
      --network "container:wordpress" \
      --user 33:33 \
      --env-file /etc/wordpress/env \
      -e WORDPRESS_DB_HOST=mariadb:3306 \
      -v /home/wpuser/wp/html:/var/www/html \
      "$(_wpcli_image)" wp --path=/var/www/html "$@" 2>/dev/null
  }

  _url="${WP_SCHEME:-https}://${WP_DOMAIN:-localhost}"
  _wp option update home "$_url"    >/dev/null && _ok "home    -> ${_url}"
  _wp option update siteurl "$_url" >/dev/null && _ok "siteurl -> ${_url}"

  # The old salts may be known to whoever had the source site. Every existing
  # session is invalidated, which is the point.
  if _wp config shuffle-salts >/dev/null 2>&1; then
    _ok "Salts regenerated — all existing sessions invalidated"
  else
    _warn "Could not shuffle salts; wp-config may not be writable"
    _note "Old salts mean old session cookies still work. Rotate by hand."
  fi

  # Scheduled tasks are the persistence mechanism that survives a file clean.
  _wp option delete cron >/dev/null 2>&1 && _ok "Scheduled tasks cleared — WordPress will rebuild them"

  _wp cache flush >/dev/null 2>&1
  _wp rewrite flush >/dev/null 2>&1 && _ok "Permalinks flushed"

  echo ""
  _hdr "Administrators on the imported site"
  _wp user list --role=administrator --fields=ID,user_login,user_email,user_registered 2>/dev/null \
    | sed 's/^/  /' || _note "Could not list users — check by hand"
  echo ""
  _warn "Every account above can log in. Any you do not recognise is a backdoor."
  _note "  wp-forensics.sh admins"
  _note "Reset a password:  wp-plugins.sh doctor   then use wp-cli via the container (see SUPPORT-RUNBOOK.md)"

  # ── Record and verify ────────────────────────────────────────────────────
  {
    printf '%s  id=%s critical=%s high=%s force=%s quarantined=%s by=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_id" "${_c:-0}" "${_h:-0}" "$_force" "${_qp:-0}" \
      "${SUDO_USER:-${DOAS_USER:-${USER:-unknown}}}"
  } >> "${STAGING}/import-log.txt"
  chmod 600 "${STAGING}/import-log.txt" 2>/dev/null || true

  _hdr "Verify"
  _note "  validate-wordpress.sh"
  _note "  wp-malware-scan.sh full        the live site, not the staging copy"
  _note "  wp-plugins.sh vulns            you have just installed someone else's plugins"
  echo ""
  [ "${_qp:-0}" -gt 0 ] && _note "Quarantined files kept at ${_q} — evidence, not rubbish."
  _ok "Import complete. Recorded in ${STAGING}/import-log.txt"
  ;;

*) sed -n '4,10p' "$0" ;;
esac
