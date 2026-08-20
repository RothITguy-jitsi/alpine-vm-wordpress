#!/usr/bin/env bash
# =============================================================================
# wasp-sign-release.sh
# =============================================================================
# Drop this in the ROOT of the unzipped WASP folder — beside install.sh — and
# run it. It signs everything and verifies its own work.
#
#     ./wasp-sign-release.sh --init          once, to create your signing key
#     ./wasp-sign-release.sh                 every time you publish
#
# Needs only bash, coreutils and minisign. Nothing to install, nothing to run
# in GitHub, no Python.
#
# DELETE THIS FILE BEFORE UPLOADING THE FOLDER. It is not part of the project
# and only ever runs on the machine holding your secret key. The script says so
# again when it finishes.
# =============================================================================
set -uo pipefail          # NOT -e: every failure below is reported explicitly

MANIFEST="MANIFEST.sha256"
SELF="$(basename "${BASH_SOURCE[0]}")"
VERSION=""
INIT=0
CHECK=0

R=$'\033[31m'; G=$'\033[32m'; Y=$'\033[33m'; B=$'\033[1m'; N=$'\033[0m'
die()  { printf '\n%sERROR:%s %s\n\n' "$R" "$N" "$1" >&2; exit 1; }
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$1"; }
warn() { printf '  %s⚠%s %s\n' "$Y" "$N" "$1"; }
say()  { printf '%s\n' "$1"; }

# ── minisign, checked only where it is needed ────────────────────────────────
# Deliberately not checked at the top: running this from the wrong folder
# should say "wrong folder", not "install minisign" — an error that sends you
# to fix something unrelated is worse than no error. --check needs nothing at
# all beyond bash and coreutils.
need_minisign() {
  command -v minisign >/dev/null 2>&1 && return 0
  cat >&2 <<'MSG'

ERROR: minisign is not installed.

  Bazzite / Silverblue / any immutable Fedora:
      brew install minisign

  If you do not have Homebrew and would rather not install it, the release
  binary needs no installation at all — unpack it and use it in place:

      curl -LO https://github.com/jedisct1/minisign/releases/latest/download/minisign-0.12-linux.tar.gz
      tar xzf minisign-0.12-linux.tar.gz
      export PATH="$PWD/minisign-linux/x86_64:$PATH"

  (Check the releases page for the current version — that filename will go
  stale. Everything else here needs nothing beyond bash and coreutils.)

MSG
  exit 1
}


while [[ $# -gt 0 ]]; do
  case "$1" in
    --init)    INIT=1; shift ;;
    --check)   CHECK=1; shift ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

# ── Key creation ─────────────────────────────────────────────────────────────
if [[ $INIT -eq 1 ]]; then
  need_minisign
  if [[ -f "$HOME/.minisign/minisign.key" ]]; then
    die "A key already exists at ~/.minisign/minisign.key

  Refusing to overwrite it: doing so makes every release you have already
  signed unverifiable, and users would see a key change — which looks exactly
  like an attack.

  To rotate on purpose:
      mkdir -p ~/.minisign/old
      mv ~/.minisign/minisign.key ~/.minisign/minisign.pub ~/.minisign/old/
  then re-run --init and update BOTH install.sh and your DNS record."
  fi
  mkdir -p "$HOME/.minisign"
  say ""
  say "Creating your signing key."
  say "You will be asked for a passphrase twice. Use a real one — an"
  say "unencrypted secret key is a file anyone reading your disk can sign"
  say "releases with."
  say ""
  ( cd "$HOME/.minisign" && minisign -G ) || die "Key generation failed."
  PUB=$(grep -v '^untrusted comment' "$HOME/.minisign/minisign.pub")
  say ""
  say "=================================================================="
  printf ' %sYOUR PUBLIC KEY%s\n' "$B" "$N"
  say "=================================================================="
  say ""
  say "    ${PUB}"
  say ""
  say " 1. Put it in install.sh — find the WASP_PUBKEY line and make it:"
  say ""
  say "      WASP_PUBKEY=\"\${WASP_PUBKEY:-${PUB}}\""
  say ""
  say " 2. Add it as a DNS TXT record on your domain:"
  say ""
  say "      name  : minisign._wasp"
  say "      value : ${PUB}"
  say ""
  say "    Paste ONLY that line — not the key ID, not the comment line."
  say "    install.sh compares the whole record against the embedded key."
  say ""
  say "    The reason DNS is worth using is that it lives at your registrar,"
  say "    under different credentials from GitHub. If someone took over the"
  say "    repository they could swap the key inside install.sh, but not the"
  say "    one in DNS — so the mismatch becomes visible."
  say ""
  say " 3. Back up ~/.minisign/minisign.key somewhere offline, now."
  say "    Lose it and every future release needs a new key."
  say ""
  exit 0
fi

# ── Are we in the right folder? ──────────────────────────────────────────────
# Checked rather than assumed. An earlier version guessed the location and,
# when guessed wrong, exited silently — which for a signing tool is the worst
# possible failure, because it looks like it worked and the release ships
# unsigned.
if [[ ! -f install.sh || ! -d lib || ! -d payload ]]; then
  die "This does not look like the WASP folder.

  Expected to find install.sh, lib/ and payload/ here.
  Currently in: $PWD

  Put this script in the root of the unzipped folder, next to install.sh,
  then run it from there:
      cd /path/to/alpine-vm-wordpress
      ./${SELF}"
fi

say ""
printf '%sWASP release signing%s\n' "$B" "$N"
say "Folder: $PWD"
say ""

# ── Collect every shipped file ───────────────────────────────────────────────
# Everything under install.sh, lib/ and payload/ — no extension filter.
#
# That is deliberate. An earlier version picked files by extension (*.sh,
# *.php, *.conf, ...) and payload/mariadb-conf/wp.cnf shipped UNSIGNED because
# .cnf was not on the list. A list of what to include silently omits anything
# it does not name, and nothing complains — so a tampered database config
# would have passed every signature check.
#
# -print0 / -d '' throughout, because folder paths often contain spaces.
FILES=(install.sh)
while IFS= read -r -d '' f; do FILES+=("$f"); done \
  < <(find lib payload -type f -print0 2>/dev/null)

(( ${#FILES[@]} > 1 )) || die "Found almost nothing to sign — is the folder complete?"

if [[ $CHECK -eq 1 ]]; then
  say "Would sign ${#FILES[@]} file(s):"
  printf '%s\0' "${FILES[@]}" | sort -z | tr '\0' '\n' | sed 's/^/  /'
  say ""
  say "Nothing was signed (--check)."
  exit 0
fi

# Only needed from here on. --check above lists files and needs nothing.
need_minisign

[[ -n "$VERSION" ]] || VERSION="$(date -u +%Y.%m.%d)"

say "Hashing ${#FILES[@]} files…"
printf '%s\0' "${FILES[@]}" | LC_ALL=C sort -z | xargs -0 sha256sum > "$MANIFEST" \
  || die "Could not write $MANIFEST"

COUNT=$(wc -l < "$MANIFEST")
(( COUNT == ${#FILES[@]} )) || die "Found ${#FILES[@]} files but the manifest has ${COUNT} lines.
  Something was skipped. Do not publish this."
ok "${COUNT} files hashed"

# ── Coverage: nothing shipped may be missing ─────────────────────────────────
# Recomputed independently of the list above, so a mistake in how FILES was
# built shows up here rather than shipping. This is the check that would have
# caught wp.cnf.
MISSING=0
while IFS= read -r -d '' f; do
  grep -qF "  ${f}" "$MANIFEST" || { warn "NOT SIGNED: $f"; MISSING=$((MISSING+1)); }
done < <(find lib payload -type f -print0 2>/dev/null)
grep -qF "  install.sh" "$MANIFEST" || { warn "NOT SIGNED: install.sh"; MISSING=$((MISSING+1)); }
(( MISSING == 0 )) || die "${MISSING} shipped file(s) are missing from the manifest."
ok "Every file under lib/ and payload/ is covered"

# ── Find the signing key ─────────────────────────────────────────────────────
KEYFILE=""
for cand in "${MINISIGN_KEY:-}" "$HOME/.minisign/minisign.key" "./minisign.key"; do
  [[ -n "$cand" && -f "$cand" ]] && { KEYFILE="$cand"; break; }
done
[[ -n "$KEYFILE" ]] || die "No signing key found.

  Looked in: ~/.minisign/minisign.key and this folder.
  Create one first:   ./${SELF} --init"

# A secret key inside this folder is one upload away from being public.
# Refused rather than warned about: a warning scrolls past, and the outcome is
# that every signature you have ever made becomes meaningless.
KEYDIR=$(cd "$(dirname "$KEYFILE")" && pwd)
if [[ "$KEYDIR" == "$PWD" || "$KEYDIR" == "$PWD"/* ]]; then
  die "Your signing key is inside this folder:
      ${KEYFILE}

  If this folder is uploaded, the key goes with it — and anyone could then
  sign a release as you.

  Move it out first:
      mkdir -p ~/.minisign
      mv minisign.key minisign.pub ~/.minisign/
      chmod 600 ~/.minisign/minisign.key"
fi

PUBFILE="${KEYFILE%.key}.pub"
[[ -f "$PUBFILE" ]] || PUBFILE="$HOME/.minisign/minisign.pub"
[[ -f "$PUBFILE" ]] || die "Found your secret key but not the public one.

  It can be regenerated from the secret key — nothing is lost:
      minisign -R -s ${KEYFILE} -p ${KEYFILE%.key}.pub"

# ── Sign ─────────────────────────────────────────────────────────────────────
say ""
say "Signing with ${KEYFILE}"
say "(enter your passphrase when asked)"
say ""
# The trusted comment is covered by the signature, so the version it names
# cannot be altered without the secret key. That is what stops someone
# re-serving an older, correctly-signed release as if it were current.
minisign -Sm "$MANIFEST" -s "$KEYFILE" \
  -t "WASP ${VERSION} | $(date -u +%Y-%m-%dT%H:%M:%SZ) | ${COUNT} files" \
  || die "Signing failed — wrong passphrase, or the key could not be read."

[[ -f "${MANIFEST}.minisig" ]] || die "minisign said it succeeded but wrote no signature file."

# ── Verify, exactly as install.sh will ───────────────────────────────────────
# Signing without checking the result is how a broken release ships.
say ""
say "Verifying, the same way install.sh will…"
PUB=$(grep -v '^untrusted comment' "$PUBFILE")
minisign -Vm "$MANIFEST" -P "$PUB" >/dev/null 2>&1 \
  || die "The signature just created does NOT verify. Do not publish this."
ok "Signature verifies"
sha256sum -c --quiet "$MANIFEST" \
  || die "A file does not match the manifest that was just written."
ok "All ${COUNT} file hashes match"

if grep -qF "$PUB" install.sh 2>/dev/null; then
  ok "install.sh carries this key"
else
  say ""
  warn "install.sh does NOT contain this public key."
  say "     Every install will refuse to proceed. Edit install.sh so the line reads:"
  say ""
  say "       WASP_PUBKEY=\"\${WASP_PUBKEY:-${PUB}}\""
  say ""
  say "     Then run this script again."
fi

say ""
say "=================================================================="
printf ' %sDone%s\n' "$B" "$N"
say "=================================================================="
say ""
say "  Created:  ${MANIFEST}"
say "            ${MANIFEST}.minisig"
say ""
say "  Upload the folder — including those two files and install.sh."
say ""
printf '  %sBefore you upload, delete this script from the folder:%s\n' "$B" "$N"
say "      rm ${SELF}"
say ""
say "  It is not part of the project, and it only ever needs to run on the"
say "  machine that holds your key."
say ""
