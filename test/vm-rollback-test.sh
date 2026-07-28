#!/bin/sh
# =============================================================================
# vm-rollback-test.sh — exercise update.sh's post-cutover ROLLBACK path
# =============================================================================
# RUN THIS ON THE VM, as root (via doas). TAKE A PROXMOX SNAPSHOT FIRST.
#
# WHAT IS BEING TESTED
#
# update.sh's cutover is: start a candidate → validate it → rename the live
# container to `wordpress-old` → start the new one as `wordpress` → validate
# THAT → drop `wordpress-old`. If the last validation fails, it must remove
# the new container, rename `wordpress-old` back, and start it.
#
# That final branch is the only significant path in this project that has
# never executed. It cannot be reached with a normal image, because it needs
# a candidate that PASSES validation and then a production container that
# FAILS it -- from the same image. So this injects the fault instead.
#
# HOW
#
# wp-health-check.sh is temporarily replaced with a wrapper that:
#   • passes through to the real script for the CANDIDATE container, and
#   • fails for the container named `wordpress` (the post-cutover check).
# The two calls are distinguishable by their first argument, so the injection
# is precise: everything up to the cutover behaves exactly as in production,
# and only the post-cutover verdict is forced.
#
# This is a real fault-injection test, not a simulation: the actual rename,
# restore and restart code runs.
#
# SAFETY
#
#   • The real health check is restored on EVERY exit path, including Ctrl-C,
#     via a trap -- not just on the happy path.
#   • Nothing is destroyed deliberately. If rollback works, the VM ends on the
#     image it started on.
#   • If rollback FAILS, the site may be down. That is the finding, and the
#     script prints the manual recovery commands.
#   • A Proxmox snapshot is your actual safety net. This script cannot undo a
#     broken rollback -- proving whether one exists is the point.
#
# USAGE
#   doas sh vm-rollback-test.sh              # auto-picks a target tag
#   doas sh vm-rollback-test.sh 6.9.4-php8.4-apache
#   doas sh vm-rollback-test.sh --yes        # skip the confirmation prompt
# =============================================================================
set -u

HC=/usr/local/bin/wp-health-check.sh
HC_BACKUP=/usr/local/bin/wp-health-check.sh.rollback-test-backup
ASSUME_YES=0
TARGET=""

for a in "$@"; do
  case "$a" in
    --yes|-y) ASSUME_YES=1 ;;
    -h|--help) sed -n '2,46p' "$0"; exit 0 ;;
    *) TARGET="$a" ;;
  esac
done

# %b, not %s: the verdict lines below embed colour escapes, and with %s
# they printed literally (\033[32mROLLBACK WORKS.\033[0m) on a real run.
say()  { printf '%b\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✔\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m  %s\n' "$*"; }
warn() { printf '  \033[33m⚠\033[0m  %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { bad "Run as root:  doas sh $0"; exit 2; }
[ -x /usr/local/bin/update.sh ] || { bad "update.sh not found"; exit 2; }
[ -x "$HC" ] || { bad "$HC not found — cannot inject"; exit 2; }

# ── Preflight: capture the state we must return to ──────────────────────────
head_ "Preflight"
if ! podman ps --filter 'name=^wordpress$' --filter status=running \
     --format '{{.Names}}' | grep -qx wordpress; then
  bad "The 'wordpress' container is not running. Fix that before testing rollback."
  exit 2
fi
ORIG_IMAGE=$(podman inspect wordpress --format '{{.ImageName}}' 2>/dev/null)
[ -n "$ORIG_IMAGE" ] || ORIG_IMAGE=$(podman inspect wordpress --format '{{.Image}}' 2>/dev/null)
ok "Current image : ${ORIG_IMAGE}"

if podman ps -a --format '{{.Names}}' | grep -qx wordpress-old; then
  bad "A leftover 'wordpress-old' container already exists."
  say  "     Clean it up first, or this test cannot tell old from new:"
  say  "       doas podman rm -f wordpress-old"
  exit 2
fi
ok "No leftover 'wordpress-old' container"

# Pick a target tag that differs from the running one, so the update actually
# proceeds far enough to reach a cutover. Same WordPress version, different
# PHP minor: a real image, no database migration, reversible either way.
if [ -z "$TARGET" ]; then
  . /etc/wp-install/pinned.env 2>/dev/null || true
  case "${WP_TAG:-}" in
    *php8.3*) TARGET=$(printf '%s' "$WP_TAG" | sed 's/php8\.3/php8.4/') ;;
    *php8.4*) TARGET=$(printf '%s' "$WP_TAG" | sed 's/php8\.4/php8.3/') ;;
    *) bad "Could not derive a target tag from WP_TAG='${WP_TAG:-unset}'."
       say  "     Pass one explicitly, e.g.:  doas sh $0 6.9.4-php8.4-apache"
       exit 2 ;;
  esac
fi
ok "Update target : ${TARGET}  (must differ from the running tag to reach cutover)"

head_ "What this will do"
say "  1. Replace ${HC} with a wrapper that PASSES for the"
say "     candidate and FAILS for 'wordpress' after the swap."
say "  2. Run: update.sh wp ${TARGET}"
say "  3. Expect update.sh to cut over, see the forced failure, and ROLL BACK"
say "     to ${ORIG_IMAGE}"
say "  4. Restore the real health check and verify the site is serving."
say ""
warn "Prompts are auto-answered 'y' so the update proceeds unattended. That"
warn "includes any Trivy findings prompt — acceptable on a TEST VM, and a"
warn "reason not to run this on anything you care about."
warn "If rollback is broken, this VM's site will be DOWN afterwards."
say ""

if [ "$ASSUME_YES" -ne 1 ]; then
  printf "Proceed? Type EXACTLY 'rollback-test' to continue: "
  read -r _confirm
  [ "$_confirm" = "rollback-test" ] || { say "Aborted — nothing was changed."; exit 0; }
fi

# ── Restore on every exit path, including Ctrl-C ────────────────────────────
restore_hc() {
  if [ -f "$HC_BACKUP" ]; then
    mv -f "$HC_BACKUP" "$HC" && chmod 755 "$HC"
    printf '  \033[32m✔\033[0m  Real health check restored\n'
  fi
}
trap 'restore_hc' EXIT INT TERM

# ── Inject ──────────────────────────────────────────────────────────────────
head_ "Injecting the fault"
cp -a "$HC" "$HC_BACKUP" || { bad "Could not back up $HC"; exit 2; }
cat > "$HC" << 'WRAPPER'
#!/bin/sh
# TEMPORARY wrapper installed by vm-rollback-test.sh.
# Passes through for every container EXCEPT 'wordpress', which it fails --
# that is the post-cutover check, and failing it is what triggers rollback.
# If you are reading this on a real system, the test did not clean up:
#   mv /usr/local/bin/wp-health-check.sh.rollback-test-backup \
#      /usr/local/bin/wp-health-check.sh
REAL=/usr/local/bin/wp-health-check.sh.rollback-test-backup
if [ "${1:-}" = "wordpress" ]; then
  echo "  [rollback-test] forcing post-cutover health FAILURE for 'wordpress'" >&2
  exit 1
fi
exec "$REAL" "$@"
WRAPPER
chmod 755 "$HC"
ok "Wrapper installed (candidate passes, post-cutover 'wordpress' fails)"

# ── Run the update ──────────────────────────────────────────────────────────
head_ "Running: update.sh wp ${TARGET}"
say "─────────────────────────────────────────────────────────────"
yes y 2>/dev/null | /usr/local/bin/update.sh wp "$TARGET" 2>&1
UPD_RC=$?
say "─────────────────────────────────────────────────────────────"
say "update.sh exit status: ${UPD_RC}"

# ── Restore before verifying, so verification uses the real check ───────────
head_ "Restoring"
restore_hc
trap - EXIT INT TERM

# ── Verify the rollback actually happened ───────────────────────────────────
head_ "Verifying"
FAILS=0

if podman ps --filter 'name=^wordpress$' --filter status=running \
   --format '{{.Names}}' | grep -qx wordpress; then
  ok "'wordpress' container is running"
else
  bad "'wordpress' container is NOT running — rollback did not restore the site"
  FAILS=$((FAILS+1))
fi

NOW_IMAGE=$(podman inspect wordpress --format '{{.ImageName}}' 2>/dev/null)
[ -n "$NOW_IMAGE" ] || NOW_IMAGE=$(podman inspect wordpress --format '{{.Image}}' 2>/dev/null)
if [ "$NOW_IMAGE" = "$ORIG_IMAGE" ]; then
  ok "Image rolled back to the original: ${NOW_IMAGE}"
else
  bad "Image is '${NOW_IMAGE}', expected the original '${ORIG_IMAGE}'"
  say  "     The cutover was NOT undone — this is the failure this test looks for."
  FAILS=$((FAILS+1))
fi

if podman ps -a --format '{{.Names}}' | grep -qx wordpress-old; then
  warn "'wordpress-old' still exists — rollback left it behind"
  say  "     Not necessarily fatal, but it will block the next update:"
  say  "       doas podman rm -f wordpress-old"
else
  ok "No leftover 'wordpress-old' container"
fi

if /usr/local/bin/wp-health-check.sh wordpress 80 >/dev/null 2>&1; then
  ok "Site passes the real health check (HTTP + PHP + DB)"
else
  bad "Site does NOT pass the real health check — it may be down"
  FAILS=$((FAILS+1))
fi

# ── Verdict ─────────────────────────────────────────────────────────────────
head_ "Result"
if [ "$FAILS" -eq 0 ]; then
  say "  \033[32mROLLBACK WORKS.\033[0m update.sh detected the forced post-cutover"
  say "  failure, undid the swap, and left the site running on its original image."
  say ""
  say "  Full report:  doas validate-wordpress.sh"
  exit 0
fi

say "  \033[31mROLLBACK FAILED\033[0m — ${FAILS} check(s) did not pass."
say ""
say "  Recover manually:"
say "    doas podman ps -a | grep wordpress"
say "    doas podman rm -f wordpress                     # if it exists but is broken"
say "    doas podman rename wordpress-old wordpress      # if wordpress-old survived"
say "    doas podman start wordpress"
say ""
say "  If that does not restore service, roll the VM back on the Proxmox host:"
say "    qm rollback <vmid> <snapshot-name>"
say ""
say "  Please capture this entire output — it is the evidence for the fix."
exit 1
