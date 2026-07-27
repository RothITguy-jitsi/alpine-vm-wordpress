#!/usr/bin/env bash
# Runs every static check in this directory plus the syntax sweeps.
# Each of these exists because a specific bug reached a real deployment and
# `bash -n` / `sh -n` passed it. They are necessary, not sufficient -- a clean
# run here is not evidence the installer works, only that these particular
# failure modes are absent. Validate on real hardware.
set -u
cd "$(dirname "$0")/.." || exit 2
rc=0
echo "── static checks ─────────────────────────────────────────"
for c in test/check-*.py; do python3 "$c" || rc=1; done
echo ""
echo "── syntax sweeps ─────────────────────────────────────────"
mapfile -t files < <(find . -type f -exec sh -c 'head -1 "$1" 2>/dev/null | grep -qE "^#!.*sh" && echo "$1"' _ {} \;)
f=0; for x in "${files[@]}"; do bash -n "$x" 2>/dev/null || { echo "  bash -n FAIL: $x"; f=1; rc=1; }; done
[ $f = 0 ] && echo "  bash -n: all ${#files[@]} files OK"
f=0; for x in "${files[@]}"; do case "$x" in ./payload/*) sh -n "$x" 2>/dev/null || { echo "  sh -n FAIL: $x"; f=1; rc=1; };; esac; done
[ $f = 0 ] && echo "  sh -n (payload/, POSIX): all OK"
echo ""
[ $rc = 0 ] && echo "ALL CHECKS PASSED" || echo "CHECKS FAILED"
exit $rc
