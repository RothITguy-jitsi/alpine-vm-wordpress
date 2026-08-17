#!/usr/bin/env python3
"""
check-expansion-order.py — a config string must not expand a variable set later.

WHY THIS EXISTS

Twice now, in the same file, from opposite directions:

  * A rule block was expanded before its definition, so it vanished — the SMTP
    allow rule silently disappeared and outbound mail broke everywhere.
  * The definition was then moved up, above its OWN dependencies, so the
    tunables it names were still empty. The generated rule read
    `tcp dport  ct state new limit rate  burst  packets` and nft rejected the
    entire file with "syntax error, unexpected ct". The VM came up with NO
    FILTER TABLE — no packet filter, no admin restriction, no egress boundary.

Shell expands at assignment time. A variable named inside a double-quoted
assignment must already be set, and `set -u` does not help because these files
run without it. `bash -n` does not help either: the syntax is perfectly valid,
and the damage only appears in the generated artifact.

WHAT IT CHECKS

For each config-building file, find multi-line double-quoted assignments
(`FOO="..."` spanning lines — the shape used to build nftables and Apache
fragments), collect the `${VAR}` references inside them, and report any that is
assigned later in the same file than the block that uses it.

Deliberately narrow: only ALL-CAPS and _lowercase config-style names, only
within a file, and only for multi-line assignments. Cross-file and runtime
variables are out of scope, because guessing at those is how a check becomes
noise.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A multi-line double-quoted assignment: the shape used to build config text.
BLOCK = re.compile(
    r'^([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*\n(?:[^"\\]|\\.)*)"',
    re.M | re.S,
)
REF = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}')
ASSIGN = re.compile(r'^[ \t]*(?:export[ \t]+|local[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)=', re.M)


def scan_text(text):
    # Where is each name first assigned?
    first_assign = {}
    for m in ASSIGN.finditer(text):
        first_assign.setdefault(m.group(1), m.start())

    problems = []
    for blk in BLOCK.finditer(text):
        name, body = blk.group(1), blk.group(2)
        block_at = blk.start()
        seen = set()
        for r in REF.finditer(body):
            var = r.group(1)
            if var in seen or var == name:
                continue
            seen.add(var)
            pos = first_assign.get(var)
            # Not assigned in this file at all -> out of scope (env, caller).
            if pos is None:
                continue
            if pos > block_at:
                line = text[:block_at].count("\n") + 1
                assigned_line = text[:pos].count("\n") + 1
                problems.append((line, name, var, assigned_line))
    return problems


def self_test():
    bad = 'RULE="line ${PORTS} more"\nPORTS="{ 80 }"\n'
    # single-line assignment is not the shape we scan; use a multi-line one
    bad = 'RULE="line one\n  ${PORTS} here"\nPORTS="{ 80 }"\n'
    got = scan_text(bad)
    assert got and got[0][2] == "PORTS", f"self-test: late assignment not detected ({got})"

    good = 'PORTS="{ 80 }"\nRULE="line one\n  ${PORTS} here"\n'
    assert not scan_text(good), "self-test: correct order flagged"

    external = 'RULE="line one\n  ${FROM_ENV} here"\n'
    assert not scan_text(external), "self-test: variable not assigned in-file flagged"
    return True


def main():
    self_test()
    files = sorted(
        glob.glob(os.path.join(REPO, "lib", "*.sh"))
        + glob.glob(os.path.join(REPO, "payload", "stages", "*.sh"))
    )
    problems = []
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        for line, name, var, assigned_line in scan_text(text):
            problems.append(
                f"{os.path.relpath(path, REPO)}:{line}: {name} expands ${{{var}}}, "
                f"but {var} is not assigned until line {assigned_line}"
            )

    if problems:
        print(f"FOUND {len(problems)} expansion-order problem(s):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  The variable expands EMPTY, and the generated config is silently")
        print("  malformed. bash -n cannot see this — the syntax is valid.")
        return 1

    print(f"Expansion order: CLEAN — {len(files)} config builders, no forward references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
