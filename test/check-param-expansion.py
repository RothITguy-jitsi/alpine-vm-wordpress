#!/usr/bin/env python3
"""Detect ${VAR:+X}${VAR:-Y} used as if it were if/else.

It reads like a ternary and is not. When VAR is set and non-empty:
    ${VAR:+X}  ->  X
    ${VAR:-Y}  ->  the VALUE OF VAR, not Y
so both parts expand and the variable's value is appended to the "true"
branch. When VAR is empty only the second part expands, and the line reads
correctly -- which is why this survives review and only shows up once someone
actually uses the feature.

Shipped as:
    "${WP_ADMIN_SLUG:+/${WP_ADMIN_SLUG} (custom)}${WP_ADMIN_SLUG:-/wp-admin (default)}"
which printed "/edith (custom)edith" in the install summary.

`bash -n` passes it; it is valid shell doing exactly what it says.
Use an explicit test instead:
    "$([ -n "$V" ] && printf 'yes %s' "$V" || printf 'no')"
"""
import glob, re, sys

# Same variable name used with :+ and then :- (or the reverse) on one line.
# Collect every ${VAR:+ / ${VAR:- occurrence and look for one variable used
# with BOTH operators on the same line. Deliberately not brace-matching: the
# first version of this check used [^}]* to find the closing brace, which
# breaks the moment the true-branch contains a nested ${...} -- precisely the
# shape of the bug it was written to catch. It reported CLEAN on its own test
# case.
PAT = re.compile(r'\$\{(\w+):([+-])')
problems = []
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith('#'):
            continue
        seen = {}
        for m in PAT.finditer(line):
            var, op = m.groups()
            seen.setdefault(var, set()).add(op)
        for var, ops in seen.items():
            if ops == {'+', '-'}:
                problems.append((f, n, var, line.strip()[:70]))
if problems:
    print(f"FOUND {len(problems)} suspect parameter expansion(s):")
    for f, n, v, txt in problems:
        print(f"  {f}:{n}  ${{{v}:+...}}${{{v}:-...}} is not if/else — when {v} is set,")
        print(f"     BOTH expand and {v}'s value is appended.")
        print(f"     {txt}")
    sys.exit(1)
print("Parameter-expansion check: CLEAN")
