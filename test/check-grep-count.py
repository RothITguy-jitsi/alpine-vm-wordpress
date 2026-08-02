#!/usr/bin/env python3
"""Detect `$(grep -c ...) || echo 0`, which produces "0\\n0".

`grep -c` always prints a count and exits 1 only when that count is zero. So
the idiom

    n=$(grep -c pattern file || echo 0)

yields the string "0\\n0" on no-match — and any arithmetic test on it fails
with "[: too many arguments" at exactly the moment the count is zero, which is
usually the healthy case. The bug therefore hides until something is working.

Correct form assigns on failure instead of appending:

    n=$(grep -c pattern file) || n=0

Found in five places at once, all written the same way, because the wrong
idiom reads naturally.
"""
import glob, re, sys

PAT = re.compile(r'\$\([^()]*grep -c[^()]*\|\|\s*echo\s+0\s*\)')
problems = []
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    for n, line in enumerate(lines, 1):
        if line.lstrip().startswith('#'):
            continue
        if PAT.search(line):
            problems.append((f, n, line.strip()[:70]))
if problems:
    print(f"FOUND {len(problems)} instance(s) of `$(grep -c ...) || echo 0`:")
    for f, n, t in problems:
        print(f"  {f}:{n}")
        print(f"     {t}")
        print(f"     -> yields \"0\\\\n0\" on no-match; use: n=$(grep -c ...) || n=0")
    sys.exit(1)
print("grep -c count check: CLEAN")
