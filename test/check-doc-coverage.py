#!/usr/bin/env python3
"""Every shipped tool must be DOCUMENTED, not merely mentioned.

A grep for a tool name returns true when the name appears once as a leaf node
in a diagram. That is what happened to wp-import.sh: the coverage sweep said
"present in ARCHITECTURE.md" while the import pipeline — whose ordering IS its
security property — had no diagram at all.

Same failure as the checks that confirmed a firewall rule was PRESENT rather
than EFFECTIVE. Presence is the easy question and rarely the useful one.

So: a tool counts as documented in a file only if it appears with surrounding
prose — a heading, or several mentions — rather than exactly once inside a
code fence or a diagram.
"""
import glob, os, re, sys

DOCS = ['README.md', 'ARCHITECTURE.md', 'INCIDENT-PLAYBOOK.md', 'MSP-RUNBOOK.md']
tools = sorted(os.path.basename(f) for f in glob.glob('payload/bin/*.sh'))

# Internal helpers invoked by cron or other scripts, not operator-facing.
INTERNAL = {'wp-cron-run.sh', 'wp-health-check.sh', 'mariadb-health-check.sh',
            'wp-vuln-cron.sh', 'wp-geoip-setup.sh'}

def strength(text, name):
    stem = name[:-3]
    total = text.count(stem)
    if total == 0:
        return 0, 'absent'
    # strip fenced blocks and mermaid to see if it is discussed in prose
    prose = re.sub(r'```.*?```', '', text, flags=re.S)
    in_prose = prose.count(stem)
    if in_prose >= 1 and total >= 2:
        return 2, 'documented'
    return 1, 'mentioned only'

problems = []
for t in tools:
    if t in INTERNAL:
        continue
    best, where = 0, None
    for d in DOCS:
        if not os.path.exists(d):
            continue
        sc, _ = strength(open(d, errors='replace').read(), t)
        if sc > best:
            best, where = sc, d
    if best == 0:
        problems.append((t, 'documented NOWHERE'))
    elif best == 1:
        problems.append((t, 'only mentioned, never explained'))

if problems:
    print(f"FOUND {len(problems)} tool(s) without real documentation:")
    for t, why in problems:
        print(f"  {t:<28} {why}")
    print("\n  A name inside a diagram is not documentation. Explain what it does")
    print("  and when to reach for it, in prose, in at least one document.")
    sys.exit(1)
print(f"Doc-coverage check: CLEAN — {len(tools) - len(INTERNAL & set(tools))} operator tools documented")
