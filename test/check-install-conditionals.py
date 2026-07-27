#!/usr/bin/env python3
"""Report the conditional nesting depth of each payload install.

Some payload files are only needed in specific configurations and are
legitimately installed inside an `if`. Others must ALWAYS land, and burying
one inside an unrelated conditional makes it silently absent for most
installs -- which is exactly what happened to the SMTP mu-plugin: it was
placed inside `if [ -n "$WP_ADMIN_SLUG" ]` because that is where the other
mu-plugin lives, so with the default (no custom slug) mail transport was
never installed and wp_mail() failed silently.

MUST_BE_UNCONDITIONAL lists files with no legitimate reason to be gated.
"""
import glob, re, sys

MUST_BE_UNCONDITIONAL = {
    'mu-plugins/01-wpvm-smtp.php',   # mail transport: unrelated to any prompt
    'bin/wp-health-check.sh',
    'bin/mariadb-health-check.sh',
    'bin/update.sh',
    'bin/validate-wordpress.sh',
    'bin/wp-db-backup.sh',
    'bin/wp-hardening.sh',
}
OPEN  = re.compile(r'^\s*(if|case)\b')
CLOSE = re.compile(r'^\s*(fi|esac)\b')
fail = 0
for f in sorted(glob.glob('payload/stages/*.sh')):
    lines = open(f, errors='replace').read().split('\n')
    depth = 0
    for n, l in enumerate(lines, 1):
        t = l.strip()
        if CLOSE.match(t): depth = max(0, depth - 1)
        m = re.search(r'\$\{PAYLOAD_DIR\}/([A-Za-z0-9._/-]+)', l)
        if m and re.search(r'\b(install|cp)\b', l):
            rel = m.group(1)
            if rel in MUST_BE_UNCONDITIONAL and depth > 0:
                print(f"  FAIL {f}:{n}  {rel} installed at conditional depth {depth}")
                print(f"       It must always be installed; gating it makes it silently absent.")
                fail += 1
        if OPEN.match(t) and not t.startswith('fi'): depth += 1
if fail:
    print(f"\n{fail} conditionally-gated install(s) that must be unconditional"); sys.exit(1)
print("Install-conditional check: CLEAN — every must-always file installs unconditionally")
