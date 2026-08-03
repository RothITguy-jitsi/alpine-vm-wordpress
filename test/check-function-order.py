#!/usr/bin/env python3
"""Shell functions called before they are defined.

Shell resolves a function name when the call executes, not when the file is
parsed — so `bash -n` accepts a call that appears above its definition, and it
fails at runtime with "not found". That is what shipped: validate-wordpress.sh
defined note() at line 711 and called it at 687, so the remoteip check printed
"note: not found" instead of its message.

Only top-level definitions and calls are considered, and only within one file.
A call inside another function is fine if that function runs after the
definition, so those are skipped rather than guessed at.
"""
import glob, re, sys

DEF = re.compile(r'^([a-z_][a-z0-9_]*)\s*\(\)\s*\{')
problems = []
for f in sorted(glob.glob('payload/bin/*.sh') + glob.glob('lib/*.sh') + ['install.sh']):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    defs, depth = {}, 0
    for n, line in enumerate(lines, 1):
        m = DEF.match(line)
        if m and depth == 0:
            defs.setdefault(m.group(1), n)
        depth += line.count('{') - line.count('}')
    # Only calls at TRUE top level matter. A call inside another function body
    # is resolved when that function RUNS, by which time every definition in
    # the file has been parsed — so flagging those is noise. The first version
    # of this check used indentation as a proxy for nesting and reported four
    # such false positives; a checker that cries wolf is how a real finding
    # gets waved through.
    depth = 0
    for n, line in enumerate(lines, 1):
        st = line.strip()
        opens = line.count('{') - line.count('}')
        if st and not st.startswith('#') and not DEF.match(line) and depth == 0:
            c = re.match(r'^\s*([a-z_][a-z0-9_]*)\s+["\'$]', line)
            if c:
                name = c.group(1)
                if name in defs and n < defs[name]:
                    problems.append((f, n, name, defs[name]))
        depth += opens
if problems:
    print(f"FOUND {len(problems)} call(s) before definition:")
    for f, n, name, d in problems:
        print(f"  {f}:{n}  calls {name}() which is defined at line {d}")
        print(f"     -> runtime 'not found'; bash -n does not catch this")
    sys.exit(1)
print("Function-order check: CLEAN")
