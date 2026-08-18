#!/usr/bin/env python3
"""Backticks inside an UNQUOTED heredoc are command substitution.

The shell expands an unquoted heredoc body, so a backtick pair anywhere in it
-- including inside what looks like a comment in the generated file -- runs as
a command on the machine doing the generating.

This shipped: an nftables ruleset comment reading

    # ... can open one live with `nft add element` -- no

caused every install to execute `nft add element` on the PROXMOX HOST, print
an nftables syntax error into the install log, and write the comment out
empty. `bash -n` passes it, because it is valid shell doing exactly what it
was told.

This is the failure mode the retired scan-heredocs.py was written for. It was
removed on the grounds that no heredoc still wrote an executable script body
-- which was true, and beside the point: the hazard is the unquoted heredoc,
not what the output happens to be used for. A config heredoc expands its body
exactly the same way.

Comments in the SHELL SOURCE (outside any heredoc) are fine: the shell does
not expand comments. Only heredoc bodies matter here.
"""
import glob, re, sys

OPEN = re.compile(r"<<-?\s*(?:'([A-Za-z_]\w*)'|\"([A-Za-z_]\w*)\"|([A-Za-z_]\w*))\s*(?:\)|;|\||$)")
problems = []
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    i = 0
    while i < len(lines):
        m = OPEN.search(lines[i])
        if m:
            quoted = bool(m.group(1) or m.group(2))
            delim = m.group(1) or m.group(2) or m.group(3)
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == delim:
                    if not quoted:
                        for k in range(i + 1, j):
                            for cmd in re.findall(r'`([^`]*)`', lines[k]):
                                problems.append((f, k + 1, delim, cmd))
                    i = j
                    break
        i += 1
# ── Also: backticks inside a DOUBLE-QUOTED assignment ────────────────────────
# The heredoc scan above missed a real one. A comment written inside a
# multi-line VAR="..." block read:
#     # symptom was `wp-mail.sh doctor` reporting
# and bash executed it -- on the PROXMOX HOST, where wp-mail.sh does not exist.
# Every install printed "lib/03-dynamic-configs.sh: line 162: wp-mail.sh:
# command not found".
#
# A `#` inside a quoted string is NOT a comment; the shell never parses it as
# one. It is just text, and backticks in text still expand. Prose written for a
# human reader is exactly where this happens, because nobody thinks of a
# comment as code.
# ── A "#" inside a quoted string is NOT a comment ────────────────────────────
# THIRD occurrence of this class. Backticks were caught by the block below;
# this catches ${VAR} and $VAR, which expand in exactly the same place and did
# exactly the same damage. Writing
#
#     # this block (as ${SMTP_RATE_LIMIT}, six lines later in the chain), so
#
# inside a multi-line VAR="..." pulled an entire nftables rule block into the
# middle of a comment. The generated file read
#
#     ... ct state new counter drop, six lines later in the chain), so
#
# nft rejected it and the VM booted with NO FIREWALL.
#
# The regex-based block scan below missed these, because the assignments
# contain escaped quotes and span a hundred lines. This tracks quote state line
# by line instead, which is slower and correct.
for f in sorted(set(glob.glob('lib/*.sh')) | set(glob.glob('payload/**/*.sh', recursive=True))):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    inside = False
    for n, line in enumerate(lines, 1):
        if not inside:
            m = re.match(r'^\s*[A-Za-z_][A-Za-z0-9_]*="', line)
            if m and len(re.findall(r'(?<!\\)"', line[m.end():])) % 2 == 0:
                inside = True
            continue
        if len(re.findall(r'(?<!\\)"', line)) % 2 == 1:
            inside = False
            continue
        if line.lstrip().startswith('#') and re.search(r'\$\{|\$[A-Za-z_]|`', line):
            problems.append((f, n, 'expanding-comment', line.strip()[:60]))

QASSIGN = re.compile(r'^[ \t]*[A-Za-z_][A-Za-z0-9_]*="(?:[^"\\]|\\.)*"', re.M | re.S)
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    try: text = open(f, errors='replace').read()
    except FileNotFoundError: continue
    for m in QASSIGN.finditer(text):
        body = m.group(0)
        if '`' not in body:
            continue
        ln = text[:m.start()].count('\n') + 1
        for cmd in re.findall(r'`([^`\n]{0,60})`', body):
            problems.append((f, ln, 'quoted-assignment', cmd))

if problems:
    print(f"FOUND {len(problems)} backtick(s) that the shell will EXECUTE:")
    for f, ln, d, cmd in problems:
        if d == 'expanding-comment':
            print(f"  {f}:{n}  a # inside a quoted string is NOT a comment — this EXPANDS:")
            print(f"     {cmd}")
            print(f"     Name the variable without the $ sigil, or move the note outside the string.")
        elif d == 'quoted-assignment':
            print(f"  {f}:~{ln}  inside a double-quoted assignment, so this EXECUTES: `{cmd}`")
            print(f"     A # inside a quoted string is not a comment. Use 'single quotes'")
            print(f"     around the command name in prose, or drop the backticks.")
        else:
            print(f"  {f}:{ln}  heredoc <<{d} is unquoted, so this EXECUTES: `{cmd}`")
            print(f"     Fix: quote the delimiter (<<'{d}') if no expansion is needed,")
            print(f"     or remove the backticks from the text.")
    sys.exit(1)
print("Heredoc-backtick check: CLEAN")
