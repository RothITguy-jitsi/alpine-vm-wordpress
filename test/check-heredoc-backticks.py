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
if problems:
    print(f"FOUND {len(problems)} backtick(s) inside unquoted heredoc(s):")
    for f, ln, d, cmd in problems:
        print(f"  {f}:{ln}  heredoc <<{d} is unquoted, so this EXECUTES: `{cmd}`")
        print(f"     Fix: quote the delimiter (<<'{d}') if no expansion is needed,")
        print(f"     or remove the backticks from the text.")
    sys.exit(1)
print("Heredoc-backtick check: CLEAN")
