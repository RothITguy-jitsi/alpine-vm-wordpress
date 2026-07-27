#!/usr/bin/env python3
"""Detect prose apostrophes inside single-quoted embedded code blocks.

`php -r '...'` (and awk/perl/python equivalents) pass their program as a
SINGLE-QUOTED shell string. An apostrophe in a comment inside that block --
"PHP's", "site's" -- silently terminates the string, and everything after it
is executed as shell. `sh -n` does NOT catch this: the result is usually
still valid shell syntax, just completely different from what was intended.

The deliberate idiom '"${VAR}"' (close quote, shell var in double quotes,
reopen) is legitimate and must not be flagged, so a quote is only reported
when it is NOT adjacent to a double quote on either side.
"""
import glob, re, sys

OPEN = re.compile(r"""(?:php|perl|awk|python3?)\s+(?:-r|-e|-c)\s*'""")
problems = []
for f in sorted(set(glob.glob('payload/**/*.sh', recursive=True)) | set(glob.glob('lib/*.sh'))):
    raw = open(f, errors='replace').read()
    # Blank out shell comment lines first: a '#' comment can legitimately
    # *describe* the php -r '...' pattern (as this project's own notes do)
    # without opening a real block. Replaced with spaces rather than removed
    # so all reported line numbers stay accurate.
    src = '\n'.join(re.sub(r'\S', ' ', l) if l.lstrip().startswith('#') else l
                    for l in raw.split('\n'))
    for m in OPEN.finditer(src):
        i = m.end()
        while i < len(src):
            if src[i] == "'":
                before = src[i-1] if i else ''
                after  = src[i+1] if i+1 < len(src) else ''
                if before == '"' or after == '"':
                    i += 1          # legitimate '"$VAR"' splice, keep scanning
                    continue
                break               # genuine end of the block
            i += 1
        block = src[m.end():i]
        # A block that ends mid-prose is the signature of the bug: what follows
        # the terminating quote should be shell punctuation, not more words.
        tail = src[i+1:i+40].lstrip()
        if tail and re.match(r'^[A-Za-z]', tail) and '\n' in block:
            ln = src[:i].count('\n') + 1
            problems.append((f, ln, tail.split('\n')[0][:60]))
if problems:
    print(f"FOUND {len(problems)} embedded-quote problem(s):")
    for f, ln, t in problems:
        print(f"  {f}:{ln}  block terminated by an apostrophe; shell then sees: {t}")
    sys.exit(1)
print("Embedded-quote check: CLEAN")
