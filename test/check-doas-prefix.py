#!/usr/bin/env python3
"""
check-doas-prefix.py — a suggested command must work when pasted.

WHY THIS EXISTS

Reported from a live install. The tool printed a diagnostic to run:

    nft list ruleset | grep -A6 'wp-front egress'

The operator pasted it and got:

    Operation not permitted (you must be root)

Root SSH is disabled on this platform by design, so an admin is never root and
every root-requiring command needs `doas`. A suggestion that fails on paste is
a small betrayal of trust in every other suggestion the tool makes — and it
happens at the worst moment, when someone is following instructions because
something has already gone wrong.

The compound case is worse than the simple one:

    doas podman rename wordpress-old wordpress && podman start wordpress

That half-works. The rename succeeds, the start fails, and the operator is left
in a state neither they nor the message anticipated. So every segment of a
chain is checked, not just the first.

WHAT IT CHECKS

Lines that PRINT a command for the operator (echo/printf/warn/_note), where the
command is one of the known root-requiring binaries and is not preceded by
`doas`. Commands that merely appear inside executing code are ignored — those
already run as root.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROOT_BINS = r"(?:nft|podman|rc-service|rc-update|apk|cscli|logrotate|sysctl)"
PRINTS = re.compile(r"\b(?:echo|printf|warn|_note|_i|msg_ok|msg_warn|msg_error|ok)\b")

# A command suggested inside a quoted string, after indentation or a chain
# operator. Deliberately narrow: it must look like a copy-pasteable suggestion.
SUGGESTION = re.compile(
    r'(?:["\'][ ]{2,}|&&[ ]+|;[ ]+|\|\|[ ]+)(' + ROOT_BINS + r')\b'
)


def scan_text(text: str):
    problems = []
    for n, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        # The print must START the statement. `ask_yn "..." && { apk update; }`
        # contains an echo-like call but is EXECUTING code, not printing a
        # suggestion, and those commands already run as root.
        if not re.match(r'^(?:echo|printf|warn|_note|_i|msg_ok|msg_warn|msg_error|ok)\b', stripped):
            continue
        # A crontab line is written for root's crontab, not pasted by a human.
        if re.search(r'["\']\s*[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s+[\d*/,-]+\s', line):
            continue
        for m in SUGGESTION.finditer(line):
            # Is this occurrence already preceded by doas?
            preceding = line[max(0, m.start() - 6):m.start(1)]
            if "doas" in preceding:
                continue
            problems.append((n, m.group(1), line.strip()[:88]))
    return problems


def self_test():
    bad = 'echo "     nft list ruleset"\n'
    assert scan_text(bad), "self-test: unprefixed suggestion not detected"

    good = 'echo "     doas nft list ruleset"\n'
    assert not scan_text(good), "self-test: prefixed suggestion flagged"

    # The half-prefixed chain -- the case that half-works.
    half = 'echo "     doas podman rename a b && podman start b"\n'
    assert scan_text(half), "self-test: half-prefixed chain not detected"

    full = 'echo "     doas podman rename a b && doas podman start b"\n'
    assert not scan_text(full), "self-test: fully prefixed chain flagged"

    # Executing code is not a suggestion.
    code = 'if nft -c -f /etc/nftables.nft; then\n'
    assert not scan_text(code), "self-test: executing code treated as a suggestion"

    # REGRESSION: a conditional that RUNS the command is not a suggestion.
    runs = 'ask_yn "Update?" && { apk update; apk upgrade --no-cache; }\n'
    assert not scan_text(runs), "self-test: executing conditional flagged"

    # REGRESSION: a crontab line is written for root, not pasted by a person.
    cron = 'echo "0 3 * * * apk update -q && apk upgrade --no-cache -q"\n'
    assert not scan_text(cron), "self-test: crontab line flagged"
    return True


def main():
    self_test()
    files = sorted(
        glob.glob(os.path.join(REPO, "payload", "**", "*.sh"), recursive=True)
        + glob.glob(os.path.join(REPO, "lib", "*.sh"))
    )
    problems = []
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        for n, cmd, line in scan_text(text):
            problems.append((os.path.relpath(path, REPO), n, cmd, line))

    if problems:
        print(f"FOUND {len(problems)} suggested command(s) missing doas:")
        for path, n, cmd, line in problems:
            print(f"  {path}:{n}  ({cmd})")
            print(f"      {line}")
        print()
        print("  Root SSH is disabled, so an admin is never root. A pasted")
        print("  suggestion without doas fails with 'Operation not permitted'.")
        return 1

    print(f"doas prefixes: CLEAN — {len(files)} scripts, every suggested root command has doas")
    return 0


if __name__ == "__main__":
    sys.exit(main())
