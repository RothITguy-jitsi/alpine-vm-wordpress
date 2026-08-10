#!/usr/bin/env python3
"""
check-menu-entries.py — every menu entry must map to a real tool + real subcommand.

WHY THIS EXISTS

wasp-menu.sh is the front door: for many operators it IS the interface. A menu
entry that points at a tool that does not exist, or a subcommand a tool does not
accept, is worse than no menu — the operator trusts it, runs it, and gets
"unknown command" in the middle of an incident. That failure is invisible to
`sh -n` (the syntax is fine) and invisible to a code read (the string looks
plausible). It only shows up when someone picks that entry, which is exactly the
wrong moment.

So this parses every run() call site out of the menu and checks:
  1. the tool exists in payload/bin/
  2. if a subcommand is passed, the tool's dispatch actually accepts it,
     including `a|b|c)` alternation forms

SELF-TEST

Like every check here, it fires on its own fixture first: a fake menu with a
known-bad entry must be detected. A check that cannot fail is not a check.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MENU = os.path.join(REPO, "payload", "bin", "wasp-menu.sh")
BIN = os.path.join(REPO, "payload", "bin")

RUN_RE = re.compile(
    r'run "([^"]+)" ([01]) ([a-z][a-z0-9.-]*\.sh)((?: [^\n;|&]*)?)'
)


def accepts_subcommand(tool_body: str, sub: str) -> bool:
    """Does this tool's case dispatch accept `sub`?

    Handles the alternation forms real dispatchers use, whether the arm's body
    is on the same line or the next one:
        sub)                     full|scan)  ...  ;;
        crowdsec|cs) do_thing ;; check|status|"") show ;;
    A bare mention in a usage string does not count — it has to look like a case
    arm, or we would pass on any tool that merely documents the word.
    """
    # Find every `<alternation>)` that starts a line (allowing leading space).
    # Stop the alternation at the first ')' so a trailing body is ignored.
    for m in re.finditer(r'^[ \t]*([A-Za-z0-9_|"\'\*\?\.-]+)\)', tool_body, re.M):
        head = m.group(1)
        alts = [a.strip().strip('"').strip("'") for a in head.split("|")]
        if sub in alts:
            return True
    return False


def first_subcommand(rest: str):
    """The first positional arg that is not a flag or a shell variable."""
    for a in rest.strip().split():
        if a.startswith("-") or a.startswith("$") or a.startswith('"$'):
            continue
        return a.strip('"')
    return None


def scan(menu_text: str, bin_dir: str):
    problems = []
    calls = RUN_RE.findall(menu_text)
    for label, _danger, tool, rest in calls:
        path = os.path.join(bin_dir, tool)
        if not os.path.exists(path):
            problems.append(f"menu entry '{label}' calls {tool}, which does not exist")
            continue
        sub = first_subcommand(rest)
        if sub:
            body = open(path, encoding="utf-8", errors="replace").read()
            if not accepts_subcommand(body, sub):
                problems.append(
                    f"menu entry '{label}' runs `{tool} {sub}`, "
                    f"but {tool} has no case arm for '{sub}'"
                )
    return len(calls), problems


def self_test():
    """Prove the check can fail before trusting it to pass."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        # a tool that accepts only 'status'
        with open(os.path.join(d, "faketool.sh"), "w") as f:
            f.write("case \"$1\" in\n  status) echo hi ;;\nesac\n")
        good = 'run "Fine" 0 faketool.sh status\n'
        bad_sub = 'run "Broken sub" 0 faketool.sh nonexistent\n'
        bad_tool = 'run "Broken tool" 0 notthere.sh status\n'

        n, p = scan(good, d)
        assert n == 1 and not p, f"self-test: good entry flagged: {p}"
        n, p = scan(bad_sub, d)
        assert p, "self-test: bad subcommand NOT detected"
        n, p = scan(bad_tool, d)
        assert p, "self-test: missing tool NOT detected"
    return True


def main():
    self_test()

    if not os.path.exists(MENU):
        print("check-menu-entries: wasp-menu.sh not found — skipping")
        return 0

    text = open(MENU, encoding="utf-8", errors="replace").read()
    count, problems = scan(text, BIN)

    if problems:
        print(f"FOUND {len(problems)} broken menu entr(ies):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  A menu entry is a promise. Pointing at a command that does not")
        print("  exist means an operator discovers it mid-incident.")
        return 1

    print(f"Menu entries: CLEAN — {count} entries, every tool and subcommand real")
    return 0


if __name__ == "__main__":
    sys.exit(main())
