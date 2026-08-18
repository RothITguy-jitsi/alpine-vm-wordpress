#!/usr/bin/env python3
"""
check-setu-unset.py — under `set -u`, referencing an unassigned variable is fatal.

WHY THIS EXISTS

Three times now, `wp-notify.sh` has shipped referencing a variable it never
assigned. Each time, `set -u` turned that into an immediate fatal error and
took EVERY notification path down with it:

    SECRETS_DIR: parameter not set
    NOTIFY_COOLDOWN_HOURS: parameter not set
    STATE: parameter not set            <- found on a live VM, 2026-08-12

The last one meant the backup-failure email, malware findings, vulnerability
findings and the heartbeat were all dead. A monitoring system that cannot
report is worse than not having one, because its silence is indistinguishable
from "all clear" — which is exactly the failure the script exists to prevent.

None of these were caught by `sh -n`: the syntax is valid. They fail only when
the line executes, and for an alert path that may be the first real incident.

WHAT IT CHECKS

For each script that sets `-u`, collect the ALL-CAPS variables it references
and the ones it assigns (or that arrive via a sourced config or the
environment), and report references with no assignment anywhere.

It deliberately only considers ALL-CAPS names — the convention for
configuration in this codebase — because lowercase locals are assigned close to
use and flagging them would bury the signal.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Names that legitimately come from elsewhere: the shell itself, or a config
# file this script sources at runtime.
EXTERNAL = {
    "PATH", "HOME", "USER", "SHELL", "PWD", "IFS", "PS1", "TERM", "LANG",
    "LC_ALL", "EDITOR", "TMPDIR", "HOSTNAME", "OPTARG", "OPTIND", "RANDOM",
    "PPID", "UID", "EUID", "BASH_SOURCE", "FUNCNAME", "LINENO", "SECONDS",
    "REPLY", "PAYLOAD_DIR", "SCRIPT_DIR", "STAGE_DIR", "DEBIAN_FRONTEND",
}

REF_RE = re.compile(r'\$\{?([A-Z][A-Z0-9_]{2,})\b')
# X=... / X="..." / export X= / read X / for X in / X=${X:-default}
ASSIGN_RE = re.compile(
    r'(?:^|\s|;|\{)\s*(?:export\s+|readonly\s+|local\s+)?([A-Z][A-Z0-9_]{2,})=|'
    r'\bread\s+(?:-r\s+)?(?:-s\s+)?(?:-p\s+"[^"]*"\s+)?([A-Z][A-Z0-9_]{2,})\b|'
    r'\bfor\s+([A-Z][A-Z0-9_]{2,})\s+in\b',
    re.M,
)
# A reference with a default (${X:-y}) is safe under set -u even if unassigned.
SAFE_REF_RE = re.compile(r'\$\{([A-Z][A-Z0-9_]{2,})(?::?[-=+?])')


def uses_set_u(text: str) -> bool:
    return bool(re.search(r'^\s*set\s+-[a-z]*u', text, re.M))


def sources_config(text: str):
    """Variables that could arrive from a sourced file are not our problem."""
    return bool(re.search(r'^\s*\.\s+\S+vars\.sh|^\s*\.\s+\S+pinned\.env', text, re.M))


def scan_text(text: str):
    # STRIP HEREDOCS FIRST, then decide whether this file uses set -u.
    #
    # A generated script written from a heredoc carries its own `set -u`,
    # which applies to THAT script and not to the file emitting it. Testing
    # before stripping made a host script inherit the strictness of something
    # it merely writes, and every variable in the outer file was then reported
    # unassigned -- three false positives on wp-geoip-setup.sh, which does not
    # set -u at all.
    body = re.sub(r"<<-?\s*'?([A-Z_]+)'?.*?^\1", " ", text, flags=re.S | re.M)
    if not uses_set_u(body):
        return set()
    # Strip comments -- they do not execute.
    body = re.sub(r'^\s*#.*$', ' ', body, flags=re.M)
    # Blank SINGLE-QUOTED strings. The host shell does not expand anything
    # inside them, so `podman exec mariadb sh -c 'mariadb -p"$MARIADB_ROOT_PASSWORD"'`
    # is not a host-side reference at all -- that variable is resolved inside
    # the container, where it genuinely is set. Treating those as unassigned
    # produced six false positives on the first run of this check, and a check
    # that cries wolf is one people switch off.
    # Per LINE, not across the whole file: a stray apostrophe in a trailing
    # comment ("don't") desynchronises quote pairing for everything after it,
    # which left two real single-quoted container commands looking like host
    # references. Scoping to the line contains that damage.
    body = "\n".join(re.sub(r"'[^']*'", "''", ln) for ln in body.split("\n"))

    assigned = set()
    for m in ASSIGN_RE.finditer(body):
        assigned.update(g for g in m.groups() if g)
    safe = set(SAFE_REF_RE.findall(body))
    referenced = set(REF_RE.findall(body))

    # Anything sourced from vars.sh/pinned.env is out of scope: those files are
    # generated at install time and their contents are not visible here.
    if sources_config(text):
        return set()

    return referenced - assigned - safe - EXTERNAL


def self_test():
    bad = 'set -u\necho "$STATE/marker"\n'
    assert scan_text(bad) == {"STATE"}, "self-test: unassigned reference not detected"

    good = 'set -u\nSTATE="/var/lib/x"\necho "$STATE/marker"\n'
    assert not scan_text(good), "self-test: assigned variable flagged"

    defaulted = 'set -u\necho "${STATE:-/tmp}"\n'
    assert not scan_text(defaulted), "self-test: ${X:-default} flagged"

    no_setu = 'echo "$STATE"\n'
    assert not scan_text(no_setu), "self-test: flagged a script without set -u"

    comment = 'set -u\n# echo "$STATE"\n'
    assert not scan_text(comment), "self-test: commented reference flagged"

    # REGRESSION: a variable inside a single-quoted string is expanded by the
    # CONTAINER, not this shell. Six false positives on the first run.
    inner = ('set -u\n'
             "podman exec mariadb sh -c 'exec mariadb -uroot -p\"$MARIADB_ROOT_PASSWORD\"'\n")
    assert not scan_text(inner), "self-test: single-quoted reference flagged"
    return True


def main():
    self_test()
    files = sorted(glob.glob(os.path.join(REPO, "payload", "bin", "*.sh")))
    problems = []
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        for name in sorted(scan_text(text)):
            problems.append((os.path.relpath(path, REPO), name))

    if problems:
        print(f"FOUND {len(problems)} unassigned variable reference(s) under set -u:")
        for path, name in problems:
            print(f"  {path}: references ${name} but never assigns it")
        print()
        print("  Under set -u this is FATAL at runtime, not a warning, and it")
        print("  passes sh -n. Assign it, or reference it as ${NAME:-default}.")
        return 1

    print(f"set -u variables: CLEAN — {len(files)} tools, every reference is assigned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
