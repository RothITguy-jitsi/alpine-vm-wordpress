#!/usr/bin/env python3
"""
check-undefined-helpers.py — a script must not call an output helper it doesn't have.

WHY THIS EXISTS

Three times now, code has called a nice-looking helper that was never defined in
that file:

  * `info` in a stage      — would have died at runtime on the progress line
  * `_p`   in the report   — killed the report mid-section on a real VM
  * `warn` in the report   — latent; would have killed the UNVERIFIED banner

Every one passed `sh -n`, because calling an undefined command is a RUNTIME
error in shell, not a syntax error. The shell happily parses `_p "hello"` and
only fails when it runs and cannot find a command named `_p`. So the syntax
sweep this project already runs is structurally incapable of catching it.

The reason it keeps happening is that different files in this repo use different
helper vocabularies: the stages have ok/warn/err/ts, the report has
ok/no/sk/inf/hdr/sub/run. Writing a new block in one file with the other file's
habits produces exactly this bug, and it looks completely correct on the page.

WHAT IT CHECKS

For each shell file, collect the helper-shaped names it defines itself, plus
anything it could inherit by being sourced into the payload entrypoint. Then
find calls to helper-shaped names that are in neither set. It deliberately only
considers a small vocabulary of output-helper-looking names rather than every
command, because guessing which arbitrary words are external binaries is how a
check becomes noise and gets ignored.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Names that are helper-shaped in this codebase. Only these are policed: a
# broad "is this command defined" check would flag every external binary.
HELPER_NAMES = {
    "ok", "no", "sk", "inf", "hdr", "sub", "warn", "err", "ts", "msg", "note",
    "info", "pass", "fail", "die", "debug", "say", "_p", "_ok", "_no", "_warn",
    "_err", "_info", "_note", "_hdr", "_sub", "_bad", "_pause", "_missing",
    "msg_ok", "msg_warn", "msg_error", "msg_info",
    # Wrapper helpers, not output helpers, but the same failure shape: a file
    # calls _wp expecting a wp-cli wrapper it never defined. Found on a real
    # VM in wp-mail.sh, where `_wp: not found` broke the mail test.
    "_wp", "_wpcli", "_db", "_sql", "_run", "_exec", "_curl",
}

DEF_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", re.M)
# A call: the name at the start of a command position, followed by an argument.
# Command position: start of a line (any indentation), or after a shell
# operator, or immediately inside a command substitution. The original regex
# anchored on ^ with no allowance for leading whitespace, so a helper called
# from inside a case arm or an if block -- which is most of them -- was never
# examined at all. That is why two real undefined helpers passed this check.
CALL_RE = re.compile(
    r"(?:^[ \t]*|\|\|\s+|&&\s+|;\s*|then\s+|else\s+|do\s+|\{\s+|\$\(\s*|`\s*)"
    # The first argument may be bare (`_wp eval "x"`), not just quoted. The
    # original class required a quote or $ here, which is exactly how a real
    # `_wp eval` call escaped this check and reached a VM.
    r"([A-Za-z_][A-Za-z0-9_]*)\s+\S",
    re.M,
)


def defs_in(text: str):
    return set(DEF_RE.findall(text))


def calls_in(text: str):
    # Ignore heredoc bodies and comments: text inside them is not executed.
    text = re.sub(r"<<-?\s*'?([A-Z_]+)'?.*?^\1", " ", text, flags=re.S | re.M)
    text = re.sub(r"^\s*#.*$", " ", text, flags=re.M)
    # Blank the CONTENTS of quoted strings. English prose inside a message is
    # not a command: `_note "…then pass the new value here."` was reported as a
    # call to a helper named `pass`. A check that cries wolf gets switched off,
    # so precision here is worth more than catching an exotic edge case.
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    text = re.sub(r"'(?:[^'])*'", "''", text)
    return {n for n in CALL_RE.findall(text) if n in HELPER_NAMES}


def scan(files, inherited_from=None):
    """inherited_from: text whose definitions every file may also use."""
    inherited = defs_in(inherited_from) if inherited_from else set()
    problems = []
    for path in files:
        text = open(path, encoding="utf-8", errors="replace").read()
        available = defs_in(text) | inherited
        for name in sorted(calls_in(text) - available):
            problems.append((path, name))
    return problems


def self_test():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        good = os.path.join(d, "good.sh")
        open(good, "w").write('ok() { echo "$1"; }\nok "fine"\n')
        assert not scan([good]), "self-test: good file flagged"

        bad = os.path.join(d, "bad.sh")
        open(bad, "w").write('ok() { echo "$1"; }\n_p "this helper does not exist"\n')
        found = scan([bad])
        assert found and found[0][1] == "_p", f"self-test: undefined call missed ({found})"

        # Inheritance must be honoured: a stage may use the entrypoint's helpers.
        entry = 'warn() { echo "$1"; }\n'
        stage = os.path.join(d, "stage.sh")
        open(stage, "w").write('warn "inherited is fine"\n')
        assert not scan([stage], inherited_from=entry), "self-test: inherited helper flagged"

        # Heredoc bodies are not code.
        hd = os.path.join(d, "hd.sh")
        open(hd, "w").write("cat <<'EOF'\n_p \"inside a heredoc\"\nEOF\n")
        assert not scan([hd]), "self-test: heredoc body treated as code"

        # REGRESSION: an INDENTED call inside a case arm. Two real bugs
        # (_hdr in wasp-offsite-backup.sh, _wp in wp-mail.sh) reached a live
        # VM because the old regex only matched calls at column zero.
        indented = os.path.join(d, "indented.sh")
        open(indented, "w").write(
            'ok() { echo "$1"; }\ncase "$1" in\n  drill)\n    _hdr "a heading"\n    ;;\nesac\n'
        )
        found = scan([indented])
        assert any(n == "_hdr" for _, n in found), \
            "self-test: indented call inside a case arm was not examined"

        # REGRESSION: an English word inside a quoted message is not a call.
        prose = os.path.join(d, "prose.sh")
        open(prose, "w").write(
            '_note() { echo "$1"; }\n_note "then pass the new value here"\n'
        )
        assert not scan([prose]), "self-test: prose inside a string treated as a call"

        # REGRESSION: a call inside a command substitution.
        subst = os.path.join(d, "subst.sh")
        open(subst, "w").write('ok() { echo "$1"; }\n_out=$(_wp eval "x")\n')
        found = scan([subst])
        assert any(n == "_wp" for _, n in found), \
            "self-test: call inside $( ) was not examined"
    return True


def main():
    self_test()

    entry_path = os.path.join(REPO, "payload", "install-wordpress.sh")
    entry = open(entry_path, encoding="utf-8", errors="replace").read() if os.path.exists(entry_path) else ""

    # Stages are sourced into the entrypoint, so they inherit its helpers.
    stages = sorted(glob.glob(os.path.join(REPO, "payload", "stages", "*.sh")))
    # Standalone tools do not — each must define what it uses.
    tools = sorted(glob.glob(os.path.join(REPO, "payload", "bin", "*.sh")))

    problems = scan(stages, inherited_from=entry) + scan(tools)

    if problems:
        print(f"FOUND {len(problems)} call(s) to undefined helpers:")
        for path, name in problems:
            print(f"  {os.path.relpath(path, REPO)}: calls `{name}`, which it neither defines nor inherits")
        print()
        print("  These pass `sh -n` — an undefined command is a runtime error, not")
        print("  a syntax error. They fail only when that line actually executes.")
        return 1

    print(f"Undefined helpers: CLEAN — {len(stages)} stages + {len(tools)} tools, every helper call resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
