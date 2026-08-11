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
}

DEF_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", re.M)
# A call: the name at the start of a command position, followed by an argument.
CALL_RE = re.compile(
    r"(?:^|\|\|\s+|&&\s+|;\s*|then\s+|else\s+|do\s+|\{\s+)([A-Za-z_][A-Za-z0-9_]*)\s+[\"'$]",
    re.M,
)


def defs_in(text: str):
    return set(DEF_RE.findall(text))


def calls_in(text: str):
    # Ignore heredoc bodies and comments: text inside them is not executed.
    text = re.sub(r"<<-?\s*'?([A-Z_]+)'?.*?^\1", " ", text, flags=re.S | re.M)
    text = re.sub(r"^\s*#.*$", " ", text, flags=re.M)
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
