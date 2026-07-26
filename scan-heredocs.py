#!/usr/bin/env python3
"""
scan-heredocs.sh — heredoc command-substitution scanner for create-wordpress-vm.

WHY THIS EXISTS
  create-wordpress-vm-*.sh generates install-wordpress.sh, which in turn writes
  eight helper scripts — all as heredocs. A heredoc whose delimiter is QUOTED
  (<< 'EOF') is literal: $(...) and backticks inside it are written verbatim and
  run later, on the VM. A heredoc whose delimiter is UNQUOTED (<< EOF) is
  expanded as it is written: $(...) and backticks execute THEN, at build/install
  time. Two shipped regressions (bugs 70 and 71) came from exactly this — a
  helper body that had to be literal was left unquoted, so its backticks fired
  during install and sprayed "command not found" through the log, or corrupted
  the generated file.

  Static `bash -n` cannot see this: the file is syntactically valid either way.
  This scanner is the standing check the v8 notes referred to but did not ship as
  identifiable code. Run it BEFORE provisioning a VM.

WHAT IT CHECKS  (proper heredoc state machine — it does NOT match `<<` that
                 appears inside a comment or inside another heredoc's body)
  ERROR  1. A backtick inside ANY unquoted heredoc body. Backticks are the
            bug-70/71 signature and are never intended in these bodies (the
            legitimate runtime substitutions all use $(...) in quoted bodies).
  ERROR  2. An executable helper script — `cat > .../bin/<name>.sh << DELIM` or
            install-wordpress.sh — opened with an UNQUOTED delimiter. These
            bodies are shell programs destined to run on the VM and MUST be
            literal at build time, so their delimiter must be quoted. Config/env
            heredocs that serialize values at build time (e.g. vars.sh with
            $(_vars_q ...), pinned.env) are intentionally unquoted and are NOT
            subject to this rule.
  INFO   3. $(...) inside an unquoted heredoc body. Reported for review, not
            failed: several config heredocs use it deliberately.

EXIT: 0 if no ERRORs, 1 if any ERROR, 2 on usage error.

USAGE: scan-heredocs.sh <path-to-create-wordpress-vm-vX.sh> [more files...]
"""
import sys, re

HEREDOC = re.compile(
    r'(<<-?)\s*(?:'
    r"'([A-Za-z_][A-Za-z0-9_]*)'"      # 2: single-quoted delim  -> literal
    r'|"([A-Za-z_][A-Za-z0-9_]*)"'     # 3: double-quoted delim  -> literal
    r'|\\([A-Za-z_][A-Za-z0-9_]*)'     # 4: backslash delim      -> literal
    r'|([A-Za-z_][A-Za-z0-9_]*)'       # 5: bare delim           -> EXPANDS
    r')'
)
# `cat > .../bin/<name>.sh << DELIM`  or  `cat > .../install-wordpress.sh << DELIM`
# (executable helper scripts whose bodies must be literal; the delimiter form is
#  checked separately). Config/env files like vars.sh and pinned.env are excluded.
SCRIPT_REDIR = re.compile(r'>\s*("?)([^\s"\']*(?:/bin/[^\s"\']+\.sh|install-wordpress\.sh))\1\s*<<')


def strip_comment(line: str) -> str:
    """Remove a trailing # comment when not inside quotes (command context only)."""
    out = []
    q = None
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if q:
            out.append(c)
            if c == q:
                q = None
            elif c == '\\' and q == '"' and i + 1 < n:
                out.append(line[i + 1]); i += 2; continue
        else:
            if c in ('"', "'"):
                q = c; out.append(c)
            elif c == '#' and (i == 0 or line[i - 1].isspace()):
                break
            else:
                out.append(c)
        i += 1
    return ''.join(out)


def scan(path: str):
    errors, infos = [], []
    try:
        lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
    except OSError as e:
        return [(0, 'FILE', f'cannot read: {e}')], []
    # FIFO queue of open heredocs: dicts {delim, quoted, dash}
    queue = []
    for lineno, raw in enumerate(lines, 1):
        if queue:
            top = queue[0]
            term = raw.lstrip('\t') if top['dash'] else raw
            if term == top['delim'] or term.rstrip() == top['delim']:
                queue.pop(0)
                continue
            if not top['quoted']:
                if '`' in raw:
                    errors.append((lineno, top['delim'],
                                   f"backtick inside unquoted heredoc <<{top['delim']}: {raw.strip()[:90]}"))
                if '$(' in raw:
                    infos.append((lineno, top['delim'],
                                  f"$(...) inside unquoted heredoc <<{top['delim']}: {raw.strip()[:90]}"))
            continue
        cmd = strip_comment(raw)
        # detect a script-writing redirect on this command line
        script_target = None
        ms = SCRIPT_REDIR.search(cmd)
        if ms:
            script_target = ms.group(2)
        for m in HEREDOC.finditer(cmd):
            dash = (m.group(1) == '<<-')
            quoted = bool(m.group(2) or m.group(3) or m.group(4))
            delim = m.group(2) or m.group(3) or m.group(4) or m.group(5)
            if script_target and not quoted:
                errors.append((lineno, delim,
                               f"script file '{script_target}' written from an UNQUOTED heredoc "
                               f"<<{delim} — its body must be literal (use << '{delim}')"))
            queue.append({'delim': delim, 'quoted': quoted, 'dash': dash})
    return errors, infos


def main():
    if len(sys.argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    total_err = 0
    for path in sys.argv[1:]:
        errors, infos = scan(path)
        print(f"── {path} ──")
        if errors:
            print(f"  {len(errors)} ERROR(s):")
            for ln, dl, msg in errors:
                print(f"    line {ln}: {msg}")
        else:
            print("  no errors: no backticks in unquoted heredocs; every *.sh heredoc is quoted.")
        if infos:
            print(f"  {len(infos)} informational $(...) occurrence(s) in unquoted heredocs "
                  f"(review that each is an intended runtime substitution):")
            shown = infos[:8]
            for ln, dl, msg in shown:
                print(f"    line {ln}: {msg}")
            if len(infos) > len(shown):
                print(f"    … and {len(infos) - len(shown)} more.")
        total_err += len(errors)
        print()
    if total_err:
        print(f"RESULT: FAIL — {total_err} error(s). Do not provision until these are resolved.")
        return 1
    print("RESULT: CLEAN — safe to provision (no unsafe substitutions in unquoted heredocs).")
    return 0


if __name__ == '__main__':
    sys.exit(main())
