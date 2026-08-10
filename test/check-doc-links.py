#!/usr/bin/env python3
"""
check-doc-links.py — internal anchor links must resolve to a real heading.

WHY THIS EXISTS

Renaming a heading silently breaks every link that pointed at it. Nothing
complains: the markdown is valid, the page renders, and the link just quietly
lands nowhere. It is found by a reader clicking it, which for a table of
contents means the reader's first interaction with the document fails.

This happened here for real: the "Outbound Firewall (optional)" heading was
renamed to "...(optional, host-service layer)" while resolving a documentation
contradiction, and the table-of-contents entry kept pointing at the old anchor.

GETTING THE ANCHOR RULE RIGHT MATTERS

A naive implementation reports false positives on any heading containing `&` or
an em-dash, which would make this check noise and get it ignored. GitHub's rule
is: lowercase, remove characters that are not word/space/hyphen, then turn each
remaining space into a hyphen. Because the removed character leaves its
surrounding spaces behind, "Malware & Integrity Scanning" becomes
"malware--integrity-scanning" with a DOUBLE hyphen. This implements that, so a
reported break is a real break.

Only same-file `](#anchor)` links are checked. Cross-file links are left alone:
verifying those needs the target file's headings and is a different job.
"""

import glob
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def gh_anchor(heading: str) -> str:
    """GitHub's heading -> anchor transformation."""
    a = heading.strip().lower()
    # Strip inline markdown that does not survive into the anchor.
    a = re.sub(r"`([^`]*)`", r"\1", a)
    a = re.sub(r"\*\*([^*]*)\*\*", r"\1", a)
    a = re.sub(r"\*([^*]*)\*", r"\1", a)
    a = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", a)
    # Remove everything that is not a word char, space, or hyphen. The removed
    # character leaves its surrounding spaces in place -- this is what produces
    # the double hyphen in "a & b" -> "a--b".
    a = re.sub(r"[^\w\s-]", "", a)
    return a.replace(" ", "-")


def headings_of(text: str):
    out = set()
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if m:
            out.add(gh_anchor(m.group(2)))
    return out


def links_of(text: str):
    """Same-file anchor links, ignoring fenced code."""
    stripped = re.sub(r"```.*?```", " ", text, flags=re.S)
    return re.findall(r"\]\(#([^)]+)\)", stripped)


def scan(text: str):
    heads = headings_of(text)
    return [l for l in links_of(text) if l not in heads]


def self_test():
    """Prove the check fails on a real break and passes on the tricky cases."""
    broken = "# Title\n\n- [Gone](#no-such-heading)\n\n## Real Heading\n"
    assert scan(broken) == ["no-such-heading"], "self-test: break NOT detected"

    # The cases a naive implementation gets wrong -- these must NOT be flagged.
    tricky = (
        "- [a](#malware--integrity-scanning)\n"
        "- [b](#tier-0--anyone)\n"
        "- [c](#outbound-firewall-optional-host-service-layer)\n"
        "\n## Malware & Integrity Scanning\n"
        "\n## Tier 0 — Anyone\n"
        "\n## Outbound Firewall (optional, host-service layer)\n"
    )
    bad = scan(tricky)
    assert not bad, f"self-test: false positive on & / em-dash / parens: {bad}"

    # Links inside code fences must be ignored.
    fenced = "# T\n\n```\n[x](#not-real)\n```\n"
    assert not scan(fenced), "self-test: link inside a fence was checked"
    return True


def main():
    self_test()

    files = sorted(
        glob.glob(os.path.join(REPO, "*.md"))
        + glob.glob(os.path.join(REPO, "docs", "*.md"))
        + glob.glob(os.path.join(REPO, "test", "*.md"))
        + glob.glob(os.path.join(REPO, "tools", "*.md"))
    )
    problems = []
    checked = 0
    for path in files:
        name = os.path.relpath(path, REPO)
        # The changelog is an append-only history; old entries may reference
        # headings that have since been renamed, and that is correct.
        if name == "CHANGELOG.md":
            continue
        text = open(path, encoding="utf-8", errors="replace").read()
        links = links_of(text)
        checked += len(links)
        for bad in scan(text):
            problems.append(f"{name}: link #{bad} matches no heading")

    if problems:
        print(f"FOUND {len(problems)} broken internal link(s):")
        for p in problems:
            print(f"  {p}")
        print()
        print("  A renamed heading silently breaks every link to it. For a table")
        print("  of contents that means the reader's first click fails.")
        return 1

    print(f"Doc links: CLEAN — {checked} internal links across {len(files)} files all resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
