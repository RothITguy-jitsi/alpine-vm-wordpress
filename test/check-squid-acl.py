#!/usr/bin/env python3
"""
check-squid-acl.py — overlapping entries in a Squid ACL file are not harmless.

WHY THIS EXISTS

A real production install died here, and the failure was completely invisible to
every other check in this repo:

    ERROR: 'registry-1.docker.io' is a subdomain of '.docker.io'
    FATAL: Bungled /etc/squid/squid.conf line 102: acl runtime_allow dstdomain

Squid stores dstdomain ACLs in a splay tree and refuses to build one containing
both a leading-dot parent and a subdomain of it. That is a FATAL config error,
not a warning: squid exits, the container crash-loops, and the install stops.
The allowlist looked entirely reasonable to a human -- `.docker.io` plus
`registry-1.docker.io` reads like being thorough.

The IP case is worse, because it does NOT stop anything and quietly weakens the
policy:

    WARNING: (B) '169.254.169.254' is a subnetwork of (A) '169.254.0.0/16'
    WARNING: because of this '169.254.0.0/16' is ignored to keep splay tree
             searching predictable

Read that carefully: squid DISCARDS the broader range. Listing the specific
cloud-metadata address alongside the /16 meant the rest of link-local was no
longer denied by that ACL at all. Being more specific made the control weaker,
and nothing failed to tell anyone.

So: for domain lists an overlap is fatal, for IP lists an overlap is a silent
security regression. Both are worth catching before an install, not during one.
"""

import glob
import ipaddress
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQUID_DIR = os.path.join(REPO, "payload", "squid")

# Which files feed a dstdomain ACL vs an IP (dst) ACL. Matches squid.conf.
DOMAIN_FILES = {
    "allowlist-runtime.txt",
    "allowlist-maintenance.txt",
    "threat-deny.txt",
}
IP_FILES = {"hard-deny.txt"}


def entries(path):
    out = []
    for raw in open(path, encoding="utf-8", errors="replace").read().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def domain_overlaps(items):
    """Squid: a subdomain of a listed '.parent' is a FATAL duplicate."""
    problems = []
    parents = [d for d in items if d.startswith(".")]
    for item in items:
        if item.startswith("."):
            continue
        for parent in parents:
            # '.docker.io' covers 'registry-1.docker.io' and 'docker.io'
            if item == parent[1:] or item.endswith(parent):
                problems.append(
                    f"'{item}' is a subdomain of '{parent}' — squid treats this as "
                    f"FATAL and will refuse to start"
                )
                break
    # Two leading-dot parents can also nest: '.a.example.com' under '.example.com'
    for a in parents:
        for b in parents:
            if a is not b and a.endswith(b) and a != b:
                problems.append(
                    f"'{a}' is inside '{b}' — remove the narrower one"
                )
    return problems


def ip_overlaps(items):
    """Squid discards the BROADER range when one contains another."""
    problems = []
    nets = []
    for item in items:
        try:
            nets.append((item, ipaddress.ip_network(item, strict=False)))
        except ValueError:
            problems.append(f"'{item}' is not a valid IP or CIDR")
    for label_a, net_a in nets:
        for label_b, net_b in nets:
            if net_a is net_b or net_a.version != net_b.version:
                continue
            if net_a != net_b and net_a.subnet_of(net_b):
                problems.append(
                    f"'{label_a}' is inside '{label_b}' — squid IGNORES the broader "
                    f"'{label_b}' to keep its tree predictable, so this makes the "
                    f"policy WEAKER. Remove '{label_a}'."
                )
    return problems


def check_conf(conf_path):
    """A method allowlist that omits CONNECT silently blocks ALL HTTPS.

    Found on a live VM: `acl allowed_methods method GET POST HEAD OPTIONS PUT`
    followed by `http_access deny !allowed_methods` denied every TLS request
    before the destination allowlist was ever reached. Squid logged
    TCP_DENIED/403, the plugin install blamed WordPress.org, and the egress
    self-test reported every deny-probe passing -- because everything was
    denied.
    """
    problems = []
    if not os.path.exists(conf_path):
        return problems
    text = open(conf_path, encoding="utf-8", errors="replace").read()
    lines = [l.strip() for l in text.splitlines() if not l.strip().startswith("#")]

    method_acls = {}
    for l in lines:
        m = re.match(r"acl\s+(\S+)\s+method\s+(.+)$", l)
        if m:
            method_acls[m.group(1)] = m.group(2).split()

    for l in lines:
        m = re.match(r"http_access\s+deny\s+!(\S+)$", l)
        if m and m.group(1) in method_acls:
            methods = method_acls[m.group(1)]
            if "CONNECT" not in methods:
                problems.append(
                    f"squid.conf: `deny !{m.group(1)}` will block ALL HTTPS — "
                    f"CONNECT is missing from `acl {m.group(1)} method "
                    f"{' '.join(methods)}`"
                )
    return problems


def scan_dir(directory):
    found = []
    for path in sorted(glob.glob(os.path.join(directory, "*.txt"))):
        name = os.path.basename(path)
        items = entries(path)
        if name in DOMAIN_FILES:
            probs = domain_overlaps(items)
        elif name in IP_FILES:
            probs = ip_overlaps(items)
        else:
            continue
        for p in probs:
            found.append((name, p))
    return found


def self_test():
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        # The exact failure that killed a real install.
        with open(os.path.join(d, "allowlist-runtime.txt"), "w") as f:
            f.write(".docker.io\nregistry-1.docker.io\n.wordpress.org\n")
        found = scan_dir(d)
        assert any("registry-1.docker.io" in p for _, p in found), \
            "self-test: the real dstdomain failure was not detected"

        # The silent IP weakening.
        with open(os.path.join(d, "hard-deny.txt"), "w") as f:
            f.write("169.254.0.0/16\n169.254.169.254/32\n")
        found = scan_dir(d)
        assert any("WEAKER" in p for _, p in found), \
            "self-test: the IP overlap was not detected"

    with tempfile.TemporaryDirectory() as d:
        conf = os.path.join(d, "squid.conf")
        with open(conf, "w") as f:
            f.write("acl m method GET POST\nhttp_access deny !m\n")
        assert check_conf(conf), "self-test: missing CONNECT not detected"
        with open(conf, "w") as f:
            f.write("acl m method GET POST CONNECT\nhttp_access deny !m\n")
        assert not check_conf(conf), "self-test: CONNECT present but flagged"

    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "allowlist-runtime.txt"), "w") as f:
            f.write(".docker.io\n.wordpress.org\nghcr.io\n")
        with open(os.path.join(d, "hard-deny.txt"), "w") as f:
            f.write("10.0.0.0/8\n169.254.0.0/16\n")
        assert not scan_dir(d), "self-test: clean files were flagged"
    return True


def main():
    self_test()

    if not os.path.isdir(SQUID_DIR):
        print("check-squid-acl: no squid config directory — skipping")
        return 0

    found = scan_dir(SQUID_DIR)
    conf_problems = check_conf(os.path.join(SQUID_DIR, "squid.conf"))
    if conf_problems:
        print(f"FOUND {len(conf_problems)} squid.conf problem(s):")
        for p in conf_problems:
            print(f"  {p}")
        return 1
    if found:
        print(f"FOUND {len(found)} overlapping ACL entr(ies):")
        for name, problem in found:
            print(f"  {name}: {problem}")
        return 1

    checked = sum(
        1 for p in glob.glob(os.path.join(SQUID_DIR, "*.txt"))
        if os.path.basename(p) in DOMAIN_FILES | IP_FILES
    )
    print(f"Squid ACLs: CLEAN — {checked} list(s), no overlapping entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
