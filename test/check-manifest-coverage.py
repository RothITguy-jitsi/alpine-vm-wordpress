#!/usr/bin/env python3
"""Every shipped file must be covered by the signed manifest.

The release manifest originally selected files by extension:

    -name '*.sh' -o -name '*.php' -o -name '*.yar' -o ...

An allowlist inverts the failure: anything it does not name is silently
unsigned, and nothing complains. `payload/mariadb-conf/wp.cnf` shipped
unsigned for exactly that reason — `.cnf` was not in the list. A modified
MariaDB config could weaken the database (bind address, local-infile, TLS
settings) and every signature check would still pass.

The manifest now covers everything under install.sh, lib/ and payload/ with no
extension filter, because that is precisely the set install.sh executes or
copies onto the VM. Documentation lives outside those paths, so nothing needs
excluding — the filter added risk for no benefit.

This check re-derives that set and fails if a manifest exists that does not
cover all of it.
"""
import os, sys, hashlib

SIGNED_ROOTS = ['lib', 'payload']
SIGNED_FILES = ['install.sh']
MANIFEST = 'MANIFEST.sha256'

expected = set(SIGNED_FILES)
for root in SIGNED_ROOTS:
    if not os.path.isdir(root):
        continue
    for d, _, fs in os.walk(root):
        for f in fs:
            expected.add(os.path.join(d, f))

if not os.path.exists(MANIFEST):
    print(f"Manifest-coverage check: no {MANIFEST} (unsigned build) — "
          f"{len(expected)} files would be signed")
    sys.exit(0)

listed = set()
for line in open(MANIFEST):
    parts = line.strip().split(None, 1)
    if len(parts) == 2:
        listed.add(parts[1].lstrip('*').lstrip('./'))

missing = sorted(expected - listed)
extra   = sorted(listed - expected)

if missing:
    print(f"FOUND {len(missing)} shipped file(s) NOT in the signed manifest:")
    for m in missing:
        print(f"  {m}")
    print("\n  These are copied onto the VM but not covered by the signature.")
    print("  Re-sign with a manifest built from ALL files under lib/ and payload/,")
    print("  not from an extension allowlist.")
    sys.exit(1)
if extra:
    print(f"NOTE: {len(extra)} manifest entry(s) no longer exist in the tree:")
    for e in extra[:10]:
        print(f"  {e}")
    print("  Stale entries make sha256sum -c fail. Re-sign.")
    sys.exit(1)
print(f"Manifest-coverage check: CLEAN — all {len(expected)} shipped files signed")
