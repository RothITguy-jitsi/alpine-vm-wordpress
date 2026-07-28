#!/usr/bin/env python3
"""wp-health-check.sh probes from INSIDE the container, so its port argument
must be the in-container listening port (80) -- never a host-published port.

Passing `-p 127.0.0.1:18080:80`'s host side made a healthy candidate report
"No HTTP response" while PHP, DNS and the database all passed, because
nothing is bound to a published port from within the container's namespace.
Two ports with the same name in different namespaces is an easy mistake to
repeat, so it is checked rather than remembered.
"""
import glob, re, sys
# Only real invocations, which always use the absolute path. This avoids
# matching status messages that merely mention the script by name (an early
# version of this check flagged an `ok "wp-health-check.sh installed — ..."`
# line and read the em dash as a port).
CALL = re.compile(r'/usr/local/bin/wp-health-check\.sh\s+("?\$?\{?[A-Za-z_][A-Za-z0-9_}]*"?)\s+("?[^\s;]+"?)')
OK_PORT = re.compile(r'^"?(80|\$\{?WEB_CHECK_PORT\}?)"?$')
bad = 0
for f in sorted(glob.glob('payload/**/*.sh', recursive=True)):
    for n, l in enumerate(open(f, errors='replace'), 1):
        if '/usr/local/bin/wp-health-check.sh' not in l or l.lstrip().startswith('#'):
            continue
        m = CALL.search(l)
        if not m:
            continue
        port = m.group(2)
        if not OK_PORT.match(port):
            print(f"  FAIL {f}:{n}  passes port {port} to an in-container probe")
            print(f"       Must be 80 (or WEB_CHECK_PORT). A host-published port does not")
            print(f"       exist inside the container and yields a false 'no response'.")
            bad += 1
if bad:
    print(f"\n{bad} health-check call(s) using a host-side port"); sys.exit(1)
print("Health-check port check: CLEAN — every probe uses the in-container port")
