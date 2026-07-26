# WordPress VM Script — Remaining TODO

*Updated for v8-1. This round works through a static forensic review of v8 (and of the test harness and its README). Every fix below was confirmed against the actual code before changing, and the changed logic was mock-tested; the deferrals are listed with their reasons rather than silently dropped. The build now has two static gates — dash+bash syntax on all nine generated scripts and the heredoc scanner — so what remains is the runtime-only class, which is what the integration harness is for.*

## What v8-1 fixed

| **Fix (source finding)** | **Status** | **What changed** |
| --- | --- | --- |
| Validator HTTP probe (16) | Done | validate-wordpress.sh dropped the BusyBox-incompatible wget for the same PHP-from-container probe the health check uses — no more false HTTP/security failures on Alpine |
| Guided-upgrade exit status (10) | Done | update.sh upgrade now aggregates per-component results, prints a summary, and returns non-zero if any accepted upgrade failed — cron/monitoring no longer see success on a partial failure |
| MariaDB LTS allowlist + EOL (7,8) | Done | Explicit supported/EOL allowlists replace the 'every future major.3 is LTS' guess; 10.6 is now flagged END-OF-LIFE and never offered |
| MariaDB documented upgrade path (9) | Done | The guided upgrade offers only a documented single LTS step (10.6→10.11→11.4→11.8→12.3) and refuses to infer one from a rolling source |
| Backup atomic publish (19) | Done | The scheduled backup stages to a hidden temp file and publishes with an atomic rename; both dumps gained --quick --hex-blob |
| Heredoc scanner (22) | Done | scan-heredocs.py ships as a companion: a real pre-provision check for unsafe substitutions in unquoted heredocs |
| Test-harness hardening | Done | 15 fixes incl. exit-status-aware assertions (no more false passes), cleanup traps, exact firewall-rule checks, atomic JSON + metadata, input validation |

**Validator HTTP probe. **This was the highest-value find: validate-wordpress.sh still ran 'wget -S -O /dev/null --max-redirect=0 --tries=1 --timeout=8' — the exact GNU option set that BusyBox wget on Alpine rejects, and the exact bug already fixed in wp-health-check.sh but missed in the standalone validator. On a real VM it produced false 'no HTTP response' and 'login not blocked' results while the health checker passed. It now uses the identical PHP-from-container probe (follow_location=0, ignore_errors=true). The validator's existing source-IP awareness is preserved — when both login paths return 403 because this host isn't in ADMIN_CIDR, it still says 'cannot verify from this host' rather than failing.

**Guided-upgrade exit status. **update.sh upgrade called each component as 'do_..._update || echo warning', so a failure was swallowed and the function fell through returning its last command's status — usually zero. A monitoring wrapper or cron could therefore record a guided upgrade as fully successful when a component had actually failed and rolled back. It now tracks each result, prints an upgrade summary, and returns non-zero if any accepted component failed — the same discipline 'all' and 'digest-check' already had. Mock-tested both ways: a WordPress-fails run returns 1 with an 'Overall: FAILED' summary; an all-succeed run returns 0.

**MariaDB LTS logic. **Two problems in one function. It classified every future major.3 branch (13.3, 14.3, …) as LTS by pattern — predicting release policy from a number, so an unannounced or preview .3 tag would be offered as a production upgrade the moment it appeared. And it still listed 10.6 as LTS after its community maintenance ended on 6 July 2026. Both are now explicit, maintained allowlists with a supported/EOL split: discovery shows 'LTS, supported' / 'LTS, END OF LIFE' / 'NOT an LTS line', and when the pinned line is EOL it prints a prominent migrate-now warning instead of implying the install is current. The guided upgrade additionally offers only a documented single LTS step and refuses to infer a jump from a rolling or unrecognized source.

**Backup atomic publication. **The scheduled backup gzipped straight to its final wp-db-*.sql.gz name, so a crash during gzip could leave a truncated archive under a normal-looking filename for an operator or an external sync to pick up before the next run. It now compresses to a hidden .part file, integrity-checks it, and publishes with a single same-filesystem rename — the archive appears complete only once it is. Both the scheduled and the pre-update rollback dumps also gained --quick (row-by-row streaming for large tables) and --hex-blob (safe binary encoding).

## The integration harness now exists — and was hardened in the same pass

The previous TODO named the integration-test harness as the explicit prerequisite for candidate database isolation. It exists now (test-wordpress-vm.sh), and the review of it surfaced a flaw worth calling out: its assertion helpers judged output without checking whether the guest command actually succeeded, so a command that failed to run — a missing script, a permission error, no guest-agent response — produced empty output and PASSED a negative assertion. A green result that could be built on a broken command undermines the entire point of the harness.

That is fixed: every normal assertion now requires the command to succeed before its output is judged, with a dedicated helper for the expected-failure cases (the rollback test). Fifteen fixes landed in all — exit-status-aware assertions, signal-safe cleanup traps so an interrupted run can't orphan a test VM, four-specific-rule firewall checks instead of counting text, a health check gated on its exit status, a comment-free answers template, SSH host-key verification, input validation, and atomic JSON output with a build-metadata block. The assertion logic was mock-validated (a failed command with empty output now fails; grep -c's legitimate zero-count still passes), and the whole harness runs end-to-end under a mock Proxmox agent without error.

## What's still open, and why

| **Still open (source finding)** | **Status** | **Why it's deferred** |
| --- | --- | --- |
| Candidate DB isolation (17) | Deferred | The harness this was gated on now exists, but the read-only-DB-account step still needs real-hardware validation before it ships |
| Production findings approval (14) | Deferred | Replacing the HIGH/CRITICAL override prompt with a root-owned, digest-scoped approval file adds an interactive flow that can't be tested without real hardware |
| Off-VM backup gate (18) | Deferred | Requiring/verifying a remote backup before a major DB upgrade is environment-specific (backup system, storage, job IDs) |
| Egress restriction (20) | Deferred | Host-level egress rules are brittle against legitimate update paths; the network edge (OPNsense/Proxmox FW) is the right layer |
| Trivy installer checksum (15) | Deferred | A pinned SHA-256 needs to be fetched and maintained per installer revision; shipping a wrong/placeholder hash would break installs |
| CrowdSec key in argv (21) | Deferred | Eliminating the brief argv exposure depends on whether the installed cscli supports a stdin/fd interface |

**On candidate DB isolation specifically. **It is no longer blocked on the absence of a harness — it's blocked on real-hardware validation, which is a smaller gap. The two designs from the last round still stand, simpler first: a temporary SELECT-only MariaDB user the candidate points at (reads work, any write-on-init fails harmlessly against production), or a full dump-and-restore into a throwaway container on an isolated network. Both change live container/DB/network orchestration, so both want the harness to prove them end-to-end on real hardware before they ship — the same reasoning that kept them out last time, now one step closer.

**On the production findings override (14). **This is a fair hardening point: a plain yes/no prompt is weak evidence for accepting a known HIGH/CRITICAL vulnerability in production. The intended replacement — a root-owned approval file matching the exact image digest, CVE, approver, and expiry — is deferred rather than half-built because its whole value is in the interactive accept/deny flow, which can't be exercised without a real scan and real hardware. The current behavior is documented, not hidden: production is already fail-closed for a missing or incomplete scan; only a genuine findings result still prompts.

**A note on the version comparator (finding 4). **The reviewer suggested rejecting non-numeric version fields rather than treating them as zero. Left as-is on purpose: the behavior fails SAFE — a malformed field sorts lowest, so it can never be mistaken for the newest release — and the tag-extraction functions already filter registry tags to a strict numeric pattern before the comparator ever sees them, so malformed input doesn't reach it.