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
| Egress restriction (20) | **DONE as an opt-in** (install prompt + `wp-hardening.sh egress-allow`); still not a default, for the reason below | Host-level egress rules are brittle against legitimate update paths; the network edge (OPNsense/Proxmox FW) is the right layer |
| Trivy installer checksum (15) | Deferred | A pinned SHA-256 needs to be fetched and maintained per installer revision; shipping a wrong/placeholder hash would break installs |
| CrowdSec key in argv (21) | Deferred | Eliminating the brief argv exposure depends on whether the installed cscli supports a stdin/fd interface |
| Backup restoration proof | Deferred | Confirming a scheduled backup archive is *structurally valid* (already done, atomically) is a different, much smaller claim than confirming it *restores clean* — the latter needs a throwaway MariaDB, a real restore, and a data-integrity check, with the same real-hardware-validation bar as candidate DB isolation above. Tracked separately rather than folded in, since it's a distinct piece of work even though both touch backups |
| Full candidate/cutover/rollback harness coverage | **DONE** — cutover proven both directions (6.9.4-php8.3 ↔ php8.4), and rollback proven by fault injection (`test/vm-rollback-test.sh`): forced post-cutover failure, automatic restore to the original image, site healthy, no leftover container | test-wordpress-vm.sh exercises the rollback trigger (section 8) and the backup script (section 7), but not a full "bad candidate → automatic rollback → verified-healthy old version" run end to end. Real hardware and a deliberately-broken candidate image are both needed to build this safely |

**On candidate DB isolation specifically. **It is no longer blocked on the absence of a harness — it's blocked on real-hardware validation, which is a smaller gap. The two designs from the last round still stand, simpler first: a temporary SELECT-only MariaDB user the candidate points at (reads work, any write-on-init fails harmlessly against production), or a full dump-and-restore into a throwaway container on an isolated network. Both change live container/DB/network orchestration, so both want the harness to prove them end-to-end on real hardware before they ship — the same reasoning that kept them out last time, now one step closer.

**On the production findings override (14). **This is a fair hardening point: a plain yes/no prompt is weak evidence for accepting a known HIGH/CRITICAL vulnerability in production. The intended replacement — a root-owned approval file matching the exact image digest, CVE, approver, and expiry — is deferred rather than half-built because its whole value is in the interactive accept/deny flow, which can't be exercised without a real scan and real hardware. The current behavior is documented, not hidden: production is already fail-closed for a missing or incomplete scan; only a genuine findings result still prompts.

**A note on the version comparator (finding 4). **The reviewer suggested rejecting non-numeric version fields rather than treating them as zero. Left as-is on purpose: the behavior fails SAFE — a malformed field sorts lowest, so it can never be mistaken for the newest release — and the tag-extraction functions already filter registry tags to a strict numeric pattern before the comparator ever sees them, so malformed input doesn't reach it.

## Independent re-audit (post-restructuring)

A second, independent evaluation was run against the split repository (`install.sh` + `lib/` + `payload/`) after the monolith-to-multi-file restructuring. It corroborated four already-tracked items above (candidate DB isolation, off-VM backup gate, Trivy findings override, Trivy installer checksum) without knowing they were already tracked — independent agreement worth noting, not a new signal on its own. It also surfaced genuinely new issues, all now fixed except where noted:

| **Finding** | **Status** | **What changed / why deferred** |
| --- | --- | --- |
| Root SSH re-enabled as a fallback when admin-account creation failed | Fixed | Root SSH now stays disabled unconditionally; recovery is `qm terminal <vmid>` (console access, already guaranteed by the unconditional root password) rather than a network-facing fallback |
| CrowdSec bouncer failure only ever warned, even in `production` | Fixed | Now fails closed under `DEPLOYMENT_PROFILE=production`, matching the pattern already used for Alpine image verification and digest pinning |
| `uploads-php` escape hatch had no auto-expiration | Fixed | Opening it now writes a timestamp marker; a new 15-min cron check (`wp-hardening.sh check-expiry`) auto re-blocks after 1 hour |
| CSP allowed `unsafe-eval` site-wide | Fixed | Scoped to a `<LocationMatch>` for `/wp-admin/` and `/wp-login.php` only (works correctly through the custom-slug rewrite too, since that rewrite resolves to the real paths before Apache serves the request) — the site-wide default no longer carries it |
| CrowdSec bouncer config internally inconsistent on IPv6 (`disable_ipv6: false` alongside `nftables.ipv6.enabled: false`) | Fixed | This deployment's nftables ruleset has no IPv6 rules at all; the bouncer config now says `disable_ipv6: true` to match reality |
| Test harness's SSH host-key trust was pure network TOFU | Fixed | Now cross-checks the network-observed key fingerprint against one fetched via the guest agent (a separate channel from the network path an attacker would need); falls back to the original TOFU behavior with a loud warning if the agent doesn't answer |
| `README.md` referenced a LICENSE file that didn't exist | Fixed | Added |
| `install-wordpress.sh`'s digest-pinning fail-closed path called a host-side-only function (`msg_error`) that doesn't exist in the VM's own execution context | Fixed | Found independently, not by either audit. `set -e` still caught it (confirmed empirically — it's not a silent bypass), but the operator got a bare "command not found" instead of the actual diagnostic. Added a real VM-side `err()` helper |
| No signed/checksummed release manifest for repo content sourced or copied as root | Tracked below | Directly relevant to the curl-based installer bootstrap being built now — see that section rather than duplicating the reasoning here |
| Rootful Podman as a category of risk | Not a bug | Already a documented, deliberate architecture choice (see README's Architecture section) — rootless was tried and removed in v7-6d for reliability reasons. Restated by the audit, not newly found |
| Unverified Alpine image allowed to continue under `standard` profile | Not a bug | This is the literal, intended difference between `standard` and `production` — `production` already fails closed here. Restated by the audit, not newly found |
## Third-party file-by-file security evaluation (46 files, hash-verified)

A third independent evaluation reviewed all 46 files individually and published a
SHA-256 for each. Those hashes were checked against this repository and **matched
exactly**, so this review was demonstrably run against the current code, not a
stale copy — which also means its "still open" items are genuinely open after the
previous round's fixes, and two of them are cases where the earlier fix was real
but did not go far enough.

Overall verdict, quoted for accuracy rather than paraphrased favorably: *"Strong
security engineering foundation; not yet ready for an unattended production
certification gate."* That is a fair summary and worth keeping visible here.

### Fixed in this round

| **Finding** | **What changed** |
| --- | --- |
| SSH host-key check only warned on failure and always proceeded | Now a real gate. A guest-agent-verified key gets `StrictHostKeyChecking=yes` bound to a `known_hosts` containing only that verified key — which also closes a narrower TOCTOU window `accept-new` never covered (a MITM appearing between the scan and the connection moments later). An unverified or mismatched key now **skips** the SSH-dependent section rather than trusting it, with `--allow-unverified-sshid` as an explicit, named opt-out for a lab VM on a network path you already trust. This is the evaluator's own remediation ("retrieve the guest key… and *then* use `StrictHostKeyChecking=yes`"), which the previous round only half-implemented |
| Host-side execution context not established before privileged work | `lib/00-preflight.sh` now fixes `PATH` to the standard system directories (so a hostile `PATH` entry can't substitute a lookalike `qm`/`qemu-nbd`/`curl`), sets `umask 027` as a floor under anything created without an explicit mode, sets `LC_ALL=C` for deterministic string/sort/regex behavior across every later file, and refuses to source or copy from a group/world-writable checkout |
| Production profile allowed password-only SSH | Production now requires an SSH key and re-prompts until one is supplied, mirroring the existing force-enable pattern for digest pinning directly above it. Standard/lab is unchanged |
| SSH agent forwarding and user scope | Added `AllowAgentForwarding no` and `AllowUsers <admin>`. Note: the evaluation also flagged TCP forwarding, X11 forwarding, and tunneling, but those three were **already** disabled in the generated config — only these two were genuinely missing |
| No overlap protection on scheduled jobs | `wp-cron-run.sh` and `wp-db-backup.sh` each take a `mkdir`-based lock (matching `update.sh`'s existing convention rather than introducing a second locking style), detect a stale lock from a crashed run via recorded PID + `kill -0`, and log non-zero exits through `logger` instead of failing silently |

### Still open, with reasoning

**Signed release manifest (High, raised against four separate files).** This is the
single most-repeated finding in the evaluation and the most substantial one still
open. `install.sh` sources every `lib/*.sh` as host root; `lib/06` copies the whole
payload into the guest; `install-wordpress.sh` executes every stage as guest root.
Nothing cryptographically proves those files are the ones the project published.
The permission check added this round narrows the window — it catches "another
local account could have modified these since you fetched them" — but that is a
genuinely weaker claim than "these are the published bytes," and should not be
mistaken for it.

The reason this isn't fixed here rather than deferred: a manifest is only worth
what its key is worth. Generating a keypair inside a build sandbox and committing
a "signature" next to the code it signs would produce something that *looks* like
supply-chain assurance while verifying the repository against itself — which is
exactly the trust circularity already documented in README's "Verifying what you
run." Doing this properly needs a signing key held outside the repository, a
release process that signs tags, and a published fingerprint users can check
independently. Those are decisions for the repository owner, not something to
manufacture unilaterally. Concretely, when that key exists: generate
`MANIFEST.sha256` over `install.sh`, `lib/**`, and `payload/**`; sign it detached;
have `install.sh` verify signature-then-hashes before sourcing any module; have
`06-vars-and-payload-inject.sh` copy manifest and signature into the guest; and
have `install-wordpress.sh` re-verify immediately before Stage 1. Until then, the
honest posture is the one README already takes: this is the same trust model as
any `curl | bash` installer, stated plainly rather than papered over.

**Carried forward unchanged**, with reasoning unchanged from the sections above:
candidate DB isolation (Critical — still the top item), off-VM backup gate,
Trivy exception governance, Trivy installer checksum, egress restriction,
backup *restore* proof (as distinct from structural verification), and full
candidate-failure/rollback integration coverage. This evaluation independently
reached all seven, which is corroboration of the existing assessment rather than
new information.

**Deliberately not changed: `allow_url_fopen = On` in `php-conf/security.ini`.**
The evaluation recommends disabling it unless a verified plugin needs it. That is
the right default for a locked-down single-purpose host, but this project targets
real WordPress installs: `allow_url_include` (the directive that actually enables
remote code inclusion) is already `Off`, while `allow_url_fopen` is used by many
WooCommerce payment gateways and plugin APIs via `file_get_contents()`. Turning it
off would silently break those integrations at runtime, which is a worse failure
mode than the marginal risk it removes given `allow_url_include=Off`. The reasoning
is already stated inline in the file at the point of use, and the recommended
tighter control — restricting egress — is tracked separately above as its own item.

**Deliberately not changed:** renaming `standard` to `lab` and making `production`
the default. The recommendation is defensible, but it silently changes behavior for
anyone with existing automation or documentation referencing the current names, and
the profile difference is already stated at the prompt, in the summary, and in
README. Worth doing at a major version boundary with a migration note — not as an
unannounced change inside a patch round.

## Planned: safe site import

Importing an existing WordPress site is a stated future direction, and the
malware scanner was built with it in mind rather than retrofitted later. Two
design decisions were made now specifically to support it:

- **`--path <dir>`** — every layer scans an arbitrary tree, not a hardcoded
  `/home/wpuser/wp/html`. An import can therefore be staged somewhere
  isolated and scanned *before* anything is activated.
- **`--json <file>`** — machine-readable findings with severity counts, so an
  import flow can gate on them programmatically instead of parsing console
  output.

What still needs building for import:

1. **Staging area** — unpack the incoming files and database somewhere the
   web server cannot reach, so a webshell in the archive is never executable
   during inspection.
2. **Database import scanning** — the current `db` layer queries a *live*
   database. Import needs the same analysis against a dump file before it is
   loaded, which is a different code path.
3. **A gate with a defined policy** — what happens on a critical finding.
   Refusing outright is wrong (people import known-compromised sites
   deliberately, to clean them); proceeding silently is worse. Probably:
   refuse by default, allow an explicit acknowledged override, quarantine
   flagged files rather than importing them.
4. **Core normalisation** — an imported site's core should be replaced with
   the pinned image's core rather than trusted, since modified core files are
   exactly what an attacker leaves behind.
