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
| Candidate DB isolation (17) | **DONE (light form)** — candidate runs under a temporary SELECT-only account, dropped on every exit path; `wasp-selftest.sh candidate-isolation` proves the grant refuses writes. Does NOT test migrations — see below | The harness this was gated on now exists, but the read-only-DB-account step still needs real-hardware validation before it ships |
| Production findings approval (14) — CLOSED | **DONE** — the y/N override is now a recorded, digest-scoped, expiring exception with a written justification, emailed to a governance address chosen at install | Replacing the HIGH/CRITICAL override prompt with a root-owned, digest-scoped approval file adds an interactive flow that can't be tested without real hardware |
| Off-VM backup gate (18) | **DONE** — optional at install (scp / rsync / rclone), pushed after each verified backup, size-confirmed remotely, and checked weekly by `wasp-selftest.sh`. Append-only destination is prompted for and reported honestly rather than assumed | Requiring/verifying a remote backup before a major DB upgrade is environment-specific (backup system, storage, job IDs) |
| Egress restriction (20) | **DONE as an opt-in** (install prompt + `wp-hardening.sh egress-allow`); still not a default, for the reason below | Host-level egress rules are brittle against legitimate update paths; the network edge (OPNsense/Proxmox FW) is the right layer |
| Trivy installer checksum (15) | **DONE** — pinned to v0.72.0 with the release checksums file anchored by SHA-256, plus a denylist refusing the known-compromised 0.69.4/0.69.5/0.69.6 builds regardless of install path | A pinned SHA-256 needs to be fetched and maintained per installer revision; shipping a wrong/placeholder hash would break installs |
| CrowdSec key in argv (21) | Deferred | Eliminating the brief argv exposure depends on whether the installed cscli supports a stdin/fd interface |
| Backup restoration proof | **DONE** — `wasp-selftest.sh restore-test` restores the newest archive into a throwaway isolated MariaDB and verifies schema, siteurl, users and row counts against production. Weekly | Confirming a scheduled backup archive is *structurally valid* (already done, atomically) is a different, much smaller claim than confirming it *restores clean* — the latter needs a throwaway MariaDB, a real restore, and a data-integrity check, with the same real-hardware-validation bar as candidate DB isolation above. Tracked separately rather than folded in, since it's a distinct piece of work even though both touch backups |
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

**Signed release manifest — MECHANISM NOW IMPLEMENTED, awaiting a key.**
A maintainer-side tool (not shipped) signs a manifest with minisign; `install.sh`
verifies signature-then-hashes before sourcing anything;
`wasp-verify-integrity.sh` re-checks the installed tooling on the VM. What
remains is a decision only the repository owner can make: generate the key,
embed the public half in `install.sh`, and publish the fingerprint somewhere
that is not this repository. Original note follows.

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

## Note on candidate DB isolation as implemented

The read-only account is the lighter of the two designs discussed, and it is
worth being precise about what it buys. It prevents the candidate from
modifying production data, which was the actual risk. It does **not** validate
that a schema migration will succeed, because a read-only candidate cannot
run one.

The heavier design — dump, restore into a throwaway instance, run the
candidate against that copy — would validate migrations too, and remains
unimplemented for the reason originally given: it adds minutes per gigabyte to
every image update and introduces its own failure modes. The restore half of
that work now exists and runs weekly as `wasp-selftest.sh restore-test`, so
the dump is known to be restorable even though the candidate does not use it.

An operator whose compliance regime requires full isolation can compose the
two: restore into a scratch instance with `restore-test`, then point a
candidate at it. The pieces are there; wiring them into every update by
default is the part that is not worth the cost.

## Vulnerability exception governance — final shape

No approval workflow is implemented, and that is a decision rather than a gap.
Request-and-approve belongs in whatever process the operator already runs;
a half-built version inside an installer would add ceremony without adding
oversight, and would be trusted as though it were real.

What is implemented is everything that makes an out-of-band approval
*reviewable* afterwards:

- a written justification, minimum length enforced
- scoped to the exact image digest, so it cannot silently cover a later image
- the accepted CVEs recorded, so a reviewer can judge whether the reason holds
- attributed and dated
- expiring, with the decision required again rather than renewed by default
- append-only root-owned log, with the email explicitly a copy of it
- a reader (`wp-hardening.sh exceptions`) so the log is not write-only
- a weekly warning 14 days before lapse

The remaining gap is inherent: nothing here can verify that the stated
justification was actually discussed with anyone. That is a property of the
process around this system, not of this system.


---

# Idea list — triage

Positions on the remaining items, so a "no" is a decision with a reason
rather than something that quietly fell off the list.

## AIDE / Tripwire — NOT PLANNED, largely redundant here

The gap AIDE fills is "has any file on this system changed unexpectedly".
Most of that is already covered by mechanisms that are stronger *because they
have an external reference*:

- **WordPress core** is compared against `/usr/src/wordpress` inside the
  **pinned, digest-verified** image. That is a cryptographically anchored
  baseline, not a database this host generated about itself.
- **The tooling** under `/usr/local/bin` is compared against the signed
  manifest by `wasp-verify-integrity.sh`.
- **Uploads, plugins and themes** are covered by the structural and YARA
  layers, and by `wp-forensics.sh since-backup`.

What AIDE would add is `/etc` and `/usr` on the host. Real, but narrower than
it sounds: those paths change on every `apk upgrade`, which runs nightly, so
the database needs re-baselining constantly and the signal decays into
"packages updated again". An AIDE database stored on the host it audits is
also trivially re-baselined by an attacker with root — the same limitation
already documented for `wasp-verify-integrity.sh`, but without the signature
that partially offsets it there.

Reconsider if the VM ever stops auto-upgrading, or if a compliance regime
requires host-level FIM by name.

## Optional profile flag `lynis_extra=auditd+aide` — NOT PLANNED

The stated motivation was "MSPs who want the score more than simplicity", and
that is the argument against it. Installing auditd to raise a Lynis number,
on a VM where nothing reads the audit log, adds a daemon, disk churn and an
update surface in exchange for a metric. If an MSP needs auditd because a
client's regime names it, that is a real requirement and belongs in
`MSP-RUNBOOK.md` as a documented deviation — not a flag that makes a score
look better.

## LUKS for data volumes — NOT PLANNED as implemented, worth understanding

Encrypting the VM's data volume protects against exactly one thing: someone
obtaining the disk image without the running system. Against every other
threat here it does nothing, because the key must be present for the VM to
boot unattended.

The options and what each actually buys:

| Approach | Protects against | Cost |
|---|---|---|
| LUKS + passphrase at boot | Stolen disk image | **No unattended reboot.** Every kernel update needs a console |
| LUKS + keyfile on the same disk | Nothing | The key sits beside the data |
| LUKS + key from Proxmox host | Guest-only compromise | Hypervisor still reads both |
| **Proxmox storage-level encryption** | Stolen physical disk | Transparent; no guest change |

For a VM on a hypervisor you control, storage-level encryption is the honest
answer — it covers the same threat without breaking unattended boot. If the
threat is a hostile hypervisor operator, no guest-side measure helps.

**What already covers the realistic case:** off-VM backups are `age`-encrypted
with a public key, so the copies that leave your control are unreadable
without a key that never touches the VM. That is where the data is genuinely
exposed.

## Header comments → docs/ — PARTIALLY, carefully

Raised in an evaluation and in the idea list. The observation is fair: some
headers are design documents.

But the "why" comments have repeatedly been the thing that made a bug
findable — the container-variable scope note, the fail-open explanation, the
heredoc-quoting rationale. Moving them wholesale would optimise for a first
read at the cost of every subsequent debugging session, and this project's
history says the debugging sessions are what matter.

Proposed compromise, not yet done:

- Keep **decision rationale** inline. "Why this, not the obvious thing" is
  worth its lines at the point of the decision.
- Move **historical narrative** — "this failed in the field on date X, here is
  the whole story" — to `docs/design-notes.md`, leaving a one-line reference.
- Only touch files whose header exceeds ~60 lines.

## Safe site import — PLANNED, biggest remaining item

Design notes already recorded above. The primitives exist: `--path` scanning,
`--json` output, quarantine, core comparison against the pinned image. What is
missing is the staging area, dump-file scanning before load, and a gate
policy. This is the highest user-facing win and a session of its own.


---

# Gap analysis — what is still missing

From a systematic pass over the project rather than a summary of it.

## Closed in this pass

- **Dead container images were never reclaimed.** Every `update.sh` left the
  superseded image on disk: roughly 700 MB each, so five updates is 3.5 GB on
  a 20 GB volume. `update.sh` now prunes dangling images *after* the
  post-cutover health check passes and `wordpress-old` is removed — the old
  image IS the rollback path until that moment.
- **Disk usage was reported, never acted on.** `wp-hardening.sh disk` breaks
  down what is consuming the volume and what can be reclaimed;
  `disk-check` runs twice daily and emails once above 80%.

  80% rather than 95% is deliberate: MariaDB refuses writes before the disk
  is actually full, the resulting errors say nothing about disk, and a backup
  that runs out of space leaves you with neither the space nor the backup.

## Open — real, not yet addressed

### Boot ordering says "started", not "ready"

`wp-container` declares `need mariadb-container`. OpenRC waits for that
service to *start*, and `podman start` returns when the container is running —
not when MariaDB accepts connections, which takes 20–60s. A live VM was
observed showing `mariadb Up 22 minutes (starting)`.

WordPress reconnects per request so this is usually self-healing, and the
visible symptom is a brief "Error establishing a database connection" after a
reboot. Worth fixing with a readiness wait in `wp-container`'s start, using
the existing `mariadb-health-check.sh`.

### Nothing knows whether the site is reachable

Every check here runs *on* the VM. If it is off, unreachable, or the
hypervisor is down, nothing reports it — the VM cannot tell you it is gone.
`MSP-RUNBOOK.md` says to pair this with external monitoring, but the project
offers no help doing so.

A `wp-notify.sh --heartbeat` writing to an external dead-man's-switch
(healthchecks.io, Uptime Kuma) would close it cheaply: absence of a heartbeat
is the signal, and absence is exactly what an on-box check cannot detect.

### No secret rotation

Database, SMTP and MariaDB root passwords are generated at install and never
rotated. There is no command to rotate them, and the incident playbook says
"rotate every credential" without providing the means. After a compromise
this is manual, error-prone, and touches several files that must stay in
step — precisely the shape of task that gets half-done.

### TLS certificates are entirely the proxy's problem

Nothing here monitors expiry. If the proxy's renewal breaks, the first
indication is a browser warning seen by a visitor. A check against the public
endpoint would be cheap; a check from inside the VM cannot see the
certificate at all, since TLS terminates at the proxy.

### Bus factor

Several things exist only in one place: the minisign secret key, the age
backup private key, the CTI and Wordfence tokens. Losing the age key makes
every encrypted backup permanently unreadable. `MSP-RUNBOOK.md` covers
decommissioning; it does not cover the operator being unavailable.

Worth a documented custody list — what exists, where it is held, and who else
can reach it — rather than tooling.

### Restore has never been proven end to end

`wasp-selftest.sh restore-test` proves the *local* backup restores into a
throwaway database. Nobody has yet taken an *encrypted, off-VM* copy,
decrypted it on a different machine, and restored it. Those are different
claims, and only the second one is the promise being made to a client.
