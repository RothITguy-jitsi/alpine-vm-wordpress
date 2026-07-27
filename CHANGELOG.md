# Changelog

All notable changes to this project are documented in this file. Versions
follow the informal `vMAJOR-MINOR` scheme this project has used since v7;
this restructuring keeps that scheme rather than switching to SemVer, so
existing references in the field (support tickets, internal docs) still
resolve.

## Unreleased — GeoIP config context + local-address exemption

The libmaxminddb fix worked: the build's new `ldd` gate passed, the module
loaded, and Apache got past `LoadModule`. It then failed on the next thing:

```
AH00526: Syntax error on line 10 of /etc/apache2/conf-enabled/geoip.conf:
<RequireAll not allowed here
```

**Two bugs, the second of which would have surfaced the moment the first was
fixed.**

1. **`<RequireAll>` in the wrong context.** It is an authorization container
   and Apache permits it only in *directory* context (`<Directory>`,
   `<Location>`, `<Files>`, `.htaccess`). `geoip.conf` is written into
   `conf-enabled/`, which is *server* context, so Apache rejected it and
   refused to start — taking the whole site down, not merely disabling
   country filtering. Now wrapped in `<Location />`, which is valid context
   and matches every URL including ones with no filesystem mapping.

2. **Private and loopback addresses have no country.** GeoLite2 has no entry
   for RFC1918 or `127.0.0.1`, so `Require env MM_COUNTRY_CODE` can never
   succeed for them. With `whitelist: US` that meant the in-container health
   check (127.0.0.1) would 403 forever — the install could never see
   WordPress as healthy — **and the operator's own LAN access to wp-admin
   would have been blocked**. Local and RFC1918 ranges are now exempted via
   `<RequireAny>`. This does not weaken filtering for real visitors: where a
   reverse proxy is in front, `mod_remoteip` has already substituted the real
   client address from `X-Forwarded-For` before authorization runs.

**Why the smoke test added last round did not catch this.** It mounted only
`maxminddb.load` — so it validated that the *module* loads, and reported
"Syntax OK", while the file that was actually broken was never mounted. A
smoke test that does not mount what the real container mounts is testing a
different container. It now mounts `geoip.conf`, `wp-security.conf` and the
GeoIP database directory as well.

**Check added:** an Apache container-nesting validator that renders
`geoip.conf` for both whitelist and blocklist modes and fails if
`<RequireAll>`/`<RequireAny>` appears outside directory context, or if any
container is unbalanced. Verified against the original broken form — it flags
it correctly.

---

## Unreleased — REGRESSION FIX 2: broke the WordPress run command

The GeoIP fix from the previous round shipped with a bug of mine that stopped
the installer dead:

```
Error: requires at least 1 arg(s), only received 0
```

**Cause.** To stop stage 06 and `wp-geoip-setup.sh` from drifting apart, I
made stage 06 record the container config to a file. I inserted that write
*into the middle of the multi-line `podman run` command* — after
`-e WORDPRESS_DEBUG="" \`. A trailing backslash continues onto the next line,
and the next line was a comment, so `#` swallowed the remainder of the
logical line: the image argument was never passed. Podman received flags and
no image and refused, and `set -e` ended the install.

**Both `bash -n` and `sh -n` passed on this**, because it is perfectly valid
shell. It is only semantically wrong. Syntax checking cannot catch this class
of error, and I had been treating a clean syntax sweep as sufficient evidence.

**Fixed:** the record is written before the run command begins.

**Two checks added** (`test/check-line-continuations.py`, and a semantic pass):

- **Line-continuation integrity** — a line ending in `\` must not be followed
  by a comment (which truncates the command) or by a bare statement (which
  splits it). Verified by re-injecting the exact bug into a copy: the check
  catches it while `sh -n` still reports the broken file as fine.
- **Every `podman run` must end with an image argument** — joins each
  invocation across its continuations and checks the final token.

**The second check immediately found a third instance of the same drift.**
The `wp-container` OpenRC service — the thing that starts WordPress on
*every boot* — was a third place constructing the container, with its own
hardcoded config and volume list. A site address or SMTP relay configured at
install would have worked until the first reboot and then silently vanished.
It now sources the same record, so all three paths share one definition. The
historical literal survives only as a fallback for a service file written
before this change.

---

## Unreleased — GeoIP root cause: missing runtime library

The GeoIP build log identified it precisely. `mod_maxminddb.so` is linked
against libmaxminddb (`-lmaxminddb` in the link line). The builder stage gets
`libmaxminddb0` as a dependency of `libmaxminddb-dev` — the apt output lists
it under *"The following NEW packages will be installed"*, proving the base
image does not have it. But the final stage starts fresh from that base image
and copied **only the module**. The result was a `.so` with an unsatisfiable
runtime dependency: `LoadModule`'s `dlopen()` failed with
`libmaxminddb.so.0: cannot open shared object file`, Apache refused to start,
and the container exited instantly — after the working container had already
been destroyed.

The build *succeeded*. That is what made it quiet: a green build producing an
image that cannot start.

**Three fixes, at three different depths:**

1. **The bug** — the builder now stages `libmaxminddb.so.0*` into `/tmp/deps`
   and the final image copies it to `/usr/local/lib` (on Debian's default
   `ld.so` path) then runs `ldconfig`.
2. **The check that was missing** — the build now runs `ldd` on the module and
   *fails the build* if anything is unresolved. A structurally broken image
   can no longer be produced at all.
3. **The systemic gap** — `wp-geoip-setup.sh` destroyed the running container
   before proving the replacement worked. Every other risky swap here
   validates a candidate first (update.sh's loopback-candidate pattern); this
   one didn't. It now runs `apache2ctl configtest` against the new image in a
   throwaway container **before** `podman rm -f`, and aborts with the site
   still running if that fails.

**Also fixed: remediation commands that send you down a blind alley.** The
validator prints `podman logs --tail 50 wordpress` as the fix-it command. Run
from the admin account — which is non-root by design — that invokes *rootless*
Podman against an empty container store, so it reports subuid warnings and no
logs, while the real rootful container sits untouched. Every such command now
says `doas podman`. (This is precisely what happened when diagnosing this
failure: the output looked like a Podman configuration problem and said
nothing at all about WordPress.)

---

## Unreleased — GeoIP rebuild fixes (from a second real deployment)

A second field install got much further — the previous regression is fixed and
the installer ran end to end — but finished with WordPress `exited` and
`mod_maxminddb is not loaded`. Three separate problems, one of them mine.

**1. My bug: enabling GeoIP silently reverted two features.**
`wp-geoip-setup.sh` rebuilds the WordPress container from scratch with its
own hardcoded env and volume list. I added the site-address config
(`WP_HOME`/`WP_SITEURL`/proxy scheme handling) and the SMTP credential mount
to stage 06 without mirroring them there, so the moment GeoIP ran, both were
discarded — outbound mail would have stopped working with no error anywhere.

Fixed by removing the duplication rather than adding to it: stage 06 records
the wp-config extras and extra mounts once to
`/etc/wp-install/wp-run-extra.env` (0600), and `wp-geoip-setup.sh` sources
that file. Two paths, one definition, so they cannot drift again. Verified
the record round-trips byte-identically, including PHP `$_SERVER` references
and embedded quotes.

**2. GeoIP reported success while leaving the site down.** Its health loop
failed all 12 attempts, printed a warning, then fell through to `exit 0` —
and stage 06 tests that exit status, so the installer announced "GeoIP
filtering active" while the container it had just rebuilt was failing to
start. It now exits non-zero on an unhealthy rebuild and prints the specific
diagnostic and recovery commands (including how to restore a working site
without GeoIP). No automatic rollback: reconstructing the pre-GeoIP run
command is exactly the duplication that caused problem 1.

**3. Production profile now fails closed on inactive GeoIP.** Consistent with
image verification, digest pinning, the CrowdSec bouncer and sysctls — a
requested control that did not take effect is a failed production install.
Country filtering silently inactive means every request is allowed through,
which is the false sense of protection that profile exists to prevent. Stage
06 also now reports explicitly when the container is not running after the
rebuild, rather than describing it as a missing feature.

**Corrected one of my own diagnoses:** I initially suspected the
`/etc/init.d/wp-container` image was left stale because `wp-geoip-setup.sh`
patches it before stage 07 creates it. On reading the code, stage 06 already
re-reads the effective image from the running container, so the service is
written correctly. No change made — recorded here because it was wrong.

**Not yet diagnosed:** *why* `mod_maxminddb` fails to load. That needs
`podman logs --tail 50 wordpress` and `/var/log/wp-geoip.log` from the failed
VM. Also unexplained: `/` returned HTTP 403 to the in-container health check
for 23 consecutive retries *before* GeoIP ran, while PHP, DNS and the
database all passed — the container was healthy and something in the Apache
config was refusing that specific request.

---



WordPress could not send mail on this VM, and did so silently. The official
container has no `sendmail`, so PHP `mail()` had nothing to hand a message
to; `wp_mail()` returned without a visible error and the UI reported success.
Password resets, notifications, contact forms and WooCommerce receipts were
all being dropped with nothing in any log. No security evaluation caught it,
because it isn't a vulnerability — it's a functional gap that only shows up
when someone needs a password reset.

**Direct-to-relay rather than relaying through the Proxmox host.** PVE's
Postfix is `loopback-only` by default, so using it would have meant binding
it to the bridge and adding the guest to `mynetworks` — reopening a
guest→host capability immediately after adding a rule to block this VM from
the hypervisor's management plane, and creating something a PVE upgrade can
silently revert. A dedicated per-site app password keeps blast radius to one
revocable credential and leaves hypervisor alerting untouched.

- **Interactive prompts** with an explanation of *why* mail fails silently,
  why a dedicated credential matters, and what the port choices mean. Blank
  skips, with a warning naming the consequence.
- **`payload/mu-plugins/01-wpvm-smtp.php`** hooks `phpmailer_init`. Sets a
  10s timeout instead of PHPMailer's 300s default (an unreachable relay
  otherwise hangs registration and password-reset requests for five minutes
  each), sets the envelope sender for SPF alignment, and forces
  `wp_mail_from`/`_from_name` so WordPress stops sending as the usually
  unauthorized `wordpress@<domain>` — which under DMARC `reject` is the same
  silent-drop failure. Certificate verification is left on and deliberately
  not exposed as a toggle.
- **Credentials outside the docroot**: `0400`, uid 33, mounted read-only at
  `/var/www/private/`. Not a container env var, since `podman inspect`
  prints those. Values are escaped for PHP single-quoted context, so an app
  password containing a quote or backslash survives intact.
- **`payload/bin/wp-mail.sh`** — `status`, `test <addr>`, `setup`, `doctor`,
  `log`. `test` goes through `wp_mail()` itself rather than swaks or
  `openssl s_client`: testing the relay another way would prove the relay
  works while saying nothing about whether WordPress can use it.
- **nftables rate limit** on outbound submission (30 new connections/hour,
  burst 10, throttled logging). Stated honestly in the docs as a
  connection-level throttle and tripwire, not a per-message cap.
- **Harness section 9** verifies configuration, file mode/ownership,
  docroot exclusion, mu-plugin presence, read-only mount, and the live
  firewall rule — without sending a live message, since that is a side
  effect a default test run should not have.

---

## Unreleased — REGRESSION FIX: installer was broken by the monolith split

**This one was mine, and it broke the installer outright.** A real deployment
failed at:

```
chmod: cannot access '/tmp/tmp.XXXXXXXX/install-wordpress.sh': No such file or directory
```

**Cause.** In the monolith, `install-wordpress.sh` was *generated* in place by a
~5,880-line quoted heredoc spanning original lines 2294–8175. The split
replaced that heredoc with a `cp` from `payload/`. But `lib/03` ends at
original line 2293 and `lib/04` begins at 8176, so the heredoc's opening line
landed in the **gap between two output files** — and the split tooling only
emitted a replacement when it encountered the opener *inside* the range it was
currently building. The `cp` was dropped silently. The `chmod +x` that had sat
on the far side of the heredoc survived into `lib/04` and pointed at a file
nothing ever created.

**Why the original verification missed it.** The post-split check proved that
every non-replaced line of the original was present, in order, byte-identical —
and that was true, which is exactly why it was misleading. It verified *nothing
was lost from the original*. It never verified *everything intended to be added
was actually added*. Those are different claims, and only the first was tested.

**Fixed:** the copy is restored at the top of `lib/04`, now with an explicit
readable-source check so a missing or half-fetched `payload/` fails with a
sentence naming the cause instead of an error about a temp path.

**Checks added, so this class of bug can't recur silently:**

- **Producer-before-consumer** for host-side artifacts: every `${TMPDIR}/…`
  path must be created by some earlier line than the one that reads,
  `chmod`s, or copies it. Run against all eight `lib/` files in sourcing
  order; this is precisely the check that would have caught the failure.
- **Payload reference resolution**: every `${PAYLOAD_DIR}/…` referenced by any
  stage must resolve to a file that exists (21 references, all resolving).
- **No orphaned tooling**: every script in `payload/bin/` must be installed by
  some stage.

All three pass. Worth stating plainly: the split's line-preservation proof was
sound and still shipped a broken installer, because it answered a narrower
question than the one that mattered.

---

## Unreleased — WordPress plugin/theme update visibility (`wp-plugins.sh`)

A gap found by looking at what the project *doesn't* cover rather than
auditing what it does — and none of the three security evaluations caught it,
because each reviewed the code as written rather than its coverage.

Everything here defended the **container**: digest-pinned images, Trivy
scanning, fail-closed production gates, `update.sh` for image swaps. But
`trivy image` scans the image's OS packages and PHP libraries, and plugins and
themes aren't in the image — they're in the mounted `wp-content` volume,
installed after deployment. Nothing scanned them, nothing reported them going
stale, and a container-image update only ever updated WordPress **core**.

The proportions make that lopsided. Per Patchstack's *State of WordPress
Security in 2026*, of 11,334 vulnerabilities disclosed in 2025 roughly **91%
were in plugins and 9% in themes — core accounted for about six**. Around 43%
require no authentication, and disclosure-to-exploitation is often measured in
hours. So the existing hardening comprehensively addressed the ~6 while the
~11,300 had no coverage at all.

**New: `payload/bin/wp-plugins.sh`**

- `status` — core, plugin, and theme updates available, plus inactive plugins
  (whose code is still on disk and still reachable, a routine entry point).
- `check` — the cron entry point. Silent when everything is current, so a
  weekly job doesn't become noise; reports via syslog with the specific plugin
  names when something is pending.
- `update-plugins` / `update-themes` — explicit, optionally per-slug.
- `update-core` — warns first that `update.sh wp` is the preferred path on
  this VM (pinned, Trivy-scanned image with the candidate/cutover and rollback
  machinery) and that writing core into the volume diverges from the image.
- `doctor` — image, volume, container state, wp-cli self-check, DB reachability.

Wired into stage 08 with a weekly cron report (Mondays 07:00 UTC).

**Design decisions worth stating explicitly:**

- **Reports, never auto-updates.** ~46% of disclosed plugin vulnerabilities
  have no patch at disclosure, so blanket updating cannot close that window;
  plugin auto-update has itself been a supply-chain delivery mechanism; and an
  unattended update that breaks a live site does so unobserved. This matches
  the existing container-layer posture, where cron runs `podman auto-update
  --dry-run` rather than an actual swap.
- **Uses the official `wordpress:cli` image, digest-pinned** alongside the
  other three. Downloading `wp-cli.phar` at runtime would have been simpler
  and would have added precisely the unverified supply-chain dependency this
  project refuses elsewhere (see the Trivy installer checksum item in
  `TODO.md`).
- **Shares the running container's network namespace**
  (`--network container:wordpress`) rather than re-attaching `wp-front` and
  `wp-db` by hand, so it resolves `mariadb` and reaches api.wordpress.org
  exactly as WordPress does, with no duplicated network wiring to drift out of
  sync.
- **Runs as uid 33 (www-data)**, so anything written into the shared volume
  lands with the ownership WordPress expects rather than root-owned files
  WordPress then can't modify.
- **Non-fatal image pull at install.** A registry hiccup shouldn't fail an
  otherwise-good install; the tool degrades to a clear error naming the pull
  command.

---

## Unreleased — WordPress site address configured at install time

An independent improvement rather than an audit response. Previously the
installer configured the infrastructure thoroughly but left WordPress itself
unconfigured: the VM came up, and whoever first browsed to it completed the
setup wizard, at which point **the VM's raw IP became the site's permanent
identity** — written into `wp_options.siteurl`/`.home`, and from there into
permalinks, emails, password-reset links, and serialized plugin/theme option
arrays. Moving to the real domain afterwards then needs a `wp-cli
search-replace` (a plain SQL find-and-replace corrupts serialized data,
because it doesn't fix the embedded string lengths).

**New prompts** (all optional; blank keeps the previous IP-based behavior, so
a lab VM is unaffected):

- **Site domain** — validated as an RFC 1123 hostname. Accepts a pasted
  `https://example.com/` and strips it back to the hostname, but rejects an
  internal-space typo like `exa mple.com` rather than silently deploying under
  a domain nobody typed.
- **Scheme** — defaults to `https` when a reverse proxy IP was given (the
  common NPM/Caddy/nginx arrangement) and `http` otherwise, since nothing in
  this VM terminates TLS on its own.
- **Site title** and **admin email**, asked only when a domain is set.

**What this generates**, in `wp-config.php` via `WORDPRESS_CONFIG_EXTRA`:

- `WP_HOME` **and** `WP_SITEURL`, always both. Setting only `WP_HOME` is a
  known misconfiguration, not merely an incomplete one: `WP_SITEURL` then
  still resolves from the stale database value, which
  `wp-login.php?action=logout&redirect_to=…` can be used to disclose
  (typically the raw VM IP). Because constants take precedence over the
  database, the site is also now portable — changing domains is a config edit
  and a restart, not a data migration.
- **`X-Forwarded-Proto` handling, but only when a trusted proxy is
  configured.** With TLS terminated upstream, PHP sees plain HTTP and
  `is_ssl()` returns false, producing the classic infinite redirect loop.
  WordPress core has declined to fix this for over a decade (Trac #15733) and
  its own documentation says to handle it in `wp-config.php`. The catch is
  that `X-Forwarded-Proto` is an ordinary request header — anything that can
  reach port 80 directly can set it — so trusting it unconditionally would
  let a direct caller assert "this was HTTPS" and defeat `FORCE_SSL_ADMIN` for
  their own session. It is therefore gated on `PROXY_IP`, the same trust
  signal `mod_remoteip` already uses for `X-Forwarded-For`. The leftmost value
  of the header is used, since a multi-hop request yields a comma-separated
  list whose first entry is the original client's scheme.
- **`FORCE_SSL_ADMIN`** alongside that — but deliberately *not* when `https`
  was chosen with no proxy configured, where forcing SSL on an admin panel
  with no working HTTPS path in front of it would lock the operator out of
  `wp-admin` rather than protect anything. That combination warns instead.

Verified that setting `WP_HOME` doesn't break the install's own gate: the
loopback health check accepts 301/302 (it deliberately doesn't follow offsite
redirects), and its PHP-execution and database checks are independent of the
HTTP status, so a redirect to the configured domain still passes.

---

## Unreleased — Third-party evaluation round (hash-verified, 46 files)

An independent file-by-file security evaluation published a SHA-256 for every
file; all of them matched this repository exactly, confirming the review ran
against current code. Its overall verdict — *"strong security engineering
foundation; not yet ready for an unattended production certification gate"* —
is recorded as-is in `TODO.md` rather than softened. Two findings were cases
where a fix from the previous round was real but didn't go far enough.

**Fixed:**

- **SSH host-key verification in the test harness is now a gate, not a
  warning.** The previous round added a guest-agent cross-check but proceeded
  regardless of its result. A verified key now gets `StrictHostKeyChecking=yes`
  against a `known_hosts` holding only that key — which additionally closes a
  TOCTOU window `accept-new` never covered — and an unverified or mismatched
  key skips the SSH section instead, with `--allow-unverified-sshid` as an
  explicit lab opt-out.
- **Host-side execution context hardened before any privileged work**
  (`lib/00-preflight.sh`): fixed `PATH` (blocks lookalike-binary substitution
  for `qm`/`qemu-nbd`/`curl`/etc.), `umask 027`, `LC_ALL=C`, and a refusal to
  source or copy from a group/world-writable checkout.
- **Production profile now requires an SSH key**, re-prompting until one is
  given, instead of silently permitting password auth on the admin account —
  mirroring the existing digest-pinning force-enable directly above it.
- **`AllowAgentForwarding no` and `AllowUsers <admin>`** added to the generated
  sshd config. (The evaluation also listed TCP/X11/tunnel forwarding, but those
  were already disabled — only these two were genuinely missing.)
- **Scheduled-job overlap protection**: `wp-cron-run.sh` and `wp-db-backup.sh`
  each take a `mkdir`-based lock — matching `update.sh`'s existing convention
  rather than adding a second locking style — with stale-lock detection via
  recorded PID plus `kill -0`, and non-zero exits logged via `logger` rather
  than passing silently.
- **Kernel hardening sysctls are now verified, not assumed.** Applying
  `99-hardening.conf` discarded both sysctl's output and its exit status, then
  printed "Sysctls applied" unconditionally — so a key this kernel rejects
  reported success anyway. Every key is now parsed from the file (not a
  hardcoded list that could drift) and read back to confirm the value actually
  took effect; production fails closed on a mismatch, standard warns and lists
  exactly which keys didn't apply.
- **Assurance language tightened** in `README.md` and `test/README.md`, per the
  finding that phrases like "verified backups" can read more strongly than
  what's implemented. Backups are now described as integrity-checked on
  creation, explicitly *not* restore-proven; `ssh-keyscan` is named as
  unauthenticated discovery rather than verification.

**Still open — signed release manifest (High, raised against four files).**
Nothing cryptographically proves that `lib/` and `payload/` are the published
bytes before they run as root. The permission check added here narrows the
window but is a weaker claim and isn't presented as equivalent. This is
deferred rather than fixed because a signing key generated in a build sandbox
and committed beside the code it signs would verify the repository against
itself — the same trust circularity already documented in README's "Verifying
what you run." `TODO.md` records the concrete implementation plan for when a
real out-of-band signing key exists.

**Deliberately not changed:** renaming `standard` → `lab` and defaulting to
`production`. Defensible, but it silently breaks existing automation and
documentation; appropriate for a major version boundary with a migration note,
not a patch round.

---

## Unreleased — Forensic audit fixes + curl-based single-command install

An independent security evaluation was run against the just-restructured
repository. Every claim in it was checked directly against the code before
acting on it — four of its Critical/High findings turned out to be
re-discoveries of items this project already had tracked in `TODO.md` as
deliberately deferred (candidate DB isolation, off-VM backup gate, Trivy
findings override, Trivy installer checksum); those are noted as
corroborated, not re-explained here. What follows is what was actually new
and has been fixed, plus one bug found independently of either audit. Full
detail, including what's still open and why, is in `TODO.md`'s
"Independent re-audit" section.

**Fixed:**

- **Root SSH login no longer re-enables itself.** It used to fall back to
  enabling root over SSH if creating the dedicated admin account failed.
  Console access (`qm terminal <vmid>`) already covers that recovery case
  — the root password is set unconditionally specifically for it — so the
  fallback was trading a working recovery path for a worse one it didn't
  need. Root SSH now stays disabled unconditionally, in
  `lib/04-nbd-mount-and-chroot.sh` and `lib/05-ssh-and-network-inject.sh`.
- **The CrowdSec firewall bouncer failing no longer passes silently in
  production mode.** CrowdSec's engine only *detects* and decides bans;
  the bouncer is what *enforces* them via nftables. A bouncer that never
  starts used to just print a warning and continue — meaning a "clean"
  install could have detection with no enforcement behind it, in every
  deployment profile. `DEPLOYMENT_PROFILE=production` now fails closed
  here, matching the pattern already used for Alpine image verification
  and digest pinning elsewhere in this same install.
  (`payload/stages/09-crowdsec-and-backup.sh`)
- **The `uploads-php` debug escape hatch now expires automatically.**
  Temporarily allowing PHP execution in `wp-content/uploads` (via
  `wp-hardening.sh enable uploads-php`) had no time limit — exactly the
  kind of thing that gets left open and forgotten, in exactly the
  directory an attacker who can upload a file would want PHP to run in.
  It now writes a timestamp marker on open, and a new cron entry
  (`wp-hardening.sh check-expiry`, every 15 min) auto re-blocks it after
  one hour if it hasn't been closed manually.
- **CrowdSec's IPv6 setting was internally contradictory** —
  `disable_ipv6: false` alongside `nftables.ipv6.enabled: false`. This
  deployment's firewall has no IPv6 rules at all; the bouncer config now
  says `disable_ipv6: true` to match, instead of implying IPv6 decisions
  were being enforced when they never were.
- **CSP's `unsafe-eval` no longer applies site-wide.** It's genuinely
  needed for the WordPress block editor in `/wp-admin/`, not for most
  themes' public-facing pages. Scoped to a `<LocationMatch>` for
  `/wp-admin/` and `/wp-login.php` (this also correctly covers requests
  arriving through the custom admin slug, which are internally rewritten
  to those real paths before Apache serves them); the site-wide default
  keeps `unsafe-inline` (far more commonly needed) but drops `unsafe-eval`.
- **The integration test harness's SSH host-key trust was pure
  network-path TOFU.** `ssh-keyscan` + `accept-new` can't detect a MITM on
  the *first* connection, only a *later* key change — and the harness's
  own prior comment already named the right fix without building it.
  It now cross-checks the network-observed key fingerprint against one
  fetched via the Proxmox guest agent (a genuinely separate channel from
  the network path SSH uses), falling back to the original TOFU behavior
  with a loud warning if the agent doesn't answer.
- **`README.md` linked to a `LICENSE` file that didn't exist.** Added
  (MIT, matching what was already claimed).
- **A real bug, found independently of either audit:** `install-wordpress.sh`'s
  `DEPLOYMENT_PROFILE=production` digest-pinning fail-closed path called
  `msg_error`, a host-side-only function that was never in scope inside
  the VM's own install process. Checked empirically — `set -e` still
  caught the resulting "command not found" and aborted the install, so
  this was never a silent bypass — but the operator got a bare error
  instead of the detailed, actionable message the code was written to
  show them. Added a real VM-side `err()` helper and fixed the call site.
- Added brief rationale comments for two already-reasonable, already-safe
  tradeoffs the audit flagged without full context: MariaDB's
  `innodb_flush_log_at_trx_commit=2` (durability/throughput tradeoff,
  appropriate for this project's target of a single self-hosted site) and
  the existing PHP/logrotate settings (already documented at point of use).

**New: single-command install, no `git` required.**
`install.sh` can now be fetched and run entirely on its own:

```bash
curl -fsSL -O https://raw.githubusercontent.com/RothITguy-jitsi/alpine-vm-wordpress/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

Proxmox doesn't ship `git`, and the goal was to avoid installing it just to
fetch a script. `install.sh` now detects whether it's running from a full
checkout (sibling `lib/`/`payload/` present) or standalone, and if
standalone, fetches the rest of the repository itself as a
GitHub-generated tarball — a plain HTTPS download, not a `git clone` — into
a temp directory that the existing `cleanup()` trap removes when the run
ends, success or failure alike. A full `git clone` still works exactly as
before and skips this step entirely, since it already has everything
`install.sh` needs sitting right next to it. See README's
["Verifying what you run"](README.md#verifying-what-you-run) for the trust
model this implies (the same one every single-file `curl | bash` installer
has) and how to pin a specific commit instead of always fetching `main`.

---

## Unreleased — Repository restructuring (split from the monolithic script)

This release contains **no functional or behavioral changes** to the
installer. It is a pure reorganization of `create-wordpress-vm-v8-1.sh`
(previously a single 8,694-line file) into a GitHub/Gitea-ready repository
of small, purpose-scoped files, done so the project can be published and
maintained as normal source rather than one script. Every change below is
mechanical: content was moved, not rewritten, and was verified line-for-line
against the original before and after the split (see `test/` for the
harness used to confirm the generated VM is unchanged).

**What changed:**

- **Host-side provisioning** (the part that runs on the Proxmox host) is now
  `install.sh` plus `lib/*.sh`, sourced in numbered order — preflight and
  validation, Alpine image handling, dynamic config-block generation, disk
  build, VM creation — instead of one top-to-bottom script.
- **The in-VM installer** (previously built by writing an ~5,880-line quoted
  heredoc to a temp file) is now `payload/install-wordpress.sh`, a thin
  dispatcher that sources 10 numbered stage files from `payload/stages/`.
  Its two-phase, reboot-driven install sequence (kernel switch, then
  containers) is unchanged.
- **Every script that used to be generated on the fly via a heredoc** —
  `update.sh`, `validate-wordpress.sh`, `wp-hardening.sh`,
  `wp-health-check.sh`, `mariadb-health-check.sh`, `wp-geoip-setup.sh`,
  `wp-db-backup.sh`, `wp-cron-run.sh`, the CrowdSec OpenRC service, and
  every static config file (sysctl, PHP, MariaDB, logrotate, the mu-plugin,
  the CrowdSec `acquis.yaml`, the cron schedule) — is now a real, standalone
  file under `payload/`. The host/VM side copies it into place instead of
  regenerating it from a heredoc.
- **Two heredocs that generate OpenRC/config files with a couple of
  install-time values baked in** (the `mariadb-container` service, the
  CrowdSec firewall-bouncer config) were converted to plain template files
  under `payload/templates/` with `__TOKEN__` placeholders, substituted with
  `sed` at the same point in the install where the heredoc used to run. This
  removes the backslash-escaping those two heredocs needed (to stop `$(...)`
  and backticks meant for the *target* file from being evaluated immediately
  by the *writing* shell) in favor of a template that is just... valid shell,
  readable and shellcheck-able on its own. Every other value-bearing heredoc
  (credentials, nftables rules, Apache CIDR blocks, `vars.sh`, the
  `wp-container` service — which bakes in more than two values, some
  multi-line) was left exactly as it was: still the right tool for content
  that has to carry real secrets or multi-line values at generation time.
- **`scan-heredocs.py` has been removed.** It existed to catch exactly one
  bug shape: a heredoc meant to write a literal, executable script body
  (`cat > .../some-script.sh << DELIM`) left with an *unquoted* delimiter, so
  `` ` `` / `$(...)` inside that body got evaluated immediately by the
  writing shell instead of staying literal for the script to interpret later
  (the bugs the tool's own docstring cites: #70 and #71). That failure mode
  requires a heredoc whose body is destined to become an executable script
  file. After this split, no such heredoc exists anywhere in the
  repository — every one of those bodies is now a plain file. The scanner
  has nothing left to check; keeping it would mean shipping a tool that can
  only ever print "no errors" against this codebase. The two remaining
  templated files use `sed` substitution, not heredoc generation, so they
  are outside the scanner's problem space too. (Its general "flag a stray
  backtick in any unquoted heredoc" info-level check was never a hard gate
  for the value-bearing heredocs that remain — see the tool's own docstring
  — so nothing that used to be caught is now unguarded.)
- `README.md` gained a repository-structure and requirements section;
  architecture notes that were living in the script's header comment
  (rootful container design) moved there too, since they describe a
  standing design decision, not a dated change.
- `test-wordpress-vm.sh` and `test-harness-README.md` moved into `test/`.

No prompts, defaults, generated file contents, permissions, package
versions, or ordering of operations changed. If you diff what lands on a
freshly-provisioned VM against a v8-1 install, it should be identical.

---

## v8-1 — ChatGPT-evaluation fixes

CHATGPT-EVALUATION FIXES. Five verified fixes from a static forensic review; each was confirmed against the actual code before changing, and the changed logic was mock-tested. All changes are tagged "v8-1" in comments at their sites.

1. [HIGH] validate-wordpress.sh used BusyBox-incompatible GNU wget options (--max-redirect/--tries/--timeout) — the exact bug already fixed in wp-health-check.sh but missed here, so the validator produced false HTTP/security failures on Alpine. Replaced with the same PHP-from-container probe the health checker uses. (v8 eval finding 16)

2. [HIGH] 'update.sh upgrade' could exit 0 even when a component upgrade failed — each failure was swallowed by '|| echo' and do_upgrade returned the last command's status, so cron/monitoring saw success on a partial failure. It now aggregates per-component results, prints a summary, and returns non-zero if any accepted upgrade failed. (v8 eval finding 10)

3. [HIGH] MariaDB LTS logic assumed every future major.3 (13.3, 14.3, …) is LTS and still labelled 10.6 as LTS after its 2026-07-06 community EOL. Replaced the inference with explicit maintained supported/EOL allowlists; version discovery now shows supported/EOL/rolling state and warns loudly when the pinned line is EOL. (v8 eval findings 7 & 8)

4. [MED] The guided MariaDB upgrade inferred the next step from sorted numbers. It now offers only a DOCUMENTED single-step LTS transition (10.6→10.11→11.4→11.8→12.3) and refuses to infer a path from an unrecognized/rolling source. (v8 eval finding 9)

5. [MED] DB backups gzipped straight to the final filename, so a crash mid-gzip could leave a truncated wp-db-*.sql.gz that looks complete. The scheduled backup now stages to a hidden temp file and publishes with an atomic rename; both dumps gained --quick --hex-blob. (v8 eval finding 19)


**COMPANION TOOL**: scan-heredocs.py (ships alongside) implements the heredoc command-substitution scanner the notes referred to but hadn't shipped as identifiable code — run it before provisioning. (v8 eval finding 22)

DELIBERATELY DEFERRED (documented, not silently dropped): production HIGH/CRITICAL Trivy findings remain overridable via prompt rather than a root-owned digest-scoped approval file (finding 14 — adds an interactive flow that can't be tested without real hardware); candidate WordPress still uses the live production DB (finding 17 — the integration harness this was gated on now exists, but the read-only-DB-account step still needs real-HW validation); no off-VM backup gate before a major DB upgrade (finding 18 — environment-specific); egress stays open (finding 20 — enforce at the network edge); Trivy installer lacks a pinned checksum (finding 15 — needs a maintained SHA); CrowdSec enrol key still appears briefly in argv (finding 21 — depends on cscli's stdin support). _ver_cmp treating a non-numeric field as 0 (finding 4) is left as-is: it fails SAFE (malformed sorts lowest) and upstream grep filtering means malformed tags never reach it.

## v8 — Version discovery + production fail-closed toggles

VERSION DISCOVERY + PRODUCTION FAIL-CLOSED TOGGLES. This release adds the future enhancements tracked in the TODO. The headline feature answers a question the tool couldn't previously answer: not "has the tag I'm pinned to been rebuilt?" (that's digest-check) but "has a newer VERSION been published?" — e.g. you're pinned to WordPress 6.9.4 and 6.9.5 ships with a security fix. You need to SEE that and CHOOSE to move the pins across all components. That's what version discovery does.

- **A.** VERSION DISCOVERY (update.sh versions) [new, fully tested] A read-only report that queries the registry (Skopeo list-tags + jq) and shows, per component, the pinned version vs the newest published release, with the exact command to move to it. It is deliberately separate from digest-check: digest-check tracks same-version rebuilds; this tracks new versions. Filtering is release-aware — WordPress excludes beta/RC/cli and non-matching PHP/server variants; CrowdSec takes stable vX.Y.Z only. Version comparison is a pure-POSIX numeric dotted compare (_ver_cmp), so 6.9.10 correctly ranks above 6.9.9 and 6.10 above 6.9 — no reliance on `sort -V`, which BusyBox sort may lack.

- **B.** MARIADB IS LTS-AWARE [new] CRITICAL nuance the research surfaced: for MariaDB, a higher version number does NOT mean more support. Rolling releases (11.5/11.6/11.7, 12.0/12.1/12.2, …) reach EOL SOONER than the LTS they follow — MariaDB 12.2 hit EOL while 10.11 LTS is supported into 2028. A production database must track LTS lines only. So version discovery for MariaDB reports and offers ONLY LTS lines (10.6, 10.11, 11.4, 11.8, and the .3 release of each major from 12 on — 12.3, 13.3, …), recommends the NEXT LTS as the safe one-step move, and never offers a rolling release.

- **C.** GUIDED CROSS-COMPONENT UPGRADE (update.sh upgrade) [new, tested] Walks all three components and, for each that has a newer release, offers to move the pin — then runs the ORDINARY update path for that component (do_wp_update / do_db_update / do_cs_update). So a version bump inherits every existing safety property unchanged: the candidate is proven on a loopback-only throwaway container first, the new digest is pinned, a failure rolls back to the current version, and the GeoIP mod_maxminddb layer is rebuilt on the new base if GeoIP was active. MariaDB is offered the next LTS only. Each component is confirmed separately.

- **D.** PRODUCTION FAIL-CLOSED: FIREWALL DEPENDENCY [new, tested] Addresses the audit's fail-closed suggestion without giving up the reason the soft dependency existed. Under the standard profile the container services keep "use nftables" (soft — a firewall hiccup can't strand the DB; availability first). Under DEPLOYMENT_PROFILE=production they switch to "need nftables" (hard — if the firewall fails to start, MariaDB does not start, and because wp-container needs mariadb-container and crowdsec needs wp-container, the whole publicly-exposed stack stays down rather than run unprotected). Gated on the profile the installer already sourced.

- **E.** PRODUCTION FAIL-CLOSED: TRIVY REQUIRED [new, tested] The two "skippable" gaps in the CVE scan are closed under production. If Trivy isn't available, or a scan doesn't COMPLETE (DB download failure, registry timeout, corrupt cache — an unknown security state, not a clean result), the standard profile still prompts/skips so a lab install isn't blocked, but production REFUSES the update outright. A genuine findings result (HIGH/CRITICAL) keeps the operator prompt in both profiles, since that's an informed judgement call (the new version may fix a different critical CVE). This gates version upgrades too — upgrading in production requires a completed scan of the target image.

- **F.** CANDIDATE DATABASE ISOLATION IN PRODUCTION [DEFERRED — with reasoning] The remaining TODO item — clone/isolate the DB so a write-on-init plugin in a new WordPress image can't touch production during candidate validation — is NOT shipped here, deliberately. It is the one enhancement that cannot be validated without exercising live container + MariaDB + network orchestration on real hardware, and the entire v7-16 round was a lesson in what happens when orchestration ships unvalidated (four of that round's seven bugs passed every syntax check and only failed on real hardware). Shipping ~100 lines of untested clone logic with production blast radius (orphaned containers, disk exhaustion, or an isolation gap that lets the candidate reach live data) would repeat exactly that mistake. The TODO documents two concrete designs (a temporary read-only DB user as the simpler first step; a full dump-and-restore clone as the stronger one) to implement once the integration-test harness — the standing top recommendation — exists to prove it end-to-end. The current candidate mitigations from v7-13 remain in place: production docroot mounted read-only, throwaway tmpfs logs, WP_ENVIRONMENT_TYPE=staging.

## v7-16 — Post-install field-bug sweep

POST-INSTALL FIELD-BUG SWEEP. The v7-15 DNS fix worked (the field install reached the containers, updates run cleanly, 3/3 digests verify), but running v7-15 surfaced a fresh batch of bugs — including one I introduced in v7-15 that broke the install-complete state, and one I introduced in v7-14. Plus the actionable items from an independent ChatGPT audit of v7-15.

70. [CRITICAL, self-inflicted in v7-15] BACKTICKS IN COMMENTS INSIDE UNQUOTED HEREDOCS were executed as command substitution. My v7-15 DNS comment in the NFT_CONF heredoc (opened with `<< NFTEOF`, which MUST be unquoted so ${SSH_RULE}/${WEB_RULE} expand) contained `policy drop`, `netavark`, `drop` in backticks, and the mariadb-container OpenRC service heredoc (`<< ORCSVC_DB`, also unquoted) had `flush ruleset`, `netavark`, `use`, `need` in backticks. The shell ran each backticked phrase as a command both when the outer script wrote the installer AND when the installer wrote /etc/nftables.nft and /etc/init.d/mariadb-container, spraying "policy: command not found", "netavark: command not found", "flush: command not found", etc. through the install (visible in the field log at generated lines 1806 and 2090). The rules themselves still landed, but the noise was alarming and the command-substitution could in principle have injected output. FIX: removed every backtick from comments inside unquoted heredocs (plain words / double quotes instead), and added a scanner to the validation pass that greps every unquoted heredoc body for backticks so this class can't recur.

71. [CRITICAL, self-inflicted in v7-14] WORDPRESS HTTP HEALTH CHECK ALWAYS FAILED with "Unexpected HTTP response: none", blocking the install-complete state through all 24 retries even though PHP, DNS, and the DB query all passed. My v7-14 hardening used GNU wget long options — --max-redirect, --tries, --timeout — but Alpine's wget is BusyBox wget, which supports none of them; it rejected the unrecognized option and printed nothing parseable, so awk extracted an empty string every time. (The separate post-install validator check PASSED because it uses PHP from inside the container, which is why "Port 80 listening" and "WordPress HTTP response" were green while the health check was red.) FIX: do the request from inside the container with PHP (always present in the WP image), using follow_location=0 to pin to the server's own first response — exactly what --max-redirect=0 was reaching for, but in a way that works here — and ignore_errors=true so 3xx/4xx are captured, not thrown. This is the same method the post-install validator already uses successfully.

72. [MEDIUM] `update.sh status` printed "column: not found". The status table was piped through `column -t`, but `column` (util-linux) isn't on stock Alpine, and the `|| true` didn't suppress the shell's "not found". FIX: use podman's own `table` format directive (native column alignment, no external tool), re-indented with sed.

73. [MEDIUM] GeoIP GeoLite2 download failed with "HTTP 302". MaxMind's download endpoint 302-redirects to a pre-signed CDN URL, and the initial-download curl lacked -L (the weekly refresh cron already had -fsSL). Without -L curl wrote the redirect body instead of the database and the 200 check failed on 302. FIX: added -L so curl follows to the CDN (credentials are correctly not resent across the redirect since the CDN URL is pre-signed).

74. [MEDIUM] The helper scripts (validate-wordpress.sh, update.sh, wp-hardening.sh) hard-failed for the unprivileged admin. Run over SSH as wpadmin — the only session where copy/paste works, since the root console via `qm terminal` can't paste — validate-wordpress.sh died with "can't open /etc/wp-install/vars.sh: Permission denied", and the others printed "Run as root". FIX: all three now auto-elevate via doas (re-exec `doas "$0" "$@"`), so they "just work" over SSH: doas prompts for the admin password once (permit persist :wheel), then everything runs as root with output in the copyable SSH session. --help/--list skip elevation. Also switched the vars.sh source guard from -f to -r so a non-readable file degrades cleanly.

75. [MEDIUM] The validator reported two FALSE failures that traced back to #74 AND to values simply not being where it looked. (a) "No wp-admin IP restriction configured" even when one was set — it gated on ${ADMIN_CIDR}, which was never written to vars.sh, so it was always empty. FIX: check the Apache config's `Require ip` block directly (the actual enforcement) as the source of truth, and also write ADMIN_CIDR/ALLOWED_ADMIN_IP/PROXY_IP/SSH_CIDR/WEB_CIDR to vars.sh for display. (b) "Digest pinning: 0/3 pinned" while `update.sh` correctly showed 3/3 — the digests live in pinned.env, not vars.sh, and the validator never sourced pinned.env. FIX: source it too (readable now that #74 runs the validator as root). Also downgraded the fresh-install backup checks ("directory does not exist" / "no backups yet") from FAIL to WARN, since a VM minutes old hasn't reached its first scheduled 02:00 backup — a genuinely broken backup system still fails via the >48h staleness check once a backup exists.

76. [DOC] Clarified the version-bump model in `update.sh` status output. A user expected `update.sh all` to offer a new WordPress major (7.0.2) and was confused when it didn't. That's deliberate: `all` and `digest-check` track newer DIGESTS under the tag you're already on (e.g. a same-version security rebuild), and never jump major versions on their own, so an unattended update can't swap in a new major. To move versions you name it: `update.sh wp <version>`. The status output now spells this out. From the v7-15 audit, also applied: DHCP input rules scoped to the gateway destination (matching the DNS rules' precision) rather than any host-local address. NOT changed, same reasoning as prior rounds: Trivy skippable and candidate-DB-in-standard-profile remain the documented tradeoffs (the audit's own fix is "make it configurable" — a feature, not a defect); `use nftables` (vs `need`) is kept so a firewall hiccup doesn't strand the DB, with fail-closed left as a future production-profile toggle.

## v7-15 — Install-failure fix + audit response

INSTALL-FAILURE FIX + AUDIT RESPONSE. This version fixes the reason a v7-14 install failed in the field (WordPress could not reach MariaDB) plus the actionable findings from an independent ChatGPT audit of v7-14. The install-failure fix is the important one — it would recur on every install until patched.

64. [CRITICAL] WORDPRESS COULD NOT RESOLVE THE 'mariadb' HOSTNAME — the install failed here, retrying DNS 24 times and giving up. MariaDB itself was fully healthy (its own in-container healthcheck passed every gate), but WordPress on the wp-db network kept reporting "mariadb hostname does not resolve (Aardvark DNS / wp-db network issue)". Root cause: aardvark-dns (Podman's DNS) runs ON THE HOST, bound to each network's GATEWAY IP (10.89.20.1, 10.89.10.1) on port 53. A container's DNS query goes to that gateway — a host-local address — so the packet traverses the nftables INPUT hook, not the forward hook. The input chain had `policy drop` and no rule permitting the container subnets to reach the gateway on 53, so every lookup was silently dropped. (MariaDB worked because talking to itself over localhost needs no DNS.) Netavark adds its own accept in a separate table, but an nftables `drop` verdict in ANY base chain on a hook is final, so the filter chain's drop policy overrode it. FIX: explicit input-chain accepts for udp+tcp port 53 from both container subnets to their gateways, plus DHCP (67). Also fixed a related boot hazard: /etc/nftables.nft does `flush ruleset`, which wipes netavark's table (container NAT + DNS); the mariadb/wp/crowdsec OpenRC services now order `after nftables` + `use nftables` so the firewall loads first and netavark lays its table on top without being flushed later.

65. [MEDIUM] logrotate config failed to validate on the VM (v7-14 bug of my own): `copytruncate` and `create` were in the same stanza, and per the logrotate man page `create` has no effect with copytruncate — the combination is rejected/ignored inconsistently across versions. Removed the pointless `create`. Validation now checks OUR file specifically (a tiny wrapper `include`) instead of the whole /etc/logrotate.conf tree (which pulls in distro fragments we don't control), and surfaces the actual error text instead of a generic "did not validate".

66. [MEDIUM, audit #4] logrotate ran once daily, which made `maxsize 50M` cosmetic — a traffic spike could grow a log to gigabytes before the cap was ever evaluated. Now runs HOURLY (the `daily` directive still limits low-volume rotation to once a day); the size cap is now real.

67. [MEDIUM, audit #14] scheduled + in-flight backups omitted stored routines, events, and triggers — a restore would rebuild tables but silently drop the logic operating on them. Added --routines --events --triggers --single-transaction to both mariadb-dump calls. The daily backup filename now includes the time (not just the date) so a manual backup on the same day doesn't overwrite the scheduled one.

68. [MEDIUM, audit #2] the Skopeo JSON fallback parser relied on the manifest "Digest" appearing before the LayersData array in field order — not a stable contract. It now uses jq (`.Digest // empty`, extracted by key) with the ordering-based grep kept only as a last resort if jq is absent. jq is installed alongside aardvark-dns.

69. [HIGH, audit #13] SSH_CIDR / WEB_CIDR / ADMIN_CIDR / ALLOWED_ADMIN_IP / PROXY_IP were inserted verbatim into nftables and Apache config. A malformed value could break the firewall load (leaving the host unprotected) or Apache startup (leaving the site down), or slip a stray token into a security rule. All five are now validated at prompt time (CIDR fields accept IPv4 or IPv4/prefix; single-IP fields reject CIDR and lists), re-prompting on bad input. Defence in depth: the generated ruleset is `nft -c` syntax-checked before it's applied, and if the check fails the ruleset is NOT loaded (rather than half-loading and leaving the firewall broken). Also added to validate-wordpress.sh: an explicit container-DNS resolution check (the #64 failure, with the exact firewall rule to inspect as its remedy), a check that the input chain carries the port-53 accepts, and consistency with the logrotate validation fix. NOT changed, with reasoning (audit findings that are deliberate tradeoffs, not defects): Trivy remains skippable and the candidate still uses the production DB in `standard` profile — both are the same documented cost/benefit calls from v7-13; the audit's own remediation for each is "make it configurable / use for production profile", a feature request rather than a bug. The residual candidate-DB risk is already documented inline in do_wp_update().

## v7-5d — Baseline sweep (older v2-v7-1 notes retired)

Older per-version notes (v2 through v7-1) have been removed from this header — those bugs are long fixed and stable, and kept growing into a changelog nobody was reading; this starts fresh. Every fix below was diagnosed from a real install log, not speculation.

**CUSTOM WP-ADMIN SLUG** — was completely non-functional, no error anywhere:

1. [CRITICAL] The slug's RewriteRules lived bare in wp-security.conf, which loads in Apache's main-server context — but the <VirtualHost> that actually serves every request never inherits main-server rewrite rules without an explicit `RewriteOptions Inherit` (never set). Dead config: no error, nothing in any log, slug just silently never fired.

2. mod_rewrite has a SECOND, independent non-inheritance boundary between a <Directory> block and a .htaccess file at the same path. Fixed by placing the same rules directly in .htaccess — the same per-directory ruleset that already makes permalinks and the 8G firewall work — ahead of the WordPress-managed BEGIN/END block, with the <Directory> copy kept as free defense-in-depth.

3. The author=N enumeration block had the identical bug; fixed the same way.


**GEOIP COUNTRY FILTERING** — was silently never applying, even with valid MaxMind credentials:

4. [CRITICAL] The mod_maxminddb build container ran on Podman's default bridge subnet, which the wp-net-only nftables forward rule silently dropped — no internet access during build, apt-get/curl failed, `podman build` failed, and every downstream step (geoip.conf, the compiled module, the mmdb database) never ran, with nothing surfaced as an error. Fixed with --network host for that one build step.

5. [CRITICAL] A bare `make` (no `make install`) never installs the compiled module into /usr/lib/apache2/modules — confirmed directly from a real build log where make succeeded but the module stayed in the build tree at .libs/mod_maxminddb.so. Fixed by searching recursively under the build directory instead of a hardcoded (and wrong) install path, with a hard failure if it's still not found instead of a confusing error two steps later.

6. GeoIP setup is now its own standalone, idempotent script — /usr/local/bin/wp-geoip-setup.sh — so a bad credential or a transient network issue can be fixed and retried on a live VM with one command: no reboot, no re-running the full installer.

7. `update.sh wp` used to silently destroy GeoIP on every WordPress update (pulled the bare upstream image with no knowledge of the custom GeoIP image or its mounts). Now re-invokes wp-geoip-setup.sh automatically after a successful base-image update.


**SHA256 DIGEST PINNING** — new:

8. WordPress/MariaDB/CrowdSec are pinned to the exact digest resolved at install time, not just the tag — resolved dynamically via `podman pull` + `podman inspect`, never hardcoded (a hardcoded digest goes stale the moment a registry rebuilds an image under the same tag). Toggle at the install prompt, or via USE_DIGEST_PINNING in /etc/wp-install/vars.sh afterward.

9. Podman's support for combined tag+digest references varies across versions (older releases hard-reject it; some newer ones accept it but drop the local tag) — tested directly against this host's Podman rather than assumed, with a safe digest-only fallback either way.

10. Pull and digest-resolution each retry up to 3 attempts before falling back to an unpinned reference. Every outcome — success or fallback — is logged with the real podman error text to /var/log/wp-digest-pinning.log, and a pin-count summary ("Digest pinning: 3/3 pinned") is shown at install and in `update.sh check`.

11. `update.sh digest-check` finds and offers to move to a newer digest published under the SAME tag (e.g. a same-version security rebuild), which a tag-only version comparison would never catch.

12. [CRITICAL, since fixed] An earlier iteration of this feature corrupted every pinned image reference: ok()/warn() print to stdout, and `$(...)` command substitution captures a function's ENTIRE stdout, not just its final `echo` — so the human-readable status line was landing inside the variable itself. Fixed by routing every in-function diagnostic to stderr.


ALPINE IMAGE INTEGRITY:

13. The downloaded Alpine cloud image is now verified against a freshly fetched .sha512 (Alpine publishes SHA-512 for cloud/ qcow2 images, not SHA-256 — confirmed directly against the CDN), fetched fresh every run rather than a hash hardcoded against a version selector that floats across point releases.


RELIABILITY FIXES:

14. `update.sh wp`/`all` always failed: "-p ${WP_PORT}:80" was one single quoted shell argument instead of two, so podman's flag parser tried to read " 80" (stray leading space included) as the port number.

15. CrowdSec's firewall bouncer routinely came up crashed on first start (a real race against LAPI still initializing) — now retries up to 5 times, both in the one-time installer AND baked into crowdsec-container's own OpenRC service, so every future reboot is covered too (an earlier fix only helped the very first boot).

16. Uploads were frequently not writable right after install, and stayed that way across a reboot. Two causes: (a) a single blind chown raced the entrypoint's own file creation, and (b) wp-content/uploads may not exist at all until the first real media operation, which makes a write-test fail exactly like a permissions problem that no amount of chown can fix. Fixed with a wait-for-entrypoint retry loop plus an unconditional mkdir -p before every writability check (install-time, inline validation, and validate-wordpress.sh).

17. WP_DEBUG validation always showed "?": WORDPRESS_CONFIG_EXTRA never actually defined WP_DEBUG, and PHP 8.3 throws a fatal error referencing an undefined constant (older PHP just warned) — this also silently broke wp-hardening.sh's enable/disable debug toggle, whose sed pattern had nothing to match. WP_DEBUG is now explicitly defined, and both checks are defensive either way.

18. CrowdSec bumped v1.7.6 → v1.7.8, patching a disclosed WAF-bypass CVE in the AppSec datasource that directly affects the crowdsecurity/appsec-wordpress collection this script enables.


SECURITY HEADER CLEANUP:

19. Removed the X-XSS-Protection header (wp-security.conf generator and the no-CIDR fallback config) — the browser-side reflected-XSS filter it configured is gone from every current browser (Chrome/Edge dropped their XSS Auditor in 2019; Firefox/Safari never implemented it), so the header did nothing on any current browser, and on older browsers that DID honor it, the filter itself was a known attack surface. CSP — already set immediately below it in both places — is the control that actually does this job.


**NETWORK SEGMENTATION** — v7-6:

20. [CRITICAL] MariaDB and WordPress previously shared one flat network (wp-net, 10.89.1.0/24) with no --internal flag. "No host port" kept MariaDB safe from inbound scans, but the network itself still had a route to the internet — MariaDB could reach out, and a compromised WordPress container had direct L2 access to the database's entire subnet. Replaced with a real two-network split: wp-front (10.89.10.0/24) — WordPress only. Has egress (needed for plugin/theme installs, WP-Cron remote requests, update checks). This is also where the published host port (-p 80:80/8080:80) and any reverse-proxy (NPM) traffic lands. wp-db (10.89.20.0/24, --internal) — WordPress + MariaDB only. Podman/netavark never configures a route out of an --internal network, so MariaDB (and this leg of WordPress) has NO path to the internet at all, regardless of nftables state. WordPress joins both (wp-front primary, wp-db via `podman network connect` after the container starts); MariaDB joins only wp-db. nftables' forward chain now allow-lists both subnets instead of one.

21. [BUG FIX] update.sh's do_wp_update/do_db_update rename the running container to *-old (not stop it) and keep it alive until the new one passes its health check, so a fixed --ip on the new container collides with the -old one still holding that same address on the same network — the new `podman run`/`network connect` fails outright and the update always rolls back. do_db_update already omitted --ip for MariaDB for this exact reason; do_wp_update did NOT (it kept a fixed IP against the old single wp-net address, 1.3, which had the identical latent bug pre-dating this network split). Both update paths now leave IP assignment to netavark on both networks; only the create-time paths (install, GeoIP rebuild, OpenRC recreate-if-missing) use fixed IPs, since none of those have an -old container coexisting to conflict with.

## v7-6d — Rootless removed

ROOTLESS REMOVED:

22. ROOTLESS PODMAN REMOVED. This script now provisions rootful Podman ONLY — the rootless deployment path (wpuser-owned containers, the port-8080 + nftables-redirect story, pasta source-IP forwarding, the generated run-mariadb.sh/run-wordpress.sh/run-crowdsec.sh launcher scripts, and every ROOTLESS_MODE branch in the installer, update.sh, wp-hardening.sh, validate-wordpress.sh, wp-geoip-setup.sh, and the three OpenRC service scripts) has been deleted rather than kept as a second, less-tested path running alongside the wp-front/wp-db network split introduced in v7-6. Rootful was already this script's battle-tested recommended default; removing the alternative removes an entire class of dispatch-related bugs (see 23 below) instead of continuing to carry them through an increasingly complex two-network topology.

23. [SECURITY] PRUN dispatch wrapper fixed. The old PRUN() had a rootless branch that re-flattened every argument through `su -s /bin/sh wpuser -c "podman $*"` — "$*" joins all arguments into a single string on IFS, discarding the argument boundaries "$@" would have preserved, and that string is then RE-PARSED by the inner `sh -c`. Any argument containing shell metacharacters (spaces, quotes, `;`, `$()`) would be reinterpreted rather than passed through intact — and this script's own WORDPRESS_CONFIG_EXTRA value ('define("WP_DEBUG",false);define(...);...') is exactly that kind of argument. With rootless gone, PRUN is now a trivial `podman "$@"` in every script that defines it — "$@" always preserves argument boundaries, so this failure mode is gone entirely, not just avoided in the common case.

24. Added validate_image_tag()/validate_digest_ref() to update.sh. The VER argument to `update.sh wp|db|crowdsec [VER]` previously flowed straight into an image reference with no validation of its own — relying entirely on podman's own parser to reject anything malformed. Both functions now run before that argument is used for anything, giving a clear error message instead of a delayed, cryptic podman failure.

## v7-6f — Skopeo + pinned state

SKOPEO + PINNED STATE:

25. SKOPEO-BASED DIGEST RESOLUTION. Resolving "what digest does this tag point to right now" used to mean pulling the FULL image (150-200+ MB each for WordPress/MariaDB) just to ask Podman what it downloaded — both at install time and on every `update.sh check`. Skopeo's `inspect docker://ref` asks the registry's manifest endpoint directly (a few KB, no layer data), so both the installer's digest-pinning step and update.sh now know the digest before anything is pulled. A `podman pull` still happens, but only once, for the exact `repo@sha256:digest` reference that's actually going to be pinned or run — never as a separate discovery step. update.sh's read-only `check`/`status` path (the default when it's run with no argument) is now a genuinely read-only Skopeo manifest query — no pulls at all. Skopeo missing or a lookup failing is never fatal: every call site falls back to the pre-v7-6f pull-then-inspect method on its own.

26. PINNED STATE EXTERNALIZED to /etc/wp-install/pinned.env. Previously "what tag/digest is currently pinned" had to be re-derived by sed-parsing it back out of the running container's own `{{.Config.Image}}` string, and update.sh kept itself current by rewriting its own PINNED_WP_VER/PINNED_DB_VER/PINNED_CS_VER constants on disk (`sed -i` against /usr/local/bin/update.sh itself) after every successful update. Both patterns are gone: pinned.env is now the single source of truth, written by the installer at install time and kept current by update.sh's `_save_pinned()` after every successful wp/db/crowdsec update — update.sh no longer self-modifies at all. If pinned.env doesn't exist yet (a VM upgraded from a pre-v7-6f update.sh), it's bootstrapped on first run from whatever's currently running.

27. DIGEST-ONLY REFERENCES, ALWAYS. Item 9's runtime test for whether the local Podman accepts a combined `repo:tag@sha256:digest` reference is gone — every pinned reference is now the universally-supported digest-only form (`repo@sha256:digest`), with the tag tracked separately in pinned.env instead of inside the reference itself. wp-geoip-setup.sh's tag-derivation logic, which used to special-case "tag+digest present" vs. "digest-only" based on that now-removed test, was updated to read the tag from pinned.env directly instead — unchanged, the old heuristic would have silently degraded to its short-digest-fragment fallback on every single run (digest-only was no longer the exception, it's now the rule), producing GeoIP image tags like `wordpress-geoip:a1b2c3d4e5f6` instead of a readable version.

28. OpenRC recreate-fallback paths (wp-container, mariadb-container) now also consult pinned.env before falling back to their install-time-baked WP_IMAGE/DB_IMAGE. Necessary consequence of 26: since update.sh no longer rewrites those baked-in values on disk, leaving this unaddressed would mean the recreate-if-missing path (the branch that only fires if a container is ever removed outside of update.sh) could silently drift back to whatever was pinned at install time. WordPress skips this override when a local GeoIP image is already in play, since pinned.env's WP_DIGEST tracks the upstream image, not the locally-built GeoIP layer.

## v7-6k — Dedicated admin account

DEDICATED ADMIN ACCOUNT:

29. [SECURITY] Root SSH login is now disabled unconditionally (PermitRootLogin no) regardless of whether an SSH key was supplied — closing remaining_tasks.txt item 5 ("SSH still allows root + password login when no key is given... no dedicated non-root admin account is created either way"). A dedicated admin account (name prompted, default wpadmin) is created in the wheel group, with doas configured (`permit persist :wheel` in /etc/doas.d/doas.conf, per Alpine's own documented pattern — doas prompts for the ACCOUNT'S OWN password, not root's, so it authenticates independently of however that account itself logs in). If an SSH key was supplied, it's placed on the admin account (not root) and password auth is disabled server-wide; if not, the admin account gets an operator-chosen password (prompted/ confirmed the same way the VM's root console password already is) and THAT is what SSH accepts — never a root password over SSH, key or no key. Root keeps its console password unconditionally (`qm terminal`/noVNC access is unrelated to and unaffected by any of this).

30. Account creation needs adduser/addgroup writing into the target filesystem's own passwd/group/shadow, and doas needs apk + network — both require a live chroot, exactly like the QEMU Guest Agent pre-install already did. Rather than mount and unmount /proc and /dev twice for two separate chroot calls, both now share one: the combined chroot runs immediately after the root password is set, and /proc and /dev stay bind-mounted through the rest of injection (nothing written in between cares whether they're mounted), torn down once at the very end instead of twice.

31. Safety fallback: adduser inside a chroot is a simple, local, network-independent operation and should essentially never fail — but if it somehow does, the script does NOT silently leave the VM unreachable over SSH. It verifies the account actually exists (grep against the target's own /etc/passwd, not the chroot's exit code, since a later doas/network failure in the same chroot must not be misread as "account missing") and, only on genuine failure, falls back to the pre-v7-6k behavior (root SSH, key or password per what was supplied) with a loud warning in the install log and in both summary banners — a degraded fallback, not a silent one.

32. SSH_KEYS and the admin password are deliberately never interpolated into the chroot's `sh -c` string at all (unlike the sanitized, regex-constrained ADMIN_USER, which is safe to interpolate) — operator-pasted key content or a chosen password could contain anything. Both are written host-side via plain redirection or a shadow sed, after the chroot exits, the exact same mechanism root's own password and key already used before this change — never passed through a shell for re-interpretation.

33. doas installation inside the pre-boot chroot depends on the PROXMOX HOST reaching Alpine's CDN at provisioning time — normally fine (the QEMU Guest Agent pre-install already relies on the same path), but as a redundant safety net Stage 1 of the installer also attempts `apk add doas` (idempotent, no-op if already present) once the VM has its own guaranteed-working network, closing the one plausible network-dependent gap in an otherwise network-independent setup.

34. Auto-generated vs. operator-chosen admin passwords are handled the same way root's own password already is: an operator-typed password (no-key path, actually used for SSH) is never written to disk in plaintext — they typed it, they know it. An auto-generated one (key-provided path, used only by doas — nobody types or needs to remember it) IS written, to /root/.wp-admin-credentials (chmod 600), the same treatment already given to the openssl-rand DB passwords in /root/.wp-credentials, and for the identical reason: without writing it down it would be permanently unusable.

## v7-6k — Two parallel production-readiness passes merged

TWO PARALLEL PRODUCTION-SAFETY REVIEWS MERGED INTO ONE:

35. [PRODUCTION SAFETY] Strengthened MariaDB health checks. wp-health-check.sh (v7-6g) closed the shallow-check gap for WordPress, but every MariaDB readiness gate — the install-time wait loop (before either container exists yet) and update.sh's do_db_update() rollback decision — was still a bare `mariadbd-admin ping`, which proves only that the server accepts TCP and that root authenticates. It proves nothing about InnoDB actually being usable or about whether WordPress's OWN database/user (MARIADB_DATABASE/ MARIADB_USER, not root) can run a query — the same shallow-success/ broken-application blind spot the old WordPress `wget -qO-` check had. New /usr/local/bin/mariadb-health-check.sh adds a root query, the exact wordpress-credential query, and an InnoDB-initialized check, and is wired into the install-time wait loop, do_db_update(), and both validate-wordpress.sh and the post-install validation suite — mirroring wp-health-check.sh's role for WordPress. Falls back to the old ping-only check automatically if the script is somehow missing (e.g. a VM recreated from an older installer).

36. [PRODUCTION SAFETY] Container-swap error handling. Every "swap in a replacement container" path in update.sh (do_wp_update/do_db_update/ do_cs_update) previously suppressed the result of `podman rename` with `2>/dev/null || true` on the forward swap, and discarded the result of both `podman rename` and `podman start` the same way on every rollback swap. Concretely, in do_wp_update(): if `podman rename wordpress wordpress-old` silently failed, "wordpress" kept its name, so the following `podman run -d --name wordpress` failed too (a name collision) — a failure that WAS checked, so control fell into the "container start failed — rolled back" branch, whose first line was `podman rm -f wordpress`: deleting the still-good, still-running ORIGINAL container in the mistaken belief it was cleaning up a failed new attempt. One suppressed error could cascade into deleting a healthy production container. New require_clean_container_state() preflights every rename's own preconditions (missing source container; a stale *-old container left over from a previous crashed/interrupted update) before attempting it, across WordPress, MariaDB, and CrowdSec. Every rename+start pair — forward swap and rollback swap alike — is now checked directly instead of discarding its result, with a loud "ROLLBACK FAILED" message plus manual-recovery commands printed if a rollback itself doesn't work, since that's the one moment silence is most dangerous: the site, database, or CrowdSec is down right now and nobody has been told. A leftover *-old container after a SUCCESSFUL update is also now flagged (it would otherwise silently block the next update's preflight check).

37. [PRODUCTION SAFETY] update.sh update lock. Nothing previously stopped two update.sh invocations from running at once — an admin running `update.sh wp` while a cron-triggered `update.sh digest-check` is already mid-run, say. That could race two processes renaming the same container to *-old, or writing /etc/wp-install/pinned.env at the same time, or overlapping MariaDB dumps against the same data directory. A plain mkdir-based lock at /run/lock/wordpress-update.lock closes this — mkdir is atomic on every storage backend this script runs on, so only one invocation can ever hold it. The holder's PID is recorded inside the lock so a stale lock left by a crashed update (OOM-killed, VM rebooted mid-update) is detected via `kill -0` and cleared automatically. Only the state-changing subcommands (os/wp/db/crowdsec/all/digest-check) take the lock — check/status/ trivy stay lock-free since they're read-only and meant to stay safe to run anytime, including while an update is in progress.

## v7-7 — Merge of the two v7-6k passes

MERGE OF THE TWO PARALLEL v7-6k LINES ABOVE INTO ONE SCRIPT:

38. The dedicated-admin-account line (items 29-34) and the production-safety line (items 35-37) were developed in parallel off the same v7-6j baseline and touch different, non-overlapping parts of the script — host-side provisioning/SSH/chroot injection vs. update.sh and its health-check scripts — so reconciling them was a straight union of both feature sets rather than a resolution of competing designs. Every item above (29-37) is present and active in this version.

39. do_db_update()/do_cs_update() now keep BOTH styles of require_clean_container_state() check that existed separately across the two parallel lines: the EARLY fail-fast call (before any backup, pull, or container is stopped — dropped in the production-safety line's rewrite of item 36) AND the check immediately before the actual rename (added by that same rewrite as tighter defense-in-depth right at the point of use). Keeping both is strictly safer than either alone and costs almost nothing (one extra `podman container exists` call): the early check avoids a wasted backup + pull + a brief unnecessary WordPress/MariaDB stop/start cycle when the update was going to be refused anyway (a stale *-old container from a previous crashed run, most commonly), while the later check still catches state that changed during that window — an operator manually intervening mid-update, for instance. At the time this note was written, do_wp_update() was unaffected: neither parallel line above had more than one check site for it, since nothing destructive happened before its single rename point. Item 40 below changes that.

## v7-7 — WordPress update cutover merged in

WORDPRESS UPDATE CUTOVER MERGED IN:

40. [CRITICAL] A third line of work, developed in parallel off the same v7-6f baseline as the two lines merged into v7-7 above (items 29-37), had never been folded in until now: a candidate/cutover rewrite of update.sh's do_wp_update() that fixes a structural bug making `update.sh wp` — and so `update.sh all` / `update.sh digest-check`, which both call it — unable to ever actually complete a WordPress update. Before this merge, do_wp_update() renamed the running "wordpress" container to wordpress-old — a rename, not a stop — and immediately tried to `podman run` a brand-new container ALSO publishing -p 80:80. wordpress-old was still running and still holding host port 80 at that exact moment (renaming a container never stops it or releases its published ports), so the new container's own port publish failed every time — not an occasional race, a structural guarantee. That `podman run` sat inside an `if ...; then`, so the failure was caught, but only after the fact: control fell into the existing rollback branch, renamed wordpress-old back to "wordpress" (which had never actually stopped serving traffic under its temporary name), and reported a plain "Container start failed — rolled back" with nothing distinguishing this from a genuine one-off failure. Item 36's container-swap error-handling rewrite (the production-safety line) fixed how this failure was reported and rolled back — every rename/start result checked, loud "ROLLBACK FAILED" messages if even the rollback failed — but never touched the underlying port-80 collision itself, since neither parallel line was aware of the other's changes to this function. (The dedicated-admin-account line was a straight ancestor of neither; this candidate/cutover rewrite was developed on a separate branch off v7-6f, alongside — not as part of — the two lines items 29-39 describe.) Net effect prior to this merge: `update.sh wp` would ask, Trivy-scan, and pull a new WordPress image, then reliably fail to deploy it and roll back (safely and loudly, thanks to item 36 — but roll back regardless), every single time. FIX: candidate/cutover. The freshly pulled image now starts first as a throwaway "wordpress-candidate" container published ONLY to 127.0.0.1:18080 (WP_CANDIDATE_PORT) — loopback-only, so it can never collide with production's 0.0.0.0:80 and is never reachable from outside the VM. It runs against the same volumes, env file, and wp-front/wp-db networks as production, so the check is real rather than a synthetic smoke test, and it must pass the same wp-health-check.sh validation (HTTP + PHP execution + mariadb DNS + a real WordPress-credential query) used at every other health-check call site in this script. Production is not touched while this runs — if the candidate never starts, or starts but fails validation, the update aborts here with nothing changed. Only once the candidate proves the new image actually works is require_clean_container_state() consulted again and "wordpress" renamed to wordpress-old and explicitly STOPPED — freeing host port 80 for real, not just freeing the name — and only then is the real "wordpress" container created against port 80 and health-checked a second time, with every rename/start result checked and a loud "ROLLBACK FAILED" report if even the rollback doesn't work, exactly per item 36's existing standard for MariaDB and CrowdSec. An early require_clean_container_state() check was also added before the pull/candidate sequence even begins — item 39's reasoning for MariaDB/CrowdSec (avoid wasting work on an update that was going to be refused anyway) now applies to WordPress too, since the candidate step means substantial work happens before the rename point for the first time. A short downtime window during the final cutover itself is unavoidable — host port 80 can only ever be held by one container at a time on a single Apache-on-:80 VM, with no second reverse-proxy layer in front of it — but it's now short and high-confidence, since the image was already proven to work before production was ever stopped. Needs 127.0.0.1:18080 free on the VM; change WP_CANDIDATE_PORT in update.sh if that port is already in use for something else.

## v7-9 — MariaDB update path

MARIADB UPDATE PATH HARDENED (do_db_update() only; MariaDB's own recreate-if-missing OpenRC fallback and the daily backup cron are untouched by this entry):

41. [CRITICAL] Three related gaps in do_db_update() — a backup step that could report success on a failed dump, a container-only rollback that left the actual data directory unprotected, and no check that WordPress could really use the new database before the rollback path was deleted — are fixed together, since all three share one root cause: nothing in this function actually verified the state it was trusting before discarding the only way back. (a) BACKUP VERIFICATION. The pre-update dump used to be `podman exec mariadb ... mariadb-dump ... | gzip > file` inside an `if ...; then`. In a pipeline, a shell's exit status is the LAST command's (gzip) — gzip happily exits 0 compressing whatever bytes it received, including zero bytes from a mariadb-dump that failed outright (bad auth, dropped connection, disk full on the container side). The `if` could therefore report a successful backup for a truncated or entirely empty one. Fixed by never piping straight into gzip: mariadb-dump now writes to a plain .sql file first (so its OWN exit code, not gzip's, is what gets checked, with stderr captured separately for diagnostics), the result is checked for non-zero size AND mariadb-dump's own trailing "-- Dump completed on ..." marker — the same structural signal most production mysqldump/mariadb-dump backup scripts use to detect a truncated run — and only THEN is it compressed, with the resulting .gz verified via `gzip -t` before the backup is considered good. Any failure at any stage aborts the update before anything is stopped, with the raw dump's stderr printed for diagnosis. (b) DATA-DIRECTORY SNAPSHOT. The replacement MariaDB container always mounted the exact same bind-mount (/home/wpuser/wp/mysql) as the one being replaced, with no volume-level rollback point — only the logical dump from (a) existed, which is slow to restore under pressure, and if a new engine version mutates on-disk structures on startup (an InnoDB redo-log/system-table upgrade, for instance) even while ultimately failing to become healthy, "renaming the container back" does NOT undo whatever it already wrote to that directory. Fixed with a real filesystem-level snapshot: once MariaDB is confirmed stopped (and after a disk-space preflight sized off the live data directory, so a too-full disk aborts loudly with zero downtime instead of leaving services stopped), /home/wpuser/wp/mysql is copied wholesale to /home/wpuser/wp/mysql-preupdate-snapshot BEFORE the new image ever touches the real data directory. Every rollback path now restores from this snapshot (via same-filesystem `mv`, not a second slow copy) before the old container is ever restarted against that directory — and refuses to start it at all if the restored directory doesn't look like a real MariaDB data directory afterward (guarding against the official image's own behavior of silently initializing a brand-new EMPTY database against a missing/empty /var/lib/mysql, which would make catastrophic data loss look exactly like a clean, healthy rollback). The failed update's own data is kept alongside (timestamped) rather than deleted, in case it's ever needed for forensics. The snapshot itself is only removed once an update is confirmed fully healthy — see (c). (c) WORDPRESS-LEVEL HEALTH GATE. mariadb-health-check.sh passing used to be the ONLY gate before mariadb-old was deleted — proving MariaDB itself is healthy, but not that WordPress, the actual application, can use it (a schema-level incompatibility a generic SELECT 1 wouldn't catch, for instance). The old code also restarted WordPress with `|| true`, silently swallowing its own failure. WordPress is now validated with the same wp-health-check.sh depth (HTTP + PHP execution + DB name resolution + a real WordPress-credential query) used at every other health-check site in this script, and mariadb-old plus the pre-update snapshot are ONLY removed once that passes. If WordPress fails to restart, or restarts but can't actually use the new database, this now triggers the exact same full rollback as an unhealthy MariaDB — restoring the data-directory snapshot from (b) and restoring the old container from mariadb-old — instead of silently leaving a broken combination in place with the rollback container already gone. All three failure paths (MariaDB itself unhealthy, the new container failing to start at all, and WordPress failing to reconnect) now share one _db_rollback() helper instead of three separately-maintained copies, closing off the kind of drift between near-identical call sites that item 7/36 already had to fix once for this same function's rename/start error handling. Empirically confirmed (not assumed) that every bare call into this helper needs an explicit `|| true` guard: update.sh runs under `set -e`, and a function returning non-zero as a plain statement aborts the whole script immediately — which would have skipped the rest of do_db_update() AND, from do_digest_check()/`update.sh all`, prevented CrowdSec from ever being checked after a MariaDB failure. NOT changed by this entry (tracked separately): mariadb-upgrade's own exit status is still unchecked (open finding #5); the daily backup cron job has the identical pipe-to-gzip pattern as (a) above and was intentionally left as-is, since this entry is scoped to do_db_update() only.

## v7-10 — MariaDB-upgrade exit code fix

MARIADB-UPGRADE EXIT STATUS CHECKED (closes open finding #5, the last remaining gap v7-9 left in do_db_update() itself):

42. [HIGH] mariadb-upgrade's own exit status used to be discarded with a bare `|| true` — the one step in do_db_update() v7-9 explicitly left unhardened (see that entry's own closing note, just above). DB_READY passing right before this step only proves the new server accepts connections and InnoDB is initialized (mariadb-health-check.sh); it says nothing about mariadb-upgrade's own result, since that command hasn't run yet at that point. A non-zero exit means mariadb-upgrade hit something it couldn't reconcile on its own — an unrepairable table, a permission problem, a dropped connection mid-run — and continuing past that silently risked handing WordPress a database that only LOOKED ready. FIX: the exit status is now checked directly. Combined stdout+stderr is captured to a variable rather than a temp file (mariadb-upgrade prints even on a clean run — "already upgraded"-style lines — so this is captured purely for diagnostics on failure, never used as the pass/fail signal itself) and printed only if the command actually failed. That failure now routes through the same _db_rollback() helper item 41 built for this function's other failure paths, instead of being swallowed. The WordPress-reconnect health gate immediately after this step (item 41c) is unchanged and still runs either way: mariadb-upgrade's own exit code isn't necessarily exhaustive, so a schema issue that slips past it but goes on to break a real WordPress query is still caught there, same safety net as before this patch. Still open (unchanged by this entry — see Remaining_todo.docx): #3 (stale mariadb hosts mapping), #8-#10 (state-file integrity), #11 (MaxMind credentials in process args), #12-#15 (Alpine/digest/Trivy verification fail open), #16 (permissive WP HTTP check), #17 (nftables egress policy still accept), and the daily backup cron's pipe-to-gzip pattern noted above. Related, but NOT fixed by this entry — spotted while empirically verifying (not assuming) that item 42's new failure path behaves the same as do_db_update()'s existing ones once it returns: both do_digest_check() and the `all` dispatch call do_wp_update / do_db_update / do_cs_update as unguarded bare statements, no `|| true`, no surrounding if. Confirmed directly (a minimal repro under both dash and bash) that update.sh's own `set -e` aborts the entire process the moment any one of those returns non-zero, before the next call in the sequence ever runs — so a MariaDB failure (this entry's new check included, but equally every do_db_update()/ do_wp_update() failure path that already existed before this patch) can still silently skip the CrowdSec check in `digest-check`/`all`, the exact outcome item 41's own comment says guarding _db_rollback() was meant to prevent. Guarding _db_rollback() only gets do_db_update() itself to its own `return 1` cleanly — it does not, by itself, stop that `return 1` from aborting the *caller's* sequence in turn. Not folded into item 42 because it isn't specific to mariadb-upgrade or to do_db_update() — it's a dispatch-level gap that would need do_digest_check()/`all` to track and continue past a per-component failure (e.g. `do_db_update ... || _fail=1`) and report the aggregate result at the end, which is a distinct piece of work.

## v7-11 — Stale MariaDB /etc/hosts entry fix

STALE MARIADB /etc/hosts ENTRY REMOVED, DISCOVERY MADE EXPLICIT (closes open finding #3, the item Remaining_todo.docx named as the next, cheapest, most contained step):

43. [HIGH] `--add-host "mariadb:10.89.20.2"` is removed from every place this script creates a WordPress container — initial install, the GeoIP rebuild in wp-geoip-setup.sh, wp-container's OpenRC recreate-if-missing fallback, and both the throwaway validation candidate and the real cutover container inside do_wp_update() (five call sites, matching the audit's own count). It was never doing the job its own comment claimed: WORDPRESS_DB_HOST=mariadb:3306 already resolves "mariadb" via aardvark-dns on wp-db, which — unlike a static /etc/hosts line — always reflects whichever address a container named "mariadb" currently holds. The static entry was redundant with that at best; at worst, actively wrong, because glibc's default /etc/nsswitch.conf order is `hosts: files dns` — /etc/hosts is checked FIRST, and a match there is used outright, with DNS never consulted at all for that name once one exists there. CONCRETE FAILURE THIS CAUSED: do_db_update()'s replacement MariaDB deliberately gets no fixed --ip — its own comment explains why: "mariadb-old still holds its wp-db address until removed". Since mariadb-old isn't removed until the very end of a SUCCESSFUL update, the new "mariadb" container is not free to reuse .2 for the entire window that matters, and lands on some other address on essentially every real run. WordPress itself is never recreated by a database update (do_db_update() only stops/starts it), so the /etc/hosts baked into WordPress at its own last creation kept saying mariadb=10.89.20.2 — which by then pointed at nothing, since the OLD MariaDB at .2 had already been cleanly stopped earlier in the same update. Because `files` pre-empts `dns`, the exact WordPress-level health gate item 41c added specifically to decide whether to keep an update or roll it back (wp-health-check.sh's real mysqli SELECT 1 against WORDPRESS_DB_HOST) would try .2, fail to connect, and report unhealthy — meaning that gate would fail and trigger a full rollback on what should have been a healthy update, essentially every time, not just in some rare edge case.

44. [MEDIUM] `--network-alias mariadb` is added to all three places this script ever creates a MariaDB container — initial install, the mariadb-container OpenRC recreate-if-missing fallback, and (most importantly) do_db_update()'s replacement container, the one place that deliberately has no fixed --ip. This directly closes the audit's separate observation that "no --network-alias was added." Functionally this is close to a no-op — Podman/aardvark-dns already registers a container's own --name as a resolvable record for other containers on the same network, which is the exact mechanism item 43 above now relies on exclusively — but making it an explicit, visible flag on every MariaDB creation is worth doing anyway: it's self-documenting (a reader doesn't need to know Podman's implicit name-registration behavior to see that this container is meant to be discoverable as "mariadb" regardless of its address), and it's cheap insurance against any future Podman/netavark change to that implicit behavior. WHAT THIS DOES NOT CHANGE: neither item above touches the network segmentation itself in any way. wp-db is still created with --internal (netavark configures no route out of it, full stop, independent of nftables state); MariaDB still has no published host port; the nftables forward chain still only allow-lists the wp-front (10.89.10.0/24) and wp-db (10.89.20.0/24) subnets with a default-drop policy otherwise. aardvark-dns for wp-db runs scoped to that network's own gateway (10.89.20.1) and only answers queries from containers already attached to wp-db — it cannot be reached from wp-front, from the host's external interface, or from the internet, so relying on it exclusively for "mariadb" resolution introduces no new path across the wp-front/wp-db boundary and no new attack surface. The only thing that changed is HOW WordPress looks up MariaDB's current address inside a boundary that was already closed — never whether that boundary itself holds. Two comments that referenced the removed --add-host entry are updated to match: do_db_update()'s "No --ip here either" note, and update.sh's own opening INTEGRATION NOTES block. Still open (unchanged by this entry — see Remaining_todo.docx): #8-#10 (state-file integrity), #11 (MaxMind credentials in process args), #12-#15 (Alpine/digest/Trivy verification fail open), #16 (permissive WP HTTP check), #17 (nftables egress policy still accept), the daily backup cron's pipe-to-gzip pattern, and the do_digest_check()/`all` dispatch gap noted in the v7-10 entry above (still not folded in here either — it isn't specific to this finding any more than it was specific to mariadb-upgrade).

## v7-12 — State-file integrity + hardening toggles

STATE-FILE INTEGRITY + CREDENTIAL EXPOSURE CLOSED (closes open findings #8, #9, #10, #11 — the grouping Remaining_todo.docx named as the next, cheapest, most contained step once v7-11 closed #3):

45. [MED/HIGH] #8 — pinned.env written non-atomically. Both places this script writes /etc/wp-install/pinned.env — the installer's own first write, and update.sh's _save_pinned(), called after every successful wp/db/crowdsec update — used a direct `cat > pinned.env << EOF`, which truncates the target the instant the shell opens it, before a single byte of the heredoc body is written. Anything reading pinned.env in that window (a crash mid-write; wp-geoip-setup.sh reads this file independently of update.sh's own update-lock, which only guards state-changing update.sh subcommands against each other, not an unrelated reader) could see a truncated or empty file — not the old value and not the new one. FIX: both call sites now write to pinned.env.tmp.$$ in the same directory, chmod it, then `mv -f` it into place — mv within one directory is a single rename(2), POSIX-atomic, so a reader always sees either the complete old file or the complete new one.

46. [MED/HIGH] #9 — pinned.env sourced without validating loaded values. The operator-supplied [VER] argument to `update.sh wp|db|crowdsec [VER]` has gone through validate_image_tag()/validate_digest_ref() since v7-6d (item 24) before it's used in an image reference — but WP_TAG/WP_DIGEST/DB_TAG/DB_DIGEST/CS_TAG/CS_DIGEST, loaded from pinned.env by a plain `. /etc/wp-install/pinned.env`, took a completely separate, unvalidated path into the exact same kind of reference. Not expected to ever fire against a pinned.env this version of update.sh wrote itself (see item 45 immediately above), but is a real gap against a pinned.env inherited from an older update.sh, a manual edit, or a file that predates item 45's atomic-write fix. FIX: every value pinned.env supplies is now run through the same two validators immediately after sourcing; anything that fails is discarded (reset to empty) rather than trusted, which the rest of the script already treats as "not pinned yet" and falls back to the PINNED_*_VER constants or a fresh resolve — never reaching a pull/run with an unvalidated string.

47. [HIGH] #10 — vars.sh serialized with no escaping. Every value written into /etc/wp-install/vars.sh — including free-text operator input (CrowdSec enrolment key, GeoIP country lists, MaxMind Account ID and License Key) — went through plain "${VAR}" interpolation into an otherwise-unquoted heredoc. A value containing a literal double-quote, backtick, or $(...) would break out of its VAR="..." assignment the moment vars.sh is next sourced — which happens as root, during Stage 2 on first boot, and on every later run of update.sh, wp-hardening.sh, and wp-geoip-setup.sh, all of which source this same file. FIX: new host-side _vars_q() wraps every value in single quotes, escaping any embedded single quote as '\'' (close quote, escaped literal quote, reopen quote) — plain POSIX single-quote escaping, applied uniformly to every field in the heredoc rather than a per-field judgment call about which ones "need" it. Deliberately NOT bash's own `printf %q`: %q can emit $'...' ANSI-C-quoted output for some inputs, which BusyBox ash (/bin/sh on the Alpine VM, and what update.sh / wp-hardening.sh / wp-geoip-setup.sh all source vars.sh under) does not reliably parse — using %q here could have silently broken the very file it was meant to make safer. Single-quote escaping is valid POSIX syntax in every Bourne-family shell without exception.

48. [HIGH] #11 — MaxMind credentials in cron/process args. Both places this script invoked curl against MaxMind's download API — inside wp-geoip-setup.sh, and the weekly refresh line that script writes into /etc/crontabs/root — passed the license key directly as `curl -u "$MAXMIND_ACCOUNT_ID:$MAXMIND_LICENSE_KEY"`. A command's argv is visible to anything on the VM that can read /proc/<pid>/cmdline (or run `ps aux`) for as long as that command runs, and the cron line itself sat in /etc/crontabs/root with the credentials spelled out in plain text — readable by root only, but also re-exposed in argv every single Wednesday when cron actually ran it. FIX: wp-geoip-setup.sh now writes those credentials once, at the top of its own run, into /etc/wp-install/.maxmind-netrc (chmod 600, root-owned — the same protection level /etc/wordpress/env and /root/.wp-credentials already get elsewhere in this script) and passes --netrc-file to curl instead of -u, both in its own download and in the cron line it generates. The credentials themselves never appear on a command line again — only a file path does. Rewritten on every wp-geoip-setup.sh run, so an updated vars.sh — the script's own documented way to fix a bad MaxMind credential — is always picked up.

49. [LOW] Discovered while implementing item 48: wp-geoip-setup.sh invoked curl for the GeoLite2 download without this script ever installing it anywhere on the Alpine VM itself (curl only appears pre-installed inside the transient, Debian-based apt-get build container used to compile mod_maxminddb — a completely different context). --netrc-file (item 48) isn't available in wget, the tool this script does reliably ensure is present, so this could no longer be sidestepped by switching tools. wp-geoip-setup.sh now installs curl itself before it's first needed (idempotent — a no-op if it's already present some other way), keeping this script genuinely standalone/rerunnable per its own header rather than silently depending on curl having arrived via some other path. Still open (unchanged by this entry — see Remaining_todo.docx): #12-#15 (Alpine/digest/Trivy verification fail open), #16 (permissive WP HTTP check), #17 (nftables egress policy still accept), the daily backup cron's pipe-to-gzip pattern, and the do_digest_check()/`all` dispatch gap noted in the v7-10 entry above. Two related items were spotted but are NOT fixed by this entry, since neither is one of the 18 and both are meaningfully larger in scope than this patch: (a) ADMIN_CIDR / ALLOWED_ADMIN_IP / PROXY_IP / SSH_CIDR / WEB_CIDR flow into the Apache and nftables config heredocs the same way vars.sh's fields used to — but those are config files, not shell scripts that later get sourced and executed, so this is a config-injection question, not the command-injection question item 47 closes, and would need its own review of what nftables/Apache syntax actually needs escaping; (b) the CrowdSec console enrolment key is passed as a `podman exec` argument (`cscli console enroll ... "$CROWDSEC_ENROLL_KEY"`), which is visible in argv for the one-time enrolment call the same way the MaxMind key used to be — unlike curl, it's not established here whether cscli has an equivalent file-based credential input, so this is noted rather than guessed at.

## v7-13 — Dispatch aggregation + backup cron + DEPLOYMENT_PROFILE

DISPATCH AGGREGATION + BACKUP CRON + TRIVY SUPPLY CHAIN + CANDIDATE ISOLATION + DEPLOYMENT PROFILE. Addresses an independent audit (ChatGPT's forensic review of v7-11 that landed after v7-12 shipped) — several of its findings duplicate items already fixed in v7-12 (state-file integrity #10, vars.sh escaping #11, MaxMind credential exposure #12 — closed by v7-12 items 45-49). The rest are addressed here or documented with explicit reasoning:

50. [HIGH] `update.sh all` and `update.sh digest-check` stopped at the first failing component (audit finding #5+#6). This dispatch-level gap was noted in v7-10 and again in v7-12's "related but not one of the 18" — folded in here now that the audit reraised it as HIGH. update.sh runs under set -e, so a WordPress registry blip during `digest-check` silently skipped the MariaDB and CrowdSec digest checks entirely — the operator saw a WordPress error and no information at all about the other two components. FIX: both dispatch paths now capture per-component return codes via `|| rc=$?` (which set -e does not treat as an error, per bash's own documented errexit exceptions), run every component regardless of prior failures, and print a per-component OK/FAILED summary at the end. Aggregate return status stays nonzero if any component failed, so cron and any calling script see the whole-run status they expect.

51. [HIGH] Daily MariaDB backup cron used the same unsafe pipe-to-gzip pattern that v7-9 fixed inside do_db_update() (audit finding #7). Noted in v7-9 as "related but not one of the 18" and still open. Same failure mode: cron's default shell has no pipefail, so a `mariadb-dump` failure gets masked by gzip's exit-0 on empty input, producing a valid, empty, unrestorable .sql.gz that then rotates out yesterday's real good backup. FIX: new /usr/local/bin/wp-db-backup.sh reuses do_db_update()'s three-gate pattern — write raw .sql first (so mariadb-dump's own exit status is what's checked), confirm dump-completed marker present, gzip -t verify the archive — and rotates old backups ONLY after all three gates pass. A failed backup leaves yesterday's good archive untouched.

52. [MEDIUM] WordPress HTTP health check accepted every status code other than 500 and 000 (audit finding #15). Which quietly waved through 401/403/404/429/502/503/504 — the exact list of "something is actually broken" codes a WordPress front page should never legitimately return on GET /. FIX: replaced with an explicit allowlist (200, 301, 302) applied identically at both call sites inside wp-health-check.sh. Any other code is now a real failure signal, not silently accepted.

53. [MEDIUM/HIGH] scan_image() collapsed real vulnerability findings and scanner-side failures into the same "vulnerabilities detected" prompt (audit finding #14). Trivy's own convention is exit 0 = clean, exit 10 = findings, anything else = scanner problem — the old code used --exit-code 1 and swallowed stderr, so a DB download failure, registry timeout, or corrupt cache all looked like "review CVEs" to the operator. FIX: --exit-code 10 for findings, explicit case on the return code, and stderr captured to a temp file surfaced only when the scan itself fails — operators now see "scan did not complete" distinctly from "HIGH/ CRITICAL detected", and can choose to proceed or abort with full information about why.

54. [MEDIUM/HIGH] Trivy install.sh was fetched from the mutable `main` branch and executed as root (audit finding #13). This is the exact supply chain surface that produced the real Trivy v0.69.4 compromise (StepSecurity's writeup: malicious release exfiltrating RSA-encrypted C2 traffic to scan.aquasecurtiy.org, backdoor tpcp-docs repos created on every runner's GitHub account). FIX: both install sites (Stage 2 installer and update.sh's setup_trivy()) now fetch install.sh from a specific commit hash — the same commit aquasecurity's OWN setup-trivy Action pins to (PR #28, "Pin Trivy install script checkout to a specific commit"). raw.githubusercontent.com serves files by commit hash content-addressably, so a compromise of the trivy repo's main branch cannot change what this URL returns. Documented in-place that TRIVY_VER and TRIVY_INSTALL_COMMIT should be updated together after auditing any change to install.sh.

55. [HIGH] WordPress candidate container mounted PRODUCTION's writable docroot and logs (audit finding #3 — a NEW finding not in the original 18). The candidate exists to prove a new image works BEFORE production is touched, but it did so with `-v /home/wpuser/wp/html:/var/www/html` (production docroot, writable), `-v /home/wpuser/wp/logs:/var/log/apache2` (production access logs), and `-v .../wp/htaccess/.htaccess:...:rw` — meaning a plugin write-on-init code path in the candidate could pollute the live docroot BEFORE the candidate was even declared healthy, and candidate failure could leave orphaned files behind that outlived the throwaway container. FIX: three mount-surface changes, none of which break the health check itself: • /home/wpuser/wp/html mounted :ro. Candidate can serve every file production serves but cannot write to any of them. A new-image plugin that writes on init will EACCES — which is the CORRECT signal, since that behavior would corrupt production either way; catching it against a throwaway is far cheaper than catching it live. • /var/log/apache2 mounted as a tmpfs (candidate's own throwaway logs — vanishes with the container). • .htaccess :rw mount dropped entirely. The health check doesn't hit any URL that requires .htaccess rewrites, and this was the last :rw mount into production storage. WP_ENVIRONMENT_TYPE=staging also set as a hint to well-behaved plugins to skip write-on-init side effects. RESIDUAL RISK (audit finding #4 — deliberately NOT fixed): the candidate still authenticates to the LIVE production database with production credentials. The audit's suggested full fix (spin up a temporary MariaDB, restore the daily dump into it, create temporary WP credentials, run the candidate against that copy, tear everything down) would double disk usage during every update, add minutes-per-GB of dump restore time to every image refresh, and introduce a new class of failure modes that themselves need careful rollback handling. That trade-off doesn't make sense for THIS script's purpose. Concretely, the candidate's DB interactions are bounded: getent hosts mariadb, PHP mysqli connect, SELECT 1, plus whatever a GET / for an anonymous user triggers with DISABLE_WP_CRON=true, WP_ENVIRONMENT_TYPE=staging, and now a read-only docroot. WordPress schema migrations are triggered by wp-admin/upgrade.php loaded WHILE authenticated, not by anonymous requests, so a version-mismatched candidate cannot silently migrate the live DB. Documented in-place; operators who need full DB isolation for their compliance regime can bolt on a dump/restore wrapper, but the base script does not pay that cost.

56. [HIGH] Alpine SHA-512 verification and container digest pinning both failed OPEN by design (audit findings #8+#9 — same as original #12+#13 in Remaining_todo.docx). Both were correct defaults for a homelab install: an admin diagnosing a bad Alpine mirror or a temporary registry outage doesn't want the script to abort mid-provision. But they left MSP-graded operators with no way to INSIST on those verifications succeeding — no toggle that turns "warn and continue" into "abort". FIX: new DEPLOYMENT_PROFILE choice at install prompt time, one of {standard, production}: • standard (default) — behavior IDENTICAL to v7-12. Warnings are loud, failures don't abort. Chosen so every existing install and repeat run behaves the same. • production — verification failure is fatal. Missing sha512sum on the Proxmox host, unfetchable/malformed .sha512 sidecar, anything less than 3/3 container images pinned to a real @sha256: digest — any of these aborts the install with a clear operator-facing message. Also implies USE_DIGEST_PINNING=1 (the two answers can't sensibly be contradictory). Persisted into vars.sh so update.sh and later scripts see the choice. Deliberately implemented as a per-install prompt, not a hardcoded policy: the tradeoff between "always run" and "refuse to run under unverified state" is genuinely operator-context-dependent, and the audit itself flagged the absence of exactly this toggle as the correct fix rather than picking one side. Still open (unchanged by this entry — see Remaining_todo.docx): #17 (nftables output policy still accept — audit finding #16; deliberately not touched here, see next-step reasoning in the TODO doc), the daily backup cron's related concerns beyond the immediate fix, the CrowdSec enrolment-key argv exposure noted in v7-12, and the Apache/nftables config-injection surface noted in v7-12. The audit ALSO recommended post-install DNS validation as a defense-in-depth safety net against v7-11's #3 fix (finding #1+#2 remediation) — deliberately not added here because that validation would fire during the wp-front bring-up sequence before the candidate check runs, at a point where the fix would be to re-do the container recreation this script's own health check would already catch and diagnose.

## v7-14 — Field-bug sweep: custom slug + validator rewrite

**FIELD-BUG SWEEP**: custom slug made functional, unbounded log growth fixed, Skopeo digest resolution fixed, candidate fidelity restored, health check hardened, validation tooling rewritten for self-service diagnosis. This pass was a review for real bugs rather than an external audit response; each item below is a defect that would (or did) bite an operator in the field.

57. [CRITICAL] Skopeo digest resolution returned a MULTI-LINE value and silently broke both digest pinning and `update.sh check`. `skopeo inspect` emits a top-level manifest "Digest" AND a "LayersData" array where every element also has a "Digest" field; the old unbounded grep returned the manifest digest followed by every layer digest, one per line. Two silent consequences: (a) _pin_digest() built "${repo}@${multiline}", an invalid reference podman rejected on all 3 retries before falling through to a full tag pull — so the entire "resolve cheaply via Skopeo without pulling" design never actually took effect and every install did full pulls; (b) worse, show_check_summary() and do_digest_check() compare that value against the single-line stored digest, which can never match — so EVERY `update.sh check` reported "NEWER DIGEST AVAILABLE" for all three components on every run forever, and `digest-check` re-pulled and re-deployed everything each time even when nothing had changed. FIX: both copies of _skopeo_digest() now ask Skopeo for exactly the one field via `--format '{{.Digest}}'` (no JSON parsing, so LayersData cannot contaminate it), fall back to a head-1'd grep for older Skopeo builds, and validate the result is exactly one well-formed sha256 line before returning — failing closed to a tag pull if anything is off rather than building garbage.

58. [CRITICAL] THE CUSTOM LOGIN SLUG WAS COSMETIC AND, WORSE, COULD LOCK YOU OUT. Two layers: (a) the install printed "direct /wp-admin access will return 403", but the DirectoryMatch that produces that 403 is only emitted when ADMIN_CIDR/ALLOWED_ADMIN_IP is set — with a slug alone, /wp-login.php stayed wide open right beside the slug, so credential-stuffing bots that only ever try the default path were completely unaffected; (b) even as a pure alias the slug leaked immediately, because WordPress generates its own login URLs from site_url('wp-login.php', 'login_post') in the login form action and in every auth redirect. FIX, in three parts: the slug rewrite now tags the request with an Apache env marker (E=WPVM_SLUG:1) and a following rule rejects any /wp-login.php request WITHOUT that marker (install.php and setup-config.php exempted so first-run setup is never locked out); a must-use plugin (mu-plugins load unconditionally and can't be disabled from the admin UI) rewrites WordPress's own generated login URLs to the slug, WITHOUT which the new block would make login impossible — this is almost certainly the "slug didn't work" symptom from earlier versions, now made correct rather than merely decorative; and the install validates the placeholder was substituted and runs `php -l` on the plugin, removing it rather than leaving a site-wide fatal if it doesn't parse. Slugs colliding with a real WordPress path (wp-content, wp-json, etc.) are now rejected at prompt time.

59. [HIGH] LOGS GREW WITHOUT BOUND AND EVENTUALLY FILLED THE DISK. Nothing in any prior version rotated anything. Four writers appended forever to the same VM disk: access.log, error.log, remoteip-debug.log, and CrowdSec's logs. When the disk fills the failure is nasty and non-obvious — MariaDB can corrupt its data directory mid-write, the backup script fails, Apache stops serving, and the first symptom is "the site is down" with no clue a log file is the cause. FIX: logrotate installed with copytruncate (MANDATORY here — Apache runs in a container holding an open fd on the bind-mounted log, so a rename-based rotate would leave it writing to the unlinked inode forever while the new file stayed empty), both a daily and a 50M size trigger, 14 days retained, plus an explicit cron entry rather than relying on Alpine's periodic dir surviving this script's own crontab edits, plus an install-time `logrotate --debug` validation. Podman's own container logs (MariaDB and CrowdSec are chatty on stdout, and that stream grows independently of the Apache files) are separately capped at 50MB each via a containers.conf.d drop-in.

60. [MEDIUM] remoteip-debug.log wrote a SECOND line per request unconditionally — including on the majority of installs with no reverse proxy, where the peer-vs-interpreted comparison it exists to verify is identical by definition and proves nothing. That doubled total log volume (and, before item 59, the rate the disk filled) to answer a question nobody asked. FIX: emitted only when PROXY_IP is actually set, in both the host-generated config and the fallback.

61. [MEDIUM] v7-13 REGRESSION: dropping the candidate's .htaccess mount entirely (to close a write path the audit flagged) meant the candidate ran with NO .htaccess at all — no 8G firewall, no slug rules, no permalink rules — so it was no longer validating the configuration production actually serves, defeating the point of a candidate. FIX: mount it :ro instead, which keeps the config realistic while still closing the write path into production storage.

62. [MEDIUM] The HTTP health check followed redirects offsite and had no timeout. `tail -1` graded the FINAL redirect hop, so a canonical redirect to the real site domain (behind Cloudflare, say) returning 403 would fail a health check that has nothing to do with container health — and during an update that means a spurious rollback. FIX: --max-redirect=0 pins the check to this server's own first response, --timeout=10 stops a half-open socket hanging an entire update, and `head -1` takes the right status line.

63. [FEATURE] validate-wordpress.sh REWRITTEN for self-service diagnosis. The old version reported WHAT failed but never HOW to fix it, and most checks only confirmed a container was in state "running" — which says nothing about whether the site works. The new version runs LIVE functional tests (real HTTP fetches pinned to this server, a real DB query through WordPress's own credentials, a real gzip+completion-marker check on the newest backup, a live Skopeo digest resolution that would have caught item 57), attaches a concrete copy-paste remediation command to every single failure and reprints them all in one block at the end, separates FAIL (broken) from WARN (works but will bite later — disk filling, backup aging), and can be scoped to one area (--section security) while debugging instead of all-or-nothing. Installed also as `wp-validate`. It explicitly tests the slug end-to-end (slug path serves, default path 403s, mu-plugin present and parses) and correctly reports "can't verify from this host" rather than a false failure when ADMIN_CIDR excludes the VM's own address.
