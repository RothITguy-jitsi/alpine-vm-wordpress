# Changelog

All notable changes to this project are documented in this file. Versions
follow the informal `vMAJOR-MINOR` scheme this project has used since v7;
this restructuring keeps that scheme rather than switching to SemVer, so
existing references in the field (support tickets, internal docs) still
resolve.

## 2026.08.13d — A pasted label, and two fixes that were made but never shipped

The R2 failure was finally visible in one line of the config:

    secret_access_key = Secret Access Key: 14550d5c...

The label had been copied along with the value from the provider's panel.
rclone sent that whole string as the secret, every signature failed, and the
only symptom was `AccessDenied` on `ListBuckets` — indistinguishable from a
wrong or expired token, which is exactly where the investigation went. Two
sessions were spent on token permissions, bucket scope, and expiry, all of
which were correct throughout.

**Guarded in two places.** `set-credentials` now refuses a value containing a
space or a colon before writing it: these keys are hex, and a provider's panel
puts a label beside the value where it is easy to copy both. And `doctor` scans
an EXISTING `rclone.conf` for the same shape, because the twelve VMs already
deployed may be in that state right now and the symptom gives no hint.

**Also shipped: two fixes made last session and never packaged.** Worth naming
rather than quietly including, since the operator had to ask:

- `wasp-offsite-backup.sh set-credentials` — replacing storage credentials
  previously meant hand-editing `rclone.conf`, which is how the pasted label
  got in. It keeps the old file as `.prev`, and tests the new keys against the
  destination before declaring success rather than leaving the operator to find
  out at the next backup.
- The commission check printed the build's own VERSION NOTE as though it were a
  failure, because the note contained the word "failed". The filter now matches
  `[FAIL]` markers rather than prose.

Two things carry forward, both recorded so they are not lost:

**CrowdSec does not see failed 2FA attempts.** A correct password with a wrong
TOTP code fires no `wp_login_failed`, so the WordPress scenarios never trigger
and no ban is issued. The Two Factor plugin's own rate limiter stops the
attempt — which is why it felt handled — but an attacker holding a valid
password can grind codes without ever earning a firewall ban. The login guard
returning 429 early may also be starving CrowdSec of the events it needs.

**Credentials pasted into a support channel are compromised.** The keys, account
token and R2 token from this diagnosis should be rotated regardless of whether
the backup now works.

---

## 2026.08.13c — The off-site failure was an expired token, and nothing noticed for a week

The operator sent the R2 token screen. It reads:

    orange-butterfly-04dd | test | Object Read & Write | Aug 3, 2026 | Inactive since Aug 11, 2026

Correct permission, correct bucket, and **inactive**. The last successful upload
was `wp-db-20260811-233512.sql.gz.age`, written on 11 August. The token lapsed
the same day, and every push since returned 403.

Nothing in any WASP release caused it. The operator's reasonable suspicion --
"we added Squid or something happened a few revisions ago" -- was wrong, and so
was my own diagnosis two messages earlier: I had them checking read permissions
on a token whose permissions were never the problem. Cloudflare R2 tokens can be
created with a TTL, and an expired one returns 403 **while still displaying the
correct permissions and bucket**. There is nothing to see on the VM.

**The real defect is that it took a week to find out.** Off-site backups had
been failing since 11 August. The push error was recorded, but a recorded error
that never changes reads as one failure rather than every failure since a date,
and nothing anywhere asked the question that would have caught it: *when did
this last actually work?*

Four changes, in order of how much they matter:

- **`validate-wordpress.sh --check` now reports off-site STALENESS by age.**
  `wp-db-backup.sh` records a timestamp on each successful copy; anything older
  than two days is a warning, seven days is CRITICAL. On a daily schedule, two
  days means the last two runs failed, whatever the reason. Age is the only
  signal that survives a silent, unchanging failure -- which is precisely the
  shape an expired credential has.
- **`wasp-triage.sh` checks it too**, and checks it BEFORE the error file, so
  the twelve VMs already deployed can be swept for this in one pass.
- **`wasp-offsite-backup.sh doctor` now names the expired-token case first**,
  with the instruction to read the Status column rather than the permissions.
  If a token is inactive, no amount of checking the VM will help.
- **The setup prompt says to set the TTL to Forever**, at the moment the token
  is created, with the reason: a token with an expiry stops working on a date
  nobody has written down.

The wider lesson is one this log keeps recording from different angles. Every
control here was working. The backup ran, the error was captured, the tooling
reported honestly. What was missing was anything that asked how long a thing had
been broken -- and a failure that looks identical every day is invisible to
everything except a clock.

---

## 2026.08.13b — Proxmox notes: readable in the panel they actually appear in

Reported with a screenshot: the VM notes panel showed
"WASP ??? WordPress Alpine Sec" with the title cut off mid-word, and
"build 2026.08.12w ??" underneath.

**Two problems, both from writing for a terminal instead of a web panel.**

The replacement characters were em-dashes, middots and arrows. Whatever
encoding Proxmox applies between `qm set --description` and the web UI does not
survive them, and that is not worth fighting -- the notes are now pure ASCII,
nothing above codepoint 127.

The truncation was layout. The old notes ran to 122 characters on their longest
line, written as wide tables for a full-width terminal. The panel is narrow and
does not wrap gracefully; anything wider is simply cut. Rewritten for roughly 46
columns and stacked vertically, because Proxmox scrolls the panel down happily
and only struggles sideways. Longest line is now 34 characters.

The content was reorganised while it was being rewritten, into the order someone
actually reads it: what this is, how to get in, who is allowed in, the three
first steps, day-to-day commands, what to do when something looks wrong, and
recovery. The recovery section states plainly that off-site backups cannot be
read without the age key and points at KEY-CUSTODY.md, because the VM notes are
the one document that is guaranteed to still exist when someone is trying to
recover this machine.

It also now ends by saying the notes are generated at install and not updated
afterwards, so nobody trusts a stale line in six months' time.

**From the same run's log:** the firewall now loads cleanly -- no syntax error,
no production blocker -- which confirms the expansion-order and expanding-comment
fixes on hardware. The two remaining failures are the R2 token and the deferred
MFA install, both already diagnosable with `wasp-offsite-backup.sh doctor` and
`wasp-mfa-deferred.sh --status`.

---

## 2026.08.13a — Completing the verification pass: a CWE-377 in a root cron job

Finishing the parts of the sweep left incomplete: component currency, the full
documentation pass, and the bug classes not covered by an existing check.

**Component versions verified.** WordPress 7.0.4 is current (no 7.0.5; 7.1 due
around 19 August). CrowdSec `v1.7.8` remains the release that fixed
CVE-2026-44982 (WAF bypass) and CVE-2026-44981 (LAPI denial of service).
MariaDB `11.4` is LTS to May 2029 and its branch tag tracks patches. Two
apparently-unpinned tags were checked and are benign: `wordpress:latest` is only
read by `skopeo inspect` for a currency comparison and never run, and
`wordpress:cli` is a fallback used only when pinned.env lacks the digest.

**Documentation pass clean.** Spelling checked across every document and every
script; the single hit (`skipp`) is a deliberate partial match for
skipped/skipping. Every numeric claim matches reality — 20 tools documented, 68
menu entries, 21 MFA cases, 20 static checks.

**A real finding: the weekly GeoIP refresh.** It ran as root from a single
enormous cron line with two defects that matter for something scheduled:

  * It wrote to PREDICTABLE `/tmp` paths and untarred into one of them. A local
    user can pre-create either as a symlink and redirect a root-owned write —
    CWE-377, the class already fixed everywhere else in this codebase and
    missed here because it lived inside a cron string rather than a script.
  * The `curl` had no `--max-time`, so a hung MaxMind connection left a root
    cron job running until the next reboot.

Now a real script: `mktemp -d` with a trap, a 180-second bound, a size check on
the extracted database, and an atomic replace so a crash mid-copy cannot leave
Apache loading a half-written file. It also keeps the existing database on any
failure rather than replacing a working one with nothing.

**Two of my own mistakes, caught by the checks, in the course of fixing it.**
First, the helper was inserted INSIDE the cron heredoc — it would have been
written as literal text into `/etc/crontabs/root` rather than executed,
corrupting the root crontab. Second, once fixed, `check-setu-unset.py` reported
three false positives, and the reason was a genuine flaw in the check: it tested
for `set -u` BEFORE stripping heredocs, so a file that merely *emits* a strict
script inherited that strictness and every variable in the outer file was
reported unassigned. Heredocs are now stripped first, with a regression fixture.

Both were found because the suite ran, not because I re-read the diff. That is
the argument for the checks in one sentence.

Other classes swept and clean: no unbounded network calls remaining, no
infinite loops (the menu's `while :;` all break or return), no other predictable
temp paths, no insecure TLS flags, no secrets to world-readable locations.

---

## 2026.08.13 — Verification pass, and triage for a fleet already in production

Twelve client VMs are running builds from the 2026.08.12 series, and several of
those releases shipped defects that leave a VM running and looking healthy while
a control is silently absent. That changes what is useful: the code being clean
now does nothing for a VM deployed last week.

**Verification first. All 19 checks clean**, across doas prefixes, doc coverage,
doc links, embedded quotes, expansion order, function order, grep counts, health
probes, heredoc backticks, install conditionals, line continuations, menu
entries, parameter expansion, `set -e` captures, `set -u` variables, slug
rewrites, Squid ACLs, undefined helpers and version claims — plus `bash -n` on
48 files, `sh -n` across the payload, `php -l` on every mu-plugin, and the
21-case MFA harness.

A separate hunt for classes with no check found nothing: no insecure TLS flags
(earlier apparent hits were `-s`, not `-k`), no secrets written to world-
readable paths, no dangerous `rm -rf` on an unbounded variable, no scripts still
hiding in heredocs.

**WordPress 7.0.4 confirmed current.** No 7.0.5 exists; 7.1 is expected around
19 August. Worth passing to clients alongside the update cadence: Patchstack's
analysis of the 7.0.2 chain observed that automated research took a vulnerability
"from zero to working RCE in ten hours", and concluded that "we'll patch it
during a maintenance window" is a plan built for a threat landscape that has
already gone. That is the argument for `update.sh check` weekly rather than
quarterly, and it is a better one than any I would have written.

**New: `wasp-triage.sh`, for the VMs already out there.** "Redeploy everything"
is a week of client downtime for problems that mostly patch in place. This
checks the specific known-bad states on a RUNNING system — reading actual state
rather than the version string, because a VM may have been partly patched by
hand and the version alone will not tell you:

  1. Is there a firewall at all (nftables has tables)
  2. Can WordPress send mail (an SMTP allow rule is live)
  3. Can anything alert (wp-notify runs rather than crashing)
  4. Is the core being SERVED the one that is pinned
  5. Was MFA requested but never installed
  6. Is anything actually reaching off-site
  7. Is CrowdSec enforcing, or only detecting

Each finding names the release it came from, what it means for that client, and
the command that repairs it. Exit 2 for live exposure, 1 for something promised
but not working, 0 for clear — so it can be driven from a loop across the fleet.

MSP-RUNBOOK gains a triage section with the order to work in, worst first: no
firewall, then no mail, then no alerting, then core version. And the note that
matters on a fleet — record the output per client in the ticket, because "I
think I fixed that one" is not a record.

---

## 2026.08.12z — The deferred MFA installer could not be run, watched, or checked

Reported: MFA never installed automatically, twenty minutes of waiting produced
nothing, and there was no command to run it by hand — the install line had to be
dug out of an old log.

The install log shows the hook WAS arranged: script written, cron entry added.
So it either never fired or fired and said nothing. Three separate failures made
that impossible to tell apart, and all three are the same underlying mistake.

**It exited silently while waiting.** The hook checked whether the setup wizard
was finished and, if not, `exit 0` with no output. So an empty log meant
"waiting", "broken", or "cron never ran" — indistinguishable. It now logs every
run including the waiting ones, and records what wp-cli actually said. A
heartbeat costs one line and answers the question in one look.

**There was no way to force it.** Added `--now`: ignores the completion stamp,
prints to the terminal as well as the log, and reports what it found. And
`--status`: shows the schedule line, whether crond is running, whether the
completion stamp exists, and the last dozen log entries. Those are the three
states that look identical from outside, so the tool distinguishes them
explicitly. Both are on the Testing menu, which is the gap the operator named.

**The install assumed its own scheduling worked.** It appended to
`/etc/crontabs/root` and moved on. It now verifies the line is present, checks
that crond is actually running — a perfect crontab entry does nothing without
it, and that combination is completely silent — and prints both the forced-run
and status commands.

**And the script was invisible to every check in this repository.** It lived in
a heredoc inside stage 10, which meant no `sh -n`, no undefined-helper check, no
doas-prefix check, no menu verification. Seventy-five lines of shell that ran on
every client VM and had never been linted once. Extracted to
`payload/bin/wasp-mfa-deferred.sh` and installed like every other tool.

The extraction paid for itself immediately: the menu-entry check failed the
moment the new menu items were added (the target did not exist as a file), and
the doc-coverage check then failed because the tool was undocumented — twice,
first for being mentioned only inside a code fence. Both were real gaps that a
heredoc had been hiding. No other embedded scripts remain.

---

## 2026.08.12y — The R2 403 is a READ permission, not a wrong bucket

The operator sent a screenshot of the bucket, and it disproved the previous
release's advice cleanly. The path `test / wasp / ctrl` matches the configured
destination exactly, and an object had genuinely been written there —
`wp-db-20260811-233512.sql.gz.age`, since deleted by hand. So the bucket name,
the prefix and the upload mechanism were all fine, and sending the operator to
check the bucket name character by character was wrong.

**The failure is on `HeadObject`, which is a READ.** rclone HEADs an object
before uploading, to decide skip versus overwrite, and this tool HEADs after, to
verify the size landed. A token with **Object Write but not Object Read**
produces exactly what was observed: PutObject would succeed, HeadObject returns
403, and the transfer aborts either side of the bytes moving — with credentials
that are entirely correct. That also explains why it worked on 11 August under a
different token.

Three changes:

- `doctor` now tests **listing buckets** and **reading inside the configured
  path** as separate steps. On R2 those are different permissions, and testing
  them separately isolates a write-only token in one command instead of leaving
  the operator to guess between "wrong path" and "wrong key".
- The 403 guidance is reordered: token permission first, then bucket scope, then
  the name. The name check stays, because R2 returns 403 rather than 404 for a
  bucket a token cannot see and a typo really is indistinguishable from bad keys
  — but it is no longer presented as the likely answer.
- The setup prompt already said "Object Read & Write" and it was buried
  mid-paragraph inside advice about denying delete. It is now its own
  highlighted block stating that **Object Write alone looks sufficient and is
  not**, with the symptom named: uploads succeed, verification fails, and the
  report reads "the backup is not off-VM" while every credential is correct.

Worth recording as a diagnostic lesson rather than just a fix: the previous
advice was reasoned from the error code alone. One screenshot of the actual
bucket eliminated two of three hypotheses in a second. When a remote service is
involved, looking at the remote beats reasoning about it.

---

## 2026.08.12x — A comment expanded a variable and destroyed the ruleset

The expansion-order fix worked — the "unexpected ct" error is gone. A different
one replaced it, from the same root misunderstanding, and nft printed the
evidence directly:

    ip saddr 10.89.10.0/24 tcp dport { 25, 465, 587 } ct state new counter drop, six lines later in the chain), so

That is a firewall rule with the tail of one of my own comments welded to it. I
had written, inside the multi-line `EGRESS_PROXY_FORWARD="..."` assignment:

    # this block (as ${SMTP_RATE_LIMIT}, six lines later in the chain), so

**A `#` inside a double-quoted string is not a comment.** The shell never parses
it as one, so `${SMTP_RATE_LIMIT}` expanded — pasting an entire rule block into
the middle of explanatory prose. Two such comments existed; both did it. nft
rejected the file and the VM booted with no firewall again.

This is the THIRD time this exact class has struck: first a backtick running
`wp-mail.sh` on the Proxmox host, then this twice. Each time the mechanism is
identical and the surface looks different, because prose is not where anyone
looks for code.

**The good news, and it is real: the production blocker worked.** Last release
this same failure reported "INSTALL COMPLETED". This time it refused to certify
the VM and said plainly that everything reporting "enabled" was describing
rules not in the kernel. The fix from 2026.08.12v did its job on its first
outing.

**The check now covers variable expansion, not just backticks.** The earlier
extension scanned for backticks using a block regex, which missed these
entirely: the assignments contain escaped quotes and run to a hundred lines, so
the regex never matched them. It now tracks quote state line by line — slower
and correct — and flags `${VAR}`, `$VAR` and backticks in any comment inside a
quoted string. Verified retroactively against the exact line.

**The R2 403 diagnosis was wrong, and the operator's note is why.** They wrote
"I am copy/pasting the exact credentials that has worked before", and the
previous guidance sent them straight to the credentials. Cloudflare R2 returns
**403, not 404, for a bucket the token cannot see** — it will not confirm
whether a bucket exists to an unauthorised caller. So correct keys plus a
mistyped bucket name produce the identical error to bad keys.

`wasp-offsite-backup.sh doctor` now says so, in order: check the bucket name
character by character first, then the token's bucket scope, then Read vs
Read+Write. It also notes that a 403 on **HeadObject** specifically means the
upload may have succeeded and only the size verification was refused — so the
dashboard is worth checking before assuming nothing was written.

---

## 2026.08.12w — Proving CrowdSec actually blocks, not that it started

Reported from the console: 1 log processor, **0 remediation components**, no
active remediation visible — while the install had verified "Bouncer connected
to LAPI". Both statements can be true at once, and neither answers the question
that matters.

CrowdSec's own docs are clear about the split: the Security Engine detects and
the Local API issues decisions, but **enforcement is done by the Remediation
Component pulling those decisions and writing them to the firewall**. The
console is a dashboard reflecting what the enrolled engine last reported; it
syncs periodically and can lag. Enforcement is local. A console showing zero
components and a VM that blocks correctly is a real combination, and so is the
reverse — CrowdSec publishes a troubleshooting page for a Security Engine with
registered-but-inactive components precisely because "it appears in the console"
is not proof either.

So neither source was worth trusting, and the install's own check —
"cs-firewall-bouncer service running" — proves only that a service started.

**`wp-hardening.sh crowdsec-doctor` walks the whole chain and then tests it for
real.** Six inspections (engine running, LAPI answering, bouncer registered,
service running, last_pull recent, the crowdsec nftables set present), then the
step that actually settles it: it adds a genuine ban for `192.0.2.222`
— TEST-NET-1, RFC 5737, never routable — waits up to twenty seconds for it to
appear in `nft list ruleset`, reports how long it took, and removes it again.

If that passes, remediation works whatever the console says, and the tool says
so in those words. If it fails, the message is the one that matters: detection
may be working and nothing is being blocked.

It is on the Security menu and is now step ten of the commission check, because
"are attackers actually being blocked" belongs in the same pass as "does the
site come up".

The `last_pull` check is included specifically because CrowdSec flags
registered-but-inactive components after 24 hours — a bouncer that registered
once and never pulled again looks healthy in a service listing and enforces
nothing.

---

## 2026.08.12v — The VM had no firewall at all

The most serious defect in this series, and I introduced it two releases ago.

    /etc/nftables.nft:110:70-71: Error: syntax error, unexpected ct

`SMTP_RATE_LIMIT` is built at line 99. `_SMTP_PORTS`, `_SMTP_RATE` and
`_SMTP_BURST` were not assigned until line 290. Shell expands at assignment
time, so all three were EMPTY and the generated rule read:

    ip saddr 10.89.10.0/24 ... tcp dport  ct state new limit rate  burst  packets

nft rejected that and, correctly, **refused the entire file**. The VM came up
with no filter table: no L1 packet filter, no admin-IP restriction, no egress
boundary, nothing. `wasp-egress test` reported "the boundary is NOT holding",
which was true in the most literal sense available — there was no boundary.

This is the same ordering trap as two releases ago, from the opposite
direction. Then the consumer ran before the definition and the rule silently
vanished, breaking mail. Fixing that, I moved the definition up — above its own
dependencies. Both times the file passed `bash -n`, because both times the
shell syntax was perfectly valid and only the generated artifact was wrong.

**Worse than the bug: the install reported success.** The syntax pre-check
caught the error and printed it, then the install continued and finished with
"INSTALL COMPLETED". Every fail-closed control here blocks production —
unverified signatures, a dead Squid, MFA that cannot enrol — except the one
whose failure means there is no perimeter at all. That was an oversight, not a
decision. A ruleset that fails to check OR fails to load now writes a
PRODUCTION-BLOCKER stating plainly that everything else reporting "enabled" is
describing rules that are not in the kernel.

**New check: `check-expansion-order.py`.** It finds multi-line double-quoted
assignments — the shape used to build nftables and Apache fragments — collects
the `${VAR}` references inside them, and fails if any is assigned later in the
same file. Verified retroactively: restoring the tunables to their old position
makes it name all three variables and both line numbers.

That check is the real deliverable here. This class has now cost two releases
and produced, in turn, a site that could not send mail and a site with no
firewall — and neither was visible to `bash -n`, to the check suite, or to a
careful read. It was visible in the generated file, which is exactly what the
check now reads.

**Also in this log, and now correctly diagnosable:** the off-site push fails
with `S3 HeadObject 403 Forbidden`. That is the credentials or the bucket
policy, not the platform — and it is visible at all because of the error
surfacing added in 2026.08.12o. `wasp-offsite-backup.sh doctor` will name which
of the three causes it is.

---

## 2026.08.12u — A comment that wasn't a comment

Every install of 2026.08.12t printed, twice:

    lib/03-dynamic-configs.sh: line 162: wp-mail.sh: command not found

I introduced it in the previous release. Explaining the SMTP fix, I wrote inside
the multi-line `EGRESS_PROXY_FORWARD="..."` assignment:

    # symptom was `wp-mail.sh doctor` reporting

That is a double-quoted shell string. **A `#` inside one is not a comment** —
the shell never parses it as such; it is just text. And backticks in text are
still command substitution, so bash dutifully tried to run `wp-mail.sh` on the
PROXMOX HOST, where it has never existed.

Harmless in effect: the substitution produced an empty string and the ruleset
was built correctly. The SMTP destination pinning from that release worked, and
the log confirms it — `SMTP egress pinned to mail.ironveil.systems
(65.108.150.44)`. But an error on every single install is not something to
tolerate, and it was one small change away from being genuinely damaging: a
backtick around something that DOES exist on the host would have executed it as
root, mid-install, with no one intending it.

**The existing check should have caught this and did not.**
`check-heredoc-backticks.py` was written after this exact class bit before, but
it only inspected heredoc bodies. Quoted assignments were outside its scope, so
prose inside one was unexamined. It now scans both, reports which context it
found the backtick in, and gives the right fix for each. Verified retroactively:
restoring the line makes it fail naming the file, the line and the command.

The lesson generalises past shell. **Prose written for a human reader is exactly
where this lands**, because nobody proofreads a comment as if it were code — and
inside a quoted string, that is precisely what it is. The habit worth keeping is
to use 'single quotes' around a command name in explanatory text and reserve
backticks for markdown, where they are inert.

---

## 2026.08.12t — Deferring the boot race honestly, and writing for strangers

The boot-ordering race stays deferred at the operator's call, which is the right
decision: `wp-container` waits for MariaDB to have STARTED rather than to be
READY, and for someone running a dozen installs by hand that is a recognisable
twenty-second wait, not a fault.

**But the calculus changes now that this is public.** For a stranger who found it
on GitHub or Gitea, their first reboot shows "Error establishing a database
connection" on a site they just built, and the reasonable conclusion is that the
project is broken. That is the whole first impression, spent on a race that
resolves itself. A public project is judged by its worst thirty seconds.

So the cost of not fixing it is adoption rather than downtime — and the honest
mitigation until it IS fixed is to say so plainly, in the two places someone
would meet it:

- The completion banner now sets the expectation BEFORE the first reboot: the
  message is expected for ~30 seconds, MariaDB is still starting, reload after a
  minute, only investigate past five.
- SUPPORT-RUNBOOK's Tier 0 "website looks down" section now names that exact
  string, so nobody escalates a self-clearing condition.

Cheap, no risk to boot ordering, and it removes the "looks broken" failure
without pretending the race is gone. The TODO entry records that reasoning
rather than just the symptom.

**A "Before you use this" section in the README**, because a project serving a
dozen client sites while being publicly installable owes strangers the context
its author already has:

- Who it is built for — one MSP operator who knows the stack, which is the
  assumption behind every prompt and every default.
- What is proven on hardware versus what has a tool and a documented drill but
  needs running yourself. Off-site restore is named specifically.
- What you are taking on: this says no to things. Production disables plugin
  installs from wp-admin, blocks PHP shell functions, restricts egress, and
  refuses an unverified install. Each has a toggle and a stated reason. If you
  want a platform that gets out of your way, this is the wrong one.
- That `TODO.md` is worth reading before deciding, and that a stale entry
  claiming a closed gap is treated as a defect.
- No support commitment. MIT and public because it may be useful, not because
  there is a contract behind it.

Writing that down is not modesty. An operator who installs this expecting
something it is not will find the difference at the worst moment, and the
CHANGELOG is already a record of how much of this was learned the hard way.

---

## 2026.08.12s — Key custody written down, and a stale TODO closed

Two of the easiest remaining items, picked deliberately over the harder ones
because value-per-effort matters more than difficulty when a deadline is close.

**`docs/KEY-CUSTODY.md`.** Every secret this platform creates: where it lives,
what breaks if it is lost, and blanks to fill in per client. Pure documentation,
no code, no risk — and the highest-value item left on the list.

The reason it earns that: every other risk here is recoverable. A broken VM
rebuilds, a compromised site restores, a bad firewall re-runs. **The age backup
key is the only failure with no remedy** — lose it and every encrypted backup is
permanently unreadable, not difficult but impossible. And it is a filing problem
rather than a technical one: the private half is deliberately NOT stored on the
VM, because an attacker who reached the VM could otherwise decrypt the backups it
had just made. That design decision is precisely what makes it a custody
question.

The document draws the distinction that matters and is easy to blur: losing the
object-storage credentials means you cannot REACH the backups (a support
ticket); losing the age key means you cannot READ them (unrecoverable). It also
ends with the question worth asking out loud — if you were unavailable for a
month, could a colleague restore a client's site? If the answer depends on
something only you know, the document is not finished.

**A stale TODO closed: the heartbeat was already built.** `wp-notify.sh
--heartbeat` and `--heartbeat-url` are implemented, documented and on the cron
schedule, while TODO.md still listed external reachability as an open gap.

Worth recording as its own small lesson, because it cost marks in an external
evaluation: **a stale TODO claiming a gap you have already closed is worse than
one naming a real gap.** A reviewer reads it and marks you down for work that is
done. Verify before writing "not addressed" — the same discipline this project
applies to code claims applies to its own roadmap.

Deliberately NOT started, and worth naming so the choice is visible: TLS expiry
monitoring needs an off-box vantage point, the single slug-rewrite generator is a
refactor through the login path, and candidate DB isolation from the latest
evaluation is real design work. None of those is a good idea at this hour.

---

## 2026.08.12r — WordPress 7.0.4 (Author+ RCE), and SMTP is destination-pinned

Two independent evaluations of 2026.08.12q. Both led with the same thing, and
both were right.

**SECURITY — the default image was one release behind, again.** WordPress 7.0.4
shipped 2026-08-12, six days after 7.0.3, fixing **CVE-2026-65640** (CVSS 8.8):
an authenticated Author+ remote code execution via malicious file upload where
ImageMagick delegates to Ghostscript. ImageMagick identifies a file by its
CONTENT, not its extension; WordPress trusted the extension, so a
`holiday.png` that is really PostScript became code execution. Affects 4.7.0
through 7.0.3.

Exposure is conditional — it needs both Imagick and Ghostscript present, and an
account with `upload_files`, meaning Author or above. Neither condition makes it
skippable: WordPress backported the fix to the 4.7 branch and states that only
the most recent release is supported. Updated everywhere.

Worth drawing out, because it cuts against this platform's emphasis: **this CVE
is about the Author role, not the administrator.** Nearly everything here — the
login slug, the IP restriction, MFA, DISALLOW_FILE_MODS — protects the admin. A
client's guest contributors with upload rights are a surface this platform does
almost nothing about, and that is now noted in the code.

**SMTP egress is destination-restricted, not just rate-limited.** The top MAJOR
in both evaluations, and a gap I had written into the config myself one release
earlier while fixing the rule ordering: thirty connections an hour stops bulk
exfiltration but does nothing to stop a compromised WordPress talking to the
ATTACKER's mail server on 587. The relay is now resolved at install and the rule
pinned to its addresses.

The limits are stated rather than glossed: it resolves once, so a hosted relay
that changes IP will stop delivering until re-pinned — hence the new
`wp-hardening.sh smtp-repin`, which re-resolves and reloads with a
validate-before-load guard. And it degrades to the old port-only rule with a
WARNING when the relay cannot be resolved, because silently breaking a client's
password resets to close a theoretical channel is the wrong trade to make on
their behalf. A relay on shared infrastructure resolves to shared addresses, so
pinning buys less there — it still removes "any host on the internet".

**README advertised a WordPress version three security releases stale.** It said
`6.9.4-php8.3-apache` while the installer pinned 7.0.3 — across a login-page XSS
and an Author+ RCE. The version had been corrected in code each time and the
documentation had not. That is worse than an old number: a reader judging whether
this platform is current reads the README, not `install-wordpress.sh`.

**New check: `check-version-claims.py`** reads the tag the installer actually
pins and fails if any document states a different one, with the changelog
exempt as append-only history. It immediately found a second instance in
ARCHITECTURE.md that I would have missed by hand, which is the whole argument
for the check existing rather than a promise to be careful.

---

## 2026.08.12q — The egress proxy silently broke all outbound mail

Two findings from one line of diagnostic output the operator pointed at. The
first is the most serious functional defect in this series.

**`TCP 587: UNREACHABLE (Connection timed out)` — enabling the egress proxy
disabled email entirely.** The operator's instinct that this was egress-related
was right; it was mail rather than backups.

nftables is first-match-wins. The egress-proxy block ends with:

    ip saddr 10.89.10.0/24 counter drop

and the SMTP allow rule was expanded SIX LINES LATER in the same chain. It was
therefore never reached. Every outbound connection from the WordPress container
that was not to Squid or the resolver was dropped, including submission on 587.
Password resets, order confirmations, admin notifications, malware alerts — all
of it, silently, on every install with `EGRESS_PROXY=1`. Every other mail check
passed: config present, mu-plugin loaded, DNS resolving, credentials correct.
Only the one line that actually tried to open the socket disagreed.

Fixed by moving the SMTP rules INSIDE the egress block, ahead of its own drop.
That required moving the definition above its use as well — expanded where it
was, `${SMTP_RATE_LIMIT}` resolved to an empty string and the rule vanished,
which is the same failure wearing a different hat. Verified rendered in both
proxy-on and proxy-off states, appearing exactly once in each: expanding it
twice would duplicate the rules and halve the effective rate limit.

The honest framing is now in the config: mail cannot go through Squid, because
Squid is an HTTP proxy and speaks nothing else. Submission needs its own hole,
so the egress boundary has one outbound TCP path that is not
destination-filtered. The rate limit — 30 new connections/hour, burst 10 — is
what keeps that from being a bulk exfiltration channel: ample for a WordPress
site, useless for moving a database.

**`mu-plugin: MISSING` while another tool reported it installed.** Both check
the identical path, so they could not legitimately disagree — and the
explanation was that `validate-wordpress.sh` silently REINSTALLS it. The
WordPress image's entrypoint extracts core into the docroot when index.php is
absent, which is exactly the state when stage 06 writes these files moments
before the container's first start, and that extraction brings its own
wp-content which displaces them.

So mail worked on installs where validate happened to run first, and not
otherwise. Relying on a later tool to repair this is not a design, it is a
coincidence that happened to hold. The mu-plugins are now re-asserted
idempotently at the first moment the docroot is settled — after WordPress is
confirmed healthy — with MFA placeholder substitution repeated, and a warning
when a re-install was actually needed so the condition is visible rather than
papered over.

---

## 2026.08.12p — Squid is not the offsite problem, and now the VM can say so

The operator asked whether Squid could be blocking the off-VM backup, and
whether that path bypasses it. A fair question that nothing on the box could
answer, which is itself the defect.

**It does not go through Squid.** The egress-proxy rule matches
`ip saddr 10.89.10.0/24` in the FORWARD chain — the CONTAINER subnet. `rclone`
and `msmtp` run on the HOST as root, so they traverse the OUTPUT chain instead
and never meet that rule. The destination does not need to be in the Squid
allowlist, which is why `.r2.cloudflarestorage.com` is absent and does not need
adding. The host port filter IS enabled on this install, but 443 and 587 are
both in the permitted set, so neither is blocked there either.

So the offsite failure is a genuine rclone-level problem: credentials, bucket
name, or reachability. "It worked previously" is consistent with that — this is
a fresh VM with a freshly entered secret key, not the same configuration that
worked before, so it is a new typo rather than a regression.

**New: `wasp-offsite-backup.sh doctor`.** Answers the question in one command,
in the order it actually arises: does the proxy apply (no, with the reason), can
rclone reach and list the remote, what did the last push say, and what is
actually stored there now. When rclone fails it prints rclone's own words and
explains how to read them, because the three causes are indistinguishable from
outside and completely different to fix:

    403 / SignatureDoesNotMatch  -> the secret key is wrong or empty
    404 / NoSuchBucket           -> the bucket name is wrong
    dial tcp / timeout           -> genuinely a network problem

On the menu under Backup, and both the self-test failure and `status` now point
at it. An operator should not have to reason about which nftables chain applies
to work out why a backup is missing.

**A cosmetic SMTP bug that undermined confidence in a correct config.** The
install summary printed
`SMTP: contact@rothitguy.pro@mail.ironveil.systems:587` — a double `@`, because
the line joined `${SMTP_USER}@${SMTP_HOST}` and the username is itself an email
address. The msmtp config was correct throughout (user and host are separate
keys, and `wp-mail.sh doctor` passes every check). But a summary that looks
malformed makes an operator distrust the thing it is summarising, which is how a
working relay gets "fixed". Now reads `contact@rothitguy.pro via
mail.ironveil.systems:587`.

---

## 2026.08.12o — Local restore PROVEN on hardware; offsite push failure was being swallowed

The best run so far, and it produced the single result this project has been
working toward for weeks.

**The local restore drill passed end to end, on real hardware, with real data:**

    [PASS] Archive passes gzip integrity
    [PASS] Scratch database is running
    [PASS] Archive restored without error
    [PASS] Restored database has 12 tables
    [PASS] siteurl present in restored data: https://test.rothitguy.pro
    [PASS] Restored users table has 1 user(s)
    [PASS] Restored row counts are consistent with production (6 vs 6)
    [PASS] Scratch instance destroyed

That is a backup taken from a live site, restored into a throwaway database, and
verified to contain the actual content — 12 tables, the real siteurl, the real
user, six posts matching production. Not "the archive is valid gzip". Recovery,
demonstrated. Every previous run failed somewhere in that chain.

The MFA blocker is now the EXPECTED one: it states that the plugin cannot install
until WordPress setup is complete, that a deferred installer will handle it
within ten minutes, and that it will clear itself. Working as designed.

**The one failure was offsite, and the reason had been swallowed by a bug.**
`wp-db-backup.sh` pushes to the remote immediately after each backup. That push
failed. The block meant to report it captured the output to `"$_OFFLOG"` — a
`mktemp` path — and then read from a hardcoded `/tmp/.offsite.log`. Two
different files. So the error was captured and then read from an empty path,
logging nothing. The operator saw "Newest backup is NOT present off-VM" and
"No remote backup object found to drill" with the cause nowhere at all.

Fixed, and the reason is now persisted rather than only logged:

- The push error is written to `/etc/wp-install/offsite-last-error` (0600), so
  it survives syslog rotation and is in the same place as the complaint.
- `wasp-offsite-backup.sh status` leads with it, and lists the three usual
  causes in order of likelihood: a mistyped or empty secret access key, a
  bucket name typo, a token not scoped to write.
- `wasp-selftest.sh` prints it under the FAIL instead of only the symptom, and
  says so explicitly when no failure was recorded — because that means no push
  ever ran, which needs a different action.
- `wp-db-backup.sh` now says it on stderr too, for anyone running it by hand.

This is the fourth instance in this series of a failure being captured and then
discarded before anyone could read it. The pattern is always the same shape: the
code knows what went wrong and throws it away one line later.

---

## 2026.08.12n — File integrity: checksums here, FIM to Wazuh

Closes the last open finding from the external evaluation, and splits the work
where it belongs: WordPress.org checksums verify what WordPress.org publishes,
and a SIEM handles everything else.

**`wp-plugins.sh verify`** compares core and plugin files against published
checksums, detecting a file modified since installation — the signature of a
backdoor injected through a vulnerable plugin, which is how most WordPress
compromises persist. Weekly (Monday 04:30) and step nine of the commission
check.

**It does not trust wp-cli's exit code.** Documented behaviour, confirmed in a
report published four days ago: `wp plugin verify-checksums --all` can print
"Verified 2 of 3 plugins (1 skipped)" and still exit 0, because a plugin with
no checksum on WordPress.org is skipped rather than failed — true of every
commercial and bespoke plugin. A caller trusting the exit status sees success
while a plugin went unchecked. This project has been bitten by exactly that
shape three times now (the pipeline that masked a failed install, the report
that claimed a plugin was active, the commission check that hid its own
evidence), so the pattern was recognisable.

Three states are reported separately because they mean different things:
VERIFIED, MODIFIED (the finding), and SKIPPED (expected for Divi and anything
bespoke — not a failure, but those files are outside this control).

**The primary test is arithmetic, not phrasing.** If
`total − verified − skipped > 0`, something was checked and failed, and that is
treated as a finding even when no message matched. wp-cli's wording changes
between releases; grepping for "doesn't verify" is a useful hint and a poor
primary test. Verified against four count combinations including the exact
"2 of 3 (1 skipped)" case.

**Wazuh integration is the log format, not an agent script.** Every outcome goes
to syslog tagged `wasp-integrity` in key=value form at a severity matching its
meaning — `auth.crit` for FAIL, `auth.notice` for SKIP, `auth.info` for PASS:

    wasp_integrity result=FAIL component=core reason=checksum_mismatch
    wasp_integrity result=SKIP component=plugins reason=no_published_checksum count=2

A decoder matching `wasp_integrity` and alerting on `result=FAIL` is the whole
integration. The shape is documented as an interface so it is not casually
changed.

The SKIP line is the one worth wiring deliberately: it names the files this
control cannot cover, which is exactly where Wazuh's own FIM should point.
Checksums cover what WordPress.org publishes; FIM covers the commercial theme,
the bespoke plugin, and the uploads directory. Stating that boundary is more
useful than pretending one tool does both.

---

## 2026.08.12m — CIS gap analysis: PHP shell functions were never blocked

Checked WASP against current hardening standards rather than against my own
assumptions. The useful finding first: **CIS publishes no WordPress benchmark**
and deliberately does not — their position is that WordPress is a CMS running
on infrastructure, and if the OS, web server, PHP runtime and database are
hardened, WordPress inherits that. That is exactly the shape of this project,
which is a reassuring result: the architecture is aligned with where the
standards bodies think the work belongs, not with the plugin-shaped hardening
most WordPress advice offers.

Against CIS Level 1 items specifically, WASP already covers directory listing
disabled, TRACE/TRACK blocked, server tokens minimised, `expose_php = Off`,
`allow_url_include = Off`, restrictive file ownership, and a segmented
database. One gap was real and significant.

**`disable_functions` was not set.** PHP could call `system()`, `shell_exec()`,
`exec()` and `proc_open()`. Nearly every off-the-shelf PHP webshell — c99, r57,
WSO and the hundreds of variants dropped through a vulnerable plugin — reaches
for one of those in its first few lines. Blocking them does not stop a
determined attacker writing a bespoke shell, but it breaks the commodity ones
outright, and commodity is what actually lands on a WordPress site. This is
arguably the highest-value single line in the PHP config, and it was missing
while considerably more exotic controls were present.

Now set by default, with `proc_open`, `popen`, `pcntl_exec` and `dl` included
because they are the usual fallbacks once `system()` is gone — leaving them is
most of the way to leaving all of it.

WordPress core needs none of these. Some plugins do: image optimisers that shell
out to `jpegoptim`, backup plugins that call `mysqldump` directly, server-status
plugins. So it is a toggle, `wp-hardening.sh enable|disable php-exec`, in the
menu, with the honest framing that turning it off restores the exact capability
commodity webshells depend on — and the suggestion that a plugin needing shell
access is usually replaceable with one that does the same job in PHP.

**A bug in the toggle, caught before shipping.** The first version ran `sed`
inside the container against `/usr/local/etc/php/conf.d/security.ini`. Two
things wrong: the file is mounted there as `wp-security.ini`, and it is mounted
READ-ONLY. The toggle would have reported success while changing nothing —
the worst kind of security control, one that lies about its own state. It now
edits the host file and restarts the container, verified to round-trip.

---

## 2026.08.12l — Commercial theme installs, and a pre-review sweep

**`wp-plugins.sh install-file <zip>`** — for Divi, Elementor Pro, or a client's
bespoke plugin: anything not in the WordPress.org directory. It takes a LOCAL
file only, never a URL, because `install <slug>` exists precisely so that its
source is always the official directory over TLS and accepting a URL would
collapse that into "download and run anything". Here the trust decision is made
off-box by a human at `scp` time. `--sha256` verifies before installing;
without it the hash is recorded so what was installed can be compared later
against what the vendor shipped. Detects theme vs plugin from the archive, logs
every install, and is in `wasp-menu` → Security.

On the question of committing the .zip to a repository: don't. Divi's PHP is
GPLv2 so redistribution is lawful, but it freezes the theme at one version
while the vendor ships security fixes, adds tens of megabytes to git history
forever, does not save the licensing step (each site still needs its own vendor
API key), and puts a commercial product under your name — the GPL covers code,
not trademarks. All four documented in the code and the README.

**A disclosure bug in that feature, found and fixed before it shipped.** The
first version staged the zip in `wp-content/upgrade/` so wp-cli could reach it.
That directory is inside the web root. Only `wp-content/uploads` is protected
here, and `.zip` is blocked by the 8G ruleset — which is a TOGGLE. On a VM with
8G disabled, a commercial theme or a client's bespoke plugin was downloadable by
anyone who guessed the filename during the install window. Now the file is
mounted read-only into the wp-cli container at `/tmp`, so nothing is ever
written under the docroot.

**And a word-splitting bug in the fix.** The mount argument expands unquoted
(podman needs the flag and value as separate words), so a filename containing a
space or semicolon split into garbage arguments. Not shell injection — nothing
re-evaluates the value — but a broken mount and a baffling error. The path
charset is now constrained.

**A note for external reviewers, because this WILL be flagged.** Several
commands read `-p"$MARIADB_ROOT_PASSWORD"`, which looks like a credential on a
command line. It is not: the string is single-quoted, so the host shell never
expands it — the variable resolves inside the container from that container's
own environment, and the password never touches the host's argv. The obvious
"fix", `podman exec -e MYSQL_PWD=...`, is strictly worse: it puts the credential
in the HOST's argv where any local user can read it from `/proc`. That reasoning
is now recorded at the call site so nobody improves it into a vulnerability.

**Adding that note tripped one of this project's own checks**, which is worth
recording: the comment landed inside a line continuation, which would have
truncated the backup command. `check-line-continuation.py` caught it
immediately. A check written after an earlier bug catching a new one in the act
is the whole argument for writing them.

**Sweep results.** All 17 checks clean. Spelling checked with codespell across
every document and script — the four hits (`covert channel`, `ans`, `iif`,
`pre-emptively`) are all correct as written. No overclaiming introduced, no
world-readable secrets, no leftover TODO/FIXME in shipped code, 79 internal doc
links resolving, all mermaid diagrams balanced.

---

## 2026.08.12k — Page-builder domains are chosen, not shipped

The previous release added nine builder licence domains to the runtime
allowlist. That was backwards, and the operator caught it immediately: this
file is the list of destinations a COMPROMISED WordPress may still reach, so
shipping Elementor's licence server to a site running Divi is pure surface for
no benefit. Nine entries, eight of them useless on any given site.

They are now selected at install. The prompt only appears when the egress proxy
is enabled — without it the allowlist is not enforcing anything and the
question has no consequence — and it says plainly to pick only what the site
will actually run, with the reason: each entry is somewhere a compromised
WordPress may reach.

The shipped allowlist is back to ten entries, all of which every install
genuinely needs. The builder section remains in the file as a comment
explaining why it is empty and how to add one later, so the next person does
not assume it was an oversight.

Selections are validated before they are written: anything containing a scheme,
a path or a space is skipped with a warning, because this file feeds a
`dstdomain` ACL and one malformed line makes Squid reject the entire list —
the failure mode that cost several cycles earlier in this series. The parser
accepts commas or spaces, ignores blanks, and warns on numbers that are not on
the menu.

Also added to the pre-install requirements list, since knowing which builder a
client uses is exactly the kind of thing worth checking before starting rather
than three prompts in.

---

## 2026.08.12j — Theme upload restored, page builders allowlisted, mu-plugins explained

Post-setup feedback from the live site. Three of the four are addressed; the
fourth needs evidence I do not have.

**"I do not see the theme upload section" — that was my change.**
`DISALLOW_FILE_MODS` is set automatically under
`DEPLOYMENT_PROFILE=production` (added two releases ago on an external
evaluation's recommendation), and it removes Plugins → Add New, Appearance →
Themes → Add New, and the upload form entirely. That is the intent — a hijacked
admin session cannot install arbitrary PHP — but it also blocks an operator
uploading a commercial theme, which is a normal thing to need to do. I shipped
the restriction without a way to lift it.

Now a toggle, exactly as requested, alongside the other hardening switches:

    doas wp-hardening.sh disable file-mods    # allow uploads
    doas wp-hardening.sh enable  file-mods    # restore the block

Both are in `wasp-menu` → Security, with the "allow" direction marked
destructive so it asks for confirmation. The disable path states the trade
plainly: while it is off, anyone with an admin session — including a stolen one
— can install arbitrary PHP through the upload form. Turn it back on when the
upload is done.

**Page-builder licence domains are allowlisted.** A paid theme that installs
but cannot reach its licence server never receives updates, which for a page
builder means it silently stops getting security fixes. Verified against each
vendor's own documentation rather than guessed: Elementor activates against
`my.elementor.com` with licence/api subdomains (their docs say to allow
outbound HTTPS to it at the firewall), and Divi validates through Elegant
Themes. Added `.elementor.com` and `.elegantthemes.com` plus seven common
builders, in a clearly-marked section with the instruction to trim it — every
entry is a destination a compromised WordPress may reach, and a builder you do
not run is pure surface.

**The Must-Use Plugins descriptions are rewritten.** WordPress shows only
Plugin Name, Description, Version and Author on that screen; the rest of the
file's documentation is invisible there. Each description now stands alone,
says what the plugin does AND what breaks if the file is deleted, and is
credited to RothITguy. That last part matters more than vanity: an mu-plugin
cannot be deactivated from the UI, so the only way to remove one is to delete
the file, and anyone about to do that should know whether they are switching
off a nicety or locking themselves out. The login-slug description says
outright that deleting it does not restore /wp-login.php — Apache still blocks
that path — so it locks everyone out.

**The block-editor drag-and-drop problem is NOT diagnosed.** I checked the
candidates and ruled out the obvious ones: the standard WordPress rewrite block
is present so `/wp-json/` routes, Apache blocks only CONNECT/DEBUG/MOVE/TRACE/
TRACK so REST writes are allowed, the wp-admin IP restriction covers
admin-ajax but the operator is reaching wp-admin fine, and the MFA REST gate
only applies to unenrolled admins past grace. None of those explains it, and
guessing further would repeat the mistake that cost two cycles on the egress
issue. What would settle it is the browser console output on that page, or
`/wp-json/wp/v2/types` fetched from the VM.

---

## 2026.08.12i — Every suggested command now works when pasted

Reported from a live install. The tool printed a diagnostic to run:

    nft list ruleset | grep -A6 'wp-front egress'

Pasted, it returned `Operation not permitted (you must be root)`. Root SSH is
disabled on this platform by design, so an admin is NEVER root and every
root-requiring command needs `doas`. A suggestion that fails on paste is a
small betrayal of trust in every other suggestion the tool makes, and it lands
at the worst moment — when someone is following instructions precisely because
something has already gone wrong.

**32 commands across 9 files were missing it**, including the diagnostics
printed by `update.sh` when a container swap fails, the recovery commands in
`wp-db-backup.sh`, and the rollback instructions for WordPress, MariaDB and
CrowdSec.

**The compound case was worse than the simple one.** Five lines read like:

    doas podman rename wordpress-old wordpress && podman start wordpress

That half-works. The rename succeeds, the start fails with a permission error,
and the operator is left in a state neither they nor the message anticipated —
mid-rollback, with a renamed container and nothing running. Every segment of a
chain is now prefixed, not just the first.

**New check: `check-doas-prefix.py`.** It flags any root-requiring binary
suggested to the operator without `doas`, including after `&&`, `;` and `||`.
Getting it precise took two rounds of false positives, both worth recording:
a conditional that RUNS a command (`ask_yn "..." && { apk update; }`) is not a
suggestion, and neither is a crontab line being written for root. Both are now
regression fixtures. Verified retroactively — restoring the exact `nft` line
from the report makes it fail.

---

## 2026.08.12h — Five installer-UX corrections from operator notes

All five written down while sitting through a real install, which is the only
place most of these are visible.

**A requirements list before the first prompt.** You could get several prompts
deep before discovering you needed an account you did not have. The banner now
lists what is required, what is optional with the URL to get it, and the honest
note that every optional item can be added later but each one skipped is a
control not running. Plus a time estimate.

**The site-title prompt is gone.** It claimed to save retyping in the browser
wizard. Nothing ever applied it — WordPress asked again anyway, so it was pure
duplicate typing. The reported question was "what is the point if I have to
retype that during WordPress setup?", and there was no good answer.

**The admin-email prompt was mislabeled, not redundant.** It is not the
WordPress admin email; it is where THE VM sends its own alerts — backup
failures, malware findings, the heartbeat — and it must work when WordPress is
down, which is why it is host-side. For an MSP it is usually the operator's
address, not the client's. Relabeled and explained, since the confusion was
caused by the wording rather than the prompt existing.

**The two CrowdSec values now cross-reference each other.** The enrolment key
and the CTI key are ~380 lines apart in the prompt flow, which meant opening
the same console twice. Moving them risked breaking the flow; instead the first
prompt now says a second CrowdSec value is coming, names both console paths,
and says to copy both now. The second confirms it is the one that was
mentioned.

**The CTI quota figure was wrong, and CrowdSec's own docs are why.** The
installer said Community = 40/month. The operator's free Community account
reports 120. Checking: CrowdSec's CTI API Keys page says "Community Plan Free
Key - 40 / month", while their Premium Upgrade page lists "Community: 120 calls
/month". Both are CrowdSec's own current documentation and they contradict each
other. Default changed to 120, and the prompt now says plainly not to trust any
figure including this installer's — read it from the console, which is
authoritative for your account. It also explains why the number matters: the
budget is what stops enrichment burning a month's quota in one busy day.

**Wordfence 'both' — the reason it "kills it" is rate limiting.** Wordfence
limits by REQUEST, not bytes, so asking for two feeds in one run can get the
second refused with a 429. That was already mitigated (skip production when
scanner was refused; 60s gap otherwise), but the prompt sold 'both' as having
"no blind spot" without mentioning the cost. It now states the rate-limit
behaviour, recommends staying on scanner, and is numbered rather than requiring
a typed word.

---

## 2026.08.12g — MFA works on real hardware, and the Squid parse output is clean

**The chain closed.** On the live VM, with CONNECT added to the method
allowlist:

    Installing Two Factor (0.16.0)
    Downloading installation package from https://downloads.wordpress.org/...
    Plugin installed successfully.
    ✔  Installed two-factor
    ✔  Activated (verified)

HTTPS through the egress proxy works, the download completes, and the plugin is
active. `Activated (verified)` is the check added earlier reading the end state
rather than trusting an exit code — the second run correctly reported
`ℹ Already installed. ✔ Activated (verified)`, which is the idempotent path
working too.

That is admin MFA proven on hardware for the first time, after four releases of
chasing symptoms that all traced back to one missing word in an ACL.

**The parse output is now clean, which matters more than it sounds.** The
production fail-closed check runs `squid -k parse`, and that output carried two
warnings and an error on every single run:

- `ERROR: Directive 'dns_v4_first' is obsolete` — Squid 6 removed it. Deleted.
- `WARNING: empty ACL` for `threat-deny.txt` and `allowlist-maintenance.txt`,
  both legitimately empty on a fresh install. Seeded with
  `wasp-placeholder.invalid` (RFC 2606 reserved, can never resolve).
- `WARNING: HTTP requires the use of Via` — correct, and deliberate. `via off`
  stops Squid advertising itself to anything probing the egress path. Now
  documented in the config so nobody "fixes" it.

A config whose normal state is three complaints is a config where the fourth
one goes unnoticed. The CONNECT bug was found by reading Squid's log; that only
worked because someone was looking hard.

**Also fixed:** `podman restart squid` ended in SIGKILL every time, because
Squid's default `shutdown_lifetime` is 30 seconds and podman's stop timeout is
10. Nothing was corrupted, but SIGKILL can truncate the access log mid-line —
and the access log is what diagnosed this whole chain. Now
`shutdown_lifetime 5 seconds`.

**A bug caught before shipping:** seeding the maintenance allowlist would have
broken maintenance-mode detection, which tests for "any non-comment line" and
would have seen the placeholder and reported every VM as permanently in a
maintenance window. The detection, the expiry path and the status display now
all filter the placeholder explicitly. Both cases tested.

---

## 2026.08.12f — The actual root cause: Squid's method allowlist omitted CONNECT

The DNS fix in the previous release worked, and by working it exposed the real
problem. Squid's own access log, which the operator surfaced, named it exactly:

    TCP_DENIED/403 api.wordpress.org:443

`TCP_DENIED/403` means Squid RESOLVED the name and then refused it by policy —
so DNS was fixed, and something in the ACL chain was denying it.

**`acl allowed_methods method GET POST HEAD OPTIONS PUT` did not include
CONNECT.** Every HTTPS request through a forward proxy is a CONNECT. The
`http_access deny !allowed_methods` line sits at the top of the chain, so ALL
TLS traffic was denied there — long before the destination allowlist 60 lines
below was ever consulted. `.wordpress.org` being allowlisted was irrelevant;
nothing HTTPS ever got that far.

This single line explains the entire chain of symptoms across four releases:

  * the plugin install failing with "something may be wrong with WordPress.org"
  * `api.wordpress.org` appearing blocked despite being allowlisted
  * every deny-probe in the egress self-test "passing" — everything was denied
  * MFA never activating, because the plugin could never be fetched

CONNECT is not thereby unrestricted: `http_access deny CONNECT !SSL_ports`
immediately below confines it to port 443, which is the control that actually
matters — it prevents CONNECT being used to tunnel to arbitrary ports.

**`check-squid-acl.py` now catches this.** It parses method ACLs and their
`deny !acl` lines and fails if CONNECT is missing, because that configuration
is always wrong for a forward proxy and always silent. Verified retroactively:
restoring the original line makes it fail with the exact diagnosis.

**Also fixed, and it is my bug twice over:** the egress probe reported "no
response" while Squid's log showed a clean 403. PHP's `http://` stream wrapper
cannot perform a CONNECT tunnel, so probing an `https://` URL through a proxy
returns nothing regardless of policy. The probe now uses `http://`, which
traverses the same ACL chain (source, method, destination) — the thing under
test. That is the third time this probe has misreported, each time for a
different reason, and each time it sent the investigation somewhere useless.

---

## 2026.08.12e — MFA root cause: Squid could not resolve anything

Setup had been completed, a theme installed, and `wp-plugins.sh install
two-factor --activate` still failed. The output settled it:

    Warning: two-factor: An unexpected error occurred. Something may be wrong
    with WordPress.org or this server's configuration.
    Warning: The 'two-factor' plugin could not be found.

That is WordPress's own message, rendered through wp-cli — so wp-cli was
talking to a working WordPress, WordPress had its `WP_PROXY_HOST` constants,
and the request still could not complete. Independent confirmation that the
earlier egress failure was REAL and not the curl artifact of the previous
release.

**Squid had no working way to resolve names.** It inherited the container's
`/etc/resolv.conf`, which points at the podman gateway where aardvark-dns
listens. Aardvark resolves CONTAINER names; forwarding external names onward
depends on it being configured with upstreams and working. That link failed —
and the failure mode is genuinely nasty, because a proxy that cannot resolve
anything produces the exact same symptom as a proxy denying everything:

  * `api.wordpress.org` looked blocked by policy
  * every deny-probe "passed", because those also fail when nothing resolves
  * the egress self-test concluded "the boundary is NOT holding"
  * the plugin install blamed WordPress.org

All four of those were the same missing DNS answer wearing different clothes.
It also explains why the previous release's diagnosis stalled: I attributed the
whole thing to a missing `curl` binary, which was a real bug in the test but
not the reason the plugin failed.

**Fixed by naming the resolvers instead of inheriting them.** `squid.conf` now
carries `dns_nameservers`, substituted at provision with the servers the
operator chose at install (Quad9 by default), and the firewall opens
`10.89.10.2 → <each configured resolver>:53` — the specific addresses, not DNS
generally, so the tunnel this project deliberately closed stays closed. If the
placeholder is ever left unsubstituted, the install warns rather than shipping
a Squid that silently resolves nothing.

**Also fixed:** `update.sh status` reported "Digest pinning: enabled — 4/3
currently pinned". The denominator was hardcoded to three before Squid joined
the digest model. Arithmetic like that makes a reader distrust every other
number in the box.

---

## 2026.08.12d — Two false alarms, both in checks I added yesterday

The install completed and the fail-closed gate behaved correctly. Of the four
commission failures, **two were bugs in checks added in the last two releases**
— my own tooling reporting problems that did not exist. That is the failure
mode I have warned about repeatedly in this log, and it happened anyway.

**The core-version check read `1.2.0` and declared a mismatch.** WordPress's
`wp-includes/version.php` opens with a docblock containing `@since 1.2.0`
before it reaches `$wp_version = '7.0.3';`. My grep took the first
version-shaped string in the file. So a correctly-updated 7.0.3 site was
reported as serving 1.2.0 and failing validation — the exact opposite of the
bug the check was written to catch, and worse, because it would train an
operator to ignore a real mismatch. Now parses the `$wp_version` assignment
specifically, verified against a real version.php.

**The egress probe used `curl`, which is not in the WordPress image.** That
image is minimal — the same log says `(no netstat/ss in image)`. With curl
absent, `podman exec wordpress curl ...` produces nothing, the status comes
back empty, and the test reported `HTTP 000 — nothing answered` and
"The boundary is NOT holding" for a firewall that was working correctly.
(The `000000` in the output was a second bug in the same line: curl's
`%{http_code}` already prints `000` on failure, and my `|| echo 000` fallback
appended another.)

Replaced with a PHP probe. PHP is guaranteed present, and it is the better
test: it exercises the exact runtime and proxy path WordPress itself uses, so
a pass means the thing that matters works rather than that some tool in the
container could reach the internet.

**Not a bug: `podman logs squid` returning "no such container".** The
containers are rootful; that command was run without `doas`, so rootless
podman correctly reported an empty namespace. Squid was up throughout — the
same log shows `squid  Up 11 minutes` and a parsed policy.

The lesson is one this project keeps relearning from the other direction: a
check that fires wrongly is not a harmless false positive. It sends an
operator to investigate a working control during the week they are trying to
ship, and it erodes the trust that makes the checks useful at all. Both of
these shipped because they were verified against the CODE and not against a
real container.

---

## 2026.08.12c — `update.sh wp` never actually updated WordPress

Asked whether 7.0.3 could be digest-pinned or whether a patch was needed. The
answer to the first is yes and always was — the installer resolves the tag to a
digest with Skopeo at install time, so nothing needs hardcoding. Checking the
second uncovered something much worse.

**The official WordPress image copies core into the docroot ONLY when that
directory is empty.** On every later run it deliberately leaves it alone,
because it cannot know what you have changed there. This is documented upstream
behaviour, not a bug in the image.

WASP bind-mounts the docroot. So on any existing VM, `update.sh wp` pulled a new
digest, CVE-scanned it, booted a validation candidate, cut production over,
wrote pinned.env, printed a tick — and the site carried on serving **the
WordPress version extracted on first boot**. The image moved. WordPress did not.

The consequence is that this platform's central patching claim was false for
core, which is precisely where the CVEs that matter live. A VM would report
itself pinned to 7.0.3 while serving 7.0.2 and its pre-auth login-page XSS
(CVE-2026-64638, CVSS 8.9). Nothing anywhere would have contradicted that: the
tag was right, the digest was right, the scan was clean, and the version being
served was wrong.

**Fixed three ways.**

- `update.sh wp` now syncs core out of `/usr/src/wordpress` **inside the new
  image** after the cutover, excluding `wp-content` so themes, plugins, uploads
  and the mu-plugins survive. Taking the files from the verified image rather
  than downloading them from wordpress.org keeps the digest guarantee intact:
  what runs is what was scanned. It reports the before → after version, and
  applies any schema migration via wp-cli.
- `wp-plugins.sh core-version` reads the version out of `wp-includes/version.php`
  — the files actually being served — and compares it to the pinned tag,
  reporting a mismatch explicitly. Also on the Testing menu.
- `validate-wordpress.sh` now FAILS on that mismatch, with the honest wording:
  the site is serving the older version, so any CVE fixed in the newer release
  is still exploitable here.

The failure path matters too: if the sync cannot run, it says so on stderr and
tells the operator to verify by reading `version.php` rather than trusting the
tag. A silent partial update is what caused this.

This is the most consequential defect found in the whole series. Every other bug
broke something visibly. This one made a vulnerable system look patched.

---

## 2026.08.12b — Pre-production sweep: a live CVE on the login page, and missing credits

A full pass ahead of production: syntax, every bug class from this series, CVEs
on the shipped stack, documentation accuracy, and attribution.

**SECURITY — WordPress 7.0.2 was shipping with a known login-page CVE.**
WordPress 7.0.3 was released 2026-08-06 fixing 12 vulnerabilities, the most
serious being **CVE-2026-64638** (CVSS 8.9): a *pre-authentication reflected
XSS on the login page*, requiring no attacker privileges, which can lead to PHP
code execution via the plugin/theme editor if an administrator is phished into
clicking a crafted link.

That is precisely the surface this entire platform is built around. The custom
login slug, the wp-admin IP restriction and DISALLOW_FILE_MODS all reduce the
exposure — none of them is the fix. Updated to 7.0.3 everywhere.

Context that belongs in the record: the PREVIOUS core chain (CVE-2026-60137 /
CVE-2026-63030, fixed in 7.0.2) entered CISA's Known Exploited Vulnerabilities
catalog, with exploitation attempts observed roughly 90 minutes after
disclosure. WordPress core CVEs are weaponised in hours now. That is the
argument for running `update.sh check` weekly rather than quarterly, and it is
worth telling clients.

MariaDB `11.4`, CrowdSec `v1.7.8` and Canonical's Squid were checked and are
current; the June MariaDB Galera CVEs remain inapplicable (single-node).

**Missing attribution — fixed.** The 8G Firewall by **Jeff Starr**
(Perishable Press) is embedded verbatim in this repository and carried only a
URL, with no author credit. That is the one third-party *source* WASP ships
rather than downloads, and it was the least credited. Added inline where anyone
reading the generated `.htaccess` will see it, plus a new `NOTICE.md` crediting
every component, feed and service with its licence — container images, base
system, security tooling, crypto, mail, the Two Factor plugin, and the data
feeds including the attribution Wordfence's terms require when their data is
displayed. Linked from the README.

**Clean across the board.** All eight bug classes from this series verified
clean by their own checks; dash/bash syntax verified on every file with the
bash-only host scripts correctly separated from the dash-only payload; no
call-before-define; `rm -rf` targets all rooted in literal constants; no stale
version claims outside frozen CHANGELOG history; 18 tools documented, 56 menu
entries real, 78 doc links resolving.

---

## 2026.08.12a — Every alert path was dead. Reported from the terminal, missed by me.

Spotted by the operator in their own session output, in a line I had read past:

    testpress:~$ doas wp-db-backup.sh
    /usr/local/bin/wp-notify.sh: line 269: STATE: parameter not set

This is the most serious defect found in this series, and it is not close.

**`STATE` was referenced in six places in `wp-notify.sh` and assigned in none.**
Under `set -u` that is fatal, not a warning, so the notifier exited before
sending anything. Everything that alerts goes through it:

  * the backup-FAILED email — the alert this platform argues most strongly for,
    on the grounds that "a backup that has been failing silently for months is
    the single most common way people discover they have no backups"
  * malware scan findings
  * vulnerability scan findings
  * the heartbeat, which is the only mechanism that detects the VM being GONE
  * update and hardening alerts

A monitoring system that cannot report is worse than not having one, because
its silence is indistinguishable from all-clear. This platform had exactly that,
and it would have looked healthy right up until someone needed a backup.

Fixed: `STATE` defaults to `/var/lib/wasp-notify`, created 0700 at startup.

**This was the THIRD instance of the same bug in the same file.** The comments
above the fix record the previous two verbatim — `SECRETS_DIR: parameter not
set`, then `NOTIFY_COOLDOWN_HOURS: parameter not set`. Three times is not bad
luck, it is a missing check.

**New check: `check-setu-unset.py`.** For every script that sets `-u`, it
collects the ALL-CAPS variables referenced and the ones assigned, and reports
any reference with no assignment and no `${X:-default}`. All three historical
instances would have been caught. Verified retroactively: removing the new
`STATE=` line makes it fail naming the file and variable.

Building it took two rounds of false positives, both worth recording because
they are the reason the check is trustworthy rather than noise:

  * `$MARIADB_ROOT_PASSWORD` inside `podman exec sh -c '...'` is expanded by
    the CONTAINER, not the host shell, so single-quoted spans had to be
    excluded — six false positives on the first run.
  * Stripping those spans file-wide desynchronised on a stray apostrophe in a
    trailing comment ("don't"), leaving two real container commands looking
    like host references. Quote stripping is now line-scoped so one stray
    quote cannot poison everything after it.

The honest note: I read this log line and did not act on it. The operator did.
Every check in this suite exists because something got through, and the ones
that matter most came from someone looking at real output rather than at the
code.

---

## 2026.08.12 — All four commission failures resolved

The improved diagnostics from the previous release did their job: every failure
this time named itself, and three of the four turned out to be tooling bugs
rather than platform faults. Recorded in the order they matter.

**The egress test was probing a URL that is not a 200, and could not tell a
policy denial from a connection failure.** It requested
`https://api.wordpress.org/` with `curl -sf`. The root of that host does not
return 200, and `-f` makes curl exit nonzero on any 4xx — so an allowlisted,
perfectly reachable host looked blocked. Worse, the probe only asked "did curl
exit zero", which cannot distinguish *Squid refused this* from *Squid could not
resolve it* from *nothing answered at all*, and those need completely different
fixes.

It now captures the HTTP status and classifies: 2xx/3xx allow; **403** refused
by policy; **407** proxy auth misconfigured; **503** Squid reached but could not
resolve or connect; **000** nothing answered. On a mismatch it prints which of
those it was and what to check. The allow probe now uses
`api.wordpress.org/core/version-check/1.7/` — the endpoint WordPress itself
calls, which returns 200.

Worth stating plainly, because it was buried under a red line: **the boundary
was holding the whole time.** Every deny probe passed — not-allowlisted hosts,
cloud metadata, bare IP literals, and CONNECT to a non-443 port were all
refused. The single failure was a broken test, and it cascaded into the MFA
failure behind it.

**Backup tooling did not auto-elevate, and failed silently.** Running
`wp-db-backup.sh` as the admin user printed
`install: can't create directory '/root/wp-db-backups': Permission denied` —
blaming the filesystem for a privilege problem. Every other operator tool in
the suite already auto-elevates via doas; this one, `wasp-testreport.sh` and
`wp-geoip-setup.sh` did not. Added to all three.

Separately, the failure path emailed and syslogged but printed **nothing to the
terminal**, so an operator running it by hand got silence and exit 1. It now
prints mariadb-dump's actual stderr plus the three things worth checking, in
the order worth checking them. And `wasp-selftest.sh` no longer runs the backup
under `>/dev/null 2>&1` — that suppression is why "a backup could not be taken"
was all anyone saw.

**`validate-wordpress.sh --check` is working.** Its `FAIL (exit 2)` this run was
not a bug: it correctly reported `CRITICAL - no-backup PRODUCTION-BLOCKER`, both
of which were true. The fix from the previous release landed.

**The MFA failure was downstream of the egress test's own bug.** With
api.wordpress.org genuinely reachable, the deferred installer should now
succeed once WordPress setup is completed. A `MFA / Two Factor status` entry was
added to the Testing menu so this can be confirmed without remembering a log
path.

---

## 2026.08.11k — First commission check: 4 pass, 4 fail, and two were mine

The install completed, the fail-closed gate refused to certify with a stated
reason, and the commission check ran for the first time. That is the whole
design working. Then it found four failures, two of which were my own bugs and
one of which was a design impossibility that three previous "fixes" had been
chasing.

**`validate-wordpress.sh --check` was rejected by its own argument parser.** The
option loop hit `--check`, fell through to the default arm, printed
"Unknown option" and exited 2 — while the handler for it sat unreachable
twenty lines below, testing a `$1` the loop had already shifted away. So the
machine-readable health path, the menu's first health entry, and any external
monitor polling it were all broken, and nothing noticed because no test ever
invoked the flag. Now intercepted before the loop, with `--prom` carried
through a captured variable rather than a `$2` that no longer exists. All four
invocation paths tested.

**The Two Factor install could never have worked at provision time.** The error
changed from "plugin could not be found" to the honest one:

    Error: The site you have requested is not installed.
    Run `wp core install` to create database tables.

WordPress core is not installed during provisioning — this platform
deliberately leaves the setup wizard to the operator (STEP 1 of the completion
banner). You cannot install a plugin into a WordPress that has no database
tables. The previous two attempts moved this between stages on the theory that
it was an egress problem; that diagnosis was partly right and the fix stands
(Squid is up and reachable now, and the error changed *because* of it), but the
remaining blocker was ordering that no stage can satisfy.

Now deferred: a boot-time hook checks every ten minutes whether setup has been
completed, installs and activates Two Factor the moment it has, clears its own
production blocker, and disables itself. The operator finishes the wizard they
already had to finish, and 2FA is ready before their first login. `wp-plugins.sh`
gained an `is-site-installed` predicate for it, and its install probe now
distinguishes "setup not finished" from "cannot reach WordPress" — telling
someone to check egress when the real answer is "run the setup wizard" costs an
afternoon.

**The commission check hid the evidence it existed to surface.** It tailed six
lines, which for two of the four failures was pure summary boilerplate
("Result: FAILED — 1 issue(s)") while the line naming the actual failing probe
scrolled past above it. It now greps for failure markers, filters out the
summary lines, and keeps the complete output at
`/var/log/wasp-commission-<tool>.log`. A diagnostic that truncates away the
diagnosis is worse than no diagnostic, because it looks like it did its job.

**Two failures remain undiagnosed and I will not guess at them.** The egress
boundary test reports "The boundary is NOT holding", and `wasp-selftest.sh all`
reports 17 passed / 1 failed — both truncated to summary lines by the bug
above. The egress one matters most: it means the firewall may not be enforcing
the destination restriction and only WordPress's own proxy settings are, which
is exactly the gap the control exists to close. Both need their full output,
which the next run will now produce.

---

## 2026.08.11j — Install completes; the last failure was egress, not the plugin

A milestone worth stating plainly: **the install ran to completion.** Every tool
installed, the alias loop found them all, Squid came up with its log directory
owned 13:13 (queried from the image, as intended), the policy parsed, and the
fail-closed design did precisely its job — it refused to certify the VM, named
the reason, left a durable marker, and pointed at the tools to diagnose with,
instead of dying silently mid-build as it did two versions ago.

The one remaining blocker was real, and it was not the plugin.

**wp-cli reported "the 'two-factor' plugin could not be found", which was a
firewall decision wearing a WordPress.org error message.** Two compounding
causes:

- **Stage ordering.** The Two Factor install ran in stage 08. When
  EGRESS_PROXY=1, the nftables rules loaded in stage 06 restrict the WordPress
  network to exactly one destination: Squid at 10.89.10.2:3128. Squid does not
  start until stage 09. So every outbound request in stages 06-08 goes to a
  proxy that is not there yet. Moved to stage 10, after Squid is up and before
  the final validation, so validate-wordpress.sh reports the true end state.
- **wp-cli did not know about the proxy.** WordPress itself has WP_PROXY_HOST
  in wp-config, but wp-cli runs as a separate container process sharing the
  same network namespace, and it had no HTTP_PROXY. Even with Squid running it
  would have connected directly and been dropped — so fixing the ordering alone
  would have produced the same error for a different reason. It now reads
  EGRESS_PROXY from vars.sh and sets HTTP_PROXY/HTTPS_PROXY/NO_PROXY only when
  filtering is actually enabled.

The allowlist was already correct: `.wordpress.org` covers both
`api.wordpress.org` and `downloads.wordpress.org`. Nothing there needed
widening, which is the right outcome — the failure was a path problem, not a
policy one.

**A near-miss worth recording.** The first version of the proxy fix used
`tr -d` with nested shell quotes to strip quotes from the vars.sh value, and
dash rejected it immediately. That is the third appearance of that exact
construct in this project, and it was caught this time only because the syntax
sweep runs three parsers. Replaced with sed, and verified against both quoted
and unquoted values.

---

## 2026.08.11i — A silent `set -e` trap that cost the whole second half of the install

The slug fix worked: the log reports "Login slug mu-plugin installed (login at
/boob)", the dead `-login` suffix is gone from every banner. Then the install
stopped dead, mid-stage-08, with no error at all — and the operator was left
with `validate-wordpress.sh: not found`, `wasp-menu: not found`, no backups and
no stage 10.

**Cause: `_out=$(cmd); _rc=$?` is a trap under `set -e`.** A variable assignment
takes the exit status of its command substitution, so a failing command kills
the script AT THE ASSIGNMENT — and the `_rc=$?` on the same line, plus every bit
of judgement written to use it, never runs. The irony is that this line was
added two versions ago precisely to stop trusting a pipeline's exit status. It
replaced a bug that reported false success with a bug that reported nothing at
all.

The safe form guards the assignment: `_rc=0; _out=$(cmd) || _rc=$?`. Fixed in
all three places it had been introduced (stage 08, wp-plugins.sh,
wp-forensics.sh).

**Two ordering bugs made a single failure catastrophic.**

- The Two Factor plugin install — the one network-dependent operation in the
  stage — ran BEFORE fourteen local `install -m 0755` lines. When the network
  work failed it took every one of them with it. Local, always-succeeds work
  now runs first and anything touching the internet runs last, which is free
  and means a download problem costs one plugin instead of the entire toolset.
- The bare-name alias loop (`for _t in /usr/local/bin/*.sh`) ran near the TOP of
  the stage, when only two tools existed. It created two symlinks and reported
  "Bare-name aliases created", which is why `wasp-menu` was still not found on a
  VM whose log said the aliases were done. A loop over a directory has to run
  after the directory is populated. Moved to the end.

**New check: `check-seterr-capture.py`.** It flags the unguarded
`_out=$(cmd); _rc=$?` form anywhere in the tree, because this one passes
`sh -n`, passes review (it looks like careful error handling), and fails only at
runtime — and then fails silently. Verified retroactively: restoring the
original line makes the check fail naming the file and line number.

Three checks now exist because of failures in this series that were invisible to
every other form of testing: undefined helpers, slug-rewrite divergence, and
now this. Each was written after the bug had already cost a redeploy, which is
the honest pattern — none of them would have been thought of in advance.

---

## 2026.08.11h — The login slug redirect loop: two generators, two answers

Reported from the live VM: `https://test.rothitguy.pro/boob` returned "The page
isn't redirecting properly", and the same URL was 403 from outside the LAN while
never routing on the LAN either. The site itself loaded fine.

**Root cause: the slug rewrite is generated in two places and they disagreed.**

    lib/03-dynamic-configs.sh   ->  wp-security.conf :  ^<slug>/?$  ->  /wp-login.php
    payload/stages/04-...       ->  .htaccess        :  ^<slug>/?$  ->  /wp-admin/index.php

Whichever ruleset won, a request to `/<slug>` reached wp-admin
unauthenticated. WordPress redirected to the login page. The login-slug
mu-plugin, doing its job, rewrote that URL back to `/<slug>`. The browser
looped until it gave up.

Nothing failed. Nothing logged an error. `validate-wordpress.sh` even reported
"Login slug /boob serves the login page (HTTP 302)" — which was true, and was
the first hop of the loop. This is the failure mode where every individual
check passes and the composed system does not work.

**A dead rule made it look handled.** Stage 04 also carried
`^<slug>-login -> /wp-login.php`. That suffix was deliberately removed from the
mu-plugin some time ago (a `-login` suffix made the secret path guessable), so
nothing ever requested it. Reading the block, the login entry point appeared to
be covered; the live rule sent it elsewhere. Two other places still advertised
the dead URL too — the install message ("Login slug mu-plugin installed
(/boob-login)") and the completion banner's STEP 2 login line — so the log told
the operator to visit a URL that had not existed for several versions, while
the URL that did exist looped.

**Fixed:** the bare slug now routes to `/wp-login.php` in both generators, the
dead `-login` rule is gone, and both the install message and the completion
banner print the real login URL.

**New check: `check-slug-rewrites.py`.** It parses the rewrite rules out of both
generators and fails if they map the same slug pattern to different targets, or
if either still references the removed `-login` suffix. Verified retroactively:
restoring the divergence makes it fail with the exact mismatch named; removing
it makes it pass.

The proper fix is one generator feeding both files, and that refactor is worth
doing — it is in TODO. Until then this check makes the duplication safe by
making divergence loud instead of silent, which is the difference between a
five-minute fix and a redeploy cycle spent staring at a browser.

---

## 2026.08.11g — First install with no fatal blocker, and the bugs behind it

The install completed. Squid parsed, CrowdSec ran, stage 10 ran, the operator
menu worked. What the log then showed is a set of failures that only appear once
things get far enough to be exercised — and a fresh external evaluation
independently found the most important one.

**wp-cli was missing `--path`, so every plugin operation silently did nothing.**
`wp-plugins.sh` invoked wp-cli without `--path=/var/www/html`, which
`wp-import.sh` and `wp-rotate-secrets.sh` both had. wp-cli defaulted to a
working directory that is not the docroot, found no WordPress, printed nothing,
and exited 0. The install therefore reported "Two Factor plugin installed and
activated" for an install that never happened, and validate-wordpress.sh later
correctly reported MFA enforced with the plugin inactive. Three fixes: the
`--path`, a reachability probe (`wp core version`) that proves wp-cli can see
WordPress before anything is trusted, and activation confirmed by ASKING
(`plugin is-active`) rather than trusting the exit status of the activate call.
A claim about state should be a reading of state.

**That failure could still certify a production install.** Under production, a
requested MFA that is not actually working now writes a PRODUCTION-BLOCKER
rather than passing quietly — the external evaluation raised the same point
("Final production marker can be written without proving requested MFA is
active"), and it was right.

**Two undefined helpers reached a live VM, and the checker that exists to catch
them reported CLEAN.** `_hdr` broke the remote-restore drill's output and `_wp`
broke `wp-mail.sh test` outright. The checker had two gaps: its command-position
regex only matched calls at column zero, so anything inside a case arm or if
block — which is most calls — was never examined; and its trailing pattern
required the first argument to be quoted, so `_wp eval '...'` slipped through.
Both fixed, with regression fixtures for the indented call, the `$( )` call, and
a false positive it started producing (the English word "pass" inside a message
string). A checker that reports clean while the bug it was written for sits in
the tree is worse than no checker, because it is trusted.

**The restore drill failed on MariaDB auth.** The readiness ping succeeded and
the restore then failed with ERROR 1045 using identical nested quoting; the
difference is that the restore pipes a dump on stdin. Credentials now go through
`MYSQL_PWD` in the container environment instead of `-p` on a command line built
from nested quotes — which removes the quoting from the equation and keeps the
password out of argv as a bonus. The failure path now prints mariadb's actual
first lines and notes that a dump carrying CREATE USER/GRANT statements from the
source system is a plausible cause worth inspecting before blaming the backup.

**A duplicated allow-list display that looked like a config bug.** The validator
printed "192.168.100.0/24 72.208.112.108 192.168.100.0/24 72.208.112.108"
because the same list legitimately appears in two `<Directory>` blocks and the
display concatenated all matches. Deduplicated.

**From the evaluation, three documentation and hardening corrections:**

- The plugin installer called WordPress.org a "signed" directory. It is not.
  WordPress.org serves packages over HTTPS, which authenticates the server; the
  packages carry no signature this VM verifies. Overstating a control is worse
  than lacking it, because it stops anyone looking for the real one.
- README's Known Limitations still said no signed release manifest exists,
  contradicting the section three screens earlier that documents verifying
  against one. Corrected to the true statement: signing exists and production
  refuses unverified installs; a *development checkout* has no manifest to
  verify against. The stale backup limitation was corrected the same way, since
  both restore drills now exist.
- `DISALLOW_FILE_MODS` is now set under production. `DISALLOW_FILE_EDIT` only
  removed the code editor; an administrator — or a hijacked admin session —
  could still install a plugin from wp-admin, which is a far more direct route
  to arbitrary PHP. Verified that WP-CLI is explicitly unaffected by the
  constant (language installs are the sole documented exception), so
  `wp-plugins.sh install` still works: blocked in the UI where a stolen session
  lives, available from the console path that is logged. It also makes the site
  immune to CVE-2024-31210 by that advisory's own text.

Remaining evaluation findings — plugin checksum verification, candidate testing
against cloned data, destination-enforced immutability, cross-control semantic
tests — are real and larger, and go to TODO rather than being rushed.

---

## 2026.08.11f — Six operator-requested prompt fixes from a real install

All six came from notes written while actually sitting through the installer,
which is the only way most of these surface.

**SSH key: tell people how to make one.** The prompt asked for a public key and
assumed you had one. It now gives copy-pasteable ed25519 generation for
Linux/macOS and Windows PowerShell, explains why to name the key
(`-f ~/.ssh/wasp_ed25519`) instead of overwriting the default — a per-host key
can be revoked without breaking every other server you reach — says to set a
passphrase, warns that the file WITHOUT `.pub` must never be pasted anywhere,
and shows the resulting `ssh -i` command.

**"Additional IP for wp-admin?" now says what it is for.** It was a bare prompt
with an example address. It now explains the realistic entries — your own public
IP (with `curl -s ifconfig.me` to find it), a colleague in another office, a
static VPN exit — and notes that anything unlisted gets a 403, so a dynamic home
address is worth thinking about.

**And it accepts several.** The single-IP limit was arbitrary: Apache's
`Require ip` takes a space-separated list natively. Commas or spaces are
accepted and normalised, each address validated individually, and a CIDR entered
here gets a specific message pointing at the CIDR question above rather than a
generic rejection. The install summary shows a count instead of the list when it
would overflow the box.

**A review step for SMTP, because a typo was unrecoverable.** Reported directly:
`contact@rothitguy-pro` was entered instead of `.pro` and there was no way back
short of aborting the installer. The section now ends by showing every field
back with a number; enter a number to re-enter just that field, or press Enter
to accept. Correcting the username offers to update the From address with it,
since they normally track. The password is shown as asterisks and never echoed.
The fast path is unchanged — one Enter accepts. Verified against the exact
reported scenario.

**CrowdSec CTI quota — both numbers are right.** The report said the free key is
120/month, the installer said 40. Checking CrowdSec's documentation: a Community
plan's free key is 40/month and a Premium plan's *included* free key is 120. The
prompt now states both tiers, notes that paid keys start at 5,000 and that
unused quota does not roll over, and still asks rather than assuming.

**Deployment profile is numbered.** It required typing "standard" or
"production". Now `1` or `2`, with the consequence of each on the line; the words
still work for anyone with the muscle memory.

Note on the "back button" more generally: a true undo across a linear shell
prompt flow would mean restructuring every question into an indexed state
machine, which is a large change with real risk of its own. The review-step
pattern gets the actual benefit — recovering from a typo without losing the
whole run — in the one section with the most fields and the most typo-prone
ones. If other sections turn out to hurt the same way, the pattern is now there
to copy.

---

## 2026.08.11e — DNS resolver choice: Quad9 by default, and Cloudflare/Google dropped

Acting on an operator recommendation. The static-network prompt defaulted to
`1.1.1.1 8.8.8.8` -- fast, reliable, and the wrong default for this product.
Both are US Five-Eyes operators whose business is not DNS, and on a VM built to
minimise what leaks, every domain it ever resolves is precisely the metadata
worth not handing over by default.

**The new default is Quad9, and privacy is only half the argument.** Quad9
blocks known-malicious domains using threat intelligence, which on a WordPress
host is a genuine control rather than a nicety: a compromised plugin phoning
home to a known C2 domain fails at *resolution* -- before Squid, before
nftables, before anything in this stack is consulted. It also does not log
client IPs, validates DNSSEC, is GDPR-compliant, is run by a Swiss non-profit
(outside the Five/Nine/Fourteen Eyes arrangements), and answers from 200+
locations in 90 countries so it performs acceptably wherever the Proxmox host
sits.

The prompt is now a menu grouped by region -- global, Europe, regional -- with
the honest trade-off under each entry, and an option to enter your own.
Cloudflare and Google are not listed; the custom option accepts them and the
installer simply notes the choice rather than arguing.

**Verifying the addresses caught a bug that would have broken installs.** The
recommendation list included Mullvad, which is an excellent resolver and was
duly added to the menu. Checking its addresses before shipping them turned up
Mullvad's own documentation stating that its IPs "can only be used with DNS
resolvers that support DoH or DoT, not with DNS over UDP/53 or TCP/53".
`/etc/resolv.conf` speaks plain DNS and nothing else, so anyone choosing that
option would have got a VM with no working DNS at all -- and the listed
addresses did not match Mullvad's published ones either. Removed, along with
Applied Privacy and Wikimedia DNS for the same reason, with the disqualification
written into the code so nobody helpfully restores them. If a local DoH/DoT stub
resolver is ever added to this VM they become viable and should be revisited.

That check is the same discipline that the container-tag failure earlier in this
series taught: a plausible-looking address from a good source is still an
assumption until something authoritative confirms it.

---

## 2026.08.11d — The Squid blocker, actually identified: an overlapping ACL entry

The diagnostic capture added in the previous release did its job on the first
try, and it proved the previous release's hypothesis WRONG. That is the entry
worth writing down.

**The real cause.** Squid's own log named it exactly:

    ERROR: 'registry-1.docker.io' is a subdomain of '.docker.io'
    ERROR: You need to remove 'registry-1.docker.io' from the ACL 'runtime_allow'
    FATAL: Bungled /etc/squid/squid.conf line 102: acl runtime_allow dstdomain

`allowlist-runtime.txt` listed `.docker.io` and also `registry-1.docker.io` and
`auth.docker.io`. Squid stores dstdomain ACLs in a splay tree and refuses to
build one containing both a leading-dot parent and a subdomain of it — FATAL,
not a warning. The list read as careful and thorough to every human who looked
at it, including through several reviews.

**The cache_dir theory was wrong, and the comment saying otherwise is
corrected.** The previous release removed `cache_dir null /tmp` reasoning that
Debian/Ubuntu's squid lacks the null storeio module. Plausible, and wrong. The
removal is kept on its own merits — `cache deny all` above it already means
nothing is cached — but it is now labelled as what it is rather than as a fix
for something it did not fix. A comment that claims a false fix is how the next
person loses a day.

**A silent security regression found in the same output.** The IP deny list
listed `169.254.169.254/32` and `169.254.170.2/32` alongside `169.254.0.0/16`.
Squid warns about that, and the second line of the warning is the important one:

    WARNING: because of this '169.254.0.0/16' is ignored to keep splay tree
             searching predictable

Squid DISCARDS the broader range. Listing the specific cloud-metadata addresses
meant the rest of link-local was no longer denied by that ACL at all — being
more specific had made the control weaker, and nothing failed to say so. The
/16 alone is correct and covers every metadata endpoint in that range.

**New check: `check-squid-acl.py`.** Both failures are now caught statically
before an install: subdomain-inside-parent in dstdomain lists (fatal), and
CIDR-inside-CIDR in IP lists (silently weakening). Self-tests against the exact
two real cases plus a clean fixture. Verified retroactively — re-adding
`registry-1.docker.io` makes it fail.

**The diagnostic capture itself was improved by watching it work.**
`squid -k parse` needs a running container, and a squid with a bad policy has
already exited, so that half returned only "can only start exec sessions when
their container is running". The container's own log carried the real answer.
The log is now read first and printed first; exec output is the optional extra.

Three hardware runs, and the shape has not changed once: every bug has been a
disagreement between the code and something outside it — a registry's tag list,
a base image's uid, a shell's name resolution, and now a proxy's opinion about
what counts as a duplicate. The checks that keep catching these are the ones
that model the outside thing, and each was written only after it had already
cost a redeploy.

---

## 2026.08.11c — The in-VM log: the Squid blocker identified, and wp-cli was never working

The missing in-VM log confirmed the previous round of fixes landed: WordPress
pulled at 7.0.2 and went healthy, all four images digest-pinned via Skopeo,
MariaDB started with no spurious red, and MFA reported **active** through the
deferred verification. It also showed exactly where the install stopped, and
surfaced a class of bug that had been failing silently since it was written.

**The Squid parse failure: `cache_dir null /tmp`.** The `null` store type
requires squid to be built with the null storeio module. Alpine's build has it;
Debian/Ubuntu's typically does not (ufs, aufs, diskd, rock). When the container
was switched from `alpine + apk add squid` to Canonical's `ubuntu/squid`, that
line silently became a parse-time fatal, so squid started, rejected its own
policy, and crash-looped. The line was also redundant -- `cache deny all`
directly above it already means nothing is ever cached. Removed; squid is now
memory-only, which is what a filtering forward proxy wants and which parses on
every build.

**Squid failures now capture their own diagnosis.** The old check reported that
the policy was rejected and nothing else, which cost a full redeploy to learn
anything. It now captures the parser output, the container log, the container
state and the log-directory ownership to /var/log/wasp-squid-parse.log, and
prints the error lines inline. A fail-closed control that cannot say WHY is only
half a control.

**wp-cli has never worked.** Two separate bugs, both invisible:

- The wrapper ran `podman run … wordpress:cli plugin install two-factor`. That
  image's entrypoint execs its arguments directly unless the first starts with a
  dash, so it tried to exec a program called `plugin` and died with "plugin: not
  found". The explicit `wp` was missing. Every call site suppresses stderr and
  falls back to a friendly message, so this looked like nothing.
- Three tools and the support runbook used `podman exec wordpress wp …`. The
  official `wordpress:*-apache` image does not contain a `wp` binary at all --
  wp-cli is a separate image, which is why wp-plugins.sh has WPCLI_IMAGE. So
  `wp-import.sh`, `wp-rotate-secrets.sh` and the validate two-factor check were
  all calling a binary that was never there. Worst of these: the MFA console
  recovery procedure in SUPPORT-RUNBOOK.md, which would have failed at exactly
  the moment someone was locked out of their own site. All routed through the
  wp-cli container now.

**A false success report.** `if _wp plugin install "$_slug" 2>&1 | sed …` tests
SED's exit status, which is always 0. The install printed "✔ Installed
two-factor" on the line immediately after wp-cli had failed. Output is now
captured, the real exit status judged, then printed.

**The production digest gate did not cover Squid.** The count was hardcoded to
three, so an install that pinned four images reported "3/3 pinned". Not
cosmetic: this gate is fail-closed under production, so a Squid digest that fell
back to tag-only would have passed silently -- the egress proxy sat outside the
very guarantee the gate exists to enforce. Now counted, with the denominator
following whether egress is enabled.

Standing caveat, unchanged: `cache_dir` is a strong, specific hypothesis for the
parse failure, and the new diagnostic capture is what will confirm or refute it
on the next run. That is the honest state -- the fix is reasoned from how the
two squid builds differ, not yet from an error message that named it.

---

## 2026.08.11b — Second hardware run: the tag fix worked, three more bugs behind it

The install got much further. WordPress pulled and started
(`wordpress-geoip:7.0.2-php8.4-apache`), MariaDB and Squid both came up
digest-pinned, the operator menu ran and reported the right build. The preflight
tag check and the two corrected tags did their job. Then three more real bugs.

**Squid crash-looped because of a leftover uid from the image swap.** The log
directory was chowned to `100:101` — Alpine's squid user, from when this
container was `alpine + apk add squid`. Canonical's `ubuntu/squid` runs as
`proxy` (13:13), could not create `cache.log`, exited immediately, and
`--restart=always` turned that into a silent loop showing "Up Less than a
second" forever. The ownership is now QUERIED FROM THE IMAGE (`id -u proxy`)
with a fallback, rather than replacing one magic number with another — the
whole reason this bug existed was a hardcoded uid outliving the image it
described.

**Fail-closed aborted mid-install and left the operator with fewer tools.**
Squid's failure tripped the production fail-closed check, which called `err()`
in the middle of stage 09. The install stopped there: CrowdSec never started,
backups were never installed, and stage 10 never ran at all — so
`validate-wordpress.sh`, `wp-hardening.sh` and `wp-malware-scan.sh` were absent
from a VM whose operator now urgently needed them. Refusing to certify a broken
production install is right; aborting the build is not. Fail-closed controls
now call `block_production()`, which records the reason and lets the install
FINISH so every diagnostic tool exists, then refuses loudly at the end and
leaves a durable `/etc/wp-install/PRODUCTION-BLOCKERS` marker. `--check` reports
it as CRITICAL and the test report banners it, so a non-certified VM cannot fade
into a green dashboard.

**The test report died mid-run on an undefined helper.** `_p` was called in the
vulnerability-exceptions section; the report's helpers are
`ok/no/sk/inf/hdr/sub/run`. Two more latent instances of the same thing were
found in the UNVERIFIED banner (`warn`, which that file also does not define).

**That class now has a check.** This was its third appearance — `info` in a
stage, `_p` and `warn` in the report. Every one passed `sh -n`, because calling
an undefined command is a RUNTIME error in shell, not a syntax error: the shell
parses `_p "hello"` perfectly and only fails when the line executes. The
existing syntax sweep is structurally incapable of catching it.
`check-undefined-helpers.py` collects what each file defines (plus what stages
inherit from the entrypoint) and flags helper-shaped calls that resolve to
nothing. It keeps a deliberately narrow vocabulary rather than trying to
validate every command, so it stays signal. Verified retroactively:
re-introducing `_p` makes it fail; removing it makes it pass.

The pattern across both hardware runs is consistent. Every bug has been a
disagreement between the code and something outside it — a registry's tag list,
a base image's uid, a shell's runtime name resolution, an operator's fingers.
None were logic errors, and none were catchable by tests that only compare the
code to itself.

---

## 2026.08.11 — First hardware run: five real bugs, one of them fatal

The platform ran on real hardware for the first time. It failed. Everything
below was invisible to a check suite that had been passing for weeks, which is
the point worth recording: the checks proved the code did what the code said,
and the code said the wrong thing.

**FATAL — two container tags that do not exist.** The install died fifteen
minutes in with `manifest unknown` on
`docker.io/wordpress:6.9.6-php8.4-apache`. That tag was set during an earlier
"version audit" by reasoning from the WordPress *release* history: 6.9.6 had
shipped, PHP 8.4 was the supported line, so 6.9.6-php8.4-apache must be the
tag. It never existed. The Docker library builds a specific set of
version+variant combinations and a WordPress release number is not
automatically a Docker tag. Corrected to `7.0.2-php8.4-apache`, verified
against the official-images manifest rather than inferred.

The same mistake had been made for Squid: `ubuntu/squid:6.13-24.04_stable` was
invented from a CVE advisory that mentioned package version 6.13-1ubuntu1.2.
Canonical's actual scheme is `<squid>-<ubuntu>_<channel>` (e.g.
`6.6-24.04_edge`). Squid degraded quietly to an unpinned tag rather than
failing, which is arguably worse — the digest-pinning guarantee was silently
lost. Now `latest`, which is guaranteed to exist; the digest resolved at
install is what actually pins us, so nothing is given up.

**Preflight tag verification added, so this class fails in seconds.** The host
now checks each pinned tag against the registry before creating a VM, and
refuses to continue on a definite 404 with the offending tag named. It only
warns if the registry is unreachable — an install should not be blocked because
Docker Hub is having a bad day. Fifteen minutes of waiting for a site that was
never going to come up is now a two-second error.

**MFA verification ran against a container that did not exist yet.** Stage 06
wrote the enforcement mu-plugin and then verified it with
`podman exec wordpress php -l ...` — but WordPress is pulled and started later
in the same stage. The exec therefore always failed, and every install reported
"MFA mu-plugin failed php -l — NOT enforcing" no matter what. A check whose
failure mode is "always warn" trains people to ignore it, and this one also
silently disabled a working security control. The placeholder check (which
needs no container) stays where it was; the real `php -l` is deferred to after
WordPress is confirmed healthy.

**Tools installed as `*.sh` while every document said the bare name.** The
installer's own prompt says "Verify enforcement after install: wasp-egress
test". The operator typed exactly that and got `wasp-egress: not found`, because
the tool is `wasp-egress.sh`. Rather than rewrite every reference and have the
drift return, stage 08 now creates bare-name symlinks for all fifteen tools, so
both spellings work.

**MariaDB startup printed a wall of red for a database that was fine.** The
readiness loop called `mariadb-health-check.sh`, which is written to be run
against a database that should already be up and so reports every failed
sub-check loudly. During startup that is exactly wrong: two full blocks of
"✗ MariaDB health: ONE OR MORE CRITICAL CHECKS FAILED" scrolled past before the
third poll succeeded. Intermediate polls are now silent, with a progress note
every thirty seconds, and the captured output is shown only if the loop
genuinely runs out of attempts.

**A sixth bug was nearly introduced while fixing the fifth**: the new progress
note called `info`, which is not a defined helper in the payload. Caught by
checking the available helpers instead of assuming, then audited across every
stage for the same class. None found.

The honest lesson: the static suite, the mocks and the logic tests were all
green throughout. They were checking internal consistency, and every one of
these bugs is a disagreement between the code and the outside world — a
registry, a container lifecycle, an operator's fingers. Only running it found
them.

---

## Unreleased — Proofreading pass: two real errors, and a check so links cannot rot

A spelling and grammar pass across every document, done with tooling rather than
by eye — codespell for misspellings, aspell against a project dictionary built
from the codebase, plus scripted checks for doubled words, a/an agreement,
broken anchors and stale editorial markers.

**Spelling and grammar came back essentially clean.** Codespell's only hits were
false positives: `FO` (a Mermaid node ID for wp-forensics), `unparseable` (a
valid alternative spelling), and `pre-empts` (standard hyphenated form). The
aspell pass surfaced ~160 unknown words in the README, all of which proved to be
legitimate technical vocabulary — allowlist, cutover, docroot, rootful, skopeo,
netavark, xmlrpc and the like. `an nftables bouncer` and `apk add clamav
clamav-libunrar` were both flagged and both correct.

**Two real errors, neither of them spelling:**

- **ARCHITECTURE.md claimed "Eight views" and enumerated eight** — but a ninth
  section (the login path, added with the MFA work) had since been written. The
  intro now describes the eight diagrams accurately and notes that the ninth
  section is prose, because that layer is a sequence of decisions rather than a
  shape.
- **A broken table-of-contents link in README.md.** Renaming "Outbound Firewall
  (optional)" to "...(optional, host-service layer)" while resolving the egress
  documentation contradiction left the TOC entry pointing at the old anchor. The
  cross-reference added at the same time was correct; the TOC was not.

**An editorial wart removed.** A paragraph in the README was still labelled
"*(Superseded note:)*" and duplicated both the surrounding argument and its
install command. The one genuinely additional point (the signature database is
close to a gigabyte resident, which matters on a 4 GB VM) is folded into the
prose; the redundancy is gone.

**New check: `check-doc-links.py`.** A renamed heading silently breaks every
link to it — the markdown stays valid, the page still renders, and the failure
is discovered by a reader clicking a table-of-contents entry. Getting the anchor
rule right was the whole difficulty: a naive implementation false-positives on
every heading containing `&` or an em-dash, which would make the check noise and
get it ignored. It implements GitHub's actual rule (strip the character, keep
its surrounding spaces, spaces become hyphens — so "Malware & Integrity
Scanning" is `malware--integrity-scanning` with a double hyphen), and its
self-test asserts both that a real break is caught and that the tricky cases are
not flagged. Verified retroactively: re-introducing the TOC bug makes the check
fail, and removing it makes it pass. 77 internal links across 11 files currently
resolve.

---

## Unreleased — Menu review: a Testing section, and a check so entries cannot rot

A review pass over the menu, plus the improvement that matters most for the
stage this project is at: making validation easy to run.

**New: Testing & validation section, with a guided commission check.** Testing
capability was scattered across six menu sections, but validating a deployment
is its own task. The new section gathers all of it — health, full validation,
the self-tests, egress enforcement, tooling integrity, CVE scan, mail and wp-cli
reachability, and the offsite restore drill — and its first entry runs the
read-only ones as one sequence.

The commission check has three deliberate properties. It **does not stop at the
first failure**: a commissioning pass should tell you everything that is wrong
in one go, not make you fix-and-rerun to discover the next problem. It shows the
failing tool's last output lines inline, so a failure is actionable without
hunting. And when everything passes it **refuses to declare the VM proven** —
it names what is still owed: the offsite restore drill (which needs the recovery
key and so stays deliberate) and, if MFA is enforced, a deliberate admin lockout
to confirm console recovery. Those two are the failures that actually cost a
client their site, so they are called out rather than buried.

**New check: `check-menu-entries.py`.** A menu entry is a promise. One pointing
at a tool that does not exist, or a subcommand a tool does not accept, is
invisible to `sh -n` (syntax is fine) and to a code read (the string looks
plausible) — it surfaces when an operator picks it mid-incident. The check parses
every `run()` call site and verifies the tool exists and its dispatch really
accepts the subcommand, handling the `a|b|c)` alternation forms real dispatchers
use. All 55 entries currently verify clean.

**Its own self-test caught a bug in the checker before the checker was trusted.**
The first matcher only recognised case arms whose line ended in `)`, so a normal
`status) echo hi ;;` arm was missed and a valid entry was reported broken. The
fixture caught it immediately. This is the discipline the project keeps
returning to: a check that cannot fail is not a check, and writing the failing
fixture first is what makes the passing result mean something.

Verified by driving the menu with scripted keystrokes through a pseudo-TTY:
the commission check runs all steps, correctly reports a failing tool with its
exit code and output, continues past it, skips missing tools, and produces an
accurate PASS/FAIL/SKIP tally in both the has-failures and all-clean cases.
Version and version-note confirmed current (2026.08.10) with no stale strings
anywhere in code or docs.

---

## Unreleased — An operator menu: one front door to the tooling

`wasp-menu.sh` — a task-grouped menu over the ~20 operator tools, so no one has
to remember which flag does what. The design question was what KIND of menu
fits, and the environment answered it: pure POSIX shell, zero new packages.

Why not the obvious alternatives. A web GUI would mean a listening service, a
port, auth and TLS — a new attack surface on a VM whose entire purpose is
minimal surface. A whiptail/dialog TUI would add a package to a hardened box for
cosmetics. Neither is worth it. A plain sh menu, by contrast, runs in the
`qm terminal` console where root actually operates and CANNOT paste, works
identically over SSH, needs nothing installed, and degrades to any terminal.

What it does. Groups the tools by the task an operator has in mind — Health,
Backup, Security, Updates, Import, Diagnostics — with each entry showing its
real command. Three deliberate behaviours, chosen for a two-audience tool
(on-shift techs and engineers) without splitting into two programs:

- **Every action prints the exact command before it runs.** The menu doubles as
  a cheat-sheet: a tech learns the command by watching it, an engineer confirms
  nothing surprising happens and can skip the menu next time. Nothing here does
  anything you could not do by typing the command yourself.
- **Arguments are prompted inside the menu** (mail test address, import file
  path, new SMTP password), so the tech does not have to remember argument
  syntax, and a blank entry cancels cleanly rather than running a tool with a
  missing operand.
- **Destructive actions are marked `[!]` and require typing `yes`** — rotate,
  update, restore, purge. Everything else runs on a keystroke.

It launches the tools, it does not reimplement them; if a tool changes, its menu
entry keeps working because it just calls the tool. A top-of-menu health pulse
(`validate-wordpress.sh --check`) shows state before you act, and an `/etc/motd`
line points new operators at it on login. Installed in stage 08 alongside the
other tooling.

**Testing found and fixed two real bugs before this shipped.** First, the banner
read the build version with `tr -d` and nested shell quotes — the exact
quote-nesting anti-pattern the project's own `check-embedded-quotes.py` exists
for — which degraded into an invalid `tr` character range (`range-endpoints of
'p-i' are in reverse collating sequence order`) and blanked the version;
replaced with sed. Second, `run()` invoked tools by bare name, relying on $BIN
being in PATH, which it often is not in a bare console; it now resolves each
tool under $BIN explicitly. Both were caught by actually driving the menu with
scripted keystrokes through a pseudo-TTY and checking that the confirm-yes path
runs, confirm-no skips, non-destructive runs directly, prompted arguments pass
through, and the version displays — not by reading the code and assuming.

---

## Unreleased — Documentation brought current across the whole set

A pass over every document to close the gap between what the code now does and
what the docs described. Version bumped to 2026.08.10 with a note reflecting the
real headline (admin MFA), and the recent feature work threaded through the docs
that should mention it:

- **ARCHITECTURE.md** — MFA added to the login-path diagram as the fifth gate
  (after the login guard, gating every wp-admin request); the Day-2 tooling
  diagram updated with the tools that were missing from it (`wp-rotate-secrets`,
  `wasp-capture`, `remote-restore-drill`, `wp-plugins install`, `update.sh
  squid`); the release-trust-chain node updated to show production refusing an
  unverified install outright; and a new section 9 walking the five login layers
  in prose, with the emphasis that MFA enforcement is built around recovery.
- **INCIDENT-PLAYBOOK.md** — the post-compromise rotation step now includes
  forcing 2FA re-enrolment (a compromise may have captured or added a factor)
  and points at `wp-rotate-secrets.sh` for the infrastructure credentials.
- **MSP-RUNBOOK.md** — onboarding now includes enabling admin MFA and walking
  the client through enrolment plus printed backup codes.
- **SUPPORT-RUNBOOK.md** — already carried the console recovery procedure from
  the MFA work; unchanged this pass beyond that.
- **TODO.md** — two long-standing open items marked addressed: "no secret
  rotation" (now `wp-rotate-secrets.sh`) and "restore never proven end to end"
  (now `remote-restore-drill` — with the honest note that the tool exists but the
  real-hardware *run* is still owed and remains the highest-value action). Added
  an MFA follow-ups subsection (WebAuthn companion, runtime re-verification) as
  optional future work.
- **test/README.md** — added a section distinguishing the two test suites, since
  it previously documented only the integration harness and not
  `run-all-checks.sh` (which now carries the 21-case MFA logic test).

Verified across the set: doc-coverage clean at 17 tools, all 9 mermaid diagrams
balanced, all code fences balanced, and a stale-fact sweep confirms no document
still claims rotation is absent, restore is unproven-by-any-means, or references
the old version. The standing caveat is unchanged and stated in the docs that
matter: the platform is validated by the check suite and by construction, not
yet by a real-hardware run.

---

## Unreleased — MFA review pass: three real bugs found and fixed

A second read of the MFA work with fresh eyes, looking specifically for what a
mocked logic test cannot see — real WordPress hook timing and plugin internals.
Three genuine bugs surfaced, each of which would have either let an admin bypass
enforcement or locked one out, and all three passed the original checks.

**Bug 1 — enforcement only fired at the login moment.** The original design
gated on `wp_login` only, which has two holes: an admin already logged in when
enforcement is switched on never fires `wp_login` again until their cookie
expires (up to 14 days unprotected), and `wp_clear_auth_cookie()` at `wp_login`
races the auth cookie the login flow already queued in the same response — it
usually wins on header order, but "usually" is not a control. Fixed by adding an
`admin_init` gate that runs on EVERY wp-admin request, redirecting an unenrolled
in-scope admin past grace to the setup page. A stale session is caught on its
next click; a survived cookie never reaches an admin screen. The `wp_login`
handler stays as a second layer. Critically, the gate allows the enrollment
paths (profile, the TOTP setup AJAX/POST, logout) through — gating without that
allowance would itself be the lockout.

**Bug 2 — the REST filter deferred to a prior ALLOW.** `rest_authentication_
errors` used `if ( ! empty( $result ) ) return` — but WordPress core's
convention is that `true` on that filter means "already authenticated, allow
it". Treating a prior `true` as "someone decided, stop" meant enforcement was
skipped exactly when another handler had authenticated an unenrolled admin.
Fixed to defer only to a prior `WP_Error` (never override another control's
denial) while still applying our own check when the request was merely allowed.

**Bug 3 — "enrolled" counted enabled-but-not-configured providers.** The
enrollment check called `get_enabled_providers_for_user()` (what the user
ticked) rather than `get_available_providers_for_user()` (enabled AND
configured). A user could enable TOTP, never scan the QR, and be counted as
enrolled — then be blocked at their next fresh login with no factor that
actually works. Fixed to require a configured provider, with a defensive
fallback for unexpected plugin versions.

**Also confirmed and improved by the review:**

- The console-recovery meta keys in the runbook (`_two_factor_enabled_providers`,
  `_two_factor_provider`) were verified against the plugin source — a wrong key
  would silently no-op and leave the admin locked out. They are correct. Added
  clearing of the plugin's rate-limit keys (`_two_factor_last_login_failure`,
  `_two_factor_failed_login_attempts`) too, so a recovered account is not still
  throttled from the failed attempts that caused the lockout.
- Added `MFA_ENFORCE`/`MFA_GRACE_DAYS` to the payload's defensive-defaults block,
  so a re-provision from an older vars.sh defaults enforcement OFF (the safe
  direction) rather than leaving it undefined.

The logic-test harness grew from 13 to 21 cases, adding the enrollment-path gate
(the lockout-critical function: profile and TOTP-setup endpoints must stay
reachable, normal admin pages must not). All pass. The broader lesson is the one
this project keeps relearning: the check suite proves the code does what the
code says, and a review against the real system is what catches the code saying
the wrong thing. Mocks cannot model `wp_login` cookie timing or the difference
between a ticked and a configured provider; only reading how WordPress and the
plugin actually behave could.

---

## Unreleased — Two-factor authentication for administrators

Answering "add MFA to the admin login" — but not with any of the four identity
providers that were suggested (Kanidm, Authentik, Authelia, PocketID). Those are
SSO servers: they add MFA by making WordPress speak OIDC/forward-auth, which
means a standalone always-on identity service (Authentik needs PostgreSQL and
Redis), a second WordPress integration on top, and a new single point of
compromise — if the IdP is lost, every downstream app loses auth at once. That
is the opposite of WASP's minimal-surface design, and the wrong amount of
machinery to protect one login form. An IdP is a fleet-identity decision for
later, not a wp-admin-MFA decision now.

The right fit is the **Two Factor plugin maintained by the WordPress core
contributors** (TOTP, backup codes, passkeys via its WebAuthn companion) — the
smallest code surface, no upsell, no phone-home — plus a WASP mu-plugin for the
enforcement the plugin deliberately omits.

**What was built:**

- `wp-plugins.sh install <slug> [--activate]` — a slug-only installer from the
  already-allowlisted WordPress.org directory. Refuses URLs and ZIPs, so the
  source is always the signed directory and never an arbitrary runtime download,
  which is the thing this project otherwise avoids. Logs what it installed.
- `payload/mu-plugins/03-wpvm-mfa-enforce.php` — requires 2FA for administrators
  (`manage_options`), and is built entirely around not locking anyone out:
  a grace window (default 7 days, capped 30, held as a constant so a compromised
  session can't widen it), backup codes counting as a factor, email explicitly
  NOT sufficient for admins (it's the reset channel), and a console recovery
  path. It also closes the REST and application-password side doors so the
  second factor can't be bypassed via an API.
- Installed at provisioning: the mu-plugin in stage 06 (with placeholder
  substitution and a `php -l` gate), and the Two Factor plugin itself in stage
  08 where `wp-plugins.sh` exists to install it — ordered so a failed fetch
  cannot wall the login (the mu-plugin treats "plugin absent" as "don't enforce
  yet, show a notice").
- An install prompt (`MFA_ENFORCE`, `MFA_GRACE_DAYS`) with the lockout-safety
  explanation, and `validate-wordpress.sh` now fails loudly if enforcement is on
  while the plugin is inactive — the one state that would lock admins out.

**Composition was tested, not assumed.** The subtle risk was interaction with
the three things already on the login path: the custom slug, the brute-force
guard, and the IP restriction. They compose as sequential stages — the slug
decides where the form lives, the guard throttles the password on the
`authenticate` filter, 2FA gates the second factor on `wp_login` after a correct
password. MFA deliberately does not touch the `authenticate` filter the guard
owns; where both use `wp_login`, ordering (02 before 03) means the guard clears
failure counters on success before MFA gates, which is correct. A 13-case logic
harness (`test/test-mfa-enforcement.php`) proves the scope, enrollment (including
email-insufficient and backup-codes-sufficient), grace maths, and combined
blocking decision, and now runs in `run-all-checks.sh` alongside `php -l` of
every mu-plugin — because this session has repeatedly shown that login-path
interactions are exactly where lockout bugs hide.

The console recovery procedure is documented in SUPPORT-RUNBOOK.md as a Tier 2
action, with the reasoning that it is safe to document openly precisely because
it needs hypervisor access — an attacker with that already has more than a
login, and it must never become a network-reachable reset.

---

## Unreleased — Session capture for review, redacted and self-contained

`wasp-capture.sh` — records what you did on the VM and produces one shareable
bundle, so handing a problem over means handing over exactly what ran and
exactly what the machine saw, not a description of it.

The research question was whether an existing tool does this. Two do —
asciinema and util-linux `script` — but for a WASP VM the important finding was
a privacy one, surfaced repeatedly in the sources: a terminal transcript here
contains client IPs and hostnames, which under GDPR is personal data the moment
it leaves the machine, and public recording services (asciinema.org and the
like) are explicitly the wrong destination. So the answer is not a third-party
uploader; it is a thin wrapper around `script` (already on the VM, zero new
dependency) that redacts and bundles locally.

Most of the work was already done: `wasp-testreport.sh` is the
diagnostic-gathering half and already redacts secrets to lengths. The wrapper
adds the session transcript, an environment snapshot, and correlated
firewall/egress/CrowdSec logs, then applies a SECOND redaction pass that scrubs
BY VALUE every secret the installer knows about — reading the actual values
from vars.sh and the secrets files and replacing them with typed
`«REDACTED:NAME»` markers in both the transcript and the report. Verified
end to end: a mock report leaking an admin password and an API key came out
clean.

Modes: `start`/`stop` for an interactive session, `report` for just the VM's
current state, and `oneshot -- CMD` for a single command. The bundle is a local
tar.gz the operator attaches in a browser; it uploads nowhere, and the tool
tells the operator to skim it before sending because they are the last check.

**A quote-nesting bug caught in build, and it was the exact class the project's
own `check-embedded-quotes.py` exists for.** Two spots used
`tr -d '\"'"'"'` — a double-quote-and-single-quote strip written with nested
shell quoting — inside a `$( )` inside an `echo`. It was unparseable by dash
(the error walked down the file as each surface symptom was patched, the
signature of an unclosed quote), and unreadable regardless. Replaced with a
small `_unquote` helper that uses character variables (`_sq`, `_dq` from
`printf '\047'`/`'\042'`) so there is never a literal quote-inside-quote for a
POSIX parser to mishandle. The lesson the checker encodes held up: if a quote
construct is too tangled to read, it is usually also wrong.

---

## Unreleased — External security evaluation: 6 of 8 MAJOR findings fixed in source

An independent evaluation (2026-08-09, 91 files, 34,587 lines) rated the build
a strong controlled-pilot platform, not yet unconditionally MSP-production
certified, with 8 distinct MAJOR findings, ~98 MINOR (mostly two repeated
inherent-design observations), and 3 PASS. Six of the eight MAJORs were real
and fixable in source; they are fixed. The other two are the unsigned-build
state (expected for a development tarball) and a subset now partially closed.

**MAJOR — Squid startup/parser failure only warned.** A production site whose
egress proxy failed to start could complete installation with all WordPress
web access broken. Now fatal under `DEPLOYMENT_PROFILE=production`, matching the
existing CrowdSec-bouncer pattern: both a failed `podman run` and a failed
`squid -k parse` abort the install with the logs, while lab/standard still
warns. A running proxy with a broken policy is treated as worse than one that
did not start, because the firewall directs traffic to it and it does not
filter.

**MAJOR — DNS unrestricted from WordPress.** The egress firewall allowed UDP/TCP
53 to any destination, leaving a DNS tunnel open: a compromised WordPress could
exfiltrate by encoding data into lookups to a resolver it controls, bypassing
Squid entirely. DNS and NTP are now pinned to the wp-front gateway resolver
(where aardvark-dns listens) rather than any destination. Squid resolves
external names itself, so WordPress only needs to resolve `mariadb` and its few
direct-path names — all via the gateway. Off-network resolver attempts now hit
the logged drop.

**MAJOR — WASP_ACCEPT_UNVERIFIED reachable in production.** A signature-check
failure could be bypassed noninteractively. Under
`DEPLOYMENT_PROFILE=production` neither the `WASP_ACCEPT_UNVERIFIED` escape nor
the interactive UNVERIFIED prompt is now available — the only fix is a correctly
signed build. Any unverified install (only possible under standard/lab) persists
a durable `/etc/wp-install/UNVERIFIED` marker that `validate-wordpress.sh
--check` surfaces as a WARNING and `wasp-testreport.sh` banners at the top, so a
lab build can never be quietly mistaken for a verified one.

**MAJOR — Candidate read live data and could call out.** The update candidate
container mounts the docroot read-only and has a SELECT-only DB grant already,
but the evaluator noted it could still call external APIs, send mail or
exfiltrate. It now has two-layer egress isolation: at the firewall (on wp-front,
restricted to Squid + gateway DNS when egress is enabled) and at the
application (`WP_HTTP_BLOCK_EXTERNAL=true`, plus disabled cron, file-mods and
auto-updater — candidate-only, not production). A health-check boot needs no
external HTTP, so blocking all of it costs nothing and removes the whole class.

**MAJOR — Weekly self-test proved local restore, not remote recovery.** Verifying
the offsite object EXISTS is not proof it RESTORES — it can be truncated,
encrypted to a recipient whose key is gone, or otherwise unusable exactly when
needed. New `wasp-offsite-backup.sh remote-restore-drill` forces the full
round-trip: pull the actual remote object (never a local shortcut), decrypt it
with the recovery key, restore into a throwaway database, verify it is
non-empty, and record fetch/decrypt/restore timing as a real RTO. This directly
converts the project's weakest claim — recovery — from reasoning into evidence.

**MAJOR — README contradicted itself on egress.** Early sections described Squid
as the destination boundary; a later section still described port-only egress
as "may connect out to anything." Resolved with an explicit two-layer hierarchy:
Squid is the destination boundary for WordPress web traffic (the layer that
matters, since 443 is open at the port level either way), and the outbound
firewall is the coarser VM-wide port control for the host's own non-HTTP
services. Both sections now cross-reference and frame each other as complementary
layers rather than alternatives.

**Partially closed — vulnerability-exception governance.** The exception
mechanism was already digest-scoped with expiry (the core of the finding). Added
the missing half: `wasp-testreport.sh` now surfaces every ACTIVE (unexpired)
exception with its digest and lapse date, so weekly review sees what has been
accepted — an unreviewed exception is how one quietly becomes permanent policy.

**Expected, not a defect — unsigned build.** The evaluated tarball is an unsigned
development build (empty `WASP_PUBKEY`, no `MANIFEST.sha256`). That is the
correct state for a source drop; the signing path exists and is now
additionally enforced by the production profile above. A real MSP deployment is
built from a signed release.

The two-repeated MINOR themes — "permanent root tooling is a persistence target"
and "correct static content still needs runtime validation" — are inherent to a
root-run provisioner audited from source, not defects, and are answered by the
existing integrity manifest plus the standing caveat that none of this is proven
until it runs on hardware. That caveat is unchanged and remains the honest
headline: these fixes are validated by the check suite and by construction, not
yet by a disposable-VM drill.

---

## Unreleased — Squid folded into the update path (it was the one component left out)

The question was whether every component, Squid included, was in `update.sh`.
It was not — and the gap was worse than a missing dispatch line.

**Squid was not a pinnable image at all.** It ran `alpine:3.21` and did
`apk add squid` at container start, so its version was whatever Alpine's repo
served the moment the container booted. That cannot be digest-pinned (the
binary is not in the image), cannot be CVE-scanned before deployment, and
cannot be updated through the same mechanism as everything else — it was the
one container outside the entire digest-pinning security model, and it was the
container most defined by CVE exposure, having just had four mitigations added.

**Fixed by making Squid a real pinned image and wiring it in fully.** Now uses
Canonical's `ubuntu/squid`, whose digest represents a known Squid version, on
identical footing to WordPress, MariaDB and CrowdSec:

- Registry constant, pinned-version fallback, and `pinned.env` tag+digest.
- Digest-pinned at install (stage 02) alongside the others, guarded so it only
  pins when egress filtering is enabled.
- `do_squid_update()` following the CrowdSec pattern — candidate scan, clean
  stop, rename-to-rollback, run, policy-parse verification, and rollback on any
  failure. Simpler than CrowdSec in fact: Squid is on an isolated network with
  no persistent state, so there is no two-engines-on-one-port hazard.
- Present in `update.sh squid`, `update.sh all`, `update.sh digest-check`,
  `update.sh trivy`, `update.sh status`, `update.sh versions`, and the usage
  string. Verified every path the other three appear in.

**Research corrected a wrong assumption in the process.** The version guard and
a config comment claimed CVE-2025-62168 (the CVSS 10.0) requires Squid 7.2.
Canonical BACKPORTS that fix into the 6.x line — it is fixed in the
6.13-1ubuntu1.2 package — so a "must be >= 7.2" check would have wrongly warned
on a fully patched image. The guard now reports the version and points at
`update.sh squid` for currency rather than asserting a version floor the
Canonical image deliberately does not follow. The `email_err_data off` policy
workaround stays as defence in depth regardless.

The result: there is no longer any component that cannot be checked, scanned
and updated through one tool. That was the actual question, and the honest
answer required fixing the image model, not just adding a case to a switch.

---

## Unreleased — Version audit against upstream: WordPress and PHP floors bumped

A pass with a research lens rather than a re-read: every pinned version,
base image and external command checked against its current upstream state as
of August 2026, because that is the kind of staleness a self-review cannot see.

**Two real findings, both in the default version floors:**

- **WordPress default was 6.9.4; 6.9.6 shipped 2026-08-06.** The 6.9 branch has
  had active security releases (6.9.2/6.9.3 addressed security issues, and
  6.9.4 itself was reissued because not all fixes had applied). A fresh install
  on 6.9.4 was therefore born two maintenance releases behind on a branch that
  was actively patching. Floor moved to 6.9.6. Note this only affected first
  boot: `update.sh` already moves off the floor by digest after a CVE scan, so
  an operator who had run an update was current regardless.
- **PHP was pinned to 8.3, which entered SECURITY-ONLY support on 2025-11-23**
  (full EOL 2027-12-31). 8.4 is the recommended production line, with bug fixes
  through 2028-12-31. New installs should not start on the security-only line;
  floor moved to php8.4.

Both defaults are documented in the code as *starting floors, not the version
you end up on*, with the verification date and the upstream reasoning inline,
so the next person can see why the number is what it is rather than guessing
whether it is arbitrary.

**Four things checked and confirmed already correct — the more useful half of
an audit:**

- **MariaDB 11.4** is right and current. It is LTS with support to May 2029 —
  the longest runway of any release — and the bare `11.4` branch tag tracks
  patch releases (11.4.12 latest). The existing code comment that `11.4-lts` is
  not a real tag is accurate and was kept.
- **The June 2026 MariaDB Galera CVEs do not apply.** They affect Galera
  clustering; WASP is single-node and enables no clustering (the only `cluster`
  reference is a Proxmox VMID lookup). Verified rather than assumed.
- **CrowdSec v1.7.8** is the current latest (2026-05-11) and is already the
  correct security release — the code comment correctly identifies it as the
  CVE-2026-44982 WAF-bypass fix. No change needed.
- **`cscli dashboard`**, removed in CrowdSec 1.7, appears nowhere. No removed
  MariaDB config directives, no `docker-compose`, no deprecated container
  syntax. The `--allow-root` and `allow_url_fopen` uses are deliberate and
  documented, not leftovers.

All illustrative version strings in comments, examples and the Proxmox notes
were aligned too, so no reader is misled by a stale example even where it was
never functional. The point of that is not cosmetic: a comment showing
`6.9.4-php8.3` next to code that installs `6.9.6-php8.4` is a small lie that
costs the next reader time.

---

## Unreleased — Support runbook that supports everyone, tiered by reader

`SUPPORT-RUNBOOK.md` — the gap the project's own assessment kept naming: a
troubleshooting guide for the person who is *not* the author, so an incident
does not route to whoever wrote the system.

Structured by who is reading it, not by subsystem, because that is what decides
what a reader can safely do:

- **Tier 0 — Anyone.** A client or account manager, no command line. Deliberately
  cannot break anything: it is all looking and reporting. Covers the three real
  Tier-0 events — site looks down, cannot log in, got an alert email — with an
  emphasis on reporting the exact error rather than "it's broken", because a 502
  and a 403 send a technician to entirely different places. Includes what never
  to do: stop retrying a password before CrowdSec bans you, do not install a
  plugin to fix an outage.
- **Tier 1 — On-shift tech.** A symptom-to-action table keyed on what the client
  actually says, each row naming the first check and the likely fix. The 403
  tree gets its own walkthrough because it is the most common WASP-specific call
  and has three distinct causes. Un-banning, the console escape hatch, and an
  explicit "stop before changing something you don't understand" with what to
  hand up.
- **Tier 2 — Engineer.** The failures Tier 1 correctly does not attempt:
  container-dies-on-start, CRITICAL-after-obvious-fixes, the ordered compromise
  response (with the reminder that quarantining first destroys the timeline),
  restore, rollback, integrity verification. Ends with a "needs you
  specifically" list — the judgement calls that have no runbook entry on
  purpose, because some decisions should not be made by someone following a
  script.

Writing it did what a runbook should: it forced verification that every command
it names is real. That surfaced a genuine regression — `validate-wordpress.sh
--check`, the single most-referenced command in the runbook and the health
signal the whole fleet-monitoring story depends on, had been lost from the file
when an earlier edit aborted mid-write. Restored, with the Prometheus mode, and
re-verified. A runbook that points at a command which no longer exists is worse
than none, and the doc-vs-code check plus this pass is what caught it.

Cross-linked from the MSP runbook (the business layer), the incident playbook
(compromise response), and the README, so each points to the right companion
rather than duplicating it.

---

## Unreleased — Fleet management: a researched decision, not a build

Whether WASP needs to build a central aggregator, or use Pulse for per-VM pod
status. Researched rather than assumed, and the answer is: build almost nothing.

`docs/FLEET.md` lays it out as three separate problems, because conflating them
is how you build a monitoring product instead of running a hosting business:

- **Is the VM alive?** Pulse — one LXC on the Proxmox host, auto-discovers
  guests via the API, shows every VM's CPU/RAM/disk/up-down with console links
  and downtime alerts. The visual pod-status dashboard, free, self-hosted,
  nothing installed on the VMs. Blind to everything inside the guest, which is
  exactly the set of failures WASP catches and which never show as a red VM.
- **Is WASP healthy inside?** The seam nothing off-the-shelf covers, tiny
  because `validate-wordpress.sh --check` already emits the signal. Recommended
  start builds nothing: the existing heartbeat and `--check` fed to a hosted
  checker is complete fleet monitoring today. A read-only aggregator is a later
  option if that gets noisy — status only, never fleet credentials.
- **Is WordPress maintained?** MainWP if you want central updates and reports,
  self-hosted, carrying an explicit warning: every tool in this category holds
  a key that controls every connected site, a single point of compromise for
  the whole portfolio, in tension with WASP's no-single-owner design.

The recommendation, stated as a principle: monitor with tools that observe, not
tools that control. WASP's value is that no component owns the fleet; fleet
management should preserve that, not undo it with one dashboard holding every
key.

**`validate-wordpress.sh --check --prom`** added so the scale path is real:
the same health signal as Prometheus text with stable metric names
(`wasp_health`, `wasp_disk_percent`, `wasp_backup_age_hours`,
`wasp_container_up`), for a textfile collector or scrape endpoint.

No aggregator VM was built, deliberately — the trigger is real pain with the
zero-infrastructure option, not anticipation of it.

---

## Unreleased — Credential rotation, and a health code for monitoring

Two gaps that separate "works" from "an MSP can run a fleet of these".

**`wp-rotate-secrets.sh`** closes the sharpest one. The incident playbook said
"rotate every credential" and gave no way to do it — so the moment rotation
matters most, just after a compromise, was the moment an operator was
hand-editing several config files under pressure, hoping they caught every
copy. A missed copy is either a broken site or a credential the attacker still
holds.

The database password is the hard case because it lives in more than one
place: the container environment and the MariaDB grant. The tool changes
MariaDB first, then the environment, then restarts WordPress — an order that
keeps the site serving throughout, because MySQL does not drop the live
connection when the password changes. It verifies the new password
authenticates before committing and rolls both back if it does not. Generated
passwords are drawn from a shell- and SQL-safe alphabet, so no value can break
an env file or a SQL statement.

It refuses to rotate the age backup key, loudly. Every existing backup was
encrypted to the current key; a new key cannot read them, so rotating it
discards the backup history. That is a re-encryption workflow, not a rotation,
and pretending otherwise would lose someone their backups.

**`validate-wordpress.sh --check`** gives monitoring a number instead of a
report. One line, standard exit codes — 0 healthy, 1 degraded, 2 critical — so
Nagios, Zabbix, Checkmk or a cron poller can watch the VM without parsing
anything. It checks the four page-worthy conditions: containers up, database
answering, disk under 90%, newest backup under 26 hours. The rest of the
validator is diagnosis for humans; this is alerting for machines, and mixing
the two is why so many health checks are too chatty to alert on.

It complements the heartbeat rather than duplicating it: `--check` reports the
VM is *unhealthy*, the heartbeat's absence reports the VM is *gone*. An on-box
check cannot detect its own host being down, and an off-box heartbeat cannot
see disk usage. Both, or a blind spot.

`MSP-RUNBOOK.md` now maps both `--check` exit codes to severities, and the
decommissioning section documents rotation as tooled rather than manual.

The doc-coverage check earned its place again — it failed the build twice on
this tool, once for no documentation and once for prose that described the
behaviour without naming the command. Both are real: a tool documented only
inside a code fence is undiscoverable by anyone searching for it.

---

## Unreleased — Perimeter test wired into the report, off-box by default

`wasp-testreport.sh --perimeter <url>` runs the external harness as a section
of the full report, so one command spans interior and perimeter.

The wiring resolves a real tension rather than papering over it. The harness
lives in `tools/`, deliberately outside the deployable payload, so a
compromised VM does not contain a ready-made scanner — which means it is not on
the VM for `--perimeter` to call. Rather than auto-installing it and undoing
that, the report treats its absence as **correct**, and prints the two commands
to run it from a Kali box, including the `--ip` form that tests WEB_CIDR.

It is also honest about vantage. Even when the harness is present on the VM
(because the operator copied it there), the report states plainly that this
host is on the LAN and probably allow-listed, so admin endpoints may answer
here that an outside attacker cannot reach — and that the real access-control
test is still from off-LAN. A green perimeter section from the VM is not
allowed to imply more than it shows.

This is deliberately not folded into `test/run-all-checks.sh`, which runs at
build time in the sandbox and lints shell against no live target. A perimeter
test needs a reachable VM and makes real HTTP requests; it belongs in the
on-VM report, not the build-time linter. The two harnesses answer different
questions and are kept separate on purpose.

---

## Unreleased — External validation harness for Kali

`tools/wasp-pentest.sh` — run from a Kali box against a WASP VM you own, to
confirm the controls WASP claims actually fire from an attacker's position.
Every defensive claim becomes a probe with an expected result: admin surface
refused, XML-RPC disabled, no username enumeration, headers present at the
edge, no exposed files, rate limiting returning 429 rather than the field
bug's 503, TLS floor, and — with `--ip` — whether WEB_CIDR really restricts
direct access to the proxy.

**Deliberately a validation tool, not an attack tool**, and the line is
explicit in the code and the doc. It makes ordinary HTTP requests and checks
responses. No exploit payloads, no credential wordlists, no injection strings,
no traffic flood. The one rate-limit probe is eight spaced requests — enough to
see the limiter engage without flooding anything or risking a real lockout.
Every request identifies itself as `wasp-pentest/1.0` in the target's logs.

Confirming a control fires needs one well-formed request with a known expected
answer. The moment such a tool needs a wordlist or a CVE payload it has stopped
validating the owner's system and started being useful against systems that are
not theirs — a different tool with a different purpose, and not this one.

**Authorisation is enforced, not assumed.** The script requires the operator to
type `I OWN THIS` before sending anything, with the CFAA named. That prompt is
the boundary between security testing and an offence.

**It is honest about its vantage.** Egress filtering, CrowdSec's ban list,
backup encryption and malware scanning live inside the VM and cannot be seen
from outside; the harness says so and points at the VM's own commands rather
than pretending to cover them. And it treats *where you test from* as the
substance of the access-control test: an allow-listed address is expected to
reach wp-admin, an unauthorised one is not, and the difference between the two
runs is the control working.

Placed in `tools/`, outside the deployable payload, so it is never installed on
the VM it tests. Verified against a mock hardened endpoint: the hardened
responses pass and unhandled paths correctly fail.

---

## Unreleased — Forensic audit: CWE-377, and four Squid CVEs the config ignored

An audit against known issue classes rather than a re-read of my own comments.

**Predictable temporary files (CWE-377), eight instances.** Root-run scripts
wrote error output to fixed paths — `/tmp/.age.err`, `/tmp/.offsite.err`,
`/tmp/.nfterr`, `/tmp/.offsite.log`. Any local user can pre-create one of
those as a symlink and have root truncate whatever it points at. The
dot-prefix hid them from `ls` and from nothing else. All now `mktemp` with a
trap; the pre-existing function-local trap in `wasp-offsite-backup.sh` was
checked rather than assumed and survived.

**Four published Squid CVEs, none mitigated by the config I wrote:**

- **CVE-2025-62168, CVSS 10.0** — HTTP credentials were not redacted from
  error pages, letting a remote client harvest tokens used by backend
  applications. Fixed in Squid 7.2; `email_err_data off` is the vendor's
  workaround and is now set, with an install-time version check that says
  plainly when the running version predates the actual fix.
- **CVE-2025-54574** — heap overflow in URN handling, remote code execution,
  everything before 6.4. `http_access deny URN`.
- **CVE-2026-47729** — out-of-bounds read in the FTP gateway leaking data
  between sessions. `http_access deny FTP`.
- **CVE-2026-50012** — heap overflow via crafted cache_digest replies.
  `digest_generation off`.

Disabling unused protocol handlers is worth doing beyond these specific
issues: the next flaw in a parser this deployment never invokes is one the
configuration is already immune to.

**And the fix reproduced the exact bug its own comment warns about.** The URN
and FTP denies were first placed with the other CVE mitigations near the end
of the file — *after* `http_access allow`, where they would never be
evaluated. An allowed source requesting a `urn:` URI would have matched the
allow first and the deny would have been decorative. Caught by re-reading the
rendered order, and now enforced by a check that no specific deny follows any
allow.

**Dead code:** one orphaned function removed. Four more flagged were
cross-file false positives — `msg_ok` alone is used 67 times — verified before
deleting anything, since a per-file sweep cannot see cross-file use. No
dangling `${PAYLOAD_DIR}` references. The two remaining TODO markers are prose
inside explanatory comments, not unfinished work.

**Clean:** no secrets in host-visible argv (database passwords expand inside
the container), no `eval` on non-constant input, no TLS verification bypass,
no world-writable permissions.

---

## Unreleased — Import pipeline diagram, and a coverage check that is not fooled by a mention

Asked where the import section was in `ARCHITECTURE.md`. It was not there —
`wp-import.sh` existed only as four leaf nodes in the day-2 tooling map.

**The coverage sweep from the previous entry reported it as present**, because
grep found the string. That is the same failure as the checks which confirmed
a firewall rule was *present* rather than *effective*: presence is the easy
question and rarely the useful one, and here it produced a confident "✔" for a
multi-stage pipeline with no representation at all.

**Section 7 added: the import pipeline**, because the ordering *is* the
security property and a list of tool names cannot show ordering. The diagram
follows the archive from inbox through index-only inspection, bounded
extraction outside the docroot, file and dump scanning, the graded gate,
normalisation and re-hardening — with the refusal paths drawn rather than
described.

Sections renumbered 1–8; `3b` was a leftover from inserting the egress
boundary.

**`test/check-doc-coverage.py` added**, and written to distinguish *mentioned*
from *documented*: a tool counts only if it appears in prose outside code
fences and diagrams, not merely once as a node label. It immediately found two
more that the grep-based sweep had passed — `wasp-testreport.sh` and
`wp-notify.sh`, both operator-facing and both only ever named.

Then it caught a third case on the fix itself: the new alerts section
described what `wp-notify.sh` does without naming it outside a code fence.
Technically documented behaviour, undiscoverable by anyone searching for the
command. Fixed by naming it in the prose.

Internal helpers invoked only by cron are listed as exempt rather than
silently ignored, so the exemption is a decision someone can disagree with.

---

## Unreleased — Documentation brought level with the code

A coverage sweep rather than a tidy-up. Four things were missing entirely and
two of them mattered.

**`ARCHITECTURE.md` gains a seventh diagram: the egress boundary.** It shows
the eight-stage policy chain in evaluation order, the three paths that are
blocked (direct :80/:443, raw sockets, the database container), and states in
prose why the order is not cosmetic — a hard deny placed after the allowlist
can be overridden by a wildcard, which is how a metadata endpoint becomes
reachable.

The component diagram gains Squid; the tooling map gains `wasp-egress.sh`,
`wp-import.sh`, `wp-forensics.sh`, `wasp-testreport.sh` and the heartbeat.
Six shipped tools had no representation at all — the same drift that was
fixed once already, which suggests the check should be automated rather than
repeated by hand.

**`INCIDENT-PLAYBOOK.md` did not mention `wp-forensics.sh`** — the tool most
likely to be reached for during an actual incident. Worse, the CRITICAL
malware sequence had quarantine at step 2, before any timeline capture. That
ordering destroys the correlation: the file's mtime is the anchor for
everything around it, and once it moves the anchor becomes the quarantine
time. Timeline capture is now step 2 and quarantine step 3, with the reason
stated inline so nobody reorders it.

It also gains an egress step — a compromised site calling out is often the
clearest evidence of what the payload was *for*, and the denial log records
attempts that succeeded at nothing.

**`MSP-RUNBOOK.md` gains a client-onboarding section.** Inspect and scan
before quoting the work: a backup with a webshell in uploads and code in
autoloaded options is a cleanup engagement, not a migration, and discovering
that afterwards is how a fixed-price migration becomes unpaid incident
response.

**Two commands were documented nowhere at all: `web-allow` and `admin-rule`.**
Both are lockout recovery, which is the worst possible place for an
undocumented command — they are needed precisely when the operator cannot
reach the system to go looking. Now in the README with the reasoning, and in
the playbook's lockout table.

The sweep itself is worth keeping as a habit: a matrix of every feature
against every document, so "documented nowhere" is a result rather than
something noticed by accident.

---

## Unreleased — Egress control: Squid + firewall enforcement

Implements the WASP Egress Control Plan. The outbound firewall added earlier
restricts which **ports** WordPress may use; this restricts which
**destinations**, which matters because 443 is open either way and 443 is
where exfiltration goes.

**HTTPS is filtered without decrypting anything.** A client opening an HTTPS
connection through a proxy sends `CONNECT host:443` in plaintext before the
TLS handshake, so `dstdomain` allowlisting works with no SSL Bump, no
certificate authority on the VM, and no ability to read the traffic. TLS
interception was a stated non-goal and is not needed to get the property.

**The firewall half is the one that matters.** `WP_PROXY_HOST` is honoured
only by code that chooses to honour it — a plugin calling `fsockopen()`, or
`curl` without `CURLOPT_PROXY`, ignores it completely. Without an nftables
rule the proxy filters only well-behaved traffic, which is not the traffic
anyone is worried about. wp-front may reach `10.89.10.2:3128` and DNS/NTP;
everything else outbound is logged and dropped, and Squid alone may reach the
web.

**ACL order is the security property, not presentation.** Source, then
method/port, then hard deny, then IP literals, then threat list, then
allowlist, then maintenance, then deny all. Every deny precedes every allow —
a hard deny placed after the allowlist can be overridden by a wildcard entry,
which is how a metadata endpoint becomes reachable because somebody
allowlisted too broadly.

Cloud metadata is denied **by address**, not only by name, because the
property has to survive a request straight to `169.254.169.254` — which is
exactly what an SSRF payload does. Bare IP literals are refused outright:
there is no legitimate WordPress update that needs one, and an IP request
bypasses every name-based rule below it.

**`wasp-egress test` proves enforcement rather than reviewing configuration.**
Ten checks, and the important ones remove WordPress's proxy settings and
confirm egress *still* fails. That is what distinguishes a firewall enforcing
a boundary from an application politely observing one. It also covers a raw
`fsockopen()`, a CONNECT to port 22 on an allowlisted host, and the database
container reaching anything at all.

**Maintenance windows, no open mode.** A window needs a reason of at least ten
characters, is capped at 120 minutes, records who opened it, emails the fact,
and closes itself. Expiry is evaluated on every command rather than by a
timer, so a window cannot outlive its duration because a cron job did not run.

**Discovery never auto-promotes.** Denied destinations are reported and
classified by hand — REQUIRED, MAINTENANCE, UNNECESSARY, SUSPICIOUS. An
allowlist grown by accepting whatever asked for access is not an allowlist,
and a destination the operator cannot account for is a finding.

**A test-harness bug caught by the embedded-quote check**, and fixed as a
class rather than an instance: `_t` took its command as a string and `eval`'d
it, so every nested quote had to be escaped correctly twice — and one was not.
Rewritten to take arguments. A test harness whose own quoting can silently
change what it runs is not a test harness.

The starting allowlist is deliberately short and says what it excludes and
why: Gravatar, font CDNs and the rest of the CDN estate are common
exfiltration paths, and a site that visibly breaks without one has just told
you about a dependency you did not know it had.

---

## Unreleased — Import: the gate, normalisation and re-hardening

The destructive stages, and the ones where the safety rails matter more than
the feature.

**The gate is graded, not binary.** Refusing outright would be wrong — people
import compromised sites deliberately, in order to clean them — and
proceeding silently defeats the tool's only purpose. Unscanned refuses;
CRITICAL refuses without `--force`; HIGH refuses without `--accept-findings`;
every override is recorded with who made it.

**A backup of the current database is mandatory**, taken before anything is
replaced, and the import refuses if it fails. An import without a way back is
a replacement.

**Normalisation is where most of the safety comes from**, and it works by
discarding rather than inspecting wherever a good replacement exists. Core
comes from the pinned image; `wp-config.php`, `.htaccess` and mu-plugins are
withheld — mu-plugins especially, because they are active on arrival with no
activation step to withhold. Executable files in uploads are quarantined as
evidence rather than deleted.

**Re-hardening runs because an import undoes hardening.** `home` and `siteurl`
are rewritten for this deployment, salts regenerated — invalidating every
session the source site had, which is the point — scheduled tasks cleared, and
administrators listed with the observation that any unrecognised account is
persistence that outlives deleting the file which created it.

**A real bug found while testing, in code written minutes earlier.** The table
prefix rewrite matched single-quoted meta keys only. `wp_capabilities`,
`wp_user_level` and `wp_user_roles` are stored as meta **values** and carry the
prefix, so rewriting table names alone imports every user with no capabilities
— the classic "changed the prefix and lost admin access", presenting as a
completely successful import.

Worse, the first fix only handled single quotes: `mysqldump` emits those, but
phpMyAdmin, Adminer and several backup plugins emit double, so dumps from the
most likely sources would still have locked the operator out. Now
quote-agnostic, verified against both styles.

That is the second time in this feature that a quote-style assumption would
have produced a silent failure in exactly the case that matters. Worth
recording as a pattern rather than two coincidences: **SQL dumps are not one
format**, and any check or rewrite against them needs testing against more
than the exporter that happened to be to hand.

---

## Unreleased — Import: bounded extraction and dump scanning

Steps 2 and 3 of the import design. Together with `inspect` this answers
"what is in this backup, and is it safe" without writing anything to the live
site.

**Extraction treats the archive as hostile.** Hostile-member checks are
re-run rather than assumed — a check that only fires when the operator
remembers to run `inspect` first is not a control. Ownership and permission
bits from the archive are never honoured (`--no-same-owner`,
`--no-same-permissions`): a setuid binary or root-owned file inside a client's
backup is not something to reproduce faithfully. Disk headroom is verified
before writing, because running out mid-extract leaves a half-populated
staging directory *and* a disk too full for the live site to write its own
logs.

**Everything extracted has its execute bit removed.** The staging tree is
never served and nothing in it should run, so removing the bit costs nothing
and eliminates a class of accident — including a script or an operator
invoking something from the archive without meaning to.

Duplicator's installer is deleted at extraction rather than at import. There
is no stage at which keeping it is useful.

**The dump is scanned as a file, before it is loaded.** Loading it and then
querying it is the same error as extracting into the docroot: by the time you
look, the thing being checked for has already happened. Three checks, each
for something most import tooling ignores entirely:

- **Code in autoloaded options** — runs on every page load, invisible in the
  filesystem, survives any file-level clean.
- **Suspicious scheduled tasks** — the `cron` option re-creates files after a
  clean, which is why malware appears to "come back" and why the operator
  concludes the clean failed.
- **Administrator rows** — persistence that outlives deleting the file that
  created the account.

**A real fragility fixed during testing.** The cron pattern matched
single-quoted option names only. `mysqldump` emits single quotes, but
phpMyAdmin, Adminer and several backup plugins emit double — so the check
would have passed silently on those dumps, for the persistence mechanism most
likely to be missed. Now quote-agnostic, verified against both styles and
against a legitimate `wp_version_check` entry, which correctly does not match.

Tested end to end against a constructed infected backup: webshell in uploads,
Duplicator installer, mu-plugins, core files, a poisoned autoloaded option, a
malicious cron entry and a rogue administrator row. Every one was reported at
the right severity.

`check-grep-count.py` fired a fifth time on the same idiom, again minutes
after the check had passed.

---

## Unreleased — `wp-import.sh`: ingest and inspection

Steps 1 and 2 of `docs/IMPORT-DESIGN.md`, chosen first because they are the
only part of the import pipeline with **no destructive failure mode**.
Everything after them writes to disk; this only reads.

**Ingest reuses what is already configured.** `fetch s3` uses the same rclone
remote set up for off-VM backups — a second set of credentials for the same
bucket is a second thing to rotate and forget. Also `fetch url` with an
optional checksum, and an SFTP inbox at
`/var/lib/wasp-import/incoming`, group-writable by the admin user so a
drag-and-drop transfer does not stall on permissions. That is the most common
reason a non-technical handover gets stuck.

`fetch url` detects an HTML share page masquerading as an archive and says so.
Without that the failure surfaces three steps later as an unreadable archive,
and nobody connects it to having copied the wrong link.

**`inspect` never extracts.** Reading an index is safe; extraction is where
path traversal, symlink escapes and decompression bombs happen. Checking
against the listing means a hostile archive is refused while its contents are
still only names.

Refused outright, no override: `../` members, absolute paths, symlinks. A
backup does not need any of them, so there is no legitimate case to
accommodate.

Flagged: executable PHP in uploads (the strongest single indicator the source
was compromised), Duplicator's `installer.php`, mu-plugins (active on arrival,
no activation step to withhold), `wp-config.php` and core (both discarded at
import in favour of this VM's own), and the expansion ratio against free disk
— because running out mid-import leaves a broken site *and* no import.

Verified against real archives: a clean one passes, one with a webshell in
uploads warns, and the traversal/symlink checks fire on the listing rather
than on extracted files.

`.wpress` is detected and declined with instructions, rather than half-handled.
It is a custom binary format and a shell reader for fixed-width headers is
unpleasant enough to be worth deferring — saying so is better than a partial
implementation that fails obscurely.

---

## Unreleased — Three operational gaps closed

**WordPress now waits for MariaDB to accept connections**, not merely for its
service to have started. `need mariadb-container` satisfies OpenRC as soon as
`podman start` returns, which is 20–60s before the database is ready — a live
VM was observed at `mariadb Up 22 minutes (starting)`.

WordPress reconnects per request so this was self-healing, but the visible
symptom was "Error establishing a database connection" for the first minute
after a reboot: a message that sends people hunting a database fault that does
not exist, appearing at exactly the moment someone is checking whether the
reboot worked. Capped at 60s, then it starts anyway — a container that is up
and erroring is more diagnosable than one that never started.

**`wp-notify.sh --heartbeat` closes the only gap nothing else could.** Every
check in this project runs *on* the VM, so a VM that is off, unreachable, or
on a dead hypervisor reports nothing, and silence is indistinguishable from
health. An external dead-man's-switch inverts that: absence of a ping is the
signal, which is precisely what an on-box check cannot produce.

It verifies WordPress serves and MariaDB answers **before** pinging. A
heartbeat proving only that cron ran would report healthy through a completely
broken site — worse than none, because it converts an outage into a false
assurance.

**`wp-hardening.sh tls` checks certificate expiry from outside.** TLS
terminates at the proxy, so the VM cannot see its own certificate and an
`openssl` check against loopback would test nothing. Going to the public
endpoint also confirms the domain resolves and the proxy answers.

Warns at **14 days rather than 30**, because Let's Encrypt renews at 30 — a
warning there fires on every healthy certificate and is filtered away within a
week. At 14, automatic renewal has had its chance and has not taken it. The
failure message names the most likely cause: an ACME challenge blocked by a
dotfile deny rule, since `/.well-known/` begins with a dot.

`check-heredoc-backticks.py` caught backticks in the new init-script heredoc —
the fourth time that check has fired on the same class, and the third time in
code written minutes after running it.

---

## Unreleased — Gap analysis: disk exhaustion was the sleeper

A systematic pass rather than a summary. The most serious finding is
unglamorous.

**Nothing ever reclaimed dead container images.** Every `update.sh` left the
superseded image on disk — roughly 700 MB each, so five updates is 3.5 GB on
a 20 GB volume. The failure mode is a site that stops working months after an
update, for reasons that look nothing like an update: MariaDB refuses writes
before the disk is actually full, and none of the resulting errors mention
disk.

`update.sh` now prunes dangling images, placed carefully — **after** the
post-cutover health check passes and `wordpress-old` has been removed,
because the old image *is* the rollback path until that moment. Filtered to
`dangling=true` only, so nothing still referenced by a container or pinned in
`pinned.env` is touched; a blunt `image prune -a` would delete exactly what a
rollback needs.

**Disk usage was reported and never acted on.** `wp-hardening.sh disk` shows
what is consuming the volume and what is reclaimable; `disk-check` runs twice
daily and emails once above **80%** — not 95%, because a backup that runs out
of space leaves you with neither the space nor the backup.

**Five gaps recorded in `TODO.md` rather than left implicit:**

- **Boot ordering says "started", not "ready".** `need mariadb-container`
  waits for the service, and `podman start` returns before MariaDB accepts
  connections. A live VM showed `mariadb Up 22 minutes (starting)`. Usually
  self-healing, since WordPress reconnects per request, but the first requests
  after a reboot fail.
- **Nothing knows whether the site is reachable.** Every check runs *on* the
  VM; a VM that is off cannot report that it is off. A heartbeat to an
  external dead-man's-switch would close it — absence is precisely what an
  on-box check cannot detect.
- **No secret rotation.** The incident playbook says "rotate every credential"
  and provides no means to. After a compromise that is manual, touches several
  files that must stay in step, and is the shape of task that gets half-done.
- **TLS expiry is unmonitored.** It terminates at the proxy, so the VM cannot
  see the certificate at all; the first sign of a broken renewal is a visitor's
  browser warning.
- **Restore has not been proven end to end.** The self-test proves a *local*
  backup restores. Nobody has taken an *encrypted, off-VM* copy, decrypted it
  elsewhere, and restored it — and only that second claim is the one being
  made to a client.

---

## Unreleased — Lynis profile, quarantine timeline capture, and triage of the rest

**`lynis-custom.prf`** ships with documented exclusions. Lynis audits a
general-purpose Linux server; this is a single-purpose Alpine VM running three
containers, and several of its findings are structurally impossible here —
separate partitions on a single-qcow2 guest, GRUB on a hypervisor-booted
system, a host web server when Apache runs in a container.

Every skip carries its reason, and the file states the rule for adding to it:
a skip needs a justification that survives being read back in six months by
someone who did not write it. "Noisy" is not one. If the honest reason is "we
have not fixed it yet", it belongs in `TODO.md` as a known gap — a profile
that hides real findings makes the score say the opposite of the truth.

Time synchronisation is explicitly **not** skipped, with a note saying so,
because TLS validation and log correlation both depend on the clock and
somebody will eventually try to suppress it to tidy the report.

`wp-hardening.sh lynis [run]` reads the score and warnings, and says plainly
that the index compares against a general-purpose profile: a trend to watch,
not a target to chase, since digest pinning, the internal database network and
the signed manifest are all invisible to it.

**Quarantine now captures the timeline first.** The file's mtime is the anchor
for everything around it, and once it moves that anchor becomes the quarantine
time instead. This is the step people skip under pressure and cannot recover
afterwards.

**`wp-malware-scan.sh purge [days]`** disposes of old quarantined samples,
kept separate from quarantine deliberately: containment is a decision made in
minutes, disposal is one made after the investigation, and merging them is how
evidence leaves in the same motion as the threat. Timeline captures and the
manifest are always kept — a few kilobytes, and the only record once the files
are gone. Requires typing `PURGE`, and records the purge itself.

**Four ideas triaged in `TODO.md` with reasons rather than silence:** AIDE
(largely redundant against a pinned image and a signed manifest, and its
database is re-baselined by every nightly `apk upgrade`); `lynis_extra=auditd`
(installing a daemon nothing reads, to raise a number, is the argument against
it); LUKS (protects only against a stolen disk image, and every variant either
breaks unattended boot or keeps the key beside the data — Proxmox
storage-level encryption is the honest answer, and off-VM backups are already
age-encrypted where the data is genuinely exposed); and the header-comment
refactor (accepted in part — move historical narrative out, keep decision
rationale inline, because those comments are repeatedly what made a bug
findable).

---

## Unreleased — CTI: timeline enrichment and opt-in ban enrichment

Two additions requested after the base lookup landed, both shaped by the same
40-per-month constraint.

**`wp-forensics.sh timeline --enrich`** looks up the distinct public addresses
appearing in a timeline window. Opt-in per run rather than automatic, because
a window containing a dozen scanner IPs would otherwise spend a quarter of the
monthly budget answering a question nobody asked. Private, loopback and
container addresses are filtered out — they cost a lookup and CTI knows
nothing about them.

**`wp-hardening.sh cti-watch`** enriches new bans and emails them, off unless
enabled at install. It considers **login brute-force bans only**, never
generic `http-probing` decisions: an address that reached the login form and
failed repeatedly is targeting this site, whereas a probing ban is noise
hitting everyone and enriching those is exactly how a month's budget vanishes
in a day.

**The installer defaults ban enrichment to NO below 100 lookups/month**, says
plainly that it is likely to exhaust the budget at the free tier, and points
at the on-demand commands instead. Above that it defaults to yes. Recommending
a feature the operator's quota cannot sustain would be worse than not offering
it.

**`cti-lookup`** added as a machine-readable form sharing the same cache and
the same budget counter. A second code path with its own accounting is how a
quota gets spent twice over, so the interactive command, the timeline
enrichment and the ban watcher all go through one.

The enriched ban notice ends by pointing at
`wp-forensics.sh timeline | grep <ip>` — CTI says what an address does
globally and nothing about what it did here, and those are different
questions.

The CTI key is written to `/etc/wp-install/cti.conf` at 0600 and deliberately
**not** to `vars.sh`, which several tools source and which gets read during
troubleshooting.

---

## Unreleased — CrowdSec CTI enrichment, built around a quota that is 37x smaller than assumed

Requested from the task list, which cited the 2024 announcement: *"request
information up to 50 times a day."* Checking the current documentation first
found that figure is out of date. It is now:

> **Community Plan Free Key — 40 / month.** Unused quota does not roll over.

Roughly **1.3 lookups per day**, not 50. Building against the old number would
have exhausted a month's budget in an afternoon on a site with ordinary
scanner traffic — and the failure would have surfaced as a 429 at the moment
an address actually mattered.

So the quota is the design constraint rather than a footnote:

- **Not wired into ban notifications**, which was the obvious first use and is
  wrong at this quota. A WordPress site bans dozens of addresses a day and
  nearly all are commodity scanners; spending the month confirming that leaves
  nothing for the one that matters. It is an operator command for the address
  in a malware timeline or a repeat offender that reached the login form.
- **Cached 7 days.** CTI describes weeks of observed behaviour, so a
  same-week repeat lookup buys nothing and costs a lookup.
- **A local counter refuses at the budget** rather than letting the API
  refuse. Discovering the quota is gone during an investigation is the failure
  worth designing against; a cached answer is offered instead where one
  exists.
- `cti-key <key> <budget>` for paid tiers, so the guard scales rather than
  being hardcoded to the free figure.

Two behaviours worth calling out in the output. A **404 is informative**, not
an error: the address has not been seen attacking anyone in CrowdSec's
network — not innocence, but not a known mass-scanner either. And
**`false_positives` is surfaced prominently**, because CTI flags crawlers,
monitoring services and CDNs, and permanently banning Googlebot is a
self-inflicted outage.

The output ends by pointing at `wp-forensics.sh timeline`, because CTI
describes what an address does globally and says nothing about what it did to
this site — which is the question an operator is usually actually asking.

Parsing verified against a realistic smoke response, including the
`target_countries` percentage sort and empty-array handling for behaviours and
attack details.

`check-grep-count.py` caught a third instance of
`$(grep -c ...) || echo 0` in this new code — the same idiom, written again by
the person who wrote the check, minutes after running it.

---

## Unreleased — `wp-forensics.sh` and the MSP runbook

Two items from the operator's own task list, and the ones described in most
detail there.

**`wp-forensics.sh`** assembles a timeline from sources already on the VM:
malware findings, the quarantine manifest, file mtimes (uploads and mu-plugins
first, because a change there is almost never legitimate), login-guard events,
Apache denials, POST requests, CrowdSec decisions, and backup timestamps as
the "last known clean" anchor.

It answers what the scanner cannot — *when did this appear, and what was
happening then*. The shape that makes it worth having:

```
21:54:31  POST           203.0.113.9 /wp-content/plugins/x/upload.php 200
21:55:31  file-changed   wp-content/uploads/2026/08/shell.php
21:55:51  scan-CRITICAL  Executable PHP inside uploads
```

Four subcommands: `timeline` (with `--around <file>` for ±1h about a specific
finding, and `--json` for the governance mail), `since-backup`, `admins`, and
`entry-class` — the uploads / plugin / admin / core decision tree written out.

**Three deliberate limits, stated in the tool rather than the docs:**

- **It is not a patient-zero report.** It places events side by side and
  leaves the inference to the operator. Correlation inside a ten-minute window
  is suggestive and routinely wrong, and a tool that asserted a conclusion
  would be confidently wrong on precisely the occasions that matter.
- **It reports where its evidence runs out.** Logs rotate hourly; an intrusion
  older than retention leaves file and database timestamps but no HTTP
  context. Presenting a short window as a complete one is how an investigation
  reaches the wrong answer.
- **It only reads.** Nothing modifies, deletes or quarantines. Deciding what
  happened and acting on it are separate steps, and merging them is how
  evidence gets destroyed by someone in a hurry.

`wp-malware-scan.sh`'s CRITICAL remediation now opens with
`wp-forensics.sh timeline --around <file>` — before quarantine, because the
timeline is the thing quarantining makes harder to reconstruct.

**`MSP-RUNBOOK.md`** covers RTO/RPO with the defaults this system actually
delivers, severity levels mapped to the alerts that exist, change control,
exception review and decommissioning.

Two things it says that a template would not. The **compromise RTO is
deliberately vague**, because restoring takes minutes while establishing when
the compromise began — which decides which backup is clean — takes as long as
it takes, and a tight RTO is what pressures someone into restoring a backup
that still contains the backdoor. And the client-facing summary has a
**"cannot" column**: no guarantee against compromise, nothing detects a
backdoor written for this site, ~46% of plugin vulnerabilities have no patch
at disclosure. A client who believes they bought immunity will be angry about
the wrong thing.

Decommissioning is ordered so the last step destroys the evidence for the
earlier ones, and it keeps the stopped VM through a retention period, because
"one more thing from the old site" arrives after shutdown rather than before.

---

## Unreleased — WEB_CIDR takes a list; admin can reach the VM directly

Reported: restricting 80/443 to the proxy produced a **403 on wp-admin** while
the public site kept working, from addresses explicitly on the allow list.

The cause is the fail-closed rule added earlier. Through the proxy, Apache
only knows the client because `X-Forwarded-For` told it. When that
substitution is not happening, Apache sees the **proxy's** address — and the
rule now explicitly denies it. Before, that same condition silently allowed
everyone; now it denies everyone, including the operator. Failing closed is
right, and this is what failing closed costs when the substitution is broken
rather than merely absent.

**The operator's proposed fix was the correct one**, and better than repairing
the substitution: allow their own addresses to reach 80/443 **directly**,
alongside the proxy. A direct request has no proxy in the path, so there is
nothing to substitute and nothing to get wrong. Apache reads the real client
address off the connection.

External visitors are still funnelled through the proxy, because their
addresses are not on the list — the property that was wanted is kept.

- `WEB_CIDR` now accepts a comma-separated list, which nftables treats as an
  anonymous set in both the input and forward rules.
- The installer offers this automatically when the proxy lock is chosen,
  pre-filled from the admin CIDR and extra admin IP already given, with the
  reasoning stated: without it, every admin request depends on the proxy
  passing a header correctly, and the failure mode is a 403 on a site that
  otherwise looks completely healthy.
- `wp-hardening.sh web-list | web-allow <ip> | web-deny <ip>` manages it live.
  It edits **both** the input and forward rules — editing one leaves them
  disagreeing, and the forward rule is the one that actually decides for a
  published container port. It refuses to remove the proxy address, since
  that takes the site offline for every visitor rather than just the
  operator, and it validates with `nft -c` before applying, restoring the
  backup if the edited ruleset does not parse.

---

## Unreleased — Security headers were set on the VM and never reached the internet

An external scan of a live deployment, alongside a clean local report
(12 pass, 0 fail), showed something the VM's own checks cannot see:

```
contentSecurityPolicy : False        server: openresty
xFrameOptions         : False        strict-transport-security: max-age=63072000; preload
xContentTypeOptions   : False
referrerPolicy        : False
permissionsPolicy     : False
```

WASP sets CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
Permissions-Policy in Apache. **None of them reached the client.** The only
security header present was HSTS, which the proxy adds itself.

The VM was configured correctly throughout, and every local check passed —
because they all confirm the header is *configured*, and none confirms it is
*received*. Same shape as the WEB_CIDR and wp-admin failures: correct on the
box, absent in effect.

**Fixed by setting them at the edge as well**, in the generated nginx snippet
and the README reference. `proxy_hide_header` before each `add_header`,
because nginx appends rather than replaces and a duplicated header is
resolved differently by different browsers. `always`, so they are sent on
error responses too — a 403 page is still a page a browser renders.

**CSP is deliberately not duplicated at the edge.** The VM tailors it per
path: wp-admin needs `unsafe-eval` and the public site does not. One blanket
policy would either break the admin interface or weaken the public site to
match it. The README gives the command to verify it arrives instead.

**HSTS was invalid.** The scan found `max-age=63072000; preload` **without**
`includeSubDomains` — which is not merely weaker, it is rejected by the HSTS
preload list. The `preload` directive was doing nothing at all. Corrected,
with the warning that it should only be enabled once every subdomain serves
HTTPS.

**`wp-hardening.sh security-txt <contact>` added** (RFC 9116), flagged missing
by the same scan. It writes the `Expires:` field the RFC requires and everyone
forgets — a stale security.txt is worse than none, because it tells a
researcher the contact is current when it may not be.

And a trap avoided: the dotfile deny rule in the reference config
(`location ~* /\.(git|env|svn|ht)`) would have blocked `/.well-known/`,
taking security.txt and ACME challenges with it. A `^~` prefix match is now
placed above it.

Worth recording: **DNSSEC is enabled on the domain** (DNSKEY, DS and RRSIG all
present). That materially strengthens the minisign key cross-check, which
until now had to be described as corroboration because plain DNS is spoofable.

---

## Unreleased — Branding, VM notes, and a heredoc that would have run 27 commands

Logo added at `docs/wasp-logo.png` and used in the README header.

**The Proxmox VM description is now a real page**, not a one-line summary.
Proxmox renders that field as Markdown and it is the first thing anyone sees
on the VM, so it now carries the logo linked to the repository, the build
number, **the login URL for this build**, five things to do next, a command
cheat sheet, and a lockout table mapping 403 / 503 / 502 / SSH-refused to
their actual causes.

The login URL is there specifically because of the session that prompted
this: a VM served `/<slug>-login` while the operator visited `/<slug>`, and
nothing on screen said which build was installed.

**The first draft of that block was a serious bug.** It used an unquoted
heredoc containing Markdown code spans — and
`test/check-heredoc-backticks.py` reported **27 backticked commands that would
have executed on the Proxmox host** while building the VM description:
`doas validate-wordpress.sh`, `qm snapshot`, `podman logs`, and the rest. The
render confirmed it: the output was littered with "command not found".

Rewritten as a **quoted** heredoc with `@@PLACEHOLDER@@` tokens substituted by
`sed` afterwards. The document is inert; nothing in it can be interpreted.
That is the right pattern for any generated document containing shell syntax,
and it is what the earlier nftables incident should already have taught.

Worth noting the check was written after that earlier incident and has now
caught the same class twice — the second time in code written by the person
who wrote the check, minutes after running it.

**The installer intro now states who this is for and who it is not.** An MSP
or consultant where a compromise is a 2am phone call; anyone running WordPress
on their own hardware who would rather not become an incident responder. And
not: throwaway test sites, shared hosting, or anyone wanting a one-click
install with no decisions — several prompts here have consequences worth
reading, and saying so is more honest than implying it is effortless.

---

## Unreleased — Builds are identified now, and the validator probed the wrong URL

Requested after a long, avoidable diagnosis. A VM installed from an earlier
build served its login page at `/<slug>-login`; a later build moved it to the
bare `/<slug>`. Several hours went into imagined faults in mod_remoteip,
nftables chains, `limit_req` and `X-Forwarded-Proto` before anyone established
**which of the two was actually running**. The operator was simply visiting a
URL that build did not serve.

`WASP_VERSION` is now declared in `install.sh`, written to `vars.sh`, and
printed by the install banner, the validator header and the test report —
alongside a short note naming the behaviour most likely to differ. A log that
does not state its build cannot be reasoned about safely, and this project has
now proved that at cost.

**A real bug found while doing it:** `validate-wordpress.sh` still probed
`http://127.0.0.1/${WP_ADMIN_SLUG}-login`. It was never updated when the
suffix was removed. On a current build it would report a 404 for a slug that
works; on an older build it printed a URL that no longer exists. Both are
routes to an operator concluding they are locked out of a working site — and
in this case it printed the *old* URL, which was the only correct instruction
on screen while everything I was saying was wrong.

The test report now also prints the login URL derived from the installed
configuration, so the right path is in front of the operator before anything
else is interpreted.

Two stale comments referring to `/slug-login` were corrected. Remaining
`*-login` matches are filenames (`wpvm-login.yaml`,
`02-wpvm-login-guard.php`) and the literal `wp-login.php`, which are correct.

---

## Unreleased — SECURITY: WEB_CIDR permitted the entire LAN

Proven on a live VM. With `WEB_CIDR=192.168.100.101`, a curl from
`192.168.100.148`:

```
* Established connection to 192.168.100.100 (port 80) from 192.168.100.148
```

and the loaded ruleset containing, plainly:

```
ip saddr { 192.168.100.101 } tcp dport { 80, 443 } accept
```

The rule is real, loaded and readable. It matches nothing.

**Podman publishes a container port by DNAT'ing it in prerouting.** After DNAT
the destination is the container's address rather than the host's, so the
packet traverses the **FORWARD** hook — the filter **INPUT** chain never sees
it. Every `WEB_CIDR` restriction written since this feature was added has been
a no-op for the published web port, while reading as a working rule and
passing every check.

This is the third instance of the same shape: the wp-admin restriction failing
open when mod_remoteip stopped substituting, the login rate limiter counting
every visitor as one address, and now this. In all three the control was
present, correct-looking, and permissive — and in all three the automated
checks confirmed presence rather than effect.

**Fixed** by enforcing in the forward chain, placed *before* the blanket
`ip daddr 10.89.10.0/24 accept` or it would never be reached. The negated set
excludes loopback and the container networks so host-local health probes and
container-to-container traffic are unaffected; only genuinely external sources
outside `WEB_CIDR` are dropped, with rate-limited logging.

**The validator now checks the FORWARD chain specifically**, and fails with an
explanation if it finds the restriction only in `input` — because "the rule
exists somewhere in the ruleset" is precisely the evidence that made the
broken version look correct for weeks.

Worth stating plainly: this was found because the operator ran a curl, not
because anything in this repository noticed. Every static check passed
throughout.

---

## Unreleased — libmaxminddb installed with GeoIP

Reported: `geoip-test 8.8.8.8` answered *"mmdblookup is not installed, so the
address cannot be resolved"*. Fair — a diagnostic that stops to tell you to
install a diagnostic is a poor trade for 100 KB, particularly when the thing
it is diagnosing was just enabled in the same run.

`wp-geoip-setup.sh` now installs `libmaxminddb` on the host as part of
enabling GeoIP, so the test works the first time it is run. It is host-side
only and touches nothing in the containers.

`wp-hardening.sh geoip-test` also now offers to install it inline when it is
missing, for VMs that predate this.

---

## Unreleased — Backup encryption was configured and silently not applied

The most serious defect found so far, from a live test report. `vars.sh` held
a valid recipient:

```
OFFSITE_AGE_RECIPIENT='age1ug0zyaemm56h0eweg8av4tl00untqr7tw8ugmp3vze2wtmtpfecqhquh6s'
```

and the bucket listing showed four `.sql.gz` archives and no `.age`. Database
dumps — password hashes, user emails, private post content — had been going to
Cloudflare R2 **in plaintext** while the operator had explicitly asked for
encryption.

**Cause: one line in the wrong place.** `AGE_RECIPIENT="${OFFSITE_AGE_RECIPIENT:-}"`
sat at line 58; the config file it comes from is sourced at line 103. The
variable was therefore always empty, `_encrypt_for_upload` returned the
plaintext path unchanged, and every upload skipped encryption.

What made it survive: `status` reported **"Encryption : NONE"** perfectly
truthfully. That reads as *"you did not configure this"*, not as *"your
setting is being ignored"* — so the honest output actively concealed the bug.

Fixed by reading the value after the config loads, with the ordering
demonstrated in the comment so it is not reintroduced.

**Three false alarms in `wp-mail.sh status`, all in one screen:**

- `File mode: 440 root:UNKNOWN ⚠ expected 440 root:www-data`. GID 33 is
  `www-data` on Debian but has **no name on Alpine**, so `stat %G` returns
  `UNKNOWN` and a name comparison can never match. The container is Debian and
  the host is Alpine; numbers mean the same on both. Now compares `%u:%g`
  against `0:33`. `validate-wordpress.sh` got this right and passed the same
  file.
- Same fault on the directory line.
- `mu-plugin: MISSING ⚠` — `MU_PLUGIN` was **never assigned**, so the test was
  `[ -r "" ]`, always false. The validator confirmed the same file present and
  parsing two sections earlier. Now checks the real path and, beyond presence,
  whether PHP can parse it.

**`wp-notify.sh: NOTIFY_COOLDOWN_HOURS: parameter not set`** — the default was
removed by an earlier edit replacing the `_cfg()` helper, and under `set -u`
that killed `--status`: the command an operator runs to confirm notifications
work. Restored.

A status screen reporting faults that are not there is worse than one saying
nothing. It sends someone to fix working components while a real problem —
here, unencrypted backups leaving the VM — sits three sections below reported
as a non-event.

---

## Unreleased — The login-guard test was testing the wrong thing

Full report run on hardware: **12 pass, 1 fail.** The failure was in the test,
not the guard.

It POSTed to `http://127.0.0.1/wp-login.php` from inside the container and
then looked for the resulting log line. That cannot work: `wp-login.php` is
IP-restricted, the request originates from the container's own address, Apache
returns **403 before PHP runs**, and the guard never executes. So it reported

> no wpvm-login entries — guard may not be active

for a guard that was fine, and the same VM's own diagnostic had already shown
`wp-login.php -> HTTP/1.1 403 Forbidden` from inside, which is the correct
answer.

A test that must defeat one protection in order to exercise something else is
testing the wrong thing. Replaced with a direct question to WordPress —
whether the guard's functions exist and whether its `wp_login_failed` hook is
registered — which proves it is active without needing to reach a page that is
deliberately unreachable from there.

A second, separate check now reports whether any real login events have been
recorded, and says plainly that none is expected until someone reaches the
login form. Where there are none it prints the two commands that prove the
CrowdSec parser matches using a synthetic line, so the detection chain can be
verified without a working login.

**Also fixed:** the report's closing notes still told the operator to browse
`/<slug>-login`, which stopped being the login URL when the suffix was
removed. Stale instructions in a test report are worse than none — they send
someone to a 404 and cast doubt on everything else in the output.

**Still outstanding on that VM:** `remoteip-debug.log` is empty, so
`proxy-check` cannot yet say whether client addresses are being substituted
correctly. That needs one successful request through the domain, which the
redirect loop has been preventing.

---

## Unreleased — CrowdSec parser confirmed loaded; timestamp capture added

Both custom rules are live on the VM:

```
rothitguy/wpvm-login-logs         enabled,local
rothitguy/wpvm-login-bruteforce   enabled,local
```

That settles the earlier path bug — the files are somewhere the container can
read, and CrowdSec has parsed and enabled them.

**The 🔴 "parser failure" markers in `cscli explain` are correct behaviour, not
a fault**, and worth writing down because they read alarmingly. `explain` took
the last ten lines of the error log, and every one was an Apache startup
message or an authz denial — `AH00170`, `AH00163`, `AH01630`. None contains
`[wpvm-login]`, so this parser declines them, and 🔴 means "no parser claimed
this line". A parser that matched Apache's own startup noise would be the bug.

There are no login events to test against yet because the redirect loop has
prevented anyone reaching the login form.

**A real defect the same output exposed:** every line warned

> Line N is missing evt.StrTime ... will prevent your logs being processed in
> time-machine/forensic mode

The grok captured event, IP and username but not Apache's timestamp. Live
detection was unaffected — CrowdSec falls back to arrival time — but replaying
a log after an incident, which is precisely when you want it, would have had
nothing to order events by.

Fixed by capturing the leading `[%{DATA:apache_ts}]` and setting
`evt.StrTime` from it, so `s02-enrich/dateparse-enrich` can normalise it.
Verified the pattern still matches real `failed` and `lockout` lines, extracts
the timestamp, and still correctly declines Apache's own log lines.

---

## Unreleased — Three instructions were wearing a warning glyph

The operator asked to look at "the CrowdSec errors". There are none. Every
CrowdSec check in that run passed: LAPI up, bouncer key generated, service
running, bouncer connected, container up, enrolled, whitelist written, and
both post-install validation checks green.

What produced the impression was three lines printed with `warn`:

```
⚠    Untested against live traffic. Verify the parser once the VM is up:
⚠      doas podman exec crowdsec cscli explain ...
⚠      doas podman exec crowdsec cscli scenarios list | grep wpvm
```

Those are a to-do, not a failure. A warning marker on an instruction sends
someone hunting a problem that does not exist — which is precisely what
happened, in the middle of an already-long debugging session. Changed to `ok`,
and the command corrected to `cscli parsers list`, which is what actually
answers "did the parser load".

One other instance of the pattern was checked and left alone: the MaxMind
block in `lib/01` uses `msg_warn` for "GeoIP will be SKIPPED" followed by the
command to enable it later. There the warning is genuine — a control the
operator asked for is not active — and the command is part of the remedy
rather than a bare instruction.

Small, and worth fixing: this project asks operators to read a lot of install
output, and that only works if the severity markers mean what they say.

---

## Unreleased — The 502 was an infinite redirect_to loop, caused by the bare slug

From the operator's session:

```
/xlzr?redirect_to=…/xlzr?redirect_to=…/xlzr?redirect_to=… &reauth=1
502 bad gateway
```

and, decisively, *"with no custom nginx configuration still 502"* — so not the
proxy.

**Cause, and it is a consequence of removing the `-login` suffix.** With the
bare slug, the login page and the URL WordPress redirects unauthenticated
users to are **the same URL**. When `wp-login.php` decides a reauth is needed
it redirects to `wp_login_url($redirect_to)`, where `$redirect_to` is the
current `REQUEST_URI` — which already contains a `redirect_to`. Each pass
nests another copy, the URL grows exponentially, and it eventually exceeds the
proxy's header buffer. nginx then answers **502**, which looks like a backend
fault and is not one.

With `<slug>-login` this could not happen: the entry point and the login page
were different URLs, so the redirect terminated. That consequence was not
obvious when the suffix was removed, and it is recorded here rather than
quietly patched — the obscurity argument for removing it still holds, but it
had a cost that needed paying separately.

**Fixed in the slug mu-plugin**, two independent ways:

- `login_init` at priority 1 replaces a `redirect_to` that points back at the
  login page with `admin_url()`. Being sent to the login form *after* logging
  in is meaningless, so nothing is lost. Triggers on the login slug,
  `wp-login.php`, any already-nested `redirect_to`, or a value over 512
  characters — the last being a catch-all for whatever else might produce this
  shape.
- A `wp_redirect` filter at priority 200 refuses to emit any location
  containing more than one `redirect_to`, stripping the query entirely.

Verified against six shapes: normal and deep admin targets are preserved;
login-slug, `wp-login.php`, already-nested and absurd-length values are
replaced.

---

## Unreleased — Self-test passes 18/18 on hardware; xmlrpc status was lying

`wasp-selftest.sh all` on a real VM: **18 passed, 0 failed.**

Both guarantees are now proven against real data rather than reasoned about:

- **Backup restore** — 12 tables restored into a throwaway instance, `siteurl`
  present, users and posts intact, and row counts consistent with production
  (4 vs 4), so a silently shrinking backup would have shown.
- **Off-VM copy** — *"Newest backup is also present off-VM, same size."*
- **Candidate DB isolation** — INSERT, UPDATE, DELETE, CREATE and DROP all
  correctly denied, and the account cannot reach the production database.

Quietly the most significant line is `Table prefix: wpebd2cd_`. That is the
randomised per-install prefix, read from inside the container — confirming the
fix for expanding container variables on the host, which had left four
features inert while reporting success.

**`wp-hardening.sh status` was under-reporting xmlrpc.** It grepped for
`xmlrpc.php.*Require all denied` on a single line, but the directive spans
three:

```apache
<Files "xmlrpc.php">
    Require all denied
</Files>
```

So it printed `OPEN` for a file that had been blocked since install. A status
check that under-reports protection is worse than none — it prompts an
operator to "fix" something already correct, and in this case appended a
redundant second block. Replaced with a multi-line-aware check, verified
against configs with and without the directive.

**Two smaller fixes from the same session:**

- `wasp-selftest.sh` now takes a backup when none exists instead of reporting
  FAIL. The observed sequence was: first run fails, operator takes a backup,
  re-run passes 18/18 — a FAIL for "you have not done the prerequisite" is
  noise that teaches people to skim the output.
- `wasp-testreport.sh` is now shipped in `payload/bin/` and installed to
  `/usr/local/bin`. It had been delivered as a standalone file, so the VM
  answered `command not found`.

`check-grep-count.py` caught a `$(grep -c ...) || echo 0` in
`wasp-testreport.sh` — written before that check existed. The check found it
the first time the file entered the tree.

---

## Unreleased — A shipped file was unsigned, and the manifest design caused it

Raised as the most urgent defect in a fifth evaluation:
`payload/mariadb-conf/wp.cnf` is not in the signed manifest.

Correct, and the file is not the interesting part. The manifest selected files
by **extension allowlist** — `*.sh`, `*.php`, `*.yar`, `*.yaml`, `*.conf`,
`*.ini`, `*.tmpl`, `*.cron` — and `.cnf` was not among them. An allowlist
inverts the failure mode: anything it does not name is silently unsigned, and
nothing complains. A modified MariaDB config could weaken the database — bind
address, `local-infile`, TLS settings — while every signature check passed.

The selection is now **everything under `install.sh`, `lib/` and `payload/`**
with no extension filter, because that is exactly the set `install.sh`
executes or copies onto the VM. Documentation lives outside those paths, so
nothing needed excluding; the filter added risk for no benefit.

**`test/check-manifest-coverage.py` added.** It re-derives the shipped set and
fails if a manifest exists that does not cover all of it, and also flags stale
entries for files that no longer exist. Verified against a tree reproducing
the exact gap. It runs automatically, since `run-all-checks.sh` discovers
`test/check-*.py`.

**`INCIDENT-PLAYBOOK.md` added**, also from that evaluation. Written for the
person on call rather than someone holding the whole system in their head:
what each alert means, what to do first, and what **not** to do — several of
the tempting moves (deleting the malicious file, updating to "clean" it,
restoring immediately) destroy the evidence of the entry point, and a restored
site with the original vulnerability is compromised again within days.

It includes a **RACI**, expressed as roles so it survives someone leaving.
Two separations are deliberate and stated: a vulnerability exception is the
operator's to make and governance's to own, because the system can enforce the
record but not that a conversation happened; and taking a site offline is the
site owner's call, because the commercial consequence is theirs. Agreeing that
threshold in advance is the point — 02:00 is the wrong time to discover nobody
can authorise it.

---

## Unreleased — The 503 was my nginx rate limit, and it was mine twice over

Resolved from the VM's own output. `wp-login.php` returns **403** when queried
from inside the container, `apache2ctl configtest` says **Syntax OK**, and
there is no 503 anywhere in the error log. Apache never emitted one. The
`Require not ip` rule was innocent, as was every other thing suspected on the
VM side.

**`limit_req` returns HTTP 503 by default**, and the snippet applied
`rate=6r/m burst=3` to a location matching
`^/(wp-admin/|wp-login\.php|SLUG)` — which matches every asset the login page
loads: `login.min.css`, `load-styles.php`, `load-scripts.php`, the logo, the
spinner. A single page load is a dozen or more requests against a six-per-
minute budget. It exhausted itself, and everything after got 503. The front
page kept working because it did not match the location, which is exactly the
reported symptom.

Two separate errors in one snippet:

- **Scope.** Rate limiting an admin path counts static assets. Fixed with a
  `map $request_method` so the zone keys on POST only — an empty key is not
  rate limited, so GETs pass freely and only the actual login submission is
  counted, which is the thing worth limiting.
- **Status.** `limit_req_status 429` was present in the location block but
  commented out along with the rate limit in the previous fix, leaving the
  default. A rate-limited client should be told to slow down, not that the
  service is broken — and a 503 sent an operator hunting a backend outage that
  did not exist.

The rate limit is now uncommented by default, because it is safe once
POST-scoped.

**Also added:** a triage step that settles nginx-versus-VM in one command, by
querying `wp-login.php` from inside the container. A 403 there is the *correct*
answer — the request comes from an address not in the allow list — and proves
the VM is healthy.

Worth recording: three guesses preceded this (the proxy IP, the zone ordering,
the strict authz rule), all plausible, all wrong. One command run on the
affected machine settled it. The diagnostic should have come first.

---

## Unreleased — 503 narrowed to wp-login.php; live rule toggle added

More detail from the operator changed the diagnosis: the site loads,
`/wp-admin/install.php` works, and only the custom slug and the login page
return 503 — on the LAN and off it.

That rules out most of what was suspected. Apache is running. The IP
restriction is passing, or `install.php` would fail too, since it sits inside
the same `<DirectoryMatch>`. What the two failing paths share is that both end
at **wp-login.php**: the slug rewrites to it, and `/wp-admin/` redirects to it
when not logged in. `install.php` does neither.

Nothing in the generated config emits 503 explicitly, so it is coming from
Apache's authorization layer or from PHP — and the honest position is that it
cannot be determined from the source alone. Guessing again would be the second
wrong guess this session, after a fix keyed to `DEPLOYMENT_PROFILE` that could
never have fired.

**`wp-hardening.sh admin-rule [show|strict|simple]` added** so the question can
be answered in one command instead of a reinstall. It switches the
wp-admin/wp-login authorization between the fail-closed form (which uses
`Require not ip`) and the plain allow-list, live, keeping a timestamped backup.
If `simple` clears the 503, the `Require not ip` construct is the cause on this
Apache build and can be replaced with something equivalent. If it does not, the
cause is elsewhere and the strict rule is exonerated.

`simple` states plainly that it restores the fail-OPEN behaviour and is for
isolating a fault, not for living in.

**Documentation:** a full Nginx Proxy Manager reference section, since
"recommended settings" had only existed as generated output. It covers the
ordering constraint that caused the earlier 503 (zone file first, restart,
confirm, then the location block), the admin-path restriction at the edge,
`X-Forwarded-For $remote_addr` rather than NPM's appending default, denials for
`wp-config.php`/dotfiles/executable uploads, which NPM toggles matter and why,
and a 503 triage sequence that starts by saying 503 is not the IP restriction.

---

## Unreleased — The nginx snippet could 503 the entire host

Reported: blocked from the admin path on cellular *and* getting **503 on the
LAN**. The 503 is the part that matters — a `Require` denial returns 403, so
this was never the IP restriction. 503 is nginx reporting it could not reach
the backend, or that its own configuration failed to load.

The Apache side checks out: `<RequireAll>` containing `Require not ip` plus a
nested `<RequireAny>` is valid 2.4 syntax, and renders correctly for both the
`wp-admin` and `wp-login.php` blocks.

**The snippet I generated had an ordering trap.** It printed the `location`
block as section 1 and the `limit_req_zone` definition as section 2. Anyone
following it top to bottom pastes a server block naming a zone that does not
exist yet — and nginx refuses to load that block entirely, so NPM answers 503
for the **whole host**, not just the admin path. The site goes down.

Three changes so a partial application cannot do that:

- The zone file is now **section 1** and the location block **section 2**,
  with an explicit instruction to restart NPM and confirm the site still loads
  in between.
- The `limit_req` lines are **commented out by default**, with the reason
  inline. Uncommenting them is a deliberate step taken after the zone exists.
- A "If you get 503 after applying this" section states plainly that 503 is
  not the IP restriction, and says to clear the Advanced tab first and reapply
  one piece at a time.

Worth recording as a general point: a configuration snippet with a
cross-file dependency is a snippet that will be applied wrongly. Printing the
dependency second made that near-certain, and the failure mode was the whole
site rather than the feature.

---

## Unreleased — Container variables expanded on the host: four features were inert

From a real VM session. Several failures with one root cause, and it is the
most consequential bug class in this project so far because everything
affected reported success.

**`MARIADB_ROOT_PASSWORD` only exists inside the mariadb container.** The
original scripts knew this — `wp-db-backup.sh` and `mariadb-health-check.sh`
single-quote the command so the container's shell expands it. Every script I
added since expanded it on the host, where it is empty, producing
`mariadb -p""`.

That fails as **"no rows"**, not "access denied". So:

- `wasp-selftest.sh` reported *"siteurl missing from the restored options
  table"* and *"restored users table is empty"* against a restore that was
  perfectly fine
- `wp-malware-scan.sh`'s database layer returned clean on every run without
  ever querying anything
- `update.sh`'s read-only candidate account was never created — the feature
  guarded itself on a variable that is always empty, so it silently did nothing
- the Trivy exception CVE capture returned nothing

Four features that appeared to work and did not. Fixed with a shared `_mdb`
helper that runs the query inside the container, plus the same pattern applied
in `update.sh`.

**The table prefix was also wrong.** Installs generate `wp<hex>_`, randomised
per install; the new code defaulted to `wp_`, which matches no table. Now read
from the container.

**`wp-notify.sh` was entirely broken:** `SECRETS_DIR: parameter not set`. The
`_cfg()` helper was copied from `wp-mail.sh` complete with a reference to a
variable only that script defines. Every notification path failed — so none of
the email alerting worked. A one-line default, and a reminder that copying a
helper between scripts copies its assumptions too.

**`note: not found`** in `validate-wordpress.sh`: the function was defined at
line 711 and called at 687. Shell resolves a function name when the call
executes, so `bash -n` accepts it and it fails at runtime. Moved up beside the
other reporters.

**`test/check-function-order.py` added** for that last class. Its first version
used indentation as a proxy for nesting and reported four false positives —
calls inside function bodies, which are resolved when that function runs and
are therefore fine. Rewritten to track brace depth and consider only true
top-level calls. Verified it still catches the real shape while passing the
clean tree.

---

## Unreleased — Exception governance: closing the loop, not adding a workflow

The operator's read was right — approval belongs out of band, and a
request-and-approve workflow built into an installer would add ceremony
without adding oversight while being trusted as though it were real. So no
workflow was added. Three gaps that stopped the existing design working as a
review process were closed instead.

**1. The record said a decision happened, not what was decided.** The log and
the email carried the image, the reason and the expiry, but not *which
vulnerabilities* were accepted — so a reviewer could not judge whether the
reason still applied, which is the only question a review asks. Trivy is now
re-run in JSON to enumerate the accepted CVEs (cheap, the cache is warm), and
they go into both the log line and the email body.

**2. The log was write-only.** Nothing read it back. A governance process that
records decisions and never surfaces them is a filing cabinet.
`wp-hardening.sh exceptions` now lists every exception with its status —
active, expiring within 14 days, or expired — with the CVEs, the reason, who
accepted it and when.

**3. Expiry happened silently.** An exception lapsed and nobody knew until an
update was blocked by it, which is the worst moment to be re-arguing a
decision. A weekly job now emails 14 days ahead, and stays silent otherwise —
including about entries that have *already* lapsed, which are not news.

Verified the date classification against real dates: an exception 80 days out
reads active, one 7 days out reads expiring, one from April reads expired, and
the cron would email about exactly one of the three.

The remaining gap is recorded in `TODO.md` rather than papered over: nothing
here can verify that the stated justification was genuinely discussed with
anyone. That is a property of the process around this system, not of the
system.

---

## Unreleased — Reverted on-VM key generation; documented it properly instead

Generating the age keypair on the VM was convenient and it weakened the one
property that made public-key mode worth choosing: that this host holds only
the public half and cannot read what it sends. Even generating into a shell
variable rather than a file, the secret existed on the VM and on its terminal.
Reverted at the operator's call, which was the right one.

`init` now prompts for the public key and **refuses** an `AGE-SECRET-KEY` —
refuses, not warns — because accepting one would discard the property silently
while appearing to work perfectly.

**Everything else from that change is kept.** SSH key generation stays on the
VM: a key made where it is used and never transmitted has no window in which
it existed elsewhere, and only the public half travels. `restore` stays in
full — fetch, decrypt with a key supplied for that one operation, verify gzip
integrity, and either write to a file or replace the live database behind a
pre-restore backup and a typed `REPLACE`.

**Key creation is now documented per platform**, since "generate it on your
own machine" is only actionable if the reader knows how on theirs: Debian,
Ubuntu, Fedora, RHEL, Arch, openSUSE, Alpine, immutable Fedora variants via
Homebrew, macOS via Homebrew or MacPorts, Windows 11 via winget or Scoop, and
Windows Server via the release zip — including the TLS 1.2 line older Server
builds need before `Invoke-WebRequest` will reach GitHub.

Each section says where to read the public key back out if the terminal has
scrolled, states that the private key belongs in a **third** location — not the
VM, not the backup bucket, since an attacker may hold both — and ends with the
decrypt test to run before relying on any of it.

**A structural error was introduced and caught during the revert:** removing
the generation block also removed a `case`/`esac` and a closing `fi`, leaving
the function unparseable. `sh -n` failed immediately, which is the one class of
bug it reliably catches.

---

## Unreleased — `wasp-offsite-backup.sh init` and `restore`

**`init`** sets up transport and encryption in one pass: generates the SSH key
on the VM, prints the `authorized_keys` line to install remotely, generates an
age keypair, pins the destination host key, and writes the config.

The `authorized_keys` line it prints includes the
`command="rrsync -no-del ...",restrict` prefix, with an explanation of why —
without it the key can run anything, and anyone who takes root on the VM can
delete every backup it ever sent. That prefix is the difference between a copy
that survives a compromise and one that only survives a disk failure, and it
is the part an operator is most likely to omit when following instructions
from memory.

**On generating the age key here at all.** The security property of
public-key mode is that this VM holds only the public half and cannot read
what it sends. Generating the keypair on the VM puts the private half here,
however briefly, which is a real weakening of that. It is done as carefully as
the convenience allows: `age-keygen` writes to a shell variable rather than a
file, so the secret never touches this VM's disk — it exists in process memory
and on the terminal. The operator must type `SAVED` before it is dropped, and
the caveat that a logged terminal captures it is stated rather than glossed.
Pasting a key generated elsewhere remains available and remains stronger.

**`restore`** closes the loop the encryption opened. The VM cannot decrypt on
its own, so the private key is supplied for that one operation: read into a
variable with echo off, written to a temp directory only for the duration of
the `age -d` call, removed immediately. `--key-file` covers the
non-interactive case.

Two safeguards on `--to-database`, which replaces the live database:

- **A backup of the current state is taken first, unprompted**, and the
  restore refuses to proceed if that fails. Restoring the wrong archive is
  recoverable only while the thing being overwritten still exists.
- Typing `REPLACE` is required, after the pre-restore backup has succeeded.

Gzip integrity is checked after decryption and before anything is loaded, so a
wrong key or a truncated download fails without touching the database.

---

## Unreleased — ARCHITECTURE.md brought current (it had drifted badly)

Asked directly: had the diagrams been updated? They had not, and the gap was
worse than a missing box. Signing, off-VM backup, the self-test, the notifier
and the integrity checker were all absent — the evaluation's *"signing
architecture is not fully represented"* was understated.

Documentation that describes a system as it was two weeks ago is worse than
none: a reader trusts it, and it is confidently wrong.

**New: section 3, the release trust chain.** Signing had been implemented but
never *drawn*, so a reader could not see where trust starts or stops. The
diagram now shows the secret key never leaving the maintainer's machine, the
public half published under separate credentials at the registrar, the
embedded key in `install.sh`, both verification gates and what each refusal
does — and says in prose that a first-time user fetching `install.sh` and the
release from the same repository is still trusting that repository. Signing
makes a swap *detectable*, not impossible. Where it stops is stated as plainly
as where it starts.

**Component diagram** gains the backup path and the off-VM destination,
annotated `append-only recommended` since that is what separates protection
from loss and protection from malice.

**Update diagram** gains the temporary SELECT-only database account, so the
candidate step no longer implies it runs against production data unrestricted.

**Tooling map** gains `wasp-offsite-backup.sh`, `wasp-selftest.sh`,
`wasp-verify-integrity.sh` and `wp-notify.sh`, each with the property worth
knowing — that the VM cannot decrypt what it uploads, that the restore proof
uses a real restore, that notification is host-side so it survives WordPress
being down.

Validated after every edit: subgraph/`end` pairing, every `style` target
resolving to a declared node, balanced fences. One error was introduced and
caught this way — an inserted `end` closed the VM subgraph early, leaving the
backup nodes outside it, which would have rendered as a detached fragment
rather than failing visibly.

---

## Unreleased — Signature verification fails closed; lockout no longer punishes shared NAT

A fourth evaluation, against a day-old archive. Several of its findings were
already closed (executable PHP SMTP config, informal Trivy exceptions,
read-only candidate account). Two were not, and both were right.

**Critical — signature enforcement was fail-open.** Its wording is the useful
part: *"the strongest production control dependent on an operator remembering
an environment variable."* That is exactly backwards from how everything else
here behaves.

The first attempt at a fix keyed the decision off
`DEPLOYMENT_PROFILE=production`, matching Alpine's SHA-512 check, digest
pinning, the CrowdSec bouncer and the sysctls. **That would never have
fired**: verification runs at install.sh line 295, during the self-bootstrap,
and the profile is not chosen until lib/01 at line 1262. Verification has to
happen before anything is sourced, which is precisely why it cannot consult an
answer collected afterwards.

So the default is now to **refuse**, and proceeding requires typing
`UNVERIFIED`. A warning that scrolls past is not a decision; a prompt that will
not accept Enter is. Non-interactive runs abort outright — an unattended
install cannot meaningfully consent to executing unverified code as root —
unless `WASP_ACCEPT_UNVERIFIED=1` is set deliberately.

**High — IP-only lockout punished shared NAT.** Also correct, and worse than
it sounds: under carrier-grade NAT a mobile visitor sharing an address is the
normal case, not an edge case, so an attacker could lock out every legitimate
user of an office or carrier network by failing five logins.

Lockouts are now scoped to **IP and username together**, so hammering `admin`
cannot lock out `editor` from the same address. A second, much looser
address-wide tier (6× the per-account threshold) still catches username
spraying, which a per-pair limit alone would never trip. Two thresholds, two
purposes: the tight one protects an account, the loose one catches spraying.

**Also:** the DNS key cross-check now reports whether the answer was
**DNSSEC-validated**, by checking dig's AD flag, instead of implying that a
match means more than it does. Without validation the lookup is spoofable on
the network path, and the output now says so rather than printing an
unqualified tick.

Still open from that review and tracked in `TODO.md`: destination-restricted
egress, off-VM *restore* proof (as distinct from off-VM backup, which now
exists), authoritative verification from outside the guest, and formal key
rotation procedure.

---

## Unreleased — README signing section rewritten for readers, not maintainers

The signing documentation had drifted into being maintainer notes in a
public README: how to generate a key, how to run the signing tool, what DNS
record to create, where to back up the secret key. None of that is anything a
reader of this project can act on, and the tool itself is no longer shipped —
so it described a workflow using a file that is not in the repository.

Rewritten as **"Verifying What You Run"**, answering the questions a reader
actually has:

- **Why this exists at all** — `install.sh` executes code as root on a
  hypervisor, and every `curl | bash` installer asks for trust it gives no way
  to check.
- **What happens automatically**, including that a missing `minisign` says the
  signature was *not* checked rather than quietly reporting success.
- **How to check independently** — the DNS lookup and the two commands to
  verify a release by hand.
- **What it proves and what it does not.** Signing does not bootstrap trust
  for someone fetching `install.sh` and the release from the same place; it
  makes a substitution *detectable*. Tamper-evidence, not prevention — stated
  rather than implied.
- **`wasp-verify-integrity.sh`**, which is the more useful half, with its own
  limit named: an attacker with root can edit the checker too.

**Also fixed:** the proxy-hardening section had been inserted *inside* the
signing section, so `nginx-snippet` appeared under a heading about release
signatures. Moved out. And the table-of-contents anchor still pointed at the
old heading — checked every internal link afterwards, all 48 headings resolve.

---

## Unreleased — The login slug no longer contains the word "login"

Reported by the operator: `/edith-login` does not hide a login page from
anything scanning for `*login*`.

Correct, and it defeated the only thing a slug is for. The suffix existed to
separate the login path from wp-admin, but subpaths do that just as well and
leak nothing:

```
/edith        -> wp-login.php
/edith/       -> wp-login.php
/edith/foo    -> wp-admin/foo
/wp-login.php -> 403
```

**The same reasoning applies to the slug itself**, so the installer now
rejects anything containing `login`, `admin`, `auth`, `signin`, `panel`,
`dashboard` or `wp-`, checked as a substring rather than an exact match. A
slug like `siteadmin` or `mylogin42` is found by the same wordlist that finds
`wp-login.php`; choosing one is worse than choosing none, because it feels
like protection.

**A pre-existing bug found while adding that:** the reserved-path check
cleared the slug and carried on. The operator asked for a slug, was told it
was ignored, and the install completed with the default path — no re-prompt,
no second chance. The prompt is now a loop, so any rejection asks again. It
had never been one.

Also caught before shipping: the first version of the rejection used
`continue` with no enclosing loop. `bash -n` accepts that, and the effect
would have been to fall through with an empty slug — the exact behaviour being
fixed.

---

## Unreleased — `wp-hardening.sh nginx-snippet`

Generates reverse-proxy configuration from this VM's real values — admin CIDR,
extra allowed IP, login slug, VM address — rather than documenting a template
to transcribe. A snippet copied by hand with one value wrong is worse than
none, because it looks configured.

Three things it does that the VM cannot do for itself:

- **Restricts the admin paths at nginx.** Apache only knows the client address
  because a header told it; nginx is the edge, so `$remote_addr` *is* the
  client. There is no substitution step to fail silently. Both layers are kept
  — they fail independently, which is the point of having two.
- **Replaces `X-Forwarded-For` instead of appending.** NPM defaults to
  `$proxy_add_x_forwarded_for`, which appends to whatever the client sent, so a
  forged header arrives as `<forged>, <real>`. mod_remoteip should still choose
  correctly, but only while `RemoteIPTrustedProxy` is exactly right. Replacing
  removes the class rather than relying on the walk being correct.
- **Rate-limits logins at the edge**, before a request costs a WordPress
  bootstrap. This is the only control in the whole system that holds when
  everything downstream is misconfigured, because it never touches
  `X-Forwarded-For`.

The output ends by stating what it does **not** fix: the login guard, CrowdSec
and GeoIP still identify clients from the header, so they still depend on
mod_remoteip working. The snippet makes that header trustworthy; it does not
remove the dependency.

**Caught by an existing check while writing it.**
`test/check-param-expansion.py` flagged
`/${_slug:-wp-login.php}${_slug:+-login}` in the new code. That instance is
actually correct — `:-` supplies the default, `:+` adds a suffix — but it is
the same shape as a bug fixed two entries earlier, and confirming it requires
reasoning about expansion semantics. Rewritten as an explicit `if`. A checker
firing on a correct-but-confusing construct is doing its job; suppressing it
would have been the wrong response.

---

## Unreleased — `$(grep -c ...) || echo 0` produced "0\\n0" in five places

Caught by testing the remoteip detection I had just written, against data I
made up:

```
bash: line 9: [: too many arguments
```

`grep -c` always prints a count and exits 1 *only when that count is zero*.
So `n=$(grep -c pattern file || echo 0)` yields the string `"0\n0"` on
no-match, and every arithmetic test on it dies — at exactly the moment the
count is zero, which is usually the healthy case. The bug hides until
something is working.

Five instances, all written the same way, because the wrong idiom reads
naturally. Fixed to `n=$(grep -c ...) || n=0`, which assigns on failure
instead of appending. Added `test/check-grep-count.py`; `sh -n` passes the
broken form, since it is valid shell that only misbehaves at runtime.

**Also hardened the same check while there.** It matched
`interpreted=<ip> ` with a trailing space, which is present in the current log
format — meaning a format change would silently turn the check into "always
passes". Now anchored with `( |$)`, which also stops `192.168.100.11` matching
`192.168.100.112`. Verified against both cases.

---

## Unreleased — The same root cause silently defeats three more controls

Asked by the operator after the wp-admin fix: does a mod_remoteip failure
affect the login guard and CrowdSec too? It does, and the login-guard case is
worse than the one already fixed.

**One root cause, four symptoms.** Everything that identifies a client keys off
the address mod_remoteip is responsible for substituting:

| Control | What a failure does |
|---|---|
| wp-admin restriction | allowed everyone (fixed in the previous entry — now fails closed) |
| **Login rate limiting** | every visitor shares one counter. **Five failed logins from anyone locks out every user.** An attacker does not need to guess a password to take the site down; they need to guess wrong, five times |
| **CrowdSec** | bans the proxy at nftables — a site-wide outage for every visitor. Or, if the proxy is whitelisted (which the installer suggests), detects nothing at all |
| **GeoIP** | sees an RFC1918 address, which the local-IP exemption allows, so country filtering does nothing |

Each of these looks like it is working. None of them reports anything.

**Neither failing open nor failing closed is right for the rate limiter.**
Without a client identity, per-client limiting is not possible; locking
everyone out *is* the denial of service. So the limiter keeps working — some
limit beats none — and the condition is now logged on every occurrence as
`REMOTEIP-BROKEN`, with the specific consequence spelled out, so it is
discoverable rather than invisible.

**`validate-wordpress.sh` now checks the root cause once, explicitly**, rather
than leaving four separate oddities to be correlated: it reads
`remoteip-debug.log`, counts requests where `peer` and `interpreted` are both
the proxy, and fails with the full list of what that breaks. It also fails if
the login guard has ever logged `REMOTEIP-BROKEN`.

The general lesson worth recording: four controls depended on one mechanism,
and nothing verified that mechanism was working. Layered defences that share
an unchecked dependency are not four layers.

---

## Unreleased — SECURITY: wp-admin restriction could fail OPEN

Found by the operator testing from a phone on cellular data: the login page
was reachable from an address in no allow list. That should have been a 403.

**Cause.** With a reverse proxy in front, every request arrives from the
proxy's address, and `mod_remoteip` is what substitutes the real client. If it
does not apply — module absent, header not sent, or the connection arriving
from an address other than the declared `RemoteIPTrustedProxy` — Apache
evaluates the rules against the **proxy's** address.

And a proxy on the LAN is normally inside the operator's own admin CIDR.
Here, `192.168.100.112` sits inside `192.168.100.0/24`. So the failure did not
deny everyone, which would have been noticed within minutes. It **allowed
everyone**, and looked exactly like a working configuration.

That is the worst shape a security control can fail in: silently, in the
permissive direction, while continuing to report success. Every other check in
this project passed throughout — because they verify the rule is *present*,
not that it *excludes* anything.

**Fixed** by emitting `Require not ip <proxy>` inside a `RequireAll` whenever a
proxy is configured. When `mod_remoteip` works, the client is the real
visitor, never the proxy, so this passes and the allow-list decides as
intended. When it fails, the client *is* the proxy, this fails, and the
request is denied. The control now breaks toward locked-out instead of
wide-open.

Consequence, documented at the prompt: WordPress can no longer be administered
from a shell on the proxy host itself. That is a fair trade for the
restriction meaning what it claims.

**Also added, because the fix should not be the only thing standing between
this and a repeat:**

- The installer detects when the proxy address falls inside the admin CIDR and
  explains why that combination is dangerous, rather than leaving it as an
  implicit property of two separately-sensible answers.
- `wp-hardening.sh proxy-check` now greps the live config for the deny rule and
  reports its absence directly, instead of leaving the operator to infer it —
  and tells them the test that actually proves it: browse the login page from
  a phone on mobile data and expect 403.

Worth recording plainly: this shipped through four security evaluations and
every automated check in the repository. It took someone opening the site on
their phone. Configuration-dependent failures like this one — where two
individually correct answers combine badly — are not something static analysis
finds.

---

## Unreleased — Off-VM backups can be encrypted (age, public-key mode)

Flagged as a consideration when off-VM backup was designed and not implemented
then. It matters more than usual here: a WordPress dump carries every user's
password hash, email and real name, private and draft post content, and
whatever plugins wrote into `wp_options` — API keys, form submissions, order
records. Unencrypted in third-party object storage, the provider has all of
it, and so does anyone who reaches the bucket.

**age in public-key mode, and the mode is the point.** The VM holds only the
recipient (public) key, so it can encrypt backups and cannot read them — not
the ones it sends, and not the ones already at the destination. An attacker
with root on this VM can create backups but decrypt none of them. That
composes with the append-only destination: they can neither read what is
stored nor delete it.

The installer rejects an `AGE-SECRET-KEY` if one is pasted by mistake and
explains why, since putting the private half on the VM would discard the whole
property while appearing to work.

**Two deliberate limits, both stated at the prompt rather than in docs alone:**

- **The local backup stays unencrypted.** It never leaves the host, and
  keeping it readable is what lets `wasp-selftest.sh` prove a restore actually
  works. Encrypting the copy that leaves your control while keeping the one
  that does not preserves both properties; encrypting both would trade a
  working restore proof for protection the VM boundary already provides.
- **Losing the private key destroys every encrypted backup.** An encrypted
  backup nobody can decrypt is not a backup. That warning is in red at the
  prompt, and `restore-help` exists to make testing a decrypt an obvious thing
  to do before it is needed rather than during an incident.

If `age` cannot be installed, the upload **refuses** rather than sending
plaintext. A silent downgrade from "encrypted offsite backup" to "the entire
database in someone else's bucket" is not an acceptable failure.

Verification accounts for the ciphertext: the `.age` artifact is what gets
uploaded and what the remote size is compared against, since comparing a
remote ciphertext to a local plaintext would mismatch every time.

---

## Unreleased — Off-VM backup, and the web restriction made usable

**Off-VM backup, optional at install:** `scp`, `rsync` or `rclone` (S3, B2,
Wasabi, ~40 providers). Pushed after each *verified* nightly backup — after
verification and rotation deliberately, since a copy of a backup that failed
its own checks is not worth sending, and a push failure must not stop a good
local backup being kept. The remote copy's **size is read back and compared**
rather than trusting the transport's exit status; a silently truncated upload
looks fine until a restore. `wasp-selftest.sh` now also fails if the newest
backup is missing remotely.

The point given most prominence is not the transport. This VM must hold a
credential that can reach the destination, so an attacker with root here can
reach it too — encrypting a site and then wiping its backups is the standard
pattern, not an exotic one. Off-VM copying protects against disk failure and
losing the VM; **append-only** destinations are what protect against malice.
The installer asks whether the destination is append-only and `status` reports
which protection is actually in place, because claiming the stronger one
without having it is worse than claiming neither. `prune` failing against a
correctly append-only destination is documented as correct rather than as a
fault to fix by granting delete rights.

Credentials are root-owned `0400`; WordPress runs as uid 33 and cannot read
them, so a web-application compromise alone does not reach the backup
destination. The destination's SSH host key is captured at install from the
Proxmox host so the VM can use `StrictHostKeyChecking=yes` — for a backup
target, `accept-new` would let a MITM silently receive every database dump.

**"Restrict Web (80/443) to a CIDR?" — the operator's reasoning was right.**
Pointing it at the reverse proxy's address is the best answer to that
question, not a misunderstanding: it stops anyone reaching the site by its IP
and bypassing the proxy, which also bypasses TLS termination, the proxy's own
rules, and the `X-Forwarded-For` header this VM depends on to see real client
addresses.

The problem was ordering. The question is asked before the proxy IP is known,
so answering it well required knowing that address in advance. The installer
now offers to narrow 80/443 to the proxy immediately after collecting it, and
states both consequences plainly: the VM's IP can no longer be browsed
directly for testing, and if the proxy's address ever changes the site goes
dark silently at the packet level with no error page — which the operator had
just experienced from the other direction with a NAT forward.

---

## Unreleased — Vulnerability exception governance, and Trivy pinned

**Trivy pinned to v0.72.0, anchored by checksum, with a denylist.**
Researching the current release surfaced why this item mattered more than it
looked: Trivy's distribution was compromised **twice** in 2026 — a repository
takeover on 28 February, then on 19 March a credential stealer injected into
`trivy-action` and `setup-trivy` and **a malicious binary published as
v0.69.4 for about three hours**. On 22 March the `aquasec/trivy` 0.69.5 and
0.69.6 Docker Hub images were also found to contain the attacker's C2 domain.

A version pin alone would not have saved anyone who happened to pin 0.69.4.
The release's own `checksums.txt` is now anchored by a SHA-256 recorded in the
stage file, out of band from the download, and the binary is verified against
that. A denylist additionally refuses 0.69.4/0.69.5/0.69.6 **whichever path
installed them**, including apk — a distribution package built from a poisoned
upstream carries the same code. Bumps are manual by design; a stale pinned
hash fails closed, which is the right direction to fail.

**Vulnerability exceptions are now recorded rather than clicked through.**
The y/N override became a written justification, and the operator's design was
extended in two ways that cost nothing at the prompt:

- **Digest-scoped.** The exception records the exact image digest and is only
  honoured for that digest. Accepting a finding on one image must not silently
  carry to the next, which has a different set of vulnerabilities. A blanket
  "yes" that outlives its subject is how exceptions become policy by accident.
- **Expiring**, 90 days by default, capped at 365. Without expiry the first
  person to type a reason decides forever.

An unexpired exception for the same digest is honoured without re-asking —
re-prompting for a decision already recorded is how people learn to type
anything to get past a prompt. An expired one says so and must be re-argued.
Justifications under 15 characters are refused: a low bar that stops "ok" and
"asdf", not someone determined.

The record is an append-only root-owned log, and the email is explicitly a
**copy** — mail can fail, and an audit trail that depends on delivery is not
an audit trail. Notices route to a separate governance address collected at
install, with a warning if it matches the admin address, because a record only
the decision-maker receives is a diary rather than oversight.

---

## Unreleased — Release-signing tool removed from the distribution

`wasp-sign-release.sh` is no longer shipped. It only ever runs on the machine
holding the secret key, so including it in every deployment added attack
surface without adding any capability there — a script present on hundreds of
VMs that none of them can use.

Nothing depended on it: the manifest it builds covers `install.sh`, `lib/` and
`payload/`, and `tools/` was never part of the signed set, so removing it
changes no hash and invalidates no signature.

**Verification is unaffected and is what users actually need.** The README now
documents how to check a release independently rather than how to sign one:

```sh
dig +short TXT minisign._wasp.rothitguy.pro   # key, from a source that is not this repo
minisign -Vm MANIFEST.sha256 -P "RW..."       # signature
sha256sum -c MANIFEST.sha256                  # every file against it
```

One reference in `wasp-verify-integrity.sh` pointed at the tool by path when
explaining why integrity checking was unavailable; it now describes what a
signed release contains instead of naming a file that is not there. Earlier
changelog entries still mention the tool, which is correct — they record what
happened at the time.

Worth noting for later: since the tool now lives only on the maintainer's
machine, improvements made here will not reach it. If the signing format or
the manifest's file selection ever changes, that copy needs updating by hand
or `install.sh` will reject its output.

---

## Unreleased — install.sh cross-checks the signing key against DNS

The embedded public key answers "was this release signed by the key in this
file?" — but not "is the key in this file the project's key?" `install.sh` now
also looks up a TXT record (`minisign._wasp.<domain>` by default) and compares.

The reason a second location helps at all is **different credentials**, not a
different URL. A Gist or a GitHub Pages site on the same account falls to
precisely the compromise this is meant to expose; a DNS record lives at the
registrar, which is a separate login entirely. That reasoning is in the code
comment, the signing tool's output and the README, because "publish it
somewhere else" without it invites the useless version.

**Stated as corroboration, not a root of trust.** Plain DNS is spoofable on
the network path, so this catches a repository compromise that swapped both
the release and the embedded key, and catches nothing against an attacker who
also controls the resolver. DNSSEC strengthens it. That caveat is in the
script rather than only the docs.

Failure handling is deliberately graded: no key, no record, or no `dig`
skips with a note — an absent record has many innocent causes and failing on
it would be noise. A genuine **mismatch** warns loudly with both values and
requires confirmation, and is fatal under `WASP_REQUIRE_SIGNATURE=1`. It is
not fatal by default because a legitimate key rotation would otherwise brick
every stale checkout, and the signature check immediately after is the control
that actually decides authenticity.

`wasp-sign-release.sh --init` now prints the exact TXT record to publish and
the `dig` command to confirm it, so the fingerprint does not end up published
only in the repository it is meant to vouch for.

TXT parsing verified against `dig` output (including a zone with other TXT
records present) and `host` output.

---

## Unreleased — Release signing with minisign

The signed-manifest item has been the largest open blocker since the
repository was first split, and it was stuck on the wrong thing: I framed it
as needing GPG, and GPG's keyring and trust model made the bootstrap awkward
enough that it stayed unimplemented.

minisign removes that. `minisign -Vm file -P <base64-key>` takes the public
key **on the command line** — no keyring, no trust database, nothing to
distribute but one line of text — so the key can be embedded directly in
`install.sh`, the file a user fetches first.

- `tools/wasp-sign-release.sh` builds a SHA-256 manifest of every file
  `install.sh` executes and signs it. Documentation is deliberately excluded:
  signing it would mean a README typo invalidates the release, which trains
  people to ignore failures.
- The signature carries a **trusted comment** with version and timestamp.
  minisign's own documentation recommends this specifically to prevent
  downgrade attacks — a bare signature cannot distinguish a current release
  from a correctly-signed older one.
- `install.sh` verifies the signature, then the hashes, before sourcing
  anything. Failure modes are distinguished rather than collapsed: an invalid
  signature or a hash mismatch is always fatal; a missing key, missing
  manifest or absent minisign warns and is fatal only under
  `WASP_REQUIRE_SIGNATURE=1`. Notably, a missing minisign is **not** silently
  downgraded to hash-only checking — hashes from an unverified manifest catch
  corruption, not tampering, and calling that "verified" would be worse than
  reporting nothing.
- `wasp-verify-integrity.sh` re-checks the installed tooling on the VM.

That last one is the more valuable half. Verifying a release at install
catches a tampered download, which is a one-off risk. Verifying the installed
files catches an attacker with root on the VM editing `update.sh` or the
malware scanner to disable a control — invisible to every other check here,
because every other check trusts the scripts it is running. Its limit is
stated in the script: an attacker with root can edit the checker too, so it
catches malware that ignores the integrity check rather than one that
anticipates it.

**The honest scope is documented in three places** rather than only the
commit message: signing does not bootstrap trust for a first-time user
fetching `install.sh` and the release from the same repository. It makes
tampering evident to anyone who recorded the fingerprint, and it forces an
attacker to need the secret key rather than write access.

Verified the chain end to end: an edited file fails `sha256sum -c`; an
attacker who also rewrites the manifest defeats the hashes but not the
signature, so `install.sh` aborts before it ever reads them.

---

## Unreleased — SMTP credentials are no longer an executable PHP file

A third-party evaluation raised, as High: *"Setup writes executable PHP secret
config — quoting defects or replacement can become code execution."* Correct,
and worth acting on rather than defending.

`smtp.php` returned a PHP array and was `include()`d, which made the
credentials file **code**. The escaping that wrote it was careful — it was
tested against passwords containing quotes and backslashes — but careful
escaping is a mitigation, and a data format is a fix. Two ways it could have
bitten: a defect in the escaper turning a crafted password into a statement,
and any future write access to the file becoming immediate RCE rather than a
wrong password.

Now written as `smtp.ini` and parsed with `parse_ini_file(..., INI_SCANNER_RAW)`
— values are taken literally, with no interpretation of quotes, constants or
types. Nothing in it can execute. The password is base64-encoded so that
quotes, semicolons, `=` and whitespace cannot interact with INI parsing at
all; that is **encoding for robustness, not secrecy**, and the file's
permissions remain what protects it. Verified a password containing
`;`, `"`, `=`, `'` and `\` round-trips byte-exact.

Existing VMs keep working: the mu-plugin still reads a legacy `smtp.php` if
present, logs that it did so, and `wp-mail.sh setup` rewrites as INI and
deletes the old file. `validate-wordpress.sh` warns while an executable
config remains.

**On the rest of that evaluation:** it reviewed a build predating
`wasp-selftest.sh` and the read-only candidate account, so two of its six
stated blockers — live-database candidate testing, and restore proof — were
already closed. Off-VM restore, the signed manifest and formal vulnerability
exceptions remain open and are tracked in `TODO.md` with their blockers named.
Destination-restricted egress is a genuine gap and is discussed there rather
than silently ignored: allowlisting destinations for HTTPS is brittle against
CDNs and registries with rotating addresses, which is why it is not simply
switched on.

---

## Unreleased — Rate-limit handling, silent test failure, and an unexplained prompt

A clean run: 15/15 at install, 47 passed / 1 warning / 0 failed after. Three
things the log and the operator's own note exposed.

**1. "Restrict Web (80/443) to a CIDR?" had no explanation** — reported
directly: *"not well explained during install but ssh is."* Correct, and the
omission was mine: the SSH prompt got a reasoning block and its neighbour did
not, which is worse than neither having one because it implies the unexplained
question is the unimportant one.

It now says plainly that **almost every site should leave this blank** — a
public website that answers only one network is not a public website, and
visitors, search engines and uptime monitors are dropped at the packet level
with no error page. It names the two cases where it is right (an internal or
staging site; a proxied site restricted to the proxy's own address, which
stops anyone bypassing the proxy), distinguishes it from the wp-admin
restriction asked separately, and notes that leaving it blank is not "no
protection" — CrowdSec, the 8G firewall, the admin IP rules and the login
limiter all still apply.

**2. Wordfence rate limiting was being made worse by the code.** The
diagnostic showed `scanner -> HTTP 206` (a successful range request) and
`production -> HTTP 429`, then `vulns` seconds later hit 429 on *scanner* too:
the limit counts requests, and a 1 KB range request spends one.

Two faults. `Retry-After` was ignored in favour of a guessed 20 seconds — the
server states the wait and the client was overriding it. And when scanner was
refused, the code went on to request the 100 MB production feed anyway, which
could not succeed and only deepened the limit; the log shows two 429s and two
pointless waits back to back. Now: `Retry-After` is honoured (capped at 300s,
45s default), production is skipped entirely when scanner was refused, and the
gap between the two feeds is 60s rather than the 5s I picked without evidence.

**3. `wp-notify.sh --test` failed silently.** The field log shows it returning
straight to the prompt with no output, which reads like success. It used
`send_mail ... && echo "sent"`, so a failure printed nothing. It now reports
the failure, shows msmtp's own error, and exits non-zero. A test command that
is silent when it fails is worse than not having one.

---

## Unreleased — `vulns` aborted on a rate limit and hid its own commands

From the field:

```
wordpress:~$ wp-plugins.sh vulns
  Fetching Wordfence Intelligence v3 scanner feed…
  Fetching Wordfence Intelligence v3 production feed…
  ⚠ Rate limited by Wordfence (HTTP 429).
wordpress:~$
```

Three separate faults, all introduced with the feed-choice feature.

**1. A failure on the second feed discarded the first.** With
`WORDFENCE_FEED=both`, `_wf_refresh` returned non-zero if *either* fetch
failed, so the whole scan aborted — despite the scanner feed having
downloaded successfully seconds earlier. The most useful feed was in the
cache and went unused. It now succeeds if **either** feed is available, and
only fails when neither is.

**2. `both` all but guaranteed the rate limit.** Two large downloads fired
back to back, the second being 100 MB+. Adding the option without considering
request rate made the default experience for anyone choosing it a 429 on
first run. There is now a pause between the two fetches, and a 429 waits 20
seconds and retries once — a burst limit generally clears, and giving up
immediately meant `both` users effectively never received the production
feed. The install prompt now says this outright rather than letting the
operator choose blind.

**3. The usage text listed none of the vulnerability commands.** Running
`wp-plugins.sh --nvd` printed help showing only `status`, `check`, `list`,
`doctor`, `update-plugins`, `update-themes`, `update-core` — while the
paragraph underneath it explained that ~91% of WordPress vulnerabilities live
in plugins. The headline feature was undiscoverable from its own help.
`vulns`, `vulns --nvd`, `vuln-sources`, `vuln-refresh` and `set-key` are now
listed.

Failure messaging also names the specific remedy: switch to a single feed with
the exact `sed` command, rather than leaving the operator to work out that
`both` was the cause.

---

## Unreleased — `${V:+X}${V:-Y}` is not if/else (and it leaked a secret)

The install summary printed:

```
  Admin slug:        /edith (custom)edith
```

`${V:+X}${V:-Y}` reads like a ternary and is not. When `V` is set and
non-empty, `:+` yields `X` **and** `:-` yields *the value of V*, so both halves
expand and the variable is appended to the "true" branch. When `V` is empty
only the second half expands and the line reads perfectly — which is why it
survived every run until someone actually used the feature.

The same line also displayed `/edith` while the URL genuinely served is
`/edith-login`. The slug itself worked correctly throughout; validation
confirmed it serves HTTP 302 and that the default path 403s.

**A check for the pattern found a second instance**, and that one was not
cosmetic:

```
"${CROWDSEC_ENROLL_KEY:+key provided (auto-enrol)}${CROWDSEC_ENROLL_KEY:-manual (after install)}"
```

Supplying a CrowdSec enrolment key would have printed **the key itself** into
the install summary and the log. It never surfaced because that field was left
blank in every test run — the only branch that reads correctly.

Both fixed with explicit tests.

**`test/check-param-expansion.py` added**, and it needed fixing before it was
worth having. The first version located the closing brace with `[^}]*`, which
breaks the moment the true-branch contains a nested `${...}` — exactly the
shape of the shipped bug. It reported CLEAN on its own test case while
correctly flagging the CrowdSec line, which has no nesting. Rewritten to
collect every `${VAR:+` / `${VAR:-` on a line and flag any variable used with
both operators; no brace-matching, so nesting cannot defeat it. Verified
against both real instances and a synthetic one.

`bash -n` passes all of these. They are valid shell doing precisely what they
were told.

---

## Unreleased — SMTP credentials unreadable by PHP (directory traversal)

The backtick fix worked — that error is gone from the install log. The
remaining failure was mail, and the symptoms looked contradictory:

- `wp-mail.sh doctor` reported the config present and correct
- the mu-plugin *was* loaded (its own handler logged the failure)
- yet PHPMailer reported `Could not instantiate mail function`, which is the
  **mail()** transport error, and sendmail then tried 127.0.0.1 and was refused

**Cause: the credentials directory was `root:root 0700`.** The file inside was
`0400` owned by uid 33 and looked correct, but www-data could not **traverse**
the directory, so `is_readable()` returned false, `wpvm_smtp_config()` returned
false, the `phpmailer_init` hook returned early, and PHPMailer stayed on
`mail()`. `doctor` disagreed because it runs as root via doas — the two were
reading with different privileges and reaching different answers.

A directory mode defeating a correct file mode is exactly the kind of failure
that points nowhere near its cause.

**Fixed:** directory `root:33 0750`, file `root:33 0440`. The PHP worker can
traverse and read; nothing else on the system can. The file is root-owned
rather than owned by uid 33 deliberately — a compromised PHP process must be
able to *read* the relay credentials to send mail, but now cannot rewrite
them to point at a server it controls.

**Three checks added**, because inferring from modes is what missed it:

- the credential **directory** mode and ownership, not just the file's;
- an end-to-end test — `podman exec --user 33 wordpress test -r ...` — which
  asks PHP, as the user it actually runs as, whether it can read the file;
- `wp-mail.sh test` now resolves the relay hostname before sending, so a
  typo'd host reports "does not resolve" instead of surfacing PHPMailer's
  "Could not instantiate mail function" and pointing at the mail system.

That last one matters for this log specifically: the relay was entered as
`mail.ironmail.systems`, which does not resolve. Both faults were present at
once, and each masked the other.

**Also:** the closing summary and README now suggest
`tail -800 /var/log/wp-install.log` rather than `tail -f`, so the whole
install is visible rather than only what arrives after you start watching.

---

## Unreleased — Backticks in an unquoted heredoc executed nft on the HOST

From a real install log:

```
Error: syntax error, unexpected newline, expecting string or last
add element
           ^
```

**Cause.** The generated nftables ruleset is built with
`NFT_CONF=$(cat << NFTEOF ...)` — an **unquoted** heredoc, because it has to
substitute the operator's CIDRs. A comment inside that body read:

```
# so wp-hardening.sh can open one live with `nft add element` -- no
```

The shell expands an unquoted heredoc body, so those backticks were command
substitution. Every install ran `nft add element` **on the Proxmox host**,
printed nftables' syntax error into the install log, and wrote the comment
out with the text replaced by empty output.

Nothing downstream broke, which is the uncomfortable part: it executed an
unintended command on the hypervisor and produced a scary error in the middle
of an otherwise-clean run, and the install carried on regardless.

**This is precisely the failure mode `scan-heredocs.py` existed to catch**,
and it was retired earlier in this project on the grounds that no heredoc
still wrote an executable script body. That reasoning was true and beside the
point: the hazard is the unquoted heredoc, not what its output is later used
for. A config heredoc expands its body exactly the same way.

**Fixed**, and the capability is restored as
`test/check-heredoc-backticks.py`, which finds backticks in any unquoted
heredoc across the repo. Verified three ways: it flags a known-bad file;
`bash -n` passes that same file cleanly; and the shell demonstrably
substitutes the command when the delimiter is unquoted and leaves it literal
when quoted.

Shell comments *outside* heredocs are unaffected — the shell does not expand
comments — so the other backticks in the file were checked and are safe.

---

## Unreleased — Production feed and ClamAV both offered at install

Two things that were hardcoded decisions are now operator choices, each with
its actual reasoning stated at the prompt.

**Wordfence feed: scanner / production / both.** The honest framing here is
not "production is better but heavy" — the feeds contain different things.
Scanner carries vulnerabilities that are still under research and therefore
absent from production, so it detects **more** and **earlier**; production
carries fully analysed records with CVSS vectors, references and patched
versions, which is better for deciding what to do and for client-facing
evidence, but a record only lands once analysis completes.

So production is optional for a **security** reason before a resource one:
using it alone narrows detection. A freshly disclosed plugin flaw is the one
most likely to be under active exploitation, and that is precisely the record
production does not have yet. `both` is offered as the combination with no
blind spot, costing disk and parse time rather than accuracy.

Implemented by splitting the fetch into a per-feed helper; the matcher reads
every cached feed file, so `both` needs no special case downstream and
duplicate findings collapse naturally.

**ClamAV: asked at install, default no.** The memory cost was the reason
given previously, and it was the least interesting one. ClamAV is a
general-purpose signature scanner built largely for email attachments, and
its coverage of obfuscated PHP webshells is weak next to the YARA rules
already installed, which target exactly that shape of threat. It
false-positives on some minified JavaScript, and a WordPress tree is full of
minified plugin assets — triage noise is how a scanner stops being read. Its
signatures also need refreshing, and a stale AV database is worse than none
because it looks like coverage.

Where it does earn its place, and the prompt says so: sites accepting visitor
file uploads, non-PHP payloads such as dropped ELF binaries that the YARA
rules do not target, and compliance regimes that simply require an AV
product. Answering yes installs it, fetches signatures during the install
rather than letting the first scan discover an empty database, and schedules
a weekly scan — weekly rather than daily because a full pass takes minutes
and the layers that matter most for WordPress already run daily.

---

## Unreleased — Wordfence API v3 (v2 is retired and the code pointed at it)

Reported by the operator, and correct: the integration was written against
Wordfence Intelligence **v2**, which required no authentication. v2 has since
been retired in favour of **v3**, which requires a token generated under
Integrations in a free Wordfence account and sent in the `Authorization`
header.

This mattered more than a version bump. Code pointing at a retired endpoint
does not announce itself — the daily scan would have failed quietly and the
site would have looked monitored while nothing was being checked. Worth
recording that my original research returned the v2 documentation and I
treated it as current; the operator's correction is what caught it.

**Changed:**

- Endpoint moved to `/api/intelligence/v3/vulnerabilities/scanner`, with
  `Authorization: Bearer <token>`.
- The token is prompted for at install, immediately after the CrowdSec
  enrolment key — the same shape of question, in the same part of the run.
- Persisted to `/etc/wp-install/vuln-sources.conf` (0600), the single file the
  vulnerability code reads, rather than left only in `vars.sh` which several
  tools source for unrelated reasons.
- `wp-plugins.sh set-key wordfence <token>` added for configuring it later.

**Failure paths are explicit rather than silent**, since a vulnerability
scanner that stops working quietly is worse than one that was never
installed. Verified across the matrix: no token with no cache fails with
signup instructions; no token with a cache warns and uses it; HTTP 401/403
reports a rejected token; 429 reports rate limiting; each falls back to the
cached feed when one exists and says how old it is.

**Scanner feed rather than Production, now documented as a decision.**
Production carries the fully analysed records and is well over 100 MB — a
poor thing to hand `jq` on a 4 GB VM also running WordPress and MariaDB.
Scanner is the minimal detection format, which is exactly the fields this
matching uses, and it additionally carries newly discovered vulnerabilities
not yet fully analysed. Smaller and earlier.

The privacy property is unchanged: the token authenticates the download, it
does not report what you run. The feed is still fetched whole and matched on
the VM.

---

## Unreleased — Email alerts from scheduled scans (`wp-notify.sh`)

Scans logged to syslog, which nobody reads on a VM they are not currently
looking at. They now email, through the relay already configured for
WordPress.

**One shared sender**, not a snippet copied into each job. This project has
been bitten repeatedly by the same logic living in several places and
drifting; the container run command alone turned out to exist in five.

**Host-side via msmtp rather than `wp_mail()`.** Reusing the WordPress mail
path would be the tidier reuse and was the first instinct. It is wrong here:
these alerts fire when something is broken, and "WordPress or MariaDB is
down" is simultaneously the moment an alert matters most and the moment
`wp_mail()` cannot run. Credentials are read from the same `smtp.php` the
mu-plugin uses — no second config file — and reach msmtp through
`--passwordeval` rather than the argument list, where `ps` would show the
relay password to any local account.

**Deduplicated by body content, 24h default.** A daily scan that emails the
same unpatched plugin every morning becomes a filter rule inside a week, and
then the finding that matters arrives unread. Hashing the *body* rather than
the subject matters: a subject like "3 findings" is identical two days running
even when the findings changed completely, and deduplicating on that would
suppress a genuinely new alert. Verified: identical findings suppressed,
changed findings sent immediately.

**Two deliberate exceptions:**

- **Malware emails on CRITICAL only.** HIGH includes a world-writable file —
  worth fixing, not worth an email at 03:30. Sending those daily is precisely
  how the CRITICAL mail stops being read.
- **Backup failure sends every time, no cooldown.** A repeated failure is the
  thing you most need to keep hearing about, and the error text will be
  identical each night, so content-dedup would silence it after the first.
  A backup failing silently for months is the most common way people find out
  they have no backups, at the worst possible moment.

Nothing changes if no relay is configured: every job still logs to syslog as
before, and `wp-notify.sh` exits cleanly rather than erroring.

---

## Unreleased — Vulnerability scan cron: scan once, not twice

The daily vulnerability scan was wired as the obvious inline cron form:

```
wp-plugins.sh vulns | grep -q FINDING && wp-plugins.sh vulns | logger
```

That runs the **entire scan twice** — two `podman run` starts of the wp-cli
container, and one `jq` invocation per installed plugin, doubled. On a site
with 30 plugins that is 120 jq calls to answer a question 60 could answer,
every day, forever.

Replaced with `wp-vuln-cron.sh`: runs once, captures the output, decides from
that. It logs a one-line summary plus the CRITICAL and HIGH findings
individually, and stays completely silent when there is nothing to report — a
daily job that says "nothing found" every day teaches the operator to ignore
it, and an ignored alert is worse than no alert because it manufactures the
feeling of monitoring.

**Also fixed while there:** colour escapes are now emitted only when stdout is
a terminal. These tools are read by humans *and* piped to `logger` by cron,
and raw `\033[31m` sequences in syslog are unreadable and break grep. Applies
to every path in `wp-plugins.sh`, not just the cron one.

Daily rather than weekly is deliberate and worth stating: Wordfence adds
dozens of records per week and disclosure-to-exploitation for WordPress
plugins is often measured in hours, so a weekly scan can leave a
known-exploited plugin live for six days.

---

## Unreleased — ARCHITECTURE.md (Mermaid diagrams)

Four diagrams, in a separate file rather than one unreadable chart in the
README, rendering natively on GitHub:

1. **Components and trust boundaries** — makes the structural point visible:
   MariaDB on a Podman `--internal` network with no host port and no route
   out, so a compromised WordPress cannot reach past it.
2. **What a request passes through** — layered by cost. A packet dropped at
   nftables is free; a request reaching PHP has already bought a WordPress
   bootstrap and a database query. That ordering explains why brute-force
   protection escalates *down* to the firewall instead of living in PHP.
3. **Install flow** — the two phases, split by the reboot the kernel switch
   requires.
4. **Update: candidate, cutover, rollback** — including the branch where
   `wordpress-old` is renamed back, and the GeoIP rebuild that follows a
   successful cutover.

Plus a tooling map showing which layer each script covers.

**One diagram type was swapped before shipping.** The tooling map was written
as a Mermaid `mindmap`, which is the fussiest diagram type in Mermaid and
whose documented syntax does not include quoted strings — and it could not be
rendered here to confirm. Replaced with a `graph`, whose behaviour is
predictable. Choosing the diagram type that can be reasoned about beats the
one that looks tidier and might not render.

Validated: fences balanced, every `subgraph` has a matching `end`, and every
`style` target resolves to a declared node. The first pass of that check
produced false positives because its node-declaration regex only matched
line-start declarations, missing nodes declared as arrow targets — fixed, and
worth noting since a checker that cries wolf is how real problems get waved
through.

---

## Unreleased — Plugin vulnerability scanning (`wp-plugins.sh vulns`)

`wp-plugins.sh status` answered "what is out of date". It now also answers
"what is actually vulnerable", matching installed plugins and themes against
known-vulnerable version ranges.

**Wordfence Intelligence is the default source**, and the reason is as much
privacy as cost. Wordfence publishes the complete database as a bulk feed with
no API key, free for commercial use. It is downloaded once, cached, and
matched **locally** — so the site's plugin inventory never leaves the VM. A
per-plugin API, by contrast, tells the provider your exact attack surface.
That is why Patchstack and WPScan are opt-in rather than default: they are
per-slug lookups, which is a fair trade for coverage but should be a decision
rather than a default nobody noticed.

NVD is available via `vulns --nvd` and framed honestly: keyword matching only,
5 requests per 30 seconds without a key, and WordPress plugin entries there
are sparse and noisy because plugin names are ordinary words. Useful as a
prompt to investigate, never as a verdict.

Keys are stored in `/etc/wp-install/vuln-sources.conf` at 0600.

**Verified before shipping:** the version comparator handles the shapes
WordPress plugins actually use (`1.2`, `1.2.3`, `1.2.3.4`) including
`1.10 > 1.9`, which naive string comparison gets wrong; and the range-matching
logic was simulated against a realistic feed structure covering inclusive
upper bound, inclusive lower bound, one patch above, well below, and a slug
with no records — all eight cases correct. The jq expression's *syntax* is
unverified, since jq is not available in this environment; its logic is what
was tested.

**Two honesty requirements built into the output.** A clean result states that
it means no *disclosed* vulnerability in that feed — around 46% of plugin
vulnerabilities have no patch at disclosure, and an unaudited plugin has no
CVEs by definition. And the Wordfence feed's licence requires that MITRE
copyright claims be displayed for MITRE-sourced records, so that attribution
is printed with every scan rather than buried in documentation.

---

## Unreleased — CrowdSec whitelist (and a path bug that would have silently disabled detection)

Login rate limiting made a lockout hazard concrete enough to need addressing:
CrowdSec bans at nftables, so a ban drops **SSH as well as HTTP**. Five
mistyped admin passwords and the operator is locked out of the VM, recoverable
only from the Proxmox console.

The installer now asks for never-ban addresses, pre-filled from answers
already given — reverse proxy and admin IP. The proxy is flagged in red,
because banning it takes the site down for **every visitor at once**: all
traffic arrives from it.

Managed afterwards with `wp-hardening.sh crowdsec-whitelist [list|add|remove]`,
which also shows currently-banned addresses, and surfaced by
`validate-wordpress.sh` — "am I about to lock myself out" should be answered
by the validator rather than discovered the hard way.

**Written as a postoverflow whitelist, not a parser whitelist.** A
parser-stage whitelist drops the events before any scenario sees them, so a
whitelisted address becomes invisible. At the postoverflow stage the bucket
still fills and the alert is still raised — only the ban is suppressed. If the
operator's own workstation is compromised and starts brute-forcing, it shows
up in `cscli alerts list` instead of having silent free rein. Both goals were
achievable; the parser stage would have quietly traded one for the other.

**Path bug fixed, introduced in the previous entry.** Only
`/opt/crowdsec/config` is mounted into the container (as `/etc/crowdsec`).
The login parser and scenario were being written to `/opt/crowdsec/parsers`
and `/opt/crowdsec/scenarios` — paths the container cannot see. CrowdSec would
have started cleanly, loaded neither, and brute-force detection would simply
never have fired, with nothing anywhere to indicate why. Found by checking the
container's actual mounts before adding the whitelist rather than assuming the
directory layout.

Verified: generated whitelist YAML parses, and the `add` path keeps `ip:` and
`cidr:` lists separate — CrowdSec validates that shape and silently ignores
the entire file if a CIDR appears under `ip:`.

---

## Unreleased — Login rate limiting (replaces Limit Login Attempts)

Two layers, because the application layer alone is the weaker half.

**`02-wpvm-login-guard.php`** — progressive lockout (5 failures → 15 min,
doubling per subsequent lockout, capped at 24 h). A fixed penalty is a rate an
attacker plans around; doubling makes sustained guessing against one address
pointless while a mistyped password still costs only the base wait. Hooked at
`authenticate` priority 5, ahead of `wp_authenticate_username_password`, so a
locked-out request never reaches bcrypt verification — deliberately expensive,
and most of the CPU this layer can save.

It also closes WordPress's **username-enumeration leak**: core distinguishes
"Unknown username" from "the password you entered is incorrect", confirming
which accounts exist and turning a guess at two unknowns into a guess at one.
Both now return identical text.

**CrowdSec parser + scenario** — the guard logs every outcome in a fixed
format and CrowdSec now reads it, banning the source at nftables. CrowdSec
could already see Apache access logs, but a failed and a successful login are
both a `POST /wp-login.php` there, indistinguishable without inspecting the
response body. The gap was never the bouncer; it was that **WordPress does not
log failed logins at all**.

**Decisions worth recording:**

- **`REMOTE_ADDR`, never `X-Forwarded-For`, in PHP.** mod_remoteip has already
  corrected `REMOTE_ADDR`, and only for the single proxy IP declared trusted.
  Reading the header in PHP would accept it from anyone — an attacker sends a
  fresh forged address per attempt and never accumulates a count. That is the
  most common way application-layer login limiters are defeated.
- **The parser reads the guard's `ip=` field, not Apache's `[client ...]`.**
  Behind a proxy the connection address is the proxy, and banning it would
  take the site offline for every visitor.
- **`blocked` events are not counted toward the ban.** The application layer
  already refused those, so counting them would double-count one attacker and
  fire on far fewer real guesses than intended.
- **A successful login clears the counter but not the escalation history**,
  so an attacker who guesses right once cannot reset their own penalty ladder.

Verified: the grok pattern matches all four event shapes wrapped in Apache's
error-log prefix, and the scenario filter selects the intended two. The
CrowdSec side is **untested against live traffic** — stage 09 prints the
`cscli explain` command to validate it on the VM.

---

## Unreleased — `wp-hardening.sh geoip-test`

GeoIP-enabled cutover and rollback both verified on hardware: the swap
happened, the forced failure triggered a revert, and GeoIP was then rebuilt on
the restored image with `mod_maxminddb` loading again. Full cycle clean.

That exposed a gap in what could be checked afterwards. `validate-wordpress.sh`
only confirms the module is **loaded** — which says nothing about whether the
database resolves addresses correctly, or whether the allow/block list does
what the operator believes it does.

`wp-hardening.sh geoip-test [ip]` now checks the parts that are checkable:
module live in the running Apache, database present **and fresh** (GeoLite2 is
republished weekly and allocations move — a stale database misclassifies real
visitors, which presents as random 403s rather than as an out-of-date file),
the policy read from the live `geoip.conf` rather than from `vars.sh`, and how
a given address resolves along with the verdict it would receive.

**It states plainly what it cannot do.** Every request originating on the VM
comes from a private address, and private addresses are exempt by design, so
an in-VM test will always be allowed regardless of policy. Reporting that as
"GeoIP works" would be worse than not testing at all. The command says so and
gives the two real end-to-end tests: curl from a host in a blocked country, or
curl from the trusted reverse proxy with a forged `X-Forwarded-For` — noting
that only the configured proxy IP is trusted for that header, so it cannot be
faked from elsewhere.

---

## Unreleased — ROLLBACK PROVEN. Every install-time path now verified.

The fault-injection test ran on real hardware and the rollback branch worked:

```
✔  Candidate healthy — swapping production to the new image now
   [rollback-test] forcing post-cutover health FAILURE for 'wordpress'
✗  Health check failed — rolling back…
✗  Rolled back to 6.9.4-php8.3-apache.
✔  'wordpress' container is running
✔  Image rolled back to the original: localhost/wordpress-geoip:6.9.4-php8.3-apache
✔  No leftover 'wordpress-old' container
✔  Site passes the real health check (HTTP + PHP + DB)
```

Worth noting what that last part demonstrates beyond the branch itself: the
restored image is the **GeoIP-built** one, so rollback returned the VM to its
actual prior state rather than to the upstream base image. And the retry loop
is visible in the log — the forced failure was hit six times before update.sh
gave up and reverted, which is the intended behaviour for a container that
might simply be slow to come up.

`TODO.md` has carried candidate/cutover/rollback coverage as deferred since
the repository was first split, on the grounds that it needed real hardware
and a deliberately broken image. Both halves are now proven: cutover in both
directions, and rollback by fault injection. **Every install-time and
update-time path in this project has now executed successfully at least
once.**

**One bug in the test script itself**, found by reading its own output: the
verdict printed `\033[32mROLLBACK WORKS.\033[0m` literally. `say()` used
`printf '%s'`, which does not interpret escapes. Changed to `%b`. Cosmetic,
but the summary line is the one thing an operator reads, and it should not
look broken at the exact moment it reports success.

---

## Unreleased — README voice

The README read as a specification: accurate, thorough, and anonymous. Added
the part that was missing — a first-person **"Why I built this"** section
before the table of contents, and a signed footer.

It opens on the three failures that motivated the project, in the order they
actually happen: a plugin four versions behind that nobody was watching while
the host and container were both patched; a nightly backup that had been an
empty file for a year because no one ever restored one; and an update that
broke a site at a bad hour with no way back. Then the distinction that the
whole design follows from — every one-click installer solves *"get WordPress
running"* and none solve *"still be running, still be yours, in six months."*

Written in first person and kept specific, because a README that says
"enterprise-grade security" tells a reader nothing, while "the backup was an
empty file and had been for a year" tells them exactly which problem this
exists to solve. Personality here is not decoration — it is the part that
explains *why* the opinionated defaults are what they are.

The closing paragraph restates the project's stance: every control states its
limits at the prompt rather than in documentation, because a control you
over-trust is worse than one whose edges you know.

Footer invites issues and pull requests, and says that a report of something
this gets wrong is the most useful thing to send — which, given how many of
this project's real bugs were found by running it rather than reading it, is
straightforwardly true.

---

## Unreleased — Closing line on the introduction

A one-line summary now sits below the signature, in the installer and at the
top of the README:

> "~91% of WordPress vulnerabilities live in plugins — where most hardening
> never looks. This one does."

Two deliberate choices in the wording. It says **"looks there too"** rather
than "scans your plugins for CVEs": `wp-plugins.sh` surfaces what is out of
date through the WordPress.org update API, which is the practical remediation
path, but it is not a CVE-matching scanner. Overstating that in the one line
people will remember would be precisely the behaviour the rest of this
installer refuses to engage in.

And the figure carries its source (Patchstack, *State of WordPress Security in
2026*) rather than floating as an unattributed statistic. A security tool
quoting a number at you without saying where it came from is asking for trust
it has not earned.

---

## Unreleased — Introduction before the first prompt

The installer opened straight onto "VM ID [101]:" with a three-line banner.
It now leads with a short explanation of what is actually different here,
shown once before anything is asked, ending **by RothITguy**.

The constraint applied while writing it: every claim has to be checkable
against the finished VM. So it names the specific mechanisms — MariaDB on an
`--internal` network with no host port and no egress; a CVE-scanned,
health-checked candidate container validated while production keeps serving,
with automatic rollback; digests rather than tags, so what was scanned is what
runs; backups whose exit status, completion marker and archive are all
verified before anything is rotated away; ~45 post-install checks that print
the command to fix each failure; and plugin CVE visibility, which is where
~91% of WordPress vulnerabilities live and which container scanning does not
reach.

It also states what this is **not** — not a managed service, not a substitute
for off-box backups, not protection against someone specifically targeting
you. "It raises the floor considerably and is honest about the ceiling."

That last paragraph is the point of the whole thing. An installer that lists
only its strengths sets someone up to over-trust it, and this project has
spent the last several rounds fixing exactly that failure mode at the level of
individual prompts. Doing it in the introduction and not at the top would have
been inconsistent.

A single Enter keypress separates it from the first prompt, so it is read
rather than scrolled past.

---

## Unreleased — Security reasoning on every relevant prompt, attributed

Extended the "state the bound of the control" principle across the installer.
Nine prompts now carry a signed *"What this does and does not buy you"* block,
rendered by shared `_sec_head` / `_sec_note` helpers so the format and the
attribution stay consistent:

- **Root password** — root SSH is disabled unconditionally, so this is a
  console-only credential. That is deliberate (a recovery path independent of
  the network, SSH, and whether the admin account was created), but it means
  the password is only as meaningful as the Proxmox login that can open that
  console. Hypervisor-tier secret, not a throwaway. Placed *before* the retry
  loop, or it would reprint on every mistyped confirmation.
- **Network mode** — framed as a security decision, not just networking:
  SSH and wp-admin restrictions, reverse-proxy trust, and any external rule
  naming this VM are all keyed to its address. A DHCP lease change moves the
  host out from under all of them silently.
- **SSH source restriction** — the highest-value control here, because it
  removes the host from internet-wide brute-forcing entirely rather than
  surviving it; and it trusts the network, so a compromised workstation
  inside the allowed range is unaffected by it.
- **Custom wp-admin slug** — named as obscurity, and defended as worth having
  on its own terms (bots only try `/wp-login.php`, so they get a 403 before
  PHP runs). Then what it does not stop: a leaked reset email, a plugin that
  prints the login URL, the REST API. A filter, not a secret.
- **CrowdSec enrolment** — states plainly that signals about attacks on this
  VM leave it, alongside the real gain (a shared blocklist of addresses
  already attacking others), so it is a decision rather than an unnoticed
  default.
- **Digest pinning** — guarantees **identity, not safety**. A pinned image
  with a critical CVE stays pinned to that vulnerable image; pinning is what
  makes Trivy's verdict meaningful, not a substitute for it.
- Plus the egress firewall and GeoIP blocks from the previous entry.

Each block is signed **— RothITguy**, making clear these are the project
author's considered judgements rather than generic vendor boilerplate. The
signature is applied once per reasoning block via a helper rather than
sprinkled through the output, so it reads as authorship rather than noise.

---

## Unreleased — Security prompts state their own limits

The egress caveat existed but was structurally backwards: the concrete,
memorable examples (a reverse shell on 4444, IRC on 6667) were attached to the
**benefit**, while the limitation was abstract and sat above a paragraph of
reassurance about opening ports later. That is how a control gets
over-trusted — the vivid part sells it and the bound gets skimmed.

Reordered so the limitation is as concrete as the benefit and appears
immediately before the question, with nothing between it and the prompt.

**Applied the same standard to GeoIP**, which had no limitation statement at
all. It now says plainly that country filtering is very effective against
bulk opportunistic traffic — which is most of what hits a WordPress site —
and is defeated in seconds by a VPN, proxy or Tor exit in an allowed country.
A noise filter, not a boundary. It also warns that legitimate visitors
travelling or on a VPN will be blocked, and confirms that LAN and loopback are
exempt so it cannot lock the operator out of wp-admin.

The principle: if the honest bound on a security control is worth writing in
the README, it is worth putting in front of the person choosing whether to
rely on it.

---

## Unreleased — Optional outbound (egress) firewall

`TODO.md` has carried egress restriction as deferred, on the grounds that
host-level egress rules are brittle against legitimate update paths and the
network edge is the better layer. That reasoning holds for a *default*; it
does not hold for an informed opt-in, which is what this adds.

**Off by default.** Answering no leaves behaviour exactly as before — only the
hypervisor management plane is blocked. Answering yes allows 53, 123, 67/68,
80, 443 and the mail ports, and drops everything else with rate-limited
logging.

Each allowed port has a named consumer, so the list describes this system's
actual dependencies rather than a guess: DNS and NTP (chrony — TLS validation
and log correlation depend on it), apk repositories, container registries,
WordPress and plugin update APIs, CrowdSec CAPI, MaxMind, the Trivy
vulnerability database, and SMTP.

**Stated honestly in the prompt and the README:** 443 must stay open, so this
is not containment against a determined attacker. It removes the easy
options — C2 on an odd port, a reverse shell on 4444, IRC on 6667, bulk
exfiltration over a random high port.

**Two ordering hazards handled, both of which fail silently if you get them
wrong:**

- The `forward` chain now accepts traffic *toward* the container subnets
  before any egress allowlist is consulted. WordPress reaches MariaDB across
  wp-front/wp-db, and a "restrict what containers may send" rule placed above
  that would sever the database connection while looking like a hardening win.
- The `output` chain accepts `ct state established,related` and loopback
  before anything can drop. Without it the reply packets of an *inbound* SSH
  session count as new egress and get dropped — locking the operator out of a
  VM that is otherwise fine.

**Runtime management** via `wp-hardening.sh egress-list|egress-allow|egress-deny`.
Added ports live in nftables named sets, so a change applies to the running
ruleset immediately — no regeneration, and no window where the firewall is
absent — and is persisted to `/etc/wp-install/egress-extra.nft`, which the
main ruleset includes. That file is created empty at install because nftables
treats a missing include as fatal, and a fatal ruleset error means the VM
boots with **no firewall at all** — much worse than the feature not working.

---

## Unreleased — Rollback fault-injection test (`test/vm-rollback-test.sh`)

The post-cutover rollback branch is the last significant path in this project
that has never executed. It cannot be reached with a normal image, because it
requires a candidate that PASSES validation and then a production container
that FAILS it — from the same image.

So it is now tested by fault injection rather than by contriving a broken
image. `wp-health-check.sh` is temporarily replaced with a wrapper that passes
through for the candidate and fails for the container named `wordpress`. The
two calls are distinguishable by their first argument (`wordpress-candidate`
vs `wordpress`), so everything up to the cutover behaves exactly as in
production and only the post-cutover verdict is forced. The real rename,
restore and restart code then runs — this is a genuine test of that branch,
not a simulation of it.

Verified before shipping: the wrapper passes for `wordpress-candidate` and
fails for `wordpress`; a non-zero result there reaches the
`Health check failed — rolling back…` branch; and that branch does
`podman rm -f wordpress` before `podman rename wordpress-old wordpress`, so
the rename cannot collide with the container it is replacing.

One refinement to the checks while writing it: `check-line-continuations.py`
flagged a line in the new script that was a *comment* ending in a backslash,
followed by another comment — help text wrapping a long example command. A
trailing backslash on a comment line is not a continuation, so that was a
false positive in the checker, now fixed. Confirmed it still catches the
genuine bug by re-injecting it.

The script restores the real health check on every exit path including
`Ctrl-C` (trap, not just the happy path), refuses to run if a stale
`wordpress-old` already exists, auto-derives a target tag that differs from
the running one, and requires typing `rollback-test` to proceed. On failure it
prints the manual recovery sequence and the `qm rollback` fallback, and says
plainly that a Proxmox snapshot is the real safety net — the script cannot
undo a broken rollback, and finding out whether one exists is the point.

---

## Unreleased — Cutover proven end to end; wp-cli wrappers had no DB access

**The candidate/cutover path works, in both directions.**

```
✔  Candidate healthy (HTTP + PHP + DB confirmed) — swapping production to the new image now
✔  WordPress base image updated to 6.9.4-php8.4-apache
...
✔  WordPress base image updated to 6.9.4-php8.3-apache
```

That was the last major unexercised path in the project. `TODO.md` has carried
it as deferred since the beginning because it needed real hardware. It is now
proven forwards and back: candidate start, validation, rename to
`wordpress-old`, new container up, post-cutover validation, old container
removed.

**Separately: both wp-cli wrappers could not reach the database.**

`wp-mail.sh test` reported:

```
Error: Error establishing a database connection.
```

That is not a mail failure -- wp-cli never got as far as SMTP. The official
WordPress image uses `wp-config-docker.php`, which reads `DB_NAME`, `DB_USER`
and `DB_PASSWORD` from the **environment**. The wp-cli container mounted the
same html directory but was given none of those variables, so it loaded a
wp-config that resolved to nothing. `wp-plugins.sh` had the identical defect
and would have failed identically on first use.

Both now pass `--env-file /etc/wordpress/env` and
`-e WORDPRESS_DB_HOST=mariadb:3306` -- the same env-file the real container
uses, so they cannot drift.

Confirmed by the operator receiving a real message from the VM: `wp_mail()`
inside the container was working the whole time, which is exactly what this
diagnosis predicts. The relay credentials were never the problem.

**Error attribution fixed too.** `wp-mail.sh` reported a database failure
under "Credentials, TLS, DNS or reachability" -- pointing at the mail server
when the mail server was fine. A database error is now named as one, with an
explicit note that the relay was never contacted.

**Cosmetic:** `podman rename`/`stop` echo the container name, so cutover
printed a bare `wordpress-old` three times into the operator's output, looking
like a warning. Suppressed on stdout; stderr and exit status (which the
surrounding `if !` depends on) are untouched.

**Worth recording:** while making the above fix, the comment explaining it was
inserted inside a `podman run` line-continuation -- the exact mistake that
broke the installer two rounds ago. `test/check-line-continuations.py` caught
it before it shipped. That is the first time one of these checks has stopped a
regression rather than explained one after the fact.

---

## Unreleased — Candidate health check probed the wrong port

The cutover test got further than ever: the candidate started, and PHP, DNS
and the database all passed inside it. Only HTTP failed, with `none` -- no
response at all rather than an error code. Production was never touched.

**Cause: a port-namespace mistake.** The candidate publishes
`-p 127.0.0.1:18080:80`, so 18080 is the **host** side and Apache listens on
**80** inside the container. `wp-health-check.sh` does `podman exec` and
probes `127.0.0.1` *from within* that namespace, where nothing is bound to
18080 -- so a genuinely healthy candidate reported no HTTP response. The
other three checks passed precisely because none of them involve the port.

Two ports with the same name in different namespaces, one variable. The
host-side wget fallback a few lines below is correct to use 18080; the
`podman exec` probe never was.

**Fixed:** the candidate probe passes 80, like every other call site
(`WEB_CHECK_PORT=80` elsewhere -- this was the only defect). This was the
last unexercised bug in the never-before-run candidate path.

**Diagnosis improved.** `Unexpected HTTP response: none` said nothing useful.
A no-response result is now reported distinctly from a real HTTP error code,
states that the probe runs inside the container and the port must therefore
be the in-container one, and prints the sockets actually listening in there.
The argument is documented at the point it is read.

**Check added** (`test/check-healthcheck-ports.py`): every
`wp-health-check.sh` invocation must pass `80` or `WEB_CHECK_PORT`. Verified
by re-injecting the bug. (Its first version matched an `ok "..."` status
message that merely named the script and read an em dash as a port -- caught
and tightened to absolute-path invocations before shipping.)

---

## Unreleased — A nonexistent image tag is now reported as such

A cutover test targeted `6.9.3-php8.3-apache`, which does not exist on Docker
Hub. **The system behaved correctly** -- Skopeo could not resolve it, Trivy
could not find it, `DEPLOYMENT_PROFILE=production` refused to proceed on an
unknown security state, and production was never touched. The fail-closed
path worked.

The *diagnosis* was the problem. The operator was told:

> Scanner-side failures (DB download, registry timeout, corrupt cache) look
> like this — treat as unknown security state. [...] Investigate the scanner
> failure above and retry.

None of which applied. Trivy emits four errors for a missing tag and three
are irrelevant noise (no docker socket, no containerd socket, no podman
socket); the real one -- `MANIFEST_UNKNOWN` -- is last and easily missed. So
a mistyped version sent the operator to debug a scanner that was working
fine.

**Fixed in two places:**

- `scan_image` now recognises `MANIFEST_UNKNOWN`/`unknown tag` and says the
  tag does not exist, with the command to list the tags that do -- instead of
  reporting an unknown security state.
- More usefully, `_check_component` catches it **first**. Skopeo is the
  earliest thing to touch the registry, so the condition is detectable
  minutes before the pull and scan that would fail for the same reason. This
  required actually capturing Skopeo's stderr, which was previously sent to
  `/dev/null` -- so the distinction between "no such tag" (fatal) and "lookup
  failed" (transient, tag comparison is a reasonable fallback) was not
  available at all.

All three callers now stop on that condition; previously the return value was
discarded and execution fell through to the pull and scan regardless.
`_check_component` also got an explicit `return 0`, since its exit status is
now load-bearing rather than incidental.

---

## Unreleased — Clean install; `wp-mail.sh test` argument bug fixed

**A fully clean run.** Install-time validation `15 checks passed, 0 failed`,
post-install `Passed: 47  Warnings: 0  Failed: 0`. Every failure mode found in
the field so far -- the lost `cp`, the broken `podman run`, the missing
libmaxminddb, the `<RequireAll>` context, the GeoIP local-address 403, the
empty-User-Agent 403, the apostrophe, the conditionally-gated mu-plugin -- is
resolved on real hardware.

The only failure came from `--send-test-mail`, and it was mine:

```
Error: Too many positional arguments: contact@rothitguy.pro
```

`wp eval` takes exactly one positional (the code) and has no `$argv`
passthrough -- that is `wp eval-file`. I passed the recipient as a second
argument, so wp-cli rejected the call and the send never reached the relay.
The failure therefore looked like a mail problem when `wp-mail.sh doctor`
showed the whole path healthy: DNS resolving, TCP 587 reachable, credentials
present, mount read-only.

**Fixed** by passing the address through the container environment instead:
nothing to quote wrongly, and the address never becomes part of the PHP source,
so an unusual character in it cannot alter the code being evaluated. The
address is also validated before it reaches either the argument list or the
environment.

**Also:** `wp-mail.sh doctor` printed the mount as `/var/www/private:false`,
where `false` is the read-write flag -- so the correct state read like a
failure. It now says `mounted READ-ONLY (correct)`. And `mail` was missing
from the validator's "Sections:" hint.

---

## Unreleased — First real `update.sh` run: candidate could not start

`update.sh` had never been exercised on hardware -- `TODO.md` has carried
"full candidate/cutover/rollback coverage" as deferred precisely because it
needed a real VM. The first run found a latent bug in the candidate path.

```
(13)Permission denied: AH00091: apache2: could not open error log file
    /var/log/apache2/error.log
```

**Cause.** The candidate mounted `/var/log/apache2` as a bare `--tmpfs`,
which is root-owned. Apache in this image runs as **www-data**, not root --
which is exactly why the candidate must be granted `NET_BIND_SERVICE` to bind
:80 in the first place -- so it could not create `error.log` and refused to
start. Production has always worked because it bind-mounts
`/home/wpuser/wp/logs`, which stage 04 chowns to `33:33`. The candidate never
mirrored that.

**Fixed** by giving the candidate its own `logs-candidate` directory, owned
`33:33`, cleared before each run -- the same arrangement production has been
proving correct since the beginning, rather than a second mechanism with
different ownership semantics.

**A second reason this was hard to find, now also fixed.** A tmpfs is
destroyed with its container, so `podman rm -f` on the failed candidate
deleted the one log that explained the failure. The bind mount survives, and
the failure path now prints both `podman logs` and the candidate Apache
`error.log` inline instead of discarding them.

Everything downstream in that run -- "PHP did not execute", "mariadb hostname
does not resolve", "DB check did not run" -- was the health check probing a
container that had already exited, not four separate faults.

**Correct behavior worth noting:** production was never touched. The
candidate/cutover design did its job; only the candidate itself was broken.

---

## Unreleased — GeoIP working end to end; SMTP mu-plugin install fixed

**GeoIP now works completely.** From the field log: `Smoke test passed -
Apache loads mod_maxminddb in the new image`, then `WordPress responding and
healthy with GeoIP active`. Every fix in the chain landed -- libmaxminddb
carried into the final image, the build-time `ldd` gate, `<RequireAll>` inside
`<Location />`, the RFC1918/loopback exemption, and full mount parity in the
smoke test.

**Install validation is clean:** `15 checks passed, 0 failed`. Post-install:
`43 passed, 0 warnings, 1 failed`.

**That one failure was the new mail section catching a real bug of mine.**
`SMTP mu-plugin is missing` -- because I had installed it inside
`if [ -n "$WP_ADMIN_SLUG" ]`, which is where the *other* mu-plugin lives and
where `MU_DIR` is defined. With no custom slug (the default) that block is
skipped entirely, so mail transport was never installed and `wp_mail()` fell
back to PHP `mail()` with no sendmail present -- failing silently, which is
the precise thing this feature exists to prevent.

Fixed: its own unconditional block with its own directory variable, plus a
post-install verification, since assuming is what failed. It installs even
with no relay configured -- the mu-plugin returns early without its config
file, so `wp-mail.sh setup` can enable mail later with no container rebuild.

**Check added** (`test/check-install-conditionals.py`): flags any
must-always-install payload file sitting inside a conditional. Verified by
re-introducing the exact bug -- it reports it. Also added
`test/run-all-checks.sh` to run every static check and both syntax sweeps in
one command, with a note in its header that these are necessary and not
sufficient.

---

## Unreleased — Smoke test mount parity, mail validation, plugin CVE answer

**The health check passes.** `HTTP response: 302`, `ALL CRITICAL CHECKS
PASSED`. The User-Agent root cause is closed.

**The smoke test did its job.** It rejected a bad GeoIP image and left the
running container untouched -- "the site is still up and still serving" --
which is exactly the systemic gap it was added to close.

**But the failure it reported was its own.** `Invalid command 'Header'` is
mod_headers not being enabled, because the smoke test mounted
`wp-security.conf` without `headers.load`. The comment above that block said
the test "must mount EVERY file the real container will mount", and then
hand-maintained a second list anyway -- twice now (first geoip.conf, then
headers.load). Fixed structurally: one `GEOIP_VOL_ARGS` list is built once
and used by both the smoke test and the real run, including the conditional
`remoteip.conf`, so they cannot drift.

**New: `validate-wordpress.sh` mail section.** Runs on every validation:
relay configured, credential file `0400`/uid 33, file outside the docroot,
mu-plugin present, mount read-only, firewall rate limit live. A real delivery
is opt-in via `--send-test-mail <addr>` -- a command people run repeatedly
should not mail a person every time -- and it goes through `wp_mail()`
itself, since testing the relay another way proves the relay works while
saying nothing about whether WordPress can use it.

---

## Unreleased — REGRESSION FIX 3: an apostrophe broke the health check

The User-Agent fix was correct; the comment I wrote explaining it was not.

```
/usr/local/bin/wp-health-check.sh: line 54: //: Permission denied
```

The PHP probe is passed to the interpreter as a **single-quoted shell
string**. I put the explanation inside that block, and the prose contained
`PHP's` and `site's`. Each apostrophe terminates the string; everything after
it is handed to the shell, which then tried to execute `//` as a command. The
probe never ran, so HTTP reported `none` on every retry.

`sh -n` passed it. The file remained valid shell -- just a completely
different program from the intended one. (A different apostrophe placement
*can* produce a syntax error, so this is not reliably caught either way,
which is the point.)

**Fixed** by moving all prose into shell `#` comments above the block, where
apostrophes are harmless -- the file already contains "server's" and "can't"
there safely. The PHP block now holds only PHP.

**Check added** (`test/check-embedded-quotes.py`): finds single-quoted
embedded code blocks (`php -r`, `perl -e`, `awk`, `python -c`) and reports
any that get terminated mid-prose by an apostrophe. It understands the
deliberate `'"$VAR"'` splice idiom and does not flag it, and it blanks shell
comment lines first so a comment that merely *describes* the pattern is not
mistaken for one (which it was, on the first attempt -- caught and fixed
before shipping this time).

Verified by re-injecting the exact bug: the checker reports it.

---

## Unreleased — MaxMind credential prompt no longer degrades silently

Answering `y` to GeoIP and then getting `GeoIP: disabled` in the summary, with
no `/var/log/wp-geoip.log` to explain it, was a UX failure rather than a bug:
the License Key had come back empty, so `GEOIP_ENABLED=0` and
`wp-geoip-setup.sh` was never run.

Why that was easy to miss: the License Key prompt is a no-echo read, so a
paste that failed to register looks identical to typing it correctly. The old
code printed one warning and continued straight into the digest-pinning
explainer, which pushed it off screen within a second.

Now it re-prompts rather than degrading silently -- the same pattern the
production profile already uses for a missing SSH key -- says specifically
*which* field was empty and that the key prompt does not echo, links the
MaxMind page, and requires an explicit `n` to continue without GeoIP. On
success it confirms what was captured (account ID, and the key's **length**
only, never its value) so a bad paste is visible immediately. The skip path
now also points at `wp-geoip-setup.sh`, which can enable GeoIP later with no
reinstall.

---

## Unreleased — ROOT CAUSE of the persistent 403: the WAF blocked our own probe

The install now completes: 14 of 15 post-install checks pass, the container
is up, port 80 listens, and the validator's own HTTP check reports a non-error
response. The single remaining failure was the 403 that has appeared in every
field log since the beginning — and the contradiction in this run is what
isolated it, since GeoIP was disabled, so GeoIP was not the cause.

**The 8G firewall this project installs contains, deliberately:**

```apache
RewriteCond %{HTTP_USER_AGENT} ^$ [NC]
RewriteRule .* - [F,L]
```

That 403s any request with an empty `User-Agent`, which is a sound rule --
it is a common scanner signature. But `wp-health-check.sh` probes the site
with PHP's HTTP stream wrapper, which sends the `user_agent` ini value, and
that is **empty by default** in the official WordPress image.

So the site's own WAF had been blocking the installer's own health check on
every request, for the entire life of this project. It explains the exact
signature seen every time: PHP passes, DNS passes, the database query
passes, and HTTP returns 403 through all 24 retries while the container is
demonstrably healthy.

**Fixed** by having the probes identify themselves (`User-Agent:
wp-health-check/1.0`) rather than by weakening the rule. This is also better
practice independently: health probes are now distinguishable in the access
log instead of looking like anonymous scanner traffic.

Applied to every in-container probe, not just the one that surfaced:
`wp-health-check.sh`, `validate-wordpress.sh`, `update.sh` (three candidate
and cutover probes) and `wp-geoip-setup.sh`. The BusyBox `wget` probes send a
UA of their own today, so they were not failing -- they are set explicitly so
a future BusyBox change cannot reintroduce this silently.

Verified that the chosen string matches none of the six 8G user-agent
patterns, and restricted it to `[A-Za-z0-9./_-]` so it cannot trip a future
rule either.

---

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
