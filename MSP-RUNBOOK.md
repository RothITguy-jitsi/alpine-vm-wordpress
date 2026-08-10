# WASP — MSP Operational Runbook

> For day-to-day troubleshooting organised by who is handling the ticket —
> a non-technical client, an on-shift tech, or an engineer — see
> **[SUPPORT-RUNBOOK.md](SUPPORT-RUNBOOK.md)**. This document is the business
> layer (SLAs, 
**Prove offsite recovery, not just offsite presence.** Verifying the remote
object exists is not proof it restores — it can be truncated or encrypted to a
key you no longer hold. Run the full round-trip monthly, and after any change
to the backup key, destination, or encryption recipient:

```sh
wasp-offsite-backup.sh remote-restore-drill
```

It pulls the actual remote object, decrypts it with the recovery key, restores
it into a throwaway database, verifies it is non-empty, and records the RTO —
turning the recovery-time number from an assumption into evidence.

RTO/RPO, onboarding, decommissioning); that one is the
> hands-on-keyboard layer.


For running WASP deployments as a service for clients. Companion to
[INCIDENT-PLAYBOOK.md](INCIDENT-PLAYBOOK.md), which covers what to do when
something fires; this covers the commitments around it.

**These are templates with defaults, not promises made on your behalf.** Every
number below should be argued about with the client before it appears in a
contract. A target you cannot meet on a bad day is worse than a longer one you
can always meet.

---

## Recovery objectives

**RPO** — how much data you can afford to lose.
**RTO** — how long until service is back.

| | Default | Determined by | To improve it |
|---|---|---|---|
| **RPO** | **24 hours** | Backup runs nightly at 02:00 UTC | Add a midday run; WordPress has no incremental DB backup |
| **RTO — bad update** | **~5 minutes** | `update.sh` auto-rollback, or a Proxmox snapshot | Snapshot before every change |
| **RTO — VM lost** | **2–4 hours** | Reinstall, then restore the newest off-VM backup | Keep a warm standby, or a recent full VM backup |
| **RTO — compromise** | **4–24 hours** | Investigation time, not restore time | Nothing shortens this safely; see below |

**Compromise RTO is deliberately vague, and should stay that way in a contract.**
Restoring takes minutes. Establishing *when* the compromise started — which
decides which backup is clean — takes as long as it takes. Restoring a backup
that already contains the backdoor is the common and expensive mistake, and a
tight RTO is what pressures someone into it.

Verify the objectives rather than assuming them:

```sh
wasp-selftest.sh restore-test        # proves the backup restores
wasp-offsite-backup.sh verify        # proves a copy exists off the VM
```

An RPO backed by a backup nobody has restored is a number, not a commitment.

---

## Service levels

Response time is when a human starts; resolution depends on what it turns out to be.

| Severity | Example | Response | Notes |
|---|---|---|---|
| **S1** | Site down, or active compromise | 1 hour | Compromise may mean deliberately staying down |
| **S2** | Admin inaccessible, backups failing, off-VM copy missing | 4 hours | Failing backups are S2 even though nothing is visibly broken |
| **S3** | Vulnerable plugin with a fix available, cert expiring | 1 business day | |
| **S4** | Advisory, hardening suggestion, expiring exception | Next window | |

**Backup failure is S2, not S3.** Nothing looks wrong to the client, and each
day it continues raises the cost of the incident that eventually needs it.

**Fleet monitoring is three layers, covered in `docs/FLEET.md`:** Pulse for VM liveness, `validate-wordpress.sh --check` per VM for WASP health, optionally MainWP for WordPress maintenance (protect its dashboard hardest — it holds keys to every site).

### What monitoring covers

| Alert | Tag | Severity |
|---|---|---|
| Backup failed | `wp-db-backup` | S2 |
| `validate-wordpress.sh --check` returns 2 | poll from your monitoring | S1 |
| `validate-wordpress.sh --check` returns 1 | poll from your monitoring | S2 |
| Off-VM copy failed | `wasp-offsite` | S2 |
| CRITICAL malware finding | `wp-malware` | S1 |
| Vulnerability finding | `wp-vulns` | S3 |
| Self-test failed | `wasp-selftest` | S2 |
| Exception expiring | `wasp-vuln-exception` | S4 |

**Uptime is covered by the heartbeat, and only by that.** Every other check
runs *on* the VM, so a VM that is off, unreachable, or on a dead hypervisor
reports nothing — and silence looks identical to health.

```sh
wp-notify.sh --heartbeat-url https://hc-ping.com/<uuid>
```

It verifies WordPress serves and MariaDB answers before pinging, so a
heartbeat cannot report healthy through a broken site. Set the external
check's period to 15 minutes with a 30-minute grace.

---

## Change control

| Change | Approval | Before | After |
|---|---|---|---|
| Plugin/theme update | Operator | Snapshot | `validate-wordpress.sh` |
| WordPress core / PHP | Operator, client informed | Snapshot | Candidate cutover handles rollback |
| Host `apk upgrade` | Operator | Snapshot | Reboot in a window |
| Firewall or admin CIDR | Operator + a second pair of eyes | **Console access confirmed** | `wp-hardening.sh proxy-check` |
| Accepting a vulnerability | Operator; governance accountable | Written justification | Emailed automatically |
| Restoring from backup | Client decides | Backup of current state | `wasp-selftest.sh` |
| Proving offsite recovery works | Operator, monthly | — | `wasp-offsite-backup.sh remote-restore-drill` |
| Egress allowlist change | Operator | Note why the destination is required | `wasp-egress test` |
| Importing a client site | Client confirms the source | `wp-import.sh inspect` and `scan` | `wp-malware-scan.sh full` on the live site |

**Confirm console access before any firewall change.** `qm terminal <VMID>`
works when SSH and HTTP do not, and the failure mode of an access-control
change is losing the ability to undo it. This has already happened once in
this project's history.

### Standard change

```sh
qm snapshot <VMID> pre-change-$(date +%Y%m%d)     # Proxmox host
doas update.sh versions
doas update.sh wp <tag>                            # candidate → scan → cutover
doas validate-wordpress.sh
doas wasp-testreport.sh
```

Rollback: `qm rollback <VMID> pre-change-YYYYMMDD`, or let `update.sh` do it —
it reverts automatically when the post-cutover health check fails.

---

## Vulnerability exceptions

Accepting a HIGH or CRITICAL finding to allow an update is sometimes right —
the fix may not exist. What must not happen is that it becomes invisible.

```sh
wp-hardening.sh exceptions          # active, expiring, expired
wp-hardening.sh exceptions-check    # the weekly reminder
```

Each exception records the **image digest** (so it cannot silently cover a
later image), the **CVEs accepted**, **who** accepted it, and an **expiry**
(90 days default). It emails the governance address with the CVE list.

**This is not an approval workflow, deliberately.** Approval belongs in
whatever process you already run. The system enforces the record; it cannot
enforce that a conversation happened — which is exactly why the notice goes to
an address other than the person who accepted it.

Review monthly. An exception nobody re-argues should lapse rather than quietly
become policy.

---

## Onboarding a client site

```sh
wp-import.sh where                    # how to get the backup here
wp-import.sh inspect <file>           # reads the index, extracts nothing
wp-import.sh extract <file>
wp-import.sh scan
wp-import.sh apply
```

**Inspect and scan before quoting the work.** A backup with a webshell in
uploads and code in autoloaded options is a cleanup engagement, not a
migration, and finding that out afterwards is how a fixed-price migration
becomes an unpaid incident response.

The gate refuses on CRITICAL without `--force`, and every override is
recorded with who made it — useful when the client later asks what was known
at the time.

**After any import**, treat the plugin set as unknown: it is someone else's.

```sh
wp-plugins.sh vulns
wp-malware-scan.sh full
wp-forensics.sh admins                # accounts you did not create
```

---

## Decommissioning

Order matters — the last step destroys the evidence for the others.

```sh
# 1. Final backup, verified, off-VM
doas wp-db-backup.sh
doas wasp-offsite-backup.sh verify

# 2. Prove it restores BEFORE anything is destroyed
doas wasp-selftest.sh restore-test

# 3. Export what the client is owed
doas wp-forensics.sh admins                    # account list
doas wp-hardening.sh exceptions                # accepted risks
doas cp /var/log/wasp-vuln-exceptions.log /root/handover/

# 4. Stop, do not delete
doas rc-service wp-container stop
# Proxmox host:
qm snapshot <VMID> decommission-$(date +%Y%m%d)
qm stop <VMID>
```

**Then wait.** Keep the stopped VM for your agreed retention — 30 days is
common — before `qm destroy`. Requests for "one more thing from the old site"
arrive after shutdown, not before.

### Credentials to revoke

Not on the VM, so nothing on it will remind you:

**Rotation is now tooled**, so "rotate every credential" in the incident
process is a command rather than an afternoon of hand-editing:

```sh
wp-rotate-secrets.sh all              # database + salts, verified and reversible
wp-rotate-secrets.sh smtp '<new>'     # after changing it at the relay
```

The age backup key is deliberately excluded — rotating it makes every existing
encrypted backup unreadable. Treat that as a re-encryption project, not a
rotation.

### Credentials to revoke on decommission

- SSH key on the backup host (`authorized_keys`)
- S3/R2 API token
- MaxMind licence key
- Wordfence token
- CrowdSec console enrolment
- SMTP relay account
- DNS records pointing at the proxy

### Backup encryption key

If backups were encrypted, **keep the age private key for as long as you keep
the backups** — they are unreadable without it. If you are destroying the
backups, destroy the key with them and record that you did. A key retained
after the data is gone is a liability with no corresponding benefit.

---

## Client-facing summary

What you can honestly claim, and what you cannot:

**Can:** egress restricted to approved destinations, with the firewall — not
application settings — enforcing it. Nightly backups, verified and copied off the VM, with restores proven
weekly by an automated test. Daily vulnerability scanning against known-issue
databases. Daily malware and integrity scanning. Firewall, geographic and
behavioural blocking. Updates tested on a throwaway container before
production, with automatic rollback. Every accepted risk recorded, expiring
and reported.

**Cannot:** guarantee no compromise. Nothing detects a backdoor written
specifically for this site, and roughly 46% of WordPress plugin
vulnerabilities have no patch when disclosed. What this buys is that a
compromise is more likely to be *detected*, that recovery is *proven* rather
than hoped for, and that the decisions taken along the way are *written down*.

Say the second part out loud. A client who believes they bought immunity is a
client who will be angry about the wrong thing.

---

*Templates. Argue about the numbers before signing them.*

— **RothITguy**
