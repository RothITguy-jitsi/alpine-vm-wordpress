# WASP — MSP Operational Runbook

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

### What monitoring covers

| Alert | Tag | Severity |
|---|---|---|
| Backup failed | `wp-db-backup` | S2 |
| Off-VM copy failed | `wasp-offsite` | S2 |
| CRITICAL malware finding | `wp-malware` | S1 |
| Vulnerability finding | `wp-vulns` | S3 |
| Self-test failed | `wasp-selftest` | S2 |
| Exception expiring | `wasp-vuln-exception` | S4 |

Nothing here monitors uptime. Pair it with external checks — this VM cannot
tell you it is unreachable.

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

**Can:** nightly backups, verified and copied off the VM, with restores proven
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
