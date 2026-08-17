# WASP Support Runbook

A troubleshooting guide organised by **who is reading it**, so the right person
can act without needing everything the author knows. Three tiers:

- **[Tier 0 — Anyone](#tier-0--anyone)** — a client or non-technical person.
  No command line. What to check, what to report, when to escalate.
- **[Tier 1 — On-shift tech](#tier-1--on-shift-tech)** — can run commands, follow
  a decision tree, knows basic Linux. Most incidents resolve here.
- **[Tier 2 — Engineer](#tier-2--engineer)** — understands the architecture and
  handles what Tier 1 escalates.

**If you only read one thing:** the console always works. On the Proxmox host,
`qm terminal <VMID>` reaches the VM even when SSH, the website and everything
else is down. Root SSH is disabled by design; the console is not. That is the
way back in when nothing else responds.

Every command below that touches the VM is run over SSH as the admin user and
elevates itself (it will ask for the admin password once), **or** typed at the
`qm terminal` console as root. You do not need to prefix anything with `sudo`.

---

## Tier 0 — Anyone

For a client, an account manager, or anyone without a technical background.
**You cannot break anything by following this section** — it is all looking, not
changing. Your job here is to check three things and report clearly.

### The website looks down

1. **Try it from your phone on mobile data** (not office wifi). If it loads on
   your phone but not your computer, the problem is your own network or an
   ad-blocker, not the site. Nothing to report.
2. **Wait two minutes and reload once.** A site briefly restarting looks down
   for under a minute. If it comes back, note the time and move on.
3. **If you see "Error establishing a database connection" just after a reboot,
   that is expected and clears itself.** The database takes 20–60 seconds to
   accept connections after the VM starts, and WordPress reconnects on the next
   request. Wait a minute and reload. It is only worth reporting if it is still
   showing after five minutes, which means something else.
3. **If it is still down after two minutes**, report it with these exact details,
   which are what a technician needs and cannot get after the fact:
   - The **web address** you tried
   - The **exact error** on screen — take a screenshot, do not paraphrase.
     "It's broken" and "502 Bad Gateway" send a technician to completely
     different places.
   - **When** it last worked, if you know
   - Whether it fails **for everyone** or just you (ask one other person)

### You cannot log in to the WordPress admin

- **A "not found" or "forbidden" page at the login address** usually means you
  are connecting from a location that is not on the allow list — a new office, a
  phone hotspot, a VPN. Report the **network you are on**; access is restricted
  by location on purpose.
- **The login page loads but rejects your password** is an ordinary password
  problem. Use the reset link, or ask for a reset. This is not an outage.
- **Do not keep retrying a password.** After several failures the system will
  block your address for a while as a security measure, and you will lock
  yourself out longer. Stop after two or three and ask for a reset.
- **A page asking you to set up two-factor authentication** is expected for
  administrator accounts. Follow it: install an authenticator app (Google
  Authenticator, 1Password, Authy, Microsoft Authenticator all work), scan the
  code, and — this part matters — **print or save the backup codes it gives
  you.** Those codes are how you get back in from any device if you lose your
  phone. If you are blocked because a grace period ended before you set it up,
  ask an engineer; they can help you enrol.

### You received an alert email from the system

The VM sends these itself. **Forward it — do not act on it.** The subject line
tells a technician most of what they need:

- **"Disk at 8x%"** — housekeeping, not urgent, but forward it today.
- **"Backup failed"** or **"Self-test failed"** — forward promptly. Nothing is
  visibly wrong to you, which is exactly why it matters.
- **Anything mentioning "malware", "CRITICAL", or "compromise"** — forward
  immediately and do not use the site's admin area until told it is clear.

### What to never do

- Do not share the login address publicly — its obscurity is part of the
  protection.
- Do not install a plugin "to fix it". On a WASP site a new plugin can trip the
  security controls and turn a small problem into a visible one.
- Do not forward alert emails to the client if you *are* the client — send them
  to whoever maintains the site.

---

## Tier 1 — On-shift tech

You can SSH in and run commands. This tier covers the large majority of what
comes in. Work top to bottom; the first matching symptom is usually the answer.

### Start every investigation the same way

One command gives you the whole picture and an exit code a script can read:

```sh
ssh admin@<vm-ip>
validate-wordpress.sh --check
```

- **`OK`** → the platform is healthy. The problem is content, DNS, or the
  client's network, not the VM. Skip to *Site loads but something's wrong*.
- **`WARNING`** → degraded but serving. Usually backup age. Note it, continue.
- **`CRITICAL`** → containers or database or disk. Go to *Site is down* now.

If SSH itself does not connect, go straight to **[the console](#when-nothing-responds)**.

### Symptom → action

| What the client reports | First check | Most likely cause and fix |
|---|---|---|
| **Whole site down, 502** | `validate-wordpress.sh --check` | Backend not answering. `podman ps` — is `wordpress` up? If not, `podman restart wordpress`. If it restarts then dies, → Tier 2 |
| **Whole site down, 503** | `validate-wordpress.sh --check` | Overload or a rate limiter. Check `podman logs --tail 40 wordpress`. If disk is full (`--check` says so), that is the cause |
| **Site down, "database connection"** | `podman ps` | MariaDB not ready. `mariadb-health-check.sh`. After a reboot this self-clears in ~1 minute |
| **403 on the admin area** | `wp-hardening.sh proxy-check` | Your IP is not allowed, or the proxy is not passing it. See *The 403 tree* below |
| **Admin login rejects a good password** | — | Ordinary reset. Not an outage. `wp-rotate-secrets.sh` is **not** for this — that rotates system creds, not user passwords |
| **A plugin or update fails silently** | `wasp-egress status` | If egress filtering is on, the plugin may be calling a blocked destination. `wasp-egress discovery` shows what was denied — check *before* blaming the plugin |
| **Contact form / site email not arriving** | `wp-mail.sh status` | `wp-mail.sh test you@example.com`. A wrong SMTP password fails silently — that is the usual cause |
| **"I'm locked out by SSH too"** | — | CrowdSec may have banned the address. See *Un-banning* below |
| **Alert: disk at 8x%** | `wp-hardening.sh disk` | Shows what is using it and what is safe to reclaim. Usually old images: `podman image prune -f --filter dangling=true` |
| **Alert: backup failed** | `wasp-offsite-backup.sh status` | Is the off-site destination reachable? Run `wp-db-backup.sh` by hand and watch it. If it fails the same way, → Tier 2 |
| **Alert: malware / CRITICAL** | **stop** | Do not clean anything yet. Go to *Suspected compromise* and follow it in order |

### The 403 tree

A 403 on the admin area, with the public site working, is the single most
common WASP-specific call. Work it in this order:

```sh
wp-hardening.sh proxy-check
```

- **It shows your real client IP** → your address simply is not on the allow
  list. Add it: `wp-hardening.sh web-allow <your-ip>`. Done.
- **It shows the proxy's IP instead of yours** → the reverse proxy is not
  passing the real client address, so the VM thinks every request comes from the
  proxy and the fail-closed rule denies it. Give yourself a direct path that
  does not depend on the proxy:
  ```sh
  wp-hardening.sh web-allow <your-ip>
  ```
  then reach the site directly. If that fixes it, the proxy's forwarding is
  misconfigured — → Tier 2 to fix the proxy properly.
- **Still 403 after both** → the fail-closed admin rule may be the cause.
  Isolate it, do not leave it this way:
  ```sh
  wp-hardening.sh admin-rule simple      # temporarily relax; note you've done this
  # test access
  wp-hardening.sh admin-rule strict      # put it back
  ```
  If `simple` lets you in, the rule and the proxy header are the issue → Tier 2.

### Un-banning an address CrowdSec blocked

```sh
podman exec crowdsec cscli decisions list           # see who is banned
podman exec crowdsec cscli decisions delete --ip <ip>
```

Only remove a ban you recognise as a false positive — a client's own office IP
that got caught retrying a password. Do not clear bans wholesale; most of them
are correct.

### When nothing responds

SSH refused, site dead, `--check` unreachable. From the **Proxmox host**:

```sh
qm list                        # find the VMID and confirm the VM is running
qm terminal <VMID>             # root console — always works
```

At that console you are root, no elevation needed. `podman ps`, restart what is
down, check `df -h` for a full disk. If the VM itself shows stopped in
`qm list`, `qm start <VMID>`.

> Note: the console cannot paste. For anything you need to copy in, use the SSH
> session as the admin user instead — but the console is what you have when SSH
> is gone.

### What to hand up, and how

Escalate to Tier 2 when: a container restarts and immediately dies, `--check`
stays CRITICAL after the obvious fixes, anything mentions malware, or you find
yourself about to change something you do not understand. **Stop before that
last one.** When you escalate, include:

```sh
wasp-testreport.sh                    # the full report — capture the file it writes
```

plus what you already tried. A report the engineer can read beats a description
of the symptom.

---

## Tier 2 — Engineer

You know the architecture (see `ARCHITECTURE.md`). This tier is the failures
Tier 1 correctly did not attempt, and the ones that need judgement.

### A container starts then dies

```sh
podman logs --tail 100 wordpress          # or mariadb / crowdsec / squid
podman inspect wordpress | grep -iA3 'health\|exit'
```

Common causes: a bad `wp-config.php` after a hand-edit (the container refuses to
start rather than serve broken); MariaDB not up when WordPress checked (the
readiness wait in the service should cover this — if it is not, the wait may
have been bypassed by a manual `podman start`); a corrupted image after an
interrupted pull (`update.sh versions`, then re-pull the pinned tag).

### `--check` stays CRITICAL after the obvious fixes

Walk the four things it checks, by hand:

```sh
podman ps                                         # containers
podman exec mariadb mariadb-admin ping -uroot -p"$MARIADB_ROOT_PASSWORD"
df -h /                                            # disk
ls -t /root/wp-db-backups/*.sql.gz | head -1       # backup freshness
```

Disk at 100% is the sleeper: MariaDB refuses writes before the disk is visibly
full and nothing names disk as the cause. `wp-hardening.sh disk` shows the
consumers; old container images are usually it.

### Suspected compromise — the ordered response

Do **not** start deleting files. The order matters, because the first instinct
(quarantine the bad file) destroys the evidence for everything else. Full detail
in `INCIDENT-PLAYBOOK.md`; the spine:

```sh
wp-malware-scan.sh full                   # 1. full picture — do not act on line one
wp-forensics.sh timeline --around <file>  # 2. WHEN did it appear, what else happened then
wp-forensics.sh entry-class               #    which way in (uploads / plugin / admin / core)
wp-malware-scan.sh quarantine <file>      # 3. NOW contain it — captures the timeline first
wp-forensics.sh admins                    # 4. persistence that outlives cleaning the file
```

If egress is on, what the site tried to reach outward is often the clearest
signal of intent:

```sh
wasp-egress discovery
grep DENIED /opt/squid/logs/access.log | tail -30
```

Then rotate everything and reset admin passwords:

```sh
wp-rotate-secrets.sh all                  # database + salts, kept in sync, reversible
wp-rotate-secrets.sh smtp '<new>'         # after changing it at the relay
wp-forensics.sh admins                    # then reset each admin's password
```

**Do not rotate the age backup key** — it makes every existing encrypted backup
unreadable. If the compromise predates your backups, that is a restore-point
decision, not a key-rotation one.

### Restore from backup

```sh
wasp-offsite-backup.sh verify             # a good copy exists off the VM
wasp-selftest.sh restore-test             # prove it restores into a throwaway DB first
```

Only after the restore-test passes do you restore for real. Restoring a backup
that itself contains the compromise is the expensive, common mistake — establish
*when* the compromise started (the timeline above) before choosing which backup
is clean. A tight deadline is what pressures someone into restoring a poisoned
backup; resist it.

### Update or roll back

```sh
update.sh versions                        # what tags exist
update.sh wp <tag>                        # candidate → CVE scan → health check → cutover
```

The update stages a candidate, scans it, health-checks it, and only then cuts
over — rolling back automatically if the post-cutover check fails. If you need to
force a rollback, the previous image is kept until the new one passes; on the
Proxmox host, `qm rollback <VMID> <snapshot>` is the coarser undo if you
snapshotted first (you should have).

### Verify the tooling itself hasn't been tampered with

```sh
wasp-verify-integrity.sh                  # scripts vs the signed manifest
```

If this fails, treat the VM as compromised at the system level, not just the
application — and rebuild rather than clean.

### An admin has lost their second factor and is locked out

This is the recovery path that makes it safe to *require* 2FA at all. It needs
the VM console, which is deliberately the one entry point that keeps working
when the network login does not — so this is a Tier 2 action by design, not
something reachable from outside.

First, confirm it is genuinely a lost-factor lockout and not an IP or CrowdSec
block (walk the 403 tree and *Un-banning* first — a 2FA reset will not fix
those). The symptom for this section is specific: the admin passes the password,
then cannot complete the second step and has no backup codes.

Reset 2FA for that one user from the console. This does not touch their
password; it removes their enrolled second factors so they can log in with the
password alone and immediately re-enrol:

**wp-cli runs in its own container.** The WordPress image does not contain a
`wp` binary — `podman exec wordpress wp ...` fails with "wp: not found". Use the
wp-cli container, which shares the site's network and environment:

```sh
# On the VM console (qm terminal <VMID>), as root:
wp-plugins.sh doctor    # confirm wp-cli can reach the site first

# A small wrapper, so the rest of this section stays readable:
wpcli() {
  podman run --rm --network container:wordpress --user 33:33 \
    --env-file /etc/wordpress/env -e WORDPRESS_DB_HOST=mariadb:3306 \
    -v /home/wpuser/wp/html:/var/www/html \
    "$(sed -n 's/^WPCLI_IMAGE=//p' /etc/wp-install/pinned.env | tr -d '"')" \
    wp --path=/var/www/html "$@"
}

# Remove the user's two-factor providers. Replace <login> with their username.
wpcli user meta delete <login> _two_factor_enabled_providers
wpcli user meta delete <login> _two_factor_provider

# Also clear the WASP grace anchor so they get a fresh window to re-enrol,
# rather than being blocked again on their next login.
wpcli user meta delete <login> wpvm_mfa_grace_start

# And clear Two Factor's own login rate-limit counters, so the account is not
# still throttled from the failed 2FA attempts that led to the lockout.
wpcli user meta delete <login> _two_factor_last_login_failure
wpcli user meta delete <login> _two_factor_failed_login_attempts
```

> The two `_two_factor_*` provider keys are the plugin's own storage
> (`_two_factor_enabled_providers` and `_two_factor_provider`) — verified against
> the plugin source, because a wrong key here would silently do nothing and
> leave the admin still locked out. If a future plugin version renames them,
> `wp user meta list <login>` shows the current keys.

Then tell the admin to log in (password only now works), go straight to their
profile, re-enable an authenticator, and **print the backup codes this time.**
Watch them do it if you can — the whole reason they were locked out is that this
step was skipped once already.

If `wp-cli` itself cannot reach the site, the site has a bigger problem than
2FA; fix that first (*A container starts then dies*, *`--check` stays CRITICAL*).

> Why this is safe to document openly: it requires the VM console, which is
> reachable only with hypervisor access. An attacker who already has that has
> far more than a WordPress login. What this procedure must never become is a
> network-reachable reset — that would turn the second factor back into a
> single factor.

### The things that need you specifically

These have no runbook entry on purpose — they are judgement calls the author or
a senior engineer owns:

- Deciding a site is clean enough to return to a client after a compromise
- Choosing a restore point when the clean/compromised boundary is unclear
- Changing the egress allowlist for a plugin whose need you cannot verify
- Anything involving the age backup key or the release-signing key
- Rebuild-vs-clean after a system-level integrity failure

When you hit one of these, it goes to whoever owns the platform. That is not a
gap in the runbook; it is the line the runbook deliberately draws.

---

## Appendix — command quick reference

| Need | Command |
|---|---|
| One-line health + exit code | `validate-wordpress.sh --check` |
| Full report to read or send | `wasp-testreport.sh` |
| What's using the disk | `wp-hardening.sh disk` |
| Give an address direct access | `wp-hardening.sh web-allow <ip>` |
| What the proxy thinks your IP is | `wp-hardening.sh proxy-check` |
| See / clear CrowdSec bans | `podman exec crowdsec cscli decisions list` / `... delete --ip <ip>` |
| What egress blocked | `wasp-egress discovery` |
| Test outbound mail | `wp-mail.sh test <addr>` |
| Backups: where, encrypted, off-VM | `wasp-offsite-backup.sh status` |
| Prove a backup restores | `wasp-selftest.sh restore-test` |
| Malware scan (live site) | `wp-malware-scan.sh full` |
| Incident timeline | `wp-forensics.sh timeline --around <file>` |
| Rotate credentials | `wp-rotate-secrets.sh all` |
| Update / roll back | `update.sh wp <tag>` |
| Console when SSH is dead (Proxmox host) | `qm terminal <VMID>` |

---

*Tier 0 changes nothing and cannot break anything. Tier 1 resolves most
incidents. Tier 2 handles the rest. The line above Tier 2's "needs you
specifically" list is deliberate — some decisions should not be made by someone
following a script.*
