# KEY CUSTODY

What secrets exist, where they live, what breaks if they are lost, and who else
can reach them.

This is the bus-factor document. Every other risk on this platform is
recoverable: a broken VM can be rebuilt, a compromised site can be restored, a
misconfigured firewall can be re-run. **A lost age key cannot be recovered, and
every encrypted backup becomes permanently unreadable.** That is the only
failure here with no remedy, and it is a filing problem rather than a technical
one.

Fill this in per client and store it somewhere that survives you being
unavailable. A copy on the workstation that generated the keys is not custody.

---

## The one that matters most

### age backup key

| | |
|---|---|
| What | The private half of the keypair that decrypts off-site backups |
| Where generated | `wasp-offsite-backup.sh init`, on the VM |
| Public half | In `/etc/wp-install/vars.sh` as `OFFSITE_AGE_RECIPIENT` — safe to share |
| Private half | **Shown once at init and never stored on the VM, deliberately** |
| If lost | Every existing encrypted backup is permanently undecryptable. Not difficult — impossible |
| Rotating it | Orphans all prior backups. `wp-rotate-secrets.sh` refuses to touch it for exactly this reason |

**The private key is not on the VM on purpose.** If it were, an attacker who
reached the VM could decrypt the backups they just encrypted, which defeats the
point. That design decision is what makes this a custody problem rather than a
technical one.

Custody record:

- Held in: ________________________________ (password manager / vault, name it)
- Second copy in: _________________________ (must not be the same system)
- Who else can reach it: __________________
- Verified readable on: ____________________ (date — re-check quarterly)

**Verify it, do not assume it.** `wasp-offsite-backup.sh remote-restore-drill`
requires the key and proves it works. A key you have never tested is a key you
do not have.

---

## Release signing

### minisign secret key

| | |
|---|---|
| What | Signs `MANIFEST.sha256` for release verification |
| Where | Your build machine, never on a provisioned VM |
| Public half | Embedded in `install.sh` as `WASP_PUBKEY` and published at the DNS record |
| If lost | You cannot sign new releases. Existing ones still verify. Generate a new keypair, publish the new public key, re-sign |
| Severity | Recoverable but disruptive — every client must trust a new key |

- Held in: ________________________________
- Second copy in: _________________________
- Published public key at: _________________

---

## Credentials that are annoying, not fatal

All of these can be regenerated from the provider. None loses data.

| Secret | Where it lives on the VM | If lost |
|---|---|---|
| MariaDB root password | `/etc/wordpress/env` (0600) | Rotate with `wp-rotate-secrets.sh db` |
| WordPress DB password | `/etc/wordpress/env` (0600) | Rotate with `wp-rotate-secrets.sh db` |
| WordPress salts | `wp-config.php` | Rotate with `wp-rotate-secrets.sh salts` — logs everyone out |
| SMTP relay password | `/home/wpuser/wp/secrets/smtp.ini` (0440) | Reissue at the relay, then `wp-rotate-secrets.sh smtp` |
| Admin account password | Not stored — set at install | WordPress password reset, or console |
| Root console password | Not stored — set at install | Proxmox console + single-user boot |
| CrowdSec enrolment key | `/etc/crowdsec/` | Re-enrol from the CrowdSec console |
| CrowdSec CTI key | `/etc/wp-install/vars.sh` | New key from the console |
| Wordfence token | `/etc/wp-install/` (0600) | New token from Wordfence |
| MaxMind licence key | netrc file, root-only | New key from MaxMind |
| Object-storage keys | `/etc/wp-install/rclone.conf` (0600) | New token from the provider. **Does not affect decryptability — that is the age key** |

Note the distinction in the last row. Losing the storage credentials means you
cannot *reach* the backups. Losing the age key means you cannot *read* them.
The first is a support ticket; the second is unrecoverable.

---

## Access paths to the VM itself

| Path | Credential | If lost |
|---|---|---|
| Admin SSH | Your private SSH key | Console in as root, add a new public key |
| Root console (`qm terminal`) | Root password | Proxmox host access, single-user boot |
| wp-admin | WordPress password + second factor | Console reset — see SUPPORT-RUNBOOK.md |
| Proxmox host | Hypervisor credentials | **No path back through WASP.** Out of scope and above it |

The last row is worth stating plainly: everything here assumes you still have
the hypervisor. If Proxmox access is lost, none of this helps.

---

## Review

- [ ] Every blank above filled in
- [ ] age key verified by an actual restore drill, within the last quarter
- [ ] A second person can reach the age key and the minisign key
- [ ] Storage credentials confirmed working (`wasp-offsite-backup.sh doctor`)
- [ ] This document stored somewhere that is not the workstation that made the keys

Reviewed by: ______________________  Date: ______________

---

*The uncomfortable question worth asking out loud: if you were unavailable for a
month, could a colleague restore a client's site from an off-site backup? If the
answer depends on something only you know, this document is not finished.*
