# Safe Site Import — design

A plan, not an implementation. Written first because the ordering of this
feature is the security property: get the sequence wrong and the tool becomes
the thing that infects the VM.

---

## The one rule everything else follows from

**Nothing from the archive may be reachable by the web server, or executed by
anything, until it has been scanned.**

That sounds obvious and is the step most import tooling skips. The natural
implementation — extract into the document root, then scan — means a webshell
is live and serving for however long the scan takes. On a site being imported
*because* it is suspected compromised, that window is the whole problem.

So: extract to a staging path outside the docroot, scan there, decide there,
and only then move. If the scan fails, nothing was ever reachable.

---

## Threat model

What an untrusted WordPress backup can contain, roughly in order of how often
it is missed.

### Archive level — before a single file is read

| Threat | Why it matters |
|---|---|
| **Path traversal (zip slip)** | `../../etc/cron.d/x` in a member name writes outside the extraction directory. `tar`/`unzip` will happily do this unless told not to |
| **Symlinks** | A symlink to `/etc/shadow` or into the live docroot turns a later copy into an arbitrary write |
| **Decompression bomb** | A few KB expanding to fill the disk, taking the live site down with it |
| **Control characters in names** | Terminal escape sequences in a filename, rendered when an operator lists the directory |

Extraction has to be bounded and validated before the contents are trusted at
all. This is the layer where a tool that "just untars it" has already lost.

### File level

- **Webshells in uploads** — the classic. Near-zero false positives to detect,
  because nothing legitimate puts executable PHP there.
- **Backdoored plugins and themes** — the hard case. A modified legitimate
  plugin looks entirely normal, and there is no pristine copy to compare a
  *nulled* plugin against.
- **mu-plugins** — worse than plugins, because they are **active on arrival**.
  There is no "activate" step to withhold. A malicious mu-plugin runs the
  first time WordPress loads.
- **Modified core** — detectable, and the one case where a good answer exists:
  discard the imported core entirely and use the pinned image's.
- **`.htaccess` handler injection** — `AddType application/x-httpd-php .jpg`
  makes an innocuous upload executable.
- **`wp-config.php`** — contains the *old* site's database credentials, salts
  and often `define()`s that disable security features. It must never be
  imported; the receiving VM's own config is authoritative.

### Database level — the layer most often skipped entirely

- **Autoloaded options containing code.** `wp_options` with `autoload=yes`
  runs on every page load. Maximum reliability, invisible in the filesystem,
  and survives every file-based clean.
- **Scheduled events.** The `cron` option holds serialised scheduled tasks. A
  backdoor scheduled here **re-infects the filesystem after you clean it**,
  and the operator concludes the malware "came back". This is the persistence
  mechanism most likely to be missed, and it is worth a dedicated check.
- **Rogue administrators**, and `usermeta` capability grants on accounts that
  do not look like admins.
- **Injected post content** — SEO spam, script tags, base64 blobs.
- **Serialised-data traps.** Search-and-replace on a URL inside serialised PHP
  corrupts string lengths. Not a security issue but a correctness one, and it
  breaks sites silently.

### Format-specific

- **Duplicator's `installer.php`** must be deleted, never executed. A
  left-behind Duplicator installer is a documented site-takeover vector; a
  tool that runs one as part of "restore" is doing the attacker's work.
- **UpdraftPlus** splits into several archives (`-db.gz`, `-plugins.zip`,
  `-themes.zip`, `-uploads.zip`, `-others.zip`). Every part must be present;
  a missing `-plugins.zip` yields a site that half-works in confusing ways.
- **`.wpress`** (All-in-One WP Migration) is a *custom* format, not an
  archive. Header per file: 255-byte name, 14-byte size, 12-byte mtime,
  4096-byte path, then data, terminated by a null block. A small reader is
  needed; the plugin itself is not.

---

## Supported inputs

| Format | Detect by | Notes |
|---|---|---|
| **UpdraftPlus** | `backup_*-db.gz` + siblings | Multi-file; verify the set is complete first |
| **Duplicator** | `archive.zip` + `installer.php` | Installer deleted on sight |
| **All-in-One WP Migration** | `.wpress` | Custom reader required |
| **BackWPup / generic** | `.tar.gz` / `.zip` + `.sql` | Best effort |
| **Manual** | a directory + a `.sql` file | The simplest and most predictable path |

Start with **UpdraftPlus and manual**. They cover most real cases, and the
`.wpress` reader is a self-contained piece that can follow.

---

## Pipeline

```
 1. INSPECT     identify format, list contents, refuse hostile members
 2. EXTRACT     to /var/lib/wasp-import/<id>/ — outside the docroot, noexec
 3. SCAN FILES  wp-malware-scan.sh --path <staging> --json
 4. SCAN DB     the dump file, before it is ever loaded
 5. REPORT      findings, with a class per finding
 6. GATE        operator decides, with the findings in front of them
 7. NORMALISE   discard core, wp-config, mu-plugins; keep content
 8. IMPORT      files into place, then the database
 9. RE-HARDEN   regenerate salts, reset admin, re-apply the slug and rules
10. VERIFY      re-scan the live site; validate-wordpress.sh
```

Steps 3 and 4 already exist. Steps 1, 2, 4's dump-scanning and 7 are the work.

### Step 2 — extraction is a security boundary

- Extract as an **unprivileged user**, into a directory mounted `noexec`
- Reject any member whose normalised path escapes the target
- Reject symlinks and hard links outright — a backup does not need them
- Cap total extracted size and file count; abort past either
- Never preserve ownership or setuid bits from the archive

### Step 4 — scan the dump, not the database

The existing `wp-malware-scan.sh db` queries a *live* database. Importing needs
the same analysis against a **dump file**, before it is loaded — a different
code path, and the point of the exercise. Loading it first and scanning after
is the same mistake as extracting into the docroot.

Grep-level checks are adequate here and avoid needing a throwaway MariaDB:
autoloaded options containing `eval(`/`base64_decode`/`<?php`, `INSERT` rows
into `wp_users` with administrator capabilities, and the serialised `cron`
option.

### Step 7 — normalisation is where most of the safety comes from

Discard rather than inspect, wherever a good replacement exists:

| Component | Action | Why |
|---|---|---|
| **WordPress core** | **Discard.** Use the pinned image's | A pristine, digest-verified copy already exists. Comparing is strictly worse than replacing |
| **`wp-config.php`** | **Discard.** Keep the receiving VM's | Contains the old site's credentials and salts, and often security-weakening defines |
| **`.htaccess`** | **Discard.** Regenerate | Handler injection lives here; the VM's own rules are known-good |
| **mu-plugins** | **Quarantine all, re-add ours** | Active on arrival, no activation step to withhold |
| **`wp-content/uploads`** | Import, minus anything executable | Media is the point of the import |
| **Plugins / themes** | Import, then scan for known vulnerabilities | The genuinely hard case — see below |
| **Database** | Import after scanning, then re-harden | Content is the point |

**The honest weak spot is plugins and themes.** A backdoored copy of a
legitimate plugin is not reliably distinguishable from the real thing without
a reference — and for nulled or abandoned plugins no reference exists. The
realistic mitigation is to reinstall from wordpress.org anything whose slug
exists there, keeping only genuinely custom code, and to run
`wp-plugins.sh vulns` immediately after. That should be offered, and its limit
stated, rather than implied to be a solved problem.

### Step 9 — re-harden, because an import undoes hardening

The imported database carries the old site's `siteurl`, users and settings.
After import:

- Regenerate salts and keys — the old ones may be known to whoever had the site
- Force a password reset on every administrator, or at minimum report them
- Re-apply `WP_HOME`/`WP_SITEURL` for this deployment
- Re-apply the login slug and the wp-admin restriction
- Re-run `wp-plugins.sh vulns`, because you have just installed someone else's
  plugin set
- Clear the `cron` option and let WordPress rebuild it — the cheapest defence
  against the scheduled-task persistence above

---

## The gate

What happens when the scan finds something. The wrong answers are obvious in
both directions: refusing outright is useless because **people import
compromised sites deliberately, in order to clean them**, and proceeding
silently defeats the tool's only purpose.

| Findings | Default |
|---|---|
| None | Proceed, with a summary |
| SUSPICIOUS only | Proceed, findings listed and recorded |
| HIGH | Proceed only with `--accept-findings`, which is recorded |
| **CRITICAL** | **Refuse.** Override needs `--force` **and** typing the finding count |
| Hostile archive member | **Refuse. No override.** Nothing legitimate needs it |

Flagged files are **quarantined rather than imported** — the site comes up
without them, which is usually still a working site and is always a safer
starting point than one that boots with a webshell in place.

Every import writes a record: what was imported, what was found, what was
quarantined, who accepted what. Same shape as the vulnerability exception
log, and for the same reason — a decision nobody can reconstruct later is not
a decision anyone can defend.

---

## What it will not do

Stated so the tool does not imply otherwise:

- **It cannot certify a site clean.** It finds what the scanners find. A
  backdoor written for that specific site, or hiding in a plugin nobody has
  audited, passes.
- **It cannot detect a backdoored plugin without a reference copy.** Nulled
  and abandoned plugins have no reference. This is the largest gap and no
  amount of engineering closes it.
- **It will not run the source site's code**, including Duplicator's
  installer, which is the fastest way to lose the VM you are importing into.
- **It does not merge.** Import is into a fresh WASP deployment; merging two
  live sites is a different, much harder problem.
- **It does not fix the database's serialisation.** URL search-and-replace is
  delegated to `wp search-replace`, which handles serialised data correctly.

---

## Open questions

1. **Staging on disk or in a scratch volume?** A 5 GB site plus its extraction
   needs ~10 GB free on a 20 GB VM. Probably: check free space first and refuse
   early rather than filling the disk mid-extract — the failure mode of
   running out is a broken live site alongside a failed import.
2. **Import into a live VM, or provision fresh?** Fresh is much safer — the
   rollback is `qm destroy`. Importing into a running site means a failed
   import has already replaced the working one. Leaning strongly toward
   requiring a fresh deployment for v1.
3. **`.wpress` reader in shell or Python?** Fixed-width binary headers in
   POSIX shell is unpleasant. Python is not installed on the VM by default,
   and adding it for one format is a real cost. Possibly defer `.wpress` to v2
   and document extracting it on the workstation first.
4. **Where does the operator put the archive?** Uploading several GB over SSH
   to a VM is awkward. Options: `wasp-offsite-backup.sh`'s rclone remote,
   a URL fetch with checksum, or a Proxmox-side mount.

---

## Implementation order

1. `wp-import.sh inspect <path>` — identify, list, refuse hostile members.
   Read-only, no extraction. Useful on its own and the safest thing to build
   first.
2. Extraction with the bounds above, into staging.
3. Dump-file scanning, reusing the existing detection patterns.
4. The gate and the record.
5. Normalisation and import.
6. Re-hardening.
7. `.wpress`, if it still seems worth it.

Steps 1–3 alone are worth shipping: *"tell me what is in this backup before I
touch it"* is a real need on its own, and it is the part with no destructive
failure mode.

---

*Plan. Nothing here is implemented yet.*

— **RothITguy**
