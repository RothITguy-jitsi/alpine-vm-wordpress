# WordPress VM Provisioner for Proxmox VE

A small, git-cloneable repository (`install.sh` plus `lib/` and `payload/`) that turns a bare Proxmox VE host into a fully provisioned, network-segmented WordPress VM — Alpine Linux, rootful Podman, MariaDB, and CrowdSec — with layered firewalling, SHA256 image digest pinning, optional GeoIP filtering, structurally-verified automated backups (see [Known Limitations](#known-limitations) for exactly what "verified" covers), and a full day-2 update/rollback/self-diagnosis toolchain baked in.

No Ansible, no Terraform, no cloud-init dependency, nothing beyond what a Proxmox host already has. Answer around 16 interactive prompts and roughly 15 minutes later — most of it unattended — you have a WordPress site sitting behind its own firewall, intrusion-prevention engine, vulnerability scanner, and nightly database backups that are integrity-checked on creation.

A note on how to read that sentence, and this README generally: "integrity-checked" means each backup's dump completion marker and gzip archive are verified before old backups are rotated — it does **not** mean the backup has been test-restored, or that a copy exists off this VM. Both of those are open items ([Known Limitations](#known-limitations), `TODO.md`). The same care applies elsewhere: the WordPress update "candidate" is isolated at the HTTP and filesystem level but shares the live database; CrowdSec provides firewall-level enforcement of ban decisions, not WAF request inspection; and rootful containers are contained primarily by the VM boundary rather than by the container runtime. Each of those is spelled out where it comes up below.

| | |
|---|---|
| **Host** | Proxmox VE (anything with `qm`, `pvesm`, `pvesh`) |
| **Guest OS** | Alpine Linux — auto-detects the newest available release (3.24 → 3.21), BIOS cloud image |
| **Container runtime** | Podman, **rootful only** |
| **Stack** | WordPress `6.9.4-php8.3-apache` · MariaDB `11.4` · CrowdSec `v1.7.8` |
| **Default sizing** | 2 vCPU · 4096 MB RAM · 20G disk (edit `CORES`/`RAM`/`DISK` in `lib/00-preflight.sh` to change) |
| **Networking** | Two segmented Podman networks — `wp-front` (egress + published port) and `wp-db` (`--internal`, no egress) |
| **Deployment profile** | `standard` (warn, don't abort, on a failed verification) or `production` (abort) — chosen at install time |
| **Setup time** | ~15 minutes, mostly unattended after the prompts |
| **CLI flags** | None — `install.sh` itself is fully interactive (the management scripts it installs are not — see [Day-2 Operations](#day-2-operations)) |

---

## Table of Contents

- [What This Is](#what-this-is)
- [Repository Structure](#repository-structure)
- [Architecture](#architecture)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
  - [Verifying what you run](#verifying-what-you-run)
- [Outbound Email](#outbound-email)
- [WordPress Site Address](#wordpress-site-address)
- [Interactive Setup Walkthrough](#interactive-setup-walkthrough)
- [What Gets Created](#what-gets-created)
- [Security Model](#security-model)
- [Day-2 Operations](#day-2-operations)
- [GeoIP Country Filtering](#geoip-country-filtering)
- [SHA256 Digest Pinning](#sha256-digest-pinning)
- [Deployment Profiles](#deployment-profiles)
- [Automated Jobs](#automated-jobs)
- [File and Directory Reference](#file-and-directory-reference)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Changelog Highlights](#changelog-highlights)
- [Credits](#credits)
- [License](#license)

---

## What This Is

Run `install.sh` on a Proxmox VE host as root. It will:

1. **Ask you a series of prompts** — VM sizing lives in `lib/00-preflight.sh` as variables (not a prompt); networking, SSH access, firewall CIDRs (format-validated, re-prompting on a bad value), a custom `wp-admin` URL, CrowdSec enrolment, GeoIP filtering, image-digest pinning, and a deployment profile are all configured interactively.
2. **Download and verify** the newest Alpine Linux cloud image directly from Alpine's CDN, checked against a freshly fetched SHA-512 sidecar.
3. **Inject a two-stage installer** straight into the disk image via `qemu-nbd` — no cloud-init involved (cloud-init is explicitly disabled on first boot).
4. **Create and start the VM** in Proxmox, then wait for it to come up and report its IP.
5. **Let the VM finish provisioning itself** on first boot:
   - *Stage 1* — expand the root filesystem, apply Alpine updates, switch to the `linux-lts` kernel if not already on it (reboots once if needed).
   - *Stage 2* — install Podman, create the two segmented container networks, stand up MariaDB → WordPress → CrowdSec, generate a syntax-checked nftables ruleset, configure hourly log rotation, install Trivy and Lynis, write out the `update.sh` / `wp-hardening.sh` / `validate-wordpress.sh` / `wp-db-backup.sh` management scripts, and run a full post-install validation suite.

Everything is logged to `/var/log/wp-install.log` on the guest, viewable in real time via `qm terminal <VMID>`.

---

## Repository Structure

`install.sh` is a thin entry point. It sources `lib/*.sh` in numbered order to
build and inject the VM, and copies `payload/` onto the VM disk for the
in-VM installer to use on first boot. Nothing here is meant to be run out
of order or in isolation — each numbered file depends on variables and
functions earlier files set up, same as it would in one unsplit script.

Run standalone (the curl one-liner in [Quick Start](#quick-start)) with no
`lib/`/`payload/` next to it, `install.sh` fetches them itself — a
GitHub-generated tarball of this repo, into a temp directory removed when
the run finishes. Run from a full clone, it finds them right next to itself
and skips that step. Either way this is what actually gets used:

```
.
├── install.sh                 # entry point — run this
├── lib/                       # host-side (runs on the Proxmox host), sourced in order
│   ├── 00-preflight.sh          # colors/logging, VMID lookup, Alpine image detection, cleanup trap
│   ├── 01-interactive-setup.sh  # every prompt (networking, SSH, firewall, GeoIP, ...)
│   ├── 02-image-and-disk.sh     # Alpine download + SHA-512 verify + working-copy resize
│   ├── 03-dynamic-configs.sh    # builds nftables/Apache config blocks that need your answers baked in
│   ├── 04-nbd-mount-and-chroot.sh    # mounts the disk image, creates the admin account
│   ├── 05-ssh-and-network-inject.sh  # SSH hardening, credentials, nftables.nft, network config
│   ├── 06-vars-and-payload-inject.sh # vars.sh, stages payload/ onto the disk, first-boot launcher
│   └── 07-vm-create-and-start.sh     # qm create/importdisk/start, waits for an IP, prints the summary
├── payload/                    # copied onto the VM disk; the in-VM installer reads from here
│   ├── install-wordpress.sh     # in-VM installer entry point (Stage 2 dispatcher)
│   ├── stages/                  # install-wordpress.sh's own numbered stages (01-10)
│   ├── bin/                     # update.sh, validate-wordpress.sh, wp-hardening.sh, and the rest
│   │                             #   of the day-2 tooling — see Day-2 Operations below
│   ├── templates/                # the 2 files needing install-time values, as __TOKEN__ templates
│   ├── init.d/, cron/, apache-conf/, php-conf/, mariadb-conf/,
│   │   apache-mods/, mu-plugins/, crowdsec/, etc/    # static config files, copied verbatim
├── test/
│   ├── test-wordpress-vm.sh     # integration test harness (see test/README.md)
│   └── README.md
├── CHANGELOG.md                # what changed and why, including this restructuring
├── TODO.md                     # currently open items and why they're deferred
├── LICENSE                     # MIT
└── README.md                   # this file
```

None of this changes what ends up on the VM — every path in
[File and Directory Reference](#file-and-directory-reference) below, every
prompt, and every default is identical to before the split. See
`CHANGELOG.md` if you want the mechanical details of how the split was
done and verified.

---

## Architecture

```mermaid
flowchart TB
    client(["Client browser"])

    subgraph host["Proxmox VE host"]
        nft["nftables — L1<br/>SSH + Web CIDR filtering"]

        subgraph vm["Alpine Linux VM — rootful Podman"]
            subgraph frontnet["wp-front · 10.89.10.0/24"]
                wp["wordpress container<br/>Apache + PHP 8.3<br/>--cap-drop ALL"]
            end

            subgraph dbnet["wp-db · 10.89.20.0/24<br/>--internal, no egress"]
                wp2["wordpress<br/>(second network leg)"]
                db["mariadb container<br/>--cap-drop ALL"]
            end

            cs["crowdsec container<br/>--network host<br/>LAPI on 127.0.0.1:8080"]
        end
    end

    client -->|"80 / 443"| nft
    nft --> wp
    wp === wp2
    wp2 -->|"3306, via aardvark-dns"| db
    wp -.->|"access.log"| cs
    cs -.->|"bans pushed via cs-firewall-bouncer"| nft
```

The key design decision is the **network split**. Earlier versions put WordPress and MariaDB on one flat network with a route to the internet — "no host port" kept MariaDB safe from *inbound* scans, but a compromised WordPress container still had a clear L2 path to the database subnet, which itself could still reach out. `wp-db` is created with `--internal`, so Podman/netavark never configures a route out of it at all, regardless of nftables state — MariaDB (and WordPress's second leg) has no egress, full stop. `mariadb` is also given an explicit `--network-alias` on `wp-db`, so DNS resolution of the hostname `mariadb` doesn't depend on it happening to be the container's `--name`.

One consequence of running container-to-container DNS over a bridge gateway is worth calling out explicitly, because it caused a real install failure in the field: Podman's DNS resolver (aardvark-dns) runs *on the host*, bound to each network's gateway IP. A container's DNS query is therefore a packet hitting the host's own input chain, not the forward chain — so the host firewall has to explicitly permit it, or WordPress can never resolve `mariadb` even though MariaDB itself is perfectly healthy. The generated nftables ruleset now carries that accept rule (and the equivalent for DHCP) for both subnets, and it's syntax-checked with `nft -c` before it's ever loaded, so a malformed rule can't half-load and leave the firewall broken.

The other standing design decision is **rootful, not rootless, Podman** (see [Known Limitations](#known-limitations) for why rootless was removed). Every container still gets `--cap-drop ALL` plus only what it specifically needs: MariaDB adds back 5 capabilities and is isolated to `wp-db` (`--internal`, no host port, no egress); WordPress adds back 6, including `NET_BIND_SERVICE` — needed because Apache binds port 80 inside the container's own network namespace even with `-p 80:80` (Podman's host-side port publish and Apache's in-netns bind are separate things); CrowdSec runs `--network host` with minimal capabilities and `--read-only`, because it needs the host network namespace to see syslog and write nftables rules directly.

---

## Features

**Provisioning**
- Auto-detects and downloads the newest available Alpine BIOS cloud image (tries `3.24` → `3.23` → `3.22` → `3.21`), with a pinned last-known-good fallback if the CDN listing can't be reached.
- SHA-512 integrity check against a freshly fetched sidecar from the same CDN directory (Alpine doesn't publish SHA-256 for cloud/qcow2 images — only SHA-512 and a detached GPG signature). Whether a failed check aborts the install or just warns depends on the [deployment profile](#deployment-profiles).
- Files are injected directly into the disk image via `qemu-nbd`; cloud-init is explicitly disabled on first boot.
- Two-stage first-boot installer, fully logged, idempotent enough to resume from `/var/lib/wp-install-stage` if the VM reboots mid-install.
- DHCP or static IPv4 addressing, chosen interactively; auto-detects the next free Proxmox VMID and the right disk options for your storage backend (`nfs`/`dir`/`btrfs`/block).
- Every CIDR/IP prompt (SSH, Web, `wp-admin` CIDR, the extra allowed IP, the reverse-proxy IP) is format-validated at input time, re-prompting on anything malformed, instead of letting a typo reach a security-critical config file.

**Runtime**
- Rootful Podman only — the rootless code path was deliberately removed (see [Known Limitations](#known-limitations)).
- Every container runs `--cap-drop ALL` plus only the specific capabilities it needs, and `--security-opt no-new-privileges:true`.
- WP-Cron is disabled in favor of a real system cron job every 5 minutes — the standard fix for "WP-Cron only fires on page load."
- MariaDB's InnoDB buffer pool is capped (256M) so a busy site can't starve WordPress and CrowdSec of memory on a 4 GB VM.
- The host firewall explicitly permits container-to-gateway DNS (port 53) and DHCP on both container subnets — closing a real-world failure mode where WordPress could never resolve the `mariadb` hostname even though MariaDB itself was fully healthy.
- Podman's own container log files (stdout/stderr) are capped at 50 MB each via a `containers.conf.d` drop-in, independent of the Apache log rotation below — MariaDB and CrowdSec are both chatty on stdout and can otherwise grow unbounded in container storage.

**Security**
- nftables default-deny host firewall, generated with your CIDR choices baked in at install time and syntax-checked (`nft -c`) before it's ever loaded.
- Apache-level IP restriction on `/wp-admin` and `wp-login.php`, independent of the network firewall and reverse-proxy-aware via `mod_remoteip`.
- Optional custom `/wp-admin` slug — and it's a real boundary, not a cosmetic one: the default `/wp-login.php` returns `403` unless the request actually came through the slug's rewrite, and a must-use plugin keeps WordPress's own generated login/logout/redirect URLs pointed at the slug so the feature can't lock you out of your own site.
- The [8G Firewall](https://perishablepress.com/8g-firewall/) v1.4 `.htaccess` ruleset (query-string, request-URI, user-agent, method, and referrer filtering), placed ahead of WordPress's own rewrite block.
- [CrowdSec](https://www.crowdsec.net/) with the `apache2`, `wordpress`, `linux`, `sshd`, `http-cve`, and `appsec-wordpress` collections, enforced via a native nftables bouncer.
- Optional MaxMind GeoLite2 country allow/block-listing at the Apache module level, before PHP ever runs. Credentials are protected via a `--netrc-file`, never on a command line (see [GeoIP Country Filtering](#geoip-country-filtering)).
- A dedicated non-root SSH admin account (`wheel` + `doas`); root SSH login is disabled unconditionally in the normal path.
- Kernel hardening sysctls (`kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `unprivileged_bpf_disabled`, the `fs.protected_*` family, and more).
- SHA256 digest pinning for all three images, resolved via Skopeo manifest queries rather than full pulls, and validated as a single well-formed digest before use.
- [Trivy](https://github.com/aquasecurity/trivy) HIGH/CRITICAL CVE scanning gates every `update.sh` image swap. The fallback installer is fetched from a specific, audited commit hash rather than a mutable branch, and a scanner failure is reported distinctly from an actual CVE finding rather than the two being conflated.
- [Lynis](https://cisofy.com/lynis/) runs a weekly OS hardening audit for compliance evidence.
- A `standard`/`production` [deployment profile](#deployment-profiles) toggle controls whether a failed image/digest verification is a warning or a hard install-time abort.

**WordPress hardening**
- `DISALLOW_FILE_EDIT`, capped post revisions, minor-only auto-updates, tuned memory limits, `WP_DEBUG` off by default.
- A randomized `wp<6 hex chars>_` table prefix rather than the well-known `wp_` default.
- `wp-config.php`, `readme.html`, `license.txt`, and backup/dotfile patterns blocked at the Apache layer.
- PHP execution blocked inside `wp-content/uploads` — the single highest-impact rule against an uploaded webshell.
- `?author=N` user-enumeration blocked; `xmlrpc.php` blocked by default (toggle-able).
- Security headers via `mod_headers`: CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.

**Day-2 tooling**
- **`wp-mail.sh`** — outbound email status, live test send, reconfiguration, and diagnostics. See [Outbound Email](#outbound-email).
- **`wp-plugins.sh`** — WordPress-level update visibility: plugins, themes, and core. This covers a different layer than `update.sh`, and the difference matters. `update.sh` and Trivy cover the **container image** (OS packages, PHP, WordPress core). Plugins and themes live in the mounted `wp-content` volume, so an image update never touches them — and per Patchstack's *State of WordPress Security in 2026*, of the 11,334 vulnerabilities disclosed in 2025, roughly **91% were in plugins and 9% in themes, with about six in core**. `wp-plugins.sh status` shows what's out of date (including inactive plugins, whose code is still on disk and still reachable); a weekly cron reports pending updates via syslog. It **never auto-updates** — see [Known Limitations](#known-limitations) for why that's deliberate. Runs the official `wordpress:cli` image, digest-pinned like the other three.
- `update.sh` — per-component updates, Trivy pre-scan, an exclusive lock, and a candidate/cutover pattern for WordPress so production never loses port 80 mid-update. `all` and `digest-check` now run every component regardless of an earlier one failing, and print a per-component OK/FAILED summary at the end instead of stopping silently partway through.
- `wp-hardening.sh` — toggle 8G Firewall / xmlrpc / uploads-PHP-execution / `WP_DEBUG`, callable remotely via `qm guest exec`.
- `validate-wordpress.sh` (also `wp-validate`) — live functional checks across every layer, scoped to one area with `--section`, with a concrete copy-paste remediation command attached to every failure.
- `wp-geoip-setup.sh` — a rerunnable, idempotent GeoIP (re)installer.
- `wp-db-backup.sh` — the daily MariaDB backup, verified end-to-end (raw dump → completion-marker check → gzip integrity check → rotate-only-on-success) instead of trusting a piped `gzip`'s own exit code.
- `wp-health-check.sh` / `mariadb-health-check.sh` — the real functional health checks that gate every install-time wait loop and every `update.sh` rollback decision, available as standalone scripts you can run by hand.
- Daily verified MariaDB backups (7-day retention), weekly `podman auto-update --dry-run`, weekly Lynis audit, hourly log rotation.

---

## Requirements

- A Proxmox VE host you can reach as **root** (SSH, or the Proxmox web shell / `qm terminal`).
- `git`, to clone this repository.
- `qm`, `pvesm`, `pvesh` — ship with Proxmox VE.
- `qemu-nbd`, `qemu-img` — `apt install qemu-utils` if missing.
- `openssl`, `curl`.
- Outbound internet access from the Proxmox host (Alpine's CDN) and from the guest during Stage 2 (Docker Hub for images, Alpine repos, GitHub at a pinned commit for the Trivy fallback installer, and MaxMind if GeoIP filtering is enabled).
- A storage target with `images` content enabled (default offered: `local-lvm`).
- A bridge interface (default offered: `vmbr0`), optionally a VLAN tag.
- *(Optional)* a free [MaxMind](https://www.maxmind.com/en/geolite2/signup) account if you want GeoIP filtering.
- *(Optional)* a [CrowdSec Console](https://app.crowdsec.net/) enrolment key if you want the engine auto-enrolled.

---

## Quick Start

On your Proxmox host, as root — either the web UI (select your node → **Shell**) or SSH. Proxmox doesn't ship `git`, so the default path doesn't need it:

```bash
curl -fsSL -O https://raw.githubusercontent.com/RothITguy-jitsi/alpine-vm-wordpress/refs/heads/main/install.sh
chmod +x install.sh
./install.sh
```

`install.sh` notices it's on its own (no sibling `lib/`/`payload/`) and fetches the rest of the repository itself — a GitHub-generated tarball, not a `git clone`, so no `git` install is required on the host. That copy lives in a temp directory for the life of the install and is removed automatically when it finishes, same as every other temp file this creates. See [Verifying what you run](#verifying-what-you-run) below for the trust model and how to pin a specific commit instead of always fetching the latest `main`.

If you already have `git`, or want the full commit history for your own review, cloning works exactly the same way and skips the self-fetch entirely:

```bash
git clone https://github.com/RothITguy-jitsi/alpine-vm-wordpress.git
cd alpine-vm-wordpress
./install.sh
```

Either way, there are no command-line flags — everything is prompted for interactively, with sensible defaults shown in brackets that you can accept by pressing Enter. Resource sizing (2 vCPU / 4096 MB / 20G by default) is set in `lib/00-preflight.sh` in `CORES`, `RAM`, and `DISK` if you want different defaults before running it.

### Verifying what you run

The one-liner above downloads over HTTPS, which rules out tampering in transit, from whichever ref `install.sh` is told to fetch — `main` by default, i.e. whatever is on that branch right now. That's the right default for "always get the latest fixes," but it means a future compromise of this repo would be fetched by every install run from that point on, with nothing in the script itself to catch it — the same trust model as any other single-file `curl | bash` installer (Docker's, rustup's, Homebrew's all work the same way). No checksum published in this repo could change that, since a checksum sitting next to the code it's meant to verify only checks the repo against itself.

If you want a fixed, reviewable reference instead of "whatever `main` is today," pin to a specific commit SHA from this repo's own history:

```bash
WPVM_REPO_REF=<40-char-commit-sha> ./install.sh
```

(if you `sudo`'d into root rather than already being root, use `sudo -E` so the environment variable survives)

---

## Outbound Email

**WordPress cannot send mail without this, and it fails silently.** The official WordPress container has no `sendmail` binary, so PHP's `mail()` has nothing to hand a message to. `wp_mail()` returns without a visible error and the admin UI reports success. Password resets, new-user notifications, comment alerts, contact-form submissions and WooCommerce receipts all vanish. The usual way people discover this is a locked-out administrator whose reset email never arrives.

The installer asks for an SMTP relay (optional — blank keeps the previous behavior). Afterwards, manage it on the VM with `wp-mail.sh`:

```sh
wp-mail.sh status                    # what's configured (password redacted)
wp-mail.sh test you@example.com      # send a real message, report the result
wp-mail.sh setup                     # (re)configure interactively
wp-mail.sh doctor                    # DNS, port reachability, mount, mu-plugin
wp-mail.sh log                       # recent wp_mail failures
```

**Use a dedicated mailbox or app password for each site.** The credential is stored on the VM, so if the site is ever compromised you want to revoke exactly one credential without disturbing anything else that sends mail.

How it's handled:

| | |
|---|---|
| **Credential location** | `/home/wpuser/wp/secrets/smtp.php`, mode `0400`, owned by uid 33, mounted **read-only** at `/var/www/private/` — deliberately outside the web root, so no URL maps to it even if PHP execution breaks and Apache starts serving `.php` as plain text. Not passed as a container env var either, since `podman inspect` prints those. |
| **Transport** | A mu-plugin (`01-wpvm-smtp.php`) hooking `phpmailer_init`. WordPress bundles PHPMailer with SMTP support, so no third-party plugin is needed. mu-plugins can't be deactivated from wp-admin and survive core updates. |
| **TLS** | Certificate verification stays on and is not exposed as a toggle. The usual reason to disable it is a self-signed cert, and accepting those hands the relay password to anyone on-path. |
| **Timeout** | 10s, not PHPMailer's 300s default — otherwise an unreachable relay hangs user-visible requests like registration for five minutes each. |
| **From address** | Set explicitly, including the envelope sender. WordPress otherwise sends as `wordpress@<domain>`, which is usually not SPF-authorized — and under a DMARC policy of `quarantine`/`reject` that means silent non-delivery, the same invisible failure again. |
| **Rate limit** | nftables caps outbound submission at 30 new connections/hour (burst 10), logging `nft-smtp-ratelimit`. A compromised site spamming through an authenticated relay damages your sending domain's reputation, and that outlasts the compromise. Enforced at the packet layer because the application layer is what the attacker already controls. |

One honest limitation: the rate limit bounds *connections*, not messages — one SMTP connection can carry many recipients. It's a meaningful throttle and a good tripwire, not a hard per-message cap. Pair it with a per-account sending limit on the relay.

---

## WordPress Site Address

Set the site's real domain during install and WordPress is configured with it
from first boot. This matters more than it looks: WordPress writes its
canonical URL into the **database** the first time setup completes, so if that
first visit is to the VM's IP, the IP becomes the site's identity — in
permalinks, in emails, in password-reset links, and inside serialized plugin
and theme options where a plain SQL find-and-replace will corrupt the data.

The installer asks for:

| Prompt | Notes |
|---|---|
| **Site domain** | e.g. `example.com`. Blank = use the VM's IP (fine for a lab VM). Pasting `https://example.com/` works — it's stripped back to the hostname. |
| **Scheme** | Defaults to `https` if you gave a reverse proxy IP, `http` otherwise. |
| **Site title** | Defaults to the domain. |
| **Admin email** | For recovery and notifications. Optional. |

Giving a domain sets both `WP_HOME` and `WP_SITEURL` as constants in
`wp-config.php`. Because constants take precedence over the database copy,
changing domains later is a config edit and a container restart rather than a
database migration.

**If you're behind a reverse proxy terminating TLS** (Nginx Proxy Manager,
Caddy, nginx — the usual setup), also give the proxy's IP at the
`mod_remoteip` prompt. That's what makes the installer trust
`X-Forwarded-Proto` and set `FORCE_SSL_ADMIN`, which is what prevents the
classic "too many redirects" loop where WordPress wants HTTPS, redirects, and
the proxy forwards the next request as HTTP again. Without a proxy IP the
header is deliberately **not** trusted, because any caller able to reach port
80 directly could forge it.

---

## Interactive Setup Walkthrough

In order, the script asks about:

1. **VM ID** — auto-suggested from `pvesh get /cluster/nextid`.
2. **Root password** (for local/console access — this is *not* used for SSH; see step 7).
3. **Hostname**, **storage target**, **bridge**, and an optional **VLAN tag**.
4. **Network mode** — DHCP, or static IPv4 (address, prefix, gateway, DNS servers).
5. **SSH public key** (paste, or a path to a `.pub` file) — or leave blank to use a password instead.
6. **Admin account username** (default `wpadmin`) — this becomes the `wheel`+`doas` account; if you supplied a key, its `doas` password is auto-generated and password SSH login is disabled entirely. If you left the key blank, you're prompted for a password for this account instead.
7. **Firewall CIDRs** — restrict SSH (22) and/or Web (80/443) at the packet level (blank = open to any source). Each value is validated as it's entered; an invalid CIDR or IP re-prompts instead of being silently accepted.
8. **Apache-level `wp-admin` restriction** — a CIDR and/or a single extra IP allowed to reach `/wp-admin` and `wp-login.php`, independent of the nftables rule above. Also validated at input time.
9. **Reverse proxy IP** — if set, `mod_remoteip` is configured so Apache trusts `X-Forwarded-For` from that address only.
10. **Custom `wp-admin` slug** — blank keeps the default `/wp-admin` path. Sanitized to lowercase alphanumeric+hyphen, and rejected (with a re-prompt) if it collides with a real WordPress path (`wp-content`, `wp-login`, `xmlrpc`, etc.).
11. **CrowdSec Console enrolment key** — optional, masked input.
12. **GeoIP filtering** — enable/disable; if enabled, MaxMind Account ID + License Key, then a whitelist *or* blocklist of ISO country codes.
13. **SHA256 digest pinning** — on by default.
14. **Deployment profile** — `standard` (default) or `production`; see [Deployment Profiles](#deployment-profiles).
15. A full **summary screen**, then a final `Proceed? [Y/n]`.

---

## What Gets Created

**The VM** (via `qm create`): `--cpu host`, `virtio-scsi-single`, serial console (`--vga serial0 --serial0 socket`), QEMU guest agent enabled with `fstrim_cloned_disks=1`, `--onboot 1` with `--startup order=3,up=30`, tablet device disabled (`--tablet 0`), boots from `scsi0`.

**Containers**

| Container | Image | Network(s) | Published port | Notable flags |
|---|---|---|---|---|
| `wordpress` | `wordpress:6.9.4-php8.3-apache` (or a locally-built `wordpress-geoip:*` layer if GeoIP is enabled) | `wp-front` (primary) + `wp-db` | `80:80` | `--cap-drop ALL --cap-add NET_BIND_SERVICE,SETUID,SETGID,CHOWN,DAC_OVERRIDE,FOWNER`, 768 MB memory cap, 200 PID limit |
| `mariadb` | `mariadb:11.4` | `wp-db` only | none | `--cap-drop ALL --cap-add SETUID,SETGID,CHOWN,DAC_OVERRIDE,FOWNER`, 512 MB memory cap, InnoDB buffer pool capped at 256M, explicit `--network-alias mariadb` |
| `crowdsec` | `crowdsecurity/crowdsec:v1.7.8` | host network | LAPI locked to `127.0.0.1:8080` | `--read-only --cap-drop ALL --cap-add DAC_OVERRIDE,SETUID,SETGID,CHOWN`, 512 MB memory cap |

**Networks**

| Network | Subnet | `--internal`? | Members | Purpose |
|---|---|---|---|---|
| `wp-front` | `10.89.10.0/24` | No | WordPress | Egress (plugin/theme installs, WP-Cron remote requests, update checks) + the published host port |
| `wp-db` | `10.89.20.0/24` | Yes | WordPress, MariaDB | Database traffic only — no route to the internet, ever, regardless of nftables state |

If digest pinning is enabled, all three images above are actually pulled and run by `repo@sha256:<digest>` reference, not by floating tag — see [SHA256 Digest Pinning](#sha256-digest-pinning).

---

## Security Model

| Layer | Component | Enforces |
|---|---|---|
| L1 | nftables | Default-deny host firewall, syntax-checked before load; SSH/Web CIDR restriction; forward chain scoped to `wp-front`/`wp-db` only; explicit accepts for container-to-gateway DNS + DHCP |
| L2 | Apache | `ADMIN_CIDR`/extra-IP restriction on wp-admin & wp-login.php, a functionally-enforced custom slug (default path 403s, mu-plugin keeps WordPress's own links on the slug), 8G Firewall WAF, security headers, sensitive-file blocks |
| L3 | CrowdSec | Behavioral/signature banning — brute force, WAF-bypass CVEs, WordPress-specific attacks — enforced via an nftables bouncer |
| L4 | Podman | `--cap-drop ALL` + minimal capability grants, `no-new-privileges`, per-container network isolation, resource limits |
| L5 | Kernel | `rp_filter`, `syncookies`, `dmesg_restrict`, `ptrace_scope`, `fs.protected_*`, disabled unprivileged BPF, and more |
| L6 | SSH | Root login disabled, dedicated `wheel`+`doas` admin account, key-only auth when a key is supplied, restricted ciphers/KEX/MACs |

---

## Day-2 Operations

### `update.sh`

```
update.sh [check|status|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all|trivy]
```

Aliases: `cs` for `crowdsec`, `digest` or `pin` for `digest-check`, `scan` for `trivy`.

- **`check` / `status` / *(no args)*** — read-only. Skopeo manifest queries only, no pulls, no prompts. Shows what's running, what's pinned, and whether the registry has anything newer.
- **`os`** — Alpine `apk upgrade`.
- **`wp [VER]`** — pulls the new WordPress image, boots it as a throwaway `wordpress-candidate` on `127.0.0.1:18080` with a read-only mount of production's files, but connected to the *live* production database with production credentials (see [Known Limitations](#known-limitations)) — HTTP exposure and the filesystem are isolated, the database is not — and health-checks it there. Production is only stopped and swapped over once the candidate proves out — if it doesn't, production was never touched.
- **`db [VER]`** — takes a verified `mariadb-dump` backup (own exit status checked, completion marker confirmed, gzip integrity-checked), snapshots the data directory at the filesystem level, stops WordPress, stops MariaDB cleanly (verified stopped, not just renamed), swaps the image, checks `mariadb-upgrade`'s own exit status, re-verifies with a credentialed query + InnoDB check, restarts WordPress and confirms *it* can use the new database too — and only then discards the pre-update container and snapshot.
- **`crowdsec [VER]`** (alias `cs`) — same stop → verify-stopped → swap pattern; confirms LAPI comes back up and restarts the firewall bouncer.
- **`digest-check`** (aliases `digest`, `pin`) — refreshes any component whose tag was rebuilt under the same version (e.g. a same-version security rebuild). Runs all three components regardless of an earlier one failing, and prints a per-component OK/FAILED summary.
- **`all`** — runs everything above in sequence; each step still asks before making a change; same per-component summary behavior as `digest-check`.
- **`trivy`** (alias `scan`) — CVE-scans whatever images are actually running right now.

Every state-changing subcommand takes an exclusive lock at `/run/lock/wordpress-update.lock` (stale-PID-aware) so two invocations can never race each other. Read-only subcommands (`check`/`status`/`trivy`) stay lock-free and are safe to run anytime, including mid-update.

### `wp-hardening.sh`

```
wp-hardening.sh [status|enable <feature>|disable <feature>|restart-wp|trivy-scan|lynis]
```

Features: `8g`, `xmlrpc`, `uploads-php`, `debug`. Can be run remotely from the Proxmox host itself:

```bash
qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
```

### `validate-wordpress.sh`

```
validate-wordpress.sh                    # run everything
validate-wordpress.sh --section web      # just one section (-s)
validate-wordpress.sh --list             # list section names (-l)
validate-wordpress.sh --quiet            # only print failures/warnings (-q)
validate-wordpress.sh --quick            # skip slow checks (network, backups)
validate-wordpress.sh --help             # usage (-h)
```

Also installed as `wp-validate`. Sections: `containers`, `database`, `web`, `security`, `updates`, `logs`, `backups`. Runs live functional tests — real HTTP fetches, a real DB query through WordPress's own credentials, a real gzip integrity check on the newest backup, a live Skopeo digest resolution, an end-to-end test of the custom login slug (including checking that the default path 403s and that the mu-plugin is present and parses), a direct check that the nftables input chain carries the container-DNS accept rules — rather than just checking that containers are in state "running." Every failure prints a concrete, copy-paste remediation command, and separates **FAIL** (something is broken) from **WARN** (works now, will bite you later). Exit codes: `0` = all passed, `1` = one or more failures, `2` = warnings only, no failures.

### `wp-geoip-setup.sh`

Rerunnable and idempotent. If GeoIP setup fails at install time (bad MaxMind credentials, a transient network blip), fix `/etc/wp-install/vars.sh` and re-run this one script — no reboot, no re-running the whole installer.

### `wp-db-backup.sh`

```
wp-db-backup.sh
```

Called nightly by cron (02:00 UTC); safe to run by hand too. Writes a raw `.sql` dump first — so `mariadb-dump`'s own exit code is what gets checked, not gzip's — confirms the dump actually reached its own `Dump completed` marker, gzips and `gzip -t` verifies the resulting archive, and only *then* rotates backups older than 7 days. A failed run leaves yesterday's good backup untouched and logs the failure via `logger -t wp-db-backup`. Dumps include `--routines --events --triggers --single-transaction`, so stored procedures, triggers, and scheduled events survive a restore, not just table data.

### `wp-health-check.sh` / `mariadb-health-check.sh`

```
wp-health-check.sh [container] [port]
mariadb-health-check.sh [container]
```

The same real functional checks that gate every install-time wait loop and every `update.sh` rollback decision, exposed as standalone scripts you can run by hand. `wp-health-check.sh` checks HTTP response (an explicit `200`/`301`/`302` allow-list, pinned to this server's own first response), PHP execution inside the container, MariaDB DNS resolution, and a real WordPress-credentialed `SELECT 1`. `mariadb-health-check.sh` checks a root ping, a root `SELECT 1`, the exact WordPress-credentialed query, and InnoDB initialization.

---

## GeoIP Country Filtering

Optional, off by default. When enabled:

- MaxMind's free **GeoLite2-Country** database is used via the `mod_maxminddb` Apache module, compiled from source in a multi-stage build (the build step runs with `--network host` so it can reach the internet, then is discarded) so it survives future WordPress image updates without persistence hacks.
- Choose **whitelist** mode (only listed countries can reach the site) or **blocklist** mode (everyone *except* listed countries).
- Filtering happens at the Apache layer, before WordPress or PHP ever runs.
- MaxMind credentials are written once to a root-owned, `chmod 600` netrc file (`/etc/wp-install/.maxmind-netrc`) and passed to `curl` via `--netrc-file` — never spelled out on a command line or in the weekly refresh's cron entry, where they'd otherwise be visible to anything reading `/proc/<pid>/cmdline` or `ps aux` for the duration of the request.
- The database refreshes automatically every Wednesday at 06:00 UTC.
- If it fails at install time, re-run `/usr/local/bin/wp-geoip-setup.sh` after fixing your credentials — check `/var/log/wp-geoip.log` for the exact failure.

---

## SHA256 Digest Pinning

On by default, togglable at the install prompt or afterward via `USE_DIGEST_PINNING` in `/etc/wp-install/vars.sh`. Forced on unconditionally under the `production` [deployment profile](#deployment-profiles).

- Digests are resolved with **Skopeo** (`skopeo inspect docker://...`), which asks the registry's manifest endpoint directly — a few KB, no image pulled just to check. The result is validated as a single well-formed `sha256:` line (preferring Skopeo's own `--format`, falling back to `jq`, with a raw grep kept only as a last resort for very old Skopeo builds) before it's trusted — an earlier version could return every layer digest alongside the manifest digest, which silently broke both pinning and `update.sh check`.
- A `podman pull` still happens, but only once, against the exact `repo@sha256:<digest>` reference that's actually going to run.
- The currently-pinned tag + digest per component is tracked in `/etc/wp-install/pinned.env`, written atomically (temp file + rename) and re-validated every time it's sourced back in — `update.sh` treats it as the single source of truth.
- `update.sh digest-check` finds and offers to move to a newer digest published under the *same* tag — the case a plain version comparison would never catch (e.g. a same-version security rebuild).
- If Skopeo is unavailable or a lookup fails, pinning falls back to the older pull-then-inspect method automatically for that one image; under `standard` profile this is a warning, under `production` it aborts the install (see below).

---

## Deployment Profiles

Chosen once, at the very end of the interactive prompts, and persisted to `/etc/wp-install/vars.sh` as `DEPLOYMENT_PROFILE`. It controls exactly one thing: **what happens when this script's own integrity/verification steps can't complete** — not anything about the runtime security posture of the finished VM. nftables, Apache, CrowdSec, capability drops, and everything else in the [Security Model](#security-model) are identical either way.

| Check | `standard` (default) | `production` |
|---|---|---|
| Alpine base-image SHA-512 verification | Failure is a loud warning; the install continues unverified | Failure **aborts the install** |
| `sha512sum` missing on the Proxmox host | Warning only | **Aborts the install** |
| Container digest pinning | A lookup failure falls back to an unpinned (tag-only) reference for that image, with a warning | Anything short of 3/3 images resolving to a real `@sha256:` digest **aborts the install**; also forces `USE_DIGEST_PINNING=1` regardless of the earlier prompt answer |

Why `standard` is the default: a Proxmox host with a flaky path to Alpine's CDN, or a registry having a bad day, shouldn't brick a homelab install that would otherwise succeed just fine unverified. `production` exists for the opposite case — an MSP or compliance-driven deployment that needs to be able to tell an auditor the base image and every container really were verified against upstream, not merely attempted.

What `production` does **not** change: it has no effect on the WordPress-update candidate's use of production database credentials, on Trivy's scan-and-ask-to-proceed behavior, or on anything at runtime — see [Known Limitations](#known-limitations) for what's a deliberate tradeoff regardless of profile.

---

## Automated Jobs

| Schedule (UTC) | Job | What it does |
|---|---|---|
| Every 5 min | `wp-cron-run.sh` | Runs `wp-cron.php` inside the container — replaces unreliable page-load-triggered WP-Cron |
| Hourly, at :17 | `logrotate` | Enforces the 50M size cap in practice (a once-daily check would let a spike grow a log to gigabytes first); rotates Apache logs (14-day retention), CrowdSec logs (7-day), and this script's own install/GeoIP/digest-pinning logs (8-week) |
| Daily, 02:00 | `wp-db-backup.sh` | Verified `mariadb-dump --all-databases` (incl. routines/events/triggers) → gzip, integrity-checked at every stage → `/root/wp-db-backups/`, 7-day retention |
| Daily, 03:00 | Alpine security updates | `apk update && apk upgrade` |
| Weekly, Sun 04:00 | `podman auto-update --dry-run` | Logged only — nothing is applied automatically |
| Weekly, Wed 06:00 | GeoLite2-Country refresh | Only scheduled if GeoIP filtering is enabled; credentials via `--netrc-file` |
| Weekly, Sat 05:00 | Lynis audit | Writes `/var/log/lynis-report.dat` — hardening index for compliance evidence |

---

## File and Directory Reference

| Path | Contents |
|---|---|
| `/root/.wp-credentials` | MariaDB root/WordPress passwords, table prefix (`chmod 600`) |
| `/root/.wp-admin-credentials` | The SSH admin account's `doas` password — only written when an SSH key was supplied (`chmod 600`) |
| `/etc/wordpress/env` | Env-file mounted into both the WordPress and MariaDB containers (`chmod 600`) |
| `/etc/wp-install/vars.sh` | Installer-time choices — slug, GeoIP, network mode, admin user, digest-pinning toggle, deployment profile — sourced by every management script |
| `/etc/wp-install/pinned.env` | Currently-pinned tag + digest per component; authoritative for `update.sh`; written atomically |
| `/etc/wp-install/.maxmind-netrc` | MaxMind credentials for `curl --netrc-file` (`chmod 600`) — never on a command line |
| `/etc/logrotate.d/wordpress-vm` | Log rotation rules for Apache logs, CrowdSec logs, and this script's own logs |
| `/home/wpuser/wp/html` | WordPress files (bind-mount, UID 33 / `www-data`) |
| `/home/wpuser/wp/html/wp-content/mu-plugins/00-wpvm-login-slug.php` | Must-use plugin that rewrites WordPress's own generated login links to the custom slug (only present if a slug was configured) |
| `/home/wpuser/wp/mysql` | MariaDB data directory (bind-mount, UID 999) |
| `/home/wpuser/wp/mysql-preupdate-snapshot` | Transient filesystem-level MariaDB snapshot, created during `update.sh db` and removed once the update is confirmed healthy |
| `/home/wpuser/wp/logs` | Apache access + `remoteip-debug` logs, read by CrowdSec |
| `/home/wpuser/wp/htaccess/.htaccess` | 8G Firewall + slug + author-enum rules, mounted read-write |
| `/home/wpuser/wp/apache-conf/wp-security.conf` | Generated Apache security config |
| `/var/log/wp-install.log` | Full first-boot install log |
| `/var/log/wp-digest-pinning.log` | Exact pull/resolve errors for anything that fell back to tag-only |
| `/var/log/wp-geoip.log` | GeoIP (re)install log |
| `/var/log/lynis-report.dat`, `/var/log/lynis.log` | Weekly Lynis audit output |
| `/root/wp-db-backups/` | Daily gzipped, integrity-verified MariaDB dumps, 7-day retention (`chmod 700`) |

---

## FAQ

**Does this work on a non-Proxmox hypervisor?**
No — it's built directly on `qm`, `pvesm`, and `pvesh`.

**Is CrowdSec optional?**
No, the engine is always installed. Only Console *enrolment* (the key prompt) is optional.

**Can I skip GeoIP or digest pinning?**
Yes, both are opt-in/opt-out at the relevant prompt.

**What's the difference between the `standard` and `production` deployment profiles?**
Whether a failed image/digest verification is a warning (`standard`, default) or a hard install-time abort (`production`). See [Deployment Profiles](#deployment-profiles) — it doesn't change anything about the finished VM's runtime security.

**Can I run more than one WordPress site per VM?**
Not by design — it's one install per VM, which is what keeps the network-segmentation and capability model simple and auditable.

**How do I resize the VM after it's created?**
Use normal Proxmox tooling (`qm set`, disk resize). The script's `CORES`/`RAM`/`DISK` variables only control the *initial* size.

**Can I point this at an Alpine VM I already have?**
No — the script builds the VM from a freshly downloaded Alpine cloud image and owns the whole disk-injection process.

---

## Troubleshooting

- **During first boot:** `qm terminal <VMID>`, then `tail -f /var/log/wp-install.log`.
- **Container status/logs:** `podman ps`, `podman logs wordpress`, `podman logs mariadb`, `podman logs crowdsec`.
- **Something's broken and you don't know where to start:** `validate-wordpress.sh` (or `wp-validate`) for a full sweep, or `--section <name>` to isolate one area — every failure line comes with a copy-paste fix.
- **Security feature status:** `wp-hardening.sh status`.
- **"mariadb hostname does not resolve" / Aardvark DNS errors in the install log:** `nft list chain inet filter input | grep 'dport 53'` — if that's empty, the host firewall predates the fix that permits container-to-gateway DNS; re-provision, or add the accept rules by hand (`validate-wordpress.sh --section security` checks this directly).
- **GeoIP failed:** fix `/etc/wp-install/vars.sh`, re-run `/usr/local/bin/wp-geoip-setup.sh`, check `/var/log/wp-geoip.log`.
- **Digest pinning partially failed:** check `/var/log/wp-digest-pinning.log` for the real pull/inspect error behind any component that fell back to tag-only.
- **An `update.sh` run seems stuck:** check for a stale lock at `/run/lock/wordpress-update.lock` — it's cleared automatically if the holding PID is dead, or remove it by hand if you're certain nothing is running.
- **A `db` update rolled back:** the update log names the exact health gate that failed. `/home/wpuser/wp/mysql-preupdate-snapshot` and a timestamped `*.failed-*` directory may still be present alongside it if a rollback didn't fully clean up — inspect before deleting anything.

---

## Known Limitations

This project has been through several rounds of independent security review and real-world field fixes. In the interest of setting accurate expectations before you point it at a client's production site, here's an honest breakdown of what's already solid, what's a deliberate tradeoff rather than an oversight, and what genuinely isn't addressed yet. **`TODO.md`** tracks the currently-open items in more detail, including why each is deferred rather than dropped.

**On plugin updates being reported rather than applied automatically.** `wp-plugins.sh` deliberately reports and stops. Auto-updating plugins unattended looks like the safer default and mostly isn't: roughly 46% of disclosed plugin vulnerabilities had no patch available at disclosure, so blanket updating can't close that window anyway; plugin auto-update has itself been the delivery mechanism in real supply-chain incidents, where legitimate directory plugins pushed malicious updates to sites that trusted them; and an unattended update that breaks a live site breaks it with nobody watching. The same reasoning is already applied one layer down — the container-image cron runs `podman auto-update --dry-run`, never an actual unattended swap. Visibility plus a human decision is the intended posture, not an unfinished feature.

**Already addressed**
- WordPress updates use a candidate/cutover pattern — a freshly pulled image is booted read-only against production's real data and database on a loopback-only port and health-checked *before* production is touched, closing what used to be a guaranteed port-80 collision on every `update.sh wp`.
- MariaDB updates verify the pre-update dump itself (own exit status, a completion-marker check, and a `gzip -t` integrity check — not a piped `gzip`'s exit code), take a filesystem-level snapshot of the data directory before anything is touched, check `mariadb-upgrade`'s own exit status, and re-verify that WordPress itself can use the new database — not just that MariaDB is healthy — before the rollback path is ever discarded.
- Container rename/rollback failures are no longer swallowed — every rename/start in the update path is checked, and a failed rollback prints an explicit "ROLLBACK FAILED" with manual-recovery commands instead of silently claiming success.
- `update.sh all` and `update.sh digest-check` run every component regardless of an earlier failure and print a per-component summary, instead of silently stopping partway through.
- A dedicated non-root SSH account exists; root SSH login is disabled unconditionally in the normal path, with a `wheel`+`doas` admin account instead.
- Update operations are serialized behind an exclusive lock, and both MariaDB and CrowdSec are fully stopped — and verified stopped — before a replacement container is started against the same data/state.
- The static `--add-host mariadb:...` entry that used to coexist with (and could shadow) DNS-based resolution has been removed entirely; MariaDB discovery is DNS-only now, backed by an explicit `--network-alias`.
- Secrets no longer land in cron lines or process arguments: MaxMind credentials go through a `--netrc-file`, and every value written into a sourced shell file (`vars.sh`) is single-quote-escaped rather than interpolated raw.
- `/etc/wp-install/pinned.env` is written atomically (temp file + rename) and every value is re-validated after being sourced back in.
- The Trivy fallback installer is fetched from a specific, audited commit hash rather than a mutable branch, and a scanner failure is now reported distinctly from an actual CVE finding via Trivy's own exit-code convention.
- The WordPress HTTP health check now allow-lists only `200`/`301`/`302`, pins to this server's own first response instead of following an offsite redirect, and times out instead of hanging indefinitely.
- The custom `/wp-admin` login slug is a real boundary now, not a cosmetic one — the default `/wp-login.php` is blocked server-side unless the request came through the slug's rewrite, and a must-use plugin keeps WordPress's own generated login links pointed at the slug.
- Logs (Apache, CrowdSec, and the installer's own) are rotated hourly with a real, enforced size cap; Podman's own container log files are separately capped.
- A host firewall rule that silently dropped every container-to-container DNS lookup — the exact cause of a real "mariadb hostname does not resolve" install failure — has been fixed, and the generated nftables ruleset is syntax-checked before it's ever loaded.
- Digest resolution via Skopeo is validated as a single well-formed digest before use (a previous version could return every layer digest alongside the manifest digest and silently break both pinning and `update.sh check`).

**Deliberate design tradeoffs (documented, not defects)**
- Trivy CVE scanning can be waved through by the operator on a HIGH/CRITICAL finding, or on a scanner failure — by design, so a scanner outage or an accepted risk doesn't block an otherwise-wanted update.
- The WordPress update candidate authenticates to the *live* production database with production credentials (a read-only docroot, tmpfs logs, and a staging-environment hint are as far as the isolation goes). A fully isolated candidate — temporary MariaDB, a restored dump, throwaway credentials — would double disk usage and add real time to every image update; this is a documented cost/benefit call, not an oversight.
- Alpine base-image and container-digest verification fail **open** (warn, don't abort) under the default `standard` deployment profile. Switch to `production` at the install prompt if you need a hard abort instead — see [Deployment Profiles](#deployment-profiles).

**Not yet addressed**
- The host's outbound (egress) firewall policy is fully open (`policy accept` on the nftables output chain) — there's no restriction on what the VM itself can initiate outbound, beyond `wp-db`'s `--internal` boundary for the containers on it.
- The CrowdSec Console enrolment key is passed as a `podman exec` argument for the one-time enrolment call, visible in `argv`/`ps` output for the duration of that command — the same exposure MaxMind's credentials used to have before that was fixed. It isn't currently established whether `cscli` has an equivalent file-based credential input.
- **"Verified" backups mean structurally verified, not restore-proven.** `wp-db-backup.sh`'s checks (dump exit status, completion marker, `gzip -t`) confirm the archive is a complete, uncorrupted `mariadb-dump` output — they do not restore it anywhere or confirm the data inside is what you expect. Nothing here periodically restores a backup into a disposable MariaDB instance to prove it, and nothing copies backups off the VM — a lost or destroyed VM takes its backups with it.
- No mandatory gate requires a recent, verified off-VM backup before `update.sh db` performs a major MariaDB upgrade. The local pre-update backup and filesystem snapshot (see above) protect against a bad upgrade; they don't protect against losing the VM itself mid-upgrade.
- The Trivy fallback installer (used if Trivy isn't already packaged) is fetched from a specific, audited commit rather than a mutable branch, but that commit's script isn't checksummed or signature-verified before it runs — commit-pinning rules out a *later* tampering of that ref, not a compromise of the delivery path itself.
- No signed release manifest exists for this repository. `install.sh` sources every `lib/*.sh` file and copies every `payload/` file as root, trusting that the checkout on disk is what you expect it to be — beyond the group/world-writable check `lib/00-preflight.sh` now does, and pinning to a specific commit SHA instead of a floating branch (see [Verifying what you run](#verifying-what-you-run)), nothing here cryptographically verifies the content itself. See `TODO.md` for why this is a tracked, deliberately-deferred item rather than something bolted on ad hoc.

---

## Changelog Highlights

Full notes for every fix live in **`CHANGELOG.md`** (this used to be the script's own header comment block; it's a real file now, same content). This table is a summary, not a substitute for reading it if you're deciding whether to trust this on a production box.

| Version(s) | Theme |
|---|---|
| Unreleased | Forensic audit fixes (root-SSH fallback removed, CrowdSec bouncer + CSP + IPv6 config hardening, `uploads-php` auto-expiry, a VM-side error-handling bug) and a `git`-free single-command install via a self-fetching `install.sh` — see below and TODO.md |
| Unreleased | Repository restructuring: the single 8,694-line script became `install.sh` + `lib/` + `payload/` (see [Repository Structure](#repository-structure)); every heredoc that generated an executable script is now a real file; `scan-heredocs.py` retired (see below) |
| v8-1 | Static-review fixes: `validate-wordpress.sh`'s BusyBox-incompatible wget options, `update.sh upgrade`'s swallowed exit status, MariaDB LTS/EOL allowlists, and atomic backup publication |
| v8 | Version discovery (`update.sh versions`), a guided cross-component `update.sh upgrade`, MariaDB LTS-awareness, and the `production` fail-closed nftables dependency |
| v7-16 | Post-install field-bug sweep after the v7-15 fixes reached real hardware |
| v7-15 | Fixed a real-world install failure where WordPress could never resolve `mariadb` (the host firewall silently dropped container DNS at the input chain); log rotation moved to hourly so the size cap is real; verified backups now include routines/events/triggers; the nftables ruleset is syntax-checked before load; CIDR/IP prompts validated at input time |
| v7-14 | Custom `/wp-admin` slug made functionally real (it was previously cosmetic and could even lock you out); unbounded log growth fixed with logrotate + container log caps; `validate-wordpress.sh` rewritten with copy-paste remediation and `--section` scoping; WordPress HTTP health check hardened against offsite redirects and hangs |
| v7-13 | Response to an independent security audit: per-component update reporting instead of stopping at the first failure; verified daily backups (`wp-db-backup.sh`); Trivy supply-chain hardening (commit-pinned installer, real scan-failure-vs-finding distinction); read-only candidate mounts; the `standard`/`production` deployment profile toggle introduced |
| v7-12 | State-file integrity (atomic writes, re-validation on load) and credential exposure closed — MaxMind credentials off the command line, `vars.sh` values properly shell-escaped |
| v7-11 | Removed a stale static MariaDB `/etc/hosts` entry that could shadow DNS and break WordPress's database connection right after an update |
| v7-9 – v7-10 | MariaDB update path hardened end-to-end: verified backups, filesystem-level data snapshots, `mariadb-upgrade` exit status checked, WordPress re-verified against the new database before the rollback path is discarded |
| v7-6 – v7-8 | Network segmentation introduced (`wp-front` / `wp-db`, the latter `--internal`); rootless Podman support removed in favor of a single, better-tested rootful path; dedicated non-root SSH admin account; SHA256 digest pinning via Skopeo; WordPress candidate/cutover update pattern |
| v7-3 – v7-5 | Custom `wp-admin` slug and GeoIP country filtering introduced; Alpine SHA-512 image verification added; CrowdSec bumped for a WAF-bypass CVE |

**A note on `scan-heredocs.py`:** earlier revisions shipped this as a companion static check. It caught one specific bug shape — a heredoc meant to write a literal, executable script file left with an unquoted delimiter, so its `$(...)`/backticks fired immediately instead of staying literal for the script to run later. That shape needs a heredoc whose body becomes an executable script; after this restructuring, no such heredoc exists anywhere in the repository (every one of those bodies is a real file under `payload/` now), so the tool was retired rather than kept as a check that can only ever pass. See `CHANGELOG.md` and `test/README.md` for the full reasoning.

---

## Credits

- [8G Firewall](https://perishablepress.com/8g-firewall/) — Perishable Press (free for all use; credit kept intact in the generated `.htaccess`)
- [CrowdSec](https://www.crowdsec.net/)
- [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2/geolite2-free-geolocation-data) (requires a free account and acceptance of MaxMind's EULA)
- [Trivy](https://github.com/aquasecurity/trivy) — Aqua Security
- [Lynis](https://cisofy.com/lynis/) — CISOfy
- [Alpine Linux](https://alpinelinux.org/)
- [Podman](https://podman.org)

---

## License

[MIT](LICENSE) — Copyright © 2026 RothITguy-jitsi.

---
