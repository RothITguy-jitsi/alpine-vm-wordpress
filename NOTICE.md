# NOTICE — third-party components

WASP is MIT-licensed (see `LICENSE`). It is a *provisioner*: most of what it
installs is other people's work, pulled from upstream at install time. This file
credits all of it, and flags the one component whose source is embedded in this
repository rather than downloaded.

Nothing here is a legal opinion. If you are redistributing WASP commercially,
read the upstream licences yourself — particularly the GPL ones, which have
obligations that MIT does not.

---

## Embedded in this repository

These are the only third-party works whose **source text ships inside WASP**.
Everything else in the lists below is downloaded from upstream at install time.

### 8G Firewall — Jeff Starr (Perishable Press)

- Source: https://perishablepress.com/8g-firewall/
- Author: **Jeff Starr**, Perishable Press
- Used in: `payload/stages/04-apache-hardening.sh` (written to `.htaccess`)

The 8G Firewall is a widely used Apache ruleset that blocks a large set of
malicious request patterns before PHP is reached. WASP embeds the ruleset
directly because it must exist before WordPress starts, and because fetching it
at install time would mean trusting an unauthenticated download — the exact
supply-chain pattern this project otherwise refuses.

Jeff Starr publishes the ruleset freely for use on any site. WASP's use is
unmodified in substance; the file carries a header pointing at the original.
If you find this useful, the author's work is worth supporting directly.

---

## Installed from upstream at provision time

WASP pulls these; it does not redistribute them.

### Container images (digest-pinned)

| Component | Upstream | Licence |
|---|---|---|
| WordPress | https://hub.docker.com/_/wordpress | GPL-2.0-or-later |
| MariaDB | https://hub.docker.com/_/mariadb | GPL-2.0 |
| CrowdSec | https://github.com/crowdsecurity/crowdsec | MIT |
| Squid (Canonical build) | https://hub.docker.com/r/ubuntu/squid | GPL-2.0 |
| WP-CLI | https://hub.docker.com/_/wordpress (`:cli`) | MIT |

### Base system and runtime

| Component | Upstream | Licence |
|---|---|---|
| Alpine Linux | https://alpinelinux.org | MIT (base), various |
| Podman | https://podman.io | Apache-2.0 |
| Skopeo | https://github.com/containers/skopeo | Apache-2.0 |
| netavark / aardvark-dns | https://github.com/containers/netavark | Apache-2.0 |
| nftables | https://netfilter.org | GPL-2.0 |
| OpenRC | https://github.com/OpenRC/openrc | BSD-2-Clause |
| doas | https://github.com/Duncaen/OpenDoas | ISC |

### Security tooling

| Component | Upstream | Licence |
|---|---|---|
| Trivy | https://github.com/aquasecurity/trivy | Apache-2.0 |
| Lynis | https://github.com/CISOfy/lynis | GPL-3.0 |
| YARA | https://github.com/VirusTotal/yara | BSD-3-Clause |
| ClamAV (optional) | https://www.clamav.net | GPL-2.0 |
| cs-firewall-bouncer | https://github.com/crowdsecurity/cs-firewall-bouncer | MIT |

### Backup, crypto and mail

| Component | Upstream | Licence |
|---|---|---|
| age | https://github.com/FiloSottile/age | BSD-3-Clause |
| minisign | https://github.com/jedisct1/minisign | ISC |
| rclone | https://rclone.org | MIT |
| msmtp | https://marlam.de/msmtp/ | GPL-3.0 |

### WordPress plugins

| Plugin | Upstream | Licence |
|---|---|---|
| Two Factor | https://wordpress.org/plugins/two-factor/ | GPL-2.0-or-later |

Installed by slug from the WordPress.org directory, never from a URL or ZIP.
Maintained by WordPress core contributors.

---

## Data feeds and services

These are queried at runtime. They have their own terms, and several have
usage limits worth knowing about before you rely on them.

| Service | Purpose | Notes |
|---|---|---|
| Wordfence Intelligence | Plugin/theme vulnerability data | Free feed; attribution required by their terms |
| CrowdSec CTI | IP reputation enrichment | Free key is 40/month (Community) or 120/month (Premium) |
| MaxMind GeoLite2 | Country-level GeoIP | Requires a free licence key; MaxMind's EULA applies |
| Patchstack / WPScan / NVD | Optional extra vulnerability sources | Each has its own key and rate limits |
| WordPress.org API | Core and plugin metadata | Public |

**On Wordfence:** their vulnerability data is provided free for
non-commercial *and* commercial use, but their licence requires attribution
when the data is displayed. WASP's reports name Wordfence as the source; if you
resurface this data in a client-facing dashboard, keep that attribution.

---

## What WASP itself is

Everything under `lib/`, `payload/bin/`, `payload/stages/`, `payload/mu-plugins/`
and `test/` is original work, MIT-licensed, © 2026 RothITguy.

The value here is not the code — it is the accumulated record of what actually
breaks, written down. See `CHANGELOG.md`, which is deliberately a post-mortem
log rather than a feature list.
