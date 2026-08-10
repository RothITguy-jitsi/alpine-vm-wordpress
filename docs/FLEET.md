# Fleet management for WASP

You do not need to build a fleet manager, and you should not. What you need is
already three separate problems solved by three existing tools, plus one small
piece of glue that WASP is uniquely placed to provide. This document says which
tool answers which question, where the seams are, and what the one warning is.

## The mistake to avoid first

"Fleet management" sounds like one thing. It is three, and no single tool does
all three well:

1. **Is the VM alive?** — hypervisor and guest health: CPU, RAM, disk, up/down.
2. **Is WASP healthy inside the VM?** — containers, backups encrypted, CrowdSec
   banning, egress holding. The things this project exists to guarantee.
3. **Is WordPress maintained?** — plugin updates, core version, content.

A tool built for one answers the others badly. The WordPress-agency tools
(ManageWP, MainWP) are excellent at (3) and blind to (1) and (2). Pulse is
excellent at (1) and knows nothing of (2) or (3). Trying to make one cover all
three is how you end up building a monitoring platform instead of running a
hosting business.

## Layer 1 — is the VM alive? Use Pulse.

**Pulse** (github.com/rcourtman/Pulse) is the right answer and it is worth
being specific about why:

- Deploys as its own LXC on the Proxmox host — one container, not one per VM.
- Auto-discovers guests via the Proxmox API. Add a WASP VM and it appears; no
  per-VM agent, no configuration on the VM at all.
- Shows every VM and LXC with CPU, RAM, disk and network, links straight to the
  Proxmox console, and alerts on downtime, high load, storage filling, and
  failed Proxmox backups.
- Integrates with Proxmox Backup Server, so if you adopt PBS the snapshot state
  is in the same pane.
- Actively developed (v6 line as of mid-2026) and installable from the Proxmox
  community-scripts catalogue.

**What it gives you:** a single screen showing all your WASP VMs across all your
Proxmox hosts, green or red, with the pod-level resource view you asked about.
This is the visual fleet dashboard. It is free, self-hosted, and your data stays
yours.

**What it cannot see:** anything inside the guest that Proxmox does not report.
It knows the VM is up and using 40% RAM. It does not know that last night's
backup silently went to plaintext, that CrowdSec's parser stopped loading, or
that the egress allowlist was edited. Those are WASP's job, and they are exactly
the failures that do not show up as a red VM.

## Layer 2 — is WASP healthy? This is the seam, and it is small.

This is the one piece that does not exist off the shelf, because it is specific
to what WASP guarantees. The good news is that it is tiny, because the hard part
is already done: `validate-wordpress.sh --check` already prints one line and
returns 0/1/2.

The question is only how that line reaches you across a fleet. Three options, in
increasing order of effort, and you can start at the top and move down only if
you outgrow it:

### Option A — feed the exit code to what you already have (recommended start)

Every WASP VM already sends email via a host-side relay and can ping an external
dead-man's-switch. So per-VM alerting already works today:

```sh
# already available on every VM, via cron
wp-notify.sh --heartbeat        # absence = VM gone
validate-wordpress.sh --check   # exit 0/1/2 = WASP health
```

Point the heartbeat at a hosted checker (healthchecks.io, Better Stack,
Uptime Kuma) with one check per VM. You get: a dashboard of green/red per site,
alerts on failure, and escalation — for free, today, with no new infrastructure.
`--check` can be wired to alert through the same channel by having its cron
entry send on a non-zero exit.

**This is where to begin.** It covers the actual requirement — "tell me when a
WASP guarantee stops holding" — without a central server to run, secure and
patch. For most MSP portfolios it is the whole answer.

### Option B — a central aggregator VM (only if you outgrow A)

If you reach the point where per-VM checks are too many to eyeball and you want
one WASP-specific pane, then a small aggregator makes sense. Note what it is and
is not:

- It is a **poller**, not an agent platform. It SSHes to each VM (or curls a
  minimal authenticated endpoint), runs `validate-wordpress.sh --check`,
  collects the line, and renders a table. A few hundred lines, not a product.
- It holds **read-only** health status, never credentials for the fleet. The
  moment it holds SSH keys or API tokens for every VM, it becomes the single
  most valuable target you own — see the warning below.
- It is the natural home for a fleet-wide `--check` roll-up, a fleet CVE summary
  (each VM already runs `wp-plugins.sh vulns`), and per-client reporting.

WASP could ship this as an optional role — an `install.sh --role aggregator`
that provisions a minimal VM whose only job is to poll the others. That is a
reasonable thing to build **when you have the fleet to justify it**, and a
premature thing to build before. The trigger is real pain with Option A, not
anticipation of it.

### Option C — Prometheus + Grafana (only at real scale)

If the fleet grows into the dozens and you want history, trends and
sophisticated alerting rules, the standard answer is a node-exporter-style
metrics endpoint per VM scraped by Prometheus, with Grafana for dashboards.
`validate-wordpress.sh --check` can be adapted to emit Prometheus text format
trivially. This is heavier than most WASP operators will ever need, and it is
listed so the path is known, not because it should be taken early.

## Layer 3 — is WordPress maintained? Use MainWP if you want it.

Plugin updates, core versions and content across a portfolio are what the
WordPress-agency tools are for. **MainWP** is the one that fits WASP's stance
best: it is self-hosted (a dashboard on a WordPress install you control, not a
SaaS holding your fleet's keys), and it connects to sites you already run
without migration.

This layer is **optional and separate**. WASP already updates plugins and cores
on its own schedule; MainWP is for when you want to drive that centrally and
produce client-facing "updates performed, backups completed" reports. Adopt it
if the reporting is worth it to you, ignore it if the per-VM automation is
enough. It has no bearing on Layers 1 and 2.

## The one warning, and it is important

Every third-party WordPress management tool works by installing a plugin that
accepts commands from a central dashboard. That dashboard, and its API key,
**controls every connected site**. It is, by construction, a single point of
compromise for your entire portfolio — a leaked key or a vulnerability in the
tool exposes all of it at once.

This is in direct tension with WASP's whole design, which is about *not* having
a single thing that owns everything. So:

- **Layers 1 and 2 do not have this problem.** Pulse reads the Proxmox API and
  changes nothing. The health checks report outward and hold no fleet
  credentials. Keep them that way.
- **Layer 3 does have it.** If you adopt MainWP, treat its dashboard as the most
  sensitive machine you operate: its own hardened host, MFA, IP-restricted
  admin, and a very short list of who can reach it. A management plane that can
  push code to every client site deserves more protection than any single
  client site.
- **Prefer read-only wherever the workflow allows.** Monitoring that can only
  observe cannot be turned against the fleet. The aggregator in Option B is
  valuable precisely because it holds status and not control.

## Recommended path

1. **Now, zero build:** Pulse on the Proxmox host for VM-level visibility, plus
   the existing heartbeat and `--check` per VM through a hosted checker. This is
   a complete fleet-monitoring solution and costs nothing but an afternoon.
2. **When Option A gets noisy:** build the small read-only aggregator (Option B),
   possibly as a WASP `--role aggregator`. Status only, never credentials.
3. **If you want central WordPress maintenance and client reports:** add MainWP,
   self-hosted, and protect its dashboard harder than anything else you run.
4. **Only at dozens of VMs with a need for history:** Prometheus + Grafana.

The through-line: **monitor with tools that observe, not tools that control.**
WASP's value is that no single component owns the fleet. Fleet management should
preserve that, not quietly undo it by introducing one dashboard with the keys to
everything.

---

*WASP provides the per-VM health signal (`validate-wordpress.sh --check`) and
the liveness signal (`wp-notify.sh --heartbeat`). Everything above is about
where those signals go. Start simple; add infrastructure only when real pain
justifies it.*
