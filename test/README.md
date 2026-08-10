# WordPress VM — Integration Test Harness

`test-wordpress-vm.sh` runs on the **Proxmox VE host** and asserts, end-to-end, that a provisioned WordPress VM actually works — the runtime-only class of failure that `dash -n` and `bash -n` cannot see. Four of the v7-16 round's seven bugs were exactly that: they passed every syntax check and only surfaced on real hardware. This harness runs the thing and checks the results.

## Two test suites, different jobs

This repository has two independent test entry points, and it is worth knowing
which does what:

- **`test/run-all-checks.sh`** — static and unit checks that need no VM. It runs
  `bash -n`/`sh -n` across every script, the auto-discovered `check-*.py` suite
  (each of which self-tests against its own fixture — including
  `check-menu-entries.py`, which verifies every `wasp-menu` entry maps to a tool
  that exists and a subcommand that tool actually accepts), and — when PHP is present
  — `php -l` on every mu-plugin plus `test/test-mfa-enforcement.php`, the
  21-case logic harness for the MFA enforcement decision (scope, enrollment,
  grace maths, the enrollment-path gate). Run this on every change; it is fast
  and catches the class of bug that has repeatedly bitten this project.
- **`test/test-wordpress-vm.sh`** (documented below) — the integration harness
  that runs against a real provisioned VM and checks live behaviour.

The rest of this document describes the integration harness.

## Requirements

- Runs on the Proxmox VE host (needs `qm`).
- `jq` on the host (`apt install jq`) — it parses `qm guest exec` output. The harness refuses to run without it.
- The VM's QEMU guest agent, which the provisioning script installs. All core checks go through `qm guest exec` (runs as root in the guest); no SSH or VM network reachability is needed for the core suite.

## Quick start

Run these from the repository root (so `install.sh`'s sibling `lib/` and
`payload/` directories are where it expects them).

Test a VM you have already provisioned (the common case):

```sh
./test/test-wordpress-vm.sh --target 900
```

The default suite is **non-destructive except for one operation**: it runs the real backup script (section 7), which creates a backup archive, reads the database, and applies the backup's own rotation policy. That is a state-changing operation and it runs in *every* mode. Use a maintenance window if that matters on a live VM.

Add the rollback-safety check, which *does* trigger a (failing) update attempt — throwaway VMs only:

```sh
./test/test-wordpress-vm.sh --target 900 --destructive
```

`--destructive` adds only the bad-update rollback test (section 8). It does **not** control the backup check, which always runs.

Write machine-readable results as well (now includes a metadata block — see below):

```sh
./test/test-wordpress-vm.sh --target 900 --json results.json
```

Treat skipped checks as failure, for use as a release gate:

```sh
./test/test-wordpress-vm.sh --target 900 --strict
```

Provision a fresh VM, then test it, then tear it down:

```sh
./test/test-wordpress-vm.sh --emit-answers-template > answers.txt   # then edit it
./test/test-wordpress-vm.sh --provision --script ./install.sh \
                       --answers answers.txt --vmid 900
```

**Exit code:** `0` all passed (skips allowed unless `--strict`), `1` one or more failed (or, under `--strict`, any skipped), `2` harness/usage error — including a requested `--json` file that could not be written.

## What it checks

Each assertion maps to a specific past bug or a v8 feature, so a regression in any of them turns the suite red. **Every normal assertion now requires the guest command to succeed before its output is judged** — a command that fails to run can no longer pass by producing empty output.

1. **Install completed & containers up** — the `wp-install.done` marker exists, all three containers run, and the install log is free of the v7-16 bug-70 command-substitution spray.
2. **Container DNS** — the WordPress container resolves `mariadb` through aardvark-dns, and the nftables input chain contains the *four specific* DNS accepts (both backend subnets, udp **and** tcp) rather than merely four matching lines. The direct regression test for the v7-15 field-critical fix.
3. **WordPress HTTP health** — the health checker is run once; its **exit status** is the primary verdict, and the output is then checked for a real HTTP status (not `none`, the v7-16 BusyBox-wget fix) and a working DB query.
4. **Validator correctness** — digest pinning isn't falsely reported as `0/3`, and a configured wp-admin restriction isn't falsely reported missing (the two v7-16 false-failure fixes).
5. **Helper accessibility** — doas is configured for `wheel`, the admin account is in `wheel`, the helper runs as the unprivileged admin (the v7-16 doas fix), and a non-interactive `doas -n` elevation probe confirms the elevation path (SKIP if the policy requires a password, which is a valid choice).
6. **Update & version features (v8)** — `update.sh status` runs; version discovery is captured once and reported honestly (SKIP if the registry was unreachable, rather than passing on the report shell); and the firewall service dependency is checked in the OpenRC `depend()` block specifically — `need nftables` under production (and *not* a bare `use`), `use nftables` under standard.
7. **Backup integrity** — a backup runs, exists, passes `gzip -t`, and carries the dump completion marker. (Structural integrity of the archive — not a full restore; see limitations.)
8. **Rollback safety** (`--destructive`) — a nonexistent update target must **exit non-zero** (be rejected), production is left running on its original image, no orphaned `wordpress-old`/`wordpress-candidate` container remains, and the update lock is released. The invalid target is derived from the VM's current variant, so it does not rot.
9. **Outbound email configuration** — verifies the relay is configured, the credential file is `0400`/uid 33 and lives outside the web root, the SMTP mu-plugin is installed, its mount is read-only, and the nftables submission rate limit is in the live ruleset. Deliberately does **not** send a live message: every other check is contained to the VM, and a real email leaves it. Use `wp-mail.sh test <addr>` for that, deliberately. Skips cleanly when no relay is configured.

10. **wpadmin SSH + doas** (optional, `--ssh-host`) — verifies elevation over a real SSH session, with the key file validated.

   On host-key trust, stated precisely: `ssh-keyscan` is **unauthenticated discovery**, not verification — it learns whatever key answers on the network, which is exactly the path an attacker would need to control for this to matter. So the scanned key is cross-checked against the host keys reported by the guest through `qm guest exec`, which travels over QEMU's guest-agent channel rather than the network. On a match, the connection uses `StrictHostKeyChecking=yes` against a `known_hosts` containing only that verified key. On a mismatch, or if the agent can't be reached, this section is **skipped** rather than run over an unverified key — pass `--allow-unverified-sshid` to accept plain network TOFU anyway, which is reasonable for a throwaway lab VM and is not a production trust path.

## JSON output

With `--json`, results are written **atomically** (temp file in the target directory, then rename) and a failure to write is fatal (exit 2) — a requested evidence file never silently disappears. The document includes a `metadata` object: start/finish timestamps, VMID, deployment profile, mode flags, `sha256` of the harness, Alpine/Podman versions, and the three image digests — enough to tie a passing report to a specific build. A symlink or non-regular target path is refused. Install-timeout failures also write a JSON record before exiting.

`provisioner_sha256` identifies the exact provisioning code that ran. Since the provisioner is no longer one file, this now covers `install.sh` plus every file under its sibling `lib/` and `payload/` directories (hashed by path *relative* to `install.sh`, so it's identical across clones regardless of where the repo was checked out) — `provisioner_layout` records which mode was used (`install.sh+lib+payload`, or `single-file` if `--script` was pointed at a standalone script with no `lib/`/`payload/` siblings).

## Note: `scan-heredocs.py` has been retired

Earlier revisions shipped a companion static check, `scan-heredocs.py`: the
provisioning script used to write `install-wordpress.sh` as one large
heredoc, which in turn wrote eight helper scripts, all *also* as heredocs.
A helper body that had to be literal but was left with an unquoted
delimiter would have its `$(...)`/backticks execute at build time instead
of staying literal for the helper to interpret later — the exact shape of
two shipped bugs the scanner's own docstring cited, which `bash -n` cannot
see.

That failure mode required a heredoc whose body was destined to become an
executable script file. This repository no longer has any of those: every
helper script that used to be generated that way is now a real file under
`payload/`, copied into place rather than regenerated from a heredoc (see
`CHANGELOG.md`). With the pattern gone, the scanner has nothing left to
check, so it was removed rather than kept as a tool that can only ever
report "no errors." A useful side effect of the split: `bash -n`/`sh -n`
against each small file in `lib/`, `payload/stages/`, and `payload/bin/`
now catches far more than it could against one 8,694-line file, since a
syntax error in what's now a 100-300 line file no longer hides inside
thousands of surrounding lines. The functional checks below remain the
runtime gate this static checking can't replace.

## Honest limitations

- It needs a real Proxmox host and a real (or provisionable) VM. There is no substitute environment — that is the point.
- `--provision` feeds the *interactive* provisioning script an answers file on stdin, so the answer order must match the current prompt sequence. The template is now comment-free on its value lines (an inline `# ...` after a value would be sent to the installer verbatim); still, run the installer once interactively to learn the exact remaining prompts and adjust.
- **Backup integrity is structural, not a restore test.** It proves the archive is complete and decompresses with the dump marker — not that the SQL restores, or that users/grants/routines/triggers come back. A true restore test needs a disposable MariaDB container to load into; that is deferred.
- The rollback assertion proves a bad target fails *safely* and leaves no half-swapped state — not the full candidate-health-then-cutover-then-rollback path, which needs a purpose-built image that pulls but fails validation from a test registry. Deferred.
- The `--ssh-host` doas check still records a SKIP (not a FAIL) when elevation would need a password or auth otherwise fails, because ssh's merged output cannot cleanly separate an expected password-required policy from a genuine auth failure. Treat a SKIP here as "verify the operator path manually," or gate the whole run with `--strict`.
