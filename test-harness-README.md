# WordPress VM — Integration Test Harness

`test-wordpress-vm.sh` runs on the **Proxmox VE host** and asserts, end-to-end, that a provisioned WordPress VM actually works — the runtime-only class of failure that `dash -n` and `bash -n` cannot see. Four of the v7-16 round's seven bugs were exactly that: they passed every syntax check and only surfaced on real hardware. This harness runs the thing and checks the results.

## Requirements

- Runs on the Proxmox VE host (needs `qm`).
- `jq` on the host (`apt install jq`) — it parses `qm guest exec` output. The harness refuses to run without it.
- The VM's QEMU guest agent, which the provisioning script installs. All core checks go through `qm guest exec` (runs as root in the guest); no SSH or VM network reachability is needed for the core suite.

## Quick start

Test a VM you have already provisioned (the common case):

```sh
./test-wordpress-vm.sh --target 900
```

The default suite is **non-destructive except for one operation**: it runs the real backup script (section 7), which creates a backup archive, reads the database, and applies the backup's own rotation policy. That is a state-changing operation and it runs in *every* mode. Use a maintenance window if that matters on a live VM.

Add the rollback-safety check, which *does* trigger a (failing) update attempt — throwaway VMs only:

```sh
./test-wordpress-vm.sh --target 900 --destructive
```

`--destructive` adds only the bad-update rollback test (section 8). It does **not** control the backup check, which always runs.

Write machine-readable results as well (now includes a metadata block — see below):

```sh
./test-wordpress-vm.sh --target 900 --json results.json
```

Treat skipped checks as failure, for use as a release gate:

```sh
./test-wordpress-vm.sh --target 900 --strict
```

Provision a fresh VM, then test it, then tear it down:

```sh
./test-wordpress-vm.sh --emit-answers-template > answers.txt   # then edit it
./test-wordpress-vm.sh --provision --script ./create-wordpress-vm-v8-1.sh \
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
9. **wpadmin SSH + doas** (optional, `--ssh-host`) — verifies elevation over a real SSH session, with host-key verification enabled (a throwaway `known_hosts` seeded via `ssh-keyscan`, `StrictHostKeyChecking=accept-new`) and the key file validated.

## JSON output

With `--json`, results are written **atomically** (temp file in the target directory, then rename) and a failure to write is fatal (exit 2) — a requested evidence file never silently disappears. The document includes a `metadata` object: start/finish timestamps, VMID, deployment profile, mode flags, `sha256` of the harness and (if provisioning) the provisioner script, Alpine/Podman versions, and the three image digests — enough to tie a passing report to a specific build. A symlink or non-regular target path is refused. Install-timeout failures also write a JSON record before exiting.

## Companion: `scan-heredocs.py`

`scan-heredocs.py` is a pre-provision static check for the generator script itself. The generator writes `install-wordpress.sh`, which writes eight helper scripts, all as heredocs. A helper body that must be literal but is left with an **unquoted** delimiter will have its `$(...)`/backticks execute at build time — the exact shape of shipped bugs 70 and 71, which `bash -n` cannot see. The scanner walks a proper heredoc state machine (it does not match `<<` inside comments or other heredoc bodies) and flags: any backtick inside an unquoted heredoc, and any executable `/bin/*.sh` (or `install-wordpress.sh`) written from an unquoted delimiter. Intentionally-unquoted config/env heredocs (e.g. `vars.sh`) are reported only informationally.

```sh
python3 scan-heredocs.py ./create-wordpress-vm-v8-1.sh    # exit 0 = clean, 1 = problems
```

Run it before provisioning; it needs only `python3` (already present on Proxmox).

## Honest limitations

- It needs a real Proxmox host and a real (or provisionable) VM. There is no substitute environment — that is the point.
- `--provision` feeds the *interactive* provisioning script an answers file on stdin, so the answer order must match the current prompt sequence. The template is now comment-free on its value lines (an inline `# ...` after a value would be sent to the installer verbatim); still, run the installer once interactively to learn the exact remaining prompts and adjust.
- **Backup integrity is structural, not a restore test.** It proves the archive is complete and decompresses with the dump marker — not that the SQL restores, or that users/grants/routines/triggers come back. A true restore test needs a disposable MariaDB container to load into; that is deferred.
- The rollback assertion proves a bad target fails *safely* and leaves no half-swapped state — not the full candidate-health-then-cutover-then-rollback path, which needs a purpose-built image that pulls but fails validation from a test registry. Deferred.
- The `--ssh-host` doas check still records a SKIP (not a FAIL) when elevation would need a password or auth otherwise fails, because ssh's merged output cannot cleanly separate an expected password-required policy from a genuine auth failure. Treat a SKIP here as "verify the operator path manually," or gate the whole run with `--strict`.
