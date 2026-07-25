# WordPress VM — Integration Test Harness

`test-wordpress-vm.sh` runs on the **Proxmox VE host** and asserts, end-to-end, that a provisioned WordPress VM actually works — the runtime-only class of failure that `dash -n` and `bash -n` cannot see. Four of the v7-16 round's seven bugs were exactly that: they passed every syntax check and only surfaced on real hardware. This harness runs the thing and checks the results.

## Requirements

- Runs on the Proxmox VE host (needs `qm`).
- `jq` on the host (`apt install jq`) — it parses `qm guest exec` output.
- The VM's QEMU guest agent, which the provisioning script installs. All checks go through `qm guest exec` (runs as root in the guest); no SSH or VM network reachability is needed for the core suite.

## Quick start

Test a VM you have already provisioned (the common case):

```sh
./test-wordpress-vm.sh --target 900
```

Also run the rollback-safety and backup checks (triggers an update attempt — throwaway VMs only):

```sh
./test-wordpress-vm.sh --target 900 --destructive
```

Write machine-readable results as well:

```sh
./test-wordpress-vm.sh --target 900 --json results.json
```

Provision a fresh VM, then test it, then tear it down:

```sh
./test-wordpress-vm.sh --emit-answers-template > answers.txt   # then edit it
./test-wordpress-vm.sh --provision --script ./create-wordpress-vm-v8.sh \
                       --answers answers.txt --vmid 900
```

**Exit code:** `0` all passed, `1` one or more failed, `2` harness/usage error.

## What it checks

Each assertion maps to a specific past bug or a v8 feature, so a regression in any of them turns the suite red.

1. **Install completed & containers up** — the `wp-install.done` marker exists, all three containers run, and the install log is free of the v7-16 bug-70 command-substitution spray.
2. **Container DNS** — the WordPress container resolves `mariadb` through aardvark-dns, and the nftables input chain has the port-53 accepts. This is the direct regression test for the v7-15 field-critical fix.
3. **WordPress HTTP health** — the health-check probe returns a real status, not `none` (the v7-16 BusyBox-wget fix), and a DB query works.
4. **Validator correctness** — digest pinning isn't falsely reported as `0/3`, and a configured wp-admin restriction isn't falsely reported missing (the two v7-16 false-failure fixes).
5. **Helper accessibility** — doas is configured for `wheel`, the admin account is in `wheel`, and the helper runs as the unprivileged admin (the v7-16 doas fix).
6. **Update & version features (v8)** — `update.sh status` and `update.sh versions` run and produce a discovery report, and the firewall service dependency matches the deployment profile (`need nftables` under production, `use` under standard).
7. **Backup integrity** — a backup runs, exists, passes `gzip -t`, and carries the dump completion marker.
8. **Rollback safety** (`--destructive`) — a bad update target fails without disturbing production (still running, still on the original image).
9. **wpadmin SSH + doas** (optional, `--ssh-host`) — verifies the elevation over a real SSH session, the way an operator uses it.

## Honest limitations

- It needs a real Proxmox host and a real (or provisionable) VM. There is no substitute environment — that is the point.
- `--provision` feeds the *interactive* provisioning script an answers file on stdin, so the answer order must match the current prompt sequence. Use `--emit-answers-template`, run the installer once interactively to learn the exact remaining prompts, and adjust. The assertion suite itself does not share this fragility.
- The rollback assertion proves a bad target fails *safely*, not the full candidate-health-then-rollback path — that needs a purpose-built image that pulls but fails validation.
- The `--ssh-host` doas check needs passwordless key auth and a doas policy that doesn't prompt; otherwise it records a SKIP, which may be expected.
