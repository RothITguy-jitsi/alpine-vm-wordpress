#!/usr/bin/env bash
# =============================================================================
# WORDPRESS VM — PROXMOX VE PROVISIONING SCRIPT
# =============================================================================
#
# v7-5d PATCH NOTES (on top of v7-3 baseline). Older per-version notes (v2
# through v7-1) have been removed from this header — those bugs are long
# fixed and stable, and kept growing into a changelog nobody was reading;
# this starts fresh. Every fix below was diagnosed from a real install log,
# not speculation.
#
# CUSTOM WP-ADMIN SLUG — was completely non-functional, no error anywhere:
#   1. [CRITICAL] The slug's RewriteRules lived bare in wp-security.conf,
#      which loads in Apache's main-server context — but the <VirtualHost>
#      that actually serves every request never inherits main-server
#      rewrite rules without an explicit `RewriteOptions Inherit` (never
#      set). Dead config: no error, nothing in any log, slug just silently
#      never fired.
#   2. mod_rewrite has a SECOND, independent non-inheritance boundary
#      between a <Directory> block and a .htaccess file at the same path.
#      Fixed by placing the same rules directly in .htaccess — the same
#      per-directory ruleset that already makes permalinks and the 8G
#      firewall work — ahead of the WordPress-managed BEGIN/END block, with
#      the <Directory> copy kept as free defense-in-depth.
#   3. The author=N enumeration block had the identical bug; fixed the same way.
#
# GEOIP COUNTRY FILTERING — was silently never applying, even with valid
# MaxMind credentials:
#   4. [CRITICAL] The mod_maxminddb build container ran on Podman's default
#      bridge subnet, which the wp-net-only nftables forward rule silently
#      dropped — no internet access during build, apt-get/curl failed,
#      `podman build` failed, and every downstream step (geoip.conf, the
#      compiled module, the mmdb database) never ran, with nothing surfaced
#      as an error. Fixed with --network host for that one build step.
#   5. [CRITICAL] A bare `make` (no `make install`) never installs the
#      compiled module into /usr/lib/apache2/modules — confirmed directly
#      from a real build log where make succeeded but the module stayed in
#      the build tree at .libs/mod_maxminddb.so. Fixed by searching
#      recursively under the build directory instead of a hardcoded (and
#      wrong) install path, with a hard failure if it's still not found
#      instead of a confusing error two steps later.
#   6. GeoIP setup is now its own standalone, idempotent script —
#      /usr/local/bin/wp-geoip-setup.sh — so a bad credential or a
#      transient network issue can be fixed and retried on a live VM with
#      one command: no reboot, no re-running the full installer.
#   7. `update.sh wp` used to silently destroy GeoIP on every WordPress
#      update (pulled the bare upstream image with no knowledge of the
#      custom GeoIP image or its mounts). Now re-invokes
#      wp-geoip-setup.sh automatically after a successful base-image update.
#
# SHA256 DIGEST PINNING — new:
#   8. WordPress/MariaDB/CrowdSec are pinned to the exact digest resolved at
#      install time, not just the tag — resolved dynamically via
#      `podman pull` + `podman inspect`, never hardcoded (a hardcoded digest
#      goes stale the moment a registry rebuilds an image under the same
#      tag). Toggle at the install prompt, or via USE_DIGEST_PINNING in
#      /etc/wp-install/vars.sh afterward.
#   9. Podman's support for combined tag+digest references varies across
#      versions (older releases hard-reject it; some newer ones accept it
#      but drop the local tag) — tested directly against this host's Podman
#      rather than assumed, with a safe digest-only fallback either way.
#  10. Pull and digest-resolution each retry up to 3 attempts before falling
#      back to an unpinned reference. Every outcome — success or fallback —
#      is logged with the real podman error text to
#      /var/log/wp-digest-pinning.log, and a pin-count summary
#      ("Digest pinning: 3/3 pinned") is shown at install and in
#      `update.sh check`.
#  11. `update.sh digest-check` finds and offers to move to a newer digest
#      published under the SAME tag (e.g. a same-version security rebuild),
#      which a tag-only version comparison would never catch.
#  12. [CRITICAL, since fixed] An earlier iteration of this feature
#      corrupted every pinned image reference: ok()/warn() print to stdout,
#      and `$(...)` command substitution captures a function's ENTIRE
#      stdout, not just its final `echo` — so the human-readable status
#      line was landing inside the variable itself. Fixed by routing every
#      in-function diagnostic to stderr.
#
# ALPINE IMAGE INTEGRITY:
#  13. The downloaded Alpine cloud image is now verified against a freshly
#      fetched .sha512 (Alpine publishes SHA-512 for cloud/ qcow2 images,
#      not SHA-256 — confirmed directly against the CDN), fetched fresh
#      every run rather than a hash hardcoded against a version selector
#      that floats across point releases.
#
# RELIABILITY FIXES:
#  14. `update.sh wp`/`all` always failed: "-p ${WP_PORT}:80" was one single
#      quoted shell argument instead of two, so podman's flag parser tried
#      to read " 80" (stray leading space included) as the port number.
#  15. CrowdSec's firewall bouncer routinely came up crashed on first start
#      (a real race against LAPI still initializing) — now retries up to 5
#      times, both in the one-time installer AND baked into
#      crowdsec-container's own OpenRC service, so every future reboot is
#      covered too (an earlier fix only helped the very first boot).
#  16. Uploads were frequently not writable right after install, and stayed
#      that way across a reboot. Two causes: (a) a single blind chown raced
#      the entrypoint's own file creation, and (b) wp-content/uploads may
#      not exist at all until the first real media operation, which makes a
#      write-test fail exactly like a permissions problem that no amount of
#      chown can fix. Fixed with a wait-for-entrypoint retry loop plus an
#      unconditional mkdir -p before every writability check (install-time,
#      inline validation, and validate-wordpress.sh).
#  17. WP_DEBUG validation always showed "?": WORDPRESS_CONFIG_EXTRA never
#      actually defined WP_DEBUG, and PHP 8.3 throws a fatal error
#      referencing an undefined constant (older PHP just warned) — this
#      also silently broke wp-hardening.sh's enable/disable debug toggle,
#      whose sed pattern had nothing to match. WP_DEBUG is now explicitly
#      defined, and both checks are defensive either way.
#  18. CrowdSec bumped v1.7.6 → v1.7.8, patching a disclosed WAF-bypass CVE
#      in the AppSec datasource that directly affects the
#      crowdsecurity/appsec-wordpress collection this script enables.
#
# SECURITY HEADER CLEANUP:
#  19. Removed the X-XSS-Protection header (wp-security.conf generator and
#      the no-CIDR fallback config) — the browser-side reflected-XSS filter
#      it configured is gone from every current browser (Chrome/Edge
#      dropped their XSS Auditor in 2019; Firefox/Safari never implemented
#      it), so the header did nothing on any current browser, and on older
#      browsers that DID honor it, the filter itself was a known attack
#      surface. CSP — already set immediately below it in both places — is
#      the control that actually does this job.
#
# NETWORK SEGMENTATION — v7-6:
#  20. [CRITICAL] MariaDB and WordPress previously shared one flat network
#      (wp-net, 10.89.1.0/24) with no --internal flag. "No host port" kept
#      MariaDB safe from inbound scans, but the network itself still had a
#      route to the internet — MariaDB could reach out, and a compromised
#      WordPress container had direct L2 access to the database's entire
#      subnet. Replaced with a real two-network split:
#        wp-front (10.89.10.0/24) — WordPress only. Has egress (needed for
#          plugin/theme installs, WP-Cron remote requests, update checks).
#          This is also where the published host port (-p 80:80/8080:80)
#          and any reverse-proxy (NPM) traffic lands.
#        wp-db (10.89.20.0/24, --internal) — WordPress + MariaDB only.
#          Podman/netavark never configures a route out of an --internal
#          network, so MariaDB (and this leg of WordPress) has NO path to
#          the internet at all, regardless of nftables state.
#      WordPress joins both (wp-front primary, wp-db via `podman network
#      connect` after the container starts); MariaDB joins only wp-db.
#      nftables' forward chain now allow-lists both subnets instead of one.
#
#  21. [BUG FIX] update.sh's do_wp_update/do_db_update rename the running
#      container to *-old (not stop it) and keep it alive until the new
#      one passes its health check, so a fixed --ip on the new container
#      collides with the -old one still holding that same address on the
#      same network — the new `podman run`/`network connect` fails
#      outright and the update always rolls back. do_db_update already
#      omitted --ip for MariaDB for this exact reason; do_wp_update did
#      NOT (it kept a fixed IP against the old single wp-net address,
#      1.3, which had the identical latent bug pre-dating this network
#      split). Both update paths now leave IP assignment to netavark on
#      both networks; only the create-time paths (install, GeoIP rebuild,
#      OpenRC recreate-if-missing) use fixed IPs, since none of those have
#      an -old container coexisting to conflict with.
#
# v7-6d PATCH NOTES (on top of v7-6c baseline) — ROOTLESS REMOVED:
#  22. ROOTLESS PODMAN REMOVED. This script now provisions rootful Podman
#      ONLY — the rootless deployment path (wpuser-owned containers, the
#      port-8080 + nftables-redirect story, pasta source-IP forwarding, the
#      generated run-mariadb.sh/run-wordpress.sh/run-crowdsec.sh launcher
#      scripts, and every ROOTLESS_MODE branch in the installer, update.sh,
#      wp-hardening.sh, validate-wordpress.sh, wp-geoip-setup.sh, and the
#      three OpenRC service scripts) has been deleted rather than kept as a
#      second, less-tested path running alongside the wp-front/wp-db network
#      split introduced in v7-6. Rootful was already this script's
#      battle-tested recommended default; removing the alternative removes
#      an entire class of dispatch-related bugs (see 23 below) instead of
#      continuing to carry them through an increasingly complex two-network
#      topology.
#  23. [SECURITY] PRUN dispatch wrapper fixed. The old PRUN() had a rootless
#      branch that re-flattened every argument through
#      `su -s /bin/sh wpuser -c "podman $*"` — "$*" joins all arguments into
#      a single string on IFS, discarding the argument boundaries "$@" would
#      have preserved, and that string is then RE-PARSED by the inner
#      `sh -c`. Any argument containing shell metacharacters (spaces,
#      quotes, `;`, `$()`) would be reinterpreted rather than passed through
#      intact — and this script's own WORDPRESS_CONFIG_EXTRA value
#      ('define("WP_DEBUG",false);define(...);...') is exactly that kind of
#      argument. With rootless gone, PRUN is now a trivial `podman "$@"` in
#      every script that defines it — "$@" always preserves argument
#      boundaries, so this failure mode is gone entirely, not just avoided
#      in the common case.
#  24. Added validate_image_tag()/validate_digest_ref() to update.sh. The
#      VER argument to `update.sh wp|db|crowdsec [VER]` previously flowed
#      straight into an image reference with no validation of its own —
#      relying entirely on podman's own parser to reject anything malformed.
#      Both functions now run before that argument is used for anything,
#      giving a clear error message instead of a delayed, cryptic podman
#      failure.
#
# v7-6f PATCH NOTES (on top of v7-6e baseline) — SKOPEO + PINNED STATE:
#  25. SKOPEO-BASED DIGEST RESOLUTION. Resolving "what digest does this tag
#      point to right now" used to mean pulling the FULL image (150-200+ MB
#      each for WordPress/MariaDB) just to ask Podman what it downloaded —
#      both at install time and on every `update.sh check`. Skopeo's
#      `inspect docker://ref` asks the registry's manifest endpoint directly
#      (a few KB, no layer data), so both the installer's digest-pinning
#      step and update.sh now know the digest before anything is pulled.
#      A `podman pull` still happens, but only once, for the exact
#      `repo@sha256:digest` reference that's actually going to be pinned or
#      run — never as a separate discovery step. update.sh's read-only
#      `check`/`status` path (the default when it's run with no argument)
#      is now a genuinely read-only Skopeo manifest query — no pulls at
#      all. Skopeo missing or a lookup failing is never fatal: every call
#      site falls back to the pre-v7-6f pull-then-inspect method on its own.
#  26. PINNED STATE EXTERNALIZED to /etc/wp-install/pinned.env. Previously
#      "what tag/digest is currently pinned" had to be re-derived by
#      sed-parsing it back out of the running container's own
#      `{{.Config.Image}}` string, and update.sh kept itself current by
#      rewriting its own PINNED_WP_VER/PINNED_DB_VER/PINNED_CS_VER constants
#      on disk (`sed -i` against /usr/local/bin/update.sh itself) after
#      every successful update. Both patterns are gone: pinned.env is now
#      the single source of truth, written by the installer at install time
#      and kept current by update.sh's `_save_pinned()` after every
#      successful wp/db/crowdsec update — update.sh no longer self-modifies
#      at all. If pinned.env doesn't exist yet (a VM upgraded from a
#      pre-v7-6f update.sh), it's bootstrapped on first run from whatever's
#      currently running.
#  27. DIGEST-ONLY REFERENCES, ALWAYS. Item 9's runtime test for whether the
#      local Podman accepts a combined `repo:tag@sha256:digest` reference is
#      gone — every pinned reference is now the universally-supported
#      digest-only form (`repo@sha256:digest`), with the tag tracked
#      separately in pinned.env instead of inside the reference itself.
#      wp-geoip-setup.sh's tag-derivation logic, which used to special-case
#      "tag+digest present" vs. "digest-only" based on that now-removed
#      test, was updated to read the tag from pinned.env directly instead —
#      unchanged, the old heuristic would have silently degraded to its
#      short-digest-fragment fallback on every single run (digest-only was
#      no longer the exception, it's now the rule), producing GeoIP image
#      tags like `wordpress-geoip:a1b2c3d4e5f6` instead of a readable
#      version.
#  28. OpenRC recreate-fallback paths (wp-container, mariadb-container) now
#      also consult pinned.env before falling back to their install-time-
#      baked WP_IMAGE/DB_IMAGE. Necessary consequence of 26: since update.sh
#      no longer rewrites those baked-in values on disk, leaving this
#      unaddressed would mean the recreate-if-missing path (the branch that
#      only fires if a container is ever removed outside of update.sh) could
#      silently drift back to whatever was pinned at install time. WordPress
#      skips this override when a local GeoIP image is already in play,
#      since pinned.env's WP_DIGEST tracks the upstream image, not the
#      locally-built GeoIP layer.
#
# v7-6k PATCH NOTES (on top of v7-6j baseline) — DEDICATED ADMIN ACCOUNT:
#  29. [SECURITY] Root SSH login is now disabled unconditionally
#      (PermitRootLogin no) regardless of whether an SSH key was supplied —
#      closing remaining_tasks.txt item 5 ("SSH still allows root + password
#      login when no key is given... no dedicated non-root admin account is
#      created either way"). A dedicated admin account (name prompted,
#      default wpadmin) is created in the wheel group, with doas configured
#      (`permit persist :wheel` in /etc/doas.d/doas.conf, per Alpine's own
#      documented pattern — doas prompts for the ACCOUNT'S OWN password, not
#      root's, so it authenticates independently of however that account
#      itself logs in). If an SSH key was supplied, it's placed on the admin
#      account (not root) and password auth is disabled server-wide; if not,
#      the admin account gets an operator-chosen password (prompted/
#      confirmed the same way the VM's root console password already is)
#      and THAT is what SSH accepts — never a root password over SSH, key or
#      no key. Root keeps its console password unconditionally (`qm
#      terminal`/noVNC access is unrelated to and unaffected by any of this).
#  30. Account creation needs adduser/addgroup writing into the target
#      filesystem's own passwd/group/shadow, and doas needs apk + network —
#      both require a live chroot, exactly like the QEMU Guest Agent
#      pre-install already did. Rather than mount and unmount /proc and
#      /dev twice for two separate chroot calls, both now share one: the
#      combined chroot runs immediately after the root password is set,
#      and /proc and /dev stay bind-mounted through the rest of injection
#      (nothing written in between cares whether they're mounted), torn
#      down once at the very end instead of twice.
#  31. Safety fallback: adduser inside a chroot is a simple, local,
#      network-independent operation and should essentially never fail —
#      but if it somehow does, the script does NOT silently leave the VM
#      unreachable over SSH. It verifies the account actually exists
#      (grep against the target's own /etc/passwd, not the chroot's exit
#      code, since a later doas/network failure in the same chroot must
#      not be misread as "account missing") and, only on genuine failure,
#      falls back to the pre-v7-6k behavior (root SSH, key or password per
#      what was supplied) with a loud warning in the install log and in
#      both summary banners — a degraded fallback, not a silent one.
#  32. SSH_KEYS and the admin password are deliberately never interpolated
#      into the chroot's `sh -c` string at all (unlike the sanitized,
#      regex-constrained ADMIN_USER, which is safe to interpolate) —
#      operator-pasted key content or a chosen password could contain
#      anything. Both are written host-side via plain redirection or a
#      shadow sed, after the chroot exits, the exact same mechanism root's
#      own password and key already used before this change — never passed
#      through a shell for re-interpretation.
#  33. doas installation inside the pre-boot chroot depends on the PROXMOX
#      HOST reaching Alpine's CDN at provisioning time — normally fine (the
#      QEMU Guest Agent pre-install already relies on the same path), but
#      as a redundant safety net Stage 1 of the installer also attempts
#      `apk add doas` (idempotent, no-op if already present) once the VM
#      has its own guaranteed-working network, closing the one plausible
#      network-dependent gap in an otherwise network-independent setup.
#  34. Auto-generated vs. operator-chosen admin passwords are handled the
#      same way root's own password already is: an operator-typed password
#      (no-key path, actually used for SSH) is never written to disk in
#      plaintext — they typed it, they know it. An auto-generated one
#      (key-provided path, used only by doas — nobody types or needs to
#      remember it) IS written, to /root/.wp-admin-credentials (chmod 600),
#      the same treatment already given to the openssl-rand DB passwords in
#      /root/.wp-credentials, and for the identical reason: without writing
#      it down it would be permanently unusable.
#
# v7-6k PATCH NOTES (on top of v7-6j baseline) — TWO PARALLEL PRODUCTION-
# SAFETY REVIEWS MERGED INTO ONE:
#  35. [PRODUCTION SAFETY] Strengthened MariaDB health checks. wp-health-
#      check.sh (v7-6g) closed the shallow-check gap for WordPress, but
#      every MariaDB readiness gate — the install-time wait loop (before
#      either container exists yet) and update.sh's do_db_update()
#      rollback decision — was still a bare `mariadbd-admin ping`, which
#      proves only that the server accepts TCP and that root
#      authenticates. It proves nothing about InnoDB actually being usable
#      or about whether WordPress's OWN database/user (MARIADB_DATABASE/
#      MARIADB_USER, not root) can run a query — the same shallow-success/
#      broken-application blind spot the old WordPress `wget -qO-` check
#      had. New /usr/local/bin/mariadb-health-check.sh adds a root query,
#      the exact wordpress-credential query, and an InnoDB-initialized
#      check, and is wired into the install-time wait loop, do_db_update(),
#      and both validate-wordpress.sh and the post-install validation
#      suite — mirroring wp-health-check.sh's role for WordPress. Falls
#      back to the old ping-only check automatically if the script is
#      somehow missing (e.g. a VM recreated from an older installer).
#  36. [PRODUCTION SAFETY] Container-swap error handling. Every "swap in a
#      replacement container" path in update.sh (do_wp_update/do_db_update/
#      do_cs_update) previously suppressed the result of `podman rename`
#      with `2>/dev/null || true` on the forward swap, and discarded the
#      result of both `podman rename` and `podman start` the same way on
#      every rollback swap. Concretely, in do_wp_update(): if
#      `podman rename wordpress wordpress-old` silently failed, "wordpress"
#      kept its name, so the following `podman run -d --name wordpress`
#      failed too (a name collision) — a failure that WAS checked, so
#      control fell into the "container start failed — rolled back"
#      branch, whose first line was `podman rm -f wordpress`: deleting the
#      still-good, still-running ORIGINAL container in the mistaken belief
#      it was cleaning up a failed new attempt. One suppressed error could
#      cascade into deleting a healthy production container. New
#      require_clean_container_state() preflights every rename's own
#      preconditions (missing source container; a stale *-old container
#      left over from a previous crashed/interrupted update) before
#      attempting it, across WordPress, MariaDB, and CrowdSec. Every
#      rename+start pair — forward swap and rollback swap alike — is now
#      checked directly instead of discarding its result, with a loud
#      "ROLLBACK FAILED" message plus manual-recovery commands printed if a
#      rollback itself doesn't work, since that's the one moment silence is
#      most dangerous: the site, database, or CrowdSec is down right now
#      and nobody has been told. A leftover *-old container after a
#      SUCCESSFUL update is also now flagged (it would otherwise silently
#      block the next update's preflight check).
#  37. [PRODUCTION SAFETY] update.sh update lock. Nothing previously stopped
#      two update.sh invocations from running at once — an admin running
#      `update.sh wp` while a cron-triggered `update.sh digest-check` is
#      already mid-run, say. That could race two processes renaming the
#      same container to *-old, or writing /etc/wp-install/pinned.env at
#      the same time, or overlapping MariaDB dumps against the same data
#      directory. A plain mkdir-based lock at /run/lock/wordpress-update.lock
#      closes this — mkdir is atomic on every storage backend this script
#      runs on, so only one invocation can ever hold it. The holder's PID is
#      recorded inside the lock so a stale lock left by a crashed update
#      (OOM-killed, VM rebooted mid-update) is detected via `kill -0` and
#      cleared automatically. Only the state-changing subcommands
#      (os/wp/db/crowdsec/all/digest-check) take the lock — check/status/
#      trivy stay lock-free since they're read-only and meant to stay safe
#      to run anytime, including while an update is in progress.
#
# v7-7 PATCH NOTES (on top of the v7-6k baseline) — MERGE OF THE TWO
# PARALLEL v7-6k LINES ABOVE INTO ONE SCRIPT:
#  38. The dedicated-admin-account line (items 29-34) and the production-
#      safety line (items 35-37) were developed in parallel off the same
#      v7-6j baseline and touch different, non-overlapping parts of the
#      script — host-side provisioning/SSH/chroot injection vs. update.sh
#      and its health-check scripts — so reconciling them was a straight
#      union of both feature sets rather than a resolution of competing
#      designs. Every item above (29-37) is present and active in this
#      version.
#  39. do_db_update()/do_cs_update() now keep BOTH styles of
#      require_clean_container_state() check that existed separately across
#      the two parallel lines: the EARLY fail-fast call (before any backup,
#      pull, or container is stopped — dropped in the production-safety
#      line's rewrite of item 36) AND the check immediately before the
#      actual rename (added by that same rewrite as tighter defense-in-depth
#      right at the point of use). Keeping both is strictly safer than
#      either alone and costs almost nothing (one extra `podman container
#      exists` call): the early check avoids a wasted backup + pull + a
#      brief unnecessary WordPress/MariaDB stop/start cycle when the update
#      was going to be refused anyway (a stale *-old container from a
#      previous crashed run, most commonly), while the later check still
#      catches state that changed during that window — an operator manually
#      intervening mid-update, for instance. At the time this note was
#      written, do_wp_update() was unaffected: neither parallel line above
#      had more than one check site for it, since nothing destructive
#      happened before its single rename point. Item 40 below changes that.
#
# v7-7 PATCH NOTES (continued) — WORDPRESS UPDATE CUTOVER MERGED IN:
#  40. [CRITICAL] A third line of work, developed in parallel off the same
#      v7-6f baseline as the two lines merged into v7-7 above (items 29-37),
#      had never been folded in until now: a candidate/cutover rewrite of
#      update.sh's do_wp_update() that fixes a structural bug making
#      `update.sh wp` — and so `update.sh all` / `update.sh digest-check`,
#      which both call it — unable to ever actually complete a WordPress
#      update. Before this merge, do_wp_update() renamed the running
#      "wordpress" container to wordpress-old — a rename, not a stop — and
#      immediately tried to `podman run` a brand-new container ALSO
#      publishing -p 80:80. wordpress-old was still running and still
#      holding host port 80 at that exact moment (renaming a container
#      never stops it or releases its published ports), so the new
#      container's own port publish failed every time — not an occasional
#      race, a structural guarantee. That `podman run` sat inside an
#      `if ...; then`, so the failure was caught, but only after the fact:
#      control fell into the existing rollback branch, renamed wordpress-old
#      back to "wordpress" (which had never actually stopped serving traffic
#      under its temporary name), and reported a plain "Container start
#      failed — rolled back" with nothing distinguishing this from a
#      genuine one-off failure. Item 36's container-swap error-handling
#      rewrite (the production-safety line) fixed how this failure was
#      reported and rolled back — every rename/start result checked, loud
#      "ROLLBACK FAILED" messages if even the rollback failed — but never
#      touched the underlying port-80 collision itself, since neither
#      parallel line was aware of the other's changes to this function.
#      (The dedicated-admin-account line was a straight ancestor of neither;
#      this candidate/cutover rewrite was developed on a separate branch off
#      v7-6f, alongside — not as part of — the two lines items 29-39
#      describe.) Net effect prior to this merge: `update.sh wp` would ask,
#      Trivy-scan, and pull a new WordPress image, then reliably fail to
#      deploy it and roll back (safely and loudly, thanks to item 36 — but
#      roll back regardless), every single time.
#      FIX: candidate/cutover. The freshly pulled image now starts first as
#      a throwaway "wordpress-candidate" container published ONLY to
#      127.0.0.1:18080 (WP_CANDIDATE_PORT) — loopback-only, so it can never
#      collide with production's 0.0.0.0:80 and is never reachable from
#      outside the VM. It runs against the same volumes, env file, and
#      wp-front/wp-db networks as production, so the check is real rather
#      than a synthetic smoke test, and it must pass the same
#      wp-health-check.sh validation (HTTP + PHP execution + mariadb DNS +
#      a real WordPress-credential query) used at every other health-check
#      call site in this script. Production is not touched while this
#      runs — if the candidate never starts, or starts but fails
#      validation, the update aborts here with nothing changed. Only once
#      the candidate proves the new image actually works is
#      require_clean_container_state() consulted again and "wordpress"
#      renamed to wordpress-old and explicitly STOPPED — freeing host port
#      80 for real, not just freeing the name — and only then is the real
#      "wordpress" container created against port 80 and health-checked a
#      second time, with every rename/start result checked and a loud
#      "ROLLBACK FAILED" report if even the rollback doesn't work, exactly
#      per item 36's existing standard for MariaDB and CrowdSec. An early
#      require_clean_container_state() check was also added before the
#      pull/candidate sequence even begins — item 39's reasoning for
#      MariaDB/CrowdSec (avoid wasting work on an update that was going to
#      be refused anyway) now applies to WordPress too, since the candidate
#      step means substantial work happens before the rename point for the
#      first time. A short downtime window during the final cutover itself
#      is unavoidable — host port 80 can only ever be held by one container
#      at a time on a single Apache-on-:80 VM, with no second reverse-proxy
#      layer in front of it — but it's now short and high-confidence, since
#      the image was already proven to work before production was ever
#      stopped. Needs 127.0.0.1:18080 free on the VM; change
#      WP_CANDIDATE_PORT in update.sh if that port is already in use for
#      something else.
#
# v7-9 PATCH NOTES (on top of the v7-8 baseline) — MARIADB UPDATE PATH
# HARDENED (do_db_update() only; MariaDB's own recreate-if-missing OpenRC
# fallback and the daily backup cron are untouched by this entry):
#  41. [CRITICAL] Three related gaps in do_db_update() — a backup step that
#      could report success on a failed dump, a container-only rollback
#      that left the actual data directory unprotected, and no check that
#      WordPress could really use the new database before the rollback
#      path was deleted — are fixed together, since all three share one
#      root cause: nothing in this function actually verified the state it
#      was trusting before discarding the only way back.
#        (a) BACKUP VERIFICATION. The pre-update dump used to be
#            `podman exec mariadb ... mariadb-dump ... | gzip > file`
#            inside an `if ...; then`. In a pipeline, a shell's exit status
#            is the LAST command's (gzip) — gzip happily exits 0
#            compressing whatever bytes it received, including zero bytes
#            from a mariadb-dump that failed outright (bad auth, dropped
#            connection, disk full on the container side). The `if` could
#            therefore report a successful backup for a truncated or
#            entirely empty one. Fixed by never piping straight into gzip:
#            mariadb-dump now writes to a plain .sql file first (so its
#            OWN exit code, not gzip's, is what gets checked, with stderr
#            captured separately for diagnostics), the result is checked
#            for non-zero size AND mariadb-dump's own trailing
#            "-- Dump completed on ..." marker — the same structural
#            signal most production mysqldump/mariadb-dump backup scripts
#            use to detect a truncated run — and only THEN is it
#            compressed, with the resulting .gz verified via `gzip -t`
#            before the backup is considered good. Any failure at any
#            stage aborts the update before anything is stopped, with the
#            raw dump's stderr printed for diagnosis.
#        (b) DATA-DIRECTORY SNAPSHOT. The replacement MariaDB container
#            always mounted the exact same bind-mount
#            (/home/wpuser/wp/mysql) as the one being replaced, with no
#            volume-level rollback point — only the logical dump from (a)
#            existed, which is slow to restore under pressure, and if a
#            new engine version mutates on-disk structures on startup (an
#            InnoDB redo-log/system-table upgrade, for instance) even
#            while ultimately failing to become healthy, "renaming the
#            container back" does NOT undo whatever it already wrote to
#            that directory. Fixed with a real filesystem-level snapshot:
#            once MariaDB is confirmed stopped (and after a disk-space
#            preflight sized off the live data directory, so a too-full
#            disk aborts loudly with zero downtime instead of leaving
#            services stopped), /home/wpuser/wp/mysql is copied wholesale
#            to /home/wpuser/wp/mysql-preupdate-snapshot BEFORE the new
#            image ever touches the real data directory. Every rollback
#            path now restores from this snapshot (via same-filesystem
#            `mv`, not a second slow copy) before the old container is
#            ever restarted against that directory — and refuses to start
#            it at all if the restored directory doesn't look like a real
#            MariaDB data directory afterward (guarding against the
#            official image's own behavior of silently initializing a
#            brand-new EMPTY database against a missing/empty
#            /var/lib/mysql, which would make catastrophic data loss look
#            exactly like a clean, healthy rollback). The failed update's
#            own data is kept alongside (timestamped) rather than deleted,
#            in case it's ever needed for forensics. The snapshot itself
#            is only removed once an update is confirmed fully healthy —
#            see (c).
#        (c) WORDPRESS-LEVEL HEALTH GATE. mariadb-health-check.sh passing
#            used to be the ONLY gate before mariadb-old was deleted —
#            proving MariaDB itself is healthy, but not that WordPress,
#            the actual application, can use it (a schema-level
#            incompatibility a generic SELECT 1 wouldn't catch, for
#            instance). The old code also restarted WordPress with
#            `|| true`, silently swallowing its own failure. WordPress is
#            now validated with the same wp-health-check.sh depth (HTTP +
#            PHP execution + DB name resolution + a real WordPress-
#            credential query) used at every other health-check site in
#            this script, and mariadb-old plus the pre-update snapshot are
#            ONLY removed once that passes. If WordPress fails to restart,
#            or restarts but can't actually use the new database, this now
#            triggers the exact same full rollback as an unhealthy
#            MariaDB — restoring the data-directory snapshot from (b) and
#            restoring the old container from mariadb-old — instead of
#            silently leaving a broken combination in place with the
#            rollback container already gone.
#      All three failure paths (MariaDB itself unhealthy, the new
#      container failing to start at all, and WordPress failing to
#      reconnect) now share one _db_rollback() helper instead of three
#      separately-maintained copies, closing off the kind of drift between
#      near-identical call sites that item 7/36 already had to fix once
#      for this same function's rename/start error handling. Empirically
#      confirmed (not assumed) that every bare call into this helper needs
#      an explicit `|| true` guard: update.sh runs under `set -e`, and a
#      function returning non-zero as a plain statement aborts the whole
#      script immediately — which would have skipped the rest of
#      do_db_update() AND, from do_digest_check()/`update.sh all`,
#      prevented CrowdSec from ever being checked after a MariaDB failure.
#      NOT changed by this entry (tracked separately): mariadb-upgrade's
#      own exit status is still unchecked (open finding #5); the daily
#      backup cron job has the identical pipe-to-gzip pattern as (a) above
#      and was intentionally left as-is, since this entry is scoped to
#      do_db_update() only.
#
# ROOTFUL DEPLOYMENT (fixed design — not a dated note):
#   MariaDB   — rootful, --cap-drop ALL + 5 caps, isolated to wp-db
#               (--internal, no host port, no egress).
#   WordPress — rootful, --cap-drop ALL + 6 caps. Requires NET_BIND_SERVICE
#               because Apache binds port 80 inside the container's own
#               network namespace even with -p 80:80 (Podman's host-side
#               port publish is separate from Apache's in-netns bind).
#   CrowdSec  — rootful, --network host, --read-only, minimal caps.
#               Must use host network to see syslog and write nftables rules.
# =============================================================================
set -e

RD='\033[0;31m' GN='\033[0;32m' YW='\033[0;33m' BL='\033[0;36m'
BLD='\033[1m'   CL='\033[0m'
msg_info()  { echo -e "  ${BL}➜${CL}  $*"; }
msg_ok()    { echo -e "  ${GN}✔${CL}  $*"; }
msg_warn()  { echo -e "  ${YW}⚠${CL}  $*"; }
msg_error() { echo -e "  ${RD}✗${CL}  $*" >&2; exit 1; }

# ── VM sizing ─────────────────────────────────────────────────────────────────
_next_vmid() { pvesh get /cluster/nextid 2>/dev/null | tr -d '"' || echo 100; }
VMID=""
CORES=2
RAM=4096
DISK="20G"

# ── Alpine BIOS cloud image — auto-detect newest from CDN ────────────────────
_find_alpine_image() {
  local base="https://dl-cdn.alpinelinux.org/alpine"
  for minor in 3.24 3.23 3.22 3.21; do
    local idx="${base}/v${minor}/releases/cloud/"
    local fname
    fname=$(curl -fsSL --max-time 10 "$idx" 2>/dev/null \
      | grep -oE "generic_alpine-${minor//./\\.}\\.[0-9]+-x86_64-bios-cloudinit-r[0-9]+\\.qcow2" \
      | sort -V | tail -1)
    if [[ -n "$fname" ]]; then
      ALPINE_VER=$(echo "$fname" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
      ALPINE_MINOR="$minor"
      ALPINE_URL="${idx}${fname}"
      return 0
    fi
  done
  ALPINE_VER="3.23.4"; ALPINE_MINOR="3.23"
  ALPINE_URL="${base}/v3.23/releases/cloud/generic_alpine-3.23.4-x86_64-bios-cloudinit-r0.qcow2"
}
ALPINE_VER="" ALPINE_MINOR="" ALPINE_URL=""
_find_alpine_image
IMG_CACHE="/var/lib/vz/template/iso"
IMG_FILE="${IMG_CACHE}/$(basename "$ALPINE_URL")"

# ── Cleanup on error ──────────────────────────────────────────────────────────
_NBD="" _MNT="" _DESTROY_VM=1
cleanup() {
  set +e
  [[ -n "$_MNT" ]] && { umount "$_MNT/dev" 2>/dev/null; umount "$_MNT/proc" 2>/dev/null
                         umount "$_MNT"      2>/dev/null; }
  [[ -n "$_NBD" ]] && qemu-nbd --disconnect "$_NBD" 2>/dev/null
  if (( _DESTROY_VM )) && [[ -n "$VMID" ]] && qm status "$VMID" &>/dev/null 2>&1; then
    qm stop "$VMID" --skiplock 2>/dev/null; qm destroy "$VMID" --purge 2>/dev/null
  fi
}
trap cleanup EXIT

# ── Pre-flight ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]]                || msg_error "Must run as root on the Proxmox host."
[[ -f /etc/pve/pve-root-ca.pem ]] || msg_error "Not a Proxmox VE host."
command -v qm        &>/dev/null || msg_error "'qm' not found."
command -v qemu-nbd  &>/dev/null || msg_error "'qemu-nbd' not found — apt install qemu-utils"
command -v qemu-img  &>/dev/null || msg_error "'qemu-img' not found — apt install qemu-utils"
command -v openssl   &>/dev/null || msg_error "'openssl' not found."

# ── Interactive setup ─────────────────────────────────────────────────────────
clear
echo -e "\n${BLD}  WordPress VM${CL}"
echo    "  Alpine (auto) + Podman (WordPress + MariaDB) + CrowdSec + nftables"
echo    "  ${CORES} CPU · ${RAM} MB · ${DISK} · hardened Apache + PHP"
echo ""

SUGGESTED=$(_next_vmid)
while true; do
  read -rp "  VM ID        [${SUGGESTED}] : " _vmid
  VMID="${_vmid:-$SUGGESTED}"
  [[ "$VMID" =~ ^[0-9]+$ ]] || { echo -e "  ${RD}ID must be a number.${CL}"; continue; }
  (( VMID >= 100 ))          || { echo -e "  ${RD}ID must be ≥ 100.${CL}"; continue; }
  if qm status "$VMID" &>/dev/null 2>&1 || \
     [[ -f "/etc/pve/qemu-server/${VMID}.conf" ]] || \
     [[ -f "/etc/pve/lxc/${VMID}.conf" ]]; then
    echo -e "  ${RD}VM ${VMID} already exists.${CL}"
    SUGGESTED=$(( VMID + 1 )); continue
  fi
  break
done

ROOT_PASS=""
while [[ -z "$ROOT_PASS" ]]; do
  read -rsp "  Root password for the VM : " p1; echo
  read -rsp "  Confirm                  : " p2; echo
  [[ "$p1" == "$p2" && -n "$p1" ]] && ROOT_PASS="$p1" \
    || echo -e "  ${RD}Passwords do not match.${CL}"
done

read -rp "  Hostname       [wordpress] : " HN; HN="${HN:-wordpress}"

echo ""
msg_info "Available storages:"
pvesm status --content images 2>/dev/null \
  | awk 'NR>1 && $2=="active" {printf "    • %-20s (%s)\n", $1, $4}'
read -rp "  Storage  [local-lvm] : " STORAGE; STORAGE="${STORAGE:-local-lvm}"
read -rp "  Bridge       [vmbr0] : " BRIDGE;  BRIDGE="${BRIDGE:-vmbr0}"
read -rp "  VLAN tag  (blank=no) : " VLAN_RAW
VLAN="${VLAN_RAW:+,tag=${VLAN_RAW}}"

echo ""
echo -e "  ${BLD}Network addressing${CL}"
echo -e "  ${YW}Proxmox host interfaces (for reference — pick an address on the same subnet):${CL}"
ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print "    " a[1] "  (subnet: " $2 ")"}' | head -6
echo ""
echo "  [1] DHCP — VM gets an address automatically (default)"
echo "  [2] Static IPv4 — you assign the address, gateway, and DNS now"
read -rp "  Network mode [1] : " NET_MODE_SEL
NET_MODE="dhcp"
VM_STATIC_IP="" VM_PREFIX="" VM_GATEWAY="" VM_DNS=""

_valid_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a parts <<< "$ip"
  for o in "${parts[@]}"; do (( o >= 0 && o <= 255 )) || return 1; done
  return 0
}

if [[ "$NET_MODE_SEL" == "2" ]]; then
  while true; do
    read -rp "  VM static IPv4 address (e.g. 192.168.1.50) : " VM_STATIC_IP
    _valid_ipv4 "$VM_STATIC_IP" && break || echo -e "  ${RD}Not a valid IPv4 address — try again.${CL}"
  done
  while true; do
    read -rp "  Subnet prefix length, CIDR bits [24] : " VM_PREFIX
    VM_PREFIX="${VM_PREFIX:-24}"
    [[ "$VM_PREFIX" =~ ^[0-9]+$ ]] && (( VM_PREFIX >= 1 && VM_PREFIX <= 32 )) && break
    echo -e "  ${RD}Enter a number 1-32 (e.g. 24 for a /24).${CL}"
  done
  while true; do
    read -rp "  Gateway IPv4 address (required) : " VM_GATEWAY
    _valid_ipv4 "$VM_GATEWAY" && break || echo -e "  ${RD}Not a valid IPv4 address — try again.${CL}"
  done
  read -rp "  DNS servers, space-separated [1.1.1.1 8.8.8.8] : " VM_DNS
  VM_DNS="${VM_DNS:-1.1.1.1 8.8.8.8}"
  NET_MODE="static"

  # CIDR prefix -> dotted-decimal netmask (e.g. 24 -> 255.255.255.0)
  _cidr_to_netmask() {
    local cidr=$1 mask="" i bits
    for ((i=0; i<4; i++)); do
      if (( cidr >= 8 )); then bits=255; cidr=$((cidr-8));
      elif (( cidr > 0 )); then bits=$((256 - 2**(8-cidr))); cidr=0;
      else bits=0; fi
      mask+="${bits}"
      (( i < 3 )) && mask+="."
    done
    echo "$mask"
  }
  VM_NETMASK=$(_cidr_to_netmask "$VM_PREFIX")
  msg_ok "Static IP: ${VM_STATIC_IP}/${VM_PREFIX} (netmask ${VM_NETMASK}) via ${VM_GATEWAY}, DNS: ${VM_DNS}"
else
  NET_MODE="dhcp"
  msg_ok "Network: DHCP (default)"
fi

echo ""
echo -e "  ${BLD}SSH access${CL}"
echo -e "  ${YW}Root SSH login is always disabled on this VM. A dedicated admin account${CL}"
echo -e "  ${YW}is created instead, in the 'wheel' group, with doas configured for root${CL}"
echo -e "  ${YW}access after login (root still has a local console password for${CL}"
echo -e "  ${YW}'qm terminal' access — that's separate from SSH).${CL}"
echo "  Paste your public key (starts with ssh-ed25519 or ssh-rsa),"
echo "  or press Enter to load from a file path."
read -rp "  Public key (paste, or blank) : " SSH_KEY_PASTE
SSH_KEYS=""
if [[ -n "$SSH_KEY_PASTE" ]]; then
  SSH_KEYS="$SSH_KEY_PASTE"
else
  read -rp "  ...or path to a .pub file (blank = set an admin password instead) : " SK
  [[ -n "$SK" && -f "$SK" ]] && SSH_KEYS=$(cat "$SK")
fi

# Sanitise: lowercase, alnum + underscore/hyphen, must start with a letter
# (POSIX username rules) — same sanitisation style as WP_ADMIN_SLUG below,
# plus an explicit leading-character check that a URL slug doesn't need.
read -rp "  Admin account username [wpadmin] : " ADMIN_USER_RAW
ADMIN_USER=$(echo "${ADMIN_USER_RAW:-wpadmin}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9_-' '-' | sed 's/^-//;s/-$//')
[[ "$ADMIN_USER" =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || ADMIN_USER="wpadmin"
# Reserved names: root (this whole feature's point), wpuser (already used
# for file/volume ownership — see wpuser creation later — colliding would
# make adduser fail and trip the ADMIN_USER_CREATED fallback further down).
[[ "$ADMIN_USER" == "root" || "$ADMIN_USER" == "wpuser" ]] && ADMIN_USER="wpadmin"

ADMIN_PASS=""
if [[ -n "$SSH_KEYS" ]]; then
  DISABLE_PW_AUTH=1
  # Password auth is off session-wide, so this account's password is never
  # typed over SSH — it exists purely so doas has something to authenticate
  # against once logged in. Generated the same way the DB passwords are
  # (openssl rand, unknown to the operator, written to a credentials file
  # on disk) rather than asked for, since nobody needs to remember it.
  ADMIN_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 24)
  msg_ok "SSH key set — password login disabled. Admin account: ${ADMIN_USER}"
else
  DISABLE_PW_AUTH=0
  msg_warn "No SSH key — ${ADMIN_USER} will use password login (root SSH stays disabled either way)"
  while [[ -z "$ADMIN_PASS" ]]; do
    read -rsp "  Password for ${ADMIN_USER} : " ap1; echo
    read -rsp "  Confirm                  : " ap2; echo
    [[ "$ap1" == "$ap2" && -n "$ap1" ]] && ADMIN_PASS="$ap1" \
      || echo -e "  ${RD}Passwords do not match.${CL}"
  done
fi

echo ""
echo -e "  ${BLD}Firewall + access control${CL}"
echo ""
echo -e "  ${BLD}Layer 1 — nftables (packet level, applies to ALL traffic on 80/443):${CL}"
read -rp "  Restrict SSH (22) to a CIDR?           (blank = any)  : " SSH_CIDR
read -rp "  Restrict Web (80/443) to a CIDR?       (blank = any)  : " WEB_CIDR
[[ -z "$WEB_CIDR" ]] && msg_warn "Web ports open to any IP — Layer 2 (Apache) still enforces wp-admin"
echo ""
echo -e "  ${BLD}Layer 2 — Apache (request level, wp-admin + wp-login.php only):${CL}"
echo -e "  ${YW}This restriction works whether traffic is direct OR through a reverse proxy.${CL}"
echo -e "  ${YW}Set to your local network CIDR (e.g. 192.168.1.0/24).${CL}"
echo ""
echo -e "  ${YW}Your workstation is likely on one of these subnets (from the Proxmox host):${CL}"
ip -4 addr show scope global 2>/dev/null | awk '/inet /{split($2,a,"/"); print "    " a[1] "  (subnet: " $2 ")"}' | head -5
echo ""
read -rp "  Local network CIDR for wp-admin?  e.g. 192.168.100.0/24 (blank = open) : " ADMIN_CIDR
read -rp "  Additional IP for wp-admin?  (e.g. 203.0.113.5, blank = none)  : " ALLOWED_ADMIN_IP
echo ""
echo -e "  ${BLD}Layer 2b — mod_remoteip (only needed if behind a reverse proxy):${CL}"
echo -e "  ${YW}If WordPress is behind NPM / nginx / Caddy, Apache sees the proxy IP${CL}"
echo -e "  ${YW}not the real client IP. Enter the proxy's internal IP so Apache trusts${CL}"
echo -e "  ${YW}its X-Forwarded-For header for accurate wp-admin IP checks.${CL}"
read -rp "  Reverse proxy IP (e.g. 192.168.1.50, blank = direct access) : " PROXY_IP
echo ""
echo -e "  ${BLD}Security features${CL}"
echo -e "  ${YW}Custom wp-admin slug: replaces /wp-admin and /wp-login.php with a secret URL.${CL}"
echo -e "  ${YW}Choose something unique (e.g. siteadmin, seclogin, mymsp2024).${CL}"
echo -e "  ${YW}Avoid obvious words: admin, login, dashboard, wp, secure.${CL}"
read -rp "  wp-admin custom slug?  (blank = keep default /wp-admin) : " WP_ADMIN_SLUG
# Sanitise: lowercase, alphanumeric + hyphen only
WP_ADMIN_SLUG=$(echo "${WP_ADMIN_SLUG}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed 's/^-//;s/-$//')
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  msg_ok "Admin slug: /${WP_ADMIN_SLUG}  (direct /wp-admin access will return 403)"
else
  msg_warn "No slug set — /wp-admin accessible at default URL (still protected by ADMIN_CIDR + CrowdSec)"
fi
echo ""
echo -e "  ${BLD}CrowdSec Console enrolment (optional — can be done after install):${CL}"
echo -e "  ${YW}Get your enrolment key at https://app.crowdsec.net → Security Engines → Add${CL}"
echo -e "  ${YW}This automates the enrolment step so you don't need to SSH in afterwards.${CL}"
read -rsp "  CrowdSec enrolment key (blank = skip, enrol manually later) : " CROWDSEC_ENROLL_KEY; echo

echo ""
echo -e "  ${BLD}GeoIP country filtering (optional — Layer 2 Apache, site-wide)${CL}"
echo -e "  ${YW}Blocks or allows visitors by country before WordPress/PHP ever runs.${CL}"
echo -e "  ${YW}Uses MaxMind's free GeoLite2-Country database via the mod_maxminddb${CL}"
echo -e "  ${YW}Apache module (compiled during install — adds ~2 min, then removed${CL}"
echo -e "  ${YW}build tools to keep the container lean).${CL}"
echo -e "  ${YW}Requires a FREE MaxMind account: https://www.maxmind.com/en/geolite2/signup${CL}"
read -rp "  Enable GeoIP country filtering? [y/N] : " GEOIP_ENABLE
GEOIP_ENABLED=0 GEOIP_MODE="" GEOIP_WHITELIST="" GEOIP_BLOCKLIST=""
MAXMIND_ACCOUNT_ID="" MAXMIND_LICENSE_KEY=""
if [[ "${GEOIP_ENABLE:-N}" =~ ^[Yy] ]]; then
  read -rp "  MaxMind Account ID  : " MAXMIND_ACCOUNT_ID
  read -rsp "  MaxMind License Key : " MAXMIND_LICENSE_KEY; echo
  if [[ -z "$MAXMIND_ACCOUNT_ID" || -z "$MAXMIND_LICENSE_KEY" ]]; then
    msg_warn "Both Account ID and License Key are required — GeoIP filtering will be skipped"
  else
    echo ""
    echo "  Whitelist mode : ONLY listed countries can reach the site (strict)"
    echo "  Blocklist mode : everyone EXCEPT listed countries can reach the site"
    read -rp "  Whitelist countries (ISO codes, e.g. US,CA,GB) or blank for blocklist mode : " GEOIP_WHITELIST
    if [[ -z "$GEOIP_WHITELIST" ]]; then
      read -rp "  Block countries (ISO codes, comma-separated, e.g. CN,RU,KP) : " GEOIP_BLOCKLIST
      GEOIP_MODE="blocklist"
    else
      GEOIP_MODE="whitelist"
    fi
    GEOIP_ENABLED=1
    msg_ok "GeoIP ${GEOIP_MODE}: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}"
  fi
fi


echo -e "  ${YW}When enabled, WordPress/MariaDB/CrowdSec are pinned to the exact SHA256${CL}"
echo -e "  ${YW}digest resolved at install time, not just the floating tag. This${CL}"
echo -e "  ${YW}guarantees the bits that get audited/tested are the exact bits that${CL}"
echo -e "  ${YW}run — a registry silently repointing a tag can't change what's deployed.${CL}"
echo -e "  ${YW}Digests are resolved via Skopeo (a registry manifest query, a few KB —${CL}"
echo -e "  ${YW}no image is pulled just to check), so this stays cheap on every check.${CL}"
echo -e "  ${YW}update.sh re-pins on every update, and${CL}"
echo -e "  ${YW}'update.sh digest-check' can find and move to a newer digest published${CL}"
echo -e "  ${YW}under the SAME tag (e.g. a same-version security rebuild).${CL}"
read -rp "  Use SHA256 image digest pinning? [Y/n] : " PINNING_SEL
USE_DIGEST_PINNING=1
[[ "${PINNING_SEL:-Y}" =~ ^[Nn] ]] && USE_DIGEST_PINNING=0
if (( USE_DIGEST_PINNING )); then
  msg_ok "Digest pinning enabled — resolved during install via Skopeo (manifest query, not a full pull)"
else
  msg_warn "Digest pinning disabled — images run by floating tag only"
fi

echo ""
echo -e "  ${BLD}Vulnerability & compliance tooling (always installed)${CL}"
echo -e "  ${YW}Trivy  — scans every container image for known CVEs (HIGH/CRITICAL)${CL}"
echo -e "  ${YW}         before update.sh applies an update. Maintains a local cache${CL}"
echo -e "  ${YW}         at /var/cache/trivy so repeat scans take under 15 seconds.${CL}"
echo -e "  ${YW}         Run on demand:  update.sh trivy   |   wp-hardening.sh trivy-scan${CL}"
echo -e "  ${YW}Lynis  — audits the OS itself: SSH config, kernel hardening, file${CL}"
echo -e "  ${YW}         permissions, exposed services. Produces a 0-100 hardening${CL}"
echo -e "  ${YW}         index, useful as compliance evidence for MSP clients.${CL}"
echo -e "  ${YW}         Runs automatically every Saturday 05:00 UTC. Run on demand:${CL}"
echo -e "  ${YW}         wp-hardening.sh lynis${CL}"
echo -e "  ${YW}Both results are combined in one place:  wp-hardening.sh security-report${CL}"

echo ""
echo -e "  ${BLD}─── Summary ──────────────────────────────────────${CL}"
printf  "  %-18s %s\n"  "VM ID:"       "$VMID"
printf  "  %-18s %s\n"  "Hostname:"    "$HN"
printf  "  %-18s %s CPU · %s MB · %s\n" "Resources:"  "$CORES" "$RAM" "$DISK"
printf  "  %-18s Alpine %s (auto)\n"   "OS:"          "$ALPINE_VER"
printf  "  %-18s %s\n"  "SSH:"         "${ADMIN_USER} — $([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password')  (root SSH disabled)"
printf  "  %-18s nft SSH=%-15s  nft Web=%s\n"   "L1 Firewall:"  "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
printf  "  %-18s admin-cidr=%-18s  allowed-ip=%s\n" "L2 wp-admin:" "${ADMIN_CIDR:-none}" "${ALLOWED_ADMIN_IP:-none}"
printf  "  %-18s %s\n"  "Proxy IP:"    "${PROXY_IP:-direct (no proxy)}"
printf  "  %-18s %s\n"  "Admin slug:"  "${WP_ADMIN_SLUG:+/${WP_ADMIN_SLUG} (custom)}${WP_ADMIN_SLUG:-/wp-admin (default)}"
printf  "  %-18s %s\n"  "CS enrolment:" "${CROWDSEC_ENROLL_KEY:+key provided (auto-enrol)}${CROWDSEC_ENROLL_KEY:-manual (after install)}"
printf  "  %-18s WordPress + MariaDB (internal) + CrowdSec\n" "Containers:"
printf  "  %-18s %s\n"  "Network:"     "${NET_MODE}${VM_STATIC_IP:+ ($VM_STATIC_IP/$VM_PREFIX)}"
printf  "  %-18s %s\n"  "GeoIP:"       "$([[ $GEOIP_ENABLED -eq 1 ]] && echo "${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})" || echo 'disabled')"
printf  "  %-18s %s\n"  "Digest pinning:" "$([[ $USE_DIGEST_PINNING -eq 1 ]] && echo 'enabled (SHA256-pinned images)' || echo 'disabled (tag-only)')"
[[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]] && msg_warn "WEB_CIDR set + PROXY_IP set → ${PROXY_IP} auto-added to nftables so NPM can reach port 80/443"
[[ -n "$WEB_CIDR" && -z "$PROXY_IP" ]] && msg_warn "WEB_CIDR restricts port 80/443 to ${WEB_CIDR}. If NPM is on a different subnet, add its IP as PROXY_IP or re-run the script."
echo ""
read -rp "  Proceed? [Y/n] : " yn
[[ "${yn:-Y}" =~ ^[Yy] ]] || { echo "Aborted."; _DESTROY_VM=0; exit 0; }


# ── Storage type ──────────────────────────────────────────────────────────────
STYPE=$(pvesm status -storage "$STORAGE" 2>/dev/null | awk 'NR>1{print $2}')
case "$STYPE" in
  nfs|dir)  DISK_EXT=".qcow2"; DISK_REF="${VMID}/"; DISK_FMT="-format qcow2" ;;
  btrfs)    DISK_EXT=".raw";   DISK_REF="${VMID}/"; DISK_FMT="-format raw"   ;;
  *)        DISK_EXT="";       DISK_REF="";          DISK_FMT="-format raw"   ;;
esac
DISK0="vm-${VMID}-disk-0${DISK_EXT}"
DISK0_REF="${STORAGE}:${DISK_REF}${DISK0}"
case "$STYPE" in
  nfs|dir|btrfs) DISK_OPTS="${DISK0_REF},size=${DISK}"                 ;;
  *)             DISK_OPTS="${DISK0_REF},discard=on,ssd=1,size=${DISK}" ;;
esac

# ── Download + verify Alpine image ────────────────────────────────────────────
# BUG FIX (v7-5): added real integrity verification. Checked directly against
# the Alpine CDN: the cloud/ qcow2 images do NOT publish a .sha256 sidecar —
# only a .sha512 and a detached GPG .asc signature (their .iso releases do
# ship .sha256, but this is a different image type/directory). SHA-512 is a
# stronger hash than SHA-256 anyway, so this isn't a downgrade — it's simply
# what Alpine actually publishes for this file. The checksum is fetched fresh
# from the SAME directory as the image, matching the already auto-selected
# ${ALPINE_URL} exactly. Deliberately NOT hardcoded: this script's own image
# selection floats across point releases (3.24, 3.23, 3.22, 3.21, whichever
# has a build available), so a fixed hash would break on the very next Alpine
# point release. GPG verification of the .asc would add defense-in-depth
# against a compromised CDN, but requires pinning Alpine's rotating
# per-release signing key — left as a manual step rather than guessed at
# here (current fingerprint is posted at https://alpinelinux.org/downloads/
# if you want to add `gpg --verify` yourself).
_verify_alpine_sha512() {
  local img="$1" url="$2" sidecar_url expected actual
  sidecar_url="${url}.sha512"
  expected=$(curl -fsSL --max-time 10 "$sidecar_url" 2>/dev/null | awk '{print $1}')
  if [[ -z "$expected" || ! "$expected" =~ ^[0-9a-fA-F]{128}$ ]]; then
    msg_warn "Could not fetch a valid .sha512 for $(basename "$img") — skipping integrity check"
    msg_warn "  (provisioning continues, but this download was not verified)"
    return 0
  fi
  actual=$(sha512sum "$img" | awk '{print $1}')
  if [[ "$actual" == "$expected" ]]; then
    msg_ok "SHA512 verified: $(basename "$img")"
  else
    rm -f "$img"
    msg_error "SHA512 MISMATCH for $(basename "$img") — refusing to use this image (deleted).
    Expected: ${expected}
    Got:      ${actual}
    Re-run to re-download, or investigate your network (captive portal / MITM proxy)."
  fi
}

# ── Download Alpine image ─────────────────────────────────────────────────────
mkdir -p "$IMG_CACHE"
if [[ -f "$IMG_FILE" ]]; then
  msg_ok "Cached: $(basename "$IMG_FILE")"
else
  msg_info "Downloading Alpine ${ALPINE_VER}…"
  curl -fL --progress-bar -o "$IMG_FILE" "$ALPINE_URL" \
    || { rm -f "$IMG_FILE"; msg_error "Download failed."; }
  msg_ok "Downloaded"
fi
if command -v sha512sum &>/dev/null; then
  _verify_alpine_sha512 "$IMG_FILE" "$ALPINE_URL"
else
  msg_warn "sha512sum not found on this host — skipping Alpine image integrity check"
fi
WORK_IMG="/tmp/wp-vm-${VMID}-alpine.qcow2"
cp "$IMG_FILE" "$WORK_IMG"
qemu-img resize "$WORK_IMG" "$DISK" >/dev/null
msg_ok "Working image ready (${DISK})"

# ── Build nftables ruleset (host-side substitution) ───────────────────────────
# WEB_CONTAINER_PORT is what the *filter* chain must match. Rootful Podman
# always publishes -p 80:80, so this is fixed at 80.
WEB_CONTAINER_PORT=80

if [[ -n "$SSH_CIDR" ]]; then
  SSH_RULE="ip saddr ${SSH_CIDR} tcp dport 22"
else
  SSH_RULE="tcp dport 22"
fi
if [[ -n "$WEB_CIDR" && -n "$PROXY_IP" ]]; then
  # Both set: allow local CIDR AND the reverse proxy IP.
  # Critical for NPM setups — without this, nftables blocks the proxy's requests
  # to port 80 even though mod_remoteip would correctly identify the real client.
  WEB_RULE="ip saddr { ${WEB_CIDR}, ${PROXY_IP} } tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
elif [[ -n "$WEB_CIDR" ]]; then
  WEB_RULE="ip saddr ${WEB_CIDR} tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
else
  WEB_RULE="tcp dport { ${WEB_CONTAINER_PORT}, 443 }"
fi

NFT_CONF=$(cat << NFTEOF
#!/usr/sbin/nft -f
# nftables — generated by create-wordpress-vm.sh
# MariaDB (3306) is NOT here — isolated inside Podman wp-db (10.89.20.0/24,
# --internal — no route out regardless of this ruleset).
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        icmp  type echo-request limit rate 5/second accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
        # SSH: CrowdSec (crowdsecurity/sshd) handles brute-force banning
        ${SSH_RULE} ct state new limit rate 10/minute accept
        # HTTP/HTTPS: CrowdSec (crowdsecurity/apache2 + crowdsecurity/wordpress
        # + crowdsecurity/http-cve) handles application-layer banning.
        # wp-admin/wp-login IP restriction is enforced at Apache level (Layer 2).
        ${WEB_RULE} accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
        # Allow Podman container traffic on both application networks.
        # FIX: without these rules the nftables DROP policy prevents containers
        # from reaching the internet even after netavark sets up NAT — because
        # nftables and iptables both operate on the FORWARD netfilter hook, and
        # nftables DROP is evaluated regardless of iptables ACCEPT rules.
        # Allowing only the known subnets keeps the forward chain tight.
        ct state established,related accept
        ct state invalid drop
        # wp-front (10.89.10.0/24): WordPress's egress + published-port network.
        ip saddr 10.89.10.0/24 accept
        ip daddr 10.89.10.0/24 accept
        # wp-db (10.89.20.0/24, --internal): WordPress<->MariaDB traffic only.
        # netavark never routes an --internal network to the internet, so this
        # rule cannot grant MariaDB egress — it only permits the local
        # container-to-container path.
        ip saddr 10.89.20.0/24 accept
        ip daddr 10.89.20.0/24 accept
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
NFTEOF
)

# ── Build Apache security config (host-side — CIDRs baked in here) ────────────
# Built on the host where ADMIN_CIDR, ALLOWED_ADMIN_IP, and PROXY_IP are known.
# Written to /root/wp-security.conf on the VM disk and copied by the installer.
# This avoids any runtime variable substitution inside the VM.

# Build wp-admin Require block
REQUIRE_ADMIN=""
if [[ -n "$ADMIN_CIDR" || -n "$ALLOWED_ADMIN_IP" ]]; then
  [[ -n "$ADMIN_CIDR" ]]       && REQUIRE_ADMIN+=$'\n'"    Require ip ${ADMIN_CIDR}"
  [[ -n "$ALLOWED_ADMIN_IP" ]] && REQUIRE_ADMIN+=$'\n'"    Require ip ${ALLOWED_ADMIN_IP}"
fi

# Build wp-admin block strings (empty = no restriction added)
if [[ -n "$REQUIRE_ADMIN" ]]; then
  WP_ADMIN_BLOCK=$(cat << ADMINBLOCK
# wp-admin and wp-login.php are restricted to the IPs below.
# Access from any other source receives HTTP 403 Forbidden.
# Local network CIDR : ${ADMIN_CIDR:-not set}
# Allowed extra IP   : ${ALLOWED_ADMIN_IP:-not set}
# Proxy IP (trusted) : ${PROXY_IP:-direct — no proxy}
#
# PROXY BEHAVIOUR: If this VM is behind NPM or another reverse proxy,
# Apache sees the proxy IP as the source, not the real client IP.
# mod_remoteip (below) corrects this by trusting the proxy's
# X-Forwarded-For header — so Require ip checks the REAL client IP.
<DirectoryMatch "^/var/www/html/wp-admin">
${REQUIRE_ADMIN}
</DirectoryMatch>

<Files "wp-login.php">
${REQUIRE_ADMIN}
</Files>
ADMINBLOCK
)
else
  WP_ADMIN_BLOCK="# wp-admin: no IP restriction configured (open to any source IP)."$'\n'"# Re-run with ADMIN_CIDR set, or edit this file and restart the container."
fi

# Build mod_remoteip block (only if PROXY_IP was set)
if [[ -n "$PROXY_IP" ]]; then
  REMOTEIP_BLOCK=$(cat << RIBLOCK
# mod_remoteip — loaded because a reverse proxy IP was specified.
# Tells Apache to trust X-Forwarded-For from ${PROXY_IP} only.
# Other sources' X-Forwarded-For headers are ignored (prevents IP spoofing).
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy ${PROXY_IP}
RIBLOCK
)
else
  REMOTEIP_BLOCK="# mod_remoteip not loaded (direct access — no proxy IP specified)."$'\n'"# If you add a reverse proxy later, set RemoteIPTrustedProxy here and"$'\n'"# LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so"
fi

# ── Build custom admin slug Apache block ──────────────────────────────────────
if [[ -n "$WP_ADMIN_SLUG" ]]; then
  # FIX: The previous version used <If "%%{THE_REQUEST} =~ ..."> which caused
  # Apache to crash with "Cannot parse condition clause: Parse error near '%'".
  # Root cause: %%{THE_REQUEST} is two literal percent signs (not a printf
  # escape in a bash heredoc) — Apache's ap_expr parser rejects it.
  #
  # NEW APPROACH: remove <If> entirely. The URL mapping is done by RewriteRule
  # only. Access control (who may USE wp-admin) is handled by the REQUIRE_ADMIN
  # Require ip block below — which already fires when WordPress serves the
  # rewritten /wp-admin/ response. No conditional logic needed here at all.
  # This is simpler, avoids the parser issue, and works correctly with Divi.
  #
  # BUG FIX (v7-5) — THE SLUG NEVER ACTUALLY FIRED: this block used to be
  # emitted bare in wp-security.conf, which loads via conf-enabled/*.conf —
  # processed by Debian's apache2.conf in MAIN SERVER context, BEFORE
  # sites-enabled/000-default.conf defines the <VirtualHost> that actually
  # serves every request. mod_rewrite has a documented, mod_rewrite-specific
  # exception to Apache's normal config inheritance: RewriteEngine/RewriteRule
  # set in main-server scope are NOT inherited by a <VirtualHost> unless that
  # vhost explicitly sets `RewriteOptions Inherit` (it doesn't, since it's the
  # stock Debian-packaged vhost from the apache2 package). So the slug's own
  # RewriteRules were silently never evaluated for real requests — 100% dead
  # config, no error, no log line, nothing.
  # FIX: the calling code now places this block INSIDE the existing
  # <Directory /var/www/html> container (see APACHE_SECURITY_CONF below)
  # instead of bare in server scope. Per-directory context (<Directory>,
  # <Files>, .htaccess) is NOT subject to the inheritance restriction above —
  # it's the exact same rewrite phase that already makes WordPress's own
  # .htaccess permalinks and the 8G Firewall .htaccess rules work correctly
  # today. Per-directory pattern matching is also RELATIVE to the directory
  # (no leading "/"), the same convention WordPress's own .htaccess uses
  # (`RewriteRule ^index\.php$ ...`, not `^/index\.php$`) — so the leading
  # "/" added by the old v7-1 fix (needed back when this ran in server
  # context) is now removed from the pattern side; the substitution side
  # keeps its leading "/" (an absolute path from the document root), same as
  # WordPress core's own `RewriteRule . /index.php [L]`.
  SLUG_BLOCK=$(cat << SLUGEOF
    # ── Custom wp-admin slug ────────────────────────────────────────────────
    # Slug: /${WP_ADMIN_SLUG}
    # How it works:
    #   Requests to /${WP_ADMIN_SLUG}/, /${WP_ADMIN_SLUG}/anything.php, etc. are
    #   rewritten internally to the matching literal file under /wp-admin/.
    #   Requests to /${WP_ADMIN_SLUG}-login  → rewritten to /wp-login.php  (internally)
    #   Direct access to /wp-admin/ and /wp-login.php is then controlled
    #   by the Require ip block below — bots hitting the default paths
    #   get 403 if they are not on the allowed ADMIN_CIDR.
    # Divi Visual Builder uses /wp-admin/admin-ajax.php from authenticated sessions,
    # which follow the session cookie — not the URL slug — so it is unaffected.
    # Targeting literal files (index.php, wp-login.php, and whatever file a
    # wp-admin sub-path already names, e.g. post.php, admin-ajax.php) avoids
    # Apache's fragile directory/trailing-slash resolution on an internally
    # rewritten directory target — every RewriteRule target below is a real file.
    <IfModule mod_rewrite.c>
      RewriteEngine On
      RewriteRule ^${WP_ADMIN_SLUG}/?$ /wp-admin/index.php [L,QSA]
      RewriteRule ^${WP_ADMIN_SLUG}/(.+)$ /wp-admin/\$1 [L,QSA]
      RewriteRule ^${WP_ADMIN_SLUG}-login/?$ /wp-login.php [L,QSA]
    </IfModule>
SLUGEOF
)
else
  SLUG_BLOCK=""
fi

APACHE_SECURITY_CONF=$(cat << APACHEEOF
# ============================================================
# WordPress Apache Security Configuration
# Generated by create-wordpress-vm.sh — do not edit by hand.
# Re-generate by re-running the provisioning script.
# Loaded via bind-mount: /etc/apache2/conf-enabled/wp-security.conf
# ============================================================

${REMOTEIP_BLOCK}

# Hide Apache and OS versions from HTTP headers and error pages.
ServerTokens Prod
ServerSignature Off

# File-based access log for CrowdSec.
# The bind-mount at /var/log/apache2 hides Docker's default stdout symlinks,
# so Apache creates real files here that CrowdSec reads from the host.
CustomLog /var/log/apache2/access.log combined

# BUG FIX (v7-6e): dual-IP diagnostic log, added alongside — not instead of —
# the access.log above. mod_remoteip rewrites %h/%a to the X-Forwarded-For-
# derived "logical" client once a trusted proxy is configured, which is
# exactly what CrowdSec's apache2 collection needs for correct IP-based
# banning — so access.log's format is deliberately left untouched here.
# Prepending or appending a field to it instead would risk either breaking
# CrowdSec's grok parser outright, or worse, silently rebinding every ban to
# the reverse proxy's own IP instead of the real visitor (the exact failure
# this script has already fixed once via mod_remoteip in the first place).
# This second log captures both IPs side by side purely for verification:
# %{c}a is the raw connection peer (the proxy's own IP, if any), %a is the
# post-substitution address. If a trusted proxy is configured and these two
# never differ, RemoteIPTrustedProxy doesn't match the real proxy source —
# a silent misconfiguration that would otherwise be invisible.
LogFormat "%t peer=%{c}a interpreted=%a \"%r\" %>s" wp_remoteip_debug
CustomLog /var/log/apache2/remoteip-debug.log wp_remoteip_debug

${WP_ADMIN_BLOCK}

# Suppress "Could not reliably determine the server's fully qualified domain name"
# (Apache warning AH00558). ServerName must be set — use the container hostname.
ServerName wordpress

# Disable directory listing and enable symlink following.
# BUG FIX (v7-5): the custom wp-admin slug and the author=N enumeration block
# both live INSIDE this <Directory> container now, not bare in server/global
# scope — see the long explanation above SLUG_BLOCK's generation on the host
# side. Short version: mod_rewrite rules bare in conf-enabled/*.conf run in
# main-server context and are never inherited by the <VirtualHost> that
# actually serves requests, so they silently never fired. Per-directory
# context (this container, same phase as .htaccess) does not have that
# restriction.
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride All

${SLUG_BLOCK}

    # Block ?author=N user enumeration. Attackers use this to harvest
    # WordPress usernames for targeted brute-force campaigns.
    # BUG FIX (v7-5): moved from bare server scope (never fired — see note
    # above) into this per-directory context.
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteCond %{QUERY_STRING} author=
        RewriteRule ^ - [F,L]
    </IfModule>
</Directory>

# Block PHP execution in wp-content/uploads.
# Prevents a successfully uploaded webshell from being executed —
# the highest-impact single PHP restriction for WordPress security.
<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>

# Block access to sensitive files that must never be served via HTTP.
<FilesMatch "(wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>

# Block backup and script files
<FilesMatch "\.(bak|orig|sql|log|sh|swp|save)$">
    Require all denied
</FilesMatch>

# Block wp-config backup patterns (some tools write these)
<FilesMatch "wp-config.*\.(php|txt|bak)$">
    Require all denied
</FilesMatch>

# Block WordPress debug log — written to /var/www/html/ when WP_DEBUG_LOG=true.
# Even though WP_DEBUG=false in our config, block it in case a plugin enables it.
<Files "debug.log">
    Require all denied
</Files>

# Block XML-RPC — common attack vector for brute-force and pingback DDoS.
# Remove this block only if a plugin explicitly requires XML-RPC (e.g. Jetpack).
<Files "xmlrpc.php">
    Require all denied
</Files>

# Security headers
Header always set X-Content-Type-Options  "nosniff"
Header always set X-Frame-Options         "SAMEORIGIN"
Header always set Referrer-Policy         "strict-origin-when-cross-origin"
Header always unset X-Powered-By
# Content-Security-Policy — 'unsafe-inline' and 'unsafe-eval' are required
# by WordPress admin panels (inline JS/CSS is core to WP admin UX).
# Tighten these on the front-end only if your theme does not use inline scripts.
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
APACHEEOF
)
msg_ok "Apache security config built (wp-admin: ${ADMIN_CIDR:-open}, extra-ip: ${ALLOWED_ADMIN_IP:-none}, proxy: ${PROXY_IP:-none}, slug: ${WP_ADMIN_SLUG:-default})"

# ── Build the installer ───────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)

cat > "${TMPDIR}/install-wordpress.sh" << 'INSTALLER_EOF'
#!/bin/sh
# WordPress installer — runs via /etc/local.d on every boot until complete.
# Self-bootstraps bash. Two stages: 1=kernel switch, 2=containers.

if [ -z "${BASH_VERSION:-}" ]; then
  apk add --no-cache bash >/dev/null 2>&1 \
    || { echo "FATAL: apk failed — networking up?"; exit 1; }
  exec bash "$0" "$@"; exit 1
fi

set -e
LOG=/var/log/wp-install.log
exec >> "$LOG" 2>&1

ts()   { echo; echo "=== [$(date '+%H:%M:%S')] $* ==="; }
ok()   { echo "  ✔  $*"; }
warn() { echo "  ⚠  $*"; }

# ── Pinned image versions ─────────────────────────────────────────────────────
# BUG FIX: mariadb:11.4-lts does NOT exist on Docker Hub.
# Correct tags: mariadb:11.4 (branch), mariadb:lts (always current LTS).
# wordpress:6.7.2-php8.3-apache (full semver) is more stable than 6.7.
WP_IMAGE="docker.io/wordpress:6.9.4-php8.3-apache"
DB_IMAGE="docker.io/mariadb:11.4"
# BUG FIX (v7-5): v1.7.6 → v1.7.8. v1.7.8 (2026-05-11) is a security release
# patching CVE-2026-44982 (a HIGH-impact partial WAF bypass in the AppSec
# datasource — chunked-encoding/HTTP2-no-Content-Length requests were
# evaluated against an empty body, silently bypassing any WAF rule targeting
# body content; this directly affects the crowdsecurity/appsec-wordpress
# collection this script enables) and CVE-2026-44981 (a LAPI DoS via
# unbounded gzip decompression — lower impact here since LAPI is bound to
# 127.0.0.1 only, but still worth the patch).
CROWDSEC_IMAGE="docker.io/crowdsecurity/crowdsec:v1.7.8"

STAGE_FILE=/var/lib/wp-install-stage
STAGE=$(cat "$STAGE_FILE" 2>/dev/null || echo 1)

echo "=================================================="
echo "  WordPress Installer — $(date)  [stage ${STAGE}]"
echo "  Alpine $(cat /etc/alpine-release 2>/dev/null)  Kernel $(uname -r)"
echo "  WordPress : ${WP_IMAGE}"
echo "  MariaDB   : ${DB_IMAGE}"
echo "  CrowdSec  : ${CROWDSEC_IMAGE}"
echo "=================================================="

# ════════════════════════════════════════════════════════════════════════════
# STAGE 1 — filesystem, updates, kernel switch
# ════════════════════════════════════════════════════════════════════════════
if [ "$STAGE" = "1" ]; then

  ts "Expanding root filesystem"
  apk add --no-cache e2fsprogs >/dev/null 2>&1 || true
  ROOT_DEV=$(df / | awk 'NR==2{print $1}')
  resize2fs "$ROOT_DEV" 2>/dev/null && ok "$(df -h / | awk 'NR==2{print $2}') total" \
    || ok "Already at full size"

  ts "Updating Alpine"
  VER=$(cut -d. -f1,2 /etc/alpine-release)
  cat > /etc/apk/repositories << REPOS
https://dl-cdn.alpinelinux.org/alpine/v${VER}/main
https://dl-cdn.alpinelinux.org/alpine/v${VER}/community
REPOS
  apk update  >/dev/null 2>&1
  apk upgrade --no-cache >/dev/null 2>&1
  ok "Alpine ${VER} up to date"

  ts "Enabling nightly security updates (crond)"
  apk add --no-cache busybox-openrc >/dev/null 2>&1 || true
  rc-update add crond default 2>/dev/null || true
  rc-service crond start 2>/dev/null || true
  echo "0 3 * * * apk update -q && apk upgrade --no-cache -q && logger -t alpine-autoupdate done" \
    >> /etc/crontabs/root
  ok "Nightly apk upgrade @ 03:00 UTC"

  ts "QEMU Guest Agent"
  apk add --no-cache qemu-guest-agent >/dev/null
  rc-update add qemu-guest-agent default 2>/dev/null || true
  rc-service qemu-guest-agent start      2>/dev/null || true
  ok "Agent running"

  ts "Admin account doas (redundant safety net)"
  # The admin account, its wheel-group membership, and doas.conf normally
  # already exist by this point — created host-side before first boot in
  # create-wordpress-vm.sh's pre-boot chroot (see ADMIN_USER_CREATED in
  # /etc/wp-install/vars.sh). That chroot only needs local filesystem
  # writes for the account/group itself, so it's virtually guaranteed to
  # succeed regardless of network — but installing the `doas` PACKAGE from
  # that same chroot did depend on the PROXMOX HOST reaching Alpine's CDN
  # at provisioning time. This VM now has its own real networking (Stage 1
  # already ran a full apk update/upgrade above), so retry here — cheap,
  # fully idempotent, and closes the one plausible network-dependent gap
  # in an otherwise network-independent setup.
  command -v doas >/dev/null 2>&1 || apk add --no-cache doas >/dev/null 2>&1 || true
  if command -v doas >/dev/null 2>&1; then
    ok "doas present"
  else
    warn "doas still unavailable — install manually: apk add doas"
  fi

  ts "Clock sync"
  apk add --no-cache chrony >/dev/null
  for s in pool.ntp.org time.cloudflare.com time.google.com; do
    chronyd -q "server $s iburst maxsamples 4" >/dev/null 2>&1 && break || true
  done
  hwclock --systohc 2>/dev/null || true
  rc-update add chronyd default 2>/dev/null || true
  rc-service chronyd start      2>/dev/null || true
  ok "$(date '+%Y-%m-%d %H:%M:%S %Z')"

  ts "Kernel check — switching to linux-lts if needed"
  CURRENT_FLAVOR=$(uname -r | grep -oE '[a-z]+$')
  KERNEL_SWITCH_OK=0
  if [ "$CURRENT_FLAVOR" = "lts" ]; then
    ok "Already linux-lts ($(uname -r))"
  else
    warn "Running linux-${CURRENT_FLAVOR} — installing linux-lts"
    apk add --no-cache linux-lts >/dev/null 2>&1 || warn "linux-lts install failed"
    if [ -f /boot/vmlinuz-lts ]; then
      apk add --no-cache syslinux >/dev/null 2>&1 || true
      if [ -f /etc/update-extlinux.conf ]; then
        grep -qE '^[# ]*default=' /etc/update-extlinux.conf \
          && sed -i -E 's|^[# ]*default=.*|default=lts|' /etc/update-extlinux.conf \
          || echo 'default=lts' >> /etc/update-extlinux.conf
        update-extlinux 2>&1 | sed 's/^/    /'
        grep -q 'vmlinuz-lts' /boot/extlinux.conf 2>/dev/null \
          && { ok "Bootloader → linux-lts"; KERNEL_SWITCH_OK=1; } \
          || warn "extlinux.conf has no vmlinuz-lts — staying on current kernel"
      else
        warn "/etc/update-extlinux.conf not found"
      fi
    else
      warn "/boot/vmlinuz-lts missing after install"
    fi
  fi

  echo 2 > "$STAGE_FILE"
  if [ "$KERNEL_SWITCH_OK" = "1" ]; then
    ts "Rebooting into linux-lts"
    sync; sleep 2; reboot; exit 0
  fi
fi

# ════════════════════════════════════════════════════════════════════════════
# STAGE 2 — Podman, MariaDB, WordPress, CrowdSec
# ════════════════════════════════════════════════════════════════════════════
ts "Stage 2 — kernel: $(uname -r)"

# ── Source installer variables (slug, CS key, GeoIP, network) ────────────────
# These were injected at provisioning time into /etc/wp-install/vars.sh
# because the INSTALLER_EOF heredoc is single-quoted (no host var expansion).
if [ -f /etc/wp-install/vars.sh ]; then
  . /etc/wp-install/vars.sh
  ok "Installer vars loaded: slug=${WP_ADMIN_SLUG:-default}, cs-enroll=${CROWDSEC_ENROLL_KEY:+provided}, net=${NET_MODE:-dhcp}, geoip=${GEOIP_ENABLED:-0}"
else
  WP_ADMIN_SLUG=""
  CROWDSEC_ENROLL_KEY=""
  NET_MODE="dhcp"
  VM_STATIC_IP=""
  GEOIP_ENABLED="0"
  GEOIP_MODE=""
  GEOIP_WHITELIST=""
  GEOIP_BLOCKLIST=""
  MAXMIND_ACCOUNT_ID=""
  MAXMIND_LICENSE_KEY=""
  ADMIN_USER=""
  ADMIN_USER_CREATED="0"
  warn "/etc/wp-install/vars.sh not found — new features default off"
fi
# Defensive defaults in case vars.sh exists but is missing newer keys
# (e.g. a VM re-provisioned from an older version of this script's injection)
GEOIP_ENABLED="${GEOIP_ENABLED:-0}"
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_USER_CREATED="${ADMIN_USER_CREATED:-0}"

# ── PRUN: podman dispatch wrapper ─────────────────────────────────────────────
# BUG FIX (v7-6d): PRUN used to have a rootless branch that rebuilt the whole
# command as a single string — su -s /bin/sh wpuser -c "podman $*" — and "$*"
# joins every argument on IFS, discarding the argument boundaries "$@" would
# have preserved. That string was then RE-PARSED by the inner `sh -c`, so any
# argument containing shell metacharacters (spaces, quotes, ;, $()) got
# reinterpreted instead of passed through intact — exactly what happens to
# WORDPRESS_CONFIG_EXTRA's 'define("WP_DEBUG",false);define(...);...' value.
# Now that this script is rootful-only, that dispatch — and the vulnerable
# reconstruction it required — is gone. PRUN is kept as a thin wrapper (so
# every "PRUN <cmd>" call site elsewhere in this installer, update.sh,
# wp-hardening.sh, and validate-wordpress.sh needs no changes), but it now
# ALWAYS calls podman directly with "$@", which preserves argument
# boundaries exactly.
PRUN() {
  podman "$@"
}

# ── wp-health-check.sh — real WordPress health validation ────────────────────
# BUG FIX (v7-6g, item #6 from the 7-6f review): every prior "is WordPress
# ready?" gate in this script (initial install, GeoIP rebuild, and
# update.sh's rollback decision) was a bare `wget -qO- http://127.0.0.1/`
# treating any non-500 HTTP response as success. That proves Apache answered
# a socket — nothing more. It happily passes on "Error establishing a
# database connection", a PHP fatal-error page, a WordPress maintenance
# page, a partially initialized site, or the Apache default page — every one
# of which returns 200/302 while WordPress itself is broken. This is
# especially dangerous in update.sh's do_wp_update(): a health check that
# lies "healthy" is exactly the case that skips rollback and leaves a broken
# site live.
#
# Installed once, here, before MariaDB/WordPress ever start, so it's
# available to every later health-check call site in this file (initial
# install, wp-geoip-setup.sh, and update.sh) without duplicating the logic
# three times and letting the copies drift.
#
# Checks, in order, each independently gating pass/fail:
#   1. HTTP response      — sanity check only; proves a socket answers.
#   2. PHP execution      — proves PHP itself runs inside the container,
#                            not just that Apache is up.
#   3. MariaDB DNS         — `getent hosts mariadb` proves Aardvark DNS /
#                            the wp-db network path resolves the hostname,
#                            independent of credentials.
#   4+5. MariaDB auth + real WordPress DB query — one PHP mysqli call using
#        WordPress's own WORDPRESS_DB_HOST/USER/PASSWORD/NAME env vars (the
#        exact values Apache/PHP itself uses) that opens a connection AND
#        runs `SELECT 1`. This is the check that actually proves "WordPress
#        can talk to its database", not just "MariaDB's TCP port is open".
# Recent container logs are also grepped for fatal/uncaught/segfault/
# permission-denied lines and printed for a human to review — informational
# only, since some of these can be transient noise during first boot, so it
# never gates pass/fail on its own.
ts "Installing wp-health-check.sh (real health validation, not just HTTP)"
cat > /usr/local/bin/wp-health-check.sh << 'HEALTHEOF'
#!/bin/sh
# wp-health-check.sh — proves WordPress is actually functional, not just
# that Apache answers a socket. See the long comment above this heredoc in
# create-wordpress-vm.sh for the full rationale.
# Usage: wp-health-check.sh [container_name] [http_port]
# Exit 0 = all critical checks passed. Exit 1 = one or more failed.
CONTAINER="${1:-wordpress}"
HTTP_PORT="${2:-80}"
FAIL=0

_pass() { echo "  ✔  $*"; }
_fail() { echo "  ✗  $*" >&2; FAIL=1; }

# 1) HTTP response — sanity check only, proves nothing about WordPress
# itself (a DB-error page or PHP fatal page can still answer 200/302).
HTTP_CODE=$(wget -S -O /dev/null "http://127.0.0.1:${HTTP_PORT}/" 2>&1 \
  | awk '/HTTP\// {print $2}' | tail -1)
if [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "500" ] && [ "$HTTP_CODE" != "000" ]; then
  _pass "HTTP response: ${HTTP_CODE}"
else
  _fail "HTTP response: ${HTTP_CODE:-none}"
fi

# 2) PHP actually executes inside the container.
PHP_OK=$(podman exec "$CONTAINER" php -r 'echo "ok";' 2>/dev/null)
if [ "$PHP_OK" = "ok" ]; then
  _pass "PHP executes"
else
  _fail "PHP did not execute inside ${CONTAINER}"
fi

# 3) MariaDB name resolution via Aardvark DNS — proves the wp-db network
# path is up, independent of credentials.
if podman exec "$CONTAINER" getent hosts mariadb >/dev/null 2>&1; then
  _pass "mariadb hostname resolves"
else
  _fail "mariadb hostname does not resolve (Aardvark DNS / wp-db network issue)"
fi

# 4+5) MariaDB authentication AND a real WordPress DB query — using
# WordPress's own WORDPRESS_DB_* env vars (the exact values Apache/PHP
# itself uses), proving both that MariaDB accepts these credentials and
# that a real query succeeds — not just that a TCP socket opens.
DB_CHECK=$(podman exec "$CONTAINER" php -r '
$host = getenv("WORDPRESS_DB_HOST");
$user = getenv("WORDPRESS_DB_USER");
$pass = getenv("WORDPRESS_DB_PASSWORD");
$name = getenv("WORDPRESS_DB_NAME");
$db = @new mysqli($host, $user, $pass, $name);
if ($db->connect_errno) {
    fwrite(STDERR, $db->connect_error . PHP_EOL);
    echo "connect_fail";
    exit(0);
}
$result = $db->query("SELECT 1");
echo $result ? "ok" : "query_fail";
' 2>/dev/null)
case "$DB_CHECK" in
  ok) _pass "MariaDB auth + WordPress DB query (SELECT 1)" ;;
  connect_fail) _fail "MariaDB connection failed (auth/DNS/credentials) — see: podman logs ${CONTAINER}" ;;
  query_fail) _fail "MariaDB connected but SELECT 1 failed" ;;
  *) _fail "DB check did not run (PHP/mysqli unavailable in ${CONTAINER}?)" ;;
esac

# Informational only — recent fatal/uncaught/segfault/permission lines from
# the container's own logs, surfaced for a human. Never gates pass/fail by
# itself: some of these can be transient noise during first boot (e.g. a
# plugin autoloader race), and the checks above are what actually decide
# health.
RECENT_ERRORS=$(podman logs --since 2m "$CONTAINER" 2>&1 \
  | grep -Ei 'fatal|uncaught|segmentation|permission denied' | tail -5)
if [ -n "$RECENT_ERRORS" ]; then
  echo "  ⚠  Recent log lines worth reviewing (informational, not fatal):"
  echo "$RECENT_ERRORS" | sed 's/^/       /'
fi

if [ "$FAIL" = "0" ]; then
  echo "  ✔  WordPress health: ALL CRITICAL CHECKS PASSED"
  exit 0
fi
echo "  ✗  WordPress health: ONE OR MORE CRITICAL CHECKS FAILED"
exit 1
HEALTHEOF
chmod +x /usr/local/bin/wp-health-check.sh
ok "wp-health-check.sh installed — HTTP + PHP + DB-DNS + DB-auth + real query"
ok "  Manual use: wp-health-check.sh [container] [port]"

# ── mariadb-health-check.sh — real MariaDB health validation ─────────────────
# PRODUCTION SAFETY FIX (v7-6k, "Strengthen service health checks" from the
# 7-6f review): wp-health-check.sh (above) closed this gap for WordPress,
# but every MariaDB readiness gate in this script — the wait loop just
# below (before either container even exists yet) AND update.sh's
# do_db_update() rollback decision — was still a bare
# `mariadbd-admin ping`. A ping only proves the server accepts a TCP
# connection and that ROOT authenticates; it proves nothing about InnoDB
# actually being usable, and nothing about whether WordPress's OWN
# database/user (MARIADB_DATABASE/MARIADB_USER, not root) can run a query.
# That is the identical blind spot the old `wget -qO-` WordPress check had
# — a shallow protocol-level success coexisting with a broken
# application-level path (see the long comment above the wp-health-check.sh
# heredoc). It matters most inside do_db_update(): DB_READY there directly
# decides whether the new MariaDB container is kept or rolled back to
# mariadb-old, and at that point in the update WordPress is deliberately
# stopped, so wp-health-check.sh — which needs a running WordPress
# container to test through — cannot be used to validate the new database.
# A MariaDB-only check is the only way to test it there.
#
# Installed once, here, before either container starts, so it's available
# to every later call site (the wait loop just below, and update.sh)
# without duplicating the query logic and letting copies drift.
ts "Installing mariadb-health-check.sh (real health validation, not just ping)"
cat > /usr/local/bin/mariadb-health-check.sh << 'DBHEALTHEOF'
#!/bin/sh
# mariadb-health-check.sh — proves MariaDB is actually functional, not just
# that mariadbd-admin ping succeeds. See the long comment above this
# heredoc in create-wordpress-vm.sh for the full rationale.
# Usage: mariadb-health-check.sh [container_name]
# Exit 0 = all critical checks passed. Exit 1 = one or more failed.
CONTAINER="${1:-mariadb}"
FAIL=0

_pass() { echo "  ✔  $*"; }
_fail() { echo "  ✗  $*" >&2; FAIL=1; }

# 1) Root ping — sanity check only. Proves the server accepts TCP and root
# authenticates; proves nothing about InnoDB or WordPress's own grants.
if podman exec "$CONTAINER" sh -c \
     'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
      mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null' \
     >/dev/null 2>&1; then
  _pass "root ping"
else
  _fail "root ping failed"
fi

# 2) A real query as root — proves the SQL engine itself answers, not just
# that the ping protocol handshake succeeds (ping and query are different
# code paths inside mariadbd).
ROOT_QUERY=$(podman exec "$CONTAINER" sh -c \
  'mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" -N -e "SELECT 1;" 2>/dev/null ||
   mysql   -uroot -p"${MARIADB_ROOT_PASSWORD}" -N -e "SELECT 1;" 2>/dev/null')
if [ "$ROOT_QUERY" = "1" ]; then
  _pass "root SELECT 1"
else
  _fail "root SELECT 1 did not return 1 (got: '${ROOT_QUERY}')"
fi

# 3) The EXACT credentials WordPress itself uses — MARIADB_USER/PASSWORD/
# DATABASE come from the same /etc/wordpress/env file mounted into both the
# mariadb and wordpress containers, so this is the identical database,
# user, and password WORDPRESS_DB_* resolves to on the WordPress side. A
# root-only check can report healthy while WordPress's own grants are
# broken (e.g. a botched restore, a user dropped by an errant migration) —
# proving root works is not the same as proving WordPress can log in.
WP_QUERY=$(podman exec "$CONTAINER" sh -c \
  'mariadb -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" "${MARIADB_DATABASE}" -N -e "SELECT 1;" 2>/dev/null ||
   mysql   -u"${MARIADB_USER}" -p"${MARIADB_PASSWORD}" "${MARIADB_DATABASE}" -N -e "SELECT 1;" 2>/dev/null')
if [ "$WP_QUERY" = "1" ]; then
  _pass "wordpress-user SELECT 1 (same credentials WordPress itself uses)"
else
  _fail "wordpress-user SELECT 1 failed — WordPress's own DB user/grants may be broken"
fi

# 4) InnoDB actually initialized — read directly via the same healthcheck.sh
# shipped in the official MariaDB image and already used as this
# container's own --health-cmd, but invoked here directly rather than
# trusting Podman's health-check timer: this script's own install-time
# comments already document that timer as unreliable on Alpine (no
# systemd/conmon poller to drive it — .State.Health.Status can sit on
# "starting" forever even once MariaDB is fully usable).
if podman exec "$CONTAINER" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then
  _pass "InnoDB initialized"
else
  _fail "InnoDB not confirmed initialized (healthcheck.sh --innodb_initialized)"
fi

# Informational only — recent error/corruption-flavoured log lines, surfaced
# for a human. Never gates pass/fail by itself, same rationale as
# wp-health-check.sh's own log scan: some of these can be transient noise
# (e.g. a single retried connection during startup), and the checks above
# are what actually decide health.
RECENT_ERRORS=$(podman logs --since 2m "$CONTAINER" 2>&1 \
  | grep -Ei 'error|corrupt|assertion|crashed' | tail -5)
if [ -n "$RECENT_ERRORS" ]; then
  echo "  ⚠  Recent log lines worth reviewing (informational, not fatal):"
  echo "$RECENT_ERRORS" | sed 's/^/       /'
fi

if [ "$FAIL" = "0" ]; then
  echo "  ✔  MariaDB health: ALL CRITICAL CHECKS PASSED"
  exit 0
fi
echo "  ✗  MariaDB health: ONE OR MORE CRITICAL CHECKS FAILED"
exit 1
DBHEALTHEOF
chmod +x /usr/local/bin/mariadb-health-check.sh
ok "mariadb-health-check.sh installed — ping + root query + wpdb query + InnoDB"
ok "  Manual use: mariadb-health-check.sh [container]"

ts "Loading kernel modules"
modprobe overlay 2>/dev/null && ok "overlay" || warn "overlay modprobe failed"
modprobe fuse    2>/dev/null && ok "fuse"    || warn "fuse modprobe failed"
grep -q '^overlay$' /etc/modules 2>/dev/null || echo overlay >> /etc/modules
grep -q '^fuse$'    /etc/modules 2>/dev/null || echo fuse    >> /etc/modules

ts "cgroup v2"
if ! grep -q '^cgroup2 ' /etc/fstab 2>/dev/null; then
  echo "cgroup2 /sys/fs/cgroup cgroup2 nosuid,noexec,nodev 0 0" >> /etc/fstab
fi
mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null || true
mount -t cgroup2 cgroup2 /sys/fs/cgroup
ok "cgroup2 mounted"
# Required for Podman overlay with bind mounts on some kernels
mount --make-shared / 2>/dev/null || true

ts "Hardening /tmp"
if ! grep -q 'tmpfs.*\/tmp ' /etc/fstab 2>/dev/null; then
  echo "tmpfs   /tmp   tmpfs   defaults,noexec,nosuid,nodev,size=256M   0 0" >> /etc/fstab
fi
mount -a 2>/dev/null || true
ok "/tmp: 256M noexec nosuid nodev"

ts "Kernel sysctls"
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=1
vm.swappiness=10
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
# BUG FIX (v7-6e): the remaining review item on kernel hardening — none of
# these were present before. All are standard, low-risk hardening values
# that nothing in this stack (Podman/crun, Apache/PHP, MariaDB, CrowdSec,
# Trivy, Lynis) needs to be more permissive than; Lynis's own hardening_index
# (already tracked via wp-hardening.sh lynis) scores several of these
# directly, so this also raises that number.
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1
kernel.unprivileged_bpf_disabled=1
fs.protected_fifos=2
fs.protected_regular=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
SYSCTL
sysctl -p /etc/sysctl.d/99-hardening.conf >/dev/null 2>&1
ok "Sysctls applied"

ts "Installing Podman"
apk add --no-cache podman crun >/dev/null
ok "Podman $(podman --version 2>/dev/null | awk '{print $3}')"
echo 'export PODMAN_IGNORE_CGROUPSV1_WARNING=1' >> /etc/profile

# Skopeo: registry manifest inspection — lets digest pinning (below) and
# update.sh ask "what digest does this tag point to right now" by querying
# the registry's manifest endpoint directly (a few KB) instead of pulling
# the full image just to find out. Lives in Alpine's standard repos, built
# on the same containers/image library as podman/buildah — plain apk add,
# no edge/testing repo needed. Never fatal if it fails: every digest lookup
# that uses it falls back to the older pull-then-inspect method on its own.
ts "Installing Skopeo (registry manifest inspection — powers cheap digest checks)"
if apk add --no-cache skopeo >/dev/null 2>&1; then
  ok "Skopeo $(skopeo --version 2>/dev/null | awk '{print $NF}') ready"
else
  warn "Skopeo install failed — digest pinning/checks will fall back to the"
  warn "  slower pull-then-inspect method (still correct, just heavier)"
fi

# aardvark-dns: required for container-to-container DNS resolution on wp-db.
# Without it WordPress can't resolve the hostname 'mariadb:3306'.
# It may be a podman dependency on some Alpine versions but install explicitly.
apk add --no-cache aardvark-dns 2>/dev/null \
  || warn "aardvark-dns not in current repo — container DNS may use fallback"

# FIX: configure netavark to use nftables as firewall driver.
# The default on Alpine's netavark version is iptables, which causes:
#   Error: netavark: iptables: No such file or directory (os error 2)
# Setting nftables here means netavark uses the 'nft' binary (already
# installed via our nftables package) instead of looking for iptables.
# The wp-front and wp-db subnets (10.89.10.0/24, 10.89.20.0/24) are explicitly
# allowed in the nftables forward chain so container-to-internet traffic
# isn't dropped.
# CRITICAL: use a drop-in file in containers.conf.d/, NOT cat >> to the main
# containers.conf. Alpine's packaged containers.conf already defines [network].
# TOML does not allow duplicate section headers, so appending another [network]
# block causes: "Key 'network' has already been defined" and Podman refuses to
# start any container with a custom network.
# Drop-in files are merged on top of the main config without that restriction.
mkdir -p /etc/containers/containers.conf.d
cat > /etc/containers/containers.conf.d/10-netavark-nftables.conf << 'CONTAINERSCONF'
[network]
firewall_driver = "nftables"
CONTAINERSCONF
ok "netavark: firewall_driver=nftables (drop-in: containers.conf.d/)"

ts "Configuring Podman storage"
mkdir -p /etc/containers
cat > /etc/containers/registries.conf << 'REGCONF'
[registries.search]
registries = ["docker.io"]
[registries.insecure]
registries = []
REGCONF

DRIVER_CHOSEN="vfs"
if lsmod | grep -q '^overlay'; then
  cat > /etc/containers/storage.conf << 'SC1'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC1
  DRIVER_CHOSEN="overlay"
elif lsmod | grep -q '^fuse'; then
  apk add --no-cache fuse fuse3 fuse-overlayfs >/dev/null
  cat > /etc/containers/storage.conf << 'SC2'
[storage]
driver = "overlay"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
[storage.options]
mount_program = "/usr/bin/fuse-overlayfs"
SC2
  DRIVER_CHOSEN="fuse-overlayfs"
else
  cat > /etc/containers/storage.conf << 'SC3'
[storage]
driver = "vfs"
runroot = "/run/containers/storage"
graphroot = "/var/lib/containers/storage"
SC3
  warn "Using vfs storage (uses more disk) — overlay unavailable"
fi
podman system migrate >/dev/null 2>&1 || true
ok "Storage driver: ${DRIVER_CHOSEN}"

# ── Container image digest pinning (default ON) ───────────────────────────────
# BUG FIX (v7-5): real SHA256 digest pinning, resolved dynamically instead of
# a hardcoded placeholder. A hardcoded digest goes stale the instant any of
# these images is rebuilt under the same tag — which registries do routinely
# for security patches — silently pinning every future install to a WORSE,
# older image forever with no warning.
#
# SKOPEO REWRITE (v7-6f): resolving "what digest does this tag point to right
# now" used to mean a full `podman pull` (150-200+ MB each for WordPress/
# MariaDB) just to ask Podman what it downloaded. Skopeo's `inspect
# docker://ref` asks the registry's manifest endpoint directly — a few KB, no
# layer data — so the digest is known before anything is pulled. A `podman
# pull` still happens here (the image needs to actually land locally to run
# it), but only once, against the exact `repo@sha256:digest` reference that's
# actually going to be pinned — not as a separate discovery pull first. If
# Skopeo is missing or a lookup fails, _pin_digest falls back to the
# pre-v7-6f method (pull by tag, ask Podman what it resolved) automatically
# — never fatal, just the old bandwidth cost for that one image. update.sh
# uses this same Skopeo-first approach for its own checks, where the payoff
# is bigger: a routine `update.sh check` no longer pulls anything at all.
#
# FORMAT NOTE (v7-6f): the old "does this Podman accept a combined
# repo:tag@sha256:digest reference" compatibility test is gone. Every pinned
# reference is now the universally-supported digest-only form
# (`repo@sha256:digest`); the tag is tracked separately in the new
# /etc/wp-install/pinned.env instead of inside the image reference itself —
# see the PERSIST block below. update.sh's `check`/`status` output is the
# place to see tag info now, not `podman ps`. wp-geoip-setup.sh's tag
# derivation was updated to match — it now reads pinned.env directly instead
# of trying to sed the tag back out of a reference that may no longer
# contain one (see that script for details).
#
# RETRY + DIAGNOSTICS (v7-5c, carried forward unchanged): both the pull and
# the digest-resolution step retry up to 3 times, and any final failure
# writes the ACTUAL error text (not just "failed") to
# /var/log/wp-digest-pinning.log for later diagnosis, plus a short pointer
# to that log in the normal warn() output. A pin-count summary is also
# printed once all three images are resolved.
DIGEST_PIN_LOG="/var/log/wp-digest-pinning.log"

_skopeo_digest() {
  # $1 = full tag reference, e.g. docker.io/wordpress:6.9.4-php8.3-apache
  # stdout: sha256:<64 hex> on success. Returns 1 on any failure (Skopeo
  # missing, network error, unparseable output) — treated as "fall back",
  # never as fatal.
  local ref="$1" out digest
  command -v skopeo >/dev/null 2>&1 || return 1
  out=$(skopeo inspect "docker://${ref}" 2>/dev/null) || return 1
  digest=$(printf '%s' "$out" \
    | grep -oE '"Digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]{64}"' \
    | grep -oE 'sha256:[0-9a-f]{64}')
  [ -n "$digest" ] || return 1
  printf '%s\n' "$digest"
}

_resolve_digest() {
  local ref="$1" attempt digest
  for attempt in 1 2 3; do
    digest=$(_skopeo_digest "$ref") && [ -n "$digest" ] && { printf '%s\n' "$digest"; return 0; }
    [ "$attempt" -lt 3 ] && sleep 2
  done
  return 1
}

if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
  ts "Resolving image digests (Skopeo registry query — no image pulled yet)"

  _pin_digest() {
    # $1 = tag reference   $2 = label (for logs)
    # stdout: repo@sha256:digest if a digest was resolved (the common case),
    # or the original tag reference if resolution failed outright (that one
    # image falls back to tag-only, same graceful-degradation behavior as
    # USE_DIGEST_PINNING=0 for just that image).
    # BUG FIX (v7-5b, still applies): ok()/warn() print to plain stdout, and
    # this function is called as WP_IMAGE=$(_pin_digest ...) — a command
    # substitution captures EVERYTHING written to stdout, not just the final
    # `echo`. Every ok/warn call in this function must go to stderr (>&2).
    local ref="$1" label="$2" repo tag digest candidate attempt pull_ok pull_output
    repo="${ref%:*}"; tag="${ref##*:}"

    # Preferred path: Skopeo resolves the digest with no image pull at all.
    digest=""
    if command -v skopeo >/dev/null 2>&1; then
      digest=$(_resolve_digest "$ref") || digest=""
    fi

    if [ -n "$digest" ]; then
      candidate="${repo}@${digest}"
      pull_ok=0
      for attempt in 1 2 3; do
        if pull_output=$(podman pull "$candidate" 2>&1); then pull_ok=1; break; fi
        warn "${label}: pull attempt ${attempt}/3 failed, retrying…" >&2
        [ "$attempt" -lt 3 ] && sleep 4
      done
      if [ "$pull_ok" = "1" ]; then
        ok "${label}: pinned to ${digest} (Skopeo — no full pull needed just to check)" >&2
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PINNED (skopeo) — ${candidate}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
        echo "$candidate"
        return 0
      fi
      warn "${label}: Skopeo resolved a digest but pulling it failed after 3 attempts — trying a plain tag pull instead. Detail: ${DIGEST_PIN_LOG}" >&2
      {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: DIGEST PULL FAILED after 3 attempts — ref=${candidate}"
        echo "${pull_output}" | sed 's/^/    /'
      } >> "$DIGEST_PIN_LOG" 2>/dev/null || true
    else
      warn "${label}: Skopeo digest lookup unavailable or failed — falling back to tag pull + local inspect" >&2
    fi

    # Fallback: pull by tag, then ask Podman what digest it resolved to.
    pull_ok=0
    for attempt in 1 2 3; do
      if pull_output=$(podman pull "$ref" 2>&1); then pull_ok=1; break; fi
      warn "${label}: pull attempt ${attempt}/3 failed, retrying…" >&2
      [ "$attempt" -lt 3 ] && sleep 4
    done
    if [ "$pull_ok" != "1" ]; then
      warn "${label}: pull failed after 3 attempts — continuing with tag-only reference (no digest pin). Detail: ${DIGEST_PIN_LOG}" >&2
      {
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PULL FAILED after 3 attempts — ref=${ref}"
        echo "${pull_output}" | sed 's/^/    /'
      } >> "$DIGEST_PIN_LOG" 2>/dev/null || true
      echo "$ref"; return 0
    fi
    digest=$(podman inspect "$ref" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    if [ -z "$digest" ]; then
      warn "${label}: could not resolve a digest after pulling — continuing with tag-only reference. Detail: ${DIGEST_PIN_LOG}" >&2
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: DIGEST RESOLUTION FAILED (post-pull) — ref=${ref}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
      echo "$ref"; return 0
    fi
    ok "${label}: pinned to ${digest} (tag pull + local inspect — Skopeo path unavailable)" >&2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${label}: PINNED (fallback) — ${repo}@${digest}" >> "$DIGEST_PIN_LOG" 2>/dev/null || true
    echo "${repo}@${digest}"
  }

  WP_TAG_INIT="${WP_IMAGE##*:}"
  DB_TAG_INIT="${DB_IMAGE##*:}"
  CS_TAG_INIT="${CROWDSEC_IMAGE##*:}"
  WP_IMAGE=$(_pin_digest "$WP_IMAGE" "WordPress")
  DB_IMAGE=$(_pin_digest "$DB_IMAGE" "MariaDB")
  CROWDSEC_IMAGE=$(_pin_digest "$CROWDSEC_IMAGE" "CrowdSec")

  # ── Visibility: pin-count summary, captured now before GeoIP can later
  # reassign WP_IMAGE to a locally-built (never digest-pinned) image, which
  # would otherwise make a successfully-pinned upstream pull look like a
  # failure in any summary computed after that point. ──────────────────────
  DIGEST_PIN_COUNT=0
  case "$WP_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  case "$DB_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  case "$CROWDSEC_IMAGE" in *@sha256:*) DIGEST_PIN_COUNT=$((DIGEST_PIN_COUNT+1)) ;; esac
  DIGEST_PIN_SUMMARY="${DIGEST_PIN_COUNT}/3 pinned"
  if [ "$DIGEST_PIN_COUNT" = "3" ]; then
    ok "Digest pinning: ${DIGEST_PIN_SUMMARY}"
  else
    warn "Digest pinning: ${DIGEST_PIN_SUMMARY} — see ${DIGEST_PIN_LOG} for exactly why the rest fell back to tag-only"
  fi
else
  WP_TAG_INIT="${WP_IMAGE##*:}"
  DB_TAG_INIT="${DB_IMAGE##*:}"
  CS_TAG_INIT="${CROWDSEC_IMAGE##*:}"
  DIGEST_PIN_SUMMARY="disabled"
  ok "Digest pinning disabled (USE_DIGEST_PINNING=0) — using tag-only references"
fi

# ── Persist pinned tag+digest — the source of truth update.sh reads ────────
# BUG FIX (v7-6f): previously there was no persisted record of this at all —
# "what tag/digest is pinned" had to be re-derived later by sed-parsing it
# back out of the running container's own image string, which only worked
# because a pinned reference still had a visible tag in it
# (repo:tag@sha256:digest). Now that every pinned reference is digest-only
# (see FORMAT NOTE above), that string has no tag left in it to parse out.
# /etc/wp-install/pinned.env is the fix: written here at install time, kept
# current by update.sh (see its _save_pinned()) after every successful
# wp/db/crowdsec update, and read by both update.sh and wp-geoip-setup.sh.
WP_PIN_DIGEST=""; case "$WP_IMAGE" in *@sha256:*) WP_PIN_DIGEST="${WP_IMAGE#*@}" ;; esac
DB_PIN_DIGEST=""; case "$DB_IMAGE" in *@sha256:*) DB_PIN_DIGEST="${DB_IMAGE#*@}" ;; esac
CS_PIN_DIGEST=""; case "$CROWDSEC_IMAGE" in *@sha256:*) CS_PIN_DIGEST="${CROWDSEC_IMAGE#*@}" ;; esac
mkdir -p /etc/wp-install
cat > /etc/wp-install/pinned.env << PINNEDENV
# WordPress VM — pinned image tag + digest per component.
# Written by the installer; kept current by update.sh after every
# successful update. update.sh treats this file as authoritative for
# "what is currently pinned" instead of parsing tags back out of the
# running container's image reference. Do not edit by hand while update.sh
# might be running.
WP_TAG="${WP_TAG_INIT}"
WP_DIGEST="${WP_PIN_DIGEST}"
DB_TAG="${DB_TAG_INIT}"
DB_DIGEST="${DB_PIN_DIGEST}"
CS_TAG="${CS_TAG_INIT}"
CS_DIGEST="${CS_PIN_DIGEST}"
PINNEDENV
chmod 600 /etc/wp-install/pinned.env
ok "pinned.env written — WordPress ${WP_TAG_INIT}, MariaDB ${DB_TAG_INIT}, CrowdSec ${CS_TAG_INIT}"

ts "Creating wpuser account"
apk add --no-cache shadow >/dev/null
id wpuser >/dev/null 2>&1 || adduser -D -s /sbin/nologin wpuser
ok "wpuser ready (file layout only — not used for container UID)"

ts "Generating database credentials"
apk add --no-cache openssl >/dev/null 2>&1 || true
DB_ROOT_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)
DB_WP_PASS=$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32)
WP_TABLE_PREFIX="wp$(openssl rand -hex 3)_"

mkdir -p /etc/wordpress
cat > /etc/wordpress/env << WPCREDS
MARIADB_ROOT_PASSWORD=${DB_ROOT_PASS}
MARIADB_DATABASE=wordpress
MARIADB_USER=wpdb
MARIADB_PASSWORD=${DB_WP_PASS}
WORDPRESS_DB_HOST=mariadb:3306
WORDPRESS_DB_USER=wpdb
WORDPRESS_DB_PASSWORD=${DB_WP_PASS}
WORDPRESS_DB_NAME=wordpress
WORDPRESS_TABLE_PREFIX=${WP_TABLE_PREFIX}
WPCREDS
chmod 600 /etc/wordpress/env
ok "/etc/wordpress/env written (chmod 600)"

cat > /root/.wp-credentials << WPCREDSINFO
# ============================================================
# WordPress VM Credentials — $(date '+%Y-%m-%d %H:%M:%S')
# chmod 600 /root/.wp-credentials
# ============================================================
# MariaDB root password  : ${DB_ROOT_PASS}
# MariaDB DB             : wordpress
# MariaDB WP user        : wpdb
# MariaDB WP password    : ${DB_WP_PASS}
# WordPress table prefix : ${WP_TABLE_PREFIX}
#
# WordPress Admin: http://<VM-IP>/wp-admin/install.php
#   (the 5-minute install — do this before anyone else finds your site)
#
# Machine env file: /etc/wordpress/env  (chmod 600)
# ============================================================
WPCREDSINFO
chmod 600 /root/.wp-credentials
ok "/root/.wp-credentials written (chmod 600)"

ts "Creating Podman wp-front / wp-db networks"
# Explicit subnets keep the nftables forward chain rules exact:
#   ip saddr/daddr 10.89.10.0/24 accept   (wp-front, in /etc/nftables.nft)
#   ip saddr/daddr 10.89.20.0/24 accept   (wp-db,    in /etc/nftables.nft)
# Without fixed subnets, netavark assigns them dynamically and the forward
# rules could stop matching after a network recreate.
#
# wp-front: WordPress only. Has normal egress (plugin/theme installs, WP-Cron
# remote requests, update checks) and is where the published host port lands.
PRUN network exists wp-front 2>/dev/null \
  || PRUN network create --subnet 10.89.10.0/24 --gateway 10.89.10.1 wp-front
ok "wp-front: 10.89.10.0/24 — WordPress egress + published port"
#
# wp-db: WordPress + MariaDB only, --internal. netavark never configures a
# route out of an --internal network, so MariaDB has no path to the internet
# regardless of nftables state — a real isolation boundary, not just "no
# host port".
PRUN network exists wp-db 2>/dev/null \
  || PRUN network create --internal --subnet 10.89.20.0/24 --gateway 10.89.20.1 wp-db
ok "wp-db: 10.89.20.0/24 — internal (no egress), no host port for MariaDB"

ts "Installing 8G Firewall v1.4"
mkdir -p /home/wpuser/wp/htaccess
cat > /home/wpuser/wp/htaccess/.htaccess << '8GEOF'
# 8G FIREWALL v1.4 — https://perishablepress.com/8g-firewall/
# Installed by create-wordpress-vm.sh

# ── 8G[QUERY STRING] ────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{QUERY_STRING} (eval\(|base64_encode|GLOBALS\[|_REQUEST\[) [NC,OR]
  RewriteCond %{QUERY_STRING} (<|%3C).*script.*(>|%3E) [NC,OR]
  RewriteCond %{QUERY_STRING} (\.\./|%2e%2e%2f|%252e%252e) [NC,OR]
  RewriteCond %{QUERY_STRING} (union.*select|select.*from.*information_schema) [NC,OR]
  RewriteCond %{QUERY_STRING} (benchmark\s*\(|sleep\s*\() [NC,OR]
  RewriteCond %{QUERY_STRING} (cmd=|passthru=|system\(|exec\() [NC,OR]
  RewriteCond %{QUERY_STRING} (127\.0\.0\.1|localhost|loopback) [NC,OR]
  RewriteCond %{QUERY_STRING} (<script|javascript:|vbscript:) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REQUEST URI] ─────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_URI} (\.(asp|bak|cfg|cgi|config|dat|dll|exe|git|gz|hta|ini|jsp|log|old|orig|sql|svn|swp|tar|tgz|zip)) [NC,OR]
  RewriteCond %{REQUEST_URI} (etc/passwd|etc/shadow|proc/self) [NC,OR]
  RewriteCond %{REQUEST_URI} (phpmyadmin|myadmin|pma|mysql) [NC,OR]
  RewriteCond %{REQUEST_URI} (wp-config\.php|wp-config-sample) [NC,OR]
  RewriteCond %{REQUEST_URI} (wp-content/uploads/.*\.ph(p|tml)) [NC,OR]
  RewriteCond %{REQUEST_URI} (webshell|c99\.php|r57\.php|hack\.php) [NC,OR]
  RewriteCond %{REQUEST_URI} (eval\(|base64_encode|\.\./) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[USER AGENT] ──────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_USER_AGENT} (acunetix|nikto|nessus|sqlmap|masscan|zgrab) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (dirbuster|gobuster|ffuf|wfuzz|nuclei|metasploit) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (scrapy|havij|libwww-perl|HTTrack|WPScan) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} (wikodo|semrush.*bot|dotbot|ahrefsbot) [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} ^(-|_|\.|\s)*$ [NC,OR]
  RewriteCond %{HTTP_USER_AGENT} ^$ [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REQUEST METHOD] ──────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_METHOD} ^(CONNECT|DEBUG|MOVE|TRACE|TRACK) [NC]
  RewriteRule .* - [F,L]
</IfModule>

# ── 8G[REFERRER] ────────────────────────────────────────────────────────────
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP_REFERER} (<|>|\'|\") [NC,OR]
  RewriteCond %{HTTP_REFERER} (base64_encode|eval\() [NC]
  RewriteRule .* - [F,L]
</IfModule>
8GEOF
# ── Custom wp-admin slug + author=N enumeration blocking ─────────────────────
# BUG FIX (v7-5): these were originally emitted ONLY in wp-security.conf's
# <Directory> block. That fixes the server-vs-vhost mod_rewrite inheritance
# problem (see the long note above SLUG_BLOCK's generation on the host side),
# but mod_rewrite has a SEPARATE, independent non-inheritance boundary
# between a <Directory> block and a .htaccess file at that same path — by
# default a .htaccess file's own ruleset can reset/replace what a covering
# <Directory> block established, unless that .htaccess explicitly opts in
# with `RewriteOptions Inherit`. Rather than depend on that merge behavior
# working a particular way, the exact same rules are placed here too —
# directly inside the .htaccess file, in the exact per-directory ruleset
# already proven to work (this is the same file WordPress's own permalinks
# and the 8G rules above run from). Placed BEFORE the WordPress-managed
# BEGIN/END block (and so, critically, evaluated BEFORE it) so: (1) it
# survives any WordPress .htaccess rewrite (permalink structure changes,
# etc. only ever touch content between those markers), and (2) requests to
# the custom slug resolve to a real file (/wp-admin/index.php) before
# WordPress's own catch-all `RewriteCond %{REQUEST_FILENAME} !-f` rule can
# claim them and route them into ordinary front-end 404 handling instead.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  {
    echo ""
    echo "# ── Custom wp-admin slug (mirrors wp-security.conf) ─────────────────────────"
    echo "<IfModule mod_rewrite.c>"
    echo "    RewriteEngine On"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/?\$ /wp-admin/index.php [L,QSA]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/(.+)\$ /wp-admin/\$1 [L,QSA]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}-login/?\$ /wp-login.php [L,QSA]"
    echo "</IfModule>"
  } >> /home/wpuser/wp/htaccess/.htaccess
fi
cat >> /home/wpuser/wp/htaccess/.htaccess << '8GEOF2'

# ── author=N user enumeration blocking (mirrors wp-security.conf) ───────────
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} author=
    RewriteRule ^ - [F,L]
</IfModule>

# ── WordPress Permalink Rules (WordPress manages this block — do not edit) ──
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
8GEOF2
chmod 644 /home/wpuser/wp/htaccess/.htaccess
chown 33:33 /home/wpuser/wp/htaccess/.htaccess
ok "8G Firewall .htaccess ready at /home/wpuser/wp/htaccess/"
ok "  Toggle anytime: wp-hardening.sh disable 8g | enable 8g"

ts "Preparing volume directories"
mkdir -p /home/wpuser/wp/html /home/wpuser/wp/logs
mkdir -p /home/wpuser/wp/mysql
mkdir -p /home/wpuser/wp/apache-conf /home/wpuser/wp/php-conf
chown -R wpuser:wpuser /home/wpuser/wp 2>/dev/null || true

# Container UIDs map 1:1 to host UIDs under rootful Podman (no subordinate
# UID/GID mapping is involved), so a literal chown is correct here.
chown -R 33:33  /home/wpuser/wp/html /home/wpuser/wp/logs
chown -R 999:999 /home/wpuser/wp/mysql
ok "Volume directories owned by UID 33 (www-data) and 999 (mysql)"

# ── Deploy Apache security config (pre-built by host script) ─────────────────
# /root/wp-security.conf was written by create-wordpress-vm.sh via qemu-nbd
# with ADMIN_CIDR, ALLOWED_ADMIN_IP, and PROXY_IP already substituted.
# No runtime variable substitution needed here.
if [ -f /root/wp-security.conf ]; then
  cp /root/wp-security.conf /home/wpuser/wp/apache-conf/wp-security.conf
  chmod 644 /home/wpuser/wp/apache-conf/wp-security.conf
  ok "Apache security config deployed (with your CIDR/IP restrictions baked in)"
  # If mod_remoteip files were also injected, deploy them too
  if [ -f /root/wp-remoteip.load ]; then
    mkdir -p /home/wpuser/wp/apache-mods
    cp /root/wp-remoteip.load /home/wpuser/wp/apache-mods/remoteip.load
    cp /root/wp-remoteip.conf /home/wpuser/wp/apache-mods/remoteip.conf 2>/dev/null || true
    chmod 644 /home/wpuser/wp/apache-mods/remoteip.load \
              /home/wpuser/wp/apache-mods/remoteip.conf 2>/dev/null || true
    ok "mod_remoteip files deployed — proxy IP trusted for X-Forwarded-For"
  fi
else
  warn "/root/wp-security.conf not found — generating fallback (no IP restriction)"
  cat > /home/wpuser/wp/apache-conf/wp-security.conf << 'APACHEFALLBACK'
# Fallback Apache security config — no wp-admin IP restriction.
ServerTokens Prod
ServerSignature Off
CustomLog /var/log/apache2/access.log combined
# Dual-IP diagnostic log — see main wp-security.conf for rationale. Kept
# separate from access.log so CrowdSec's apache2 collection parsing is
# never affected.
LogFormat "%t peer=%{c}a interpreted=%a \"%r\" %>s" wp_remoteip_debug
CustomLog /var/log/apache2/remoteip-debug.log wp_remoteip_debug
<Directory /var/www/html>
    Options -Indexes +FollowSymLinks
    AllowOverride All
</Directory>
<FilesMatch "(wp-config\.php|readme\.html|license\.txt)$">
    Require all denied
</FilesMatch>
<FilesMatch "\.(bak|orig|sql|log|sh|swp|save)$">
    Require all denied
</FilesMatch>
<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
<Files "xmlrpc.php">
    Require all denied
</Files>
<Files "debug.log">
    Require all denied
</Files>
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{QUERY_STRING} author=
    RewriteRule ^ - [F,L]
</IfModule>
Header always set X-Content-Type-Options "nosniff"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always unset X-Powered-By
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
APACHEFALLBACK
fi
chmod 644 /home/wpuser/wp/apache-conf/wp-security.conf

# PHP security configuration
cat > /home/wpuser/wp/php-conf/security.ini << 'PHPSEC'
; WordPress PHP Security Configuration
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/apache2/php-errors.log
; allow_url_fopen: ON for MSP production.
; WordPress core uses cURL (not fopen) for HTTP, but many WooCommerce payment
; gateways and plugin APIs use file_get_contents() with URLs. Disabling breaks
; those integrations. Restrict at the nftables output chain if tighter control
; is needed. Flip to Off only for high-security environments with no plugins.
allow_url_fopen = On
allow_url_include = Off
; File upload limits
upload_max_filesize = 64M
post_max_size = 64M
; Runtime limits
memory_limit = 256M
max_execution_time = 300
; Session security — Lax (not Strict) for WordPress OAuth and payment flows.
; Strict breaks SSO callbacks, WooCommerce, and any cross-origin POST redirect.
session.cookie_httponly = 1
session.cookie_samesite = Lax
session.use_strict_mode = 1
PHPSEC
chmod 644 /home/wpuser/wp/php-conf/security.ini

ok "Volume directories and config files ready:"
ok "  /home/wpuser/wp/html     WordPress files   (UID 33:www-data)"
ok "  /home/wpuser/wp/logs     Apache access log (UID 33:www-data)"
ok "  /home/wpuser/wp/mysql    MariaDB data      (UID 999:mysql)"
ok "  /home/wpuser/wp/apache-conf/wp-security.conf"
ok "  /home/wpuser/wp/php-conf/security.ini"

ts "Enabling syslog"
rc-update add syslog boot 2>/dev/null || true
rc-service syslog status >/dev/null 2>&1 || rc-service syslog start 2>/dev/null || true
ok "syslog active"



ts "nftables firewall"
apk add --no-cache nftables >/dev/null
rc-update add nftables default 2>/dev/null || true
if [ -f /etc/nftables.nft ]; then
  nft -f /etc/nftables.nft && ok "Rules loaded" \
    || warn "Ruleset load failed — check /etc/nftables.nft"
  rc-service nftables start 2>/dev/null || true
else
  warn "/etc/nftables.nft not found"
fi

# ── MariaDB container ─────────────────────────────────────────────────────────
# wp-db ONLY (--internal, no route out) — zero host port exposure AND zero
# egress, not just "no port published".
# BUG FIX: tag was 11.4-lts (does not exist) — now using 11.4.
ts "Starting MariaDB (pulling ~150 MB — internal network only)"
# Mount a custom MariaDB config to cap InnoDB buffer pool and enable slow
# query logging. Without a buffer pool limit MariaDB can consume all available
# RAM on busy sites, evicting WordPress and CrowdSec from memory.
mkdir -p /home/wpuser/wp/mariadb-conf
cat > /home/wpuser/wp/mariadb-conf/wp.cnf << 'MYCNF'
# MariaDB 11.4 configuration for WordPress
# Use [mariadbd] (not [mysqld]) — MariaDB 11.x canonical section name.
# [mysqld] still works for compat but [mariadbd] avoids deprecation warnings.
[mariadbd]
# InnoDB: cap buffer pool to prevent OOM on a 4 GB VM shared with WordPress
# and CrowdSec. innodb_log_file_size removed — deprecated in 11.x, now
# controlled by innodb_redo_log_capacity (default is fine for WP workloads).
innodb_buffer_pool_size        = 256M
# innodb_log_file_size is the correct MariaDB variable (innodb_redo_log_capacity
# is MySQL 8.0.30+ syntax and does NOT exist in MariaDB — using it crashes mariadbd)
innodb_log_file_size           = 64M
innodb_flush_log_at_trx_commit = 2
# Suppress io_uring probe: MariaDB 11.x tries io_uring first, falls back to
# libaio when blocked by seccomp (our --cap-drop ALL). The fallback works fine
# but generates noisy log lines. Disable the probe entirely.
innodb_use_native_aio         = OFF
# Charset: utf8mb4 required for WordPress emoji and 4-byte Unicode support
character_set_server          = utf8mb4
collation_server              = utf8mb4_unicode_ci
# Connection limits
max_connections               = 100
max_allowed_packet            = 64M
# Slow query log for MSP performance diagnostics
slow_query_log                = 1
slow_query_log_file           = /var/lib/mysql/slow.log
long_query_time               = 2
MYCNF
chmod 644 /home/wpuser/wp/mariadb-conf/wp.cnf
ok "MariaDB config: innodb_buffer_pool=256M, slow_query_log=on"

podman rm -f mariadb 2>/dev/null || true
podman run -d \
  --name    mariadb \
  --network wp-db \
  --ip      10.89.20.2 \
  --restart always \
  --label   io.containers.autoupdate=image \
  --cap-drop ALL \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --cap-add  DAC_OVERRIDE \
  --cap-add  FOWNER \
  --security-opt no-new-privileges:true \
  --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
  --pids-limit 100 \
  --memory=512m \
  --cpu-shares=512 \
  --env-file /etc/wordpress/env \
  -v /home/wpuser/wp/mysql:/var/lib/mysql \
  -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \
  --health-cmd "healthcheck.sh --connect --innodb_initialized" \
  --health-interval 5s \
  --health-timeout 5s \
  --health-retries 24 \
  --health-start-period 30s \
  "${DB_IMAGE}"

# FIX 2: Do NOT rely on Podman health check status.
# On Alpine without systemd, conmon's health check timer often does not fire —
# the container stays in "starting" state indefinitely even when MariaDB is
# fully ready. Instead, use a direct exec-based probe (mariadbd ping with
# credentials) which works regardless of conmon or cgroup configuration.
# The --health-cmd is still configured for 'podman ps' display purposes, but
# we never block on its output here.
ts "Waiting for MariaDB to accept connections (up to 3 min)"
# PRODUCTION SAFETY FIX (v7-6k): this loop used to gate readiness on a bare
# ping — see the mariadb-health-check.sh rationale above (installed earlier
# in this stage) for why that's not enough. Now gated on the same real
# query + InnoDB validation used at update time, with the old ping-only
# check kept as a fallback only if that script is somehow missing.
DB_READY=0
for i in $(seq 1 36); do
  if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
    if /usr/local/bin/mariadb-health-check.sh mariadb; then
      DB_READY=1; break
    fi
  # Run mariadbd ping INSIDE the container where MARIADB_ROOT_PASSWORD is set.
  # Use sh -c so the env var expands in the container's shell context, not here.
  elif PRUN exec mariadb sh -c \
       'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
        mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
    DB_READY=1; break
  fi
  sleep 5
done
[ "$DB_READY" = "1" ] \
  && ok "MariaDB healthy — ping + real query (root and wpdb) + InnoDB initialized" \
  || warn "MariaDB did not pass full health validation in 3 min — WordPress will retry. Check: PRUN logs mariadb | tail -20"



# ── WordPress container ───────────────────────────────────────────────────────
# BUG FIX: WordPress previously had NO --cap-drop ALL (MariaDB did).
# All containers now use the same cap discipline:
#   --cap-drop ALL        remove every Linux capability from the bounding set
#   --cap-add NET_BIND_SERVICE  Apache binds port 80 inside container netns
#                               (required even with -p 80:80 and custom network;
#                               Podman's host-side publish is separate from the
#                               in-container bind)
#   --cap-add SETUID/SETGID     Apache drops from root to www-data (UID 33)
#   --cap-add CHOWN             WordPress entrypoint sets file ownership on init
#   --cap-add DAC_OVERRIDE      read/write files across UID boundaries
#   --cap-add FOWNER            chmod on files not owned by current process
# --security-opt no-new-privileges blocks setuid binary privilege escalation
# but does NOT block Apache's intentional setuid() call to drop to www-data.
ts "Starting WordPress (pulling ~180 MB)"

# Determine remoteip volume mounts (only if mod_remoteip files were deployed)
REMOTEIP_MOUNTS=""
if [ -d /home/wpuser/wp/apache-mods ]; then
  REMOTEIP_MOUNTS_FLAG="yes"
else
  REMOTEIP_MOUNTS_FLAG="no"
fi

# mod_headers is NOT enabled by default in the WordPress Docker image
# (despite mod_remoteip being pre-enabled). Without headers.load Apache
# crashes on every 'Header always set ...' directive in wp-security.conf.
# We always create and mount this file.
mkdir -p /home/wpuser/wp/apache-mods
cat > /home/wpuser/wp/apache-mods/headers.load << 'HLOAD'
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
HLOAD
chmod 644 /home/wpuser/wp/apache-mods/headers.load
ok "headers.load created — enables mod_headers for security headers"

# Build volume args for podman run
WP_VOL_ARGS="-v /home/wpuser/wp/html:/var/www/html"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/logs:/var/log/apache2"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro"
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro"
# Always mount headers.load (mod_headers not pre-enabled in wordpress image)
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro"
# NOTE: remoteip.load is intentionally NOT mounted — mod_remoteip is already
# pre-enabled in the WordPress Docker image. Mounting it again just generates
# a harmless "already loaded" warning but we keep things clean.
# Mount 8G Firewall .htaccess as :rw — WordPress updates permalink rules
# inside the # BEGIN/END WordPress markers without touching the 8G section above.
WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw"
# Only mount remoteip.conf if a trusted proxy IP was configured (sets RemoteIPTrustedProxy).
if [ -f /home/wpuser/wp/apache-mods/remoteip.conf ]; then
  WP_VOL_ARGS="${WP_VOL_ARGS} -v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"
fi

WEB_CHECK_PORT=80

podman rm -f wordpress 2>/dev/null || true
# shellcheck disable=SC2086
podman run -d \
  --name    wordpress \
  --network wp-front \
  --ip      10.89.10.3 \
  -p 80:80 \
  --restart always \
  --label   io.containers.autoupdate=image \
  --cap-drop ALL \
  --cap-add  NET_BIND_SERVICE \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --cap-add  DAC_OVERRIDE \
  --cap-add  FOWNER \
  --security-opt no-new-privileges:true \
  --pids-limit 200 \
  --memory=768m \
  --cpu-shares=512 \
  --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
  --env-file /etc/wordpress/env \
  -e WORDPRESS_DB_HOST=mariadb:3306 \
  -e WORDPRESS_DEBUG="" \
  --add-host "mariadb:10.89.20.2" \
  -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
  ${WP_VOL_ARGS} \
  "${WP_IMAGE}"
# wp-db (--internal) attached second — Podman's --network flag on `run` only
# takes a static --ip for the primary network in this Podman/Alpine
# combination, so wp-db is attached post-create via `network connect`, the
# same pattern Podman's own docs recommend for multi-network containers.
podman network connect --ip 10.89.20.3 wp-db wordpress

# Wait for WordPress to pass full health validation — NOT just a non-500
# HTTP response. BUG FIX (v7-6g): a bare HTTP check happily passes on
# "Error establishing a database connection", a PHP fatal-error page, or a
# partially initialized site — every one of these can return a non-500
# code while WordPress itself is broken. wp-health-check.sh (installed
# earlier in this stage) additionally proves PHP actually executes, that
# the mariadb hostname resolves, and — the check that actually matters here
# — that a real mysqli connection using WordPress's own DB credentials can
# run SELECT 1.
ts "Validating WordPress health (HTTP + PHP + DB name resolution + DB auth + real query)"
WP_READY=0
for i in $(seq 1 24); do
  if /usr/local/bin/wp-health-check.sh wordpress "${WEB_CHECK_PORT}"; then
    WP_READY=1; break
  fi
  warn "WordPress not fully healthy yet (retry ${i}/24) — see checks above"
  sleep 5
done
[ "$WP_READY" = "0" ] && warn "WordPress did not pass full health validation after 24 attempts — check: podman logs wordpress"
ok "Container: $(podman ps --filter name='^wordpress$' --format '{{.Status}}' 2>/dev/null)"

# Fix uploads ownership — critical for theme/plugin/media uploads.
# Root cause: WordPress Docker entrypoint runs as UID 0 and creates
# wp-content/uploads/ as root:root. After Apache drops to www-data via
# setuid(), it LOSES DAC_OVERRIDE (Linux clears effective capabilities
# on UID drop). www-data (UID 33) then cannot write to root:root 755 dirs.
# Note: 'podman exec wordpress php -r is_writable(...)' falsely shows true
# because exec runs as container root, not as www-data — misleading.
ts "Fixing wp-content/uploads ownership (www-data must own uploads)"
# BUG FIX (v7-4): a single chown 3s after container start was racing the
# WordPress entrypoint, which continues copying/creating files under
# wp-content *after* that 3s mark (root-owned each time it touches a file).
# Symptom seen in the field: uploads worked fine after a reboot (because the
# OpenRC start() handler re-runs the same chown well after the entrypoint is
# done) but failed right after first install. Fix: wait for a concrete signal
# that the entrypoint's copy is finished (wp-content/plugins exists with the
# default plugins in it), THEN chown, THEN verify with an actual www-data
# write test, retrying a few times if the entrypoint is still mid-copy.
UPLOADS_FIXED=0
for attempt in 1 2 3 4 5; do
  # Wait for a sign the entrypoint has finished its initial copy.
  PRUN exec wordpress sh -c '[ -d /var/www/html/wp-content/plugins ]' >/dev/null 2>&1 || { sleep 4; continue; }
  # BUG FIX (v7-5d): WordPress doesn't necessarily create wp-content/uploads
  # until the first real media operation — confirmed in the field, this
  # retry loop kept "failing" even with correct ownership because the
  # touch-test's target directory simply didn't exist yet, which looks
  # identical to a permissions failure but chown can never fix it. Create it
  # unconditionally (safe no-op if it already exists) before testing.
  PRUN exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
  PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
  if PRUN exec --user www-data wordpress sh -c \
       'touch /var/www/html/wp-content/uploads/.write_test 2>/dev/null && rm -f /var/www/html/wp-content/uploads/.write_test' \
       >/dev/null 2>&1; then
    UPLOADS_FIXED=1
    ok "wp-content/ ownership → www-data:www-data (verified writable, attempt ${attempt})"
    break
  fi
  sleep 4
done
[ "$UPLOADS_FIXED" = "1" ] \
  || warn "uploads still not confirmed writable after 5 attempts; fix: PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content"
# Mirror ownership fix on the host-side bind-mount for persistence across
# restarts (container UID 33 maps 1:1 to host UID 33 under rootful Podman).
chown -R 33:33 /home/wpuser/wp/html/wp-content 2>/dev/null \
  && ok "Host-side /home/wpuser/wp/html/wp-content ownership fixed too" || true


# ── OpenRC: mariadb-container ─────────────────────────────────────────────────

# ════════════════════════════════════════════════════════════════════════════
# GEOIP COUNTRY FILTERING (optional — only runs if GEOIP_ENABLED=1)
#
# BUG FIX (v7-4): GeoIP silently never got applied in the field even with
# valid MaxMind credentials. Root cause: `podman build` for the mod_maxminddb
# image runs its RUN steps (apt-get, curl) in a build-time container that
# is NOT on wp-front/wp-db (10.89.10.0/24 / 10.89.20.0/24) — it's on Podman's
# default bridge subnet. But by this point in Stage 2 the nftables ruleset is
# already loaded, and its forward chain only allows those two subnets before
# its policy DROP:
#   ip saddr/daddr 10.89.10.0/24 accept
#   ip saddr/daddr 10.89.20.0/24 accept
# So the build container's outbound internet access (apt-get update, the
# mod_maxminddb download) was silently dropped by the firewall, apt-get
# failed, `podman build` failed, and — because everything past that point
# (maxminddb.load, the GeoLite2 download, geoip.conf) lives inside the
# `if podman build ...; then` success branch — nothing else ever ran. No
# error reached the console because the build's own output only went to
# the install log, and the failure path just printed one generic warning.
#
# FIX: `podman build --network host` for this one build step, so it shares
# the host's already-working internet access instead of an unlisted bridge
# subnet the firewall drops. This does not weaken the running containers'
# isolation — it only applies to the transient build container, which never
# runs application code and is discarded once the image layer is committed.
#
# DESIGN NOTE — why a custom image at all (unchanged from v7-3):
#   Compiling mod_maxminddb via `podman exec` into a RUNNING container writes
#   to that container's ephemeral writable layer and is lost on recreate.
#   Building a small custom image instead (multi-stage: one stage compiles,
#   the final stage is the pinned WordPress image plus only the compiled
#   .so) means GeoIP survives every future update/recreate with no
#   persistence hacks. The GeoLite2 database itself is fetched directly via
#   curl on the Alpine host (documented MaxMind permalink API, plain HTTPS —
#   host-level curl uses the OUTPUT chain, which is policy-accept, so it was
#   never affected by the bug above) and bind-mounted in.
#
# REUSABILITY FIX (v7-4): this logic is now written out as a standalone,
# idempotent script — /usr/local/bin/wp-geoip-setup.sh — instead of living
# only inline here. That means if GeoIP setup ever fails again (bad
# credentials, MaxMind rate limit, transient network blip), it can be fixed
# and retried on a live VM with a single command and NO reboot and NO
# re-running the whole provisioning script:
#   1. Fix /etc/wp-install/vars.sh (MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY
#      / GEOIP_MODE / GEOIP_WHITELIST or GEOIP_BLOCKLIST / GEOIP_ENABLED=1)
#   2. Run: /usr/local/bin/wp-geoip-setup.sh
#   3. Check: tail -40 /var/log/wp-geoip.log
# ════════════════════════════════════════════════════════════════════════════
mkdir -p /home/wpuser/wp/geoip-build /home/wpuser/wp/geoip-db /home/wpuser/wp/apache-mods
cat > /usr/local/bin/wp-geoip-setup.sh << 'WPGEOSETUP'
#!/bin/sh
# wp-geoip-setup.sh — (Re)apply MaxMind GeoIP country filtering.
# Safe to re-run anytime on a live VM: no reboot, no full reinstall needed.
# Reads credentials/mode from /etc/wp-install/vars.sh, written at
# provisioning time (edit that file to fix bad credentials, then re-run
# this script). Exit code 0 = applied, 1 = failed (see the log below).
LOG=/var/log/wp-geoip.log
exec >> "$LOG" 2>&1
echo ""
echo "=== [$(date '+%Y-%m-%d %H:%M:%S')] wp-geoip-setup.sh starting ==="

[ "$(id -u)" -eq 0 ] || { echo "FATAL: must run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
PRUN() {
  podman "$@"
}

if [ "${GEOIP_ENABLED:-0}" != "1" ]; then
  echo "GEOIP_ENABLED is not 1 in /etc/wp-install/vars.sh — nothing to do."
  echo "Set GEOIP_ENABLED=1, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY, GEOIP_MODE"
  echo "(whitelist|blocklist), and GEOIP_WHITELIST or GEOIP_BLOCKLIST there, then re-run."
  exit 0
fi
if [ -z "${MAXMIND_ACCOUNT_ID:-}" ] || [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "FATAL: MaxMind Account ID / License Key missing from /etc/wp-install/vars.sh"
  exit 1
fi

CURRENT_WP_IMAGE=$(PRUN inspect wordpress --format '{{.Config.Image}}' 2>/dev/null)
[ -z "$CURRENT_WP_IMAGE" ] && CURRENT_WP_IMAGE="docker.io/wordpress:6.9.4-php8.3-apache"
# Derive a human-friendly tag for naming the local GeoIP image.
# BUG FIX (v7-6f): the Skopeo rewrite of digest pinning dropped the "does
# this Podman accept a combined tag+digest reference" test — every pinned
# reference is now digest-only (repo@sha256:..., no tag at all), ALWAYS,
# not just on the subset of hosts where the combined form used to fail.
# That leaves CURRENT_WP_IMAGE's own string with no tag to parse out once
# pinning is on, so the old heuristic here (parse a tag out of the image
# string, only falling back to a short digest fragment when none was
# present) would now hit that fallback on every single run — every GeoIP
# rebuild producing a digest-fragment tag (wordpress-geoip:a1b2c3d4e5f6)
# instead of a readable one (wordpress-geoip:6.9.4-php8.3-apache).
# /etc/wp-install/pinned.env carries the tag separately from the image
# reference for exactly this reason (see the installer's PERSIST comment) —
# read WP_TAG from there first. Only fall back to parsing CURRENT_WP_IMAGE
# itself when pinned.env has no tag to offer (digest pinning disabled, or
# the file is missing/not yet written).
WP_TAG_FROM_PIN=""
[ -f /etc/wp-install/pinned.env ] && WP_TAG_FROM_PIN=$(. /etc/wp-install/pinned.env; echo "$WP_TAG")
if [ -n "$WP_TAG_FROM_PIN" ]; then
  WP_TAG_PORTION="$WP_TAG_FROM_PIN"
else
  WP_BASE_NO_DIGEST=$(echo "${CURRENT_WP_IMAGE}" | sed 's|@sha256:.*||')
  case "$WP_BASE_NO_DIGEST" in
    *:*) WP_TAG_PORTION="${WP_BASE_NO_DIGEST##*:}" ;;
    *)   WP_TAG_PORTION=$(echo "${CURRENT_WP_IMAGE}" | grep -oE 'sha256:[0-9a-f]{12}' | sed 's|sha256:||' || true)
         [ -z "$WP_TAG_PORTION" ] && WP_TAG_PORTION="latest"
         ;;
  esac
fi
WP_TAG_PORTION=$(echo "$WP_TAG_PORTION" | sed 's|^geoip-||')
GEOIP_IMG_TAG="localhost/wordpress-geoip:${WP_TAG_PORTION}"
echo "Base image: ${CURRENT_WP_IMAGE}  ->  Target: ${GEOIP_IMG_TAG}"

mkdir -p /home/wpuser/wp/geoip-build /home/wpuser/wp/geoip-db /home/wpuser/wp/apache-mods

MMDB_ASSET_URL=$(wget -qO- https://api.github.com/repos/maxmind/mod_maxminddb/releases/latest 2>/dev/null \
  | grep -oE '"browser_download_url":\s*"[^"]*mod_maxminddb-[0-9.]+\.tar\.gz"' \
  | head -1 | sed -E 's/.*"(https[^"]+)"/\1/')
if [ -z "$MMDB_ASSET_URL" ]; then
  MMDB_ASSET_URL="https://github.com/maxmind/mod_maxminddb/releases/download/1.2.0/mod_maxminddb-1.2.0.tar.gz"
  echo "GitHub API lookup failed — using pinned mod_maxminddb 1.2.0"
else
  echo "Latest mod_maxminddb release: $(basename "$MMDB_ASSET_URL")"
fi

cat > /home/wpuser/wp/geoip-build/Containerfile << CONTAINERFILE
FROM ${CURRENT_WP_IMAGE} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2-dev libmaxminddb-dev build-essential curl ca-certificates \
    && curl -fsSL -o /tmp/mod_maxminddb.tar.gz "${MMDB_ASSET_URL}" \
    && mkdir -p /tmp/build && tar xzf /tmp/mod_maxminddb.tar.gz -C /tmp/build --strip-components=1 \
    && cd /tmp/build && ./configure --with-apxs=/usr/bin/apxs && make \
    && find /tmp/build -name 'mod_maxminddb.so' -exec cp {} /tmp/mod_maxminddb.so \; \
    && test -s /tmp/mod_maxminddb.so || { echo "FATAL: mod_maxminddb.so not found anywhere under /tmp/build after make — the mod_maxminddb build layout may have changed upstream" >&2; exit 1; }

FROM ${CURRENT_WP_IMAGE}
COPY --from=builder /tmp/mod_maxminddb.so /etc/apache2/maxminddb-module/mod_maxminddb.so
CONTAINERFILE

echo "Building ${GEOIP_IMG_TAG} — using --network host (the wp-front/wp-db-only nftables"
echo "forward rule otherwise drops this build container's internet access, which"
echo "was the actual cause of GeoIP silently failing to apply)…"
if ! podman build --network host -t "${GEOIP_IMG_TAG}" -f /home/wpuser/wp/geoip-build/Containerfile /home/wpuser/wp/geoip-build; then
  echo "FATAL: podman build failed — the output directly above is the real apt-get/curl/make error."
  exit 1
fi
echo "Custom image built: ${GEOIP_IMG_TAG}"

cat > /home/wpuser/wp/apache-mods/maxminddb.load << 'MMLOAD'
LoadModule maxminddb_module /etc/apache2/maxminddb-module/mod_maxminddb.so
MMLOAD
chmod 644 /home/wpuser/wp/apache-mods/maxminddb.load

echo "Fetching GeoLite2-Country database…"
HTTP_CODE=$(curl -sS -o /tmp/geolite2-country.tar.gz -w '%{http_code}' \
  -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" \
  'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz')
if [ "$HTTP_CODE" != "200" ]; then
  echo "FATAL: GeoLite2 download failed — HTTP ${HTTP_CODE}."
  case "$HTTP_CODE" in
    401) echo "  401 = wrong MAXMIND_ACCOUNT_ID / MAXMIND_LICENSE_KEY." ;;
    403) echo "  403 = credentials valid, but this key isn't permitted to download GeoLite2." ;;
    *)   echo "  Check outbound access to download.maxmind.com from this host." ;;
  esac
  rm -f /tmp/geolite2-country.tar.gz
  exit 1
fi
mkdir -p /tmp/geolite-extract
tar xzf /tmp/geolite2-country.tar.gz -C /tmp/geolite-extract --strip-components=1
find /tmp/geolite-extract -name '*.mmdb' -exec cp {} /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb \;
rm -rf /tmp/geolite-extract /tmp/geolite2-country.tar.gz
if [ ! -s /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb ]; then
  echo "FATAL: download succeeded but no .mmdb file was extracted."
  exit 1
fi
chmod 644 /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb
echo "GeoLite2-Country.mmdb ready ($(du -h /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb | cut -f1))"

if [ "${GEOIP_MODE}" = "whitelist" ]; then
  GEOIP_CC_PATTERN=$(echo "${GEOIP_WHITELIST}" | tr -d ' ' | tr ',' '|')
  GEOIP_REQUIRE_LINE="    Require env AllowCountry"
  GEOIP_SETENV_LINE="SetEnvIf MM_COUNTRY_CODE \"^(${GEOIP_CC_PATTERN})\$\" AllowCountry"
else
  GEOIP_CC_PATTERN=$(echo "${GEOIP_BLOCKLIST}" | tr -d ' ' | tr ',' '|')
  GEOIP_REQUIRE_LINE="    Require not env BlockCountry"
  GEOIP_SETENV_LINE="SetEnvIf MM_COUNTRY_CODE \"^(${GEOIP_CC_PATTERN})\$\" BlockCountry"
fi

cat > /home/wpuser/wp/apache-conf/geoip.conf << GEOIPCONF
# GeoIP country filtering — generated by wp-geoip-setup.sh
# Mode: ${GEOIP_MODE}   Countries: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}
# Database refreshed weekly via host cron (Wed 06:00 UTC).
<IfModule maxminddb_module>
    MaxMindDBEnable On
    MaxMindDBFile COUNTRY_DB /usr/share/GeoIP/GeoLite2-Country.mmdb
    MaxMindDBEnv MM_COUNTRY_CODE COUNTRY_DB/country/iso_code

    ${GEOIP_SETENV_LINE}
    <RequireAll>
        Require env MM_COUNTRY_CODE
${GEOIP_REQUIRE_LINE}
    </RequireAll>
</IfModule>
GEOIPCONF
chmod 644 /home/wpuser/wp/apache-conf/geoip.conf
echo "geoip.conf written (${GEOIP_MODE}: ${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})"

WEB_CHECK_PORT=80

echo "Recreating WordPress container with GeoIP module + database mounted…"
podman rm -f wordpress >/dev/null 2>&1 || true
podman run -d \
  --name wordpress --network wp-front --ip 10.89.10.3 -p 80:80 --restart always \
  --label io.containers.autoupdate=image \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
  --cap-add DAC_OVERRIDE --cap-add FOWNER \
  --security-opt no-new-privileges:true \
  --pids-limit 200 --memory=768m --cpu-shares=512 \
  --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
  --env-file /etc/wordpress/env \
  -e WORDPRESS_DB_HOST=mariadb:3306 \
  -e WORDPRESS_DEBUG="" \
  --add-host "mariadb:10.89.20.2" \
  -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
  -v /home/wpuser/wp/html:/var/www/html \
  -v /home/wpuser/wp/logs:/var/log/apache2 \
  -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
  -v /home/wpuser/wp/apache-conf/geoip.conf:/etc/apache2/conf-enabled/geoip.conf:ro \
  -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
  -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
  -v /home/wpuser/wp/apache-mods/maxminddb.load:/etc/apache2/mods-enabled/maxminddb.load:ro \
  -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
  -v /home/wpuser/wp/geoip-db:/usr/share/GeoIP:ro \
  "${GEOIP_IMG_TAG}"
podman network connect --ip 10.89.20.3 wp-db wordpress
sed -i "s|WP_IMAGE=.*|WP_IMAGE=\"${GEOIP_IMG_TAG}\"|" /etc/init.d/wp-container 2>/dev/null || true
sed -i "s|^PINNED_WP_VER=.*|PINNED_WP_VER=\"geoip-$(echo "${GEOIP_IMG_TAG}" | sed 's|.*:||')\"|" /usr/local/bin/update.sh 2>/dev/null || true

sleep 5
PRUN exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
# BUG FIX (v7-6g): this used to be a bare `wget -qO-` check, which passes on
# a DB-connection-error page or a PHP fatal-error page just as readily as on
# a working site — meaningless right after swapping to a newly-built GeoIP
# image, exactly the moment a broken mod_maxminddb build or a bad mount is
# most likely to surface. Use the same full health check (HTTP + PHP + DB
# name resolution + DB auth + a real SELECT 1) as the rest of the script,
# falling back to the old bare check only if wp-health-check.sh is somehow
# missing (e.g. this script run standalone on a VM provisioned before v7-6g).
echo "Validating GeoIP-enabled WordPress health (HTTP + PHP + DB name resolution + DB auth + real query)…"
GEOIP_WP_READY=0
for i in $(seq 1 12); do
  if [ -x /usr/local/bin/wp-health-check.sh ]; then
    if /usr/local/bin/wp-health-check.sh wordpress "${WEB_CHECK_PORT}"; then
      GEOIP_WP_READY=1; break
    fi
  else
    wget -qO- "http://127.0.0.1:${WEB_CHECK_PORT}/" >/dev/null 2>&1 && { GEOIP_WP_READY=1; break; }
  fi
  sleep 5
done
if [ "$GEOIP_WP_READY" = "1" ]; then
  echo "WordPress responding and healthy with GeoIP active"
else
  echo "WARNING: WordPress did not pass full health validation with GeoIP active — check: podman logs wordpress"
fi

grep -q "GeoLite2-Country database refresh" /etc/crontabs/root 2>/dev/null || cat >> /etc/crontabs/root << GEOCRON
# Weekly GeoLite2-Country database refresh (Wednesday 06:00 UTC)
0 6 * * 3 curl -fsSL -u "${MAXMIND_ACCOUNT_ID}:${MAXMIND_LICENSE_KEY}" 'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz' -o /tmp/geolite-refresh.tar.gz && mkdir -p /tmp/geolite-refresh && tar xzf /tmp/geolite-refresh.tar.gz -C /tmp/geolite-refresh --strip-components=1 && find /tmp/geolite-refresh -name '*.mmdb' -exec cp {} /home/wpuser/wp/geoip-db/GeoLite2-Country.mmdb \; && rm -rf /tmp/geolite-refresh /tmp/geolite-refresh.tar.gz && logger -t geoip-update "GeoLite2-Country refreshed"
GEOCRON

echo "=== wp-geoip-setup.sh done — GeoIP ${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST}) active ==="
WPGEOSETUP
chmod +x /usr/local/bin/wp-geoip-setup.sh
ok "wp-geoip-setup.sh installed — reusable, rerunnable anytime with no reboot needed"
ok "  Retry after fixing creds: /usr/local/bin/wp-geoip-setup.sh   then: tail -40 /var/log/wp-geoip.log"

if [ "${GEOIP_ENABLED:-0}" = "1" ] && [ -n "${MAXMIND_ACCOUNT_ID}" ] && [ -n "${MAXMIND_LICENSE_KEY}" ]; then
  ts "GeoIP country filtering — building mod_maxminddb image layer"
  if /usr/local/bin/wp-geoip-setup.sh; then
    ok "GeoIP filtering active — see /var/log/wp-geoip.log for details"
    # Reflect the new pinned image tag for the rest of THIS install run too
    # (later heredocs below substitute ${WP_IMAGE} at write time).
    WP_IMAGE=$(PRUN inspect wordpress --format '{{.Config.Image}}' 2>/dev/null || echo "$WP_IMAGE")
  else
    warn "GeoIP setup failed — full detail in /var/log/wp-geoip.log"
    warn "  Fix credentials/network, then re-run: /usr/local/bin/wp-geoip-setup.sh"
  fi
elif [ "${GEOIP_ENABLED:-0}" = "1" ]; then
  warn "GeoIP was enabled but MaxMind credentials are missing — skipping GeoIP setup"
fi

ts "Creating mariadb-container service"
cat > /etc/init.d/mariadb-container << ORCSVC_DB
#!/sbin/openrc-run
name="mariadb-container"
description="MariaDB for WordPress (rootful Podman, internal wp-db)"
# Install-time snapshot — used only as a fallback if /etc/wp-install/
# pinned.env can't be read when this service needs to recreate the
# container from scratch (see start(), below).
DB_IMAGE="${DB_IMAGE}"

depend() {
  need net
  after sysfs qemu-guest-agent
}

start() {
  ebegin "Starting MariaDB"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  lsmod | grep -q '^overlay' || modprobe overlay 2>/dev/null || true
  lsmod | grep -q '^fuse'    || modprobe fuse    2>/dev/null || true
  if [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \\
     && [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  podman network exists wp-db 2>/dev/null || podman network create --internal --subnet 10.89.20.0/24 --gateway 10.89.20.1 wp-db 2>/dev/null || true
  if podman container exists mariadb 2>/dev/null; then
    podman start mariadb >/dev/null 2>&1
  else
    podman rm -f mariadb 2>/dev/null || true
    # Prefer the live pin over the install-time DB_IMAGE snapshot above:
    # update.sh keeps /etc/wp-install/pinned.env current after every update
    # but (by design, under the new pinned.env model) no longer rewrites
    # this file's baked-in DB_IMAGE the way older versions did.
    _DB_RUN_IMAGE="\$DB_IMAGE"
    if [ -f /etc/wp-install/pinned.env ]; then
      . /etc/wp-install/pinned.env
      [ -n "\$DB_DIGEST" ] && _DB_RUN_IMAGE="docker.io/mariadb@\${DB_DIGEST}"
    fi
    podman run -d --name mariadb --network wp-db --ip 10.89.20.2 --restart always \\
      --label io.containers.autoupdate=image \\
      --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add DAC_OVERRIDE --cap-add FOWNER \\
      --security-opt no-new-privileges:true \\
      --tmpfs /tmp:size=32M,noexec,nosuid,nodev \\
      --pids-limit 100 --memory=512m --cpu-shares=512 \\
      --env-file /etc/wordpress/env \\
      -v /home/wpuser/wp/mysql:/var/lib/mysql \\
      -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \\
      --health-cmd "healthcheck.sh --connect --innodb_initialized" \\
      --health-interval 5s --health-timeout 5s --health-retries 24 \\
      --health-start-period 30s \\
      "\$_DB_RUN_IMAGE" >/dev/null 2>&1
  fi
  eend \$?
}

stop() {
  ebegin "Stopping MariaDB"
  podman stop mariadb >/dev/null 2>&1
  eend \$?
}
ORCSVC_DB
chmod +x /etc/init.d/mariadb-container
rc-update add mariadb-container default 2>/dev/null || true
ok "mariadb-container service registered"

# ── OpenRC: wp-container ──────────────────────────────────────────────────────
ts "Creating wp-container service"
# Determine remoteip volume mounts for the service script
# headers.load is always mounted (mod_headers not pre-enabled in WP image).
# remoteip.load is NOT mounted (already pre-enabled in WP image — would warn).
# remoteip.conf only mounted if a trusted proxy was configured (file exists).
SVC_HEADERS_VOL='-v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw'
SVC_REMOTEIP_VOLS=''
if [ -f /home/wpuser/wp/apache-mods/remoteip.conf ]; then
  SVC_REMOTEIP_VOLS='\\
      -v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro'
fi

cat > /etc/init.d/wp-container << ORCSVC_WP
#!/sbin/openrc-run
name="wp-container"
description="WordPress Apache (rootful Podman, wp-front, port 80)"
# Install-time snapshot — used only as a fallback if /etc/wp-install/
# pinned.env can't be read when this service needs to recreate the
# container from scratch (see start(), below).
WP_IMAGE="${WP_IMAGE}"

depend() {
  need net mariadb-container
  after sysfs mariadb-container
}

start() {
  ebegin "Starting WordPress"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  lsmod | grep -q '^overlay' || modprobe overlay 2>/dev/null || true
  lsmod | grep -q '^fuse'    || modprobe fuse    2>/dev/null || true
  if [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \\
     && [ "\$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  if podman container exists wordpress 2>/dev/null; then
    podman start wordpress >/dev/null 2>&1
    # Fix uploads ownership after every start (entrypoint creates dirs as root)
    sleep 3 && podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
  else
    podman rm -f wordpress 2>/dev/null || true
    # Prefer the live pin over the install-time WP_IMAGE snapshot above —
    # same rationale as mariadb-container — but ONLY when WP_IMAGE isn't
    # already a locally-built GeoIP image (localhost/wordpress-geoip:...):
    # a GeoIP layer has no upstream registry digest of its own to
    # reconstruct from pinned.env (WP_DIGEST there is always the upstream
    # wordpress image, not the local GeoIP build). Recreating from the
    # existing GeoIP tag as-is is still correct here; re-run
    # wp-geoip-setup.sh afterwards if you want it rebuilt on a newer base.
    _WP_RUN_IMAGE="\$WP_IMAGE"
    case "\$WP_IMAGE" in
      localhost/wordpress-geoip:*) : ;;
      *)
        if [ -f /etc/wp-install/pinned.env ]; then
          . /etc/wp-install/pinned.env
          [ -n "\$WP_DIGEST" ] && _WP_RUN_IMAGE="docker.io/wordpress@\${WP_DIGEST}"
        fi
        ;;
    esac
    podman run -d --name wordpress --network wp-front --ip 10.89.10.3 -p 80:80 --restart always \\
      --label io.containers.autoupdate=image \\
      --cap-drop ALL --cap-add NET_BIND_SERVICE \\
      --cap-add SETUID --cap-add SETGID --cap-add CHOWN \\
      --cap-add DAC_OVERRIDE --cap-add FOWNER \\
      --security-opt no-new-privileges:true \\
      --pids-limit 200 --memory=768m --cpu-shares=512 \\
      --tmpfs /tmp:size=64M,noexec,nosuid,nodev \\
      --env-file /etc/wordpress/env \\
      -e WORDPRESS_DB_HOST=mariadb:3306 \\
      -e WORDPRESS_DEBUG="" \\
      --add-host "mariadb:10.89.20.2" \\
      -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \\
      -v /home/wpuser/wp/html:/var/www/html \\
      -v /home/wpuser/wp/logs:/var/log/apache2 \\
      -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \\
      -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \\
      ${SVC_HEADERS_VOL}${SVC_REMOTEIP_VOLS} \\
      "\$_WP_RUN_IMAGE" >/dev/null 2>&1
    podman network connect --ip 10.89.20.3 wp-db wordpress >/dev/null 2>&1 || true
  fi
  eend \$?
}

stop() {
  ebegin "Stopping WordPress"
  podman stop wordpress >/dev/null 2>&1
  eend \$?
}
ORCSVC_WP
chmod +x /etc/init.d/wp-container
rc-update add wp-container default 2>/dev/null || true
ok "wp-container service registered"

# ── WP-Cron runner ─────────────────────────────────────────────────────────────
cat > /usr/local/bin/wp-cron-run.sh << 'WPCRON'
#!/bin/sh
# WordPress system cron — runs wp-cron.php inside the WordPress container.
podman exec wordpress php /var/www/html/wp-cron.php
WPCRON
chmod +x /usr/local/bin/wp-cron-run.sh
ok "wp-cron-run.sh installed"

# ── Update script ─────────────────────────────────────────────────────────────
ts "Installing update script"
cat > /usr/local/bin/update.sh << 'UPDSCRIPT'
#!/bin/sh
# =============================================================================
# update.sh — WordPress VM update utility
# Usage: update.sh [check|status|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all|trivy]
#
# INTEGRATION NOTES (read before dropping this in):
#  - Rootful only. No ROOTLESS_MODE, no PRUN dispatch wrapper — every call is
#    a plain `podman ...`. If your install script still writes ROOTLESS_MODE
#    into /etc/wp-install/vars.sh that's harmless; it's just never read here.
#  - Assumes container names wordpress / mariadb / crowdsec, and the
#    network-segmented layout from the v7-6/v7-6c line: wp-front (public,
#    WordPress's egress + published port) and wp-db (--internal,
#    WordPress+MariaDB only, static MariaDB address 10.89.20.2). If your
#    main script still uses a single flat wp-net, the two spots that
#    reference wp-front/wp-db/10.89.20.2 (marked below) are the only ones
#    that need adjusting to match.
#  - Reads /etc/wp-install/vars.sh for USE_DIGEST_PINNING and GEOIP_ENABLED
#    (same file your installer already writes) and reads/writes a new
#    /etc/wp-install/pinned.env for per-component pinned tag+digest — see
#    the PINNED STATE note below. Pair this file with the companion
#    installer-side snippet (digest-pinning + Skopeo block) so pinned.env
#    exists from first boot; if it doesn't exist yet, this script bootstraps
#    it from whatever's currently running the first time it's invoked.
#  - Container-recreation commands (the actual `podman run ...` blocks in
#    do_wp_update/do_db_update/do_cs_update) mirror the flags your install
#    script should already be using to create these containers the first
#    time (caps, mounts, env-file, etc.). If your install script customizes
#    any of that, mirror the same customization here or the recreated
#    container will drift from the original.
#  - `update.sh wp` validates a freshly pulled WordPress image on a
#    throwaway "wordpress-candidate" container bound to 127.0.0.1:18080
#    (WP_CANDIDATE_PORT, defined below) — using the same wp-health-check.sh
#    depth as every other health-check site in this script — before it
#    ever touches the production container on :80. Production is only
#    renamed and stopped once that candidate passes. Needs 127.0.0.1:18080
#    free on the VM; change WP_CANDIDATE_PORT if that's already in use for
#    something else.
#
# WHAT CHANGED FROM THE PRE-SKOPEO VERSION OF THIS SCRIPT:
#  - `digest-check` (and therefore a bare `update.sh`/`update.sh check`)
#    used to `podman pull` WordPress, MariaDB, AND CrowdSec on every single
#    invocation just to see whether the registry had republished anything
#    under the same tag — 500 MB-1 GB+ downloaded to answer "did anything
#    change?", every time, even when the answer was no. Skopeo's
#    `inspect docker://ref` asks the registry's manifest endpoint directly
#    (a few KB, no layer data) and reports the digest currently published
#    for a tag without pulling anything. Every digest check below tries
#    Skopeo first; a `podman pull` only happens once a digest is actually
#    going to be used — because it's new, or because Skopeo itself failed,
#    in which case this falls back to pulling by tag and asking Podman what
#    it resolved (the old method — still correct, just back to the old
#    bandwidth cost for that one check).
#  - The old version derived "what tag/digest is currently pinned" by
#    sed-parsing it back out of the running container's own
#    `{{.Config.Image}}` string, which only worked because a pinned
#    reference still had a visible tag in it (`repo:tag@sha256:digest`) —
#    itself dependent on a runtime test of whether this Podman accepted a
#    combined tag+digest reference at all. Every pull below is now a plain
#    `repo@sha256:digest` (no tag, no ambiguity, no version-dependent
#    combined-reference test needed), and the tag is tracked explicitly in
#    /etc/wp-install/pinned.env instead of being re-derived from a string
#    that may no longer contain it.
#  - A bare `update.sh` / `update.sh check` / `update.sh status` is now
#    READ-ONLY: it reports what's running, what's pinned, and whether the
#    registry has anything newer (Skopeo only — no pulls, no prompts).
#    `update.sh all` is the explicit "update everything" command (unchanged
#    otherwise — each component still asks before touching anything).
#    `update.sh digest-check` still exists as a shortcut for "refresh
#    wp/db/crowdsec if the registry has anything newer, skip the OS package
#    prompt" — it now shares the same Skopeo-first check the wp/db/crowdsec
#    update paths use directly, instead of a separate implementation that
#    used to re-pull everything just to compare.
# =============================================================================
set -e

# Fallback target tags — used only if /etc/wp-install/pinned.env doesn't
# exist yet, or is missing an entry for a component (fresh VM never
# updated through this script, or the file was lost). Once pinned.env has
# a value for a component, THAT value is authoritative, not this constant.
PINNED_WP_VER="6.9.4-php8.3-apache"
PINNED_DB_VER="11.4"
PINNED_CS_VER="v1.7.8"
WP_REGISTRY="docker.io/wordpress"
DB_REGISTRY="docker.io/mariadb"
CS_REGISTRY="docker.io/crowdsecurity/crowdsec"

# Loopback-only port do_wp_update() uses to validate a freshly pulled
# WordPress image BEFORE the production container on host port 80 is ever
# touched — see the main script's WORDPRESS UPDATE CUTOVER header note
# (item 40) for the full rationale. Change this only if something else on
# the VM already binds it.
WP_CANDIDATE_PORT="18080"

# MariaDB's bind-mounted data directory, and where do_db_update() keeps a
# pre-update filesystem snapshot of it before the new image ever touches
# the real thing — see the v7-9 header notes (item 41b) for the full
# rationale. Both live on the VM's single root filesystem, same as
# everything else this script writes.
DB_DATA_DIR="/home/wpuser/wp/mysql"
DB_SNAPSHOT_DIR="/home/wpuser/wp/mysql-preupdate-snapshot"

[ "$(id -u)" -eq 0 ] || { echo "ERROR: Must run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"

# ── Image reference validation (v7-6d, carried forward) ────────────────────
# validate_image_tag: closes a gap flagged in review — the VER argument to
# `update.sh wp|db|crowdsec [VER]` used to flow straight into an image
# reference with no validation of its own, relying entirely on podman's own
# parser to reject anything malformed. Grammar matches Docker/OCI tag rules:
# starts with [A-Za-z0-9_], then up to 127 more of [A-Za-z0-9_.-].
validate_image_tag() {
  _vit_tag="$1"
  if [ -z "$_vit_tag" ]; then
    echo "ERROR: empty version/tag supplied" >&2
    return 1
  fi
  if [ "${#_vit_tag}" -gt 128 ]; then
    echo "ERROR: '${_vit_tag}' exceeds the 128-character tag limit" >&2
    return 1
  fi
  case "$_vit_tag" in
    [A-Za-z0-9_]*) ;;
    *) echo "ERROR: '${_vit_tag}' must start with a letter, digit, or underscore" >&2; return 1 ;;
  esac
  case "$_vit_tag" in
    *[!A-Za-z0-9._-]*)
      echo "ERROR: '${_vit_tag}' contains characters other than A-Z a-z 0-9 . _ -" >&2
      return 1 ;;
  esac
  return 0
}

# validate_digest_ref: sanity-checks a "sha256:<64 lowercase hex>" digest, or
# a full "repo[:tag]@sha256:<64 hex>" reference, before anything trusts it.
validate_digest_ref() {
  _vdr_ref="$1"
  case "$_vdr_ref" in
    *@sha256:*) _vdr_digest="${_vdr_ref##*@sha256:}" ;;
    sha256:*)   _vdr_digest="${_vdr_ref#sha256:}" ;;
    *) echo "ERROR: '${_vdr_ref}' has no sha256: digest" >&2; return 1 ;;
  esac
  if [ "${#_vdr_digest}" -ne 64 ]; then
    echo "ERROR: '${_vdr_ref}' digest is not 64 characters" >&2
    return 1
  fi
  case "$_vdr_digest" in
    *[!0-9a-f]*)
      echo "ERROR: '${_vdr_ref}' digest is not lowercase hex" >&2
      return 1 ;;
  esac
  return 0
}

cd /tmp

DIGEST_PIN_LOG="/var/log/wp-digest-pinning.log"

# ── PINNED STATE ────────────────────────────────────────────────────────────
# /etc/wp-install/pinned.env is the single source of truth for "what tag and
# digest are we currently pinned to" per component — written by the
# installer-side Skopeo/digest-pinning snippet at install time, and kept
# current here after every successful update. Deliberately NOT re-derived
# from the running container's image string on every run (see header note).
WP_TAG="" WP_DIGEST="" DB_TAG="" DB_DIGEST="" CS_TAG="" CS_DIGEST=""
# shellcheck disable=SC1091
[ -f /etc/wp-install/pinned.env ] && . /etc/wp-install/pinned.env

_save_pinned() {
  mkdir -p /etc/wp-install
  cat > /etc/wp-install/pinned.env << PINNEDENV
# WordPress VM — pinned image tag + digest per component.
# Written by the installer's digest-pinning snippet; kept current by
# update.sh after every successful update. Do not edit by hand while
# update.sh might be running.
WP_TAG="${WP_TAG}"
WP_DIGEST="${WP_DIGEST}"
DB_TAG="${DB_TAG}"
DB_DIGEST="${DB_DIGEST}"
CS_TAG="${CS_TAG}"
CS_DIGEST="${CS_DIGEST}"
PINNEDENV
  chmod 600 /etc/wp-install/pinned.env 2>/dev/null || true
}

# Running-container inspection — status display and GeoIP detection only.
# NOT used for version comparisons (see PINNED STATE above).
RUNNING_WP_RAW=$(podman inspect wordpress --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_DB_RAW=$(podman inspect mariadb   --format "{{.Config.Image}}" 2>/dev/null || true)
RUNNING_CS_RAW=$(podman inspect crowdsec  --format "{{.Config.Image}}" 2>/dev/null || true)
WP_IS_GEOIP=0
case "$RUNNING_WP_RAW" in localhost/wordpress-geoip:*) WP_IS_GEOIP=1 ;; esac

# Bootstrap pinned.env the first time this script runs on a VM that doesn't
# have one yet (upgraded from an older update.sh, or the file was lost):
# best-effort reconstruct tag/digest from whatever's actually running right
# now, then persist it so every run after this one uses the fast path.
_bootstrap_one() {
  local raw="$1" registry="$2"
  echo "$raw" | sed -e 's|^localhost/wordpress-geoip:||' -e "s|^${registry}:||" -e 's|@sha256:.*||'
}
_BOOTSTRAPPED=0
if [ -z "$WP_TAG" ] && [ -z "$WP_DIGEST" ] && [ -n "$RUNNING_WP_RAW" ]; then
  WP_TAG=$(_bootstrap_one "$RUNNING_WP_RAW" "$WP_REGISTRY")
  WP_DIGEST=$(echo "$RUNNING_WP_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$WP_TAG" ] && _BOOTSTRAPPED=1
fi
if [ -z "$DB_TAG" ] && [ -z "$DB_DIGEST" ] && [ -n "$RUNNING_DB_RAW" ]; then
  DB_TAG=$(_bootstrap_one "$RUNNING_DB_RAW" "$DB_REGISTRY")
  DB_DIGEST=$(echo "$RUNNING_DB_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$DB_TAG" ] && _BOOTSTRAPPED=1
fi
if [ -z "$CS_TAG" ] && [ -z "$CS_DIGEST" ] && [ -n "$RUNNING_CS_RAW" ]; then
  CS_TAG=$(_bootstrap_one "$RUNNING_CS_RAW" "$CS_REGISTRY")
  CS_DIGEST=$(echo "$RUNNING_CS_RAW" | grep -oE 'sha256:[0-9a-f]{64}' || true)
  [ -n "$CS_TAG" ] && _BOOTSTRAPPED=1
fi
[ "$_BOOTSTRAPPED" = "1" ] && _save_pinned

ask_yn() { printf "%s [y/N]: " "$1"; read ans; case "$ans" in [Yy]*) return 0;; *) return 1;; esac; }

# ── Container-state preflight — stop suppressing critical Podman errors ────
# PRODUCTION SAFETY FIX (v7-6k): every "swap in a replacement container"
# path in this script hid its `podman rename <live> <live>-old` behind
# `2>/dev/null || true` (WordPress's forward swap), and every rollback swap
# (`podman rename <live>-old <live>` for WordPress, MariaDB, AND CrowdSec)
# discarded its result the same way. That meant a rename failure — source
# container missing, a stale *-old container left over from a previous
# crashed/interrupted update, or Podman itself in an inconsistent state —
# was silently swallowed and the script carried on as if nothing had
# happened.
#
# The concrete failure this caused in do_wp_update(): if
# `podman rename wordpress wordpress-old` silently failed, "wordpress" kept
# its original name, so the following `podman run -d --name wordpress ...`
# then failed too (a name collision) — a failure that WAS checked, so
# control fell into the "container start failed — rolled back" branch.
# That branch's first line was `podman rm -f wordpress`, deleting the
# still-good, still-running ORIGINAL WordPress container in the mistaken
# belief it was cleaning up a failed new attempt. One suppressed error
# cascaded into deleting a healthy production container.
#
# require_clean_container_state() closes the forward half of this by
# verifying the rename's own preconditions up front instead of discovering
# them via a cascading failure two steps later. Every rename call site below
# — forward swap and rollback swap, across WordPress, MariaDB, and CrowdSec
# — now also checks the rename/start result directly instead of discarding
# it, and prints exactly what needs manual attention when a rollback itself
# fails, since that's the one moment silence is most dangerous: it means the
# site (or the database, or CrowdSec) is down right now and nobody has been
# told.
require_clean_container_state() {
  local current="$1" old_name="$2"
  podman container exists "$current" || {
    echo "✗  Required container '${current}' does not exist — nothing to update. Aborting; nothing was changed." >&2
    return 1
  }
  if podman container exists "$old_name"; then
    echo "✗  Stale container '${old_name}' already exists, left over from a previous" >&2
    echo "   update that didn't finish cleanly (crashed, interrupted, or aborted mid-way)." >&2
    echo "   Refusing to rename over it. Inspect it first, then either restore from it" >&2
    echo "   or remove it once you're sure it's not needed:" >&2
    echo "     podman inspect ${old_name}" >&2
    echo "     podman rm -f ${old_name}" >&2
    return 1
  fi
  return 0
}

# ── Skopeo: remote digest lookup, no image pull ────────────────────────────
# $1 = full tag reference, e.g. docker.io/wordpress:6.9.4-php8.3-apache
# stdout: sha256:<64 hex> on success. Returns 1 on any failure (Skopeo
# missing, network error, unparseable output) — every caller treats that as
# "fall back to the old method", never as fatal.
_skopeo_digest() {
  local ref="$1" out digest
  command -v skopeo >/dev/null 2>&1 || return 1
  out=$(skopeo inspect "docker://${ref}" 2>/dev/null) || return 1
  digest=$(printf '%s' "$out" \
    | grep -oE '"Digest"[[:space:]]*:[[:space:]]*"sha256:[0-9a-f]{64}"' \
    | grep -oE 'sha256:[0-9a-f]{64}')
  [ -n "$digest" ] || return 1
  printf '%s\n' "$digest"
}
_resolve_digest() {
  local ref="$1" attempt digest
  for attempt in 1 2 3; do
    digest=$(_skopeo_digest "$ref") && [ -n "$digest" ] && { printf '%s\n' "$digest"; return 0; }
    [ "$attempt" -lt 3 ] && sleep 2
  done
  return 1
}

# ── Trivy: container vulnerability scanner ────────────────────────────────
TRIVY_CACHE_DIR="/var/cache/trivy"

setup_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    mkdir -p "${TRIVY_CACHE_DIR}"
    return 0
  fi
  echo "  → Installing Trivy (vulnerability scanner)..."
  mkdir -p "${TRIVY_CACHE_DIR}"
  if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
       trivy >/dev/null 2>&1; then
    echo "  ✔  Trivy installed (apk)"
  else
    apk add --no-cache wget >/dev/null 2>&1 || true
    TRIVY_VER="v0.71.2"
    wget -qO /tmp/trivy-install.sh \
      https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh 2>/dev/null \
    && sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && echo "  ✔  Trivy ${TRIVY_VER} installed (official script)" \
    || { echo "  ⚠  Trivy install failed — scans will be skipped"; return 1; }
    rm -f /tmp/trivy-install.sh
  fi
}

scan_image() {
  local img="$1"
  if ! command -v trivy >/dev/null 2>&1; then
    echo "  ⚠  Trivy not available — skipping vulnerability scan"
    return 0
  fi
  echo "  → Scanning ${img} for HIGH/CRITICAL vulnerabilities (cache: ${TRIVY_CACHE_DIR})..."
  if trivy image \
       --cache-dir "${TRIVY_CACHE_DIR}" \
       --exit-code 1 \
       --severity HIGH,CRITICAL \
       --no-progress \
       --quiet \
       "${img}" 2>/dev/null; then
    echo "  ✔  No HIGH/CRITICAL vulnerabilities found"
    return 0
  else
    echo "  ⚠  HIGH or CRITICAL vulnerabilities detected in ${img}"
    echo "     Review the findings above before updating."
    ask_yn "  Proceed with update anyway? (not recommended)" || {
      echo "  Update aborted. Check for a newer image version."
      return 1
    }
    return 0
  fi
}

do_os_update() {
  echo "── Alpine OS ──────────────────────────────────────────────────"
  echo "  Current: Alpine $(cat /etc/alpine-release 2>/dev/null)"
  ask_yn "Update Alpine OS packages?" && { apk update; apk upgrade --no-cache; echo "✔  Done"; } \
    || echo "   Skipped."
}

# ── Shared digest-aware check ───────────────────────────────────────────────
# Resolves the target's current digest via Skopeo BEFORE deciding whether
# there's anything to do. Sets three variables the caller reads immediately
# after: _UPD_ACTION (skip|refresh|bump), _UPD_PULL_REF (what to pull),
# _UPD_DIGEST (resolved digest, or empty if Skopeo couldn't resolve one —
# in which case the caller falls back to comparing tags only).
_check_component() {
  local registry="$1" running_tag="$2" running_digest="$3" target_ver="$4"
  local target_img="${registry}:${target_ver}"
  _UPD_PULL_REF="$target_img"
  _UPD_DIGEST=""
  if [ "${USE_DIGEST_PINNING}" = "1" ]; then
    echo "  → Checking ${target_img} against the registry (Skopeo, no download)…"
    _UPD_DIGEST=$(_resolve_digest "$target_img") || _UPD_DIGEST=""
    if [ -n "$_UPD_DIGEST" ]; then
      _UPD_PULL_REF="${registry}@${_UPD_DIGEST}"
      if [ "$target_ver" = "$running_tag" ] && [ "$_UPD_DIGEST" = "$running_digest" ]; then
        _UPD_ACTION="skip"; return 0
      fi
      if [ "$target_ver" = "$running_tag" ]; then _UPD_ACTION="refresh"; else _UPD_ACTION="bump"; fi
      return 0
    fi
    echo "  ⚠  Skopeo digest lookup failed — comparing by tag only this run."
  fi
  if [ "$target_ver" = "$running_tag" ]; then _UPD_ACTION="skip"; else _UPD_ACTION="bump"; fi
}

do_wp_update() {
  local target_ver="${1:-${WP_TAG:-$PINNED_WP_VER}}"
  echo "── WordPress ──────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${WP_TAG:-none}  digest=${WP_DIGEST:-none}"
  echo "  Target  : ${WP_REGISTRY}:${target_ver}"
  echo "  Data    : /home/wpuser/wp/html (bind-mount — never removed)"

  _check_component "$WP_REGISTRY" "$WP_TAG" "$WP_DIGEST" "$target_ver"
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it?" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update WordPress to ${target_ver}?" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 40): fail fast, before the pull + candidate-boot +
  # candidate-validate sequence below even begins, if wordpress-old already
  # exists (a stale leftover from an update that crashed/was interrupted
  # before cleanup) or wordpress itself is missing. Same rationale item 39
  # gives for MariaDB/CrowdSec: this used not to apply here (nothing
  # substantial happened before do_wp_update()'s one rename point), but the
  # candidate step below now means a full image pull plus a candidate
  # container boot/validate cycle happens first — worth not wasting if the
  # rename was always going to be refused. The check immediately before the
  # actual cutover rename, further down, stays in place too, catching state
  # that changed during the pull/candidate window — an operator manually
  # intervening mid-update, for instance.
  require_clean_container_state wordpress wordpress-old || return 1

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${WP_REGISTRY}@${_UPD_DIGEST}"
  fi

  RI_VOLS=""
  [ -f /home/wpuser/wp/apache-mods/remoteip.conf ] && \
    RI_VOLS="-v /home/wpuser/wp/apache-mods/remoteip.conf:/etc/apache2/mods-enabled/remoteip.conf:ro"

  # ── CANDIDATE: prove the pulled image works BEFORE production is touched
  # (item 40 — merged in from a third parallel line off v7-6f). See the
  # WORDPRESS UPDATE CUTOVER header note for the full history: starting the
  # new "wordpress" straight on -p 80:80 while the old one was merely
  # renamed (still running, still holding port 80) was a structural
  # guarantee of failure, not an occasional race. The pulled image is
  # proven out here instead, on a throwaway container bound ONLY to
  # loopback:WP_CANDIDATE_PORT, with production left completely alone.
  local WP_CANDIDATE="wordpress-candidate"
  local candidate_ok=0 i
  podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true

  echo "  → Starting a validation candidate on 127.0.0.1:${WP_CANDIDATE_PORT} (production stays up on :80)…"
  # No --ip on wp-front (or on the wp-db connect below): production's own
  # wordpress container is still fully up and may hold a fixed address on
  # either network — the candidate must not contend for it. netavark
  # assigns the candidate a free address on both instead.
  # shellcheck disable=SC2086
  if podman run -d --name "$WP_CANDIDATE" --network wp-front \
    -p "127.0.0.1:${WP_CANDIDATE_PORT}:80" --restart no \
    --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 200 --memory=768m --cpu-shares=512 \
    --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -e WORDPRESS_DEBUG="" \
    --add-host "mariadb:10.89.20.2" \
    -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
    -v /home/wpuser/wp/html:/var/www/html \
    -v /home/wpuser/wp/logs:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
    ${RI_VOLS} \
    "${_UPD_PULL_REF}"; then
    podman network connect wp-db "$WP_CANDIDATE" >/dev/null 2>&1 || true
  else
    echo "✗  Candidate failed to start — production WordPress was never touched."
    podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true
    return 1
  fi

  # PRODUCTION SAFETY (item 40): the candidate is validated with the same
  # wp-health-check.sh depth (HTTP + PHP execution + mariadb DNS + a real
  # WordPress-credential SELECT 1) used at the final cutover check below and
  # every other health-check call site in this script, instead of a bare
  # HTTP-plus-raw-mysqli check — a candidate that merely answers HTTP but
  # can't actually run PHP or reach the database would otherwise be waved
  # through here. Falls back to the older bare check only if
  # wp-health-check.sh is somehow missing.
  echo "  → Validating candidate (HTTP + PHP + DB name resolution + DB auth + real query)…"
  for i in $(seq 1 12); do
    if [ -x /usr/local/bin/wp-health-check.sh ]; then
      if /usr/local/bin/wp-health-check.sh "$WP_CANDIDATE" "${WP_CANDIDATE_PORT}"; then
        candidate_ok=1; break
      fi
    else
      if wget -qO- "http://127.0.0.1:${WP_CANDIDATE_PORT}/" >/dev/null 2>&1; then
        podman exec --user www-data "$WP_CANDIDATE" php -r \
          '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"));exit($c?0:1);' \
          >/dev/null 2>&1 && { candidate_ok=1; break; }
      fi
    fi
    sleep 5
  done

  if [ "$candidate_ok" != "1" ]; then
    echo "✗  Candidate failed validation — production WordPress was never touched."
    echo "   Left running for inspection: podman logs ${WP_CANDIDATE}   (remove with: podman rm -f ${WP_CANDIDATE})"
    return 1
  fi
  podman rm -f "$WP_CANDIDATE" >/dev/null 2>&1 || true
  echo "  ✔  Candidate healthy (HTTP + PHP + DB confirmed) — swapping production to the new image now (brief downtime)…"

  # ── CUTOVER: production is only ever touched from this point on ────────
  # Merges the production-safety line's checked rename/rollback (item 36)
  # with the candidate/cutover line's actual STOP of wordpress-old (item
  # 40) — the piece that was missing before this merge. Renaming alone only
  # frees the NAME "wordpress"; it does not stop the container or release
  # its published port, which is what let the pre-merge code try to start a
  # second container on -p 80:80 while the first was still holding that
  # port, guaranteeing every update attempt would fail (see the WORDPRESS
  # UPDATE CUTOVER header note above for the full history).
  require_clean_container_state wordpress wordpress-old || return 1
  if ! podman rename wordpress wordpress-old; then
    echo "✗  Unable to rename wordpress → wordpress-old — Podman error above. Aborting; production is untouched." >&2
    return 1
  fi
  if ! podman stop --time 15 wordpress-old; then
    echo "✗  wordpress-old would not stop — attempting to restore the 'wordpress' name…" >&2
    if podman rename wordpress-old wordpress; then
      echo "   Restored. The site is NOT down — it's still running as 'wordpress', just" >&2
      echo "   on the previous image. The update did not proceed; investigate why the" >&2
      echo "   container wouldn't stop, then retry." >&2
    else
      echo "✗✗ Could not restore the 'wordpress' name either. The production container" >&2
      echo "   is still running and still serving traffic, but currently named" >&2
      echo "   'wordpress-old'. The site is NOT down, but fix the name before the next" >&2
      echo "   update attempt:" >&2
      echo "     podman rename wordpress-old wordpress" >&2
    fi
    return 1
  fi
  sleep 2

  # No --ip on wp-front: wordpress-old (stopped above, but not yet removed)
  # still holds that address until it's removed below (after the health
  # check passes) — Podman ties an IP reservation to the container's
  # existence, not whether it's currently running. netavark assigns the
  # new container a free address instead.
  # shellcheck disable=SC2086
  if podman run -d --name wordpress --network wp-front -p 80:80 --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --pids-limit 200 --memory=768m --cpu-shares=512 \
    --tmpfs /tmp:size=64M,noexec,nosuid,nodev \
    --env-file /etc/wordpress/env \
    -e WORDPRESS_DB_HOST=mariadb:3306 \
    -e WORDPRESS_DEBUG="" \
    --add-host "mariadb:10.89.20.2" \
    -e WORDPRESS_CONFIG_EXTRA='define("WP_DEBUG",false);define("DISALLOW_FILE_EDIT",true);define("WP_POST_REVISIONS",10);define("WP_AUTO_UPDATE_CORE","minor");define("WP_MEMORY_LIMIT","256M");define("WP_MAX_MEMORY_LIMIT","512M");define("DISABLE_WP_CRON",true);' \
    -v /home/wpuser/wp/html:/var/www/html \
    -v /home/wpuser/wp/logs:/var/log/apache2 \
    -v /home/wpuser/wp/apache-conf/wp-security.conf:/etc/apache2/conf-enabled/wp-security.conf:ro \
    -v /home/wpuser/wp/php-conf/security.ini:/usr/local/etc/php/conf.d/wp-security.ini:ro \
    -v /home/wpuser/wp/apache-mods/headers.load:/etc/apache2/mods-enabled/headers.load:ro \
    -v /home/wpuser/wp/htaccess/.htaccess:/var/www/html/.htaccess:rw \
    ${RI_VOLS} \
    "${_UPD_PULL_REF}"; then

    podman network connect wp-db wordpress 2>/dev/null || true
    # BUG FIX (v7-6g): this was a bare `wget -qO-` check — the single most
    # dangerous place in the whole script for that, since HEALTHY directly
    # gates whether do_wp_update() keeps the new container or rolls back to
    # wordpress-old. A DB-connection-error page or a PHP fatal-error page
    # returns a perfectly normal HTTP response, so the old check could mark
    # a broken update "healthy" and delete the last-known-good container
    # right after. Use the same wp-health-check.sh (HTTP + PHP execution +
    # mariadb DNS + MariaDB auth + a real SELECT 1 through WordPress's own
    # DB env vars) installed by the main provisioning script, with the old
    # bare check only as a last-resort fallback if it's somehow missing.
    HEALTHY=0
    echo "  → Validating new WordPress container health (HTTP + PHP + DB name resolution + DB auth + real query)…"
    for i in $(seq 1 6); do
      if [ -x /usr/local/bin/wp-health-check.sh ]; then
        if /usr/local/bin/wp-health-check.sh wordpress 80; then
          HEALTHY=1; break
        fi
      else
        wget -qO- "http://127.0.0.1:80/" >/dev/null 2>&1 && { HEALTHY=1; break; }
      fi
      sleep 5
    done
    if [ "$HEALTHY" = "1" ]; then
      podman stop wordpress-old 2>/dev/null; podman rm -f wordpress-old 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): a leftover wordpress-old here isn't
      # fatal to THIS update (it already succeeded above), but it now
      # blocks the NEXT one — require_clean_container_state() refuses to
      # rename over a stale *-old container. Surface that now instead of
      # letting the next admin discover it as a confusing abort.
      podman container exists wordpress-old 2>/dev/null \
        && echo "  ⚠  wordpress-old could not be fully removed — clean it up before the next update: podman rm -f wordpress-old" >&2
      sleep 3
      podman exec wordpress chown -R www-data:www-data /var/www/html/wp-content >/dev/null 2>&1 || true
      echo "✔  WordPress base image updated to ${target_ver}"
      WP_TAG="$target_ver"; WP_DIGEST="${_UPD_DIGEST}"
      _save_pinned
      # GeoIP is a locally-built image layered on top of whatever WordPress
      # base is currently running — it has no registry digest of its own to
      # check, so it just gets rebuilt on the new base whenever that base
      # changes. WP_IS_GEOIP reflects whether GeoIP was active BEFORE this
      # update started; GEOIP_ENABLED covers "configured but not yet applied".
      if [ "${WP_IS_GEOIP:-0}" = "1" ] || [ "${GEOIP_ENABLED:-0}" = "1" ]; then
        if [ -x /usr/local/bin/wp-geoip-setup.sh ]; then
          echo "  → GeoIP was active — rebuilding the GeoIP image on the new base…"
          if /usr/local/bin/wp-geoip-setup.sh; then
            echo "  ✔  GeoIP re-applied on the updated WordPress image"
          else
            echo "  ⚠  GeoIP re-apply FAILED — WordPress is updated but GeoIP filtering is now OFF."
            echo "     Check /var/log/wp-geoip.log, then re-run: /usr/local/bin/wp-geoip-setup.sh"
          fi
        else
          echo "  ⚠  GeoIP was active but wp-geoip-setup.sh is missing — GeoIP filtering is now OFF."
        fi
      fi
    else
      echo "✗  Health check failed — rolling back…"
      podman stop wordpress 2>/dev/null; podman rm -f wordpress 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): was `2>/dev/null` on both the rename
      # and the start, discarding the one result that matters most here —
      # this IS the rollback; if it silently fails the site is down with no
      # indication why. Check it and say so loudly.
      if podman rename wordpress-old wordpress && podman start wordpress >/dev/null 2>&1; then
        echo "✗  Rolled back to ${WP_TAG:-previous}."
      else
        echo "✗✗ ROLLBACK FAILED — wordpress-old could not be restored to 'wordpress'" >&2
        echo "   and/or started. The site is DOWN. Manual recovery needed now:" >&2
        echo "     podman ps -a --filter name=wordpress" >&2
        echo "     podman rename wordpress-old wordpress && podman start wordpress" >&2
      fi
      return 1
    fi
  else
    echo "✗  Production container failed to start on :80 — rolling back…"
    podman rm -f wordpress 2>/dev/null
    if podman rename wordpress-old wordpress && podman start wordpress >/dev/null 2>&1; then
      echo "✗  Container start failed — rolled back."
    else
      echo "✗✗ ROLLBACK FAILED — wordpress-old could not be restored to 'wordpress'" >&2
      echo "   and/or started. The site is DOWN. Manual recovery needed now:" >&2
      echo "     podman ps -a --filter name=wordpress" >&2
      echo "     podman rename wordpress-old wordpress && podman start wordpress" >&2
    fi
    return 1
  fi
}

# ── v7-9: MariaDB data-directory snapshot helpers (items 41a/41b/41c) ──────
# Shared by do_db_update() so its normal-failure and rollback paths all use
# the exact same restore logic instead of three near-identical copies — the
# kind of drift item 7/36 already had to clean up once for this same
# function's rename/start error handling.

# _snapshot_space_ok: true if there's enough free space on the filesystem
# backing DB_DATA_DIR to hold a full copy of it. Sized off a live `du` of
# the current data directory, plus 10% and a fixed ~350MB floor that covers
# both copy overhead and the MariaDB image this same update is about to
# pull — both draw on the same VM disk. Checked BEFORE anything is stopped,
# so a too-full disk aborts loudly with zero downtime instead of leaving
# WordPress/MariaDB stopped partway through an update.
_snapshot_space_ok() {
  local data_kb avail_kb need_kb
  data_kb=$(du -sk "$DB_DATA_DIR" 2>/dev/null | awk '{print $1}' || true)
  avail_kb=$(df -Pk "$DB_DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}' || true)
  [ -n "$data_kb" ] && [ -n "$avail_kb" ] || return 1
  need_kb=$(( data_kb + data_kb / 10 + 358400 ))
  [ "$avail_kb" -ge "$need_kb" ]
}

# _data_dir_looks_valid: true if DB_DATA_DIR looks like a real, non-empty
# MariaDB data directory. Exists purely so _db_rollback() never starts
# mariadb-old against a directory that's missing or empty — the official
# MariaDB image auto-initializes a brand-new EMPTY database the instant it
# sees an empty /var/lib/mysql, which would make catastrophic data loss
# look exactly like a clean, healthy rollback.
_data_dir_looks_valid() {
  [ -d "$DB_DATA_DIR" ] || return 1
  [ -d "${DB_DATA_DIR}/mysql" ] || return 1
  [ -n "$(ls -A "$DB_DATA_DIR" 2>/dev/null)" ]
}

# _restore_snapshot: restores DB_DATA_DIR from DB_SNAPSHOT_DIR. Must only be
# called with no container mounting DB_DATA_DIR — do_db_update() always
# stops+removes the failed new "mariadb" before calling this. Uses `mv` (a
# same-filesystem rename), not a copy, so this is fast regardless of
# database size. The failed update's own data is kept alongside
# (timestamped), not deleted, in case it's ever needed for forensics.
_restore_snapshot() {
  if [ ! -d "$DB_SNAPSHOT_DIR" ]; then
    echo "✗✗ No pre-update snapshot found at ${DB_SNAPSHOT_DIR} — nothing to" >&2
    echo "   restore from. ${DB_DATA_DIR} is left exactly as the failed" >&2
    echo "   update left it." >&2
    return 1
  fi
  local failed_dir="${DB_DATA_DIR}.failed-$(date +%Y%m%d-%H%M%S)"
  if ! mv "$DB_DATA_DIR" "$failed_dir" 2>/dev/null; then
    echo "✗✗ Could not move ${DB_DATA_DIR} aside — restore aborted, left untouched." >&2
    return 1
  fi
  if mv "$DB_SNAPSHOT_DIR" "$DB_DATA_DIR" 2>/dev/null; then
    echo "  ✔  Data directory restored from the pre-update snapshot." >&2
    echo "     The failed update's own data was kept for inspection at:" >&2
    echo "       ${failed_dir}" >&2
    echo "     Remove it once you're satisfied it's not needed: rm -rf ${failed_dir}" >&2
    return 0
  fi
  echo "✗✗ Could not move the snapshot into place. Restoring the pre-restore" >&2
  echo "   directory instead so there's SOMETHING there, but this is the" >&2
  echo "   UN-rolled-back state — investigate by hand:" >&2
  echo "     ${DB_DATA_DIR} (put back)  /  snapshot still at ${DB_SNAPSHOT_DIR}  /  also see ${failed_dir}" >&2
  mv "$failed_dir" "$DB_DATA_DIR" 2>/dev/null || true
  return 1
}

# _db_rollback: shared rollback path for do_db_update(), used whether the
# new MariaDB never started, started but failed its own health check, or
# looked healthy but WordPress couldn't actually use it. Tears down the
# failed new "mariadb" (if any), restores the data directory from the
# pre-update snapshot — the new engine may have mutated on-disk state even
# without ever reporting healthy — then restores and restarts mariadb-old
# under the original name, restarts WordPress, and reports the outcome.
# $1 = human-readable reason, used in the opening status line.
#
# Every bare call into this function elsewhere in do_db_update() MUST be
# guarded with `|| true` (e.g. `_db_rollback "reason" || true`) — this
# function always returns 1, and update.sh runs under `set -e`, under which
# an unguarded function call returning non-zero aborts the ENTIRE script
# immediately (confirmed empirically, not assumed), which would skip the
# `return 1` that follows and, from do_digest_check()/`update.sh all`,
# would prevent CrowdSec from ever being checked after a MariaDB failure.
_db_rollback() {
  local reason="$1"
  echo "✗  ${reason} — rolling back…" >&2
  podman stop wordpress >/dev/null 2>&1 || true
  podman stop mariadb   >/dev/null 2>&1 || true
  podman rm -f mariadb  >/dev/null 2>&1 || true
  _restore_snapshot || true
  if ! _data_dir_looks_valid; then
    echo "✗✗ CRITICAL: ${DB_DATA_DIR} does not look like a valid MariaDB data" >&2
    echo "   directory after the restore attempt — refusing to start MariaDB" >&2
    echo "   against it (an empty/missing directory would make the container" >&2
    echo "   silently initialize a brand-new EMPTY database instead of failing" >&2
    echo "   loudly). Manual recovery needed now — inspect before doing anything:" >&2
    echo "     ls -la ${DB_DATA_DIR}" >&2
    echo "     ls -la ${DB_SNAPSHOT_DIR} 2>/dev/null   (pre-update snapshot, if still present)" >&2
    echo "   Logical backup: ${BACKUP_FILE}" >&2
    return 1
  fi
  if podman rename mariadb-old mariadb && podman start mariadb >/dev/null 2>&1; then
    local rb_db_ok=0
    for i in $(seq 1 12); do
      if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
        /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1 && { rb_db_ok=1; break; }
      elif podman exec mariadb sh -c \
        'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
         mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
        rb_db_ok=1; break
      fi
      sleep 5
    done
    if podman start wordpress >/dev/null 2>&1; then
      if [ "$rb_db_ok" = "1" ]; then
        echo "✗  Rolled back to ${DB_TAG:-previous} — data directory restored from the pre-update snapshot." >&2
      else
        echo "✗  Rolled back to ${DB_TAG:-previous}, but the restored MariaDB failed its" >&2
        echo "   own health check — investigate now: mariadb-health-check.sh mariadb" >&2
      fi
    else
      echo "  ⚠  Rolled back to ${DB_TAG:-previous} but WordPress did not restart — start it manually: podman start wordpress" >&2
    fi
    echo "✗  Logical backup: ${BACKUP_FILE}" >&2
    return 1
  fi
  echo "✗✗ ROLLBACK FAILED — mariadb-old could not be restored to 'mariadb'" >&2
  echo "   and/or started. The database is DOWN. Manual recovery needed now:" >&2
  echo "     podman ps -a --filter name=mariadb" >&2
  echo "     podman rename mariadb-old mariadb && podman start mariadb && podman start wordpress" >&2
  echo "   Logical backup: ${BACKUP_FILE}" >&2
  return 1
}

do_db_update() {
  local target_ver="${1:-${DB_TAG:-$PINNED_DB_VER}}"
  echo "── MariaDB ────────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${DB_TAG:-none}  digest=${DB_DIGEST:-none}"
  echo "  Target  : ${DB_REGISTRY}:${target_ver}"
  echo "  Data    : ${DB_DATA_DIR} (bind-mount — never removed)"
  echo "  Rollback: snapshotted to ${DB_SNAPSHOT_DIR} before the swap, removed after a verified success"

  _check_component "$DB_REGISTRY" "$DB_TAG" "$DB_DIGEST" "$target_ver"
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it? (backup + data-directory snapshot taken first)" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update MariaDB to ${target_ver}? (backup + data-directory snapshot taken first)" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 39): fail fast, before the backup/pull/stop sequence below
  # even begins, if mariadb-old already exists (a stale leftover from an
  # update that was interrupted before cleanup) or mariadb itself is
  # missing. Without this, that problem is only discovered much further
  # down, right at the actual rename — by which point a full backup has
  # been taken, the new image pulled, and WordPress AND MariaDB have both
  # already been stopped for nothing. The require_clean_container_state()
  # call right before the rename further down stays in place too, as a
  # second, belt-and-suspenders guard against state changing in the window
  # between this early check and the actual rename attempt.
  require_clean_container_state mariadb mariadb-old || return 1

  # v7-9 (item 41a): mariadb-dump no longer pipes straight into gzip — see
  # the header note for the full rationale. It writes to a plain .sql file
  # first (so its OWN exit status, not gzip's, is what gets checked), the
  # result is checked for size and mariadb-dump's own trailing completion
  # marker, and only THEN is it compressed and the archive integrity-
  # checked with gzip -t.
  BACKUP_FILE="/root/wp-db-backup-$(date +%Y%m%d-%H%M%S).sql.gz"
  BACKUP_RAW="${BACKUP_FILE%.gz}"
  echo "  → Backing up to ${BACKUP_FILE}…"
  BACKUP_OK=0
  if ( umask 077; podman exec mariadb sh -c \
       'exec mariadb-dump --all-databases -uroot -p"$MARIADB_ROOT_PASSWORD"' \
       > "${BACKUP_RAW}" 2> "${BACKUP_RAW}.err" ); then
    if [ -s "${BACKUP_RAW}" ] && tail -c 200 "${BACKUP_RAW}" | grep -q "Dump completed"; then
      if gzip -f "${BACKUP_RAW}" && gzip -t "${BACKUP_FILE}" 2>/dev/null; then
        chmod 600 "${BACKUP_FILE}" 2>/dev/null || true
        BACKUP_OK=1
      else
        echo "✗  Compressing or verifying the backup archive failed." >&2
      fi
    else
      echo "✗  mariadb-dump's output looks incomplete (empty, or missing its own" >&2
      echo "   trailing completion marker) — treating this as a failed backup even" >&2
      echo "   though the command itself exited 0." >&2
    fi
  else
    echo "✗  mariadb-dump exited with an error." >&2
  fi
  if [ "$BACKUP_OK" != "1" ]; then
    if [ -s "${BACKUP_RAW}.err" ]; then
      echo "   mariadb-dump stderr:" >&2
      sed 's/^/     /' "${BACKUP_RAW}.err" >&2 || true
    fi
    rm -f "${BACKUP_RAW}" "${BACKUP_RAW}.err" "${BACKUP_FILE}" 2>/dev/null || true
    echo "✗  Backup failed — aborting. Fix the database before retrying."
    return 1
  fi
  rm -f "${BACKUP_RAW}.err" 2>/dev/null || true
  echo "  ✔  Backup verified (dump completed + archive integrity OK): ${BACKUP_FILE} ($(du -sh "${BACKUP_FILE}" | cut -f1))"

  # v7-9 (item 41b): fail fast — before anything is stopped — if there
  # isn't room for the pre-update data-directory snapshot taken further
  # below. See _snapshot_space_ok()'s own comment for the headroom math.
  echo "  → Checking free disk space for a pre-update data-directory snapshot…"
  if ! _snapshot_space_ok; then
    echo "✗  Not enough free disk space to safely snapshot ${DB_DATA_DIR} before" >&2
    echo "   this update — aborting before touching any running container. Free" >&2
    echo "   up space (or grow the VM disk) and retry. The logical backup above" >&2
    echo "   is still on disk and valid: ${BACKUP_FILE}" >&2
    return 1
  fi

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${DB_REGISTRY}@${_UPD_DIGEST}"
  fi

  echo "  → Stopping WordPress (brief downtime)…"
  if ! podman stop --time 30 wordpress; then
    echo "✗  Unable to stop WordPress — aborting before touching MariaDB."
    return 1
  fi

  # BUG FIX (missing-item #2 — MariaDB old container remains running during
  # replacement): this used to rename mariadb -> mariadb-old WITHOUT
  # stopping it first. `podman rename` does not stop a container, so the
  # old mariadbd process stayed live against /home/wpuser/wp/mysql at the
  # same moment the replacement container below mounts that same directory
  # — two InnoDB instances against one data directory, risking redo-log
  # corruption, data-dictionary corruption, and unrecoverable damage.
  # MariaDB is now stopped cleanly (a longer timeout than WordPress, since
  # InnoDB needs time to flush the buffer pool) before the rename, and the
  # old container's stopped state is verified explicitly afterward rather
  # than assumed.
  echo "  → Stopping MariaDB cleanly before replacement…"
  if ! podman stop --time 60 mariadb; then
    echo "✗  MariaDB did not stop cleanly — aborting update."
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  # PRODUCTION SAFETY FIX (v7-6k): preflight the rename's own preconditions
  # (see require_clean_container_state() above) before attempting it, so a
  # stale mariadb-old from a previous crashed update is reported clearly
  # instead of surfacing as a generic rename failure below.
  require_clean_container_state mariadb mariadb-old || {
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  }

  # v7-9 (item 41b): the actual pre-update snapshot — taken only once
  # MariaDB is confirmed stopped (so it's crash-consistent) and BEFORE the
  # new image is ever started against the real data directory. Every
  # rollback path (_db_rollback(), via _restore_snapshot()) restores from
  # this with a same-filesystem `mv`, not a second slow copy.
  echo "  → Snapshotting the data directory (rollback safety net)…"
  rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
  if ! cp -a "$DB_DATA_DIR" "$DB_SNAPSHOT_DIR"; then
    echo "✗  Could not snapshot ${DB_DATA_DIR} — aborting before the new MariaDB" >&2
    echo "   image ever touches it. Restarting the existing database untouched." >&2
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi
  echo "  ✔  Snapshot ready: ${DB_SNAPSHOT_DIR} ($(du -sh "$DB_SNAPSHOT_DIR" 2>/dev/null | cut -f1))"

  if ! podman rename mariadb mariadb-old; then
    echo "✗  Unable to prepare MariaDB rollback container — aborting."
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start mariadb   >/dev/null 2>&1 || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  DB_OLD_RUNNING="$(podman inspect mariadb-old --format '{{.State.Running}}' 2>/dev/null)"
  if [ "$DB_OLD_RUNNING" != "false" ]; then
    echo "✗  mariadb-old is still running — refusing to start a second MariaDB"
    echo "   instance against the same data directory. Update aborted."
    rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
    podman start wordpress >/dev/null 2>&1 || true
    return 1
  fi

  # No --ip here either — mariadb-old still holds its wp-db address until
  # removed below. netavark auto-assigns a free wp-db address; WordPress
  # still finds it via aardvark-dns (the --add-host static entry above is a
  # fallback only, and can go stale after this — pre-existing limitation,
  # unrelated to Skopeo/pinning).
  if podman run -d --name mariadb --network wp-db --restart always \
    --label io.containers.autoupdate=image \
    --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --cap-add DAC_OVERRIDE --cap-add FOWNER \
    --security-opt no-new-privileges:true \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --cpu-shares=512 \
    --env-file /etc/wordpress/env \
    -v /home/wpuser/wp/mysql:/var/lib/mysql \
    -v /home/wpuser/wp/mariadb-conf/wp.cnf:/etc/mysql/conf.d/wp.cnf:ro \
    --health-cmd "healthcheck.sh --connect --innodb_initialized" \
    --health-interval 5s --health-timeout 5s --health-retries 24 \
    --health-start-period 30s \
    "${_UPD_PULL_REF}"; then

    # PRODUCTION SAFETY FIX (v7-6k): DB_READY used to gate this rollback
    # decision on a bare ping. This is the highest-stakes place a shallow
    # check could bite — DB_READY directly decides whether do_db_update()
    # keeps the new MariaDB container or rolls back to mariadb-old, and a
    # ping can report healthy while the wpdb user/database or InnoDB itself
    # are still broken. WordPress is also stopped at this point in the
    # update, so wp-health-check.sh (which needs a running WordPress
    # container to test through) can't be used here — mariadb-health-check.sh
    # (installed by the main provisioning script; see its rationale there)
    # is the real equivalent for MariaDB itself. The old ping-only check is
    # kept as a fallback only if that script is somehow missing (e.g. a VM
    # provisioned before v7-6k).
    DB_READY=0
    for i in $(seq 1 24); do
      if [ -x /usr/local/bin/mariadb-health-check.sh ]; then
        /usr/local/bin/mariadb-health-check.sh mariadb && { DB_READY=1; break; }
      elif podman exec mariadb sh -c \
        'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null ||
         mariadb-admin  ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" 2>/dev/null'; then
        DB_READY=1; break
      fi
      sleep 5
    done

    if [ "$DB_READY" = "1" ]; then
      echo "  → mariadb-upgrade (no-op if not needed)…"
      # mariadb-upgrade's own exit status is still not checked here — open
      # finding #5, intentionally out of scope for this patch (see
      # Remaining_todo.docx). The WordPress-reconnect gate immediately below
      # at least catches the case where an upgrade problem breaks
      # WordPress's own queries.
      podman exec mariadb sh -c \
        'mariadb-upgrade -uroot -p"$MARIADB_ROOT_PASSWORD"' >/dev/null 2>&1 || true

      # v7-9 (item 41c): mariadb-old and the pre-update snapshot used to be
      # deleted right after `podman start wordpress ... || true` — WordPress's
      # own restart failure was swallowed, and nothing confirmed WordPress
      # could actually USE the new database before the only way back was
      # removed. WordPress is now validated with the same wp-health-check.sh
      # depth (HTTP + PHP + DB name resolution + a real WordPress-credential
      # query) used at every other health-check site in this script.
      WP_RECONNECT_OK=0
      if podman start wordpress >/dev/null 2>&1; then
        echo "  → Confirming WordPress can actually use the updated database before removing the rollback container…"
        for i in $(seq 1 6); do
          if [ -x /usr/local/bin/wp-health-check.sh ]; then
            if /usr/local/bin/wp-health-check.sh wordpress 80; then
              WP_RECONNECT_OK=1; break
            fi
          else
            if wget -qO- "http://127.0.0.1:80/" >/dev/null 2>&1; then
              podman exec --user www-data wordpress php -r \
                '$c=@mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"));exit($c?0:1);' \
                >/dev/null 2>&1 && { WP_RECONNECT_OK=1; break; }
            fi
          fi
          sleep 5
        done
      else
        echo "✗  WordPress failed to restart after the MariaDB swap." >&2
      fi

      if [ "$WP_RECONNECT_OK" = "1" ]; then
        podman stop mariadb-old 2>/dev/null; podman rm -f mariadb-old 2>/dev/null
        # PRODUCTION SAFETY FIX (v7-6k): flag a leftover mariadb-old now — it
        # will otherwise silently block the next update's preflight check.
        podman container exists mariadb-old 2>/dev/null \
          && echo "  ⚠  mariadb-old could not be fully removed — clean it up before the next update: podman rm -f mariadb-old" >&2
        rm -rf "$DB_SNAPSHOT_DIR" 2>/dev/null || true
        echo "✔  MariaDB updated to ${target_ver} — WordPress confirmed healthy against it. Backup: ${BACKUP_FILE}"
        DB_TAG="$target_ver"; DB_DIGEST="${_UPD_DIGEST}"
        _save_pinned
      else
        _db_rollback "WordPress did not come back healthy against the updated database" || true
        return 1
      fi
    else
      _db_rollback "New MariaDB did not pass health validation" || true
      return 1
    fi
  else
    _db_rollback "MariaDB container failed to start" || true
    return 1
  fi
}

do_cs_update() {
  local target_ver="${1:-${CS_TAG:-$PINNED_CS_VER}}"
  echo "── CrowdSec ───────────────────────────────────────────────────"
  [ -n "$1" ] && { validate_image_tag "$1" || return 1; }
  echo "  Pinned  : tag=${CS_TAG:-none}  digest=${CS_DIGEST:-none}"
  echo "  Target  : ${CS_REGISTRY}:${target_ver}"

  _check_component "$CS_REGISTRY" "$CS_TAG" "$CS_DIGEST" "$target_ver"
  case "$_UPD_ACTION" in
    skip) echo "  ✔  Already on target — tag and digest both unchanged."; return 0 ;;
    refresh) ask_yn "Same tag (${target_ver}) but the registry has a newer digest — refresh it?" || { echo "   Skipped."; return 0; } ;;
    bump) ask_yn "Update CrowdSec to ${target_ver}?" || { echo "   Skipped."; return 0; } ;;
  esac

  setup_trivy
  scan_image "${_UPD_PULL_REF}" || return 1

  # v7-7 (item 39): fail fast, before the pull/stop sequence below, if
  # crowdsec-old already exists (a stale leftover from an update that was
  # interrupted before cleanup) or crowdsec itself is missing. Without
  # this, that problem is only discovered much further down, right at the
  # actual rename. The require_clean_container_state() call right before
  # the rename further down stays in place too, as a second,
  # belt-and-suspenders guard — same rationale as do_db_update() above.
  require_clean_container_state crowdsec crowdsec-old || return 1

  echo "  → Pulling ${_UPD_PULL_REF}…"
  podman pull "${_UPD_PULL_REF}" || { echo "✗  Pull failed."; return 1; }
  if [ -z "${_UPD_DIGEST}" ] && [ "${USE_DIGEST_PINNING}" = "1" ]; then
    _UPD_DIGEST=$(podman inspect "${_UPD_PULL_REF}" --format '{{index .RepoDigests 0}}' 2>/dev/null \
      | grep -oE 'sha256:[0-9a-f]{64}' || true)
    [ -n "${_UPD_DIGEST}" ] && _UPD_PULL_REF="${CS_REGISTRY}@${_UPD_DIGEST}"
  fi

  # BUG FIX (missing-item #7 — CrowdSec old and new containers may compete
  # on host networking): this used to rename crowdsec -> crowdsec-old
  # WITHOUT stopping it first. `podman rename` does not stop a container,
  # and CrowdSec runs --network host (the host's own network namespace,
  # not an isolated Podman network like wp-front/wp-db) — so the still-
  # running renamed engine and the new container started below would both
  # be live on the HOST network at once, competing for the same LAPI port
  # (127.0.0.1:8080, locked down earlier in the installer), any AppSec
  # listener, and the same bind-mounted /opt/crowdsec/config and
  # /opt/crowdsec/data. Same class of bug already fixed for MariaDB above
  # (two engines against one set of persistent state/ports) — same fix:
  # stop cleanly first, verify the old container actually stopped, THEN
  # rename, so there is never a moment with two CrowdSec engines both
  # live on the host network.
  echo "  → Stopping CrowdSec cleanly before replacement…"
  if ! podman stop --time 30 crowdsec; then
    echo "✗  CrowdSec did not stop cleanly — aborting update."
    return 1
  fi

  # PRODUCTION SAFETY FIX (v7-6k): preflight the rename's own preconditions
  # (see require_clean_container_state() above) before attempting it, so a
  # stale crowdsec-old from a previous crashed update is reported clearly
  # instead of surfacing as a generic rename failure below.
  require_clean_container_state crowdsec crowdsec-old || {
    podman start crowdsec >/dev/null 2>&1 || true
    return 1
  }
  if ! podman rename crowdsec crowdsec-old; then
    echo "✗  Unable to prepare CrowdSec rollback container — aborting."
    podman start crowdsec >/dev/null 2>&1 || true
    return 1
  fi

  CS_OLD_RUNNING="$(podman inspect crowdsec-old --format '{{.State.Running}}' 2>/dev/null)"
  if [ "$CS_OLD_RUNNING" != "false" ]; then
    echo "✗  crowdsec-old is still running — refusing to start a second CrowdSec"
    echo "   engine against the same host-network ports and data. Update aborted."
    return 1
  fi

  if podman run -d --name crowdsec --restart always --network host \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
    --security-opt no-new-privileges:true --read-only \
    --tmpfs /tmp:size=32M,noexec,nosuid,nodev --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
    --pids-limit 100 --memory=512m --label io.containers.autoupdate=image \
    -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
    -v /opt/crowdsec/config:/etc/crowdsec:rw -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
    -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
    -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
    -v /var/log/messages:/var/log/host/messages:ro \
    "${_UPD_PULL_REF}"; then

    LAPI_UP=0
    for i in $(seq 1 6); do
      podman exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_UP=1; break; }; sleep 5
    done
    if [ "$LAPI_UP" = "1" ]; then
      rc-service cs-firewall-bouncer restart 2>/dev/null || true
      podman stop crowdsec-old 2>/dev/null; podman rm -f crowdsec-old 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): flag a leftover crowdsec-old now — it
      # will otherwise silently block the next update's preflight check.
      podman container exists crowdsec-old 2>/dev/null \
        && echo "  ⚠  crowdsec-old could not be fully removed — clean it up before the next update: podman rm -f crowdsec-old" >&2
      echo "✔  CrowdSec updated to ${target_ver}"
      CS_TAG="$target_ver"; CS_DIGEST="${_UPD_DIGEST}"
      _save_pinned
    else
      echo "✗  LAPI not responding — rolling back…"
      podman stop crowdsec 2>/dev/null; podman rm -f crowdsec 2>/dev/null
      # PRODUCTION SAFETY FIX (v7-6k): was `2>/dev/null` on the rename and
      # start, discarding the one result that matters most — this IS the
      # rollback. Check it and say so loudly if it doesn't work.
      if podman rename crowdsec-old crowdsec && podman start crowdsec >/dev/null 2>&1; then
        rc-service cs-firewall-bouncer restart 2>/dev/null || true
      else
        echo "✗✗ ROLLBACK FAILED — crowdsec-old could not be restored to 'crowdsec'" >&2
        echo "   and/or started. Intrusion protection is DOWN. Manual recovery needed now:" >&2
        echo "     podman ps -a --filter name=crowdsec" >&2
        echo "     podman rename crowdsec-old crowdsec && podman start crowdsec" >&2
      fi
      return 1
    fi
  else
    podman rm -f crowdsec 2>/dev/null
    if podman rename crowdsec-old crowdsec && podman start crowdsec >/dev/null 2>&1; then
      rc-service cs-firewall-bouncer restart 2>/dev/null || true
    else
      echo "✗✗ ROLLBACK FAILED — crowdsec-old could not be restored to 'crowdsec'" >&2
      echo "   and/or started. Intrusion protection is DOWN. Manual recovery needed now:" >&2
      echo "     podman ps -a --filter name=crowdsec" >&2
      echo "     podman rename crowdsec-old crowdsec && podman start crowdsec" >&2
    fi
    return 1
  fi
}

show_status() {
  echo ""; echo "── Status ─────────────────────────────────────────────────────"
  podman ps --format "  {{.Names}}\t{{.Status}}\t{{.Image}}" 2>/dev/null | column -t || true
  echo ""
  echo "  Firewall : $(nft list tables 2>/dev/null | grep -c table) nft tables"
  echo "  Bouncer  : $(rc-service cs-firewall-bouncer status 2>/dev/null | head -1)"
  echo ""
}

# ── Digest-only refresh (no OS, no version bump — just "is the currently
# pinned tag's digest still current everywhere?") ─────────────────────────
do_digest_check() {
  echo "── Digest Check (Skopeo manifest query only — pulls happen only if something actually changed) ──"
  if [ "${USE_DIGEST_PINNING}" != "1" ]; then
    echo "  Digest pinning is disabled (USE_DIGEST_PINNING=0 in vars.sh) — nothing to check."
    return 0
  fi
  do_wp_update "${WP_TAG:-$PINNED_WP_VER}"
  do_db_update "${DB_TAG:-$PINNED_DB_VER}"
  do_cs_update "${CS_TAG:-$PINNED_CS_VER}"
}

# ── Read-only summary (default action) ─────────────────────────────────────
# Reports; changes nothing. Every remote lookup here is a Skopeo manifest
# query (a few KB) — no `podman pull` happens in this code path at all.
show_check_summary() {
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║  WordPress VM — Status (read-only, no downloads)          ║"
  echo "╠══════════════════════════════════════════════════════════╣"
  echo "║  Alpine   : $(cat /etc/alpine-release 2>/dev/null)"
  _report_one() {
    local label="$1" registry="$2" tag="$3" digest="$4" note remote
    if [ "${USE_DIGEST_PINNING}" = "1" ]; then
      remote=$(_resolve_digest "${registry}:${tag}") || remote=""
      if [ -z "$remote" ]; then
        note="tag=${tag}  (couldn't reach registry to check digest)"
      elif [ -z "$digest" ]; then
        note="tag=${tag}  not pinned yet — current registry digest: ${remote}"
      elif [ "$remote" = "$digest" ]; then
        note="tag=${tag}  digest up to date"
      else
        note="tag=${tag}  NEWER DIGEST AVAILABLE under this tag"
      fi
    else
      note="tag=${tag}  (digest pinning disabled)"
    fi
    printf "║  %-9s %s\n" "${label}:" "$note"
  }
  _report_one "WordPress" "$WP_REGISTRY" "${WP_TAG:-$PINNED_WP_VER}" "$WP_DIGEST"
  _report_one "MariaDB"   "$DB_REGISTRY" "${DB_TAG:-$PINNED_DB_VER}" "$DB_DIGEST"
  _report_one "CrowdSec"  "$CS_REGISTRY" "${CS_TAG:-$PINNED_CS_VER}" "$CS_DIGEST"
  if [ "${USE_DIGEST_PINNING:-1}" = "1" ]; then
    _PIN_COUNT=0
    [ -n "$WP_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    [ -n "$DB_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    [ -n "$CS_DIGEST" ] && _PIN_COUNT=$((_PIN_COUNT+1))
    echo "║  Digest pinning: enabled — ${_PIN_COUNT}/3 currently pinned"
  else
    echo "║  Digest pinning: disabled"
  fi
  echo "╚══════════════════════════════════════════════════════════╝"
  echo ""
  echo "  update.sh all                  — update everything (asks before each change)"
  echo "  update.sh wp|db|crowdsec [VER] — update one component (asks first)"
  echo "  update.sh digest-check         — refresh any component whose tag got rebuilt"
  echo "  update.sh os                   — Alpine package updates"
  echo "  update.sh trivy                — CVE scan of the images actually running"
  show_status
}

# ── Update lock — prevents concurrent update.sh invocations from stepping
# on each other ─────────────────────────────────────────────────────────
# PRODUCTION SAFETY FIX (v7-6j): nothing previously stopped two update.sh
# invocations from running at the same time — e.g. an admin running
# `update.sh wp` while a cron-triggered `update.sh digest-check` is already
# mid-run, or two admins each updating a different component. Concrete
# failure modes this allowed: two processes racing to rename the same
# container to *-old (the loser's rename fails, or worse, a second update
# removes/renames a rollback container the first update still depends on);
# two processes writing /etc/wp-install/pinned.env around the same time;
# overlapping MariaDB dumps against the same data directory; one process
# restarting a service while another process's health check is mid-poll
# against it.
#
# A plain mkdir-based lock closes this: mkdir is atomic on every storage
# backend this script runs on (overlay/vfs/fuse-overlayfs), so exactly one
# invocation can ever hold the lock directory at a time — no flock/
# lockfile binary dependency required. The holder's PID is recorded inside
# the lock so a stale lock left behind by a crashed update (OOM-killed, VM
# rebooted mid-update, etc.) is detected via `kill -0` and cleared
# automatically instead of wedging every future update permanently.
#
# Only the state-changing subcommands below (os/wp/db/crowdsec/all/
# digest-check) take the lock — check/status/trivy stay lock-free since
# they're read-only (no container renames, no pinned.env writes) and are
# meant to stay safe to run anytime, including while an update is already
# in progress (see "bare update.sh is read-only" under WHAT CHANGED above).
LOCK_DIR="/run/lock/wordpress-update.lock"
acquire_lock() {
  local lock_pid
  mkdir -p /run/lock
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
    trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
    return 0
  fi
  # Lock dir already exists: either a live update holds it, or a previous
  # run crashed without cleaning up. Only trust the recorded PID if that
  # process is actually still alive.
  if [ -f "${LOCK_DIR}/pid" ]; then
    lock_pid=$(cat "${LOCK_DIR}/pid" 2>/dev/null || true)
    if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
      echo "  ⚠  Clearing a stale update lock left by dead process ${lock_pid}…" >&2
      rm -rf "$LOCK_DIR"
      if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "${LOCK_DIR}/pid" 2>/dev/null
        trap 'rm -rf "$LOCK_DIR"' EXIT INT TERM HUP
        return 0
      fi
    fi
  fi
  echo "✗  Another update.sh is already running (PID ${lock_pid:-unknown})." >&2
  echo "   Lock: ${LOCK_DIR} — wait for it to finish, or if you're certain" >&2
  echo "   nothing is actually running, clear it with: rm -rf ${LOCK_DIR}" >&2
  return 1
}

case "${1:-check}" in
  os)          acquire_lock || exit 1; do_os_update ;;
  wp)          acquire_lock || exit 1; do_wp_update "${2:-}" ;;
  db)          acquire_lock || exit 1; do_db_update "${2:-}" ;;
  crowdsec|cs) acquire_lock || exit 1; do_cs_update "${2:-}" ;;
  all)         acquire_lock || exit 1; do_os_update; do_wp_update; do_db_update; do_cs_update ;;
  digest-check|digest|pin) acquire_lock || exit 1; do_digest_check ;;
  trivy|scan)
    setup_trivy
    for img in wordpress mariadb crowdsec; do
      running=$(podman inspect "$img" --format "{{.Config.Image}}" 2>/dev/null || echo "")
      [ -n "$running" ] && scan_image "$running"
    done ;;
  check|status|"") show_check_summary ;;
  *) echo "Usage: update.sh [check|status|os|wp [VER]|db [VER]|crowdsec [VER]|digest-check|all|trivy]"; exit 1 ;;
esac
UPDSCRIPT
chmod +x /usr/local/bin/update.sh
ok "update.sh installed (wp / db / crowdsec / os / digest-check / all)"
ok "  Concurrent runs are now blocked by an exclusive lock at /run/lock/wordpress-update.lock"
ok "  Container swaps (wp/db/crowdsec) now check every rename/start instead of discarding the result — a silent failure here used to be able to delete a still-healthy container"
ok "  WordPress updates now validate the pulled image on a loopback candidate (127.0.0.1:18080) before cutting production over on :80"
ok "  MariaDB updates now verify the backup dump itself, snapshot the data directory before the swap, and confirm WordPress can use the new database before mariadb-old is ever deleted"

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC
# ════════════════════════════════════════════════════════════════════════════
ts "CrowdSec — engine"
mkdir -p /opt/crowdsec/config /opt/crowdsec/data
mkdir -p /home/wpuser/wp/logs; chown 33:33 /home/wpuser/wp/logs 2>/dev/null || true
# Ensure /var/log/messages exists before CrowdSec bind-mounts it.
touch /var/log/messages 2>/dev/null || true

cat > /opt/crowdsec/acquis.yaml << 'ACQUIS'
filenames:
  - /var/log/wordpress/access.log
labels:
  type: apache2
---
filenames:
  - /var/log/host/messages
labels:
  type: syslog
ACQUIS
ok "acquis.yaml: Apache logs + syslog"

podman rm -f crowdsec 2>/dev/null || true
podman run -d \
  --name    crowdsec \
  --restart always \
  --network host \
  --cap-drop ALL \
  --cap-add  DAC_OVERRIDE \
  --cap-add  SETUID \
  --cap-add  SETGID \
  --cap-add  CHOWN \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:size=32M,noexec,nosuid,nodev \
  --tmpfs /var/run:size=16M,noexec,nosuid,nodev \
  --pids-limit 100 \
  --memory=512m \
  --label io.containers.autoupdate=image \
  -e COLLECTIONS="crowdsecurity/apache2 crowdsecurity/wordpress crowdsecurity/linux crowdsecurity/sshd crowdsecurity/http-cve crowdsecurity/appsec-wordpress" \
  -v /opt/crowdsec/config:/etc/crowdsec:rw \
  -v /opt/crowdsec/data:/var/lib/crowdsec/data:rw \
  -v /opt/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro \
  -v /home/wpuser/wp/logs:/var/log/wordpress:ro \
  -v /var/log/messages:/var/log/host/messages:ro \
  "${CROWDSEC_IMAGE}"

ts "Waiting for CrowdSec LAPI"
LAPI_READY=0
for i in $(seq 1 30); do
  PRUN exec crowdsec cscli lapi status >/dev/null 2>&1 && { LAPI_READY=1; break; }
  sleep 5
done
[ "$LAPI_READY" = "1" ] && ok "LAPI up" || warn "LAPI not confirmed — continuing"

ts "Locking LAPI to 127.0.0.1:8080"
CFG=/opt/crowdsec/config/config.yaml
for i in $(seq 1 12); do [ -f "$CFG" ] && break || sleep 5; done
if [ -f "$CFG" ]; then
  grep -qE '^\s*listen_uri:' "$CFG" \
    && sed -i -E 's|^(\s*listen_uri:).*|\1 127.0.0.1:8080|' "$CFG"
  PRUN restart crowdsec >/dev/null 2>&1; sleep 3
  ok "LAPI → 127.0.0.1:8080"
else
  warn "config.yaml not found — restrict LAPI manually"
fi

ts "Generating bouncer API key"
PRUN exec crowdsec cscli bouncers delete firewall-bouncer >/dev/null 2>&1 || true
BOUNCER_KEY=$(PRUN exec crowdsec cscli bouncers add firewall-bouncer -o raw 2>/dev/null | tail -1)
[ -n "$BOUNCER_KEY" ] && ok "Bouncer key generated" \
  || warn "Could not generate key — check: podman logs crowdsec"

ts "Installing cs-firewall-bouncer"
apk add --no-cache nftables cs-firewall-bouncer cs-firewall-bouncer-openrc >/dev/null 2>&1 \
  || warn "cs-firewall-bouncer not in apk — try edge repo"

if [ -n "$BOUNCER_KEY" ]; then
  mkdir -p /etc/crowdsec/bouncers
  cat > /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml << BOUNCERCFG
mode: nftables
pid_dir: /var/run/
update_frequency: 10s
daemonize: true
log_mode: file
log_dir: /var/log/
log_level: info
api_url: http://127.0.0.1:8080/
api_key: ${BOUNCER_KEY}
disable_ipv6: false
deny_action: DROP
deny_log: false
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
    priority: -10
  ipv6:
    enabled: false
nftables_hooks:
  - input
BOUNCERCFG
  chmod 600 /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  rc-update add cs-firewall-bouncer default 2>/dev/null || true
  rc-service cs-firewall-bouncer start 2>/dev/null || true
  # BUG FIX (v7-4): the bouncer's first start frequently loses a race against
  # CrowdSec's LAPI still finishing initialization and comes up "crashed"
  # (confirmed in the field: `rc-service cs-firewall-bouncer status` showed
  # crashed immediately after install, and a plain `restart` — no config
  # change — fixed it instantly). Retry the start a few times instead of
  # accepting the first crash.
  BOUNCER_UP=0
  for attempt in 1 2 3 4 5; do
    if rc-service cs-firewall-bouncer status 2>/dev/null | grep -q started; then
      BOUNCER_UP=1; break
    fi
    warn "cs-firewall-bouncer not started yet (attempt ${attempt}/5) — restarting"
    rc-service cs-firewall-bouncer restart >/dev/null 2>&1 || true
    sleep 5
  done
  [ "$BOUNCER_UP" = "1" ] \
    && ok "cs-firewall-bouncer service running" \
    || warn "cs-firewall-bouncer still not started after retries — run: rc-service cs-firewall-bouncer restart"
  sleep 2
  PRUN exec crowdsec cscli bouncers list 2>/dev/null | grep -q firewall-bouncer \
    && ok "Bouncer connected to LAPI" \
    || warn "Bouncer not yet showing — check rc-service cs-firewall-bouncer status"
fi

cat > /etc/init.d/crowdsec-container << 'CSSVC'
#!/sbin/openrc-run
name="crowdsec-container"
description="CrowdSec engine (Podman)"
depend() {
  need net wp-container
  after sysfs wp-container
}
start() {
  ebegin "Starting CrowdSec"
  export PODMAN_IGNORE_CGROUPSV1_WARNING=1
  if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ] \
     && [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" != "UNKNOWN" ]; then
    mountpoint -q /sys/fs/cgroup 2>/dev/null && umount /sys/fs/cgroup 2>/dev/null
    mount -t cgroup2 cgroup2 /sys/fs/cgroup 2>/dev/null
  fi
  mount --make-shared / 2>/dev/null || true
  # BUG FIX (v7-5d): cs-firewall-bouncer is a SEPARATE OpenRC service that
  # starts independently and can lose a race against CrowdSec's LAPI still
  # coming up — confirmed in the field to recur on every reboot, not just
  # the first install (an earlier fix only lived in the one-shot installer
  # script, so it never helped subsequent boots). Waiting here for LAPI to
  # actually respond, then restarting the bouncer, runs on EVERY boot that
  # brings this service up, not just the first one.
  podman container exists crowdsec 2>/dev/null && podman start crowdsec >/dev/null 2>&1
  CS_START_STATUS=$?
  if [ "$CS_START_STATUS" = "0" ]; then
    for _i in 1 2 3 4 5 6; do
      podman exec crowdsec cscli lapi status >/dev/null 2>&1 && break
      sleep 5
    done
    rc-service cs-firewall-bouncer restart >/dev/null 2>&1 || true
  fi
  eend "$CS_START_STATUS"
}
stop() {
  ebegin "Stopping CrowdSec"
  podman stop crowdsec >/dev/null 2>&1
  eend $?
}
CSSVC
chmod +x /etc/init.d/crowdsec-container
rc-update add crowdsec-container default 2>/dev/null || true
ok "crowdsec-container service registered"

# BUG FIX: podman-compose is NOT needed for podman auto-update.
# podman auto-update is a built-in Podman command.
cat >> /etc/crontabs/root << 'AUTOCRON'
# Weekly container image update check (Sunday 04:00 UTC — dry run only)
0 4 * * 0 podman auto-update --dry-run 2>&1 | logger -t podman-autoupdate
# WordPress system cron — replaces unreliable WP-Cron (which only fires on
# page loads). DISABLE_WP_CRON=true is set in WORDPRESS_CONFIG_EXTRA.
# Runs every 5 min; WordPress schedules (backups, updates, email) fire on time.
*/5 * * * * /usr/local/bin/wp-cron-run.sh >/dev/null 2>&1
# Daily MariaDB backup — gzipped SQL dump to /root/wp-db-backups/.
# Retains 7 days automatically. Restore: gunzip < file.sql.gz | mariadb -u root
0 2 * * * mkdir -p /root/wp-db-backups && podman exec mariadb sh -c 'exec mariadb-dump --all-databases -uroot -p"$MARIADB_ROOT_PASSWORD"' | gzip > "/root/wp-db-backups/wp-db-$(date +\%Y\%m\%d).sql.gz" && find /root/wp-db-backups -name 'wp-db-*.sql.gz' -mtime +7 -delete 2>&1 | logger -t wp-db-backup
AUTOCRON
ok "Cron jobs scheduled:"
ok "  Weekly  : podman auto-update dry-run (Sun 04:00)"
ok "  Every 5m: WordPress system cron (replaces WP-Cron)"
ok "  Daily   : MariaDB backup to /root/wp-db-backups/ (7-day retention)"

# ════════════════════════════════════════════════════════════════════════════
# 8G FIREWALL v1.4 — Apache .htaccess WAF, runs before PHP (fast)
# Sourced: perishablepress.com/8g-firewall (free for all use, credit intact)
# WordPress only rewrites between # BEGIN/END WordPress markers —
# our 8G rules placed ABOVE that block survive any WordPress .htaccess flush.
# DIVI: visual builder (admin-ajax, REST API) unaffected by these rules.
# Toggle: wp-hardening.sh disable 8g  or  wp-hardening.sh enable 8g
# ════════════════════════════════════════════════════════════════════════════

# ════════════════════════════════════════════════════════════════════════════
# TRIVY — Container vulnerability scanner (gates updates in update.sh)
# Latest: v0.71.2 (June 2026). Cache at /var/cache/trivy persists reboots.
# First scan downloads the DB (~100-200 MB); subsequent scans use cache (<15s).
# ════════════════════════════════════════════════════════════════════════════
ts "Installing Trivy vulnerability scanner"
TRIVY_VER="v0.71.2"
TRIVY_CACHE_DIR="/var/cache/trivy"
mkdir -p "${TRIVY_CACHE_DIR}"; chmod 755 "${TRIVY_CACHE_DIR}"

# Try edge/testing first (clean apk) then fall back to official install script
if apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
     trivy >/dev/null 2>&1; then
  ok "Trivy installed via apk edge/testing"
elif apk add --no-cache wget >/dev/null 2>&1 && \
     wget -qO /tmp/trivy-install.sh \
       https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
       2>/dev/null; then
  sh /tmp/trivy-install.sh -b /usr/local/bin "${TRIVY_VER}" >/dev/null 2>&1 \
    && ok "Trivy ${TRIVY_VER} installed via official script" \
    || warn "Trivy install failed — vulnerability scanning disabled in update.sh"
  rm -f /tmp/trivy-install.sh
else
  warn "Trivy unavailable — update.sh will skip vulnerability scanning"
fi

if command -v trivy >/dev/null 2>&1; then
  ok "Trivy $(trivy --version 2>/dev/null | head -1) ready"
  ok "  Pre-seeding vulnerability DB (~100 MB, takes 30-90s)..."
  trivy image --cache-dir "${TRIVY_CACHE_DIR}" --download-db-only --quiet 2>/dev/null \
    && ok "  Trivy DB cached at ${TRIVY_CACHE_DIR}" \
    || warn "  Trivy DB pre-seed failed (will download on first update scan)"
fi

# ════════════════════════════════════════════════════════════════════════════
# LYNIS — Security auditing for MSP compliance evidence
# lynis is only in Alpine edge/testing, NOT in stable repos (3.21-3.24).
# Try stable first (may land in community someday), then edge/testing,
# then direct GitHub install as a final fallback — so Lynis is never
# silently absent even if Alpine packaging changes.
# Weekly automated audit; manual: lynis audit system
# Score: grep hardening_index /var/log/lynis-report.dat
# ════════════════════════════════════════════════════════════════════════════
ts "Installing Lynis security auditor"
LYNIS_OK=0

# Try 1: Alpine stable community (might appear in future versions)
apk add --no-cache lynis >/dev/null 2>&1 && LYNIS_OK=1

# Try 2: Alpine edge/testing (where it currently lives as of Alpine 3.24)
if [ "$LYNIS_OK" = "0" ]; then
  apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing \
    lynis >/dev/null 2>&1 && LYNIS_OK=1
fi

# Try 3: Direct install from CISOfy's stable release tarball (no OS dependency)
if [ "$LYNIS_OK" = "0" ]; then
  warn "Lynis not in apk repos — trying GitHub release tarball"
  apk add --no-cache wget >/dev/null 2>&1 || true
  LYNIS_TAG=$(wget -qO- https://api.github.com/repos/CISOfy/lynis/releases/latest 2>/dev/null \
    | grep '"tag_name"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  LYNIS_TAG="${LYNIS_TAG:-3.1.3}"  # pinned fallback if API unavailable
  if wget -qO /tmp/lynis.tar.gz \
       "https://github.com/CISOfy/lynis/archive/refs/tags/${LYNIS_TAG}.tar.gz" 2>/dev/null; then
    tar xzf /tmp/lynis.tar.gz -C /usr/local/lib 2>/dev/null
    ln -sf "/usr/local/lib/lynis-${LYNIS_TAG}/lynis" /usr/local/bin/lynis 2>/dev/null
    rm -f /tmp/lynis.tar.gz
    command -v lynis >/dev/null 2>&1 && LYNIS_OK=1 && ok "Lynis ${LYNIS_TAG} installed from GitHub release"
  fi
fi

if [ "$LYNIS_OK" = "1" ]; then
  ok "Lynis $(lynis --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ready"
  cat >> /etc/crontabs/root << 'LYNISCRON'
# Weekly Lynis security audit (Saturday 05:00 UTC) — MSP compliance evidence
0 5 * * 6 lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat 2>&1 | logger -t lynis-audit
LYNISCRON
  ok "Lynis: weekly audit Sat 05:00 | manual: wp-hardening.sh lynis"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
  ok "  Score: grep hardening_index /var/log/lynis-report.dat"
else
  warn "Lynis could not be installed — all install methods failed"
  warn "  Manual install: apk add --repository https://dl-cdn.alpinelinux.org/alpine/edge/testing lynis"
  warn "  Or: wget https://github.com/CISOfy/lynis/archive/refs/tags/3.1.3.tar.gz"
fi

# ════════════════════════════════════════════════════════════════════════════
# CROWDSEC CONSOLE AUTO-ENROLMENT
# If an enrolment key was provided at provisioning time, enrol now.
# After enrolment: visit https://app.crowdsec.net → Accept the engine.
# Then restart CrowdSec: podman restart crowdsec
# ════════════════════════════════════════════════════════════════════════════
if [ -n "${CROWDSEC_ENROLL_KEY}" ]; then
  ts "CrowdSec console auto-enrolment"
  CS_NAME=$(hostname 2>/dev/null || echo "wordpress-vm")
  if PRUN exec crowdsec cscli console enroll \
       --name "${CS_NAME}" \
       --tags "wordpress,msp,podman,alpine" \
       "${CROWDSEC_ENROLL_KEY}" 2>/dev/null; then
    ok "CrowdSec enrolled as '${CS_NAME}' — accept it at https://app.crowdsec.net"
    ok "  Then restart: podman restart crowdsec"
  else
    warn "CrowdSec enrolment failed — check key at app.crowdsec.net"
    warn "  Manual: podman exec crowdsec cscli console enroll <key>"
  fi
  # Scrub key from disk now that it's been used
  sed -i 's/^CROWDSEC_ENROLL_KEY=.*/CROWDSEC_ENROLL_KEY=""/' \
    /etc/wp-install/vars.sh 2>/dev/null || true
fi

# ════════════════════════════════════════════════════════════════════════════
# WP-HARDENING.SH — Toggle security features from Proxmox or SSH
# qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# ════════════════════════════════════════════════════════════════════════════
ts "Installing wp-hardening.sh security toggle"
cat > /usr/local/bin/wp-hardening.sh << 'HARDEN'
#!/bin/sh
# WordPress VM Security Feature Toggle
# Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp]
# From Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status
# Features: 8g  xmlrpc  uploads-php  author-enum  debug
set -e
[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
PRUN() {
  podman "$@"
}

HTACCESS="/home/wpuser/wp/htaccess/.htaccess"
APACHE_CONF="/home/wpuser/wp/apache-conf/wp-security.conf"
TRIVY_CACHE_DIR="/var/cache/trivy"

restart_wp() { PRUN restart wordpress >/dev/null 2>&1 && echo "  ✔  WordPress restarted" || true; }

feature_state() {
  case "$1" in
    8g)          grep -q '^# 8G DISABLED' "$HTACCESS" 2>/dev/null && echo DISABLED || echo ENABLED ;;
    xmlrpc)      grep -q 'xmlrpc.php.*Require all denied' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    uploads-php) grep -q 'wp-content/uploads' "$APACHE_CONF" 2>/dev/null && echo BLOCKED || echo OPEN ;;
    debug)       PRUN exec wordpress php -r 'echo (defined("WP_DEBUG") && WP_DEBUG)?"ON":"OFF";' 2>/dev/null || echo UNKNOWN ;;
  esac
}

show_status() {
  echo ""
  echo "WordPress VM — Security Features"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  %-18s %s\n" "8G Firewall:"    "$(feature_state 8g)"
  printf "  %-18s %s\n" "xmlrpc.php:"     "$(feature_state xmlrpc)"
  printf "  %-18s %s\n" "uploads PHP:"    "$(feature_state uploads-php)"
  printf "  %-18s %s\n" "WP_DEBUG:"       "$(feature_state debug)"
  echo ""
  echo "Containers:"
  PRUN ps --format "  {{.Names}}: {{.Status}}" 2>/dev/null | head -5
  echo ""
  echo "Trivy cache: $(du -sh ${TRIVY_CACHE_DIR} 2>/dev/null | cut -f1 || echo 'not installed')"
  echo "Lynis last:  $(stat -c '%y' /var/log/lynis-report.dat 2>/dev/null | cut -d. -f1 || echo 'not run yet')"
  echo ""
  echo "Commands: enable|disable [8g|xmlrpc|uploads-php|debug|author-enum]"
  echo "Proxmox:  qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
}

enable_feature() {
  case "$1" in
    8g)
      sed -i 's/^# 8G DISABLED //' "$HTACCESS" 2>/dev/null || true
      echo "✔ 8G Firewall enabled"; restart_wp ;;
    xmlrpc)
      sed -i '/<Files "xmlrpc\.php">/,/<\/Files>/d' "$APACHE_CONF" 2>/dev/null
      echo "✔ xmlrpc.php unblocked (Jetpack etc. can now use it)"
      echo "  ⚠ Monitor with: podman exec crowdsec cscli decisions list"
      restart_wp ;;
    uploads-php)
      sed -i '/<DirectoryMatch.*uploads/,/<\/DirectoryMatch>/d' "$APACHE_CONF" 2>/dev/null
      echo "✔ PHP in uploads unblocked  ⚠ security risk — re-block when done"
      restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",false)/define(\"WP_DEBUG\",true)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG ON  ⚠ DISABLE after troubleshooting — exposes internals" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

disable_feature() {
  case "$1" in
    8g)
      sed -i 's/^  RewriteEngine On$/# 8G DISABLED   RewriteEngine On/g;s/^  RewriteCond /# 8G DISABLED   RewriteCond /g;s/^  RewriteRule /# 8G DISABLED   RewriteRule /g' \
        "$HTACCESS" 2>/dev/null
      echo "✔ 8G Firewall disabled  |  re-enable: wp-hardening.sh enable 8g"
      restart_wp ;;
    xmlrpc)
      grep -q 'xmlrpc' "$APACHE_CONF" \
        || printf '\n<Files "xmlrpc.php">\n    Require all denied\n</Files>\n' >> "$APACHE_CONF"
      echo "✔ xmlrpc.php blocked"; restart_wp ;;
    uploads-php)
      grep -q 'wp-content/uploads' "$APACHE_CONF" \
        || cat >> "$APACHE_CONF" << 'B'

<DirectoryMatch "^/var/www/html/wp-content/uploads">
    <FilesMatch "\.ph(p[0-9]?|tml)$">
        Require all denied
    </FilesMatch>
</DirectoryMatch>
B
      echo "✔ PHP in uploads blocked"; restart_wp ;;
    debug)
      PRUN exec wordpress sh -c \
        "sed -i 's/define(\"WP_DEBUG\",true)/define(\"WP_DEBUG\",false)/' /var/www/html/wp-config.php" 2>/dev/null || true
      echo "✔ WP_DEBUG OFF" ;;
    *) echo "Unknown: $1. Valid: 8g xmlrpc uploads-php debug" ;;
  esac
}

case "${1:-status}" in
  status)      show_status ;;
  enable)      [ -n "$2" ] && enable_feature "$2"  || echo "Usage: wp-hardening.sh enable <feature>" ;;
  disable)     [ -n "$2" ] && disable_feature "$2" || echo "Usage: wp-hardening.sh disable <feature>" ;;
  restart-wp)  restart_wp ;;
  trivy-scan)
    echo "Scanning running containers for vulnerabilities..."
    for img in $(PRUN ps --format "{{.Image}}"); do
      echo "  → Scanning ${img}"
      trivy image --cache-dir "${TRIVY_CACHE_DIR}" --severity HIGH,CRITICAL --quiet "${img}" 2>/dev/null \
        && echo "  ✔  Clean" || echo "  ⚠  Vulnerabilities found — run: update.sh"
    done ;;
  lynis)
    echo "Running Lynis audit (2-5 min)..."
    lynis audit system --quiet \
      --logfile /var/log/lynis.log \
      --report-file /var/log/lynis-report.dat 2>&1 | logger -t lynis-manual
    echo "✔  Done. Score: $(grep hardening_index /var/log/lynis-report.dat | cut -d= -f2)" ;;
  *)
    echo "Usage: wp-hardening.sh [status|enable <f>|disable <f>|restart-wp|trivy-scan|lynis]"
    ;;
esac
HARDEN
chmod +x /usr/local/bin/wp-hardening.sh
ok "wp-hardening.sh installed"
ok "  Usage: wp-hardening.sh status"
ok "  Proxmox: qm guest exec <VMID> -- /usr/local/bin/wp-hardening.sh status"
ok "  Commands: enable|disable [8g|xmlrpc|uploads-php|debug]  |  trivy-scan  |  lynis"

# ════════════════════════════════════════════════════════════════════════════
# POST-INSTALL VALIDATION SUITE
# Verifies every critical component before declaring the install complete.
# Creates /usr/local/bin/validate-wordpress.sh for ongoing health checks.
# ════════════════════════════════════════════════════════════════════════════
ts "Running post-install validation"

PASS=0; FAIL=0
check() {
  local label="$1"; local result="$2"; local expected="${3:-ok}"
  if [ "$result" = "$expected" ]; then
    ok "  PASS  ${label}"
    PASS=$((PASS+1))
  else
    warn "  FAIL  ${label} (got: ${result}, expected: ${expected})"
    FAIL=$((FAIL+1))
  fi
}

# WordPress container running
check "WordPress container up"   "$(podman inspect wordpress --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB container running
check "MariaDB container up"   "$(podman inspect mariadb --format '{{.State.Status}}' 2>/dev/null)" "running"

# CrowdSec container running
check "CrowdSec container up"   "$(podman inspect crowdsec --format '{{.State.Status}}' 2>/dev/null)" "running"

# MariaDB reachability check — NOT Health.Status. Podman's health-check timer
# frequently never fires on Alpine (no systemd/conmon poller to drive it), so
# .State.Health.Status can sit on "starting" forever even though MariaDB is
# fully up — same finding as the FIX 2 note above the MariaDB wait loop.
# stdout is redirected too, not just stderr: mariadb(d)-admin ping --silent
# still prints "mysqld is alive" on success, which would otherwise leak into
# the captured value and break the "ok" string comparison below.
_DB_PING_CHECK=$(PRUN exec mariadb sh -c 'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' && echo ok || echo fail)
check "MariaDB reachable (exec ping)" "$_DB_PING_CHECK"

# WordPress DB connectivity (PHP mysqli test, runs as www-data via su)
DB_CHECK=$(podman exec --user www-data wordpress php -r   'echo @mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"))?"ok":"fail";'   2>/dev/null || echo "error")
check "WordPress DB connection (www-data)" "$DB_CHECK"

# PRODUCTION SAFETY FIX (v7-6k): the two checks above are narrow (root-only
# ping; a bare mysqli_connect proves a socket opens, not that a query
# succeeds). These two additional checks call the same strengthened
# health-check scripts that gate update.sh's rollback decisions
# (wp-health-check.sh / mariadb-health-check.sh, installed earlier in this
# stage), so install-time validation is exactly as rigorous as update-time
# validation — HTTP + PHP execution + DB name resolution + a real
# WordPress-credential query for WordPress, and root + wpdb-credential
# queries + InnoDB-initialized for MariaDB itself. Added alongside, not
# instead of, the checks above.
_MARIADB_FULL_CHECK=$([ -x /usr/local/bin/mariadb-health-check.sh ] && /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1 && echo ok || echo fail)
check "MariaDB full health (query + InnoDB)" "$_MARIADB_FULL_CHECK"

_WP_FULL_CHECK=$([ -x /usr/local/bin/wp-health-check.sh ] && /usr/local/bin/wp-health-check.sh wordpress 80 >/dev/null 2>&1 && echo ok || echo fail)
check "WordPress full health (HTTP+PHP+DB)" "$_WP_FULL_CHECK"

# Port 80 listening — ss (iproute2) isn't installed on stock Alpine and this
# script never adds it, so this always read "0" regardless of real state.
# Busybox's netstat ships by default and is a drop-in replacement here.
check "Port 80 listening"   "$(netstat -tlnp 2>/dev/null | grep -c ':80 ' | tr -d ' ')" "1"

# WordPress HTTP response (should be 302 redirect to /wp-admin/install.php)
HTTP_CODE=$(podman exec --user www-data wordpress php -r   'error_reporting(0);$r=@file_get_contents("http://127.0.0.1/",false,stream_context_create(["http"=>["timeout"=>5,"method"=>"GET","ignore_errors"=>true]]));$code=preg_match("/HTTP\/[0-9.]+ ([0-9]+)/",$http_response_header[0]??"",$m)?$m[1]:"0";echo($code>=200&&$code<500)?"ok":"fail:".$code;'   2>/dev/null || echo "skip")
[ "$HTTP_CODE" = "skip" ] && ok "  SKIP  WordPress HTTP check (PHP network unavailable)"   || check "WordPress HTTP response (non-error)" "$HTTP_CODE"

# uploads directory writable by www-data
# BUG FIX (v7-5d): ensure the directory exists first — WordPress doesn't
# necessarily create wp-content/uploads until first real media use, and a
# missing directory makes this touch-test fail identically to a real
# permissions problem, even with correct ownership already in place.
podman exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
UPLOADS_CHECK=$(podman exec --user www-data wordpress sh -c   'touch /var/www/html/wp-content/uploads/.write_test && rm /var/www/html/wp-content/uploads/.write_test && echo ok || echo fail'   2>/dev/null || echo "fail")
check "Uploads dir writable (www-data)" "$UPLOADS_CHECK"

# nftables loaded
check "nftables active"   "$(nft list tables 2>/dev/null | grep -c filter | tr -d ' ')" "1"

# CrowdSec bouncer connected
check "CS firewall bouncer"   "$(rc-service cs-firewall-bouncer status 2>/dev/null | grep -c started | tr -d ' ')" "1"

# 8G firewall .htaccess present
check "8G .htaccess installed"   "$([ -f /home/wpuser/wp/htaccess/.htaccess ] && grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess || echo 0)" "1"

# Trivy available
check "Trivy scanner"   "$(command -v trivy >/dev/null 2>&1 && echo ok || echo missing)"

# Lynis available
check "Lynis auditor"   "$(command -v lynis >/dev/null 2>&1 && echo ok || echo missing)"

echo ""
if [ "$FAIL" = "0" ]; then
  ok "Validation: ${PASS} checks passed, 0 failed — install is healthy"
else
  warn "Validation: ${PASS} passed, ${FAIL} FAILED — review warnings above"
  warn "  Re-run after fix: /usr/local/bin/validate-wordpress.sh"
fi

# Write the validation script for ongoing use
cat > /usr/local/bin/validate-wordpress.sh << 'VALSCRIPT'
#!/bin/sh
# WordPress VM Health Validation
# Usage: validate-wordpress.sh [--quiet]
# Exit code: 0 = all pass, 1 = failures found
QUIET="${1:-}"
PASS=0; FAIL=0
[ -f /etc/wp-install/vars.sh ] && . /etc/wp-install/vars.sh
PRUN() {
  podman "$@"
}

chk() {
  local label="$1" got="$2" want="${3:-ok}"
  if [ "$got" = "$want" ]; then
    [ "$QUIET" != "--quiet" ] && echo "  ✔  ${label}"
    PASS=$((PASS+1))
  else
    echo "  ✗  ${label}  (got: ${got})"
    FAIL=$((FAIL+1))
  fi
}

echo ""
echo "═══════════════════════════════════════════════════"
echo "  WordPress VM — Health Validation"
echo "═══════════════════════════════════════════════════"

chk "WordPress running"  "$(PRUN inspect wordpress --format '{{.State.Status}}' 2>/dev/null)" "running"
chk "MariaDB running"    "$(PRUN inspect mariadb --format '{{.State.Status}}' 2>/dev/null)" "running"
chk "CrowdSec running"  "$(PRUN inspect crowdsec --format '{{.State.Status}}' 2>/dev/null)" "running"
  # stdout redirected too, not just stderr — mariadb(d)-admin ping --silent
  # still prints "mysqld is alive" on success, which otherwise leaks into
  # $_DB_PING and breaks the "ok" string comparison even on a good ping.
  _DB_PING=$(PRUN exec mariadb sh -c 'mariadbd-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1 || mariadb-admin ping --silent -uroot -p"${MARIADB_ROOT_PASSWORD}" >/dev/null 2>&1' && echo ok || echo fail)
  chk "MariaDB reachable (exec ping)" "${_DB_PING}"

DB=$(PRUN exec --user www-data wordpress php -r   'echo @mysqli_connect(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME"))?"ok":"fail";' 2>/dev/null || echo error)
chk "DB connectivity (www-data)" "$DB"

# PRODUCTION SAFETY FIX (v7-6k): same strengthened checks used at install
# and update time — see the matching comment in the post-install
# validation suite (create-wordpress-vm.sh) for the full rationale. Added
# alongside, not instead of, the ping/mysqli_connect checks above, so an
# admin running this script gets the same depth of validation update.sh
# relies on for its own rollback decisions.
_MARIADB_FULL=$([ -x /usr/local/bin/mariadb-health-check.sh ] && /usr/local/bin/mariadb-health-check.sh mariadb >/dev/null 2>&1 && echo ok || echo fail)
chk "MariaDB full health (query + InnoDB)" "${_MARIADB_FULL}"

_WP_FULL=$([ -x /usr/local/bin/wp-health-check.sh ] && /usr/local/bin/wp-health-check.sh wordpress 80 >/dev/null 2>&1 && echo ok || echo fail)
chk "WordPress full health (HTTP+PHP+DB)" "${_WP_FULL}"

PRUN exec wordpress mkdir -p /var/www/html/wp-content/uploads >/dev/null 2>&1 || true
UPL=$(PRUN exec --user www-data wordpress sh -c   'touch /var/www/html/wp-content/uploads/.wt && rm /var/www/html/wp-content/uploads/.wt && echo ok || echo fail' 2>/dev/null || echo fail)
chk "Uploads writable (www-data)" "$UPL"

chk "Port 80 listening" "$(netstat -tlnp 2>/dev/null | grep -c ':80 ' | tr -d ' ')" "1"
chk "nftables active"   "$(nft list tables 2>/dev/null | grep -c filter | tr -d ' ')" "1"
chk "CS bouncer"        "$(rc-service cs-firewall-bouncer status 2>/dev/null | grep -c started | tr -d ' ')" "1"
chk "8G .htaccess"      "$(grep -c '8G FIREWALL' /home/wpuser/wp/htaccess/.htaccess 2>/dev/null || echo 0)" "1"
chk "Trivy available"   "$(command -v trivy >/dev/null 2>&1 && echo ok || echo missing)"
chk "Lynis available"   "$(command -v lynis >/dev/null 2>&1 && echo ok || echo missing)"

WP_DEBUG=$(PRUN exec wordpress php -r 'echo (defined("WP_DEBUG") && WP_DEBUG)?"ON":"OFF";' 2>/dev/null || echo "?")
chk "WP_DEBUG is OFF"   "$WP_DEBUG" "OFF"

echo ""
echo "  Passed: ${PASS}  Failed: ${FAIL}"
[ "$FAIL" -gt 0 ] && echo "  Run wp-hardening.sh status for details" && exit 1
echo "  All checks passed"
exit 0
VALSCRIPT
chmod +x /usr/local/bin/validate-wordpress.sh
ok "validate-wordpress.sh installed — run anytime to check VM health"

# ── Done ──────────────────────────────────────────────────────────────────────
touch /var/log/wp-install.done
# Retry IP detection — filter out Podman bridges (10.89.x.x) and loopback.
# hostname -I can be empty briefly while DHCP completes, or contain only
# a wp-front/wp-db gateway address which is useless as a published address.
IP=""
for _ip_try in $(seq 1 12); do
  IP=$(hostname -I 2>/dev/null | tr ' ' '\n' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
    | grep -v '^10\.89\.' \
    | grep -v '^127\.' \
    | head -1)
  [ -n "$IP" ] && break
  sleep 5
done
IP="${IP:-<run: ip addr show eth0 | grep inet>}"

# Build ongoing login/admin URLs from custom slug if configured.
# IMPORTANT: WordPress setup (/wp-admin/install.php) is ALWAYS at the
# default path regardless of custom slug. The slug only applies AFTER
# setup completes — for day-to-day login and admin access.
if [ -n "${WP_ADMIN_SLUG}" ]; then
  LOGIN_URL="http://${IP}/${WP_ADMIN_SLUG}-login"
  ADMIN_URL="http://${IP}/${WP_ADMIN_SLUG}/"
else
  LOGIN_URL="http://${IP}/wp-login.php"
  ADMIN_URL="http://${IP}/wp-admin/"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║       WordPress VM Setup Complete!                         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 1 — MUST DO FIRST (standard WP setup URL):       ║"
echo "║     http://${IP}/wp-admin/install.php"
echo "║     ^ This URL is ALWAYS /wp-admin/install.php             ║"
echo "║     ^ Do NOT try /slug/install.php — that will 404         ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  ★  STEP 2 — After setup, use your custom slug:           ║"
echo "║     Login : ${LOGIN_URL}"
echo "║     Admin : ${ADMIN_URL}"
echo "║  WP         : ${WP_IMAGE}"
echo "║  MariaDB    : ${DB_IMAGE}  (internal wp-db only)"
echo "║  CrowdSec   : ${CROWDSEC_IMAGE}"
echo "║  Digest pin : ${DIGEST_PIN_SUMMARY:-disabled}$([ "${DIGEST_PIN_COUNT:-0}" != "3" ] && [ "${DIGEST_PIN_SUMMARY:-}" != "disabled" ] && echo " — see ${DIGEST_PIN_LOG}")"
echo "║  Kernel     : $(uname -r)"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Credentials  : /root/.wp-credentials (chmod 600)        ║"
if [ "${ADMIN_USER_CREATED:-0}" = "1" ]; then
echo "║  Admin login  : /root/.wp-admin-credentials (chmod 600)  ║"
fi
echo "║  Env file     : /etc/wordpress/env    (chmod 600)        ║"
echo "║  DB backups   : /root/wp-db-backups/ (daily, 7-day keep)║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Security layers active:                                  ║"
echo "║   L1  nftables       default-deny + wp-front/wp-db rules ║"
echo "║   L2  Apache         ADMIN_CIDR + custom slug + 8G WAF   ║"
echo "║   L3  CrowdSec       apache2 + wordpress + appsec-wp     ║"
echo "║   L4  Podman         cap-drop ALL, static IPs, DB=internal║"
echo "║   L5  Kernel         rp_filter=2, syncookies, ip_forward ║"
if [ "${ADMIN_USER_CREATED:-0}" = "1" ]; then
echo "║   L6  SSH            root login disabled — admin: ${ADMIN_USER} (doas for root)"
else
echo "║   L6  SSH            FALLBACK: admin account creation failed —"
echo "║                      root SSH is active instead. Create one by"
echo "║                      hand: adduser, addgroup <user> wheel,"
echo "║                      apk add doas, permit persist :wheel"
fi
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  Tooling:                                                 ║"
echo "║   update.sh status    — check + update all components    ║"
echo "║   update.sh trivy     — scan running containers for CVEs ║"
echo "║   wp-hardening.sh     — toggle security features         ║"
echo "║   validate-wordpress.sh — health check all layers        ║"
echo "║   wp-hardening.sh lynis — run Lynis security audit       ║"
echo "╠════════════════════════════════════════════════════════════╣"
[ -n "${CROWDSEC_ENROLL_KEY}" ]   && echo "║  CrowdSec: ENROLLED — accept at https://app.crowdsec.net ║"   || echo "║  CrowdSec: podman exec crowdsec cscli console enroll <k> ║"
echo "║  SSL: put behind NPM  OR  apk add certbot certbot-apache  ║"
echo "╚════════════════════════════════════════════════════════════╝"
INSTALLER_EOF

chmod +x "${TMPDIR}/install-wordpress.sh"
INST_LINES=$(wc -l < "${TMPDIR}/install-wordpress.sh")
(( INST_LINES > 100 )) || msg_error "Installer truncated (${INST_LINES} lines)"
msg_ok "Installer ready (${INST_LINES} lines)"

# ── Inject via qemu-nbd ───────────────────────────────────────────────────────
msg_info "Mounting disk image for injection…"
modprobe nbd max_part=8 2>/dev/null || true; sleep 1

NBD=""
for n in $(seq 0 15); do
  d="/dev/nbd${n}"; [[ -b "$d" ]] || continue
  sz=$(lsblk -bdno SIZE "$d" 2>/dev/null || echo 1)
  [[ "$sz" == "0" ]] && { NBD="$d"; break; }
done
[[ -n "$NBD" ]] || NBD="/dev/nbd0"
_NBD="$NBD"

qemu-nbd --connect="$NBD" "$WORK_IMG"; sleep 2
partprobe "$NBD" 2>/dev/null || true; sleep 1

ROOT_PART=""
for p in "${NBD}p2" "${NBD}p1" "${NBD}"; do
  [[ -b "$p" ]] || continue
  blkid "$p" 2>/dev/null | grep -qiE 'TYPE="ext[234]"' && { ROOT_PART="$p"; break; }
done
[[ -n "$ROOT_PART" ]] || ROOT_PART="${NBD}p1"
[[ -b "$ROOT_PART" ]] || ROOT_PART="$NBD"
msg_ok "Root partition: $ROOT_PART"

MNT="${TMPDIR}/mnt"; mkdir -p "$MNT"
mount "$ROOT_PART" "$MNT" || msg_error "Could not mount $ROOT_PART"
_MNT="$MNT"

# ─ Root password ──────────────────────────────────────────────────────────────
# Kept unconditionally — root SSH login is disabled below regardless of what
# the operator chose, but this password still matters for local console
# access (Proxmox `qm terminal` / serial0), which is unrelated to SSH.
HASHED=$(openssl passwd -6 "$ROOT_PASS")
if [[ -f "$MNT/etc/shadow" ]]; then
  sed -i "s|^root:[^:]*:|root:${HASHED}:|" "$MNT/etc/shadow"
else
  printf "root:%s:0:0:99999:7:::\n" "$HASHED" > "$MNT/etc/shadow"; chmod 640 "$MNT/etc/shadow"
fi

# ─ Admin account + doas + QEMU Guest Agent (needs a live chroot w/ network) ───
# BUG FIX (v7-6k): root SSH login is now disabled unconditionally (see the
# SSH hardening block below) — per remaining_tasks.txt item 5 ("no dedicated
# non-root admin account is created either way"), a real admin account
# replaces it: wheel group + doas, so root is only ever reached deliberately
# (doas), never as the SSH identity itself.
# Creating that account means `adduser`/`addgroup` writing into the target
# filesystem's own passwd/group/shadow — and installing doas needs apk +
# network — both requiring a live chroot, exactly like the QEMU Guest Agent
# pre-install already did on its own. Rather than mount and unmount /proc and
# /dev twice for two separate chroot calls, this single chroot now does all
# three (admin account, doas, guest agent); the mounts are left in place
# afterward and torn down once, at the very end of injection, right before
# the disk is unmounted — nothing else written between here and there cares
# whether /proc or /dev happen to be bind-mounted under $MNT.
# Each step below is independent (no `&&` chaining across concerns, nothing
# feeds set -e a bare failing command) so a doas/network hiccup can't stop
# the admin account or the guest agent from being set up, and vice versa —
# each is verified separately afterward rather than inferred from one
# shared exit code.
# ADMIN_USER is interpolated into this otherwise-single-quoted chroot string
# via close-quote/expand/reopen-quote — safe only because ADMIN_USER was
# already constrained to ^[a-z][a-z0-9_-]{0,31}$ above; no shell metachar is
# possible in it. SSH_KEYS and ADMIN_PASS are deliberately NOT interpolated
# here at all (operator-supplied content, unvalidated) — both are written
# host-side via plain redirection/sed after the chroot exits, the same way
# root's own password and key already are, never passed through `sh -c`.
cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true
mount --bind /proc "$MNT/proc" 2>/dev/null || true
mount --bind /dev  "$MNT/dev"  2>/dev/null || true
if chroot "$MNT" /bin/sh -c '
  VER=$(cut -d. -f1,2 /etc/alpine-release 2>/dev/null || echo "3.23")
  grep -q community /etc/apk/repositories 2>/dev/null \
    || printf "\nhttps://dl-cdn.alpinelinux.org/alpine/v%s/community\n" \
         "$VER" >> /etc/apk/repositories
  apk update --quiet --no-progress 2>/dev/null

  addgroup wheel 2>/dev/null || true
  id "'"$ADMIN_USER"'" >/dev/null 2>&1 || adduser -D -s /bin/sh "'"$ADMIN_USER"'" 2>/dev/null
  addgroup "'"$ADMIN_USER"'" wheel 2>/dev/null || true

  apk add --quiet --no-progress --no-cache doas 2>/dev/null
  mkdir -p /etc/doas.d
  echo "permit persist :wheel" > /etc/doas.d/doas.conf
  chown root:root /etc/doas.d/doas.conf
  chmod 0400 /etc/doas.d/doas.conf

  apk add --quiet --no-progress --no-cache qemu-guest-agent 2>/dev/null
  ln -sf /etc/init.d/qemu-guest-agent /etc/runlevels/default/qemu-guest-agent 2>/dev/null
' 2>/dev/null; then
  msg_ok "QEMU Guest Agent pre-installed"
else
  msg_warn "Guest agent pre-install skipped (will install on first boot)"
fi

# Verify the admin account independently of the chroot's own exit status
# (that status reflects the LAST command in the script above, i.e. the
# guest-agent symlink — a doas/network failure earlier must not be read as
# "admin account missing" or vice versa). grep's non-match is a real
# possible outcome here, not a bug, so this is an explicit if — under
# set -e a bare failing grep outside a conditional would abort the script.
ADMIN_USER_CREATED=0
ADMIN_UID="" ADMIN_GID=""
if grep -q "^${ADMIN_USER}:" "$MNT/etc/passwd" 2>/dev/null; then
  ADMIN_USER_CREATED=1
  ADMIN_UID=$(grep "^${ADMIN_USER}:" "$MNT/etc/passwd" | cut -d: -f3)
  ADMIN_GID=$(grep "^${ADMIN_USER}:" "$MNT/etc/passwd" | cut -d: -f4)
  msg_ok "Admin account: ${ADMIN_USER} (uid ${ADMIN_UID}), wheel + doas configured"
else
  msg_warn "Admin account creation failed — root SSH will be used as a fallback (see summary)"
fi

# ─ Hostname ───────────────────────────────────────────────────────────────────
echo "$HN" > "$MNT/etc/hostname"
grep -q "$HN" "$MNT/etc/hosts" 2>/dev/null || echo "127.0.1.1  $HN" >> "$MNT/etc/hosts"

# ─ SSH hardening ──────────────────────────────────────────────────────────────
SSHCFG="$MNT/etc/ssh/sshd_config"; mkdir -p "$MNT/etc/ssh"
[[ $DISABLE_PW_AUTH -eq 1 ]] && _PWAUTH="no" || _PWAUTH="yes"

if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  # Normal path: root SSH is fully disabled — the admin account (wheel +
  # doas, created in the chroot above) is the only way in.
  _ROOTLOGIN="no"
  ADMIN_HASHED=$(openssl passwd -6 "$ADMIN_PASS")
  sed -i "s|^${ADMIN_USER}:[^:]*:|${ADMIN_USER}:${ADMIN_HASHED}:|" "$MNT/etc/shadow"
  if [[ -n "$SSH_KEYS" ]]; then
    mkdir -p "$MNT/home/${ADMIN_USER}/.ssh"
    echo "$SSH_KEYS" > "$MNT/home/${ADMIN_USER}/.ssh/authorized_keys"
    chmod 700 "$MNT/home/${ADMIN_USER}/.ssh"
    chmod 600 "$MNT/home/${ADMIN_USER}/.ssh/authorized_keys"
    chown -R "${ADMIN_UID}:${ADMIN_GID}" "$MNT/home/${ADMIN_USER}"
  fi
else
  # FALLBACK — should be rare, adduser is a simple local-filesystem
  # operation with no network dependency. If the admin account genuinely
  # couldn't be created, root SSH is re-enabled as a safety net rather than
  # leaving the VM completely unreachable over SSH after first boot. This
  # is a degraded state, not a final one — flagged loudly here and again in
  # the closing summary; fix by hand after boot: adduser, addgroup <user>
  # wheel, apk add doas, echo 'permit persist :wheel' > /etc/doas.d/doas.conf.
  [[ $DISABLE_PW_AUTH -eq 1 ]] && _ROOTLOGIN="prohibit-password" || _ROOTLOGIN="yes"
fi

cat > "$SSHCFG" << SSHEOF
PermitRootLogin ${_ROOTLOGIN}
PasswordAuthentication ${_PWAUTH}
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 6
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
IgnoreRhosts yes
HostbasedAuthentication no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
SSHEOF
chmod 600 "$SSHCFG"

if [[ "$ADMIN_USER_CREATED" -ne 1 && -n "$SSH_KEYS" ]]; then
  # Only reached in the fallback branch above — normal path puts the key on
  # the admin account instead (see the ADMIN_USER_CREATED block above).
  mkdir -p "$MNT/root/.ssh"
  echo "$SSH_KEYS" > "$MNT/root/.ssh/authorized_keys"
  chmod 700 "$MNT/root/.ssh"; chmod 600 "$MNT/root/.ssh/authorized_keys"
fi

if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  msg_ok "SSH: ${ADMIN_USER} ($([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password')), root login disabled"
else
  msg_warn "SSH: FALLBACK — root login (${_ROOTLOGIN}), admin account unavailable"
fi

# ─ Admin credentials note (only what the operator doesn't already know) ──────
# ROOT_PASS is never written to disk in plaintext (the operator typed it, no
# need to also leave a copy lying around) — same treatment here. The
# operator-chosen admin password (no-key path) is likewise never written.
# The AUTO-GENERATED admin password (key-provided path, used only by doas —
# see the SSH access prompt) is the one exception: nobody typed it, so
# without writing it down it would be permanently unusable, exactly like the
# openssl-rand DB passwords already documented in /root/.wp-credentials.
if [[ "$ADMIN_USER_CREATED" -eq 1 ]]; then
  if [[ -n "$SSH_KEYS" ]]; then
    cat > "$MNT/root/.wp-admin-credentials" << ADMINCREDS
# ============================================================
# Admin account — generated by create-wordpress-vm.sh
# chmod 600 /root/.wp-admin-credentials
# ============================================================
# Username : ${ADMIN_USER}
# SSH      : key-only (the public key supplied during provisioning)
# Password : ${ADMIN_PASS}
#   Not used for SSH (password login is disabled) — only for 'doas'
#   once logged in, or as a local-console recovery password.
# doas     : any command as root, e.g.  doas -s   (interactive root shell)
# ============================================================
ADMINCREDS
  else
    cat > "$MNT/root/.wp-admin-credentials" << ADMINCREDS
# ============================================================
# Admin account — generated by create-wordpress-vm.sh
# chmod 600 /root/.wp-admin-credentials
# ============================================================
# Username : ${ADMIN_USER}
# SSH      : password (the one set during provisioning)
# doas     : any command as root, e.g.  doas -s   (interactive root shell)
# ============================================================
ADMINCREDS
  fi
  chmod 600 "$MNT/root/.wp-admin-credentials"
  msg_ok "/root/.wp-admin-credentials written (chmod 600)"
fi

# ─ nftables ───────────────────────────────────────────────────────────────────
echo "$NFT_CONF" > "$MNT/etc/nftables.nft"; chmod 600 "$MNT/etc/nftables.nft"
msg_ok "nftables.nft injected"

# ─ Network addressing (DHCP or static) ────────────────────────────────────────
# Alpine's cloud image reads /etc/network/interfaces via the OpenRC "networking"
# service (already enabled below). We overwrite it unconditionally so behaviour
# is deterministic regardless of what the base image shipped with.
mkdir -p "$MNT/etc/network"
if [[ "$NET_MODE" == "static" ]]; then
  IFS=' ' read -r -a _dns_arr <<< "$VM_DNS"
  cat > "$MNT/etc/network/interfaces" << IFACEEOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address ${VM_STATIC_IP}
    netmask ${VM_NETMASK}
    gateway ${VM_GATEWAY}
    dns-nameservers ${_dns_arr[*]}
IFACEEOF
  msg_ok "Static network config injected: ${VM_STATIC_IP}/${VM_PREFIX} via ${VM_GATEWAY}"
else
  cat > "$MNT/etc/network/interfaces" << 'IFACEEOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
IFACEEOF
  msg_ok "DHCP network config injected"
fi

# Write installer variables that can't go in the INSTALLER_EOF heredoc
# (which is single-quoted on the host, so host variables don't expand inside).
# The installer sources this file early in Stage 2.
mkdir -p "$MNT/etc/wp-install"
cat > "$MNT/etc/wp-install/vars.sh" << INSTALLERENV
# WordPress VM installer variables — generated by create-wordpress-vm.sh
# Sourced by /root/install-wordpress.sh during Stage 2
WP_ADMIN_SLUG="${WP_ADMIN_SLUG}"
CROWDSEC_ENROLL_KEY="${CROWDSEC_ENROLL_KEY}"
NET_MODE="${NET_MODE}"
VM_STATIC_IP="${VM_STATIC_IP}"
GEOIP_ENABLED="${GEOIP_ENABLED:-0}"
GEOIP_MODE="${GEOIP_MODE:-}"
GEOIP_WHITELIST="${GEOIP_WHITELIST:-}"
GEOIP_BLOCKLIST="${GEOIP_BLOCKLIST:-}"
MAXMIND_ACCOUNT_ID="${MAXMIND_ACCOUNT_ID:-}"
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"
USE_DIGEST_PINNING="${USE_DIGEST_PINNING:-1}"
ADMIN_USER="${ADMIN_USER}"
ADMIN_USER_CREATED="${ADMIN_USER_CREATED:-0}"
INSTALLERENV
chmod 600 "$MNT/etc/wp-install/vars.sh"
msg_ok "Installer vars injected (slug=${WP_ADMIN_SLUG:-default}, cs-enroll=${CROWDSEC_ENROLL_KEY:+provided}, net=${NET_MODE}, geoip=${GEOIP_ENABLED:-0}, digest-pin=${USE_DIGEST_PINNING:-1}, admin=${ADMIN_USER})"

# ─ Apache security config (host-built, CIDRs/IPs already substituted) ─────────
# The installer reads this from /root/wp-security.conf and copies it to the
# correct bind-mount path. This is the same pattern as nftables injection.
printf '%s\n' "$APACHE_SECURITY_CONF" > "$MNT/root/wp-security.conf"
chmod 644 "$MNT/root/wp-security.conf"
msg_ok "wp-security.conf injected (admin: ${ADMIN_CIDR:-open}, extra-ip: ${ALLOWED_ADMIN_IP:-none})"

# ─ mod_remoteip files (only if PROXY_IP was set) ─────────────────────────────
if [[ -n "$PROXY_IP" ]]; then
  cat > "$MNT/root/wp-remoteip.load" << RILOAD
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
RILOAD
  cat > "$MNT/root/wp-remoteip.conf" << RICONF
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy ${PROXY_IP}
RICONF
  chmod 644 "$MNT/root/wp-remoteip.load" "$MNT/root/wp-remoteip.conf"
  msg_ok "mod_remoteip files injected (trusted proxy: ${PROXY_IP})"
fi

# ─ Installer script ───────────────────────────────────────────────────────────
mkdir -p "$MNT/root"
cp "${TMPDIR}/install-wordpress.sh" "$MNT/root/install-wordpress.sh"
chmod +x "$MNT/root/install-wordpress.sh"
[[ -s "$MNT/root/install-wordpress.sh" ]] || msg_error "Installer copy failed."
msg_ok "install-wordpress.sh written ($(wc -l < "$MNT/root/install-wordpress.sh") lines)"

# ─ First-boot launcher ────────────────────────────────────────────────────────
mkdir -p "$MNT/etc/local.d"
cat > "$MNT/etc/local.d/01-wordpress.start" << 'LAUNCH'
#!/bin/sh
[ -f /var/log/wp-install.done ] && exit 0
mkdir -p /var/log
exec sh /root/install-wordpress.sh >> /var/log/wp-install.log 2>&1
LAUNCH
chmod +x "$MNT/etc/local.d/01-wordpress.start"

# ─ OpenRC runlevel symlinks ───────────────────────────────────────────────────
mkdir -p "$MNT/etc/runlevels/default"
for svc in local sshd networking; do
  [[ -f "$MNT/etc/init.d/$svc" ]] \
    && ln -sf "/etc/init.d/$svc" "$MNT/etc/runlevels/default/$svc" 2>/dev/null || true
done

# ─ Disable cloud-init ─────────────────────────────────────────────────────────
touch "$MNT/etc/cloud/cloud-init.disabled" 2>/dev/null || true
for s in cloud-init-local cloud-init cloud-config cloud-final; do
  rm -f "$MNT/etc/runlevels/"{default,boot,sysinit}"/$s" 2>/dev/null || true
done

# ─ Unmount ────────────────────────────────────────────────────────────────────
# /proc and /dev were bind-mounted much earlier (right after the root
# password block) for the combined admin-account/doas/QEMU-agent chroot —
# see the comment there for why the mounts were left in place since then
# instead of being torn down and remounted a second time.
umount "$MNT/dev"  2>/dev/null || true
umount "$MNT/proc" 2>/dev/null || true
umount "$MNT" && _MNT=""
qemu-nbd --disconnect "$NBD" && _NBD=""
msg_ok "Injection complete"

# ── Create VM ─────────────────────────────────────────────────────────────────
msg_info "Creating VM ${VMID} (${HN})…"
qm create "$VMID" \
  --name        "$HN" \
  --memory      "$RAM" \
  --cores       "$CORES" \
  --sockets     1 \
  --cpu         host \
  --net0        "virtio,bridge=${BRIDGE}${VLAN}" \
  --scsihw      virtio-scsi-single \
  --ostype      l26 \
  --onboot      1 \
  --startup     "order=3,up=30" \
  --tablet      0 \
  --vga         serial0 \
  --serial0     socket \
  --boot        order=scsi0 \
  --agent       "enabled=1,fstrim_cloned_disks=1" \
  --description "Alpine ${ALPINE_VER} | WordPress + MariaDB (wp-front/wp-db) + CrowdSec | $(date '+%Y-%m-%d')"
msg_ok "VM skeleton created"

msg_info "Importing disk to ${STORAGE}…"
qm importdisk "$VMID" "$WORK_IMG" "$STORAGE" ${DISK_FMT} 1>/dev/null
rm -f "$WORK_IMG"
msg_ok "Disk imported"

qm set "$VMID" --scsi0 "$DISK_OPTS" --boot order=scsi0 --serial0 socket 1>/dev/null
msg_ok "Disk attached"

# ── Start VM ──────────────────────────────────────────────────────────────────
qm start "$VMID"
msg_ok "VM ${VMID} started"
_DESTROY_VM=0

# ── Wait for IP ───────────────────────────────────────────────────────────────
VM_MAC=$(qm config "$VMID" 2>/dev/null \
  | grep -m1 '^net0:' \
  | grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' \
  | tr '[:upper:]' '[:lower:]') || VM_MAC=""

echo ""
if [[ "$NET_MODE" == "static" ]]; then
  echo -e "  ${YW}Static IP configured — confirming the VM boots (up to 30s)…${CL}"
else
  echo -e "  ${YW}Waiting up to 2 minutes for an IP address… (Ctrl-C to skip)${CL}"
fi
echo ""

VM_IP="${VM_STATIC_IP}" ELAPSED=0 AGENT=0
WAIT_CAP=120
[[ "$NET_MODE" == "static" ]] && WAIT_CAP=30
SPIN=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏'); SI=0

set +e
while (( ELAPSED < WAIT_CAP )); do
  if (( AGENT == 0 )) && qm agent "$VMID" ping &>/dev/null 2>&1; then
    AGENT=1; printf "\r  ${GN}✔${CL}  Guest agent online (%ds)\n" "$ELAPSED"
    if [[ "$NET_MODE" == "static" ]]; then
      printf "  ${GN}✔${CL}  Using configured static IP: ${BLD}%s${CL}\n" "$VM_IP"
      break
    fi
  fi
  if (( AGENT == 1 )) && [[ "$NET_MODE" != "static" ]]; then
    VM_IP=$(qm agent "$VMID" network-get-interfaces 2>/dev/null \
      | grep -oP '"ip-address":\s*"\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
      | grep -v '^127\.' | head -1) || VM_IP=""
    [[ -n "$VM_IP" ]] && { printf "\r  ${GN}✔${CL}  IP (agent): ${BLD}%s${CL}\n" "$VM_IP"; break; }
  fi
  if [[ -n "$VM_MAC" && "$NET_MODE" != "static" ]]; then
    VM_IP=$(ip -4 neigh show 2>/dev/null \
      | awk -v m="$VM_MAC" 'tolower($5)==m{print $1;exit}') || VM_IP=""
    [[ -n "$VM_IP" ]] && { printf "\r  ${GN}✔${CL}  IP (ARP):   ${BLD}%s${CL}\n" "$VM_IP"; break; }
  fi
  printf "\r  ${SPIN[$SI]}  Booting… %ds " "$ELAPSED"
  SI=$(( (SI+1) % ${#SPIN[@]} ))
  sleep 5; ELAPSED=$(( ELAPSED+5 ))
done
set -e

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
printf "${GN}${BLD}"
echo   "  ╔══════════════════════════════════════════════════════════════╗"
echo   "  ║        WordPress VM Created                                  ║"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
printf "  ║  VM ID    :  %-47s║\n"  "$VMID"
printf "  ║  Hostname :  %-47s║\n"  "$HN"
printf "  ║  Alpine   :  %-47s║\n"  "$ALPINE_VER"
printf "  ║  Resources:  %-47s║\n"  "${CORES} CPU · ${RAM} MB · ${DISK}"
printf "  ║  MAC      :  %-47s║\n"  "${VM_MAC:-see: qm config $VMID}"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
if [[ "${ADMIN_USER_CREATED:-0}" -eq 1 ]]; then
  _SSH_DESC="${ADMIN_USER} — $([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password'), root SSH disabled"
else
  _SSH_DESC="FALLBACK: root SSH ($([[ $DISABLE_PW_AUTH -eq 1 ]] && echo 'key-only' || echo 'password')) — admin account failed"
fi
printf "  ║  SSH      :  %-47s║\n" "$_SSH_DESC"
[[ "${ADMIN_USER_CREATED:-0}" -eq 0 ]] && printf "  ║  ${RD}⚠ Admin account was NOT created — see install log, create by hand${CL}  ║\n"
printf "  ║  L1 nftables   SSH=%-12s  Web=%-21s║\n" "${SSH_CIDR:-any}" "${WEB_CIDR:-any}"
printf "  ║  L2 wp-admin   cidr=%-11s  extra-ip=%-16s║\n" "${ADMIN_CIDR:-open}" "${ALLOWED_ADMIN_IP:-none}"
printf "  ║  mod_remoteip  proxy=%-40s║\n"  "${PROXY_IP:-not configured (direct)}"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  # Pre-compute summary values (avoids quote-in-subshell issues)
  _WP_PORT_DESC="6.9.4-php8.3-apache → port 80"
  if [[ -n "${VM_STATIC_IP}" ]]; then
    _NET_DESC="${NET_MODE:-dhcp} → ${VM_STATIC_IP}/${VM_PREFIX} via ${VM_GATEWAY}"
  else
    _NET_DESC="${NET_MODE:-dhcp}"
  fi
  if [[ "${GEOIP_ENABLED:-0}" == "1" ]]; then
    _GEO_DESC="${GEOIP_MODE} (${GEOIP_WHITELIST:-$GEOIP_BLOCKLIST})"
  else
    _GEO_DESC="disabled"
  fi
  echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  Containers (all --cap-drop ALL):                           ║"
  printf "  ║    WordPress  %-47s║\n" "${_WP_PORT_DESC}"
  printf "  ║    MariaDB    %-47s║\n" "11.4 → wp-db:10.89.20.0/24 internal (no host port)"
  printf "  ║    CrowdSec   %-47s║\n" "v1.7.8 → host network, read-only"
  echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  Networking: netavark firewall_driver=nftables (no iptables)║"
  echo   "  ║  nftables forward: wp-front 10.89.10.0/24 + wp-db 10.89.20.0/24,║"
  echo   "  ║  all else DROP. wp-db is --internal (MariaDB has no egress) ║"
  printf "  ║  Network:       %-44s║\n" "${_NET_DESC}"
  printf "  ║  GeoIP:         %-44s║\n" "${_GEO_DESC}"
  [[ -n "${WP_ADMIN_SLUG}" ]] && printf "  ║  Custom slug:   %-44s║\n" "/${WP_ADMIN_SLUG}-login"
echo   "  ║  Background install (~15 min total):                       ║"
echo   "  ║    qm terminal $VMID  then:  tail -f /var/log/wp-install.log"
echo   "  ╠══════════════════════════════════════════════════════════════╣"
  echo   "  ║  When done: http://<VM-IP>/wp-admin/install.php            ║"
echo   "  ╚══════════════════════════════════════════════════════════════╝"
printf "${CL}"
echo ""
