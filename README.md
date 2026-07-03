# alpine-vm-wordpress

=============================================================================
# WORDPRESS VM — PROXMOX VE PROVISIONING SCRIPT  (v6.5 — production-ready)
# =============================================================================
#
# CRITICAL BUGS FIXED vs v3:
#   1. netavark firewall_driver now set to "nftables" — eliminates the
#      "netavark: iptables: No such file or directory" error on Alpine.
#      Alpine's netavark defaults to iptables which isn't installed; setting
#      nftables here uses the already-installed 'nft' binary instead.
#   2. nftables forward chain now allows 10.89.1.0/24 (wp-net subnet) before
#      the policy drop — without this containers couldn't reach the internet
#      even after fix #1, because nftables DROP preempts any iptables ACCEPT.
#   3. aardvark-dns installed explicitly — provides container-to-container DNS
#      on wp-net so WordPress can resolve hostname 'mariadb:3306'. Without it
#      the container starts but the DB connection fails with a name lookup error.
#   4. /var/log/messages touched before CrowdSec starts — Podman fails with
#      "No such file or directory" if the bind-mount source doesn't exist yet.
#   5. wp-net created with explicit subnet 10.89.1.0/24 — makes nftables
#      forward rule deterministic; without it netavark assigns a random subnet.
#   6. rp_filter changed from strict (1) to loose (2) — strict mode can drop
#      container NAT traffic due to asymmetric routing on the Podman bridge.
#   7. net.ipv4.ip_forward=1 now explicit in sysctl — required for container
#      packet forwarding; netavark enables it but explicit is more resilient.
#
# WRONG VERSIONS FIXED vs v3:
#   8. WordPress: 6.7.2 → 6.8 floating tag (6.8.x security patches auto)
#      6.8 is current stable; 7.0.0 released June 2026 but too new for MSP.
#   9. CrowdSec: v1.6.8 (DOES NOT EXIST) → v1.7.4 (latest stable, Dec 2024).
#      v1.7.0+ requires /var/lib/crowdsec/data volume — already mounted ✓.
#
# FUNCTIONAL ISSUES FIXED vs v3:
#  10. PHP session.cookie_samesite: Strict → Lax. Strict breaks WordPress
#      OAuth flows, WooCommerce payment gateway callbacks, and SSO plugins.
#  11. PHP allow_url_fopen: Off → On. Many WooCommerce payment gateways and
#      plugin APIs use file_get_contents() with URLs; Off breaks them silently.
#      allow_url_include stays Off (blocks remote code inclusion attacks).
#  12. DISABLE_WP_CRON=true added to wp-config — WP-Cron only fires on page
#      loads and is unreliable in production. Real system cron added instead.
#  13. WordPress system cron added (*/5 * * * *) — runs wp-cron.php inside
#      the container; handles scheduled posts, updates, and plugin jobs.
#  14. Daily MariaDB backup cron (02:00) — gzipped mysqldump to /root/wp-db-
#      backups/ with 7-day auto-retention. Essential for MSP production.
#  15. MariaDB InnoDB buffer pool capped (256M) — without a limit MariaDB can
#      consume all available VM RAM, evicting other containers.
#      Also enables slow query log for performance debugging.
#  16. MariaDB conf mounted in OpenRC service and update.sh — consistent
#      between first install, reboots, and updates.
#   1. mariadb:11.4-lts → mariadb:11.4   (11.4-lts tag does not exist on Hub)
#   2. wordpress pin updated to 6.7.2-php8.3-apache (full semver, more stable)
#   3. mariadb-admin ping now passes credentials (anonymous ping can be denied)
#   4. WordPress container now has --cap-drop ALL + exact cap-add (was missing)
#   5. mariadb-container + wp-container services now export PODMAN_IGNORE env
#   6. wp-container service now has lsmod + modprobe calls (matched mariadb-svc)
#   7. mount --make-shared / added to both container services (Podman overlay)
#   8. podman-compose removed — podman auto-update is a built-in, needs no pkg
#
# SECURITY IMPROVEMENTS vs v2:
#   A. wp-admin / wp-login.php Apache IP restriction (new prompts)
#      — separate from nftables WEB_CIDR; works at HTTP request layer
#   B. mod_remoteip enabled when behind a reverse proxy (new PROXY_IP prompt)
#      — ensures Require ip checks real client IP through NPM/nginx/Caddy
#   C. WordPress now has --cap-drop ALL (same discipline as MariaDB)
#      + NET_BIND_SERVICE (Apache binds port 80 in container netns)
#      + SETUID/SETGID/CHOWN/DAC_OVERRIDE/FOWNER (same as MariaDB)
#   D. PHP: allow_url_fopen=Off + allow_url_include=Off (blocks RFI attacks)
#   E. Apache: Content-Security-Policy + Permissions-Policy headers
#   F. Apache: PHP execution blocked in wp-content/uploads (webshell guard)
#   G. Apache: author=N query string blocked (username enumeration)
#   H. Apache: debug.log access blocked
#   I. Apache config now built HOST-SIDE with CIDRs baked in, injected via
#      qemu-nbd — same pattern as nftables, no runtime substitution needed
#
# ROOTFUL vs ROOTLESS DECISION (documented):
#   MariaDB  — rootful, --cap-drop ALL + 5 caps, isolated to wp-net, no host
#              port. Equivalent security to rootless for this workload.
#   WordPress — rootful, --cap-drop ALL + 6 caps. Requires NET_BIND_SERVICE
#              because Apache binds port 80 inside the container's own network
#              namespace even with -p 80:80 (Podman's host-side port publish
#              is separate from Apache's in-netns bind). Making WordPress
#              rootless requires either running Apache on port 8080+ (needs
#              a ports.conf override) or sysctl ip_unprivileged_port_start=0,
#              both of which add fragility with no meaningful security gain
#              given the VM is the primary isolation boundary.
#   CrowdSec  — rootful, --network host, --read-only, minimal caps.
#              Must use host network to see syslog and write nftables rules.
# =============================================================================
