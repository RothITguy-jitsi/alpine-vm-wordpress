#!/usr/bin/env bash
# 03-dynamic-configs.sh — part of install.sh (host-side, runs on the Proxmox VE host).
# Builds the host-side dynamic config blocks that need operator-supplied values baked in at generation time: nftables ruleset, wp-admin IP block, mod_remoteip block, custom-slug block, and the combined Apache security config.
# Sourced by install.sh in order -- do not run this file directly; it
# depends on variables and functions (msg_*, TMPDIR, REPO_DIR, MNT, etc.)
# that install.sh and earlier lib files set up.

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

# ── Egress proxy enforcement ─────────────────────────────────────────────────
# The control that turns Squid from a suggestion into a boundary.
#
# WordPress's own proxy settings are honoured only by code that chooses to
# honour them. A plugin calling fsockopen(), or curl without CURLOPT_PROXY,
# goes straight past WP_PROXY_HOST and reaches the internet directly. Without
# a firewall rule the proxy filters only well-behaved traffic — which is not
# the traffic anyone is worried about.
#
# So: wp-front may reach the proxy, and nothing else on the WAN. Squid runs on
# the same bridge and is exempt because it IS the sanctioned path out.
#
# Placed BEFORE the general container-egress accept, or it never matches.
# One accept per configured resolver. Built here rather than inlined so an
# operator who picked three DNS servers gets three rules, and so a malformed
# entry cannot silently produce a rule that matches nothing.
SQUID_DNS_RULES=""
for _d in ${VM_DNS:-9.9.9.9 149.112.112.112}; do
  case "$_d" in
    *[!0-9.]*|"") continue ;;
  esac
  SQUID_DNS_RULES="${SQUID_DNS_RULES}        ip saddr 10.89.10.2 ip daddr ${_d} udp dport 53 accept"$'\n'
  SQUID_DNS_RULES="${SQUID_DNS_RULES}        ip saddr 10.89.10.2 ip daddr ${_d} tcp dport 53 accept"$'\n'
done
SQUID_DNS_RULES="${SQUID_DNS_RULES%$'\n'}"

# SMTP rules are built HERE, before the egress-proxy block below, because that
# block now expands ${SMTP_RATE_LIMIT} inside itself -- ahead of its own
# catch-all drop. Defining it afterwards expanded to an empty string and the
# rule silently vanished, which is exactly the failure this move is fixing.
# ── Destination restriction for SMTP ─────────────────────────────────────────
# An external evaluation's top finding, and it was already noted as a known gap
# in the comment below: rate-limiting submission stops bulk exfiltration but
# does not stop a compromised WordPress talking to an attacker's OWN mail server
# on 587. Thirty connections an hour is plenty to leak credentials or stage
# small payloads to a destination of the attacker's choosing.
#
# So the rule is now pinned to the relay's addresses when they can be resolved
# at install time. Note the honest limits of this:
#
#   * It resolves the relay ONCE, here. A relay that changes IP -- common with
#     hosted providers behind load balancers -- will stop working until this is
#     re-run. That is a real operational cost, and it is why this degrades to
#     the old port-only rule with a WARNING rather than failing the install:
#     silently breaking a client's password resets to close a theoretical
#     channel is the wrong trade to make on their behalf.
#   * A relay on shared infrastructure (Google, Microsoft 365) resolves to
#     addresses shared with thousands of tenants, so pinning buys less there.
#     It still removes "any host on the internet".
SMTP_DEST_RULE=""
if [[ -n "${SMTP_HOST:-}" ]]; then
  _smtp_ips=$(getent ahostsv4 "$SMTP_HOST" 2>/dev/null | awk '{print $1}' | sort -u | head -8)
  if [[ -n "$_smtp_ips" ]]; then
    for _sip in $_smtp_ips; do
      case "$_sip" in
        *[!0-9.]*) continue ;;
      esac
      SMTP_DEST_RULE="${SMTP_DEST_RULE}${SMTP_DEST_RULE:+ }${_sip}"
    done
  fi
fi
if [[ -n "$SMTP_DEST_RULE" ]]; then
  _SMTP_DADDR="ip daddr { $(printf '%s' "$SMTP_DEST_RULE" | tr ' ' ',') } "
  msg_ok "SMTP egress pinned to ${SMTP_HOST} (${SMTP_DEST_RULE})"
  msg_info "  If the relay changes IP, mail stops until you re-run:"
  msg_info "    doas wp-hardening.sh smtp-repin"
else
  _SMTP_DADDR=""
  [[ -n "${SMTP_HOST:-}" ]] && msg_warn "Could not resolve ${SMTP_HOST} — SMTP egress stays port-only (any destination on those ports)."
fi

SMTP_RATE_LIMIT="        # Outbound mail submission — rate limited AND, where the relay
        # resolved at install time, destination-restricted. See lib/03.
        ip saddr 10.89.10.0/24 ${_SMTP_DADDR}tcp dport ${_SMTP_PORTS} ct state new limit rate ${_SMTP_RATE} burst ${_SMTP_BURST} packets counter accept
        ip saddr 10.89.10.0/24 tcp dport ${_SMTP_PORTS} ct state new limit rate 5/minute counter log prefix \"nft-smtp-ratelimit \" level warn
        ip saddr 10.89.10.0/24 tcp dport ${_SMTP_PORTS} ct state new counter drop"

# When the proxy is ON, SMTP is handled inside that block; expanding it twice
# would duplicate the rules and the rate limit would count each connection once
# per copy, halving the effective allowance.
SMTP_RATE_LIMIT_IF_NO_PROXY="${SMTP_RATE_LIMIT}"
if [[ "${EGRESS_PROXY:-0}" == "1" ]]; then
  SMTP_RATE_LIMIT_IF_NO_PROXY=""
  EGRESS_PROXY_FORWARD="        # WordPress -> Squid only. Everything else outbound is dropped.
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.2 tcp dport 3128 accept
        # DNS is pinned to the network's OWN resolver (the wp-front gateway,
        # where aardvark-dns listens), NOT allowed to any destination. Allowing
        # 53 to the whole internet leaves a DNS tunnel open: a compromised
        # WordPress can exfiltrate by encoding data into lookups to a resolver
        # it controls, entirely bypassing Squid. Squid resolves external names
        # itself (rule below), so WordPress only needs to resolve 'mariadb' and
        # the handful of names its own direct paths use -- all via the gateway.
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 udp dport 53 accept
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 tcp dport 53 accept
        # NTP to the gateway/host time service only, for the same reason: no
        # arbitrary-destination UDP 123 from the container subnet.
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 udp dport 123 accept
        # Squid reaches the web, and resolves external destinations itself. It
        # is the only thing that may leave, and its DNS also goes to the
        # gateway resolver rather than anywhere.
        ip saddr 10.89.10.2 ip daddr 10.89.10.1 udp dport 53 accept
        ip saddr 10.89.10.2 ip daddr 10.89.10.1 tcp dport 53 accept
        # Squid resolves external names itself, so it must reach the REAL
        # resolvers -- not only the podman gateway. Relying on aardvark-dns to
        # forward external queries was the single point of failure that made
        # every outbound request fail: Squid could not resolve anything, and
        # the symptom looked exactly like a policy denial. These are the
        # specific servers chosen at install, so DNS is still pinned to named
        # destinations and the tunnel stays closed.
${SQUID_DNS_RULES}
        ip saddr 10.89.10.2 tcp dport { 80, 443 } accept
        # ── SMTP, and it MUST be here rather than further down the chain ──────
        # nftables is first-match-wins, and the drop immediately below matches
        # the whole container subnet. The SMTP allow rule used to live AFTER
        # this block (as ${SMTP_RATE_LIMIT}, six lines later in the chain), so
        # it was never reached: enabling the egress proxy silently broke
        # WordPress's ability to send mail entirely. Password resets, order
        # confirmations and admin notifications all failed, and the only
        # symptom was `wp-mail.sh doctor` reporting
        # \"TCP 587: UNREACHABLE (Connection timed out)\" while every other
        # mail check passed.
        #
        # Mail cannot go through Squid: Squid is an HTTP proxy and speaks
        # nothing else. So submission needs its own hole, and the honest
        # framing is that this is a real gap in the egress boundary -- one
        # outbound TCP path that is not destination-filtered. The rate limit is
        # what keeps it from being a bulk exfiltration channel: 30 new
        # connections/hour with a burst of 10 is ample for a WordPress site
        # and useless for moving a database.
${SMTP_RATE_LIMIT}
        # Everything else from wp-front, logged then dropped. The log is what
        # discovery reads to find destinations the allowlist is missing, and
        # now also catches any attempt to reach an off-network resolver.
        ip saddr 10.89.10.0/24 limit rate 10/minute log prefix \"nft-egress-bypass \" level warn
        ip saddr 10.89.10.0/24 counter drop"
else
  EGRESS_PROXY_FORWARD="        # Egress proxy not enabled — WordPress reaches the web directly."
fi

# ── Web restriction, enforced where published ports actually pass ────────────
# VERIFIED BROKEN ON A LIVE VM: with WEB_CIDR=192.168.100.101, a curl from
# 192.168.100.148 connected successfully. The input-chain rule below reads
# correctly and matches nothing.
#
# Podman publishes a container port by DNAT'ing it in prerouting. After DNAT
# the destination is the container's address, not the host's, so the packet
# traverses the FORWARD hook — the filter INPUT chain never sees it. A
# restriction written for `input` on dport 80 is therefore a no-op for every
# published container port, while looking exactly like a working rule.
#
# This is the same failure shape as the wp-admin fail-open: the control is
# present, readable, and permissive.
#
# The negated set excludes loopback and the container networks so that
# host-local probes and container-to-container traffic are unaffected; only
# genuinely external sources outside WEB_CIDR are dropped.
if [[ -n "$WEB_CIDR" ]]; then
  WEB_CIDR_FORWARD="        # Enforce WEB_CIDR here, not in input — see the note in lib/03.
        ip daddr 10.89.10.0/24 tcp dport { 80, 443 } \
            ip saddr != { ${WEB_CIDR}, 127.0.0.0/8, 10.89.0.0/16 } \
            limit rate 5/minute log prefix \"nft-web-cidr-drop \" level warn
        ip daddr 10.89.10.0/24 tcp dport { 80, 443 } \
            ip saddr != { ${WEB_CIDR}, 127.0.0.0/8, 10.89.0.0/16 } counter drop"
else
  WEB_CIDR_FORWARD="        # Web ports open to any source (WEB_CIDR unset)."
fi

# ── Optional outbound (egress) restriction ────────────────────────────────────
# Default OFF. When on, the VM and its containers may only reach the ports
# every feature here actually needs; everything else is logged and dropped.
#
# What is allowed and why -- each of these has a concrete consumer, so the
# list is a statement about this system's dependencies rather than a guess:
#   53  DNS        resolution for everything below
#   123 NTP        chrony; without it TLS validation and log correlation drift
#   67/68 DHCP     only used when the VM is not statically addressed
#   80  HTTP       Alpine apk repositories, redirect-to-HTTPS
#   443 HTTPS      registries (Docker Hub), WordPress + plugin update APIs,
#                  CrowdSec CAPI, MaxMind, Trivy vulnerability DB, GitHub
#   25/465/587     outbound mail (already connection-rate-limited above)
#
# Stated plainly: 443 has to stay open, so this is not containment against a
# determined attacker -- anyone who wants a covert channel will use 443. It
# removes the easy options: C2 on an odd port, a reverse shell on 4444, a
# botnet joining IRC on 6667, bulk exfiltration over a random high port.
#
# Operator-added ports live in the named sets declared on the table, so
# `wp-hardening.sh egress-allow 8443` takes effect immediately and survives a
# reboot, without regenerating or reloading this file.
if [[ "${RESTRICT_EGRESS:-0}" == "1" ]]; then
  EGRESS_OUTPUT="        # ── Egress restriction ACTIVE (RESTRICT_EGRESS=1) ──
        # The host's own outbound traffic. ct-established and lo were already
        # accepted above, so only genuinely new connections reach here.
        ip daddr { 10.89.10.0/24, 10.89.20.0/24 } accept
        udp dport { 53, 67, 68, 123 } accept
        tcp dport { 53, 80, 443 } accept
        tcp dport { 25, 465, 587 } accept
        tcp dport @egress_extra_tcp accept
        udp dport @egress_extra_udp accept
        icmp type echo-request accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
        limit rate 5/minute log prefix \"nft-egress-drop \" level warn
        counter drop"
  EGRESS_FORWARD="        # ── Container egress, restricted (RESTRICT_EGRESS=1) ──
        # SMTP is handled by the rate-limit rules above and never reaches here.
        ip saddr 10.89.10.0/24 udp dport { 53, 123 } accept
        ip saddr 10.89.10.0/24 tcp dport { 53, 80, 443 } accept
        ip saddr 10.89.10.0/24 tcp dport @egress_extra_tcp accept
        ip saddr 10.89.10.0/24 udp dport @egress_extra_udp accept
        ip saddr 10.89.10.0/24 icmp type echo-request accept
        ip saddr 10.89.10.0/24 limit rate 5/minute log prefix \"nft-egress-drop-ctr \" level warn
        ip saddr 10.89.10.0/24 counter drop"
else
  EGRESS_OUTPUT="        # Egress unrestricted (RESTRICT_EGRESS=0) — only the hypervisor
        # management plane above is blocked."
  EGRESS_FORWARD="        # wp-front (10.89.10.0/24): WordPress's egress + published-port network.
        ip saddr 10.89.10.0/24 accept"
fi

# ── Hypervisor management-plane egress block (NEW) ────────────────────────────
# A compromised WordPress VM has no legitimate reason to reach the Proxmox
# management plane, and that plane is the highest-value thing on the LAN from
# the VM's point of view: reaching it turns "one web app is owned" into "the
# hypervisor hosting every other VM is being probed." These rules drop
# egress from both the VM itself (output hook) and its containers (forward
# hook) toward the Proxmox/PBS/console ports.
#
# Deliberately scoped to RFC1918 destinations and to management ports only,
# which is what makes this operationally safe rather than merely strict:
#   - Internet egress is untouched (WordPress/plugin updates, Alpine apk,
#     CrowdSec, MaxMind) -- those are public addresses, not RFC1918.
#   - LAN services on their own ports are untouched -- a LAN DNS resolver on
#     53, NTP on 123, an SMTP relay on 25/587 all still work, because only
#     the management ports below are matched.
# So the blast radius of the rule is exactly "this VM can no longer talk to a
# hypervisor/console management interface on the local network," which is
# not something a WordPress host ever legitimately does.
#
# Ports: 8006 Proxmox VE web UI/API, 8007 Proxmox Backup Server,
#        3128 SPICE proxy, 5900-5999 VNC consoles.
# Storage ports (NFS/iSCSI) are deliberately NOT included -- a future
# off-VM backup target could legitimately need them, and blocking them
# pre-emptively would be the kind of change that breaks something later for
# no gain today.
# ── Outbound SMTP submission rate limit (NEW) ─────────────────────────────────
# A compromised WordPress that can authenticate to a mail relay is a spam
# cannon with valid credentials, and the lasting damage is not to this VM --
# it is to the sending domain's reputation, which survives long after the
# site is cleaned up. Enforced at the packet level rather than in PHP,
# because the application layer is exactly what an attacker already controls
# in that scenario.
#
# Honest about what this does and does not do: it limits new CONNECTIONS,
# not messages, and one SMTP connection can carry many recipients. So this
# is a meaningful throttle and a good tripwire (the log lines are the real
# value -- they tell you something is wrong), not a hard per-message cap.
# Pair it with a per-account sending limit on the relay itself.
#
# Applied whether or not SMTP was configured at install: if mail was never
# set up, nothing should be opening submission connections at all, so the
# rule costs nothing and any hits are worth seeing. Legitimate WordPress
# mail volume (resets, notifications, receipts) sits far below the default.
_SMTP_PORTS="{ 25, 465, 587 }"
_SMTP_RATE="${SMTP_RATE_LIMIT_RATE:-30/hour}"
_SMTP_BURST="${SMTP_RATE_LIMIT_BURST:-10}"

if [[ "${BLOCK_PVE_MGMT:-1}" == "1" ]]; then
  _PVE_RULE="ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport { 8006, 8007, 3128, 5900-5999 } counter log prefix \"nft-drop-pve-mgmt \" level warn limit rate 5/minute drop"
  PVE_BLOCK_FORWARD="        # Hypervisor management plane — see note in install.sh/lib/03
        ${_PVE_RULE}"
  PVE_BLOCK_OUTPUT="        # Hypervisor management plane — see note in install.sh/lib/03
        ${_PVE_RULE}"
else
  PVE_BLOCK_FORWARD="        # Hypervisor management-plane egress block disabled (BLOCK_PVE_MGMT=0)"
  PVE_BLOCK_OUTPUT="        # Hypervisor management-plane egress block disabled (BLOCK_PVE_MGMT=0)"
fi


NFT_CONF=$(cat << NFTEOF
#!/usr/sbin/nft -f
# nftables — generated by create-wordpress-vm.sh
# MariaDB (3306) is NOT here — isolated inside Podman wp-db (10.89.20.0/24,
# --internal — no route out regardless of this ruleset).
flush ruleset
table inet filter {
    # Operator-added egress ports live in named sets rather than in this file,
    # so wp-hardening.sh can open one live with an 'nft add element' call
    # regeneration, no reload, no window where the whole ruleset is absent.
    # Declared unconditionally: harmless when egress is unrestricted, and it
    # means the management commands behave identically either way.
    set egress_extra_tcp { type inet_service; flags interval; }
    set egress_extra_udp { type inet_service; flags interval; }

    chain input {
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        ct state invalid drop
        icmp  type echo-request limit rate 5/second accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert } accept
        # ── Container DNS (Aardvark) ────────────────────────────────────────
        # CRITICAL (v7-15 fix): aardvark-dns runs ON THE HOST, bound to each
        # Podman network's gateway IP (10.89.10.1 and 10.89.20.1) on port 53.
        # A container resolving "mariadb" sends its query to that gateway
        # address, and because the gateway IP is a host-local address the
        # packet traverses THIS input hook, not the forward hook. Without an
        # explicit accept here it hits the chain's drop policy and every
        # in-container name lookup fails, even though netavark adds its own
        # accept rule in a separate table: with nftables, when two base chains
        # are registered on the same hook, a drop verdict in EITHER chain is
        # final, so this chain's drop policy overrides netavark's accept. That
        # is the exact cause of "mariadb hostname does not resolve (Aardvark
        # DNS / wp-db network issue)" seen in the field. MariaDB itself is
        # healthy (its own in-container healthcheck needs no DNS), but
        # WordPress can't find it. Both container subnets are allowed to reach
        # their gateway on 53 (udp and tcp; large responses fall back to TCP).
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 udp dport 53 accept
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 tcp dport 53 accept
        ip saddr 10.89.20.0/24 ip daddr 10.89.20.1 udp dport 53 accept
        ip saddr 10.89.20.0/24 ip daddr 10.89.20.1 tcp dport 53 accept
        # DHCP from containers to their gateway (netavark's IPAM can hand out
        # leases on the bridge). Scoped to the gateway destination for the same
        # precision as the DNS rules above.
        ip saddr 10.89.10.0/24 ip daddr 10.89.10.1 udp dport 67 accept
        ip saddr 10.89.20.0/24 ip daddr 10.89.20.1 udp dport 67 accept
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
${PVE_BLOCK_FORWARD}
        # Traffic TOWARD the container subnets is accepted before any egress
        # allowlist is consulted. This ordering is load-bearing: WordPress
        # reaches MariaDB across wp-front/wp-db, and a "restrict what
        # containers may send" rule placed above these would sever the
        # database connection while looking like a hardening win.
${WEB_CIDR_FORWARD}
${EGRESS_PROXY_FORWARD}
        ip daddr 10.89.10.0/24 accept
        ip daddr 10.89.20.0/24 accept
        # wp-db (10.89.20.0/24) is --internal: netavark never routes it to
        # the internet, so this permits only the container-to-container path.
        ip saddr 10.89.20.0/24 accept
        # NOTE: ${SMTP_RATE_LIMIT} used to be expanded here. It is now inside
        # the egress-proxy block above, because the drop at the end of that
        # block made this position unreachable. When the proxy is OFF, the
        # block below still needs it -- see EGRESS_SMTP_FALLBACK.
${SMTP_RATE_LIMIT_IF_NO_PROXY}
${EGRESS_FORWARD}
    }
    chain output {
        type filter hook output priority filter; policy accept;
        # Both of these MUST precede any drop below. Without the conntrack
        # rule, the reply packets of an INBOUND ssh or http connection count
        # as fresh egress and get dropped -- locking the operator out of a VM
        # that is otherwise working perfectly.
        ct state established,related accept
        oif "lo" accept
${PVE_BLOCK_OUTPUT}
${EGRESS_OUTPUT}
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
  _allow=""
  [[ -n "$ADMIN_CIDR" ]]       && _allow+=$'\n'"            Require ip ${ADMIN_CIDR}"
  [[ -n "$ALLOWED_ADMIN_IP" ]] && _allow+=$'\n'"            Require ip ${ALLOWED_ADMIN_IP}"

  if [[ -n "$PROXY_IP" ]]; then
    # FAIL-CLOSED FIX (found in the field: an admin logged in over cellular
    # data from an address in no allow list).
    #
    # When a reverse proxy fronts this VM, EVERY request arrives from the
    # proxy's address and mod_remoteip is what replaces it with the real
    # client. If mod_remoteip does not apply -- the module missing, the
    # header absent because the proxy was not configured to send it, or the
    # connection arriving from an address other than the declared
    # RemoteIPTrustedProxy -- then Apache evaluates these rules against the
    # PROXY'S address.
    #
    # And a proxy on the LAN is usually inside the operator's own admin CIDR.
    # 192.168.100.112 is inside 192.168.100.0/24. So the failure does not
    # deny everyone, which would be noticed within minutes; it ALLOWS
    # everyone, and looks exactly like a working configuration.
    #
    # `Require not ip <proxy>` inverts that. When mod_remoteip works the
    # client is the real visitor, never the proxy, so this passes and the
    # allow-list below decides as intended. When mod_remoteip fails the
    # client IS the proxy, this fails, and the request is denied. The control
    # now breaks toward locked-out rather than wide-open.
    #
    # Consequence worth knowing: you cannot administer WordPress from a shell
    # ON the proxy host itself. That is a fair trade for the restriction
    # meaning what it says.
    REQUIRE_ADMIN="
    <RequireAll>
        # Deny the proxy's own address. It is only ever the apparent client
        # when mod_remoteip has failed — see the note above.
        Require not ip ${PROXY_IP}
        <RequireAny>${_allow}
        </RequireAny>
    </RequireAll>"
  else
    REQUIRE_ADMIN="${_allow}"
  fi
  unset _allow
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
  # v7-14: the dual-IP verification log is only meaningful behind a proxy —
  # see the long note at its emission point in APACHE_SECURITY_CONF below.
  REMOTEIP_DEBUG_LOG=$(cat << 'RIDEBUG'
LogFormat "%t peer=%{c}a interpreted=%a \"%r\" %>s" wp_remoteip_debug
CustomLog /var/log/apache2/remoteip-debug.log wp_remoteip_debug
RIDEBUG
)
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
  REMOTEIP_DEBUG_LOG="# remoteip-debug.log not enabled (no PROXY_IP set — the peer-vs-interpreted"$'\n'"# comparison it exists to verify is meaningless without a trusted proxy)."
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
    #   Requests to /${WP_ADMIN_SLUG}  → rewritten to /wp-login.php  (internally)
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
      # The BARE slug is the login page. It used to be "<slug>-login", which
      # defeated the only thing a slug is for: anything scanning for paths
      # matching *login* found it immediately, so the login page was hidden
      # from nobody. The suffix existed to separate login from wp-admin;
      # subpaths do that just as well and leak nothing.
      #   /edith        -> wp-login.php
      #   /edith/       -> wp-login.php
      #   /edith/foo    -> wp-admin/foo
      RewriteRule ^${WP_ADMIN_SLUG}/?$ /wp-login.php [L,QSA,E=WPVM_SLUG:1]
      RewriteRule ^${WP_ADMIN_SLUG}/(.+)$ /wp-admin/\$1 [L,QSA,E=WPVM_SLUG:1]

      # v7-14: block the default login path unless the request came through
      # the slug rewrite above. Without this the slug was decorative — bots
      # hammering /wp-login.php never noticed it existed. install.php and
      # setup-config.php stay reachable so first-run setup still works.
      RewriteCond %{ENV:WPVM_SLUG} !=1
      RewriteCond %{ENV:REDIRECT_WPVM_SLUG} !=1
      RewriteCond %{REQUEST_URI} !install\.php$
      RewriteCond %{REQUEST_URI} !setup-config\.php$
      RewriteRule ^wp-login\.php$ - [F,L]
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
#
# BUG FIX (v7-14): this used to be emitted UNCONDITIONALLY, writing a second
# line to disk for every single request on every install — including the
# majority of installs with no reverse proxy at all, where %{c}a and %a are
# always identical by definition and the log proves nothing. That doubled
# total log volume (and, before v7-14 added logrotate, doubled the rate at
# which the disk filled) to answer a question nobody had asked. Now emitted
# only when PROXY_IP is actually set, which is the only case where the
# comparison carries information.
${REMOTEIP_DEBUG_LOG}

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
# FORENSIC FIX (new-audit High finding, confirmed accurate): 'unsafe-eval'
# used to apply site-wide. It's genuinely needed for wp-admin (the block
# editor's bundled JS uses eval() in places) but the public-facing site
# rarely does. Default now drops unsafe-eval; the LocationMatch below adds
# it back only for wp-admin and the login page (this also covers requests
# arriving through the custom slug above -- those are internally rewritten
# to the real /wp-admin/... and /wp-login.php paths before Apache serves
# them, which is what LocationMatch matches against). 'unsafe-inline' stays
# site-wide -- far more commonly needed by ordinary theme/plugin behavior
# (inline critical CSS, small inline scripts) than eval() is.
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
<LocationMatch "^/(wp-admin/|wp-login\.php)">
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; frame-ancestors 'self'"
</LocationMatch>
APACHEEOF
)
msg_ok "Apache security config built (wp-admin: ${ADMIN_CIDR:-open}, extra-ip: ${ALLOWED_ADMIN_IP:-none}, proxy: ${PROXY_IP:-none}, slug: ${WP_ADMIN_SLUG:-default})"

# ── Build the installer ───────────────────────────────────────────────────────
TMPDIR=$(mktemp -d)

