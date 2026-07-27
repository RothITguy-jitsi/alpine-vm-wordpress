#!/bin/sh
# 04-apache-hardening.sh — part of install-wordpress.sh (Stage 2 on the VM).
# 8G firewall WAF rules, custom wp-admin slug support, volume directory preparation, and Apache security config deployment.
# Sourced by install-wordpress.sh in order -- do not run this file directly;
# it depends on variables and helper functions (ts/ok/warn/PRUN, vars.sh
# contents, PAYLOAD_DIR, etc.) that the dispatcher and earlier stages set up.

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
    echo "# BUG FIX (v7-14): the slug used to be a pure ALIAS — /slug-login served"
    echo "# the login page, but /wp-login.php stayed wide open right beside it, so"
    echo "# every credential-stuffing bot that only ever tries the default path was"
    echo "# completely unaffected. The install even printed 'direct /wp-admin access"
    echo "# will return 403', which was only true if ADMIN_CIDR happened to be set."
    echo "# Now the slug rewrite tags the request with an environment marker, and"
    echo "# the block below rejects any request for wp-login.php that arrives"
    echo "# WITHOUT that marker — i.e. anything that didn't come through the slug."
    echo "# Apache prefixes env vars set before an internal redirect with REDIRECT_,"
    echo "# so both spellings are checked."
    echo "<IfModule mod_rewrite.c>"
    echo "    RewriteEngine On"
    echo ""
    echo "    # Slug -> real admin paths. E=WPVM_SLUG:1 marks the request as having"
    echo "    # legitimately come through the secret URL."
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/?\$ /wp-admin/index.php [L,QSA,E=WPVM_SLUG:1]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}/(.+)\$ /wp-admin/\$1 [L,QSA,E=WPVM_SLUG:1]"
    echo "    RewriteRule ^${WP_ADMIN_SLUG}-login/?\$ /wp-login.php [L,QSA,E=WPVM_SLUG:1]"
    echo ""
    echo "    # Block the default login path unless it came via the slug above."
    echo "    # install.php and setup-config.php are exempt: first-run WordPress"
    echo "    # setup ALWAYS happens at the default /wp-admin/install.php URL, and"
    echo "    # locking that out would make a fresh VM unusable."
    echo "    RewriteCond %{ENV:WPVM_SLUG} !=1"
    echo "    RewriteCond %{ENV:REDIRECT_WPVM_SLUG} !=1"
    echo "    RewriteCond %{REQUEST_URI} !install\\.php\$"
    echo "    RewriteCond %{REQUEST_URI} !setup-config\\.php\$"
    echo "    RewriteRule ^wp-login\\.php\$ - [F,L]"
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
install -m 0644 "${PAYLOAD_DIR}/apache-conf/wp-security-fallback.conf" /home/wpuser/wp/apache-conf/wp-security.conf
fi
chmod 644 /home/wpuser/wp/apache-conf/wp-security.conf

# PHP security configuration
install -m 0644 "${PAYLOAD_DIR}/php-conf/security.ini" /home/wpuser/wp/php-conf/security.ini
chmod 644 /home/wpuser/wp/php-conf/security.ini

ok "Volume directories and config files ready:"
ok "  /home/wpuser/wp/html     WordPress files   (UID 33:www-data)"
ok "  /home/wpuser/wp/logs     Apache access log (UID 33:www-data)"
ok "  /home/wpuser/wp/mysql    MariaDB data      (UID 999:mysql)"
ok "  /home/wpuser/wp/apache-conf/wp-security.conf"
ok "  /home/wpuser/wp/php-conf/security.ini"
