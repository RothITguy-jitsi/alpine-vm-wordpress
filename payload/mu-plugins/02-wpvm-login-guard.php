<?php
/**
 * Plugin Name: WPVM Login Guard
 * Description: Rate-limits failed logins with a progressive lockout, removes
 *              WordPress's username-enumeration leak in its login errors, and
 *              logs failures in a form CrowdSec can act on.
 * Author: RothITguy
 *
 * WHY THIS EXISTS RATHER THAN A PLUGIN
 *
 * Functionally this covers what Limit Login Attempts does, minus the
 * dashboard. The reason to have it here instead is that a plugin is a
 * separate update surface, a separate CVE surface, and can be deactivated
 * from an admin panel that an attacker who got in would immediately reach.
 * A mu-plugin cannot be deactivated from wp-admin and survives core updates.
 *
 * WHAT THIS LAYER IS AND IS NOT
 *
 * This is the APPLICATION layer, and it is the weaker of the two by design.
 * Every attempt it blocks has still paid for a full WordPress bootstrap:
 * PHP started, the database was queried, the request cost you real CPU. Under
 * a distributed attack that cost is the actual problem, not the guessing.
 *
 * The strong layer is CrowdSec, which reads what this writes and bans the
 * source at nftables -- where the packet never reaches PHP at all. That is
 * why this logs in a fixed, parseable format: the log is the interface
 * between the cheap-but-weak layer and the effective one.
 *
 * ON XML-RPC: xmlrpc.php's system.multicall lets an attacker try hundreds of
 * passwords in ONE request, which is how brute-force protection is usually
 * bypassed. This VM already blocks xmlrpc.php in Apache (see wp-security.conf
 * and `wp-hardening.sh status`), so that path is closed before PHP. If you
 * ever unblock it, note that wp_login_failed fires per credential pair, so
 * this counts multicall attempts individually rather than as one request.
 */

if (!defined('ABSPATH')) {
    exit;
}

/* Tunables. Defined with defaults so wp-config.php (or WORDPRESS_CONFIG_EXTRA)
 * can override any of them without editing this file. */
defined('WPVM_LOGIN_MAX_ATTEMPTS') || define('WPVM_LOGIN_MAX_ATTEMPTS', 5);
defined('WPVM_LOGIN_LOCKOUT_SECS') || define('WPVM_LOGIN_LOCKOUT_SECS', 900);      // 15 min
defined('WPVM_LOGIN_WINDOW_SECS')  || define('WPVM_LOGIN_WINDOW_SECS', 1200);      // count within 20 min
defined('WPVM_LOGIN_MAX_LOCKOUT')  || define('WPVM_LOGIN_MAX_LOCKOUT', 86400);     // cap at 24 h

/**
 * The client address, as Apache determined it.
 *
 * REMOTE_ADDR is used deliberately and X-Forwarded-For is deliberately NOT
 * read here. When a reverse proxy is configured, mod_remoteip has already
 * replaced REMOTE_ADDR with the real client address, and it only does so for
 * the one proxy IP the operator declared trusted. Reading the header directly
 * in PHP would accept it from anyone -- letting an attacker send a different
 * forged address on every attempt and never accumulate a count. That is the
 * single most common way application-layer login limiters are defeated.
 */
function wpvm_login_client_ip() {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

/**
 * Detect the case where mod_remoteip is NOT substituting the real client.
 *
 * Behind a proxy, every request arrives from the proxy and mod_remoteip
 * replaces REMOTE_ADDR with the real visitor. When that stops working, every
 * visitor looks like the proxy — and this rate limiter then keys every
 * failure in the world to a single counter. Five failed logins from anyone
 * locks out EVERYONE. An attacker does not need to guess a password to take
 * the site down; they need to guess wrong, five times.
 *
 * It also silently defeats CrowdSec (which reads the address this file logs)
 * and GeoIP (which sees an RFC1918 address and exempts it).
 *
 * Neither failing open nor failing closed is right here: without a client
 * identity, per-client rate limiting is not possible, and locking everyone
 * out is the DoS itself. So the limiter keeps working -- some limit beats
 * none -- and the condition is logged on every occurrence so it is
 * discoverable rather than invisible. validate-wordpress.sh checks for it
 * explicitly.
 */
function wpvm_login_remoteip_broken() {
    $cfg = '/var/www/private/proxy.txt';
    if (!is_readable($cfg)) {
        return false;               // no proxy configured; nothing to detect
    }
    $proxy = trim(@file_get_contents($cfg));
    if ($proxy === '' || !filter_var($proxy, FILTER_VALIDATE_IP)) {
        return false;
    }
    return wpvm_login_client_ip() === $proxy;
}

/**
 * Lockout key.
 *
 * Scoped to IP **and username**, not IP alone. A third-party review made the
 * point: behind an office or carrier NAT, many people share one address, so an
 * IP-only lockout lets an attacker deliberately lock out every legitimate user
 * of that network by failing five logins. Carrier-grade NAT makes that a
 * mobile visitor's normal situation, not an edge case.
 *
 * Keying on the pair means an attacker hammering "admin" cannot lock out
 * "editor" from the same address, while still stopping repeated guesses at any
 * single account.
 *
 * The IP-only counter is kept as a second, much looser tier (see below): an
 * attacker spraying many usernames from one address would otherwise never
 * trip a per-pair limit at all. Two thresholds, two purposes — the tight one
 * protects an account, the loose one catches spraying.
 */
function wpvm_login_key($suffix, $username = '') {
    $u = strtolower(trim((string) $username));
    return 'wpvm_lg_' . $suffix . '_' . md5(wpvm_login_client_ip() . '|' . $u);
}

/** IP-only key, for the spray tier. */
function wpvm_login_ipkey($suffix) {
    return 'wpvm_lgip_' . $suffix . '_' . md5(wpvm_login_client_ip());
}

/** Failures recorded for this address inside the current window. */
function wpvm_login_attempts($username = '') {
    $n = get_transient(wpvm_login_key('att', $username));
    return $n === false ? 0 : (int) $n;
}

/** Seconds remaining on an active lockout, or 0 if not locked out. */
function wpvm_login_lock_remaining($username = '') {
    $until = get_transient(wpvm_login_key('lock', $username));
    if ($until === false) {
        return 0;
    }
    $left = (int) $until - time();
    return $left > 0 ? $left : 0;
}

/**
 * Structured log line. Fixed field order and a stable prefix so CrowdSec can
 * parse it without heuristics. Goes to error_log, which this VM routes to
 * /home/wpuser/wp/logs and rotates hourly.
 *
 * The attempted username is recorded because it is genuinely useful triage --
 * a flood against "admin" is a bot, a flood against a real editor's account is
 * someone who has done homework. It is not treated as trustworthy input: it
 * is stripped of anything that could break the log format or inject a fake
 * line, since it arrives straight from the request.
 */
function wpvm_login_log($event, $username, $extra = '') {
    $u = preg_replace('/[^A-Za-z0-9._@-]/', '', (string) $username);
    if (strlen($u) > 64) {
        $u = substr($u, 0, 64);
    }
    if (wpvm_login_remoteip_broken()) {
        // Deliberately its own line and its own tag: this is a different
        // problem from a failed login and needs finding by grep.
        error_log('[wpvm-login] REMOTEIP-BROKEN every visitor appears to be the '
            . 'reverse proxy. Rate limiting, CrowdSec and GeoIP are all keyed to '
            . 'this address and are therefore not distinguishing clients. '
            . 'Run: wp-hardening.sh proxy-check');
    }
    error_log(sprintf(
        '[wpvm-login] event=%s ip=%s user=%s attempts=%d%s',
        $event,
        wpvm_login_client_ip(),
        $u === '' ? '-' : $u,
        wpvm_login_attempts($username),
        $extra === '' ? '' : ' ' . $extra
    ));
}

/**
 * Refuse the attempt before any credential checking happens.
 *
 * Hooked at priority 5 -- earlier than wp_authenticate_username_password (20)
 * -- so a locked-out request never reaches the password hash comparison.
 * bcrypt verification is deliberately expensive, so skipping it is most of the
 * CPU saving this layer can offer.
 */
add_filter('authenticate', function ($user, $username, $password) {
    if (empty($username) && empty($password)) {
        return $user;                       // not a login attempt; leave it alone
    }
    $left = wpvm_login_lock_remaining($username);
    if ($left === 0) {
        $sp = get_transient(wpvm_login_ipkey('lock'));
        if ($sp !== false) {
            $left = max(0, (int) $sp - time());
        }
    }
    if ($left > 0) {
        wpvm_login_log('blocked', $username, 'lock_remaining=' . $left);
        $mins = max(1, (int) ceil($left / 60));
        return new WP_Error(
            'wpvm_locked_out',
            sprintf(
                /* Deliberately states the limit and the wait. Hiding it does
                 * not slow an attacker down -- they measure it -- and it does
                 * confuse the legitimate user who mistyped a password twice. */
                __('<strong>Too many failed attempts.</strong> Try again in %d minute(s).'),
                $mins
            )
        );
    }
    return $user;
}, 5, 3);

/** Count a failure and lock out once the threshold is crossed. */
add_action('wp_login_failed', function ($username) {
    /* Spray tier: failures from this ADDRESS against ANY username. Set much
     * higher than the per-account limit, because on a shared NAT a high count
     * is normal traffic rather than an attack. It exists so username spraying
     * -- one guess each against hundreds of accounts -- is still bounded. */
    $ip_fails = (int) get_transient(wpvm_login_ipkey('att'));
    set_transient(wpvm_login_ipkey('att'), $ip_fails + 1, WPVM_LOGIN_WINDOW_SECS);
    if ($ip_fails + 1 >= WPVM_LOGIN_MAX_ATTEMPTS * 6) {
        set_transient(wpvm_login_ipkey('lock'), time() + WPVM_LOGIN_LOCKOUT_SECS,
                      WPVM_LOGIN_LOCKOUT_SECS);
        wpvm_login_log('spray-lockout', $username,
            'ip_failures=' . ($ip_fails + 1) . ' scope=address');
    }

    $attempts = wpvm_login_attempts($username) + 1;
    set_transient(wpvm_login_key('att', $username), $attempts, WPVM_LOGIN_WINDOW_SECS);

    if ($attempts >= WPVM_LOGIN_MAX_ATTEMPTS) {
        /* Progressive: each further lockout doubles, capped. A fixed 15-minute
         * penalty is a rate limit an attacker simply plans around -- 5 guesses
         * every quarter hour, indefinitely. Doubling makes sustained guessing
         * against one address pointless, while a legitimate user who mistyped
         * still only waits the base period. */
        $prev = (int) get_transient(wpvm_login_key('count', $username));
        $count = $prev + 1;
        $secs = min(WPVM_LOGIN_LOCKOUT_SECS * pow(2, $prev), WPVM_LOGIN_MAX_LOCKOUT);

        set_transient(wpvm_login_key('lock', $username), time() + $secs, $secs);
        set_transient(wpvm_login_key('count', $username), $count, WPVM_LOGIN_MAX_LOCKOUT);
        delete_transient(wpvm_login_key('att', $username));

        wpvm_login_log('lockout', $username, 'duration=' . $secs . ' lockout_number=' . $count);
    } else {
        wpvm_login_log('failed', $username, 'remaining=' . (WPVM_LOGIN_MAX_ATTEMPTS - $attempts));
    }
});

/** A success clears the counter, but not the escalation history. */
add_action('wp_login', function ($user_login) {
    delete_transient(wpvm_login_key('att', $user_login));
    delete_transient(wpvm_login_key('lock', $user_login));
    delete_transient(wpvm_login_ipkey('att'));
    /* wpvm_lg_count is intentionally left in place. An address that locked
     * itself out four times and then succeeded is more interesting than one
     * that logged in cleanly, and clearing the history would let an attacker
     * who guesses correctly once reset their own penalty ladder. */
    wpvm_login_log('success', $user_login);
});

/**
 * Remove the username-enumeration leak.
 *
 * WordPress distinguishes "Unknown username" from "The password you entered
 * is incorrect", which confirms which accounts exist -- turning a guess at
 * two unknowns into a guess at one. Both now return the same text. This costs
 * nothing and is a real gain: it is the difference between an attacker
 * needing a valid username and being told when they have found one.
 */
add_filter('login_errors', function ($error) {
    if (is_string($error) && (
            strpos($error, 'Unknown username') !== false ||
            strpos($error, 'incorrect') !== false ||
            strpos($error, 'not registered') !== false ||
            strpos($error, 'Invalid username') !== false)) {
        return __('<strong>Error:</strong> Invalid username, email address or password.');
    }
    return $error;
});
