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

function wpvm_login_key($suffix) {
    return 'wpvm_lg_' . $suffix . '_' . md5(wpvm_login_client_ip());
}

/** Failures recorded for this address inside the current window. */
function wpvm_login_attempts() {
    $n = get_transient(wpvm_login_key('att'));
    return $n === false ? 0 : (int) $n;
}

/** Seconds remaining on an active lockout, or 0 if not locked out. */
function wpvm_login_lock_remaining() {
    $until = get_transient(wpvm_login_key('lock'));
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
    error_log(sprintf(
        '[wpvm-login] event=%s ip=%s user=%s attempts=%d%s',
        $event,
        wpvm_login_client_ip(),
        $u === '' ? '-' : $u,
        wpvm_login_attempts(),
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
    $left = wpvm_login_lock_remaining();
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
    $attempts = wpvm_login_attempts() + 1;
    set_transient(wpvm_login_key('att'), $attempts, WPVM_LOGIN_WINDOW_SECS);

    if ($attempts >= WPVM_LOGIN_MAX_ATTEMPTS) {
        /* Progressive: each further lockout doubles, capped. A fixed 15-minute
         * penalty is a rate limit an attacker simply plans around -- 5 guesses
         * every quarter hour, indefinitely. Doubling makes sustained guessing
         * against one address pointless, while a legitimate user who mistyped
         * still only waits the base period. */
        $prev = (int) get_transient(wpvm_login_key('count'));
        $count = $prev + 1;
        $secs = min(WPVM_LOGIN_LOCKOUT_SECS * pow(2, $prev), WPVM_LOGIN_MAX_LOCKOUT);

        set_transient(wpvm_login_key('lock'), time() + $secs, $secs);
        set_transient(wpvm_login_key('count'), $count, WPVM_LOGIN_MAX_LOCKOUT);
        delete_transient(wpvm_login_key('att'));

        wpvm_login_log('lockout', $username, 'duration=' . $secs . ' lockout_number=' . $count);
    } else {
        wpvm_login_log('failed', $username, 'remaining=' . (WPVM_LOGIN_MAX_ATTEMPTS - $attempts));
    }
});

/** A success clears the counter, but not the escalation history. */
add_action('wp_login', function ($user_login) {
    delete_transient(wpvm_login_key('att'));
    delete_transient(wpvm_login_key('lock'));
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
