<?php
/**
 * Plugin Name: WASP — SMTP Transport
 * Description: Sends all wp_mail() through your authenticated SMTP relay, with the credentials held in a file outside the web root rather than in the database. Without it WordPress hands mail to a local sendmail that does not exist, and password resets, order confirmations and admin alerts fail silently.
 * Author: RothITguy
 * Version: 1.0
 *
 * WHY THE CREDENTIALS LIVE OUTSIDE THE DOCROOT
 *
 * The relay password is read from /var/www/private/smtp.ini, mounted
 * read-only from the host and deliberately NOT under /var/www/html. Two
 * distinct reasons:
 *
 *   1. If PHP execution ever breaks (a bad container update, a misapplied
 *      .htaccess, a mangled php.ini), Apache serves .php files as plain
 *      text. Anything holding secrets inside the docroot is then readable
 *      over HTTP. Outside the docroot there is no URL that maps to it.
 *   2. It is not passed as a container environment variable the way
 *      WORDPRESS_DB_PASSWORD is, because `podman inspect wordpress` prints
 *      the full environment -- so env vars are visible to anything that can
 *      talk to the Podman socket, and they leak into container logs and
 *      crash dumps more readily than a 0400 file does.
 *
 * mu-plugins (not a normal plugin) because these cannot be deactivated from
 * wp-admin, load before regular plugins, and survive core updates -- mail
 * transport should not be something an admin can switch off by accident.
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
 * NON-EXECUTABLE CONFIG FORMAT
 *
 * This was previously a .php file returning an array, which meant the
 * credentials file was CODE: it was include()d, so any flaw in the escaping
 * that wrote it -- or any future write access to it -- became remote code
 * execution rather than a bad password. The escaping was careful, but
 * "careful escaping" is a mitigation and a data format is a fix.
 *
 * It is now an INI file parsed with INI_SCANNER_RAW, so a malformed value is
 * a malformed value and can never be a statement. The password is stored
 * base64-encoded purely so that quotes, semicolons and whitespace cannot
 * interact with INI parsing at all -- that is encoding for robustness, NOT
 * secrecy, and the file's permissions remain the thing protecting it.
 */
if (!defined('WPVM_SMTP_CONFIG')) {
    define('WPVM_SMTP_CONFIG', '/var/www/private/smtp.ini');
}
/* Legacy PHP config, still read if present so an existing VM keeps sending
 * mail after an update. Deliberately second: if both exist, the INI wins. */
if (!defined('WPVM_SMTP_CONFIG_LEGACY')) {
    define('WPVM_SMTP_CONFIG_LEGACY', '/var/www/private/smtp.php');
}

/**
 * Load and cache the relay config. Returns false when SMTP was never
 * configured, which is a supported state -- the site simply keeps
 * WordPress's default behavior rather than erroring.
 */
function wpvm_smtp_config() {
    static $cfg = null;
    if ($cfg !== null) {
        return $cfg;
    }
    $cfg = false;
    if (is_readable(WPVM_SMTP_CONFIG)) {
        // INI_SCANNER_RAW: values are taken literally, with no interpretation
        // of quotes, constants or type juggling. Nothing here can execute.
        $ini = @parse_ini_file(WPVM_SMTP_CONFIG, false, INI_SCANNER_RAW);
        if (is_array($ini) && !empty($ini['host']) && !empty($ini['user'])) {
            $ini['pass'] = isset($ini['pass_b64'])
                ? base64_decode($ini['pass_b64'], true)
                : '';
            if ($ini['pass'] !== false) {
                $cfg = $ini;
            }
        }
    }
    if ($cfg === false && is_readable(WPVM_SMTP_CONFIG_LEGACY)) {
        // Pre-INI installs. Logged so it is visible rather than silent, since
        // the whole point of the change is not to include() this file.
        $loaded = include WPVM_SMTP_CONFIG_LEGACY;
        if (is_array($loaded) && !empty($loaded['host']) && !empty($loaded['user'])) {
            $cfg = $loaded;
            error_log('[wpvm-smtp] using legacy smtp.php; re-run wp-mail.sh setup to migrate to the non-executable smtp.ini');
        }
    }
    return $cfg;
}

add_action('phpmailer_init', function ($phpmailer) {
    $cfg = wpvm_smtp_config();
    if (!$cfg) {
        return;
    }

    $phpmailer->isSMTP();
    $phpmailer->Host       = $cfg['host'];
    $phpmailer->Port       = (int) $cfg['port'];
    $phpmailer->SMTPAuth   = true;
    $phpmailer->Username   = $cfg['user'];
    $phpmailer->Password   = $cfg['pass'];

    // 'ssl' = implicit TLS, the whole session encrypted from connect (port
    // 465). 'tls' = STARTTLS, an explicit upgrade after a plaintext greeting
    // (port 587). Both are fine against a modern relay; 587/STARTTLS is the
    // submission standard and the default here.
    $phpmailer->SMTPSecure  = (isset($cfg['encryption']) && $cfg['encryption'] === 'ssl') ? 'ssl' : 'tls';
    $phpmailer->SMTPAutoTLS = true;

    // Certificate verification is left at PHPMailer's default (ON). It is
    // deliberately not exposed as a config toggle: the usual reason people
    // reach for SMTPOptions/verify_peer=false is a self-signed or
    // mismatched cert, and silently accepting those turns an authenticated
    // TLS session into one an on-path attacker can read -- including the
    // relay password on every send. If the relay's certificate does not
    // validate, fix the certificate.

    // Bound how long a page load can block on an unreachable relay.
    // PHPMailer's default Timeout is 300 seconds: with the default, a mail
    // server that is down (or a dropped packet to it) hangs user-visible
    // requests like registration and password reset for five minutes each.
    $phpmailer->Timeout = isset($cfg['timeout']) ? (int) $cfg['timeout'] : 10;

    if (!empty($cfg['from'])) {
        $phpmailer->From = $cfg['from'];
        // Envelope sender (Return-Path). SPF is evaluated against THIS, not
        // the visible From: header, so setting it is what keeps SPF aligned
        // when the relay checks the envelope domain.
        $phpmailer->Sender = $cfg['from'];
    }
    if (!empty($cfg['from_name'])) {
        $phpmailer->FromName = $cfg['from_name'];
    }
}, 10, 1);

/**
 * WordPress defaults the sender to wordpress@<site-domain>, which frequently
 * is not a real mailbox and frequently is not a sender the relay's SPF
 * record authorizes. Under a DMARC policy of quarantine or reject that
 * mismatch means silent non-delivery -- the same invisible failure this
 * plugin exists to fix. Both filters run at priority 99 so a site-specific
 * plugin can still deliberately override them.
 */
add_filter('wp_mail_from', function ($email) {
    $cfg = wpvm_smtp_config();
    return ($cfg && !empty($cfg['from'])) ? $cfg['from'] : $email;
}, 99);

add_filter('wp_mail_from_name', function ($name) {
    $cfg = wpvm_smtp_config();
    return ($cfg && !empty($cfg['from_name'])) ? $cfg['from_name'] : $name;
}, 99);

/**
 * Make failures visible. Silent failure is the entire problem being solved
 * here, so a send that fails is written to the PHP error log (which this VM
 * ships to /home/wpuser/wp/logs and rotates hourly). wp-mail.sh reads these.
 */
add_action('wp_mail_failed', function ($error) {
    if (is_wp_error($error)) {
        error_log('[wpvm-smtp] wp_mail failed: ' . $error->get_error_message());
    }
});
