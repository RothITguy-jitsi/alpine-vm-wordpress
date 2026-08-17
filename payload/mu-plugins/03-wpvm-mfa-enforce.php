<?php
/**
 * Plugin Name: WASP — MFA Enforcement
 * Description: Requires administrators to hold a configured second factor via the Two Factor plugin, and closes the REST and application-password routes that would otherwise let an admin skip it. Built around recovery: a grace window before blocking, backup codes count, and a console reset if every factor is lost. Deleting this file disables the requirement — it does not lock anyone out.
 * Author: RothITguy
 * Version: 1.0
 * WHY THIS EXISTS AS A SEPARATE PIECE
 *
 * The Two Factor plugin (maintained by the WordPress core contributors) provides
 * the actual TOTP / backup-code / WebAuthn machinery, but deliberately has NO
 * enforcement: every user opts in from their own profile. For an MSP that is the
 * wrong default — an administrator who never visits their profile page has no
 * second factor, which is exactly the account that most needs one. This adds the
 * enforcement WITHOUT modifying the plugin, so the plugin can update freely.
 *
 * THE THING THIS MUST NOT DO IS LOCK ANYONE OUT
 *
 * Enforcement that has no escape hatch is how a lost phone becomes a rebuild.
 * So this is built around recovery, not just around blocking:
 *
 *   1. A GRACE WINDOW. A newly-created or newly-promoted admin is not blocked
 *      immediately; they are steered to set up 2FA and given a configurable
 *      number of days to do it. Blocking someone before they have had any
 *      chance to enrol is the fastest way to manufacture a lockout.
 *
 *   2. BACKUP CODES ARE PART OF "ENROLLED". The Two Factor plugin's backup-code
 *      provider counts. An admin with TOTP + printed backup codes can always get
 *      back in from any device, which is the property that makes enforcement
 *      safe to turn on.
 *
 *   3. A CONSOLE RECOVERY PATH. If every factor is lost, 2FA for a single user
 *      can be reset from the VM console with wp-cli — documented in
 *      SUPPORT-RUNBOOK.md — because the console is the one entry point WASP
 *      keeps working when everything else is locked. That is a deliberate,
 *      audited override, not a bypass reachable from the network.
 *
 * HOW IT COMPOSES WITH THE REST OF THE LOGIN PATH
 *
 * WASP already has three things on this path: the custom login slug
 * (00-wpvm-login-slug), the SMTP transport (01), and the brute-force login guard
 * (02). This is 03 and is ordered AFTER them on purpose:
 *
 *   - The slug rewrite decides WHERE the login form lives; 2FA happens after the
 *     form is reached, so they do not interact.
 *   - The login guard runs on the `authenticate` filter and the wp_login_failed
 *     action, gating the FIRST factor (password). Two Factor runs its second
 *     factor AFTER a successful password on the `wp_login`/interim-login flow.
 *     They are sequential stages of the same login, not competitors for the same
 *     hook, so both apply cleanly: guard throttles password guessing, 2FA blocks
 *     a guessed-or-phished password from being enough.
 *   - The IP restriction is enforced at Apache, before PHP runs at all, so it is
 *     strictly outside this — a request that reaches here has already passed it.
 *
 * The one real interaction risk is REST and XML-RPC: a second factor on the
 * interactive login does nothing if an attacker can authenticate via an API that
 * bypasses it. WASP already disables XML-RPC. This additionally blocks
 * application-password and basic REST authentication for administrators unless
 * they have 2FA enrolled, so the enforcement cannot be walked around the side.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/*
 * Configuration, substituted at provisioning time. Kept as constants rather than
 * options so they cannot be changed from a compromised admin session — an
 * attacker who could set the grace window to 3650 days could defeat the whole
 * control.
 */
if ( ! defined( 'WPVM_MFA_ENFORCE' ) ) {
    // 1 = enforce for administrators, 0 = plugin present but enforcement off.
    define( 'WPVM_MFA_ENFORCE', WPVM_MFA_ENFORCE_PLACEHOLDER );
}
if ( ! defined( 'WPVM_MFA_GRACE_DAYS' ) ) {
    // Days a new/promoted admin has to enrol before they are blocked.
    define( 'WPVM_MFA_GRACE_DAYS', WPVM_MFA_GRACE_PLACEHOLDER );
}

/**
 * Is the Two Factor plugin actually present and providing its API?
 *
 * Everything here is a no-op if it is not — enforcing "you must use a plugin that
 * is not installed" would lock out every admin with no way to comply, which is
 * the exact failure this file exists to avoid. So absence disables enforcement
 * and surfaces an admin notice instead.
 */
function wpvm_mfa_available() {
    return class_exists( 'Two_Factor_Core' );
}

/**
 * Has this user enrolled at least one REAL second factor?
 *
 * "Real" excludes the email fallback deliberately for administrators: the email
 * account is usually also the password-reset channel, so email-as-2FA collapses
 * both factors into one inbox. TOTP, backup codes and WebAuthn all count.
 */
function wpvm_mfa_user_enrolled( $user_id ) {
    if ( ! wpvm_mfa_available() ) {
        return true; // cannot require what is not available
    }
    // AVAILABLE, not merely ENABLED. The plugin distinguishes a provider the
    // user ticked (enabled) from one they actually finished setting up
    // (available = enabled AND configured). This matters for lockout safety: a
    // user can enable TOTP and never scan the QR, leaving no secret. If we
    // counted that as enrolled we would stop nudging them and then block them at
    // their next fresh login with no factor that actually works. Requiring a
    // *configured* provider means "enrolled" means "can really pass 2FA".
    if ( method_exists( 'Two_Factor_Core', 'get_available_providers_for_user' ) ) {
        $providers = Two_Factor_Core::get_available_providers_for_user( $user_id );
        // Keyed by provider classname => instance; the keys are what we test.
        $providers = is_array( $providers ) ? array_keys( $providers ) : array();
    } else {
        // Defensive fallback for an unexpected plugin version.
        $providers = Two_Factor_Core::get_enabled_providers_for_user( $user_id );
        $providers = is_array( $providers ) ? $providers : array();
    }
    if ( empty( $providers ) ) {
        return false;
    }
    // Any configured provider other than plain email satisfies enforcement.
    // Email is excluded for admins because the inbox is usually also the
    // password-reset channel, which would collapse both factors into one.
    foreach ( $providers as $provider ) {
        if ( 'Two_Factor_Email' !== $provider ) {
            return true;
        }
    }
    // Only email is configured — for an admin that is not sufficient on its own.
    return false;
}

/**
 * Does this user fall under enforcement? Administrators (manage_options) do.
 */
function wpvm_mfa_user_in_scope( $user ) {
    if ( ! ( $user instanceof WP_User ) ) {
        return false;
    }
    return user_can( $user, 'manage_options' );
}

/**
 * When did this user's grace window start? First seen under enforcement anchors
 * it, so a pre-existing admin at rollout also gets a fair window rather than
 * being blocked the instant enforcement turns on.
 */
function wpvm_mfa_grace_expired( $user_id ) {
    $started = get_user_meta( $user_id, 'wpvm_mfa_grace_start', true );
    if ( empty( $started ) ) {
        $started = time();
        update_user_meta( $user_id, 'wpvm_mfa_grace_start', $started );
    }
    $deadline = (int) $started + ( WPVM_MFA_GRACE_DAYS * DAY_IN_SECONDS );
    return time() > $deadline;
}

/*
 * ── The real gate: every wp-admin request, not just the login moment ─────────
 *
 * Enforcing only at wp_login has two holes that a mocked test cannot show but a
 * real install will:
 *
 *   1. An admin who was ALREADY logged in when enforcement was turned on never
 *      fires wp_login again until their cookie expires (up to 14 days), so they
 *      would go unprotected for that whole window.
 *
 *   2. wp_clear_auth_cookie() at wp_login races the auth cookie that the login
 *      flow already queued earlier in the same response. It usually wins on
 *      header order, but "usually" is not a control — a surviving cookie would
 *      be logged straight into wp-admin on the next request.
 *
 * Gating on admin_init closes both: it runs on EVERY wp-admin request, checks
 * the current user, and redirects an unenrolled in-scope admin (past grace) to
 * the 2FA setup page. A stale session is caught on its very next click; a
 * survived cookie never reaches an admin screen.
 *
 * The critical subtlety is that the gate must NOT block the paths an admin needs
 * to actually enrol, or "enforcement" becomes "lockout". So the profile page,
 * the AJAX/POST endpoints the Two Factor plugin uses to set up and verify TOTP,
 * and logout are all allowed through even while the admin is unenrolled.
 */
function wpvm_mfa_request_is_enrollment_path() {
    global $pagenow;

    // The profile screen is where the Two Factor options live. Both profile.php
    // (your own) and user-edit.php (an admin editing themselves) qualify.
    if ( in_array( $pagenow, array( 'profile.php', 'user-edit.php' ), true ) ) {
        return true;
    }
    // TOTP setup and verification, and other providers' setup, go through these.
    if ( in_array( $pagenow, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
        return true;
    }
    // Never trap someone on the way OUT — logout must always be reachable.
    if ( 'wp-login.php' === $pagenow ) {
        return true;
    }
    if ( isset( $_REQUEST['action'] ) && 'logout' === $_REQUEST['action'] ) {
        return true;
    }
    return false;
}

add_action( 'admin_init', function () {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return;
    }
    // AJAX during enrollment (the TOTP verify step) must pass, or setup breaks.
    if ( wp_doing_ajax() ) {
        return;
    }
    $user = wp_get_current_user();
    if ( ! $user || ! $user->ID ) {
        return;
    }
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return;
    }
    // Within grace: allow through (the admin notice does the nudging). Only a
    // fully-expired grace turns the redirect on, so nobody is walled before they
    // have had a chance to enrol.
    if ( ! wpvm_mfa_grace_expired( $user->ID ) ) {
        return;
    }
    // Past grace and still unenrolled: let them reach the enrollment paths, and
    // redirect everything else to the profile so they cannot use the admin until
    // they set up 2FA.
    if ( wpvm_mfa_request_is_enrollment_path() ) {
        return;
    }
    wp_safe_redirect( admin_url( 'profile.php#two-factor-options' ) );
    exit;
} );

/*
 * ── Login-moment enforcement, kept as a second layer ─────────────────────────
 *
 * The admin_init gate above is the primary control. This wp_login handler stays
 * as defence in depth: it nudges within grace, and past grace it refuses to let
 * the login complete into a working session in the first place, so the common
 * case never even reaches the admin_init redirect. Belt and braces on a login is
 * the right amount of paranoia.
 */
add_action( 'wp_login', function ( $user_login, $user ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return;
    }
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return;
    }
    if ( wpvm_mfa_grace_expired( $user->ID ) ) {
        // Destroy the freshly-created session and clear the cookie. Even if the
        // cookie survives the header race, the admin_init gate will catch the
        // next request — this just makes the common path clean.
        wp_destroy_current_session();
        wp_clear_auth_cookie();
        $setup = admin_url( 'profile.php#two-factor-options' );
        wp_die(
            wp_kses_post(
                '<h1>Two-factor authentication required</h1>' .
                '<p>Administrator accounts on this site must have two-factor ' .
                'authentication enabled. Your grace period to set it up has ended.</p>' .
                '<p>If you have lost access, an administrator can reset your ' .
                'two-factor from the server console (see the support runbook). ' .
                'Otherwise, ask another administrator to help you enrol.</p>'
            ),
            'Two-factor authentication required',
            array( 'response' => 403, 'link_url' => $setup, 'link_text' => 'Set up two-factor' )
        );
    }
    // Within grace: set a transient so an admin notice nudges them.
    set_transient( 'wpvm_mfa_nudge_' . $user->ID, 1, HOUR_IN_SECONDS );
}, 20, 2 );

/*
 * Admin notice within the grace window: a persistent, dismissible reminder with
 * the days remaining, so enrolment is a prompt rather than a surprise wall.
 */
add_action( 'admin_notices', function () {
    if ( ! WPVM_MFA_ENFORCE ) {
        return;
    }
    $user = wp_get_current_user();
    if ( ! wpvm_mfa_user_in_scope( $user ) || wpvm_mfa_user_enrolled( $user->ID ) ) {
        return;
    }
    if ( ! wpvm_mfa_available() ) {
        echo '<div class="notice notice-error"><p><strong>Two-factor enforcement is on, but the Two Factor plugin is not active.</strong> Administrators cannot enrol until it is activated. Activate it under Plugins.</p></div>';
        return;
    }
    $started  = (int) get_user_meta( $user->ID, 'wpvm_mfa_grace_start', true );
    $deadline = $started + ( WPVM_MFA_GRACE_DAYS * DAY_IN_SECONDS );
    $days     = max( 0, (int) ceil( ( $deadline - time() ) / DAY_IN_SECONDS ) );
    $url      = esc_url( admin_url( 'profile.php#two-factor-options' ) );
    printf(
        '<div class="notice notice-warning"><p><strong>Set up two-factor authentication.</strong> This administrator account will be required to use it in %d day%s. <a href="%s">Set it up now</a> — you will need an authenticator app, and you should print the backup codes.</p></div>',
        (int) $days,
        1 === $days ? '' : 's',
        $url
    );
} );

/*
 * ── Close the API side doors ─────────────────────────────────────────────────
 *
 * A second factor on the browser login is meaningless if an administrator can
 * authenticate through an API that skips it. XML-RPC is already disabled by
 * WASP. Here we refuse REST authentication and application-password auth for an
 * in-scope admin who has not enrolled — so the enforcement cannot be sidestepped
 * by switching channels. A non-admin, or an enrolled admin, is unaffected.
 */
add_filter( 'rest_authentication_errors', function ( $result ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return $result;
    }
    // Defer ONLY to a prior ERROR, never to a prior ALLOW. WordPress core's
    // convention for this filter is that null = no opinion and true = "already
    // authenticated, allow it". If we treated a prior `true` as "someone decided,
    // stop here" we would skip enforcement exactly when another handler had
    // authenticated an unenrolled admin — the opposite of what we want. So we
    // pass an existing WP_Error straight through (do not override another
    // control's denial) but we do NOT stop on a prior allow.
    if ( is_wp_error( $result ) ) {
        return $result;
    }
    $user = wp_get_current_user();
    if ( $user && $user->ID && wpvm_mfa_user_in_scope( $user )
         && ! wpvm_mfa_user_enrolled( $user->ID )
         && wpvm_mfa_grace_expired( $user->ID ) ) {
        return new WP_Error(
            'wpvm_mfa_required',
            'Two-factor authentication must be enabled on this administrator account before using the REST API.',
            array( 'status' => 403 )
        );
    }
    return $result;
} );

/*
 * Application passwords are a REST-auth bypass by design (they exist to skip
 * interactive login for automation). For an unenrolled in-scope admin past
 * grace, refuse to let them be USED for authentication — issuance is separately
 * a profile action, but an un-2FA'd admin should not have a working app password
 * standing in for the second factor.
 */
add_filter( 'wp_is_application_passwords_available_for_user', function ( $available, $user ) {
    if ( ! WPVM_MFA_ENFORCE || ! wpvm_mfa_available() ) {
        return $available;
    }
    if ( wpvm_mfa_user_in_scope( $user )
         && ! wpvm_mfa_user_enrolled( $user->ID )
         && wpvm_mfa_grace_expired( $user->ID ) ) {
        return false;
    }
    return $available;
}, 10, 2 );
