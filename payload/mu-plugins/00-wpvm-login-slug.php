<?php
/**
 * Plugin Name: WASP — Custom Login Slug
 * Description: Rewrites every login URL WordPress generates so the login form lives at your secret slug instead of /wp-login.php. Apache blocks the default path outright, so deleting this file does not restore it — it locks everyone out. Change the slug in the Apache config first, then here.
 * Author: RothITguy
 * Version: 1.0
 * Apache blocks direct requests to wp-login.php unless they arrive through
 * the slug rewrite. WordPress, left alone, would still emit wp-login.php in
 * its login form action and in every auth redirect, so submitting the login
 * form would hit the blocked path and fail. This rewrites those URLs.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'WPVM_LOGIN_SLUG' ) ) {
    // Bare slug, no suffix. A '-login' suffix made the path findable by
    // anything scanning for *login*, which is the entire class of thing a
    // slug is supposed to hide it from.
    define( 'WPVM_LOGIN_SLUG', 'WPVM_SLUG_PLACEHOLDER' );
}

/**
 * Swap wp-login.php for the slug in any URL string.
 */
function wpvm_swap_login_path( $url ) {
    if ( is_string( $url ) && false !== strpos( $url, 'wp-login.php' ) ) {
        return str_replace( 'wp-login.php', WPVM_LOGIN_SLUG, $url );
    }
    return $url;
}

/*
 * site_url() with the 'login' or 'login_post' scheme is what wp_login_url()
 * and the login form's own action attribute are built from — filtering here
 * covers both, plus anything else in core or a plugin that asks for a login
 * URL the documented way.
 */
add_filter(
    'site_url',
    function ( $url, $path, $scheme ) {
        if ( 'login' === $scheme || 'login_post' === $scheme ) {
            return wpvm_swap_login_path( $url );
        }
        return $url;
    },
    100,
    3
);

add_filter( 'network_site_url', function ( $url, $path, $scheme ) {
    if ( 'login' === $scheme || 'login_post' === $scheme ) {
        return wpvm_swap_login_path( $url );
    }
    return $url;
}, 100, 3 );

add_filter( 'login_url',        'wpvm_swap_login_path', 100 );
add_filter( 'logout_url',       'wpvm_swap_login_path', 100 );
add_filter( 'lostpassword_url', 'wpvm_swap_login_path', 100 );
add_filter( 'register_url',     'wpvm_swap_login_path', 100 );

/*
 * Catch redirects that were built before the filters above could apply
 * (some plugins hand-assemble a wp-login.php URL and pass it to
 * wp_redirect / wp_safe_redirect directly).
 */
add_filter( 'wp_redirect', 'wpvm_swap_login_path', 100 );

/*
 * Break the redirect_to loop.
 *
 * Since the bare slug became the login URL, the login page and the page
 * WordPress redirects unauthenticated users to are THE SAME URL. So when
 * wp-login.php decides a reauth is needed, it redirects to
 * wp_login_url($redirect_to) — where $redirect_to is the current REQUEST_URI,
 * which already contains a redirect_to. Each pass nests another copy:
 *
 *   /slug?redirect_to=…/slug?redirect_to=…/slug?redirect_to=…&reauth=1
 *
 * The URL grows exponentially until it exceeds the proxy's header buffer and
 * the request comes back as 502 Bad Gateway — which looks like a proxy fault
 * and is not one.
 *
 * With the old "<slug>-login" suffix this could not happen: the entry point
 * and the login page were different URLs, so the redirect terminated. That is
 * a consequence of removing the suffix which was not obvious at the time, and
 * is worth stating rather than quietly patching.
 *
 * The fix: a redirect_to that points back at the login page is meaningless —
 * nobody wants to be sent to the login form after logging in. Replace it with
 * the admin URL, which is what was intended.
 */
function wpvm_break_login_redirect_loop() {
    if ( empty( $_REQUEST['redirect_to'] ) ) {
        return;
    }
    $rt = (string) $_REQUEST['redirect_to'];

    $points_at_login =
        ( defined( 'WPVM_LOGIN_SLUG' ) && WPVM_LOGIN_SLUG !== ''
          && strpos( $rt, '/' . WPVM_LOGIN_SLUG ) !== false )
        || strpos( $rt, 'wp-login.php' ) !== false
        // A nested redirect_to at all means this has already bounced once.
        || strpos( $rt, 'redirect_to' ) !== false
        // Defensive: a legitimate redirect_to is short. Anything this long is
        // the loop, whatever produced it.
        || strlen( $rt ) > 512;

    if ( $points_at_login ) {
        $safe = admin_url();
        $_REQUEST['redirect_to'] = $safe;
        if ( isset( $_GET['redirect_to'] ) )  { $_GET['redirect_to']  = $safe; }
        if ( isset( $_POST['redirect_to'] ) ) { $_POST['redirect_to'] = $safe; }
    }
}
/* login_init fires on wp-login.php before it decides where to send anyone. */
add_action( 'login_init', 'wpvm_break_login_redirect_loop', 1 );

/*
 * Second line of defence: refuse to emit a redirect that still contains a
 * nested redirect_to. Priority 200 so it runs after wpvm_swap_login_path has
 * rewritten the path.
 */
add_filter( 'wp_redirect', function ( $location ) {
    if ( is_string( $location ) && substr_count( $location, 'redirect_to' ) > 1 ) {
        $parts = wp_parse_url( $location );
        $base  = ( $parts['scheme'] ?? 'https' ) . '://' . ( $parts['host'] ?? '' )
               . ( $parts['path'] ?? '/' );
        return $base;
    }
    return $location;
}, 200 );

/*
 * Emails — password reset and new-user notifications embed a login URL
 * built from network_site_url() in some code paths that run before the
 * filters above are registered in a multisite context.
 */
add_filter( 'retrieve_password_message', 'wpvm_swap_login_path', 100 );
add_filter( 'wp_mail', function ( $args ) {
    if ( isset( $args['message'] ) ) {
        $args['message'] = wpvm_swap_login_path( $args['message'] );
    }
    return $args;
}, 100 );
