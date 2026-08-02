<?php
/**
 * Plugin Name: WPVM Custom Login Slug
 * Description: Routes WordPress-generated login URLs through the custom slug
 *              configured at provisioning time. Installed by
 *              create-wordpress-vm.sh — do not edit by hand.
 *
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
