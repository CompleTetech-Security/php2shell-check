<?php
/**
 * Plugin Name: CompleteTech Authorized PHP2Shell Scan Queue
 * Description: Confirmation-gated, one-target PHP2Shell screening queue for Promo Requests.
 * Version: 0.1.0
 *
 * This MU plugin stores authorization and job state locally. It never starts a
 * scanner process. The external worker talks to the signed REST routes below.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'CT_SCAN_DEFAULT_TERMS_VERSION' ) ) {
	define( 'CT_SCAN_DEFAULT_TERMS_VERSION', '2026-10-21-r2' );
}

if ( ! defined( 'CT_SCAN_SCHEMA_VERSION' ) ) {
	define( 'CT_SCAN_SCHEMA_VERSION', '4' );
}

/**
 * Execution profiles. A job freezes its profile id at creation, and the limits
 * live here in code rather than in editable configuration, so a later setting
 * cannot broaden an existing authorization. `r2-header-v1` is the current
 * homepage-header screening: robots.txt (at most six hops) plus the homepage
 * (at most six hops, with at most one HTTP-to-HTTPS origin change) is at most
 * 20 requests. Unknown profiles are refused.
 */
function ct_scan_current_profile() {
	return 'r2-header-v1';
}

function ct_scan_profile_limits( $profile_id ) {
	$profiles = array(
		'r2-header-v1' => array(
			'http_requests'   => 20,
			// At most one request per second for the target, enforced centrally.
			'min_interval_ms' => 1000,
			// Disclosed bounds: an admission may be used for one second, and one
			// admitted request may finish within the ten-second timeout.
			'valid_ms'        => 1000,
			'timeout_ms'      => 10000,
		),
	);
	return is_string( $profile_id ) && isset( $profiles[ $profile_id ] ) ? $profiles[ $profile_id ] : false;
}

/** Load the secret-bearing settings without ever rendering their values. */
function ct_scan_config() {
	static $config = null;
	if ( null !== $config ) {
		return $config;
	}

	$config = array(
		'enabled'                  => false,
		'supported_terms_version'  => CT_SCAN_DEFAULT_TERMS_VERSION,
		'expected_checker_revision'=> '',
		'expected_rules_as_of'     => '2026-10-21',
		'worker_hmac_secret'       => '',
		'authorization_end_at'     => '2026-12-20T23:59:59Z',
		'confirmation_ttl_hours'   => 168,
		'global_daily_limit'       => 20,
		'target_daily_limit'       => 1,
		'job_retention_days'       => 365,
		// Terms versions whose acceptance MUST carry a bound snapshot and Target Summary.
		'bound_terms_versions'     => array(),
		// Email the verified contact their accepted copy after confirmation (off by default).
		'send_accepted_copy'       => false,
	);

	$path = defined( 'CT_SCAN_PRIVATE_CONFIG' )
		? CT_SCAN_PRIVATE_CONFIG
		: WP_CONTENT_DIR . '/ct-scan-private/config.php';
	if ( ! is_string( $path ) || ! is_readable( $path ) ) {
		return $config;
	}

	try {
		$loaded = include $path;
	} catch ( Throwable $error ) {
		return $config;
	}
	if ( ! is_array( $loaded ) ) {
		return $config;
	}
	$config = array_merge( $config, $loaded );
	$config['enabled'] = true === $config['enabled']
		&& is_string( $config['worker_hmac_secret'] )
		&& strlen( $config['worker_hmac_secret'] ) >= 32
		&& is_string( $config['expected_checker_revision'] )
		&& 1 === preg_match( '/\A[a-f0-9]{40}\z/i', $config['expected_checker_revision'] )
		&& is_string( $config['supported_terms_version'] )
		&& '' !== $config['supported_terms_version'];

	return $config;
}

function ct_scan_enabled() {
	$config = ct_scan_config();
	return ! empty( $config['enabled'] );
}

function ct_scan_jobs_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_jobs';
}

function ct_scan_nonces_table() {
	global $wpdb;
	return $wpdb->prefix . 'ct_scan_nonces';
}

/** Create plugin tables once; MU plugins do not receive activation hooks. */
function ct_scan_maybe_install_schema() {
	$previous = get_option( 'ct_scan_schema_version' );
	if ( $previous === CT_SCAN_SCHEMA_VERSION ) {
		return;
	}
	global $wpdb;
	require_once ABSPATH . 'wp-admin/includes/upgrade.php';
	$charset = $wpdb->get_charset_collate();
	$jobs    = ct_scan_jobs_table();
	$nonces  = ct_scan_nonces_table();
	$sql     = "CREATE TABLE {$jobs} (
		job_id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		request_id bigint(20) unsigned NOT NULL,
		target_origin varchar(512) NOT NULL,
		scope_hash char(64) NOT NULL,
		terms_version varchar(64) NOT NULL,
		terms_hash char(64) NOT NULL,
		terms_accepted_at datetime NOT NULL,
		authorization_expires_at datetime NOT NULL,
		contact_email varchar(320) NOT NULL,
		contact_name varchar(190) NOT NULL,
		referrer varchar(128) NOT NULL,
		status varchar(32) NOT NULL,
		created_at datetime NOT NULL,
		confirmation_token_hash char(64) NULL,
		stop_token_hash char(64) NULL,
		confirmation_expires_at datetime NULL,
		confirmation_email_status varchar(16) NOT NULL DEFAULT 'pending',
		confirmed_at datetime NULL,
		lease_hash char(64) NULL,
		lease_until datetime NULL,
		attempts tinyint(3) unsigned NOT NULL DEFAULT 0,
		started_at datetime NULL,
		finished_at datetime NULL,
		outcome varchar(16) NULL,
		error_code varchar(64) NULL,
		checker_revision char(40) NULL,
		result_json longtext NULL,
		receipt_hash char(64) NULL,
		manual_remainder_status varchar(16) NOT NULL DEFAULT 'pending',
		manual_remainder_notes longtext NULL,
		manual_remainder_completed_at datetime NULL,
		report_notification_status varchar(16) NOT NULL DEFAULT 'not_sent',
		report_notification_at datetime NULL,
		report_delivered_at datetime NULL,
		revoked_at datetime NULL,
		profile_id varchar(32) NOT NULL DEFAULT 'r2-header-v1',
		http_admitted smallint(5) unsigned NOT NULL DEFAULT 0,
		last_admit_ms bigint(20) unsigned NULL,
		summary_sha256 char(64) NULL,
		accepted_copy_status varchar(16) NOT NULL DEFAULT 'not_sent',
		accepted_copy_at datetime NULL,
		PRIMARY KEY  (job_id),
		UNIQUE KEY request_id (request_id),
		KEY status_created (status,created_at),
		KEY scope_created (scope_hash,created_at),
		KEY authorization_expires_at (authorization_expires_at),
		KEY confirmation_token_hash (confirmation_token_hash),
		KEY stop_token_hash (stop_token_hash)
	) {$charset};";
	dbDelta( $sql );
	$sql = "CREATE TABLE {$nonces} (
		nonce_hash char(64) NOT NULL,
		expires_at datetime NOT NULL,
		PRIMARY KEY  (nonce_hash),
		KEY expires_at (expires_at)
	) {$charset};";
	dbDelta( $sql );
	$required = array(
		$jobs   => array( 'job_id', 'request_id', 'target_origin', 'scope_hash', 'terms_version', 'terms_hash', 'terms_accepted_at', 'authorization_expires_at', 'status', 'lease_hash', 'result_json', 'receipt_hash', 'report_delivered_at', 'stop_token_hash', 'profile_id', 'http_admitted', 'last_admit_ms', 'summary_sha256', 'accepted_copy_status', 'accepted_copy_at' ),
		$nonces => array( 'nonce_hash', 'expires_at' ),
	);
	foreach ( $required as $table => $columns ) {
		$found = $wpdb->get_col( "SHOW COLUMNS FROM {$table}", 0 );
		if ( ! is_array( $found ) || array_diff( $columns, $found ) ) {
			return;
		}
	}
	if ( is_string( $previous ) && '' !== $previous && version_compare( $previous, '3', '<' ) ) {
		// A job that started before request counting existed has no record of what it already
		// sent: it gets no fresh budget, so its remaining admissions are refused.
		$limits = ct_scan_profile_limits( ct_scan_current_profile() );
		$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET http_admitted = %d WHERE status = 'running'", (int) $limits['http_requests'] ) );
	}
	update_option( 'ct_scan_schema_version', CT_SCAN_SCHEMA_VERSION, false );
}
add_action( 'init', 'ct_scan_maybe_install_schema', 2 );

/** Normalize a visitor-supplied URL to the exact authorized HTTP(S) origin. */
function ct_scan_normalize_target( $url ) {
	$bad = function ( $message ) {
		return new WP_Error( 'ct_scan_invalid_target', $message );
	};
	if ( ! is_string( $url ) ) {
		return $bad( 'The website address must be text.' );
	}
	if ( '' === $url || strlen( $url ) > 2048 || preg_match( '/[\x00-\x20\x7f]/', $url ) ) {
		return $bad( 'Enter one valid public website address.' );
	}
	$url = trim( $url );
	$parts = wp_parse_url( $url );
	if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
		return $bad( 'Include a complete http:// or https:// website address.' );
	}
	$scheme = strtolower( $parts['scheme'] );
	$host   = strtolower( $parts['host'] );
	if ( ! in_array( $scheme, array( 'http', 'https' ), true )
		|| isset( $parts['user'] ) || isset( $parts['pass'] )
		|| isset( $parts['query'] ) || isset( $parts['fragment'] ) ) {
		return $bad( 'Use an HTTP or HTTPS address without credentials, a query, or a fragment.' );
	}
	$port = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	if ( ( 'https' === $scheme && 443 !== $port ) || ( 'http' === $scheme && 80 !== $port ) ) {
		return $bad( 'Only the standard HTTP and HTTPS ports are allowed.' );
	}
	if ( isset( $parts['path'] ) && '' !== $parts['path'] && '/' !== $parts['path'] ) {
		return $bad( 'Enter the website homepage so the authorized scope is explicit.' );
	}
	if ( false !== strpos( $host, '%' ) || false !== inet_pton( trim( $host, '[]' ) ) ) {
		return $bad( 'IP address literals are not allowed.' );
	}
	if ( preg_match( '/\A(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}\z/i', $host ) ) {
		return $bad( 'Numeric IP address forms are not allowed.' );
	}
	if ( strlen( $host ) > 253 || substr( $host, -1 ) === '.' || false !== strpos( $host, '..' ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$labels = explode( '.', $host );
	if ( count( $labels ) < 2 ) {
		return $bad( 'Use a public hostname with at least two labels.' );
	}
	foreach ( $labels as $label ) {
		if ( strlen( $label ) > 63 || ! preg_match( '/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/i', $label ) ) {
			return $bad( 'The website hostname is not valid.' );
		}
	}
	$tld = end( $labels );
	if ( strlen( $tld ) < 2 || ctype_digit( $tld ) ) {
		return $bad( 'The website hostname is not valid.' );
	}
	$private_suffixes = array( 'localhost', 'local', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'test', 'example', 'invalid', 'onion' );
	if ( in_array( $tld, $private_suffixes, true ) || 'localhost' === $host ) {
		return $bad( 'Local and reserved hostnames are not allowed.' );
	}
	return $scheme . '://' . $host . '/';
}

function ct_scan_utc_now() {
	return gmdate( 'Y-m-d H:i:s' );
}

function ct_scan_utc_parse( $value ) {
	if ( ! is_string( $value ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/', $value ) ) {
		return false;
	}
	try {
		$date = new DateTimeImmutable( $value, new DateTimeZone( 'UTC' ) );
		return $date->format( 'Y-m-d\TH:i:s\Z' ) === $value ? $date : false;
	} catch ( Throwable $error ) {
		return false;
	}
}

function ct_scan_meta_string( $post_id, $key ) {
	$value = get_post_meta( $post_id, $key, true );
	return is_string( $value ) ? $value : '';
}

/**
 * Evidence binding. A "bound" acceptance retains the exact terms bytes that the signer was
 * shown and the exact Target Summary, each next to the digest the signer's form carried:
 *
 *   _ct_terms_binding        '1' marks the acceptance as bound
 *   _ct_terms_snapshot       the terms bytes as displayed (the immutable artifact)
 *   _ct_terms_sha256         SHA-256 of those bytes
 *   _ct_terms_shown_digest   the digest the rendered form carried (must equal the above)
 *   _ct_summary_text         the Target Summary as displayed ("Label: value" lines)
 *   _ct_summary_sha256       SHA-256 of that text
 *   _ct_summary_shown_digest the digest the form carried for the summary
 *
 * Any partial or mismatched set refuses the job (and cancels a queued or running one via
 * ct_scan_authorization_is_live). Versions listed in config `bound_terms_versions` must be bound.
 * An unbound legacy acceptance is accepted only for versions that are not listed.
 */
function ct_scan_check_bound_evidence( $request_id, $terms_version, $terms_hash, $identity ) {
	$config   = ct_scan_config();
	$required = in_array( $terms_version, (array) $config['bound_terms_versions'], true );
	$marker   = ct_scan_meta_string( $request_id, '_ct_terms_binding' );
	$partial  = false;
	foreach ( array( '_ct_terms_snapshot', '_ct_terms_shown_digest', '_ct_summary_text', '_ct_summary_sha256', '_ct_summary_shown_digest' ) as $key ) {
		if ( '' !== ct_scan_meta_string( $request_id, $key ) ) {
			$partial = true;
		}
	}
	if ( '1' !== $marker ) {
		if ( $required || '' !== $marker || $partial ) {
			return new WP_Error( 'ct_scan_binding_required', 'The saved acceptance does not carry the required bound evidence.' );
		}
		return array( 'bound' => false, 'summary_sha256' => null );
	}
	$snapshot = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary  = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	if ( '' === $snapshot || strlen( $snapshot ) > 524288 || '' === $summary || strlen( $summary ) > 8192 ) {
		return new WP_Error( 'ct_scan_binding_mismatch', 'The retained terms or Target Summary is missing or oversized.' );
	}
	$snapshot_hash = hash( 'sha256', $snapshot );
	$summary_hash  = hash( 'sha256', $summary );
	$checks = array(
		$snapshot_hash => array( $terms_hash, strtolower( ct_scan_meta_string( $request_id, '_ct_terms_shown_digest' ) ) ),
		$summary_hash  => array( strtolower( ct_scan_meta_string( $request_id, '_ct_summary_sha256' ) ), strtolower( ct_scan_meta_string( $request_id, '_ct_summary_shown_digest' ) ) ),
	);
	foreach ( $checks as $computed => $recorded ) {
		foreach ( $recorded as $value ) {
			if ( ! is_string( $value ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $value ) || ! hash_equals( $computed, $value ) ) {
				return new WP_Error( 'ct_scan_binding_mismatch', 'The retained evidence does not match the digest the signer was shown.' );
			}
		}
	}
	$expected = array(
		'Website (scan scope)' => $identity['target'],
		'Client email'         => $identity['email'],
		'Client contact'       => $identity['name'],
		'Profile'              => ct_scan_current_profile(),
	);
	foreach ( $expected as $label => $value ) {
		if ( ! preg_match( '/^' . preg_quote( $label, '/' ) . ': (.*)$/m', $summary, $match ) || $match[1] !== $value ) {
			return new WP_Error( 'ct_scan_binding_mismatch', 'The retained Target Summary does not match the authorized request.' );
		}
		if ( preg_match_all( '/^' . preg_quote( $label, '/' ) . ':/m', $summary ) !== 1 ) {
			return new WP_Error( 'ct_scan_binding_mismatch', 'The retained Target Summary repeats a field.' );
		}
	}
	return array( 'bound' => true, 'summary_sha256' => $summary_hash );
}

/** Check the saved request and acceptance snapshot before any job is created. */
function ct_scan_validate_saved_request( $request_id, $fields, $require_current_terms = true, $frozen_expiry = '' ) {
	$config = ct_scan_config();
	$post   = get_post( $request_id );
	if ( ! $post || 'ct_promo_request' !== $post->post_type || 'private' !== $post->post_status ) {
		return new WP_Error( 'ct_scan_request_missing', 'The saved private request could not be verified.' );
	}
	if ( ! is_array( $fields ) ) {
		return new WP_Error( 'ct_scan_fields_invalid', 'The saved request fields could not be verified.' );
	}
	foreach ( array( 'target', 'email', 'name', 'referrer' ) as $key ) {
		if ( ! isset( $fields[ $key ] ) || ! is_string( $fields[ $key ] ) ) {
			return new WP_Error( 'ct_scan_fields_incomplete', 'The saved request fields are incomplete.' );
		}
	}
	$target = ct_scan_normalize_target( $fields['target'] );
	if ( is_wp_error( $target ) || $target !== $fields['target'] ) {
		return new WP_Error( 'ct_scan_target_mismatch', 'The saved authorized target is not in normalized form.' );
	}
	$email = sanitize_email( $fields['email'] );
	$name  = sanitize_text_field( $fields['name'] );
	$ref   = sanitize_title( $fields['referrer'] );
	if ( ! is_email( $email ) || $email !== $fields['email'] || '' === $name || $name !== $fields['name']
		|| '' === $ref || $ref !== $fields['referrer'] ) {
		return new WP_Error( 'ct_scan_contact_mismatch', 'The saved contact or referral fields are incomplete.' );
	}
	foreach ( array(
		'_ct_scan_target' => $target,
		'_ct_scan_email'  => $email,
		'_ct_scan_name'   => $name,
		'_ct_ref'         => $ref,
	) as $key => $expected ) {
		if ( ct_scan_meta_string( $request_id, $key ) !== $expected ) {
			return new WP_Error( 'ct_scan_request_readback_mismatch', 'The saved request did not match its authorization event.' );
		}
	}
	if ( '1' !== ct_scan_meta_string( $request_id, '_ct_terms_saved' ) ) {
		return new WP_Error( 'ct_scan_acceptance_incomplete', 'A complete saved terms acceptance is required.' );
	}
	$terms_version = ct_scan_meta_string( $request_id, '_ct_terms_version' );
	$terms_url     = ct_scan_meta_string( $request_id, '_ct_terms_url' );
	$terms_hash    = strtolower( ct_scan_meta_string( $request_id, '_ct_terms_sha256' ) );
	$accepted_raw  = ct_scan_meta_string( $request_id, '_ct_terms_accepted_at' );
	$contract      = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$accepted_at   = ct_scan_utc_parse( $accepted_raw );
	if ( ( $require_current_terms && $terms_version !== $config['supported_terms_version'] ) || '' === $terms_url
		|| ! preg_match( '/\A[a-f0-9]{64}\z/', $terms_hash ) || ! $accepted_at
		|| '' === trim( $contract ) ) {
		return new WP_Error( 'ct_scan_acceptance_stale', 'The saved terms acceptance is missing or no longer current.' );
	}
	if ( $accepted_at->getTimestamp() > time() + 300 ) {
		return new WP_Error( 'ct_scan_acceptance_time_invalid', 'The saved acceptance time could not be verified.' );
	}
	$expected_lines = array(
		'Client contact'       => $name,
		'Client email'         => $email,
		'Website (scan scope)' => $target,
		'Referred by'          => $ref,
	);
	foreach ( $expected_lines as $label => $expected ) {
		if ( ! preg_match( '/^' . preg_quote( $label, '/' ) . ':\s*(.*)$/m', $contract, $match ) || trim( $match[1] ) !== $expected ) {
			return new WP_Error( 'ct_scan_contract_mismatch', 'The saved acceptance copy does not match the authorized request fields.' );
		}
	}
	if ( false === strpos( $post->post_content, $contract ) ) {
		return new WP_Error( 'ct_scan_contract_readback_mismatch', 'The saved acceptance copy could not be read back from the request.' );
	}
	$bound = ct_scan_check_bound_evidence( $request_id, $terms_version, $terms_hash, array( 'target' => $target, 'email' => $email, 'name' => $name ) );
	if ( is_wp_error( $bound ) ) {
		return $bound;
	}
	if ( $require_current_terms ) {
		$window_end = ct_scan_utc_parse( $config['authorization_end_at'] );
		if ( ! $window_end ) {
			return new WP_Error( 'ct_scan_config_invalid', 'The authorization end date is not configured.' );
		}
		$expires = $accepted_at->modify( '+60 days' );
		if ( $window_end < $expires ) {
			$expires = $window_end;
		}
	} else {
		if ( ! preg_match( '/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\z/', $frozen_expiry ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		try {
			$expires = new DateTimeImmutable( $frozen_expiry, new DateTimeZone( 'UTC' ) );
		} catch ( Throwable $error ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry could not be verified.' );
		}
		if ( $expires > $accepted_at->modify( '+60 days' ) ) {
			return new WP_Error( 'ct_scan_expiry_invalid', 'The saved authorization expiry exceeds its accepted window.' );
		}
	}
	if ( $expires <= new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) ) {
		return new WP_Error( 'ct_scan_authorization_expired', 'The scan authorization window has expired.' );
	}
	return array(
		'post'                  => $post,
		'target'                => $target,
		'email'                 => $email,
		'name'                  => $name,
		'referrer'              => $ref,
		'terms_version'         => $terms_version,
		'terms_hash'            => $terms_hash,
		'terms_accepted_at'     => $accepted_at->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'authorization_expires' => $expires->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'Y-m-d H:i:s' ),
		'summary_sha256'        => $bound['summary_sha256'],
	);
}

/** Acquire the per-site MySQL advisory lock used to serialize state changes. */
function ct_scan_lock_acquire( $wait_seconds = 0 ) {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	// Worker paths never wait (they fail closed and retry). Customer stop and
	// operator revocation may wait briefly so a concurrent admission cannot make
	// a cancellation spuriously fail.
	$wait = max( 0, min( 5, (int) $wait_seconds ) );
	return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', $name, $wait ) );
}

function ct_scan_lock_release() {
	global $wpdb;
	$name = 'ctscan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 24 );
	$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $name ) );
}

function ct_scan_mark_request_status( $request_id, $status, $detail = '' ) {
	update_post_meta( $request_id, '_ct_scan_status', sanitize_key( $status ) );
	if ( '' !== $detail ) {
		update_post_meta( $request_id, '_ct_scan_status_detail', sanitize_key( $detail ) );
	} else {
		delete_post_meta( $request_id, '_ct_scan_status_detail' );
	}
}

function ct_scan_safe_notice( $request_id, $code ) {
	ct_scan_mark_request_status( $request_id, 'not_queued', $code );
	return new WP_Error( 'ct_scan_' . sanitize_key( $code ), 'The request was retained, but the scan was not queued.' );
}

/**
 * Single event entry point. The theme calls this only after durable readback;
 * the plugin repeats that readback and never infers scope from post text.
 */
function ct_scan_on_request_ready( $request_id, $fields ) {
	$request_id = absint( $request_id );
	if ( ! $request_id || ! ct_scan_enabled() ) {
		if ( $request_id ) {
			return ct_scan_safe_notice( $request_id, 'disabled' );
		}
		return new WP_Error( 'ct_scan_request_id_invalid', 'The saved request could not be identified.' );
	}
	$config = ct_scan_config();
	$token  = bin2hex( random_bytes( 32 ) );
	// Separate long-lived token for the customer's Stop link; only its hash is stored.
	$stop_token = bin2hex( random_bytes( 32 ) );
	$now    = time();
	$ttl    = max( 1, min( 168, absint( $config['confirmation_ttl_hours'] ) ) );
	$created = gmdate( 'Y-m-d H:i:s', $now );
	$confirm_expires = gmdate( 'Y-m-d H:i:s', $now + ( $ttl * HOUR_IN_SECONDS ) );
	$jobs = ct_scan_jobs_table();
	global $wpdb;
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_safe_notice( $request_id, 'queue_busy' );
	}
	try {
		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
		if ( $existing ) {
			update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
			update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
			update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
			ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
			return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
		}
		if ( get_post_meta( $request_id, '_ct_scan_event_recorded', true ) ) {
			return new WP_Error( 'ct_scan_duplicate_event', 'This request already has a scan event.' );
		}
		$accepted = ct_scan_validate_saved_request( $request_id, $fields );
		if ( is_wp_error( $accepted ) ) {
			return ct_scan_safe_notice( $request_id, $accepted->get_error_code() );
		}
		$scope_hash = hash( 'sha256', $accepted['target'] );
		$since = gmdate( 'Y-m-d H:i:s', $now - DAY_IN_SECONDS );
		$global_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE created_at >= %s", $since ) );
		$target_count = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE scope_hash = %s AND created_at >= %s", $scope_hash, $since ) );
		if ( $global_count >= min( 1000, max( 1, absint( $config['global_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'global_quota' );
		}
		if ( $target_count >= min( 10, max( 1, absint( $config['target_daily_limit'] ) ) ) ) {
			return ct_scan_safe_notice( $request_id, 'target_quota' );
		}
		$inserted = $wpdb->insert(
			$jobs,
			array(
				'request_id'               => $request_id,
				'target_origin'            => $accepted['target'],
				'scope_hash'               => $scope_hash,
				'terms_version'            => $accepted['terms_version'],
				'terms_hash'               => $accepted['terms_hash'],
				'terms_accepted_at'        => $accepted['terms_accepted_at'],
				'authorization_expires_at' => $accepted['authorization_expires'],
				'contact_email'            => $accepted['email'],
				'contact_name'             => $accepted['name'],
				'referrer'                 => $accepted['referrer'],
				'status'                   => 'awaiting_confirmation',
				'created_at'               => $created,
				'confirmation_token_hash'  => hash( 'sha256', $token ),
				'confirmation_expires_at'  => $confirm_expires,
				'stop_token_hash'          => hash( 'sha256', $stop_token ),
				'profile_id'               => ct_scan_current_profile(),
				'summary_sha256'           => $accepted['summary_sha256'],
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		if ( 1 !== $inserted ) {
			$existing = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$jobs} WHERE request_id = %d LIMIT 1", $request_id ) );
			if ( $existing ) {
				update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
				update_post_meta( $request_id, '_ct_scan_job_id', (int) $existing->job_id );
				update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $existing->authorization_expires_at );
				ct_scan_mark_request_status( $request_id, $existing->status, $existing->error_code ? $existing->error_code : '' );
				return array( 'job_id' => (int) $existing->job_id, 'status' => $existing->status, 'confirmation_email_status' => $existing->confirmation_email_status, 'duplicate' => true );
			}
			return ct_scan_safe_notice( $request_id, 'queue_write_failed' );
		}
		$job_id = (int) $wpdb->insert_id;
		update_post_meta( $request_id, '_ct_scan_event_recorded', '1' );
		update_post_meta( $request_id, '_ct_scan_job_id', $job_id );
		update_post_meta( $request_id, '_ct_scan_authorization_expires_at', $accepted['authorization_expires'] );
		ct_scan_mark_request_status( $request_id, 'awaiting_confirmation' );
	} finally {
		ct_scan_lock_release();
	}

	$url = add_query_arg(
		array( 'action' => 'ct_scan_confirm', 'token' => $token ),
		admin_url( 'admin-post.php' )
	);
	$stop_url = add_query_arg(
		array( 'action' => 'ct_scan_stop', 'stop' => $stop_token ),
		admin_url( 'admin-post.php' )
	);
	$subject = 'Confirm your authorized PHP2Shell screening';
	$message = "A request was saved to screen the website you authorized.\n\n"
		. "To confirm and allow one passive check of " . wp_parse_url( $accepted['target'], PHP_URL_HOST ) . ", open this link and press Confirm. Opening the link alone does not authorize a scan:\n\n"
		. $url . "\n\nThis confirmation expires in {$ttl} hours. If you did not submit this request, ignore this message. Mailbox confirmation shows control of this email address; it does not independently prove domain ownership.\n\n"
		. "To stop this screening at any time, open this link and press Stop. Opening the link alone changes nothing:\n\n"
		. $stop_url . "\n";
	$mail_status = 'unknown';
	$pending = $wpdb->update( $jobs, array( 'confirmation_email_status' => 'unknown' ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'pending' ), array( '%s' ), array( '%d', '%s' ) );
	if ( 1 !== $pending ) {
		update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
		return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => 'unknown' );
	}
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', 'unknown' );
	try {
		$mail_status = wp_mail( $accepted['email'], $subject, $message ) ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$mail_status = 'unknown';
	}
	$wpdb->update( $jobs, array( 'confirmation_email_status' => $mail_status ), array( 'job_id' => $job_id, 'confirmation_email_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	update_post_meta( $request_id, '_ct_scan_confirmation_email_status', $mail_status );
	return array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_email_status' => $mail_status );
}
add_action( 'ct_promo_request_ready', 'ct_scan_on_request_ready', 10, 2 );

function ct_scan_row( $job_id ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE job_id = %d", absint( $job_id ) ) );
}

function ct_scan_authorization_is_live( $row ) {
	if ( ! is_object( $row ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
		|| strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		return false;
	}
	if ( ct_scan_meta_string( (int) $row->request_id, '_ct_scan_authorization_expires_at' ) !== $row->authorization_expires_at ) {
		return false;
	}
	$fields = array(
		'target'   => $row->target_origin,
		'email'    => $row->contact_email,
		'name'     => $row->contact_name,
		'referrer' => $row->referrer,
	);
	$accepted = ct_scan_validate_saved_request( (int) $row->request_id, $fields, false, $row->authorization_expires_at );
	if ( is_wp_error( $accepted ) ) {
		return false;
	}
	return hash_equals( $row->scope_hash, hash( 'sha256', $accepted['target'] ) )
		&& hash_equals( $row->terms_hash, $accepted['terms_hash'] )
		&& $row->terms_version === $accepted['terms_version']
		&& $row->terms_accepted_at === $accepted['terms_accepted_at']
		&& $row->authorization_expires_at === $accepted['authorization_expires']
		// The retained Target Summary is part of the authorization: it cannot change afterwards.
		&& ( null === $accepted['summary_sha256']
			? empty( $row->summary_sha256 )
			: ( is_string( $row->summary_sha256 ) && hash_equals( $row->summary_sha256, $accepted['summary_sha256'] ) ) );
}

/** Reconcile bounded leases and apply the published data-retention windows. */
function ct_scan_maintenance_locked() {
	global $wpdb;
	$table = ct_scan_jobs_table();
	$now   = ct_scan_utc_now();
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'authorization_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL, confirmation_token_hash = NULL WHERE status IN ('awaiting_confirmation','queued','leased','running') AND authorization_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'expired', error_code = 'confirmation_expired', finished_at = %s, confirmation_token_hash = NULL WHERE status = 'awaiting_confirmation' AND confirmation_expires_at <= %s",
		$now,
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'queued', lease_hash = NULL, lease_until = NULL WHERE status = 'leased' AND lease_until <= %s AND attempts = 0",
		$now
	) );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET status = 'failed_unknown', outcome = 'failed', error_code = 'lease_expired', finished_at = %s, lease_hash = NULL, lease_until = NULL WHERE status = 'running' AND lease_until <= %s",
		$now,
		$now
	) );
	$queued = $wpdb->get_results( "SELECT job_id,request_id,target_origin,scope_hash,terms_version,terms_hash,terms_accepted_at,authorization_expires_at,contact_email,contact_name,referrer,revoked_at,report_delivered_at,summary_sha256 FROM {$table} WHERE status = 'queued'" );
	foreach ( (array) $queued as $row ) {
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => $now, 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		}
	}
	$nonce_table = ct_scan_nonces_table();
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$nonce_table} WHERE expires_at < %s", gmdate( 'Y-m-d H:i:s', time() - 600 ) ) );

	$result_cutoff = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-12 months' )->format( 'Y-m-d H:i:s' );
	$wpdb->query( $wpdb->prepare(
		"UPDATE {$table} SET result_json = NULL, manual_remainder_notes = NULL WHERE (result_json IS NOT NULL OR manual_remainder_notes IS NOT NULL) AND finished_at IS NOT NULL AND finished_at < %s",
		$result_cutoff
	) );
	$request_cutoff = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-3 years' )->format( 'Y-m-d H:i:s' );
	$old_rows = $wpdb->get_results( $wpdb->prepare( "SELECT job_id,request_id FROM {$table} WHERE terms_accepted_at < %s AND status IN ('completed','failed','failed_unknown','cancelled','expired')", $request_cutoff ) );
	foreach ( (array) $old_rows as $row ) {
		$post = get_post( (int) $row->request_id );
		$personal_scrubbed = $wpdb->update(
			$table,
			array( 'contact_email' => '', 'contact_name' => '' ),
			array( 'job_id' => (int) $row->job_id ),
			array( '%s', '%s' ),
			array( '%d' )
		);
		if ( false === $personal_scrubbed ) {
			continue;
		}
		if ( 0 === $personal_scrubbed ) {
			$scrubbed = $wpdb->get_row( $wpdb->prepare( "SELECT contact_email,contact_name FROM {$table} WHERE job_id = %d", (int) $row->job_id ) );
			if ( ! $scrubbed || '' !== $scrubbed->contact_email || '' !== $scrubbed->contact_name ) {
				continue;
			}
		}
		if ( $post && 'ct_promo_request' === $post->post_type && 'private' === $post->post_status && (int) $post->ID === (int) $row->request_id ) {
			if ( ! wp_delete_post( (int) $row->request_id, true ) ) {
				continue;
			}
		}
		$wpdb->delete( $table, array( 'job_id' => (int) $row->job_id ), array( '%d' ) );
	}
}

function ct_scan_maintain() {
	if ( ! ct_scan_lock_acquire() ) {
		return false;
	}
	try {
		ct_scan_maintenance_locked();
	} finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_confirmation_token_from_request( $source ) {
	if ( ! isset( $source['token'] ) || ! is_string( $source['token'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['token'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_confirmation_markup( $job_id, $token, $nonce, $target, $terms_version, $accepted_at ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	$accepted_label = esc_html( str_replace( ' ', 'T', $accepted_at ) . 'Z (UTC)' );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Confirm website screening</title><body><main><h1>Confirm your website screening</h1><p>Confirm one passive check of this exact website origin:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>Terms version accepted: <strong>' . esc_html( $terms_version ) . '</strong><br>Acceptance recorded: <strong>' . $accepted_label . '</strong></p><p>Opening this page alone does not authorize a scan. This confirms control of the request email address; it does not independently prove domain ownership.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_confirm"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="token" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Confirm one passive screening</button></form></main></body></html>';
}

function ct_scan_send_confirmation_page( $message, $status = 200, $markup = '' ) {
	nocache_headers();
	status_header( $status );
	header( 'Content-Type: text/html; charset=UTF-8' );
	header( 'Referrer-Policy: no-referrer' );
	header( 'X-Content-Type-Options: nosniff' );
	header( "Content-Security-Policy: default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; style-src 'unsafe-inline'" );
	if ( '' === $markup ) {
		$markup = '<!doctype html><html lang="en"><meta charset="utf-8"><title>Website screening</title><body><main><h1>Website screening</h1><p>' . esc_html( $message ) . '</p></main></body></html>';
	}
	echo $markup; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- markup is assembled from escaped fields above.
	exit;
}

function ct_scan_confirmation_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_confirmation_token_from_request( $_GET );
		if ( '' === $token ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 404 );
		}
		$row = ct_scan_row_by_confirmation_hash( hash( 'sha256', $token ) );
		if ( ! $row || 'awaiting_confirmation' !== $row->status || strtotime( $row->confirmation_expires_at . ' UTC' ) <= time()
			|| ! ct_scan_authorization_is_live( $row ) ) {
			ct_scan_send_confirmation_page( 'This confirmation link is invalid or expired.', 410 );
		}
		$nonce = wp_create_nonce( 'ct_scan_confirm_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_confirmation_markup( (int) $row->job_id, $token, $nonce, $row->target_origin, $row->terms_version, $row->terms_accepted_at ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the confirmation form to continue.', 405 );
	}
	$token  = ct_scan_confirmation_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_confirm_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This confirmation form is invalid or expired.', 403 );
	}
	if ( ! ct_scan_lock_acquire() ) {
		ct_scan_send_confirmation_page( 'The request is temporarily busy. Please try again.', 503 );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	$message = 'This confirmation link is invalid or expired.';
	$response_status = 410;
	try {
		$row = ct_scan_row( $job_id );
		if ( $row && 'awaiting_confirmation' === $row->status && ! empty( $row->confirmation_token_hash )
			&& hash_equals( $row->confirmation_token_hash, hash( 'sha256', $token ) )
			&& strtotime( $row->confirmation_expires_at . ' UTC' ) > time() && ct_scan_authorization_is_live( $row ) ) {
			$updated = $wpdb->update(
				$table,
				array( 'status' => 'queued', 'confirmed_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null, 'confirmation_expires_at' => null ),
				array( 'job_id' => $job_id, 'status' => 'awaiting_confirmation', 'confirmation_token_hash' => $row->confirmation_token_hash ),
				array( '%s', '%s', '%s', '%s' ),
				array( '%d', '%s', '%s' )
			);
			if ( 1 === $updated ) {
				ct_scan_mark_request_status( (int) $row->request_id, 'queued' );
				$message = 'Your screening is confirmed and queued. It will run once, within the authorization window.';
				$response_status = 200;
			}
		}
	} finally {
		ct_scan_lock_release();
	}
	if ( 200 === $response_status ) {
		try {
			ct_scan_send_accepted_copy( $job_id );
		} catch ( Throwable $error ) {
			// The copy is independent of the confirmed, queued job.
			unset( $error );
		}
	}
	ct_scan_send_confirmation_page( $message, $response_status );
}

/**
 * Send the verified contact a retainable copy of what they accepted. Runs after mailbox
 * confirmation, independently of scanning: a failure here never cancels, delays or repeats a
 * scan, and a send is attempted at most once per job (the status is claimed with a
 * compare-and-set before mail is handed off, and an uncertain outcome is never resent).
 * Transport acceptance is not receipt. Off unless config `send_accepted_copy` is true.
 * TODO(owner): review the wording of this message before enabling.
 * Returns 'disabled', 'sent', 'unknown', 'already_handled', or a WP_Error.
 */
function ct_scan_send_accepted_copy( $job_id ) {
	global $wpdb;
	if ( ! ct_scan_enabled() || empty( ct_scan_config()['send_accepted_copy'] ) ) {
		return 'disabled';
	}
	$table = ct_scan_jobs_table();
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->confirmed_at ) || '' === (string) $row->contact_email ) {
			return new WP_Error( 'accepted_copy_unavailable', 'The accepted copy requires a confirmed recipient.' );
		}
		$claimed = $wpdb->update(
			$table,
			array( 'accepted_copy_status' => 'unknown', 'accepted_copy_at' => ct_scan_utc_now() ),
			array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'not_sent' ),
			array( '%s', '%s' ),
			array( '%d', '%s' )
		);
		if ( 1 !== $claimed ) {
			return 'already_handled';
		}
	} finally {
		ct_scan_lock_release();
	}
	$request_id = (int) $row->request_id;
	$contract   = ct_scan_meta_string( $request_id, '_ct_terms_contract' );
	$snapshot   = ct_scan_meta_string( $request_id, '_ct_terms_snapshot' );
	$summary    = ct_scan_meta_string( $request_id, '_ct_summary_text' );
	$bound      = '1' === ct_scan_meta_string( $request_id, '_ct_terms_binding' ) && $row->summary_sha256 === hash( 'sha256', $summary ) && hash( 'sha256', $snapshot ) === $row->terms_hash;
	$lines = array(
		'This is the copy of the free PHP2Shell screening agreement and scope that you accepted. Please keep it for your records.',
		'',
		'Website (scan scope): ' . $row->target_origin,
		'Terms version: ' . $row->terms_version,
		'Terms SHA-256: ' . $row->terms_hash,
		'Accepted (UTC): ' . $row->terms_accepted_at,
		'Mailbox confirmed (UTC): ' . $row->confirmed_at,
		'Authorization expires (UTC): ' . $row->authorization_expires_at,
	);
	$attachments = array();
	$tempfile    = '';
	if ( $bound ) {
		$lines[] = 'Target Summary SHA-256: ' . $row->summary_sha256;
		$lines[] = '';
		$lines[] = 'Target Summary as shown to you:';
		$lines[] = $summary;
		$tempfile = tempnam( sys_get_temp_dir(), 'ctat' ); // created mode 0600
		if ( is_string( $tempfile ) && '' !== $tempfile && false !== file_put_contents( $tempfile, $snapshot ) ) {
			$named = dirname( $tempfile ) . '/accepted-terms-' . (int) $row->job_id . '-' . preg_replace( '/[^A-Za-z0-9._-]/', '', $row->terms_version ) . '-' . substr( $row->terms_hash, 0, 12 ) . '.html';
			if ( @rename( $tempfile, $named ) ) {
				$tempfile = $named;
			}
			$attachments[] = $tempfile;
			$lines[]       = 'The attached file contains the exact terms text you were shown; its SHA-256 is the value above.';
		}
	}
	$lines[] = '';
	$lines[] = $contract;
	$status  = 'unknown';
	try {
		$sent   = wp_mail( $row->contact_email, 'Your accepted PHP2Shell screening agreement', implode( "\n", $lines ), '', $attachments );
		$status = $sent ? 'accepted' : 'unknown';
	} catch ( Throwable $error ) {
		$status = 'unknown';
	}
	if ( '' !== $tempfile ) {
		@unlink( $tempfile );
	}
	$wpdb->update( $table, array( 'accepted_copy_status' => $status ), array( 'job_id' => (int) $row->job_id, 'accepted_copy_status' => 'unknown' ), array( '%s' ), array( '%d', '%s' ) );
	return 'accepted' === $status ? 'sent' : 'unknown';
}

function ct_scan_row_by_confirmation_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE confirmation_token_hash = %s LIMIT 1", $hash ) );
}
add_action( 'admin_post_nopriv_ct_scan_confirm', 'ct_scan_confirmation_handler' );
add_action( 'admin_post_ct_scan_confirm', 'ct_scan_confirmation_handler' );

function ct_scan_stop_token_from_request( $source ) {
	if ( ! isset( $source['stop'] ) || ! is_string( $source['stop'] ) ) {
		return '';
	}
	$token = wp_unslash( $source['stop'] );
	return preg_match( '/\A[a-f0-9]{64}\z/i', $token ) ? strtolower( $token ) : '';
}

function ct_scan_row_by_stop_hash( $hash ) {
	global $wpdb;
	$table = ct_scan_jobs_table();
	return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE stop_token_hash = %s LIMIT 1", $hash ) );
}

/**
 * Customer stop: request-bound and idempotent, serialized with claims, starts, results and
 * request admissions by the queue lock. A cancelled job is rejected by the start, admit and
 * result endpoints. A request already admitted when the stop commits may finish within its
 * ten-second timeout; no further request is admitted. Waits briefly for the lock so that a
 * concurrent admission cannot make the customer's stop fail.
 * Returns 'stopped', 'already_stopped', 'already_finished', or a WP_Error.
 */
function ct_scan_customer_stop( $job_id, $token ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The request is temporarily busy. Please try again.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || empty( $row->stop_token_hash ) || '' === $token || ! hash_equals( $row->stop_token_hash, hash( 'sha256', $token ) ) ) {
			return new WP_Error( 'stop_link_invalid', 'This stop link is invalid.' );
		}
		if ( 'cancelled' === $row->status ) {
			return 'already_stopped';
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			return 'already_finished';
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'cancelled', 'error_code' => 'customer_stopped', 'finished_at' => $now, 'confirmation_token_hash' => null, 'confirmation_expires_at' => null, 'lease_hash' => null, 'lease_until' => null ),
			array( 'job_id' => (int) $row->job_id, 'status' => $row->status ),
			null,
			array( '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'stop_write_failed', 'The stop could not be recorded. Please try again or contact support@complete.tech.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'customer_stopped' );
	} finally {
		ct_scan_lock_release();
	}
	return 'stopped';
}

function ct_scan_stop_markup( $job_id, $token, $nonce, $target ) {
	$action = esc_url( admin_url( 'admin-post.php' ) );
	return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Stop website screening</title><body><main><h1>Stop your website screening</h1><p>Stop the screening of this website:</p><p><strong>' . esc_html( $target ) . '</strong></p><p>No new screening will start after you press Stop. A check that has already started may finish its current requests. Opening this page alone changes nothing.</p><form method="post" action="' . $action . '"><input type="hidden" name="action" value="ct_scan_stop"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="stop" value="' . esc_attr( $token ) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr( $nonce ) . '"><button type="submit">Stop screening</button></form></main></body></html>';
}

function ct_scan_stop_handler() {
	$method = isset( $_SERVER['REQUEST_METHOD'] ) && is_string( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : '';
	if ( 'GET' === $method ) {
		$token = ct_scan_stop_token_from_request( $_GET );
		$row   = '' === $token ? null : ct_scan_row_by_stop_hash( hash( 'sha256', $token ) );
		if ( ! $row ) {
			ct_scan_send_confirmation_page( 'This stop link is invalid.', 404 );
		}
		if ( ct_scan_terminal_status( $row->status ) ) {
			ct_scan_send_confirmation_page( 'cancelled' === $row->status ? 'This screening is already stopped.' : 'This screening has already finished. Nothing further will run.' );
		}
		$nonce = wp_create_nonce( 'ct_scan_stop_' . (int) $row->job_id . '_' . $token );
		ct_scan_send_confirmation_page( '', 200, ct_scan_stop_markup( (int) $row->job_id, $token, $nonce, $row->target_origin ) );
	}
	if ( 'POST' !== $method ) {
		ct_scan_send_confirmation_page( 'Use the stop form to continue.', 405 );
	}
	$token  = ct_scan_stop_token_from_request( $_POST );
	$job_id = isset( $_POST['job_id'] ) && is_scalar( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	if ( ! $job_id || '' === $token || ! isset( $_POST['_wpnonce'] ) || ! is_string( $_POST['_wpnonce'] )
		|| ! wp_verify_nonce( wp_unslash( $_POST['_wpnonce'] ), 'ct_scan_stop_' . $job_id . '_' . $token ) ) {
		ct_scan_send_confirmation_page( 'This stop form is invalid or expired. Open the stop link again.', 403 );
	}
	$result = ct_scan_customer_stop( $job_id, $token );
	if ( is_wp_error( $result ) ) {
		ct_scan_send_confirmation_page( $result->get_error_message(), 'queue_busy' === $result->get_error_code() ? 503 : 410 );
	}
	$messages = array(
		'stopped'          => 'Your screening is stopped. No new screening will start.',
		'already_stopped'  => 'This screening is already stopped.',
		'already_finished' => 'This screening has already finished. Nothing further will run.',
	);
	ct_scan_send_confirmation_page( $messages[ $result ] );
}
add_action( 'admin_post_nopriv_ct_scan_stop', 'ct_scan_stop_handler' );
add_action( 'admin_post_ct_scan_stop', 'ct_scan_stop_handler' );

function ct_scan_rest_response( $status, $payload ) {
	return new WP_REST_Response( $payload, (int) $status );
}

function ct_scan_rest_error( $status, $code ) {
	return ct_scan_rest_response( $status, array( 'error' => sanitize_key( $code ) ) );
}

/** Authenticate and consume a unique, short-lived worker nonce. */
function ct_scan_rest_authenticate( WP_REST_Request $request, $route ) {
	if ( ! ct_scan_enabled() || get_option( 'ct_scan_schema_version' ) !== CT_SCAN_SCHEMA_VERSION ) {
		return new WP_Error( 'ct_scan_disabled', 'Worker API is disabled.', array( 'status' => 503 ) );
	}
	$body = $request->get_body();
	if ( ! is_string( $body ) || strlen( $body ) > 65536 ) {
		return new WP_Error( 'ct_scan_body_too_large', 'Request body is too large.', array( 'status' => 413 ) );
	}
	$timestamp = $request->get_header( 'x-ct-timestamp' );
	$nonce     = $request->get_header( 'x-ct-nonce' );
	$signature = $request->get_header( 'x-ct-signature' );
	if ( ! is_string( $timestamp ) || ! preg_match( '/\A[0-9]{10}\z/', $timestamp )
		|| abs( time() - (int) $timestamp ) > 300
		|| ! is_string( $nonce ) || ! preg_match( '/\A[a-f0-9]{32}\z/i', $nonce )
		|| ! is_string( $signature ) || ! preg_match( '/\A[a-f0-9]{64}\z/i', $signature ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	$signing = $timestamp . "\n" . strtolower( $nonce ) . "\nPOST\n" . $route . "\n" . hash( 'sha256', $body );
	$expected = hash_hmac( 'sha256', $signing, ct_scan_config()['worker_hmac_secret'] );
	if ( ! hash_equals( $expected, strtolower( $signature ) ) ) {
		return new WP_Error( 'ct_scan_auth_invalid', 'Worker authentication failed.', array( 'status' => 401 ) );
	}
	global $wpdb;
	$table = ct_scan_nonces_table();
	$nonce_hash = hash( 'sha256', strtolower( $nonce ) );
	$inserted = $wpdb->query( $wpdb->prepare(
		"INSERT IGNORE INTO {$table} (nonce_hash, expires_at) VALUES (%s, %s)",
		$nonce_hash,
		gmdate( 'Y-m-d H:i:s', time() + 600 )
	) );
	if ( 1 !== $inserted ) {
		return new WP_Error( 'ct_scan_replay', 'Worker authentication failed.', array( 'status' => 409 ) );
	}
	return $body;
}

function ct_scan_decode_request_body( $body ) {
	$data = json_decode( $body, true );
	if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $data ) ) {
		return new WP_Error( 'ct_scan_json_invalid', 'Expected a JSON object.' );
	}
	return $data;
}

function ct_scan_expected_keys( $data, $keys ) {
	$actual = array_keys( $data );
	sort( $actual );
	sort( $keys );
	return $actual === $keys;
}

function ct_scan_is_list( $value ) {
	return is_array( $value ) && ( array() === $value || array_keys( $value ) === range( 0, count( $value ) - 1 ) );
}

function ct_scan_claim( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/claim' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array() ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$active = $wpdb->get_var( "SELECT job_id FROM {$table} WHERE status IN ('leased','running') LIMIT 1" );
		if ( $active ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$row = $wpdb->get_row( "SELECT * FROM {$table} WHERE status = 'queued' AND attempts = 0 ORDER BY created_at ASC, job_id ASC LIMIT 1" );
		if ( ! $row ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$lease       = bin2hex( random_bytes( 32 ) );
		$expiry      = strtotime( $row->authorization_expires_at . ' UTC' );
		$lease_until = min( time() + 300, $expiry );
		if ( $lease_until <= time() ) {
			return ct_scan_rest_response( 200, array( 'job' => null ) );
		}
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'leased', 'lease_hash' => hash( 'sha256', $lease ), 'lease_until' => gmdate( 'Y-m-d H:i:s', $lease_until ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'queued', 'attempts' => 0 ),
			array( '%s', '%s', '%s' ),
			array( '%d', '%s', '%d' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 503, 'claim_race' );
		}
		return ct_scan_rest_response( 200, array(
			'job' => array(
				'id'          => (int) $row->job_id,
				'target'      => $row->target_origin,
				'scope_hash'  => $row->scope_hash,
				'terms_hash'  => $row->terms_hash,
				'expires_at'  => (int) $expiry,
				'lease'       => $lease,
				'lease_until' => (int) $lease_until,
			),
		) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_callback_payload( $data ) {
	if ( ! isset( $data['id'], $data['lease'], $data['scope_hash'] ) || ! is_int( $data['id'] ) || $data['id'] < 1
		|| ! is_string( $data['lease'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['lease'] )
		|| ! is_string( $data['scope_hash'] ) || ! preg_match( '/\A[a-f0-9]{64}\z/', $data['scope_hash'] ) ) {
		return false;
	}
	return true;
}

function ct_scan_start( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/start' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash' ) ) || ! ct_scan_callback_payload( $data ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row || 'leased' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( strtotime( $row->lease_until . ' UTC' ) <= time() || 0 !== (int) $row->attempts ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		$now = ct_scan_utc_now();
		$authorization_expiry = strtotime( $row->authorization_expires_at . ' UTC' );
		$updated = $wpdb->update(
			$table,
			array( 'status' => 'running', 'attempts' => 1, 'started_at' => $now, 'lease_until' => gmdate( 'Y-m-d H:i:s', min( time() + 300, $authorization_expiry ) ) ),
			array( 'job_id' => (int) $row->job_id, 'status' => 'leased', 'attempts' => 0, 'lease_hash' => $row->lease_hash ),
			array( '%s', '%d', '%s', '%s' ),
			array( '%d', '%s', '%d', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'start_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, 'running' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

/**
 * Per-request admission decision. The sandboxed scanner holds no key: before every
 * connection to the target, the supervisor asks this guard through the signed
 * `admit` route. The caller MUST hold the queue lock, so this decision is
 * serialized with customer stop, operator revocation, expiry, lease changes and
 * every other admission. Returns array( http_status, payload ).
 *
 * `http` reserves one request from the frozen profile's budget and records the
 * admission time in the same compare-and-set update; the reservation is consumed
 * at once and is valid for ct_scan_profile_limits()['valid_ms']. `probe` only
 * reports whether the job is still live (no budget, no pacing).
 *
 * Nothing here is permissive on failure: an unknown profile, a clock that moved
 * backwards, a failed write, or an unconfirmed recipient is a refusal.
 */
function ct_scan_admit_locked( $data, $now_ms ) {
	global $wpdb;
	$table  = ct_scan_jobs_table();
	$refuse = static function ( $status, $reason, $extra = array() ) {
		return array( (int) $status, array_merge( array( 'ok' => false, 'reason' => sanitize_key( $reason ) ), $extra ) );
	};
	// No table-wide maintenance here: probes run every couple of seconds under the same
	// lock as Stop, so this path stays short. Expiry and lease are checked on the row.
	$row = ct_scan_row( $data['id'] );
	if ( ! $row ) {
		return $refuse( 410, 'job_not_found' );
	}
	if ( 'running' === $row->status && strtotime( $row->authorization_expires_at . ' UTC' ) <= time() ) {
		$wpdb->update( $table, array( 'status' => 'expired', 'error_code' => 'authorization_expired', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null, 'confirmation_token_hash' => null ), array( 'job_id' => (int) $row->job_id, 'status' => 'running' ), array( '%s', '%s', '%s', '%s', '%s', '%s' ), array( '%d', '%s' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'expired', 'authorization_expired' );
		return $refuse( 410, 'job_expired' );
	}
	if ( 'cancelled' === $row->status ) {
		return $refuse( 410, 'job_cancelled' );
	}
	if ( 'expired' === $row->status ) {
		return $refuse( 410, 'job_expired' );
	}
	if ( 'running' !== $row->status || 1 !== (int) $row->attempts ) {
		return $refuse( 410, 'job_not_running' );
	}
	if ( empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
		|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
		return $refuse( 410, 'lease_invalid_or_expired' );
	}
	if ( empty( $row->confirmed_at ) ) {
		return $refuse( 410, 'recipient_unconfirmed' );
	}
	if ( ! ct_scan_authorization_is_live( $row ) ) {
		$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
		ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
		return $refuse( 410, 'authorization_revoked_or_expired' );
	}
	$limits = ct_scan_profile_limits( $row->profile_id );
	if ( ! $limits ) {
		return $refuse( 410, 'profile_unknown' );
	}
	if ( 'probe' === $data['kind'] ) {
		return array( 200, array( 'ok' => true, 'live' => true ) );
	}
	$last = null === $row->last_admit_ms ? null : (int) $row->last_admit_ms;
	if ( null !== $last ) {
		if ( $now_ms + $limits['min_interval_ms'] < $last ) {
			// The clock moved backwards by more than the pacing interval: do not guess.
			return $refuse( 410, 'clock_anomaly' );
		}
		$wait = $last + $limits['min_interval_ms'] - $now_ms;
		if ( $wait > 0 ) {
			return $refuse( 429, 'rate_wait', array( 'retry_after_ms' => (int) min( $wait, $limits['min_interval_ms'] ) ) );
		}
	}
	$used = (int) $row->http_admitted;
	if ( $used >= $limits['http_requests'] ) {
		return $refuse( 409, 'budget_exhausted' );
	}
	$updated = $wpdb->update(
		$table,
		array( 'http_admitted' => $used + 1, 'last_admit_ms' => $now_ms ),
		array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash, 'http_admitted' => $used ),
		array( '%d', '%d' ),
		array( '%d', '%s', '%s', '%d' )
	);
	if ( 1 !== $updated ) {
		return $refuse( 503, 'admission_write_failed' );
	}
	return array( 200, array(
		'ok'             => true,
		'admitted'       => true,
		'sequence'       => $used + 1,
		'valid_ms'       => (int) $limits['valid_ms'],
		'timeout_ms'     => (int) $limits['timeout_ms'],
		'http_remaining' => (int) ( $limits['http_requests'] - $used - 1 ),
	) );
}

function ct_scan_admit( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/admit' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, array( 'id', 'lease', 'scope_hash', 'kind' ) ) || ! ct_scan_callback_payload( $data )
		|| ! is_string( $data['kind'] ) || ! in_array( $data['kind'], array( 'http', 'probe' ), true ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		// Fail closed: a refusal here ends the screening rather than risking an unserialized send.
		return ct_scan_rest_response( 503, array( 'ok' => false, 'reason' => 'queue_busy' ) );
	}
	try {
		$decision = ct_scan_admit_locked( $data, (int) floor( microtime( true ) * 1000 ) );
	} catch ( Throwable $error ) {
		$decision = array( 503, array( 'ok' => false, 'reason' => 'admission_error' ) );
	} finally {
		ct_scan_lock_release();
	}
	return ct_scan_rest_response( $decision[0], $decision[1] );
}

function ct_scan_clean_result_line( $value, $limit = 500 ) {
	return is_string( $value ) && strlen( $value ) <= $limit;
}

function ct_scan_result_url_matches_scope( $url, $target ) {
	if ( ! is_string( $url ) || '' === $url || strlen( $url ) > 4096 ) {
		return false;
	}
	$parts = wp_parse_url( $url );
	$base  = wp_parse_url( $target );
	if ( ! is_array( $parts ) || ! is_array( $base ) || empty( $parts['scheme'] ) || empty( $parts['host'] )
		|| isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
		return false;
	}
	$scheme = strtolower( $parts['scheme'] );
	$port   = isset( $parts['port'] ) ? (int) $parts['port'] : ( 'https' === $scheme ? 443 : 80 );
	$base_port = 'https' === $base['scheme'] ? 443 : 80;
	return in_array( $scheme, array( 'http', 'https' ), true )
		&& strtolower( $parts['host'] ) === $base['host']
		&& $port === ( 'https' === $scheme ? 443 : 80 )
		&& ( 'https' !== $base['scheme'] || 'https' === $scheme );
}

/** Validate the small, single-result checker payload before persisting it. */
function ct_scan_validate_result( $result, $row, $stored_snapshot = false ) {
	if ( ! is_array( $result ) || count( $result ) > 64 ) {
		return new WP_Error( 'result_invalid', 'result_invalid' );
	}
	$required = array(
		'input_url', 'final_url', 'status', 'fetch_status', 'http_status', 'wordpress_version', 'php_version', 'server', 'powered_by', 'title',
		'evidence', 'asset_version_hints', 'notes', 'checked_at', 'php_version_candidates', 'php_evidence', 'php2shell_status',
		'php2shell_version_status', 'php2shell_fixed_version', 'php2shell_exploitability', 'php2shell_cves', 'php2shell_rules_as_of',
		'php2shell_sources', 'php2shell_notes', 'php2shell_recommendation',
	);
	if ( ! ct_scan_expected_keys( $result, $required ) ) {
		return new WP_Error( 'result_schema_mismatch', 'result_schema_mismatch' );
	}
	$version_states = array( 'version_not_disclosed', 'conflicting_versions', 'unrecognized_or_partial_version', 'branch_requires_vendor_review', 'prerelease_unverified', 'vendor_build_unverified', 'below_upstream_fix', 'at_or_above_upstream_fix' );
	$config = ct_scan_config();
	if ( ! is_string( $result['input_url'] ) || $result['input_url'] !== $row->target_origin
		|| ! is_string( $result['final_url'] )
		|| ! in_array( $result['status'], array( 'wordpress', 'likely_wordpress', 'no_evidence', 'uncertain', 'blocked', 'error' ), true )
		|| ! in_array( $result['fetch_status'], array( 'ok', 'blocked', 'timeout', 'dns_error' ), true )
		|| ! in_array( $result['php2shell_status'], array( 'potentially_affected', 'fixed_version_reported', 'unknown' ), true )
		|| ! is_string( $result['php2shell_version_status'] ) || ! in_array( $result['php2shell_version_status'], $version_states, true )
		|| 'not_tested' !== $result['php2shell_exploitability']
		|| ! is_string( $result['php2shell_rules_as_of'] ) || ! preg_match( '/\A\d{4}-\d{2}-\d{2}\z/', $result['php2shell_rules_as_of'] )
		|| ! checkdate( (int) substr( $result['php2shell_rules_as_of'], 5, 2 ), (int) substr( $result['php2shell_rules_as_of'], 8, 2 ), (int) substr( $result['php2shell_rules_as_of'], 0, 4 ) )
		|| ( ! $stored_snapshot && $result['php2shell_rules_as_of'] !== $config['expected_rules_as_of'] )
		|| ! is_string( $result['checked_at'] ) || strlen( $result['checked_at'] ) > 64
		|| ! preg_match( '/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z/', $result['checked_at'] )
		|| ! is_string( $result['php_version'] ) || strlen( $result['php_version'] ) > 128
		|| ! is_string( $result['wordpress_version'] ) || strlen( $result['wordpress_version'] ) > 128
		|| ! is_string( $result['php2shell_fixed_version'] ) || strlen( $result['php2shell_fixed_version'] ) > 32 ) {
		return new WP_Error( 'result_semantics_invalid', 'result_semantics_invalid' );
	}
	if ( '' !== $result['final_url'] && ! ct_scan_result_url_matches_scope( $result['final_url'], $row->target_origin ) ) {
		return new WP_Error( 'result_scope_mismatch', 'result_scope_mismatch' );
	}
	if ( null !== $result['http_status'] && ( ! is_int( $result['http_status'] ) || $result['http_status'] < 100 || $result['http_status'] > 599 ) ) {
		return new WP_Error( 'result_http_status_invalid', 'result_http_status_invalid' );
	}
	foreach ( array( 'server', 'powered_by', 'title', 'php2shell_recommendation' ) as $key ) {
		if ( ! ct_scan_clean_result_line( $result[ $key ], 2048 ) ) {
			return new WP_Error( 'result_text_invalid', 'result_text_invalid' );
		}
	}
	foreach ( array( 'evidence', 'asset_version_hints', 'notes', 'php_version_candidates', 'php_evidence', 'php2shell_cves', 'php2shell_sources', 'php2shell_notes' ) as $key ) {
		if ( ! is_array( $result[ $key ] ) || ! ct_scan_is_list( $result[ $key ] ) || count( $result[ $key ] ) > 100 ) {
			return new WP_Error( 'result_list_invalid', 'result_list_invalid' );
		}
		foreach ( $result[ $key ] as $entry ) {
			$limit = in_array( $key, array( 'php_version_candidates' ), true ) ? 128 : 2048;
			if ( ! ct_scan_clean_result_line( $entry, $limit ) ) {
				return new WP_Error( 'result_list_item_invalid', 'result_list_item_invalid' );
			}
		}
	}
	if ( array_values( $result['php2shell_cves'] ) !== array( 'CVE-2026-109618', 'CVE-2026-109619' ) ) {
		return new WP_Error( 'result_cves_invalid', 'result_cves_invalid' );
	}
	$encoded = wp_json_encode( $result );
	if ( ! is_string( $encoded ) || strlen( $encoded ) > 32768 ) {
		return new WP_Error( 'result_too_large', 'result_too_large' );
	}
	return $encoded;
}

function ct_scan_canonicalize( $value ) {
	if ( ! is_array( $value ) ) {
		return $value;
	}
	if ( ct_scan_is_list( $value ) ) {
		return array_map( 'ct_scan_canonicalize', $value );
	}
	ksort( $value, SORT_STRING );
	foreach ( $value as $key => $item ) {
		$value[ $key ] = ct_scan_canonicalize( $item );
	}
	return $value;
}

function ct_scan_result( WP_REST_Request $request ) {
	$body = ct_scan_rest_authenticate( $request, '/ct-scan/v1/result' );
	if ( is_wp_error( $body ) ) {
		return ct_scan_rest_error( (int) $body->get_error_data()['status'], $body->get_error_code() );
	}
	$data = ct_scan_decode_request_body( $body );
	$keys = array( 'id', 'lease', 'scope_hash', 'outcome', 'result', 'error', 'checker_revision' );
	if ( is_wp_error( $data ) || ! ct_scan_expected_keys( $data, $keys ) || ! ct_scan_callback_payload( $data )
		|| ! in_array( $data['outcome'], array( 'completed', 'failed' ), true ) || ! is_string( $data['checker_revision'] )
		|| ! preg_match( '/\A[a-f0-9]{40}\z/', $data['checker_revision'] ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$config = ct_scan_config();
	if ( ! hash_equals( strtolower( $config['expected_checker_revision'] ), strtolower( $data['checker_revision'] ) ) ) {
		return ct_scan_rest_error( 422, 'checker_revision_mismatch' );
	}
	$encoded_result = null;
	if ( 'completed' === $data['outcome'] ) {
		if ( ! is_array( $data['result'] ) || '' !== $data['error'] ) {
			return ct_scan_rest_error( 400, 'result_invalid' );
		}
	} else {
		if ( null !== $data['result'] || ! is_string( $data['error'] ) || ! preg_match( '/\A[a-z][a-z0-9_]{0,63}\z/', $data['error'] ) ) {
			return ct_scan_rest_error( 400, 'failure_receipt_invalid' );
		}
	}
	$canonical = wp_json_encode( ct_scan_canonicalize( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	if ( ! is_string( $canonical ) ) {
		return ct_scan_rest_error( 400, 'request_invalid' );
	}
	$receipt_hash = hash( 'sha256', $canonical );
	if ( ! ct_scan_lock_acquire() ) {
		return ct_scan_rest_error( 503, 'queue_busy' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		ct_scan_maintenance_locked();
		$row = ct_scan_row( $data['id'] );
		if ( ! $row ) {
			return ct_scan_rest_error( 410, 'job_not_found' );
		}
		if ( in_array( $row->status, array( 'completed', 'failed' ), true ) && ! empty( $row->receipt_hash ) ) {
			return hash_equals( $row->receipt_hash, $receipt_hash )
				? ct_scan_rest_response( 200, array( 'ok' => true ) )
				: ct_scan_rest_error( 409, 'receipt_conflict' );
		}
		if ( in_array( $row->status, array( 'cancelled', 'expired', 'failed_unknown' ), true ) ) {
			return ct_scan_rest_error( 410, 'job_permanently_rejected' );
		}
		if ( 'running' !== $row->status || empty( $row->lease_hash ) || ! hash_equals( $row->lease_hash, hash( 'sha256', $data['lease'] ) )
			|| ! hash_equals( $row->scope_hash, $data['scope_hash'] ) || strtotime( $row->lease_until . ' UTC' ) <= time() ) {
			return ct_scan_rest_error( 410, 'lease_invalid_or_expired' );
		}
		if ( ! ct_scan_authorization_is_live( $row ) ) {
			$wpdb->update( $table, array( 'status' => 'cancelled', 'error_code' => 'authorization_changed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $row->job_id ), array( '%s', '%s', '%s', '%s', '%s' ), array( '%d' ) );
			ct_scan_mark_request_status( (int) $row->request_id, 'cancelled', 'authorization_changed' );
			return ct_scan_rest_error( 410, 'authorization_revoked_or_expired' );
		}
		if ( 'completed' === $data['outcome'] ) {
			$encoded_result = ct_scan_validate_result( $data['result'], $row );
			if ( is_wp_error( $encoded_result ) ) {
				return ct_scan_rest_error( 422, $encoded_result->get_error_code() );
			}
		}
		$state = 'completed' === $data['outcome'] ? 'completed' : 'failed';
		$updated = $wpdb->update(
			$table,
			array(
				'status'           => $state,
				'outcome'          => $data['outcome'],
				'error_code'       => 'failed' === $data['outcome'] ? $data['error'] : null,
				'checker_revision' => strtolower( $data['checker_revision'] ),
				'result_json'      => $encoded_result,
				'receipt_hash'     => $receipt_hash,
				'finished_at'      => ct_scan_utc_now(),
				'lease_hash'       => null,
				'lease_until'      => null,
			),
			array( 'job_id' => (int) $row->job_id, 'status' => 'running', 'lease_hash' => $row->lease_hash ),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ),
			array( '%d', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return ct_scan_rest_error( 409, 'result_rejected' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, $state, 'failed' === $state ? $data['error'] : '' );
		return ct_scan_rest_response( 200, array( 'ok' => true ) );
	} finally {
		ct_scan_lock_release();
	}
}

function ct_scan_register_rest_routes() {
	register_rest_route( 'ct-scan/v1', '/claim', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_claim',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/start', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_start',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/admit', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_admit',
		'permission_callback' => '__return_true',
	) );
	register_rest_route( 'ct-scan/v1', '/result', array(
		'methods'             => WP_REST_Server::CREATABLE,
		'callback'            => 'ct_scan_result',
		'permission_callback' => '__return_true',
	) );
}
add_action( 'rest_api_init', 'ct_scan_register_rest_routes' );

function ct_scan_terminal_status( $status ) {
	return in_array( $status, array( 'completed', 'failed', 'failed_unknown', 'cancelled', 'expired' ), true );
}

function ct_scan_email_safe_text( $value, $max = 2000 ) {
	if ( ! is_string( $value ) ) {
		return '';
	}
	$value = wp_strip_all_tags( $value );
	$value = preg_replace( '/https?:\/\/[^\s<>"\']+/i', '[URL omitted]', $value );
	$value = preg_replace( '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+/', ' ', $value );
	$value = preg_replace( '/[ \t]+/', ' ', $value );
	$value = preg_replace( '/\n{3,}/', "\n\n", $value );
	return substr( trim( $value ), 0, $max );
}

function ct_scan_build_report_body( $row ) {
	if ( ! is_object( $row ) || ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status || '' === trim( (string) $row->manual_remainder_notes ) ) {
		return new WP_Error( 'report_not_ready', 'The scan and manual remainder are not ready for a reviewed report.' );
	}
	$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
	if ( ! is_string( $host ) || '' === $host ) {
		return new WP_Error( 'report_target_invalid', 'The saved target could not be verified.' );
	}
	$lines = array(
		'PHP2Shell passive screening and manual review',
		'Authorized target host: ' . $host,
		'Terms version: ' . $row->terms_version,
		'Terms accepted (UTC): ' . $row->terms_accepted_at,
		'',
		'PHP2Shell passive screening',
	);
	if ( 'completed' === $row->status ) {
		if ( ! is_string( $row->result_json ) || '' === $row->result_json ) {
			return new WP_Error( 'report_result_missing', 'The stored PHP2Shell result is unavailable.' );
		}
		$result = json_decode( $row->result_json, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$validated = ct_scan_validate_result( $result, $row, true );
		if ( is_wp_error( $validated ) ) {
			return new WP_Error( 'report_result_invalid', 'The stored PHP2Shell result could not be verified.' );
		}
		$labels = array(
			'potentially_affected'   => 'Potentially affected: an advertised PHP version is below an upstream fix threshold; an administrator should verify the actual package and vendor backports.',
			'fixed_version_reported' => 'Fixed version reported: the public advertisement meets an upstream threshold; this does not verify the running package or prove safety.',
			'unknown'               => 'Unknown: public evidence did not support a reliable version classification.',
		);
		$lines[] = 'Screen status: ' . $labels[ $result['php2shell_status'] ];
		$lines[] = 'WordPress detection: ' . $result['status'];
		$lines[] = 'Fetch status: ' . $result['fetch_status'];
		$lines[] = 'HTTP status: ' . ( null === $result['http_status'] ? 'unavailable' : (string) $result['http_status'] );
		$lines[] = 'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : ct_scan_email_safe_text( $result['php_version'], 128 ) );
		$lines[] = 'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available for this advertised version' : $result['php2shell_fixed_version'] );
		$lines[] = 'PHP2Shell rules date: ' . $result['php2shell_rules_as_of'];
		$lines[] = 'Exploitability: not tested; no exploit payloads were sent.';
		$lines[] = 'Limit: this passive screen reads public robots policy, page content, and headers. It cannot verify the deployed runtime, vendor backports, or patch state.';
		$evidence = array_slice( $result['php_evidence'], 0, 10 );
		if ( $evidence ) {
			$lines[] = 'Observed PHP-related header evidence:';
			foreach ( $evidence as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 500 );
			}
		}
		$notes = array_slice( $result['php2shell_notes'], 0, 10 );
		if ( $notes ) {
			$lines[] = 'Interpretation notes:';
			foreach ( $notes as $item ) {
				$lines[] = '- ' . ct_scan_email_safe_text( $item, 1000 );
			}
		}
	} else {
		$lines[] = 'No PHP2Shell classification was produced.';
		$lines[] = 'Execution state: ' . $row->status . ( $row->error_code ? ' (' . sanitize_key( $row->error_code ) . ')' : '' );
		$lines[] = 'No rescan was started while preparing this report.';
	}
	$lines[] = '';
	$lines[] = 'Other checks in the accepted service terms (manual remainder)';
	$lines[] = ct_scan_email_safe_text( $row->manual_remainder_notes, 12000 );
	$lines[] = '';
	$lines[] = 'This report is limited to the evidence above. It does not establish confirmed exploitation or a verified clean bill of health.';
	return implode( "\n", $lines ) . "\n";
}

function ct_scan_admin_revoke( $job_id ) {
	if ( ! ct_scan_lock_acquire( 3 ) ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->report_delivered_at ) ) {
			return new WP_Error( 'job_unavailable', 'This job cannot be revoked.' );
		}
		$now = ct_scan_utc_now();
		$update = array( 'revoked_at' => $now, 'confirmation_token_hash' => null, 'lease_hash' => null, 'lease_until' => null );
		if ( ! ct_scan_terminal_status( $row->status ) ) {
			$update['status'] = 'cancelled';
			$update['error_code'] = 'operator_revoked';
			$update['finished_at'] = $now;
		}
		$updated = $wpdb->update( $table, $update, array( 'job_id' => (int) $row->job_id, 'status' => $row->status, 'report_delivered_at' => null ), null, array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'revoke_write_failed', 'The authorization state could not be durably updated. No success was recorded.' );
		}
		ct_scan_mark_request_status( (int) $row->request_id, ct_scan_terminal_status( $row->status ) ? $row->status : 'cancelled', 'operator_revoked' );
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_save_manual_remainder( $job_id, $notes ) {
	if ( ! is_string( $notes ) ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter the completed manual review notes.' );
	}
	$notes = trim( sanitize_textarea_field( wp_unslash( $notes ) ) );
	if ( '' === $notes || strlen( $notes ) > 12000 ) {
		return new WP_Error( 'manual_notes_invalid', 'Enter manual review notes of 1 to 12,000 characters.' );
	}
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! ct_scan_terminal_status( $row->status ) || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'manual_review_not_ready', 'Manual completion is available only after the scan is terminal and before revocation or delivery.' );
		}
		$updated = $wpdb->update( $table, array( 'manual_remainder_status' => 'complete', 'manual_remainder_notes' => $notes, 'manual_remainder_completed_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null, 'revoked_at' => null ), array( '%s', '%s', '%s' ), array( '%d', '%s', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'manual_review_write_failed', 'The manual review could not be durably saved.' );
		}
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_send_report( $job_id ) {
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! empty( $row->revoked_at ) || ! empty( $row->report_delivered_at )
			|| ! in_array( $row->report_notification_status, array( 'not_sent', 'failed' ), true ) ) {
			return new WP_Error( 'report_send_unavailable', 'This report cannot be sent in its current state.' );
		}
		if ( ! ct_scan_terminal_status( $row->status ) || 'complete' !== $row->manual_remainder_status
			|| '' === trim( (string) $row->manual_remainder_notes ) ) {
			return new WP_Error( 'report_not_ready', 'Complete and review the manual remainder before sending.' );
		}
		// Detailed findings go only to a recipient who confirmed the request, whatever the terminal state.
		if ( empty( $row->confirmed_at ) ) {
			return new WP_Error( 'report_recipient_unconfirmed', 'The recipient never confirmed this request. Detailed findings cannot be sent.' );
		}
		if ( ! is_email( $row->contact_email )
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_scan_email' ) !== $row->contact_email
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_version' ) !== $row->terms_version
			|| ct_scan_meta_string( (int) $row->request_id, '_ct_terms_sha256' ) !== $row->terms_hash ) {
			return new WP_Error( 'report_contact_changed', 'The original authorized report contact could not be verified.' );
		}
		$body = ct_scan_build_report_body( $row );
		if ( is_wp_error( $body ) ) {
			return $body;
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update(
			$table,
			array( 'report_notification_status' => 'unknown', 'report_notification_at' => $now ),
			array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null, 'revoked_at' => null ),
			array( '%s', '%s' ),
			array( '%d', '%s', '%s', '%s' )
		);
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_state_write_failed', 'The one-time send state could not be durably recorded. No email was sent.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', 'unknown' );
		$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
		$status = 'unknown';
		try {
			if ( wp_mail( $row->contact_email, 'Reviewed website screening report for ' . $host, $body ) ) {
				$status = 'accepted';
			}
		} catch ( Throwable $error ) {
			$status = 'unknown';
		}
		$updated = $wpdb->update( $table, array( 'report_notification_status' => $status, 'report_notification_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => 'unknown', 'report_delivered_at' => null ), array( '%s', '%s' ), array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_state_write_failed', 'The email outcome could not be durably recorded. Its status remains unknown; do not resend.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_notification_status', $status );
	}
	finally {
		ct_scan_lock_release();
	}
	return 'accepted' === $status ? true : new WP_Error( 'report_transport_unknown', 'The mail transport did not confirm acceptance. Check delivery logs before attempting another send.' );
}

function ct_scan_admin_record_delivery( $job_id ) {
	if ( ! ct_scan_lock_acquire() ) {
		return new WP_Error( 'queue_busy', 'The queue is temporarily busy.' );
	}
	global $wpdb;
	$table = ct_scan_jobs_table();
	try {
		$row = ct_scan_row( $job_id );
		if ( ! $row || ! in_array( $row->report_notification_status, array( 'accepted', 'unknown' ), true ) || ! empty( $row->report_delivered_at ) ) {
			return new WP_Error( 'report_delivery_unverified', 'Record delivery only after independently confirming that the full report reached the saved contact.' );
		}
		$now = ct_scan_utc_now();
		$updated = $wpdb->update( $table, array( 'report_delivered_at' => $now ), array( 'job_id' => (int) $row->job_id, 'report_notification_status' => $row->report_notification_status, 'report_delivered_at' => null ), array( '%s' ), array( '%d', '%s', '%s' ) );
		if ( 1 !== $updated ) {
			return new WP_Error( 'report_delivery_write_failed', 'The delivery confirmation could not be durably saved.' );
		}
		$cancelled = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET status = 'cancelled', error_code = 'report_delivered', finished_at = %s, lease_hash = NULL, lease_until = NULL, confirmation_token_hash = NULL WHERE job_id = %d AND status IN ('awaiting_confirmation','queued','leased','running')", $now, (int) $row->job_id ) );
		if ( false === $cancelled ) {
			return new WP_Error( 'report_delivery_write_failed', 'Delivery was saved, but follow-up scan cancellation could not be confirmed.' );
		}
		update_post_meta( (int) $row->request_id, '_ct_scan_report_delivered_at', $now );
		ct_scan_mark_request_status( (int) $row->request_id, ct_scan_terminal_status( $row->status ) ? $row->status : 'cancelled', 'report_delivered' );
	}
	finally {
		ct_scan_lock_release();
	}
	return true;
}

function ct_scan_admin_action_handler() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to manage scan requests.', 'ct-scan' ), '', array( 'response' => 403 ) );
	}
	$job_id = isset( $_POST['job_id'] ) ? absint( wp_unslash( $_POST['job_id'] ) ) : 0;
	$action = isset( $_POST['ct_scan_operation'] ) && is_string( $_POST['ct_scan_operation'] ) ? sanitize_key( wp_unslash( $_POST['ct_scan_operation'] ) ) : '';
	if ( ! $job_id || ! in_array( $action, array( 'revoke', 'manual_complete', 'send_report', 'record_delivery' ), true ) ) {
		wp_die( esc_html__( 'The requested action is invalid.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	check_admin_referer( 'ct_scan_admin_' . $action . '_' . $job_id );
	$confirmations = array(
		'revoke'          => 'ct_scan_revoke_confirm',
		'manual_complete' => 'ct_scan_review_confirm',
		'send_report'     => 'ct_scan_send_confirm',
		'record_delivery' => 'ct_scan_delivery_confirm',
	);
	$confirm_key = $confirmations[ $action ];
	if ( ! isset( $_POST[ $confirm_key ] ) || ! is_string( $_POST[ $confirm_key ] ) || '1' !== wp_unslash( $_POST[ $confirm_key ] ) ) {
		wp_die( esc_html__( 'Confirm this action before continuing.', 'ct-scan' ), '', array( 'response' => 400 ) );
	}
	if ( 'revoke' === $action ) {
		$result = ct_scan_admin_revoke( $job_id );
	} elseif ( 'manual_complete' === $action ) {
		$result = ct_scan_admin_save_manual_remainder( $job_id, isset( $_POST['manual_remainder_notes'] ) && is_string( $_POST['manual_remainder_notes'] ) ? $_POST['manual_remainder_notes'] : '' );
	} elseif ( 'send_report' === $action ) {
		$result = ct_scan_admin_send_report( $job_id );
	} else {
		$result = ct_scan_admin_record_delivery( $job_id );
	}
	$notice = is_wp_error( $result ) ? $result->get_error_code() : 'updated';
	$url = add_query_arg( array( 'page' => 'ct-scan-queue', 'ct_scan_notice' => sanitize_key( $notice ) ), admin_url( 'edit.php?post_type=ct_promo_request' ) );
	wp_safe_redirect( $url );
	exit;
}
add_action( 'admin_post_ct_scan_admin_action', 'ct_scan_admin_action_handler' );

function ct_scan_admin_form( $job_id, $operation, $label, $extra = '' ) {
	$nonce = wp_nonce_field( 'ct_scan_admin_' . $operation . '_' . $job_id, '_wpnonce', true, false );
	return '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline-block;margin:4px 8px 4px 0"><input type="hidden" name="action" value="ct_scan_admin_action"><input type="hidden" name="job_id" value="' . esc_attr( (string) $job_id ) . '"><input type="hidden" name="ct_scan_operation" value="' . esc_attr( $operation ) . '">' . $nonce . $extra . '<button class="button" type="submit">' . esc_html( $label ) . '</button></form>';
}

function ct_scan_admin_result_details( $row ) {
	if ( ! is_object( $row ) || 'completed' !== $row->status || ! is_string( $row->result_json ) || '' === $row->result_json ) {
		return '';
	}
	$result = json_decode( $row->result_json, true );
	if ( JSON_ERROR_NONE !== json_last_error() || is_wp_error( ct_scan_validate_result( $result, $row, true ) ) ) {
		return '<p>Stored result failed its integrity and schema check.</p>';
	}
	$lines = array(
		'PHP2Shell status: ' . $result['php2shell_status'],
		'Advertised PHP version: ' . ( '' === $result['php_version'] ? 'not disclosed' : $result['php_version'] ),
		'Upstream fix threshold: ' . ( '' === $result['php2shell_fixed_version'] ? 'not available' : $result['php2shell_fixed_version'] ),
		'Rules date: ' . $result['php2shell_rules_as_of'],
		'Exploitability: not tested; no exploit payloads were sent.',
	);
	$html = '<details><summary>Private stored PHP2Shell evidence and summary</summary><pre>' . esc_html( implode( "\n", $lines ) ) . '</pre>';
	foreach ( array( 'php_evidence' => 'Observed PHP evidence', 'php2shell_notes' => 'Assessment notes', 'php2shell_sources' => 'Assessment sources' ) as $key => $label ) {
		if ( empty( $result[ $key ] ) ) {
			continue;
		}
		$html .= '<p><strong>' . esc_html( $label ) . '</strong></p><ul>';
		foreach ( array_slice( $result[ $key ], 0, 20 ) as $entry ) {
			$html .= '<li><code>' . esc_html( $entry ) . '</code></li>';
		}
		$html .= '</ul>';
	}
	if ( '' !== $result['php2shell_recommendation'] ) {
		$html .= '<p><strong>Recommendation:</strong> ' . esc_html( $result['php2shell_recommendation'] ) . '</p>';
	}
	return $html . '</details>';
}

function ct_scan_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	ct_scan_maintain();
	global $wpdb;
	$table = ct_scan_jobs_table();
	$rows  = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC, job_id DESC LIMIT 100" );
	$config = ct_scan_config();
	echo '<div class="wrap"><h1>PHP2Shell screening queue</h1>';
	echo '<p>Worker API: <strong>' . ( ct_scan_enabled() ? 'enabled' : 'disabled' ) . '</strong>. This page never displays the worker secret. The screening covers public passive evidence only; broader checks remain manual.</p>';
	if ( isset( $_GET['ct_scan_notice'] ) && is_string( $_GET['ct_scan_notice'] ) ) {
		echo '<div class="notice notice-info"><p>' . esc_html( sanitize_key( wp_unslash( $_GET['ct_scan_notice'] ) ) ) . '</p></div>';
	}
	if ( empty( $rows ) ) {
		echo '<p>No screening jobs are stored.</p></div>';
		return;
	}
	echo '<table class="widefat striped"><thead><tr><th>Job / request</th><th>Authorized scope and terms</th><th>Execution</th><th>Confirmation / report</th><th>Manual remainder and actions</th></tr></thead><tbody>';
	foreach ( $rows as $row ) {
		$request_url = admin_url( 'post.php?post=' . (int) $row->request_id . '&action=edit' );
		$host = wp_parse_url( $row->target_origin, PHP_URL_HOST );
		$exec = 'Status: ' . $row->status . "\nAttempts: " . (int) $row->attempts . "\nOutcome: " . ( $row->outcome ? $row->outcome : 'pending' ) . "\nError: " . ( $row->error_code ? sanitize_key( $row->error_code ) : '—' ) . "\nChecker revision: " . ( $row->checker_revision ? substr( $row->checker_revision, 0, 12 ) . '…' : '—' );
		$mail = 'Confirmation email: ' . sanitize_key( $row->confirmation_email_status ) . "\nReport transport: " . sanitize_key( $row->report_notification_status ) . "\nDelivery confirmed: " . ( $row->report_delivered_at ? $row->report_delivered_at . ' UTC' : 'no' ) . "\nRevoked: " . ( $row->revoked_at ? $row->revoked_at . ' UTC' : 'no' );
		echo '<tr><td><a href="' . esc_url( $request_url ) . '">Job #' . (int) $row->job_id . ' / request #' . (int) $row->request_id . '</a><br>Created ' . esc_html( $row->created_at ) . ' UTC</td>';
		echo '<td><code>' . esc_html( $row->target_origin ) . '</code><br>Terms ' . esc_html( $row->terms_version ) . '<br>Accepted ' . esc_html( $row->terms_accepted_at ) . ' UTC<br>Expires ' . esc_html( $row->authorization_expires_at ) . ' UTC<br>Scope hash <code>' . esc_html( substr( $row->scope_hash, 0, 16 ) ) . '…</code></td>';
		echo '<td><pre>' . esc_html( $exec ) . '</pre>' . ct_scan_admin_result_details( $row ) . '</td><td><pre>' . esc_html( $mail ) . '</pre></td><td>';
		if ( ! empty( $row->manual_remainder_notes ) ) {
			echo '<details><summary>Manual remainder (' . esc_html( sanitize_key( $row->manual_remainder_status ) ) . ')</summary><pre>' . esc_html( $row->manual_remainder_notes ) . '</pre></details>';
		}
		if ( ct_scan_terminal_status( $row->status ) && empty( $row->revoked_at ) && empty( $row->report_delivered_at ) ) {
			$notes = esc_textarea( (string) $row->manual_remainder_notes );
			$extra = '<br><textarea name="manual_remainder_notes" rows="4" cols="42" maxlength="12000" placeholder="Record the remaining checks covered by the accepted service terms, including limitations or why any check was not completed.">' . $notes . '</textarea><br><label><input type="checkbox" name="ct_scan_review_confirm" value="1" required> I reviewed these manual findings and limitations.</label> ';
			echo ct_scan_admin_form( (int) $row->job_id, 'manual_complete', 'Save manual remainder', $extra );
			$preview = ct_scan_build_report_body( $row );
			if ( ! is_wp_error( $preview ) ) {
				echo '<details><summary>Reviewed customer report preview</summary><pre>' . esc_html( $preview ) . '</pre></details>';
				if ( 'not_sent' === $row->report_notification_status || 'failed' === $row->report_notification_status ) {
					echo ct_scan_admin_form( (int) $row->job_id, 'send_report', 'Send reviewed report to stored contact', '<label><input type="checkbox" name="ct_scan_send_confirm" value="1" required> Send this report to the saved authorized email contact.</label> ' );
				}
			}
			if ( in_array( $row->report_notification_status, array( 'accepted', 'unknown' ), true ) && empty( $row->report_delivered_at ) ) {
				echo ct_scan_admin_form( (int) $row->job_id, 'record_delivery', 'Record confirmed delivery', '<label><input type="checkbox" name="ct_scan_delivery_confirm" value="1" required> I independently confirmed the full report reached the saved contact.</label> ' );
			}
		}
		if ( empty( $row->revoked_at ) && empty( $row->report_delivered_at ) ) {
			echo ct_scan_admin_form( (int) $row->job_id, 'revoke', 'Revoke authorization', '<label><input type="checkbox" name="ct_scan_revoke_confirm" value="1" required> Revoke this request and block further execution or report sending.</label> ' );
		}
		echo '</td></tr>';
	}
	echo '</tbody></table></div>';
}

function ct_scan_register_admin_menu() {
	add_submenu_page( 'edit.php?post_type=ct_promo_request', 'PHP2Shell screening queue', 'PHP2Shell queue', 'manage_options', 'ct-scan-queue', 'ct_scan_admin_page' );
}
add_action( 'admin_menu', 'ct_scan_register_admin_menu', 30 );

function ct_scan_add_request_meta_box() {
	add_meta_box( 'ct-scan-request-status', 'PHP2Shell screening', 'ct_scan_request_meta_box', 'ct_promo_request', 'side', 'high' );
}
add_action( 'add_meta_boxes_ct_promo_request', 'ct_scan_add_request_meta_box' );

function ct_scan_request_meta_box( $post ) {
	$job_id = absint( get_post_meta( $post->ID, '_ct_scan_job_id', true ) );
	$row = $job_id ? ct_scan_row( $job_id ) : null;
	if ( ! $row ) {
		echo '<p>No scan job is linked to this request.</p>';
		return;
	}
	echo '<p>Status: <strong>' . esc_html( $row->status ) . '</strong></p><p>Target: <code>' . esc_html( $row->target_origin ) . '</code></p><p>Terms: ' . esc_html( $row->terms_version ) . ' / <code>' . esc_html( substr( $row->terms_hash, 0, 16 ) ) . '…</code></p><p>Confirmation email: ' . esc_html( $row->confirmation_email_status ) . '</p><p>Attempts: ' . (int) $row->attempts . ' · report transport: ' . esc_html( $row->report_notification_status ) . '</p><p><a href="' . esc_url( admin_url( 'edit.php?post_type=ct_promo_request&page=ct-scan-queue' ) ) . '">Open private queue</a></p>';
}
