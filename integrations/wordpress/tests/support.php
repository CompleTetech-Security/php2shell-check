<?php
/**
 * Shared bootstrap and helpers for the disposable WordPress + MariaDB checks.
 * Run only with the repository's `fixture-only` Docker Compose environment.
 */
if ( PHP_SAPI !== 'cli' || getenv( 'WORDPRESS_DB_PASSWORD' ) !== 'fixture-only' || getenv( 'WORDPRESS_DB_HOST' ) !== 'db' ) {
	throw new RuntimeException( 'Refusing to run outside the disposable WordPress fixture.' );
}

$private_config = tempnam( '/tmp', 'ct-scan-integration-' );
file_put_contents( $private_config, '<?php return ' . var_export( array(
	'enabled'                   => '0' !== getenv( 'CT_TEST_ENABLED' ),
	'egress_enforced'           => '0' !== getenv( 'CT_TEST_EGRESS' ),
	'supported_terms_version'   => '2026-10-21-r2',
	'expected_checker_revision' => str_repeat( 'a', 40 ),
	'expected_rules_as_of'      => '2026-10-21',
	'worker_hmac_secret'        => str_repeat( 'fixture-key-', 4 ),
	'authorization_end_at'      => gmdate( 'Y-m-d\TH:i:s\Z', time() + 30 * 86400 ),
	'confirmation_ttl_hours'    => 24,
	'global_daily_limit'        => 1000,
	'target_daily_limit'        => 100,
), true ) . ';' );
define( 'CT_SCAN_PRIVATE_CONFIG', $private_config );
register_shutdown_function( static function () use ( $private_config ) { @unlink( $private_config ); } );

$_SERVER['HTTP_HOST'] = 'wordpress';
require ( getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html' ) . '/wp-load.php';
ct_scan_maybe_install_schema();

function ct_test_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function ct_test_request( $host, $email = 'fixture@example.com' ) {
	$target = 'https://' . $host . '/';
	$contract = "Client contact: Fixture Reviewer\nClient email: {$email}\nWebsite (scan scope): {$target}\nReferred by: direct\nTerms version: 2026-10-21-r2\nAccepted test fixture terms.";
	$id = wp_insert_post( array(
		'post_type'    => 'ct_promo_request',
		'post_status'  => 'private',
		'post_title'   => 'Integration fixture request',
		'post_content' => "TERMS AS ACCEPTED\n\n" . $contract,
	), true );
	if ( is_wp_error( $id ) ) {
		throw new RuntimeException( $id->get_error_message() );
	}
	$meta = array(
		'_ct_scan_target'            => $target,
		'_ct_scan_email'             => $email,
		'_ct_scan_name'              => 'Fixture Reviewer',
		'_ct_ref'                    => 'direct',
		'_ct_terms_saved'            => '1',
		'_ct_terms_version'          => '2026-10-21-r2',
		'_ct_terms_url'              => 'https://complete.tech/php2shell-scan-terms/',
		'_ct_terms_sha256'           => hash( 'sha256', 'Accepted test fixture terms.' ),
		'_ct_terms_accepted_at'      => gmdate( 'Y-m-d\TH:i:s\Z', time() - 30 ),
		'_ct_terms_contract'         => $contract,
	);
	foreach ( $meta as $key => $value ) {
		update_post_meta( $id, $key, $value );
	}
	return array( (int) $id, array( 'target' => $target, 'email' => $email, 'name' => 'Fixture Reviewer', 'referrer' => 'direct' ) );
}

function ct_test_rest_call( $callback, $route, $payload, $nonce = null, $timestamp = null ) {
	$body = wp_json_encode( $payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	$timestamp = null === $timestamp ? (string) time() : (string) $timestamp;
	$nonce = null === $nonce ? bin2hex( random_bytes( 16 ) ) : $nonce;
	$signing = $timestamp . "\n" . strtolower( $nonce ) . "\nPOST\n" . $route . "\n" . hash( 'sha256', $body );
	$request = new WP_REST_Request( 'POST', $route );
	$request->set_body( $body );
	$request->set_header( 'X-CT-Timestamp', $timestamp );
	$request->set_header( 'X-CT-Nonce', $nonce );
	$request->set_header( 'X-CT-Signature', hash_hmac( 'sha256', $signing, ct_scan_config()['worker_hmac_secret'] ) );
	return call_user_func( $callback, $request );
}

function ct_test_result( $target ) {
	return array(
		'input_url' => $target, 'final_url' => $target, 'status' => 'wordpress', 'fetch_status' => 'ok', 'http_status' => 200,
		'wordpress_version' => '6.8', 'php_version' => '8.2.1', 'server' => 'fixture', 'powered_by' => 'PHP/8.2.1', 'title' => 'Fixture',
		'evidence' => array( 'generator present' ), 'asset_version_hints' => array(), 'notes' => array(), 'checked_at' => gmdate( 'Y-m-d\TH:i:s\Z' ),
		'php_version_candidates' => array( '8.2.1' ), 'php_evidence' => array( 'X-Powered-By: PHP/8.2.1 <script>alert(1)</script>' ),
		'php2shell_status' => 'potentially_affected', 'php2shell_version_status' => 'below_upstream_fix', 'php2shell_fixed_version' => '8.2.31',
		'php2shell_exploitability' => 'not_tested', 'php2shell_cves' => array( 'CVE-2026-109618', 'CVE-2026-109619' ),
		'php2shell_rules_as_of' => '2026-10-21', 'php2shell_sources' => array( 'https://www.php.net/' ), 'php2shell_notes' => array( 'Public evidence only.' ),
		'php2shell_recommendation' => 'Verify the deployed package and vendor backports.',
	);
}

function ct_test_queue_job( $job_id ) {
	global $wpdb;
	$wpdb->update( ct_scan_jobs_table(), array( 'status' => 'queued', 'confirmation_token_hash' => null, 'confirmation_expires_at' => null, 'confirmed_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $job_id ) );
}


/** Create a fixture request, confirm it, claim and start it. Returns the running job and its worker lease. */
function ct_test_running_job( $host ) {
	global $wpdb;
	list( $request_id, $fields ) = ct_test_request( $host );
	$event = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_array( $event ) && empty( $event['duplicate'] ), 'Fixture job was not created.' );
	ct_test_queue_job( $event['job_id'] );
	$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
	$job   = $claim->get_data()['job'];
	ct_test_assert( is_array( $job ) && (int) $job['id'] === (int) $event['job_id'], 'Fixture expected to claim its own job.' );
	$start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $job['id'], 'lease' => $job['lease'], 'scope_hash' => $job['scope_hash'] ) );
	ct_test_assert( 200 === $start->get_status(), 'Fixture job did not start.' );
	return array( 'request_id' => $request_id, 'fields' => $fields, 'job_id' => (int) $event['job_id'], 'job' => $job );
}

function ct_test_admit( $running, $kind = 'http', $override = array() ) {
	$payload = array_merge( array( 'id' => $running['job']['id'], 'lease' => $running['job']['lease'], 'scope_hash' => $running['job']['scope_hash'], 'kind' => $kind ), $override );
	return ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', $payload );
}

/** Make the previous admission old enough that pacing allows the next one. */
function ct_test_age_admission( $job_id, $ms = 1100 ) {
	global $wpdb;
	$wpdb->query( $wpdb->prepare( 'UPDATE ' . ct_scan_jobs_table() . ' SET last_admit_ms = last_admit_ms - %d WHERE job_id = %d', $ms, $job_id ) );
}

/** Remove only leftovers of earlier fixture runs. */
function ct_test_purge_fixtures() {
	global $wpdb;
	$jobs = ct_scan_jobs_table();
	$old_fixture_ids = $wpdb->get_col( $wpdb->prepare( "SELECT request_id FROM {$jobs} WHERE contact_name = %s", 'Fixture Reviewer' ) );
	foreach ( (array) $old_fixture_ids as $old_id ) {
		$old_post = get_post( (int) $old_id );
		if ( $old_post && 'ct_promo_request' === $old_post->post_type && 'private' === $old_post->post_status && 'Integration fixture request' === $old_post->post_title ) {
			$wpdb->delete( $jobs, array( 'request_id' => (int) $old_id ), array( '%d' ) );
			wp_delete_post( (int) $old_id, true );
		}
	}
}
