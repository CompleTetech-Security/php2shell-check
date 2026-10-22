<?php
/**
 * Disposable WordPress + MariaDB integration checks for the MU plugin.
 * Run only with the repository's `fixture-only` Docker Compose environment.
 */
if ( PHP_SAPI !== 'cli' || getenv( 'WORDPRESS_DB_PASSWORD' ) !== 'fixture-only' || getenv( 'WORDPRESS_DB_HOST' ) !== 'db' ) {
	throw new RuntimeException( 'Refusing to run outside the disposable WordPress fixture.' );
}

$private_config = tempnam( '/tmp', 'ct-scan-integration-' );
file_put_contents( $private_config, '<?php return ' . var_export( array(
	'enabled'                   => true,
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
require '/var/www/html/wp-load.php';
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

// Canonical scope normalization and control-character rejection.
ct_test_assert( 'https://example.com/' === ct_scan_normalize_target( 'https://EXAMPLE.com/' ), 'Canonical origin must have lowercase host and trailing slash.' );
foreach ( array( "https://example.com/\n", 'https://example.com/path', 'https://127.0.0.1/', 'https://user@example.com/', 'https://example.com:8443/' ) as $bad_target ) {
	ct_test_assert( is_wp_error( ct_scan_normalize_target( $bad_target ) ), 'Invalid target accepted: ' . bin2hex( $bad_target ) );
}

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
$request_ids = array();
$mail_calls = array();
$mail_mode = true;
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail_calls, &$mail_mode ) {
	$mail_calls[] = $atts;
	return $mail_mode;
}, 10, 2 );

// A new accepted request creates one confirmation-gated immutable job.
list( $request_id, $fields ) = ct_test_request( 'queue-fixture.example.net' );
$request_ids[] = $request_id;
$event = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( is_array( $event ) && 'awaiting_confirmation' === $event['status'], 'Accepted request was not queued for confirmation.' );
ct_test_assert( 1 === (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$jobs} WHERE request_id=%d", $request_id ) ), 'Expected exactly one durable job.' );
$row = ct_scan_row( $event['job_id'] );
ct_test_assert( hash( 'sha256', $fields['target'] ) === $row->scope_hash, 'Scope hash must cover the exact canonical target.' );
ct_test_assert( 'accepted' === $row->confirmation_email_status, 'Confirmation mail acceptance state was not recorded.' );
ct_test_assert( false !== strpos( $mail_calls[0]['message'], 'token=' ), 'Confirmation link missing from the captured fixture email.' );

// Duplicate hook delivery is database-idempotent even when the event meta is absent.
delete_post_meta( $request_id, '_ct_scan_event_recorded' );
$duplicate = ct_scan_on_request_ready( $request_id, $fields );
ct_test_assert( ! is_wp_error( $duplicate ) && ! empty( $duplicate['duplicate'] ) && (int) $duplicate['job_id'] === (int) $event['job_id'], 'Duplicate event created a second job or changed state.' );

// Confirmed queue: claim, start-before-work, validated result, and exact receipt retry.
ct_test_queue_job( $event['job_id'] );
$claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $claim->get_status() && is_array( $claim->get_data()['job'] ), 'Signed claim did not return a job.' );
$claimed = $claim->get_data()['job'];
ct_test_assert( $claimed['target'] === $fields['target'] && is_int( $claimed['expires_at'] ) && is_int( $claimed['lease_until'] ), 'Claim fields or Unix timestamps are misaligned.' );
$start_payload = array( 'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'] );
$start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', $start_payload );
ct_test_assert( 200 === $start->get_status() && true === $start->get_data()['ok'], 'Start callback was not acknowledged.' );
$run = array(
	'id' => $claimed['id'], 'lease' => $claimed['lease'], 'scope_hash' => $claimed['scope_hash'], 'outcome' => 'completed',
	'result' => ct_test_result( $fields['target'] ), 'error' => '', 'checker_revision' => str_repeat( 'a', 40 ),
);
$result = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $result->get_status() && true === $result->get_data()['ok'], 'Valid checker receipt was not acknowledged.' );
$retry = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $run );
ct_test_assert( 200 === $retry->get_status(), 'An exact receipt retry must be idempotent.' );
$changed = $run;
$changed['result']['title'] = 'Different valid receipt';
$conflict = ct_test_rest_call( 'ct_scan_result', '/ct-scan/v1/result', $changed );
ct_test_assert( 409 === $conflict->get_status(), 'Changed receipt must conflict.' );
$stale = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), null, time() - 301 );
ct_test_assert( 401 === $stale->get_status(), 'Stale HMAC timestamp must be rejected.' );
$replay_nonce = bin2hex( random_bytes( 16 ) );
$replay1 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
$replay2 = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array(), $replay_nonce );
ct_test_assert( 200 === $replay1->get_status() && 409 === $replay2->get_status(), 'Authenticated nonce replay was not rejected.' );

// Reports preserve old result snapshots, escape evidence, freeze after first send, and separate acceptance from delivery.
$stored = ct_scan_row( $event['job_id'] );
$snapshot = ct_test_result( $fields['target'] );
$snapshot['php2shell_rules_as_of'] = '2024-02-29';
$wpdb->update( $jobs, array( 'result_json' => wp_json_encode( $snapshot ) ), array( 'job_id' => (int) $event['job_id'] ) );
$stored = ct_scan_row( $event['job_id'] );
ct_test_assert( is_wp_error( ct_scan_validate_result( $snapshot, $stored ) ), 'New receipts must match current configured rules date.' );
ct_test_assert( ! is_wp_error( ct_scan_validate_result( $snapshot, $stored, true ) ), 'Stored report snapshot must remain valid after rules-date changes.' );
$admin_details = ct_scan_admin_result_details( $stored );
ct_test_assert( false !== strpos( $admin_details, 'Private stored PHP2Shell evidence' ) && false === strpos( $admin_details, '<script>' ), 'Private result details must render escaped evidence for reviewers.' );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $event['job_id'], 'Reviewed the remaining service scope.' ), 'Manual remainder did not save.' );
$preview = ct_scan_build_report_body( ct_scan_row( $event['job_id'] ) );
ct_test_assert( ! is_wp_error( $preview ) && false !== strpos( $preview, '2024-02-29' ), 'Reviewed report did not retain the frozen rule snapshot.' );
ct_test_assert( false === strpos( $preview, '<script>' ), 'HTML in observed evidence must not appear as executable markup.' );
ct_test_assert( true === ct_scan_admin_send_report( $event['job_id'] ), 'Reviewed report send was not accepted by the isolated mail fixture.' );
ct_test_assert( 'accepted' === ct_scan_row( $event['job_id'] )->report_notification_status, 'Report transport and delivery state were conflated.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $event['job_id'], 'Edited after send' ) ), 'Report details must freeze after a send attempt.' );
ct_test_assert( true === ct_scan_admin_record_delivery( $event['job_id'] ), 'Independently confirmed delivery did not persist.' );

// An expired, never-confirmed request cannot receive detailed findings, even after manual review.
list( $unconfirmed_id, $unconfirmed_fields ) = ct_test_request( 'unconfirmed-report-fixture.example.net' );
$request_ids[] = $unconfirmed_id;
$unconfirmed_event = ct_scan_on_request_ready( $unconfirmed_id, $unconfirmed_fields );
$wpdb->update( $jobs, array( 'status' => 'expired', 'error_code' => 'confirmation_expired', 'finished_at' => ct_scan_utc_now(), 'confirmation_token_hash' => null ), array( 'job_id' => (int) $unconfirmed_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unconfirmed_event['job_id'], 'Operator notes entered after expiry.' ), 'Unconfirmed fixture manual notes failed.' );
$mail_count = count( $mail_calls );
$unconfirmed_send = ct_scan_admin_send_report( $unconfirmed_event['job_id'] );
ct_test_assert( is_wp_error( $unconfirmed_send ) && 'report_recipient_unconfirmed' === $unconfirmed_send->get_error_code(), 'An unconfirmed recipient was allowed a detailed report.' );
ct_test_assert( count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unconfirmed_event['job_id'] )->report_notification_status, 'A refused unconfirmed report must not send or change send state.' );

// Unknown mail outcomes remain one-shot; independently confirmed delivery can still be recorded.
list( $unknown_id, $unknown_fields ) = ct_test_request( 'unknown-mail-fixture.example.net' );
$request_ids[] = $unknown_id;
$unknown_event = ct_scan_on_request_ready( $unknown_id, $unknown_fields );
ct_test_queue_job( $unknown_event['job_id'] );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => ct_scan_utc_now() ), array( 'job_id' => (int) $unknown_event['job_id'] ) );
ct_test_assert( true === ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'No remaining work was performed in this fixture.' ), 'Unknown-mail fixture manual notes failed.' );
$mail_mode = false;
$mail_count = count( $mail_calls );
$fail_send_state_once = true;
$fail_send_state_filter = static function ( $query ) use ( &$fail_send_state_once, $jobs ) {
	if ( $fail_send_state_once && false !== strpos( $query, "SET `report_notification_status` = 'unknown'" ) && false !== strpos( $query, $jobs ) ) {
		$fail_send_state_once = false;
		return preg_replace( '/ WHERE /', ' WHERE 1=0 AND ', $query, 1 );
	}
	return $query;
};
add_filter( 'query', $fail_send_state_filter );
$write_failure = ct_scan_admin_send_report( $unknown_event['job_id'] );
remove_filter( 'query', $fail_send_state_filter );
ct_test_assert( is_wp_error( $write_failure ) && count( $mail_calls ) === $mail_count && 'not_sent' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'A failed durable one-time send write must not send email.' );
$unknown_send = ct_scan_admin_send_report( $unknown_event['job_id'] );
ct_test_assert( is_wp_error( $unknown_send ) && 'unknown' === ct_scan_row( $unknown_event['job_id'] )->report_notification_status, 'Unconfirmed mail must remain unknown and must not be retried.' );
ct_test_assert( is_wp_error( ct_scan_admin_save_manual_remainder( $unknown_event['job_id'], 'Altered content' ) ), 'Report contents changed after an unknown send outcome.' );
ct_test_assert( true === ct_scan_admin_record_delivery( $unknown_event['job_id'] ), 'Independent proof must allow recording delivery from unknown state.' );
$mail_mode = true;

// Old requests are never backfilled, and any changed saved target permanently cancels authorization.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'legacy-fixture.example.net' );
$request_ids[] = $legacy_id;
delete_post_meta( $legacy_id, '_ct_terms_saved' );
$legacy_event = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
ct_test_assert( is_wp_error( $legacy_event ) && ! $wpdb->get_var( $wpdb->prepare( "SELECT job_id FROM {$jobs} WHERE request_id=%d", $legacy_id ) ), 'A legacy request without the durable acceptance marker was backfilled.' );

list( $changed_id, $changed_fields ) = ct_test_request( 'changed-target-fixture.example.net' );
$request_ids[] = $changed_id;
$changed_event = ct_scan_on_request_ready( $changed_id, $changed_fields );
ct_test_assert( ! is_wp_error( $changed_event ), 'Changed-target fixture setup failed.' );
update_post_meta( $changed_id, '_ct_scan_target', 'https://different-fixture.example.net/' );
ct_test_assert( ! ct_scan_authorization_is_live( ct_scan_row( $changed_event['job_id'] ) ), 'A changed saved target remained authorized.' );
ct_test_queue_job( $changed_event['job_id'] );
$changed_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( 200 === $changed_claim->get_status() && null === $changed_claim->get_data()['job'] && 'cancelled' === ct_scan_row( $changed_event['job_id'] )->status, 'A changed-target job was claimable instead of being canceled.' );

// Revocation while leased prevents start; an expired running lease is terminal and never rescanned.
list( $revoked_id, $revoked_fields ) = ct_test_request( 'revoked-fixture.example.net' );
$request_ids[] = $revoked_id;
$revoked_event = ct_scan_on_request_ready( $revoked_id, $revoked_fields );
ct_test_queue_job( $revoked_event['job_id'] );
$revoked_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$revoked_job = $revoked_claim->get_data()['job'];
ct_test_assert( is_array( $revoked_job ), 'Expected to claim the revocation fixture.' );
ct_test_assert( true === ct_scan_admin_revoke( $revoked_job['id'] ), 'Admin revocation did not persist.' );
$revoked_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $revoked_job['id'], 'lease' => $revoked_job['lease'], 'scope_hash' => $revoked_job['scope_hash'] ) );
ct_test_assert( 410 === $revoked_start->get_status() && 'cancelled' === ct_scan_row( $revoked_job['id'] )->status, 'Revoked authorization allowed worker start.' );

list( $lease_id, $lease_fields ) = ct_test_request( 'expired-lease-fixture.example.net' );
$request_ids[] = $lease_id;
$lease_event = ct_scan_on_request_ready( $lease_id, $lease_fields );
ct_test_queue_job( $lease_event['job_id'] );
$lease_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_job = $lease_claim->get_data()['job'];
ct_test_assert( is_array( $lease_job ), 'Expected to claim the expired-lease fixture.' );
$lease_start = ct_test_rest_call( 'ct_scan_start', '/ct-scan/v1/start', array( 'id' => $lease_job['id'], 'lease' => $lease_job['lease'], 'scope_hash' => $lease_job['scope_hash'] ) );
ct_test_assert( 200 === $lease_start->get_status(), 'Expired-lease fixture did not enter running state.' );
$wpdb->update( $jobs, array( 'lease_until' => gmdate( 'Y-m-d H:i:s', time() - 5 ) ), array( 'job_id' => (int) $lease_job['id'] ) );
$after_expiry_claim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
$lease_row = ct_scan_row( $lease_job['id'] );
ct_test_assert( 200 === $after_expiry_claim->get_status() && null === $after_expiry_claim->get_data()['job'] && 'failed_unknown' === $lease_row->status && 1 === (int) $lease_row->attempts, 'An expired running lease was automatically rescanned or not marked unknown.' );

// Calendar-based retention clears result/manual content at 12 months, and only removes the exact private linked request at 3 years.
list( $retention_id, $retention_fields ) = ct_test_request( 'retention-fixture.example.net' );
$request_ids[] = $retention_id;
$retention_event = ct_scan_on_request_ready( $retention_id, $retention_fields );
$old_finished = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-13 months' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'status' => 'failed', 'finished_at' => $old_finished, 'terms_accepted_at' => $old_finished, 'result_json' => '{}', 'manual_remainder_notes' => 'private notes' ), array( 'job_id' => (int) $retention_event['job_id'] ) );
ct_scan_maintenance_locked();
$retained = ct_scan_row( $retention_event['job_id'] );
ct_test_assert( $retained && null === $retained->result_json && null === $retained->manual_remainder_notes && get_post( $retention_id ), '12-month cleanup must clear result/manual data but retain the request evidence.' );
$three_years = ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( '-3 years -1 day' )->format( 'Y-m-d H:i:s' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => $three_years, 'finished_at' => $three_years ), array( 'job_id' => (int) $retention_event['job_id'] ) );
$hold_delete = static function ( $check, $post ) use ( $retention_id ) {
	return (int) $retention_id === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $hold_delete, 10, 2 );
ct_scan_maintenance_locked();
remove_filter( 'pre_delete_post', $hold_delete, 10 );
ct_test_assert( ct_scan_row( $retention_event['job_id'] ) && get_post( $retention_id ) && '' === ct_scan_row( $retention_event['job_id'] )->contact_email && '' === ct_scan_row( $retention_event['job_id'] )->contact_name, 'Failed three-year post deletion must retain the job link while scrubbing contact fields.' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_scan_row( $retention_event['job_id'] ) && ! get_post( $retention_id ), 'Three-year cleanup must remove the exact linked private request and job.' );

// Remove only records created by this test.
foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "WordPress integration checks passed.\n";
