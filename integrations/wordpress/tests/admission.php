<?php
/**
 * Per-request admission guard: cancellation/admission race, expiry, budgets, pacing,
 * lease and scope binding, and fail-closed behavior. Disposable fixture only.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
add_filter( 'pre_wp_mail', '__return_true' );

function ct_test_job_fields( $job_id ) {
	return ct_scan_row( $job_id );
}

function ct_test_end_job( $job_id ) {
	global $wpdb;
	$wpdb->update( ct_scan_jobs_table(), array( 'status' => 'failed', 'outcome' => 'failed', 'finished_at' => ct_scan_utc_now(), 'lease_hash' => null, 'lease_until' => null ), array( 'job_id' => (int) $job_id ) );
}

function ct_test_stop_token( $job_id ) {
	// The raw token exists only in the customer's email; a test token is installed by hash.
	global $wpdb;
	$token = bin2hex( random_bytes( 32 ) );
	$wpdb->update( ct_scan_jobs_table(), array( 'stop_token_hash' => hash( 'sha256', $token ) ), array( 'job_id' => (int) $job_id ) );
	return $token;
}

// Schema 3 columns exist and the schema option is current.
$columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . $jobs, 0 );
foreach ( array( 'profile_id', 'http_admitted', 'last_admit_ms' ) as $column ) {
	ct_test_assert( in_array( $column, $columns, true ), "Schema is missing {$column}." );
}
ct_test_assert( get_option( 'ct_scan_schema_version' ) === CT_SCAN_SCHEMA_VERSION, 'Schema version option is not current.' );

// Authentication and shape: unsigned, replayed, extra-key and unknown-kind requests never admit.
$bad = new WP_REST_Request( 'POST', '/ct-scan/v1/admit' );
$bad->set_body( '{}' );
ct_test_assert( 401 === ct_scan_admit( $bad )->get_status(), 'An unsigned admission request was not rejected.' );

$job1 = ct_test_running_job( 'admit-one.example.net' );
$request_ids[] = $job1['request_id'];
$row = ct_test_job_fields( $job1['job_id'] );
ct_test_assert( 'r2-header-v1' === $row->profile_id && 0 === (int) $row->http_admitted && null === $row->last_admit_ms, 'New job must freeze its profile with empty counters.' );
ct_test_assert( 400 === ct_test_admit( $job1, 'http', array( 'extra' => 1 ) )->get_status(), 'Extra fields must be rejected.' );
ct_test_assert( 400 === ct_test_admit( $job1, 'tls' )->get_status(), 'An unknown admission kind must be rejected.' );
ct_test_assert( 400 === ct_test_admit( $job1, 'http', array( 'kind' => array( 'http' ) ) )->get_status(), 'A non-string kind must be rejected.' );
$replay_nonce = bin2hex( random_bytes( 16 ) );
$payload = array( 'id' => $job1['job']['id'], 'lease' => $job1['job']['lease'], 'scope_hash' => $job1['job']['scope_hash'], 'kind' => 'probe' );
ct_test_assert( 200 === ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', $payload, $replay_nonce )->get_status(), 'A signed probe was refused.' );
ct_test_assert( 409 === ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', $payload, $replay_nonce )->get_status(), 'A replayed admission request was accepted.' );
ct_test_assert( 401 === ct_test_rest_call( 'ct_scan_admit', '/ct-scan/v1/admit', $payload, null, time() - 4000 )->get_status(), 'A stale-timestamp admission request was accepted.' );

// Wrong lease or scope: refused, no counter change.
$wrong = ct_test_admit( $job1, 'http', array( 'lease' => str_repeat( 'c', 64 ) ) );
ct_test_assert( 410 === $wrong->get_status() && 'lease_invalid_or_expired' === $wrong->get_data()['reason'], 'A wrong lease was admitted.' );
$wrong = ct_test_admit( $job1, 'http', array( 'scope_hash' => str_repeat( 'd', 64 ) ) );
ct_test_assert( 410 === $wrong->get_status(), 'A wrong scope hash was admitted.' );
ct_test_assert( 0 === (int) ct_test_job_fields( $job1['job_id'] )->http_admitted, 'A refused admission consumed budget.' );

// First admission is granted and recorded before it is returned; probes do not consume or pace.
$grant = ct_test_admit( $job1 );
$data  = $grant->get_data();
ct_test_assert( 200 === $grant->get_status() && true === $data['ok'] && true === $data['admitted'] && 1 === $data['sequence'] && 1000 === $data['valid_ms'] && 10000 === $data['timeout_ms'] && 19 === $data['http_remaining'], 'First admission was not granted with the disclosed bounds.' );
$row = ct_test_job_fields( $job1['job_id'] );
ct_test_assert( 1 === (int) $row->http_admitted && null !== $row->last_admit_ms, 'The reservation was not persisted with the grant.' );
$probe = ct_test_admit( $job1, 'probe' );
ct_test_assert( 200 === $probe->get_status() && true === $probe->get_data()['live'] && 1 === (int) ct_test_job_fields( $job1['job_id'] )->http_admitted, 'A probe consumed budget or reported a live job incorrectly.' );

// Pacing: a second request inside the interval is told to wait and consumes nothing.
$early = ct_test_admit( $job1 );
ct_test_assert( 429 === $early->get_status() && 'rate_wait' === $early->get_data()['reason'] && $early->get_data()['retry_after_ms'] > 0 && $early->get_data()['retry_after_ms'] <= 1000, 'Pacing did not require a wait.' );
ct_test_assert( 1 === (int) ct_test_job_fields( $job1['job_id'] )->http_admitted, 'A paced request consumed budget.' );
ct_test_age_admission( $job1['job_id'] );
$second = ct_test_admit( $job1 );
ct_test_assert( 200 === $second->get_status() && 2 === $second->get_data()['sequence'], 'Admission after the interval was refused.' );

// A clock that moved backwards by more than the interval refuses rather than guessing.
$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET last_admit_ms = last_admit_ms + 3600000 WHERE job_id = %d", $job1['job_id'] ) );
$anomaly = ct_test_admit( $job1 );
ct_test_assert( 410 === $anomaly->get_status() && 'clock_anomaly' === $anomaly->get_data()['reason'], 'A backwards clock was not refused.' );
$wpdb->query( $wpdb->prepare( "UPDATE {$jobs} SET last_admit_ms = last_admit_ms - 3600000 WHERE job_id = %d", $job1['job_id'] ) );

// Budget: exhausted at the frozen limit; refusal is stable and does not reset.
ct_test_age_admission( $job1['job_id'] );
$wpdb->update( $jobs, array( 'http_admitted' => 19 ), array( 'job_id' => $job1['job_id'] ) );
$last = ct_test_admit( $job1 );
ct_test_assert( 200 === $last->get_status() && 0 === $last->get_data()['http_remaining'], 'The final budgeted request was refused.' );
ct_test_age_admission( $job1['job_id'] );
$over = ct_test_admit( $job1 );
ct_test_assert( 409 === $over->get_status() && 'budget_exhausted' === $over->get_data()['reason'] && 20 === (int) ct_test_job_fields( $job1['job_id'] )->http_admitted, 'The request budget was exceeded.' );

// Duplicate delivery of the ready event neither creates a job nor resets counters, profile or expiry.
delete_post_meta( $job1['request_id'], '_ct_scan_event_recorded' );
$expiry_before = ct_test_job_fields( $job1['job_id'] )->authorization_expires_at;
$dup = ct_scan_on_request_ready( $job1['request_id'], $job1['fields'] );
$after = ct_test_job_fields( $job1['job_id'] );
ct_test_assert( ! empty( $dup['duplicate'] ) && 20 === (int) $after->http_admitted && $expiry_before === $after->authorization_expires_at && 'running' === $after->status, 'A duplicate event reset the job budget, expiry or state.' );

// An unknown profile is refused even though the job is otherwise live.
$wpdb->update( $jobs, array( 'profile_id' => 'unknown-v9', 'http_admitted' => 0 ), array( 'job_id' => $job1['job_id'] ) );
ct_test_age_admission( $job1['job_id'] );
$unknown = ct_test_admit( $job1 );
ct_test_assert( 410 === $unknown->get_status() && 'profile_unknown' === $unknown->get_data()['reason'], 'An unknown profile was admitted.' );
$wpdb->update( $jobs, array( 'profile_id' => 'r2-header-v1' ), array( 'job_id' => $job1['job_id'] ) );

// An unconfirmed recipient is never admitted.
$wpdb->update( $jobs, array( 'confirmed_at' => null ), array( 'job_id' => $job1['job_id'] ) );
$unconfirmed = ct_test_admit( $job1 );
ct_test_assert( 410 === $unconfirmed->get_status() && 'recipient_unconfirmed' === $unconfirmed->get_data()['reason'], 'An unconfirmed job was admitted.' );
$wpdb->update( $jobs, array( 'confirmed_at' => ct_scan_utc_now() ), array( 'job_id' => $job1['job_id'] ) );

// Saved authorization changed after the job began: refused and the job is cancelled.
$original_hash = get_post_meta( $job1['request_id'], '_ct_terms_sha256', true );
update_post_meta( $job1['request_id'], '_ct_terms_sha256', str_repeat( '9', 64 ) );
$changed = ct_test_admit( $job1 );
ct_test_assert( 410 === $changed->get_status() && 'authorization_revoked_or_expired' === $changed->get_data()['reason'] && 'cancelled' === ct_test_job_fields( $job1['job_id'] )->status, 'A changed authorization was admitted.' );
update_post_meta( $job1['request_id'], '_ct_terms_sha256', $original_hash );
$after_change = ct_test_admit( $job1 );
ct_test_assert( 410 === $after_change->get_status(), 'A cancelled job became admissible again.' );

// Before start: a claimed (leased) job and a queued job have no admission.
list( $leased_request, $leased_fields ) = ct_test_request( 'admit-leased.example.net' );
$request_ids[] = $leased_request;
$leased_event = ct_scan_on_request_ready( $leased_request, $leased_fields );
ct_test_queue_job( $leased_event['job_id'] );
$claimed = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() )->get_data()['job'];
$leased  = array( 'job' => $claimed, 'job_id' => (int) $leased_event['job_id'] );
$pre = ct_test_admit( $leased );
ct_test_assert( 410 === $pre->get_status() && 'job_not_running' === $pre->get_data()['reason'] && 0 === (int) ct_test_job_fields( $leased['job_id'] )->http_admitted, 'A leased-but-unstarted job was admitted.' );
$stop_token = ct_test_stop_token( $leased['job_id'] );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $leased['job_id'], $stop_token ), 'Fixture could not stop the leased job.' );
ct_test_assert( 410 === ct_test_admit( $leased )->get_status(), 'A stopped, unstarted job was admitted.' );

// Cancellation/admission race, order 1: stop commits first, so the next admission is refused.
$job2 = ct_test_running_job( 'admit-stop-first.example.net' );
$request_ids[] = $job2['request_id'];
$stop2 = ct_test_stop_token( $job2['job_id'] );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $job2['job_id'], $stop2 ), 'Customer stop failed on a running job.' );
$refused = ct_test_admit( $job2 );
ct_test_assert( 410 === $refused->get_status() && 'job_cancelled' === $refused->get_data()['reason'] && 0 === (int) ct_test_job_fields( $job2['job_id'] )->http_admitted, 'An admission was granted after a recorded customer stop.' );
ct_test_assert( 410 === ct_test_admit( $job2, 'probe' )->get_status(), 'A probe reported a stopped job as live.' );

// Order 2: the admission commits first, so exactly that one request may finish; every later one is refused.
$job3 = ct_test_running_job( 'admit-grant-first.example.net' );
$request_ids[] = $job3['request_id'];
$stop3 = ct_test_stop_token( $job3['job_id'] );
ct_test_assert( 200 === ct_test_admit( $job3 )->get_status(), 'Fixture admission before stop was refused.' );
ct_test_assert( 'stopped' === ct_scan_customer_stop( $job3['job_id'], $stop3 ), 'Customer stop after an admission failed.' );
ct_test_age_admission( $job3['job_id'] );
ct_test_assert( 410 === ct_test_admit( $job3 )->get_status() && 410 === ct_test_admit( $job3, 'probe' )->get_status(), 'A request was admitted after the stop that followed an admission.' );
ct_test_assert( 1 === (int) ct_test_job_fields( $job3['job_id'] )->http_admitted, 'Exactly the one already-admitted request should be counted.' );

// Order 3, real contention: a second process holds the queue lock (an admission in progress).
// An admission cannot proceed unserialized (busy, nothing written); the stop waits for the lock,
// wins, and the next admission is refused.
$job4 = ct_test_running_job( 'admit-contended.example.net' );
$request_ids[] = $job4['request_id'];
$stop4 = ct_test_stop_token( $job4['job_id'] );
$holder = proc_open( array( PHP_BINARY, __DIR__ . '/lock-holder.php', '1.3' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, null );
ct_test_assert( is_resource( $holder ) && "locked\n" === fgets( $pipes[1] ), 'The lock-holder helper did not acquire the queue lock.' );
$busy = ct_test_admit( $job4 );
ct_test_assert( 503 === $busy->get_status() && 'queue_busy' === $busy->get_data()['reason'] && 0 === (int) ct_test_job_fields( $job4['job_id'] )->http_admitted, 'An admission proceeded while the queue lock was held elsewhere.' );
$started = microtime( true );
$stopped = ct_scan_customer_stop( $job4['job_id'], $stop4 );
$elapsed = microtime( true ) - $started;
ct_test_assert( 'stopped' === $stopped && $elapsed > 0.3, 'The stop did not wait for the in-progress lock holder and then succeed.' );
ct_test_assert( 410 === ct_test_admit( $job4 )->get_status(), 'An admission followed a stop that waited on the lock.' );
fclose( $pipes[1] );
fclose( $pipes[2] );
proc_close( $holder );

// Operator revocation behaves like a stop for admission.
$job5 = ct_test_running_job( 'admit-revoked.example.net' );
$request_ids[] = $job5['request_id'];
ct_test_assert( true === ct_scan_admin_revoke( $job5['job_id'] ), 'Operator revocation failed.' );
ct_test_assert( 410 === ct_test_admit( $job5 )->get_status(), 'A revoked job was admitted.' );

// Expiry: authorization expiry blocks the next admission; lease expiry cannot start a fresh budget.
$job6 = ct_test_running_job( 'admit-expiry.example.net' );
$request_ids[] = $job6['request_id'];
ct_test_assert( 200 === ct_test_admit( $job6 )->get_status(), 'Fixture admission before expiry was refused.' );
$wpdb->update( $jobs, array( 'authorization_expires_at' => gmdate( 'Y-m-d H:i:s', time() - 1 ) ), array( 'job_id' => $job6['job_id'] ) );
ct_test_age_admission( $job6['job_id'] );
$expired = ct_test_admit( $job6 );
ct_test_assert( 410 === $expired->get_status() && 'job_expired' === $expired->get_data()['reason'], 'An admission was granted after authorization expiry.' );
$job7 = ct_test_running_job( 'admit-lease.example.net' );
$request_ids[] = $job7['request_id'];
ct_test_assert( 200 === ct_test_admit( $job7 )->get_status(), 'Fixture admission before lease expiry was refused.' );
$wpdb->update( $jobs, array( 'lease_until' => gmdate( 'Y-m-d H:i:s', time() - 2 ) ), array( 'job_id' => $job7['job_id'] ) );
ct_test_age_admission( $job7['job_id'] );
$lapsed = ct_test_admit( $job7 );
ct_test_assert( 410 === $lapsed->get_status() && 1 === (int) ct_test_job_fields( $job7['job_id'] )->http_admitted && 'failed_unknown' === ct_test_job_fields( $job7['job_id'] )->status, 'A lapsed lease was admitted or its counters reset.' );
$reclaim = ct_test_rest_call( 'ct_scan_claim', '/ct-scan/v1/claim', array() );
ct_test_assert( null === $reclaim->get_data()['job'] && 1 === (int) ct_test_job_fields( $job7['job_id'] )->http_admitted, 'Recovery produced a fresh claim or budget for a started job.' );

// Unavailable authorization store: a schema mismatch disables the whole worker API, including admission.
$job8 = ct_test_running_job( 'admit-store.example.net' );
$request_ids[] = $job8['request_id'];
update_option( 'ct_scan_schema_version', '2', false );
$unavailable = ct_test_admit( $job8 );
update_option( 'ct_scan_schema_version', CT_SCAN_SCHEMA_VERSION, false );
ct_test_assert( 503 === $unavailable->get_status() && 0 === (int) ct_test_job_fields( $job8['job_id'] )->http_admitted, 'Admission was granted while the store was not at the expected schema.' );
ct_test_end_job( $job8['job_id'] );

// Global operator kill switch: with the integration disabled, nothing is admitted.
$disabled = proc_open( array( PHP_BINARY, __DIR__ . '/admission-disabled.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $dpipes, null, array_merge( $_ENV, array( 'CT_TEST_ENABLED' => '0', 'WORDPRESS_DB_PASSWORD' => 'fixture-only', 'WORDPRESS_DB_HOST' => 'db', 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html', 'PATH' => getenv( 'PATH' ) ) ) );
$out = stream_get_contents( $dpipes[1] );
$err = stream_get_contents( $dpipes[2] );
proc_close( $disabled );
ct_test_assert( "disabled\n" === $out, 'The disabled-integration check failed: ' . $out . $err );

// Remove only records created by this test.
foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "Admission guard checks passed.\n";
