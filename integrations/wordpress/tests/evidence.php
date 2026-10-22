<?php
/**
 * Bound acceptance evidence and the accepted copy. Disposable fixture only.
 * Default configuration here: binding optional, accepted copy off. The strict
 * configuration (binding required, copy on) runs in evidence-strict.php.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
$mail = array();
add_filter( 'pre_wp_mail', static function ( $pre, $atts ) use ( &$mail ) {
	$mail[] = $atts;
	return true;
}, 10, 2 );

function ct_test_refused_with( $request_id, $fields, $code, $message ) {
	global $wpdb;
	$result = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_wp_error( $result ) && 'ct_scan_' . $code === get_post_meta( $request_id, '_ct_scan_status_detail', true ) && 'not_queued' === get_post_meta( $request_id, '_ct_scan_status', true ), $message . ' (got ' . ( is_wp_error( $result ) ? get_post_meta( $request_id, '_ct_scan_status_detail', true ) : 'a job' ) . ')' );
	ct_test_assert( 0 === (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . ct_scan_jobs_table() . ' WHERE request_id = %d', $request_id ) ), $message . ': a job was created' );
}

// Legacy (unbound) acceptance still works when its version is not required, and has no summary digest.
list( $legacy_id, $legacy_fields ) = ct_test_request( 'evidence-legacy.example.net' );
$request_ids[] = $legacy_id;
$legacy = ct_scan_on_request_ready( $legacy_id, $legacy_fields );
ct_test_assert( is_array( $legacy ) && null === ct_scan_row( $legacy['job_id'] )->summary_sha256, 'A legacy acceptance was refused or gained a summary digest.' );

// A valid bound acceptance creates a job that records the summary digest.
list( $ok_id, $ok_fields ) = ct_test_request( 'evidence-ok.example.net' );
$request_ids[] = $ok_id;
$meta = ct_test_bind( $ok_id, $ok_fields );
$ok = ct_scan_on_request_ready( $ok_id, $ok_fields );
ct_test_assert( is_array( $ok ) && hash( 'sha256', $meta['_ct_summary_text'] ) === ct_scan_row( $ok['job_id'] )->summary_sha256, 'A valid bound acceptance was refused or its summary digest was not recorded.' );
// The retained bytes are exactly the bytes hashed, including multibyte text and quotes, after a database round trip.
ct_test_assert( ct_scan_meta_string( $ok_id, '_ct_terms_snapshot' ) === $meta['_ct_terms_snapshot'] && hash( 'sha256', ct_scan_meta_string( $ok_id, '_ct_terms_snapshot' ) ) === ct_scan_row( $ok['job_id'] )->terms_hash, 'The retained snapshot bytes do not reproduce the recorded hash.' );

// Every single-piece break refuses the request and creates no job.
$cases = array(
	'snapshot changed after hashing'      => array( array( 'meta' => array( '_ct_terms_snapshot' => "<h1>Terms as displayed</h1>\n<p>Altered.</p>\n" ) ), 'binding_mismatch' ),
	'stale form digest (terms)'           => array( array( 'meta' => array( '_ct_terms_shown_digest' => str_repeat( 'a', 64 ) ) ), 'binding_mismatch' ),
	'terms hash differs from snapshot'    => array( array( 'meta' => array( '_ct_terms_sha256' => str_repeat( 'b', 64 ) ) ), 'binding_mismatch' ),
	'missing form digest'                 => array( array( 'meta' => array( '_ct_terms_shown_digest' => null ) ), 'binding_mismatch' ),
	'non-hex digest'                      => array( array( 'meta' => array( '_ct_terms_shown_digest' => str_repeat( 'z', 64 ) ) ), 'binding_mismatch' ),
	'summary digest mismatch'             => array( array( 'meta' => array( '_ct_summary_sha256' => str_repeat( 'c', 64 ) ) ), 'binding_mismatch' ),
	'stale form digest (summary)'         => array( array( 'meta' => array( '_ct_summary_shown_digest' => str_repeat( 'd', 64 ) ) ), 'binding_mismatch' ),
	'missing summary'                     => array( array( 'meta' => array( '_ct_summary_text' => null ) ), 'binding_mismatch' ),
	'missing snapshot'                    => array( array( 'meta' => array( '_ct_terms_snapshot' => null ) ), 'binding_mismatch' ),
	'oversized snapshot'                  => array( array( 'snapshot' => str_repeat( 'x', 524289 ) ), 'binding_mismatch' ),
	'summary names another website'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://other.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary names another contact'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Someone Else', 'email' => 'fixture@example.com' ) ) ), 'binding_mismatch' ),
	'summary names another profile'       => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ), array( 'Profile' => 'external-web-v1' ) ) ), 'binding_mismatch' ),
	'summary repeats the website line'    => array( array( 'summary' => ct_test_summary( array( 'target' => 'https://evidence-case.example.net/', 'name' => 'Fixture Reviewer', 'email' => 'fixture@example.com' ) ) . "Website (scan scope): https://other.example.net/\n" ), 'binding_mismatch' ),
	'bound pieces without the marker'     => array( array( 'meta' => array( '_ct_terms_binding' => null ) ), 'binding_required' ),
	'marker with another value'           => array( array( 'meta' => array( '_ct_terms_binding' => 'yes' ) ), 'binding_required' ),
);
$n = 0;
foreach ( $cases as $label => $case ) {
	$host = 'evidence-case-' . ( ++$n ) . '.example.net';
	list( $case_id, $case_fields ) = ct_test_request( $host );
	$request_ids[] = $case_id;
	$mutations = $case[0];
	// Summaries built for "evidence-case" must name this request's website for the other checks to be the only fault.
	if ( isset( $mutations['summary'] ) ) {
		$mutations['summary'] = str_replace( 'https://evidence-case.example.net/', $case_fields['target'], $mutations['summary'] );
	}
	ct_test_bind( $case_id, $case_fields, $mutations );
	ct_test_refused_with( $case_id, $case_fields, $case[1], 'Case "' . $label . '"' );
}

// After a job exists, the retained evidence cannot change: any alteration ends the authorization.
$running = ct_test_running_job_for_bound( 'evidence-running.example.net' );
$request_ids[] = $running['request_id'];
ct_test_assert( 200 === ct_test_admit( $running )->get_status(), 'A bound running job was not admitted.' );
$new_summary = ct_test_summary( $running['fields'] ) . "Note: edited afterwards\n";
update_post_meta( $running['request_id'], '_ct_summary_text', wp_slash( $new_summary ) );
update_post_meta( $running['request_id'], '_ct_summary_sha256', hash( 'sha256', $new_summary ) );
update_post_meta( $running['request_id'], '_ct_summary_shown_digest', hash( 'sha256', $new_summary ) );
ct_test_age_admission( $running['job_id'] );
$edited = ct_test_admit( $running );
ct_test_assert( 410 === $edited->get_status() && 'authorization_revoked_or_expired' === $edited->get_data()['reason'] && 'cancelled' === ct_scan_row( $running['job_id'] )->status, 'Editing the retained Target Summary after acceptance did not end the authorization.' );

// The accepted copy is off by default: nothing is sent and the state is untouched.
$before = count( $mail );
$off = ct_scan_send_accepted_copy( $ok['job_id'] );
ct_test_assert( 'disabled' === $off && count( $mail ) === $before && 'not_sent' === ct_scan_row( $ok['job_id'] )->accepted_copy_status, 'The accepted copy was sent although it is disabled.' );

// Strict configuration (binding required, copy on) in its own process.
$env = array_merge( getenv(), array( 'CT_TEST_BOUND' => '1', 'CT_TEST_COPY' => '1', 'CT_TEST_WP_ROOT' => getenv( 'CT_TEST_WP_ROOT' ) ?: '/var/www/html' ) );
$strict = proc_open( array( PHP_BINARY, __DIR__ . '/evidence-strict.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $spipes, null, $env );
$out = stream_get_contents( $spipes[1] );
$err = stream_get_contents( $spipes[2] );
proc_close( $strict );
ct_test_assert( false !== strpos( $out, 'Strict evidence checks passed.' ), 'The strict-configuration checks failed: ' . $out . $err );

foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
echo "Evidence binding checks passed.\n";
