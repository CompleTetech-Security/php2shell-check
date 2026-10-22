<?php
/**
 * Closure, retention periods, preservation holds and deletion tombstones. Disposable fixture only.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
$request_ids = array();
add_filter( 'pre_wp_mail', '__return_true' );

function ct_test_old( $modifier ) {
	return ( new DateTimeImmutable( 'now', new DateTimeZone( 'UTC' ) ) )->modify( $modifier )->format( 'Y-m-d H:i:s' );
}

/** A job in $status whose acceptance and closure are the given ages. */
function ct_test_aged_job( $host, $status, $accepted, $closed, $version = '2026-10-21-r2' ) {
	global $wpdb, $request_ids;
	list( $request_id, $fields ) = ct_test_request( $host );
	$request_ids[] = $request_id;
	$event = ct_scan_on_request_ready( $request_id, $fields );
	ct_test_assert( is_array( $event ), 'Retention fixture job was not created.' );
	$update = array( 'status' => $status, 'terms_accepted_at' => ct_test_old( $accepted ), 'terms_version' => $version, 'confirmation_token_hash' => null );
	if ( null !== $closed ) {
		$update['finished_at'] = ct_test_old( $closed );
		$update['result_json'] = '{"fixture":true}';
		$update['manual_remainder_notes'] = 'private findings';
	}
	$wpdb->update( ct_scan_jobs_table(), $update, array( 'job_id' => (int) $event['job_id'] ) );
	return array( 'job_id' => (int) $event['job_id'], 'request_id' => $request_id );
}

function ct_test_exists( $job ) {
	return (bool) ct_scan_row( $job['job_id'] );
}

// ---- Closure is explicit, and only terminal jobs close ---------------------------------------------------
list( $live_request, $live_fields ) = ct_test_request( 'ret-live.example.net' );
$request_ids[] = $live_request;
$live_event = ct_scan_on_request_ready( $live_request, $live_fields );
ct_test_queue_job( $live_event['job_id'] );
$live = array( 'job_id' => (int) $live_event['job_id'], 'request_id' => $live_request );
$closing = ct_test_aged_job( 'ret-closing.example.net', 'failed', '-1 day', '-1 hour' );
$blocked = ct_test_aged_job( 'ret-blocked.example.net', 'blocked', '-2 days', '-1 day' );
ct_scan_maintenance_locked();
$row = ct_scan_row( $closing['job_id'] );
ct_test_assert( $row->closed_at === $row->finished_at && ! empty( $row->retain_until ), 'A finished job was not stamped closed with a deletion date.' );
ct_test_assert( null === ct_scan_row( $live['job_id'] )->closed_at && null === ct_scan_row( $live['job_id'] )->retain_until, 'A job that can still run was stamped closed.' );
ct_test_assert( ! empty( ct_scan_row( $blocked['job_id'] )->closed_at ), 'A blocked job was not closed.' );
ct_test_assert( ct_test_exists( $live ) && get_post( $live['request_id'] ), 'A job that can still run was deleted or closed by retention.' );

// r2: three years from acceptance. Other versions: six years after closure.
$r2 = ct_scan_row( $closing['job_id'] );
ct_test_assert( $r2->retain_until === ( new DateTimeImmutable( $r2->terms_accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'r2 evidence is not kept three years from acceptance.' );
$newer = ct_test_aged_job( 'ret-newer.example.net', 'cancelled', '-1 year', '-1 month', '2027-06-01-r3' );
ct_scan_maintenance_locked();
$nr = ct_scan_row( $newer['job_id'] );
ct_test_assert( $nr->retain_until === ( new DateTimeImmutable( $nr->closed_at, new DateTimeZone( 'UTC' ) ) )->modify( '+6 years' )->format( 'Y-m-d H:i:s' ), 'A newer version is not kept six years after closure.' );

// The date is fixed at closure: a later change of the stored acceptance date does not move it.
$fixed = $nr->retain_until;
$wpdb->update( $jobs, array( 'terms_accepted_at' => ct_test_old( '-9 years' ) ), array( 'job_id' => $newer['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_scan_row( $newer['job_id'] )->retain_until === $fixed, 'The deletion date was recomputed after closure.' );

// An accepted-but-unverified request that expires is closed too.
list( $unverified_id, $unverified_fields ) = ct_test_request( 'ret-unverified.example.net' );
$request_ids[] = $unverified_id;
$unverified = ct_scan_on_request_ready( $unverified_id, $unverified_fields );
$wpdb->update( $jobs, array( 'confirmation_expires_at' => ct_test_old( '-1 hour' ) ), array( 'job_id' => $unverified['job_id'] ) );
ct_scan_maintenance_locked();
$u = ct_scan_row( $unverified['job_id'] );
ct_test_assert( 'expired' === $u->status && ! empty( $u->closed_at ) && ! empty( $u->retain_until ), 'An unconfirmed request that expired was not closed with a deletion date.' );

// ---- Findings: twelve months after closure; evidence is kept ------------------------------------------------
$young = ct_test_aged_job( 'ret-young.example.net', 'completed', '-2 years', '-11 months' );
$old   = ct_test_aged_job( 'ret-old.example.net', 'completed', '-2 years', '-13 months' );
ct_scan_maintenance_locked();
ct_test_assert( null !== ct_scan_row( $young['job_id'] )->result_json && null !== ct_scan_row( $young['job_id'] )->manual_remainder_notes, 'Findings were cleared before twelve months.' );
$o = ct_scan_row( $old['job_id'] );
ct_test_assert( null === $o->result_json && null === $o->manual_remainder_notes && ct_test_exists( $old ) && get_post( $old['request_id'] ), 'Findings were not cleared at twelve months, or the signed evidence went with them.' );

// ---- Evidence deadlines --------------------------------------------------------------------------------------
$edge_keep = ct_test_aged_job( 'ret-keep.example.net', 'failed', '-2 years -11 months', '-1 day' );
$edge_del  = ct_test_aged_job( 'ret-del.example.net', 'failed', '-3 years -1 day', '-1 day' );
$six_keep  = ct_test_aged_job( 'ret-six-keep.example.net', 'cancelled', '-7 years', '-5 years -11 months', '2027-06-01-r3' );
$six_del   = ct_test_aged_job( 'ret-six-del.example.net', 'cancelled', '-7 years', '-6 years -1 day', '2027-06-01-r3' );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $edge_keep ) && get_post( $edge_keep['request_id'] ), 'r2 evidence was deleted before three years.' );
ct_test_assert( ! ct_test_exists( $edge_del ) && ! get_post( $edge_del['request_id'] ), 'r2 evidence was not deleted after three years.' );
ct_test_assert( ct_test_exists( $six_keep ) && get_post( $six_keep['request_id'] ), 'Six-year evidence was deleted early.' );
ct_test_assert( ! ct_test_exists( $six_del ) && ! get_post( $six_del['request_id'] ), 'Six-year evidence was not deleted after its period.' );

// ---- Tombstones: identifiers only ----------------------------------------------------------------------------
$stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $edge_del['job_id'] ) );
ct_test_assert( $stone && (int) $stone->request_id === $edge_del['request_id'] && 'retention' === $stone->reason && 64 === strlen( $stone->scope_hash ), 'No tombstone recorded the deletion.' );
$columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . ct_scan_tombstones_table(), 0 );
ct_test_assert( array() === array_intersect( $columns, array( 'contact_email', 'contact_name', 'target_origin', 'result_json', 'terms_hash' ) ), 'The tombstone table can hold personal or customer data.' );

// A restored backup brings the rows back: maintenance deletes them again.
$ghost = array( 'job_id' => $edge_del['job_id'], 'request_id' => $edge_del['request_id'], 'target_origin' => 'https://ret-del.example.net/', 'scope_hash' => $stone->scope_hash, 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'restored@example.com', 'contact_name' => 'Restored Person', 'referrer' => 'direct', 'status' => 'failed', 'created_at' => $stone->created_at, 'finished_at' => ct_test_old( '-1 day' ), 'closed_at' => ct_test_old( '-1 day' ) );
$wpdb->insert( $jobs, $ghost );
$restored_post = wp_insert_post( array( 'import_id' => $edge_del['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $edge_del['request_id'], '_ct_scan_job_id', $edge_del['job_id'] );
ct_test_assert( ct_test_exists( $edge_del ) && get_post( $edge_del['request_id'] ), 'Fixture failed to restore the deleted records.' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $edge_del ) && ! get_post( $edge_del['request_id'] ), 'A restored backup resurrected deleted records.' );
// A different job that merely reuses the identifier is not touched.
$wpdb->insert( $jobs, array_merge( $ghost, array( 'created_at' => ct_test_old( '-1 day' ), 'status' => 'failed', 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'other@example.com' ) ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $edge_del ), 'A job that is not the deleted one matched the tombstone.' );
$wpdb->delete( $jobs, array( 'job_id' => $edge_del['job_id'] ) );
// A post with the same id but another job id is not deleted either.
$other = wp_insert_post( array( 'import_id' => $six_del['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'unrelated' ) );
update_post_meta( $six_del['request_id'], '_ct_scan_job_id', 999999999 );
ct_scan_maintenance_locked();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted a request that belongs to a different job.' );
wp_delete_post( $six_del['request_id'], true );
// Tombstones expire after the backup window, not before.
$wpdb->update( ct_scan_tombstones_table(), array( 'deleted_at' => ct_test_old( '-100 days' ) ), array( 'job_id' => $edge_del['job_id'] ) );
$wpdb->update( ct_scan_tombstones_table(), array( 'deleted_at' => ct_test_old( '-130 days' ) ), array( 'job_id' => $six_del['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( null !== $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $edge_del['job_id'] ) ), 'A tombstone was purged inside the backup window.' );
ct_test_assert( null === $wpdb->get_var( $wpdb->prepare( 'SELECT job_id FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $six_del['job_id'] ) ), 'A tombstone outlived the backup window.' );

// ---- Narrow preservation holds ---------------------------------------------------------------------------------
$held = ct_test_aged_job( 'ret-held.example.net', 'failed', '-3 years -1 day', '-13 months' );
wp_set_current_user( 0 );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_set_hold( $held['job_id'], 'Preserving records for dispute number 123.', 30 )->get_error_code(), 'An anonymous caller placed a hold.' );
wp_set_current_user( 1 );
foreach ( array( array( 'too short', 30 ), array( str_repeat( 'x', 191 ), 30 ), array( 'Preserving records for dispute number 123.', 0 ), array( 'Preserving records for dispute number 123.', 731 ), array( 'Preserving records for dispute number 123.', 'forever' ), array( 'Preserving records for dispute number 123.', -5 ) ) as $i => $bad ) {
	ct_test_assert( 'hold_invalid' === ct_scan_admin_set_hold( $held['job_id'], $bad[0], $bad[1] )->get_error_code(), "Invalid hold case $i was accepted." );
}
ct_test_assert( true === ct_scan_admin_set_hold( $held['job_id'], '<b>Preserving</b> records for dispute number 123.', 30 ), 'A valid hold was refused.' );
$h = ct_scan_row( $held['job_id'] );
ct_test_assert( 'Preserving records for dispute number 123.' === $h->hold_reason && 1 === (int) $h->hold_set_by && $h->hold_until > ct_scan_utc_now() && $h->hold_until <= ct_test_old( '+31 days' ), 'The hold does not record its purpose, setter and expiry.' );
ct_scan_maintenance_locked();
$h = ct_scan_row( $held['job_id'] );
ct_test_assert( $h && null !== $h->result_json && null !== $h->manual_remainder_notes && get_post( $held['request_id'] ), 'A held job lost records.' );
// Once the hold expires, retention proceeds: both the findings and the evidence are past their dates.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-1 minute' ) ), array( 'job_id' => $held['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $held ) && ! get_post( $held['request_id'] ), 'An expired hold still pinned the record.' );
// Release works; a damaged hold (purpose without expiry) preserves rather than deletes.
$rel = ct_test_aged_job( 'ret-release.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_scan_admin_set_hold( $rel['job_id'], 'Preserving records for dispute number 456.', 10 );
ct_test_assert( true === ct_scan_admin_release_hold( $rel['job_id'] ), 'Release failed.' );
ct_test_assert( null === ct_scan_row( $rel['job_id'] )->hold_reason && null === ct_scan_row( $rel['job_id'] )->hold_until, 'Release left the hold in place.' );
$damaged = ct_test_aged_job( 'ret-damaged.example.net', 'failed', '-3 years -1 day', '-1 day' );
$wpdb->update( $jobs, array( 'hold_reason' => 'Purpose without an expiry (damaged).', 'hold_until' => null ), array( 'job_id' => $damaged['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $rel ) && ct_test_exists( $damaged ), 'Release did not allow deletion, or a damaged hold allowed it.' );
wp_set_current_user( 0 );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_release_hold( $damaged['job_id'] )->get_error_code() && ct_test_exists( $damaged ) && ! empty( ct_scan_row( $damaged['job_id'] )->hold_reason ), 'An anonymous caller released a hold.' );

// Deletion that cannot complete leaves the record (and its tombstone) rather than half-deleting.
$stuck = ct_test_aged_job( 'ret-stuck.example.net', 'failed', '-3 years -1 day', '-1 day' );
$block = static function ( $check, $post ) use ( $stuck ) {
	return (int) $stuck['request_id'] === (int) $post->ID ? false : $check;
};
add_filter( 'pre_delete_post', $block, 10, 2 );
ct_scan_maintenance_locked();
remove_filter( 'pre_delete_post', $block, 10 );
$s = ct_scan_row( $stuck['job_id'] );
ct_test_assert( $s && get_post( $stuck['request_id'] ) && '' === $s->contact_email, 'A failed deletion lost the link between the job and its request.' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $stuck ) && ! get_post( $stuck['request_id'] ), 'The deletion was not completed on the next run.' );

foreach ( $request_ids as $id ) {
	$wpdb->delete( $jobs, array( 'request_id' => $id ), array( '%d' ) );
	wp_delete_post( $id, true );
}
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() );
echo "Retention checks passed.\n";
