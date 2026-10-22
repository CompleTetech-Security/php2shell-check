<?php
/**
 * Closure, retention periods, preservation holds and deletion tombstones. Disposable fixture only.
 */
require __DIR__ . '/support.php';

global $wpdb;
$jobs = ct_scan_jobs_table();
ct_test_purge_fixtures();
// Leftovers of an aborted earlier run of this script.
$wpdb->query( "DELETE FROM {$jobs} WHERE job_id >= 888000000" );
$wpdb->query( 'DELETE FROM ' . ct_scan_tombstones_table() );
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
	$update = array( 'status' => $status, 'terms_accepted_at' => ct_test_old( $accepted ), 'created_at' => ( new DateTimeImmutable( ct_test_old( $accepted ), new DateTimeZone( 'UTC' ) ) )->modify( '+30 seconds' )->format( 'Y-m-d H:i:s' ), 'terms_version' => $version, 'confirmation_token_hash' => null );
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
$six_keep  = ct_test_aged_job( 'ret-six-keep.example.net', 'cancelled', '-6 years -2 days', '-5 years -11 months', '2027-06-01-r3' );
$six_del   = ct_test_aged_job( 'ret-six-del.example.net', 'cancelled', '-6 years -2 days', '-6 years -1 day', '2027-06-01-r3' );
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
update_post_meta( $edge_del['request_id'], '_ct_scan_identity', $stone->identity );
ct_test_assert( 32 === strlen( (string) $stone->identity ), 'The tombstone did not keep the opaque identity.' );
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
// Same id and job id but not the same identity (a recycled id after a restore): untouched.
$six_stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $six_del['job_id'] ) );
update_post_meta( $six_del['request_id'], '_ct_scan_job_id', $six_del['job_id'] );
update_post_meta( $six_del['request_id'], '_ct_scan_identity', str_repeat( 'f', 32 ) );
ct_scan_maintenance_locked();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted a request with a different identity.' );
// Same identity but a live job row now uses that request id: a recycled id must never reach a live record.
update_post_meta( $six_del['request_id'], '_ct_scan_identity', $six_stone->identity );
$wpdb->insert( $jobs, array( 'job_id' => 888000001, 'request_id' => $six_del['request_id'], 'target_origin' => 'https://recycled.example.net/', 'scope_hash' => str_repeat( 'c', 64 ), 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'live@example.com', 'contact_name' => 'Live', 'referrer' => 'direct', 'status' => 'awaiting_confirmation', 'created_at' => ct_test_old( '-1 hour' ) ) );
ct_scan_maintenance_locked();
ct_test_assert( get_post( $six_del['request_id'] ), 'A tombstone deleted the request of a live job that reuses its id.' );
$wpdb->delete( $jobs, array( 'job_id' => 888000001 ) );
// With no live row, a matching identity does delete a restored post, in any post status.
wp_update_post( array( 'ID' => $six_del['request_id'], 'post_status' => 'trash' ) );
ct_scan_maintenance_locked();
ct_test_assert( ! get_post( $six_del['request_id'] ), 'A restored request in the trash was not deleted.' );
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
$subscriber = wp_insert_user( array( 'user_login' => 'ct_ret_sub_' . wp_generate_password( 6, false ), 'user_pass' => wp_generate_password(), 'role' => 'subscriber' ) );
wp_set_current_user( (int) $subscriber );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_set_hold( $held['job_id'], 'Preserving records for dispute number 123.', 30 )->get_error_code() && 'hold_forbidden' === ct_scan_admin_release_hold( $held['job_id'] )->get_error_code(), 'A logged-in non-administrator managed a hold.' );
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
// A hold that just expired still preserves for the grace period, so nothing vanishes the minute it lapses.
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-1 minute' ) ), array( 'job_id' => $held['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $held ) && null !== ct_scan_row( $held['job_id'] )->result_json, 'A hold that expired a minute ago released its records at once.' );
$wpdb->update( $jobs, array( 'hold_until' => ct_test_old( '-4 days' ) ), array( 'job_id' => $held['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $held ) && ! get_post( $held['request_id'] ), 'An expired hold still pinned the record after its grace period.' );
// The tombstone path honours a hold too: a restored row under a hold is kept.
$restore_held = ct_test_aged_job( 'ret-restore-held.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $restore_held ), 'Fixture expected the job to be deleted first.' );
$rstone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $restore_held['job_id'] ) );
$wpdb->insert( $jobs, array( 'job_id' => $restore_held['job_id'], 'request_id' => $restore_held['request_id'], 'target_origin' => 'https://ret-restore-held.example.net/', 'scope_hash' => $rstone->scope_hash, 'terms_version' => '2026-10-21-r2', 'terms_hash' => str_repeat( 'a', 64 ), 'terms_accepted_at' => ct_test_old( '-1 day' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'contact_email' => 'held@example.com', 'contact_name' => 'Held', 'referrer' => 'direct', 'status' => 'failed', 'created_at' => $rstone->created_at, 'hold_reason' => 'Preserving this restored record for a dispute.', 'hold_until' => ct_test_old( '+30 days' ) ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $restore_held ), 'A restored job under a hold was deleted by its tombstone.' );
$wpdb->delete( $jobs, array( 'job_id' => $restore_held['job_id'] ) );

// ---- Untrustworthy dates and doubtful rows are kept, never deleted --------------------------------------------
$zero_r2 = ct_test_aged_job( 'ret-zero-r2.example.net', 'failed', '-3 years -1 day', '-1 hour' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => '0000-00-00 00:00:00', 'closed_at' => null, 'retain_until' => null ), array( 'job_id' => $zero_r2['job_id'] ) );
$zero_new = ct_test_aged_job( 'ret-zero-new.example.net', 'cancelled', '-1 year', '-1 hour', '2027-06-01-r3' );
$wpdb->update( $jobs, array( 'finished_at' => '0000-00-00 00:00:00', 'closed_at' => '0000-00-00 00:00:00', 'retain_until' => null ), array( 'job_id' => $zero_new['job_id'] ) );
$garbled = ct_test_aged_job( 'ret-garbled.example.net', 'failed', '-3 years -1 day', '-1 hour' );
$wpdb->update( $jobs, array( 'terms_accepted_at' => '1999-01-01 00:00:00', 'closed_at' => null, 'retain_until' => null ), array( 'job_id' => $garbled['job_id'] ) );
ct_scan_maintenance_locked();
ct_scan_maintenance_locked();
foreach ( array( $zero_r2, $zero_new, $garbled ) as $case ) {
	$r = ct_scan_row( $case['job_id'] );
	ct_test_assert( $r && null === $r->retain_until && get_post( $case['request_id'] ), 'A job with an untrustworthy date was given a deletion date or deleted.' );
}
ct_test_assert( null !== ct_scan_row( $zero_new['job_id'] )->result_json, 'Findings were cleared on the strength of a zero date.' );
// A stored date earlier than the one derived today, or earlier than three years after creation, is not honoured.
$tampered = ct_test_aged_job( 'ret-tampered.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $tampered ), 'Fixture expected a normal due job to be deleted.' );
$early = ct_test_aged_job( 'ret-early.example.net', 'failed', '-2 years', '-1 day' );
ct_scan_maintenance_locked();
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $early['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $early ) && get_post( $early['request_id'] ), 'A retain_until earlier than three years after creation (or the derived date) deleted the evidence.' );
// The derived-date check alone (the creation floor passes): accepted two years ago, created four years ago.
$early2 = ct_test_aged_job( 'ret-early2.example.net', 'failed', '-2 years', '-1 day' );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-4 years' ) ), array( 'job_id' => $early2['job_id'] ) );
ct_scan_maintenance_locked();
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 day' ) ), array( 'job_id' => $early2['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $early2 ), 'A retain_until earlier than the date derived from the row deleted the evidence.' );
// The creation floor alone: a record created long after its acceptance date is not deleted on that date.
$late_created = ct_test_aged_job( 'ret-late-created.example.net', 'failed', '-3 years -1 day', '-1 day' );
$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-1 day' ) ), array( 'job_id' => $late_created['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $late_created ), 'A record created after its stated acceptance date was deleted on that date.' );
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '+1 year' ) ), array( 'job_id' => $early['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $early ) && ct_scan_row( $early['job_id'] )->retain_until > ct_test_old( '+1 day' ), 'A later stored deletion date was shortened.' );
// A job that can still run is never deleted even if its dates say it is due.
$running = ct_test_aged_job( 'ret-running.example.net', 'awaiting_confirmation', '-3 years -1 day', null );
$wpdb->update( $jobs, array( 'closed_at' => ct_test_old( '-1 day' ), 'retain_until' => ct_test_old( '-1 hour' ), 'authorization_expires_at' => ct_test_old( '+30 days' ), 'confirmation_expires_at' => ct_test_old( '+1 day' ) ), array( 'job_id' => $running['job_id'] ) );
ct_scan_maintenance_locked();
$rr = ct_scan_row( $running['job_id'] );
ct_test_assert( $rr && get_post( $running['request_id'] ) && null === $rr->closed_at && null === $rr->retain_until, 'A job that can still run was deleted, or kept a closure stamp, because its dates said so.' );
// Reopening clears the closure stamp so the old date cannot delete it later.
$reopen = ct_test_aged_job( 'ret-reopen.example.net', 'failed', '-1 day', '-1 hour' );
ct_scan_maintenance_locked();
ct_test_assert( null !== ct_scan_row( $reopen['job_id'] )->retain_until, 'Fixture expected a closed job.' );
$wpdb->update( $jobs, array( 'status' => 'awaiting_confirmation' ), array( 'job_id' => $reopen['job_id'] ) );
ct_scan_maintenance_locked();
$ro = ct_scan_row( $reopen['job_id'] );
ct_test_assert( null === $ro->closed_at && null === $ro->retain_until, 'Reopening a job left its old closure and deletion date.' );
// A terminal job with no finished_at is closed now, not left open.
$nofinish = ct_test_aged_job( 'ret-nofinish.example.net', 'cancelled', '-1 day', null );
ct_scan_maintenance_locked();
ct_test_assert( ! empty( ct_scan_row( $nofinish['job_id'] )->closed_at ), 'A terminal job without finished_at was never closed.' );

// ---- Version rules and period floors ----------------------------------------------------------------------------
foreach ( array( '2026-01-01-r1' => true, '2026-10-21-r1' => true, '2026-10-21-r2' => true, '2026-10-21-r3' => false, '2026-10-22-r1' => false, '2027-06-01-r3' => false, 'weird' => false, '' => false, '2026-10-21-r2 ' => false, '2020-01-01-r9999' => false ) as $version => $legacy ) {
	ct_test_assert( $legacy === ct_scan_is_legacy_version( $version ), "Version '$version' was classified wrongly." );
}
ct_test_assert( 3 === ct_scan_clamp_years( 1 ) && 3 === ct_scan_clamp_years( 0 ) && 3 === ct_scan_clamp_years( 'x' ) && 3 === ct_scan_clamp_years( -6 ) && 3 === ct_scan_clamp_years( null ) && 6 === ct_scan_clamp_years( 6 ) && 10 === ct_scan_clamp_years( '10' ), 'The three-year floor does not hold.' );
$old_version = ct_test_aged_job( 'ret-old-version.example.net', 'failed', '-2 years', '-1 day', '2026-01-01-r1' );
$weird_version = ct_test_aged_job( 'ret-weird-version.example.net', 'failed', '-2 years', '-1 day', 'weird' );
ct_scan_maintenance_locked();
$ov = ct_scan_row( $old_version['job_id'] );
$wv = ct_scan_row( $weird_version['job_id'] );
ct_test_assert( $ov->retain_until === ( new DateTimeImmutable( $ov->terms_accepted_at, new DateTimeZone( 'UTC' ) ) )->modify( '+3 years' )->format( 'Y-m-d H:i:s' ), 'A pre-r2 acceptance is not kept three years from acceptance.' );
ct_test_assert( $wv->retain_until === ( new DateTimeImmutable( $wv->closed_at, new DateTimeZone( 'UTC' ) ) )->modify( '+6 years' )->format( 'Y-m-d H:i:s' ), 'An unrecognised version did not get the longer period.' );

// ---- Deleting in any post status; bounded work per run ----------------------------------------------------------
$trashed = ct_test_aged_job( 'ret-trashed.example.net', 'failed', '-3 years -1 day', '-1 day' );
wp_update_post( array( 'ID' => $trashed['request_id'], 'post_status' => 'trash' ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $trashed ) && ! get_post( $trashed['request_id'] ), 'A trashed request (with the contact details and contract) outlived its deleted job.' );
$batch = array();
for ( $i = 0; $i < 53; $i++ ) {
	$batch[] = ct_test_aged_job( "ret-batch-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
}
ct_scan_maintenance_locked();
$remaining = count( array_filter( $batch, 'ct_test_exists' ) );
ct_test_assert( $remaining >= 3 && $remaining < 53, "A single run did not bound its deletions ($remaining of 53 remain)." );
ct_scan_maintenance_locked();
ct_scan_maintenance_locked();
ct_test_assert( 0 === count( array_filter( $batch, 'ct_test_exists' ) ), 'The remaining due jobs were not deleted on later runs.' );

// Release works; a damaged hold (purpose without expiry) preserves rather than deletes.
$rel = ct_test_aged_job( 'ret-release.example.net', 'failed', '-3 years -1 day', '-1 day' );
ct_scan_admin_set_hold( $rel['job_id'], 'Preserving records for dispute number 456.', 10 );
ct_test_assert( true === ct_scan_admin_release_hold( $rel['job_id'] ), 'Release failed.' );
$released = ct_scan_row( $rel['job_id'] );
ct_test_assert( null === $released->hold_reason && null === $released->hold_until && 1 === (int) $released->hold_released_by && ! empty( $released->hold_released_at ), 'Release left the hold in place or did not record who released it.' );
ct_test_assert( 'hold_unavailable' === ct_scan_admin_release_hold( $rel['job_id'] )->get_error_code() && 'hold_unavailable' === ct_scan_admin_release_hold( 999999999 )->get_error_code() && 'hold_unavailable' === ct_scan_admin_release_hold( 0 )->get_error_code(), 'Releasing a hold that does not exist reported success.' );
$damaged = ct_test_aged_job( 'ret-damaged.example.net', 'failed', '-3 years -1 day', '-1 day' );
$wpdb->update( $jobs, array( 'hold_reason' => 'Purpose without an expiry (damaged).', 'hold_until' => null ), array( 'job_id' => $damaged['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $rel ) && ct_test_exists( $damaged ), 'Release did not allow deletion, or a damaged hold allowed it.' );
wp_set_current_user( 0 );
ct_test_assert( 'hold_forbidden' === ct_scan_admin_release_hold( $damaged['job_id'] )->get_error_code() && ct_test_exists( $damaged ) && ! empty( ct_scan_row( $damaged['job_id'] )->hold_reason ), 'An anonymous caller released a hold.' );


// ---- Second review: no starvation, identity backfill, damaged holds, far-future dates ---------------------------
// Doubtful rows (a deletion date a year short of the floor) are judged once a day and cannot hide a due job.
$doubtful = array();
for ( $i = 0; $i < 52; $i++ ) {
	$d = ct_test_aged_job( "ret-doubtful-$i.example.net", 'failed', '-3 years -1 day', '-1 day' );
	$wpdb->update( $jobs, array( 'created_at' => ct_test_old( '-1 day' ) ), array( 'job_id' => $d['job_id'] ) );
	$doubtful[] = $d;
}
$due_behind = ct_test_aged_job( 'ret-behind-doubtful.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 year' ) ), array( 'job_id' => $due_behind['job_id'] ) ); // sorts first, but is itself doubtful
// Due only after all the doubtful rows in date order (so a 50-row window would never reach it).
$really_due = ct_test_aged_job( 'ret-really-due.example.net', 'failed', '-3 years -2 hours', '-1 hour' );
for ( $run = 0; $run < 3; $run++ ) {
	ct_scan_maintenance_locked();
}
ct_test_assert( ! ct_test_exists( $really_due ), 'Doubtful rows starved a due job.' );
ct_test_assert( 52 === count( array_filter( $doubtful, 'ct_test_exists' ) ) && ct_test_exists( $due_behind ), 'Doubtful rows were deleted.' );
ct_test_assert( ! empty( ct_scan_row( $doubtful[0]['job_id'] )->retention_checked_at ), 'A doubtful row was not marked as examined.' );
foreach ( array_merge( $doubtful, array( $due_behind ) ) as $d ) {
	$wpdb->delete( $jobs, array( 'job_id' => $d['job_id'] ) );
	wp_delete_post( $d['request_id'], true );
}

// A job from before the identity existed gets one (adopting what its request carries), so a restore can be recognised.
$legacy = ct_test_aged_job( 'ret-preidentity.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'identity' => null, 'retain_until' => ct_test_old( '+1 day' ) ), array( 'job_id' => $legacy['job_id'] ) );
delete_post_meta( $legacy['request_id'], '_ct_scan_identity' );
ct_scan_maintenance_locked();
$identity = ct_scan_row( $legacy['job_id'] )->identity;
ct_test_assert( 1 === preg_match( '/\A[a-f0-9]{32}\z/', (string) $identity ) && $identity === ct_scan_meta_string( $legacy['request_id'], '_ct_scan_identity' ), 'A job without an identity was not given one together with its request.' );
$carried = ct_test_aged_job( 'ret-carried.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'identity' => null, 'retain_until' => ct_test_old( '+1 day' ) ), array( 'job_id' => $carried['job_id'] ) );
update_post_meta( $carried['request_id'], '_ct_scan_identity', str_repeat( 'a', 32 ) );
ct_scan_maintenance_locked();
ct_test_assert( str_repeat( 'a', 32 ) === ct_scan_row( $carried['job_id'] )->identity && str_repeat( 'a', 32 ) === ct_scan_meta_string( $carried['request_id'], '_ct_scan_identity' ), 'An identity the request already carried was replaced.' );
// Then delete it and restore the post: it is recognised and deleted again.
$wpdb->update( $jobs, array( 'retain_until' => ct_test_old( '-1 hour' ) ), array( 'job_id' => $legacy['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $legacy ) && ! get_post( $legacy['request_id'] ), 'Fixture expected the pre-identity job to be deleted.' );
wp_insert_post( array( 'import_id' => $legacy['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $legacy['request_id'], '_ct_scan_job_id', $legacy['job_id'] );
update_post_meta( $legacy['request_id'], '_ct_scan_identity', $identity );
ct_scan_maintenance_locked();
ct_test_assert( ! get_post( $legacy['request_id'] ), 'The restored request of a pre-identity job was not deleted again.' );
// The duplicate-event path restores the identity meta of a request that lost it.
list( $dup_id, $dup_fields ) = ct_test_request( 'ret-dup.example.net' );
$request_ids[] = $dup_id;
$dup_event = ct_scan_on_request_ready( $dup_id, $dup_fields );
$dup_identity = ct_scan_row( $dup_event['job_id'] )->identity;
ct_test_assert( 1 === preg_match( '/\A[a-f0-9]{32}\z/', (string) $dup_identity ) && $dup_identity === ct_scan_meta_string( $dup_id, '_ct_scan_identity' ), 'A new job does not carry its identity on the request.' );
delete_post_meta( $dup_id, '_ct_scan_identity' );
delete_post_meta( $dup_id, '_ct_scan_event_recorded' );
ct_scan_on_request_ready( $dup_id, $dup_fields );
ct_test_assert( $dup_identity === ct_scan_meta_string( $dup_id, '_ct_scan_identity' ), 'The duplicate-event path left the request without its identity.' );

// A damaged hold (zero expiry) also protects the findings.
$zero_hold = ct_test_aged_job( 'ret-zero-hold.example.net', 'completed', '-2 years', '-13 months' );
$wpdb->update( $jobs, array( 'hold_reason' => 'Preserving for a dispute (damaged expiry).', 'hold_until' => '0000-00-00 00:00:00' ), array( 'job_id' => $zero_hold['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( null !== ct_scan_row( $zero_hold['job_id'] )->result_json, 'A hold with a zero expiry did not protect the findings.' );

// A far-future creation date does not defeat the creation floor.
$future = ct_test_aged_job( 'ret-future.example.net', 'failed', '-3 years -2 days', '-2 days' );
$wpdb->update( $jobs, array( 'created_at' => '9999-01-01 00:00:00' ), array( 'job_id' => $future['job_id'] ) );
ct_scan_maintenance_locked();
ct_test_assert( ct_test_exists( $future ) && ! ct_scan_valid_datetime( '9999-01-01 00:00:00' ) && ! ct_scan_valid_datetime( '10000-01-01 00:00:00' ), 'A far-future date was accepted.' );

// A restored request hidden behind many newer tombstones that point at live records is still found.
$buried = ct_test_aged_job( 'ret-buried.example.net', 'failed', '-3 years -2 days', '-2 days' );
ct_scan_maintenance_locked();
ct_test_assert( ! ct_test_exists( $buried ), 'Fixture expected the buried job to be deleted.' );
$buried_stone = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . ct_scan_tombstones_table() . ' WHERE job_id = %d', $buried['job_id'] ) );
for ( $i = 0; $i < 55; $i++ ) {
	$wpdb->insert( ct_scan_tombstones_table(), array( 'job_id' => 770000000 + $i, 'request_id' => 780000000 + $i, 'scope_hash' => str_repeat( 'd', 64 ), 'created_at' => ct_test_old( '-1 hour' ), 'deleted_at' => ct_test_old( '-1 minute' ), 'reason' => 'retention', 'identity' => bin2hex( random_bytes( 16 ) ) ) );
}
wp_insert_post( array( 'import_id' => $buried['request_id'], 'post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'Integration fixture request', 'post_content' => 'restored' ) );
update_post_meta( $buried['request_id'], '_ct_scan_job_id', $buried['job_id'] );
update_post_meta( $buried['request_id'], '_ct_scan_identity', $buried_stone->identity );
ct_scan_maintenance_locked();
ct_test_assert( ! get_post( $buried['request_id'] ), 'Newer tombstones hid a restored request from cleanup.' );

wp_set_current_user( 1 );
// Placing a new hold clears the audit of an earlier release.
$reheld = ct_test_aged_job( 'ret-reheld.example.net', 'failed', '-1 day', '-1 hour' );
ct_scan_admin_set_hold( $reheld['job_id'], 'First preservation purpose for this job.', 10 );
ct_scan_admin_release_hold( $reheld['job_id'] );
ct_scan_admin_set_hold( $reheld['job_id'], 'Second preservation purpose for this job.', 10 );
$rh = ct_scan_row( $reheld['job_id'] );
ct_test_assert( null === $rh->hold_released_by && null === $rh->hold_released_at && 'Second preservation purpose for this job.' === $rh->hold_reason, 'A new hold kept the audit of an earlier release.' );

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
