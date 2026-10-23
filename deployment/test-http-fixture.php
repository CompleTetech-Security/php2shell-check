<?php
// CLI-only, disposable Docker fixture for testing the real HTTP boundary.
if (PHP_SAPI !== 'cli' || getenv('WORDPRESS_DB_PASSWORD') !== 'fixture-only' || getenv('WORDPRESS_DB_HOST') !== 'db') {
    exit(1);
}
$mode = $argv[1] ?? 'status';
$private = '/var/www/html/wp-content/ct-scan-private';
if ('setup' === $mode) {
    if (!is_dir($private)) { mkdir($private, 0700); }
    file_put_contents($private . '/.htaccess', "Require all denied\n");
    file_put_contents($private . '/config.php', '<?php return ' . var_export(array(
        'enabled' => true,
        'egress_enforced' => true, // disposable fixture: no network beyond the test network
        'terms_policy' => array('2026-10-21-r2' => 'legacy'),
        'worker_hmac_secret' => str_repeat('fixture-', 8),
        'expected_checker_revision' => str_repeat('a', 40),
        'authorization_end_at' => gmdate('Y-m-d\TH:i:s\Z', time() + 86400 * 30),
        'global_daily_limit' => 1000,
        'target_daily_limit' => 10,
    ), true) . ';');
    chmod($private . '/config.php', 0600);
    foreach (array($private, $private . '/config.php', $private . '/.htaccess') as $path) {
        chown($path, 'www-data');
        chgrp($path, 'www-data');
    }
}
$_SERVER['HTTP_HOST'] = 'wordpress';
require '/var/www/html/wp-load.php';
$state_file = '/tmp/ct-http-fixture.json';
global $wpdb;
if ('setup' === $mode) {
    register_post_type('ct_promo_request', array('public' => false));
    $fields = array('target' => 'https://http-fixture.example.com/', 'email' => 'fixture@example.com', 'name' => 'HTTP Fixture', 'referrer' => 'direct');
    $contract = "Client contact: HTTP Fixture\nClient email: fixture@example.com\nWebsite (scan scope): {$fields['target']}\nReferred by: direct\nTerms version: 2026-10-21-r2\nSynthetic fixture only.";
    $id = wp_insert_post(array('post_type' => 'ct_promo_request', 'post_status' => 'private', 'post_title' => 'HTTP fixture', 'post_content' => $contract));
    foreach (array('target', 'email', 'name') as $key) { update_post_meta($id, '_ct_scan_' . $key, $fields[$key]); }
    update_post_meta($id, '_ct_ref', 'direct');
    foreach (array('saved' => '1', 'version' => '2026-10-21-r2', 'url' => 'http://wordpress/terms/', 'sha256' => hash('sha256', $contract), 'accepted_at' => gmdate('Y-m-d\TH:i:s\Z'), 'contract' => $contract, 'ip' => '192.0.2.1', 'remote_addr' => '192.0.2.1', 'user_agent' => 'Local HTTP fixture') as $key => $value) {
        update_post_meta($id, '_ct_terms_' . $key, wp_slash($value));
    }
    $token = '';
    add_filter('pre_wp_mail', static function ($return, $mail) use (&$token) {
        if (preg_match('/token=([a-f0-9]{64})/', $mail['message'], $match)) { $token = $match[1]; }
        return true;
    }, 10, 2);
    $result = ct_scan_on_request_ready($id, $fields);
    if (is_wp_error($result) || !$token) { throw new RuntimeException('Fixture enqueue failed'); }
    $state = array('request_id' => $id, 'job_id' => $result['job_id'], 'token' => $token);
    file_put_contents($state_file, json_encode($state));
    echo json_encode($state) . "\n";
} else {
    $state = json_decode(file_get_contents($state_file), true);
    $row = ct_scan_row($state['job_id']);
    if ('cleanup' === $mode) {
        $wpdb->delete(ct_scan_jobs_table(), array('job_id' => $state['job_id']));
        wp_delete_post($state['request_id'], true);
        unlink($state_file);
        unlink($private . '/config.php');
        echo "HTTP fixture removed.\n";
    } else {
        echo json_encode(array('status' => $row->status, 'attempts' => (int)$row->attempts, 'result' => $row->result_json ? json_decode($row->result_json, true) : null)) . "\n";
    }
}
