<?php
/** Test helper: one maintenance pass (state transitions, then retention) under the environment's retention config. */
require __DIR__ . '/support.php';
ct_test_maintain();
echo "maintained\n";
