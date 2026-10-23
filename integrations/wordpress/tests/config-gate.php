<?php
/** Prints whether the integration is enabled under the environment-selected configuration. */
require __DIR__ . '/support.php';
echo ct_scan_enabled() ? "enabled\n" : "refused\n";
