<?php
// Preserve hardened deployment settings, including behind TLS proxies. Maintainer: Uli Schäffler.
putenv('MARKYDOWN_ALLOW_ADVANCED_SELECTORS=0');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_only_cookies', '0');
ini_set('session.use_trans_sid', '1');
require __DIR__ . '/../../index.php';
