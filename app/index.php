<?php
/**
 * php2shell lab target.
 *
 * This file is deliberately trivial. There is no session_start(), no upload
 * handling, no include, no unserialize(), no database and no third-party code.
 * The exploit does not touch this file: it runs inside PHP's request startup,
 * before the script is compiled or executed.
 *
 * If you find yourself editing this file to "make the exploit work", the lab
 * has been misunderstood. The moving parts are php.ini, apache/prefork-single.conf
 * and the pinned PHP version in the Dockerfile.
 */

header('Content-Type: text/plain; charset=utf-8');
echo "php2shell lab target\n";
echo 'php_version=' . PHP_VERSION . "\n";
echo "the script executed\n";
