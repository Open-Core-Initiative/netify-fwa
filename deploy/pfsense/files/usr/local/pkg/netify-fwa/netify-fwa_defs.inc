<?php
/*
 * netify-fwa_defs.inc
 *
 * Netify FWA for pfSense
 * Copyright (C) 2015-2019 eGloo Incorporated
 *
 * This program comes with ABSOLUTELY NO WARRANTY.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions according to the GNU General Public
 * License version 3, or (at your option) any later version.
 */

if (! defined('NETIFY_FWA_PREFIX'))
	define('NETIFY_FWA_PREFIX', '/usr/local/');

if (! defined('NETIFY_FWA_SBINDIR'))
	define('NETIFY_FWA_SBINDIR', NETIFY_FWA_PREFIX . 'sbin/');

if (! defined('NETIFY_FWA_CONFDIR'))
	define('NETIFY_FWA_CONFDIR', NETIFY_FWA_PREFIX . 'etc/netify-fwa/');

if (! defined('NETIFY_FWA_VOLATILE_STATEDIR'))
	define('NETIFY_FWA_VOLATILE_STATEDIR', '/var/run/netify-fwa/');

if (! defined('NETIFY_FWA_VERSION')) {
//	$version = exec_command(NETIFY_FWA_SBINDIR .
//		'netify-fwa --version 2>&1 | head -n 1 | cut -d\' \' -f2 | cut -d \'/\' -f2');
//	define('NETIFY_FWA_VERSION', $version);
	define('NETIFY_FWA_VERSION', '1.0.0.');
}

if (! define('NETIFY_FWA_JSON_STATUS'))
	define('NETIFY_FWA_JSON_STATUS', NETIFY_FWA_VOLATILE_STATEDIR . '/status.json');
?>