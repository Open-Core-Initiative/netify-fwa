<?php
/*
 * netify-fwa.inc
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

require_once("config.inc");
require_once("pfsense-utils.inc");
require_once("util.inc");
require_once('services.inc');
require_once("service-utils.inc");

require_once("/usr/local/pkg/netify-fwa/netify-fwa_defs.inc");

function netify_fwa_create_rc() {
	$rcfile['file'] = 'netify-fwa.sh';
	$rcfile['start'] = 'mkdir -p ' .
		NETIFY_FWA_VOLATILE_STATEDIR . "\n\t" .
		NETIFY_FWA_PREFIX . "etc/rc.d/netify-fwa onestart\n\t";
	$rcfile['stop'] = NETIFY_FWA_PREFIX . "etc/rc.d/netify-fwa onestop\n\t";
	write_rcfile($rcfile);
}

function netify_fwa_make_directories() {
	safe_mkdir(NETIFY_FWA_VOLATILE_STATEDIR);
}

function netify_fwa_is_running() {
       return isvalidpid(NETIFY_FWA_VOLATILE_STATEDIR . 'netify-fwa.pid');
}

function netify_fwa_generate_filter_rules($type) {
	return "anchor \"nfa/*\" all\n";
}

function netify_fwa_package_sync() {
	netify_fwa_make_directories();
	netify_fwa_create_rc();
}

function netify_fwa_package_install() {
	netify_fwa_create_rc();
}

function netify_fwa_package_deinstall() {
}
?>
