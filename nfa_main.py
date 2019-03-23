#!/usr/bin/python3 -Es

# Netify Firewall Agent
# Copyright (C) 2019 eGloo Incorporated <http://www.egloo.ca>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import json
import socket
import errno
import time
import os.path

from getopt import getopt, GetoptError

from signal import \
    signal, Signals, SIGHUP, SIGINT, SIGTERM

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_config
import nfa_daemonize
import nfa_netifyd
import nfa_task
import nfa_ipset

from nfa_version import NFA_VERSION

__nfa_debug = False

__nfa_pid_file = '/var/run/netify-fwa/netify-fwa.pid'

__nfa_fw = None
__nfa_fw_interfaces = { "internal": [], "external": [] }

__nfa_config_reload = True
__nfa_should_terminate = False

__nfa_config = None
__nfa_config_dynamic = None
__nfa_config_cat_cache = None

__nfa_log_options = LOG_PID | LOG_PERROR

def nfa_signal_handler(signum, frame):
    global __nfa_config_reload, __nfa_should_terminate

    if isinstance(SIGHUP, int):
        signo_HUP = SIGHUP
        signo_INT = SIGINT
        signo_TERM = SIGTERM
    else:
        signo_HUP = SIGHUP.value
        signo_INT = SIGINT.value
        signo_TERM = SIGTERM.value

    if signum == signo_HUP:
        __nfa_config_reload = True
    elif signum == signo_INT or signum == signo_TERM:
        syslog(LOG_WARNING, "Exiting...")
        __nfa_should_terminate = True
    else:
        syslog(LOG_WARNING,
            "Caught unhandled signal: %s" %(Signals(signum).name))

def nfa_config_load():
    global __nfa_config

    __nfa_config = nfa_config.load_main('/etc/netify-fwa/netify-fwa.ini')

def nfa_config_reload():
    global __nfa_config_reload
    global __nfa_config_dynamic

    config_dynamic = __nfa_config.get('netify-fwa', 'path-config-dynamic')

    if os.path.isfile(config_dynamic):

        config = nfa_config.load_dynamic(config_dynamic)
        if config is not None:
            __nfa_config_dynamic = config
            syslog("Loaded dynamic configuration.")

        if __nfa_config_dynamic is not None:
            __nfa_config_reload = False

def nfa_cat_cache_refresh(config_cat_cache, ttl_cat_cache):
    if not os.path.isfile(config_cat_cache) or \
        int(os.path.getmtime(config_cat_cache)) + int(ttl_cat_cache) < int(time.time()):

        syslog(LOG_DEBUG, "Updating category cache...")

        task_cat_update = nfa_task.cat_update(__nfa_config)
        task_cat_update.start()

        return task_cat_update

    return None

def nfa_cat_cache_reload(config_cat_cache, task_cat_update):
    global __nfa_config_cat_cache

    if not task_cat_update.is_alive():

        task_cat_update.join()

        if not task_cat_update.exit_success:
            syslog(LOG_DEBUG, "Failed to update category cache.")
            os.remove(config_cat_cache)
        else:
            cat_cache = nfa_config.load_cat_cache(config_cat_cache)

            if cat_cache is not None:
                syslog("Reloaded category cache.")
                __nfa_config_cat_cache = cat_cache

        return None

    return task_cat_update

def nfa_fw_init():
    global __nfa_fw, __nfa_fw_interfaces

    try:
        fw_engine = __nfa_config.get('netify-fwa', 'firewall-engine')
    except NoOptionError as e:
        printf("Mandatory configuration option not set: firewall-engine")
        return False

    if fw_engine == 'iptables':
        from nfa_iptables import nfa_firewall
    elif fw_engine == 'firewalld':
        from nfa_firewalld import nfa_firewall
    else:
        print("Unsupported firewall engine: %s" %(fw_engine))
        return False

    __nfa_fw = nfa_firewall()

    if fw_engine == 'firewalld':
        # XXX: Have to open syslog again because the firewalld client code
        # is rude and does some of it's own syslog initialization.
        openlog('netify-fwa', __nfa_log_options, LOG_DAEMON)

    syslog("Firewall engine: %s" %(__nfa_fw.get_version()))

    if not __nfa_fw.is_running():
        syslog(LOG_ERR, "Firewall engine is not running.")
        return False

    #__nfa_fw.test()

    # Get interfaces by role
    __nfa_fw_interfaces['external'].extend(
        __nfa_fw.get_external_interfaces(__nfa_config)
    )
    __nfa_fw_interfaces['internal'].extend(
        __nfa_fw.get_internal_interfaces(__nfa_config)
    )

    if len(__nfa_fw_interfaces['external']) == 0 and \
        len(__nfa_fw_interfaces['internal']) == 0:
        syslog(LOG_ERR, "No interface roles defined.")
        return False

    # Create whitelist chain
    __nfa_fw.add_chain('mangle', 'NFA_whitelist')
    __nfa_fw.add_chain('mangle', 'NFA_whitelist', 6)

    # Add jumps to whitelist chain
    __nfa_fw.add_rule('mangle', 'FORWARD', '-j NFA_whitelist')
    __nfa_fw.add_rule('mangle', 'FORWARD', '-j NFA_whitelist', 6)

    # Create ingress/egress chains
    __nfa_fw.add_chain('mangle', 'NFA_ingress')
    __nfa_fw.add_chain('mangle', 'NFA_ingress', 6)
    __nfa_fw.add_chain('mangle', 'NFA_egress')
    __nfa_fw.add_chain('mangle', 'NFA_egress', 6)

    # Add jumps to ingress/egress chains
    for iface in __nfa_fw_interfaces['external']:
        __nfa_fw.add_rule('mangle', 'FORWARD', '-i %s -j NFA_ingress' %(iface))
        __nfa_fw.add_rule('mangle', 'FORWARD', '-i %s -j NFA_ingress' %(iface), 6)
    for iface in __nfa_fw_interfaces['internal']:
        __nfa_fw.add_rule('mangle', 'FORWARD', '-i %s -j NFA_egress' %(iface))
        __nfa_fw.add_rule('mangle', 'FORWARD', '-i %s -j NFA_egress' %(iface), 6)

    return True

def nfa_fw_cleanup():
    __nfa_fw.delete_rule('mangle', 'FORWARD', '-j NFA_whitelist')
    __nfa_fw.delete_rule('mangle', 'FORWARD', '-j NFA_whitelist', 6)

    for iface in __nfa_fw_interfaces['external']:
        __nfa_fw.delete_rule('mangle', 'FORWARD', '-i %s -j NFA_ingress' %(iface))
        __nfa_fw.delete_rule('mangle', 'FORWARD', '-i %s -j NFA_ingress' %(iface), 6)
    for iface in __nfa_fw_interfaces['internal']:
        __nfa_fw.delete_rule('mangle', 'FORWARD', '-i %s -j NFA_egress' %(iface))
        __nfa_fw.delete_rule('mangle', 'FORWARD', '-i %s -j NFA_egress' %(iface), 6)

    __nfa_fw.delete_chain('mangle', 'NFA_whitelist')
    __nfa_fw.delete_chain('mangle', 'NFA_whitelist', 6)

    __nfa_fw.delete_chain('mangle', 'NFA_ingress')
    __nfa_fw.delete_chain('mangle', 'NFA_ingress', 6)
    __nfa_fw.delete_chain('mangle', 'NFA_egress')
    __nfa_fw.delete_chain('mangle', 'NFA_egress', 6)

    for i in nfa_ipset.nfa_ipset_list():
        ipset = nfa_ipset.nfa_ipset(i)
        ipset.destroy()

def nfa_fw_sync():
    if __nfa_config_dynamic is None:
        return

    ipsets = nfa_ipset.nfa_ipset_list()

def nfa_process_flow(flow):
    # syslog(LOG_DEBUG, str(flow))
    # {'flow': {'ip_nat': False, 'other_ip': '35.182.46.62', 'local_port': 47948, 'other_port': 443, 'local_origin': True, 'detected_protocol': 91, 'ip_version': 4, 'local_ip': '192.168.100.2', 'first_seen_at': 1553313050091, 'detected_protocol_name': 'SSL', 'detection_guessed': 0, 'other_mac': '1a:f8:43:32:1f:c7', 'ip_protocol': 6, 'detected_application_name': 'netify.netify', 'digest': '97efb33a180bbca8435aa32295afc15a06aa5987', 'local_mac': 'f6:97:f1:30:8a:f3', 'detected_application': 275, 'last_seen_at': 1553313050202, 'vlan_id': 0, 'other_type': 'remote', 'ssl': {'client': 'sink.netify.ai', 'version': '0x0303', 'cipher_suite': '0xc030'}}, 'type': 'flow', 'internal': False, 'interface': 'host0'}
    pass

def nfa_create_daemon():
    try:
        nfa_daemonize.create(
            pid_file=__nfa_pid_file,
            debug=__nfa_debug
        )
    except BlockingIOError as e:
        if e.errno == errno.EAGAIN or e.errno == errno.EACCESS:
            syslog(LOG_ERR, "An instance is already running.")
        else:
            syslog(LOG_ERR, "Error starting daemon: %d" %(e.errno))
        return False

    return True

def nfa_main():
    global __nfa_config_reload
    global __nfa_config, __nfa_config_dynamic, __nfa_config_cat_cache

    nfa_fw_init()

    fh = None
    nd = nfa_netifyd.netifyd()

    task_cat_cache_update = None

    config_cat_cache = __nfa_config.get('netify-api', 'path-category-cache')
    ttl_cat_cache = __nfa_config.get('netify-api', 'ttl-category-cache')

    if os.path.isfile(config_cat_cache):
        __nfa_config_cat_cache = nfa_config.load_cat_cache(config_cat_cache)

    #ipset = nfa_ipset.nfa_ipset('NFA_test', 60, 6)

    #result = ipset.destroy()
    #syslog(LOG_DEBUG, "ipset destroy: %s" %(result))
    #nfa_ipset.nfa_ipset_list()

    #result = ipset.create()
    #syslog(LOG_DEBUG, "ipset create: %s" %(result))
    #nfa_ipset.nfa_ipset_list()

    #result = ipset.upsert('8.8.8.8', 6, 80, '192.168.100.100')
    #result = ipset.upsert('fe80::d685:64ff:fe77:354a', 6, 80, 'fe80::d685:64ff:fe77:354b')
    #syslog(LOG_DEBUG, "ipset add: %s" %(result))

    while not __nfa_should_terminate:

        if __nfa_config_reload: nfa_config_reload()

        if task_cat_cache_update is None:
            task_cat_cache_update = nfa_cat_cache_refresh(config_cat_cache, ttl_cat_cache)

        if task_cat_cache_update is not None:
            task_cat_cache_update = nfa_cat_cache_reload(config_cat_cache, task_cat_cache_update)

        if fh is None:
            fh = nd.connect(
                __nfa_config.get('netify-agent', 'socket-uri')
            )
        else:
            jd = nd.read()

            if jd is None:
                nd.close()
                fh = None
                time.sleep(5)
                continue

            if jd['type'] == 'flow':
                nfa_process_flow(jd)

    nd.close()
    nfa_fw_cleanup()

    return 0

if __name__ == "__main__":

    openlog('netify-fwa', __nfa_log_options, LOG_DAEMON)
    syslog("Netify FWA v%s started." %(NFA_VERSION))

    nfa_config_load()

    try:
        params, args = getopt(sys.argv[1:], 'd', ('debug','help'))
    except GetoptError as e:
        print("Parameter error: %s" %(e.msg))
        print("Try option --help for usage information.")
        sys.exit(1)

    for option in params:
        if option[0] == '-d' or option[0] == '--debug':
            __nfa_debug = True
        elif option[0] == '--help':
            print("Netify FWA v%s" %(NFA_VERSION))
            sys.exit(0)

    if not __nfa_debug:
        __nfa_log_options = LOG_PID
        openlog('netify-fwa', __nfa_log_options, LOG_DAEMON)
        if not nfa_create_daemon():
            sys.exit(1)

    signal(SIGHUP, nfa_signal_handler)
    signal(SIGINT, nfa_signal_handler)
    signal(SIGTERM, nfa_signal_handler)

    sys.exit(nfa_main())
