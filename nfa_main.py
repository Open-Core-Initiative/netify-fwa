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
import re

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

__nfa_ipsets = None

__nfa_config = None
__nfa_config_dynamic = None
__nfa_config_cat_cache = None

__nfa_log_options = LOG_PID | LOG_PERROR

__nfa_rx_app_id = None

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

def nfa_rule_criteria(rule):
    criteria = []
    if 'protocol' in rule:
        criteria.append(str(rule['protocol']))
    if 'protocol_category' in rule:
        criteria.append(str(rule['protocol_category']))
    if 'application' in rule:
        criteria.append(str(rule['application']))
    if 'application_category' in rule:
        criteria.append(str(rule['application_category']))

    return '_'.join(criteria)

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

    mark_base = int(__nfa_config.get('netify-fwa', 'mark-base'), 16)
    mark_mask = int(__nfa_config.get('netify-fwa', 'mark-mask'), 16)

    # Create whitelist chain
    for ipv in [4, 6]:
        __nfa_fw.add_chain('mangle', 'NFA_whitelist', ipv)

        # Add jumps to whitelist chain
        __nfa_fw.add_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

        # Create ingress/egress chains
        __nfa_fw.add_chain('mangle', 'NFA_ingress', ipv)
        __nfa_fw.add_chain('mangle', 'NFA_egress', ipv)

        # Add jumps to ingress/egress chains
        for iface in __nfa_fw_interfaces['external']:
            __nfa_fw.add_rule('mangle', 'FORWARD',
                '-i %s -j NFA_ingress' %(iface), ipv)
        for iface in __nfa_fw_interfaces['internal']:
            __nfa_fw.add_rule('mangle', 'FORWARD',
                '-i %s -j NFA_egress' %(iface), ipv)

        # Create block chain
        __nfa_fw.add_chain('mangle', 'NFA_block', ipv)

        __nfa_fw.add_rule('mangle', 'NFA_block', '-j DROP', ipv)

        # Add jumps to block chain
        __nfa_fw.add_rule('mangle', 'FORWARD',
            '-m mark --mark 0x%08x/0x%08x -j NFA_block' %(mark_base, mark_mask), ipv)

    return True

def nfa_fw_cleanup():
    mark_base = int(__nfa_config.get('netify-fwa', 'mark-base'), 16)
    mark_mask = int(__nfa_config.get('netify-fwa', 'mark-mask'), 16)

    for ipv in [4, 6]:
        __nfa_fw.delete_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

        for iface in __nfa_fw_interfaces['external']:
            __nfa_fw.delete_rule('mangle', 'FORWARD',
                '-i %s -j NFA_ingress' %(iface), ipv)
        for iface in __nfa_fw_interfaces['internal']:
            __nfa_fw.delete_rule('mangle', 'FORWARD',
                '-i %s -j NFA_egress' %(iface), ipv)

        __nfa_fw.flush_chain('mangle', 'NFA_whitelist', ipv)
        __nfa_fw.delete_chain('mangle', 'NFA_whitelist', ipv)

        __nfa_fw.flush_chain('mangle', 'NFA_ingress', ipv)
        __nfa_fw.delete_chain('mangle', 'NFA_ingress', ipv)

        __nfa_fw.flush_chain('mangle', 'NFA_egress', ipv)
        __nfa_fw.delete_chain('mangle', 'NFA_egress', ipv)


        __nfa_fw.delete_rule('mangle', 'FORWARD',
            '-m mark --mark 0x%08x/0x%08x -j NFA_block' %(mark_base, mark_mask), ipv)

        __nfa_fw.flush_chain('mangle', 'NFA_block', ipv)
        __nfa_fw.delete_chain('mangle', 'NFA_block', ipv)

    for name in nfa_ipset.nfa_ipset_list():
        nfa_ipset.nfa_ipset_destroy(name)

def nfa_fw_sync():
    global __nfa_ipsets

    if __nfa_config_dynamic is None:
        return

    for ipv in [4, 6]:
        __nfa_fw.flush_chain('mangle', 'NFA_whitelist', ipv)
        __nfa_fw.flush_chain('mangle', 'NFA_ingress', ipv)
        __nfa_fw.flush_chain('mangle', 'NFA_egress', ipv)

    ttl_match = int(__nfa_config.get('netify-fwa', 'ttl-match'))
    mark_base = int(__nfa_config.get('netify-fwa', 'mark-base'), 16)

    ipsets_new = []
    ipsets_created = []
    ipsets_existing = nfa_ipset.nfa_ipset_list()

    for rule in __nfa_config_dynamic['rules']:
        if rule['type'] != 'block': continue

        name = nfa_rule_criteria(rule)

        for ipv in [4, 6]:
            ipset = nfa_ipset.nfa_ipset(name, ipv, ttl_match)
            ipsets_new.append(ipset.name)

            if ipset.name not in ipsets_existing and ipset.name not in ipsets_created:
                if ipset.create():
                    ipsets_created.append(ipset.name)
                else:
                    syslog(LOG_WARNING, "Error creating ipset: %s" %(ipset.name))
                    continue

            directions = {}

            if 'direction' not in rule or rule['direction'] == 'ingress':
                directions.update({'ingress': 'src,src,dst'})
            if 'direction' not in rule or rule['direction'] == 'egress':
                directions.update({'egress': 'dst,dst,src'})

            for direction, ipset_param in directions.items():

                params = '-m set --match-set %s %s' %(ipset.name, ipset_param)

                if 'weekdays' in rule or 'time-start' in rule:
                    params = '%s -m time' %(params)
                    if 'weekdays' in rule:
                        params = '%s --weekdays %s' %(params, rule['weekdays'])
                    if 'time-start' in rule:
                        params = '%s --timestart %s' %(params, rule['time-start'])
                    if 'time-stop' in rule:
                        params = '%s --timestop %s' %(params, rule['time-stop'])

                __nfa_fw.add_rule('mangle', 'NFA_%s' %(direction),
                    '%s -j MARK --set-mark 0x%x' %(params, mark_base), ipv)

                mark_base += 1

    for name in ipsets_existing:
        if name in ipsets_new: continue
        syslog(LOG_DEBUG, "ipset destroy: %s" %(name))
        nfa_ipset.nfa_ipset_destroy(name)

    __nfa_ipsets = nfa_ipset.nfa_ipset_list()
    #syslog(LOG_DEBUG, "ipset new: %s" %(__nfa_ipsets))

    for rule in __nfa_config_dynamic['whitelist']:
        if rule['type'] == 'mac':
            # TODO: iptables mac module only supports --mac-source
            continue

        ipv = 0
        if rule['type'] == 'ipv4':
            ipv = 4
        if rule['type'] == 'ipv6':
            ipv = 6

        directions = ['-s', '-d']

        for direction in directions:
            __nfa_fw.add_rule('mangle', 'NFA_whitelist',
                '%s %s -j ACCEPT' %(direction, rule['address']), ipv)

def nfa_flow_matches_rule(flow, rule):
    if 'protocol' in rule and flow['detected_protocol'] != rule['protocol']:
        return False
    if 'application' in rule and flow['detected_application'] != rule['application']:
        return False

    if 'protocol_category' in rule:
        key = str(flow['detected_protocol'])
        if key not in __nfa_config_cat_cache['protocols']:
            return False
        if __nfa_config_cat_cache['protocols'][key] != rule['protocol_category']:
            return False
    if 'application_category' in rule:
        match = __nfa_rx_app_id.match(flow['detected_application_name'])
        if match is None: return False

        key = match.group()
        if key not in __nfa_config_cat_cache['applications']:
            return False
        if __nfa_config_cat_cache['applications'][key] != rule['application_category']:
            return False

    return True

def nfa_process_flow(flow):
    for rule in __nfa_config_dynamic['rules']:
        if rule['type'] != 'block': continue
        if not nfa_flow_matches_rule(flow['flow'], rule): continue

        name = nfa_rule_criteria(rule)
        ipset = nfa_ipset.nfa_ipset(name, flow['flow']['ip_version'])
        if not ipset.upsert( \
            flow['flow']['other_ip'], flow['flow']['other_port'], \
            flow['flow']['local_ip']):
            syslog(LOG_WARNING, "Error upserting ipset with flow match.")

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
    global __nfa_rx_app_id
    global __nfa_config_reload
    global __nfa_config, __nfa_config_dynamic, __nfa_config_cat_cache

    nfa_fw_init()

    fh = None
    nd = nfa_netifyd.netifyd()

    task_cat_cache_update = None

    __nfa_rx_app_id = re.compile('\d+')

    config_cat_cache = __nfa_config.get('netify-api', 'path-category-cache')
    ttl_cat_cache = __nfa_config.get('netify-api', 'ttl-category-cache')

    if os.path.isfile(config_cat_cache):
        __nfa_config_cat_cache = nfa_config.load_cat_cache(config_cat_cache)

    while not __nfa_should_terminate:

        if __nfa_config_reload:
            nfa_config_reload()
            nfa_fw_sync()

        if task_cat_cache_update is None:
            task_cat_cache_update = nfa_cat_cache_refresh(config_cat_cache, ttl_cat_cache)

        if task_cat_cache_update is not None:
            task_cat_cache_update = nfa_cat_cache_reload(config_cat_cache, task_cat_cache_update)

        if fh is None:
            fh = nd.connect(
                __nfa_config.get('netify-agent', 'socket-uri')
            )
            time.sleep(1)
        else:
            jd = nd.read()

            if jd is None:
                nd.close()
                fh = None
                time.sleep(5)
                continue

            if jd['type'] == 'flow':
                # Only interested in flows that have a remote partner
                if jd['flow']['other_type'] != 'remote': continue
                # Only interested in flows that originate from internal interfaces
                if not jd['internal']: continue

                # We can only mark the following: TCP, UDP, SCTP, and UDPLite
                if jd['flow']['ip_protocol'] != 6 and \
                    jd['flow']['ip_protocol'] != 17 and \
                    jd['flow']['ip_protocol'] != 132 and \
                    jd['flow']['ip_protocol'] != 136: continue

                # Ignore DNS and MDNS
                if jd['flow']['detected_protocol'] == 5 or \
                    jd['flow']['detected_protocol'] == 8: continue

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
