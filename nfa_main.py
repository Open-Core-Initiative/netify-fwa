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
import select

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
import nfa_rule

from nfa_defaults import NFA_CONF

from nfa_version import NFA_VERSION

__nfa_debug = False

__nfa_pid_file = '/var/run/netify-fwa/netify-fwa.pid'

__nfa_fw = None
__nfa_fw_interfaces = { "internal": [], "external": [] }

__nfa_config_reload = True
__nfa_should_terminate = False

__nfa_config = None
__nfa_config_dynamic = None

global __nfa_config_cat_cache
__nfa_config_cat_cache = None

__nfa_log_options = LOG_PID | LOG_PERROR

__nfa_stats = { 'flows': 0, 'blocked': 0, 'prioritized': 0 }

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

    __nfa_config = nfa_config.load_main(NFA_CONF)

def nfa_config_reload():
    global __nfa_config_reload
    global __nfa_config_dynamic

    config_dynamic = __nfa_config.get('netify-fwa', 'path-config-dynamic')

    if os.path.isfile(config_dynamic):

        config = nfa_config.load_dynamic(config_dynamic)
        if config is not None:
            __nfa_config_dynamic = config
            syslog("Loaded dynamic configuration.")

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
        else:
            cat_cache = nfa_config.load_cat_cache(config_cat_cache)

            if cat_cache is not None:
                syslog("Reloaded category cache.")
                __nfa_config_cat_cache = cat_cache

        return None

    return task_cat_update

def nfa_fw_init():
    global __nfa_fw, __nfa_config, __nfa_fw_interfaces

    try:
        fw_engine = __nfa_config.get('netify-fwa', 'firewall-engine')
    except NoOptionError as e:
        printf("Mandatory configuration option not set: firewall-engine")
        return False

    if fw_engine == 'iptables':
        from nfa_fw_iptables import nfa_fw_iptables
        __nfa_fw = nfa_fw_iptables(__nfa_config)
    elif fw_engine == 'firewalld':
        from nfa_fw_firewalld import nfa_fw_firewalld
        __nfa_fw = nfa_fw_firewalld(__nfa_config)
    elif fw_engine == 'clearos':
        from nfa_fw_clearos import nfa_fw_clearos
        __nfa_fw = nfa_fw_clearos(__nfa_config)
    elif fw_engine == 'pf':
        from nfa_fw_pf import nfa_fw_pf
        __nfa_fw = nfa_fw_pf(__nfa_config)
    elif fw_engine == 'pfsense':
        from nfa_fw_pfsense import nfa_fw_pfsense
        __nfa_fw = nfa_fw_pfsense(__nfa_config)
    else:
        print("Unsupported firewall engine: %s" %(fw_engine))
        return False

    if fw_engine == 'firewalld':
        # XXX: Have to open syslog again because the firewalld client code
        # is rude and does some of it's own syslog initialization.
        openlog('netify-fwa', __nfa_log_options, LOG_DAEMON)

    syslog("Firewall engine: %s" %(__nfa_fw.get_version()))

    if not __nfa_fw.is_running():
        syslog(LOG_ERR, "Firewall engine is not running.")
        return False

    __nfa_fw.test()

    return __nfa_fw.install_hooks()

def nfa_process_agent_status(status):
    global __nfa_stats

    if 'flows' in status and 'flows_prev' in status:
        __nfa_stats['flows'] = status['flows']

    status = __nfa_config.get('netify-fwa', 'path-status')

    try:
        with open(status, 'w') as fh:
            json.dump(__nfa_stats, fh)
    except:
        syslog(LOG_ERR, "Unable to update status file: %s" %(status))

    __nfa_stats['blocked'] = 0
    __nfa_stats['prioritized'] = 0

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
    global __nfa_fw
    global __nfa_rx_app_id
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

    wd = None
    if __nfa_fw.flavor == 'iptables':
        from inotify_simple import INotify, flags

        inotify = INotify()
        config_dynamic = __nfa_config.get('netify-fwa', 'path-config-dynamic')
        wd = inotify.add_watch(config_dynamic, flags.CLOSE_WRITE | flags.MOVE_SELF | flags.MODIFY)

    while not __nfa_should_terminate:

        if wd is not None:
            fd_read = [ inotify.fd ]
            fd_write = []

            rd, wr, ex = select.select(fd_read, fd_write, fd_read, 0)

            if len(rd):
                for event in inotify.read():
                    __nfa_config_reload = True

        if __nfa_config_reload:
            nfa_config_reload()
            __nfa_fw.sync(__nfa_config_dynamic)
            if fh is not None:
                nd.close()
                fh = None

        if __nfa_config_cat_cache is None:
            print("config cat cache is None")
        else:
            print("config cat cache is not None")

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

                #print(jd)

                __nfa_fw.process_flow(jd, __nfa_config_dynamic, __nfa_stats)

            if jd['type'] == 'agent_status':
                nfa_process_agent_status(jd)

    nd.close()
    __nfa_fw.remove_hooks()

    return 0

if __name__ == "__main__":

    openlog('netify-fwa', __nfa_log_options, LOG_DAEMON)
    syslog("Netify FWA v%s started." %(NFA_VERSION))

    nfa_config_load()

    try:
        params, args = getopt(sys.argv[1:], 'd', ('debug', 'save-default-config', 'help'))
    except GetoptError as e:
        print("Parameter error: %s" %(e.msg))
        print("Try option --help for usage information.")
        sys.exit(1)

    for option in params:
        if option[0] == '-d' or option[0] == '--debug':
            __nfa_debug = True
        elif option[0] == '--save-default-config':
            print("Generating default configuration file: %s" %(NFA_CONF))
            nfa_config.save_main(NFA_CONF, __nfa_config)
            sys.exit(0)
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
