#!/usr/bin/python3 -Es

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

from nfa_version import NFA_VERSION

__nfa_debug = False

__nfa_config_reload = True
__nfa_should_terminate = False

__nfa_config = None
__nfa_config_dynamic = None
__nfa_config_api = None

__nfa_pid_file = '/var/run/netify-fwa/netify-fwa.pid'

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

def nfa_main():
    global __nfa_config_reload
    global __nfa_config, __nfa_config_dynamic

    signal(SIGHUP, nfa_signal_handler)
    signal(SIGINT, nfa_signal_handler)
    signal(SIGTERM, nfa_signal_handler)

    fh = None
    nd = nfa_netifyd.netifyd()

    api_task = None
    config_dynamic = __nfa_config.get('netify-fwa', 'path-config-dynamic')

    while not __nfa_should_terminate:

        if __nfa_config_reload and os.path.isfile(config_dynamic):
            config = nfa_config.load_dynamic(config_dynamic)
            if config is not None:
                __nfa_config_dynamic = config
                __nfa_config_reload = False
                syslog("Loaded dynamic configuration.")

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
                syslog(LOG_DEBUG, str(jd))

    nd.close()

def api_update_test():
    api_update = nfa_task.api_update(__nfa_config)
    api_update.start()

    while api_update.is_alive():
        syslog(LOG_DEBUG, "API update task is still alive...")
        time.sleep(1)

    api_update.join()
    if api_update.exit_success is True:
        syslog(LOG_DEBUG, "Task was successful.")
    else:
        syslog(LOG_DEBUG, "Task failed.")

def daemonize():
    try:
        nfa_daemonize.start(
            nfa_main,
            pid_file=__nfa_pid_file,
            debug=__nfa_debug
        )
    except BlockingIOError as e:
        if e.errno == errno.EAGAIN or e.errno == errno.EACCESS:
            syslog(LOG_ERR, "An instance is already running.")
        else:
            syslog(LOG_ERR, "Error starting daemon: %d" %(e.errno))
        sys.exit(1)

__nfa_config = nfa_config.load_static('/etc/netify-fwa/netify-fwa.ini')

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

try:
    fw_engine = __nfa_config.get('netify-fwa', 'firewall-engine')
except NoOptionError as e:
    printf("Mandatory configuration option not set: firewall-engine")

if fw_engine == 'iptables':
    from nfa_iptables import nfa_firewall
elif fw_engine == 'firewalld':
    from nfa_firewalld import nfa_firewall
else:
    print("Unsupported firewall engine: %s" %(fw_engine))
    sys.exit(1)

openlog('netify-fwa', LOG_PID | LOG_PERROR, LOG_DAEMON)
syslog("Netify FWA v%s started." %(NFA_VERSION))

fw = nfa_firewall()
fw.test()

if not __nfa_debug:
    daemonize()

nfa_main()

sys.exit(0)
