#!/usr/bin/python3 -Es

import sys
import json
import socket
import signal
import errno
import time

import nfa_config
import nfa_daemonize
#import nfa_firewall
import nfa_netifyd
import nfa_task

__nfa_config_reload = True
__nfa_should_terminate = False

__nfa_config = None
__nfa_config_dynamic = None
__nfa_config_api = None

def nfa_signal_handler(signum, frame):
    global __nfa_config_reload, __nfa_should_terminate

    if isinstance(signal.SIGHUP, int):
        signo_HUP = signal.SIGHUP
        signo_INT = signal.SIGINT
        signo_TERM = signal.SIGTERM
    else:
        signo_HUP = signal.SIGHUP.value
        signo_INT = signal.SIGINT.value
        signo_TERM = signal.SIGTERM.value

    if signum is signo_HUP:
        __nfa_config_reload = True
    elif signum is signo_INT or signum is signo_TERM:
        print("Exiting...")
        __nfa_should_terminate = True
    else:
        print("Caught unhandled signal: %s" %(signal.Signals(signum).name))

def nfa_main():
    global __nfa_config_reload
    global __nfa_config, __nfa_config_dynamic

    fh = None
    nd = nfa_netifyd.netifyd()

    api_task = None

    while not __nfa_should_terminate:

        if __nfa_config_reload:
            config = nfa_config.load_dynamic(
                __nfa_config.get('netify-fwa', 'path-dynamic-config')
            )
            if config is not None:
                __nfa_config_dynamic = config
                __nfa_config_reload = False
                print("Loaded dynamic configuration.")

        if fh is None:
            fh = nd.connect(
                __nfa_config.get('netify-agent', 'socket-uri')
            )
            nd.close()
            fh = None
            time.sleep(5)
        else:
            jd = nd.read()

            if jd is None:
                continue

            if jd['type'] == 'flow':
                print(jd)

    nd.close()

__nfa_config = nfa_config.load_static('/etc/netify-fwa/netify-fwa.ini')

def api_update_test():
    api_update = nfa_task.api_update(__nfa_config)
    api_update.start()

    while api_update.is_alive():
        print("API update task is still alive...")
        time.sleep(1)

    api_update.join()
    if api_update.exit_success is True:
        print("Task was successful.")
    else:
        print("Task failed.")

#try:
#    nfa_daemonize.start(nfa_main, pid_file='/var/run/netifyd/netify-fwa.pid', debug=True)
#except BlockingIOError as e:
#    if e.errno == errno.EAGAIN or e.errno == errno.EACCESS:
#        print("An instance is already running.")
#    else:
#        print("Error starting daemon: %d" %(e.errno))
#    sys.exit(1)

signal.signal(signal.SIGHUP, nfa_signal_handler)
signal.signal(signal.SIGINT, nfa_signal_handler)
signal.signal(signal.SIGTERM, nfa_signal_handler)

#fwd1 = nfa_firewall.fwd1()
#fwd1.test()

nfa_main()

sys.exit(0)
