#!/usr/bin/python3 -Es

import sys
import json
import socket

import nfa_config
import nfa_daemonize
import nfa_socket

import nfa_firewall

def nfa_main():
    sd = nfa_socket.connect()
    fh = sd.makefile()

    while True:
        data = fh.readline()
        if not data: break

        print("Read: %d bytes" %(len(data)))
        #print("Data: \"%s\"" %(data))

        jd = json.loads(data)

        if 'length' in jd: continue
        if 'type' in jd:
            print("Netify Message Type: %s" %(jd['type']))

        #print(jd)

    sd.close()

#nfa_daemonize.start(nfa_main, pid_file='/var/run/netifyd/netify-fwa.pid', debug=True)
fw = nfa_firewall.nfa_fwd1()
fw.test()

nfa_main()

sys.exit(0)
