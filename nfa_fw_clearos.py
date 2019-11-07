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

import re
import subprocess

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_ipset

from nfa_fw_iptables import nfa_fw_iptables

class nfa_fw_clearos(nfa_fw_iptables):
    """ClearOS support for Netify FWA"""

    def __init__(self):
        super(nfa_fw_clearos, self).__init__()
        syslog(LOG_DEBUG, "ClearOS Firewall driver initialized.")
        self.load_clearos_configuration()

    # Status

    def get_version(self):
        result = subprocess.run(
            ["iptables", "--version"],
            stdout=subprocess.PIPE, universal_newlines=True
        )
        version = result.stdout
        parts = version.split()
        return "ClearOS Firewall %s" %(parts[1])

    def is_running(self):
        result = subprocess.run(
            ["systemctl", "--property=ActiveState", "show", "firewall"],
            stdout=subprocess.PIPE, universal_newlines=True
        )
        rx_kv = re.compile('^ActiveState\s*=\s*(.*)$')

        match = rx_kv.match(result.stdout)
        if match is not None:
            if match.group(1) == "active":
                return True
        return False

    # Interfaces

    def get_external_interfaces(self, config):
        return self.interfaces['external']

    def get_internal_interfaces(self, config):
        return self.interfaces['internal']

    # Chains

    def get_chains(self):
        nfa_chains = []

        return nfa_chains

    def chain_exists(self, table, name, ipv=4):
        chains = []

        return False

    def add_chain(self, table, name, ipv=4):
        pass

    def flush_chain(self, table, name, ipv=4):
        pass

    def delete_chain(self, table, name, ipv=4):
        pass

    # Rules

    def rule_exists(self, table, chain, args, ipv=4, priority=0):
        return False

    def add_rule(self, table, chain, args, ipv=4, priority=0):
        pass

    def delete_rule(self, table, chain, args, ipv=4, priority=0):
        pass

    # Test

    def test(self):
        pass

    # Private

    def load_clearos_configuration(self):
        self.interfaces = { "internal": [], "external": [] }

        rx_kv = re.compile('^(\w+)\s*=\s*["]*([\w\s]+)["]*$')

        path = "/etc/clearos/network.conf"
        with open(path, 'r') as fd:
            for i, line in enumerate(fd):
                match = rx_kv.match(line)
                if match is not None:
                    if match.group(1) == "EXTIF":
                        for value in match.group(2).split():
                            self.interfaces['external'].append(value)
                    elif match.group(1) == "LANIF":
                        for value in match.group(2).split():
                            self.interfaces['internal'].append(value)

