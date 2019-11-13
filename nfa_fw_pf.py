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

import subprocess

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

class nfa_fw_pf():
    """Generic PF support for Netify FWA"""

    def __init__(self, nfa_config):
        self.flavor = 'pf'
        self.nfa_config = nfa_config
        syslog(LOG_DEBUG, "PF Firewall driver initialized.")

    # Status

    def get_version(self):
        return "pf"
#        result = subprocess.run(
#            ["iptables", "--version"],
#            stdout=subprocess.PIPE, universal_newlines=True
#        )
#        return result.stdout

    def is_running(self):
        return True

    # Interfaces

    def get_external_interfaces(self):
        ifaces = []

        return ifaces

    def get_internal_interfaces(self):
        ifaces = []

        return ifaces

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

    # PF Table List

    def table_list(self):
        tables = []

        result = subprocess.run(
            ['pfctl', '-s', 'Tables'],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode == 0:
            if len(result.stdout):
                _tables = result.stdout.split()
                for s in _tables:
                    if s.startswith('NFA_'):
                        tables.append(s)
        else:
            syslog(LOG_ERR, "pfctl(Tables) error: %s" %(result))

        return tables

    # Synchronize state

    def sync(self, config_dynamic):
        pass

    # Process flow

    def process_flow(self, flow, config_dynamic, nfa_stats):
        pass

    # Install hooks

    def install_hooks(self):
        pass

    # Remove hooks

    def remove_hooks(self):
        pass

    # Test

    def test(self):
        tables = self.table_list()

        for table in tables:
            syslog(LOG_DEBUG, "table: %s" %(table))
