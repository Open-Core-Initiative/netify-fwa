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

import nfa_ipset

from nfa_fw_pf import nfa_fw_pf

class nfa_fw_pfsense(nfa_fw_pf):
    """pfSense support for Netify FWA"""

    def __init__(self):
        super(nfa_fw_pf, self).__init__()
        syslog(LOG_DEBUG, "pfSense Firewall driver initialized.")

    # Status

    def get_version(self):
        return "pfSense"
#        result = subprocess.run(
#            ["iptables", "--version"],
#            stdout=subprocess.PIPE, universal_newlines=True
#        )
#        return result.stdout

    def is_running(self):
        return True

    # Interfaces

    def get_external_interfaces(self, config):
        ifaces = []

        return ifaces

    def get_internal_interfaces(self, config):
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

    # Test

    def test(self):
        pass
