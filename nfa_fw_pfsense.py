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

import xml.etree.ElementTree as et

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

from nfa_fw_pf import nfa_fw_pf

import nfa_util

class nfa_fw_pfsense(nfa_fw_pf):
    """pfSense support for Netify FWA"""

    def __init__(self, nfa_config):

        super(nfa_fw_pfsense, self).__init__(nfa_config)
        syslog(LOG_DEBUG, "pfSense Firewall driver initialized.")
        self.load_pfsense_configuration()

    # Status

    def get_version(self):

        result = nfa_util.exec(
            'nfa_fw_pfsense::get_version', ["cat", "/etc/version"]
        )

        if result['rc'] == 0:
            return "pfSense v%s" %(result['stdout'])

        return 'pfSense'

    def is_running(self):
        return True

    # Interfaces

    def get_external_interfaces(self):
        return self.interfaces['external']

    def get_internal_interfaces(self):
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
        super().test()

    # Private

    def load_pfsense_configuration(self):
        self.interfaces = { "internal": [], "external": [] }
        tree = et.parse('/cf/conf/config.xml')
        root = tree.getroot()
        ifaces = root.find('interfaces')

        for iface in ifaces.findall('wan'):
            if iface.find('enable') is not None:
                name = iface.find('if')
                self.interfaces['external'].append(name)

        for iface in ifaces.findall('lan'):
            if iface.find('enable') is not None:
                name = iface.find('if')
                self.interfaces['internal'].append(name)

