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

import dbus

from firewall import client
from firewall.functions import splitArgs

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_ipset

import nfa_fw_iptables

class nfa_fw_firewalld(nfa_fw_iptables, client.FirewallClient):
    """Firewalld support for Netify FWA"""

    def __init__(self):
        super(nfa_fw_firewalld, self).__init__()
        syslog(LOG_DEBUG, "Firewalld driver initialized.")

    def ip_version(self, ipv):
        if ipv == 6:
            return 'ipv6'
        return 'ipv4'

    # Status

    def get_version(self):
        return "firewalld v" + self.get_property("version")

    def is_running(self):
        state = self.get_property("state")
        syslog(LOG_DEBUG, "Firewall engine state: %s" %(state))
        if state == "RUNNING":
            return True
        return False

    # Zones

    def get_zone_interfaces(self, zone):
        ifaces = []
        fw_config = self.config()
        try:
            zone_config = fw_config.getZoneByName(zone)
        except:
            syslog(LOG_WARNING, "Zone doesn't exist: %s" %(zone))
            return ifaces

        return self.getInterfaces(zone)

    # Interfaces

    def get_external_interfaces(self, config):
        ifaces = []
        zones = config.get('firewalld', 'zones-external').split(',')

        for zone in zones:
            ifaces.extend(self.get_zone_interfaces(zone.strip()))

        return ifaces

    def get_internal_interfaces(self, config):
        ifaces = []
        zones = config.get('firewalld', 'zones-internal').split(',')

        for zone in zones:
            ifaces.extend(self.get_zone_interfaces(zone.strip()))

        return ifaces

    # Chains

    def get_chains(self):
        nfa_chains = []
        all_chains = self.getAllChains()
        for chain in all_chains:
            if chain[2].startswith('NFA_'):
                nfa_chains.append(chain)
        return nfa_chains

    def chain_exists(self, table, name, ipv=4):
        chains = self.get_chains()
        for chain in chains:
            if self.ip_version(ipv) == chain[0] and \
                table == chain[1] and name[0:28] == chain[2]:
                return True
        return False

    def add_chain(self, table, name, ipv=4):
        if not self.chain_exists(table, name, ipv):
            self.addChain(self.ip_version(ipv), table, name[0:28])

    def flush_chain(self, table, name, ipv=4):
        self.removeRules(self.ip_version(ipv), table, name[0:28])

    def delete_chain(self, table, name, ipv=4):
        if self.chain_exists(table, name, ipv):
            self.removeChain(self.ip_version(ipv), table, name[0:28])

    # Rules

    def rule_exists(self, table, chain, args, ipv=4, priority=0):
        return self.queryRule(
            self.ip_version(ipv), table, chain, priority, splitArgs(args)
        )

    def add_rule(self, table, chain, args, ipv=4, priority=0):
        if not self.rule_exists(table, chain, args, ipv, priority):
            self.addRule(
                self.ip_version(ipv), table, chain, priority, splitArgs(args)
            )

    def delete_rule(self, table, chain, args, ipv=4, priority=0):
        if self.rule_exists(table, chain, args, ipv, priority):
            self.removeRule(
                self.ip_version(ipv), table, chain, priority, splitArgs(args)
            )

    # Test

    def test(self):
        zone_default = self.getDefaultZone()
        zone_settings = self.getZoneSettings(zone_default)

        syslog(LOG_DEBUG, "  name: %s" %(zone_settings.getShort()))
        syslog(LOG_DEBUG, "  desc: %s" %(zone_settings.getDescription()))

        syslog(LOG_DEBUG, "  chains: %s" %(self.get_chains()))

        self.delete_chain('mangle', 'NFA_test')
        syslog(LOG_DEBUG, "  chains: %s" %(self.get_chains()))

        self.add_chain('mangle', 'NFA_test')
        syslog(LOG_DEBUG, "  chains: %s" %(self.get_chains()))

        syslog(LOG_DEBUG, "  ipsets: %s" %(nfa_ipset.nfa_ipset_list()))

        self.delete_rule('mangle', 'PREROUTING',
            '-s 10.0.0.1 -j MARK --set-mark=0x9000')

        self.add_rule('mangle', 'PREROUTING',
            '-s 10.0.0.1 -j MARK --set-mark=0x9000')
