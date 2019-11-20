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

import nfa_global
import nfa_ipset
import nfa_rule

class nfa_fw_iptables():
    """Generic iptables support for Netify FWA"""

    def __init__(self, nfa_config):
        self.flavor = 'iptables'
        self.nfa_config = nfa_config
        self.mark_base = int(nfa_config.get('netify-fwa', 'mark-base'), 16)
        self.mark_mask = int(nfa_config.get('netify-fwa', 'mark-mask'), 16)

        syslog(LOG_DEBUG, "IPTables Firewall driver initialized.")

    # Status

    def get_version(self):
        result = subprocess.run(
            ["iptables", "--version"],
            stdout=subprocess.PIPE, universal_newlines=True
        )
        return result.stdout

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

    # Install hooks

    def install_hooks(self):
        ifn_int = self.get_internal_interfaces()
        ifn_ext = self.get_external_interfaces()

        if len(ifn_int) == 0 and len(ifn_ext) == 0:
            syslog(LOG_ERR, "No interfaces with roles defined.")
            return False

        # Create whitelist chain
        for ipv in [4, 6]:
            self.add_chain('mangle', 'NFA_whitelist', ipv)

            # Add jumps to whitelist chain
            self.add_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

            # Create ingress/egress chains
            self.add_chain('mangle', 'NFA_ingress', ipv)
            self.add_chain('mangle', 'NFA_egress', ipv)

            # Add jumps to ingress/egress chains
            for iface in self.interfaces['external']:
                self.add_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_ingress' %(iface), ipv)
            for iface in self.interfaces['internal']:
                self.add_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_egress' %(iface), ipv)

            # Create block chain
            self.add_chain('mangle', 'NFA_block', ipv)

            self.add_rule('mangle', 'NFA_block', '-j DROP', ipv)

            # Add jumps to block chain
            self.add_rule('mangle', 'FORWARD',
                '-m mark --mark 0x%08x/0x%08x -j NFA_block' %(
                    self.mark_base, self.mark_mask
                ), ipv)

        return True

    # Remove hooks

    def remove_hooks(self):
        for ipv in [4, 6]:
            self.delete_rule('mangle', 'FORWARD', '-j NFA_whitelist', ipv)

            for iface in self.interfaces['external']:
                self.delete_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_ingress' %(iface), ipv)
            for iface in self.interfaces['internal']:
                self.delete_rule('mangle', 'FORWARD',
                    '-i %s -j NFA_egress' %(iface), ipv)

            self.flush_chain('mangle', 'NFA_whitelist', ipv)
            self.delete_chain('mangle', 'NFA_whitelist', ipv)

            self.flush_chain('mangle', 'NFA_ingress', ipv)
            self.delete_chain('mangle', 'NFA_ingress', ipv)

            self.flush_chain('mangle', 'NFA_egress', ipv)
            self.delete_chain('mangle', 'NFA_egress', ipv)


            self.delete_rule('mangle', 'FORWARD',
                '-m mark --mark 0x%08x/0x%08x -j NFA_block' %(
                    self.mark_base, self.mark_mask
                ), ipv)

            self.flush_chain('mangle', 'NFA_block', ipv)
            self.delete_chain('mangle', 'NFA_block', ipv)

        for name in nfa_ipset.nfa_ipset_list():
            nfa_ipset.nfa_ipset_destroy(name)

    # Synchronize state

    def sync(self, config_dynamic):
        if (config_dynamic is None):
            return

        for ipv in [4, 6]:
            self.flush_chain('mangle', 'NFA_whitelist', ipv)
            self.flush_chain('mangle', 'NFA_ingress', ipv)
            self.flush_chain('mangle', 'NFA_egress', ipv)

        ttl_match = int(self.nfa_config.get('netify-fwa', 'ttl-match'))
        mark_base = int(self.nfa_config.get('netify-fwa', 'mark-base'), 16)

        ipsets_new = []
        ipsets_created = []
        ipsets_existing = nfa_ipset.nfa_ipset_list()

        for rule in config_dynamic['rules']:
            if rule['type'] != 'block': continue

            name = nfa_rule.criteria(rule)

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

                    self.add_rule('mangle', 'NFA_%s' %(direction),
                        '%s -j MARK --set-mark 0x%x' %(params, mark_base), ipv)

                    mark_base += 1

            for name in ipsets_existing:
                if name in ipsets_new: continue
                syslog(LOG_DEBUG, "ipset destroy: %s" %(name))
                nfa_ipset.nfa_ipset_destroy(name)

        for rule in config_dynamic['whitelist']:
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
                self.add_rule('mangle', 'NFA_whitelist',
                    '%s %s -j ACCEPT' %(direction, rule['address']), ipv)

    # Process flow

    def process_flow(self, flow):

        if nfa_global.config_dynamic is None:
            return

        for rule in nfa_global.config_dynamic['rules']:
            if rule['type'] != 'block': continue
            if not nfa_rule.flow_matches(flow['flow'], rule): continue

            name = nfa_rule.criteria(rule)

            ipset = nfa_ipset.nfa_ipset(name, flow['flow']['ip_version'])
            if not ipset.upsert( \
                flow['flow']['other_ip'], flow['flow']['other_port'], \
                flow['flow']['local_ip']):
                syslog(LOG_WARNING, "Error upserting ipset with flow match.")
            else:
                nfa_global.stats['blocked'] += 1

    # Test

    def test(self):
        pass
