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
import tempfile

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_rule

class nfa_fw_pf():
    """Generic PF support for Netify FWA"""

    def __init__(self, nfa_config):
        self.flavor = 'pf'
        self.nfa_config = nfa_config
        syslog(LOG_DEBUG, "PF Firewall driver initialized.")

    # Status

    def get_version(self):
        return "pf"

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

    # List NFA anchors

    def anchor_list(self, anchor="nfa"):
        anchors = []

        result = subprocess.run(
            ['pfctl', '-a', anchor, '-s', 'Anchors'],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode == 0:
            if len(result.stdout):
                anchors = result.stdout.split()
        else:
            syslog(LOG_ERR, "anchor_list: error: %s" %(result))

        return anchors

    # Flush all rules from anchor

    def anchor_flush(self, anchor):
        result = subprocess.run(
            ['pfctl', '-a', anchor, '-F', 'rules'],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "anchor_flush: error: %s" %(result))

    # Load rules into anchor

    def anchor_load(self, anchor, rules):
        fh = tempfile.NamedTemporaryFile()

        try:
            for rule in rules: fh.write(rule + b"\n")
            fh.flush()

            result = subprocess.run(
                ['pfctl', '-a', anchor, '-f', fh.name],
                    stdout=subprocess.PIPE, universal_newlines=True
            )
            if result.returncode != 0:
                syslog(LOG_ERR, "anchor_flush: error: %s" %(result))
        finally:
            fh.close()

    # Upsert table host entry

    def table_upsert(self, anchor, table, host):
        result = subprocess.run(
            ['pfctl', '-a', anchor, '-t', table, '-T', 'delete', host],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "table_upsert: error: %s" %(result))

        result = subprocess.run(
            ['pfctl', '-a', anchor, '-t', table, '-T', 'add', host],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "table_upsert: error: %s" %(result))

    # Flush table

    def table_flush(self, anchor, table):
        result = subprocess.run(
            ['pfctl', '-a', anchor, '-t', table, '-T', 'flush'],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "table_flush: error: %s" %(result))

    # Kill table

    def table_kill(self, anchor, table):
        result = subprocess.run(
            ['pfctl', '-a', anchor, '-t', table, '-T', 'kill'],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "table_kill: error: %s" %(result))

    # Expire table entries

    def table_expire(self, anchor, table):
        ttl_match = int(self.nfa_config.get('netify-fwa', 'ttl-match'))

        result = subprocess.run(
            ['pfctl', '-a', anchor, '-t', table, '-T', 'expire', ttl_match],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "table_expire: error: %s" %(result))

    # Kill state for entries matching label

    def kill_state_by_label(self, anchor, label):
        result = subprocess.run(
            ['pfctl', '-a', anchor, '-k', 'label', '-k', label],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "kill_state_by_label: error: %s" %(result))

    # Kill state for entries matching host

    def kill_state_by_host(self, host):
        result = subprocess.run(
            ['pfctl', '-k', '0.0.0.0/0', '-k', host],
                stdout=subprocess.PIPE, universal_newlines=True
        )
        if result.returncode != 0:
            syslog(LOG_ERR, "kill_state_by_host: error: %s" %(result))

    # Synchronize state

    def sync(self, config_dynamic):
        if (config_dynamic is None):
            return

        ba_new = []
        ba_existing = []

        anchors = self.anchor_list()

        for anchor in anchors:
            if anchor == 'nfa/00_whitelist':
                self.table_flush(anchor, 'nfa_whitelist')
                self.kill_state_by_label(anchor, 'nfa_whitelist')
                continue

            ba_existing.append(anchor)
            self.kill_state_by_label(anchor, 'nfa_block')

        for rule in config_dynamic['rules']:
            if rule['type'] != 'block': continue
            if 'weekdays' in rule or 'time-start' in rule:
                syslog(LOG_WARNING, "Time-of-day rules not supported by pf driver.")
                continue

            name = "nfa/block_%s" %(nfa_rule.criteria(rule))

            ba_new.append(name)

            self.anchor_flush(name)

            rules = [
                b'block drop log quick from <nfa_local> to <nfa_remote> label "nfa_block"',
                b'block drop log quick from <nfa_remote> to <nfa_local> label "nfa_block"'
            ]
            self.anchor_load(name, rules)

        for name in ba_existing:
            if name in ba_new: continue

            self.table_flush(name, 'nfa_local')
            self.table_flush(name, 'nfa_remote')

            self.table_kill(name, 'nfa_local')
            self.table_kill(name, 'nfa_remote')

            self.anchor_flush(name)

        rules = [ b'anchor "00_whitelist"' ]

        for name in ba_new:
            rules.append(b'anchor "%b"' %(str.encode(name)))

        self.anchor_load('nfa', rules)

        self.anchor_flush('nfa/00_whitelist')
        rules = [ b'pass in quick from <nfa_whitelist> to any label "nfa_whitelist"' ]
        self.anchor_load('nfa/00_whitelist', rules)

        for rule in config_dynamic['whitelist']:
            if rule['type'] == 'mac':
                continue

            self.table_upsert(
                'nfa/00_whitelist', 'nfa_whitelist', rule['address']
            )

    # Process flow

    def process_flow(self, flow, config_dynamic, nfa_stats):
        if config_dynamic is None:
            return

        for rule in config_dynamic['rules']:
            if rule['type'] != 'block': continue
            if not nfa_rule.flow_matches(flow['flow'], rule): continue

            anchor = "nfa/block_%s" %(nfa_rule.criteria(rule))

            self.table_upsert(anchor, "nfa_local", flow['flow']['local_ip'])
            self.table_upsert(anchor, "nfa_remote", flow['flow']['other_ip'])

            self.kill_state_by_host(flow['flow']['other_ip'])

    # Install hooks

    def install_hooks(self):
        pass

    # Remove hooks

    def remove_hooks(self):
        pass

    # Test

    def test(self):
        anchors = self.anchor_list()

        for anchor in anchors:
            syslog(LOG_DEBUG, "NFA anchor: %s" %(anchor))
