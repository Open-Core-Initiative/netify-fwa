# Netify Firewall Agent
# Copyright (C) 2019-2020 eGloo Incorporated <http://www.egloo.ca>
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

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_ipset
import nfa_util

from nfa_fw_iptables import nfa_fw_iptables

class nfa_fw_clearos(nfa_fw_iptables):
    """ClearOS support for Netify FWA"""

    def __init__(self, nfa_config):
        super(nfa_fw_clearos, self).__init__(nfa_config)
        syslog(LOG_DEBUG, "ClearOS Firewall driver initialized.")
        self.load_clearos_configuration()

    # Status

    def get_version(self):
        result = nfa_util.exec(
            'nfa_fw_clearos::get_version', ["iptables", "--version"]
        )

        if result['rc'] == 0:
            version = result['stdout']
            parts = version.split()
            return "ClearOS Firewall %s" %(parts[1])
        else:
            return "ClearOS Firewall"

    def is_running(self):
        result = nfa_util.exec(
            'nfa_fw_clearos::is_running',
            ["systemctl", "--property=ActiveState", "show", "firewall"]
        )

        rx_kv = re.compile('^ActiveState\s*=\s*(.*)$')
        match = rx_kv.match(result['stdout'])

        if match is not None:
            if match.group(1) == "active":
                return True

        return False

    # Interfaces

    def get_external_interfaces(self):
        return self.interfaces['external']

    def get_internal_interfaces(self):
        return self.interfaces['internal']

    # Test

    def test(self):
        super().test()

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

