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

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

debug = False

pid_file = '/var/run/netify-fwa/netify-fwa.pid'

fw = None
fw_interfaces = { "internal": [], "external": [] }

config_reload = True
should_terminate = False
expire_matches = False

config = None
config_dynamic = None
config_cat_cache = None

log_options = LOG_PID | LOG_PERROR

stats = { 'flows': 0, 'blocked': 0, 'prioritized': 0 }

rx_app_id = None