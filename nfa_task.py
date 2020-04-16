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

import json
import socket
import threading

import nfa_global
import nfa_config
import nfa_netify_api

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

class cat_update(threading.Thread):
    config = None
    exit_success = False

    def __init__(self, config):
        self.config = config
        super().__init__()

    def run(self):
        pages_protocols = []
        pages_applications = []

        url_api = self.config.get('netify-api', 'url')

        try:
            pages_protocols = nfa_netify_api.get_data(
                url_api + '/lookup/protocols'
            )

            if pages_protocols is None or nfa_global.should_terminate:
                return

            pages_applications = nfa_netify_api.get_data(
                url_api + '/lookup/applications'
            )

            if pages_applications is None or nfa_global.should_terminate:
                return

        except socket.gaierror as e:
            syslog(LOG_WARNING,
                "Netify API request failed: %s: %s [%d]" %(url_api, e.errstr, e.errno))
            return

        metadata = {
            'applications': {}, 'protocols': {},
            'application_category': {}, 'protocol_category': {}
        }

        if 'protocol_category' in pages_protocols[0]:
            for i, entry in enumerate(pages_protocols[0]['protocol_category']):
                metadata['protocol_category'][entry] = {
                    'label': pages_protocols[0]['protocol_category'][entry]
                }

        if 'application_category' in pages_applications[0]:
            for i, entry in enumerate(pages_applications[0]['application_category']):
                metadata['application_category'][entry] = {
                    'label': pages_applications[0]['application_category'][entry]
                }

        proto_index = {}

        for page in pages_protocols[1]:
            for proto in page:
                if 'id' not in proto:
                    break
                if 'protocol_category' not in proto:
                    break
                if 'id' not in proto['protocol_category']:
                    break

                proto_index[proto['id']] = proto['protocol_category']['id'];

                metadata['protocols'][proto['id']] = {
                    'label': proto['label'],
                }

        syslog(LOG_DEBUG, "Indexed %d protocol categories." %(len(proto_index)))

        app_index = {}

        for page in pages_applications[1]:
            for app in page:
                if 'id' not in app:
                    break
                if 'application_category' not in app:
                    break
                if 'id' not in app['application_category']:
                    break

                app_index[app['id']] = app['application_category']['id'];

                metadata['applications'][app['id']] = {
                    'label': app['label'],
                    'icon': app['favicon']
                }

        syslog(LOG_DEBUG, "Indexed %d application categories." %(len(app_index)))

        data = { 'protocols': proto_index, 'applications': app_index}

        path_cat_index = self.config.get('netify-api', 'path-category-index')

        try:
            with open(path_cat_index, 'w') as fh:
                json.dump(data, fh)
        except FileNotFoundError as e:
            syslog(LOG_ERR, "Error saving categories index: %s: File not found." %(path_cat_index))
            return
        except IOError as e:
            syslog(LOG_ERR, "Error saving categories index: %s" %(path_cat_index))
            return

        path_app_proto_data = self.config.get('netify-api', 'path-app-proto-data')

        try:
            with open(path_app_proto_data, 'w') as fh:
                json.dump(metadata, fh)
        except FileNotFoundError as e:
            syslog(LOG_ERR, "Error saving application/protocol metadata: %s: File not found." %(path_app_proto_data))
            return
        except IOError as e:
            syslog(LOG_ERR, "Error saving application/protocol metadata: %s" %(path_app_proto_data))
            return

        self.exit_success = True
