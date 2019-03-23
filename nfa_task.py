import json
import socket
import threading

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
        pages_protocols = ()
        pages_applications = ()

        url_api = self.config.get('netify-api', 'url')

        try:
            pages_protocols = nfa_netify_api.get_data(
                url_api + '/lookup/protocols'
            )

            if pages_protocols is None:
                return

            pages_applications = nfa_netify_api.get_data(
                url_api + '/lookup/applications'
            )

            if pages_applications is None:
                return
        except socket.gaierror as e:
            syslog(LOG_WARNING,
                "Netify API request failed: %s: %s [%d]" %(url_api, e.errstr, e.errno))

        protocols = {}

        for page in pages_protocols:
            for proto in page:
                if 'id' not in proto:
                    break
                if 'protocol_category' not in proto:
                    break
                if 'id' not in proto['protocol_category']:
                    break

                protocols[proto['id']] = proto['protocol_category']['id'];

        syslog(LOG_DEBUG, "Indexed category cache for %d protocols." %(len(protocols)))

        applications = {}

        for page in pages_applications:
            for app in page:
                if 'id' not in app:
                    break
                if 'application_category' not in app:
                    break
                if 'id' not in app['application_category']:
                    break

                applications[app['id']] = app['application_category']['id'];

        syslog(LOG_DEBUG, "Indexed category cache for %d applications." %(len(applications)))

        data = { 'protocols': protocols, 'applications': applications }

        path_cat_cache = self.config.get('netify-api', 'path-category-cache')

        try:
            with open(path_cat_cache, 'w') as fh:
                json.dump(data, fh)
        except FileNotFoundError as e:
            syslog(LOG_ERR, "Error saving category cache: %s: File not found." %(path_cat_cache))
            return
        except IOError as e:
            syslog(LOG_ERR, "Error saving category cache: %s" %(path_cat_cache))
            return

        self.exit_success = True
