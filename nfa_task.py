import json
import socket
import threading

import nfa_config
import nfa_netify_api

class api_update(threading.Thread):
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
            pages_protocols = nfa_netify_api.get_data(url_api + '/lookup/protocols')

            if pages_protocols is None:
                return

            print("Loaded %d protocol pages from Netify API." %(len(pages_protocols)))

            pages_applications = nfa_netify_api.get_data(url_api + '/lookup/applications')

            if pages_applications is None:
                return

            print("Loaded %d application pages from Netify API." %(len(pages_applications)))
        except socket.gaierror as e:
            print("API request failed: %s [%d]" %(e.errstr, e.errno))

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

        print("Indexed %d protocols." %(len(protocols)))

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

        print("Indexed %d applications." %(len(applications)))

        data = { 'protocols': protocols, 'applications': applications }

        path_cache = self.config.get('netify-api', 'path-cache')

        try:
            with open(path_cache, 'w') as fh:
                json.dump(data, fh)
        except FileNotFoundError as e:
            print("Error writing JSON API file: %s: File not found." %(path_cache))
            return
        except IOError as e:
            print("Error writing JSON API file: %s" %(path_cache))
            return

        self.exit_success = True
