import sys
import json
import socket
import select

from urllib.parse import urlparse

netifyd_json_version = 1.7

class netifyd:
    sd = None
    fh = None
    uri = None

    agent_version = None
    json_version = 0

    uptime = 0
    flows = 0
    flows_delta = 0

    def connect(self, uri):
        self.uri = uri

        port = 2100
        uri_parsed = urlparse(uri)

        if uri_parsed.scheme == 'file':
            self.sd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif uri_parsed.scheme == 'tcp':
            self.sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if uri_parsed.port is not None:
                port = uri_parsed.port
        else:
            print("Invalid netify-agent scheme (only tcp:// and file:// are supported).")
            return None

        try:
            if uri_parsed.scheme == 'file':
                print("Connecting to: %s" %(uri_parsed.path))
                self.sd.connect(uri_parsed.path)
            else:
                print("Connecting to: %s:%d" %(uri_parsed.hostname, port))
                self.sd.connect((uri_parsed.hostname, port))
        except socket.error as e:
            print("Error connecting to: %s: %s" %(uri, e.strerror))
            return None

        print("Connected to: %s" %(uri))

        self.fh = self.sd.makefile()

        return self.fh

    def read(self):
        fd_read = [ self.sd ]
        fd_write = []

        readable, writable, exceptional = select.select(fd_read, fd_write, fd_read, 1.0)

        if not len(readable):
            return None

        data = self.fh.readline()
        if not data:
            return None

        print("%s: Read: %d bytes" %(self.uri, len(data)))

        jd = json.loads(data)

        if 'length' not in jd:
            print("%s: Malformed JSON structure: expected length" %(self.uri))
            return None

        data = self.fh.readline()
        if not data:
            return None

        print("%s: Read: %d bytes, expected: %d" %(self.uri, len(data), jd['length']))
        if len(data) != jd['length']:
            print("%s: Malformed JSON structure: invalid length" %(self.uri))
            return None

        jd = json.loads(data)

        if 'type' not in jd:
            print("%s: Malformed JSON structure: expected type" %(self.uri))
            return None

        print("%s: Type: %s" %(self.uri, jd['type']))

        if jd['type'] == 'agent_hello':
            self.agent_version = jd['build_version']
            self.json_version = jd['json_version']
            print("%s: %s" %(self.uri, self.agent_version))
            if self.json_version > netifyd_json_version:
                printf("%s: Unsupported JSON version." %(self.uri))
                sys.exit(1)
        elif jd['type'] == 'agent_status':
            self.uptime = jd['uptime']
            self.flows = jd['flows']
            self.flows_delta = jd['flows_prev'] - jd['flows']

        return jd

    def close(self):
        if self.sd is not None:
            self.sd.close()
