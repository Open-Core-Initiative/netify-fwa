import sys
import json
import socket
import select

from urllib.parse import urlparse

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

netifyd_json_version = 1.8

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

        if uri_parsed.scheme == 'unix':
            self.sd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        elif uri_parsed.scheme == 'tcp':
            self.sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if uri_parsed.port is not None:
                port = uri_parsed.port
        else:
            syslog(LOG_ERR, "Invalid netify-agent scheme " +
                "(only tcp:// and unix:// schemes are supported).")
            return None

        try:
            syslog("Connecting to: %s" %(uri))

            if uri_parsed.scheme == 'unix':
                self.sd.connect(uri_parsed.path)
            else:
                self.sd.connect((uri_parsed.hostname, port))

        except socket.error as e:
            syslog(LOG_ERR, "Error connecting to: %s: %s" %(uri, e.strerror))
            return None

        syslog("Connected to: %s" %(uri))

        self.fh = self.sd.makefile()

        return self.fh

    def read(self):
        jd = { "type": "noop" }

        fd_read = [ self.sd ]
        fd_write = []

        rd, wr, ex = select.select(fd_read, fd_write, fd_read, 1.0)

        if not len(rd):
            return jd

        data = self.fh.readline()
        if not data:
            return None

        #syslog(LOG_DEBUG, "%s: Read: %d bytes" %(self.uri, len(data)))

        jd = json.loads(data)

        if 'length' not in jd:
            syslog(LOG_WARNING,
                "%s: Malformed JSON structure: expected length" %(self.uri))
            return None

        data = self.fh.readline()
        if not data:
            return None

        #syslog(LOG_DEBUG,
        #        "%s: Read: %d bytes, expected: %d"
        #        %(self.uri, len(data), jd['length']))

        if len(data) != jd['length']:
            syslog(LOG_WARNING,
                "%s: Malformed JSON structure: invalid length" %(self.uri))
            return None

        jd = json.loads(data)

        if 'type' not in jd:
            syslog(LOG_WARNING,
                "%s: Malformed JSON structure: expected type" %(self.uri))
            return None

        syslog(LOG_DEBUG, "%s: Type: %s" %(self.uri, jd['type']))

        if jd['type'] == 'agent_hello':
            self.agent_version = jd['build_version']
            self.json_version = jd['json_version']
            syslog("%s: %s" %(self.uri, self.agent_version))
            if self.json_version > netifyd_json_version:
                syslog(LOG_ERR, "%s: Unsupported JSON version." %(self.uri))
                sys.exit(1)
        elif jd['type'] == 'agent_status':
            self.uptime = jd['uptime']
            self.flows = jd['flows']
            self.flows_delta = jd['flows_prev'] - jd['flows']

        return jd

    def close(self):
        if self.sd is not None:
            self.sd.close()
