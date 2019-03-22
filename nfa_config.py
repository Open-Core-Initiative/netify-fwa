import json
import configparser

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

def load_static(path):
    config = {}

    config = configparser.ConfigParser()

    config.add_section('netify-fwa')
    config.set('netify-fwa', 'firewall-engine', 'firewalld')
    config.set('netify-fwa', 'path-config-dynamic', '/etc/netify-fwa/netify-fwa.json')
    config.set('netify-fwa', 'ttl-match', '600')

    config.add_section('firewalld')
    config.set('firewalld', 'zones-external', 'public')
    config.set('firewalld', 'zones-internal', 'internal')

    config.add_section('iptables')
    config.set('iptables', 'interfaces-external', 'eth0')
    config.set('iptables', 'interfaces-internal', 'eth1,eth2')

    config.add_section('netify-agent')
    config.set('netify-agent', 'socket-uri', 'unix:///var/run/netifyd/netifyd.sock')

    config.add_section('netify-api')
    config.set('netify-api', 'path-cache', '/etc/netify-fwa/netify-api.json')
    config.set('netify-api', 'ttl-cache', '86400')
    config.set('netify-api', 'url', 'https://api.netify.ai/api/v1')

    not_found = False

    try:
        with open(path, 'r') as fd:
            config.read_file(fd)
    except FileNotFoundError as e:
        not_found = True        
        syslog(LOG_WARNING, "Configuration file not found: %s" %(path))

    if not_found:
        with open(path, 'w') as fd:
            config.write(fd)

    return config

def load_dynamic(path):
    config = None
    try:
        with open(path, 'r') as fd:
            config = json.load(fd)
    except FileNotFoundError as e:
        syslog(LOG_WARNING, "Configuration file not found: %s" %(path))

    return config
