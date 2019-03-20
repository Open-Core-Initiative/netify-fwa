import json
import configparser

def load_static(path):
    config = {}

    config = configparser.ConfigParser()

    config.add_section('netify-fwa')
    config.set('netify-fwa', 'path-dynamic-config', '/etc/netify-fwa/netify-fwa.json')

    config.add_section('netify-agent')
    #config.set('netify-agent', 'socket-uri', 'tcp://somehost.com:2100/')
    config.set('netify-agent', 'socket-uri', 'file:///var/run/netifyd/netifyd.sock')

    config.add_section('netify-api')
    config.set('netify-api', 'url', 'https://api.netify.ai/api/v1')
    config.set('netify-api', 'ttl-cache', '86400')
    config.set('netify-api', 'path-cache', '/etc/netify-fwa/netify-api.json')

    try:
        with open(path, 'r') as fd:
            config.read_file(fd)
    except FileNotFoundError as e:
        print("Configuration file not found: %s" %(path))

    return config

def load_dynamic(path):
    config = None
    try:
        with open(path, 'r') as fd:
            config = json.load(fd)
    except FileNotFoundError as e:
        print("Configuration file not found: %s" %(path))

    return config
