import json
import configparser

def load_static(path):
    config = {}

    config = configparser.ConfigParser()

    config.add_section('netify-fwa')

    config.set('netify-fwa', 'path-dynamic-config', '/etc/netify-fwa/netify-fwa.json')

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
