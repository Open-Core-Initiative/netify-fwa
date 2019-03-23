import json
import configparser

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

from nfa_version import NFA_JSON_CONFIG_VERSION

def load_main(path):
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
    config.set('netify-api', 'path-category-cache', '/etc/netify-fwa/netify-categories.json')
    config.set('netify-api', 'ttl-category-cache', '86400')
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

def key_exists(data, name, key):
    if key not in data:
        syslog(LOG_ERR, "Malformed %s, required key \"%s\" not found." %(name, key))
        return False

    return True

def one_key_exists(data, name, keys):
    key_found = False
    for key in keys:
        if key in data:
            key_found = True
            break

    if not key_found:
        syslog(LOG_ERR, "Malformed %s, at least one key required: \"%s\"." %(name, key.join(', ')))
        return False

    return True

def all_keys_exists(data, name, keys):
    keys_found = True
    for key in keys:
        if key not in data:
            keys_found = False
            break

    if not keys_found:
        syslog(LOG_ERR, "Malformed %s, all keys required: \"%s\"." %(name, key.join(', ')))
        return False

    return True

def load_json(path):
    config = None
    try:
        with open(path, 'r') as fd:
            config = json.load(fd)
    except FileNotFoundError as e:
        syslog(LOG_WARNING, "Configuration file not found: %s" %(path))

    return config

def load_dynamic(path):
    config = load_json(path)

    if config is None:
        return None

    name = 'dynamic JSON configuration'

    if not key_exists(config, name, 'version'):
        return None

    if config['version'] > NFA_JSON_CONFIG_VERSION:
        syslog(LOG_ERR, "Unsupported %s version: %.02f" %(name, config['version']))
        return None

    if not key_exists(config, name, 'rules'):
        return None
    if not key_exists(config, name, 'whitelist'):
        return None

    valid_rule_types = [ 'block', 'prioritize' ]

    for rule in config['rules']:

        if not key_exists(rule, name, 'type'):
            return None

        if rule['type'] not in valid_rule_types:
            syslog(LOG_ERR,
                "Malformed %s, invalid rule type: \"%s\"." %(name, rule['type']))
            return None

        if rule['type'] == 'prioritize' and not key_exists(rule, name, 'priority'):
            return None

        if not one_key_exists(rule, name, [
            'protocol', 'application', 'protocol_category', 'application_category'
            ]):
            return None

        if 'time-start' in rule and 'time-stop' not in rule:
            syslog(LOG_ERR,
                "Malformed %s, required key not found: \"%s\"." %(name, 'time-stop'))
            return None
        elif 'time-stop' in rule and 'time-start' not in rule:
            syslog(LOG_ERR,
                "Malformed %s, required key not found: \"%s\"." %(name, 'time-start'))
            return None

    valid_whitelist_types = [ 'mac', 'ipv4', 'ipv6' ]

    for addr in config['whitelist']:

        if not key_exists(addr, name, 'type'):
            return None

        if addr['type'] not in valid_whitelist_types:
            syslog(LOG_ERR,
                "Malformed %s, invalid address type: \"%s\"." %(name, addr['type']))
            return None

        if not key_exists(addr, name, 'address'):
            return None

    return config

def load_cat_cache(path):
    config = load_json(path)

    if config is None:
        return None

    return config
