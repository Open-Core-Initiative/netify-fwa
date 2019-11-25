import re

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

import nfa_global

def criteria(rule):
    criteria = []
    if 'protocol' in rule:
        criteria.append(str(rule['protocol']))
    else:
        criteria.append(str(0))

    if 'protocol_category' in rule:
        criteria.append(str(rule['protocol_category']))
    else:
        criteria.append(str(0))

    if 'application' in rule:
        criteria.append(str(rule['application']))
    else:
        criteria.append(str(0))

    if 'application_category' in rule:
        criteria.append(str(rule['application_category']))
    else:
        criteria.append(str(0))

    return '_'.join(criteria)

def flow_matches(flow, rule):
    if nfa_global.rx_app_id is None:
        nfa_global.rx_app_id = re.compile('\d+')

    app_id = 0
    app_match = nfa_global.rx_app_id.match(flow['detected_application_name'])
    if app_match is not None:
        app_id = int(app_match.group())

    if 'protocol' in rule and flow['detected_protocol'] != int(rule['protocol']):
        return False
    if 'application' in rule and app_id != int(rule['application']):
        return False

    try:
        if 'protocol_category' in rule:
            key = str(flow['detected_protocol'])
            if key not in nfa_global.config_cat_cache['protocols']:
                return False
            if nfa_global.config_cat_cache['protocols'][key] != int(rule['protocol_category']):
                return False
        if 'application_category' in rule:
            key = str(app_id)
            if key not in nfa_global.config_cat_cache['applications']:
                return False
            if nfa_global.config_cat_cache['applications'][key] != int(rule['application_category']):
                return False
    except TypeError:
        return False

    return True
