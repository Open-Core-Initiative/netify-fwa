import re

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

from nfa_main import __nfa_config_cat_cache

__nfa_rx_app_id = None

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
    global __nfa_rx_app_id
    if __nfa_rx_app_id is None:
        __nfa_rx_app_id = re.compile('\d+')

    app_id = 0
    app_match = __nfa_rx_app_id.match(flow['detected_application_name'])
    if app_match is not None:
        app_id = int(app_match.group())

    if 'protocol' in rule and flow['detected_protocol'] != rule['protocol']:
        return False
    if 'application' in rule and app_id != rule['application']:
        return False

    if 'protocol_category' in rule:
        if __nfa_config_cat_cache is None:
            syslog(LOG_WARNING, "The protocol category cache is empty.")
            return False
        key = str(flow['detected_protocol'])
        if key not in __nfa_config_cat_cache['protocols']:
            return False
        if __nfa_config_cat_cache['protocols'][key] != rule['protocol_category']:
            return False
    if 'application_category' in rule:
        if __nfa_config_cat_cache is None:
            syslog(LOG_WARNING, "The application category cache is empty.")
            return False
        if app_id not in __nfa_config_cat_cache['applications']:
            return False
        if __nfa_config_cat_cache['applications'][app_id] != rule['application_category']:
            return False

    return True
