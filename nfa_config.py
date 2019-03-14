import configparser

def nfa_config_load(path):
    config = configparser.ConfigParser()
    config.read(path)

    return config

