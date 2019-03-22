import subprocess

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

class nfa_firewall():
    """Generic iptables support for Netify FWA"""

    def __init__(self):
        super().__init__()

    def get_version(self):
        result = subprocess.run(
            ["iptables", "--version"],
            stdout=subprocess.PIPE, universal_newlines=True
        )
        return result.stdout

    def is_running(self):
        return True

    def test(self):
        pass
