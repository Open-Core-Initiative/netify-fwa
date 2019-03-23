import subprocess

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

def nfa_ipset_list():
    sets = []

    result = subprocess.run(
        ["ipset", "-L", "-n"],
            stdout=subprocess.PIPE, universal_newlines=True
        )
    if result.returncode == 0:
        if len(result.stdout):
            _sets = result.stdout.split()
            for s in _sets:
                if s.startswith('NFA_'):
                    sets.append(s)
    else:
        syslog(LOG_ERR, "IPSet error: %s" %(result))

    return sets

class nfa_ipset():
    """IPSet support for Netify FWA"""

    name = None
    type = "hash:ip,port,ip"
    ipv = "inet"
    timeout = 0

    def __init__(self, name, timeout=0, ipv=4, type="hash:ip,port,ip"):
        self.name = name
        self.type = type
        if ipv == 4:
            self.ipv = "inet"
        elif ipv == 6:
            self.ipv = "inet6"
        self.timeout = timeout

    def create(self):
        params = ["ipset", "create", self.name, self.type, "family", self.ipv]
        if self.timeout > 0:
            params.extend(["timeout", str(self.timeout)])

        result = subprocess.run(params,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            return False

        return True

    def destroy(self):
        params = ["ipset", "destroy", self.name]
        result = subprocess.run(params,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            return False

        return True

    def upsert(self, other_ip, ip_protocol, other_port, local_ip):
        entry = "%s,%d:%d,%s" %(other_ip, ip_protocol, other_port, local_ip)
        params = ["ipset", "-exist", "add", self.name, entry]
        result = subprocess.run(params,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if result.returncode != 0:
            return False

        return True
