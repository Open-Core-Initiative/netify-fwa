from firewall import client

from syslog import \
    openlog, syslog, LOG_PID, LOG_PERROR, LOG_DAEMON, \
    LOG_DEBUG, LOG_ERR, LOG_WARNING

class nfa_firewall(client.FirewallClient):
    """Firewalld support for Netify FWA"""

    def __init__(self):
        super().__init__()

    def test(self):
        zone_default = self.getDefaultZone()
        zone_settings = self.getZoneSettings(zone_default)

        syslog(LOG_DEBUG, " name: %s" %(zone_settings.getShort()))
        syslog(LOG_DEBUG, " desc: %s" %(zone_settings.getDescription()))
