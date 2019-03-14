from firewall import client

class nfa_firewall:
    """Firewall interface for Netify FWA"""

    #def __init__(self):

class nfa_fwd1(nfa_firewall, client.FirewallClient):
    """Firewalld support for Netify FWA"""

    def __init__(self):
        super().__init__()

    def test(self):
        zone_default = self.getDefaultZone()
        zone_settings = self.getZoneSettings(zone_default)

        print(" name: %s" %(zone_settings.getShort()))
        print(" desc: %s" %(zone_settings.getDescription()))
