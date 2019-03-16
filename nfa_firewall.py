from firewall import client

class fwd1(client.FirewallClient):
    """Firewalld support for Netify FWA"""

    def __init__(self):
        super().__init__()

    def test(self):
        zone_default = self.getDefaultZone()
        zone_settings = self.getZoneSettings(zone_default)

        print(" name: %s" %(zone_settings.getShort()))
        print(" desc: %s" %(zone_settings.getDescription()))
