from dhcp_modules import discovery, request
from scapy.all import *

class Dhcp(object):
    """Handles all aspects of DHCP"""

    def __init__(self, dbInstance, unity):
        self.unity = unity
        self.discovery = discovery.Discovery(dbInstance, unity)
        self.request = request.Request(dbInstance, unity)
        dbInstance.db.execute('CREATE TABLE IF NOT EXISTS dhcp(pid INTEGER,\
                                                         epoch INTEGER,\
                                                         date TEXT,\
                                                         time TEXT,\
                                                         addr1 TEXT,\
                                                         addr2 TEXT,\
                                                         addr3 TEXT,\
                                                         `message-type` TEXT,\
                                                         `requested_addr` TEXT,\
                                                         server TEXT,\
                                                         vendor TEXT,\
                                                         hostname TEXT)')


    def trigger(self, packet):
        """Trigger mechanism for DHCP entries"""
        logged = False

        ## DHCP Discovery
        if packet.haslayer('DHCP') and packet[DHCP].options[0][1] == 1:
            self.discovery.entry(packet, self.unity)
            logged = True

        ## DHCP Request
        if packet.haslayer('DHCP') and packet[DHCP].options[0][1] == 3:
            self.request.entry(packet, self.unity)
            logged = True
        
        return logged
        