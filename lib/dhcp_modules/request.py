from lib.parser import Names
from scapy.all import *

pParser = Names()

class Request(object):
    """Adds DHCP Request entries to a pre-existing sqlite3 database"""
    def __init__(self, dbInstance, unity):
        self.cap = dbInstance
        self.unity = unity


    def entry(self, packet, unity):
        """packet.haslayer('DHCP') and packet[DHCP].options[0][1] == 3"""
        pDict = {}
        for i in packet[DHCP].options:
            if type(i) is tuple:
                pDict.update({i[0]: i[1]})

        ## Values for DB entry
        epoch, lDate, lTime = self.unity.times()

        self.cap.db.execute('INSERT INTO `dhcp` VALUES(?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?,\
                                                       ?);',\
                                                           (self.unity.logDict.get('total'),\
                                                            epoch,\
                                                            lDate,\
                                                            lTime,\
                                                            packet.addr1,\
                                                            packet.addr2,\
                                                            packet.addr3,\
                                                            pParser.dhcpType(pDict.get('message-type')),\
                                                            pDict.get('requested_addr'),\
                                                            pDict.get('server_id'),\
                                                            pDict.get('vendor'),\
                                                            pDict.get('hostname')))
