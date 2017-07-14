class Names(object):
    """This class helps kSnarf to parse
    
    Parsing is done by way of dictionaries
    This is sort of a reverse way to look at scapy
    """

    def __init__(self):
        pass


    def channels(self, val):
        """Frequency to Channel converter"""
        typeDict = {2412: '1',
                    2417: '2',
                    2422: '3',
                    2427: '4',
                    2432: '5',
                    2437: '6',
                    2442: '7',
                    2447: '8',
                    2452: '9',
                    2457: '10',
                    2462: '11',
                    2467: '12',
                    2472: '13',
                    2484: '14'}
        return typeDict.get(val)

    
    def dhcpType(self, val):
        """DHCP Type converter"""
        typeDict = {1: "discover",
                    2: "offer",
                    3: "request",
                    4: "decline",
                    5: "ack",
                    6: "nak",
                    7: "release",
                    8: "inform",
                    9: "force_renew",
                    10:"lease_query",
                    11:"lease_unassigned",
                    12:"lease_unknown",
                    13:"lease_active"}
        return typeDict.get(val)


    def drivers(self, val):
        """Driver offsets for RadioTap Headers"""
        typeDict = {'ath9k': 19,
                    'ath9k_htc': 19,
                    'wl12xx': 11}
        return typeDict.get(val)


    def symString(self, packet, pField, fString):
        """Shows the symblic string for a given field

        Where p is UDP(), and you want p.dport symbolically:
            symString(p, p.dport, 'dport')
        
        Where p is UDP()/DNS(), and you want p[DNS].opcode symbolically:
            symString(p[DNS], p[DNS].opcode, 'opcode')
        """
        return packet.get_field(fString).i2repr(packet, pField)
