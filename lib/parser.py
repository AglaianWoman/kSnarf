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
        """Driver offsets for RadioTap Headers
        
        Any portion of notdecoded could have been chosen for the offset, but
        after careful examination of multiple frames, it was determined that
        the frequency should be used as the offset point.  The reason behind
        this being that the things of most interest are closest to the
        frequency from a left to right perspective, bytewise.
        
        This offset is determined by taking packet.notdecoded and turning it
        into a list of bytes.  This is done by the following:
        notDecoded = hexstr(str(packet.notdecoded), onlyhex=1).split(' ')
        
        The list of bytes is then used as an offset based on the last byte of
        the frequency.  As an example, 2.447 GHz will be used.
        
        Bytewise 2447 is represented as 0x8f09.  Due to the way the IEEE deals
        with certain aspects of 802.11, we have to Little Endian this,
        thus 0x098f when converted to Decimal becomes 2447.
        
        Looking at this type of frame in Wireshark with the ath9k or ath9k_htc
        driver would yield the 09 byte in question as the 20th byte from left
        to right.  Thus, in list form using a zero index Python wise, we
        ascertain the offset to be that of 19.

        Capturing a Beacon in Scapy for PCAP consumption goes something like:
        pkt = sniff(iface = 'wlan0mon',
                    count = 1,
                    lfilter = lambda x: x[Dot11].type == 0 and\
                                        x[Dot11].subtype == 8)
        wrpcap('beacon.pcap', pkt)
        
        As of right now, this list is very small.  If you wish to contribute,
        please contact via a Github Issue with the type of driver you have and
        the offset associated with it.
        """
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
