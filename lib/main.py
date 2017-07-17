from dhcp_modules import discovery
from scapy.all import *

class Main(object):
    """Handles Main logging aspect"""

    def __init__(self, dbInstance, unity):
        self.unity = unity
        self.cap = dbInstance
        self.cap.db.execute('CREATE TABLE IF NOT EXISTS main(pid INTEGER,\
                                                         epoch INTEGER,\
                                                         date TEXT,\
                                                         time TEXT,\
                                                         addr1 TEXT,\
                                                         addr2 TEXT,\
                                                         addr3 TEXT,\
                                                         type TEXT,\
                                                         subtype TEXT,\
                                                         rssi INTEGER,\
                                                         direc TEXT,\
                                                         channel INTEGER,\
                                                         frequency INTEGER)')


    def trigger(self, packet):
        """Trigger mechanism for main entries"""

        ## Deal with driver offsets
        notDecoded = hexstr(str(packet.notdecoded), onlyhex=1).split(' ')
        if self.unity.offset:
            #print('OFFSET')
            try:
                fChannel = self.unity.pParser.channels(int(notDecoded[self.unity.offset] + notDecoded[self.unity.offset - 1], 16))
            except:
                fChannel = 'Unknown'
            try:
                fFreq = int(notDecoded[self.unity.offset] + notDecoded[self.unity.offset - 1], 16)
            except:
                fFreq = ''
            try:
                fSig = -(256 - int(notDecoded[self.unity.offset + 3], 16))
            except IndexError:
                fSig = ''
        else:
            fChannel = ''
            fFreq = ''
            fSig = ''
            
        ## Values for DB entry
        epoch, lDate, lTime = self.unity.times()
        #self.unity.pParser.nType(packet.type)
        pType = self.unity.pParser.symString(packet[Dot11],
                                             packet[Dot11].type,
                                             'type')
        fcField = self.unity.pParser.symString(packet[Dot11],
                                               packet[Dot11].FCfield,
                                               'FCfield')
        
        ## DB entry
        self.cap.db.execute('INSERT INTO main VALUES(?,\
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
                                                ?,\
                                                ?);',\
                                                    (self.unity.logDict.get('total'),\
                                                    epoch,\
                                                    lDate,\
                                                    lTime,\
                                                    packet.addr1,\
                                                    packet.addr2,\
                                                    packet.addr3,\
                                                    pType,\
                                                    packet.subtype,\
                                                    fSig,\
                                                    fcField,\
                                                    fChannel,\
                                                    fFreq))
        
        return True
        