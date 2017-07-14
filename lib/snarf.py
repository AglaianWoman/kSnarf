import logging, logging, netaddr, re, sys, time
from curses.ascii import isprint
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from lib.unifier import Unify
from lib.dhcp import Dhcp
from lib.main import Main

class Snarf(object):
    """Main class for packet handling"""
    
    def __init__(self, dbInstance, unity, sMode, sProtocol):
        self.cap = dbInstance
        self.unity = unity
        self.main = Main(self.cap, self.unity)
        self.sMode = sMode
        self.protocols = []

        ### Switch to dict when newer protocols are implemented
        if sProtocol is not None:
            self.protocols.append(sProtocol)
            self.dhcp = Dhcp(self.cap, self.unity)


    def sniffer(self):
        def snarf(packet):
            """Sniff the data"""
            
            ## Handle main
            self.main.trigger(packet)
            self.unity.logUpdate('main')
            
            ## Handle protocols
            if 'dhcp' in self.protocols:
                logged = self.dhcp.trigger(packet)
                if logged == True:
                    self.unity.logUpdate('dhcp')

            ## Increase total
            self.unity.logUpdate('total')
            
            ## stdouts
            self.unity.logUpdate('iterCount')
            if self.unity.logDict.get('iterCount') == 1000:
                self.cap.con.commit()
                print 'Total packets logged: %s' % self.unity.logDict.get('total')
                self.unity.logDict.update({'iterCount': 0})
        return snarf
                

    def string(self, word):
        def snarf(packet):
            """This function controls what we gather and pass to the DB
            Right now, there is no filtering at all
            The object word is simply an example of closure
            
            The parsing work is currently done in dbControl.py,
            Eventually this needs to be a pure API type call with different libs,
            for choosing what type of db entries to make
            """
            self.cap.entry(packet)
            self.pCount += 1
            self.tCount += 1
            if self.pCount == 100:
                print '%s frames logged' % self.tCount
                self.pCount = 0
                self.cap.con.commit()
        return snarf


    def printable(self, iPut):
        """Pretty printing function"""
        return ''.join(char for char in iPut if isprint(char))


    def k9(self, mac):
        def snarf(packet):
            """This function listens for a given MAC
            Currently no logic for detecting FCfield, etc...
            This functionality will be added later on
            """
            if packet.addr1 == mac or\
                packet.addr2 == mac or\
                packet.addr3 == mac or\
                packet.addr4 == mac:
                
                ## Handle main
                self.main.trigger(packet)
                self.unity.logUpdate('main')
                
                ## Increase total
                self.unity.logUpdate('total')
                
                ## Notify
                print 'SNARF!! %s traffic detected!' % (mac)
                
                notDecoded = hexstr(str(packet.notdecoded), onlyhex=1).split(' ')
                try:
                    fSig = -(256 - int(notDecoded[self.unity.offset + 3], 16))
                except IndexError:
                    fSig = ''
                print 'RSSI: %s' % fSig
                print '\n'
                #self.cap.entry(packet)
            else:
                return
        return snarf


    def macGrab(self, packet):
        """Defines the OUI for a given MAC
        This function serves as an example, it is not ready for implementation
        """
        try:
            parsed_mac = netaddr.EUI(packet.addr2)
            print parsed_mac.oui.registration().org
        except netaddr.core.NotRegisteredError, e:
            fields.append('UNKNOWN')
            
