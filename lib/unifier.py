import time
from parser import Names

pParser = Names()

class Unify(object):
    """This class acts a singular point of contact for tracking purposes"""

    def __init__(self, iwDriver):
        ## Set the driver
        self.iwDriver = iwDriver
        
        ## Notate driver offset
        self.pParser = Names()
        self.offset = self.pParser.drivers(self.iwDriver)

        ## Packet logs
        self.logDict = {'iterCount': 1,
                        'dhcp': 1,
                        'main': 1,
                        'total': 1}


    def logUpdate(self, key):
        """Increase the count by 1 for a given key"""
        count = self.logDict.get(key)
        self.logDict.update({key: count + 1})


    def times(self):
        """Timestamp function"""
        ### This converts to Wireshark style
        #int(wepCrypto.endSwap('0x' + p.byteRip(f.notdecoded[8:], qty = 8, compress = True)), 16)
        epoch = int(time.time())
        lDate = time.strftime('%Y%m%d', time.localtime())
        lTime = time.strftime('%H:%M:%S', time.localtime())
        return epoch, lDate, lTime
