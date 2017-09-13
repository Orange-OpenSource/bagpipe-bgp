"""
Copyright (c) 2014, Orange
All rights reserved.

File released under the BSD 3-Clause license.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions 
are met:

1. Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in 
   the documentation and/or other materials provided with the 
   distribution.

3. Neither the name of the copyright holder nor the names of its 
   contributors may be used to endorse or promote products derived 
   from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN 
ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.
"""

from struct import pack, unpack

import socket

from bagpipe.exabgp.structure.address    import AFI,SAFI

from bagpipe.exabgp.structure.vpn import RouteDistinguisher

from bagpipe.exabgp.structure.mpls import LabelStackEntry, NO_LABEL





class EthernetSegmentIdentifier(object):
    
    #
    # TODO: take into account E-VPN specs that specify the role of the first bit of ESI
    # (since draft-ietf-l2vpn-evpn-05)
    
    default = [0 for _ in range(0,10)]
    
    def __init__(self,byteList=None):
        '''
        byteList: a list of bytes
        '''
        if byteList is None:
            self.bytes = EthernetSegmentIdentifier.default 
        elif (len(byteList)==10):
            self.bytes = byteList
        else:
            raise Exception("ESI identifier must be 10-bytes long")

    def __str__ (self):
        if self.bytes == EthernetSegmentIdentifier.default:
            return "-"
        else:
            return ":".join( map(lambda x: hex(x)[2:4], self.bytes ) )

    def __repr__(self):
        return self.__str__() 

    def pack (self):
        return pack("B"*len(self.bytes),*self.bytes)

    def __len__ (self):
        return 10
        
    def __cmp__(self,other):
        if (isinstance(other,EthernetSegmentIdentifier) and
                self.bytes == other.bytes):
            return 0
        else:
            return -1
        
    def __hash__(self): #FIXME: improve for better performance?
        return hash( ":".join(self.bytes))

    @staticmethod
    def unpack(data):
        return EthernetSegmentIdentifier( list(unpack("B"*len(data),data)) )
        
        
class EthernetTag(object):

    MAX = 2**32-1

    def __init__(self,tag=0):
        '''
        tag is a 4-byte numerical value, with 0 <= value < EthernetTag.MAX (2^32-1)
        '''
        if (isinstance(tag,int) and tag>=0 and tag < EthernetTag.MAX):
            self.tag=tag
        else:
            raise Exception("Ethernet tag value not integer, too high or too low: %d" % tag)
        
    def __str__ (self):
        return repr(self.tag)
        
    def __repr__(self):
        return repr(self.tag) 

    def pack (self):
        return pack("!I",self.tag)
        
    def __len__ (self):
        return 4
        
    def __cmp__(self,other):
        if (isinstance(other,EthernetTag) and
                self.tag == other.tag):
            return 0
        else:
            return -1
        
    def __hash__(self):
        return self.tag
            
    @staticmethod
    def unpack(data):
        if len(data)==4:
            return EthernetTag( unpack("!I",data)[0] )
        else:
            raise Exception("data length must be 4 for an Ethernet tag")


class MAC(object):
    
    def __init__(self,mac):
        '''
        mac: a colon separated MAC address (eg. "de:ad:00:00be:ef")
        '''
        self.bytes = MAC.bytesFromMac(mac)
    
    @staticmethod
    def bytesFromMac(mac):
        if not (isinstance(mac,str) or isinstance(mac,unicode)):
            raise Exception("cannot create MAC from something else than a string (%s was given)" % type(mac))
        try:
            bytesV = map(lambda x: int(x,16), mac.split(":"))
        except ValueError as e:
            raise Exception("wrong mac format (%s)" % e)
                     
        if len(bytesV) != 6 :
            raise Exception("wrong mac format (must have six bytes)")
        
        for b in bytesV:
            if b>=256: raise Exception("wrong mac format (at least one value is too big))") 
        
        return bytesV
    
    def __str__ (self):
        return ":".join( map(lambda x: ("0" if x<16 else "")+(hex(x).lower()[2:4]), self.bytes ) )
    
    def __repr__(self):
        return self.__str__() 
    
    def pack (self):
        return pack("B"*len(self.bytes),*self.bytes)
            
    def __len__ (self):
        return 10
        
    def __cmp__(self,other):
        if (isinstance(other,MAC) and
                self.bytes == other.bytes):
            return 0
        else:
            return -1
        
    def __hash__(self): #FIXME: improve for better performance?
        return hash( self.__str__() )
    
    @staticmethod
    def unpack(data):
        bytesL = list(unpack("B"*len(data),data))
        
        return MAC( ":".join( map(lambda x: hex(x)[2:4], bytesL ) ) )



EVPN_types_to_class = dict()

def register(myclass):
    EVPN_types_to_class[myclass.subtype] = myclass

class EVPNNLRI(object):
    '''
    +-----------------------------------+
    |    Route Type (1 octet)           |
    +-----------------------------------+
    |     Length (1 octet)              |
    +-----------------------------------+
    | Route Type specific (variable)    |
    +-----------------------------------+
    '''
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)
    
    def __init__(self,subtype,packedValue=None):
        self.subtype = subtype
        self.packedValue = packedValue

    def __str__ (self):
        if self.subtype in EVPN_types_to_class:
            type_string = EVPN_types_to_class[self.subtype].nickname
            return "EVPN:%s" % type_string
        else:
            type_string = "%d" % self.subtype
            return "EVPN:%s:%s" % (type_string,"...")  #FIXME: add binascii dump of packedValue

    def __repr__(self):
        return self.__str__()

    def pack(self):
        if self.packedValue is None:
            self._computePackedValue()
        return pack('!BB', self.subtype, len(self.packedValue)) + self.packedValue

    def _computePackedValue(self):
        raise Exception("Abstract class, cannot compute packedValue")
        
    def __len__ (self):
        if self.packedValue is None:
            self._computePackedValue()
        return len(self.packedValue)+2
    
    def __cmp__(self,other):
        #
        # For subtype 2, we will have to ignore a part of the route, so this method will be overridden 
        #
        if self.packedValue is None:
            self._computePackedValue()
        if other.packedValue is None:
            other._computePackedValue()
            
        if (isinstance(other,EVPNNLRI) and
            self.subtype == other.subtype and
            self.packedValue == other.packedValue):
            return 0
        else:
            return -1
        
    def __hash__(self):  #FIXME: improve for better performance?
        #
        # same as above: need to ignore label and ESI for subtype 2
        #
        if self.packedValue is None:
            self._computePackedValue()
        return hash("%s:%s:%s:%s" % (self.afi,self.safi,self.subtype,self.packedValue))
        
    @staticmethod
    def unpack(data):
        
        #subtype
        typeid = ord(data[0])
        data=data[1:]
        
        #length
        length = ord(data[0]) 
        data=data[1:length+1]
        
        if typeid in EVPN_types_to_class:
            return EVPN_types_to_class[typeid].unpack(data)
        else:
            return EVPNNLRI



    
class EVPNMACAdvertisement(EVPNNLRI):
    '''
    +---------------------------------------+
    |      RD   (8 octets)                  |
    +---------------------------------------+
    |Ethernet Segment Identifier (10 octets)|
    +---------------------------------------+
    |  Ethernet Tag ID (4 octets)           |
    +---------------------------------------+
    |  MAC Address Length (1 octet)         |  
    +---------------------------------------+
    |  MAC Address (6 octets)               |
    +---------------------------------------+
    |  IP Address Length (1 octet)          |  zero if IP Address field absent
    +---------------------------------------+
    |  IP Address (4 or 16 octets)          |
    +---------------------------------------+
    |  MPLS Label (3 octets)                |
    +---------------------------------------+
    '''
    subtype = 2
    nickname = "MACAdv"

    def __init__(self,rd,esi,etag,mac,label,ip=None,maclen=48):
        '''
        rd: a RouteDistinguisher
        esi: an EthernetSegmentIdentifier
        etag: an EthernetTag
        mac: a MAC
        label: a LabelStackEntry
        ip: an IP address (dotted quad string notation)  - optional
        maclen: length in bits of the MAC prefix being advertised (defaults to 48)
        '''
        self.rd = rd
        self.esi = EthernetSegmentIdentifier(0) if esi is None else esi
        self.etag = EthernetTag(0) if etag is None else etag
        self.maclen = maclen
        self.mac = mac
        self.ip = ip
        self.label = label
        if self.label is None: self.label = NO_LABEL
        # what to do with super ?
        EVPNNLRI.__init__(self, self.__class__.subtype)

    def __str__ (self):
        desc = "[rd:%s][esi:%s][etag:%s][%s%s][%s][label:%s]" % (self.rd, self.esi, self.etag, 
                                             self.mac, "" if self.maclen==48 else "/%d" % self.maclen, 
                                             self.ip if self.ip else "", 
                                             self.label)
        return "%s:%s" % (EVPNNLRI.__str__(self), desc) 
    
    def __cmp__(self,other):
        if (isinstance(other,self.__class__)
            and self.rd == other.rd
            #and self.esi == other.esi  ## must *not* be part of the test
            and self.etag == other.etag
            and self.mac == other.mac
            and self.ip == other.ip
            #and self.label == other.label ## must *not* be part of the test 
            ):
            return 0
        else:
            return -1
        
    def __hash__(self):
        # esi and label must *not* be part of the hash
        return hash("%s:%s:%s:%s" % (self.rd,self.etag,self.mac,self.ip))
    
    def _computePackedValue(self):
        
        value = ( self.rd.pack() +
                  self.esi.pack() +
                  self.etag.pack() +
                  pack("B",self.maclen) +
                  self.mac.pack()
                )
        
        if self.ip:
            encoded_ip = socket.inet_pton( socket.AF_INET, self.ip )
            value += pack("B",len(encoded_ip)*8) + encoded_ip
        else:
            value += b'\0'
        
        value += self.label.pack()
        
        self.packedValue = value
        
    @staticmethod
    def unpack(data):
        
        rd = RouteDistinguisher.unpack(data[:8])
        data=data[8:]
        
        esi = EthernetSegmentIdentifier.unpack(data[:10])
        data=data[10:]
        
        etag = EthernetTag.unpack(data[:4])
        data=data[4:]
        
        maclen = ord(data[0])
        data=data[1:]
        
        mac = MAC.unpack(data[:6])
        data=data[6:]
        
        iplen = ord(data[0])
        data=data[1:]
        
        if iplen == 0:
            ip = None
            iplen_byte=0
        elif iplen == 4*8:
            ip = socket.inet_ntop( socket.AF_INET, data[:4] )
            iplen_byte=4
        elif iplen == 16*8:
            ip = socket.inet_ntop( socket.AF_INET6, data[:16] )
            iplen_byte=16
        else:
            raise Exception("IP field length is given as %d, but EVPN route currently support only IPv4" % iplen)
        data=data[iplen_byte:]
        
        label = LabelStackEntry.unpack(data[:3])
        
        return EVPNMACAdvertisement(rd,esi,etag,mac,label,ip,maclen)
        
register(EVPNMACAdvertisement)



class EVPNMulticast(EVPNNLRI):
    '''
    +---------------------------------------+
    |      RD   (8 octets)                  |
    +---------------------------------------+
    |  Ethernet Tag ID (4 octets)           |
    +---------------------------------------+
    |  IP Address Length (1 octet)          |
    +---------------------------------------+
    |   Originating Router's IP Addr        |
    |          (4 or 16 octets)             |
    +---------------------------------------+
    '''
    
    subtype = 3
    nickname = "Multicast"

    def __init__(self,rd,etag,ip):
        '''
        rd: a RouteDistinguisher
        etag: an EthernetTag
        '''
        self.rd = rd
        self.etag = EthernetTag(0) if etag is None else etag
        self.ip = ip

        EVPNNLRI.__init__(self, self.__class__.subtype)

    def __str__ (self):
        desc = "[rd:%s][etag:%s][%s]" % (self.rd, self.etag, self.ip)
        return EVPNNLRI.__str__(self) + ":" + desc
    
    def __cmp__(self,other):
        if (isinstance(other,self.__class__)
            and self.rd == other.rd
            and self.etag == other.etag
            and self.ip == other.ip 
            ):
            return 0
        else:
            return -1
    
    def __hash__(self):  #FIXME: improve for better performance?
        return hash("%s:%s:%s:%s:%s:%s" % (self.afi,self.safi,self.subtype,self.rd,self.etag,self.ip))
    
    def _computePackedValue(self):

        encoded_ip = socket.inet_pton( socket.AF_INET, self.ip )
        
        self.packedValue = ( self.rd.pack() +
                             self.etag.pack() +
                             pack("B",len(encoded_ip)*8) + 
                             encoded_ip
                            )
        
    @staticmethod
    def unpack(data):
        
        rd = RouteDistinguisher.unpack(data[:8])
        data=data[8:]
              
        etag = EthernetTag.unpack(data[:4])
        data=data[4:]
                
        iplen = ord(data[0])
        data=data[1:]
        
        if iplen == 4*8:
            ip = socket.inet_ntop( socket.AF_INET, data[:4] )
        elif iplen == 16*8:
            ip = socket.inet_ntop( socket.AF_INET6, data[:16] )
        else:
            raise Exception("IP len is %d, but EVPN route currently support only IPv4" % iplen)
        data=data[iplen:]
        
        return EVPNMulticast(rd,etag,ip)

register(EVPNMulticast)

