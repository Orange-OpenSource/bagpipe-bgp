# encoding: utf-8
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

from struct import pack,unpack
import socket

from bagpipe.exabgp.structure.ip import _Prefix
from bagpipe.exabgp.structure.ip import _bgp as len_to_bytes
from bagpipe.exabgp.structure.ip import Inet
from bagpipe.exabgp.structure.address    import AFI,SAFI

from bagpipe.exabgp.structure.mpls import unpackLabelStack

class RouteDistinguisher(object):

    TYPE_AS2_LOC = 0    # Format AS(2bytes):AN(4bytes) 
    TYPE_IP_LOC  = 1    # Format IP address:AN(2bytes)
    TYPE_AS4_LOC = 2    # Format AS(4bytes):AN(2bytes)

    def __init__(self,rdtype,asn,ip,loc):
        self.type = rdtype

        if rdtype in (self.TYPE_AS2_LOC, self.TYPE_AS4_LOC):
            self.asn = asn
            self.loc = loc 
            self.ip = ""
        elif rdtype == self.TYPE_IP_LOC:
            self.ip = ip
            self.loc = loc
            self.asn = 0
        else: 
            raise Exception("unsupported rd rdtype")
        
    def __str__ (self):
        if self.type in(self.TYPE_AS2_LOC,self.TYPE_AS4_LOC):
            return "%s:%s" % (self.asn, self.loc)
        elif self.type == self.TYPE_IP_LOC:
            return "%s:%s" % (self.ip, self.loc)
        else:
            raise "BROKEN RD / UNKNOWN TYPE"

    def __len__(self):
        return 8

    def __repr__ (self):
        return str(self)
    
    def __cmp__(self,other):
        if (isinstance(other,RouteDistinguisher) 
            and self.type == other.type and
            self.asn == other.asn and
            self.ip == other.ip and
            self.loc == other.loc ):
            return 0
        else:
            return -1
    
    def pack(self):
        if self.type == self.TYPE_AS2_LOC:
            return pack( '!HHL', self.type, self.asn, self.loc)
        elif self.type == self.TYPE_IP_LOC:
            encoded_ip = socket.inet_pton(socket.AF_INET, self.ip )
            return pack( '!H4sH', self.type, encoded_ip, self.loc)
        elif self.type == self.TYPE_AS4_LOC:
            return pack( '!HLH', self.type, self.asn, self.loc)
        else:
            raise Exception("Incorrect RD type %d // not supposed to happen !!" % self.type)
        
    @staticmethod
    def unpack(data):
        rdtype = unpack( '!H', data[0:2] )[0]
        data = data[2:]
    
        if rdtype == RouteDistinguisher.TYPE_AS2_LOC:
            asn,loc = unpack("!HL",data )
            ip = None
        elif rdtype == RouteDistinguisher.TYPE_IP_LOC:
            ip = socket.inet_ntop(socket.AF_INET, data[0:4])
            loc = unpack( '!H', data[4:])[0]
            asn = None
        elif rdtype == RouteDistinguisher.TYPE_AS4_LOC:
            asn,loc = unpack("!LH",data )
            ip = None
        else: 
            raise Exception("unsupported rd rdtype: %d" % rdtype)
        
        return RouteDistinguisher(rdtype,asn,ip,loc)


class VPNLabelledPrefix(object):

    def __init__(self,afi,safi,prefix,rd,labelStack):
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.rd = rd
        self.labelStack = labelStack  # an array of LabelStackEntry's
        if type(labelStack) != list or len(labelStack)==0:
            raise Exception("Labelstack has to be a non-empty array")
        self.prefix = prefix
    
    def __str__ (self):
        return "RD:%s %s MPLS:[%s]" % (self.rd, self.prefix, "|".join(map(str,self.labelStack)))

    def __repr__(self):
        return self.__str__() 

    def pack(self):
        bitlen = (len(self)-len(self.prefix))*8 + self.prefix.mask
        
        stack = ''.join( map(lambda x:x.pack(), self.labelStack ) )
        
        return chr(bitlen) + stack + self.rd.pack() + self.prefix.pack()[1:]
        
    def __len__(self):
        # returns the length in bits!
        return    len(self.labelStack) * len(self.labelStack[0]) + len(self.rd) + len(self.prefix)
        
        
    def __cmp__(self,other):
        #
        # Note well: we need an advertise and a withdraw for the same RD:prefix to result in 
        # objects that are equal for Python, this is why the test below does not look at self.labelstack
        #
        if (isinstance(other,VPNLabelledPrefix) and
            self.rd == other.rd and
            self.prefix == other.prefix):
            return 0
        else:
            return -1
        
    def __hash__(self):  #FIXME: improve for better performance?
        return hash("%s:%s" % (self.rd,self.prefix))
    
    @staticmethod
    def unpack(afi,safi,data):
                
        # prefix len
        bitlen = ord(data[0]) 
        data=data[1:]
        initial_len = len(data)
        
        # data is supposed to be: label stack, rd, prefix
        labelStack,consummed = unpackLabelStack(data)
        data=data[consummed:]
        
        rd = RouteDistinguisher.unpack(data[:8])
        data=data[8:]
        
        prefix_len_in_bits = bitlen - (initial_len - len(data))*8
        last_byte = len_to_bytes[prefix_len_in_bits]
        prefix = _Prefix(afi, data[0:last_byte] + '\0'*(Inet._length[afi]-last_byte) , prefix_len_in_bits )
        
        return VPNLabelledPrefix(afi,safi,prefix,rd,labelStack)
