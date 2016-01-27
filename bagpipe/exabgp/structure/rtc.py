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

from bagpipe.exabgp.structure.asn import ASN
from bagpipe.exabgp.structure.address    import AFI,SAFI
from bagpipe.exabgp.message.update.attribute.communities import RouteTarget

class RouteTargetConstraint(object):
    # TODO: no support yet for RTC variable length with prefixing
    
    def __init__(self,afi,safi,origin_as,route_target):
        self.afi = AFI(afi)
        self.safi = SAFI(safi)
        self.origin_as = origin_as
        self.route_target = route_target
        
    def __len__(self):
        if self.route_target is None:
            return 1
        else:
            return (5 + len(self.route_target))
    
    def __str__ (self):
        if self.route_target is None:
            return "RTC Wildcard"
        else:
            return "RTC<%s>:%s" % ( self.origin_as, self.route_target )
    
    def __repr__(self):
        return self.__str__() 
    
    def __cmp__(self,other):
        if (isinstance(other,RouteTargetConstraint) and
            self.origin_as == other.origin_as and
            self.route_target == other.route_target):
            return 0
        else:
            return -1
        
    def __hash__(self):
        return hash(self.pack())

    @staticmethod
    def resetFlags(char):
        return chr(ord(char) & ~(0x40))

    def pack(self):
        if self.route_target ==  None:
            return pack("!B",0)
        else:
            packedRT = self.route_target.pack()
            # We reset ext com flag bits from the first byte in the packed RT
            # because in an RTC route these flags never appear.
            return pack("!BL", len(self)*8, self.origin_as) + RouteTargetConstraint.resetFlags(packedRT[0]) + packedRT[1:]
        
    @staticmethod
    def unpack(afi,safi,data):
        len_in_bits = ord(data[0]) 
        data=data[1:]
                
        if (len_in_bits==0):
            return RouteTargetConstraint(afi,safi,ASN(0),None)
        
        if (len_in_bits<4):
            raise Exception("RTC route too short to be decoded (len %d bits)" % len_in_bits)
        
        asn = ASN( unpack('!L', data[0:4] )[0] )
        data = data[4:]
        
        rt = RouteTarget.unpackFrom(data)
        return RouteTargetConstraint(afi,safi,asn,rt)
