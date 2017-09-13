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

from struct import pack

import socket

from bagpipe.exabgp.message.update.attribute import AttributeID,Flag,Attribute

from bagpipe.exabgp.structure.mpls import LabelStackEntry, NO_LABEL



tunnel_types_to_class = dict()
def register(myclass):
    tunnel_types_to_class[myclass.subtype] = myclass


class PMSITunnel(Attribute):
    '''
    http://tools.ietf.org/html/rfc6514#section-5
    
      +---------------------------------+
      |  Flags (1 octet)                |
      +---------------------------------+
      |  Tunnel Type (1 octets)         |
      +---------------------------------+
      |  MPLS Label (3 octets)          |
      +---------------------------------+
      |  Tunnel Identifier (variable)   |
      +---------------------------------+
    '''
    ID = AttributeID.PMSI_TUNNEL
    FLAG = Flag.OPTIONAL | Flag.TRANSITIVE
    MULTIPLE = False

    def __init__ (self,subtype,label=NO_LABEL,flags=0,packedTunnelId=None):
        if label==None: label=NO_LABEL
        if not isinstance(label,LabelStackEntry): raise Exception("label should be of LabelStackEntry type (is: %s)" % type(label))
        self.subtype = subtype
        self.label = label
        self.pmsi_flags = flags
        self.packedTunnelId = packedTunnelId

    def pack(self):
        if self.packedTunnelId is None:
            self._computePackedTunnelId()
        return self._attribute(pack('!BB', self.pmsi_flags, self.subtype) + self.label.pack() + self.packedTunnelId)
    
    def __len__ (self):
        if self.packedTunnelId is None:
            self._computePackedTunnelId()
        return 4+len(self.packedTunnelId)

    def __str__ (self):
        if self.subtype in tunnel_types_to_class:
            type_string = tunnel_types_to_class[self.subtype].nickname
            return "PMSITunnel:%s:%s:[%s]" % (type_string,str(self.pmsi_flags) or '',self.label or "-")
        else:
            type_string = "%d" % self.subtype
            return "PMSITunnel:%s:%s:[%s]:%s" % (type_string,str(self.pmsi_flags) or '',self.label or "-","xxx") 
            #TODO: add hex dump of packedValue 

    def __repr__ (self):
        return str(self)

    def _computePackedTunnelId(self):
        raise Exception("Abstract class, cannot compute packedTunnelId")
    
    def __cmp__(self,o):
        if (not isinstance(o,PMSITunnel) or
            (self.subtype != o.subtype) or
            (self.label != o.label) or
            (self.pmsi_flags != o.pmsi_flags) or
            (self.packedTunnelId != o.packedTunnelId)
            ): 
            return -1
        else:
            return 0
    
    @staticmethod
    def unpack(data):
        #flags
        flags = ord(data[0])
        data=data[1:]
        
        #subtype
        subtype = ord(data[0])
        data=data[1:]
        
        #label
        label = LabelStackEntry.unpack(data[:3])
        data=data[3:]
        
        if subtype in tunnel_types_to_class:
            return tunnel_types_to_class[subtype].unpack(label,flags,data)
        else:
            return PMSITunnel(subtype,label,flags,data)



class PMSITunnelIngressReplication(PMSITunnel):

    subtype = 6
    nickname = "IngressReplication"

    def __init__(self,ip,label=NO_LABEL,flags=0):
        try:
            socket.inet_pton( socket.AF_INET, ip )
        except:
            raise Exception("Malformed IP address")
        self.ip = ip

        PMSITunnel.__init__(self, self.subtype, label, flags)
        
    def __str__ (self):
        desc = "[%s]" % self.ip
        return PMSITunnel.__str__(self) + ":" + desc
        
    def _computePackedTunnelId(self):
        self.packedTunnelId = socket.inet_pton( socket.AF_INET, self.ip )

    @staticmethod
    def unpack(label,flags,data):
        ip = socket.inet_ntop( socket.AF_INET, data[:4] )
        return PMSITunnelIngressReplication(ip,label,flags)


register(PMSITunnelIngressReplication)

