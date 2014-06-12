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


import socket

from exabgp.message.update.attribute import AttributeID,Flag,Attribute

class OriginatorId(Attribute):
    ID = AttributeID.ORIGINATOR_ID
    FLAG = Flag.OPTIONAL
    MULTIPLE = False

    def __init__ (self,ip):
        '''
        ip is an IP address (dotted quad string)
        '''
        self.ip = ip

    def pack (self):
        return self._attribute( socket.inet_pton( socket.AF_INET, self.ip ) )

    def __len__ (self):
        return 4

    def __str__ (self):
        return str(self.ip)

    def __repr__ (self):
        return str(self)
    
    def __cmp__(self,other):
        if ( not isinstance(other,OriginatorId) or
             (self.ip != other.ip)
            ):
            return -1
        else:
            return 0
    
    @staticmethod
    def unpack(data):
        ip = socket.inet_ntop( socket.AF_INET, data[0:4] )
        return OriginatorId(ip)
    
