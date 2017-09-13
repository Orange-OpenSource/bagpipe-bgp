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

import struct

class LabelStackEntry(object):
    
    MAX_LABEL = 2**20-1
    
    def __init__(self,value,bottomOfStack=False):
        self.labelValue = int(value)
        if int(value) > LabelStackEntry.MAX_LABEL :
            raise Exception("Label is beyond the limit (%d > %d)" % (int(value),LabelStackEntry.MAX_LABEL) )
        self.bottomOfStack = bottomOfStack
        self.withdraw = (self.labelValue == 0)

    def __str__ (self):
        return "%s%s" % (str(self.labelValue), "-B" if self.bottomOfStack else "" )          

    def __repr__ (self):
        return str(self)

    def __len__(self):
        return 3

    def pack (self):
        number = (self.labelValue << 4) + self.bottomOfStack
        return struct.pack('!L',number)[1:4]

    def __cmp__(self,other):
        if (isinstance(other,LabelStackEntry) and
            self.labelValue == other.labelValue and
            self.bottomOfStack == other.bottomOfStack
            ):
            return 0
        else:
            return -1

    @staticmethod
    def unpack(data):
        # data is supposed to be 3 bytes, the last 4 bits including the TC code and BOS bit
        if len(data)!=3:
            raise Exception("MPLS Label stack entry cannot be created from %d bytes (must be 3)" % len(data))
        
        number = struct.unpack('!L', "\0"+data) [0] 
        value = number >> 4
        # tc =   #FIXME: not done yet
        bos = bool(number & 1)
        
        return LabelStackEntry(value,bos)

NO_LABEL=LabelStackEntry(0)

def unpackLabelStack(data):
    # returns the amount of bytes consumed
    initial_length = len(data)
    stack=[]
    while(len(data)>3):
        stack.append( LabelStackEntry.unpack(data[0:3]) )
        data = data[3:]
        if stack[-1].bottomOfStack or stack[-1].withdraw : break
        
    return stack, initial_length - len(data)