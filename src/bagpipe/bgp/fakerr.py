# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2014 Orange
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
run me with 'twistd -y fakerr.py', and then connect with 
(at most 2) BGP clients...
"""

from threading import Lock

from twisted.protocols import basic

from twisted.internet import protocol
from twisted.application import service, internet

class FakeRR(basic.LineReceiver):
    
    delimiter = chr(255) * 16
    
    def __init__(self):
        self.lock = Lock()
    
    def connectionMade(self):
        with self.lock:
            if self.factory.clients == 2:
                print "Have already 2 peers, not accepting %s, reseting everyone !" % self.transport.getPeer().host 
                for client in self.factory.clients:
                    client.transport.loseConnection()
                raise Exception("Have already 2 peers, not accepting more !  (%s)" % self.transport.getPeer().host)
            
            print "Got new peer: %s" % self.transport.getPeer().host
            
            self.factory.clients.append(self)
            if len(self.factory.clients) == 2:
                # we are the second client
                print "%s is second peer, sending buffered data..." % self.transport.getPeer().host
                for olddata in self.factory.buffer:
                    print "   sending buffered data to peer %s (%d bytes)" % (self.transport.getPeer().host, len(olddata))
                    self.transport.write(olddata)
                self.factory.buffer = []
                self.factory.ready = True
                print "now ready"
            else:
                print "%s is first peer, will buffer data until second peer arrives..." % self.transport.getPeer().host
                self.factory.ready = False
                self.factory.buffer = []
    
    def connectionLost(self, reason):
        print "Lost peer %s" % self.transport.getPeer().host
        try:
            self.factory.clients.remove(self)
        except Exception:
            pass
        
        for c in self.factory.clients:
            if not c == self:
                c.transport.loseConnection()
        try:
            self.factory.clients.remove(c)
        except Exception:
            pass
        
        self.factory.ready = False
        self.factory.buffer = []
    
    def dataReceived(self, data):
        if self.factory.ready:
            # print "received %d bytes" % len(data)
            for c in self.factory.clients:
                if not c == self:
                    # print "   sending to peer %s" % c.transport.getPeer().host
                    c.transport.write(data)
        else:
            print "buffering received data (%d bytes)" % len(data)
            if self.factory.buffer is None:
                print "??? not ready, but no self.factory.buffer...??"
                self.factory.buffer = []
            self.factory.buffer.append(data)



factory = protocol.ServerFactory()
factory.protocol = FakeRR
factory.clients = []
factory.ready = False
factory.buffer = []

application = service.Application("fakerr")
internet.TCPServer(179, factory).setServiceParent(application)

