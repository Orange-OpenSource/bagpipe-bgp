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


import socket

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger, LGMap

from bagpipe.bgp.common.run_command import runCommand

from exabgp.message.update.attribute.communities import Encapsulation

class DataplaneDriver(object,LookingGlassLocalLogger):
    
    encaps = [Encapsulation(Encapsulation.DEFAULT)]
    
    def __init__(self,config,init=True):
        '''config is a dict'''
        LookingGlassLocalLogger.__init__(self)
        
        self.config = config
        
        self.local_address = None
        try:
            self.local_address = self.config["dataplane_local_address"]
            socket.inet_pton(socket.AF_INET, self.local_address)
            self.log.info("Will use %s as local_address" % self.local_address)
        except KeyError:
            self.log.info("Will use local BGP address as dataplane_local_address")
            self.local_address = None
        except socket.error:
            raise Exception("malformed local_address: '%s'" % self.local_address)
        
        if init:  # skipped if instantiated with init=False, to be used for cleanup script
            self._initReal(config)
        
        # Flag to trigger cleanup all dataplane states on first call to vifPlugged
        self.firstInit = True

    def resetState(self):
        self.log.info("function not implemented: resetState")
       
    def _initReal(self, config):
        '''
        This is called after resetState (which, e.g. cleans up the stuff
        possibly left-out by a previous failed run).
        
        All init things that should not be cleaned up go here.
        '''
        pass
    
    def initializeDataplaneInstance(self, instanceId, externalInstanceId, gatewayIP, mask, instanceLabel, **kwargs):
        '''
        returns a VPNInstanceDataplane subclass
        after calling resetState on the dataplane driver, if this is the first 
        call to initializeDataplaneInstance
        '''
        self.log.info("initialize VPNInstance %(instanceId)s, %(externalInstanceId)s, %(gatewayIP)s, %(mask)s" % locals())

        if self.firstInit:
            self.log.info("First VPN instance init, resetting dataplane state")
            try:
                self.resetState()
            except Exception as e:
                self.log.error("Exception while resetting state: %s" % e)
            self.firstInit = False
        else:
            self.log.debug("(not resetting dataplane state)")

        return self.dataplaneClass( self, instanceId, externalInstanceId, gatewayIP, mask, instanceLabel, **kwargs)
    
    def cleanup(self):
        self._cleanupReal()
        
    def getLocalAddress(self):
        return self.local_address
    
    def supportedEncaps(self):
        return self.__class__.encaps
    
    def _runCommand(self, command, *args, **kwargs):
        return runCommand(self.log, command, *args, **kwargs)
    
    def getLGMap(self):
        encaps=[]
        for encap in self.supportedEncaps():
            encaps.append(repr(encap))
        return {
                "name": (LGMap.VALUE, self.__class__.__name__),
                'local_address': (LGMap.VALUE, self.local_address),
                "supported_encaps": (LGMap.VALUE,encaps),
                "config": (LGMap.VALUE,self.config)
                }

class VPNInstanceDataplane(LookingGlassLocalLogger): 
 
    def __init__(self, dataplaneDriver, instanceId, externalInstanceId, gatewayIP, mask, instanceLabel=None):
        LookingGlassLocalLogger.__init__(self,repr(instanceId))
        self.log.info("VPNInstanceDataplane init( %(externalInstanceId)s, %(gatewayIP)s/%(mask)d)" % locals())
        self.driver = dataplaneDriver
        self.config = dataplaneDriver.config
        self.instanceId = instanceId
        self.externalInstanceId = externalInstanceId
        self.gatewayIP = gatewayIP
        self.mask = mask
        self.instanceLabel = instanceLabel

    def cleanup(self):
        self.log.info("function not implemented: cleanup instance %d" % self.instanceId )

    def vifPlugged(self, macAddress, ipAddressPrefix, localPort, label):
        self.log.warning("function not implemented: vifPlugged()")
        
    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort):
        self.log.warning("function not implemented: vifUnplugged()")
        
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri, encaps):
        self.log.warning("function not implemented: setupDataplaneForRemoteEndpoint()")

    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.warning("function not implemented: removeDataplaneForRemoteEndpoint()")
         
    def _runCommand(self,*args,**kwargs):
        return runCommand(self.log,*args,**kwargs)
    
    #### Looking glass info ####

    def getLGMap(self):
        return {
                "driver": (LGMap.DELEGATE,self.driver),
                }

class DummyVPNInstanceDataplane(VPNInstanceDataplane):

    def __init__(self,*args):
        VPNInstanceDataplane.__init__(self,*args)
        self.log.info("----- Init dataplane for VPNInstance %s %d" % (self.__class__.__name__,self.instanceId))

    def vifPlugged(self, macAddress, ipAddressPrefix, localPort, label):
        self.log.info("vifPlugged: %s, %s, %s" % (macAddress,ipAddressPrefix,localPort))

    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort, label):
        self.log.info("vifUnplugged: %s, %s, %s" % (macAddress,ipAddressPrefix,localPort))
        
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri, encaps):
        self.log.info("----- VPNInstance %(instanceId)d: setupDataplaneForRemoteEndpoint: %(prefix)s --> %(remotePE)s label %(label)d encaps %(encaps)s!" % locals())
        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("----- VPNInstance %(instanceId)d: removeDataplaneForRemoteEndpoint: %(prefix)s (was at %(remotePE)s label %(label)d)" % locals())
 
    def cleanup(self):
        self.log.info("----- VPNInstance %s %d: cleaning up!" % (self.__class__.__name__, self.instanceId))

class DummyDataplaneDriver(DataplaneDriver):
    
    dataplaneClass = DummyVPNInstanceDataplane

    def __init__(self,*args):
        DataplaneDriver.__init__(self,*args)

    def _initReal(self,config):
        self.log.info("--- initReal()")
        
    def _cleanupReal(self):
        self.log.info("--- cleanupReal()")
