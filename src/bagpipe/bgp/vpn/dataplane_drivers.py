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


import logging

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

log = logging.getLogger(__name__)

class DataplaneDriver(object,LookingGlass):
    
    def __init__(self,config,init=True):
        '''config is a dict'''
        self.config = config
        
        self.myDataplanes = []
        
        if init:  # skipped if instantiated with init=False, to be used for cleanup script
            self._initReal(config)

    def resetState(self):
        log.info("function not implemented: resetState")
       
    def initializeDataplaneInstance(self, instanceId, vpnInstanceId, gatewayIP, mask, instanceLabel):
        '''
        returns a VPNInstanceDataplane subclass
        '''
        log.info("initialize VPNInstance %(instanceId)s, %(vpnInstanceId)s, %(gatewayIP)s, %(mask)s" % locals())
        
        if self.dataplaneClass:
            vpnInstanceDataplane = self.dataplaneClass( self, instanceId, vpnInstanceId, gatewayIP, mask, instanceLabel)
            self.myDataplanes.append(vpnInstanceDataplane)
        
            self._initializeInstanceReal(vpnInstanceDataplane)
        
            vpnInstanceDataplane.initialize()
            
            return vpnInstanceDataplane
        else:
            raise Exception("Cannot initialize dataplane instance, Dataplane driver has no dataplaneClass")
    
    def cleanup(self):
        # Call cleanup on all dataplane instances
        for vpnInstanceDataplane in self.myDataplanes:
            vpnInstanceDataplane.cleanup()
            
        self.myDataplanes = None
        
        self._cleanupReal()
        
    def getLGMap(self):
        return {
                "name": (LGMap.VALUE, self.__class__.__name__)
                }


class VPNInstanceDataplane(LookingGlass): 
 
    def __init__(self, dataplaneDriver, instanceId, vpnInstanceId, gatewayIP, mask, instanceLabel=None):
        '''
        WARNING: 
        The .resetState method of the dataplane driver will be called after instantiating the VPNInstanceDataplane
        object (if this is the first instantiation after startup).
        Hence, no dataplane setup should be done in __init__.
        '''
        log.info("VPNInstanceDataplane init( %(dataplaneDriverName)s, %(instanceId)d, %(vpnInstanceId)s, %(gatewayIP)s/%(mask)d)" % dict(locals(),**{"dataplaneDriverName":dataplaneDriver.__class__.__name__}))
        self.driver = dataplaneDriver
        self.config = dataplaneDriver.config
        self.instanceId = instanceId
        self.vpnInstanceId = vpnInstanceId
        self.gatewayIP = gatewayIP
        self.instanceLabel = instanceLabel
        self.mask = mask
        self.dataplanePortsData = dict()
 
    def initialize(self):
        '''
        This method is not called before calling .resetState on the dataplane driver.
        '''
        log.info("function not implemented: initialize instance %d" % self.instanceId )
 
    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        log.info("VPNInstance %(instanceId)d: vifPlugged(%(macAddress)s,%(ipAddress)s,%(localPort)s,%(label)d)" % dict(locals(),**self.__dict__))
    
        # FIXME: need to fail if port was already plugged    
        self.dataplanePortsData[localPort] = dict()
        
        self._vifPluggedReal(macAddress, ipAddress, localPort, label)    
    
    def vifUnplugged(self, macAddress, ipAddress, localPort, label):
        log.info("VPNInstance %(instanceId)d: vifUnplugged(%(macAddress)s,%(ipAddress)s,%(localPort)s,%(label)d)" % dict(locals(),**self.__dict__))
        
        del self.dataplanePortsData[localPort]
        
        self._vifUnpluggedReal(macAddress, ipAddress, localPort, label)

    def cleanup(self):
        log.info("function not implemented: cleanup instance %d" % self.instanceId )
        
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        log.warning("function not implemented: setupDataplaneForRemoteEndpoint()" )

    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri):
        '''
        dataplaneInfo is the object that was returned by setupDataplaneForRemoteEndpoint for the same prefix/remotePE/label
        '''
        log.warning("function not implemented: removeDataplaneForRemoteEndpoint()" )
 
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.warning("function not implemented: addDataplaneForBroadcastEndpoint()" )
        
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.warning("function not implemented: removeDataplaneForBroadcastEndpoint()" )
        
    def _runCommand(self,*args,**kwargs):
        return self.driver._runCommand(*args,**kwargs)
    
    #### Looking glass info ####

    def getLGMap(self):
        return {
                "driver": (LGMap.DELEGATE,self.driver),
                }


class DummyVPNInstanceDataplane(VPNInstanceDataplane):

    def __init__(self,*args):
        VPNInstanceDataplane.__init__(self,*args)
        log.info("----- Init dataplane for VPNInstance %s %d" % (self.__class__.__name__,self.instanceId))

    def initialize(self): 
        log.info("----- VPNInstanceinitialize()")

    def _vifPluggedReal(self, macAddress, ipAddress, localPort, label):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: _vifPluggedReal(%(macAddress)s,%(ipAddress)s,%(localPort)s,%(label)d)" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))
    
    def _vifUnpluggedReal(self, macAddress, ipAddress, localPort, label):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: _vifUnpluggedReal(%(macAddress)s,%(ipAddress)s,%(mask)s,%(localPort)s,%(label)d)" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))

    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: setupDataplaneForRemoteEndpoint: %(prefix)s --> %(remotePE)s label %(label)d !" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))
        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: removeDataplaneForRemoteEndpoint: %(prefix)s (was at %(remotePE)s label %(label)d)" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))

    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))
         
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("----- VPNInstance %(instanceName)s %(instanceId)d: removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(dict(locals(),**self.__dict__), **{"instanceName":self.__class__.__name__}))

    def cleanup(self):
        log.info("----- VPNInstance %s %d: cleaning up!" % (self.__class__.__name__, self.instanceId))


class DummyDataplaneDriver(DataplaneDriver):
    
    dataplaneClass = DummyVPNInstanceDataplane

    def __init__(self,*args):
        DataplaneDriver.__init__(self,*args)

    def _initReal(self,config):
        log.info("--- initReal()")
        
    def _cleanupReal(self):
        log.info("--- cleanupReal()")

    def _initializeInstanceReal(self,vpnInstanceDataplane):
        pass

