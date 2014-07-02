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


from threading import Lock

import re
import logging

from bagpipe.bgp.vpn.ipvpn import VRF
from bagpipe.bgp.vpn.evpn import EVI

import bagpipe.bgp.common.exceptions as exc

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap
from bagpipe.bgp.common import utils

from bagpipe.bgp.vpn.label_allocator import LabelAllocator

from exabgp.message.update.attribute.communities import RouteTarget


log = logging.getLogger(__name__)

class VPNManager(object, LookingGlass):
    """
    Creates, and keeps track of, VPN instances (VRFs and EVIs) and passes plug/unplug calls to the right VPN instance. 
    """
    
    type2class = { "ipvpn": VRF,
                   "evpn": EVI
                  }
    
    def __init__(self, bgpManager, dataplaneDrivers):
        '''
        dataplaneDrivers is a dict from vpn type to each dataplane driver, e.g. { "ipvpn": driverA, "evpn": driverB }
        '''
        
        log.debug("VPNManager init")
        
        self.bgpManager = bgpManager
        
        self.dataplaneDrivers = dataplaneDrivers

        # Init VPN instance identifiers
        self.instanceId = 1
        
        # VPN instance workers dict
        self.vpnWorkers = {}
        
        logging.debug("Creating label allocator")
        self.labelAllocator = LabelAllocator()
        
        self.lock = Lock()
    
    def _convertRouteTargetString2Dict(self, rtString):
        try:
            rt_list = re.split(',[ ]?', rtString)
        
            rt_dict = []
            for rt in rt_list:
                if rt == '': continue
                try:
                    asn, nn = rt.split(':')
                except Exception:
                    raise Exception("Malformed route target: '%s'" % rt)
                rt_dict.append(RouteTarget(int(asn), None, int(nn)))
                
            return rt_dict
        except Exception:
            raise Exception("Malformed route target list: '%s'" % rtString)
        
    
    def _formatIpAddressPrefix(self, ipAddress):
        if re.match('([12]?\d?\d\.){3}[12]?\d?\d\/[123]?\d', ipAddress):
            address = ipAddress
        elif re.match('([12]?\d?\d\.){3}[12]?\d?\d', ipAddress):
            address = ipAddress + "/32"
        else:
            raise exc.MalformedIPAddress
            
        return address
    
    @utils.synchronized
    def getInstanceId(self):
        iid = self.instanceId
        self.instanceId += 1
        return iid

    def plugVifToVPN(self, vpnInstanceId, instanceType, importRTs, exportRTs, macAddress, ipAddress, gatewayIP, localPort):
        
        # Verify and format IP address with prefix if necessary
        try:
            ipAddressPrefix = self._formatIpAddressPrefix(ipAddress)
        except exc.MalformedIPAddress:
            raise
        
        # Convert route target string to RouteTarget dictionary
        importRTs = self._convertRouteTargetString2Dict(importRTs)
        exportRTs = self._convertRouteTargetString2Dict(exportRTs)

        # retrieve network mask
        mask = int(ipAddressPrefix.split('/')[1])

        # Retrieve VPN worker or create new one if does not exist
        try:
            vpnInstance = self.vpnWorkers[vpnInstanceId]
            if (vpnInstance._type != instanceType):
                raise Exception("Trying to plug port on an existing instance of a different type (existing: %s, asked: %s)"% (vpnInstance._type,instanceType))
        except KeyError:
            instanceId = self.getInstanceId()
            log.info("Create and start new VPN instance %d for identifier %s" % (instanceId, vpnInstanceId))
            try:
                vpnInstanceFactory = VPNManager.type2class[instanceType]
            except KeyError:
                log.error("Unsupported instanceType for VPNInstance: %s" % instanceType)
                raise Exception("Unsupported instance type: %s" % instanceType)
         
            try:
                dataplaneDriver = self.dataplaneDrivers[instanceType]
            except KeyError:
                log.error("No dataplane driver configured for VPN type %s" % instanceType)
                raise Exception("No dataplane driver configured for VPN type %s" % instanceType)
         
            vpnInstance = vpnInstanceFactory(
                                        self.bgpManager, self.labelAllocator, dataplaneDriver,
                                        vpnInstanceId, instanceId, importRTs, exportRTs, gatewayIP, mask
                                        )
            
            vpnInstance._type = instanceType
            
            vpnInstance.start()
        
        # Check if new route target import/export must be updated in VRF
        if not ((set(vpnInstance.importRTs) == set(importRTs)) and
                 (set(vpnInstance.exportRTs) == set(exportRTs))):
            vpnInstance.updateRouteTargets(importRTs, exportRTs)

        # Plug VIF to VRF
        vpnInstance.vifPlugged(macAddress, ipAddressPrefix, localPort)
        
        # Update VRF workers list
        self.vpnWorkers[vpnInstanceId] = vpnInstance
        
    def unplugVifFromVPN(self, vpnInstanceId, macAddress, ipAddress, localPort):
        
        # Verify and format IP address with prefix if necessary
        try:
            ipAddressPrefix = self._formatIpAddressPrefix(ipAddress)
        except exc.MalformedIPAddress:
            raise
        
        # Retrieve VRF worker or raise exception if does not exist
        try:
            vpnInstance = self.vpnWorkers[vpnInstanceId]
            # Unplug VIF to VRF
            vpnInstance.vifUnplugged(macAddress, ipAddressPrefix, localPort)
            
            if vpnInstance.isEmpty():
                vpnInstance.cleanup()
                del self.vpnWorkers[vpnInstanceId]
        except KeyError:
            log.error("Try to unplug VIF from non existing VPN instance worker %s" % vpnInstanceId)
            raise exc.VPNNotFound(vpnInstanceId)

    def stop(self):
        for worker in self.vpnWorkers.itervalues():
            worker.stop()
        for worker in self.vpnWorkers.itervalues():
            worker.join()

    ### Looking Glass hooks ####
    
    def getLGMap(self):
        class DataplaneLGHook(LookingGlass):
            def __init__(self, vpnManager):
                self.vpnManager = vpnManager
            def getLGMap(self):
                return {
                "drivers": (LGMap.COLLECTION, (self.vpnManager.getLGDataplanesList, self.vpnManager.getLGDataplaneFromPathItem)),
                "ids":     (LGMap.DELEGATE, self.vpnManager.labelAllocator)
                }
        dataplaneHook = DataplaneLGHook(self)
        return { 
               "instances": (LGMap.COLLECTION, (self.getLGVPNList, self.getLGVPNFromPathItem)),
               "dataplane": (LGMap.DELEGATE, dataplaneHook)
               }
    
    def getLGVPNList(self):
        return [{"id": i} for i in self.vpnWorkers.iterkeys()]
        
    def getLGVPNFromPathItem(self, pathItem):
        return self.vpnWorkers[pathItem]
    
    def getVPNWorkersCount(self):
        return len(self.vpnWorkers)

    ######## LookingGLass ########
    
    def getLGDataplanesList(self):
        return [{"id": i} for i in self.dataplaneDrivers.iterkeys()]

    def getLGDataplaneFromPathItem(self, pathItem):
        return self.dataplaneDrivers[pathItem]
    


