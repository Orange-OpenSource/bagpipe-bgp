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

from copy import copy

from threading import Thread
from threading import Lock

from bagpipe.bgp.common import utils
from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger, LGMap

from bagpipe.bgp.engine.tracker_worker import TrackerWorker

from bagpipe.bgp.engine import RouteEvent, RouteEntry

from exabgp.structure.address import AFI, SAFI

from exabgp.message.update.attribute.communities import ECommunities, Encapsulation
from exabgp.message.update.attribute.id import AttributeID

from exabgp.message.update.attribute.nexthop import NextHop
from exabgp.structure.ip import Inet

class VPNInstance(TrackerWorker, Thread, LookingGlassLocalLogger):
    
    afi = None
    safi = None

    def __init__(self, bgpManager, labelAllocator, dataplaneDriver, externalInstanceId, instanceId, importRTs, exportRTs, gatewayIP, mask):
        
        self.instanceType = self.__class__.__name__
        self.instanceId = instanceId

        Thread.__init__(self)
        self.setDaemon(True)

        TrackerWorker.__init__(self, bgpManager, "%s %d" % (self.instanceType, self.instanceId))
        
        LookingGlassLocalLogger.__init__(self, "%s-%d" % (self.instanceType, self.instanceId))
        
        self.log.info("VPNInstance init( %(instanceId)d, %(externalInstanceId)s, %(importRTs)s, %(exportRTs)s %(gatewayIP)s/%(mask)d)" % locals())
        
        self.lock = Lock()
        
        self.importRTs = importRTs
        self.exportRTs = exportRTs
        self.externalInstanceId = externalInstanceId
        self.gatewayIP = gatewayIP
        self.mask = mask
        
        self.afi = self.__class__.afi
        self.safi = self.__class__.safi
        assert(isinstance(self.afi, AFI))
        assert(isinstance(self.safi, SAFI))
        
        self.dataplaneDriver = dataplaneDriver
        self.labelAllocator = labelAllocator
        
        self.instanceLabel = self.labelAllocator.getNewLabel("Incoming traffic for %s %d" % (self.instanceType, self.instanceId))
        
        self.localPortData = dict()
        
        self.initialized = False
    
    def initialize(self, *args):
        '''
        Subclasses should call this super method only *after* they are fully initialized
        '''
        self.dataplane = self.dataplaneDriver.initializeDataplaneInstance(self.instanceId, self.externalInstanceId, self.gatewayIP, self.mask, self.instanceLabel, *args)
        
        self.initialized = True
        
    def _postFirstPlug(self):
        # we defer subscription to any route until we have had a first plug
        # (this is absolutely necessary for the LinuxVXLANHybridDataplaneDriver which cannot handle any route
        # before a port has been plugged)
        
        for rt in self.importRTs:
            self._subscribe(self.afi, self.safi, rt)
    
    def cleanup(self):
        # cleanup is not supposed to be called if we still have ports attached
        assert(self.isEmpty())
        
        # cleanup BGP subscriptions
        for rt in self.importRTs:
            self._unsubscribe(self.afi, self.safi, rt)
        
        self.dataplane.cleanup()
        
        self.labelAllocator.release(self.instanceLabel)
        
        # this makes sure that the thread will be stopped, and any remaining routes/subscriptions are released: 
        self.stop()
        
    def isEmpty(self):
        return False if self.localPortData else True
        
    def updateRouteTargets(self, newImportRTs, newExportRTs):
        added_import_rt = set(newImportRTs) - set(self.importRTs)
        removed_import_rt = set(self.importRTs) - set(newImportRTs)

        self.log.debug("%s %d - Added Import RT: %s" % (self.instanceType, self.instanceId, added_import_rt))
        self.log.debug("%s %d - Removed Import RT: %s" % (self.instanceType, self.instanceId, removed_import_rt))

        # Register to BGP with these route targets
        for rt in added_import_rt:
            self._subscribe(self.afi, self.safi, rt)
        
        # Unregister from BGP with these route targets
        for rt in removed_import_rt:
            self._unsubscribe(self.afi, self.safi, rt)
        
        # Update import and export route targets
        self.importRTs = newImportRTs
        
        # Re-advertise all routes with new export RTs
        if  set(newExportRTs) != set(self.exportRTs):
            self.exportRTs = newExportRTs
            for routeEntry in self.getWorkerRouteEntries():
                self.log.info("Re-advertising route %s with updated RTs (%s)" % (routeEntry.nlri, newExportRTs))
                
                updatedAttributes = copy(routeEntry.attributes)
                del updatedAttributes[ AttributeID.EXTENDED_COMMUNITY ]
                updatedAttributes.add(self._genExtendedCommunities())
                
                updatedRouteEntry = self._newRouteEntry(routeEntry.afi, routeEntry.safi, self.exportRTs, routeEntry.nlri, updatedAttributes)
                self.log.debug("   updated route: %s" % (updatedRouteEntry))
                
                self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, updatedRouteEntry))
                
    def _parseIPAddressPrefix(self, ipAddressPrefix):
        ipAddress = ""
        mask = 0
        try:
            (ipAddress, mask) = ipAddressPrefix.split('/')
        except ValueError as e:
            self.log.error("Cannot split %s into address/mask (%s)" % (ipAddressPrefix, e))
            raise Exception("Cannot split %s into address/mask (%s)")
        
        return (ipAddress, mask)

    def _genExtendedCommunities(self):
        ecommunities = ECommunities(copy(self.exportRTs))
        for encap in self.dataplaneDriver.supportedEncaps():
            if not isinstance(encap,Encapsulation):
                raise Exception("dataplaneDriver.supportedEncaps() should return a list of Encapsulation objects")
            
            if encap != Encapsulation(Encapsulation.DEFAULT):
                ecommunities.add(encap)
        #FIXME: si DEFAULT + xxx => adv MPLS
        return ecommunities

    def generateVifBGPRoute(self, macAdress, ipAddress, label):
        raise Exception("Not implemented.")

    @utils.synchronized
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort):
        self.log.info("vifPlugged %s %d macAddress: %s ipAddressPrefix: %s localPort:%s"
                  % (self.instanceType, self.instanceId, macAddress, ipAddressPrefix, localPort))

        # Parse address/mask
        (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)

        # Check if this port has already been plugged
        # - If True, only update route   #FIXME: not needed anymore => updateRouteTargets takes care of that
        # - Else, plug port on dataplane
        #
        try:
            portData = dict()

            if localPort['linuxif'] not in self.localPortData:
                self.log.debug("Plugging port (%s)", ipAddress)
                
                portData['label'] = self.labelAllocator.getNewLabel("Incoming traffic for %s %d, interface %s" % (self.instanceType, self.instanceId, localPort['linuxif']))

                # Call driver to setup the dataplane for incoming traffic
                self.dataplane.vifPlugged(macAddress, ipAddress, localPort, portData['label'])
            else:
                self.log.debug("Port already plugged, will advertize new route (%s)", ipAddress)
                portData = self.localPortData[localPort['linuxif']]
            
            self.log.info("Generating BGP route for VIF")
            routeEntry = self.generateVifBGPRoute(macAddress, ipAddress, portData['label'])
            
            nh = Inet(1, socket.inet_pton(socket.AF_INET, self.dataplane.driver.getLocalAddress()))
            routeEntry.attributes.add(NextHop(nh))
            
            assert(isinstance(routeEntry, RouteEntry))
            
            routeEntry.attributes.add(self._genExtendedCommunities())
            
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, routeEntry))
            
            portData["endpoint_info"]={'mac':macAddress,'ip':ipAddressPrefix}
            portData["port_info"]=localPort
            # Store route for this prefix to be able to:
            # - Update on another plug
            # - Or withdraw on unplug
            portData['routeEntry'] = routeEntry
            self.localPortData[localPort['linuxif']] = portData
            
            #FIXME: the code below is called after *all* plugs, not
            # only after the first one. Harmless but can be improved...
            self._postFirstPlug()
            
        except Exception as e:
            self.log.error("Error in vifPlugged: %s" % e)
            if localPort['linuxif'] in self.localPortData: 
                del self.localPortData[localPort['linuxif']]
            raise

    @utils.synchronized
    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort):
        # macAddress, ipAddressPrefix, localPort
        self.log.info("vifUnplugged %s %d macAddress: %s ipAddressPrefix: %s localPort:%s" % (self.instanceType, self.instanceId, macAddress, ipAddressPrefix, localPort))

        # Parse address/mask
        (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)
        
        # Find route, label and data plane informations
        try:
            portData = self.localPortData[localPort['linuxif']]
        except KeyError:
            self.log.warning("vifUnplugged called for localPort %s, but port was not plugged yet" % localPort['linuxif'])
            raise Exception("this port is not plugged yet, cannot unplug")
        
        try:
            routeEntry = portData['routeEntry']
            label = portData['label']
        except KeyError as e :
            self.log.error("vifPlugged called for localPort %s, but port data is incomplete (%s)" % (localPort['linuxif'], e))
            raise Exception("bgp component bug, check its logs")
        
        # Withdraw BGP route
        self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, routeEntry))
        
        # Unplug port from data plane
        self.dataplane.vifUnplugged(macAddress, ipAddress, localPort, label)
        
        # Free label to the allocator
        self.labelAllocator.release(label)
        
        # Forget data for this port
        del self.localPortData[localPort['linuxif']]

    def _checkEncaps(self,route):
        '''
        returns a list of encaps supported by both the dataplane driver and the
        route advertizer (based on BGP Encapsulation community)
        
        raise an Exception, if there is no common encap
        '''
        try:
            advEncaps = filter(lambda ecom:isinstance(ecom, Encapsulation),
                        route.attributes[AttributeID.EXTENDED_COMMUNITY].communities
                        )
            self.log.debug("Advertized Encaps: %s" % advEncaps)
        except Exception as e:
            self.log.debug("Exception on adv encaps: %s" % e)
            advEncaps = [ Encapsulation(Encapsulation.DEFAULT) ]
        
        goodEncaps = set(advEncaps) & set(self.dataplaneDriver.supportedEncaps())
        
        if not goodEncaps:
            self.log.warning("No encap supported by dataplane driver for route %s, dataplane supports %s)" % (route,advEncaps,self.dataplaneDriver.supportedEncaps()) )
        
        return goodEncaps

    #### Looking Glass ####

    def getLGMap(self):
        return {
                "dataplane":     (LGMap.DELEGATE, self.dataplane),
                "route_targets": (LGMap.SUBITEM, self.getRTs),
                "gateway_ip":    (LGMap.SUBITEM, self.getGatewayIP),  # use future LGMap.ATTRIBUTE
                "subnet_mask":   (LGMap.SUBITEM, self.getMask),  # use future LGMap.ATTRIBUTE
                "instance_dataplane_id": (LGMap.VALUE, self.instanceLabel),
                "ports":         (LGMap.SUBTREE, self.getLGLocalPortData)
            }
    
    def getLGLocalPortData(self, pathPrefix):
        r = {}
        for (port, data) in self.localPortData.iteritems():
            r[port] = {
                 'route': data['routeEntry'].getLookingGlassInfo(pathPrefix),
                 'label': data['label'],
                 'port_info': data['port_info'],
                 'endpoint_info': data['endpoint_info']
                 }
        return r
    
    def getRTs(self):
        return {
                "import": [repr(rt) for rt in self.importRTs],
                "export": [repr(rt) for rt in self.exportRTs]
                }
        
    def getGatewayIP(self):
        return self.gatewayIP
    
    def getMask(self):
        return self.mask
    
