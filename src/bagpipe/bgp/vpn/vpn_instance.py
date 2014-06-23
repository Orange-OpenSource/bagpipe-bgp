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

from copy import copy

from threading import Thread
from threading import Lock

from bagpipe.bgp.common import utils
from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

from bagpipe.bgp.engine.tracker_worker import TrackerWorker

from bagpipe.bgp.engine import RouteEvent, RouteEntry

from exabgp.structure.address import AFI, SAFI

from exabgp.message.update.attribute.communities import ECommunities
from exabgp.message.update.attribute.id import AttributeID

log = logging.getLogger(__name__)

class VPNInstance(TrackerWorker, Thread, LookingGlass):
    
    afi = None
    safi = None

    def __init__(self, bgpManager, labelAllocator, dataplaneDriver, vpnInstanceId, instanceId, importRTs, exportRTs, gatewayIP, mask):
                
        log.info("VPNInstance init( %(instanceId)d, %(vpnInstanceId)s, %(importRTs)s, %(exportRTs)s %(gatewayIP)s/%(mask)d)" % locals())

        self.instanceType = self.__class__.__name__
        self.instanceId = instanceId

        Thread.__init__(self)
        self.setDaemon(True)

        TrackerWorker.__init__(self, bgpManager, "%s %d" % (self.instanceType, self.instanceId))
        
        self.lock = Lock()
        
        self.importRTs = importRTs
        self.exportRTs = exportRTs
        self.vpnInstanceId = vpnInstanceId
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
        
        self.route2dataplaneInfo = dict()
        
        self.initialized = False
    
    def _hasIntersection(self, a, b):
        return False if not list(set(a) & set(b)) else True
    
    def initialize(self):
        '''
        Subclasses should call this super method only *after* they are fully initialized
        '''
        self.dataplane = self.dataplaneDriver.initializeDataplaneInstance(self.instanceId, self.vpnInstanceId, self.gatewayIP, self.mask, self.instanceLabel)
        
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

        log.debug("%s %d - Added Import RT: %s" % (self.instanceType, self.instanceId, added_import_rt))
        log.debug("%s %d - Removed Import RT: %s" % (self.instanceType, self.instanceId, removed_import_rt))

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
                log.info("Re-advertising route %s with updated RTs (%s)" % (routeEntry.nlri, newExportRTs))
                
                updatedAttributes = copy(routeEntry.attributes)
                del updatedAttributes[ AttributeID.EXTENDED_COMMUNITY ]
                updatedAttributes.add(self._genExtendedCommunities())
                
                updatedRouteEntry = self._newRouteEntry(routeEntry.afi, routeEntry.safi, self.exportRTs, routeEntry.nlri, updatedAttributes)
                log.debug("   updated route: %s" % (updatedRouteEntry))
                
                self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, updatedRouteEntry))

        
    def _parseIPAddressPrefix(self, ipAddressPrefix):
        ipAddress = ""
        mask = 0
        try:
            (ipAddress, mask) = ipAddressPrefix.split('/')
        except ValueError as e:
            log.error("Cannot split %s into address/mask (%s)" % (ipAddressPrefix, e))
            raise Exception("Cannot split %s into address/mask (%s)")
        
        return (ipAddress, mask)

    # TODO: should be merged with self.vifPlugged
    def _isVifPlugged(self, macAddress, ipAddress, localPort):
        portData = dict()
        label = 0
        if localPort not in self.localPortData:
            log.debug("Plugging port (%s)", ipAddress)
            if not self.initialized: self.initialize()
            
            label = self.labelAllocator.getNewLabel("Incoming traffic for %s %d, interface %s" % (self.instanceType, self.instanceId, localPort))
            portData['label'] = label
            
            # Call driver to setup the dataplane for incoming traffic
            self.dataplane.vifPlugged(macAddress, ipAddress, localPort, label)
        else:
            log.debug("Port already plugged, updating routes (%s)", ipAddress)
            portData = self.localPortData[localPort]
            label = portData['label']
            
        return (portData, label)

    def _genExtendedCommunities(self):
        ecommunities = ECommunities(copy(self.exportRTs))
        for ecom in self.genAdditionalExtendedCommunities():
            ecommunities.add(ecom)
        return ecommunities

    def genAdditionalExtendedCommunities(self):
        """
        returns a list of extended communities to add to a route additionnaly to the Route Targets
        """
        return []

    def generateVifBGPRoute(self, macAdress, ipAddress, label):
        raise Exception("Not implemented.")

    @utils.synchronized
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort):
        # macAddress, ipAddressPrefix, localPort
        log.info("vifPlugged %s %d macAddress: %s ipAddressPrefix: %s localPort:%s" % (self.instanceType, self.instanceId, macAddress, ipAddressPrefix, localPort))

        # Parse address/mask
        (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)

        # Check if this port has already been plugged
        # - If True, only update route   #FIXME: not needed anymore => updateRouteTargets takes care of that
        # - Else, plug port on dataplane
        #
        try:
            (portData, label) = self._isVifPlugged(macAddress, ipAddress, localPort)
            
            log.info("Generating BGP route for VIF")
            routeEntry = self.generateVifBGPRoute(macAddress, ipAddress, label)
            
            assert(isinstance(routeEntry, RouteEntry))
            
            routeEntry.attributes.add(self._genExtendedCommunities())
            
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, routeEntry))
            
            # Store route for this prefix to be able to:
            # - Update on another plug
            # - Or withdraw on unplug
            portData['routeEntry'] = routeEntry
            self.localPortData[localPort] = portData
            
            self._postFirstPlug()
            
        except Exception as e:
            log.error("Error in vifPlugged: %s" % e)
            if localPort in self.localPortData: 
                del self.localPortData[localPort]
            raise

    @utils.synchronized
    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort):
        # macAddress, ipAddressPrefix, localPort
        log.info("vifUnplugged %s %d macAddress: %s ipAddressPrefix: %s localPort:%s" % (self.instanceType, self.instanceId, macAddress, ipAddressPrefix, localPort))

        # Parse address/mask
        (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)
        
        # Find route, label and data plane informations
        try:
            portData = self.localPortData[localPort]
        except KeyError:
            log.warning("vifUnplugged called for localPort %s, but port was not plugged yet" % localPort)
            raise Exception("this port is not plugged yet, cannot unplug")
        
        try:
            routeEntry = portData['routeEntry']
            label = portData['label']
        except KeyError as e :
            log.error("vifPlugged called for localPort %s, but port data is incomplete (%s)" % (localPort, e))
            raise Exception("bgp component bug, check its logs")
        
        # Withdraw BGP route
        self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, routeEntry))
        
        # Unplug port from data plane
        self.dataplane.vifUnplugged(macAddress, ipAddress, localPort, label)
        
        # Free label to the allocator
        self.labelAllocator.release(label)
        
        # Forget data for this port
        del self.localPortData[localPort]

    #### Looking Glass ####

    def getLGMap(self):
        return {
                "dataplane":     (LGMap.DELEGATE, self.dataplane),
                # TODO: add localportdata as a SUBTREE
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
                     'label': data['label']
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
    
