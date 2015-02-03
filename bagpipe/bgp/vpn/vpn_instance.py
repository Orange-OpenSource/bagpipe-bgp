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

    def __init__(self, bgpManager, labelAllocator, dataplaneDriver, externalInstanceId, instanceId, importRTs, exportRTs, gatewayIP, mask, **kwargs):
        
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
        
        # One local port -> List of endpoints (MAC and IP addresses tuple)
        self.localPort2Endpoints = dict()
        # One MAC address -> One local port
        self.macAddress2LocalPortData = dict()
        # One IP address ->  One MAC address
        self.ipAddress2MacAddress = dict()
        
        self.dataplane = self.dataplaneDriver.initializeDataplaneInstance(self.instanceId, self.externalInstanceId, self.gatewayIP, self.mask, self.instanceLabel, **kwargs)
        
        for rt in self.importRTs:
            self._subscribe(self.afi, self.safi, rt)
    
    @utils.synchronized
    def cleanupIfEmpty(self):
        self.log.debug("cleanupIfEmpty localPort2Endpoints: %s" % self.localPort2Endpoints)
        if self.isEmpty():
            # cleanup BGP subscriptions
            for rt in self.importRTs:
                self._unsubscribe(self.afi, self.safi, rt)
            
            self.dataplane.cleanup()
            
            self.labelAllocator.release(self.instanceLabel)
            
            # this makes sure that the thread will be stopped, and any remaining routes/subscriptions are released: 
            self.stop()
            
            return True
        
        return False

    def isEmpty(self):
        return (not self.localPort2Endpoints)

    def hasEnpoint(self, linuxif):
        return (self.localPort2Endpoints.get(linuxif) is not None)
    
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

    def generateVifBGPRoute(self, macAddress, ipAddress, label):
        raise Exception("Not implemented.")

    def synthesizeVifBGPRoute(self, macAddress, ipAddress, label):
        routeEntry = self.generateVifBGPRoute(macAddress, ipAddress, label)
        assert(isinstance(routeEntry, RouteEntry))
        
        nh = Inet(1, socket.inet_pton(socket.AF_INET,
                                      self.dataplane.driver.getLocalAddress()))
        routeEntry.attributes.add(NextHop(nh))
        routeEntry.attributes.add(self._genExtendedCommunities())
        
        return routeEntry
        

    @utils.synchronized
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort):
        self.log.info("vifPlugged %s %d macAddress: %s ipAddressPrefix: %s "
                      "localPort:%s" %
                      (self.instanceType, self.instanceId, macAddress,
                       ipAddressPrefix, localPort))

        # Check if this port has already been plugged
        # - Verify port informations consistency
        if macAddress in self.macAddress2LocalPortData:
            self.log.debug("MAC address already plugged, checking port "
                           "consistency")
            portData = self.macAddress2LocalPortData[macAddress]
            
            if (portData.get("port_info") != localPort):
                raise Exception("Port information is not consistent with previous plug for port %s (%s != %s)" %
                                (localPort['linuxif'],portData.get("port_info"),localPort))

        # - Verify (MAC address, IP address) tuple consistency
        if ipAddressPrefix in self.ipAddress2MacAddress:
            if self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress:
                raise Exception("No consistent endpoint (%s, %s) informations" %
                                (macAddress, ipAddressPrefix))
            else:
                return

        # Else, plug port on dataplane
        try:
            # Parse address/mask
            (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)

            self.log.debug("Plugging port (%s)", ipAddress)
            
            portData = dict()    
            portData['label'] = self.labelAllocator.getNewLabel(
                "Incoming traffic for %s %d, interface %s, endpoint (%s, %s)" %
                (self.instanceType, self.instanceId, localPort['linuxif'],
                 macAddress, ipAddressPrefix)
            )
            portData["port_info"] = localPort

            # Call driver to setup the dataplane for incoming traffic
            self.dataplane.vifPlugged(macAddress, ipAddress, localPort, portData['label'])
            
            self.log.info("Synthesizing and advertising BGP route for VIF %s "
                          "endpoint (%s, %s)" %
                          (localPort['linuxif'], macAddress, ipAddressPrefix))
            routeEntry = self.synthesizeVifBGPRoute(macAddress,
                                                    ipAddress,
                                                    portData['label'])
            
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, routeEntry))

            if localPort['linuxif'] not in self.localPort2Endpoints:
                self.localPort2Endpoints[localPort['linuxif']] = list()

            self.localPort2Endpoints[localPort['linuxif']].append(
                {'mac': macAddress, 'ip': ipAddressPrefix}
            )
            self.macAddress2LocalPortData[macAddress] = portData
            self.ipAddress2MacAddress[ipAddressPrefix] = macAddress
            
        except Exception as e:
            self.log.error("Error in vifPlugged: %s" % e)
            if localPort['linuxif'] in self.localPort2Endpoints:
                if len(self.localPort2Endpoints[localPort['linuxif']]) > 1:
                    self.localPort2Endpoints[localPort['linuxif']].remove(
                        {'mac': macAddress, 'ip': ipAddressPrefix}
                    )
                else:
                    del self.localPort2Endpoints[localPort['linuxif']]
            if macAddress in self.macAddress2LocalPortData:
                del self.macAddress2LocalPortData[macAddress]
            if ipAddressPrefix in self.ipAddress2MacAddress:
                del self.ipAddress2MacAddress[ipAddressPrefix]
            
            raise

    @utils.synchronized
    def vifUnplugged(self, macAddress, ipAddressPrefix):
        self.log.info("vifUnplugged %s %d macAddress: %s ipAddressPrefix: %s" %
                      (self.instanceType, self.instanceId, macAddress,
                       ipAddressPrefix))

        # Verify port and endpoint (MAC address, IP address) tuple consistency
        portData = self.macAddress2LocalPortData.get(macAddress)
        if (not portData or
            self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but no "
                           "consistent informations or was not plugged yet" %
                           (macAddress, ipAddressPrefix))
            raise Exception("No consistent endpoint (%s, %s) informations or "
                            "was not plugged yet, cannot unplug" %
                            (macAddress, ipAddressPrefix))

        # Finding label and local port informations
        label = portData.get('label')
        localPort = portData.get('port_info')
        if (not label or not localPort):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but "
                           "port data (%s, %s) is incomplete" %
                           (macAddress, ipAddressPrefix, label, localPort))
            raise Exception("No consistent informations for port, BGP "
                            "component bug")

        if localPort['linuxif'] in self.localPort2Endpoints:
            # Parse address/mask
            (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)
        
            lastEndpoint = False if len(self.localPort2Endpoints[localPort['linuxif']]) > 1 else True

            self.log.info("Synthesizing and withdrawing BGP route for VIF %s "
                          "endpoint (%s, %s)" %
                          (localPort['linuxif'], macAddress,
                           ipAddressPrefix))
            routeEntry = self.synthesizeVifBGPRoute(macAddress,
                                                    ipAddress,
                                                    label)
            self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, routeEntry))
            
            # Unplug endpoint from data plane
            self.dataplane.vifUnplugged(macAddress, ipAddress, localPort, label, lastEndpoint)
            
            # Free label to the allocator
            self.labelAllocator.release(label)
    
            # Forget data for this port if last endpoint
            if lastEndpoint:
                del self.localPort2Endpoints[localPort['linuxif']]
            else:
                self.localPort2Endpoints[localPort['linuxif']].remove(
                    {'mac': macAddress, 'ip': ipAddressPrefix}
                )
            
            del self.macAddress2LocalPortData[macAddress]
            del self.ipAddress2MacAddress[ipAddressPrefix]
        else:
            self.log.error("vifUnplugged called for endpoint {%s, %s}, but port data is incomplete" %
                           (macAddress, ipAddressPrefix))
            raise Exception("BGP component bug, check its logs")            

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
        for (port, endpoints) in self.localPort2Endpoints.iteritems():
            eps = []
            for endpoint in endpoints:
                eps.append({
                            'label': self.macAddress2LocalPortData[endpoint['mac']]['label'],
                            'macAddress': endpoint['mac'],
                            'ipAddress': endpoint['ip']
                           })

            r[port] = {
                 'endpoints': eps
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
    
