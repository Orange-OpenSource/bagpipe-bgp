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

from abc import ABCMeta, abstractmethod

import socket

from copy import copy

from threading import Thread
from threading import Lock

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import logDecorator
from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger, LGMap

from bagpipe.bgp.engine.tracker_worker import TrackerWorker, \
    compareECMP, compareNoECMP

from bagpipe.bgp.engine import RouteEvent, RouteEntry

from bagpipe.exabgp.structure.address import AFI, SAFI

from bagpipe.exabgp.message.update.attribute.communities import ECommunities, \
    Encapsulation
from bagpipe.exabgp.message.update.attribute.id import AttributeID

from bagpipe.exabgp.message.update.attribute.nexthop import NextHop
from bagpipe.exabgp.structure.ip import Inet


class VPNInstance(TrackerWorker, Thread, LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    afi = None
    safi = None

    @logDecorator.log
    def __init__(self, bgpManager, labelAllocator, dataplaneDriver,
                 externalInstanceId, instanceId, importRTs, exportRTs,
                 gatewayIP, mask, readvertise, **kwargs):

        self.instanceType = self.__class__.__name__
        self.instanceId = instanceId

        Thread.__init__(self)
        self.setDaemon(True)

        if dataplaneDriver.ecmpSupport:
            compareRoutes = compareECMP
        else:
            compareRoutes = compareNoECMP

        TrackerWorker.__init__(self, bgpManager, "%s %d" %
                               (self.instanceType, self.instanceId),
                               compareRoutes)

        LookingGlassLocalLogger.__init__(self,
                                         "%s-%d" % (self.instanceType,
                                                    self.instanceId))
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

        self.instanceLabel = self.labelAllocator.getNewLabel(
            "Incoming traffic for %s %d" % (self.instanceType,
                                            self.instanceId))

        self.localPortData = dict()

        # One local port -> List of endpoints (MAC and IP addresses tuple)
        self.localPort2Endpoints = dict()
        # One MAC address -> One local port
        self.macAddress2LocalPortData = dict()
        # One IP address ->  One MAC address
        self.ipAddress2MacAddress = dict()

        self.dataplane = self.dataplaneDriver.initializeDataplaneInstance(
            self.instanceId, self.externalInstanceId,
            self.gatewayIP, self.mask, self.instanceLabel, **kwargs)

        for rt in self.importRTs:
            self._subscribe(self.afi, self.safi, rt)

        if readvertise:
            self.readvertise = True
            self.readvertiseFromRTs = readvertise['from_rt']
            self.readvertiseToRTs = readvertise['to_rt']
            self.log.debug("readvertise enabled, from %s, to %s",
                           self.readvertiseFromRTs, self.readvertiseToRTs)
            for rt in self.readvertiseFromRTs:
                self._subscribe(self.afi, self.safi, rt)
        else:
            self.log.debug("readvertise not enabled")
            self.readvertise = False

    @utils.synchronized
    def stop(self):
        self._stop()

    @logDecorator.log
    def _stop(self):
        # cleanup BGP subscriptions
        for rt in self.importRTs:
            self._unsubscribe(self.afi, self.safi, rt)

        self.dataplane.cleanup()

        self.labelAllocator.release(self.instanceLabel)

        # this makes sure that the thread will be stopped, and any remaining
        # routes/subscriptions are released:
        TrackerWorker.stop(self)

    @utils.synchronized
    @logDecorator.log
    def stopIfEmpty(self):
        self.log.debug("localPort2Endpoints: %s", self.localPort2Endpoints)
        if self.isEmpty():
            self._stop()
            return True

        return False

    def isEmpty(self):
        return (not self.localPort2Endpoints)

    def hasEnpoint(self, linuxif):
        return (self.localPort2Endpoints.get(linuxif) is not None)

    @logDecorator.log
    def updateRouteTargets(self, newImportRTs, newExportRTs):
        added_import_rt = set(newImportRTs) - set(self.importRTs)
        removed_import_rt = set(self.importRTs) - set(newImportRTs)

        self.log.debug("%s %d - Added Import RT: %s",
                       self.instanceType, self.instanceId, added_import_rt)
        self.log.debug("%s %d - Removed Import RT: %s",
                       self.instanceType, self.instanceId, removed_import_rt)

        # Register to BGP with these route targets
        for rt in added_import_rt:
            self._subscribe(self.afi, self.safi, rt)

        # Unregister from BGP with these route targets
        for rt in removed_import_rt:
            self._unsubscribe(self.afi, self.safi, rt)

        # Update import and export route targets
        self.importRTs = newImportRTs

        # Re-advertise all routes with new export RTs
        if set(newExportRTs) != set(self.exportRTs):
            self.exportRTs = newExportRTs
            for routeEntry in self.getWorkerRouteEntries():
                self.log.info("Re-advertising route %s with updated RTs (%s)",
                              routeEntry.nlri, newExportRTs)

                updatedAttributes = copy(routeEntry.attributes)
                del updatedAttributes[AttributeID.EXTENDED_COMMUNITY]
                updatedAttributes.add(self._genExtendedCommunities())

                updatedRouteEntry = self._newRouteEntry(
                    routeEntry.afi, routeEntry.safi, self.exportRTs,
                    routeEntry.nlri, updatedAttributes)
                self.log.debug("   updated route: %s", updatedRouteEntry)

                self._pushEvent(
                    RouteEvent(RouteEvent.ADVERTISE, updatedRouteEntry))

    def _parseIPAddressPrefix(self, ipAddressPrefix):
        ipAddress = ""
        mask = 0
        try:
            (ipAddress, mask) = ipAddressPrefix.split('/')
        except ValueError as e:
            self.log.error("Cannot split %s into address/mask (%s)",
                           ipAddressPrefix, e)
            raise Exception("Cannot split %s into address/mask (%s)")

        return (ipAddress, mask)

    def _genExtendedCommunities(self):
        ecommunities = ECommunities(copy(self.exportRTs))
        for encap in self.dataplaneDriver.supportedEncaps():
            if not isinstance(encap, Encapsulation):
                raise Exception("dataplaneDriver.supportedEncaps() should "
                                "return a list of Encapsulation objects")

            if encap != Encapsulation(Encapsulation.DEFAULT):
                ecommunities.add(encap)
        # FIXME: si DEFAULT + xxx => adv MPLS
        return ecommunities

    @abstractmethod
    def generateVifBGPRoute(self, macAddress, ipAddress, label):
        pass

    def synthesizeVifBGPRoute(self, macAddress, ipAddress, label):
        routeEntry = self.generateVifBGPRoute(macAddress, ipAddress, label)
        assert(isinstance(routeEntry, RouteEntry))

        nh = Inet(1, socket.inet_pton(socket.AF_INET,
                                      self.dataplane.driver.getLocalAddress()))
        routeEntry.attributes.add(NextHop(nh))
        routeEntry.attributes.add(self._genExtendedCommunities())

        return routeEntry

    @utils.synchronized
    @logDecorator.logInfo
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort):
        # Check if this port has already been plugged
        # - Verify port informations consistency
        if macAddress in self.macAddress2LocalPortData:
            self.log.debug("MAC address already plugged, checking port "
                           "consistency")
            portData = self.macAddress2LocalPortData[macAddress]

            if (portData.get("port_info") != localPort):
                raise Exception("Port information is not consistent. MAC "
                                "address cannot be bound to two different"
                                "ports. Previous plug for port %s (%s != %s)" %
                                (localPort['linuxif'],
                                 portData.get("port_info"), localPort))

        # - Verify (MAC address, IP address) tuple consistency
        if ipAddressPrefix in self.ipAddress2MacAddress:
            if self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress:
                raise Exception("Inconsistent endpoint info: %s already bound "
                                "to a MAC address different from %s" %
                                (ipAddressPrefix, macAddress))
            else:
                return

        # Else, plug port on dataplane
        try:
            # Parse address/mask
            (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)

            self.log.debug("Plugging port (%s)", ipAddress)

            portData = dict()
            portData['label'] = self.labelAllocator.getNewLabel(
                "Incoming traffic for %s %d, interface %s, endpoint %s/%s" %
                (self.instanceType, self.instanceId, localPort['linuxif'],
                 macAddress, ipAddressPrefix)
            )
            portData["port_info"] = localPort

            # Call driver to setup the dataplane for incoming traffic
            self.dataplane.vifPlugged(
                macAddress, ipAddress, localPort, portData['label'])

            self.log.info("Synthesizing and advertising BGP route for VIF %s "
                          "endpoint (%s, %s)", localPort['linuxif'],
                          macAddress, ipAddressPrefix)
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
            self.log.error("Error in vifPlugged: %s", e)
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
    @logDecorator.logInfo
    def vifUnplugged(self, macAddress, ipAddressPrefix):
        # Verify port and endpoint (MAC address, IP address) tuple consistency
        portData = self.macAddress2LocalPortData.get(macAddress)
        if (not portData or
                self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but no "
                           "consistent informations or was not plugged yet",
                           macAddress, ipAddressPrefix)
            raise Exception("No consistent endpoint (%s, %s) informations or "
                            "was not plugged yet, cannot unplug" %
                            (macAddress, ipAddressPrefix))

        # Finding label and local port informations
        label = portData.get('label')
        localPort = portData.get('port_info')
        if (not label or not localPort):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but "
                           "port data (%s, %s) is incomplete",
                           macAddress, ipAddressPrefix, label, localPort)
            raise Exception("Inconsistent informations for port, bug "
                            "in BaGPipe BGP?")

        if localPort['linuxif'] in self.localPort2Endpoints:
            # Parse address/mask
            (ipAddress, _) = self._parseIPAddressPrefix(ipAddressPrefix)

            lastEndpoint = len(self.localPort2Endpoints[localPort['linuxif']
                                                        ]) <= 1

            self.log.info("Synthesizing and withdrawing BGP route for VIF %s "
                          "endpoint (%s, %s)",
                          localPort['linuxif'], macAddress, ipAddressPrefix)
            routeEntry = self.synthesizeVifBGPRoute(macAddress,
                                                    ipAddress,
                                                    label)
            self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, routeEntry))

            # Unplug endpoint from data plane
            self.dataplane.vifUnplugged(
                macAddress, ipAddress, localPort, label, lastEndpoint)

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
            self.log.error("vifUnplugged called for endpoint {%s, %s}, but"
                           " port data is incomplete", macAddress,
                           ipAddressPrefix)
            raise Exception("BGP component bug, check its logs")

    def _checkEncaps(self, route):
        '''
        returns a list of encaps supported by both the dataplane driver and the
        advertized route (based on BGP Encapsulation community)

        logs a warning if there is no common encap
        '''
        advEncaps = None
        try:
            advEncaps = filter(lambda ecom: isinstance(ecom, Encapsulation),
                               route.attributes[
                AttributeID.EXTENDED_COMMUNITY].communities
            )
            self.log.debug("Advertized Encaps: %s", advEncaps)
        except KeyError:
            self.log.debug("no encap advertized, let's use default")

        if not advEncaps:
            advEncaps = [Encapsulation(Encapsulation.DEFAULT)]

        goodEncaps = set(advEncaps) & set(
            self.dataplaneDriver.supportedEncaps())

        if not goodEncaps:
            self.log.warning("No encap supported by dataplane driver for route"
                             " %s, advertized: %s,dataplane supports: %s)",
                             route, advEncaps,
                             self.dataplaneDriver.supportedEncaps())

        return goodEncaps

    def _skipRouteRemoval(self, last):
        '''
        returns true if the removal of the route should be skipped, based
        whether or not the route removed is the last one and depending on
        the desired behavior for the dataplane driver
        '''
        return not last and not (self.dataplaneDriver.makeB4BreakSupport or
                                 self.dataplaneDriver.ecmpSupport)

    # Looking Glass ####

    def getLGMap(self):
        return {
            "dataplane":     (LGMap.DELEGATE, self.dataplane),
            "route_targets": (LGMap.SUBITEM, self.getRTs),
            "gateway_ip":    (LGMap.VALUE, self.gatewayIP),
            "subnet_mask":   (LGMap.VALUE, self.mask),
            "instance_dataplane_id": (LGMap.VALUE, self.instanceLabel),
            "ports":         (LGMap.SUBTREE, self.getLGLocalPortData),
            "readvertise":   (LGMap.SUBITEM, self.getLGReadvertise)
        }

    def getLGLocalPortData(self, pathPrefix):
        r = {}
        for (port, endpoints) in self.localPort2Endpoints.iteritems():
            eps = []
            for endpoint in endpoints:
                eps.append({
                    'label':
                    self.macAddress2LocalPortData[endpoint['mac']]['label'],
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

    def getLGReadvertise(self):
        if self.readvertise:
            return {'from': [repr(rt) for rt in self.readvertiseFromRTs],
                    'to': [repr(rt) for rt in self.readvertiseToRTs]}
        else:
            return {}
