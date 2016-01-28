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

from copy import copy

from threading import Thread
from threading import Lock

from netaddr.ip import IPNetwork
import netaddr

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import logDecorator
from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger, LGMap

from bagpipe.bgp.engine.tracker_worker import TrackerWorker, \
    compareECMP, compareNoECMP

from bagpipe.bgp.engine import RouteEntry

from exabgp.reactor.protocol import AFI, SAFI

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation
from exabgp.bgp.message.update.attribute.attribute import Attribute

from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities

from bagpipe.bgp.rest_api import APIException


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
            try:
                self.readvertiseToRTs = readvertise['to_rt']
            except KeyError:
                raise APIException("'readvertise' specified with no 'to_rt'")
            self.readvertiseFromRTs = readvertise.get('from_rt', [])
            self.log.debug("readvertise enabled, from RT:%s, to %s",
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

        self.log.debug("%s %d - Added Import RTs: %s",
                       self.instanceType, self.instanceId, added_import_rt)
        self.log.debug("%s %d - Removed Import RTs: %s",
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
        self.log.debug("Exports RTs: %s -> %s", self.exportRTs, newExportRTs)
        if frozenset(newExportRTs) != frozenset(self.exportRTs):
            self.log.debug("Will re-export routes with new RTs")
            self.exportRTs = newExportRTs
            # FIXME: we should only update the routes that
            # are routes of ports plugged to the VPN instance,
            # not all routes which would wrongly include
            # routes that we re-advertise between RTs
            for routeEntry in self.getRouteEntries():
                self.log.info("Re-advertising route %s with updated RTs (%s)",
                              routeEntry.nlri, newExportRTs)

                updatedRouteEntry = RouteEntry(routeEntry.nlri, None,
                                               copy(routeEntry.attributes))
                # reset the routeTargets
                # will RTs originally present in routeEntry.attributes
                updatedRouteEntry.setRouteTargets(self.exportRTs)

                self.log.debug("   updated route: %s", updatedRouteEntry)

                self._advertiseRoute(updatedRouteEntry)

    def _parseIPAddressPrefix(self, ipAddressPrefix):
        ipAddress = ""
        mask = 0
        try:
            net = IPNetwork(ipAddressPrefix)
            (ipAddress, mask) = (str(net.ip), net.prefixlen)
        except netaddr.core.AddrFormatError as e:
            raise APIException("Bogus IP prefix: %s" % ipAddressPrefix)

        return (ipAddress, mask)

    def _genExtendedCommunities(self):
        ecommunities = ExtendedCommunities()
        for encap in self.dataplaneDriver.supportedEncaps():
            if not isinstance(encap, Encapsulation):
                raise Exception("dataplaneDriver.supportedEncaps() should "
                                "return a list of Encapsulation objects (%s)",
                                type(encap))

            if encap != Encapsulation(Encapsulation.Type.DEFAULT):
                ecommunities.communities.append(encap)
        # FIXME: si DEFAULT + xxx => adv MPLS
        return ecommunities

    @abstractmethod
    def generateVifBGPRoute(self, macAddress, ipPrefix, prefixLen, label):
        '''
        returns a RouteEntry
        '''
        pass

    def synthesizeVifBGPRoute(self, macAddress, ipPrefix, prefixLen, label):
        routeEntry = self.generateVifBGPRoute(macAddress, ipPrefix, prefixLen,
                                              label)
        assert(isinstance(routeEntry, RouteEntry))

        routeEntry.attributes.add(self._genExtendedCommunities())
        routeEntry.setRouteTargets(self.exportRTs)

        self.log.debug("synthesized route entry: %s", routeEntry)
        return routeEntry

    @utils.synchronized
    @logDecorator.logInfo
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort,
                   advertiseSubnet=False):
        # Check if this port has already been plugged
        # - Verify port informations consistency
        if macAddress in self.macAddress2LocalPortData:
            self.log.debug("MAC address already plugged, checking port "
                           "consistency")
            portData = self.macAddress2LocalPortData[macAddress]

            if (portData.get("port_info") != localPort):
                raise APIException("Port information is not consistent. MAC "
                                   "address cannot be bound to two different"
                                   "ports. Previous plug for port %s "
                                   "(%s != %s)" % (localPort['linuxif'],
                                                   portData.get("port_info"),
                                                   localPort))

        # - Verify (MAC address, IP address) tuple consistency
        if ipAddressPrefix in self.ipAddress2MacAddress:
            if self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress:
                raise APIException("Inconsistent endpoint info: %s already "
                                   "bound to a MAC address different from %s" %
                                   (ipAddressPrefix, macAddress))
            else:
                return

        # Else, plug port on dataplane
        try:
            # Parse address/mask
            (ipPrefix, prefixLen) = self._parseIPAddressPrefix(ipAddressPrefix)

            self.log.debug("Plugging port (%s)", ipPrefix)

            portData = self.macAddress2LocalPortData.get(macAddress, dict())
            if not portData:
                portData['label'] = self.vpnManager.labelAllocator.getNewLabel(
                    "Incoming traffic for %s %d, interface %s, endpoint %s/%s" %
                    (self.instanceType, self.instanceId, localPort['linuxif'],
                     macAddress, ipAddressPrefix)
                )
                portData["port_info"] = localPort

            # Call driver to setup the dataplane for incoming traffic
            self.dataplane.vifPlugged(macAddress, ipPrefix,
                                      localPort, portData['label'])

            if not advertiseSubnet:
                self.log.debug("Will advertise as /32 instead of /%d" %
                               prefixLen)
                prefixLen = 32

            self.log.info("Synthesizing and advertising BGP route for VIF %s "
                          "endpoint (%s, %s/%d)", localPort['linuxif'],
                          macAddress, ipPrefix, prefixLen)
            routeEntry = self.synthesizeVifBGPRoute(macAddress,
                                                    ipPrefix, prefixLen,
                                                    portData['label'])

            self._advertiseRoute(routeEntry)

            if localPort['linuxif'] not in self.localPort2Endpoints:
                self.localPort2Endpoints[localPort['linuxif']] = list()

            self.localPort2Endpoints[localPort['linuxif']].append(
                {'mac': macAddress, 'ip': ipAddressPrefix,
                 # FIXME: maybe add prefix len for the LG
                 }
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
    def vifUnplugged(self, macAddress, ipAddressPrefix,
                     advertiseSubnet=False):
        # Verify port and endpoint (MAC address, IP address) tuple consistency
        portData = self.macAddress2LocalPortData.get(macAddress)
        if (not portData or
                self.ipAddress2MacAddress.get(ipAddressPrefix) != macAddress):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but no "
                           "consistent informations or was not plugged yet",
                           macAddress, ipAddressPrefix)
            raise APIException("No consistent endpoint (%s, %s) informations "
                               "or was not plugged yet, cannot unplug" %
                               (macAddress, ipAddressPrefix))

        # Finding label and local port informations
        label = portData.get('label')
        localPort = portData.get('port_info')
        if (not label or not localPort):
            self.log.error("vifUnplugged called for endpoint (%s, %s), but "
                           "port data (%s, %s) is incomplete",
                           macAddress, ipAddressPrefix, label, localPort)
            raise Exception("Inconsistent informations for port, bug ?")

        if localPort['linuxif'] in self.localPort2Endpoints:
            # Parse address/mask
            (ipPrefix, prefixLen) = self._parseIPAddressPrefix(ipAddressPrefix)

            lastEndpoint = len(self.localPort2Endpoints[localPort['linuxif']
                                                        ]) <= 1

            if not advertiseSubnet:
                self.log.debug("Will advertise as /32 instead of /%d" %
                               prefixLen)
                prefixLen = 32

            self.log.info("Synthesizing and withdrawing BGP route for VIF %s "
                          "endpoint (%s, %s/%d)", localPort['linuxif'],
                          macAddress, ipPrefix, prefixLen)
            routeEntry = self.synthesizeVifBGPRoute(macAddress,
                                                    ipPrefix, prefixLen,
                                                    label)
            self._withdrawRoute(routeEntry)

            # Unplug endpoint from data plane
            self.dataplane.vifUnplugged(
                macAddress, ipPrefix, localPort, label, lastEndpoint)

            # Forget data for this port if last endpoint
            if lastEndpoint:
                # Free label to the allocator
                self.vpnManager.labelAllocator.release(label)

                del self.localPort2Endpoints[localPort['linuxif']]
                del self.macAddress2LocalPortData[macAddress]
            else:
                self.localPort2Endpoints[localPort['linuxif']].remove(
                    {'mac': macAddress, 'ip': ipAddressPrefix}
                )

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
                Attribute.CODE.EXTENDED_COMMUNITY].communities
            )
            self.log.debug("Advertized Encaps: %s", advEncaps)
        except KeyError:
            self.log.debug("no encap advertized, let's use default")

        if not advEncaps:
            advEncaps = [Encapsulation(Encapsulation.Type.DEFAULT)]

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
