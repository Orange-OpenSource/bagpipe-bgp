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
import socket

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import logDecorator

from bagpipe.bgp.vpn.vpn_instance import VPNInstance

from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import RouteEntry

from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message.update.nlri.qualifier.labels import Labels

from exabgp.bgp.message.update.nlri.mpls import MPLSVPN
from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities

from exabgp.bgp.message import OUT

from exabgp.protocol.ip import IP


def prefixFromNLRI(nlri):
    return "%s/%s" % (nlri.ip, nlri.mask)


def prefixToPackedIPMask(prefix):
    ipString, mask = prefix.split("/")
    return (IP.pton(ipString), int(mask))


class VRF(VPNInstance, LookingGlass):
    # component managing a VRF:
    # - calling a driver to instantiate the dataplane
    # - registering to receive routes for the needed route targets
    # - calling the driver to setup/update/remove routes in the dataplane
    # - cleanup: calling the driver, unregistering for BGP routes

    type = "ipvpn"
    afi = AFI(AFI.ipv4)
    safi = SAFI(SAFI.mpls_vpn)

    @logDecorator.log
    def __init__(self, *args, **kwargs):
        VPNInstance.__init__(self, *args, **kwargs)
        self.readvertised = set()

    def _nlriFrom(self, prefix, label, rd):
        assert(rd is not None)
        packedPrefix, mask = prefixToPackedIPMask(prefix)
        nlri = MPLSVPN(self.afi, self.safi, packedPrefix, mask,
                       Labels([label], True), rd,
                       IP.pton(self.dataplaneDriver.getLocalAddress()))

        return nlri

    def generateVifBGPRoute(self, macAdress, ipPrefix, prefixLen, label):
        # Generate BGP route and advertise it...
        rd = RouteDistinguisher.fromElements(self.bgpManager.getLocalAddress(),
                                             self.instanceId)
        nlri = self._nlriFrom("%s/%s" % (ipPrefix, prefixLen), label, rd)

        return RouteEntry(self.afi, self.safi, nlri)

    def _getLocalLabels(self):
        for portData in self.macAddress2LocalPortData.itervalues():
            yield portData['label']

    def _getRDFromLabel(self, label):
        # FIXME: this is a crude hack that will break beyond 10000 VRFs
        return RouteDistinguisher.fromElements(
            self.bgpManager.getLocalAddress(),
            10000+label)

    @logDecorator.log
    def _readvertise(self, nlri):
        for label in self._getLocalLabels():
            # need a distinct RD for each route...
            nlri = self._nlriFrom(prefixFromNLRI(nlri), label,
                                  self._getRDFromLabel(label))

            attributes = Attributes()

            attributes.add(ExtendedCommunities(self.readvertiseToRTs))

            routeEntry = RouteEntry(self.afi, self.safi, nlri,
                                    self.readvertiseToRTs, attributes)
            self._advertiseRoute(routeEntry)

        self.readvertised.add(nlri.prefix())

    @logDecorator.log
    def _readvertiseStop(self, nlri):
        for label in self._getLocalLabels():
            nlri = self._nlriFrom(prefixFromNLRI(nlri), label,
                                  self._getRDFromLabel(label))
            routeEntry = RouteEntry(self.afi, self.safi, nlri)
            self._withdrawRoute(routeEntry)

        self.readvertised.remove(nlri.prefix())

    def vifPlugged(self, macAddress, ipAddressPrefix, localPort,
                   advertiseSubnet):
        VPNInstance.vifPlugged(self, macAddress, ipAddressPrefix, localPort,
                               advertiseSubnet)

        label = self.macAddress2LocalPortData[macAddress]['label']
        for prefix in self.readvertised:
            nlri = self._nlriFrom(prefix, label, self._getRDFromLabel(label))
            routeEntry = RouteEntry(self.afi, self.safi, nlri,
                                    self.readvertiseToRTs)
            self._advertiseRoute(routeEntry)

    def vifUnplugged(self, macAddress, ipAddressPrefix, advertiseSubnet):
        label = self.macAddress2LocalPortData[macAddress]['label']
        for prefix in self.readvertised:
            nlri = self._nlriFrom(prefix, label, self._getRDFromLabel(label))
            routeEntry = RouteEntry(self.afi, self.safi, nlri)
            self._withdrawRoute(routeEntry)

        VPNInstance.vifUnplugged(self, macAddress, ipAddressPrefix,
                                 advertiseSubnet)

    # Callbacks for BGP route updates (TrackerWorker) ########################

    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, MPLSVPN):
            return route.nlri.prefix()
        else:
            self.log.error("We should not receive routes of type %s",
                           type(route.nlri))
            return None

    def _toReadvertise(self, route):
        return (len(set(route.routeTargets).intersection(
                    set(self.readvertiseFromRTs))) > 0)

    def _imported(self, route):
        return (len(set(route.routeTargets).intersection(
                    set(self.readvertiseFromRTs))) > 0)

    @utils.synchronized
    @logDecorator.log
    def _newBestRoute(self, entry, newRoute):

        prefix = entry

        if self.readvertise:
            # check if this is a route we need to re-advertise
            self.log.debug("route RTs: %s", newRoute.routeTargets)
            self.log.debug("readv from RTs: %s", self.readvertiseFromRTs)
            if self._toReadvertise(newRoute):
                self.log.debug("Need to re-advertise %s", prefix)
                self._readvertise(newRoute.nlri)
                if not self._imported(newRoute):
                    self.log.debug("No need to setup dataplane for:%s", prefix)
                    return

        encaps = self._checkEncaps(newRoute)
        if not encaps:
            return

        assert(len(newRoute.nlri.labels.labels) == 1)

        self.dataplane.setupDataplaneForRemoteEndpoint(
            prefix, newRoute.nexthop,
            newRoute.nlri.labels.labels[0], newRoute.nlri, encaps)

    @utils.synchronized
    @logDecorator.log
    def _bestRouteRemoved(self, entry, oldRoute, last):

        prefix = entry

        if self.readvertise and last:
            # check if this is a route we were re-advertising
            if self._toReadvertise(oldRoute):
                self.log.debug("Need to stop re-advertising %s", prefix)
                self._readvertiseStop(oldRoute.nlri)
                if not self._imported(oldRoute):
                    self.log.debug("No need to setup dataplane for:%s", prefix)
                    return

        if self._skipRouteRemoval(last):
            self.log.debug("Skipping removal of non-last route because "
                           "dataplane does not want it")
            return

        assert(len(oldRoute.nlri.labels.labels) == 1)

        self.dataplane.removeDataplaneForRemoteEndpoint(
            prefix, oldRoute.nexthop,
            oldRoute.nlri.labels.labels[0], oldRoute.nlri)

    def getLGMap(self):
        return {
            "readvertised":  (LGMap.VALUE, [prefix for prefix in
                                            self.readvertised])
        }
