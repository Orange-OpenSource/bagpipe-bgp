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

from bagpipe.bgp.vpn.vpn_instance import VPNInstance, TrafficClassifier

from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import RouteEntry

from bagpipe.bgp.engine.flowspec import Flow
from bagpipe.bgp.engine.ipvpn import IPVPN as IPVPNNlri
from bagpipe.bgp.engine.ipvpn import IPVPNRouteFactory

from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver \
    as _DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message.update.attribute.attribute import Attribute
from _collections import defaultdict
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended.rt \
    import RouteTarget as RTExtCom
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord

from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI

from exabgp.bgp.message.update import Attribute
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.attribute.community.extended \
    import ConsistentHashSortOrder

IPVPN = "ipvpn"


class DummyDataplaneDriver(_DummyDataplaneDriver):

    type = IPVPN


class VRF(VPNInstance, LookingGlass):
    # component managing a VRF:
    # - calling a driver to instantiate the dataplane
    # - registering to receive routes for the needed route targets
    # - calling the driver to setup/update/remove routes in the dataplane
    # - cleanup: calling the driver, unregistering for BGP routes

    type = IPVPN
    afi = AFI(AFI.ipv4)
    safi = SAFI(SAFI.mpls_vpn)

    @logDecorator.log
    def __init__(self, *args, **kwargs):
        VPNInstance.__init__(self, *args, **kwargs)
        self.readvertised = set()

    def _nlriFrom(self, prefix, label, rd):
        assert(rd is not None)

        return IPVPNRouteFactory(self.afi, prefix, label, rd,
                                 self.dataplaneDriver.getLocalAddress())

    def generateVifBGPRoute(self, macAdress, ipPrefix, prefixLen, label, rd):
        # Generate BGP route and advertise it...
        nlri = self._nlriFrom("%s/%s" % (ipPrefix, prefixLen), label, rd)

        return RouteEntry(nlri)

    def _getLocalLabels(self):
        for portData in self.macAddress2LocalPortData.itervalues():
            yield portData['label']

    def _imported(self, route):
        return (len(set(route.routeTargets).intersection(
                    set(self.importRTs))) > 0)

    def _toReadvertise(self, route):
        # Only re-advertise IP VPN routes (e.g. not Flowspec routes)
        if not isinstance(route.nlri, IPVPNNlri):
            return False

        rtRecords = route.extendedCommunities(RTRecord)
        self.log.debug("RTRecords: %s (readvertiseToRTs:%s)",
                       rtRecords,
                       self.readvertiseToRTs)

        readvertise_targets_as_records = [RTRecord.from_rt(rt)
                                          for rt in self.readvertiseToRTs]

        if self.attractTraffic:
            readvertise_targets_as_records += [RTRecord.from_rt(rt)
                                               for rt in self.attractRTs]

        if set(readvertise_targets_as_records).intersection(set(rtRecords)):
            self.log.debug("not to re-advertise because one of the readvertise"
                           " or attract-redirect RTs is in RTRecords: %s",
                           set(readvertise_targets_as_records)
                           .intersection(set(rtRecords)))
            return False

        return (len(set(route.routeTargets).intersection(
                    set(self.readvertiseFromRTs))) > 0)

    def _routeForReAdvertisement(self, route, label, rd, lbConsistentHashOrder,
                                 doDefault=False):
        prefix = "0.0.0.0/0" if doDefault else route.nlri.cidr.prefix()

        nlri = self._nlriFrom(prefix, label, rd)

        attributes = Attributes()

        # new RTRecord = original RTRecord (if any) + orig RTs
        origRTRecords = route.extendedCommunities(RTRecord)
        rts = route.extendedCommunities(RTExtCom)
        addRTRecords = [RTRecord.from_rt(rt) for rt in rts]

        finalRTRecords = list(set(origRTRecords) | set(addRTRecords))

        eComs = self._genEncapExtendedCommunities()
        eComs.communities += finalRTRecords
        eComs.communities.append(ConsistentHashSortOrder(lbConsistentHashOrder))
        attributes.add(eComs)

        entry = RouteEntry(nlri, self.readvertiseToRTs, attributes)
        self.log.debug("RouteEntry for (re-)advertisement: %s", entry)
        return entry

    @logDecorator.log
    def _routeForRedirectPrefix(self, prefix):
        prefixClassifier = self.attractClassifier.copy()
        prefixClassifier['destinationPrefix'] = prefix

        trafficClassifier = TrafficClassifier(**prefixClassifier)
        self.log.debug("Advertising prefix %s for redirection based on "
                       "traffic classifier %s", prefix, trafficClassifier)
        rules = trafficClassifier.mapTrafficClassifier2RedirectRules()

        return self.synthesizeRedirectBGPRoute(rules)

    def _advertiseRouteOrDefault(self, route, label, rd,
                                 lbConsistentHashOrder=0):
        if self.attractTraffic:
            self.log.debug("Advertising default route from VRF %d to "
                           "redirection VRF", self.instanceId)

        routeEntry = self._routeForReAdvertisement(
            route, label, rd, lbConsistentHashOrder,
            doDefault=self.attractTraffic
        )
        self._advertiseRoute(routeEntry)

    def _withdrawRouteOrDefault(self, route, label, rd,
                                lbConsistentHashOrder=0):
        if self.attractTraffic:
            self.log.debug("Stop advertising default route from VRF to "
                           "redirection VRF")

        routeEntry = self._routeForReAdvertisement(
            route, label, rd, lbConsistentHashOrder,
            doDefault=self.attractTraffic
        )
        self._withdrawRoute(routeEntry)

    @logDecorator.log
    def _readvertise(self, route):
        nlri = route.nlri

        self.log.debug("Start re-advertising %s from VRF", nlri.cidr.prefix())
        for localPort, endpoints in self.localPort2Endpoints.iteritems():
            for endpoint in endpoints:
                portData = self.macAddress2LocalPortData[endpoint['mac']]
                label = portData['label']
                lbConsistentHashOrder = portData['lbConsistentHashOrder']
                rd = self.endpoint2RD[(endpoint['mac'], endpoint['ip'])]
                self.log.debug("Start re-advertising %s from VRF, with label "
                               "%s and route distinguisher %s",
                               nlri, label, rd)
                # need a distinct RD for each route...
                self._advertiseRouteOrDefault(route, label, rd,
                                              lbConsistentHashOrder)

        if self.attractTraffic:
            flowEntry = self._routeForRedirectPrefix(nlri.cidr.prefix())
            self._advertiseRoute(flowEntry)

        self.readvertised.add(route)

    @logDecorator.log
    def _readvertiseStop(self, route):
        nlri = route.nlri

        self.log.debug("Stop re-advertising %s from VRF", nlri.cidr.prefix())
        for localPort, endpoints in self.localPort2Endpoints.iteritems():
            for endpoint in endpoints:
                portData = self.macAddress2LocalPortData[endpoint['mac']]
                label = portData['label']
                lbConsistentHashOrder = portData['lbConsistentHashOrder']
                rd = self.endpoint2RD[(endpoint['mac'], endpoint['ip'])]
                self.log.debug("Stop re-advertising %s from VRF, with label "
                               "%s and route distinguisher %s",
                               nlri, label, rd)
                self._withdrawRouteOrDefault(route, label, rd,
                                             lbConsistentHashOrder)

        if self.attractTraffic:
            flowEntry = self._routeForRedirectPrefix(nlri.cidr.prefix())
            self._withdrawRoute(flowEntry)

        self.readvertised.remove(route)

    def vifPlugged(self, macAddress, ipAddressPrefix, localPort,
                   advertiseSubnet, lbConsistentHashOrder):
        VPNInstance.vifPlugged(self, macAddress, ipAddressPrefix, localPort,
                               advertiseSubnet, lbConsistentHashOrder)

        label = self.macAddress2LocalPortData[macAddress]['label']
        rd = self.endpoint2RD[(macAddress, ipAddressPrefix)]
        for route in self.readvertised:
            self.log.debug("Re-advertising %s with this port as next hop",
                           route.nlri)
            self._advertiseRouteOrDefault(route, label, rd,
                                          lbConsistentHashOrder)

            if self.attractTraffic:
                flowEntry = self._routeForRedirectPrefix(route.nlri.cidr.prefix())
                self._advertiseRoute(flowEntry)

    def vifUnplugged(self, macAddress, ipAddressPrefix, advertiseSubnet):
        label = self.macAddress2LocalPortData[macAddress]['label']
        lbConsistentHashOrder = self.macAddress2LocalPortData[macAddress]["lbConsistentHashOrder"]
        rd = self.endpoint2RD[(macAddress, ipAddressPrefix)]
        for route in self.readvertised:
            self.log.debug("Stop re-advertising %s with this port as next hop",
                           route.nlri)
            self._withdrawRouteOrDefault(route, label, rd,
                                         lbConsistentHashOrder)

            if self.attractTraffic and self.hasOnlyOneEndpoint():
                flowEntry = self._routeForRedirectPrefix(route.nlri.cidr.prefix())
                self._withdrawRoute(flowEntry)

        VPNInstance.vifUnplugged(self, macAddress, ipAddressPrefix,
                                 advertiseSubnet, lbConsistentHashOrder)

    # Callbacks for BGP route updates (TrackerWorker) ########################

    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, IPVPNNlri):
            return route.nlri.cidr.prefix()
        elif isinstance(route.nlri, Flow):
            return (Flow, route.nlri._rules())
        else:
            self.log.error("We should not receive routes of type %s",
                           type(route.nlri))
            return None

    @utils.synchronized
    @logDecorator.log
    def _newBestRoute(self, entry, newRoute):

        if isinstance(newRoute.nlri, Flow):
            rule = entry

            if len(newRoute.extendedCommunities(TrafficRedirect)) == 1:
                trafficRedirect = newRoute.extendedCommunities(TrafficRedirect)
                redirectRT = "%s:%s" % (trafficRedirect[0].asn,
                                        trafficRedirect[0].target)

                self.startRedirectTraffic(redirectRT, newRoute.nlri.rules)
            else:
                self.log.warning("FlowSpec action or multiple traffic redirect"
                                 " actions not supported: %s",
                                 newRoute.extendedCommunities())
        else:
            prefix = entry

            if self.readvertise:
                # check if this is a route we need to re-advertise
                self.log.debug("route RTs: %s", newRoute.routeTargets)
                self.log.debug("readv from RTs: %s", self.readvertiseFromRTs)
                if self._toReadvertise(newRoute):
                    self.log.debug("Need to re-advertise %s", prefix)
                    self._readvertise(newRoute)

            if not self._imported(newRoute):
                self.log.debug("No need to setup dataplane for:%s",
                               prefix)
                return

            encaps = self._checkEncaps(newRoute)
            if not encaps:
                return

            assert(len(newRoute.nlri.labels.labels) == 1)

            lbConsistentHashOrder = 0
            if newRoute.extendedCommunities(ConsistentHashSortOrder):
                lbConsistentHashOrder = newRoute.extendedCommunities(
                    ConsistentHashSortOrder)[0].order

            self.dataplane.setupDataplaneForRemoteEndpoint(
                prefix, newRoute.nexthop,
                newRoute.nlri.labels.labels[0], newRoute.nlri, encaps,
                lbConsistentHashOrder)

    @utils.synchronized
    @logDecorator.log
    def _bestRouteRemoved(self, entry, oldRoute, last):

        if isinstance(oldRoute.nlri, Flow):
            rule = entry

            if len(oldRoute.extendedCommunities(TrafficRedirect)) == 1:
                if last:
                    trafficRedirect = oldRoute.extendedCommunities(
                        TrafficRedirect)
                    redirectRT = "%s:%s" % (trafficRedirect[0].asn,
                                            trafficRedirect[0].target)

                    self.stopRedirectTraffic(redirectRT, oldRoute.nlri.rules)
            else:
                self.log.warning("FlowSpec action or multiple traffic redirect"
                                 " actions not supported: %s",
                                 oldRoute.extendedCommunities())
        else:
            prefix = entry

            if self.readvertise and last:
                # check if this is a route we were re-advertising
                if self._toReadvertise(oldRoute):
                    self.log.debug("Need to stop re-advertising %s", prefix)
                    self._readvertiseStop(oldRoute)

            if not self._imported(oldRoute):
                self.log.debug("No need to update dataplane for:%s",
                               prefix)
                return

            if self._skipRouteRemoval(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            encaps = self._checkEncaps(oldRoute)
            if not encaps:
                return

            assert(len(oldRoute.nlri.labels.labels) == 1)

            lbConsistentHashOrder = 0
            if oldRoute.extendedCommunities(ConsistentHashSortOrder):
                lbConsistentHashOrder = oldRoute.extendedCommunities(
                    ConsistentHashSortOrder)[0].order

            self.dataplane.removeDataplaneForRemoteEndpoint(
                prefix, oldRoute.nexthop,
                oldRoute.nlri.labels.labels[0], oldRoute.nlri, encaps,
                lbConsistentHashOrder)

    ### Looking glass ###

    def getLGMap(self):
        return {
            "readvertised": (LGMap.SUBTREE, self.getLGReadvertisedRoutes),
        }

    def getLGReadvertisedRoutes(self, pathPrefix):
        return [route.getLookingGlassLocalInfo(pathPrefix)
                for route in self.readvertised]

