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

from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver \
    as _DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass

from bagpipe.exabgp.structure.vpn import RouteDistinguisher, VPNLabelledPrefix
from bagpipe.exabgp.structure.mpls import LabelStackEntry
from bagpipe.exabgp.structure.address import AFI, SAFI
from bagpipe.exabgp.structure.ip import Inet, Prefix
from bagpipe.exabgp.message.update.route import Route
from bagpipe.exabgp.message.update.attribute.nexthop import NextHop

log = logging.getLogger(__name__)


class DummyDataplaneDriver(_DummyDataplaneDriver):

    pass


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

    def generateVifBGPRoute(self, macAdress, ipAddress, label):
        # Generate BGP route and advertise it...
        route = Route(VPNLabelledPrefix(self.afi,
                                        self.safi,
                                        Prefix(self.afi, ipAddress, 32),
                                        RouteDistinguisher(
                                            RouteDistinguisher.TYPE_IP_LOC,
                                            None,
                                            self.bgpManager.getLocalAddress(),
                                            self.instanceId),
                                        [LabelStackEntry(label, True)]
                                        )
                      )

        return self._newRouteEntry(self.afi, self.safi, self.exportRTs,
                                   route.nlri, route.attributes)

    # Callbacks for BGP route updates (TrackerWorker) ########################

    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, VPNLabelledPrefix):
            return route.nlri.prefix
        else:
            raise Exception("VRF %d should not receive routes of type %s" %
                            (self.instanceId, type(route.nlri)))

    @utils.synchronized
    @logDecorator.log
    def _newBestRoute(self, prefix, newRoute):
        encaps = self._checkEncaps(newRoute)
        if not encaps:
            return

        self.dataplane.setupDataplaneForRemoteEndpoint(
            prefix, newRoute.attributes.get(NextHop.ID).next_hop,
            newRoute.nlri.labelStack[0].labelValue, newRoute.nlri, encaps)

    @utils.synchronized
    @logDecorator.log
    def _bestRouteRemoved(self, prefix, oldRoute, last):
        if self._skipRouteRemoval(last):
            self.log.debug("Skipping removal of non-last route because "
                           "dataplane does not want it")
            return

        self.dataplane.removeDataplaneForRemoteEndpoint(
            prefix, oldRoute.attributes.get(NextHop.ID).next_hop,
            oldRoute.nlri.labelStack[0].labelValue, oldRoute.nlri)
