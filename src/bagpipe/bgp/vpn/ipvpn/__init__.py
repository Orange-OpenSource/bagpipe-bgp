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

from bagpipe.bgp.vpn.vpn_instance import VPNInstance

from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver as _DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass

from exabgp.structure.vpn import RouteDistinguisher, VPNLabelledPrefix
from exabgp.structure.mpls import LabelStackEntry
from exabgp.structure.address import AFI, SAFI 
from exabgp.structure.ip import Inet, Prefix
from exabgp.message.update.route import Route
from exabgp.message.update.attribute.nexthop import NextHop

log = logging.getLogger(__name__)


class DummyDataplaneDriver(_DummyDataplaneDriver):
    
    pass


########## VRF

class VRF(VPNInstance, LookingGlass):
    # component managing a VRF:
    # - calling a driver to instantiate the dataplane
    # - registering to receive routes for the needed route targets
    # - calling the driver to setup/update/remove routes in the dataplane
    # - cleanup: calling the driver, unregistering for BGP routes
    
    afi = AFI(AFI.ipv4)
    safi = SAFI(SAFI.mpls_vpn)
    
    def __init__(self, *args):
        
        log.debug("Init VRF")
        
        VPNInstance.__init__(self, *args)
        
        self.initialize()  # TODO: ???
        
    def generateVifBGPRoute(self, macAdress, ipAddress, label):
        # Generate BGP route and advertise it...
        route = Route(VPNLabelledPrefix(self.afi,
                                        self.safi,
                                        Prefix(self.afi , ipAddress, 32),
                                        RouteDistinguisher(RouteDistinguisher.TYPE_IP_LOC, None, self.bgpManager.getLocalAddress(), self.instanceId),
                                        [LabelStackEntry(label, True)]
                                        ) 
                      )
        
        nh = Inet(1, socket.inet_pton(socket.AF_INET, self.bgpManager.getLocalAddress()))         
        route.attributes.add(NextHop(nh))
        
        return self._newRouteEntry(self.afi, self.safi, self.exportRTs, route.nlri, route.attributes)

    
    ##################### Callbacks for BGP route updates (TrackerWorker) #############################################
    
    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, VPNLabelledPrefix):
            return route.nlri.prefix
        else:
            raise Exception("VRF %d should not receive routes of type %s" % (self.instanceId, type(route.nlri)))
        
    def _compareRoutes(self, routeA, routeB):
        return 0  # all routes considered equal, for now   
    
    @utils.synchronized
    def _newBestRoute(self, prefix, newRoute):
        log.info("newBestRoute for %s: %s" % (prefix, newRoute))
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.trackedEntry2bestRoutes[prefix])))
        
        nh = newRoute.attributes.get(NextHop.ID)
        remotePE = nh.next_hop
        label = newRoute.nlri.labelStack[0].labelValue
        
        dataplaneInfo = self.dataplane.setupDataplaneForRemoteEndpoint(prefix, remotePE, label, newRoute.nlri)
        self.route2dataplaneInfo[newRoute] = dataplaneInfo

    @utils.synchronized
    def _bestRouteRemoved(self, prefix, oldRoute):
        log.info("bestRouteRemoved for %s: %s" % (prefix, oldRoute))
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.trackedEntry2bestRoutes[prefix])))
        
        nh = oldRoute.attributes.get(NextHop.ID)
        remotePE = nh.next_hop
        label = oldRoute.nlri.labelStack[0].labelValue
        dataplaneInfo = self.route2dataplaneInfo[ oldRoute ]
        
        self.dataplane.removeDataplaneForRemoteEndpoint(prefix, remotePE, label, dataplaneInfo, oldRoute.nlri)



