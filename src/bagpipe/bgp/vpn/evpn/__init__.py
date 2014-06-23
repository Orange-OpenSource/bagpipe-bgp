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

from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.vpn.vpn_instance import VPNInstance
from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver as _DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass


from exabgp.structure.vpn import RouteDistinguisher
from exabgp.structure.evpn import EVPNNLRI, EVPNMACAdvertisement, EVPNMulticast, EthernetSegmentIdentifier, EthernetTag, MAC
from exabgp.structure.mpls import LabelStackEntry
from exabgp.structure.address import AFI, SAFI 
from exabgp.structure.ip import Inet
from exabgp.message.update.route import Route
from exabgp.message.update.attribute.nexthop import NextHop
from exabgp.message.update.attribute.communities import Encapsulation
from exabgp.message.update.attribute.pmsi_tunnel import PMSITunnel, PMSITunnelIngressReplication
from exabgp.message.update.attribute.id import AttributeID

log = logging.getLogger(__name__)


############ Dummy, do-nothing dataplane driver

class DummyDataplaneDriver(_DummyDataplaneDriver):
    
    encapsulation = Encapsulation.DEFAULT

    def __init__(self, *args):
        _DummyDataplaneDriver.__init__(self, *args)

########## EVI

class EVI(VPNInstance, LookingGlass):
    '''
    Component to manage an E-VPN instance (EVI).
    Based on specifications draft-ietf-l2vpn-evpn and draft-sd-l2vpn-evpn-overlay.
    '''
    
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)
    
    ENABLE_BROADCAST_SUPPORT = True
    # This is a hack to support the case where our BGP RR does not support E-VPN Inclusive multicast route and/or the PMSI Tunnel attribute
    # (it only makes sense to add this if ENABLE_BROADCAST_SUPPORT is False)
    ENABLE_BROADCAST_SUPPORT_HACKY = False

    def __init__(self, *args):
        
        log.debug("Init EVI")
        
        VPNInstance.__init__(self, *args)
        
        self.initialize()  # TODO: automatically done on first plug call, not needed here (?)
        
    def genAdditionalExtendedCommunities(self):
        ecoms = []
        if self.dataplaneDriver.encapsulation:
            ecoms.append(Encapsulation(self.dataplaneDriver.encapsulation))
        return ecoms
        
    @utils.synchronized
    def initialize(self):
        
        if EVI.ENABLE_BROADCAST_SUPPORT:
            # Advertise route to receive multi-destination traffic
            log.info("Generating BGP route for broadcast/multicast traffic")
            
            etag = None
            label = LabelStackEntry(self.instanceLabel)
        
            if (self.dataplaneDriver.encapsulation == Encapsulation.VXLAN):
                etag = EthernetTag(self.instanceLabel)
                label = None
            
            route = Route(
                              EVPNMulticast(
                                            RouteDistinguisher(RouteDistinguisher.TYPE_IP_LOC,
                                                               None,
                                                               self.bgpManager.getLocalAddress(),
                                                               self.instanceId),
                                            etag,
                                            self.bgpManager.getLocalAddress()
                                            )
                              )
            
            route.attributes.add(self._genExtendedCommunities())

            
            # add PMSI Tunnel Attribute route
            pmsi_tunnel_attribute = PMSITunnelIngressReplication(self.bgpManager.getLocalAddress(), label)
            route.attributes.add(pmsi_tunnel_attribute)
            
            nh = Inet(1, socket.inet_pton(socket.AF_INET, self.bgpManager.getLocalAddress()))
            route.attributes.add(NextHop(nh))
            
            self.multicastRouteEntry = self._newRouteEntry(self.afi,
                                                          self.safi,
                                                          self.exportRTs,
                                                          route.nlri,
                                                          route.attributes)
            
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, self.multicastRouteEntry))
        
        VPNInstance.initialize(self)
        
    def cleanup(self):
        # Withdraw route for multi-destination traffic
        if EVI.ENABLE_BROADCAST_SUPPORT:
            self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, self.multicastRouteEntry))

        VPNInstance.cleanup(self)

    def generateVifBGPRoute(self, macAddress, ipAddress, label):
        # Generate BGP route and advertise it...
        
        lse = LabelStackEntry(label, True)
        etag = None
        
        if (self.dataplaneDriver.encapsulation == Encapsulation.VXLAN):
            lse = None
            etag = EthernetTag(self.instanceLabel)
        
        route = Route(
                      EVPNMACAdvertisement(
                                           RouteDistinguisher(RouteDistinguisher.TYPE_IP_LOC,
                                                              None,
                                                              self.bgpManager.getLocalAddress(),
                                                              self.instanceId),
                                           EthernetSegmentIdentifier(),
                                           etag,
                                           MAC(macAddress),
                                           lse,
                                           ipAddress
                                           )
                      )
        
        nh = Inet(1, socket.inet_pton(socket.AF_INET, self.bgpManager.getLocalAddress()))
        route.attributes.add(NextHop(nh))
        
        return self._newRouteEntry(self.afi, self.safi, self.exportRTs, route.nlri, route.attributes)

    def _checkEncap(self, route):
        encaps = filter(lambda ecom:isinstance(ecom, Encapsulation),
                        route.attributes[AttributeID.EXTENDED_COMMUNITY].communities
                        )
        
        encap = encaps[0].tunnel_type
        if (self.dataplaneDriver.encapsulation and
            self.dataplaneDriver.encapsulation not in encap):
            raise Exception("received route not advertising the encap required by our dataplane")
    
    ##################### TrackerWorker callbacks for BGP route updates #############################################
    
    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, EVPNMACAdvertisement):
            return (EVPNMACAdvertisement, route.nlri.mac)
        elif isinstance(route.nlri, EVPNMulticast):
            return (EVPNMulticast, (route.nlri.ip, route.nlri.rd))
        elif isinstance(route.nlri, EVPNNLRI):
            log.warning("Received EVPN route of unsupported subtype: %s" % route.nlri.subtype)
        else:
            raise Exception("EVI %d should not receive routes of type %s" % (self.instanceId, type(route.nlri)))
        
    def _compareRoutes(self, routeA, routeB):
        # TODO: compare routes based on MACMobility attribute
        return 0  # all routes considered equal   
    
    @utils.synchronized
    def _newBestRoute(self, entry, newRoute):
        log.info("newBestRoute for %s: %s" % (str(entry), newRoute))
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.trackedEntry2bestRoutes[entry])))
       
        (entryClass, info) = entry

        if entryClass == EVPNMACAdvertisement:
            prefix = info
            
            # self._checkEncap(newRoute)
            
            nh = newRoute.attributes.get(NextHop.ID)
            remotePE = nh.next_hop
            label = newRoute.nlri.label.labelValue
            
            dataplaneInfo = self.dataplane.setupDataplaneForRemoteEndpoint(prefix, remotePE, label, newRoute.nlri)
            self.route2dataplaneInfo[newRoute] = dataplaneInfo
            
            # This is a hack to support the case where our BGP RR does not support E-VPN Inclusive multicast route and/or the PMSI Tunnel attribute
            if EVI.ENABLE_BROADCAST_SUPPORT_HACKY:
                self.dataplane.setupDataplaneForBroadcastEndpoint(remotePE, label, newRoute.nlri)
        
        elif entryClass == EVPNMulticast:
            remote_endpoint = info
            
            # self._checkEncap(newRoute)
            
            # check that the route is actually carrying an PMSITunnel of type ingress replication
            pmsi_tunnel = newRoute.attributes.get(PMSITunnel.ID)
            if not isinstance(pmsi_tunnel, PMSITunnelIngressReplication):
                log.warning("Received PMSI Tunnel of unsupported type: %s" % type(pmsi_tunnel))
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label.labelValue
                
                log.info("Setting up dataplane for new ingress replication destination (%s)" % remote_endpoint)
                dataplaneInfo = self.dataplane.addDataplaneForBroadcastEndpoint(remote_endpoint, label, newRoute.nlri)
                self.route2dataplaneInfo[newRoute] = dataplaneInfo
        else:
            log.error("newBestRoute not supposed to be called with such an entry")
        

    @utils.synchronized
    def _bestRouteRemoved(self, entry, oldRoute):
        log.info("bestRouteRemoved for %s: %s" % (str(entry), oldRoute))
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.trackedEntry2bestRoutes[entry])))
       
        (entryClass, info) = entry

        dataplaneInfo = self.route2dataplaneInfo[ oldRoute ]

        if entryClass == EVPNMACAdvertisement:
            prefix = info
            
            nh = oldRoute.attributes.get(NextHop.ID)
            remotePE = nh.next_hop
            label = oldRoute.nlri.label.labelValue
            
            
            self.dataplane.removeDataplaneForRemoteEndpoint(prefix, remotePE, label, dataplaneInfo, oldRoute.nlri)
            
            # This is a hack to support the case where our BGP RR does not support E-VPN Inclusive multicast route and/or the PMSI Tunnel attribute
            if EVI.ENABLE_BROADCAST_SUPPORT_HACKY:
                self.dataplane.removeDataplaneForBroadcastEndpoint(remotePE, label, oldRoute.nlri)
            
        elif entryClass == EVPNMulticast:
            remote_endpoint = info
            
            # check that the route is actually carrying an PMSITunnel of type ingress replication
            pmsi_tunnel = oldRoute.attributes.get(PMSITunnel.ID)
            if not isinstance(pmsi_tunnel, PMSITunnelIngressReplication):
                log.warning("PMSI Tunnel of suppressed route is of unsupported type")
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label.labelValue
                log.info("Setting up dataplane for new ingress replication destination (%s)" % remote_endpoint)
                self.dataplane.removeDataplaneForBroadcastEndpoint(remote_endpoint, label, oldRoute.nlri)
        else:
            log.error("newBestRoute not supposed to be called with such an entry")



