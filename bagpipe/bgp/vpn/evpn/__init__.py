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
from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane as _VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DummyVPNInstanceDataplane as _DummyVPNInstanceDataplane

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap, LookingGlassReferences

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


class VPNInstanceDataplane(_VPNInstanceDataplane):

    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.warning("function not implemented: addDataplaneForBroadcastEndpoint()" )
        
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.warning("function not implemented: removeDataplaneForBroadcastEndpoint()" )

    def setGatewayPort(self,linuxif):
        raise Exception("not implemented")
    
    def gatewayPortDown(self,linuxif):
        raise Exception("not implemented")

    def hasGatewayPort(self):
        raise Exception("not implemented")
    
############ Dummy, do-nothing dataplane driver

class DummyVPNInstanceDataplane(_DummyVPNInstanceDataplane,_VPNInstanceDataplane):

    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        self.log.info("addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % locals())
    
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.info("removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % locals())
    
    def setGatewayPort(self,linuxif):
        self.log.info("Plugging gateway port: %s" % linuxif)

    def gatewayPortDown(self,linuxif):
        self.log.info("Unplugging gateway port: %s" % linuxif)
        
    def hasGatewayPort(self):
        self.log.info("Has gateway port: ???")
        return False

class DummyDataplaneDriver(_DummyDataplaneDriver):
    
    dataplaneClass = DummyVPNInstanceDataplane

    def __init__(self, *args):
        _DummyDataplaneDriver.__init__(self, *args)


########## EVI

class EVI(VPNInstance, LookingGlass):
    '''
    Component to manage an E-VPN instance (EVI).
    Based on specifications draft-ietf-l2vpn-evpn and draft-sd-l2vpn-evpn-overlay.
    '''
    
    type = "evpn"
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)
    
    ENABLE_BROADCAST_SUPPORT = True
    # This is a hack to support the case where our BGP RR does not support E-VPN Inclusive multicast route and/or the PMSI Tunnel attribute
    # (it only makes sense to add this if ENABLE_BROADCAST_SUPPORT is False)
    ENABLE_BROADCAST_SUPPORT_HACKY = False

    def __init__(self, *args, **kwargs):
        
        log.debug("Init EVI")
        
        VPNInstance.__init__(self, *args, **kwargs)
        
        self.gwPort = None
        
        if EVI.ENABLE_BROADCAST_SUPPORT:
            # Advertise route to receive multi-destination traffic
            log.info("Generating BGP route for broadcast/multicast traffic")
            
            etag = None
            label = LabelStackEntry(self.instanceLabel)
        
            if (Encapsulation(Encapsulation.VXLAN) in self.dataplaneDriver.supportedEncaps()):
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
            pmsi_tunnel_attribute = PMSITunnelIngressReplication(self.dataplaneDriver.getLocalAddress(), label)
            route.attributes.add(pmsi_tunnel_attribute)
            
            nh = Inet(1, socket.inet_pton(socket.AF_INET, self.dataplaneDriver.getLocalAddress()))
            route.attributes.add(NextHop(nh))
            
            self.multicastRouteEntry = self._newRouteEntry(self.afi,
                                                          self.safi,
                                                          self.exportRTs,
                                                          route.nlri,
                                                          route.attributes)
            
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, self.multicastRouteEntry))
        
    def cleanup(self):
        # Withdraw route for multi-destination traffic
        if EVI.ENABLE_BROADCAST_SUPPORT:
            self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, self.multicastRouteEntry))

        VPNInstance.cleanup(self)

    def generateVifBGPRoute(self, macAddress, ipAddress, label):
        # Generate BGP route and advertise it...
        
        lse = LabelStackEntry(label, True)
        etag = None
        
        if (Encapsulation(Encapsulation.VXLAN) in self.dataplaneDriver.supportedEncaps()):
            lse = None
            etag = EthernetTag(self.instanceLabel)
        
        route = Route(
                      EVPNMACAdvertisement(
                                           RouteDistinguisher(RouteDistinguisher.TYPE_IP_LOC,
                                                              None,
                                                              self.dataplaneDriver.getLocalAddress(),
                                                              self.instanceId),
                                           EthernetSegmentIdentifier(),
                                           etag,
                                           MAC(macAddress),
                                           lse,
                                           ipAddress
                                           )
                      )
        
        return self._newRouteEntry(self.afi, self.safi, self.exportRTs, route.nlri, route.attributes)

    def setGatewayPort(self,linuxif,ipvpn):
        self.log.info("Calling dataplane driver to plug gateway port %s" % linuxif)
        self.dataplane.setGatewayPort(linuxif)
        self.gwPort = (linuxif,ipvpn)
        
    def gatewayPortDown(self,linuxif):
        self.log.info("Calling dataplane driver to unplug gateway port %s" % linuxif)
        self.dataplane.gatewayPortDown(linuxif)
        self.gwPort = None
    
    def hasGatewayPort(self):
        return (self.gwPort is not None)
    
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
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.getBestRoutesForTrackedEntry(entry))))
       
        (entryClass, info) = entry

        encaps = self._checkEncaps(newRoute)
        if not encaps:
            return

        if entryClass == EVPNMACAdvertisement:
            prefix = info

            nh = newRoute.attributes.get(NextHop.ID)
            remotePE = nh.next_hop
            label = newRoute.nlri.label.labelValue
            
            self.dataplane.setupDataplaneForRemoteEndpoint(prefix, remotePE, label, newRoute.nlri, encaps)
            
            # This is a hack to support the case where our BGP RR does not support E-VPN Inclusive multicast route and/or the PMSI Tunnel attribute
            if EVI.ENABLE_BROADCAST_SUPPORT_HACKY:
                self.dataplane.setupDataplaneForBroadcastEndpoint(remotePE, label, newRoute.nlri)
        
        elif entryClass == EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type ingress replication
            pmsi_tunnel = newRoute.attributes.get(PMSITunnel.ID)
            if not isinstance(pmsi_tunnel, PMSITunnelIngressReplication):
                log.warning("Received PMSI Tunnel of unsupported type: %s" % type(pmsi_tunnel))
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label.labelValue
                
                log.info("Setting up dataplane for new ingress replication destination %s" % remote_endpoint)
                self.dataplane.addDataplaneForBroadcastEndpoint(remote_endpoint, label, newRoute.nlri, encaps)
        else:
            log.error("newBestRoute not supposed to be called with such an entry")
        

    @utils.synchronized
    def _bestRouteRemoved(self, entry, oldRoute):
        log.info("bestRouteRemoved for %s: %s" % (str(entry), oldRoute))
        log.info("all best routes:\n  %s" % "\n  ".join(map(repr, self.getBestRoutesForTrackedEntry(entry))))
       
        (entryClass, info) = entry

        if entryClass == EVPNMACAdvertisement:
            prefix = info
            
            nh = oldRoute.attributes.get(NextHop.ID)
            remotePE = nh.next_hop
            label = oldRoute.nlri.label.labelValue
            
            self.dataplane.removeDataplaneForRemoteEndpoint(prefix, remotePE, label, oldRoute.nlri)
            
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
                log.info("Cleaning up dataplane for ingress replication destination %s" % remote_endpoint)
                self.dataplane.removeDataplaneForBroadcastEndpoint(remote_endpoint, label, oldRoute.nlri)
        else:
            log.error("newBestRoute not supposed to be called with such an entry")

    
    #### Looking Glass ####


    def getLookingGlassLocalInfo(self, pathPrefix):

        if not self.gwPort:
            return { "gwPort": None }
        else:
            (linuxif,ipvpn) = self.gwPort
            return { "gwPort": {
                    "interface": repr(linuxif),
                    "ipvpn": LookingGlassReferences.getAbsolutePath("VPN_INSTANCES", pathPrefix, [ipvpn.externalInstanceId]),
                   }}
