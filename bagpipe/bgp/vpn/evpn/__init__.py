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

import logging
import socket

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import logDecorator

from bagpipe.bgp.engine import RouteEvent, RouteEntry

from bagpipe.bgp.vpn.vpn_instance import VPNInstance
from bagpipe.bgp.vpn.dataplane_drivers import \
    DummyDataplaneDriver as _DummyDataplaneDriver
from bagpipe.bgp.vpn.dataplane_drivers import \
    VPNInstanceDataplane as _VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import \
    DummyVPNInstanceDataplane as _DummyVPNInstanceDataplane

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap, \
    LookingGlassReferences

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities

from exabgp.protocol.ip import IP

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message.update.nlri.qualifier.labels import Labels

from exabgp.bgp.message.update.nlri.evpn.nlri import EVPN as EVPNNLRI
from exabgp.bgp.message.update.nlri.evpn.mac import MAC as EVPNMAC
from exabgp.bgp.message.update.nlri.evpn.multicast import \
    Multicast as EVPNMulticast
from exabgp.bgp.message.update.nlri.qualifier.esi import ESI
from exabgp.bgp.message.update.nlri.qualifier.etag import EthernetTag
from exabgp.bgp.message.update.nlri.qualifier.mac import MAC

from exabgp.reactor.protocol import AFI, SAFI

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation
from exabgp.bgp.message.update.attribute.pmsi import PMSI
from exabgp.bgp.message.update.attribute.pmsi import PMSIIngressReplication

EVPN = "evpn"


class VPNInstanceDataplane(_VPNInstanceDataplane):
    __metaclass__ = ABCMeta

    @abstractmethod
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        pass

    @abstractmethod
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        pass

    @abstractmethod
    def setGatewayPort(self, linuxif):
        '''
        Used to determine a port to which traffic at the destination of the
        IP gateway should be sent.  This is used to plug an EVI into an IP VPN
        VRF.
        '''
        pass

    @abstractmethod
    def gatewayPortDown(self, linuxif):
        '''
        Used to revert the action done when setGatewayPort was called.
        Relevant only when an EVI had been plugged into an IP VPN VRF.
        '''
        pass


class DummyVPNInstanceDataplane(_DummyVPNInstanceDataplane,
                                _VPNInstanceDataplane):
    '''
    Dummy, do-nothing dataplane driver
    '''

    @logDecorator.logInfo
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        pass

    @logDecorator.logInfo
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        pass

    @logDecorator.logInfo
    def setGatewayPort(self, linuxif):
        pass

    @logDecorator.logInfo
    def gatewayPortDown(self, linuxif):
        pass


class DummyDataplaneDriver(_DummyDataplaneDriver):

    type = EVPN

    dataplaneInstanceClass = DummyVPNInstanceDataplane
    encaps = [Encapsulation(Encapsulation.Type.VXLAN)]

    def __init__(self, *args):
        _DummyDataplaneDriver.__init__(self, *args)


# EVI

class EVI(VPNInstance, LookingGlass):

    '''
    Implementation an E-VPN instance (EVI) based on RFC7432 and
    draft-ietf-bess-evpn-overlay.
    '''

    type = EVPN
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)

    @logDecorator.log
    def __init__(self, *args, **kwargs):

        VPNInstance.__init__(self, *args, **kwargs)

        self.gwPort = None

        # Advertise route to receive multi-destination traffic
        self.log.info("Generating BGP route for broadcast/multicast traffic")

        rd = RouteDistinguisher.fromElements(self.bgpManager.getLocalAddress(),
                                             self.instanceId)

        nlri = EVPNMulticast(rd,
                             EthernetTag(),
                             IP.create(self.bgpManager.getLocalAddress()),
                             None,
                             IP.pton(self.bgpManager.getLocalAddress()))

        attributes = Attributes()

        attributes.add(self._genExtendedCommunities())

        # add PMSI Tunnel Attribute route
        attributes.add(PMSIIngressReplication(
            self.dataplaneDriver.getLocalAddress(), self.instanceLabel))

        self.multicastRouteEntry = RouteEntry(self.afi, self.safi,
                                              nlri, self.exportRTs, attributes)

        self._advertiseRoute(self.multicastRouteEntry)

    def generateVifBGPRoute(self, macAddress, ipPrefix, prefixLen, label):
        # Generate BGP route and advertise it...

        assert(prefixLen == 32)

        rd = RouteDistinguisher.fromElements(self.bgpManager.getLocalAddress(),
                                             self.instanceId)

        # label parameter ignored, we need to use instance label
        nlri = EVPNMAC(rd, ESI(), EthernetTag(), MAC(macAddress), 6*8,
                       Labels([self.instanceLabel]),
                       IP.create(ipPrefix), None,
                       IP.pton(self.dataplaneDriver.getLocalAddress()))

        return RouteEntry(self.afi, self.safi, nlri)

    @logDecorator.log
    def setGatewayPort(self, linuxif, ipvpn):
        self.dataplane.setGatewayPort(linuxif)
        self.gwPort = (linuxif, ipvpn)

    @logDecorator.log
    def gatewayPortDown(self, linuxif):
        self.dataplane.gatewayPortDown(linuxif)
        self.gwPort = None

    def hasGatewayPort(self):
        return (self.gwPort is not None)

    # TrackerWorker callbacks for BGP route updates ##########################

    def _route2trackedEntry(self, route):
        if isinstance(route.nlri, EVPNMAC):
            return (EVPNMAC, route.nlri.mac)
        elif isinstance(route.nlri, EVPNMulticast):
            return (EVPNMulticast, (route.nlri.ip, route.nlri.rd))
        elif isinstance(route.nlri, EVPNNLRI):
            self.log.warning("Received EVPN route of unsupported subtype: %s",
                             route.nlri.CODE)
            return None
        else:
            raise Exception("EVI %d should not receive routes of type %s" %
                            (self.instanceId, type(route.nlri)))

    @utils.synchronized
    @logDecorator.log
    def _newBestRoute(self, entry, newRoute):
        (entryClass, info) = entry

        encaps = self._checkEncaps(newRoute)
        if not encaps:
            return

        if entryClass == EVPNMAC:
            prefix = info

            remotePE = newRoute.nexthop

            label = newRoute.nlri.label.labels[0]

            self.dataplane.setupDataplaneForRemoteEndpoint(
                prefix, remotePE, label, newRoute.nlri, encaps)

        elif entryClass == EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = newRoute.attributes.get(PMSI.ID)
            if not isinstance(pmsi_tunnel, PMSIIngressReplication):
                self.log.warning("Received PMSITunnel of unsupported type: %s",
                                 type(pmsi_tunnel))
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label

                self.log.info("Setting up dataplane for new ingress "
                              "replication destination %s", remote_endpoint)
                self.dataplane.addDataplaneForBroadcastEndpoint(
                    remote_endpoint, label, newRoute.nlri, encaps)
        else:
            self.log.warning("unsupported entryClass: %s", entryClass.__name__)

    @utils.synchronized
    @logDecorator.log
    def _bestRouteRemoved(self, entry, oldRoute, last):
        (entryClass, info) = entry

        if entryClass == EVPNMAC:

            if self._skipRouteRemoval(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            prefix = info

            remotePE = oldRoute.nexthop
            label = oldRoute.nlri.label.labels[0]

            self.dataplane.removeDataplaneForRemoteEndpoint(
                prefix, remotePE, label, oldRoute.nlri)

        elif entryClass == EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = oldRoute.attributes.get(PMSI.ID)
            if not isinstance(pmsi_tunnel, PMSIIngressReplication):
                self.log.warning("PMSITunnel of suppressed route is of"
                                 " unsupported type")
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label
                self.log.info("Cleaning up dataplane for ingress replication "
                              "destination %s", remote_endpoint)
                self.dataplane.removeDataplaneForBroadcastEndpoint(
                    remote_endpoint, label, oldRoute.nlri)
        else:
            self.log.warning("unsupported entryClass: %s", entryClass.__name__)

    # Looking Glass ####

    def getLookingGlassLocalInfo(self, pathPrefix):
        if not self.gwPort:
            return {"gwPort": None}
        else:
            (linuxif, ipvpn) = self.gwPort
            return {"gwPort": {
                    "interface": repr(linuxif),
                    "ipvpn": LookingGlassReferences.getAbsolutePath(
                        "VPN_INSTANCES", pathPrefix,
                        [ipvpn.externalInstanceId]),
                    }}
