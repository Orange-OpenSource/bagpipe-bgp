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

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import log_decorator

from bagpipe.bgp.engine import RouteEntry

from bagpipe.bgp.vpn.vpn_instance import VPNInstance
from bagpipe.bgp.vpn.dataplane_drivers import \
    DummyDataplaneDriver as _DummyDataplaneDriver
from bagpipe.bgp.vpn.dataplane_drivers import \
    VPNInstanceDataplane as _VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import \
    DummyVPNInstanceDataplane as _DummyVPNInstanceDataplane

from bagpipe.bgp.common import looking_glass as lg


from exabgp.protocol.ip import IP

from exabgp.bgp.message.update import Attributes
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
    def add_dataplane_for_bum_endpoint(self, remote_pe, label, nlri, encaps):
        pass

    @abstractmethod
    def remove_dataplane_for_bum_endpoint(self, remote_pe, label, nlri):
        pass

    @abstractmethod
    def set_gateway_port(self, linuxif):
        '''
        Used to determine a port to which traffic at the destination of the
        IP gateway should be sent.  This is used to plug an EVI into an IP VPN
        VRF.
        '''
        pass

    @abstractmethod
    def gateway_port_down(self, linuxif):
        '''
        Used to revert the action done when set_gateway_port was called.
        Relevant only when an EVI had been plugged into an IP VPN VRF.
        '''
        pass


class DummyVPNInstanceDataplane(_DummyVPNInstanceDataplane,
                                _VPNInstanceDataplane):
    '''
    Dummy, do-nothing dataplane driver
    '''

    @log_decorator.log_info
    def add_dataplane_for_bum_endpoint(self, remote_pe, label, nlri, encaps):
        pass

    @log_decorator.log_info
    def remove_dataplane_for_bum_endpoint(self, remote_pe, label, nlri):
        pass

    @log_decorator.log_info
    def set_gateway_port(self, linuxif):
        pass

    @log_decorator.log_info
    def gateway_port_down(self, linuxif):
        pass


class DummyDataplaneDriver(_DummyDataplaneDriver):

    type = EVPN

    dataplane_instance_class = DummyVPNInstanceDataplane
    encaps = [Encapsulation(Encapsulation.Type.VXLAN)]

    def __init__(self, *args):
        _DummyDataplaneDriver.__init__(self, *args)


class EVI(VPNInstance, lg.LookingGlassMixin):

    '''
    Implementation an E-VPN instance (EVI) based on RFC7432 and
    draft-ietf-bess-evpn-overlay.
    '''

    type = EVPN
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)

    @log_decorator.log
    def __init__(self, *args, **kwargs):

        VPNInstance.__init__(self, *args, **kwargs)

        self.gw_port = None

        # Advertise route to receive multi-destination traffic
        self.log.info("Generating BGP route for broadcast/multicast traffic")

        rd = RouteDistinguisher.fromElements(self.bgp_manager.get_local_address(),
                                             self.instance_id)

        nlri = EVPNMulticast(rd,
                             EthernetTag(),
                             IP.create(self.bgp_manager.get_local_address()),
                             None,
                             IP.create(self.bgp_manager.get_local_address()))

        attributes = Attributes()

        attributes.add(self._gen_encap_extended_communities())

        # add PMSI Tunnel Attribute route
        attributes.add(PMSIIngressReplication(
            self.dataplane_driver.get_local_address(), self.instance_label))

        self.multicast_route_entry = RouteEntry(nlri, self.export_rts,
                                                attributes)

        self._advertise_route(self.multicast_route_entry)

    def generate_vif_bgp_route(self, mac_address, ip_prefix, plen, label, rd):
        # Generate BGP route and advertise it...

        assert(plen == 32)

        # label parameter ignored, we need to use instance label
        nlri = EVPNMAC(rd, ESI(), EthernetTag(), MAC(mac_address), 6*8,
                       Labels([self.instance_label]),
                       IP.create(ip_prefix), None,
                       IP.create(self.dataplane_driver.get_local_address()))

        return RouteEntry(nlri)

    @log_decorator.log
    def set_gateway_port(self, linuxif, ipvpn):
        self.dataplane.set_gateway_port(linuxif)
        self.gw_port = (linuxif, ipvpn)

    @log_decorator.log
    def gateway_port_down(self, linuxif):
        self.dataplane.gateway_port_down(linuxif)
        self.gw_port = None

    def has_gateway_port(self):
        return (self.gw_port is not None)

    # TrackerWorker callbacks for BGP route updates ##########################

    def _route_2_tracked_entry(self, route):
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
                            (self.instance_id, type(route.nlri)))

    @utils.synchronized
    @log_decorator.log
    def _new_best_route(self, entry, new_route):
        (entry_class, info) = entry

        encaps = self._check_encaps(new_route)
        if not encaps:
            return

        if entry_class == EVPNMAC:
            prefix = info

            remote_pe = new_route.nexthop

            label = new_route.nlri.label.labels[0]

            self.dataplane.setup_dataplane_for_remote_endpoint(
                prefix, remote_pe, label, new_route.nlri, encaps)

        elif entry_class == EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = new_route.attributes.get(PMSI.ID)
            if not isinstance(pmsi_tunnel, PMSIIngressReplication):
                self.log.warning("Received PMSITunnel of unsupported type: %s",
                                 type(pmsi_tunnel))
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label

                self.log.info("Setting up dataplane for new ingress "
                              "replication destination %s", remote_endpoint)
                self.dataplane.add_dataplane_for_bum_endpoint(
                    remote_endpoint, label, new_route.nlri, encaps)
        else:
            self.log.warning("unsupported entry_class: %s", entry_class.__name__)

    @utils.synchronized
    @log_decorator.log
    def _best_route_removed(self, entry, old_route, last):
        (entry_class, info) = entry

        if entry_class == EVPNMAC:

            if self._skip_route_removal(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            prefix = info

            remote_pe = old_route.nexthop
            label = old_route.nlri.label.labels[0]

            self.dataplane.remove_dataplane_for_remote_endpoint(
                prefix, remote_pe, label, old_route.nlri)

        elif entry_class == EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = old_route.attributes.get(PMSI.ID)
            if not isinstance(pmsi_tunnel, PMSIIngressReplication):
                self.log.warning("PMSITunnel of suppressed route is of"
                                 " unsupported type")
            else:
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label
                self.log.info("Cleaning up dataplane for ingress replication "
                              "destination %s", remote_endpoint)
                self.dataplane.remove_dataplane_for_bum_endpoint(
                    remote_endpoint, label, old_route.nlri)
        else:
            self.log.warning("unsupported entry_class: %s", entry_class.__name__)

    # Looking Glass ####

    def get_log_local_info(self, path_prefix):
        if not self.gw_port:
            return {"gateway_port": None}
        else:
            (linuxif, ipvpn) = self.gw_port
            return {"gateway_port": {
                    "interface": repr(linuxif),
                    "ipvpn": {"href":
                              lg.get_absolute_path(
                                  "VPN_INSTANCES", path_prefix,
                                  [ipvpn.external_instance_id]),
                              "id": ipvpn.name,
                              "external_instance_id":
                                  ipvpn.external_instance_id
                              },
                    }}
