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

import abc

from bagpipe.bgp import constants
from bagpipe.bgp import engine
from bagpipe.bgp.engine import exa
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import utils
from bagpipe.bgp.vpn import vpn_instance
from bagpipe.bgp.vpn import dataplane_drivers as dp_drivers
from bagpipe.bgp.common import looking_glass as lg


class VPNInstanceDataplane(dp_drivers.VPNInstanceDataplane):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def add_dataplane_for_bum_endpoint(self, remote_pe, label, nlri, encaps):
        pass

    @abc.abstractmethod
    def remove_dataplane_for_bum_endpoint(self, remote_pe, label, nlri):
        pass

    @abc.abstractmethod
    def set_gateway_port(self, linuxif):
        '''
        Used to determine a port to which traffic at the destination of the
        IP gateway should be sent.  This is used to plug an EVI into an IP VPN
        VRF.
        '''
        pass

    @abc.abstractmethod
    def gateway_port_down(self, linuxif):
        '''
        Used to revert the action done when set_gateway_port was called.
        Relevant only when an EVI had been plugged into an IP VPN VRF.
        '''
        pass


class DummyVPNInstanceDataplane(dp_drivers.DummyVPNInstanceDataplane,
                                dp_drivers.VPNInstanceDataplane):
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


class DummyDataplaneDriver(dp_drivers.DummyDataplaneDriver):

    type = constants.EVPN

    dataplane_instance_class = DummyVPNInstanceDataplane
    encaps = [exa.Encapsulation(exa.Encapsulation.Type.VXLAN)]

    def __init__(self, *args):
        dp_drivers.DummyDataplaneDriver.__init__(self, *args)


class EVI(vpn_instance.VPNInstance, lg.LookingGlassMixin):

    '''
    Implementation an E-VPN instance (EVI) based on RFC7432 and
    draft-ietf-bess-evpn-overlay.
    '''

    type = constants.EVPN
    afi = exa.AFI.l2vpn
    safi = exa.SAFI.evpn

    @log_decorator.log
    def __init__(self, *args, **kwargs):

        vpn_instance.VPNInstance.__init__(self, *args, **kwargs)

        self.gw_port = None

        # Advertise route to receive multi-destination traffic
        self.log.info("Generating BGP route for broadcast/multicast traffic")

        nlri = exa.EVPNMulticast(
            self.instance_rd,
            exa.EthernetTag(),
            exa.IP.create(self.bgp_manager.get_local_address()),
            None,
            exa.IP.create(self.bgp_manager.get_local_address()))

        attributes = exa.Attributes()

        attributes.add(self._gen_encap_extended_communities())

        # add PMSI Tunnel Attribute route
        attributes.add(
            exa.PMSIIngressReplication(self.dp_driver.get_local_address(),
                                       self.instance_label))

        self.multicast_route_entry = engine.RouteEntry(nlri, self.export_rts,
                                                       attributes)

        self._advertise_route(self.multicast_route_entry)

    def generate_vif_bgp_route(self, mac_address, ip_prefix, plen, label, rd):
        # Generate BGP route and advertise it...

        assert(plen == 32)

        # label parameter ignored, we need to use instance label
        nlri = exa.EVPNMAC(
            rd, exa.ESI(), exa.EthernetTag(), exa.MAC(mac_address), 6*8,
            exa.Labels([self.instance_label]),
            exa.IP.create(ip_prefix), None,
            exa.IP.create(self.dp_driver.get_local_address()))

        return engine.RouteEntry(nlri)

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

    def route_to_tracked_entry(self, route):
        if isinstance(route.nlri, exa.EVPNMAC):
            return (exa.EVPNMAC, route.nlri.mac)
        elif isinstance(route.nlri, exa.EVPNMulticast):
            return (exa.EVPNMulticast, (route.nlri.ip, route.nlri.rd))
        elif isinstance(route.nlri, exa.EVPN):
            self.log.warning("Received EVPN route of unsupported subtype: %s",
                             route.nlri.CODE)
            return None
        else:
            raise Exception("EVI %d should not receive routes of type %s" %
                            (self.instance_id, type(route.nlri)))

    @utils.synchronized
    @log_decorator.log
    def new_best_route(self, entry, new_route):
        (entry_class, info) = entry

        encaps = self._check_encaps(new_route)
        if not encaps:
            return

        if entry_class == exa.EVPNMAC:
            prefix = info

            remote_pe = new_route.nexthop

            label = new_route.nlri.label.labels[0]

            self.dataplane.setup_dataplane_for_remote_endpoint(
                prefix, remote_pe, label, new_route.nlri, encaps)

        elif entry_class == exa.EVPNMulticast:
            remote_endpoint = info

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = new_route.attributes.get(exa.PMSI.ID)
            if not isinstance(pmsi_tunnel, exa.PMSIIngressReplication):
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
            self.log.warning("unsupported entry_class: %s",
                             entry_class.__name__)

    @utils.synchronized
    @log_decorator.log
    def best_route_removed(self, entry, old_route, last):
        (entry_class, info) = entry

        if entry_class == exa.EVPNMAC:

            if self._skip_route_removal(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            def ip_label_from_route(route):
                return (route.nexthop, route.nlri.labels.labels[0])

            if self.equivalent_route_in_best_routes(old_route,
                                                    ip_label_from_route):
                self.log.debug("Route for same dataplane is still in best "
                               "routes, skipping removal")
                return

            prefix = info

            remote_pe, label = ip_label_from_route(old_route)

            self.dataplane.remove_dataplane_for_remote_endpoint(
                prefix, remote_pe, label, old_route.nlri)

        elif entry_class == exa.EVPNMulticast:
            remote_endpoint = info

            def ip_label_from_route(route):
                pmsi_tunnel = route.attributes.get(exa.PMSI.ID)
                remote_endpoint = pmsi_tunnel.ip
                label = pmsi_tunnel.label
                return (remote_endpoint, label)

            # check that the route is actually carrying an PMSITunnel of type
            # ingress replication
            pmsi_tunnel = old_route.attributes.get(exa.PMSI.ID)
            if not isinstance(pmsi_tunnel, exa.PMSIIngressReplication):
                self.log.warning("PMSITunnel of suppressed route is of"
                                 " unsupported type")
                return

            if self.equivalent_route_in_best_routes(old_route,
                                                    ip_label_from_route):
                self.log.debug("Route for same dataplane is still in best "
                               "routes, skipping removal")
                return

            remote_endpoint, label = ip_label_from_route(old_route)
            self.log.info("Cleaning up dataplane for ingress replication "
                          "destination %s", remote_endpoint)

            self.dataplane.remove_dataplane_for_bum_endpoint(
                remote_endpoint, label, old_route.nlri)
        else:
            self.log.warning("unsupported entry_class: %s",
                             entry_class.__name__)

    # Looking Glass ####

    def get_lg_local_info(self, path_prefix):
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
