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

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import log_decorator

from bagpipe.bgp.vpn.vpn_instance import VPNInstance, TrafficClassifier

from bagpipe.bgp.engine import RouteEntry

from bagpipe.bgp.engine.flowspec import Flow
from bagpipe.bgp.engine.ipvpn import IPVPN as IPVPNNlri
from bagpipe.bgp.engine.ipvpn import IPVPNRouteFactory

from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver \
    as _DummyDataplaneDriver

from bagpipe.bgp.common import looking_glass as lg

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.community.extended \
    import ConsistentHashSortOrder
from exabgp.bgp.message.update.attribute.community.extended \
    import RouteTarget as RTExtCom
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord

from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI


IPVPN = "ipvpn"


class DummyDataplaneDriver(_DummyDataplaneDriver):

    type = IPVPN


class VRF(VPNInstance, lg.LookingGlassMixin):
    # component managing a VRF:
    # - calling a driver to instantiate the dataplane
    # - registering to receive routes for the needed route targets
    # - calling the driver to setup/update/remove routes in the dataplane
    # - cleanup: calling the driver, unregistering for BGP routes

    type = IPVPN
    afi = AFI(AFI.ipv4)
    safi = SAFI(SAFI.mpls_vpn)

    @log_decorator.log
    def __init__(self, *args, **kwargs):
        VPNInstance.__init__(self, *args, **kwargs)
        self.readvertised = set()

    def _nlri_from(self, prefix, label, rd):
        assert rd is not None

        return IPVPNRouteFactory(self.afi, prefix, label, rd,
                                 self.dataplane_driver.get_local_address())

    def generate_vif_bgp_route(self, mac_address, ip_prefix, plen, label, rd):
        # Generate BGP route and advertise it...
        nlri = self._nlri_from("%s/%s" % (ip_prefix, plen), label, rd)

        return RouteEntry(nlri)

    def _get_local_labels(self):
        for port_data in self.mac_2_localport_data.itervalues():
            yield port_data['label']

    def _imported(self, route):
        return len(set(route.route_targets).intersection(set(self.import_rts))
                   ) > 0

    def _to_readvertise(self, route):
        # Only re-advertise IP VPN routes (e.g. not Flowspec routes)
        if not isinstance(route.nlri, IPVPNNlri):
            return False

        rt_records = route.extended_communities(RTRecord)
        self.log.debug("RTRecords: %s (readvertise_to_rts:%s)",
                       rt_records,
                       self.readvertise_to_rts)

        readvertise_targets_as_records = [RTRecord.from_rt(rt)
                                          for rt in self.readvertise_to_rts]

        if self.attract_traffic:
            readvertise_targets_as_records += [RTRecord.from_rt(rt)
                                               for rt in self.attract_rts]

        if set(readvertise_targets_as_records).intersection(set(rt_records)):
            self.log.debug("not to re-advertise because one of the readvertise"
                           " or attract-redirect RTs is in RTRecords: %s",
                           set(readvertise_targets_as_records)
                           .intersection(set(rt_records)))
            return False

        return len(
            set(route.route_targets).intersection(set(self.readvertise_from_rts))
            ) > 0

    def _route_for_readvertisement(self, route, label, rd,
                                   lb_consistent_hash_order,
                                   do_default=False):
        prefix = "0.0.0.0/0" if do_default else route.nlri.cidr.prefix()

        nlri = self._nlri_from(prefix, label, rd)

        attributes = Attributes()

        # new RTRecord = original RTRecord (if any) + orig RTs
        orig_rtrecords = route.extended_communities(RTRecord)
        rts = route.extended_communities(RTExtCom)
        add_rtrecords = [RTRecord.from_rt(rt) for rt in rts]

        final_rtrecords = list(set(orig_rtrecords) | set(add_rtrecords))

        ecoms = self._gen_encap_extended_communities()
        ecoms.communities += final_rtrecords
        ecoms.communities.append(
            ConsistentHashSortOrder(lb_consistent_hash_order))
        attributes.add(ecoms)

        entry = RouteEntry(nlri, self.readvertise_to_rts, attributes)
        self.log.debug("RouteEntry for (re-)advertisement: %s", entry)
        return entry

    @log_decorator.log
    def _route_for_redirect_prefix(self, prefix):
        prefix_classifier = utils.dict_camelcase_to_underscore(
            self.attract_classifier)
        prefix_classifier['destination_prefix'] = prefix

        traffic_classifier = TrafficClassifier(**prefix_classifier)
        self.log.debug("Advertising prefix %s for redirection based on "
                       "traffic classifier %s", prefix, traffic_classifier)
        rules = traffic_classifier.map_traffic_classifier_2_redirect_rules()

        return self.synthesize_redirect_bgp_route(rules)

    def _advertise_route_or_default(self, route, label, rd,
                                    lb_consistent_hash_order=0):
        if self.attract_traffic:
            self.log.debug("Advertising default route from VRF %d to "
                           "redirection VRF", self.instance_id)

        route_entry = self._route_for_readvertisement(
            route, label, rd, lb_consistent_hash_order,
            do_default=self.attract_traffic
        )
        self._advertise_route(route_entry)

    def _withdraw_route_or_default(self, route, label, rd,
                                   lb_consistent_hash_order=0):
        if self.attract_traffic:
            self.log.debug("Stop advertising default route from VRF to "
                           "redirection VRF")

        route_entry = self._route_for_readvertisement(
            route, label, rd, lb_consistent_hash_order,
            do_default=self.attract_traffic
        )
        self._withdraw_route(route_entry)

    @log_decorator.log
    def _readvertise(self, route):
        nlri = route.nlri

        self.log.debug("Start re-advertising %s from VRF", nlri.cidr.prefix())
        for _, endpoints in self.localport_2_endpoints.iteritems():
            for endpoint in endpoints:
                port_data = self.mac_2_localport_data[endpoint['mac']]
                label = port_data['label']
                lb_consistent_hash_order = port_data['lb_consistent_hash_order']
                rd = self.endpoint_2_rd[(endpoint['mac'], endpoint['ip'])]
                self.log.debug("Start re-advertising %s from VRF, with label "
                               "%s and route distinguisher %s",
                               nlri, label, rd)
                # need a distinct RD for each route...
                self._advertise_route_or_default(route, label, rd,
                                              lb_consistent_hash_order)

        if self.attract_traffic:
            flow_route = self._route_for_redirect_prefix(nlri.cidr.prefix())
            self._advertise_route(flow_route)

        self.readvertised.add(route)

    @log_decorator.log
    def _readvertise_stop(self, route):
        nlri = route.nlri

        self.log.debug("Stop re-advertising %s from VRF", nlri.cidr.prefix())
        for _, endpoints in self.localport_2_endpoints.iteritems():
            for endpoint in endpoints:
                port_data = self.mac_2_localport_data[endpoint['mac']]
                label = port_data['label']
                lb_consistent_hash_order = port_data['lb_consistent_hash_order']
                rd = self.endpoint_2_rd[(endpoint['mac'], endpoint['ip'])]
                self.log.debug("Stop re-advertising %s from VRF, with label "
                               "%s and route distinguisher %s",
                               nlri, label, rd)
                self._withdraw_route_or_default(route, label, rd,
                                             lb_consistent_hash_order)

        if self.attract_traffic:
            flow_route = self._route_for_redirect_prefix(nlri.cidr.prefix())
            self._withdraw_route(flow_route)

        self.readvertised.remove(route)

    def vif_plugged(self, mac_address, ip_address_prefix, localport,
                   advertise_subnet=False,
                   lb_consistent_hash_order=0):
        VPNInstance.vif_plugged(self, mac_address, ip_address_prefix, localport,
                               advertise_subnet, lb_consistent_hash_order)

        label = self.mac_2_localport_data[mac_address]['label']
        rd = self.endpoint_2_rd[(mac_address, ip_address_prefix)]
        for route in self.readvertised:
            self.log.debug("Re-advertising %s with this port as next hop",
                           route.nlri)
            self._advertise_route_or_default(route, label, rd,
                                          lb_consistent_hash_order)

            if self.attract_traffic:
                flow_route = self._route_for_redirect_prefix(
                    route.nlri.cidr.prefix())
                self._advertise_route(flow_route)

    def vif_unplugged(self, mac_address, ip_address_prefix,
                     advertise_subnet=False,
                     lb_consistent_hash_order=0):
        label = self.mac_2_localport_data[mac_address]['label']
        lb_consistent_hash_order = (self.mac_2_localport_data[mac_address]
                                 ["lb_consistent_hash_order"])
        rd = self.endpoint_2_rd[(mac_address, ip_address_prefix)]
        for route in self.readvertised:
            self.log.debug("Stop re-advertising %s with this port as next hop",
                           route.nlri)
            self._withdraw_route_or_default(route, label, rd,
                                         lb_consistent_hash_order)

            if self.attract_traffic and self.has_only_one_endpoint():
                flow_route = self._route_for_redirect_prefix(
                    route.nlri.cidr.prefix())
                self._withdraw_route(flow_route)

        VPNInstance.vif_unplugged(self, mac_address, ip_address_prefix,
                                  advertise_subnet, lb_consistent_hash_order)

    # Callbacks for BGP route updates (TrackerWorker) ########################

    def _route_2_tracked_entry(self, route):
        if isinstance(route.nlri, IPVPNNlri):
            return route.nlri.cidr.prefix()
        elif isinstance(route.nlri, Flow):
            return (Flow, route.nlri._rules())
        else:
            self.log.error("We should not receive routes of type %s",
                           type(route.nlri))
            return None

    @utils.synchronized
    @log_decorator.log
    def _new_best_route(self, entry, new_route):

        if isinstance(new_route.nlri, Flow):
            if len(new_route.extended_communities(TrafficRedirect)) == 1:
                traffic_redirect = new_route.extended_communities(TrafficRedirect)
                redirect_rt = "%s:%s" % (traffic_redirect[0].asn,
                                        traffic_redirect[0].target)

                self.start_redirect_traffic(redirect_rt, new_route.nlri.rules)
            else:
                self.log.warning("FlowSpec action or multiple traffic redirect"
                                 " actions not supported: %s",
                                 new_route.extended_communities())
        else:
            prefix = entry

            if self.readvertise:
                # check if this is a route we need to re-advertise
                self.log.debug("route RTs: %s", new_route.route_targets)
                self.log.debug("readv from RTs: %s", self.readvertise_from_rts)
                if self._to_readvertise(new_route):
                    self.log.debug("Need to re-advertise %s", prefix)
                    self._readvertise(new_route)

            if not self._imported(new_route):
                self.log.debug("No need to setup dataplane for:%s",
                               prefix)
                return

            encaps = self._check_encaps(new_route)
            if not encaps:
                return

            assert len(new_route.nlri.labels.labels) == 1

            lb_consistent_hash_order = 0
            if new_route.extended_communities(ConsistentHashSortOrder):
                lb_consistent_hash_order = new_route.extended_communities(
                    ConsistentHashSortOrder)[0].order

            self.dataplane.setup_dataplane_for_remote_endpoint(
                prefix, new_route.nexthop,
                new_route.nlri.labels.labels[0], new_route.nlri, encaps,
                lb_consistent_hash_order)

    @utils.synchronized
    @log_decorator.log
    def _best_route_removed(self, entry, old_route, last):

        if isinstance(old_route.nlri, Flow):
            if len(old_route.extended_communities(TrafficRedirect)) == 1:
                if last:
                    traffic_redirect = old_route.extended_communities(
                        TrafficRedirect)
                    redirect_rt = "%s:%s" % (traffic_redirect[0].asn,
                                             traffic_redirect[0].target)

                    self.stop_redirect_traffic(redirect_rt,
                                               old_route.nlri.rules)
            else:
                self.log.warning("FlowSpec action or multiple traffic redirect"
                                 " actions not supported: %s",
                                 old_route.extended_communities())
        else:
            prefix = entry

            if self.readvertise and last:
                # check if this is a route we were re-advertising
                if self._to_readvertise(old_route):
                    self.log.debug("Need to stop re-advertising %s", prefix)
                    self._readvertise_stop(old_route)

            if not self._imported(old_route):
                self.log.debug("No need to update dataplane for:%s",
                               prefix)
                return

            if self._skip_route_removal(last):
                self.log.debug("Skipping removal of non-last route because "
                               "dataplane does not want it")
                return

            encaps = self._check_encaps(old_route)
            if not encaps:
                return

            assert len(old_route.nlri.labels.labels) == 1

            lb_consistent_hash_order = 0
            if old_route.extended_communities(ConsistentHashSortOrder):
                lb_consistent_hash_order = old_route.extended_communities(
                    ConsistentHashSortOrder)[0].order

            self.dataplane.remove_dataplane_for_remote_endpoint(
                prefix, old_route.nexthop,
                old_route.nlri.labels.labels[0], old_route.nlri, encaps,
                lb_consistent_hash_order)

    # Looking glass ###

    def get_lg_map(self):
        return {
            "readvertised": (lg.SUBTREE, self.get_lg_readvertised_routes),
        }

    def get_lg_readvertised_routes(self, path_prefix):
        return [route.get_log_local_info(path_prefix)
                for route in self.readvertised]
