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

"""This module classes related to producing and consuming events related to
BGP routes.

routes: RouteEntry

events: RouteEvent
    an announcement or a withdrawal of a BGP route

workers: Worker
    * produce events
    * subscribe to the route table manager to consume events related to
      certain BGP routes

route table manager (singleton)
    * tracks subscriptions of workers
    * dispatches events based on subscriptions

"""

import types

import logging

from bagpipe.bgp.common import looking_glass as lg

from bagpipe.bgp.common import log_decorator

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.attribute import Attribute
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget

from exabgp.bgp.message import OUT

from exabgp.reactor.protocol import AFI, SAFI

log = logging.getLogger(__name__)


class RouteEntry(lg.LookingGlassMixin):
    """A route entry describes a BGP route, i.e. the association of:
* a BGP NLRI of a specific type (e.g. a VPNv4 route
  like "1.2.3.4:5:192.168.0.5/32")
* BGP attributes
* the source of the BGP route (e.g. the BGP peer, or the local VPN instance,
  that advertizes the route)
"""

    def __init__(self, nlri, rts=None, attributes=None,
                 source=None):
        if attributes is None:
            attributes = Attributes()
        assert isinstance(attributes, Attributes)
        if rts is not None:
            assert isinstance(rts, list)
            assert len(rts) == 0 or isinstance(rts[0], RouteTarget)

        self.source = source
        self.afi = nlri.afi
        self.safi = nlri.safi
        assert isinstance(self.afi, AFI)
        assert isinstance(self.safi, SAFI)
        self.nlri = nlri
        self.attributes = attributes
        # a list of exabgp.bgp.message.update.attribute.community.
        #   extended.RouteTargetASN2Number
        self._route_targets = []
        if Attribute.CODE.EXTENDED_COMMUNITY in self.attributes:
            ecoms = self.attributes[
                Attribute.CODE.EXTENDED_COMMUNITY].communities
            # use type(..) because isinstance(rtrecord, RouteTarget) is True
            self._route_targets = [ecom for ecom in ecoms
                                  if type(ecom) == RouteTarget]
            if rts:
                ecoms += rts
                self._route_targets += rts
        else:
            if rts:
                self.attributes.add(ExtendedCommunities(rts))
                self._route_targets += rts

    @property
    def route_targets(self):
        return self._route_targets

    def extended_communities(self, filter_=None):
        if filter_ is None:
            def filter_real(ecom):
                return True
        elif isinstance(filter_, (types.ClassType, types.TypeType)):
            def filter_real(ecom):
                return isinstance(ecom, filter_)
        else:
            # filter is a function(ecom)
            filter_real = filter_

        if Attribute.CODE.EXTENDED_COMMUNITY in self.attributes:
            return filter(filter_real,
                          self.attributes[Attribute.CODE.EXTENDED_COMMUNITY]
                          .communities)
        else:
            return []

    @log_decorator.log
    def set_route_targets(self, route_targets):
        # first build a list of ecoms without any RT
        ecoms = self.extended_communities(lambda ecom:
                                         not isinstance(ecom, RouteTarget))

        # then add the right RTs
        new_ecoms = ExtendedCommunities()
        new_ecoms.communities += ecoms
        new_ecoms.communities += route_targets

        # update
        self._route_targets = route_targets

        self.attributes.remove(new_ecoms.ID)
        self.attributes.add(new_ecoms)

    @property
    def nexthop(self):
        try:
            return self.nlri.nexthop.top()
        except AttributeError:
            try:
                return self.attributes[Attribute.CODE.NEXT_HOP].top()
            except KeyError:
                return None

    def __cmp__(self, other):
        if other is None:
            return -1
        assert isinstance(other, RouteEntry)
        if (self.afi == other.afi and
                self.safi == other.safi and
                self.source == other.source and
                self.nlri == other.nlri and
                self.attributes.sameValuesAs(other.attributes)):
            res = 0
        else:
            res = -1
        return res

    def __hash__(self):
        return hash((self.afi, self.safi, str(self.source),
                     str(self.nexthop), self.nlri,
                     self.attributes))

    def __repr__(self, skip_nexthop=False):
        from_string = " from:%s" % self.source if self.source else ""

        nexthop = ""
        if not skip_nexthop:
            nexthop = str(self.nexthop)

        return "[RouteEntry: %s/%s %s nh:%s %s%s]" % (
            self.afi, self.safi, self.nlri, nexthop,
            self.attributes, from_string)

    def get_log_local_info(self, path_prefix):

        att_dict = {}

        for attribute in self.attributes.itervalues():

            # skip some attributes that we care less about
            if (attribute.ID == Attribute.CODE.AS_PATH or
                    attribute.ID == Attribute.CODE.ORIGIN or
                    attribute.ID == Attribute.CODE.LOCAL_PREF):
                continue

            att_dict[repr(Attribute.CODE(attribute.ID))] = str(attribute)

        res = {"afi-safi": "%s/%s" % (self.afi, self.safi),
               "attributes": att_dict,
               "next_hop": self.nexthop
               }

        if self.source:
            res["source"] = {"id": self.source.name,
                             "href": lg.get_absolute_path("BGP_WORKERS",
                                                        path_prefix,
                                                        [self.source.name])
                             }

        if self.safi in [SAFI.mpls_vpn, SAFI.evpn]:
            res["route_targets"] = [str(rt) for rt in self.route_targets]

        return {
            repr(self.nlri): res
        }


class RouteEvent(object):

    """A RouteEvent represents an advertisement or a withdrawal of a RouteEntry
    """

    # event Types
    ADVERTISE = 1
    WITHDRAW = 2

    type2name = {ADVERTISE: "Advertise",
                 WITHDRAW: "Withdraw"}

    def __init__(self, event_type, route_entry, source=None):
        assert(event_type == RouteEvent.ADVERTISE or
               event_type == RouteEvent.WITHDRAW)
        assert isinstance(route_entry, RouteEntry)
        self.type = event_type
        self.route_entry = route_entry
        if source is not None:
            self.source = source
            self.route_entry.source = source
        else:
            self.source = route_entry.source
        assert self.source is not None
        self.replaced_route = None

        # this is required to overwrite the action field in an NLRI
        # in the case where we generate a withdraw from an existing NLRI
        # on a replaced route
        # and this spares us the pain of specifying the action
        # when creating an nlri
        if event_type == RouteEvent.ADVERTISE:
            self.route_entry.nlri.action = OUT.ANNOUNCE
        else:  # WITHDRAW
            self.route_entry.nlri.action = OUT.WITHDRAW

    @log_decorator.log
    def set_replaced_route(self, replaced_route):
        ''' Called only by RouteTableManager, replaced_route should be a
        RouteEntry '''
        assert(isinstance(replaced_route, RouteEntry)
               or (replaced_route is None))
        assert replaced_route != self.route_entry
        self.replaced_route = replaced_route

    def __repr__(self):
        if self.replaced_route:
            replaces_str = "replaces one route"
        else:
            replaces_str = "replaces no route"
        return "[RouteEvent(%s): %s %s %s]" % (replaces_str,
                                               RouteEvent.type2name[self.type],
                                               self.route_entry,
                                               self.source)


class _SubUnsubCommon(object):

    def __init__(self, afi, safi, route_target, worker=None):
        assert isinstance(afi, AFI)
        assert isinstance(safi, SAFI)
        assert route_target is None or isinstance(route_target, RouteTarget)
        self.afi = afi
        self.safi = safi
        self.route_target = route_target
        self.worker = worker

    def __repr__(self):
        by_worker = " by %s" % self.worker.name if self.worker else ""
        return "%s [%s/%s,%s]%s" % (self.__class__.__name__,
                                    self.afi or "*", self.safi or "*",
                                    self.route_target or "*", by_worker)


class Subscription(_SubUnsubCommon):

    """Represents a Subscription to RouteEvents

A subscription specifies the AFI, the SAFI, and the Route Target of the
RouteEntry for which the subscriber wants to receive events.

Any of these (afi, safi or route target) can be replaced by a wildcard:

* Subscription.ANY_AFI
* Subscription.ANY_SAFI
* Subscription.ANY_RT
    """

    ANY_AFI = AFI(0)
    ANY_SAFI = SAFI(0)
    ANY_RT = None

    def __init__(self, afi, safi, route_target=None, worker=None):
        _SubUnsubCommon.__init__(self, afi, safi, route_target, worker)


class Unsubscription(_SubUnsubCommon):

    def __init__(self, afi, safi, route_target=None, worker=None):
        _SubUnsubCommon.__init__(self, afi, safi, route_target, worker)


class EventSource(lg.LookingGlassMixin):
    '''
    Class for objects that advertise and withdraw routes
    need to have a 'name' attribute
    '''

    def __init__(self, route_table_manager):
        self.rtm = route_table_manager
        # private data of RouteTableManager
        self._rtm_route_entries = set()

    def get_route_entries(self):
        return self._rtm_route_entries

    @log_decorator.log_info
    def _advertise_route(self, route_entry):
        log.debug("Publish advertise route event")
        self.rtm.enqueue(RouteEvent(RouteEvent.ADVERTISE, route_entry, self))

    @log_decorator.log_info
    def _withdraw_route(self, route_entry):
        log.debug("Publish withdraw route event")
        self.rtm.enqueue(RouteEvent(RouteEvent.WITHDRAW, route_entry, self))

    def get_lg_map(self):
        return {
            "adv_routes": (lg.SUBTREE, self.get_lg_routes)
        }

    def get_lg_routes(self, path_prefix):
        return [route.get_looking_glass_info(path_prefix) for route in
                self.get_route_entries()]


class WorkerCleanupEvent(object):

    def __init__(self, worker):
        self.worker = worker

    def __repr__(self):
        return "WorkerCleanupEvent:%s" % (self.worker.name)
