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

from bagpipe.bgp.common.looking_glass import LookingGlass
from bagpipe.bgp.common.looking_glass import LookingGlassReferences
from bagpipe.bgp.common.looking_glass import LGMap

from bagpipe.bgp.common import logDecorator

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.attribute import Attribute
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget

from exabgp.bgp.message import OUT

from exabgp.reactor.protocol import AFI, SAFI

log = logging.getLogger(__name__)


class RouteEntry(LookingGlass):
    """A route entry describes a BGP route, i.e. the association of:
* a BGP NLRI of a specific type (e.g. a VPNv4 route
  like "1.2.3.4:5:192.168.0.5/32")
* BGP attributes
* the source of the BGP route (e.g. the BGP peer, or the local VPN instance,
  that advertizes the route)
"""

    def __init__(self, nlri, RTs=None, attributes=None,
                 source=None):
        if attributes is None:
            attributes = Attributes()
        assert(isinstance(attributes, Attributes))
        if RTs is not None:
            assert(isinstance(RTs, list))
            assert(len(RTs) == 0 or isinstance(RTs[0], RouteTarget))

        self.source = source
        self.afi = nlri.afi
        self.safi = nlri.safi
        assert(isinstance(self.afi, AFI))
        assert(isinstance(self.safi, SAFI))
        self.nlri = nlri
        self.attributes = attributes
        # a list of exabgp.bgp.message.update.attribute.community.
        #   extended.RouteTargetASN2Number
        self._routeTargets = []
        if Attribute.CODE.EXTENDED_COMMUNITY in self.attributes:
            ecoms = self.attributes[
                Attribute.CODE.EXTENDED_COMMUNITY].communities
            # use type(..) because isinstance(rtrecord, RouteTarget) is True
            self._routeTargets = [ecom for ecom in ecoms
                                  if type(ecom) == RouteTarget]
            if RTs:
                ecoms += RTs
                self._routeTargets += RTs
        else:
            if RTs:
                self.attributes.add(ExtendedCommunities(RTs))
                self._routeTargets += RTs

    @property
    def routeTargets(self):
        return self._routeTargets

    def extendedCommunities(self, filter_=None):
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

    @logDecorator.log
    def setRouteTargets(self, routeTargets):
        # first build a list of ecoms without any RT
        eComs = self.extendedCommunities(lambda ecom:
                                         not isinstance(ecom, RouteTarget))

        # then add the right RTs
        newEComs = ExtendedCommunities()
        newEComs.communities += eComs
        newEComs.communities += routeTargets

        # update
        self._routeTargets = routeTargets

        self.attributes.remove(newEComs.ID)
        self.attributes.add(newEComs)

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
        assert(isinstance(other, RouteEntry))
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

    def __repr__(self, skipNextHop=False):
        fromString = " from:%s" % self.source if self.source else ""

        nexthop = ""
        if not skipNextHop:
            nexthop = str(self.nexthop)

        return "[RouteEntry: %s/%s %s nh:%s %s%s]" % (
            self.afi, self.safi, self.nlri, nexthop,
            self.attributes, fromString)

    def getLookingGlassLocalInfo(self, pathPrefix):

        attDict = {}

        for attribute in self.attributes.itervalues():

            # skip some attributes that we care less about
            if (attribute.ID == Attribute.CODE.AS_PATH or
               attribute.ID == Attribute.CODE.ORIGIN or
               attribute.ID == Attribute.CODE.LOCAL_PREF):
                continue

            attDict[repr(Attribute.CODE(attribute.ID))] = str(attribute)

        res = {"afi-safi": "%s/%s" % (self.afi, self.safi),
               "attributes": attDict,
               "next_hop": self.nexthop
               }

        if self.source:
            res["source"] = {"id": self.source.name,
                             "href": LookingGlassReferences.getAbsolutePath(
                                 "BGP_WORKERS", pathPrefix, [self.source.name])
                             }

        if (self.safi) in [SAFI.mpls_vpn, SAFI.evpn]:
            res["route_targets"] = [str(rt) for rt in self.routeTargets]

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

    def __init__(self, eventType, routeEntry, source=None):
        assert(eventType == RouteEvent.ADVERTISE or
               eventType == RouteEvent.WITHDRAW)
        assert(isinstance(routeEntry, RouteEntry))
        self.type = eventType
        self.routeEntry = routeEntry
        if source is not None:
            self.source = source
            self.routeEntry.source = source
        else:
            self.source = routeEntry.source
        assert(self.source is not None)
        self.replacedRoute = None

        # this is required to overwrite the action field in an NLRI
        # in the case where we generate a withdraw from an existing NLRI 
        # on a replaced route
        # and this spares us the pain of specifying the action
        # when creating an nlri
        if eventType == RouteEvent.ADVERTISE:
            self.routeEntry.nlri.action = OUT.ANNOUNCE
        else:  # WITHDRAW
            self.routeEntry.nlri.action = OUT.WITHDRAW

    @logDecorator.log
    def setReplacedRoute(self, replacedRoute):
        ''' Called only by RouteTableManager, replacedRoute should be a
        RouteEntry '''
        assert(isinstance(replacedRoute, RouteEntry)
               or (replacedRoute is None))
        assert(replacedRoute != self.routeEntry)
        self.replacedRoute = replacedRoute

    def __repr__(self):
        if self.replacedRoute:
            replacesStr = "replaces one route"
        else:
            replacesStr = "replaces no route"
        return "[RouteEvent(%s): %s %s %s]" % (replacesStr,
                                               RouteEvent.type2name[self.type],
                                               self.routeEntry,
                                               self.source)


class _SubUnsubCommon(object):

    def __init__(self, afi, safi, routeTarget, worker=None):
        assert(isinstance(afi, AFI))
        assert(isinstance(safi, SAFI))
        assert(routeTarget is None or isinstance(routeTarget, RouteTarget))
        self.afi = afi
        self.safi = safi
        self.routeTarget = routeTarget
        self.worker = worker

    def __repr__(self):
        byWorker = " by %s" % self.worker.name if self.worker else ""
        return "%s [%s/%s,%s]%s" % (self.__class__.__name__,
                                    self.afi or "*", self.safi or "*",
                                    self.routeTarget or "*", byWorker)


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

    def __init__(self, afi, safi, routeTarget=None, worker=None):
        _SubUnsubCommon.__init__(self, afi, safi, routeTarget, worker)


class Unsubscription(_SubUnsubCommon):

    def __init__(self, afi, safi, routeTarget=None, worker=None):
        _SubUnsubCommon.__init__(self, afi, safi, routeTarget, worker)


class EventSource(LookingGlass):
    '''
    Class for objects that advertise and withdraw routes
    need to have a 'name' attribute
    '''

    def __init__(self, routeTableManager):
        self.routeTableManager = routeTableManager
        # private data of RouteTableManager
        self._rtm_routeEntries = set()

    def getRouteEntries(self):
        return self._rtm_routeEntries

    @logDecorator.logInfo
    def _advertiseRoute(self, routeEntry):
        log.debug("Publish advertise route event")
        self.routeTableManager.enqueue(RouteEvent(RouteEvent.ADVERTISE,
                                                  routeEntry, self))

    @logDecorator.logInfo
    def _withdrawRoute(self, routeEntry):
        log.debug("Publish withdraw route event")
        self.routeTableManager.enqueue(RouteEvent(RouteEvent.WITHDRAW,
                                                  routeEntry, self))

    def getLGMap(self):
        return {
            "adv_routes": (LGMap.SUBTREE, self.getLGRoutes)
        }

    def getLGRoutes(self, pathPrefix):
        return [route.getLookingGlassInfo(pathPrefix) for route in
                self.getRouteEntries()]


class WorkerCleanupEvent(object):

    def __init__(self, worker):
        self.worker = worker

    def __repr__(self):
        return "WorkerCleanupEvent:%s" % (self.worker.name)
