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

import logging

from exabgp.reactor.protocol import AFI, SAFI

from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget

from exabgp.bgp.message.update.attribute.attribute import Attribute
from exabgp.bgp.message.update import Attributes

from bagpipe.bgp.common.looking_glass import LookingGlass
from bagpipe.bgp.common.looking_glass import LookingGlassReferences
from bagpipe.bgp.common.looking_glass import LGMap

from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities

from bagpipe.exabgp.message.update.attribute.communities import ECommunities

log = logging.getLogger(__name__)


class RouteEntry(LookingGlass):
    """A route entry describes a BGP route, i.e. the association of:
* a BGP NLRI of a specific type (e.g. a VPNv4 route
  like "1.2.3.4:5:192.168.0.5/32")
* BGP attributes
* the source of the BGP route (e.g. the BGP peer, or the local VPN instance,
  that advertizes the route)
"""


    def __init__(self, afi, safi, nlri, RTs=None, attributes=None, source=None):
        assert(isinstance(afi, AFI))
        assert(isinstance(safi, SAFI))
        if attributes is None:
            attributes = Attributes()
        assert(isinstance(attributes, Attributes))

        self.source = source
        self.afi = afi
        self.safi = safi
        self.nlri = nlri
        self.attributes = attributes
        # a list of exabgp.bgp.message.update.attribute.community.
        #   extended.RouteTargetASN2Number
        self._routeTargets = []
        if Attribute.CODE.EXTENDED_COMMUNITY in self.attributes:
            self._routeTargets = [ecom for ecom in self.attributes[
                Attribute.CODE.EXTENDED_COMMUNITY].communities
                if isinstance(ecom, RouteTarget)]
        if RTs:
            self.attributes.add(ExtendedCommunities(RTs))
            self._routeTargets += RTs

    @property
    def routeTargets(self):
        return self._routeTargets

    def setRouteTargets(self, routeTargets):
        log.debug("attributes before srt: %s", self.attributes)

        # first build a list of ecoms without any RT
        newEComs = ExtendedCommunities()
        if Attribute.CODE.EXTENDED_COMMUNITY in self.attributes:
            ecoms = self.attributes[
                Attribute.CODE.EXTENDED_COMMUNITY].communities
            log.debug("ecoms: %s", ecoms)
            log.debug("ecoms type: %s", type(ecoms))
            for ecom in ecoms:
                if not isinstance(ecom, RouteTarget):
                    newEComs.communities.append(ecom)

        # then add the right RTs
        newEComs.communities += routeTargets

        # update
        self._routeTargets = routeTargets
        self.attributes[Attribute.CODE.EXTENDED_COMMUNITY] = newEComs

        log.debug("attributes after srt: %s", self.attributes)

    def __cmp__(self, other):
        if other is None:
            return -1
        assert(isinstance(other, RouteEntry))
        if (self.afi == other.afi and
                self.safi == other.safi and
                self.source == other.source and
                self.nlri == other.nlri and
                self.attributes.sameValuesAs(other.attributes)):
            return 0
        else:
            log.debug("attributes comparison: %s",
                      self.attributes.sameValuesAs(other.attributes))
            return -1

    def __hash__(self):  # FIXME: improve for better performance ?
        return hash("%d/%d %s %d %s" % (self.afi, self.safi, self.source,
                                        hash(self.nlri), hash(self.attributes)
                                        ))

    def __repr__(self):
        fromString = " from:%s" % self.source if self.source else ""
        return "[RouteEntry: %s %s %s %s RT:%s%s]" % (self.afi, self.safi,
                                                      self.nlri,
                                                      self.attributes,
                                                      self._routeTargets,
                                                      fromString)

    def getLookingGlassLocalInfo(self, pathPrefix):

        attributesDict = {}

        for (attributeId, value) in self.attributes.iteritems():

            # skip some attributes that we care less about
            if (attributeId == Attribute.CODE.AS_PATH or
               attributeId == Attribute.CODE.ORIGIN or
               attributeId == Attribute.CODE.LOCAL_PREF):
                continue

            attributesDict[str(attributeId)] = repr(value)

        res = {"afi-safi": "%s/%s" % (self.afi, self.safi),
               "attributes": attributesDict
               }

        if self.source:
            res["source"] = {"id": self.source.name,
                             "href": LookingGlassReferences.getAbsolutePath(
                                 "BGP_WORKERS", pathPrefix, [self.source.name])
                             }

        if (self.safi) in [SAFI.mpls_vpn, SAFI.evpn]:
            res["route_targets"] = [repr(rt) for rt in self.routeTargets]

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
        assert(eventType in RouteEvent.type2name.keys())
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
        # FIXME: check consistency of eventType and nlri.action

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

    def _advertiseRoute(self, routeEntry):
        log.debug("Publish withdraw route event")
        self.routeTableManager.enqueue(RouteEvent(RouteEvent.ADVERTISE,
                                                  routeEntry, self))

    def _withdrawRoute(self, routeEntry):
        log.debug("Publish advertise route event")
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
