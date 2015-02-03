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

"""This module classes related to producing and consuming events related to BGP routes.

routes: RouteEntry

events: RouteEvent
    an announcement or a withdrawal of a BGP route

workers: Worker
    * produce events
    * subscribe to the route table manager to consume events related to certain BGP routes
    
route table manager (singleton)
    * tracks subscriptions of workers
    * dispatches events based on subscriptions

"""

import logging

from exabgp.structure.address    import AFI, SAFI
from exabgp.message.update.attribute.communities import RouteTarget
from exabgp.message.update.attribute import AttributeID
from exabgp.message.update.attributes import Attributes

from bagpipe.bgp.common.looking_glass import LookingGlass, LookingGlassReferences


log = logging.getLogger(__name__)

class RouteEntry(object, LookingGlass):
    """A route entry describes a BGP route, i.e. the association of:

* a BGP NLRI of a specific type (e.g. a VPNv4 route like "1.2.3.4:5:192.168.0.5/32")
* BGP attributes
* the source of the BGP route (e.g. the BGP peer, or the local VPN instance, that advertizes the route)

"""
    
    def __init__(self, afi, safi, routeTargets, nlri, attributes, source):
        assert(isinstance(afi, AFI))
        assert(isinstance(safi, SAFI))
        assert(isinstance(attributes, Attributes))
        self.source = source
        self.afi = afi
        self.safi = safi
        self.nlri = nlri
        self.attributes = attributes
        self.routeTargets = routeTargets  # a list of exabgp.message.update.attribute.communities.RouteTarget

    
    def __cmp__(self, other):
        if (isinstance(other, RouteEntry) and 
                self.afi == other.afi and 
                self.safi == other.safi and 
                self.source == other.source and
                self.nlri == other.nlri and
                self.attributes.sameValuesAs(other.attributes)):
            return 0
        else:
            return -1 
        
    def __hash__(self):  # FIXME: improve for better performance ?
        return hash("%d/%d %s %d %s" % (self.afi, self.safi, self.source, hash(self.nlri), hash(self.attributes)))
        
    def __repr__(self):
        return "[RouteEntry: %s %s %s %s RT:%s%s]" % (self.afi, self.safi, self.nlri, self.attributes, self.routeTargets,
                                                      " from:%s" % self.source if self.source else "")

    def getLookingGlassLocalInfo(self, pathPrefix):
        
        attributesDict = {}
        
        for (attributeId, value) in self.attributes.iteritems():
            
            # skip some attributes that we care less about
            if  (attributeId == AttributeID.AS_PATH or
                 attributeId == AttributeID.ORIGIN or
                 attributeId == AttributeID.LOCAL_PREF): continue
            
            attributesDict[ str(AttributeID(attributeId)).lower() ] = repr(value)
        
        res = {
                 "afi-safi": "%s/%s" % (self.afi, self.safi),
                 "attributes": attributesDict
                 }
        
        if self.source:
            res["source"] = { "id": self.source.name,
                              "href": LookingGlassReferences.getAbsolutePath("BGP_WORKERS", pathPrefix, [self.source.name])}
        
        if (self.safi) in [SAFI.mpls_vpn, SAFI.evpn]:
            res["route_targets"] = [ repr(rt) for rt in self.routeTargets]
        
        return {
                repr(self.nlri): res 
            }




class RouteEvent(object):
    """A RouteEvent represents an advertisement or a withdrawal of a RouteEntry
    """

    # event Types
    ADVERTISE = 1
    WITHDRAW = 2

    type2name = { ADVERTISE:"Advertise",
                  WITHDRAW: "Withdraw" }

    def __init__(self, eventType, routeEntry, source=None):
        assert(eventType in RouteEvent.type2name.keys())
        assert(isinstance(routeEntry, RouteEntry))
        self.type = eventType
        self.routeEntry = routeEntry
        if source is not None:
            self.source = source
        else:
            self.source = routeEntry.source
        self.replacedRoute = None

    def _setReplacedRoute(self, replacedRoute):
        ''' Called only by RouteTableManager, replacedRoute should be a RouteEntry '''
        assert(isinstance(replacedRoute, RouteEntry) or (replacedRoute is None))
        assert(replacedRoute != self.routeEntry)
        self.replacedRoute = replacedRoute

    def __repr__(self):
        return "[RouteEvent%s: %s %s %s]" % ("(replaces %s route)" % ("one" if self.replacedRoute is not None else "no"),
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
        return "%s [%s/%s,%s]%s" % (self.__class__.__name__,
                                    self.afi or "*",
                                    self.safi or "*",
                                    self.routeTarget or "*",
                                    " by %s" % self.worker.name if self.worker else "")



class Subscription(_SubUnsubCommon):
    """Represents a Subscription to RouteEvents
    
A subscription specifies the AFI, the SAFI, and the Route Target of the RouteEntry for which the subscriber wants to receive events.

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

