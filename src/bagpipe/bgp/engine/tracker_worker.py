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


import types

import logging

import traceback

from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine import RouteEvent, RouteEntry

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

from exabgp.message.update.attribute import AttributeID
from exabgp.message.update.attributes import Attributes

log = logging.getLogger(__name__)


keepAttributes_default = [ AttributeID.NEXT_HOP,
                           AttributeID.PMSI_TUNNEL,
                           AttributeID.MED,
                           AttributeID.LOCAL_PREF ]


class FilteredRouteEntry(RouteEntry):

    def __init__(self, re, keepAttributes=keepAttributes_default):

        attributes = Attributes()
        for (attributeId, attribute) in re.attributes.iteritems():
            if attributeId in keepAttributes:
                attributes.add(attribute)
        
        RouteEntry.__init__(self, re.afi, re.safi, re.routeTargets, re.nlri, attributes, None)


class TrackerWorker(Worker, LookingGlass):
    
    
    def __init__(self, bgpManager, workerName):
        Worker.__init__(self, bgpManager, workerName)
        self.trackedEntry2routes = dict()  # dict: entry -> list of routes
        self.trackedEntry2bestRoutes = dict()  # dict: entry -> set of bestRoutes
        
    def _onEvent(self, routeEvent):
        log.debug("Received route event: %s" % routeEvent)
        
        newRoute = routeEvent.routeEntry
        filteredNewRoute = FilteredRouteEntry(newRoute)
        
        entry = self._route2trackedEntry(newRoute)
        
        log.debug("trackedEntry corresponding to this route: %s (type: %s)" % (TrackerWorker._displayEntry(entry), type(entry)))
        
        self._dumpState()

        try:
            allRoutes = self.trackedEntry2routes[entry]
        except KeyError:
            log.debug("Initiating trackedEntry2routes[entry]")
            allRoutes = []
            self.trackedEntry2routes[entry] = allRoutes
            
        log.debug("We currently have %d routes for this entry" % len(allRoutes))
                
        if routeEvent.type == RouteEvent.ADVERTISE:
            
            try:
                bestRoutes = self.trackedEntry2bestRoutes[entry]
    
                withdrawnBestRoutes = []
    
                if routeEvent.replacedRoute is not None:
                    log.debug("Removing replaced route from allRoutes and bestRoutes: %s" % routeEvent.replacedRoute)
                    try:
                        allRoutes.remove(routeEvent.replacedRoute)
                    except ValueError:
                        # we did not have any route for this entry
                        log.error("replacedRoute is an entry for which we had no route ??? (not supposed to happen)")
                    
                    if routeEvent.replacedRoute in bestRoutes:
                        bestRoutes.remove(routeEvent.replacedRoute)
                        withdrawnBestRoutes.append(routeEvent.replacedRoute)
                else:
                    log.debug("No replaced route to remove")
                

                if len(bestRoutes) == 0:
                    self._recomputeBestRoutes(allRoutes, bestRoutes) 
                    currentRoute = iter(bestRoutes).next()
                    log.debug("New current best route: %s" % currentRoute)
                else:
                    # (if there is more than one route in the best routes, we take the first one)
                    currentRoute = iter(bestRoutes).next()
                    
                    log.debug("Current best route: %s" % currentRoute)
                    
                    if newRoute == currentRoute:
                        log.info("New route is a route we already had, nothing to do.")
                        # nothing to do
                        return
    
                    # we already have a route for this entry, let's find which one is better
                    # and see if we need to update our best routes                
                    routeComparison = self._compareRoutes(newRoute, currentRoute)
                    
                    log.debug("routeComparison: %d" % routeComparison)
                    
                    if routeComparison > 0:  # newRoute is a strictly better route than any current one, discard all the current best routes
                        log.debug("Replacing all best routes with the new route")
                        bestRoutesToRemove = bestRoutes.copy()
                        bestRoutes.clear()
                        bestRoutes.add(newRoute)
                        self._newBestRoute_interceptException(entry, filteredNewRoute)
                    if routeComparison == 0:  # newRoute is as good as the current ones 
                        log.debug("Adding newRoute to bestRoutes...")
                        
                        # We'll do a call to self._newBestRoute... *only* if the newRoute is, 
                        # different from all current best routes. This comparison uses FilteredRouteEntry
                        # to *not* take into account .source (the BGP peer which advertized the route)
                        # and take only into account a specific set of BGP attributes.
                        newBestRoute = (FilteredRouteEntry(newRoute) not in
                                        map(lambda r: FilteredRouteEntry(r), bestRoutes))
                        
                        bestRoutes.add(newRoute)
                        
                        if newBestRoute:
                            log.debug("Calling self._newBestRoute since we yet had no such route in best routes")
                            self._newBestRoute_interceptException(entry, filteredNewRoute)
                        else:
                            log.debug("Not calling self._newBestRoute since we had received a similar route already")
                    else:
                        log.debug("The route is not better than current best one")
                        # nothing to do
                        pass
                    
                    # if the newRoute was a better one, call _bestRouteRemoved ;
                    # we do it *after* calling _newBestRoute, do avoid breaking the old state before creating the new one
                    if routeComparison > 0:
                        for route in bestRoutesToRemove:
                            log.debug("Calling bestRouteRemoved for %s" % route)
                            self._bestRouteRemoved_interceptException(entry, FilteredRouteEntry(route))
                    
                    # We need to call self._bestRouteRemoved for routes that where implicitly withdraw, but
                    # only if they don't have an equal route (in the sense of FilteredRouteEntry) in bestRoutes
                    filteredBestRoutes = map(lambda r: FilteredRouteEntry(r), bestRoutes)
                    log.debug("Considering implicitly withdrawn best routes for self._bestRouteRemoved")
                    for filteredRoute in map(lambda r: FilteredRouteEntry(r), withdrawnBestRoutes):
                        if filteredRoute not in filteredBestRoutes:
                            log.debug("   calling self._bestRouteRemoved for route: %s" % filteredRoute)
                            self._bestRouteRemoved_interceptException(entry, filteredRoute)
                        else:
                            log.debug("   not calling self._bestRouteRemoved for route: %s" % filteredRoute)
                
            except (KeyError, StopIteration) as e:
                log.debug("We did not had any route for this entry (%s)" % e)
                currentRoute = None
                self.trackedEntry2bestRoutes[entry] = set([newRoute])
                log.debug("Calling newBestRoute")
                self._newBestRoute_interceptException(entry, filteredNewRoute)
            
            # add the route to the list of routes for this entry
            log.debug("Adding route to allRoutes for this entry")
            allRoutes.append(newRoute)
            
        else:  # RouteEvent.WITHDRAW    
            
            withdrawnRoute = newRoute
            
            log.debug("Removing route from allRoutes for this entry")
            
            try:
                allRoutes.remove(withdrawnRoute)
            except ValueError:
                # we did not have any route for this entry
                log.error("Withdraw received for an entry for which we had no route ??? (not supposed to happen)")
            
            try:
                bestRoutes = self.trackedEntry2bestRoutes[entry]
                
                if withdrawnRoute in bestRoutes:
                    log.debug("The event received is about a route which is among the best routes for this entry")
                    # remove the route from bestRoutes
                    bestRoutes.remove(withdrawnRoute)

                    log.debug("Calling bestRouteRemoved...?")
                    # We need to call self._bestRouteRemoved, but only if the withdrawn Route does not have
                    # an equal route in bestRoutes (in the sense of FilteredRouteEntry)
                    filteredWithdrawnRoute = FilteredRouteEntry(withdrawnRoute)
                    if filteredWithdrawnRoute not in map(lambda r: FilteredRouteEntry(r), bestRoutes):
                        log.debug("Calling bestRouteRemoved")
                        self._bestRouteRemoved_interceptException(entry, filteredWithdrawnRoute)

                    if len(bestRoutes) == 0:  # we don't have any best route left... 
                        newBestRoutes = self._recomputeBestRoutes(allRoutes, bestRoutes)
                    
                        if len(newBestRoutes) > 0:
                            for route in newBestRoutes:
                                log.debug("Calling newBestRoute")
                                self._newBestRoute_interceptException(entry, FilteredRouteEntry(route))
                        else:
                            log.debug("Cleanup allRoutes and bestRoutes...")
                            del self.trackedEntry2bestRoutes[entry]
                            del self.trackedEntry2routes[entry]
                    else:
                        # we still have some best routes, nothing to do
                        pass
                    
                else:
                    log.debug("The event received is not related to one of the best routes for this entry")
                    # no need to update our best route list
                    pass
                
            except (KeyError, ValueError) as e:
                # we did not have any route for this entry
                log.error("Withdraw received for an entry for which we had no route: not supposed to happen! (%s)" % e)
            except Exception:
                raise
                            
                
        log.info("We now have %d route(s) for this entry." % len(allRoutes))
        
        self._dumpState()
    
    def _recomputeBestRoutes(self, allRoutes, bestRoutes):
        '''look at all the routes in allRoutes and add them to bestRoutes'''
        
        newBestRoutes = []
        for route in allRoutes:
            if len(newBestRoutes) == 0:
                newBestRoutes = [route]
                continue
                
            comparison = self._compareRoutes(route, newBestRoutes[0]) > 0
            if comparison > 0:
                newBestRoutes = [route]
            elif comparison == 0:
                newBestRoutes += route
            else:
                # route no better
                pass
        
        bestRoutes.clear()
        bestRoutes.update(newBestRoutes)
        
        return newBestRoutes
    
    
    def _route2trackedEntry(self, route):
        """
        This method is how the subclass maps a BGP route into an object that the TrackerWorker 
        code will track.
        
        For instance, a VPN VRF is expected to keep track of IP prefixes; hence the
        route2trackedEntry code for a VRF could return the IP prefix in the VPNv4 route. 
        The result will be that the TrackerWorker code will keep track, for a each prefix,
        of all the routes and of the best routes.  
        """
        raise Exception("not implemented")
    
    def _compareRoutes(self, routeA, routeB):
        """
        should return:
         - an int>0 if routeA is better than routeB
         - an int<0 if routeB is better than routeA
         - else 0
        """
        raise Exception("not implemented")


    def _newBestRoute_interceptException(self, entry, newRoute):
        try:
            self._newBestRoute(entry, newRoute) 
        except Exception as e:
            log.error("Exception in <subclass>._newBestRoute: %s" % e)
            if log.isEnabledFor(logging.WARNING):
                log.info("%s" % traceback.format_exc())

    def _bestRouteRemoved_interceptException(self, entry, oldRoute):
        try: 
            self._bestRouteRemoved(entry, oldRoute)
        except Exception as e:
            log.error("Exception in <subclass>._bestRouteRemoved: %s" % e)
            if log.isEnabledFor(logging.WARNING):
                log.info("%s" % traceback.format_exc())
                
    
    #FIXME: need to document the behavior of these callbacks
        
    def _newBestRoute(self, entry, newRoute):
        raise Exception("not implemented")

    def _bestRouteRemoved(self, entry, oldRoute):
        raise Exception("not implemented")
    
    
    
    def _dumpState(self):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("--- trackedEntry2routes ---")
            for entry in self.trackedEntry2routes:
                log.debug("  Entry: %s" % TrackerWorker._displayEntry(entry))
                for route in self.trackedEntry2routes[entry]:
                    log.debug("    Route: %s" % route)

            log.debug("--- trackedEntry2bestRoutes ---")
            for entry in self.trackedEntry2bestRoutes:
                log.debug("  Entry: %s" % TrackerWorker._displayEntry(entry))
                for route in self.trackedEntry2bestRoutes[entry]:
                    log.debug("    Route: %s" % route)

            log.debug("--- ---")


    @staticmethod
    def _displayEntry(entry):
        if (isinstance(entry, tuple)
             and len(entry) > 0
             and (isinstance(entry[0], type) or isinstance(entry[0], types.ClassType))
            ):  
            return repr(tuple([entry[0].__name__] + list(entry[1:])))
        else: 
            return repr(entry) 

    ######### Looking glass ###########

    def getLGMap(self):
        return {
                "received routes": (LGMap.SUBTREE, self.getLGAllRoutes)
                }

    def getLGAllRoutes(self, pathPrefix):
        allRoutes = []
        for routes in self.trackedEntry2routes.itervalues():
            allRoutes += [ route.getLookingGlassInfo(pathPrefix) for route in routes ]
        return allRoutes
    
