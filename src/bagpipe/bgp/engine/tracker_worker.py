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

import traceback

import logging

from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine import RouteEvent, RouteEntry

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger, LGMap

from exabgp.message.update.attribute import AttributeID
from exabgp.message.update.attributes import Attributes

keepAttributes_default = [ AttributeID.NEXT_HOP,
                           AttributeID.PMSI_TUNNEL,
                           AttributeID.MED,
                           AttributeID.EXTENDED_COMMUNITY, # FIXME
                           AttributeID.LOCAL_PREF ]

class FilteredRouteEntry(RouteEntry):

    def __init__(self, re, keepAttributes=keepAttributes_default):

        attributes = Attributes()
        for (attributeId, attribute) in re.attributes.iteritems():
            if attributeId in keepAttributes:
                attributes.add(attribute)
        
        RouteEntry.__init__(self, re.afi, re.safi, re.routeTargets, re.nlri, attributes, None)

def plural(x):
    if len(x)>1:
        return "s"
    else:
        return ""

class TrackerWorker(Worker, LookingGlassLocalLogger):
    
    def __init__(self, bgpManager, workerName):
        Worker.__init__(self, bgpManager, workerName)
        LookingGlassLocalLogger.__init__(self)

        self.trackedEntry2routes = dict()  # dict: entry -> list of routes
        self.trackedEntry2bestRoutes = dict()  # dict: entry -> set of bestRoutes
        
    def getBestRoutesForTrackedEntry(self, entry):
        return self.trackedEntry2bestRoutes.get(entry, set())
        
    def _onEvent(self, routeEvent):
        self.log.debug("Received route event: %s" % routeEvent)
        
        newRoute = routeEvent.routeEntry
        filteredNewRoute = FilteredRouteEntry(newRoute)
        
        entry = self._route2trackedEntry(newRoute)
        
        self.log.debug("trackedEntry corresponding to this route: %s (type: %s)" % (TrackerWorker._displayEntry(entry), type(entry)))
        
        self._dumpState()

        try:
            allRoutes = self.trackedEntry2routes[entry]
        except KeyError:
            self.log.debug("Initiating trackedEntry2routes[entry]")
            allRoutes = []
            self.trackedEntry2routes[entry] = allRoutes
            
        self.log.debug("We currently have %d route%s for this entry" % (len(allRoutes),plural(allRoutes)))
                
        if routeEvent.type == RouteEvent.ADVERTISE:
            
            withdrawnBestRoutes = []
            bestRoutes = []
            
            try:
                bestRoutes = self.trackedEntry2bestRoutes[entry]
    
                if routeEvent.replacedRoute is not None:
                    self.log.debug("Removing replaced route from allRoutes and bestRoutes: %s" % routeEvent.replacedRoute)
                    try:
                        allRoutes.remove(routeEvent.replacedRoute)
                    except ValueError:
                        # we did not have any route for this entry
                        self.log.error("replacedRoute is an entry for which we had no route ??? (not supposed to happen)")
                    
                    if routeEvent.replacedRoute in bestRoutes:
                        self.log.debug("Removing replacedRoute from bestRoutes")
                        bestRoutes.remove(routeEvent.replacedRoute)
                        withdrawnBestRoutes.append(routeEvent.replacedRoute)
                    else:
                        self.log.debug("replacedRoute is not in bestRoutes")
                else:
                    self.log.debug("No replaced route to remove")
                
                callNewBestRoute4All = False
                if len(bestRoutes) == 0:
                    self.log.debug("All best routes have been replaced")
                    self._recomputeBestRoutes(allRoutes, bestRoutes)
                    if bestRoutes:
                        currentBestRoute = iter(bestRoutes).next()
                        self.log.debug("We'll need to call newBestRoute for all our new best routes")
                        callNewBestRoute4All = True
                    else:
                        currentBestRoute = None
                        callNewBestRoute4All = False
                else:
                    # (if there is more than one route in the best routes, we take the first one)
                    currentBestRoute = iter(bestRoutes).next()
                    
                    self.log.debug("Current best route: %s" % currentBestRoute)
                    
                    if newRoute == currentBestRoute:
                        self.log.info("New route is a route we already had, nothing to do.")
                        # nothing to do
                        return
    
                # let's find if we need to update our best routes
                if currentBestRoute:
                    routeComparison = self._compareRoutes(newRoute, currentBestRoute)
                else:
                    routeComparison = 1
                
                self.log.debug("routeComparison: %d" % routeComparison)
                
                if routeComparison > 0:  # newRoute is a strictly better route than any current one, discard all the current best routes
                    self.log.debug("Replacing all best routes with the new route")
                    withdrawnBestRoutes.extend(bestRoutes.copy())
                    bestRoutes.clear()
                    bestRoutes.add(newRoute)
                    self._newBestRoute_interceptException(entry, filteredNewRoute)
                    callNewBestRoute4All = False
                if routeComparison == 0:  # newRoute is as good as the current ones 
                    self.log.debug("Adding newRoute to bestRoutes...")
                    
                    if callNewBestRoute4All:
                        self._callNewBestRouteForAll(entry,bestRoutes)
                    
                    # We'll do a call to self._newBestRoute... *only* if the newRoute is, 
                    # different from all current best routes. This comparison uses FilteredRouteEntry
                    # to *not* take into account .source (the BGP peer which advertized the route)
                    # and take only into account a specific set of BGP attributes.
                    # TODO: explain more on theses BGP attributes
                    #       related to the cases where a route is re-advertized with
                    #       updated attributes
                    isReallyNew = (FilteredRouteEntry(newRoute) not in
                                    map(lambda r: FilteredRouteEntry(r), bestRoutes))
                    
                    bestRoutes.add(newRoute)
                    
                    if isReallyNew:
                        self.log.debug("Calling self._newBestRoute since we yet had no such route in best routes")
                        self._newBestRoute_interceptException(entry, filteredNewRoute)
                    else:
                        self.log.debug("Not calling self._newBestRoute since we had received a similar route already")
                        
                else:
                    self.log.debug("The route is no better than current best ones")
                    
                    if callNewBestRoute4All:
                        self._callNewBestRouteForAll(entry,bestRoutes)
                
                # if the newRoute was a better one, call _bestRouteRemoved ;
                # we do it *after* calling _newBestRoute, do avoid breaking the old state before creating the new one
                #if routeComparison > 0:
                #    for route in bestRoutesToRemove:
                #        self.log.debug("Calling bestRouteRemoved for %s" % route)
                #        self._bestRouteRemoved_interceptException(entry, FilteredRouteEntry(route))
                
            except (KeyError, StopIteration) as e:
                self.log.debug("We did not had any route for this entry (%s)" % e)
                self.trackedEntry2bestRoutes[entry] = set([newRoute])
                bestRoutes = bestRoutes
                self.log.debug("Calling newBestRoute")
                self._newBestRoute_interceptException(entry, filteredNewRoute)
            
            # We need to call self._bestRouteRemoved for routes that where implicitly withdrawn, but
            # only if they don't have an equal route (in the sense of FilteredRouteEntry) in bestRoutes
            filteredBestRoutes = map(lambda r: FilteredRouteEntry(r), bestRoutes)
            self.log.debug("Considering implicitly withdrawn best routes for self._bestRouteRemoved")
            for filteredRoute in map(lambda r: FilteredRouteEntry(r), withdrawnBestRoutes):
                if filteredRoute not in filteredBestRoutes:
                    self.log.debug("   calling self._bestRouteRemoved for route: %s" % filteredRoute)
                    self._bestRouteRemoved_interceptException(entry, filteredRoute)
                else:
                    self.log.debug("   not calling self._bestRouteRemoved for route: %s" % filteredRoute)
            
            # add the route to the list of routes for this entry
            self.log.debug("Adding route to allRoutes for this entry")
            allRoutes.append(newRoute)
            
        else:  # RouteEvent.WITHDRAW    
            
            withdrawnRoute = newRoute
            
            self.log.debug("Removing route from allRoutes for this entry")
            
            try:
                allRoutes.remove(withdrawnRoute)
            except ValueError:
                # we did not have any route for this entry
                self.log.error("Withdraw received for an entry for which we had no route ??? (not supposed to happen)")
            
            try:
                bestRoutes = self.trackedEntry2bestRoutes[entry]
                
                if withdrawnRoute in bestRoutes:
                    self.log.debug("The event received is about a route which is among the best routes for this entry")
                    # remove the route from bestRoutes
                    bestRoutes.remove(withdrawnRoute)

                    if len(bestRoutes) == 0:  # we don't have any best route left... 
                        self._recomputeBestRoutes(allRoutes, bestRoutes)
                    
                        if len(bestRoutes) > 0:
                            self._callNewBestRouteForAll(entry, bestRoutes)
                        else:
                            self.log.debug("Cleanup allRoutes and bestRoutes...")
                            del self.trackedEntry2bestRoutes[entry]
                            del self.trackedEntry2routes[entry]
                    else:
                        # we still have some best routes, no new best route call to do
                        pass
                    
                    self.log.debug("Calling bestRouteRemoved...?")
                    # We need to call self._bestRouteRemoved, but only if the withdrawn Route does not have
                    # an equal route in bestRoutes (in the sense of FilteredRouteEntry)
                    filteredWithdrawnRoute = FilteredRouteEntry(withdrawnRoute)
                    if filteredWithdrawnRoute not in map(lambda r: FilteredRouteEntry(r), bestRoutes):
                        self.log.debug("Calling bestRouteRemoved: %s" % filteredWithdrawnRoute)
                        self._bestRouteRemoved_interceptException(entry, filteredWithdrawnRoute)
                    else:
                        self.log.debug("No need to call bestRouteRemoved: %s" % filteredWithdrawnRoute)

                else:
                    self.log.debug("The event received is not related to one of the best routes for this entry")
                    # no need to update our best route list
                    pass
                
            except (KeyError, ValueError) as e:
                # we did not have any route for this entry
                self.log.error("Withdraw received for an entry for which we had no route: not supposed to happen! (%s)" % e)
            except Exception:
                raise
                
        self.log.info("We now have %d route%s for this entry." % (len(allRoutes),plural(allRoutes)))
        
        self._dumpState()
    
    def _recomputeBestRoutes(self, allRoutes, bestRoutes):
        '''update bestRoutes to contain the best routes from allRoutes, based on _compareRoutes'''
        
        newBestRoutes = []
        for route in allRoutes:
            if len(newBestRoutes) == 0:
                #self.log.debug("first route, thus our current best: %s" % route)
                newBestRoutes = [route]
                continue
                
            comparison = self._compareRoutes(route, newBestRoutes[0])
            #self.log.debug("Route comparison: %s vs %s == %d"% (route, newBestRoutes[0],comparison) )
            if comparison > 0:
                #self.log.debug("better, replaces our current best: %s" % route)
                newBestRoutes = [route]
            elif comparison == 0:
                #self.log.debug("as good as our current best: %s" % route)
                newBestRoutes.append(route)
            else:
                #self.log.debug("no better than our current best: %s" % route)
                pass
        
        bestRoutes.clear()
        bestRoutes.update(newBestRoutes)
        
        self.log.debug("Recomputed new best routes: %s" % bestRoutes)
        
        return newBestRoutes
    
    def _callNewBestRouteForAll(self,entry,bestRoutes):
        self.log.debug("Calling newBestRoute for all bestRoutes, without duplicates")
        self.log.debug("   All best routes: %s" % bestRoutes)
        bestRoutesNoDups = set()
        for route in map(lambda r: FilteredRouteEntry(r), bestRoutes):
            bestRoutesNoDups.add(route)
        self.log.debug("   After filtering duplicates: %s" % bestRoutesNoDups)
        for route in bestRoutesNoDups:
            self._newBestRoute_interceptException(entry, route)
    
    def _newBestRoute_interceptException(self, entry, newRoute):
        try:
            self._newBestRoute(entry, newRoute) 
        except Exception as e:
            self.log.error("Exception in <subclass>._newBestRoute: %s" % e)
            if self.log.isEnabledFor(logging.WARNING):
                self.log.info("%s" % traceback.format_exc())

    def _bestRouteRemoved_interceptException(self, entry, oldRoute):
        try: 
            self._bestRouteRemoved(entry, oldRoute)
        except Exception as e:
            self.log.error("Exception in <subclass>._bestRouteRemoved: %s" % e)
            if self.log.isEnabledFor(logging.WARNING):
                self.log.info("%s" % traceback.format_exc())
    
    ################## Callbacks for subclasses ########################
    
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
    
    #FIXME: need to document the behavior of these callbacks
        
    def _newBestRoute(self, entry, newRoute):
        raise Exception("not implemented")

    def _bestRouteRemoved(self, entry, oldRoute):
        raise Exception("not implemented")
    
    ######### Debug support methods #########
    
    def _dumpState(self):
        if self.log.isEnabledFor(logging.DEBUG):
            self.log.debug("--- trackedEntry2routes ---")
            for entry in self.trackedEntry2routes:
                self.log.debug("  Entry: %s" % TrackerWorker._displayEntry(entry))
                for route in self.trackedEntry2routes[entry]:
                    self.log.debug("    Route: %s" % route)

            self.log.debug("--- trackedEntry2bestRoutes ---")
            for entry in self.trackedEntry2bestRoutes:
                self.log.debug("  Entry: %s" % TrackerWorker._displayEntry(entry))
                for route in self.trackedEntry2bestRoutes[entry]:
                    self.log.debug("    Route: %s" % route)

            self.log.debug("--- ---")

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
    
