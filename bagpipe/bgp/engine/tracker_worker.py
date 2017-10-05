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
import socket
import traceback
import types

from oslo_log import log as logging

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import utils
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.engine import worker
from bagpipe.bgp.engine import exa
from bagpipe.bgp import engine


# Explanations on FilteredRoute

# We need to call self.best_route_removed for a route that was
# implicitly withdrawn, except if, in best_routes, there is
# a route that is the same with reference to what the
# best_route_removed callback will do:
# - if there is a route with same nexthop, same encap, same label
#   (other attributes make the route different)
#   => no call to best_route_removed
# - if there is a route with same nexthop, but a different label or
#   a different encap
#   => need to call best_route_removed
#
# Similarly, when multiple best routes exist for an entry
# (ECMP case), we don't want to call new_best_route multiple times
# uselessly for instance for two routes that would be 'same' wrt
# the actions done by the new_best_route callback. So we will do a
# call to self.new_best_route... *only* if the
# new_route is different from all current best routes.
#
# FilteredRoute is the class we use to identify a route
# that would be the 'same', based on the above.  For instance
# FilteredRoute removes information on the .source and
# only BGP attributes that are used by callbacks.
keep_attributes_default = [exa.Attribute.CODE.NEXT_HOP,
                           exa.Attribute.CODE.PMSI_TUNNEL,
                           exa.Attribute.CODE.MED,
                           exa.Attribute.CODE.EXTENDED_COMMUNITY,
                           exa.Attribute.CODE.LOCAL_PREF]


class FilteredRoute(engine.RouteEntry):

    def __init__(self, re, keep_attributes=None):
        if keep_attributes is None:
            keep_attributes = keep_attributes_default

        attributes = exa.Attributes()
        for (attribute_id, attribute) in re.attributes.iteritems():
            if attribute_id in keep_attributes:
                attributes.add(attribute)

        super(FilteredRoute, self).__init__(re.nlri, None, attributes)


def equivalent_route_in_routes(function, route, routes):
    reference = function(route)
    for r in routes:
        if function(r) == reference:
            return True
    return False

# a compare_route callback has the following signature:
#
# def compare_route(self, route_a, route_b):
#     """
#     should return:
#      - an int>0 if route_a is better than route_b
#      - an int<0 if route_b is better than route_a
#      - else 0
#     """

# TODO: both comparison should first compare local_pref and MAC Mobility
# if present


def compare_no_ecmp(self, route_a, route_b):
    '''
    This compares the two routes in a consistent fashion, but two routes
    will never be considered of equal cost.
    The comparison is 'salted' so that two distinct VRFs (e.g. on two distinct
    bagpipe-bgp instances will not necessarily elect the same route as the
    best one.
    '''
    self.log.trace("compare_no_ecmp used")
    salt = socket.gethostname() + self.name
    return cmp([hash(salt + repr(route_a)), route_a],
               [hash(salt + repr(route_b)), route_b])


def compare_ecmp(self, route_a, route_b):
    self.log.trace("compare_ecmp used")
    return 0


class TrackerWorker(worker.Worker, lg.LookingGlassLocalLogger):
    __metaclass__ = abc.ABCMeta

    def __init__(self, bgp_manager, worker_name,
                 compare_routes=compare_no_ecmp):

        worker.Worker.__init__(self, bgp_manager, worker_name)
        lg.LookingGlassLocalLogger.__init__(self)

        # dict: entry -> list of routes:
        self.tracked_entry_2_routes = dict()
        # dict: entry -> set of best_routes:
        self.tracked_entry_2_best_routes = dict()

        self._compare_routes = compare_routes

    @log_decorator.log
    def _on_event(self, event):
        new_route = event.route_entry
        filtered_new_route = FilteredRoute(new_route)

        entry = self.route_to_tracked_entry(new_route)

        if entry is None:
            self.log.debug("Route not mapped to a tracked entry, ignoring: %s",
                           new_route)
            return

        self.log.trace("tracked_entry for this route: %s (type: %s)",
                       TrackerWorker._display_entry(entry), type(entry))

        self._dump_state()

        all_routes = self.tracked_entry_2_routes.setdefault(entry, [])

        self.log.debug("We currently have %d route%s for this entry",
                       len(all_routes), utils.plural(all_routes))

        if event.type == engine.RouteEvent.ADVERTISE:

            withdrawn_best_routes = []

            best_routes = self.tracked_entry_2_best_routes.get(entry)

            if best_routes is None:
                self.log.trace("We had no route for this entry (%s)")
                self.tracked_entry_2_best_routes[entry] = set([new_route])
                best_routes = set()
                self._call_new_best_route(entry, filtered_new_route)
            else:
                if event.replaced_route is not None:
                    self.log.trace("Will remove replaced route from all_routes"
                                   " and best_routes: %s",
                                   event.replaced_route)
                    try:
                        all_routes.remove(event.replaced_route)
                    except ValueError:
                        # we did not have any route for this entry
                        self.log.error("replaced_route is an entry for which "
                                       "we had no route ??? (bug ?)")

                    if event.replaced_route in best_routes:
                        self.log.trace(
                            "Removing replaced_route from best_routes")
                        best_routes.remove(event.replaced_route)
                        withdrawn_best_routes.append(event.replaced_route)
                    else:
                        self.log.trace("replaced_route is not in best_routes")
                        self.log.trace("best_routes: %s", best_routes)
                else:
                    self.log.trace("No replaced route to remove")

                call_new_best_route_4_all = False
                if len(best_routes) == 0:
                    self.log.trace("All best routes have been replaced")
                    self._recompute_best_routes(all_routes, best_routes)
                    if best_routes:
                        current_best = iter(best_routes).next()
                        self.log.trace("We'll need to call new_best_route for "
                                       "all our new best routes")
                        call_new_best_route_4_all = True
                    else:
                        current_best = None
                        call_new_best_route_4_all = False
                else:
                    # (if there is more than one route in the best routes, we
                    # take the first one)
                    current_best = iter(best_routes).next()

                    self.log.trace("Current best route: %s", current_best)

                    if new_route == current_best:
                        self.log.info("New route is a route we already had, "
                                      "nothing to do.")
                        # nothing to do
                        return

                # let's find if we need to update our best routes
                if current_best:
                    route_comparison = self._compare_routes(self, new_route,
                                                            current_best)
                else:
                    route_comparison = 1

                self.log.trace("route_comparison: %d", route_comparison)

                if route_comparison > 0:
                    # new_route is a strictly better route than any current
                    # one, discard all the current best routes
                    self.log.trace("Replacing all best routes with new one")
                    withdrawn_best_routes.extend(best_routes.copy())
                    best_routes.clear()
                    best_routes.add(new_route)
                    self._call_new_best_route(entry, filtered_new_route)
                    call_new_best_route_4_all = False
                elif route_comparison == 0:
                    # new_route is as good as the current ones
                    self.log.trace("Adding new_route to best_routes...")

                    if call_new_best_route_4_all:
                        self._call_new_best_route_for_routes(entry,
                                                             best_routes)

                    if not equivalent_route_in_routes(FilteredRoute,
                                                      new_route,
                                                      best_routes):
                        best_routes.add(new_route)
                        self.log.trace("Calling self.new_best_route since we "
                                       "yet had no such route in best routes")
                        self._call_new_best_route(entry, filtered_new_route)
                    else:
                        best_routes.add(new_route)
                        self.log.trace("Not calling new_best_route since we "
                                       "had received a similar route already")
                else:
                    self.log.trace("The route is no better than current "
                                   "best ones")

                    if call_new_best_route_4_all:
                        self._call_new_best_route_for_routes(entry,
                                                             best_routes)

            self.log.trace("Considering implicitly withdrawn best routes")
            for r in withdrawn_best_routes:
                self._selective_best_route_removed(entry,
                                                   r, best_routes,
                                                   False)

            # add the route to the list of routes for this entry
            self.log.trace("Adding route to all_routes for this entry")
            all_routes.append(new_route)

        else:  # RouteEvent.WITHDRAW

            withdrawn_route = new_route

            self.log.trace("Removing route from all_routes for this entry")

            # let's update known routes for this entry
            try:
                all_routes.remove(withdrawn_route)
            except ValueError:
                # we did not have any route for this entry
                self.log.error("Withdraw received for an entry for which we "
                               "had no route ??? (not supposed to happen)")

            # let's now update best routes
            best_routes = self.tracked_entry_2_best_routes.get(entry)

            if best_routes is None:
                # we did not have any route for this entry
                self.log.error("Withdraw received for an entry for which we "
                               "had no route: not supposed to happen!")
                return

            if withdrawn_route in best_routes:
                self.log.trace("The event received is about a route which "
                               "is among the best routes for this entry")
                # remove the route from best_routes
                best_routes.remove(withdrawn_route)

                withdrawn_route_is_last = False
                if len(best_routes) == 0:
                    # we don't have any best route left...
                    self._recompute_best_routes(all_routes, best_routes)

                    if len(best_routes) > 0:
                        self._call_new_best_route_for_routes(entry,
                                                             best_routes)
                    else:
                        self.log.trace("Cleanup all_routes and best_routes")
                        withdrawn_route_is_last = True
                        del self.tracked_entry_2_best_routes[entry]
                        del self.tracked_entry_2_routes[entry]

                self._selective_best_route_removed(entry,
                                                   withdrawn_route,
                                                   best_routes,
                                                   withdrawn_route_is_last)
            else:
                self.log.trace("The event received is not related to any "
                               "of the best routes for this entry")
                # no need to update our best route list
                pass

        self.log.info("We now have %d route%s for this entry.",
                      len(all_routes), utils.plural(all_routes))

        self._dump_state()

    def _recompute_best_routes(self, all_routes, best_routes):
        '''update best_routes to contain the best routes from all_routes, based
        on _compare_routes'''

        new_best_routes = []
        for route in all_routes:
            if len(new_best_routes) == 0:
                new_best_routes = [route]
                continue

            comparison = self._compare_routes(self, route, new_best_routes[0])
            if comparison > 0:
                new_best_routes = [route]
            elif comparison == 0:
                new_best_routes.append(route)

        best_routes.clear()
        best_routes.update(new_best_routes)

        self.log.trace("Recomputed new best routes: %s", best_routes)

    @log_decorator.log
    def _selective_best_route_removed(self, entry, withdrawn_route,
                                      filtered_best_routes,
                                      withdrawn_route_is_last):
        if not equivalent_route_in_routes(FilteredRoute,
                                          withdrawn_route,
                                          filtered_best_routes):
            self._call_best_route_removed(entry,
                                          FilteredRoute(withdrawn_route),
                                          withdrawn_route_is_last)
        else:
            self.log.trace("No need to call best_route_removed: %s",
                           FilteredRoute(withdrawn_route))

    def equivalent_route_in_best_routes(self, route, function):
        # This method checks if there is in the best routes for the same
        # tracked entry as 'route', at least one route r for which function(r)
        # is equal to function(route)
        return equivalent_route_in_routes(
            function,
            route,
            self.tracked_entry_2_best_routes.get(
                self.route_to_tracked_entry(route),
                []
            )
        )

    @log_decorator.log
    def _call_new_best_route_for_routes(self, entry, routes):
        routes_no_dups = set([FilteredRoute(r) for r in routes])
        self.log.debug("   After filtering duplicates: %s", routes_no_dups)
        for route in routes_no_dups:
            self._call_new_best_route(entry, route)

    @log_decorator.log
    def _call_new_best_route(self, entry, new_route):
        try:
            self.new_best_route(entry, new_route)
        except Exception as e:
            self.log.error("Exception in <subclass>.new_best_route: %s", e)
            if self.log.isEnabledFor(logging.WARNING):
                self.log.info("%s", traceback.format_exc())

    @log_decorator.log
    def _call_best_route_removed(self, entry, old_route, last):
        try:
            self.best_route_removed(entry, old_route, last)
        except Exception as e:
            self.log.error("Exception in <subclass>.best_route_removed: %s",
                           e)
            if self.log.isEnabledFor(logging.WARNING):
                self.log.info("%s", traceback.format_exc())

    # Callbacks for subclasses ########################

    @abc.abstractmethod
    def route_to_tracked_entry(self, route):
        """
        This method is how the subclass maps a BGP route into an object that
        the TrackerWorker code will track.

        For instance, a VPN VRF is expected to keep track of IP prefixes;
        hence the route2tracked_entry code for a VRF could return the IP prefix
        in the VPNv4 route.
        The result will be that the TrackerWorker code will keep track, for a
        each prefix, of all the routes and of the best routes.
        """
        pass

    @abc.abstractmethod
    def new_best_route(self, entry, new_route):
        '''
        A new best route has been advertized for this tracked entry
        '''
        pass

    @abc.abstractmethod
    def best_route_removed(self, entry, old_route, last):
        '''
        A route that was a best route for this tracked entry has been
        removed. The 'last' flag indicates if this was the last route
        for this tracked entry.
        '''
        pass

    # Debug support methods #########

    def _dump_state(self):
        if self.log.isEnabledFor(logging.TRACE):
            self.log.trace("--- tracked_entry_2_routes ---")
            for (entry, routes) in self.tracked_entry_2_routes.iteritems():
                self.log.trace(
                    "  Entry: %s", TrackerWorker._display_entry(entry))
                for route in routes:
                    self.log.trace("    Route: %s", route)

            self.log.trace("--- tracked_entry_2_best_routes ---")
            for (entry, best_routes) in \
                    self.tracked_entry_2_best_routes.iteritems():
                self.log.trace("  Entry: %s",
                               TrackerWorker._display_entry(entry))
                for route in best_routes:
                    self.log.trace("    Route: %s", route)

            self.log.trace("--- ---")

    @staticmethod
    def _display_entry(entry):
        if (isinstance(entry, tuple) and len(entry) > 0 and
                (isinstance(entry[0], type) or
                 isinstance(entry[0], types.ClassType))):
            return repr(tuple([entry[0].__name__] + list(entry[1:])))
        else:
            return repr(entry)

    # Looking glass ###########

    def get_lg_map(self):
        return {"received_routes": (lg.SUBTREE, self.get_lg_all_routes),
                "best_routes": (lg.SUBTREE, self.get_lg_best_routes)}

    def get_lg_all_routes(self, path_prefix):
        return self._get_lg_routes(path_prefix,
                                   self.tracked_entry_2_routes)

    def get_lg_best_routes(self, path_prefix):
        return self._get_lg_routes(path_prefix,
                                   self.tracked_entry_2_best_routes)

    def _get_lg_routes(self, path_prefix, route_dict):
        '''
        route_dict is whether self.tracked_entry_2_best_routes or
        self.tracked_entry_2_routes
        '''
        routes = {}
        for entry in route_dict.iterkeys():
            entry_repr = self._display_entry(entry)
            routes[entry_repr] = [route.get_looking_glass_info(path_prefix)
                                  for route in route_dict[entry]]
        return routes
