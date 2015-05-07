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
"""

.. module:: test_tracker_worker
   :synopsis: a module that defines several test cases for the tracker_worker
              module.
   In particular, unit tests for TrackerWorker class.
   Setup: Run TrackerWorker instance.
   TearDown: Stop TrackerWorker instance.
   TrackerWorker is in charge to receive RouteEvent from RouteTableManager.
   A RouteEvent contains an event type ADVERTIZE or WITHDRAW, and a RouteEntry.
   TrackerWorker should call _newBestRoute and/or _bestRouteRemoved if the new
   RouteEntry changes the current list of the known best routes. The current
   list of the known best routes, which can be modified by the new RouteEntry,
   is selected thanks to the trackedEntry associated to the new RouteEntry.
   The trackedEntry is obtained thanks to _route2TrackedEntry.
   _compareRoutes is used to compare 2 RouteEntry.
   Unit tests are organized as follow:
   TestA: basic tests, advertise several routes with different NLRI and same or
          different sources
   TestB: same routes (with _compareRoutes) announced by different sources
   TestC: different routes (with _compareRoutes) announced by different
          sources, TrackerWorker selects the best route.
   TestD: ECMP routes or same routes (with _compareRoutes), same source, same
          attributes except NextHop
   TestE: different routes (with compareRoutes announced by the same source
          with replacedRoute not none
"""
import mock

from copy import copy

from testtools import TestCase
from threading import Thread

from bagpipe.bgp.tests import BaseTestBagPipeBGP, RT1, RT2, NLRI1, NLRI2, \
    NH1, NH2, NH3, NBR, BRR
from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine.tracker_worker import TrackerWorker
from exabgp.bgp.message.update.attribute.attribute import Attribute

import logging

log = logging.getLogger()


def _test_compareRoutes(self, routeA, routeB):
    if (routeA.nlri != routeB.nlri or
            routeA.afi != routeB.afi or
            routeA.safi != routeB.safi):
        raise Exception('Bug: compareRoutes called with routes having '
                        'different nlri/afi/safi')
    else:
        if (routeA.attributes.sameValuesAs(routeB.attributes)):
            return 0
        else:
            lpA = routeA.attributes[Attribute.CODE.LOCAL_PREF].localpref
            nhA = routeA.attributes[Attribute.CODE.NEXT_HOP].ip

            lpB = routeB.attributes[Attribute.CODE.LOCAL_PREF].localpref
            nhB = routeB.attributes[Attribute.CODE.NEXT_HOP].ip

            if nhA != nhB and lpA == lpB:
                # ECMP routes
                return 0
            else:
                return cmp(lpA, lpB)


class TrackerWorkerThread(TrackerWorker, Thread):

    def __init__(self):
        Thread.__init__(self, name='TrackerWorkerThread')
        self.setDaemon(True)
        TrackerWorker.__init__(
            self, mock.Mock(), 'TrackerWorker', _test_compareRoutes)

    def stop(self):
        self._pleaseStop.set()
        self._queue.put(self.stopEvent)
        self._stopped()

    def _route2trackedEntry(self, route):
        return route.nlri

    # the definitions below are needed because TrackerWorker is an abstract
    # class
    def _newBestRoute(self, entry, route):
        pass

    def _bestRouteRemoved(self, entry, route, last):
        pass


class TestTrackerWorker(TestCase, BaseTestBagPipeBGP):

    def setUp(self):
        super(TestTrackerWorker, self).setUp()
        self.trackerWorker = TrackerWorkerThread()
        self.trackerWorker.start()
        self.setEventTargetWorker(self.trackerWorker)
        self._calls = []

    def tearDown(self):
        super(TestTrackerWorker, self).tearDown()
        self.trackerWorker.stop()
        self.trackerWorker.join()

    def _checkCalls(self, call_args_list, expected_list, ordered=True):
        '''
        use to check the calls to newBestRoute and bestRouteRemoved
        against a list of expected calls
        '''
        expected_list_copy = []
        # clear source field in the routes in expected calls
        # because the newBestRoute and bestRouteRemoved do not receive
        # routes with this field set
        for expected in expected_list:
            route = copy(expected[1])
            route.source = None
            if len(expected) == 2:
                expected_list_copy.append((expected[0], route))
            elif len(expected) == 3:
                expected_list_copy.append((expected[0], route, expected[2]))
            else:
                assert(False)

        if not ordered:
            expected_list_copy = sorted(expected_list_copy,
                                        lambda a, b: cmp(repr(a), repr(b)))
            call_args_list = sorted(call_args_list,
                                    lambda a, b: cmp(repr(a[0]), repr(b[0])))

        for ((callArgs, _), expected) in zip(call_args_list,
                                             expected_list_copy):
            self.assertEquals(expected[0], callArgs[0], 'Bad prefix')

            observedRouteEntry = callArgs[1]
            expectedRouteEntry = expected[1]
            self.assertEquals(expectedRouteEntry, observedRouteEntry,
                              "bad route Entry")

            if len(expected) >= 3:
                self.assertEquals(expected[2], callArgs[2],
                                  "wrong 'last' flag")

    def _callList(self, method):
        def side_effect(*args, **kwargs):
            self._append_call(method)
        return side_effect

    def testA1_differentNLRISameSource(self):
        # A source A advertises and withdraws routes for different NLRI.
        # Mock objects
        self.trackerWorker._newBestRoute = mock.Mock()
        self.trackerWorker._bestRouteRemoved = mock.Mock()

        # Only 1 source A
        workerA = Worker(mock.Mock(), 'Worker-A')
        # Source A advertises a route for NLRI1
        routeNlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source A advertises a route for NLRI2
        routeNlri2A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI2, [RT1, RT2], workerA, NH1, 100)
        # Source A withdraws the route for NLRI1
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source A withdraws the route for NLRI2
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI2, [RT1, RT2], workerA, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        self.assertEqual(2, self.trackerWorker._newBestRoute.call_count,
                         '2 new best routes: 1 for NLRI1 and 1 for NLRI2')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, routeNlri1A.routeEntry),
                          (NLRI2, routeNlri2A.routeEntry)])
        self.assertEqual(2, self.trackerWorker._bestRouteRemoved.call_count,
                         '2 old routes removed: 1 for NLRI1 and 1 for NLRI2')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, routeNlri1A.routeEntry, True),
             (NLRI2, routeNlri2A.routeEntry, True)])

    def testA2_differentNLRIDifferentSource(self):
        # 2 sources A and B advertise and withdraw routes for different NLRI.
        # Mock objects
        self.trackerWorker._newBestRoute = mock.Mock()
        self.trackerWorker._bestRouteRemoved = mock.Mock()

        # 2 sources: A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')
        # Source A advertises a route for NLRI1
        routeNlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source B advertises a route for NLRI2
        routeNlri2B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI2, [RT1, RT2], workerB, NH1, 100)
        # Source A withdraws the route for NLRI1
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source B withdraws the route for NLRI2
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI2, [RT1, RT2], workerB, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        self.assertEqual(2, self.trackerWorker._newBestRoute.call_count,
                         '2 newBestRoute calls: 1 for NLRI1 and 1 for NLRI2')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, routeNlri1A.routeEntry),
                          (NLRI2, routeNlri2B.routeEntry)])
        self.assertEqual(2, self.trackerWorker._bestRouteRemoved.call_count,
                         '2 bestRouteRemoved calls: 1 for NLRI1 and 1 for '
                         'NLRI2')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, routeNlri1A.routeEntry, True),
             (NLRI2, routeNlri2B.routeEntry, True)])

    def testA3_sameNLRISameSource(self):
        # A source A advertises the same route for the same NLRI
        # Mock objects
        self.trackerWorker._newBestRoute = mock.Mock()
        self.trackerWorker._bestRouteRemoved = mock.Mock()

        # 1 source: A
        workerA = Worker(mock.Mock(), 'Worker-A')
        # Source A advertises a route for NLRI1
        routeNlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source A advertises the same route for NLRI1
        self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        self.assertEqual(1, self.trackerWorker._newBestRoute.call_count,
                         'expected 1 newBestRoute call for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, routeNlri1A.routeEntry),
                          (NLRI1, routeNlri1A.routeEntry)])

    def testA4_withdrawNLRINotKnown(self):
        # A source A withdraws a route that does not exist.
        self.trackerWorker._newBestRoute = mock.Mock()
        self.trackerWorker._bestRouteRemoved = mock.Mock()

        # 1 source: A
        workerA = Worker(mock.Mock(), 'Worker-A')
        # Source A withdraws a route for NLRI1 which is not known by
        # trackerWorker
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)

        # Check calls to _newBestRoute and _bestRouteRemoved
        self.assertEqual(0, self.trackerWorker._newBestRoute.call_count,
                         'newBestRoute should not have been called')
        self.assertEqual(0, self.trackerWorker._bestRouteRemoved.call_count,
                         'bestRouteRemoved should not have been called')

    def testB1_isTheCurrentBestRoute(self):
        # The route which is advertised by another source is the current best
        # route
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 2 sources: A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')

        # Source A advertises a route for NLRI1
        self._append_call("RE1")
        routeNlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source B advertises the same route for NLRI1
        self._append_call("RE2")
        routeNlri1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 100)
        # Source A withdraws the route for NLRI1
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source B withdraws the route for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerB, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        self.assertEqual(
            1, self.trackerWorker._newBestRoute.call_count,
            '1 new best route call for NLRI1')
        self._checkCalls(
            self.trackerWorker._newBestRoute.call_args_list,
            [(NLRI1, routeNlri1A.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, routeNlri1B.routeEntry, True)])

        expectedCalls = ["RE1", NBR, "RE2", "RE3", "RE4", BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

    def testB2_isNotTheCurrentBestRoute(self):
        # The route which is advertised by an other source is not the current
        # best route but will become the best route
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 3 sources: A, B and C
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')
        workerC = Worker(mock.Mock(), 'Worker-C')

        # Source A advertises route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2Nlri1 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerC, NH1, 200)
        # Source A withdraws route1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 300)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3", "RE4", NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new best route call for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1.routeEntry),
                          (NLRI1, route2Nlri1.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1.routeEntry, False)])

    def testC1_route1BestRoute(self):
        # Route1 is the best route
        # Mock objects
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 2 sources : A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises a route2 for NLRI1 with different attributes.
        # Route1 is better than Route2
        self._append_call("RE2")
        route2Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerB, NH1, 200)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3", NBR, BRR, "RE4", BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1B.routeEntry)])
        self.assertEqual(
            2, self.trackerWorker._bestRouteRemoved.call_count,
            '2 bestRouteRemoved calls for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False),
             (NLRI1, route2Nrli1B.routeEntry, True)])

    def testC2_route2BestRoute(self):
        # Route2 is the best route
        # Mock objects
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 2 sources: A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source B advertises a route2 for NLRI1. Route2 is better than Route1
        self._append_call("RE2")
        route2Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", NBR, BRR, "RE3"]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1B.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False)])

    def testC3_selectNewBestRouteAmongSeveral(self):
        # When current best route is withdrawn, the new best route should be
        # selected among several routes
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 3 sources: A, B and C
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')
        workerC = Worker(mock.Mock(), 'Worker-C')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises a route2 for NLRI1. Route1 is better than Route2
        self._append_call("RE2")
        route2Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source C advertises a route3 for NLRI1. Route2 is better than Route3
        self._append_call("RE3")
        route3Nrli1C = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerC, NH1, 100)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE5")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source C withdraws route3 for NLRI1
        self._append_call("RE6")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerC, NH1, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3",
                         "RE4", NBR, BRR, "RE5", NBR, BRR, "RE6", BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            3, self.trackerWorker._newBestRoute.call_count,
            '3 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1B.routeEntry),
                             (NLRI1, route3Nrli1C.routeEntry)])
        self.assertEqual(
            3, self.trackerWorker._bestRouteRemoved.call_count,
            '3 bestRouteRemoved calls for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False),
             (NLRI1, route2Nrli1B.routeEntry, False),
             (NLRI1, route3Nrli1C.routeEntry, True)])

    def testD1_ECMPRoutes(self):
        # ECMP routes are routes advertised by the same worker with the same
        # LP and different NH
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 1 source: A
        workerA = Worker(mock.Mock(), 'Worker-A')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source A advertises a route2 for NLRI1. route2 is equal to route1
        # with compareRoutes, but the next_hop are different
        self._append_call("RE2")
        route2Nrli1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH2, 100)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 100)
        # Source A withdraws route2 for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH2, 100)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", NBR, "RE3", BRR, "RE4", BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1A.routeEntry)])
        self.assertEqual(
            2, self.trackerWorker._bestRouteRemoved.call_count,
            '2 bestRouteRemoved calls for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False),
             (NLRI1, route2Nrli1A.routeEntry, True)])

    def testE1_replaceBRisNBR(self):
        # Advertise a route that replaces the best route and becomes the new
        # best route
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 1 source: A
        workerA = Worker(mock.Mock(), 'Worker-A')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 200)
        # Source A advertises a route2 for NLRI1. Route1 is better than Route2
        # BUT Route2 replaces Route1
        self._append_call("RE2")
        route2Nrli1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2],
            workerA, NH1, 100, route1Nlri1A.routeEntry)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1A.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False)])

    def testE2_replaceBRisNotNBR(self):
        # Advertise a route that replaces the best route but does not become
        # the new best route
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 2 sources : A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises a route2. Route1 is better than Route2
        self._append_call("RE2")
        route2Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source A advertises a route3 for NLRI1. Route3 replaces Route1.
        # Route2 is better than route3.
        self._append_call("RE3")
        route3Nrli1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2],
            workerA, NH1, 100, route1Nlri1A.routeEntry)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerB, NH1, 200)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3", NBR, BRR, "RE4", NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            3, self.trackerWorker._newBestRoute.call_count,
            '3 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route2Nrli1B.routeEntry),
                             (NLRI1, route3Nrli1A.routeEntry)])
        self.assertEqual(
            2, self.trackerWorker._bestRouteRemoved.call_count,
            '2 bestRouteRemoved calls for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False),
             (NLRI1, route2Nrli1B.routeEntry, False)])

    def testE3_replaceBRisNotNBR(self):
        # Advertise a route that replaces the best route but does not become
        # the new best route
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 3 sources: A, B and C
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')
        workerC = Worker(mock.Mock(), 'Worker-C')

        # Source A advertises route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2Nlri1 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerC, NH1, 200)
        # Source A advertises route3 which replaces route1
        self._append_call("RE4")
        self._newRouteEvent(RouteEvent.ADVERTISE, NLRI1, [RT1, RT2],
                            workerA, NH1, 100, route1Nlri1.routeEntry)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3", "RE4", NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new best route call for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1.routeEntry),
                          (NLRI1, route2Nlri1.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1.routeEntry)])

    def testE4_notReplaceBR(self):
        # Advertise a route that does not replaces the best route and becomes
        # the new best route when the best route is withdrawn
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 2 sources : A and B
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1A = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)
        # Source B advertises a route2. Route1 is better than Route2
        self._append_call("RE2")
        route2Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source B advertises a route3 for NLRI1. Route3 replaces Route2.
        # Route1 is better than Route3
        self._append_call("RE3")
        route3Nrli1B = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2],
            workerB, NH1, 100, route2Nrli1B.routeEntry)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE4")
        self._newRouteEvent(
            RouteEvent.WITHDRAW, NLRI1, [RT1, RT2], workerA, NH1, 300)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = ["RE1", NBR, "RE2", "RE3", "RE4", NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.trackerWorker._newBestRoute.call_count,
            '2 new newBestRoute calls for NLRI1')
        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route1Nlri1A.routeEntry),
                          (NLRI1, route3Nrli1B.routeEntry)])
        self.assertEqual(
            1, self.trackerWorker._bestRouteRemoved.call_count,
            '1 bestRouteRemoved call for NLRI1')
        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1Nlri1A.routeEntry, False)])

    def testE5_replaceBRisNBREqual(self):
        # Same as E3, but the route that replaces our current best compares
        # equally to the two initially less preferred routes, and becomes best
        # route with them
        self.trackerWorker._newBestRoute = mock.Mock(
            side_effect=self._callList(NBR))
        self.trackerWorker._bestRouteRemoved = mock.Mock(
            side_effect=self._callList(BRR))

        # 3 sources: A, B and C
        workerA = Worker(mock.Mock(), 'Worker-A')
        workerB = Worker(mock.Mock(), 'Worker-B')
        workerC = Worker(mock.Mock(), 'Worker-C')

        # Source A advertises route1 for NLRI1
        route1 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerA, NH1, 300)

        # We will only check events after this first one
        # to allow for a order-independent test after RE4
        del self.trackerWorker._newBestRoute.call_args_list[:]

        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerB, NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        route3 = self._newRouteEvent(
            RouteEvent.ADVERTISE, NLRI1, [RT1, RT2], workerC, NH2, 200)
        # Source A advertises route3 which replaces route1
        self._append_call("RE4")
        route4 = self._newRouteEvent(RouteEvent.ADVERTISE, NLRI1, [RT1, RT2],
                                     workerA, NH3, 200, route1.routeEntry)

        # Check calls and arguments list to _newBestRoute and _bestRouteRemoved
        expectedCalls = [NBR, "RE2", "RE3", "RE4", NBR, NBR, NBR, BRR]
        self.assertEqual(expectedCalls, self._calls, 'Wrong call sequence')

        self._checkCalls(self.trackerWorker._newBestRoute.call_args_list,
                         [(NLRI1, route2.routeEntry),
                          (NLRI1, route3.routeEntry),
                          (NLRI1, route4.routeEntry)], False)

        self._checkCalls(
            self.trackerWorker._bestRouteRemoved.call_args_list,
            [(NLRI1, route1.routeEntry, False)])
