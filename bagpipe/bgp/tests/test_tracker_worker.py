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
   TrackerWorker should call _new_best_route and/or _best_route_removed if the
   new RouteEntry changes the current list of the known best routes. The
   current list of the known best routes, which can be modified by the new
   RouteEntry, is selected thanks to the tracked_entry associated to the new
   RouteEntry. The tracked_entry is obtained thanks to _route2TrackedEntry.
   _compare_routes is used to compare 2 RouteEntry.
   Unit tests are organized as follow:
   TestA: basic tests, advertise several routes with different NLRI and same or
          different sources
   TestB: same routes (with _compare_routes) announced by different sources
   TestC: different routes (with _compare_routes) announced by different
          sources, TrackerWorker selects the best route.
   TestD: ECMP routes or same routes (with _compare_routes), same source, same
          attributes except NextHop
   TestE: different routes (with compare_routes announced by the same source
          with replaced_route not none
"""

import copy
import threading

import mock
import testtools

from bagpipe.bgp import engine
from bagpipe.bgp.engine import exa
from bagpipe.bgp.engine import worker
from bagpipe.bgp.engine import tracker_worker
from bagpipe.bgp import tests as t


def _test_compare_routes(self, route_a, route_b):
    if (route_a.nlri != route_b.nlri or
            route_a.afi != route_b.afi or
            route_a.safi != route_b.safi):
        raise Exception('Bug: compare_routes called with routes having '
                        'different nlri/afi/safi')
    else:
        if (route_a.attributes.sameValuesAs(route_b.attributes)):
            return 0
        else:
            lp_a = route_a.attributes[exa.Attribute.CODE.LOCAL_PREF].localpref
            nh_a = route_a.attributes[exa.Attribute.CODE.NEXT_HOP].top()

            lp_b = route_b.attributes[exa.Attribute.CODE.LOCAL_PREF].localpref
            nh_b = route_b.attributes[exa.Attribute.CODE.NEXT_HOP].top()

            if nh_a != nh_b and lp_a == lp_b:
                # ECMP routes
                return 0
            else:
                return cmp(lp_a, lp_b)


class TrackerWorkerThread(tracker_worker.TrackerWorker, threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self, name='TrackerWorkerThread')
        self.setDaemon(True)
        tracker_worker.TrackerWorker.__init__(
            self, mock.Mock(), 'TrackerWorker', _test_compare_routes)

    def stop(self):
        self._please_stop.set()
        self._queue.put(worker.STOP_EVENT)
        self._stopped()

    def _route_2_tracked_entry(self, route):
        return route.nlri

    # the definitions below are needed because TrackerWorker is an abstract
    # class
    def _new_best_route(self, entry, route):
        pass

    def _best_route_removed(self, entry, route, last):
        pass


class TestTrackerWorker(testtools.TestCase, t.BaseTestBagPipeBGP):

    def setUp(self):
        super(TestTrackerWorker, self).setUp()
        self.tracker_worker = TrackerWorkerThread()
        self.tracker_worker.start()
        self.set_event_target_worker(self.tracker_worker)
        self._calls = []

    def tearDown(self):
        super(TestTrackerWorker, self).tearDown()
        self.tracker_worker.stop()
        self.tracker_worker.join()

    def _check_calls(self, call_args_list, expected_list, ordered=True):
        '''
        use to check the calls to new_best_route and best_route_removed
        against a list of expected calls
        '''
        expected_list_copy = []
        # clear source field in the routes in expected calls
        # because the new_best_route and best_route_removed do not receive
        # routes with this field set
        for expected in expected_list:
            route = copy.copy(expected[1])
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

        for ((call_args, _), expected) in zip(call_args_list,
                                              expected_list_copy):
            self.assertEquals(expected[0], call_args[0], 'Bad prefix')

            observed_route_entry = call_args[1]
            expected_route_entry = expected[1]
            self.assertEquals(expected_route_entry, observed_route_entry,
                              "bad route Entry")

            if len(expected) >= 3:
                self.assertEquals(expected[2], call_args[2],
                                  "wrong 'last' flag")

    def _call_list(self, method):
        def side_effect(*args, **kwargs):
            self._append_call(method)
        return side_effect

    def test_a1_different_nlri_same_source(self):
        # A source A advertises and withdraws routes for different NLRI.
        # Mock objects
        self.tracker_worker._new_best_route = mock.Mock()
        self.tracker_worker._best_route_removed = mock.Mock()

        # Only 1 source A
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        # Source A advertises a route for NLRI1
        route_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A advertises a route for NLRI2
        route_nlri2a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI2, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A withdraws the route for NLRI1
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A withdraws the route for NLRI2
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI2, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        self.assertEqual(2, self.tracker_worker._new_best_route.call_count,
                         '2 new best routes: 1 for NLRI1 and 1 for NLRI2')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route_nlri1a.route_entry),
                           (t.NLRI2, route_nlri2a.route_entry)])
        self.assertEqual(2, self.tracker_worker._best_route_removed.call_count,
                         '2 old routes removed: 1 for NLRI1 and 1 for NLRI2')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route_nlri1a.route_entry, True),
             (t.NLRI2, route_nlri2a.route_entry, True)])

    def test_a2_different_nlri_different_source(self):
        # 2 sources A and B advertise and withdraw routes for different NLRI.
        # Mock objects
        self.tracker_worker._new_best_route = mock.Mock()
        self.tracker_worker._best_route_removed = mock.Mock()

        # 2 sources: A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')
        # Source A advertises a route for NLRI1
        route_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source B advertises a route for NLRI2
        route_nlri2B = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI2, [t.RT1, t.RT2],
            worker_b, t.NH1, 100)
        # Source A withdraws the route for NLRI1
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source B withdraws the route for NLRI2
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI2, [t.RT1, t.RT2],
            worker_b, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        self.assertEqual(2, self.tracker_worker._new_best_route.call_count,
                         '2 new_best_route calls: 1 for NLRI1 and 1 for NLRI2')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route_nlri1a.route_entry),
                           (t.NLRI2, route_nlri2B.route_entry)])
        self.assertEqual(2, self.tracker_worker._best_route_removed.call_count,
                         '2 best_route_removed calls: 1 for NLRI1 and 1 for '
                         'NLRI2')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route_nlri1a.route_entry, True),
             (t.NLRI2, route_nlri2B.route_entry, True)])

    def test_a3_same_nlri_same_source(self):
        # A source A advertises the same route for the same NLRI
        # Mock objects
        self.tracker_worker._new_best_route = mock.Mock()
        self.tracker_worker._best_route_removed = mock.Mock()

        # 1 source: A
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        # Source A advertises a route for NLRI1
        route_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A advertises the same route for NLRI1
        self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        self.assertEqual(1, self.tracker_worker._new_best_route.call_count,
                         'expected 1 new_best_route call for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route_nlri1a.route_entry),
                           (t.NLRI1, route_nlri1a.route_entry)])

    def test_a4_withdraw_nlri_not_known(self):
        # A source A withdraws a route that does not exist.
        self.tracker_worker._new_best_route = mock.Mock()
        self.tracker_worker._best_route_removed = mock.Mock()

        # 1 source: A
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        # Source A withdraws a route for NLRI1 which is not known by
        # tracker_worker
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)

        # Check calls to _new_best_route and _best_route_removed
        self.assertEqual(0, self.tracker_worker._new_best_route.call_count,
                         'new_best_route should not have been called')
        self.assertEqual(0, self.tracker_worker._best_route_removed.call_count,
                         'best_route_removed should not have been called')

    def test_b1_is_the_current_best_route(self):
        # The route which is advertised by another source is the current best
        # route
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 2 sources: A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')

        # Source A advertises a route for NLRI1
        self._append_call("RE1")
        route_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source B advertises the same route for NLRI1
        self._append_call("RE2")
        route_nlri1B = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 100)
        # Source A withdraws the route for NLRI1
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source B withdraws the route for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        self.assertEqual(
            1, self.tracker_worker._new_best_route.call_count,
            '1 new best route call for NLRI1')
        self._check_calls(
            self.tracker_worker._new_best_route.call_args_list,
            [(t.NLRI1, route_nlri1a.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route_nlri1B.route_entry, True)])

        expected_calls = ["RE1", t.NBR, "RE2", "RE3", "RE4", t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

    def test_b2_is_not_the_current_best_route(self):
        # The route which is advertised by an other source is not the current
        # best route but will become the best route
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 3 sources: A, B and C
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')
        worker_c = worker.Worker(mock.Mock(), 'worker.Worker-C')

        # Source A advertises route1 for NLRI1
        self._append_call("RE1")
        route1Nlri1 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2Nlri1 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_c, t.NH1, 200)
        # Source A withdraws route1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3", "RE4", t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new best route call for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1Nlri1.route_entry),
                           (t.NLRI1, route2Nlri1.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1Nlri1.route_entry, False)])

    def test_c1_route1_best_route(self):
        # Route1 is the best route
        # Mock objects
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 2 sources : A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises a route2 for NLRI1 with different attributes.
        # Route1 is better than Route2
        self._append_call("RE2")
        route2_nlri1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3",
                          t.NBR, t.BRR, "RE4", t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nlri1b.route_entry)])
        self.assertEqual(
            2, self.tracker_worker._best_route_removed.call_count,
            '2 best_route_removed calls for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False),
             (t.NLRI1, route2_nlri1b.route_entry, True)])

    def test_c2_route2_best_route(self):
        # Route2 is the best route
        # Mock objects
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 2 sources: A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source B advertises a route2 for NLRI1. Route2 is better than Route1
        self._append_call("RE2")
        route2_nlri1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", t.NBR, t.BRR, "RE3"]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nlri1b.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False)])

    def test_c3_select_new_best_route_among_several(self):
        # When current best route is withdrawn, the new best route should be
        # selected among several routes
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 3 sources: A, B and C
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')
        worker_c = worker.Worker(mock.Mock(), 'worker.Worker-C')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises a route2 for NLRI1. Route1 is better than Route2
        self._append_call("RE2")
        route2_nlri1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source C advertises a route3 for NLRI1. Route2 is better than Route3
        self._append_call("RE3")
        route3_nlri1c = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_c, t.NH1, 100)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE5")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source C withdraws route3 for NLRI1
        self._append_call("RE6")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_c, t.NH1, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3",
                          "RE4", t.NBR, t.BRR, "RE5",
                          t.NBR, t.BRR, "RE6", t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            3, self.tracker_worker._new_best_route.call_count,
            '3 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nlri1b.route_entry),
                           (t.NLRI1, route3_nlri1c.route_entry)])
        self.assertEqual(
            3, self.tracker_worker._best_route_removed.call_count,
            '3 best_route_removed calls for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False),
             (t.NLRI1, route2_nlri1b.route_entry, False),
             (t.NLRI1, route3_nlri1c.route_entry, True)])

    def test_d1_ecmp_routes(self):
        # ECMP routes are routes advertised by the same worker with the same
        # LP and different NH
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 1 source: A
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A advertises a route2 for NLRI1. route2 is equal to route1
        # with compare_routes, but the next_hop are different
        self._append_call("RE2")
        route2_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH2, 100)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100)
        # Source A withdraws route2 for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH2, 100)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", t.NBR,
                          "RE3", t.BRR, "RE4", t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nlri1a.route_entry)])
        self.assertEqual(
            2, self.tracker_worker._best_route_removed.call_count,
            '2 best_route_removed calls for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False),
             (t.NLRI1, route2_nlri1a.route_entry, True)])

    def test_e1_replace_br_is_nbr(self):
        # Advertise a route that replaces the best route and becomes the new
        # best route
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 1 source: A
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 200)
        # Source A advertises a route2 for NLRI1. Route1 is better than Route2
        # BUT Route2 replaces Route1
        self._append_call("RE2")
        route2_nrli1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100, route1_nlri1a.route_entry)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nrli1a.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False)])

    def test_e2_replace_br_is_not_nbr(self):
        # Advertise a route that replaces the best route but does not become
        # the new best route
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 2 sources : A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises a route2. Route1 is better than Route2
        self._append_call("RE2")
        route2_nrli1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source A advertises a route3 for NLRI1. Route3 replaces Route1.
        # Route2 is better than route3.
        self._append_call("RE3")
        route3_nrli1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 100, route1_nlri1a.route_entry)
        # Source B withdraws route2 for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3", t.NBR,
                          t.BRR, "RE4", t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            3, self.tracker_worker._new_best_route.call_count,
            '3 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route2_nrli1b.route_entry),
                           (t.NLRI1, route3_nrli1a.route_entry)])
        self.assertEqual(
            2, self.tracker_worker._best_route_removed.call_count,
            '2 best_route_removed calls for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False),
             (t.NLRI1, route2_nrli1b.route_entry, False)])

    def test_e3_replace_br_is_not_nbr(self):
        # Advertise a route that replaces the best route but does not become
        # the new best route
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 3 sources: A, B and C
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')
        worker_c = worker.Worker(mock.Mock(), 'worker.Worker-C')

        # Source A advertises route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2_nlri1 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_c, t.NH1, 200)
        # Source A advertises route3 which replaces route1
        self._append_call("RE4")
        self._new_route_event(engine.RouteEvent.ADVERTISE, t.NLRI1,
                              [t.RT1, t.RT2], worker_a, t.NH1, 100,
                              route1_nlri1.route_entry)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3", "RE4", t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new best route call for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1.route_entry),
                           (t.NLRI1, route2_nlri1.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1.route_entry)])

    def test_e4_not_replace_br(self):
        # Advertise a route that does not replaces the best route and becomes
        # the new best route when the best route is withdrawn
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 2 sources : A and B
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')

        # Source A advertises a route1 for NLRI1
        self._append_call("RE1")
        route1_nlri1a = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)
        # Source B advertises a route2. Route1 is better than Route2
        self._append_call("RE2")
        route2_nlri1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source B advertises a route3 for NLRI1. Route3 replaces Route2.
        # Route1 is better than Route3
        self._append_call("RE3")
        route3_nlri1b = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 100, route2_nlri1b.route_entry)
        # Source A withdraws route1 for NLRI1
        self._append_call("RE4")
        self._new_route_event(
            engine.RouteEvent.WITHDRAW, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = ["RE1", t.NBR, "RE2", "RE3", "RE4", t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self.assertEqual(
            2, self.tracker_worker._new_best_route.call_count,
            '2 new new_best_route calls for NLRI1')
        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route1_nlri1a.route_entry),
                           (t.NLRI1, route3_nlri1b.route_entry)])
        self.assertEqual(
            1, self.tracker_worker._best_route_removed.call_count,
            '1 best_route_removed call for NLRI1')
        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1_nlri1a.route_entry, False)])

    def test_e5_replace_br_is_nbr_equal(self):
        # Same as E3, but the route that replaces our current best compares
        # equally to the two initially less preferred routes, and becomes best
        # route with them
        self.tracker_worker._new_best_route = mock.Mock(
            side_effect=self._call_list(t.NBR))
        self.tracker_worker._best_route_removed = mock.Mock(
            side_effect=self._call_list(t.BRR))

        # 3 sources: A, B and C
        worker_a = worker.Worker(mock.Mock(), 'worker.Worker-A')
        worker_b = worker.Worker(mock.Mock(), 'worker.Worker-B')
        worker_c = worker.Worker(mock.Mock(), 'worker.Worker-C')

        # Source A advertises route1 for NLRI1
        route1 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_a, t.NH1, 300)

        # We will only check events after this first one
        # to allow for a order-independent test after RE4
        del self.tracker_worker._new_best_route.call_args_list[:]

        # Source B advertises route2 for NLRI1 : route1 is better than route2
        self._append_call("RE2")
        route2 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_b, t.NH1, 200)
        # Source C advertises also route2
        self._append_call("RE3")
        route3 = self._new_route_event(
            engine.RouteEvent.ADVERTISE, t.NLRI1, [t.RT1, t.RT2],
            worker_c, t.NH2, 200)
        # Source A advertises route3 which replaces route1
        self._append_call("RE4")
        route4 = self._new_route_event(engine.RouteEvent.ADVERTISE,
                                       t.NLRI1, [t.RT1, t.RT2],
                                       worker_a, t.NH3, 200,
                                       route1.route_entry)

        # Check calls and arguments list to _new_best_route and
        # _best_route_removed
        expected_calls = [t.NBR, "RE2", "RE3", "RE4",
                          t.NBR, t.NBR, t.NBR, t.BRR]
        self.assertEqual(expected_calls, self._calls, 'Wrong call sequence')

        self._check_calls(self.tracker_worker._new_best_route.call_args_list,
                          [(t.NLRI1, route2.route_entry),
                           (t.NLRI1, route3.route_entry),
                           (t.NLRI1, route4.route_entry)], False)

        self._check_calls(
            self.tracker_worker._best_route_removed.call_args_list,
            [(t.NLRI1, route1.route_entry, False)])
