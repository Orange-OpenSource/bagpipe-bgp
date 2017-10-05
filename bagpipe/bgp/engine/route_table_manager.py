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

import collections
import Queue
import threading
import traceback

from oslo_log import log as logging

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp import engine
from bagpipe.bgp.engine import exa
from bagpipe.bgp.engine import worker as worker_m
from bagpipe.bgp.engine import bgp_peer_worker


LOG = logging.getLogger(__name__)


class Match(object):

    def __init__(self, afi, safi, route_target):
        assert route_target is None or isinstance(route_target,
                                                  exa.RouteTarget)
        self.afi = afi
        self.safi = safi
        self.route_target = route_target

    def __hash__(self):
        # FIXME, could use a tuple, but RT not yet hashable
        # return hash((self.afi, self.safi, self.route_target))
        return hash(str(self))

    def __repr__(self):
        return "match:%s" % str(self)

    def __str__(self):
        return "%s/%s,%s" % (self.afi or "*", self.safi or "*",
                             self.route_target or "*")

    def __cmp__(self, other):
        assert isinstance(other, Match)

        self_afi = self.afi or engine.Subscription.ANY_AFI
        self_safi = self.safi or engine.Subscription.ANY_SAFI
        self_rt = self.route_target or exa.RouteTarget(0, 0)

        other_afi = other.afi or engine.Subscription.ANY_AFI
        other_safi = other.safi or engine.Subscription.ANY_SAFI
        other_rt = other.route_target or exa.RouteTarget(0, 0)

        val = cmp((self_afi, self_safi, str(self_rt)),
                  (other_afi, other_safi, str(other_rt)))

        return val


MATCH_ANY = Match(engine.Subscription.ANY_AFI,
                  engine.Subscription.ANY_SAFI,
                  engine.Subscription.ANY_RT)


def matches_for(afi, safi, route_targets):
    # generate all possible match entries for this afi/safi
    # and these routetargets, with all possible wildcards
    #
    # There are 4*(n+1) possible Match object (for n route_targets)
    for _afi in (engine.Subscription.ANY_AFI, afi):
        for _safi in (engine.Subscription.ANY_SAFI, safi):
            yield Match(_afi, _safi, None)
            if route_targets is not None:
                for rt in route_targets:
                    yield Match(_afi, _safi, rt)


class WorkersAndEntries(object):

    def __init__(self):
        self.workers = set()
        self.entries = set()
        self.n_local_workers = 0

    def __repr__(self):
        return "workers: %s\nentries: %s" % (self.workers,
                                             self.entries)

    def add_worker(self, worker):
        """ returns True iif first local worker """
        self.workers.add(worker)
        if not isinstance(worker, bgp_peer_worker.BGPPeerWorker):
            self.n_local_workers += 1
            return self.n_local_workers == 1

    def del_worker(self, worker):
        """ returns True iif last local worker """
        self.workers.remove(worker)
        if not isinstance(worker, bgp_peer_worker.BGPPeerWorker):
            self.n_local_workers -= 1
            return self.n_local_workers == 0

    def is_empty(self):
        return (len(self.workers) == 0 and
                len(self.entries) == 0)


STOP_EVENT = "STOP_EVENT"


def test_should_dispatch(route_event, target_worker):
    '''
    returns a (boolean,string) tuple
    the string contains the reason why the route_event should not be
    dispatched to target_worker
    '''
    if route_event.source == target_worker:
        return (False, "not dispatching an update back to its source")
    elif (isinstance(route_event.source, bgp_peer_worker.BGPPeerWorker) and
          isinstance(target_worker, bgp_peer_worker.BGPPeerWorker)):
        return (False, "do not dispatch a route between BGP peers")
    else:
        return (True, "")


class RouteTableManager(threading.Thread, lg.LookingGlassMixin):

    """
    This singleton class will dispatch events between Workers.
    Events relates to BGP routes that are announced or withdrawn by workers.
    Workers subscribe to events by indicating AFI, SAFI, Route Targets in which
    they are interested.
    There can be workers responsible for handling services locally (e.g. a VPN
    instance) and workers that are BGP peers.

    Though sources of routes are typically Workers, they don't need to be; any
    class can source a route.
    """

    def __init__(self, first_local_subscriber_cb, last_local_subscriber_cb):
        threading.Thread.__init__(self, name="RouteTableManager")
        self.setDaemon(True)

        # keys are Matches, values are WorkersAndEntries objects:
        self._match_2_workers_entries = (
            collections.defaultdict(WorkersAndEntries))

        # workers known to us
        # name -> worker dict
        self._workers = {}

        # keys are (source,nlri) tuples, values are Entry objects:
        self._source_nlri_2_entry = {}

        self.first_local_subscriber_callback = first_local_subscriber_cb
        self.last_local_subscriber_callback = last_local_subscriber_cb

        self._queue = Queue.Queue()

    @log_decorator.log_info
    def stop(self):
        self.enqueue(STOP_EVENT)

    def run(self):
        while True:
            LOG.debug("RouteTableManager waiting on queue")
            event = self._queue.get()
            if event == STOP_EVENT:
                LOG.info("STOP_EVENT => breaking main loop")
                break
            else:
                self._on_event(event)
            LOG.debug("RouteTableManager queue size: %d", self._queue.qsize())

        LOG.info("Out of main loop")

    @log_decorator.log_info
    def _on_event(self, event):
        try:
            if event.__class__ == engine.RouteEvent:
                self._receive_route_event(event)
            elif event.__class__ == engine.Subscription:
                self._worker_subscribes(event)
            elif event.__class__ == engine.Unsubscription:
                self._worker_unsubscribes(event)
            elif event.__class__ == engine.WorkerCleanupEvent:
                self._worker_cleanup(event.worker)
            else:
                raise Exception("unknown event: %s", event)
        except Exception as e:
            LOG.error("Exception during processing of event: %s", repr(e))
            LOG.error("%s", traceback.format_exc())
            LOG.error("    event was: %s", event)

    def enqueue(self, event):
        self._queue.put(event)

    def _check_match_2_workers_and_entries_cleanup(self, match):
        wa = self._match_2_workers_entries.get(match)
        if wa is None:
            LOG.warning("why are we here ?")
            # nothing to cleanup
            return
        else:
            if wa.is_empty():
                del self._match_2_workers_entries[match]

    def callback_first_local_subscriber(self, sub):
        if self.first_local_subscriber_callback:
            LOG.debug("first local subscriber callback for %s ...", sub)
            self.first_local_subscriber_callback(sub)

    def callback_last_local_subscriber(self, sub):
        if self.last_local_subscriber_callback:
            LOG.debug("last local subscriber callback for %s ...", sub)
            self.last_local_subscriber_callback(sub)

    def _worker_subscribes(self, sub):
        # TODO: this function currently will not consider whether or not
        # is already subscribed to set of route events, before considering
        # a subscription.  In particular, multiple identical subscriptions
        # will lead to this code re-synthesizing events at each call.
        #
        # Ideally, the code should detect that the worker is already subscribed
        # and skip the subscription.

        assert isinstance(sub.worker, worker_m.Worker)
        LOG.info("workerSubscribes: %s", sub)

        worker = sub.worker

        self._workers[worker.name] = worker

        match = Match(sub.afi, sub.safi, sub.route_target)

        wa = self._match_2_workers_entries[match]

        # update match2worker
        if wa.add_worker(worker):
            self.callback_first_local_subscriber(sub)

        LOG.debug("match2workers: %s", wa.workers)

        # re-synthesize events
        for entry in wa.entries:
            LOG.debug("Found an entry for this match: %s", entry)
            event = engine.RouteEvent(engine.RouteEvent.ADVERTISE, entry)
            (dispatch, reason) = test_should_dispatch(event, worker)

            if dispatch:
                # check if the entry carries a route_target to which the worker
                # was already subscribed
                for rt in entry.route_targets:
                    if Match(entry.afi,
                             entry.safi,
                             rt) in worker._rtm_matches:
                        (dispatch, reason) = (
                            False,
                            "worker already had a subscription for this route")
                        break

            if dispatch:
                LOG.info("Dispatching re-synthesized event for %s", entry)
                worker.enqueue(event)
            else:
                LOG.info("%s => not dispatching re-synthesized event for %s",
                         reason, entry)

        # update worker matches
        worker._rtm_matches.add(match)

        # self._dump_state()

    def _worker_unsubscribes(self, sub):
        assert isinstance(sub.worker, worker_m.Worker)

        worker = sub.worker

        # self._dump_state()

        match = Match(sub.afi, sub.safi, sub.route_target)

        # update worker matches
        try:
            worker._rtm_matches.remove(match)
        except KeyError:
            LOG.warning("worker %s unsubs' from %s but this match was"
                        " not tracked for this worker (should not happen,"
                        " this is a bug)", worker, match)

        # synthesize withdraw events
        wa = self._match_2_workers_entries.get(match)
        if wa:
            for entry in wa.entries:
                intersect = set(matches_for(entry.afi,
                                            entry.safi,
                                            entry.route_targets)
                                ).intersection(worker._rtm_matches)
                if len(intersect) > 0:
                    LOG.debug("Will not synthesize withdraw event for %s, "
                              "because worker subscribed to %s", entry,
                              intersect)
                else:
                    LOG.debug("Found an entry for this match: %s", entry)
                    event = engine.RouteEvent(engine.RouteEvent.WITHDRAW,
                                              entry)
                    (dispatch, reason) = test_should_dispatch(event, worker)
                    if dispatch:
                        LOG.info("Dispatching re-synthesized event for %s",
                                 entry)
                        worker.enqueue(event)
                    else:
                        LOG.info("%s => not dispatching re-synthesized event"
                                 " for %s", reason, entry)

            # update _match_2_workers_entries
            try:
                if wa.del_worker(worker):
                    LOG.debug("see if need to callback on last local worker")
                    self.callback_last_local_subscriber(sub)
                    self._check_match_2_workers_and_entries_cleanup(match)
            except KeyError:
                LOG.warning("worker %s unsubscribed from %s but was not"
                            " subscribed yet", worker, match)
        else:  # wa is None
            LOG.warning("worker %s unsubscribed from %s but we had no such"
                        " subscription yet", worker, match)

        if len(worker._rtm_matches) == 0:
            self._workers.pop(worker.name, None)

        # self._dump_state()

    @log_decorator.log
    def _propagate_route_event(self, route_event, except_workers=None):
        '''Propagate route_event to workers subscribed to the route RTs
        or wildcards, except the workers in except_workers. Returns the list of
        workers to which the event was propagated.'''

        re = route_event.route_entry

        if except_workers is None:
            except_workers = []

        target_workers = set()
        for match in matches_for(re.afi, re.safi, re.route_targets):
            LOG.debug("Finding interested workers for match %s", match)

            interested_workers = self._match_2_workers_entries[match].workers

            LOG.debug("   Workers interested in this match: %s",
                      interested_workers)

            for worker in interested_workers:
                (dispatch, reason) = test_should_dispatch(route_event, worker)
                if dispatch:
                    if worker not in except_workers:
                        LOG.debug("Will dispatch event to %s: %s",
                                  worker, route_event)
                        target_workers.add(worker)
                    else:
                        LOG.debug("Decided not to dispatch to %s, based on"
                                  " except_workers: %s", worker, route_event)
                else:
                    LOG.debug("Decided not to dispatch to %s: %s (%s)",
                              worker, reason, route_event)

        for worker in target_workers:
            LOG.info("Dispatching event to %s: %s", worker, route_event)
            worker.enqueue(route_event)

        return target_workers

    @log_decorator.log_info
    def _receive_route_event(self, route_event):
        entry = route_event.route_entry

        LOG.debug("Try to find an entry from same worker with same nlri")
        replaced_entry = self._source_nlri_2_entry.get((entry.source,
                                                        entry.nlri))

        LOG.debug("   Result: %s", replaced_entry)

        # replaced_entry should be non-empty for a withdraw
        if (replaced_entry is None and
                route_event.type == engine.RouteEvent.WITHDRAW):
            LOG.warning("WITHDRAW but found no route that we could remove: %s",
                        route_event.route_entry)
            return

        # Propagate events to interested workers...
        if route_event.type == engine.RouteEvent.ADVERTISE:

            if replaced_entry == route_event.route_entry:
                LOG.warning("Ignoring, the route advertized is the same as the"
                            " one previously advertized by the source (%s)",
                            route_event.source)
                return

            # propagate event to interested worker
            # and include the info on the route are replaced by this
            # route, if any
            route_event.set_replaced_route(replaced_entry)

            workers_already_notified = self._propagate_route_event(route_event)
        else:  # WITHDRAW
            workers_already_notified = None

        # Synthesize and dispatch a withdraw event for the route entry that
        # was withdrawn or replaced, except, in the case of a replaced route,
        # to workers that had the ADVERTISE event
        if replaced_entry is not None:
            LOG.debug("Synthesizing a withdraw event for replaced route %s",
                      replaced_entry)
            removal_event = engine.RouteEvent(engine.RouteEvent.WITHDRAW,
                                              replaced_entry,
                                              route_event.source)

            self._propagate_route_event(removal_event,
                                        workers_already_notified)

            # Update match2entries for the replaced_route
            for match in matches_for(replaced_entry.afi,
                                     replaced_entry.safi,
                                     replaced_entry.route_targets):
                wa = self._match_2_workers_entries.get(match, None)
                if wa is None:
                    LOG.error("Trying to remove a route from a match, but"
                              " match %s not found - not supposed to happen"
                              " (route: %s)", match, replaced_entry)
                else:
                    wa.entries.discard(replaced_entry)
                    self._check_match_2_workers_and_entries_cleanup(match)

            # update the route entries for this source
            replaced_entry.source._rtm_route_entries.discard(replaced_entry)

        if route_event.type == engine.RouteEvent.ADVERTISE:
            # Update match2entries and source2entries for the newly
            # advertized route
            for match in matches_for(entry.afi,
                                     entry.safi,
                                     entry.route_targets):
                self._match_2_workers_entries[match].entries.add(entry)

            entry.source._rtm_route_entries.add(entry)

            # Update _source_nlri_2_entry
            self._source_nlri_2_entry[(entry.source, entry.nlri)] = entry
        else:  # WITHDRAW
            # Update source2entries
            entry.source._rtm_route_entries.discard(entry)

            # Update _source_nlri_2_entry
            try:
                del self._source_nlri_2_entry[(entry.source, entry.nlri)]
            except KeyError:
                LOG.error("BUG: withdraw, but nothing could be removed in "
                          "_source_nlri_2_entry")

        #  self._dump_state()

    @log_decorator.log_info
    def _worker_cleanup(self, worker):
        '''
        Consider all routes announced by this worker as withdrawn.
        Consider this worker unsubscribed from all of its current
        subscriptions.
        '''
        assert isinstance(worker, worker_m.Worker)
        # synthesize withdraw events for all routes from this worker
        LOG.info("  Preparing to withdraw %d routes that were advertised "
                 "by worker", len(worker._rtm_route_entries))
        for entry in worker._rtm_route_entries:
            LOG.info("  Enqueue event to Withdraw route %s", entry)
            self.enqueue(engine.RouteEvent(engine.RouteEvent.WITHDRAW, entry))

        # remove worker from all of its subscriptions
        for match in worker._rtm_matches:
            wa = self._match_2_workers_entries[match]
            wa.del_worker(worker)
            self._check_match_2_workers_and_entries_cleanup(match)

        worker._rtm_matches.clear()

        # self._dump_state()

    def _dump_state(self):
        if not LOG.isEnabledFor(logging.DEBUG):
            return

        dump = []

        dump.append("~~~ Worker -> Matches ~~~")
        for worker in self._workers.values():
            dump.append("  %s" % worker)
            matches = list(worker._rtm_matches)
            matches.sort()
            for match in matches:
                dump.append("    %s" % match)

        match_2_worker_dump = []
        match_2_entries_dump = []

        matches = list(self._match_2_workers_entries.keys())
        matches.sort()
        for match in matches:
            match_2_worker_dump.append("  %s" % match)
            match_2_entries_dump.append("  %s" % match)
            wa = self._match_2_workers_entries.get(match)
            if wa:
                for worker in wa.workers:
                    match_2_worker_dump.append("    %s" % worker)
                for re in wa.entries:
                    match_2_entries_dump.append("    %s" % re)

        dump.append("\n~~~ Match -> Workers ~~~\n%s\n" %
                    "\n".join(match_2_worker_dump))

        dump.append("~~~ Match -> Entries ~~~\n%s\n" %
                    "\n".join(match_2_entries_dump))

        dump.append("~~~ (source,nlri) ->  entries ~~~")
        for ((source, nlri), entry) in self._source_nlri_2_entry.iteritems():
            dump.append("  (%s, %s): %s" % (source, nlri, entry))

        LOG.debug("RouteTableManager data dump:\n\n%s\n", "\n".join(dump))

    # Looking Glass #####

    def get_lg_map(self):
        return {"workers": (lg.COLLECTION, (self.get_lg_worker_list,
                                            self.get_lg_worker_from_path_item)
                            ),
                "routes": (lg.SUBTREE, self.get_lg_routes)}

    def get_lg_routes(self, path_prefix):
        result = {}

        match_IPVPN = Match(exa.AFI.ipv4, exa.SAFI.mpls_vpn,
                            engine.Subscription.ANY_RT)
        match_EVPN = Match(exa.AFI.l2vpn, exa.SAFI.evpn,
                           engine.Subscription.ANY_RT)
        match_RTC = Match(exa.AFI.ipv4, exa.SAFI.rtc,
                          engine.Subscription.ANY_RT)
        match_FlowSpecVPN = Match(exa.AFI.ipv4, exa.SAFI.flow_vpn,
                                  engine.Subscription.ANY_RT)
        for match in [match_IPVPN, match_EVPN, match_RTC, match_FlowSpecVPN]:
            match_result = []
            wa = self._match_2_workers_entries.get(match)
            if wa is not None:
                for entry in wa.entries:
                    match_result.append(
                        entry.get_looking_glass_info(path_prefix))
            result[str(match)] = match_result
        return result

    def get_lg_worker_list(self):
        return [{"id": worker.name} for worker in self._workers.itervalues()]

    def get_lg_worker_from_path_item(self, path_item):
        return self._workers.get(path_item, None)

    def get_all_routes_but_rtc(self):
        return [re for re in self._match_2_workers_entries[MATCH_ANY].entries
                if (re.afi, re.safi) != (exa.AFI.ipv4, exa.SAFI.rtc)
                ]

    def get_local_routes_count(self):
        return reduce(
            lambda count, entry:
            count + (not isinstance(entry.source,
                                    bgp_peer_worker.BGPPeerWorker)),
            self.get_all_routes_but_rtc(),
            0)

    def get_received_routes_count(self):
        return reduce(
            lambda count, entry:
            count + isinstance(entry.source, bgp_peer_worker.BGPPeerWorker),
            self.get_all_routes_but_rtc(),
            0)
