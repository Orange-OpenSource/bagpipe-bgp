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

import logging
import traceback

from threading import Thread
from Queue import Queue

from collections import defaultdict

from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import Subscription
from bagpipe.bgp.engine import Unsubscription
from bagpipe.bgp.engine import WorkerCleanupEvent

from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import logDecorator

from exabgp.reactor.protocol import AFI, SAFI
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget

log = logging.getLogger(__name__)


class Match(object):

    def __init__(self, afi, safi, routeTarget):
        assert isinstance(afi, AFI)
        assert isinstance(safi, SAFI)
        assert routeTarget is None or isinstance(routeTarget, RouteTarget)
        self.afi = afi
        self.safi = safi
        self.routeTarget = routeTarget

    def __hash__(self):
        # FIXME, could use a tuple, but RT not yet hashable
        # return hash((self.afi, self.safi, self.routeTarget))
        return hash(str(self))

    def __repr__(self):
        return "match:%s" % str(self)

    def __str__(self):
        return "%s/%s,%s" % (self.afi or "*", self.safi or "*",
                             self.routeTarget or "*")

    def __cmp__(self, other):
        assert isinstance(other, Match)

        self_afi = self.afi or AFI(0)
        self_safi = self.safi or SAFI(0)
        self_rt = self.routeTarget or RouteTarget(0, 0)

        other_afi = other.afi or AFI(0)
        other_safi = other.safi or SAFI(0)
        other_rt = other.routeTarget or RouteTarget(0, 0)

        val = cmp((self_afi, self_safi, str(self_rt)),
                  (other_afi, other_safi, str(other_rt)))

        return val


MATCH_ANY = Match(Subscription.ANY_AFI,
                  Subscription.ANY_SAFI,
                  Subscription.ANY_RT)


def matchesFor(afi, safi, routeTargets):
    # generate all possible match entries for this afi/safi
    # and these routetargets, with all possible wildcards
    #
    # There are 4*(n+1) possible Match object (for n routeTargets)
    for _afi in (Subscription.ANY_AFI, afi):
        for _safi in (Subscription.ANY_SAFI, safi):
            yield Match(_afi, _safi, None)
            if routeTargets is not None:
                for rt in routeTargets:
                    yield Match(_afi, _safi, rt)


class WorkersAndEntries(object):

    def __init__(self):
        self.workers = set()
        self.entries = set()
        self.nLocalWorkers = 0

    def __repr__(self):
        return "workers: %s\nentries: %s" % (self.workers,
                                             self.entries)

    def addWorker(self, worker):
        """ returns True iif first local worker """
        self.workers.add(worker)
        if not isinstance(worker, BGPPeerWorker):
            self.nLocalWorkers += 1
            return self.nLocalWorkers == 1

    def delWorker(self, worker):
        """ returns True iif last local worker """
        self.workers.remove(worker)
        if not isinstance(worker, BGPPeerWorker):
            self.nLocalWorkers -= 1
            return self.nLocalWorkers == 0

    def isEmpty(self):
        return (len(self.workers) == 0 and
                len(self.entries) == 0)


StopEvent = "StopEvent"


def testShouldDispatch(routeEvent, targetWorker):
    '''
    returns a (boolean,string) tuple
    the string contains the reason why the routeEvent should not be
    dispatched to targetWorker
    '''
    if routeEvent.source == targetWorker:
        return (False, "not dispatching an update back to its source")
    elif (isinstance(routeEvent.source, BGPPeerWorker)
          and isinstance(targetWorker, BGPPeerWorker)):
        return (False, "do not dispatch a route between BGP peers")
    else:
        return (True, "")


class RouteTableManager(Thread, lg.LookingGlassMixin):

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

    def __init__(self, firstLocalSubscriberCB, lastLocalSubscriberCB):
        Thread.__init__(self, name="RouteTableManager")
        self.setDaemon(True)

        # keys are Matches, values are WorkersAndEntries objects:
        self._match2workersAndEntries = defaultdict(WorkersAndEntries)

        # workers known to us
        # name -> worker dict
        self._workers = {}

        # keys are (source,nlri) tuples, values are Entry objects:
        self._source_nlri2entry = {}

        self.firstLocalSubscriberCallback = firstLocalSubscriberCB
        self.lastLocalSubscriberCallback = lastLocalSubscriberCB

        self._queue = Queue()

    @logDecorator.logInfo
    def stop(self):
        self.enqueue(StopEvent)

    def run(self):
        while True:
            log.debug("RouteTableManager waiting on queue")
            event = self._queue.get()
            log.debug("RouteTableManager received event %s", event)
            try:
                if event.__class__ == RouteEvent:
                    self._receiveRouteEvent(event)
                elif event.__class__ == Subscription:
                    self._workerSubscribes(event)
                elif event.__class__ == Unsubscription:
                    self._workerUnsubscribes(event)
                elif event.__class__ == WorkerCleanupEvent:
                    self._workerCleanup(event.worker)
                elif event == StopEvent:
                    log.info("StopEvent => breaking main loop")
                    break
            except Exception as e:
                log.error("Exception during processing of event: %s", repr(e))
                log.error("%s", traceback.format_exc())
                log.error("    event was: %s", event)

            log.debug("RouteTableManager queue size: %d", self._queue.qsize())

        log.info("Out of main loop")

    def enqueue(self, event):
        self._queue.put(event)

    def _checkMatch2workersAndEntriesCleanup(self, match):
        wa = self._match2workersAndEntries.get(match)
        if wa is None:
            log.warning("why are we here ?")
            # nothing to cleanup
            return
        else:
            if wa.isEmpty():
                del self._match2workersAndEntries[match]

    def callbackFirstLocalSubscriber(self, sub):
        if self.firstLocalSubscriberCallback:
            log.debug("first local subscriber callback for %s ...", sub)
            self.firstLocalSubscriberCallback(sub)

    def callbackLastLocalSubscriber(self, sub):
        if self.lastLocalSubscriberCallback:
            log.debug("last local subscriber callback for %s ...", sub)
            self.lastLocalSubscriberCallback(sub)

    def _workerSubscribes(self, sub):
        # TODO: this function currently will not consider whether or not
        # is already subscribed to set of route events, before considering
        # a subscription.  In particular, multiple identical subscriptions
        # will lead to this code re-synthesizing events at each call.
        #
        # Ideally, the code should detect that the worker is already subscribed
        # and skip the subscription.

        assert isinstance(sub.worker, Worker)
        log.info("workerSubscribes: %s", sub)

        worker = sub.worker

        self._workers[worker.name] = worker

        match = Match(sub.afi, sub.safi, sub.routeTarget)

        wa = self._match2workersAndEntries[match]

        # update match2worker
        if wa.addWorker(worker):
            self.callbackFirstLocalSubscriber(sub)

        log.debug("match2workers: %s", wa.workers)

        # re-synthesize events
        for entry in wa.entries:
            log.debug("Found an entry for this match: %s", entry)
            event = RouteEvent(RouteEvent.ADVERTISE, entry)
            (shouldDispatch, reason) = testShouldDispatch(event, worker)

            if shouldDispatch:
                # check if the entry carries a routeTarget to which the worker
                # was already subscribed
                for rt in entry.routeTargets:
                    if Match(entry.afi,
                             entry.safi,
                             rt) in worker._rtm_matches:
                        (shouldDispatch, reason) = (
                            False,
                            "worker already had a subscription for this route")
                        break

            if shouldDispatch:
                log.info("Dispatching re-synthesized event for %s", entry)
                worker.enqueue(event)
            else:
                log.info("%s => not dispatching re-synthesized event for %s",
                         reason, entry)

        # update worker matches
        worker._rtm_matches.add(match)

        # self._dumpState()

    def _workerUnsubscribes(self, sub):
        assert isinstance(sub.worker, Worker)

        worker = sub.worker

        # self._dumpState()

        match = Match(sub.afi, sub.safi, sub.routeTarget)

        # update worker matches
        try:
            worker._rtm_matches.remove(match)
        except KeyError:
            log.warning("worker %s unsubs' from %s but this match was"
                        " not tracked for this worker (should not happen,"
                        " this is a bug)", worker, match)

        # synthesize withdraw events
        wa = self._match2workersAndEntries.get(match)
        if wa:
            for entry in wa.entries:
                intersect = set(matchesFor(entry.afi,
                                           entry.safi,
                                           entry.routeTargets)
                                ).intersection(worker._rtm_matches)
                if len(intersect) > 0:
                    log.debug("Will not synthesize withdraw event for %s, "
                              "because worker subscribed to %s", entry,
                              intersect)
                else:
                    log.debug("Found an entry for this match: %s", entry)
                    event = RouteEvent(RouteEvent.WITHDRAW, entry)
                    (shouldDispatch, reason) = testShouldDispatch(event,
                                                                  worker)
                    if shouldDispatch:
                        log.info("Dispatching re-synthesized event for %s",
                                 entry)
                        worker.enqueue(event)
                    else:
                        log.info("%s => not dispatching re-synthesized event"
                                 " for %s", reason, entry)

            # update _match2workersAndEntries
            try:
                if wa.delWorker(worker):
                    log.debug("see if need to callback on last local worker")
                    self.callbackLastLocalSubscriber(sub)
                    self._checkMatch2workersAndEntriesCleanup(match)
            except KeyError:
                log.warning("worker %s unsubscribed from %s but was not"
                            " subscribed yet", worker, match)
        else:  # wa is None
            log.warning("worker %s unsubscribed from %s but we had no such"
                        " subscription yet", worker, match)

        if len(worker._rtm_matches) == 0:
            self._workers.pop(worker.name, None)

        # self._dumpState()

    def _propagateRouteEvent(self, routeEvent, exceptWorkers=None):
        '''Propagate routeEvent to workers subscribed to the route RTs
        or wildcards, except the workers in exceptWorkers. Returns the list of
        workers to which the event was propagated.'''

        log.debug("Propagate event to interested workers: %s", routeEvent)

        re = routeEvent.routeEntry

        if exceptWorkers is None:
            exceptWorkers = []

        targetWorkers = set()
        for match in matchesFor(re.afi, re.safi, re.routeTargets):
            log.debug("Finding interested workers for match %s", match)

            interestedWorkers = self._match2workersAndEntries[match].workers

            log.debug("   Workers interested in this match: %s",
                      interestedWorkers)

            for worker in interestedWorkers:
                (shouldDispatch, reason) = testShouldDispatch(routeEvent, worker)
                if shouldDispatch:
                    if worker not in exceptWorkers:
                        log.debug("Will dispatch event to %s: %s",
                                  worker, routeEvent)
                        targetWorkers.add(worker)
                    else:
                        log.debug("Decided not to dispatch to %s, based on"
                                  " exceptWorkers: %s", worker, routeEvent)
                else:
                    log.debug("Decided not to dispatch to %s: %s (%s)",
                              worker, reason, routeEvent)

        for worker in targetWorkers:
            log.info("Dispatching event to %s: %s", worker, routeEvent)
            worker.enqueue(routeEvent)

        return targetWorkers

    def _receiveRouteEvent(self, routeEvent):
        log.info("receive: %s", routeEvent)

        entry = routeEvent.routeEntry

        log.debug("Try to find an entry from same worker with same nlri")
        replacedEntry = self._source_nlri2entry.get((entry.source, entry.nlri))

        log.debug("   Result: %s", replacedEntry)

        # replacedEntry should be non-empty for a withdraw
        if replacedEntry is None and (routeEvent.type == RouteEvent.WITHDRAW):
            log.warning("WITHDRAW but found no route that we could remove: %s",
                        routeEvent.routeEntry)
            return

        # Propagate events to interested workers...
        if routeEvent.type == RouteEvent.ADVERTISE:

            if replacedEntry == routeEvent.routeEntry:
                log.warning("The route advertized is the same as the one"
                            " previously advertized by the source, ignoring")
                return

            # propagate event to interested worker
            # and include the info on the route are replaced by this
            # route, if any
            routeEvent.setReplacedRoute(replacedEntry)

            workersAlreadyNotified = self._propagateRouteEvent(routeEvent)
        else:  # WITHDRAW
            workersAlreadyNotified = None

        # Synthesize and dispatch a withdraw event for the route entry that
        # was withdrawn or replaced, except, in the case of a replaced route,
        # to workers that had the ADVERTISE event
        if replacedEntry is not None:
            log.debug("Synthesizing a withdraw event for replaced route %s",
                      replacedEntry)
            removalEvent = RouteEvent(RouteEvent.WITHDRAW,
                                      replacedEntry,
                                      routeEvent.source)

            self._propagateRouteEvent(removalEvent, workersAlreadyNotified)

            # Update match2entries for the replacedRoute
            for match in matchesFor(replacedEntry.afi,
                                    replacedEntry.safi,
                                    replacedEntry.routeTargets):
                wa = self._match2workersAndEntries.get(match, None)
                if wa is None:
                    log.error("Trying to remove a route from a match, but"
                              " match %s not found - not supposed to happen"
                              " (route: %s)", match, replacedEntry)
                else:
                    wa.entries.discard(replacedEntry)
                    self._checkMatch2workersAndEntriesCleanup(match)

            # update the route entries for this source
            replacedEntry.source._rtm_routeEntries.discard(replacedEntry)

        if routeEvent.type == RouteEvent.ADVERTISE:
            # Update match2entries and source2entries for the newly
            # advertized route
            for match in matchesFor(entry.afi,
                                    entry.safi,
                                    entry.routeTargets):
                self._match2workersAndEntries[match].entries.add(entry)

            entry.source._rtm_routeEntries.add(entry)

            # Update _source_nlri2entry
            self._source_nlri2entry[(entry.source, entry.nlri)] = entry
        else:  # WITHDRAW
            # Update source2entries
            entry.source._rtm_routeEntries.discard(entry)

            # Update _source_nlri2entry
            try:
                del self._source_nlri2entry[(entry.source, entry.nlri)]
            except KeyError:
                log.error("BUG: withdraw, but nothing could be removed in "
                          "_sourcenlri2entryRemove")

        #  self._dumpState()

    def _workerCleanup(self, worker):
        '''
        Consider all routes announced by this worker as withdrawn.
        Consider this worker unsubscribed from all of its current
        subscriptions.
        '''
        assert isinstance(worker, Worker)
        log.info("Cleanup for worker %s", worker.name)
        # synthesize withdraw events for all routes from this worker
        log.info("  Preparing to withdraw %d routes that were advertised "
                 "by worker", len(worker._rtm_routeEntries))
        for entry in worker._rtm_routeEntries:
            log.info("  Enqueue event to Withdraw route %s", entry)
            self.enqueue(RouteEvent(RouteEvent.WITHDRAW, entry))

        # remove worker from all of its subscriptions
        for match in worker._rtm_matches:
            wa = self._match2workersAndEntries[match]
            wa.delWorker(worker)
            self._checkMatch2workersAndEntriesCleanup(match)

        worker._rtm_matches.clear()

        # self._dumpState()

    def _dumpState(self):
        if not log.isEnabledFor(logging.DEBUG):
            return

        dump = []

        dump.append("~~~ Worker -> Matches ~~~")
        for worker in self._workers.values():
            dump.append("  %s" % worker)
            matches = list(worker._rtm_matches)
            matches.sort()
            for match in matches:
                dump.append("    %s" % match)

        match2workerDump = []
        match2entriesDump = []

        matches = list(self._match2workersAndEntries.keys())
        matches.sort()
        for match in matches:
            match2workerDump.append("  %s" % match)
            match2entriesDump.append("  %s" % match)
            wa = self._match2workersAndEntries.get(match)
            if wa:
                for worker in wa.workers:
                    match2workerDump.append("    %s" % worker)
                for re in wa.entries:
                    match2entriesDump.append("    %s" % re)

        dump.append("\n~~~ Match -> Workers ~~~\n%s\n" %
                    "\n".join(match2workerDump))

        dump.append("~~~ Match -> Entries ~~~\n%s\n" %
                    "\n".join(match2entriesDump))

        dump.append("~~~ (source,nlri) ->  entries ~~~")
        for ((source, nlri), entry) in self._source_nlri2entry.iteritems():
            dump.append("  (%s, %s): %s" % (source, nlri, entry))

        log.debug("RouteTableManager data dump:\n\n%s\n", "\n".join(dump))

    # Looking Glass #####

    def getLGMap(self):
        return {"workers": (lg.COLLECTION, (self.getLGWorkerList,
                                            self.getLGWorkerFromPathItem)),
                "routes": (lg.SUBTREE, self.getLGRoutes)}

    def getLGRoutes(self, pathPrefix):
        result = {}

        match_IPVPN = Match(
            AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn), Subscription.ANY_RT)
        match_EVPN = Match(
            AFI(AFI.l2vpn), SAFI(SAFI.evpn), Subscription.ANY_RT)
        match_RTC = Match(AFI(AFI.ipv4), SAFI(SAFI.rtc), Subscription.ANY_RT)
        match_FlowSpecVPN = Match(AFI(AFI.ipv4),
                                  SAFI(SAFI.flow_vpn),
                                  Subscription.ANY_RT)
        for match in [match_IPVPN, match_EVPN, match_RTC, match_FlowSpecVPN]:
            matchResult = []
            wa = self._match2workersAndEntries.get(match)
            if wa is not None:
                for entry in wa.entries:
                    matchResult.append(
                        entry.getLookingGlassInfo(pathPrefix))
            result[str(match)] = matchResult
        return result

    def getLGWorkerList(self):
        return [{"id": worker.name} for worker in self._workers.itervalues()]

    def getLGWorkerFromPathItem(self, pathItem):
        return self._workers.get(pathItem, None)

    def getAllRoutesButRTC(self):
        return [re for re in self._match2workersAndEntries[MATCH_ANY].entries
                if not (re.afi == AFI(AFI.ipv4) and
                        re.safi == SAFI(SAFI.rtc))
                ]

    def getLocalRoutesCount(self):
        return reduce(
            lambda count, entry:
            count + (not isinstance(entry.source, BGPPeerWorker)),
            self.getAllRoutesButRTC(),
            0)

    def getReceivedRoutesCount(self):
        return reduce(
            lambda count, entry:
            count + isinstance(entry.source, BGPPeerWorker),
            self.getAllRoutesButRTC(),
            0)
