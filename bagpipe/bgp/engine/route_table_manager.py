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

from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import Subscription
from bagpipe.bgp.engine import Unsubscription
from bagpipe.bgp.engine import WorkerCleanupEvent

from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap
from bagpipe.bgp.common import logDecorator

from exabgp.reactor.protocol import AFI, SAFI
from exabgp.bgp.message.update.attribute.community.extended import RouteTargetASN2Number as RouteTarget

log = logging.getLogger(__name__)


class Match(object):

    def __init__(self, afi, safi, routeTarget):
        assert(isinstance(afi, AFI))
        assert(isinstance(safi, SAFI))
        assert(routeTarget is None or isinstance(routeTarget, RouteTarget))
        self.afi = afi
        self.safi = safi
        self.routeTarget = routeTarget

    # FIXME: use a better hash if needed for performances
    def __hash__(self):
        return hash(repr(self))

    def __repr__(self):
        return "match:%s/%s,%s" % (self.afi or "*", self.safi or "*",
                                   self.routeTarget or "*")

    def __cmp__(self, other):
        assert isinstance(other, Match)

        self_afi = self.afi or AFI(0)
        self_safi = self.safi or SAFI(0)
        self_rt = self.routeTarget or RouteTarget(0, 0)

        other_afi = other.afi or AFI(0)
        other_safi = other.safi or SAFI(0)
        other_rt = other.routeTarget or RouteTarget(0, 0)

        return cmp((self_afi,  self_safi,  self_rt),
                   (other_afi, other_safi, other_rt))

StopEvent = "StopEvent"


class RouteTableManager(Thread, LookingGlass):

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
    class WorkersAndEntries(object):

        def __init__(self):
            self.workers = set()
            self.entries = set()
            self.nLocalWorkers = 0

        def __repr__(self):
            return "workers: %s\nentries: %s" % (self.workers,
                                                 self.entries)

        def addWorker(self, worker):
            self.workers.add(worker)
            if not isinstance(worker, BGPPeerWorker):
                self.nLocalWorkers += 1
                return (self.nLocalWorkers == 1)

        def delWorker(self, worker):
            self.workers.remove(worker)
            if not isinstance(worker, BGPPeerWorker):
                self.nLocalWorkers -= 1
                return (self.nLocalWorkers == 0)

    def __init__(self, firstLocalSubscriberCB, lastLocalSubscriberCB):
        Thread.__init__(self, name="RouteTableManager")
        self.setDaemon(True)

        # keys are Matches, values are WorkersAndEntries objects:
        self._match2workersAndEntries = {}

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
        try:
            item = self._match2workersAndEntries[match]
        except KeyError:
            log.warning("why are we here ?")
            # nothing to cleanup
            return

        if len(item.workers) == 0 and len(item.entries) == 0:
            del self._match2workersAndEntries[match]

    def _match2workersAndEntriesLookupCreate(self, match):
        try:
            return self._match2workersAndEntries[match]
        except KeyError:
            wa = RouteTableManager.WorkersAndEntries()
            self._match2workersAndEntries[match] = wa
            return wa

    def _match2entries(self, match, createIfNone=False, emptyListIfNone=True):
        if createIfNone:
            return self._match2workersAndEntriesLookupCreate(match).entries
        try:
            return self._match2workersAndEntries[match].entries
        except KeyError:
            if emptyListIfNone:
                return []
            else:
                raise

    def _match2workers(self, match, emptyListIfNone=True):
        log.debug("_match2workers: %s", match)
        try:
            return self._match2workersAndEntries[match].workers
        except KeyError:
            log.debug("match2workers: except!")
            if emptyListIfNone:
                return []
            else:
                raise

    def _matchAddWorker(self, match, worker):
        '''
        Add the worker from the list of workers subscribed to match.
        returns true if this is the first local one
        '''
        wa = self._match2workersAndEntriesLookupCreate(match)
        return wa.addWorker(worker)

    def _matchDelWorker(self, match, worker):
        '''
        Delete the worker from the list of workers subscribed to match
        returns true if this was the last local one
        '''
        wa = self._match2workersAndEntries[match]
        return wa.delWorker(worker)

    def callbackFirstLocalSubscriber(self, sub):
        if self.firstLocalSubscriberCallback:
            event = self.firstLocalSubscriberCallback(sub)
            log.debug("first local subscriber callback for %s: %s", sub, event)
            if event:
                self.enqueue(event)

    def callbackLastLocalSubscriber(self, sub):
        if self.lastLocalSubscriberCallback:
            event = self.lastLocalSubscriberCallback(sub)
            log.debug("last local subscriber callback for %s: %s", sub, event)
            if event:
                self.enqueue(event)

    def _workerSubscribes(self, sub):
        # TODO: this function currently will not consider whether or not
        # is already subscribed to set of route events, before considering
        # a subscription.  In particular, multiple identical subscriptions
        # will lead to this code re-synthesizing events at each call.
        #
        # Ideally, the code should detect that the worker is already subscribed
        # and skip the subscription. *But* such a change should not be done
        # until the code in ExaBGPPeerWorker is updated to support this.

        assert(isinstance(sub.worker, Worker))
        log.info("workerSubscribes: %s", sub)

        worker = sub.worker

        self._workers[worker.name] = worker

        match = Match(sub.afi, sub.safi, sub.routeTarget)

        # update match2worker
        if self._matchAddWorker(match, worker):
            self.callbackFirstLocalSubscriber(sub)

        log.debug("match2workers: %s", self._match2workers(match))

        # create worker matches private info if needed
        if '_rtm_matches' not in worker.__dict__:
            worker._rtm_matches = set()

        # re-synthesize events
        for entry in self._match2entries(match):
            log.debug("Found an entry for this match: %s", entry)
            event = RouteEvent(RouteEvent.ADVERTISE, entry)
            (shouldDispatch, reason) = self._shouldDispatch(event, worker)

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
        assert(isinstance(sub.worker, Worker))

        worker = sub.worker

        # self._dumpState()

        match = Match(sub.afi, sub.safi, sub.routeTarget)

        # update worker matches
        if '_rtm_matches' not in worker.__dict__:
            log.warning("worker %s unsubs'd from %s but wasn't tracked yet",
                        worker, match)
            worker._rtm_matches = set()
        else:
            try:
                worker._rtm_matches.remove(match)
            except KeyError:
                log.warning("worker %s unsubs' from %s but this match was"
                            "not tracked for this worker (should not happen,"
                            " this is a bug)", worker, match)

        # synthesize withdraw events
        for entry in self._match2entries(match, emptyListIfNone=True):
            intersect = set(
                self._matchesFor(entry.afi, entry.safi, entry.routeTargets)
                ).intersection(worker._rtm_matches)
            if len(intersect) > 0:
                log.debug("Will not synthesize withdraw event for %s, because"
                          " worker subscribed to %s", entry, intersect)
            else:
                log.debug("Found an entry for this match: %s", entry)
                event = RouteEvent(RouteEvent.WITHDRAW, entry)
                (shouldDispatch, reason) = self._shouldDispatch(event,
                                                                worker)
                if shouldDispatch:
                    log.info("Dispatching re-synthesized event for %s", entry)
                    worker.enqueue(event)
                else:
                    log.info(
                        "%s => not dispatching re-synthesized event for %s",
                        reason, entry)

        # update _match2workersAndEntries
        if match not in self._match2workersAndEntries:
            log.warning("worker %s unsubscribed from %s but we had no such"
                        " subscription yet", worker, match)
        else:
            try:
                if self._matchDelWorker(match, worker):
                    log.debug("see if need to callback on last local worker")
                    self.callbackLastLocalSubscriber(sub)
            except KeyError:
                log.warning("worker %s unsubscribed from %s but was not"
                            " subscribed yet", worker, match)

        self._checkMatch2workersAndEntriesCleanup(match)

        if ('_rtm_matches' not in worker.__dict__ or
                not worker._rtm_matches):
            self._workers.pop(worker.name, None)

        # self._dumpState()

    def _matchesFor(self, afi, safi, routeTargets):
        # generate all possible match entries for this afi/safi
        # and these routetargets, with all possible wildcards
        #
        # There are 4*(n+1) possible Match object (for n routeTargets)
        for _afi in (Subscription.ANY_AFI, afi):
            for _safi in (Subscription.ANY_SAFI, safi):
                yield Match(_afi, _safi, None)
                for rt in routeTargets:
                    yield Match(_afi, _safi, rt)

    def _propagateRouteEvent(self, routeEvent, exceptWorkers=None):
        '''Propagate routeEvent to workers subscribed to the route RTs
        or wildcards, except the workers in exceptWorkers. Returns the list of
        workers to which the event was propagated.'''

        log.debug("Propagate event to interested workers: %s", routeEvent)

        re = routeEvent.routeEntry

        if exceptWorkers is None:
            exceptWorkers = []

        targetWorkers = set()
        for match in self._matchesFor(re.afi, re.safi, re.routeTargets):
            log.debug("Finding interested workers for match %s", match)

            interestedWorkers = self._match2workers(match,
                                                    emptyListIfNone=True)
            log.debug("   Workers interested in this match: %s",
                      interestedWorkers)

            for worker in interestedWorkers:
                (shouldDispatch, reason) = self._shouldDispatch(routeEvent,
                                                                worker)
                if shouldDispatch:
                    if worker not in exceptWorkers:
                        log.debug("Will dispatch event to %s: %s",
                                  worker, routeEvent)
                        targetWorkers.add(worker)
                    else:
                        log.debug("Decided not to dispatch to %s, based on "
                                  "exceptWorkers: %s", worker, routeEvent)
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

        log.debug("Try to find an entry from same peer with same nlri")
        try:
            replacedEntry = self._source_nlri2entry[(entry.source, entry.nlri)]
        except KeyError:
            replacedEntry = None

        log.debug("   Result: %s", replacedEntry)

        # replacedEntry should be non-empty for a withdraw
        if replacedEntry is None and (routeEvent.type == RouteEvent.WITHDRAW):
            log.warning("WITHDRAW but found no route that we could remove: %s",
                        routeEvent.routeEntry)
            return

        # Propagate events to interested workers...
        if routeEvent.type == RouteEvent.ADVERTISE:

            if replacedEntry == routeEvent.routeEntry:
                log.warning("The route advertized is the same as the one "
                            "previously advertized by the source, ignoring")
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
            for match in self._matchesFor(replacedEntry.afi,
                                          replacedEntry.safi,
                                          replacedEntry.routeTargets):
                try:
                    self._match2entries(match).discard(replacedEntry)
                except KeyError:
                    log.error("Trying to remove a route from a match, but"
                              " match %s not found - not supposed to happen"
                              " (route: %s)", match, replacedEntry)
                self._checkMatch2workersAndEntriesCleanup(match)

            # update the route entries for this source
            replacedEntry.source._rtm_routeEntries.discard(replacedEntry)

        if routeEvent.type == RouteEvent.ADVERTISE:
            # Update match2entries and source2entries for the newly
            # advertized route
            for match in self._matchesFor(entry.afi,
                                          entry.safi,
                                          entry.routeTargets):
                self._match2entries(match, createIfNone=True).add(entry)

            if '_rtm_routeEntries' not in entry.source.__dict__:
                entry.source._rtm_routeEntries = set()

            entry.source._rtm_routeEntries.add(entry)

            # Update _source_nlri2entry
            self._source_nlri2entry[(entry.source, entry.nlri)] = entry
        else:  # WITHDRAW
            # Update _source_nlri2entry
            try:
                del self._source_nlri2entry[(entry.source, entry.nlri)]
            except KeyError:
                log.error("Withdraw, but nothing removed in "
                          "_sourcenlri2entryRemove")

        #  self._dumpState()

    def _shouldDispatch(self, routeEvent, targetWorker):
        '''
        returns a (boolean,string) tuple
        the string contains the reason why the routeEvent should not be
        dispatched to targetWorker
        '''
        if (routeEvent.source == targetWorker):
            return (False, "not dispatching an update back to its source")
        elif (isinstance(routeEvent.source, BGPPeerWorker)
              and isinstance(targetWorker, BGPPeerWorker)):
            return (False, "do not dispatch a route between BGP peers")
        else:
            return (True, "")

    def _workerCleanup(self, worker):
        '''
        Consider all routes announced by this worker as withdrawn.
        Consider this worker unsubscribed from all of its current
        subscriptions.
        '''
        log.info("Cleanup for worker %s", worker.name)
        # synthesize withdraw events for all routes from this worker
        if '_rtm_routeEntries' in worker.__dict__:
            log.info("  Preparing to withdraw %d routes that were advertised "
                     "by worker", len(worker._rtm_routeEntries))
            for entry in worker._rtm_routeEntries:
                log.info("  Enqueue event to Withdraw route %s", entry)
                self.enqueue(RouteEvent(RouteEvent.WITHDRAW, entry))

        # remove worker from all of its subscriptions
        if '_rtm_matches' in worker.__dict__:
            for match in worker._rtm_matches:
                wa = self._match2workersAndEntries[match]
                wa.delWorker(worker)
            del worker._rtm_matches

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
            for worker in self._match2workers(match):
                match2workerDump.append("    %s" % worker)
            for re in self._match2entries(match):
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
        return {"workers": (LGMap.COLLECTION,
                (self.getLGWorkerList, self.getLGWorkerFromPathItem)),
                "routes": (LGMap.SUBTREE, self.getLGRoutes)}

    def getLGRoutes(self, pathPrefix):
        result = {}

        match_IPVPN = Match(
            AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn), Subscription.ANY_RT)
        match_EVPN = Match(
            AFI(AFI.l2vpn), SAFI(SAFI.evpn), Subscription.ANY_RT)
        match_RTC = Match(AFI(AFI.ipv4), SAFI(SAFI.rtc), Subscription.ANY_RT)
        for match in [match_IPVPN, match_EVPN, match_RTC]:
            matchResult = []
            if match in self._match2workersAndEntries:
                for entry in self._match2entries(match):
                    matchResult.append(
                        entry.getLookingGlassInfo(pathPrefix))
            result[repr(match)] = matchResult
        return result

    def getLGWorkerList(self):
        return [{"id": worker.name} for worker in self._workers.values()]

    def getLGWorkerFromPathItem(self, pathItem):
        return self._workers.get(pathItem, None)

    def getAllRoutesButRTC(self):
        try:
            return [re for re in
                    self._match2workersAndEntries[Match(Subscription.ANY_AFI,
                                                        Subscription.ANY_SAFI,
                                                        Subscription.ANY_RT)
                                                  ].entries
                    if not (re.afi == AFI(AFI.ipv4) and
                            re.safi == SAFI(SAFI.rtc))
                    ]
        except KeyError:
            return []

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
