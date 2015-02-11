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


import socket

import logging

from bagpipe.bgp.engine.route_table_manager import RouteTableManager, \
    WorkerCleanupEvent
from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker
from bagpipe.bgp.engine.exabgp_peer_worker import ExaBGPPeerWorker
from bagpipe.bgp.engine import RouteEvent, RouteEntry, \
    Subscription, Unsubscription
from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap

from bagpipe.exabgp.message.update.route import Route
from bagpipe.exabgp.structure.rtc import RouteTargetConstraint
from bagpipe.exabgp.structure.address import AFI, SAFI
from bagpipe.exabgp.structure.ip import Inet
from bagpipe.exabgp.message.update.attribute.nexthop import NextHop

log = logging.getLogger(__name__)


class Manager(LookingGlass):

    def __init__(self, _config, peerClass=ExaBGPPeerWorker):
        def getBoolean(boolValue):
            return boolValue == "True"

        log.debug("Instantiating Manager")

        self.config = _config
        self.peerClass = peerClass

        if 'enable_rtc' not in self.config:
            self.config['enable_rtc'] = True  # RTC is not used by default
        else:
            self.config['enable_rtc'] = getBoolean(self.config['enable_rtc'])

        self.routeTableManager = RouteTableManager()
        self.routeTableManager.start()

        if 'local_address' not in self.config:
            raise Exception("config needs a local_address")

        if 'my_as' not in self.config:
            raise Exception("config needs a my_as")
        self.config['my_as'] = int(self.config['my_as'])

        if 'peer_as' in self.config:
            raise Exception("config must omit peer_as, because only iBGP "
                            "is supported yet")
        self.config['peer_as'] = self.config['my_as']

        self.peers = {}
        if self.config['peers']:
            peersAddresses = [x.strip() for x in
                              self.config['peers'].strip().split(",")]
            for peerAddress in peersAddresses:
                log.debug("Creating a peer worker for %s", peerAddress)
                peerWorker = self.peerClass(
                    self, None, peerAddress, self.config)
                self.peers[peerAddress] = peerWorker
                peerWorker.start()

        self.trackedSubs = dict()

        # we need a .name since we'll masquerade as a routeEntry source
        self.name = "BGPManager"

    def stop(self):
        for peer in self.peers.itervalues():
            peer.stop()
        self.routeTableManager.stop()
        for peer in self.peers.itervalues():
            peer.join()
        self.routeTableManager.join()

    def _pushEvent(self, routeEvent):
        log.debug("push event to RouteTableManager")
        self.routeTableManager.enqueue(routeEvent)

    def cleanup(self, worker):
        log.debug("push cleanup event for worker %s to RouteTableManager",
                  worker.name)
        self.routeTableManager.enqueue(WorkerCleanupEvent(worker))

        # TODO(tmmorin): withdraw RTC routes corresponding to worker
        # subscriptions -- currently ok since VPNInstance._stop() calls
        # unsubscribe

    def getLocalAddress(self):
        try:
            return self.config['local_address']
        except KeyError:
            log.error("BGPManager config has no localAddress defined")
            return "0.0.0.0"

    def routeEventSubUnsub(self, subobj):
        if isinstance(subobj, Subscription):
            self._routeEventSubscribe(subobj)
        elif isinstance(subobj, Unsubscription):
            self._routeEventUnsubscribe(subobj)
        else:
            assert(False)

    def _routeEventSubscribe(self, subscription):

        log.debug("subscription: %s", subscription)

        self.routeTableManager.enqueue(subscription)

        # synthesize a RouteEvent for a RouteTarget constraint route
        if (self.config['enable_rtc'] and not isinstance(subscription.worker,
                                                         BGPPeerWorker)):

            firstWorkerForSubscription = self._trackedSubscriptionsAddWorker(
                subscription)

            # FIXME: not excellent to hardcode this here
            if ((subscription.safi in (SAFI.mpls_vpn, SAFI.evpn))
                    and firstWorkerForSubscription):
                routeEvent = RouteEvent(
                    RouteEvent.ADVERTISE,
                    self._subscription2RTCRouteEntry(subscription), self)
                log.debug(
                    "Based on subscription => synthesized RTC %s", routeEvent)
                self.routeTableManager.enqueue(routeEvent)
            else:
                log.debug("No need to synthesize an RTC route "
                          "(firstWorkerForSubscription:%s) ",
                          firstWorkerForSubscription)

    def _routeEventUnsubscribe(self, unsubscription):

        log.debug("unsubscription: %s", unsubscription)

        self.routeTableManager.enqueue(unsubscription)

        if (self.config['enable_rtc'] and not isinstance(unsubscription.worker,
                                                         BGPPeerWorker)):

            wasLastWorkerForSubscription = \
                self._trackedSubscriptionsRemoveWorker(unsubscription)

            # FIXME: not excellent to hardcode this here
            if ((unsubscription.safi in (SAFI.mpls_vpn, SAFI.evpn))
                    and wasLastWorkerForSubscription):
                # synthesize a withdraw RouteEvent for a RouteTarget constraint
                # route
                routeEvent = RouteEvent(
                    RouteEvent.WITHDRAW,
                    self._subscription2RTCRouteEntry(unsubscription), self)
                log.debug("Based on unsubscription => synthesized withdraw"
                          " for RTC %s", routeEvent)
                self.routeTableManager.enqueue(routeEvent)
            else:
                log.debug("No need to synthesize an RTC route "
                          "(wasLastWorkerForSubscription:%s) ",
                          wasLastWorkerForSubscription)

    # FIXME: this can be subject to races
    def _trackedSubscriptionsAddWorker(self, subs):
        '''returns 1 if this is the first worker subscribed'''

        result = 0
        if (subs.afi, subs.safi, subs.routeTarget) not in self.trackedSubs:
            self.trackedSubs[(subs.afi, subs.safi, subs.routeTarget)] = set()
            result = 1

        self.trackedSubs[
            (subs.afi, subs.safi, subs.routeTarget)].add(subs.worker)

        return result

    # FIXME: this can be subject to races
    def _trackedSubscriptionsRemoveWorker(self, subs):
        '''returns 1 if this was the last worker subscribed'''

        self.trackedSubs[(subs.afi, subs.safi, subs.routeTarget)
                         ].remove(subs.worker)

        if len(self.trackedSubs[(subs.afi, subs.safi, subs.routeTarget)]) == 0:
            del self.trackedSubs[(subs.afi, subs.safi, subs.routeTarget)]
            return 1
        else:
            return 0

    def _subscription2RTCRouteEntry(self, subscription):

        route = Route(RouteTargetConstraint(AFI(AFI.ipv4), SAFI(
            SAFI.rtc), self.config['my_as'], subscription.routeTarget))
        nh = Inet(
            1, socket.inet_pton(socket.AF_INET, self.config['local_address']))
        route.attributes.add(NextHop(nh))

        routeEntry = RouteEntry(AFI(AFI.ipv4), SAFI(
            SAFI.rtc), [], route.nlri, route.attributes, self)

        return routeEntry

    # Looking Glass Functions ###################

    def getLGMap(self):
        return {"peers":   (LGMap.COLLECTION,
                            (self.getLGPeerList, self.getLGPeerPathItem)),
                "routes":  (LGMap.FORWARD, self.routeTableManager),
                "workers": (LGMap.FORWARD, self.routeTableManager), }

    def getEstablishedPeersCount(self):
        return reduce(lambda count, peer: count +
                      (isinstance(peer, BGPPeerWorker) and
                       peer.isEstablished()),
                      self.peers.itervalues(), 0)

    def getLGPeerList(self):
        return [{"id": peer.peerAddress,
                 "state": peer.fsm.state} for peer in self.peers.itervalues()]

    def getLGPeerPathItem(self, pathItem):
        return self.peers[pathItem]
