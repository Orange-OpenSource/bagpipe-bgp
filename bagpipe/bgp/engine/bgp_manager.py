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

from bagpipe.bgp.common.looking_glass import LookingGlass

from bagpipe.bgp.engine.route_table_manager import RouteTableManager
from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker
from bagpipe.bgp.engine.exabgp_peer_worker import ExaBGPPeerWorker
from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import EventSource

from bagpipe.bgp.common.looking_glass import LGMap
from bagpipe.bgp.common.utils import getBoolean
from bagpipe.bgp.common import logDecorator

from exabgp.bgp.message.update.nlri.rtc import RTC
from exabgp.reactor.protocol import AFI, SAFI

from exabgp.protocol.ip import IP

log = logging.getLogger(__name__)


class Manager(EventSource, LookingGlass):

    def __init__(self, _config):

        log.debug("Instantiating Manager")

        self.config = _config

        # RTC is defaults to being enabled
        self.config['enable_rtc'] = getBoolean(self.config.get('enable_rtc',
                                                               True))

        if self.config['enable_rtc']:
            firstLocalSubscriberCallback = self.rtcAdvertisementForSub
            lastLocalSubscriberCallback = self.rtcWithdrawalForSub
        else:
            firstLocalSubscriberCallback = None
            lastLocalSubscriberCallback = None

        self.routeTableManager = RouteTableManager(
            firstLocalSubscriberCallback, lastLocalSubscriberCallback)

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
                peerWorker = ExaBGPPeerWorker(self, None, peerAddress,
                                              self.config)
                self.peers[peerAddress] = peerWorker
                peerWorker.start()

        self.trackedSubs = dict()

        # we need a .name since we'll masquerade as a routeEntry source
        self.name = "BGPManager"

        EventSource.__init__(self, self.routeTableManager)

    def __repr__(self):
        return self.__class__.__name__

    @logDecorator.log
    def stop(self):
        for peer in self.peers.itervalues():
            peer.stop()
        self.routeTableManager.stop()
        for peer in self.peers.itervalues():
            peer.join()
        self.routeTableManager.join()

    def getLocalAddress(self):
        try:
            return self.config['local_address']
        except KeyError:
            log.error("BGPManager config has no localAddress defined")
            return "0.0.0.0"

    @logDecorator.log
    def rtcAdvertisementForSub(self, sub):
        if (sub.safi in (SAFI.mpls_vpn, SAFI.evpn)):
            event = RouteEvent(RouteEvent.ADVERTISE,
                               self._subscription2RTCRouteEntry(sub),
                               self)
            log.debug("Based on subscription => synthesized RTC %s", event)
            self.routeTableManager.enqueue(event)

    @logDecorator.log
    def rtcWithdrawalForSub(self, sub):
        if (sub.safi in (SAFI.mpls_vpn, SAFI.evpn)):
            event = RouteEvent(RouteEvent.WITHDRAW,
                               self._subscription2RTCRouteEntry(sub),
                               self)
            log.debug("Based on unsubscription => synthesized withdraw"
                      " for RTC %s", event)
            self.routeTableManager.enqueue(event)

    def _subscription2RTCRouteEntry(self, subscription):

        nlri = RTC.new(AFI(AFI.ipv4), SAFI(SAFI.rtc),
                       self.config['my_as'],
                       subscription.routeTarget,
                       IP.create(self.getLocalAddress()))

        routeEntry = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.rtc), nlri)

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
