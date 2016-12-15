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

from oslo_config import cfg

from bagpipe.bgp.engine.route_table_manager import RouteTableManager
from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker
from bagpipe.bgp.engine.exabgp_peer_worker import ExaBGPPeerWorker
from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import EventSource

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import utils

from exabgp.bgp.message.update.nlri.rtc import RTC
from exabgp.reactor.protocol import AFI, SAFI

from exabgp.protocol.ip import IP

log = logging.getLogger(__name__)

# SAFIs for which RFC4684 is effective
RTC_SAFIS = (SAFI.mpls_vpn, SAFI.evpn)


class Manager(EventSource, lg.LookingGlassMixin):

    _instance = None

    def __init__(self):

        log.debug("Instantiating BGPManager")

        if cfg.CONF.BGP.enable_rtc:
            first_local_subscriber_callback = self.rtc_advertisement_for_sub
            last_local_subscriber_callback = self.rtc_withdrawal_for_sub
        else:
            first_local_subscriber_callback = None
            last_local_subscriber_callback = None

        self.rtm = RouteTableManager(first_local_subscriber_callback,
                                     last_local_subscriber_callback)

        self.rtm.start()

        self.peers = {}
        if cfg.CONF.BGP.peers:
            for peer_address in cfg.CONF.BGP.peers:
                log.debug("Creating a peer worker for %s", peer_address)
                peer_worker = ExaBGPPeerWorker(self, peer_address)
                self.peers[peer_address] = peer_worker
                peer_worker.start()

        # we need a .name since we'll masquerade as a route_entry source
        self.name = "BGPManager"

        EventSource.__init__(self, self.rtm)

    def __repr__(self):
        return self.__class__.__name__

    @log_decorator.log
    def stop(self):
        for peer in self.peers.itervalues():
            peer.stop()
        self.rtm.stop()
        for peer in self.peers.itervalues():
            peer.join()
        self.rtm.join()

    def get_local_address(self):
        return cfg.CONF.BGP.local_address

    @log_decorator.log
    def rtc_advertisement_for_sub(self, sub):
        if sub.safi in RTC_SAFIS:
            event = RouteEvent(RouteEvent.ADVERTISE,
                               self._subscription_2_rtc_route_entry(sub),
                               self)
            log.debug("Based on subscription => synthesized RTC %s", event)
            self.rtm.enqueue(event)

    @log_decorator.log
    def rtc_withdrawal_for_sub(self, sub):
        if sub.safi in RTC_SAFIS:
            event = RouteEvent(RouteEvent.WITHDRAW,
                               self._subscription_2_rtc_route_entry(sub),
                               self)
            log.debug("Based on unsubscription => synthesized withdraw"
                      " for RTC %s", event)
            self.rtm.enqueue(event)

    def _subscription_2_rtc_route_entry(self, subscription):

        nlri = RTC.new(AFI(AFI.ipv4), SAFI(SAFI.rtc),
                       cfg.CONF.BGP.my_as,
                       subscription.route_target,
                       IP.create(self.get_local_address()))

        route_entry = RouteEntry(nlri)

        return route_entry

    @classmethod
    @utils.oslo_synchronized('BGPManager')
    def _create_instance(cls):
        if not cls.has_instance():
            cls._instance = cls()

    @classmethod
    def has_instance(cls):
        return cls._instance is not None

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls):
        # double checked locking
        if not cls.has_instance():
            cls._create_instance()
        return cls._instance

    # Looking Glass Functions ###################

    def get_lg_map(self):
        return {"peers":   (lg.COLLECTION, (self.get_lg_peer_list,
                                            self.get_lg_peer_path_item)),
                "routes":  (lg.FORWARD, self.rtm),
                "workers": (lg.FORWARD, self.rtm), }

    def get_established_peers_count(self):
        return reduce(lambda count, peer: count +
                      (isinstance(peer, BGPPeerWorker) and
                       peer.is_established()),
                      self.peers.itervalues(), 0)

    def get_lg_peer_list(self):
        return [{"id": peer.peer_address,
                 "state": peer.fsm.state} for peer in self.peers.itervalues()]

    def get_lg_peer_path_item(self, path_item):
        return self.peers[path_item]
