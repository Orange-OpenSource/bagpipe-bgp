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

import select
import time

from collections import defaultdict

import traceback

import logging

from oslo_config import cfg

from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker
from bagpipe.bgp.engine.bgp_peer_worker import FSM
from bagpipe.bgp.engine.bgp_peer_worker import KEEP_ALIVE_RECEIVED
from bagpipe.bgp.engine.bgp_peer_worker import InitiateConnectionException
from bagpipe.bgp.engine.bgp_peer_worker import OpenWaitTimeout
from bagpipe.bgp.engine.bgp_peer_worker import StoppedException
from bagpipe.bgp.engine.bgp_peer_worker import DEFAULT_HOLDTIME

from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.common import looking_glass as lg

from exabgp.reactor.peer import Peer
from exabgp.reactor.peer import Interrupted
from exabgp.reactor.peer import ACTION
from exabgp.bgp.neighbor import Neighbor
from exabgp.bgp.message.open.asn import ASN

from exabgp.protocol.ip import IP

from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI
from exabgp.reactor.network.error import LostConnection

from exabgp.bgp.message.open import RouterID
from exabgp.bgp.message.open.capability.capability import Capability
from exabgp.bgp.message.open.holdtime import HoldTime

from exabgp.bgp.message import NOP
from exabgp.bgp.message import Notification
from exabgp.bgp.message import Notify
from exabgp.bgp.message import Update
from exabgp.bgp.message import KeepAlive

from exabgp.bgp.message import IN

from exabgp.bgp.fsm import FSM as ExaFSM

log = logging.getLogger(__name__)


def setup_exabgp_env():
    # initialize ExaBGP config
    from exabgp.configuration.setup import environment
    environment.application = 'bagpipe-bgp'
    env = environment.setup(None)
    # tell exabgp to parse routes:
    env.log.routes = True
    # FIXME: find a way to redirect exabgp logs into bagpipe's
    env.log.destination = "stderr"
    if log.getEffectiveLevel():
        env.log.level = environment.syslog_value(
            logging.getLevelName(log.getEffectiveLevel())
            )
    else:
        env.log.level = environment.syslog_value('INFO')
    env.log.all = True
    env.log.packets = True


TRANSLATE_EXABGP_STATE = {ExaFSM.IDLE: FSM.Idle,
                          ExaFSM.ACTIVE: FSM.Active,
                          ExaFSM.CONNECT: FSM.Connect,
                          ExaFSM.OPENSENT: FSM.OpenSent,
                          ExaFSM.OPENCONFIRM: FSM.OpenConfirm,
                          ExaFSM.ESTABLISHED: FSM.Established,
                          }


class ExaBGPPeerWorker(BGPPeerWorker, lg.LookingGlassMixin):

    enabled_families = [(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn)),
                        # (AFI(AFI.ipv6), SAFI(SAFI.mpls_vpn)),
                        (AFI(AFI.l2vpn), SAFI(SAFI.evpn)),
                        (AFI(AFI.ipv4), SAFI(SAFI.flow_vpn))]

    def __init__(self, bgp_manager, peer_address):
        BGPPeerWorker.__init__(self, bgp_manager, peer_address)

        self.local_address = cfg.CONF.BGP.local_address
        self.peer_address = peer_address

        self.peer = None

        self.rtc_active = False
        self._active_families = []

    # hooks into BGPPeerWorker state changes

    def _stop_and_clean(self):
        super(ExaBGPPeerWorker, self)._stop_and_clean()

        self._active_families = []

        if self.peer is not None:
            self.log.info("Clearing peer")
            if self.peer._outgoing.proto:
                self.peer._outgoing.proto.close()
            self.peer.stop()
            self.peer = None

    def _to_established(self):
        super(ExaBGPPeerWorker, self)._to_established()

        if self.rtc_active:
            self.log.debug("RTC active, subscribing to all RTC routes")
            # subscribe to RTC routes, to be able to propagate them from
            # internal workers to this peer
            self._subscribe(AFI(AFI.ipv4), SAFI(SAFI.rtc))
        else:
            self.log.debug("RTC inactive, subscribing to all active families")
            # if we don't use RTC with our peer, then we need to see events for
            # all routes of all active families, to be able to send them to him
            for (afi, safi) in self._active_families:
                self._subscribe(afi, safi)

    # implementation of BGPPeerWorker abstract methods

    def _initiate_connection(self):
        self.log.debug("Initiate ExaBGP connection to %s from %s",
                       self.peer_address, self.local_address)

        self.rtc_active = False

        neighbor = Neighbor()
        neighbor.router_id = RouterID(self.local_address)
        neighbor.local_as = ASN(cfg.CONF.BGP.my_as)
        # no support for eBGP yet:
        neighbor.peer_as = ASN(cfg.CONF.BGP.my_as)
        neighbor.local_address = IP.create(self.local_address)
        neighbor.md5_ip = IP.create(self.local_address)
        neighbor.peer_address = IP.create(self.peer_address)
        neighbor.hold_time = HoldTime(DEFAULT_HOLDTIME)
        neighbor.api = defaultdict(list)

        for afi_safi in self.enabled_families:
            neighbor.add_family(afi_safi)

        if cfg.CONF.BGP.enable_rtc:
            neighbor.add_family((AFI(AFI.ipv4), SAFI(SAFI.rtc)))

        self.log.debug("Instantiate ExaBGP Peer")
        self.peer = Peer(neighbor, None)

        try:
            for action in self.peer._connect():
                self.fsm.state = TRANSLATE_EXABGP_STATE[
                    self.peer._outgoing.fsm.state]

                if action == ACTION.LATER:
                    time.sleep(2)
                elif action == ACTION.NOW:
                    time.sleep(0.1)

                if self.should_stop:
                    self.log.debug("We're closing, raise StoppedException")
                    raise StoppedException()

                if action == ACTION.CLOSE:
                    self.log.debug("Socket status is CLOSE, "
                                   "raise InitiateConnectionException")
                    raise InitiateConnectionException("Socket is closed")
        except Interrupted:
            self.log.debug("Connect was interrupted, "
                           "raise InitiateConnectionException")
            raise InitiateConnectionException("Connect was interrupted")
        except Notify as e:
            self.log.debug("Notify: %s", e)
            if (e.code, e.subcode) == (1, 1):
                raise OpenWaitTimeout(str(e))
            else:
                raise Exception("Notify received: %s" % e)
        except LostConnection as e:
            raise

        # check the capabilities of the session just established...

        self.protocol = self.peer._outgoing.proto

        received_open = self.protocol.negotiated.received_open

        self._set_hold_time(self.protocol.negotiated.holdtime)

        mp_capabilities = received_open.capabilities.get(
            Capability.CODE.MULTIPROTOCOL, [])

        # check that our peer advertized at least mpls_vpn and evpn
        # capabilities
        self._active_families = []
        for (afi, safi) in (self.__class__.enabled_families +
                            [(AFI(AFI.ipv4), SAFI(SAFI.rtc))]):
            if (afi, safi) not in mp_capabilities:
                if (((afi, safi) != (AFI(AFI.ipv4), SAFI(SAFI.rtc))) or
                        cfg.CONF.BGP.enable_rtc):
                    self.log.warning("Peer does not advertise (%s,%s) "
                                     "capability", afi, safi)
            else:
                self.log.info(
                    "Family (%s,%s) successfully negotiated with peer %s",
                    afi, safi, self.peer_address)
                self._active_families.append((afi, safi))

        if len(self._active_families) == 0:
            self.log.error("No family was negotiated for VPN routes")

        self.rtc_active = False

        if cfg.CONF.BGP.enable_rtc:
            if (AFI(AFI.ipv4), SAFI(SAFI.rtc)) in mp_capabilities:
                self.log.info(
                    "RTC successfully enabled with peer %s", self.peer_address)
                self.rtc_active = True
            else:
                self.log.warning(
                    "enable_rtc True but peer not configured for RTC")

    def _receive_loop_fun(self):

        try:
            select.select([self.protocol.connection.io], [], [], 2)

            if not self.protocol.connection:
                raise Exception("lost connection")

            message = self.protocol.read_message().next()

            if message.ID != NOP.ID:
                self.log.debug("protocol read message: %s", message)
        except Notification as e:
            self.log.error("Notification: %s", e)
            return 2
        except LostConnection as e:
            self.log.warning("Lost connection while waiting for message: %s",
                             e)
            return 2
        except TypeError as e:
            self.log.error("Error while reading BGP message: %s", e)
            return 2
        except Exception as e:
            self.log.error("Error while reading BGP message: %s", e)
            raise

        if message.ID == NOP.ID:
            return 1
        if message.ID == Update.ID:
            if self.fsm.state != FSM.Established:
                raise Exception("Update received but not in Established state")
            # more below
        elif message.ID == KeepAlive.ID:
            self.enqueue(KEEP_ALIVE_RECEIVED)
            self.log.debug("Received message: %s", message)
        else:
            self.log.warning("Received unexpected message: %s", message)

        if isinstance(message, Update):
            if message.nlris:
                for nlri in message.nlris:
                    if nlri.action == IN.ANNOUNCED:
                        action = RouteEvent.ADVERTISE
                    elif nlri.action == IN.WITHDRAWN:
                        action = RouteEvent.WITHDRAW
                    else:
                        raise Exception("should not be reached (action:%s)",
                                        nlri.action)
                    self._process_received_route(action, nlri,
                                                 message.attributes)
        return 1

    def _process_received_route(self, action, nlri, attributes):
        self.log.info("Received route: %s, %s", nlri, attributes)

        route_entry = RouteEntry(nlri, None, attributes)

        if action == IN.ANNOUNCED:
            self._advertise_route(route_entry)
        elif action == IN.WITHDRAWN:
            self._withdraw_route(route_entry)
        else:
            raise Exception("unsupported action ??? (%s)" % action)

        # TODO(tmmorin): move RTC code out-of the peer-specific code
        if (nlri.afi, nlri.safi) == (AFI(AFI.ipv4),
                                     SAFI(SAFI.rtc)):
            self.log.info("Received an RTC route")

            if nlri.rt is None:
                self.log.info("Received RTC is a wildcard")

            # the semantic of RTC routes does not distinguish between AFI/SAFIs
            # if our peer subscribed to a Route Target, it means that we needs
            # to send him all routes of any AFI/SAFI carrying this RouteTarget.
            for (afi, safi) in self._active_families:
                if (afi, safi) != (AFI(AFI.ipv4), SAFI(SAFI.rtc)):
                    if action == IN.ANNOUNCED:
                        self._subscribe(afi, safi, nlri.rt)
                    elif action == IN.WITHDRAWN:
                        self._unsubscribe(afi, safi, nlri.rt)
                    else:
                        raise Exception("unsupported action ??? (%s)" % action)

    def _send(self, data):
        # (error if state not the right one for sending updates)
        self.log.debug("Sending %d bytes on socket to peer %s",
                       len(data), self.peer_address)
        try:
            for _ in self.protocol.connection.writer(data):
                pass
        except Exception as e:
            self.log.error("Was not able to send data: %s", e)
            self.log.warning("%s", traceback.format_exc())

    def _keep_alive_message_data(self):
        return KeepAlive().message()

    def _update_for_route_event(self, event):
        try:
            r = Update([event.route_entry.nlri], event.route_entry.attributes)
            return ''.join(r.messages(self.protocol.negotiated))
        except Exception as e:
            self.log.error("Exception while generating message for "
                           "route %s: %s", r, e)
            self.log.warning("%s", traceback.format_exc())
            return ''

    # Looking Glass ###############

    def get_log_local_info(self, path_prefix):
        return {
            "peeringAddresses": {"peer_address":  self.peer_address,
                                 "local_address": self.local_address},
            "as_info": {"local": cfg.CONF.BGP.my_as,
                        "peer":  cfg.CONF.BGP.my_as},
            "rtc": {"active": self.rtc_active,
                    "enabled": cfg.CONF.BGP.enable_rtc},
            "active_families": [repr(f) for f in self._active_families],
        }
