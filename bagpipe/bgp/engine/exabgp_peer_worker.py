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

import traceback

from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker
from bagpipe.bgp.engine.bgp_peer_worker import FSM
from bagpipe.bgp.engine.bgp_peer_worker import KeepAliveReceived
from bagpipe.bgp.engine.bgp_peer_worker import InitiateConnectionException
from bagpipe.bgp.engine.bgp_peer_worker import OpenWaitTimeout
from bagpipe.bgp.engine.bgp_peer_worker import StoppedException

from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.common.looking_glass import LookingGlass

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

from exabgp.bgp.message import NOP
from exabgp.bgp.message import Notification
from exabgp.bgp.message import Update
from exabgp.bgp.message import KeepAlive

from exabgp.bgp.message import IN

from exabgp.bgp.fsm import FSM as ExaFSM

import logging

log = logging.getLogger(__name__)


def setupExaBGPEnv():
    # initialize ExaBGP config
    from exabgp.configuration.environment import environment
    import exabgp.configuration.setup  # initialises environment.configuration
    environment.application = 'bagpipe-bgp'
    conf = environment.setup(None)
    # tell exabgp to parse routes:
    conf.log.routes = True
    # FIXME: find a way to redirect exabgp logs into bagpipe's
    conf.log.destination = "stderr"
    conf.log.level = repr(log.getEffectiveLevel())
    conf.log.all = True
    conf.log.packets = True

setupExaBGPEnv()


TranslateExaBGPState = {ExaFSM.IDLE: FSM.Idle,
                        ExaFSM.ACTIVE: FSM.Active,
                        ExaFSM.CONNECT: FSM.Connect,
                        ExaFSM.OPENSENT: FSM.OpenSent,
                        ExaFSM.OPENCONFIRM: FSM.OpenConfirm,
                        ExaFSM.ESTABLISHED: FSM.Established,
                        }


class ExaBGPPeerWorker(BGPPeerWorker, LookingGlass):

    enabledFamilies = [(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn)),
                       # (AFI(AFI.ipv6), SAFI(SAFI.mpls_vpn)),
                       (AFI(AFI.l2vpn), SAFI(SAFI.evpn))]

    def __init__(self, routeTableManager, name, peerAddress, config):
        BGPPeerWorker.__init__(self, routeTableManager, name, peerAddress)
        self.config = config
        self.localAddress = self.config['local_address']
        self.peerAddress = peerAddress

        self.peer = None

        self.rtc_active = False
        self._activeFamilies = []

    def _toIdle(self):
        self._activeFamilies = []

        if self.peer is not None:
            self.log.info("Stopping peer before reinit")
            self.peer.stop()
            self.peer = None

    def _initiateConnection(self):
        self.log.debug("Initiate ExaBGP connection to %s from %s",
                       self.peerAddress, self.localAddress)

        self.rtc_active = False

        neighbor = Neighbor()
        neighbor.router_id = RouterID(self.localAddress)
        neighbor.local_as = ASN(self.config['my_as'])
        neighbor.peer_as = ASN(self.config['peer_as'])
        neighbor.local_address = IP.create(self.localAddress)
        neighbor.peer_address = IP.create(self.peerAddress)

        for afi_safi in self.__class__.enabledFamilies:
            neighbor.add_family(afi_safi)

        if self.config['enable_rtc']:
            neighbor.add_family((AFI(AFI.ipv4), SAFI(SAFI.rtc)))

        self.log.debug("Instantiate ExaBGP Peer")
        self.peer = Peer(neighbor, None)

        try:
            for action in self.peer._connect():
                self.fsm.state = TranslateExaBGPState[
                    self.peer._outgoing.fsm.state]

                if action == ACTION.LATER:
                    time.sleep(2)
                elif action == ACTION.NOW:
                    time.sleep(0.1)

                if self.shouldStop or action == ACTION.CLOSE:
                    raise StoppedException()
        except Interrupted:
            raise StoppedException()
        except LostConnection as e:
            raise
        # FIXME: catch exception on opensent timeout and throw OpenWaitTimeout

        # check the capabilities of the session just established...

        self.protocol = self.peer._outgoing.proto

        received_open = self.protocol.negotiated.received_open

        self._setHoldTime(self.protocol.negotiated.holdtime)

        mp_capabilities = received_open.capabilities.get(
            Capability.CODE.MULTIPROTOCOL, [])

        # check that our peer advertized at least mpls_vpn and evpn
        # capabilities
        self._activeFamilies = []
        for (afi, safi) in (self.__class__.enabledFamilies +
                            [(AFI(AFI.ipv4), SAFI(SAFI.rtc))]):
            if (afi, safi) not in mp_capabilities:
                if (((afi, safi) != (AFI(AFI.ipv4), SAFI(SAFI.rtc))) or
                        self.config['enable_rtc']):
                    self.log.warning("Peer does not advertise (%s,%s) "
                                     "capability", afi, safi)
            else:
                self.log.info(
                    "Family (%s,%s) successfully negotiated with peer %s",
                    afi, safi, self.peerAddress)
                self._activeFamilies.append((afi, safi))

        if len(self._activeFamilies) == 0:
            self.log.error("No family was negotiated for VPN routes")

        self.rtc_active = False

        if self.config['enable_rtc']:
            if (AFI(AFI.ipv4), SAFI(SAFI.rtc)) in mp_capabilities:
                self.log.info(
                    "RTC successfully enabled with peer %s", self.peerAddress)
                self.rtc_active = True
            else:
                self.log.warning(
                    "enable_rtc True but peer not configured for RTC")

    def _toEstablished(self):
        BGPPeerWorker._toEstablished(self)

        if self.rtc_active:
            self.log.debug("RTC active, subscribing to all RTC routes")
            # subscribe to RTC routes, to be able to propagate them from
            # internal workers to this peer
            self._subscribe(AFI(AFI.ipv4), SAFI(SAFI.rtc))
        else:
            self.log.debug("RTC inactive, subscribing to all active families")
            # if we don't use RTC with our peer, then we need to see events for
            # all routes of all active families, to be able to send them to him
            for (afi, safi) in self._activeFamilies:
                self._subscribe(afi, safi)

    def _receiveLoopFun(self):

        try:
            select.select([self.protocol.connection.io], [], [], 2)
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
            if (self.fsm.state != FSM.Established):
                raise Exception("Update received but not in Established state")
            # more below
        elif message.ID == KeepAlive.ID:
            self.enqueue(KeepAliveReceived)
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
                    self._processReceivedRoute(action, nlri,
                                               message.attributes)
        return 1

    def _processReceivedRoute(self, action, nlri, attributes):
        self.log.info("Received route: %s, %s", nlri, attributes)

        routeEntry = RouteEntry(nlri.afi, nlri.safi,
                                nlri, None, attributes)

        if action == IN.ANNOUNCED:
            self._advertiseRoute(routeEntry)
        elif action == IN.WITHDRAWN:
            self._withdrawRoute(routeEntry)
        else:
            assert(False)

        # TODO(tmmorin): move RTC code out-of the peer-specific code
        if (nlri.afi, nlri.safi) == (AFI(AFI.ipv4),
                                     SAFI(SAFI.rtc)):
            self.log.info("Received an RTC route")

            if nlri.rt is None:
                self.log.info("Received RTC is a wildcard")

            # the semantic of RTC routes does not distinguish between AFI/SAFIs
            # if our peer subscribed to a Route Target, it means that we needs
            # to send him all routes of any AFI/SAFI carrying this RouteTarget.
            for (afi, safi) in self._activeFamilies:
                if (afi, safi) != (AFI(AFI.ipv4), SAFI(SAFI.rtc)):
                    if action == IN.ANNOUNCED:
                        self._subscribe(afi, safi, nlri.rt)
                    elif action == IN.WITHDRAWN:
                        self._unsubscribe(afi, safi, nlri.rt)
                    else:
                        assert(False)

    def _send(self, data):
        # (error if state not the right one for sending updates)
        self.log.debug("Sending %d bytes on socket to peer %s",
                       len(data), self.peerAddress)
        try:
            for _ in self.protocol.connection.writer(data):
                pass
        except Exception as e:
            self.log.error("Was not able to send data: %s", e)
            self.log.warning("%s", traceback.format_exc())

    def _keepAliveMessageData(self):
        return KeepAlive().message()

    def _updateForRouteEvent(self, event):
        try:
            r = Update([event.routeEntry.nlri], event.routeEntry.attributes)
            return ''.join(r.messages(self.protocol.negotiated))
        except Exception as e:
            self.log.error("Exception while generating message for "
                           "route %s: %s", r, e)
            self.log.warning("%s", traceback.format_exc())
            return ''

    def stop(self):
        if self.peer is not None:
            self.peer.stop()
        BGPPeerWorker.stop(self)

    # Looking Glass ###############

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
            "peeringAddresses": {"peerAddress":  self.peerAddress,
                                 "localAddress": self.localAddress},
            "as_info": {"local": self.config['my_as'],
                        "peer":  self.config['peer_as']},
            "rtc": {"active": self.rtc_active,
                    "enabled": self.config['enable_rtc']},
            "active_families": [repr(f) for f in self._activeFamilies],
        }
