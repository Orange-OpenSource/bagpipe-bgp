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


import traceback

import select

import socket

from time import sleep

from bagpipe.bgp.engine.bgp_peer_worker import BGPPeerWorker, \
    KeepAliveReceived, SendKeepAlive, FSM, InitiateConnectionException, \
    OpenWaitTimeout
from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.common.looking_glass import LookingGlass

from bagpipe.exabgp.network.connection import Connection
from bagpipe.exabgp.network.protocol import Protocol, Failure
from bagpipe.exabgp.structure.neighbor import Neighbor

from bagpipe.exabgp.structure.address import AFI, SAFI

from bagpipe.exabgp.message.update.attribute.communities import RouteTarget
from bagpipe.exabgp.message.nop import NOP
from bagpipe.exabgp.message.open import Open, RouterID, Capabilities
from bagpipe.exabgp.message.update import Update
from bagpipe.exabgp.message.keepalive import KeepAlive
from bagpipe.exabgp.message.notification import Notification
from bagpipe.exabgp.message.update.route import Route
from bagpipe.exabgp.message.update.attribute.id import AttributeID


class FakePeer(object):

    '''Dummy class to be able to to plug into exabgp code'''

    def __init__(self, neighbor):
        self.afi = 1  # only IPv4 for now
        self.ip = neighbor.peer_address
        self.neighbor = neighbor


class FakeLocal(object):

    '''Dummy class to be able to to plug into exabgp code'''

    def __init__(self, ip):
        self.afi = 1  # only IPv4 for now
        self.ip = ip


class MyBGPProtocol(Protocol):

    '''Extends exabgp's Protocol class, but changes the new_open method'''

    def new_open(self, restarted, asn4, config, enabledFamilies=[]):
        '''Same as exabgp.Protocol.new_open except that we advertise support
        for MPLS VPN and RTC'''

        asn = self.neighbor.local_as
        # (we don't support ASN4)

        o = Open(4, asn, self.neighbor.router_id.ip, Capabilities()
                 .default(self.neighbor, restarted), self.neighbor.hold_time)

        o.capabilities[Capabilities.MULTIPROTOCOL_EXTENSIONS].remove(
            (AFI(AFI.ipv4), SAFI(SAFI.flow_ipv4)))
        o.capabilities[Capabilities.MULTIPROTOCOL_EXTENSIONS].remove(
            (AFI(AFI.ipv4), SAFI(SAFI.unicast)))
        o.capabilities[Capabilities.MULTIPROTOCOL_EXTENSIONS].remove(
            (AFI(AFI.ipv6), SAFI(SAFI.unicast)))
        for afi_safi in enabledFamilies:
            o.capabilities[
                Capabilities.MULTIPROTOCOL_EXTENSIONS].append(afi_safi)

        if config['enable_rtc']:
            o.capabilities[Capabilities.MULTIPROTOCOL_EXTENSIONS].append(
                (AFI(AFI.ipv4), SAFI(SAFI.rtc)))

        if not self.connection.write(o.message()):
            raise Exception("Error while sending open")

        return o


class ExaBGPPeerWorker(BGPPeerWorker, LookingGlass):

    enabledFamilies = [(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn)),
                       # (AFI(AFI.ipv6), SAFI(SAFI.mpls_vpn)),
                       (AFI(AFI.l2vpn), SAFI(SAFI.evpn))]

    def __init__(self, bgpManager, name, peerAddress, config):
        BGPPeerWorker.__init__(self, bgpManager, name, peerAddress)
        self.config = config
        self.localAddress = self.config['local_address']
        self.peerAddress = peerAddress

        self.connection = None

        self.rtc_active = False
        self._activeFamilies = []

    def _toIdle(self):
        self._activeFamilies = []

    def _initiateConnection(self):
        self.log.debug("Initiate ExaBGP connection to %s from %s",
                       self.peerAddress, self.localAddress)

        self.rtc_active = False

        neighbor = Neighbor()
        neighbor.router_id = RouterID(self.config['local_address'])
        neighbor.local_as = self.config['my_as']
        neighbor.peer_as = self.config['peer_as']
        neighbor.local_address = self.config['local_address']
        neighbor.peer_address = self.peerAddress
        neighbor.parse_routes = True

        # create dummy objects to fake exabgp into talking with us
        peer = FakePeer(neighbor)
        local = FakeLocal(self.localAddress)

        try:
            self.connection = Connection(peer, local, None, None)
        except Failure as e:
            raise InitiateConnectionException(repr(e))

        self.log.debug("Instantiate ExaBGP Protocol")
        self.protocol = MyBGPProtocol(peer, self.connection)
        self.protocol.connect()

        # this is highly similar to exabgp.network.peer._run

        o = self.protocol.new_open(
            False, False, self.config, ExaBGPPeerWorker.enabledFamilies)

        self.log.debug("Send open: [%s]", o)
        self.fsm.state = FSM.OpenSent

        count = 0
        self.log.debug("Wait for open...")
        while not self.shouldStop:
            # FIXME: we should time-out here, at some point
            message = self.protocol.read_open(o, None)

            count += 1
            if isinstance(message, NOP):
                # TODO(tmmorin): check compliance with BGP specs...
                if count > 20:
                    self.connection.close()
                    # FIXME: this should be moved to
                    # BGPPeerWorker in a more generic way
                    # (+ send Notify when needed)
                    raise OpenWaitTimeout("%ds" % int(20 * 0.5))
                sleep(0.5)
                continue

            self.log.debug("Read message: %s", message)

            if isinstance(message, Open):
                break
            else:
                self.log.error("Received unexpected message: %s", message)
                # FIXME

        if self.shouldStop:
            raise Exception("shouldStop")

        # An Open was received
        received_open = message

        self._setHoldTime(received_open.hold_time)

        # Hack to ease troubleshooting, have the real peer address appear in
        # the logs when fakerr is used
        if received_open.router_id.ip != self.peerAddress:
            self.log.info("changing thread name from %s to BGP-x%s, based on"
                          " the router-id advertized in Open (different from"
                          " peerAddress == %s)", self.name,
                          received_open.router_id.ip, self.peerAddress)
            self.name = "BGP-%s/%s" % (self.peerAddress,
                                       received_open.router_id.ip)

        try:
            mp_capabilities = received_open.capabilities[
                Capabilities.MULTIPROTOCOL_EXTENSIONS]
        except Exception:
            mp_capabilities = []

        # check that our peer advertized at least mpls_vpn and evpn
        # capabilities
        self._activeFamilies = []
        for (afi, safi) in (ExaBGPPeerWorker.enabledFamilies +
                            [(AFI(AFI.ipv4), SAFI(SAFI.rtc))]):
            if (afi, safi) not in mp_capabilities:
                self.log.warning(
                    "Peer does not advertise (%s,%s) capability", afi, safi)
            else:
                self.log.info(
                    "Family (%s,%s) successfully negotiated with peer %s",
                    afi, safi, self.peerAddress)
                self._activeFamilies.append((afi, safi))

        if len(self._activeFamilies) == 0:
            self.log.error("No family was negotiated for VPN routes")

        # proceed BGP session

        self.connection.io.setblocking(1)

        self.enqueue(SendKeepAlive)

        self.fsm.state = FSM.OpenConfirm

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
            # subscribe to RTC routes, to be able to propagate them from
            # internal workers to this peer
            self._subscribe(AFI(AFI.ipv4), SAFI(SAFI.rtc))
        else:
            # if we don't use RTC with our peer, then we need to see events for
            # all routes of all active families, to be able to send them to him
            for (afi, safi) in self._activeFamilies:
                self._subscribe(afi, safi)

    def _receiveLoopFun(self):

        select.select([self.connection.io], [], [], 5)

        if not self._queue.empty():
            if self._stopLoops.isSet():
                self.log.info("stopLoops is set -> Close connection and"
                              " Finish receive Loop")
                self.connection.close()
                return 0

        try:
            message = self.protocol.read_message()
        except Notification as e:
            self.log.error("Peer notified us about an error: %s", e)
            return 2
        except Failure as e:
            self.log.warning("Protocol failure: %s", e)
            return 2
        except socket.error as e:
            self.log.warning("Socket error: %s", e)
            return 2
        except Exception as e:
            self.log.error("Error while reading BGP message: %s", e)
            raise

        if message.TYPE in (NOP.TYPE):
            # we arrived here because select call timed-out
            return 1
        elif message.TYPE == Update.TYPE:
            if (self.fsm.state != FSM.Established):
                raise Exception("Update received but not in Established state")
            pass  # see below
        elif message.TYPE == KeepAlive.TYPE:
            if (self.fsm.state == FSM.OpenConfirm):
                self._toEstablished()
            self.enqueue(KeepAliveReceived)
            self.log.debug("Received message: %s", message)
        else:
            self.log.warning("Received unexpected message: %s", message)

        if isinstance(message, Update):
            self.log.info("Received message: UPDATE...")
            if message.routes:
                for route in message.routes:
                    self._processReceivedRoute(route)

        return 1

    def _processReceivedRoute(self, route):
        self.log.info("Received route: %s", route)

        rts = []
        if AttributeID.EXTENDED_COMMUNITY in route.attributes:
            rts = [ecom for ecom in route.attributes[
                   AttributeID.EXTENDED_COMMUNITY].communities
                   if isinstance(ecom, RouteTarget)]

            if not rts:
                raise Exception("Unable to find any Route Targets"
                                "in the received route")

        routeEntry = self._newRouteEntry(route.nlri.afi, route.nlri.safi, rts,
                                         route.nlri, route.attributes)

        if route.action == "announce":
            self._pushEvent(RouteEvent(RouteEvent.ADVERTISE, routeEntry))
        else:
            self._pushEvent(RouteEvent(RouteEvent.WITHDRAW, routeEntry))

        # TODO(tmmorin): move RTC code out-of the peer-specific code
        if (route.nlri.afi, route.nlri.safi) == (AFI(AFI.ipv4),
                                                 SAFI(SAFI.rtc)):
            self.log.info("Received an RTC route")

            if route.nlri.route_target is None:
                self.log.info("Received RTC is a wildcard")

            # the semantic of RTC routes does not distinguish between AFI/SAFIs
            # if our peer subscribed to a Route Target, it means that we needs
            # to send him all routes of any AFI/SAFI carrying this RouteTarget.
            for (afi, safi) in self._activeFamilies:
                if (afi, safi) != (AFI(AFI.ipv4), SAFI(SAFI.rtc)):
                    if route.action == "announce":
                        self._subscribe(afi, safi, route.nlri.route_target)
                    else:  # withdraw
                        self._unsubscribe(afi, safi, route.nlri.route_target)

    def _send(self, data):
        # (error if state not the right one for sending updates)
        self.log.debug("Sending %d bytes on socket to peer %s",
                       len(data), self.peerAddress)
        try:
            self.connection.write(data)
        except Exception as e:
            self.log.error("Was not able to send data: %s", e)

    def _keepAliveMessageData(self):
        return KeepAlive().message()

    def _updateForRouteEvent(self, event):
        r = Route(event.routeEntry.nlri)
        if event.type == event.ADVERTISE:
            self.log.info("Generate UPDATE message: %s", r)
            r.attributes = event.routeEntry.attributes
            try:
                return Update([r]).update(False, self.config['my_as'],
                                          self.config['my_as'])
            except Exception as e:
                self.log.error("Exception while generating message for "
                               "route %s: %s", r, e)
                self.log.warning("%s", traceback.format_exc())
                return ''

        elif event.type == event.WITHDRAW:
            self.log.info("Generate WITHDRAW message: %s", r)
            return Update([r]).withdraw(False, self.config['my_as'],
                                        self.config['my_as'])

    def stop(self):
        if self.connection is not None:
            self.connection.close()
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
