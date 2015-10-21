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
import time

import logging
import socket

from bagpipe.bgp.engine import RouteEvent, RouteEntry

from bagpipe.bgp.engine.exabgp_peer_worker import setupExaBGPEnv

setupExaBGPEnv()

from exabgp.reactor.protocol import AFI, SAFI
from exabgp.bgp.message.open.asn import ASN
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget
from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.nexthop import NextHop
from exabgp.bgp.message.update.attribute.localpref import LocalPreference


WAIT_TIME = 0.05

RT1 = RouteTarget(64512, 10)
RT2 = RouteTarget(64512, 20)
RT3 = RouteTarget(64512, 30)
RT4 = RouteTarget(64512, 40)
RT5 = RouteTarget(64512, 50)


class TestNLRI(object):

    def __init__(self, desc):
        self.desc = desc
        self.action = None

    def __repr__(self):
        return self.desc

    def __cmp__(self, other):
        return cmp(self.desc, other.desc)

    def __hash__(self):
        return hash(self.desc)


NLRI1 = TestNLRI("NLRI1")
NLRI2 = TestNLRI("NLRI2")

NH1 = "1.1.1.1"
NH2 = "2.2.2.2"
NH3 = "3.3.3.3"

NBR = "NBR"
BRR = "BRR"

logging.basicConfig(level=logging.DEBUG,
                    filename="bagpipe-bgp-testsuite.log",
                    format="%(asctime)s %(threadName)-30s %(name)-30s "
                    "%(levelname)-8s %(message)s")

log = logging.getLogger()


class BaseTestBagPipeBGP():

    def setEventTargetWorker(self, worker):
        self.eventTargetWorker = worker

    def _newRouteEvent(self, eventType, nlri, rts, source, nh, lp=0,
                       replacedRouteEntry=None,
                       afi=AFI(AFI.ipv4), safi=SAFI(SAFI.mpls_vpn)):
        attributes = Attributes()
        attributes.add(NextHop(nh))
        attributes.add(LocalPreference(lp))
        routeEvent = RouteEvent(eventType, RouteEntry(
            afi, safi, nlri, rts, attributes, source), source)
        routeEvent.setReplacedRoute(replacedRouteEntry)

        self.eventTargetWorker.enqueue(routeEvent)

        log.info("*** Emitting event to %s: %s",
                 self.eventTargetWorker, routeEvent)

        self._wait()

        return routeEvent

    def _wait(self):
        time.sleep(WAIT_TIME)

    def _append_call(self, obj):
        log.info("****** %s ******", obj)
        self._calls.append(obj)
