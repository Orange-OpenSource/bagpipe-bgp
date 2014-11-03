import time

import logging
import socket

from exabgp.structure.address import AFI, SAFI 
from exabgp.structure.ip import Inet
from exabgp.message.update.attributes import Attributes
from exabgp.message.update.attribute.nexthop import NextHop
from exabgp.message.update.attribute.localpref import LocalPreference
from exabgp.message.update.attribute.communities import RouteTarget

from bagpipe.bgp.engine import RouteEntry, RouteEvent

WAIT_TIME=0.02

RT1 = RouteTarget(64512, None, 10)
RT2 = RouteTarget(64512, None, 20)
RT3 = RouteTarget(64512, None, 30)

NLRI1 = "NLRI1"
NLRI2 = "NLRI2"

NH1 = Inet(1, socket.inet_pton(socket.AF_INET, "1.1.1.1"))
NH2 = Inet(1, socket.inet_pton(socket.AF_INET, "2.2.2.2"))
NH3 = Inet(1, socket.inet_pton(socket.AF_INET, "3.3.3.3"))

NBR = "NBR"
BRR = "BRR"

logging.basicConfig(level=logging.DEBUG,
                    filename='bagpipe-bgp-testsuite.log',
                    format='%(asctime)s %(threadName)-30s %(name)-30s %(levelname)-8s %(message)s')

log = logging.getLogger()

class BaseTestBagPipeBGP():
    
    def _newRouteEvent(self, worker, eventType, nlri, rts, source, nh, lp=0, replacedRouteEntry=None, afi=AFI(AFI.ipv4), safi=SAFI(SAFI.mpls_vpn)):
        attributes = Attributes()
        attributes.add(NextHop(nh))
        attributes.add(LocalPreference(lp))
        routeEvent = RouteEvent(eventType, RouteEntry(afi, safi, rts, nlri, attributes, source), source)
        routeEvent._setReplacedRoute(replacedRouteEntry)

        worker.enqueue(routeEvent)
        
        log.info("Emitting event to %s: %s" % (worker,routeEvent))
        
        return routeEvent

    def _wait(self):
        time.sleep(WAIT_TIME)
        
    def _append_call(self,obj):
        log.info("****** %s ******" % obj)
        self._calls.append(obj)
        