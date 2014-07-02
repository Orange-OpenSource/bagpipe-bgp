import logging
import socket

from exabgp.structure.address import AFI, SAFI 
from exabgp.structure.ip import Inet
from exabgp.message.update.attributes import Attributes
from exabgp.message.update.attribute.nexthop import NextHop
from exabgp.message.update.attribute.communities import RouteTarget

from bagpipe.bgp.engine import RouteEntry, RouteEvent

RT1 = RouteTarget(64512, None, 10)
RT2 = RouteTarget(64512, None, 20)
RT3 = RouteTarget(64512, None, 30)

NLRI1 = "NLRI1"
NLRI2 = "NLRI2"

NH1 = Inet(1, socket.inet_pton(socket.AF_INET, "1.1.1.1"))     
NH2 = Inet(1, socket.inet_pton(socket.AF_INET, "2.2.2.2"))     

logging.basicConfig(level=logging.DEBUG,
                    filename='bagpipe-bgp.log',
                    format='%(asctime)s %(threadName)-30s %(name)-30s %(levelname)-8s %(message)s')

class BaseTestBagPipeBGP():
    
    def _newRouteEvent(self, worker, eventType, nlri, rts, source, nh, afi=AFI(AFI.ipv4), safi=SAFI(SAFI.mpls_vpn)):
        attributes = Attributes()
        attributes.add(NextHop(nh))
        routeEvent = RouteEvent(eventType, RouteEntry(afi, safi, rts, nlri, attributes, source), source)
        worker.enqueue(routeEvent)
        return routeEvent
