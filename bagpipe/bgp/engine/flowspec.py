from exabgp.bgp.message.update.nlri.flow import Flow as ExaBGPFlow
from exabgp.bgp.message.update.nlri.nlri import NLRI

from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI

import logging
log = logging.getLogger(__name__)


@NLRI.register(AFI.ipv4, SAFI.flow_vpn, force=True)
@NLRI.register(AFI.ipv6, SAFI.flow_vpn, force=True)
class Flow(ExaBGPFlow):
    '''This wraps an ExaBGP Flow so that __eq__ and __hash__
    meet the criteria for RouteTableManager (in particular,
    not look at actions and nexthop)
    '''

    def __eq__(self, other):
        return self.rd == other.rd and self.rules == other.rules

    def __hash__(self):
        #FIXME: are dicts hashable ?
        log.warning("flow rules: %s", repr(self.rules))
        return hash((self.rd, repr(self.rules)))


def FlowRouteFactory(afi, rd):
    flowRoute = Flow(afi, safi=SAFI.flow_vpn)
    flowRoute.rd = rd
    return flowRoute
