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

from bagpipe.bgp.engine import exa


@exa.NLRI.register(exa.AFI.ipv4, exa.SAFI.flow_vpn, force=True)
@exa.NLRI.register(exa.AFI.ipv6, exa.SAFI.flow_vpn, force=True)
class Flow(exa.Flow):
    '''This wraps an ExaBGP Flow so that __eq__ and __hash__
    meet the criteria for RouteTableManager (in particular,
    not look at actions and nexthop)
    '''

    def __eq__(self, other):
        return self.pack() == other.pack()

    def __hash__(self):
        return hash(self.pack())

    def __repr__(self):
        return str(self)


def FlowRouteFactory(afi, rd):
    flow_route = Flow(afi, safi=exa.SAFI.flow_vpn)
    flow_route.rd = rd
    return flow_route
