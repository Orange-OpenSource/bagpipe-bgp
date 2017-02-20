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


def prefix_to_packed_ip_mask(prefix):
    ip_string, mask = prefix.split("/")
    return (exa.IP.pton(ip_string), int(mask))


@exa.NLRI.register(exa.AFI.ipv4, exa.SAFI.mpls_vpn, force=True)
@exa.NLRI.register(exa.AFI.ipv6, exa.SAFI.mpls_vpn, force=True)
class IPVPN(exa.IPVPN):
    # two NLRIs with same RD and prefix, but different labels need to
    # be equal and have the same hash

    def __eq__(self, other):
        return self.rd == other.rd and self.cidr == other.cidr

    def __hash__(self):
        return hash((self.rd, self.cidr._packed))


def IPVPNRouteFactory(afi, prefix, label, rd, nexthop):
    packed_prefix, mask = prefix_to_packed_ip_mask(prefix)

    return IPVPN.new(afi, exa.SAFI(exa.SAFI.mpls_vpn), packed_prefix, mask,
                     exa.Labels([label], True), rd, nexthop)
