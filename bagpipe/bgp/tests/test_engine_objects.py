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
"""

.. module:: test_vpn_instance
   :synopsis: module with unit tests for bagpipe.bgp.engine.__init__

Validates the behavior of base objects of the engine.

Also validates that ExaBGP classes behave as expected by the code in
bagpipe.bgp.engine.__init__ .

"""
from testtools import TestCase

from exabgp.bgp.message.update import Attributes

from bagpipe.bgp.engine import RouteEntry

from exabgp.reactor.protocol import AFI, SAFI

from exabgp.bgp.message.update.nlri.mpls import MPLSVPN

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message.update.nlri.qualifier.labels import Labels

from exabgp.bgp.message.update.attribute.attribute import Attribute
from exabgp.bgp.message.update.attribute.localpref import LocalPreference
from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended \
    import RouteTargetASN2Number as RouteTarget
from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation

from exabgp.protocol.ip import IP

from bagpipe.bgp.vpn.ipvpn import prefixToPackedIPMask

from exabgp.bgp.message import OUT


class TestEngineObjects(TestCase):

    def setUp(self):
        super(TestEngineObjects, self).setUp()

    def tearDown(self):
        super(TestEngineObjects, self).tearDown()

    ### tests on MPLS VPN NLRIs ###

    def test0_MPLSVPNHashEqual(self):
        '''
        Two indistinct VPN NLRI should
        hash to the same value, and be equal
        '''
        rd = RouteDistinguisher.fromElements("42.42.42.42", 5)

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test1_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *label* should
        hash to the same value, and be equal
        '''
        rd = RouteDistinguisher.fromElements("42.42.42.42", 5)

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([0], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test2_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *nexthop* should
        hash to the same value, and be equal
        '''
        rd = RouteDistinguisher.fromElements("42.42.42.42", 5)

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("77.77.77.77"),
                                  OUT.ANNOUNCE)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test3_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *action* should
        hash to the same value, and be equal
        '''
        rd = RouteDistinguisher.fromElements("42.42.42.42", 5)

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                                  packedPrefix, mask,
                                  Labels([42], True), rd,
                                  IP.pton("45.45.45.45"),
                                  OUT.WITHDRAW)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    ### tests on attributes ###
    def test4_SameNLRIDistinctAttributes(self):
        '''
        Two routes with same NLRI but distinct attributes should
        not be equal
        '''
        nlri = "Foo"

        atts1 = Attributes()
        atts1.add(LocalPreference(10))

        atts2 = Attributes()
        atts2.add(LocalPreference(20))

        entry1 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts1)

        entry2 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts2)

        self.assertNotEqual(entry1, entry2)

    def test5_SameNLRISameAttributes(self):
        '''
        Two routes with same NLRI but and same attributes should
        hash to the same values and be equal.
        '''
        nlri = "Foo"

        atts1 = Attributes()
        atts1.add(LocalPreference(10))

        atts2 = Attributes()
        atts2.add(LocalPreference(10))

        entry1 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts1)

        entry2 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts2)

        self.assertEqual(hash(entry1), hash(entry2))
        self.assertEqual(entry1, entry2)

    def test6_SameNLRISameAttributesOrderMultivalued(self):
        '''
        Two routes with same NLRI but and same attributes should
        hash to the same values and be equal, *even if* for a said
        multivalued attributes, like extended community, the values
        appear in a distinct order
        '''
        nlri = "Foo"

        atts1 = Attributes()
        eComs1 = ExtendedCommunities()
        eComs1.communities.append(RouteTarget(64512, 1))
        eComs1.communities.append(RouteTarget(64512, 2))
        atts1.add(eComs1)

        atts2 = Attributes()
        eComs2 = ExtendedCommunities()
        eComs2.communities.append(RouteTarget(64512, 2))
        eComs2.communities.append(RouteTarget(64512, 1))
        atts2.add(eComs2)

        entry1 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts1)

        entry2 = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), nlri, None,
                            atts2)

        self.assertEqual(hash(entry1), hash(entry2))
        self.assertEqual(entry1, entry2)

    def test8_RouteEntrySetRTs(self):
        atts = Attributes()
        eComs = ExtendedCommunities()
        eComs.communities.append(RouteTarget(64512, 1))
        eComs.communities.append(RouteTarget(64512, 2))
        eComs.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
        atts.add(LocalPreference(20))
        atts.add(eComs)

        entry = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), "Foo", None,
                           atts)

        # check that the routeEntry object has the RTs we wanted
        self.assertIn(RouteTarget(64512, 1), entry.routeTargets)
        self.assertIn(RouteTarget(64512, 2), entry.routeTargets)

        # modify the route targets
        entry.setRouteTargets([RouteTarget(64512, 3), RouteTarget(64512, 1)])

        # check that the new RTs have replaced the old ones
        self.assertIn(RouteTarget(64512, 1), entry.routeTargets)
        self.assertIn(RouteTarget(64512, 3), entry.routeTargets)
        self.assertNotIn(RouteTarget(64512, 2), entry.routeTargets)

        # check that other communities were preserved
        ecoms = entry.attributes[Attribute.CODE.EXTENDED_COMMUNITY].communities
        self.assertIn(Encapsulation(Encapsulation.Type.VXLAN), ecoms)
