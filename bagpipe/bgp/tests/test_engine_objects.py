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
import logging

from testtools import TestCase

from bagpipe.bgp.engine import RouteEntry


from exabgp.reactor.protocol import AFI, SAFI

from exabgp.bgp.message.update.nlri.mpls import MPLSVPN

from exabgp.bgp.message.update import Attributes

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

from exabgp.bgp.message.update.nlri.evpn.mac import MAC as EVPNMAC
from exabgp.bgp.message.update.nlri.qualifier.esi import ESI
from exabgp.bgp.message.update.nlri.qualifier.etag import EthernetTag
from exabgp.bgp.message.update.nlri.qualifier.mac import MAC


from exabgp.protocol.ip import IP

from bagpipe.bgp.vpn.ipvpn import prefixToPackedIPMask

from exabgp.bgp.message import OUT

log = logging.getLogger(__name__)


class TestEngineObjects(TestCase):

    def setUp(self):
        super(TestEngineObjects, self).setUp()

    def tearDown(self):
        super(TestEngineObjects, self).tearDown()

    # tests on MPLS VPN NLRIs

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

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([42], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("45.45.45.45"),
                        OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([0], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("45.45.45.45"),
                        OUT.ANNOUNCE)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test2_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *nexthop* should
        hash to the same value, and be equal
        '''
        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([42], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("45.45.45.45"),
                        OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([42], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("77.77.77.77"),
                        OUT.ANNOUNCE)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test3_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *action* should
        hash to the same value, and be equal
        '''

        packedPrefix, mask = prefixToPackedIPMask("1.1.1.1/32")

        nlri1 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([42], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("45.45.45.45"),
                        OUT.ANNOUNCE)

        nlri2 = MPLSVPN(AFI(AFI.ipv4), SAFI(SAFI.mpls_vpn),
                        packedPrefix, mask,
                        Labels([42], True),
                        RouteDistinguisher.fromElements("42.42.42.42", 5),
                        IP.pton("45.45.45.45"),
                        OUT.WITHDRAW)

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    # Tests on EVPN NLRIs

    def test100_EVPNMACHashEqual(self):
        '''
        Two indistinct EVPN NLRI should
        hash to the same value, and be equal
        '''

        nlri1 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"))

        nlri2 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"))

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test101_EVPNHashEqual_somefieldsvary(self):
        '''
        Two EVPN MAC NLRIs differing by their ESI or label or RD,
        or nexthop, but otherwise identical should hash to the same value,
        and be equal
        '''

        nlri0 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"))

        # Esi
        nlri1 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(1),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"))

        # label
        nlri2 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([4444], True),
                        IP.create("1.1.1.1"))

        # IP: different IPs, but same MACs: different route
        nlri3 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("2.2.2.2"))

        # with a next hop...
        nlri4 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"),
                        IP.pton("10.10.10.10"))
        nlri5 = EVPNMAC(RouteDistinguisher.fromElements("42.42.42.42", 5),
                        ESI(0),
                        EthernetTag(111),
                        MAC("01:02:03:04:05:06"), 6*8,
                        Labels([42], True),
                        IP.create("1.1.1.1"),
                        IP.pton("11.11.11.11"))

        self.assertEqual(hash(nlri0), hash(nlri1))
        self.assertEqual(hash(nlri0), hash(nlri2))
        self.assertEqual(hash(nlri0), hash(nlri4))
        self.assertEqual(nlri0, nlri1)
        self.assertEqual(nlri0, nlri2)
        self.assertEqual(nlri0, nlri4)
        self.assertEqual(nlri1, nlri2)
        self.assertEqual(nlri1, nlri4)
        self.assertEqual(nlri2, nlri4)
        self.assertEqual(nlri4, nlri5)

        self.assertNotEqual(hash(nlri0), hash(nlri3))
        self.assertNotEqual(nlri0, nlri3)
        self.assertNotEqual(nlri1, nlri3)
        self.assertNotEqual(nlri2, nlri3)
        self.assertNotEqual(nlri3, nlri4)

    # tests on attributes

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
        eComs1.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
        eComs1.communities.append(RouteTarget(64512, 2))
        atts1.add(eComs1)

        atts2 = Attributes()
        eComs2 = ExtendedCommunities()
        eComs2.communities.append(RouteTarget(64512, 2))
        eComs2.communities.append(RouteTarget(64512, 1))
        eComs2.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
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

        # also need to check the RTs in the attributes
        ecoms = entry.attributes[Attribute.CODE.EXTENDED_COMMUNITY].communities
        self.assertIn(RouteTarget(64512, 1), ecoms)
        self.assertIn(RouteTarget(64512, 3), ecoms)
        self.assertNotIn(RouteTarget(64512, 2), ecoms)

        # check that other communities were preserved
        self.assertIn(Encapsulation(Encapsulation.Type.VXLAN), ecoms)

    def test9_RouteEntryRTsAsInitParam(self):
        atts = Attributes()
        eComs = ExtendedCommunities()
        eComs.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
        atts.add(LocalPreference(20))
        atts.add(eComs)

        rts = [RouteTarget(64512, 1), RouteTarget(64512, 2)]

        entry = RouteEntry(AFI(AFI.ipv4), SAFI(SAFI.unicast), "Foo", rts,
                           atts)

        self.assertIn(RouteTarget(64512, 1), entry.routeTargets)
        self.assertIn(RouteTarget(64512, 2), entry.routeTargets)

        ecoms = entry.attributes[Attribute.CODE.EXTENDED_COMMUNITY].communities
        self.assertIn(RouteTarget(64512, 1), ecoms)
        self.assertIn(RouteTarget(64512, 2), ecoms)
        self.assertIn(Encapsulation(Encapsulation.Type.VXLAN), ecoms)

    def test10_Ecoms(self):
        eComs1 = ExtendedCommunities()
        eComs1.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
        atts1 = Attributes()
        atts1.add(eComs1)

        eComs2 = ExtendedCommunities()
        eComs2.communities.append(Encapsulation(Encapsulation.Type.VXLAN))
        eComs2.communities.append(RouteTarget(64512, 1))
        atts2 = Attributes()
        atts2.add(eComs2)

        self.assertFalse(atts1.sameValuesAs(atts2))
        self.assertFalse(atts2.sameValuesAs(atts1))

    def test11_RTs(self):
        rt1a = RouteTarget(64512, 1)
        rt1b = RouteTarget(64512, 1)
        #rt2 = RouteTarget(64512, 1, False)  # required for
                                             # compat with old bagpipe

        rt3 = RouteTarget(64512, 2)
        rt4 = RouteTarget(64513, 1)

        self.assertEqual(hash(rt1a), hash(rt1b))
        #self.assertEqual(hash(rt1a), hash(rt2))
        self.assertNotEqual(hash(rt1a), hash(rt3))
        self.assertNotEqual(hash(rt1a), hash(rt4))

        self.assertEqual(rt1a, rt1b)
        #self.assertEqual(rt1a, rt2)
        self.assertNotEqual(rt1a, rt3)
        self.assertNotEqual(rt1a, rt4)

        self.assertEqual(set([rt1a]), set([rt1b]))
        #self.assertEqual(set([rt1a]), set([rt2]))
        self.assertEqual(1, len(set([rt1a]).intersection(set([rt1b]))))
        #self.assertEqual(1, len(set([rt2]).intersection(set([rt1b]))))
