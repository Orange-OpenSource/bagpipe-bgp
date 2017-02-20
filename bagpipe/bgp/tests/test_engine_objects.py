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

from bagpipe.bgp import engine
from bagpipe.bgp.engine import exa
from bagpipe.bgp import tests


TEST_RD = exa.RouteDistinguisher.fromElements("42.42.42.42", 5)


class TestEngineObjects(TestCase):

    def setUp(self):
        super(TestEngineObjects, self).setUp()

    def tearDown(self):
        super(TestEngineObjects, self).tearDown()

    # Tests on EVPN NLRIs

    def test_100_evpn_mac_hash_equal(self):
        '''
        Two indistinct EVPN NLRI should
        hash to the same value, and be equal
        '''

        nlri1 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"))

        nlri2 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"))

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_101_evpn_hash_equal_somefieldsvary(self):
        '''
        Two EVPN MAC NLRIs differing by their ESI or label or RD,
        or nexthop, but otherwise identical should hash to the same value,
        and be equal
        '''

        nlri0 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"))

        # Esi
        nlri1 = exa.EVPNMAC(TEST_RD,
                            exa.ESI([1 for _ in range(0, 10)]),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"))

        # label
        nlri2 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([4444], True),
                            exa.IP.create("1.1.1.1"))

        # IP: different IPs, but same MACs: different route
        nlri3 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("2.2.2.2"))

        # with a next hop...
        nlri4 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"),
                            exa.IP.pton("10.10.10.10"))
        nlri5 = exa.EVPNMAC(TEST_RD,
                            exa.ESI(),
                            exa.EthernetTag(111),
                            exa.MAC("01:02:03:04:05:06"), 6*8,
                            exa.Labels([42], True),
                            exa.IP.create("1.1.1.1"),
                            exa.IP.pton("11.11.11.11"))

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

    def test_4_same_nlri_distinct_attributes(self):
        '''
        Two routes with same NLRI but distinct attributes should
        not be equal
        '''
        atts1 = exa.Attributes()
        atts1.add(exa.LocalPreference(10))

        atts2 = exa.Attributes()
        atts2.add(exa.LocalPreference(20))

        entry1 = engine.RouteEntry(tests.NLRI1, None, atts1)
        entry2 = engine.RouteEntry(tests.NLRI1, None, atts2)

        self.assertNotEqual(entry1, entry2)

    def test_5_same_nlri_same_attributes(self):
        '''
        Two routes with same NLRI but and same attributes should
        hash to the same values and be equal.
        '''
        atts1 = exa.Attributes()
        atts1.add(exa.LocalPreference(10))

        atts2 = exa.Attributes()
        atts2.add(exa.LocalPreference(10))

        entry1 = engine.RouteEntry(tests.NLRI1, None, atts1)
        entry2 = engine.RouteEntry(tests.NLRI1, None, atts2)

        self.assertEqual(hash(entry1), hash(entry2))
        self.assertEqual(entry1, entry2)

    def test_6_same_nlri_same_attributes_order_multivalued(self):
        '''
        Two routes with same NLRI but and same attributes should
        hash to the same values and be equal, *even if* for a said
        multivalued attributes, like extended community, the values
        appear in a distinct order
        '''
        atts1 = exa.Attributes()
        ecoms1 = exa.ExtendedCommunities()
        ecoms1.communities.append(exa.RouteTarget(64512, 1))
        ecoms1.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        ecoms1.communities.append(exa.RouteTarget(64512, 2))
        atts1.add(ecoms1)

        atts2 = exa.Attributes()
        ecoms2 = exa.ExtendedCommunities()
        ecoms2.communities.append(exa.RouteTarget(64512, 2))
        ecoms2.communities.append(exa.RouteTarget(64512, 1))
        ecoms2.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        atts2.add(ecoms2)

        entry1 = engine.RouteEntry(tests.NLRI1, None, atts1)
        entry2 = engine.RouteEntry(tests.NLRI1, None, atts2)

        self.assertEqual(hash(entry1), hash(entry2))
        self.assertEqual(entry1, entry2)

    def test_8_route_entry_set_rts(self):
        atts = exa.Attributes()
        ecoms = exa.ExtendedCommunities()
        ecoms.communities.append(exa.RouteTarget(64512, 1))
        ecoms.communities.append(exa.RouteTarget(64512, 2))
        ecoms.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        atts.add(exa.LocalPreference(20))
        atts.add(ecoms)

        entry = engine.RouteEntry(tests.NLRI1, None, atts)

        # check that the route_entry object has the RTs we wanted
        self.assertIn(exa.RouteTarget(64512, 1), entry.route_targets)
        self.assertIn(exa.RouteTarget(64512, 2), entry.route_targets)

        # modify the route targets
        entry.set_route_targets([exa.RouteTarget(64512, 3),
                                 exa.RouteTarget(64512, 1)])

        # check that the new RTs have replaced the old ones
        self.assertIn(exa.RouteTarget(64512, 1), entry.route_targets)
        self.assertIn(exa.RouteTarget(64512, 3), entry.route_targets)
        self.assertNotIn(exa.RouteTarget(64512, 2), entry.route_targets)

        # also need to check the RTs in the attributes
        ecoms = entry.attributes[
            exa.Attribute.CODE.EXTENDED_COMMUNITY].communities
        self.assertIn(exa.RouteTarget(64512, 1), ecoms)
        self.assertIn(exa.RouteTarget(64512, 3), ecoms)
        self.assertNotIn(exa.RouteTarget(64512, 2), ecoms)

        # check that other communities were preserved
        self.assertIn(exa.Encapsulation(exa.Encapsulation.Type.VXLAN), ecoms)

    def test_9_route_entry_rts_as_init_param(self):
        atts = exa.Attributes()
        ecoms = exa.ExtendedCommunities()
        ecoms.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        atts.add(exa.LocalPreference(20))
        atts.add(ecoms)

        rts = [exa.RouteTarget(64512, 1), exa.RouteTarget(64512, 2)]

        entry = engine.RouteEntry(tests.NLRI1, rts, atts)

        self.assertIn(exa.RouteTarget(64512, 1), entry.route_targets)
        self.assertIn(exa.RouteTarget(64512, 2), entry.route_targets)

        ecoms = entry.attributes[
            exa.Attribute.CODE.EXTENDED_COMMUNITY].communities
        self.assertIn(exa.RouteTarget(64512, 1), ecoms)
        self.assertIn(exa.RouteTarget(64512, 2), ecoms)
        self.assertIn(exa.Encapsulation(exa.Encapsulation.Type.VXLAN), ecoms)

    def test_10_ecoms(self):
        ecoms1 = exa.ExtendedCommunities()
        ecoms1.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        atts1 = exa.Attributes()
        atts1.add(ecoms1)

        ecoms2 = exa.ExtendedCommunities()
        ecoms2.communities.append(exa.Encapsulation(
            exa.Encapsulation.Type.VXLAN))
        ecoms2.communities.append(exa.RouteTarget(64512, 1))
        atts2 = exa.Attributes()
        atts2.add(ecoms2)

        self.assertFalse(atts1.sameValuesAs(atts2))
        self.assertFalse(atts2.sameValuesAs(atts1))

    def test_11_rts(self):
        rt1a = exa.RouteTarget(64512, 1)
        rt1b = exa.RouteTarget(64512, 1)

        rt3 = exa.RouteTarget(64512, 2)
        rt4 = exa.RouteTarget(64513, 1)

        self.assertEqual(hash(rt1a), hash(rt1b))
        # self.assertEqual(hash(rt1a), hash(rt2))
        self.assertNotEqual(hash(rt1a), hash(rt3))
        self.assertNotEqual(hash(rt1a), hash(rt4))

        self.assertEqual(rt1a, rt1b)
        # self.assertEqual(rt1a, rt2)
        self.assertNotEqual(rt1a, rt3)
        self.assertNotEqual(rt1a, rt4)

        self.assertEqual(set([rt1a]), set([rt1b]))
        # self.assertEqual(set([rt1a]), set([rt2]))
        self.assertEqual(1, len(set([rt1a]).intersection(set([rt1b]))))
        # self.assertEqual(1, len(set([rt2]).intersection(set([rt1b]))))
