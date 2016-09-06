#!/usr/bin/env python
# encoding: utf-8
"""
open.py

Created by Thomas Morin, Orange on 2015-07-10.
Copyright (c) 2009-2015 Orange. All rights reserved.
"""

import unittest

from bagpipe.bgp.engine.ipvpn import IPVPNRouteFactory

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message import OUT

from exabgp.reactor.protocol import AFI

TEST_RD = RouteDistinguisher.fromElements("42.42.42.42", 5)


def _create_test_ipvpn_nlri(label, nexthop):
    return IPVPNRouteFactory(AFI(AFI.ipv4),
                             "1.1.1.1/32", label, TEST_RD, nexthop)


class TestNLRIs(unittest.TestCase):

    def setUp(self):
        super(TestNLRIs, self).setUp()

    def tearDown(self):
        super(TestNLRIs, self).tearDown()

    # tests on MPLS VPN NLRIs

    def test_0_mpls_vpn_hash_equal(self):
        '''
        Two indistinct VPN NLRI should
        hash to the same value, and be equal
        '''
        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(42, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_1_mpls_vpn_hash_equal(self):
        '''
        Two VPN NLRI distinct only by their *label* should
        hash to the same value, and be equal
        '''
        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(0, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_2_mpls_vpn_hash_equal(self):
        '''
        Two VPN NLRI distinct only by their *nexthop* should
        hash to the same value, and be equal
        '''
        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2 = _create_test_ipvpn_nlri(42, "77.77.77.77")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test_3_mpls_vpn_hash_equal(self):
        '''
        Two VPN NLRI distinct only by their *action* should
        hash to the same value, and be equal
        '''
        nlri1 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri1.action = OUT.ANNOUNCE

        nlri2 = _create_test_ipvpn_nlri(42, "45.45.45.45")
        nlri2.action = OUT.WITHDRAW

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)
