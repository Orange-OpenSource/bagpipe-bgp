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


def createTestIPVPNNLRI(label, nexthop):
    return IPVPNRouteFactory(AFI(AFI.ipv4),
                             "1.1.1.1/32", label, TEST_RD, nexthop)


class TestNLRIs(unittest.TestCase):

    def setUp(self):
        super(TestNLRIs, self).setUp()

    def tearDown(self):
        super(TestNLRIs, self).tearDown()

    # tests on MPLS VPN NLRIs

    def test0_MPLSVPNHashEqual(self):
        '''
        Two indistinct VPN NLRI should
        hash to the same value, and be equal
        '''
        nlri1 = createTestIPVPNNLRI(42, "45.45.45.45")
        nlri2 = createTestIPVPNNLRI(42, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test1_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *label* should
        hash to the same value, and be equal
        '''
        nlri1 = createTestIPVPNNLRI(42, "45.45.45.45")
        nlri2 = createTestIPVPNNLRI(0, "45.45.45.45")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test2_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *nexthop* should
        hash to the same value, and be equal
        '''
        nlri1 = createTestIPVPNNLRI(42, "45.45.45.45")
        nlri2 = createTestIPVPNNLRI(42, "77.77.77.77")

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)

    def test3_MPLSVPNHashEqual(self):
        '''
        Two VPN NLRI distinct only by their *action* should
        hash to the same value, and be equal
        '''
        nlri1 = createTestIPVPNNLRI(42, "45.45.45.45")
        nlri1.action = OUT.ANNOUNCE

        nlri2 = createTestIPVPNNLRI(42, "45.45.45.45")
        nlri2.action = OUT.WITHDRAW

        self.assertEqual(hash(nlri1), hash(nlri2))
        self.assertEqual(nlri1, nlri2)
