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

import testtools
import mock

from bagpipe.bgp import constants as consts
from bagpipe.bgp.vpn import manager
from bagpipe.bgp import tests as t


REDIRECTED_INSTANCE_ID1 = 'redirected-id1'
REDIRECTED_INSTANCE_ID2 = 'redirected-id2'


class TestableVPNManager(manager.VPNManager):

    def load_drivers(self):
        return {'ipvpn': mock.Mock(),
                'evpn': mock.Mock()}


class TestVPNManager(testtools.TestCase):

    def setUp(self):
        super(TestVPNManager, self).setUp()
        self.manager = TestableVPNManager.get_instance()

    def tearDown(self):
        super(TestVPNManager, self).tearDown()
        self.manager.stop()

    def test_redirect_traffic_single_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(consts.IPVPN,
                                            t._rt_to_string(t.RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance.redirected_instances)

    def test_redirect_traffic_multiple_instance(self):
        redirect_instance_1 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )
        redirect_instance_2 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check that same redirect instance is returned
        self.assertEqual(redirect_instance_2, redirect_instance_1)
        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(consts.IPVPN,
                                            t._rt_to_string(t.RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance_1.redirected_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID2,
                      redirect_instance_1.redirected_instances)

    def test_stop_redirect_traffic_multiple_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, consts.IPVPN, t._rt_to_string(t.RT5)
        )
        self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, consts.IPVPN, t._rt_to_string(t.RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID2,
                                          consts.IPVPN, t._rt_to_string(t.RT5))
        self.assertNotIn(REDIRECTED_INSTANCE_ID2,
                         redirect_instance.redirected_instances)

        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID1,
                                          consts.IPVPN, t._rt_to_string(t.RT5))
        self.assertTrue(not self.manager.vpn_instances)
