from testtools import TestCase
from mock import Mock

from bagpipe.bgp.tests import RT5
from bagpipe.bgp.tests import _rt_to_string

from bagpipe.bgp.vpn import manager
from bagpipe.bgp.constants import IPVPN

REDIRECTED_INSTANCE_ID1 = 'redirected-id1'
REDIRECTED_INSTANCE_ID2 = 'redirected-id2'


class TestVPNManager(TestCase):

    def setUp(self):
        super(TestVPNManager, self).setUp()

        mock_dp_driver = Mock()
        dataplane_drivers = {'ipvpn': mock_dp_driver, 'evpn': mock_dp_driver}

        self.manager = manager.VPNManager(dataplane_drivers)

    def tearDown(self):
        super(TestVPNManager, self).tearDown()
        self.manager.stop()

    def test_redirect_traffic_single_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(IPVPN, _rt_to_string(RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance.redirected_instances)

    def test_redirect_traffic_multiple_instance(self):
        redirect_instance_1 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )
        redirect_instance_2 = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, IPVPN, _rt_to_string(RT5)
        )

        # Check that same redirect instance is returned
        self.assertEqual(redirect_instance_2, redirect_instance_1)
        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(
            manager.redirect_instance_extid(IPVPN, _rt_to_string(RT5)),
            self.manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance_1.redirected_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID2,
                      redirect_instance_1.redirected_instances)

    def test_stop_redirect_traffic_multiple_instance(self):
        redirect_instance = self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )
        self.manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, IPVPN, _rt_to_string(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID2,
                                          IPVPN, _rt_to_string(RT5))
        self.assertNotIn(REDIRECTED_INSTANCE_ID2,
                         redirect_instance.redirected_instances)

        self.manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID1,
                                          IPVPN, _rt_to_string(RT5))
        self.assertTrue(not self.manager.vpn_instances)
