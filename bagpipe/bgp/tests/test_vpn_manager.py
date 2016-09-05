from testtools import TestCase
from mock import Mock

from bagpipe.bgp.tests import RT5
from bagpipe.bgp.tests import _rt_to_string

from bagpipe.bgp.vpn import VPNManager
from bagpipe.bgp.vpn.ipvpn import IPVPN

REDIRECTED_INSTANCE_ID1 = 'redirected-id1'
REDIRECTED_INSTANCE_ID2 = 'redirected-id2'


class TestVPNManager(TestCase):

    def setUp(self):
        super(TestVPNManager, self).setUp()

        mock_dp_driver = Mock()
        dataplane_drivers = {'ipvpn': mock_dp_driver, 'evpn': mock_dp_driver}

        bgp_manager = Mock()
        bgp_manager.get_local_address.return_value = "4.5.6.7"

        self.vpn_manager = VPNManager(bgp_manager, dataplane_drivers)

    def tearDown(self):
        super(TestVPNManager, self).tearDown()
        self.vpn_manager.stop()

    def _get_redirect_instance_id(self, instance_type, redirect_rt):
        return "redirect-to-%s-%s" % (instance_type,
                                      redirect_rt.replace(":", "_"))

    def test_redirect_traffic_single_instance(self):
        redirect_instance = self.vpn_manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(self._get_redirect_instance_id(IPVPN,
                                                  _rt_to_string(RT5)),
                      self.vpn_manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance.redirected_instances)

    def test_redirect_traffic_multiple_instance(self):
        redirect_instance = self.vpn_manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )
        redirect_instance_bis = self.vpn_manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, IPVPN, _rt_to_string(RT5)
        )

        # Check that same redirect instance is returned
        self.assertEqual(redirect_instance_bis, redirect_instance)
        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(self._get_redirect_instance_id(IPVPN,
                                                  _rt_to_string(RT5)),
                      self.vpn_manager.vpn_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirect_instance.redirected_instances)
        self.assertIn(REDIRECTED_INSTANCE_ID2,
                      redirect_instance.redirected_instances)

    def test_stop_redirect_traffic_multiple_instance(self):
        redirect_instance = self.vpn_manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID1, IPVPN, _rt_to_string(RT5)
        )
        self.vpn_manager.redirect_traffic_to_vpn(
            REDIRECTED_INSTANCE_ID2, IPVPN, _rt_to_string(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.vpn_manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID2,
                                                 IPVPN,
                                                 _rt_to_string(RT5))
        self.assertNotIn(REDIRECTED_INSTANCE_ID2,
                         redirect_instance.redirected_instances)

        self.vpn_manager.stop_redirect_to_vpn(REDIRECTED_INSTANCE_ID1,
                                                 IPVPN,
                                                 _rt_to_string(RT5))
        self.assertTrue(not self.vpn_manager.vpn_instances)
