from testtools import TestCase
from mock import Mock

from bagpipe.bgp.tests import RT5
from bagpipe.bgp.tests import _routeTarget2String

from bagpipe.bgp.vpn import VPNManager
from bagpipe.bgp.vpn.ipvpn import IPVPN

REDIRECTED_INSTANCE_ID1 = 'redirected-id1'
REDIRECTED_INSTANCE_ID2 = 'redirected-id2'


class TestVPNManager(TestCase):

    def setUp(self):
        super(TestVPNManager, self).setUp()

        mockDPDriver = Mock()
        dataplaneDrivers = {'ipvpn': mockDPDriver, 'evpn': mockDPDriver}

        bgpManager = Mock()
        bgpManager.getLocalAddress.return_value = "4.5.6.7"

        self.vpnManager = VPNManager(bgpManager, dataplaneDrivers)

    def tearDown(self):
        super(TestVPNManager, self).tearDown()
        self.vpnManager.stop()

    def _getRedirectInstanceId(self, instanceType, redirectRT):
        return "redirect-to-%s-%s" % (instanceType,
                                      redirectRT.replace(":", "_"))

    def test_RedirectTrafficSingleInstance(self):
        redirectInstance = self.vpnManager.redirectTrafficToVPN(
            REDIRECTED_INSTANCE_ID1, IPVPN, _routeTarget2String(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(self._getRedirectInstanceId(IPVPN,
                                                  _routeTarget2String(RT5)),
                      self.vpnManager.vpnInstances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirectInstance.redirectedInstances)

    def test_RedirectTrafficMultipleInstance(self):
        redirectInstance = self.vpnManager.redirectTrafficToVPN(
            REDIRECTED_INSTANCE_ID1, IPVPN, _routeTarget2String(RT5)
        )
        redirectInstancebis = self.vpnManager.redirectTrafficToVPN(
            REDIRECTED_INSTANCE_ID2, IPVPN, _routeTarget2String(RT5)
        )

        # Check that same redirect instance is returned
        self.assertEqual(redirectInstancebis, redirectInstance)
        # Check some VPN manager and redirect instance lists consistency
        self.assertIn(self._getRedirectInstanceId(IPVPN,
                                                  _routeTarget2String(RT5)),
                      self.vpnManager.vpnInstances)
        self.assertIn(REDIRECTED_INSTANCE_ID1,
                      redirectInstance.redirectedInstances)
        self.assertIn(REDIRECTED_INSTANCE_ID2,
                      redirectInstance.redirectedInstances)

    def test_StopRedirectTrafficMultipleInstance(self):
        redirectInstance = self.vpnManager.redirectTrafficToVPN(
            REDIRECTED_INSTANCE_ID1, IPVPN, _routeTarget2String(RT5)
        )
        self.vpnManager.redirectTrafficToVPN(
            REDIRECTED_INSTANCE_ID2, IPVPN, _routeTarget2String(RT5)
        )

        # Check some VPN manager and redirect instance lists consistency
        self.vpnManager.stopRedirectTrafficToVPN(REDIRECTED_INSTANCE_ID2,
                                                 IPVPN,
                                                 _routeTarget2String(RT5))
        self.assertNotIn(REDIRECTED_INSTANCE_ID2,
                         redirectInstance.redirectedInstances)

        self.vpnManager.stopRedirectTrafficToVPN(REDIRECTED_INSTANCE_ID1,
                                                 IPVPN,
                                                 _routeTarget2String(RT5))
        self.assertTrue(not self.vpnManager.vpnInstances)
