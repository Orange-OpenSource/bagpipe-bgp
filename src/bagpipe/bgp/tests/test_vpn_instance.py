"""

.. module:: test_vpn_instance
   :synopsis: module that defines several test cases for the vpn_instance
              module.
   In particular, unit tests for VPNInstance class.
   Setup : Start VPNInstance thread instance.
   TearDown : Stop VPNInstance thread instance.
   VPNInstance is a base class for objects used to manage an E-VPN instance
   (EVI) or IP-VPN instance (VRF)
   Tests are organized as follow :
   - testAx use cases to test endpoints plug with different combinations of MAC
     and IP addresses on a port
   - testBx use cases to test enpoints plug with different combinations of MAC
     and IP addresses on different ports
   - testCx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the one plugged on a port
   - testDx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the ones plugged on different ports

"""
import mock

from testtools import TestCase
from bagpipe.bgp.tests import RT1, NLRI1

from bagpipe.bgp.vpn.label_allocator import LabelAllocator
from bagpipe.bgp.vpn.vpn_instance import VPNInstance

from exabgp.message.update.attributes import Attributes

from bagpipe.bgp.engine import RouteEntry

from exabgp.structure.address import AFI, SAFI

MAC1 = "00:00:de:ad:be:ef"
IP1 = "10.0.0.2/32"
LOCAL_PORT1 = {'linuxif':'tap1'}

MAC2 = "00:00:fe:ed:fa:ce"
IP2 = "10.0.0.3/32"
LOCAL_PORT2 = {'linuxif':'tap2'}

MAC3 = "00:00:de:ad:c0:de"
IP3 = "10.0.0.4/32"
LOCAL_PORT3 = {'linuxif':'tap3'}

MAC4 = "00:00:fe:ed:f0:0d"
IP4 = "10.0.0.5/32"
LOCAL_PORT4 = {'linuxif':'tap4'}

class TestVPNInstance(TestCase):

    def setUp(self):
        super(TestVPNInstance, self).setUp()
        self.labelAllocator = LabelAllocator()
        
        self.mockDataplane = mock.Mock()
        self.mockDataplane.vifPlugged = mock.Mock()
        self.mockDataplane.vifUnplugged = mock.Mock()
        
        self.mockDataplaneDriver = mock.Mock()
        self.mockDataplaneDriver.initializeDataplaneInstance.returnValue = self.mockDataplane
        
        VPNInstance.afi = AFI(AFI.ipv4)
        VPNInstance.safi = SAFI(SAFI.mpls_vpn)
        self.vpnInstance = VPNInstance(mock.Mock(name='BGPManager'), self.labelAllocator, self.mockDataplaneDriver, 1, 1, [RT1], [RT1], '10.0.0.1', 24)
        self.vpnInstance.synthesizeVifBGPRoute = mock.Mock(return_value=RouteEntry(self.vpnInstance.afi, self.vpnInstance.safi, NLRI1, RT1, Attributes(), None))
        self.vpnInstance._pushEvent = mock.Mock()
        self.vpnInstance._postFirstPlug = mock.Mock()
        self.vpnInstance.start()

    def tearDown(self):
        super(TestVPNInstance, self).tearDown()
        with mock.patch.object(self.vpnInstance.bgpManager, 'cleanup'):
            self.vpnInstance.stop()
            self.vpnInstance.join()

    def _get_ipAddress(self, ipAddressPrefix):
        return ipAddressPrefix[0:ipAddressPrefix.find('/')]

    def _validate_ipAddress2MacAddress_consistency(self, macAddress, ipAddress1, ipAddress2=None):
        # Validate IP address -> MAC address consistency
        self.assertIn(ipAddress1, self.vpnInstance.ipAddress2MacAddress)
        
        if ipAddress2:
            self.assertIn(ipAddress1, self.vpnInstance.ipAddress2MacAddress)
            self.assertEquals(self.vpnInstance.ipAddress2MacAddress[ipAddress1],
                              self.vpnInstance.ipAddress2MacAddress[ipAddress2])
        else:
            self.assertEquals(macAddress, self.vpnInstance.ipAddress2MacAddress[ipAddress1])

    def _validate_macAddress2LocalPortData_consistency(self, macAddress, localPort):
        # Validate MAC address -> Port informations consistency
        self.assertIn(macAddress, self.vpnInstance.macAddress2LocalPortData)
        
        port_info = self.vpnInstance.macAddress2LocalPortData[macAddress]['port_info']
        self.assertEquals(localPort['linuxif'], port_info['linuxif'])

    def _validate_localPort2Endpoints_consistency(self, length, localPort, endpoints):
        # Validate Port -> Endpoint (MAC, IP) tuple consistency
        self.assertEqual(length, len(self.vpnInstance.localPort2Endpoints[localPort['linuxif']]))
        
        for macAddress, ipAddress in endpoints:
            endpoint_info = {'mac': macAddress, 'ip': ipAddress}
            self.assertIn(endpoint_info, self.vpnInstance.localPort2Endpoints[localPort['linuxif']])

    def testA1_plugEnpointTwiceSamePort(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)

        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port must be plugged only once on dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Route for port must be advertised only once")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])

    def testA2_plugMultipleEnpointsWithSameIPSamePort(self):
        '''
        Plug multiple enpoints with different MAC addresses and same IP
        address on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be raised 
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC2, IP1, LOCAL_PORT1)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(MAC2, self.vpnInstance.macAddress2LocalPortData)

    def testA3_plugMultipleEndpointsWithSameMACSamePort(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC1, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port different IP addresses must be plugged on dataplane")
        self.assertEqual(2, self.vpnInstance._pushEvent.call_count,
                         "Route for port different IP addresses must be advertised")
        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(2, LOCAL_PORT1, [(MAC1, IP1), (MAC1, IP2)])

    def testA4_plugMultipleEndpointsSamePort(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port different endpoints must be plugged on dataplane")
        self.assertEqual(2, self.vpnInstance._pushEvent.call_count,
                         "Route for port different endpoints must be advertised")
        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(2, LOCAL_PORT1, [(MAC1, IP1), (MAC2, IP2)])

    def testB1_plugEndpointTwiceDifferentPort(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on different
        ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised 
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC1, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB2_plugMultipleEndpointsWithSameIPDifferentPort(self):
        '''
        Plug multiple endpoints with different MAC addresses and same IP
        address on different port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC2, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB4_plugMultipleEndpointsWithSameMACDifferentPort(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC1, IP2, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB5_plugMultipleEndpointsDifferentPort(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on
        different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "All ports must be plugged on dataplane")
        self.assertEqual(2, self.vpnInstance._pushEvent.call_count,
                         "Routes for all ports must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT2)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT2, [(MAC2, IP2)])

    def testC1_unplugUniqueEndpointSamePort(self):
        '''
        Unplug one endpoint with same MAC and IP addresses as the one plugged on
        port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        
        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        
        self.vpnInstance.vifUnplugged(MAC1, IP1)

        self.assertEqual(1, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could be unplugged from dataplane")
        self.assertEqual([((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, True),)],
                         self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(2, self.vpnInstance._pushEvent.call_count,
                         "Route must be first advertised and after withdrawed")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testC2_unplugUniqueEndpointWithSameIPSamePort(self):
        '''
        Unplug one endpoint with different MAC addresses and same IP address as the
        one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        
        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC2, IP1)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Route must only be advertised")

        self.assertIn(MAC1, self.vpnInstance.macAddress2LocalPortData)
        self.assertIn(IP1, self.vpnInstance.ipAddress2MacAddress)
        self.assertIn(LOCAL_PORT1['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testC3_unplugUniqueEndpointWithSameMACSamePort(self):
        '''
        Unplug one endpoint with same MAC address and different IP addresses as the
        one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        
        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpnInstance._pushEvent.call_count,
                         "Route must only be advertised")

        self.assertIn(MAC1, self.vpnInstance.macAddress2LocalPortData)
        self.assertIn(IP1, self.vpnInstance.ipAddress2MacAddress)
        self.assertIn(LOCAL_PORT1['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testC4_unplugOneEndpointSamePort(self):
        '''
        Unplug only one endpoint with same MAC and IP addresses
        corresponding to one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1)
        
        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1)

        self.assertEqual(1, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint must be unplugged from dataplane")
        self.assertEqual([((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),)],
                         self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(3, self.vpnInstance._pushEvent.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawed")

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC2, IP2)])

    def testC5_unplugAllEndpointsSamePort(self):
        '''
        Unplug all endpoints with same MAC and IP addresses
        corresponding to those plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1)
        
        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']
        
        self.vpnInstance.vifUnplugged(MAC1, IP1)
        self.vpnInstance.vifUnplugged(MAC2, IP2)

        self.assertEqual(2, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All port endpoints must be unplugged from dataplane")
        self.assertEqual([((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),),
                          ((MAC2, self._get_ipAddress(IP2), LOCAL_PORT1, label2, True),)],
                         self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(4, self.vpnInstance._pushEvent.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawed")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testD1_unplugUniqueEndpointsDifferentPort(self):
        '''
        Unplug the endpoints with different MAC and IP addresses corresponding to
        those plugged on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1)
        self.vpnInstance.vifUnplugged(MAC2, IP2)

        self.assertEqual(2, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual([((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, True),),
                          ((MAC2, self._get_ipAddress(IP2), LOCAL_PORT2, label2, True),)],
                         self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(4, self.vpnInstance._pushEvent.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawed")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testD2_unplugOneEndpointSameIPDifferentPort(self):
        '''
        Unplug one endpoint with different MAC or IP address corresponding to
        one plugged on another port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2)

        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(2, self.vpnInstance._pushEvent.call_count,
                         "Routes for all different ports endpoints must only "
                         "be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT2)
        self._validate_localPort2Endpoints_consistency(1, LOCAL_PORT2, [(MAC2, IP2)])

    def testD3_unplugMultipleEndpointsDifferentPort(self):
        '''
        Unplug multiple endpoints with same MAC and IP addresses corresponding to
        those plugged on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC3, IP3, LOCAL_PORT2)
        self.vpnInstance.vifPlugged(MAC4, IP4, LOCAL_PORT2)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']
        label3 = self.vpnInstance.macAddress2LocalPortData[MAC3]['label']
        label4 = self.vpnInstance.macAddress2LocalPortData[MAC4]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1)
        self.vpnInstance.vifUnplugged(MAC2, IP2)
        self.vpnInstance.vifUnplugged(MAC3, IP3)
        self.vpnInstance.vifUnplugged(MAC4, IP4)

        self.assertEqual(4, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual([((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),),
                          ((MAC2, self._get_ipAddress(IP2), LOCAL_PORT1, label2, True),),
                          ((MAC3, self._get_ipAddress(IP3), LOCAL_PORT2, label3, False),),
                          ((MAC4, self._get_ipAddress(IP4), LOCAL_PORT2, label4, True),)],
                         self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(8, self.vpnInstance._pushEvent.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawed")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)
        
    def test_getLGLocalPortData(self):
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1)
        self.vpnInstance.vifPlugged(MAC3, IP3, LOCAL_PORT2)
        self.vpnInstance.vifPlugged(MAC4, IP4, LOCAL_PORT2)

        print "\n"
        print self.vpnInstance.getLGLocalPortData("")
