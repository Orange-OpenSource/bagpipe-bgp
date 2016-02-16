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

import logging

from testtools import TestCase
from mock import Mock

from bagpipe.bgp.tests import RT1
from bagpipe.bgp.tests import RT2
from bagpipe.bgp.tests import RT3
from bagpipe.bgp.tests import RT4
from bagpipe.bgp.tests import RT5
from bagpipe.bgp.tests import NLRI1
from bagpipe.bgp.tests import NLRI2
from bagpipe.bgp.tests import NH1
from bagpipe.bgp.tests import BaseTestBagPipeBGP

from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine.worker import Worker

from bagpipe.bgp.vpn.label_allocator import LabelAllocator
from bagpipe.bgp.vpn.vpn_instance import VPNInstance, TrafficClassifier

from bagpipe.bgp.vpn.ipvpn import VRF

from exabgp.reactor.protocol import AFI, SAFI
from exabgp.bgp.message.update.nlri.ipvpn import IPVPN
from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher
from exabgp.bgp.message.update.nlri.qualifier.labels import Labels

from exabgp.protocol.ip import IP

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecordASN2Number

from exabgp.bgp.message.update import Attribute
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.nlri.flow import (
    Flow, FlowSourcePort, FlowDestinationPort, FlowIPProtocol, Flow4Source,
    Flow6Source, Flow4Destination, Flow6Destination, NumericOperator)
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecordASN2Number

from exabgp.protocol import Protocol

from bagpipe.bgp.vpn.ipvpn import IPVPNRouteFactory


log = logging.getLogger()

MAC1 = "00:00:de:ad:be:ef"
IP1 = "10.0.0.1/32"
LOCAL_PORT1 = {'linuxif': 'tap1'}

MAC2 = "00:00:fe:ed:fa:ce"
IP2 = "10.0.0.2/32"
LOCAL_PORT2 = {'linuxif': 'tap2'}

MAC3 = "00:00:de:ad:c0:de"
IP3 = "10.0.0.3/32"
LOCAL_PORT3 = {'linuxif': 'tap3'}

MAC4 = "00:00:fe:ed:f0:0d"
IP4 = "10.0.0.4/32"
LOCAL_PORT4 = {'linuxif': 'tap4'}

RTRecord1 = RTRecord.from_rt(RT1)
RTRecord2 = RTRecord.from_rt(RT2)
RTRecord3 = RTRecord.from_rt(RT3)
RTRecord4 = RTRecord.from_rt(RT4)

def _extractRTFromAdvertiseCall(vpnInstance, callIndex=0):
    calls = vpnInstance._advertiseRoute.call_args_list
    return calls[callIndex][0][0].routeTargets


def _extractRTRecordsFromAdvertiseCall(vpnInstance, callIndex=0):
    calls = vpnInstance._advertiseRoute.call_args_list
    route = calls[callIndex][0][0]
    return route.extendedCommunities(lambda ecom:
                                     isinstance(ecom, RTRecord))


def _extractTrafficRedirectFromAdvertiseCall(vpnInstance, callIndex=0):
    calls = vpnInstance._advertiseRoute.call_args_list
    attributes = calls[callIndex][0][0].attributes
    if Attribute.CODE.EXTENDED_COMMUNITY in attributes:
        ecoms = attributes[Attribute.CODE.EXTENDED_COMMUNITY].communities
        for ecom in ecoms:
            if isinstance(ecom, TrafficRedirect):
                return RouteTarget(int(ecom.asn), int(ecom.target))
    return None


def _extractTrafficClassifierFromAdvertiseCall(vpnInstance, callIndex=0):
    calls = vpnInstance._advertiseRoute.call_args_list
    print calls[callIndex][0][0].nlri.rules
    trafficClassifier = TrafficClassifier()
    trafficClassifier.mapRedirectRules2TrafficClassifier(calls[callIndex][0][0].nlri.rules)
    return trafficClassifier


class TestableVPNInstance(VPNInstance):

    def _bestRouteRemoved(self, entry, route):
        pass

    def _newBestRoute(self, entry, route, last):
        pass

    def _route2trackedEntry(self, route):
        pass

    def generateVifBGPRoute(self):
        pass


class TestVPNInstance(TestCase):

    def setUp(self):
        super(TestVPNInstance, self).setUp()

        mockDataplane = Mock()
        mockDataplane.vifPlugged = Mock()
        mockDataplane.vifUnplugged = Mock()

        mockDPDriver = Mock()
        mockDPDriver.initializeDataplaneInstance.return_value = mockDataplane

        VPNInstance.afi = AFI(AFI.ipv4)
        VPNInstance.safi = SAFI(SAFI.mpls_vpn)
        self.vpnInstance = TestableVPNInstance(Mock(name='VPNManager'),
                                               mockDPDriver, 1, 1,
                                               [RT1], [RT1], '10.0.0.1', 24,
                                               None, None)
        self.vpnInstance.synthesizeVifBGPRoute = Mock(
            return_value=RouteEntry(NLRI1, [RT1]))
        self.vpnInstance._advertiseRoute = Mock()
        self.vpnInstance._withdrawRoute = Mock()
        self.vpnInstance._postFirstPlug = Mock()
        self.vpnInstance.start()

    def tearDown(self):
        super(TestVPNInstance, self).tearDown()
        self.vpnInstance.stop()
        self.vpnInstance.join()

    def _get_ipAddress(self, ipAddressPrefix):
        return ipAddressPrefix[0:ipAddressPrefix.find('/')]

    def _validate_ipAddress2MacAddress_consistency(self, macAddress,
                                                   ipAddress1,
                                                   ipAddress2=None):
        # Validate IP address -> MAC address consistency
        self.assertIn(ipAddress1, self.vpnInstance.ipAddress2MacAddress)

        if ipAddress2:
            self.assertIn(ipAddress1, self.vpnInstance.ipAddress2MacAddress)
            self.assertEquals(
                self.vpnInstance.ipAddress2MacAddress[ipAddress1],
                self.vpnInstance.ipAddress2MacAddress[ipAddress2])
        else:
            self.assertEquals(
                macAddress, self.vpnInstance.ipAddress2MacAddress[ipAddress1])

    def _validate_macAddress2LocalPortData_consistency(self, macAddress,
                                                       localPort):
        # Validate MAC address -> Port informations consistency
        self.assertIn(macAddress, self.vpnInstance.macAddress2LocalPortData)

        port_info = self.vpnInstance.macAddress2LocalPortData[
            macAddress]['port_info']
        self.assertEquals(localPort['linuxif'], port_info['linuxif'])

    def _validate_localPort2Endpoints_consistency(self, length, localPort,
                                                  endpoints):
        # Validate Port -> Endpoint (MAC, IP) tuple consistency
        self.assertEqual(
            length,
            len(self.vpnInstance.localPort2Endpoints[localPort['linuxif']]))

        for macAddress, ipAddress in endpoints:
            endpoint_info = {'mac': macAddress, 'ip': ipAddress}
            self.assertIn(
                endpoint_info,
                self.vpnInstance.localPort2Endpoints[localPort['linuxif']])

    def testA1_plugEnpointTwiceSamePort(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port must be plugged only once on dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Route for port must be advertised only once")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

    def testA2_plugMultipleEnpointsWithSameIPSamePort(self):
        '''
        Plug multiple enpoints with different MAC addresses and same IP
        address on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC2, IP1, LOCAL_PORT1)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(MAC2, self.vpnInstance.macAddress2LocalPortData)

    def testA3_plugMultipleEndpointsWithSameMACSamePort(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC1, IP2, LOCAL_PORT1, False)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port different IP addresses must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Route for port different IP addresses must be "
                         "advertised")
        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC1, IP2)])

    def testA4_plugMultipleEndpointsSamePort(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on a port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1, False)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Port different endpoints must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Route for port different endpoints must be "
                         "advertised")
        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC2, IP2)])

    def testB1_plugEndpointTwiceDifferentPort(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on different
        ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC1, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB2_plugMultipleEndpointsWithSameIPDifferentPort(self):
        '''
        Plug multiple endpoints with different MAC addresses and same IP
        address on different port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC2, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB4_plugMultipleEndpointsWithSameMACDifferentPort(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpnInstance.vifPlugged,
                          MAC1, IP2, LOCAL_PORT2)
        self.assertEqual(1, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Only route for first port must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testB5_plugMultipleEndpointsDifferentPort(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on
        different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2, False)

        self.assertEqual(2, self.vpnInstance.dataplane.vifPlugged.call_count,
                         "All ports must be plugged on dataplane")
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all ports must be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT2)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def testC1_unplugUniqueEndpointSamePort(self):
        '''
        Unplug one endpoint with same MAC and IP addresses as the one plugged
        on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1, False)

        self.assertEqual(1, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, True),)],
            self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Route must be first advertised and after withdrawn")
        self.assertEqual(1, self.vpnInstance._withdrawRoute.call_count,
                         "Route must be first advertised and after withdrawn")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testC2_unplugUniqueEndpointWithSameIPSamePort(self):
        '''
        Unplug one endpoint with different MAC addresses and same IP address as
        the one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC2, IP1)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "only one Route must be advertised")

        self.assertIn(MAC1, self.vpnInstance.macAddress2LocalPortData)
        self.assertIn(IP1, self.vpnInstance.ipAddress2MacAddress)
        self.assertIn(
            LOCAL_PORT1['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testC3_unplugUniqueEndpointWithSameMACSamePort(self):
        '''
        Unplug one endpoint with same MAC address and different IP addresses
        as the one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count,
                         "Route must only be advertised once")
        self.assertEqual(0, self.vpnInstance._withdrawRoute.call_count,
                         "Route must not be withdrawn")

        self.assertIn(MAC1, self.vpnInstance.macAddress2LocalPortData)
        self.assertIn(IP1, self.vpnInstance.ipAddress2MacAddress)
        self.assertIn(
            LOCAL_PORT1['linuxif'], self.vpnInstance.localPort2Endpoints)

    def testC4_unplugOneEndpointSamePort(self):
        '''
        Unplug only one endpoint with same MAC and IP addresses
        corresponding to one plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1, False)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1)

        self.assertEqual(1, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint must be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),)],
            self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawn")
        self.assertEqual(1, self.vpnInstance._withdrawRoute.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawn")

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC2, IP2)])

    def testC5_unplugAllEndpointsSamePort(self):
        '''
        Unplug all endpoints with same MAC and IP addresses
        corresponding to those plugged on port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1, False)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1, False)
        self.vpnInstance.vifUnplugged(MAC2, IP2, False)

        self.assertEqual(2, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All port endpoints must be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),),
             ((MAC2, self._get_ipAddress(IP2), LOCAL_PORT1, label2, True),)],
            self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")
        self.assertEqual(2, self.vpnInstance._withdrawRoute.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testD1_unplugUniqueEndpointsDifferentPort(self):
        '''
        Unplug the endpoints with different MAC and IP addresses corresponding
        to those plugged on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2, False)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1, False)
        self.vpnInstance.vifUnplugged(MAC2, IP2, False)

        self.assertEqual(2, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, True),),
             ((MAC2, self._get_ipAddress(IP2), LOCAL_PORT2, label2, True),)],
            self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(2, self.vpnInstance._withdrawRoute.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def testD2_unplugOneEndpointSameIPDifferentPort(self):
        '''
        Unplug one endpoint with different MAC or IP address corresponding to
        one plugged on another port
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2, False)

        self.assertRaises(Exception,
                          self.vpnInstance.vifUnplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all different ports endpoints must only "
                         "be advertised")

        self._validate_ipAddress2MacAddress_consistency(MAC1, IP1)
        self._validate_macAddress2LocalPortData_consistency(MAC1, LOCAL_PORT1)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ipAddress2MacAddress_consistency(MAC2, IP2)
        self._validate_macAddress2LocalPortData_consistency(MAC2, LOCAL_PORT2)
        self._validate_localPort2Endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def testD3_unplugMultipleEndpointsDifferentPort(self):
        '''
        Unplug multiple endpoints with same MAC and IP addresses corresponding
        to those plugged on different ports
        '''
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC3, IP3, LOCAL_PORT2, False)
        self.vpnInstance.vifPlugged(MAC4, IP4, LOCAL_PORT2, False)

        label1 = self.vpnInstance.macAddress2LocalPortData[MAC1]['label']
        label2 = self.vpnInstance.macAddress2LocalPortData[MAC2]['label']
        label3 = self.vpnInstance.macAddress2LocalPortData[MAC3]['label']
        label4 = self.vpnInstance.macAddress2LocalPortData[MAC4]['label']

        self.vpnInstance.vifUnplugged(MAC1, IP1, False)
        self.vpnInstance.vifUnplugged(MAC2, IP2, False)
        self.vpnInstance.vifUnplugged(MAC3, IP3, False)
        self.vpnInstance.vifUnplugged(MAC4, IP4, False)

        self.assertEqual(4, self.vpnInstance.dataplane.vifUnplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ipAddress(IP1), LOCAL_PORT1, label1, False),),
             ((MAC2, self._get_ipAddress(
               IP2), LOCAL_PORT1, label2, True),),
             ((MAC3, self._get_ipAddress(
               IP3), LOCAL_PORT2, label3, False),),
             ((MAC4, self._get_ipAddress(IP4), LOCAL_PORT2, label4, True),)],
            self.vpnInstance.dataplane.vifUnplugged.call_args_list)
        self.assertEqual(4, self.vpnInstance._withdrawRoute.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(4, self.vpnInstance._advertiseRoute.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpnInstance.macAddress2LocalPortData)
        self.assertEqual({}, self.vpnInstance.ipAddress2MacAddress)
        self.assertEqual({}, self.vpnInstance.localPort2Endpoints)

    def test_getLGLocalPortData(self):
        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT1, False)
        self.vpnInstance.vifPlugged(MAC3, IP3, LOCAL_PORT2, False)
        self.vpnInstance.vifPlugged(MAC4, IP4, LOCAL_PORT2, False)

        self.vpnInstance.getLGLocalPortData("")

    # tests of updateRouteTargets

    def _test_updateRTsInit(self):
        self.vpnInstance._advertiseRoute.reset_mock()

        route = RouteEntry(NLRI1, [RT1])
        self.vpnInstance._rtm_routeEntries = set([route])

    def test_updateRTs1(self):
        self._test_updateRTsInit()

        # no change -> no route update
        self.vpnInstance.updateRouteTargets([RT1], [RT1])

        self.assertEqual(0, self.vpnInstance._advertiseRoute.call_count)

    def test_updateRTs2(self):
        self._test_updateRTsInit()

        # change imports -> no route update
        self.vpnInstance.updateRouteTargets([RT2], [RT1])

        self.assertEqual(0, self.vpnInstance._advertiseRoute.call_count)

    def test_updateRTs3(self):
        self._test_updateRTsInit()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpnInstance.updateRouteTargets([RT1], [RT2])

        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)

        self.assertIn(RT2, _extractRTFromAdvertiseCall(self.vpnInstance))
        self.assertNotIn(RT1, _extractRTFromAdvertiseCall(self.vpnInstance))

    def test_updateRTs3bis(self):
        self._test_updateRTsInit()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpnInstance.updateRouteTargets([RT1], [RT1, RT2])

        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)
        self.assertIn(RT2, _extractRTFromAdvertiseCall(self.vpnInstance))
        self.assertIn(RT1, _extractRTFromAdvertiseCall(self.vpnInstance))


TEST_RD = RouteDistinguisher.fromElements("42.42.42.42", 5)

vpnNLRI1 = IPVPNRouteFactory(AFI(AFI.ipv4), "1.1.1.1/32",
                             42, TEST_RD, '45.45.45.45')

vpnNLRI2 = IPVPNRouteFactory(AFI(AFI.ipv4), "2.2.2.2/32",
                             50, TEST_RD, '45.45.45.45')

vpnNLRI3 = IPVPNRouteFactory(AFI(AFI.ipv4), "3.3.3.3/32",
                             50, TEST_RD, '45.45.45.45')

attractTraffic1 = {'redirect_rt': [RT5],
                   'classifier': {'destinationPort': '80',
                                  'protocol': 'tcp'
                                  }
                   }

trafficClassifier1 = TrafficClassifier(destinationPrefix="1.1.1.1/32",
                                       destinationPort="80",
                                       protocol="tcp")


class TestVRF(BaseTestBagPipeBGP, TestCase):

    def setUp(self):
        super(TestVRF, self).setUp()

        self.mockDataplane = Mock()
        self.mockDataplane.vifPlugged = Mock()
        self.mockDataplane.vifUnplugged = Mock()
        self.mockDataplane.setupDataplaneForRemoteEndpoint = Mock()

        mockDPDriver = Mock()
        mockDPDriver.initializeDataplaneInstance.return_value = \
            self.mockDataplane
        mockDPDriver.getLocalAddress.return_value = "4.5.6.7"
        mockDPDriver.supportedEncaps.return_value = \
            [Encapsulation(Encapsulation.Type.DEFAULT)]

        labelAllocator = LabelAllocator()
        bgpManager = Mock()
        bgpManager.getLocalAddress.return_value = "4.5.6.7"
        vpnManager = Mock(bgpManager=bgpManager,
                          labelAllocator=labelAllocator)

#        VPNInstance.afi = AFI(AFI.ipv4)
#        VPNInstance.safi = SAFI(SAFI.mpls_vpn)
        self.vpnInstance = VRF(
            vpnManager,
            mockDPDriver, 1, 1,
            [RT1], [RT1], '10.0.0.1', 24,
            {'from_rt': [RT3],
             'to_rt': [RT4]
             }, None)
        self.vpnInstance._advertiseRoute = Mock()
        self.vpnInstance._withdrawRoute = Mock()
        self.vpnInstance.start()

#         self.vpnInstanceAttract = VRF(
#             vpnManager,
#             mockDPDriver, 1, 1,
#             [RT1], [], '10.0.0.1', 24,
#             {'from_rt': [RT3],
#              'to_rt': [RT4]
#              },
#             {'redirect_rt': [RT5],
#              'classifier': {'destinationPort': '80',
#                             'protocol': 'tcp'
#                             }
#              })
#         self.vpnInstanceAttract._advertiseRoute = Mock()
#         self.vpnInstanceAttract._withdrawRoute = Mock()
#         self.vpnInstanceAttract.start()

        self.eventTargetWorker = self.vpnInstance

    def _resetMocks(self):
        #self._wait()
        self.vpnInstance._advertiseRoute.reset_mock()
        self.vpnInstance._withdrawRoute.reset_mock()
        self.mockDataplane.setupDataplaneForRemoteEndpoint.reset_mock()
        self.mockDataplane.vifPlugged.reset_mock()
        self.mockDataplane.vifUnplugged.reset_mock()

    def tearDown(self):
        super(TestVRF, self).tearDown()
        self.vpnInstance.stop()
        self.vpnInstance.join()

    def _configVRFWithAttractTraffic(self, attractTraffic):
        self.vpnInstance.attractTraffic = True
        self.vpnInstance.attractRT = attractTraffic['redirect_rt']
        self.vpnInstance.attractClassifier = attractTraffic['classifier']

    # unit test for IPVPN re-advertisement
    def test_ReAdvertisement1(self):
        self._resetMocks()

        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        workerA = Worker(Mock(), 'Worker-A')

        self._newRouteEvent(RouteEvent.ADVERTISE, vpnNLRI1, [RT1, RT2],
                            workerA, NH1, 200)
        # no re-advertisement supposed to happen
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)
        # dataplane supposed to be updated for this route
        self.assertEqual(
            1,
            self.mockDataplane.setupDataplaneForRemoteEndpoint.call_count)

        self._resetMocks()

        event2 = self._newRouteEvent(RouteEvent.ADVERTISE, vpnNLRI2, [RT3],
                                     workerA, NH1, 200, rtrecords=[RTRecord1])
        # re-advertisement of VPN NLRI2 supposed to happen, to RT4
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)#FIXME:1
        self.assertIn(RT4, _extractRTFromAdvertiseCall(self.vpnInstance))
        self.assertNotIn(RT2, _extractRTFromAdvertiseCall(self.vpnInstance))
        self.assertNotIn(RT3, _extractRTFromAdvertiseCall(self.vpnInstance))
        self.assertIn(RTRecord3, _extractRTRecordsFromAdvertiseCall(self.vpnInstance))
        self.assertIn(RTRecord1, _extractRTRecordsFromAdvertiseCall(self.vpnInstance))
        # dataplane *not* supposed to be updated for this route
        self.assertEqual(
            0,
            self.mockDataplane.setupDataplaneForRemoteEndpoint.call_count)

        self._resetMocks()

        # new interface plugged in
        # route vpnNLRI2 should be re-advertized with this new next hop as
        # next-hop
        self.vpnInstance.vifPlugged(MAC2, IP2, LOCAL_PORT2, False)
        # advertised route count should increment by 2:
        # - vif route itself
        # - re-adv of NLRI1 with this new port as next-hop
        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count)
        self.assertEqual(0, self.vpnInstance._withdrawRoute.call_count)
        self.assertIn(RT1, _extractRTFromAdvertiseCall(self.vpnInstance, 0))
        self.assertNotIn(RT4, _extractRTFromAdvertiseCall(self.vpnInstance, 0))
        self.assertIn(RT4, _extractRTFromAdvertiseCall(self.vpnInstance, 1))
        self.assertNotIn(RT1, _extractRTFromAdvertiseCall(self.vpnInstance, 1))

        # check that second event is for re-advertised route vpnNLRI2 and
        # contains what we expect
        routeEntry = self.vpnInstance._advertiseRoute.call_args_list[1][0][0]
        self.assertEqual(vpnNLRI2.cidr.prefix(), routeEntry.nlri.cidr.prefix())
        self.assertNotEqual(vpnNLRI2.labels, routeEntry.nlri.labels)
        self.assertNotEqual(vpnNLRI2.nexthop, routeEntry.nlri.nexthop)

        self._resetMocks()

        # new route, that, because it contains the redirectRT in RTRecord
        # will not be re-advertized
        event3 = self._newRouteEvent(RouteEvent.ADVERTISE, vpnNLRI3, [RT3],
                                     workerA, NH1, 200, rtrecords=[RTRecord4])
        self.assertEqual(0, self.vpnInstance._advertiseRoute.call_count)
        self.assertEqual(0, self.vpnInstance._withdrawRoute.call_count)
        self._revertEvent(event3)

        self._resetMocks()

        # vif unplugged, routes VPN NLRI2 with next-hop
        # corresponding to this ports should now be withdrawn
        self.vpnInstance.vifUnplugged(MAC2, IP2, False)
        self.assertEqual(2, self.vpnInstance._withdrawRoute.call_count)
        routeEntry = self.vpnInstance._withdrawRoute.call_args_list[0][0][0]
        self.assertEqual(vpnNLRI2.cidr.prefix(), routeEntry.nlri.cidr.prefix())
        self.assertNotEqual(vpnNLRI2.labels, routeEntry.nlri.labels)
        self.assertNotEqual(vpnNLRI2.nexthop, routeEntry.nlri.nexthop)

        self._resetMocks()

        # RTs of route NLRI1 now include a re-advertiseed RT
        self._newRouteEvent(RouteEvent.ADVERTISE, vpnNLRI1, [RT1, RT2, RT3],
                            workerA, NH1, 200)
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)
        self.assertIn(RT4, _extractRTFromAdvertiseCall(self.vpnInstance))
        # dataplane supposed to be updated for this route
        self.assertEqual(
            1,
            self.mockDataplane.setupDataplaneForRemoteEndpoint.call_count)

        self._resetMocks()

        self._revertEvent(event2)
        # withdraw of re-adv route supposed to happen
        self.assertEqual(1, self.vpnInstance._withdrawRoute.call_count)
        self.assertEqual(0, self.vpnInstance._advertiseRoute.call_count)
        # dataplane *not* supposed to be updated for this route
        self.assertEqual(
            0,
            self.mockDataplane.setupDataplaneForRemoteEndpoint.call_count)

    # unit test for IPVPN traffic redirection
    def test_AttractTraffic1(self):
        # Configure VRF generate traffic redirection to route target, based on
        # 5-tuple classifier
        self._configVRFWithAttractTraffic(attractTraffic1)

        self._resetMocks()

        self.vpnInstance.vifPlugged(MAC1, IP1, LOCAL_PORT1, False)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpnInstance._advertiseRoute.call_count)

        self._resetMocks()

        workerA = Worker(Mock(), 'Worker-A')

        self._newRouteEvent(RouteEvent.ADVERTISE, vpnNLRI1, [RT3],
                            workerA, NH1, 200)

        self.assertEqual(2, self.vpnInstance._advertiseRoute.call_count)
        # 1 - re-advertisement of VPN NLRI1 supposed to happen to RT4
        self.assertIn(RT4, _extractRTFromAdvertiseCall(self.vpnInstance, 0))
        self.assertNotIn(RT2, _extractRTFromAdvertiseCall(self.vpnInstance, 0))
        self.assertNotIn(RT3, _extractRTFromAdvertiseCall(self.vpnInstance, 0))
        # 2 - advertisement of FlowSpec NLRI supposed to happen to RT5 for
        #     traffic redirect to RT4 on TCP destination port 80
        self.assertIn(RT5, _extractRTFromAdvertiseCall(self.vpnInstance, 1))
        self.assertEqual(
            RT4,
            _extractTrafficRedirectFromAdvertiseCall(self.vpnInstance, 1)
        )
        self.assertEqual(
            trafficClassifier1,
            _extractTrafficClassifierFromAdvertiseCall(self.vpnInstance, 1)
        )
