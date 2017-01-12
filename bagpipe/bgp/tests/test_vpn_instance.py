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
   - testBx use cases to test endpoints plug with different combinations of MAC
     and IP addresses on different ports
   - testCx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the one plugged on a port
   - testDx use cases to test endpoints unplug with different combinations of
     MAC and IP addresses as the ones plugged on different ports

"""

from oslo_log import log as logging

from testtools import TestCase
from mock import Mock

from bagpipe.bgp.tests import RT1
from bagpipe.bgp.tests import RT2
from bagpipe.bgp.tests import RT3
from bagpipe.bgp.tests import RT4
from bagpipe.bgp.tests import RT5
from bagpipe.bgp.tests import NLRI1
from bagpipe.bgp.tests import NH1
from bagpipe.bgp.tests import BaseTestBagPipeBGP
from bagpipe.bgp.tests import _rt_to_string

from bagpipe.bgp.engine import RouteEntry
from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine.flowspec import FlowRouteFactory
from bagpipe.bgp.engine.ipvpn import IPVPNRouteFactory
from bagpipe.bgp.engine.worker import Worker

from bagpipe.bgp.vpn.label_allocator import LabelAllocator
from bagpipe.bgp.vpn.rd_allocator import RDAllocator
from bagpipe.bgp.vpn.vpn_instance import VPNInstance, TrafficClassifier

from bagpipe.bgp.vpn.ipvpn import VRF

from exabgp.reactor.protocol import AFI, SAFI


from exabgp.bgp.message.update.attribute.community.extended \
    import Encapsulation
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.nlri import Flow
from exabgp.bgp.message.update.attribute.community.extended import \
    RouteTargetASN2Number as RouteTarget
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord


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


def _extract_nlri_from_call(vpn_instance, method, call_index=0):
    calls = getattr(vpn_instance, method).call_args_list
    return calls[call_index][0][0].nlri


def _extract_rt_from_call(vpn_instance, method, call_index=0):
    calls = getattr(vpn_instance, method).call_args_list
    return calls[call_index][0][0].route_targets


def _extract_rtrec_from_call(vpn_instance, method, call_index=0):
    calls = getattr(vpn_instance, method).call_args_list
    route = calls[call_index][0][0]
    return route.ecoms(RTRecord)


def _extract_traffic_redirect_from_call(vpn_instance, method, call_index=0):
    calls = getattr(vpn_instance, method).call_args_list
    route = calls[call_index][0][0]
    for ecom in route.ecoms(TrafficRedirect):
        return RouteTarget(int(ecom.asn), int(ecom.target))
    return None


def _extract_traffic_classifier_from_call(vpn_instance, method, call_index=0):
    calls = getattr(vpn_instance, method).call_args_list
    traffic_classifier = TrafficClassifier()
    traffic_classifier.map_redirect_rules_2_traffic_classifier(
        calls[call_index][0][0].nlri.rules)
    return traffic_classifier


class TestableVPNInstance(VPNInstance):

    def _best_route_removed(self, entry, route):
        pass

    def _new_best_route(self, entry, route, last):
        pass

    def _route_2_tracked_entry(self, route):
        pass

    def generate_vif_bgp_route(self):
        pass


class TestVPNInstance(TestCase):

    def setUp(self):
        super(TestVPNInstance, self).setUp()

        mock_dataplane = Mock()
        mock_dataplane.vif_plugged = Mock()
        mock_dataplane.vif_unplugged = Mock()

        mock_dp_driver = Mock()
        mock_dp_driver.initialize_dataplane_instance.return_value = (
            mock_dataplane
        )

        VPNInstance.afi = AFI(AFI.ipv4)
        VPNInstance.safi = SAFI(SAFI.mpls_vpn)
        self.vpn = TestableVPNInstance(Mock(name='VPNManager'),
                                       mock_dp_driver, 1, 1,
                                       [RT1], [RT1], '10.0.0.1', 24,
                                       None, None)
        self.vpn.synthesize_vif_bgp_route = Mock(
            return_value=RouteEntry(NLRI1, [RT1]))
        self.vpn._advertise_route = Mock()
        self.vpn._withdraw_route = Mock()
        self.vpn.start()

    def tearDown(self):
        super(TestVPNInstance, self).tearDown()
        self.vpn.stop()
        self.vpn.join()

    def _get_ip_address(self, ip_address_prefix):
        return ip_address_prefix[0:ip_address_prefix.find('/')]

    def _validate_ip_address_2_mac_address_consistency(self, mac_address,
                                                       ip_address1,
                                                       ip_address2=None):
        # Validate IP address -> MAC address consistency
        self.assertIn(ip_address1, self.vpn.ip_address_2_mac)

        if ip_address2:
            self.assertIn(ip_address1, self.vpn.ip_address_2_mac)
            self.assertEquals(
                self.vpn.ip_address_2_mac[ip_address1],
                self.vpn.ip_address_2_mac[ip_address2])
        else:
            self.assertIn(
                mac_address, self.vpn.ip_address_2_mac[ip_address1])

    def _chk_mac_2_localport_data_consistency(self, mac_address, localport):
        # Validate MAC address -> Port informations consistency
        self.assertIn(mac_address, self.vpn.mac_2_localport_data)

        port_info = self.vpn.mac_2_localport_data[
            mac_address]['port_info']
        self.assertEquals(localport['linuxif'], port_info['linuxif'])

    def _validate_localport_2_endpoints_consistency(self, length, localport,
                                                    endpoints):
        # Validate Port -> Endpoint (MAC, IP) tuple consistency
        self.assertEqual(
            length,
            len(self.vpn.localport_2_endpoints[localport['linuxif']]))

        for mac_address, ip_address in endpoints:
            endpoint_info = {'mac': mac_address, 'ip': ip_address}
            self.assertIn(
                endpoint_info,
                self.vpn.localport_2_endpoints[localport['linuxif']])

    def test_a1_plug_endpoint_twice_same_port(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on a port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.assertEqual(1, self.vpn.dataplane.vif_plugged.call_count,
                         "Port must be plugged only once on dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Route for port must be advertised only once")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

    def test_a2_plug_multiple_endpoints_with_same_ip_same_port(self):
        '''
        Plug multiple endpoints with different MAC addresses and same IP
        address on a port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(Exception,
                          self.vpn.vif_plugged,
                          MAC2, IP1, LOCAL_PORT1)
        self.assertEqual(1, self.vpn.dataplane.vif_plugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Only route for first port must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(MAC2, self.vpn.mac_2_localport_data)

    def test_a3_plug_multiple_endpoints_with_same_mac_same_port(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on a port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC1, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "Port different IP addresses must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Route for port different IP addresses must be "
                         "advertised")
        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1, IP2)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC1, IP2)])

    def test_a4_plug_multiple_endpoints_same_port(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on a port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "Port different endpoints must be plugged on "
                         "dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Route for port different endpoints must be "
                         "advertised")
        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            2, LOCAL_PORT1, [(MAC1, IP1), (MAC2, IP2)])

    def test_b1_plug_endpoint_twice_different_port(self):
        '''
        Plug one endpoint with same MAC and IP addresses twice on different
        ports
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpn.vif_plugged,
                          MAC1, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpn.dataplane.vif_plugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Only route for first port must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b2_plug_multiple_endpoints_with_same_ip_different_port(self):
        '''
        Plug multiple endpoints with different MAC addresses and same IP
        address on different port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # An IP address correspond to only one MAC address, exception must be
        # raised
        self.assertRaises(Exception,
                          self.vpn.vif_plugged,
                          MAC2, IP1, LOCAL_PORT2)
        self.assertEqual(1, self.vpn.dataplane.vif_plugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Only route for first port must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b4_plug_multiple_endpoints_with_same_mac_different_port(self):
        '''
        Plug multiple endpoints with same MAC address and different IP
        addresses on different ports
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        # A port correspond to only one MAC address, exception must be raised
        self.assertRaises(Exception,
                          self.vpn.vif_plugged,
                          MAC1, IP2, LOCAL_PORT2)
        self.assertEqual(1, self.vpn.dataplane.vif_plugged.call_count,
                         "Only first port must be plugged on dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Only route for first port must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])
        self.assertNotIn(
            LOCAL_PORT2['linuxif'], self.vpn.localport_2_endpoints)

    def test_b5_plug_multiple_endpoints_different_port(self):
        '''
        Plug multiple endpoints with different MAC and IP addresses on
        different ports
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        self.assertEqual(2, self.vpn.dataplane.vif_plugged.call_count,
                         "All ports must be plugged on dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all ports must be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT2)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def test_c1_unplug_unique_endpoint_same_port(self):
        '''
        Unplug one endpoint with same MAC and IP addresses as the one plugged
        on port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']

        self.vpn.vif_unplugged(MAC1, IP1)

        self.assertEqual(1, self.vpn.dataplane.vif_unplugged.call_count,
                         "Endpoint could be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, True),)],
            self.vpn.dataplane.vif_unplugged.call_args_list)
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Route must be first advertised and after withdrawn")
        self.assertEqual(1, self.vpn._withdraw_route.call_count,
                         "Route must be first advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_c2_unplug_unique_endpoint_with_same_ip_same_port(self):
        '''
        Unplug one endpoint with different MAC addresses and same IP address as
        the one plugged on port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.assertRaises(Exception,
                          self.vpn.vif_unplugged,
                          MAC2, IP1)

        self.assertEqual(0, self.vpn.dataplane.vif_unplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "only one Route must be advertised")

        self.assertIn(MAC1, self.vpn.mac_2_localport_data)
        self.assertIn(IP1, self.vpn.ip_address_2_mac)
        self.assertIn(
            LOCAL_PORT1['linuxif'], self.vpn.localport_2_endpoints)

    def test_c3_unplug_unique_endpoint_with_same_mac_same_port(self):
        '''
        Unplug one endpoint with same MAC address and different IP addresses
        as the one plugged on port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)

        self.assertRaises(Exception,
                          self.vpn.vif_unplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpn.dataplane.vif_unplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(1, self.vpn._advertise_route.call_count,
                         "Route must only be advertised once")
        self.assertEqual(0, self.vpn._withdraw_route.call_count,
                         "Route must not be withdrawn")

        self.assertIn(MAC1, self.vpn.mac_2_localport_data)
        self.assertIn(IP1, self.vpn.ip_address_2_mac)
        self.assertIn(
            LOCAL_PORT1['linuxif'], self.vpn.localport_2_endpoints)

    def test_c4_unplug_one_endpoint_same_port(self):
        '''
        Unplug only one endpoint with same MAC and IP addresses
        corresponding to one plugged on port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']

        self.vpn.vif_unplugged(MAC1, IP1)

        self.assertEqual(1, self.vpn.dataplane.vif_unplugged.call_count,
                         "Endpoint must be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, False),)],
            self.vpn.dataplane.vif_unplugged.call_args_list)
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawn")
        self.assertEqual(1, self.vpn._withdraw_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and only one withdrawn")

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC2, IP2)])

    def test_c5_unplug_all_endpoints_same_port(self):
        '''
        Unplug all endpoints with same MAC and IP addresses
        corresponding to those plugged on port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)

        self.assertEqual(2, self.vpn.dataplane.vif_unplugged.call_count,
                         "All port endpoints must be unplugged from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, False),),
             ((MAC2, self._get_ip_address(IP2), LOCAL_PORT1, label2, True),)],
            self.vpn.dataplane.vif_unplugged.call_args_list)
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")
        self.assertEqual(2, self.vpn._withdraw_route.call_count,
                         "Routes for all port endpoints must be first "
                         "advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_d1_unplug_unique_endpoints_different_port(self):
        '''
        Unplug the endpoints with different MAC and IP addresses corresponding
        to those plugged on different ports
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)

        self.assertEqual(2, self.vpn.dataplane.vif_unplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, True),),
             ((MAC2, self._get_ip_address(IP2), LOCAL_PORT2, label2, True),)],
            self.vpn.dataplane.vif_unplugged.call_args_list)
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(2, self.vpn._withdraw_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_d2_unplug_one_endpoint_same_ip_different_port(self):
        '''
        Unplug one endpoint with different MAC or IP address corresponding to
        one plugged on another port
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2)

        self.assertRaises(Exception,
                          self.vpn.vif_unplugged,
                          MAC1, IP2)

        self.assertEqual(0, self.vpn.dataplane.vif_unplugged.call_count,
                         "Endpoint could not be unplugged from dataplane")
        self.assertEqual(2, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must only "
                         "be advertised")

        self._validate_ip_address_2_mac_address_consistency(MAC1, IP1)
        self._chk_mac_2_localport_data_consistency(MAC1, LOCAL_PORT1)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT1, [(MAC1, IP1)])

        self._validate_ip_address_2_mac_address_consistency(MAC2, IP2)
        self._chk_mac_2_localport_data_consistency(MAC2, LOCAL_PORT2)
        self._validate_localport_2_endpoints_consistency(
            1, LOCAL_PORT2, [(MAC2, IP2)])

    def test_d3_unplug_multiple_endpoints_different_port(self):
        '''
        Unplug multiple endpoints with same MAC and IP addresses corresponding
        to those plugged on different ports
        '''
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT2)
        self.vpn.vif_plugged(MAC4, IP4, LOCAL_PORT2)

        label1 = self.vpn.mac_2_localport_data[MAC1]['label']
        label2 = self.vpn.mac_2_localport_data[MAC2]['label']
        label3 = self.vpn.mac_2_localport_data[MAC3]['label']
        label4 = self.vpn.mac_2_localport_data[MAC4]['label']

        self.vpn.vif_unplugged(MAC1, IP1)
        self.vpn.vif_unplugged(MAC2, IP2)
        self.vpn.vif_unplugged(MAC3, IP3)
        self.vpn.vif_unplugged(MAC4, IP4)

        self.assertEqual(4, self.vpn.dataplane.vif_unplugged.call_count,
                         "All different ports endpoints must be unplugged "
                         "from dataplane")
        self.assertEqual(
            [((MAC1, self._get_ip_address(IP1), LOCAL_PORT1, label1, False),),
             ((MAC2, self._get_ip_address(
               IP2), LOCAL_PORT1, label2, True),),
             ((MAC3, self._get_ip_address(
               IP3), LOCAL_PORT2, label3, False),),
             ((MAC4, self._get_ip_address(IP4), LOCAL_PORT2, label4, True),)],
            self.vpn.dataplane.vif_unplugged.call_args_list)
        self.assertEqual(4, self.vpn._withdraw_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")
        self.assertEqual(4, self.vpn._advertise_route.call_count,
                         "Routes for all different ports endpoints must be "
                         "first advertised and after withdrawn")

        self.assertEqual({}, self.vpn.mac_2_localport_data)
        self.assertEqual({}, self.vpn.ip_address_2_mac)
        self.assertEqual({}, self.vpn.localport_2_endpoints)

    def test_get_lg_localport_data(self):
        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1)
        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT2)
        self.vpn.vif_plugged(MAC4, IP4, LOCAL_PORT2)

        self.vpn.get_lg_local_port_data("")

    # tests of update_route_targets

    def _test_update_rts_init(self):
        self.vpn._advertise_route.reset_mock()

        route = RouteEntry(NLRI1, [RT1])
        self.vpn._rtm_route_entries = set([route])

    def test_update_rts_1(self):
        self._test_update_rts_init()

        # no change -> no route update
        self.vpn.update_route_targets([RT1], [RT1])

        self.assertEqual(0, self.vpn._advertise_route.call_count)

    def test_update_rts_2(self):
        self._test_update_rts_init()

        # change imports -> no route update
        self.vpn.update_route_targets([RT2], [RT1])

        self.assertEqual(0, self.vpn._advertise_route.call_count)

    def test_update_rts_3(self):
        self._test_update_rts_init()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpn.update_route_targets([RT1], [RT2])

        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self.assertIn(RT2, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route'))
        self.assertNotIn(RT1, _extract_rt_from_call(self.vpn,
                                                    '_advertise_route'))

    def test_update_rts_3bis(self):
        self._test_update_rts_init()

        # change exports
        # check that previously advertised routes are readvertised
        self.vpn.update_route_targets([RT1], [RT1, RT2])

        self.assertEqual(1, self.vpn._advertise_route.call_count)
        self.assertIn(RT2, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route'))
        self.assertIn(RT1, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route'))


LOCAL_ADDRESS = '4.5.6.7'
NEXT_HOP = '45.45.45.45'

IP_ADDR_PREFIX1 = '1.1.1.1/32'
IP_ADDR_PREFIX2 = '2.2.2.2/32'
IP_ADDR_PREFIX3 = '3.3.3.3/32'

DEFAULT_ADDR_PREFIX = '0.0.0.0/0'

ATTRACT_TRAFFIC_1 = {'redirect_rts': [RT5],
                     'classifier': {'destinationPort': '80',
                                    'protocol': 'tcp'
                                    }
                     }

TC1 = TrafficClassifier(destination_prefix="1.1.1.1/32",
                        destination_port="80",
                        protocol="tcp")

TC2 = TrafficClassifier(destination_prefix="2.2.2.2/32",
                        destination_port="80",
                        protocol="tcp")


class TestVRF(BaseTestBagPipeBGP, TestCase):

    def setUp(self):
        super(TestVRF, self).setUp()

        self.mock_dp = Mock()
        self.mock_dp.vif_plugged = Mock()
        self.mock_dp.vif_unplugged = Mock()
        self.mock_dp.setup_dataplane_for_remote_endpoint = Mock()

        mock_dp_driver = Mock()
        mock_dp_driver.initialize_dataplane_instance.return_value = \
            self.mock_dp
        mock_dp_driver.get_local_address.return_value = LOCAL_ADDRESS
        mock_dp_driver.supported_encaps.return_value = \
            [Encapsulation(Encapsulation.Type.DEFAULT)]

        label_allocator = LabelAllocator()
        bgp_manager = Mock()
        bgp_manager.get_local_address.return_value = LOCAL_ADDRESS
        rd_allocator = RDAllocator(bgp_manager.get_local_address())
        self.manager = Mock(bgp_manager=bgp_manager,
                            label_allocator=label_allocator,
                            rd_allocator=rd_allocator)

        self.vpn = VRF(self.manager, mock_dp_driver, 1, 1,
                       [RT1], [RT1], '10.0.0.1', 24,
                       {'from_rt': [RT3],
                        'to_rt': [RT4]},
                       None)

        self.vpn._advertise_route = Mock()
        self.vpn._withdraw_route = Mock()
        self.vpn.start()

        self.event_target_worker = self.vpn

    def _reset_mocks(self):
        self.vpn._advertise_route.reset_mock()
        self.vpn._withdraw_route.reset_mock()
        self.mock_dp.setup_dataplane_for_remote_endpoint.reset_mock()
        self.mock_dp.vif_plugged.reset_mock()
        self.mock_dp.vif_unplugged.reset_mock()

    def tearDown(self):
        super(TestVRF, self).tearDown()
        self.vpn.stop()
        self.vpn.join()

    def _config_vrf_with_attract_traffic(self, attract_traffic):
        self.vpn.attract_traffic = True
        self.vpn.attract_rts = attract_traffic['redirect_rts']
        self.vpn.attract_classifier = attract_traffic['classifier']

    def _mock_vpnmanager_for_attract_traffic(self):
        self.manager.redirect_traffic_to_vpn = Mock()
        self.manager.stop_redirect_to_vpn = Mock()

    def _reset_mocks_vpnmanager(self):
        self.manager.redirect_traffic_to_vpn.reset_mock()
        self.manager.stop_redirect_to_vpn.reset_mock()

    def _generate_route_nlri(self, ip_address_prefix):
        # Parse address/mask
        (_, prefix_len) = self.vpn._parse_ipaddress_prefix(ip_address_prefix)

        prefix_rd = self.manager.rd_allocator.get_new_rd(
            "Route distinguisher for prefix %s" % ip_address_prefix
        )
        rd = self.vpn.instance_rd if prefix_len == 32 else prefix_rd

        label = self.manager.label_allocator.get_new_label(
            "Label for prefix %s" % ip_address_prefix
        )

        return IPVPNRouteFactory(AFI(AFI.ipv4), ip_address_prefix,
                                 label, rd, NEXT_HOP)

    def _generate_flow_spec_nlri(self, classifier):
        flow_nlri = FlowRouteFactory(AFI(AFI.ipv4), self.vpn.instance_rd)

        for rule in classifier.map_traffic_classifier_2_redirect_rules():
            flow_nlri.add(rule)

        return flow_nlri

    # unit test for IPVPN re-advertisement
    def test_re_advertisement_1(self):
        self._reset_mocks()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri_1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri_1, [RT1, RT2],
                              worker_a, NH1, 200)
        # no re-advertisement supposed to happen
        self.assertEqual(1, self.vpn._advertise_route.call_count)
        # dataplane supposed to be updated for this route
        self.assertEqual(
            1,
            self.mock_dp.setup_dataplane_for_remote_endpoint.call_count)

        self._reset_mocks()

        vpn_nlri_2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        event2 = self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri_2, [RT3],
                                       worker_a, NH1, 200,
                                       rtrecords=[RTRecord1])
        # re-advertisement of VPN NLRI2 supposed to happen, to RT4
        self.assertEqual(1, self.vpn._advertise_route.call_count)
        self.assertIn(RT4, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route'))
        self.assertNotIn(RT2, _extract_rt_from_call(self.vpn,
                                                    '_advertise_route'))
        self.assertNotIn(RT3, _extract_rt_from_call(self.vpn,
                                                    '_advertise_route'))
        self.assertIn(RTRecord3, _extract_rtrec_from_call(self.vpn,
                                                          '_advertise_route'))
        self.assertIn(RTRecord1, _extract_rtrec_from_call(self.vpn,
                                                          '_advertise_route'))
        # dataplane *not* supposed to be updated for this route
        self.assertEqual(
            0,
            self.mock_dp.setup_dataplane_for_remote_endpoint.call_count)

        self._reset_mocks()

        # new interface plugged in
        # route vpn_nlri_2 should be re-advertized with this new next hop as
        #  next-hop
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT2, False, 0)
        # advertised route count should increment by 2:
        # - vif route itself
        # - re-adv of NLRI1 with this new port as next-hop
        self.assertEqual(2, self.vpn._advertise_route.call_count)
        self.assertEqual(0, self.vpn._withdraw_route.call_count)
        self.assertIn(RT1, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route', 0))
        self.assertNotIn(RT4, _extract_rt_from_call(self.vpn,
                                                    '_advertise_route', 0))
        self.assertIn(RT4, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route', 1))
        self.assertNotIn(RT1, _extract_rt_from_call(self.vpn,
                                                    '_advertise_route', 1))

        # check that second event is for re-advertised route vpn_nlri_2 and
        #  contains what we expect
        route_entry = self.vpn._advertise_route.call_args_list[1][0][0]
        self.assertEqual(vpn_nlri_2.cidr.prefix(),
                         route_entry.nlri.cidr.prefix())
        self.assertNotEqual(vpn_nlri_2.labels, route_entry.nlri.labels)
        self.assertNotEqual(vpn_nlri_2.nexthop, route_entry.nlri.nexthop)

        self._reset_mocks()

        # new route, that, because it contains the redirectRT in RTRecord
        # will not be re-advertized
        vpn_nlri3 = self._generate_route_nlri(IP_ADDR_PREFIX3)
        event3 = self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri3, [RT3],
                                       worker_a, NH1, 200,
                                       rtrecords=[RTRecord4])
        self.assertEqual(0, self.vpn._advertise_route.call_count)
        self.assertEqual(0, self.vpn._withdraw_route.call_count)
        self._revert_event(event3)

        self._reset_mocks()

        # vif unplugged, routes VPN NLRI2 with next-hop
        # corresponding to this ports should now be withdrawn
        self.vpn.vif_unplugged(MAC2, IP2, False)
        self.assertEqual(2, self.vpn._withdraw_route.call_count)
        route_entry = self.vpn._withdraw_route.call_args_list[0][0][0]
        self.assertEqual(vpn_nlri_2.cidr.prefix(),
                         route_entry.nlri.cidr.prefix())
        self.assertNotEqual(vpn_nlri_2.labels, route_entry.nlri.labels)
        self.assertNotEqual(vpn_nlri_2.nexthop, route_entry.nlri.nexthop)

        self._reset_mocks()

        # RTs of route NLRI1 now include a re-advertiseed RT
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri_1,
                              [RT1, RT2, RT3],
                              worker_a, NH1, 200)
        self.assertEqual(1, self.vpn._advertise_route.call_count)
        self.assertIn(RT4, _extract_rt_from_call(self.vpn,
                                                 '_advertise_route'))
        # dataplane supposed to be updated for this route
        self.assertEqual(
            1,
            self.mock_dp.setup_dataplane_for_remote_endpoint.call_count)

        self._reset_mocks()

        self._revert_event(event2)
        # withdraw of re-adv route supposed to happen
        self.assertEqual(1, self.vpn._withdraw_route.call_count)
        self.assertEqual(0, self.vpn._advertise_route.call_count)
        # dataplane *not* supposed to be updated for this route
        self.assertEqual(
            0,
            self.mock_dp.setup_dataplane_for_remote_endpoint.call_count)

    def _check_attract_traffic(self, method, redirect_rts,
                               expected_classifiers):
        self.assertEqual(len(expected_classifiers),
                         getattr(self.vpn, method).call_count)

        for index, classifier in enumerate(expected_classifiers):
            if not classifier:
                # Skip advertisement to exported route targets
                if (self.vpn.export_rts == _extract_rt_from_call(
                        self.vpn,
                        method,
                        index)):
                    continue

                # 1 - re-advertisement of a default route supposed to happen
                # to RT4
                self.assertIn(self.vpn.readvertise_to_rts[0],
                              _extract_rt_from_call(self.vpn, method, index))

                ipvpn_nlri = _extract_nlri_from_call(self.vpn, method, index)
                self.assertEqual(DEFAULT_ADDR_PREFIX, ipvpn_nlri.cidr.prefix())

                self.assertNotIn(self.vpn.readvertise_from_rts[0],
                                 _extract_rt_from_call(self.vpn,
                                                       method, index))
            else:
                # 2 - advertisement of FlowSpec NLRI supposed to happen to RT5
                #     for traffic redirection to RT4 on TCP destination port 80
                flow_nlri = _extract_nlri_from_call(self.vpn, method, index)
                self.assertIsInstance(flow_nlri, Flow)

                self.assertIn(redirect_rts[0],
                              _extract_rt_from_call(self.vpn, method, index))
                self.assertEqual(
                    self.vpn.readvertise_to_rts[0],
                    _extract_traffic_redirect_from_call(self.vpn,
                                                        method, index)
                )
                self.assertEqual(
                    classifier,
                    _extract_traffic_classifier_from_call(self.vpn,
                                                          method, index)
                )

    # unit test for IPVPN traffic redirection
    def test_attract_traffic_single_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, TC1])

    def test_attract_traffic_single_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic('_withdraw_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, TC1])

    def test_attract_traffic_multiple_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, TC1, None, TC2])

    def test_attract_traffic_multiple_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(4, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)

        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, TC2, None, TC1])

    def test_redirected_vrf_single_flow_advertised(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(RouteEvent.ADVERTISE, flow_nlri1, [RT5], [RT1],
                             worker_a)

        redirect_rt5 = _rt_to_string(RT5)
        self.assertEqual(1, self.manager.redirect_traffic_to_vpn.call_count)
        self.assertIn(TC1,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])

    def test_redirected_vrf_multiple_flow_advertised(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(RouteEvent.ADVERTISE, flow_nlri1, [RT5], [RT1],
                             worker_a)
        flow_nlri2 = self._generate_flow_spec_nlri(TC2)
        self._new_flow_event(RouteEvent.ADVERTISE, flow_nlri2, [RT5], [RT1],
                             worker_a)

        redirect_rt5 = _rt_to_string(RT5)
        self.assertEqual(2, self.manager.redirect_traffic_to_vpn.call_count)
        self.assertIn(TC1,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])
        self.assertIn(TC2,
                      self.vpn.redirect_rt_2_classifiers[redirect_rt5])

    def test_redirected_vrf_multiple_flow_withdrawn(self):
        self._mock_vpnmanager_for_attract_traffic()

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(1, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        # FlowSpec route
        flow_nlri1 = self._generate_flow_spec_nlri(TC1)
        self._new_flow_event(RouteEvent.ADVERTISE, flow_nlri1, [RT5], [RT1],
                             worker_a)
        flow_nlri2 = self._generate_flow_spec_nlri(TC2)
        self._new_flow_event(RouteEvent.ADVERTISE, flow_nlri2, [RT5], [RT1],
                             worker_a)

        self.assertEqual(2, self.manager.redirect_traffic_to_vpn.call_count)

        self._reset_mocks_vpnmanager()

        self._new_flow_event(RouteEvent.WITHDRAW, flow_nlri2, [RT5], [RT1],
                             worker_a)

        redirect_rt5 = _rt_to_string(RT5)
        self.assertNotIn(TC2,
                         self.vpn.redirect_rt_2_classifiers[redirect_rt5])

        self._new_flow_event(RouteEvent.WITHDRAW, flow_nlri1, [RT5], [RT1],
                             worker_a)

        self.assertTrue(not self.vpn.redirect_rt_2_classifiers)
        self.assertEqual(1, self.manager.stop_redirect_to_vpn.call_count)

    def test_load_balancing_single_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic('_advertise_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, None, TC1])

    def test_load_balancing_single_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic('_withdraw_route',
                                    ATTRACT_TRAFFIC_1['redirect_rts'],
                                    [None, None, TC1])

    def test_load_balancing_multiple_prefix_advertise(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None, TC1, None, None, TC2])

    def test_load_balancing_multiple_prefix_withdraw(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        vpn_nlri2 = self._generate_route_nlri(IP_ADDR_PREFIX2)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(6, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri2, [RT3],
                              worker_a, NH1, 200)
        self._new_route_event(RouteEvent.WITHDRAW, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None, TC2, None, None, TC1])

    def test_load_balancing_new_plug(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self.vpn.vif_plugged(MAC3, IP3, LOCAL_PORT1, False, 2)

        self._check_attract_traffic(
            '_advertise_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None, TC1])

    def test_load_balancing_unplug_all(self):
        # Configure VRF to generate traffic redirection, based on a 5-tuple
        # classifier, to a specific route target
        self._config_vrf_with_attract_traffic(ATTRACT_TRAFFIC_1)

        self.vpn.vif_plugged(MAC1, IP1, LOCAL_PORT1, False, 0)
        self.vpn.vif_plugged(MAC2, IP2, LOCAL_PORT1, False, 1)

        # new Route for plugged if supposed to be advertised
        self.assertEqual(2, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        worker_a = Worker(Mock(), 'Worker-A')

        vpn_nlri1 = self._generate_route_nlri(IP_ADDR_PREFIX1)
        self._new_route_event(RouteEvent.ADVERTISE, vpn_nlri1, [RT3],
                              worker_a, NH1, 200)

        self.assertEqual(3, self.vpn._advertise_route.call_count)

        self._reset_mocks()

        self.vpn.vif_unplugged(MAC1, IP1, False)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, None])

        self._reset_mocks()

        self.vpn.vif_unplugged(MAC2, IP2, False)

        self._check_attract_traffic(
            '_withdraw_route',
            ATTRACT_TRAFFIC_1['redirect_rts'],
            [None, TC1, None])
