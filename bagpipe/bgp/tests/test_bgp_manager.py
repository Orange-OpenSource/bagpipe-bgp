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

from testtools import TestCase

from bagpipe.bgp.engine.bgp_manager import Manager
from bagpipe.bgp.engine import Subscription

from exabgp.protocol.family import SAFI


class TestRouteTableManager(TestCase):

    def setUp(self):
        super(TestRouteTableManager, self).setUp()
        self.bgpManager = Manager({'my_as': '64512',
                                   'local_address': '1.2.3.4',
                                   'peers': []
                                   })

    def test1(self):
        subscription = Subscription(Subscription.ANY_AFI,
                                    Subscription.ANY_SAFI,
                                    Subscription.ANY_RT)

        routeEntry = self.bgpManager._subscription2RTCRouteEntry(subscription)

        self.assertEqual(routeEntry.safi, SAFI.rtc, "wrong RTC route")
