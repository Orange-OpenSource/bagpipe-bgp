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


import logging
import socket

from bagpipe.bgp.common import utils

from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.vpn.vpn_instance import VPNInstance
from bagpipe.bgp.vpn.dataplane_drivers import DummyDataplaneDriver as _DummyDataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass


from exabgp.structure.address import AFI, SAFI

log = logging.getLogger(__name__)

class DummyDataplaneDriver(_DummyDataplaneDriver):
    
    def __init__(self, *args):
        _DummyDataplaneDriver.__init__(self, *args)


class EVI(VPNInstance, LookingGlass):
    '''
    Component to manage an E-VPN instance (EVI).
    Based on specifications draft-ietf-l2vpn-evpn and draft-sd-l2vpn-evpn-overlay.
    
    Currently a mere placeholder.
    '''
    
    afi = AFI(AFI.l2vpn)
    safi = SAFI(SAFI.evpn)
    
    def __init__(self, *args):
        raise Exception("This E-VPN EVI implementation is only a placeholder")
