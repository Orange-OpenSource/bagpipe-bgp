# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2017 Orange
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

# This module is here to allow conciseness in exabgp imports
# by other modules

from exabgp.bgp.message import OUT
from exabgp.bgp.message import IN

from exabgp.bgp.message.open.asn import ASN

from exabgp.bgp.message.update import Attributes
from exabgp.bgp.message.update.attribute.attribute import Attribute

from exabgp.bgp.message.update.attribute.community.extended.communities \
    import ExtendedCommunities
from exabgp.bgp.message.update.attribute.community.extended \
    import communities as extcoms
from exabgp.bgp.message.update.attribute.community.extended \
    import ConsistentHashSortOrder
from exabgp.bgp.message.update.attribute.community.extended \
    import Encapsulation
from exabgp.bgp.message.update.attribute.community.extended \
    import RouteTarget as RTExtCom
from exabgp.bgp.message.update.attribute.community.extended \
    import RouteTargetASN2Number as RouteTarget
from exabgp.bgp.message.update.attribute.community.extended \
    import TrafficRedirect
from exabgp.bgp.message.update.attribute.community.extended.rt_record\
    import RTRecord

from exabgp.bgp.message.update.attribute.localpref import LocalPreference
from exabgp.bgp.message.update.attribute.nexthop import NextHop
from exabgp.bgp.message.update.attribute.pmsi import PMSI
from exabgp.bgp.message.update.attribute.pmsi import PMSIIngressReplication

from exabgp.bgp.message.update.nlri.flow import Flow
from exabgp.bgp.message.update.nlri import flow
from exabgp.bgp.message.update.nlri.ipvpn import IPVPN
from exabgp.bgp.message.update.nlri.nlri import NLRI

from exabgp.bgp.message.update.nlri.qualifier.esi import ESI
from exabgp.bgp.message.update.nlri.qualifier.etag import EthernetTag
from exabgp.bgp.message.update.nlri.qualifier.labels import Labels
from exabgp.bgp.message.update.nlri.qualifier.mac import MAC
from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher

from exabgp.bgp.message.update.nlri.rtc import RTC

from exabgp.bgp.message.update.nlri.evpn.nlri import EVPN
from exabgp.bgp.message.update.nlri.evpn.mac import MAC as EVPNMAC
from exabgp.bgp.message.update.nlri.evpn.multicast import \
    Multicast as EVPNMulticast

from exabgp.protocol.ip import IP
from exabgp.protocol import Protocol

from exabgp.reactor.protocol import AFI
from exabgp.reactor.protocol import SAFI
