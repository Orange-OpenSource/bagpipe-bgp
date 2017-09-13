# encoding: utf-8
"""
address.py

Created by Thomas Mangin on 2010-01-19.
Copyright (c) 2010-2012 Exa Networks. All rights reserved.
Modified by Orange - 2014
"""

from struct import pack

# =================================================================== AFI

# http://www.iana.org/assignments/address-family-numbers/
class AFI (int):
	ipv4 = 0x01
	ipv6 = 0x02
	l2vpn = 0x19

	def __str__ (self):
		if self == 0x01: return "IPv4"
		if self == 0x02: return "IPv6"
		if self == 0x19: return "L2VPN"
		return "unknown afi %d" % self

	def __repr__ (self):
		return str(self)

	def pack (self):
		return pack('!H',self)

# =================================================================== SAFI

# http://www.iana.org/assignments/safi-namespace
class SAFI (int):
	unicast = 1                 # [RFC4760]
	multicast = 2               # [RFC4760]
#	deprecated = 3              # [RFC4760]
	nlri_mpls = 4               # [RFC3107]
#	mcast_vpn = 5               # [draft-ietf-l3vpn-2547bis-mcast-bgp] (TEMPORARY - Expires 2008-06-19)
#	pseudowire = 6              # [draft-ietf-pwe3-dynamic-ms-pw] (TEMPORARY - Expires 2008-08-23) Dynamic Placement of Multi-Segment Pseudowires
#	encapsulation = 7           # [RFC5512]
#
#	tunel = 64                  # [Nalawade]
#	vpls = 65                   # [RFC4761]
#	bgp_mdt = 66                # [Nalawade]
#	bgp_4over6 = 67             # [Cui]
#	bgp_6over4 = 67             # [Cui]
#	vpn_adi = 69                # [RFC-ietf-l1vpn-bgp-auto-discovery-05.txt]

	evpn = 70                   #  draft-ietf-l2vpn-evpn]

	mpls_vpn = 128              # [RFC4364]
#	mcast_bgp_mpls_vpn = 129    # [RFC2547]
	rtc = 132                    # [RFC4684]
	flow_ipv4 = 133             # [RFC5575]
	flow_vpnv4 = 134            # [RFC5575]
#
#	vpn_ad = 140                # [draft-ietf-l3vpn-bgpvpn-auto]
#
#	private = [_ for _ in range(241,254)]   # [RFC4760]
#	unassigned = [_ for _ in range(8,64)] + [_ for _ in range(70,128)]
#	reverved = [0,3] + [130,131] + [_ for _ in range(135,140)] + [_ for _ in range(141,241)] + [255,]    # [RFC4760]

	def __str__ (self):
		if self == 0x01: return "unicast"
		if self == 0x02: return "multicast"
		if self == 0x04: return "nlri-mpls"
		if self == 0x46: return "evpn"
		if self == 0x80: return "mpls-vpn"
		if self == 0x84: return "rtc"
		if self == 0x85: return "flow-ipv4"
		if self == 0x86: return "flow-vpnv4"
		return "unknown safi %d" % self

	def __repr__ (self):
		return str(self)

	def pack (self):
		return chr(self)

## =================================================================== Address

class Address (object):
	def __init__ (self,afi,safi):
		self.afi = AFI(afi)
		self.safi = SAFI(safi)

	def __str__ (self):
		return "%s %s" % (str(self.afi),str(self.safi))

	def __repr__ (self):
		return str(self)
