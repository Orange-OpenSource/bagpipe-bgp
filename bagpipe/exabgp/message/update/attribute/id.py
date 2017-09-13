# encoding: utf-8
"""
id.py

Created by Thomas Mangin on 2010-01-19.
Copyright (c) 2010-2012 Exa Networks. All rights reserved.
"""

class AttributeID (int):
	# This should move within the classes and not be here
	# RFC 4271
	ORIGIN             = 0x01
	AS_PATH            = 0x02
	NEXT_HOP           = 0x03
	MED                = 0x04
	LOCAL_PREF         = 0x05
	ATOMIC_AGGREGATE   = 0x06
	AGGREGATOR         = 0x07
	# RFC 1997
	COMMUNITY          = 0x08
	#RFC4456
	ORIGINATOR_ID      = 0x09
	CLUSTER_LIST       = 0x0A
	# RFC 4360
	EXTENDED_COMMUNITY = 0x10
	# RFC 4893
	AS4_PATH           = 0x11
	AS4_AGGREGATOR     = 0x12
	# RFC 4760
	MP_REACH_NLRI      = 0x0e # 14
	MP_UNREACH_NLRI    = 0x0f # 15

	# RFC6514
	PMSI_TUNNEL        = 22

	# RFC5512
	TUNNEL_ENCAP	   = 23

	INTERNAL_WITHDRAWN = 0xFFFD
	INTERNAL_WATCHDOG  = 0xFFFE
	INTERNAL_SPLIT     = 0xFFFF

	def __str__ (self):
		# This should move within the classes and not be here
		if self == 0x01: return "ORIGIN"
		if self == 0x02: return "AS_PATH"
		if self == 0x03: return "NEXT_HOP"
		if self == 0x04: return "MULTI_EXIT_DISC"
		if self == 0x05: return "LOCAL_PREFERENCE"
		if self == 0x06: return "ATOMIC_AGGREGATE"
		if self == 0x07: return "AGGREGATOR"
		if self == 0x08: return "COMMUNITY"
		if self == 0x09: return "ORIGINATOR_ID"
		if self == 0x0A: return "CLUSTER_LIST"
		if self == 0x10: return "EXTENDED_COMMUNITY"
		if self == 0x11: return "AS4_PATH"
		if self == 0x0e: return "MP_REACH_NLRI"
		if self == 0x0f: return "MP_UNREACH_NLRI"
		if self == 22:   return "PMSI_TUNNEL"
		if self == 23:   return "TUNNEL_ENCAP"
		if self == 0xffff: return "INTERNAL SPLIT"
		return 'UNKNOWN ATTRIBUTE (%s)' % hex(self)


