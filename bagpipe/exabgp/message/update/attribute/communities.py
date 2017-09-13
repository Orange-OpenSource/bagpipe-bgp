# encoding: utf-8
"""
community.py

Created by Thomas Mangin on 2009-11-05.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
Modified by Orange - 2014
"""

from struct import pack,unpack

import socket

from bagpipe.exabgp.message.update.attribute import AttributeID,Flag,Attribute

from bagpipe.exabgp.structure.asn import ASN 


# =================================================================== Community

class Community (object):
	def __init__ (self,community):
		self.community = community
		if community == 0xFFFFFF01:
			self._str = 'no-export'
		elif community == 0xFFFFFF02:
			self._str = 'no-advertise'
		elif community == 0xFFFFFF03:
			self._str = 'no-export-subconfed'
		else:
			self._str = "%d:%d" % (community >> 16, community & 0xFFFF)

	def pack (self):
		return pack('!L',self.community)

	def __str__ (self):
		return self._str

	def __len__ (self):
		return 4

	def __cmp__ (self,other):
		if ( isinstance(other,Community) and
			self.community == other.community):
			return 0
		else:
			return -1

# =================================================================== Communities (8)

class Communities (Attribute):
	ID = AttributeID.COMMUNITY
	FLAG = Flag.TRANSITIVE|Flag.OPTIONAL
	MULTIPLE = False

	def __init__ (self,communities=None):
		# Must be None as = param is only evaluated once
		if communities:
			self.communities = communities
		else:
			self.communities = []

	def add(self,data):
		return self.communities.append(data)

	def pack (self):
		if len(self.communities):
			return self._attribute(''.join([c.pack() for c in self.communities]))
		return ''

	def __str__ (self):
		l = len(self.communities)
		if l > 1:
			return "[ %s ]" % " ".join(str(community) for community in self.communities)
		if l == 1:
			return str(self.communities[0])
		return ""

	def __repr__ (self):
		return str(self)

# =================================================================== ECommunity

#def to_ECommunity (data):
#	separator = data.find(':')
#	if separator > 0:
#		# XXX: Check that the value do not overflow 16 bits
#		return ECommunity((int(data[:separator])<<16) + int(data[separator+1:]))
#	elif len(data) >=2 and data[1] in 'xX':
#		return ECommunity(long(data,16))
#	else:
#		return ECommunity(long(data))


# http://www.iana.org/assignments/bgp-extended-communities


# MUST ONLY raise ValueError
def to_ExtendedCommunity (data):
	command,ga,la = data.split(':')

	if command == 'origin':
		subtype = chr(0x03)
	elif command == 'target':
		subtype = chr(0x02)
	else:
		raise ValueError('invalid extended community %s (only origin or target are supported) ' % command)

	gc = ga.count('.')
	lc = la.count('.')
	if gc == 0 and lc == 3:
		# ASN first, IP second
		header = chr(0x40)
		global_admin = pack('!H',int(ga))
		local_admin = pack('!BBBB',*[int(_) for _ in la.split('.')])
	elif gc == 3 and lc == 0:
		# IP first, ASN second
		header = chr(0x41)
		global_admin = pack('!BBBB',*[int(_) for _ in ga.split('.')])
		local_admin = pack('!H',int(la))
	else:
		raise ValueError('invalid extended community %s ' % data)

	return ECommunity(header+subtype+global_admin+local_admin)

class ECommunity (object):
	ID = AttributeID.EXTENDED_COMMUNITY
	FLAG = Flag.TRANSITIVE|Flag.OPTIONAL
	MULTIPLE = False

	# size of value for data (boolean: is extended)
	length_value = {False:7, True:6}
	name = {False: 'regular', True: 'extended'}

	def __init__ (self,community):
		# Two top bits are iana and transitive bits
		self.community = community

	def iana (self):
		return not not (self.community[0] & 0x80)

	def transitive (self):
		return not not (self.community[0] & 0x40)

	def pack (self):
		return self.community

	def __str__ (self):
		# 30/02/12 Quagga communities for soo and rt are not transitive when 4360 says they must be, hence the & 0x0F
		community_type = ord(self.community[0]) & 0x0F
		community_stype = ord(self.community[1])
		# Target
		if community_stype == 0x02:
			return repr( RouteTarget.unpackFrom( self.community ) )
#			if community_type in (0x00,0x02):
#				asn = unpack('!H',self.community[2:4])[0]
#				ip = '%s.%s.%s.%s' % unpack('!BBBB',self.community[4:])
#				return "target:%d:%s" % (asn,ip)
#			if community_type == 0x01:
#				ip = '%s.%s.%s.%s' % unpack('!BBBB',self.community[2:6])
#				asn = unpack('!H',self.community[6:])[0]
#				return "target:%s:%d" % (ip,asn)
		# Origin
		if community_stype == 0x03:
			if community_type in (0x00,0x02):
				asn = unpack('!H',self.community[2:4])[0]
				ip = unpack('!L',self.community[4:])[0]
				return "origin:%d:%s" % (asn,ip)
			if community_type == 0x01:
				ip = '%s.%s.%s.%s' % unpack('!BBBB',self.community[2:6])
				asn = unpack('!H',self.community[6:])[0]
				return "origin:%s:%d" % (ip,asn)
			
		# Encapsulation 
		if community_stype == 0x0c:
			return repr( Encapsulation.unpackFrom(self.community))
				
		h = 0x00
		for byte in self.community:
			h <<= 8
			h += ord(byte)
		return "0x%016X" % h

	def __repr__ (self):
		return str(self)

	def __len__ (self):
		return 8

	def __cmp__ (self,other):
		return cmp(self.community,other.community)

	@staticmethod
	def unpackFrom(data):
		community_stype = ord(data[1])
		if community_stype == 0x02:
			return RouteTarget.unpackFrom( data )
		elif community_stype == 0x0c:
			return Encapsulation.unpackFrom( data )
		else:
			return ECommunity(data)
		

class RouteTarget(ECommunity):

	def __init__(self,asn,ip,number):
		assert (asn is None or ip is None)
		assert (asn is not None or ip is not None)
		
		if not asn is None:
			self.asn = asn
			self.number = number
			self.ip = ""
		else:
			self.ip = ip
			self.number = number
			self.asn = 0
			
		self.community = self.pack()
	
	def pack(self):
		if self.asn is not None:
			# type could also be 0x02 -> FIXME check RFC
			#return pack( 'BB!H!L', 0x00,0x02, self.asn, self.number)
			return pack( '!BBHL', 0x00,0x02, self.asn, self.number)
		else:
			encoded_ip = socket.inet_pton( socket.AF_INET, self.ip )            
			return pack( '!BB4sH', 0x01,0x02, encoded_ip, self.number)

	def __str__(self):
		if self.asn is not None:
			return "target:%s:%d" % ( str(self.asn), self.number  )
		else:
			return "target:%s:%d" % ( self.ip, self.number )

	def __cmp__(self,other):
		if ( isinstance(other,RouteTarget) and
			self.community == other.community ):
			return 0
		else:
			return -1
		
	def __hash__(self):
		return hash(self.community)

	@staticmethod
	def unpackFrom(data):
		type_  = ord(data[0]) & 0x0F
		stype = ord(data[1])
		data = data[2:]
	
		if stype == 0x02:  #FIXME, unclean
			if type_ in (0x00,0x02):
				asn,number    = unpack('!HL', data[:6] )
				return RouteTarget( ASN(asn) ,None,number)
			if type_ == 0x01:
				ip = socket.inet_ntop( data[0:4] )
				number = unpack('!H',data[4:6])[0]
				return RouteTarget(None,ip,number)


		



# RFC 5512, section 4.5

class Encapsulation(ECommunity): 

	ECommunity_TYPE = 0x03
	ECommunity_SUBTYPE = 0x0c

	DEFAULT=0
	# https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#tunnel-types
	L2TPv3=1
	GRE=2
	IPIP=7
	VXLAN=8
	NVGRE=9
	MPLS=10
	VXLAN_GPE=12
	MPLS_UDP=13
	
	encapType2String={
					L2TPv3: "L2TPv3",
					GRE:    "GRE",
					VXLAN:  "VXLAN",
					NVGRE:  "NVGRE",
					IPIP:   "IP-in-IP",
					MPLS:	"MPLS",
					MPLS_UDP: "MPLS-in-UDP",
					VXLAN_GPE: "VXLAN-GPE",
					DEFAULT:"Default"
				}

	def __init__(self,tunnel_type):
		assert(isinstance(tunnel_type,int))
		self.tunnel_type = tunnel_type
		self.community = self.pack()

	def __str__(self):
		if self.tunnel_type in Encapsulation.encapType2String:
			return "Encap:" + Encapsulation.encapType2String[self.tunnel_type]
		else:
			return "Encap:(unknown:%d)" % self.tunnel_type
	
	def __hash__(self):
		return hash(self.community)

	def __cmp__(self,other):
		if isinstance(other,Encapsulation):
			return cmp(self.tunnel_type,other.tunnel_type)
		
	def pack(self):
		return pack("!BBHHH",
				Encapsulation.ECommunity_TYPE,
				Encapsulation.ECommunity_SUBTYPE,
				0,
				0,
				self.tunnel_type)
	
	@staticmethod
	def unpackFrom(data):
		type_  = ord(data[0]) & 0x0F
		stype = ord(data[1])
		data = data[2:]
	
		assert(type_==Encapsulation.ECommunity_TYPE)
		assert(stype==Encapsulation.ECommunity_SUBTYPE)
		assert(len(data)==6)
	
		tunnel_type=unpack('!H',data[4:6])[0]
		
		return Encapsulation(tunnel_type)


# =================================================================== ECommunities (16)

#def new_ECommunities (data):
#	communities = ECommunities()
#	while data:
#		ECommunity = unpack(data[:8])
#		data = data[8:]
#		communities.add(ECommunity(ECommunity))
#	return communities

class ECommunities (Communities):
	ID = AttributeID.EXTENDED_COMMUNITY

# =================================================================== FlowSpec Defined Extended Communities

def _to_FlowCommunity (action,data):
	return ECommunity(pack('!H',action) + data[:6])

# rate is bytes/seconds
def to_FlowTrafficRate (asn,rate):
	return _to_FlowCommunity (0x8006,pack('!H',asn)[:2]+pack('!f',rate))

def to_RouteOriginCommunity (asn,number,hightype=0x01):
	return ECommunity(chr(hightype) + chr(0x03) + pack('!H',asn) + pack('!L',number))

# VRF is ASN:Long
def to_RouteTargetCommunity_00 (asn,number):
	return ECommunity(chr(0x00) + chr(0x02) + pack('!H',asn) + pack('!L',number))

# VRF is A.B.C.D:Short
def to_RouteTargetCommunity_01 (ipn,number):
	return ECommunity(chr(0x01) + chr(0x02) + pack('!L',ipn) + pack('!H',number))

#def to_FlowAction (sample,terminal):
#	bitmask = chr(0)
#	if terminal: bitmask += 0x01
#	if sample: bitmask += 0x02
#	return _to_FlowCommunity (0x8007,chr(0)*5+bitmask)
#
## take a string representing a 6 bytes long hexacedimal number like "0x123456789ABC"
#def to_FlowRedirect (bitmask):
#	route_target = ''
#	for p in range(2,14,2): # 2,4,6,8,10,12
#		route_target += chr(int(bitmask[p:p+2],16))
#	return _to_FlowCommunity (0x8008,route_target)
#
#def to_FlowMark (dscp):
#	return _to_FlowCommunity (0x8009,chr(0)*5 + chr(dscp))
#
#def to_ASCommunity (subtype,asn,data,transitive):
#	r = chr(0x00)
#	if transitive: r += chr(0x40)
#	return ECommunity(r + chr(subtype) + pack('!H',asn) + ''.join([chr(c) for c in data[:4]]))
#
#import socket
#def to_IPv4Community (subtype,data,transitive):
#	r = chr(0x01)
#	if transitive: r += chr(0x40)
#	return ECommunity(r + chr(subtype) + socket.inet_pton(socket.AF_INET,ipv4) + ''.join([chr(c) for c in data[:2]]))
#
#def to_OpaqueCommunity (subtype,data,transitive):
#	r = chr(0x03)
#	if transitive: r += chr(0x40)
#	return ECommunity(r + chr(subtype) + ''.join([chr(c) for c in data[:6]]))

# See RFC4360
# 0x00, 0x02 Number is administrated by a global authority
# Format is asn:route_target (2 bytes:4 bytes)
# 0x01, Number is administered by the ASN owner
# Format is ip:route_target  (4 bytes:2 bytes)
# 0x02 and 0x03 .. read the RFC :)

