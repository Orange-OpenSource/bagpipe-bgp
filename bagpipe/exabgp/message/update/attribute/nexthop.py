# encoding: utf-8
"""
attributes.py

Created by Thomas Mangin on 2009-11-05.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
Modified by Orange - 2014
"""

from bagpipe.exabgp.message.update.attribute import AttributeID,Flag,Attribute

# =================================================================== NextHop (3)

class NextHop (Attribute):
	ID = AttributeID.NEXT_HOP
	FLAG = Flag.TRANSITIVE
	MULTIPLE = False

	# Take an IP as value
	def __init__ (self,next_hop):
		self.next_hop = next_hop

	def pack (self):
		return self._attribute(self.next_hop.pack())

	def __len__ (self):
		return len(self.next_hop.pack())

	def __str__ (self):
		return str(self.next_hop)

	def __repr__ (self):
		return str(self)

	def __cmp__(self,other):
		if ( not isinstance(other,NextHop) or
			 (self.next_hop.pack() != other.next_hop.pack()) 
			):
			return -1
		else:
			return 0