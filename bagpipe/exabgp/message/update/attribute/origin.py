# encoding: utf-8
"""
attributes.py

Created by Thomas Mangin on 2009-11-05.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
Modified by Orange - 2014
"""

from bagpipe.exabgp.message.update.attribute import AttributeID,Flag,Attribute

# =================================================================== Origin (1)

class Origin (Attribute):
	ID = AttributeID.ORIGIN
	FLAG = Flag.TRANSITIVE
	MULTIPLE = False

	IGP        = 0x00
	EGP        = 0x01
	INCOMPLETE = 0x02

	def __init__ (self,origin):
		self.origin = origin

	def pack (self):
		return self._attribute(chr(self.origin))

	def __len__ (self):
		return len(self.pack())

	def __str__ (self):
		if self.origin == 0x00: return 'IGP'
		if self.origin == 0x01: return 'EGP'
		if self.origin == 0x02: return 'INCOMPLETE'
		return 'INVALID'

	def __repr__ (self):
		return str(self)
	
	def __cmp__(self,other):
		if ( not isinstance(other,Origin) 
			  or (self.origin != other.origin)
		    ):
			return -1
		else:
			return 0
