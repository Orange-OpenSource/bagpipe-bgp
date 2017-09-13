# encoding: utf-8
"""
attributes.py

Created by Thomas Mangin on 2009-11-05.
Copyright (c) 2009-2012 Exa Networks. All rights reserved.
Modified by Orange - 2014
"""

from struct import pack

from bagpipe.exabgp.message.update.attribute import AttributeID,Flag,Attribute

# =================================================================== MED (4)

class MED (Attribute):
	ID = AttributeID.MED
	FLAG = Flag.OPTIONAL
	MULTIPLE = False

	def __init__ (self,med):
		self.med = med

	def pack (self):
		return self._attribute(pack('!L',self.med))

	def __len__ (self):
		return 4

	def __str__ (self):
		return str(self.med)

	def __repr__ (self):
		return str(self)

	def __cmp__(self,other):
		if ( not isinstance(other,MED)
			or (self.med != other.med)
			):
			return -1
		else:
			return 0