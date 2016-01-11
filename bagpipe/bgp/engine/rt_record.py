from exabgp.bgp.message.update.attribute.community.extended import ExtendedCommunity
from exabgp.bgp.message.update.attribute.community.extended import rt

import logging
log = logging.getLogger(__name__)

# draft-fm-bess-service-chaining


class RTRecord(rt.RouteTarget):
    COMMUNITY_SUBTYPE = 0x13

    @classmethod
    def from_rt(cls, rt):
        packed = rt.pack()
        return cls.unpack(packed[0] + chr(cls.COMMUNITY_SUBTYPE) + packed[2:])


@ExtendedCommunity.register
class RTRecordASN2Number(RTRecord, rt.RouteTargetASN2Number):

    def __repr__(self):
        return "rtrecord:%d:%d" % (self.asn, self.number)


@ExtendedCommunity.register
class RTRecordIPNumber(RTRecord, rt.RouteTargetIPNumber):

    def __repr__(self):
        return "rtrecord:%d:%d" % (self.ip, self.number)


@ExtendedCommunity.register
class RTRecordASN4Number(RTRecord, rt.RouteTargetASN4Number):

    def __repr__(self):
        return "rtrecord:%dL:%d" % (self.asn, self.number)

