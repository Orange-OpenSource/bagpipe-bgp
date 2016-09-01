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

import random

from threading import Lock

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import looking_glass as lg

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher

log = logging.getLogger(__name__)


class RDAllocator(lg.LookingGlassMixin):

    def __init__(self, prefix):
        self.prefix = prefix
        self.currentSuffix = random.randint(100, 200)
        self.rds = dict()

        self.lock = Lock()

    @utils.synchronized
    def getNewRD(self, description):

        if (self.currentSuffix == 2 ** 20):
            # Looking forward to the day will hit this one:
            log.error("All the 2^20 possible suffixes have been used at least "
                      "once, and this piece of code doesn't know how to reuse "
                      "them")
            raise Exception("Out of suffixes")

        rd = RouteDistinguisher.fromElements(self.prefix, self.currentSuffix)
        self.currentSuffix += 1
        self.rds[rd] = description

        log.debug("Allocated route distinguisher %s for '%s'", rd, description)
        return rd

    @utils.synchronized
    def release(self, rd):
        if rd in self.rds:
            log.debug("Released route distinguisher %s ('%s')", rd, self.rds[rd])
            del self.rds[rd]
        else:
            log.warn("Asked to release a non registered route distinguisher: "
                     "%s", rd)

    def getLookingGlassLocalInfo(self, prefix):
        return self.rds
