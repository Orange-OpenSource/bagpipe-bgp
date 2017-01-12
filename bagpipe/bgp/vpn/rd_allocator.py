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


from oslo_log import log as logging

import random

from threading import Lock

from bagpipe.bgp.common import utils
from bagpipe.bgp.common import looking_glass as lg

from exabgp.bgp.message.update.nlri.qualifier.rd import RouteDistinguisher

LOG = logging.getLogger(__name__)

MAX_RD_LOCAL_ID = 2**16-1


class RDAllocator(lg.LookingGlassMixin):

    def __init__(self, prefix):
        self.prefix = prefix
        self.current_id = random.randint(100, 200)
        self.rds = dict()

        self.lock = Lock()

    @utils.synchronized
    def get_new_rd(self, description):

        if self.current_id == MAX_RD_LOCAL_ID+1:
            LOG.error("All the %d possible local ids have been used at least "
                      "once, and this piece of code doesn't know how to reuse "
                      "them", MAX_RD_LOCAL_ID)
            raise Exception("Out of local ids")

        rd = RouteDistinguisher.fromElements(self.prefix, self.current_id)
        self.current_id += 1
        self.rds[rd] = description

        LOG.debug("Allocated route distinguisher %s for '%s'", rd, description)
        return rd

    @utils.synchronized
    def release(self, rd):
        if rd in self.rds:
            LOG.debug("Released route distinguisher %s ('%s')",
                      rd, self.rds[rd])
            del self.rds[rd]
        else:
            LOG.warn("Asked to release a non registered route distinguisher: "
                     "%s", rd)

    def get_log_local_info(self, prefix):
        return self.rds
