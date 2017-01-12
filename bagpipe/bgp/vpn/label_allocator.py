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

LOG = logging.getLogger(__name__)

MAX_LABEL = 2**20-1


class LabelAllocator(lg.LookingGlassMixin):
    # Warning: does not reuse labels, will break if more than 2**20-16 labels
    # are requested along the life-cycle
    # FIXME: add code so that all the labels that were cleaned'up will *not*
    # be reused in a short time

    def __init__(self):
        # (Labels below 16 are reserved)
        self.current_label = random.randint(100, 200)
        # using a random start value will illustrate during demos and tests
        # that the label for a VRF does not
        # need be the same on all compute nodes
        self.labels = dict()

        self.lock = Lock()

    @utils.synchronized
    def get_new_label(self, description):

        if self.current_label == MAX_LABEL+1:
            # Looking forward to the day will hit this one:
            LOG.error("All the 2^20 possible labels have been used at least "
                      "once, and this piece of code doesn't know how to reuse "
                      "them")
            raise Exception("Out of labels")

        label = self.current_label
        self.current_label += 1
        self.labels[label] = description

        LOG.debug("Allocated label %d for '%s'", label, description)
        return label

    @utils.synchronized
    def release(self, label):
        if label in self.labels:
            LOG.debug("released label %d ('%s')", label, self.labels[label])
            del self.labels[label]
        else:
            LOG.warn("asked to release a non registered label: %d", label)

    def get_log_local_info(self, prefix):
        return self.labels
