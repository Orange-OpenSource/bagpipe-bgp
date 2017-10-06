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

import Queue
import threading
import traceback

from oslo_log import log as logging

from bagpipe.bgp import engine
from bagpipe.bgp.common import looking_glass as lg


LOG = logging.getLogger(__name__)

STOP_EVENT = "STOP_EVENT"


class Worker(engine.EventSource, lg.LookingGlassMixin):

    """This is the base class for objects that interact with the route table
    manager to produce and consume events related to BGP routes.

    These objects will:
    * use _subscribe(...) and _unsubscribe(...) to subscribe to routing events
    * will specialize _on_event(event) to react to received events

    They also inherit from EventSource to publish events
    """

    def __init__(self, bgp_manager, worker_name):
        self.bgp_manager = bgp_manager
        self.rtm = bgp_manager.rtm
        self._queue = Queue.Queue()
        self._please_stop = threading.Event()

        self.name = worker_name
        assert self.name is not None

        engine.EventSource.__init__(self, self.rtm)

        # private data for RouteTableManager
        self._rtm_matches = set()

        LOG.debug("Instantiated %s worker", self.name)

    def stop(self):
        """
        Stop this worker.

        Set the _please_stop internal event to stop the event processor loop
        and indicate to the route table manager that this worker is stopped.
        Then call _stopped() to let a subclass implement any further work.
        """
        LOG.info("Stop worker %s", self)
        self._please_stop.set()
        self.enqueue(STOP_EVENT)
        self._cleanup()
        self._stopped()

    def _cleanup(self):
        self.rtm.enqueue(engine.WorkerCleanupEvent(self))

    def _stopped(self):
        """
        Hook for subclasses to react when Worker is stopped (NoOp in base
        Worker class)
        """

    def _event_queue_processor_loop(self):
        """
        Main loop where the worker consumes events.
        """
        while not self._please_stop.isSet():
            # LOG.debug("%s worker waiting on queue",self.name )
            event = self._dequeue()

            if event == STOP_EVENT:
                LOG.debug("Stop event, breaking queue processor loop")
                self._please_stop.set()
                break

            # LOG.debug("%s worker calling _on_event for %s", self.name, event)
            try:
                self._on_event(event)
            except Exception as e:
                LOG.error("Exception raised on subclass._on_event: %s", e)
                LOG.error("%s", traceback.format_exc())

    def run(self):
        self._event_queue_processor_loop()

    def _on_event(self, event):
        """
        This method is implemented by subclasses to react to routing events.
        """
        LOG.debug("Worker %s _on_event: %s", self.name, event)
        raise NotImplementedError

    def _dequeue(self):
        return self._queue.get()

    def enqueue(self, event):
        # TODO(tmmorin): replace Queue by a PriorityQueue and use a higher
        # priority for ReInit event
        self._queue.put(event)

    def _subscribe(self, afi, safi, rt=None):
        subobj = engine.Subscription(afi, safi, rt, self)
        LOG.info("Subscribe: %s ", subobj)
        self.rtm.enqueue(subobj)

    def _unsubscribe(self, afi, safi, rt=None):
        subobj = engine.Unsubscription(afi, safi, rt, self)
        LOG.info("Unsubscribe: %s ", subobj)
        self.rtm.enqueue(subobj)

    def get_subscriptions(self):
        return sorted(self._rtm_matches)

    def __repr__(self):
        return "%s" % (self.name)

    # Looking glass ###

    def get_lg_local_info(self, path_prefix):
        return {
            "name": self.name,
            "internals": {
                "event queue length": self._queue.qsize(),
                "subscriptions":
                    [repr(sub) for sub in self.get_subscriptions()],
            }
        }
