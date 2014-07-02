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
"""

.. module:: test_tracker_worker
   :synopsis: a module that defines several test cases for the tracker_worker module.
   In particular, unit tests for TrackerWorker class.
   Setup : Run TrackerWorker instance.
   TearDown : Stop TrackerWorker instance.
   TrackerWorker is in charge to ....
   
"""
import mock
import time

from testtools import TestCase
from threading import Thread

from bagpipe.bgp.tests import BaseTestBagPipeBGP, RT1, RT2, NLRI1, NH1

from bagpipe.bgp.engine import RouteEvent
from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine.tracker_worker import TrackerWorker

class TrackerWorkerThread(TrackerWorker, Thread):
    
    def __init__(self):
        Thread.__init__(self, name="TrackerWorkerThread")
        self.setDaemon(True)
        TrackerWorker.__init__(self, "BGPManager", "TrackerWorker")
        
    def stop(self):
        self._pleaseStop.set()
        self._queue.put(self.stopEvent)
        self._stopped()

class TestTrackerWorker(TestCase, BaseTestBagPipeBGP):
    
    def setUp(self):
        super(TestTrackerWorker, self).setUp()
        #logging.config.fileConfig('/etc/bagpipe-bgp/log.conf')
        self.trackerWorkerThread = TrackerWorkerThread()
        self.trackerWorkerThread.start()
        self.trackerWorkerThread._newBestRoute = mock.Mock()
        self.trackerWorkerThread._bestRouteRemoved = mock.Mock()
       
    def tearDown(self):
        super(TestTrackerWorker, self).tearDown()
        self.trackerWorkerThread.stop()  
        self.trackerWorkerThread.join()
        
    def test1(self):   
        self.trackerWorkerThread._route2trackedEntry = mock.Mock(return_value="1.1.1.10/32")
        # Worker1 advertises a route for RT1 and RT2
        worker1 = Worker("BGPManager", "Worker-1")
        routeEvent = self._newRouteEvent(self.trackerWorkerThread, RouteEvent.ADVERTISE, NLRI1, [ RT1, RT2 ], 
                                         worker1, NH1)
        
        # Waiting for trackerWorkerThread finishes to process the subscriptions        
        time.sleep(1)    
        self.assertEqual(self.trackerWorkerThread._newBestRoute.call_count, 1, "First route for this nlri")
        self.assertEqual(self.trackerWorkerThread._bestRouteRemoved.call_count, 0, "No route to delete")
               
 
