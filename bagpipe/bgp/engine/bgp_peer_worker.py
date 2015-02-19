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

from abc import ABCMeta, abstractmethod

from threading import Thread, Event, Timer

import time
from time import sleep

import logging
import traceback

from bagpipe.bgp.engine.worker import Worker
from bagpipe.bgp.engine import RouteEvent

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger

Init = "InitEvent"
ReInit = "ReInit"
SendKeepAlive = "Send KeepAlive"
KeepAliveReceived = "KeepAlive-received"

DEFAULT_HOLDTIME = 180


class FSM(object):

    '''
    Represents the state of the BGP Finite State Machine
    '''

    Idle = "Idle"
    Connect = 'Connect'
    OpenSent = 'OpenSent'
    OpenConfirm = 'OpenConfirm'
    Active = 'Active'
    Established = 'Established'

    def __init__(self, worker):
        self.worker = worker
        self._state = FSM.Idle
        self._prevState = None
        self.allStates = [FSM.Idle, FSM.Connect, FSM.OpenSent,
                          FSM.OpenConfirm, FSM.Active, FSM.Established]
        self.lastTransitionTime = time.time()

    @property
    def state(self):
        return self._state

    @property
    def previousState(self):
        return self._prevState

    @state.setter
    def state(self, state):
        if state in self.allStates:
            self._prevState = self._state
            self._state = state
            self.lastTransitionTime = time.time()
            self.worker.log.info(
                "%s BGP FSM transitioned from '%s' to '%s' state" %
                (self.worker, self._prevState, self._state))
        else:
            raise Exception("no such state (%s)" % repr(state))

    def __repr__(self):
        return self._state


class InitiateConnectionException(Exception):
    pass


class OpenWaitTimeout(Exception):
    pass


class BGPPeerWorker(Worker, Thread, LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    '''
    Partially abstract class for a Worker implementing the BGP protocol.
    '''

    def __init__(self, bgpManager, name, peerAddress):
        # call super
        Thread.__init__(self)
        self.setDaemon(True)
        self.name = "BGP-%s" % peerAddress
        Worker.__init__(self, bgpManager, self.name)

        self.bgpManager = bgpManager
        self.peerAddress = peerAddress

        # its up to subclasses to call setHoldTime again to set holdtime based
        # on value advertized by peer
        self._setHoldTime(DEFAULT_HOLDTIME)

        # used to stop receiveThread
        self._stopLoops = Event()
        # used to track that we've been told to stop:
        self.shouldStop = False

        self.sendKATimer = None
        self.KAReceptionTimer = None

        LookingGlassLocalLogger.__init__(
            self, self.peerAddress.replace(".", "-"))

        self.fsm = FSM(self)

        self.log.debug("Init %s", self.name)
        self.enqueue(Init)

    def stop(self):
        Worker.stop(self)
        self._stopLoops.set()
        self.shouldStop = True

    def _setHoldTime(self, holdtime):
        '''
        holdtime in seconds
        keepAlive expected, or sent, every holdtime/3 second
        '''
        assert(holdtime > 30)
        self.katPeriod = int(holdtime / 3.0)
        self.katExpiryTime = self.katPeriod * 3

    # called by _eventQueueProcessorLoop
    def _onEvent(self, event):

        if event == Init:
            self._initiate()

        elif event == ReInit:
            self._reinitiate()

        elif isinstance(event, RouteEvent):
            if (self.fsm.state == FSM.Established):
                self._send(self._updateForRouteEvent(event))
            else:
                # FIXME: this is possibly not correct yet: why did we received
                # this event  ? what do we do with it ?
                raise Exception(
                    "cannot process routeEvent in '%s' state" % self.fsm.state)

        elif event == SendKeepAlive:
            self._send(self._keepAliveMessageData())

        elif event == KeepAliveReceived:
            self.onKeepAliveReceived()

        else:
            self.log.warning("event not processed: %s", event)

    def _stopped(self):
        self.fsm.state = FSM.Idle

    def _initiate(self):
        self.log.info("Initiating")
        self._initiateConnectionAndThreads()

    def _initiateConnectionAndThreads(self):
        # initiate connection

        self.fsm.state = FSM.Connect

        try:
            self._initiateConnection()
        except (InitiateConnectionException, OpenWaitTimeout) as e:
            self.log.warning(
                "%s while initiating connection: %s", e.__class__.__name__, e)
            self.enqueue(ReInit)
            return
            # FIXME: we should transition to Active or Idle state depending how
            # many times we already tried
        except Exception as e:
            self.log.warning("Exception while initiating connection: %s", e)
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug("%s", traceback.format_exc())
            self.enqueue(ReInit)
            # FIXME: we should transition to Active or Idle state depending how
            # many times we already tried
            return

        self._stopLoops.clear()

        self.initSendKeepAliveTimer()
        self.initKeepAliveReceptionTimer()

        # spawns a receive thread
        self.receiveThread = Thread(target=self._receiveLoop,
                                    name="%s:receiveLoop" % self.name)
        self.receiveThread.start()

    def _toEstablished(self):
        self.fsm.state = FSM.Established

    def _toIdle(self):
        pass

    def _reinitiate(self):
        self.log.info("Re-initiating")

        self.fsm.state = FSM.Idle

        self._stopLoops.set()

        if self.sendKATimer:
            self.sendKATimer.cancel()
        if self.KAReceptionTimer:
            self.KAReceptionTimer.cancel()

        self.bgpManager.cleanup(self)

        self._toIdle()

        # TODO(tmmorin): read BGP specs to get the retries timers right
        # TODO(tmmorin): replace with a timer that injects an event, so that we
        # avoid sleeping which make us miss any stop event
        sleep(10)

        self._initiateConnectionAndThreads()

    def isEstablished(self):
        return (self.fsm.state == FSM.Established)

    def _receiveLoop(self):
        self.log.info("Start receive loop")
        while not self._stopLoops.isSet():
            try:
                loopResult = self._receiveLoopFun()
                if loopResult == 0:
                    self.log.info(
                        "receiveLoopFun returned 0, aborting receiveLoop")
                    break
                elif loopResult == 2:
                    self.log.warning("receiveLoopFun returned 2 (error), "
                                     "aborting receiveLoop and reinitializing")
                    # FIXME: use (Worker.)enqueueHighPriority so that
                    # ReInit is treated before other events
                    self.enqueue(ReInit)
                    break
                else:
                    # everything went fine
                    pass
            except Exception as e:
                self.log.error("Error: %s (=> aborting receiveLoop and "
                               "reinitializing)", e)
                if self.log.isEnabledFor(logging.WARNING):
                    self.log.warning("%s", traceback.format_exc())
                # FIXME: use (Worker.)enqueueHighPriority so that
                # ReInit is treated before other events
                self.enqueue(ReInit)
                break

        self.log.info("End receive loop")

    # Sending keep-alive's #####

    def initSendKeepAliveTimer(self):
        self.log.debug("Init sendKA timer (%ds)", self.katPeriod)
        self.sendKATimer = Timer(
            self.katPeriod, BGPPeerWorker.sendKeepAliveTrigger, [self])
        self.sendKATimer.name = "%s:sendKATimer" % self.name
        self.sendKATimer.start()

    def sendKeepAliveTrigger(self):
        self.log.debug("Trigger send KeepAlive")
        self.enqueue(SendKeepAlive)
        self.initSendKeepAliveTimer()

    # Receiving keep-alive's #####

    def initKeepAliveReceptionTimer(self):
        self.log.debug(
            "Init Keepalive reception timer (%ds)", self.katExpiryTime)
        self.KAReceptionTimer = Timer(
            self.katExpiryTime, BGPPeerWorker.onKeepAliveExpired, [self])
        self.KAReceptionTimer.start()

    def onKeepAliveReceived(self):
        self.log.debug("Keepalive received")
        self.KAReceptionTimer.cancel()
        self.initKeepAliveReceptionTimer()

    def onKeepAliveExpired(self):
        self.log.error("KeepAlive expired, re-init")
        self.fsm.state = FSM.Idle
        self.enqueue(ReInit)

    # Abstract methods

    @abstractmethod
    def _initiateConnection(self):
        '''
        Abstract method.
        The implementation will initiated the connection to the BGP peer, do
        the initial BGP handshake (send Open, receive Open, send first
        KeepAlive, receive first KeepAlive) and track the intermediate
        FSM states (OpenSent, OpenConfirm).
        '''
        pass

    @abstractmethod
    def _receiveLoopFun(self):
        '''
        Return codes:
        - 0: we decided to stop based on stopLoop being set
        - 1: everything went fine, pursue
        - 2: there was an error
        '''
        pass

    @abstractmethod
    def _keepAliveMessageData(self):
        pass

    @abstractmethod
    def _send(self, data):
        pass

    @abstractmethod
    def _updateForRouteEvent(self, event):
        pass

    # Looking glass hooks ###

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
            "protocol": {
                "state": self.fsm.state,
                "previous_state": "(%s)" % self.fsm.previousState,
                "hold_time": self.katExpiryTime,
                "last_transition_time": time.strftime(
                    '%Y-%m-%d %H:%M:%S',
                    time.localtime(self.fsm.lastTransitionTime))
            }
        }
