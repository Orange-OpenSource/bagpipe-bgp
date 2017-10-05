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

import abc
import random
import time
import threading
import traceback

from oslo_log import log as logging

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp import engine
from bagpipe.bgp.engine import worker


INIT = "Init-Event"
CONNECT_NOW = "Connect-Now"
SEND_KEEP_ALIVE = "Send-KeepAlive"
KEEP_ALIVE_RECEIVED = "KeepAlive-received"

DEFAULT_HOLDTIME = 180

ERROR_RETRY_TIMER = 20
KA_EXPIRY_RETRY_TIMER = 5
CONNECT_RETRY_TIMER = 5


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
        self._prev_state = None
        self.all_states = [FSM.Idle, FSM.Connect, FSM.OpenSent,
                           FSM.OpenConfirm, FSM.Active, FSM.Established]
        self.last_transition_time = time.time()

    @property
    def state(self):
        return self._state

    @property
    def previous_state(self):
        return self._prev_state

    @state.setter
    def state(self, state):
        if state == self._state:
            return
        if state in self.all_states:
            self._prev_state = self._state
            self._state = state
            self.last_transition_time = time.time()
            self.worker.log.info(
                "%s BGP FSM transitioned from '%s' to '%s' state" %
                (self.worker, self._prev_state, self._state))
        else:
            raise Exception("no such state (%s)" % repr(state))

    def __repr__(self):
        return self._state


class StoppedException(Exception):
    pass


class InitiateConnectionException(Exception):
    pass


class OpenWaitTimeout(Exception):
    pass


class ToIdle(object):

    def __init__(self, delay):
        # add 50% random delay to avoid reconnect bursts
        self.delay = delay*random.uniform(1, 1.5)

    def __repr__(self):
        return "ToIdle(%s)" % self.delay


class BGPPeerWorker(worker.Worker,
                    threading.Thread,
                    lg.LookingGlassLocalLogger):
    __metaclass__ = abc.ABCMeta

    '''
    Partially abstract class for a Worker implementing the BGP protocol.
    '''

    def __init__(self, bgp_manager, peer_address):
        # call super
        threading.Thread.__init__(self)
        self.setDaemon(True)
        worker.Worker.__init__(self, bgp_manager, "BGP-%s" % peer_address)

        self.peer_address = peer_address

        # its up to subclasses to call _set_hold_time again to set holdtime
        # based on value advertized by peer
        self._set_hold_time(DEFAULT_HOLDTIME)

        # used to stop receive_thread
        self._stop_loops = threading.Event()
        # used to track that we've been told to stop:
        self.should_stop = False

        self.send_ka_timer = None
        self.ka_reception_timer = None

        lg.LookingGlassLocalLogger.__init__(self,
                                            self.peer_address.replace(".",
                                                                      "-"))

        self.fsm = FSM(self)

        self.log.debug("INIT %s", self.name)
        self.enqueue(CONNECT_NOW)

    def stop(self):
        super(BGPPeerWorker, self).stop()
        self.should_stop = True
        self._stop_and_clean()

    def _set_hold_time(self, holdtime):
        '''
        holdtime in seconds
        keepalive expected, or sent, every holdtime/3 second
        '''
        assert holdtime > 30
        self.kat_period = int(holdtime / 3.0)
        self.kat_expiry_time = self.kat_period * 3

    # called by _event_queue_processor_loop
    def _on_event(self, event):

        self.log.debug("event: %s", event)

        if event == CONNECT_NOW:
            self._connect()

        elif isinstance(event, ToIdle):
            self._to_idle(event.delay)

        elif isinstance(event, engine.RouteEvent):
            if self.fsm.state == FSM.Established:
                self._send(self._update_for_route_event(event))
            else:
                raise Exception("cannot process event in '%s' state"
                                % self.fsm.state)

        elif event == SEND_KEEP_ALIVE:
            self._send(self._keep_alive_message_data())

        elif event == KEEP_ALIVE_RECEIVED:
            self.on_keep_alive_received()

        else:
            self.log.warning("event not processed: %s", event)

    def _stopped(self):
        self.fsm.state = FSM.Idle

    def _connect(self):
        self._reset_local_lg_logs()

        # initiate connection
        self.log.debug("connecting now")

        self.fsm.state = FSM.Connect

        try:
            self._initiate_connection()
        except (InitiateConnectionException, OpenWaitTimeout) as e:
            self.log.warning("%s while initiating connection: %s",
                             e.__class__.__name__, e)
            self._to_active()
            return
        except StoppedException:
            self.log.info("Thread stopped during connection init")
            return
        except Exception as e:
            self.log.warning("Exception while initiating connection: %s", e)
            if self.log.isEnabledFor(logging.DEBUG):
                self.log.debug("%s", traceback.format_exc())
            self._to_active()
            return

        self._stop_loops.clear()

        self.init_send_keep_alive_timer()
        self.init_keep_alive_reception_timer()

        # spawns a receive thread
        self.receive_thread = threading.Thread(target=self._receive_loop,
                                               name=("%s:receive_loop" %
                                                     self.name))
        self.receive_thread.start()

        self._to_established()

    def _to_active(self):
        self.fsm.state = FSM.Active
        self._stop_and_clean()
        self.init_connect_timer(CONNECT_RETRY_TIMER)

    def _to_established(self):
        self.fsm.state = FSM.Established

    def _to_idle(self, delay_before_connect=0):
        self.fsm.state = FSM.Idle
        self._stop_and_clean()

        if delay_before_connect:
            self.init_connect_timer(delay_before_connect)
        else:
            self.enqueue(CONNECT_NOW)

    def _stop_and_clean(self):
        self._stop_loops.set()

        if self.send_ka_timer:
            self.send_ka_timer.cancel()
        if self.ka_reception_timer:
            self.ka_reception_timer.cancel()

        self._cleanup()

    def is_established(self):
        return self.fsm.state == FSM.Established

    def _receive_loop(self):
        self.log.info("Start receive loop")
        self._stop_loops.clear()
        while not self._stop_loops.isSet():
            try:
                loop_result = self._receive_loop_fun()
                if loop_result == 0:
                    self.log.info("receive_loop_fun returned 0, aborting")
                    break
                elif loop_result == 2:
                    self.log.warning("receive_loop_fun returned 2 (error), "
                                     "aborting receive_loop and reinit'ing")
                    # FIXME: use (Worker.)enqueue_high_priority so that
                    # ToIdle is treated before other events
                    self.enqueue(ToIdle(ERROR_RETRY_TIMER))
                    break
                else:
                    # everything went fine
                    pass
            except Exception as e:
                self.log.error("Error: %s (=> aborting receive_loop and "
                               "reinitializing)", e)
                if self.log.isEnabledFor(logging.WARNING):
                    self.log.warning("%s", traceback.format_exc())
                # FIXME: use (Worker.)enqueue_high_priority so that
                # ToIdle is treated before other events
                self.enqueue(ToIdle(ERROR_RETRY_TIMER))
                break

        self.log.info("End receive loop")

    # Connect retry timer #####
    def init_connect_timer(self, delay):
        self.log.debug("INIT connect timer (%ds)", delay)
        self.connect_timer = threading.Timer(delay, self.enqueue,
                                             [CONNECT_NOW])
        self.connect_timer.name = "%s:connect_timer" % self.name
        self.connect_timer.start()

    # Sending keep-alive's #####

    def init_send_keep_alive_timer(self):
        self.log.debug("INIT Send Keepalive timer (%ds)", self.kat_period)
        self.send_ka_timer = threading.Timer(self.kat_period,
                                             self.send_keep_alive_trigger)
        self.send_ka_timer.name = "%s:send_ka_timer" % self.name
        self.send_ka_timer.start()

    def send_keep_alive_trigger(self):
        self.log.debug("Trigger to send Keepalive")
        self.enqueue(SEND_KEEP_ALIVE)
        self.init_send_keep_alive_timer()

    # Receiving keep-alive's #####

    def init_keep_alive_reception_timer(self):
        self.log.debug(
            "INIT Keepalive reception timer (%ds)", self.kat_expiry_time)
        self.ka_reception_timer = threading.Timer(
            self.kat_expiry_time,
            self.enqueue,
            [ToIdle(KA_EXPIRY_RETRY_TIMER)])
        self.ka_reception_timer.start()

    def on_keep_alive_received(self):
        self.log.debug("Keepalive received")
        self.ka_reception_timer.cancel()
        self.init_keep_alive_reception_timer()

    # Abstract methods

    @abc.abstractmethod
    def _initiate_connection(self):
        '''
        Abstract method.
        The implementation will initiated the connection to the BGP peer, do
        the initial BGP handshake (send Open, receive Open, send first
        KeepAlive, receive first KeepAlive) and track the intermediate
        FSM states (OpenSent, OpenConfirm).
        '''
        pass

    @abc.abstractmethod
    def _receive_loop_fun(self):
        '''
        Return codes:
        - 0: we decided to stop based on stop_loops being set
        - 1: everything went fine, pursue
        - 2: there was an error
        '''
        pass

    @abc.abstractmethod
    def _keep_alive_message_data(self):
        pass

    @abc.abstractmethod
    def _send(self, data):
        pass

    @abc.abstractmethod
    def _update_for_route_event(self, event):
        pass

    # Looking glass hooks ###

    def get_lg_local_info(self, path_prefix):
        return {
            "protocol": {
                "state": self.fsm.state,
                "previous_state": "(%s)" % self.fsm.previous_state,
                "hold_time": self.kat_expiry_time,
                "last_transition_time": time.strftime(
                    '%Y-%m-%d %H:%M:%S',
                    time.localtime(self.fsm.last_transition_time))
            }
        }
