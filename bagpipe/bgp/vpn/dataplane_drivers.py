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

import socket

from bagpipe.bgp.common import logDecorator

from bagpipe.bgp.common.looking_glass import \
    LookingGlassLocalLogger, LGMap, LookingGlassReferences

from bagpipe.bgp.common.run_command import runCommand

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation


class DataplaneDriver(LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    dataplaneInstanceClass = None
    encaps = [Encapsulation(Encapsulation.Type.DEFAULT)]
    makeB4BreakSupport = False
    ecmpSupport = False

    @logDecorator.log
    def __init__(self, config, init=True):
        '''config is a dict'''
        LookingGlassLocalLogger.__init__(self)

        assert(issubclass(self.dataplaneInstanceClass, VPNInstanceDataplane))

        self.config = config

        self.local_address = None
        try:
            self.local_address = self.config["dataplane_local_address"]
            socket.inet_pton(socket.AF_INET, self.local_address)
            self.log.info("Will use %s as local_address", self.local_address)
        except KeyError:
            self.log.info("Will use BGP address as dataplane_local_address")
            self.local_address = None
        except socket.error:
            raise Exception("malformed local_address: '%s'" %
                            self.local_address)

        # skipped if instantiated with init=False, to be used for cleanup
        if init:
            self._initReal(config)

        # Flag to trigger cleanup all dataplane states on first call to
        # vifPlugged
        self.firstInit = True

    @abstractmethod
    def resetState(self):
        pass

    @abstractmethod
    def _initReal(self, config):
        '''
        This is called after resetState (which, e.g. cleans up the stuff
        possibly left-out by a previous failed run).

        All init things that should not be cleaned up go here.
        '''
        pass

    @logDecorator.logInfo
    def initializeDataplaneInstance(self, instanceId, externalInstanceId,
                                    gatewayIP, mask, instanceLabel, **kwargs):
        '''
        returns a VPNInstanceDataplane subclass
        after calling resetState on the dataplane driver, if this is the first
        call to initializeDataplaneInstance
        '''

        if self.firstInit:
            self.log.info("First VPN instance init, resetting dataplane state")
            try:
                self.resetState()
            except Exception as e:
                self.log.error("Exception while resetting state: %s", e)
            self.firstInit = False
        else:
            self.log.debug("(not resetting dataplane state)")

        return self.dataplaneInstanceClass(self, instanceId,
                                           externalInstanceId, gatewayIP, mask,
                                           instanceLabel, **kwargs)

    def cleanup(self):
        # FIXME: to be clarified: can be removed ? should call resetState ?
        self._cleanupReal()

    def getLocalAddress(self):
        return self.local_address

    def supportedEncaps(self):
        return self.__class__.encaps

    def _runCommand(self, command, *args, **kwargs):
        return runCommand(self.log, command, *args, **kwargs)

    def getLGMap(self):
        encaps = []
        for encap in self.supportedEncaps():
            encaps.append(repr(encap))
        return {
            "name": (LGMap.VALUE, self.__class__.__name__),
            "local_address": (LGMap.VALUE, self.local_address),
            "supported_encaps": (LGMap.VALUE, encaps),
            "config": (LGMap.VALUE, self.config)
        }


class VPNInstanceDataplane(LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    @logDecorator.logInfo
    def __init__(self, dataplaneDriver, instanceId, externalInstanceId,
                 gatewayIP, mask, instanceLabel=None):
        LookingGlassLocalLogger.__init__(self, repr(instanceId))
        self.driver = dataplaneDriver
        self.config = dataplaneDriver.config
        self.instanceId = instanceId
        self.externalInstanceId = externalInstanceId
        self.gatewayIP = gatewayIP
        self.mask = mask
        self.instanceLabel = instanceLabel

    @abstractmethod
    def cleanup(self):
        pass

    @abstractmethod
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort, label):
        pass

    @abstractmethod
    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort, label,
                     lastEndpoint=True):
        pass

    @abstractmethod
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        pass

    @abstractmethod
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        pass

    def _runCommand(self, *args, **kwargs):
        return runCommand(self.log, *args, **kwargs)

    # Looking glass info ####

    def getLookingGlassLocalInfo(self, pathPrefix):
        driver = {"id": self.driver.type,
                  "href": LookingGlassReferences.getAbsolutePath(
                      "DATAPLANE_DRIVERS", pathPrefix, [self.driver.type])}
        return {
            "driver": driver,
        }


class DummyVPNInstanceDataplane(VPNInstanceDataplane):

    @logDecorator.log
    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

    @logDecorator.log
    def vifPlugged(self, macAddress, ipAddressPrefix, localPort, label):
        pass

    @logDecorator.log
    def vifUnplugged(self, macAddress, ipAddressPrefix, localPort, label,
                     lastEndpoint=True):
        pass

    @logDecorator.log
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        pass

    @logDecorator.log
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        pass

    @logDecorator.log
    def cleanup(self):
        pass


class DummyDataplaneDriver(DataplaneDriver):

    dataplaneInstanceClass = DummyVPNInstanceDataplane

    def __init__(self, *args):
        DataplaneDriver.__init__(self, *args)

    @logDecorator.logInfo
    def _initReal(self, config):
        pass

    @logDecorator.logInfo
    def resetState(self):
        pass

    @logDecorator.logInfo
    def _cleanupReal(self):
        pass
