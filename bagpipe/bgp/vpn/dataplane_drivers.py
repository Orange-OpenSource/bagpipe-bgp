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

import os
import socket

from distutils.version import StrictVersion

from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common.rootwrap_command import rootwrap_command
from bagpipe.bgp.common.run_command import run_command

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation


class DataplaneDriver(lg.LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    dataplane_instance_class = None
    encaps = [Encapsulation(Encapsulation.Type.DEFAULT),
              Encapsulation(Encapsulation.Type.MPLS)]
    makebefore4break_support = False
    ecmp_support = False

    @log_decorator.log
    def __init__(self, config):
        '''config is a dict'''
        lg.LookingGlassLocalLogger.__init__(self)

        assert issubclass(self.dataplane_instance_class, VPNInstanceDataplane)

        self.config = config

        self.root_helper = self.config.get("root_helper")
        self.root_helper_daemon = self.config.get("root_helper_daemon")

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

        # Linux kernel version check
        o = self._run_command("uname -r")
        self.kernel_release = o[0][0].split("-")[0]
        if getattr(self, 'required_kernel', None):
            if (StrictVersion(self.kernel_release) <
                    StrictVersion(self.required_kernel)):
                self.log.warning("%s requires at least Linux kernel %s"
                                 " (you are running %s)",
                                 self.__class__.__name__,
                                 self.required_kernel,
                                 self.kernel_release)

        # Flag to trigger cleanup all dataplane states on first call to
        # vif_plugged
        self.first_init = True

    @abstractmethod
    def reset_state(self):
        pass

    @abstractmethod
    def initialize(self):
        '''
        This is called after reset_state (which, e.g. cleans up the stuff
        possibly left-out by a previous failed run).

        All init things that should not be cleaned up go here.
        '''
        pass

    @log_decorator.log_info
    def initialize_dataplane_instance(self, instance_id, external_instance_id,
                                      gateway_ip, mask,
                                      instance_label, **kwargs):
        '''
        returns a VPNInstanceDataplane subclass
        after calling reset_state on the dataplane driver, if this is the first
        call to initialize_dataplane_instance
        '''

        if self.first_init:
            self.log.info("First VPN instance init, resetting dataplane state")
            try:
                self.reset_state()
            except Exception as e:
                self.log.error("Exception while resetting state: %s", e)
            self.first_init = False
        else:
            self.log.debug("(not resetting dataplane state)")

        return self.dataplane_instance_class(self, instance_id,
                                             external_instance_id,
                                             gateway_ip, mask,
                                             instance_label, **kwargs)

    def cleanup(self):
        # FIXME: to be clarified: can be removed ? should call reset_state ?
        self._cleanup_real()

    def get_local_address(self):
        return self.local_address

    def supported_encaps(self):
        return self.__class__.encaps

    def _run_command__(self, log, command, run_as_root=False, *args, **kwargs):
        if run_as_root and os.geteuid() == 0:
            # do not need to wrap any call
            run_as_root = False

        if run_as_root and self.root_helper_daemon:
            return rootwrap_command(log, self.root_helper_daemon,
                                    command, *args, **kwargs)
        else:
            if run_as_root:
                command = " ".join([self.root_helper, command])

            # remove shell from kwargs (uses shell by default)
            kwargs.pop("shell", False)
            return run_command(self.log, command, *args, **kwargs)

    def _run_command(self, command, run_as_root=False, *args, **kwargs):
        return self._run_command__(self.log, command, run_as_root,
                                   *args, **kwargs)

    def get_lg_map(self):
        encaps = []
        for encap in self.supported_encaps():
            encaps.append(repr(encap))
        return {
            "name": (lg.VALUE, self.__class__.__name__),
            "local_address": (lg.VALUE, self.local_address),
            "supported_encaps": (lg.VALUE, encaps),
            "config": (lg.VALUE, self.config),
            "kernel_release": (lg.VALUE, self.kernel_release)
        }


class VPNInstanceDataplane(lg.LookingGlassLocalLogger):
    __metaclass__ = ABCMeta

    @log_decorator.log_info
    def __init__(self, dataplane_driver, instance_id, external_instance_id,
                 gateway_ip, mask, instance_label=None):
        lg.LookingGlassLocalLogger.__init__(self, repr(instance_id))
        self.driver = dataplane_driver
        self.config = dataplane_driver.config
        self.instance_id = instance_id
        self.external_instance_id = external_instance_id
        self.gateway_ip = gateway_ip
        self.mask = mask
        self.instance_label = instance_label

    @abstractmethod
    def cleanup(self):
        pass

    @abstractmethod
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label):
        pass

    @abstractmethod
    def vif_unplugged(self, mac_address, ip_address_prefix, localport, label,
                      last_endpoint=True):
        pass

    def update_fallback(self, fallback):
        if fallback is not None:
            self.log.warning("fallback  specified (%s) but not supported by"
                             " driver, ignoring", fallback)

    @abstractmethod
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        pass

    @abstractmethod
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):
        pass

    def _run_command(self, command, run_as_root=False, *args, **kwargs):
        return self.driver._run_command__(self.log, command, run_as_root,
                                          *args, **kwargs)

    # Looking glass info ####

    def get_log_local_info(self, path_prefix):
        driver = {"id": self.driver.type,
                  "href": lg.get_absolute_path(
                      "DATAPLANE_DRIVERS", path_prefix, [self.driver.type])}
        return {
            "driver": driver,
        }


class DummyVPNInstanceDataplane(VPNInstanceDataplane):

    @log_decorator.log
    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

    @log_decorator.log
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label):
        pass

    @log_decorator.log
    def vif_unplugged(self, mac_address, ip_address_prefix, localport, label,
                      last_endpoint=True):
        pass

    @log_decorator.log
    def update_fallback(self, fallback):
        pass

    @log_decorator.log
    def setup_dataplane_for_remote_endpoint(self, *args):
        pass

    @log_decorator.log
    def remove_dataplane_for_remote_endpoint(self, *args):
        pass

    @log_decorator.log
    def cleanup(self):
        pass


class DummyDataplaneDriver(DataplaneDriver):

    dataplane_instance_class = DummyVPNInstanceDataplane

    def __init__(self, *args):
        DataplaneDriver.__init__(self, *args)

    @log_decorator.log_info
    def initialize(self):
        pass

    @log_decorator.log_info
    def reset_state(self):
        pass

    @log_decorator.log_info
    def _cleanup_real(self):
        pass
