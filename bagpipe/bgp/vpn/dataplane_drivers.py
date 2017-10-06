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
import traceback

from distutils import version
from oslo_config import cfg
from oslo_log import log as logging
import stevedore

from bagpipe.bgp.common import config
from bagpipe.bgp import constants
from bagpipe.bgp.engine import exa
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import run_command
from bagpipe.bgp.common import utils


LOG = logging.getLogger(__name__)


# NOTE(tmorin): have dataplane_local_address default to
#               cfg.CONF.BGP.local_address does not work (import order issue)
# TODO(tmorin): list possible values for dataplane_driver,
#               see what neutron-db-manage does
dataplane_common_opts = [
    cfg.Opt("dataplane_local_address",
            type=config.InterfaceAddress(),
            help=("IP address to use as next-hop in our route "
                  "advertisements, will be used to send us "
                  "VPN traffic")),
    cfg.StrOpt("dataplane_driver", default="dummy",
               help="Dataplane driver.")
]


for vpn_type in constants.VPN_TYPES:
    cfg.CONF.register_opts(dataplane_common_opts,
                           constants.config_group(vpn_type))


def register_driver_opts(vpn_type, driver_opts):
    cfg.CONF.register_opts(driver_opts, constants.config_group(vpn_type))

# prefix for setuptools entry points for dataplane drivers
DATAPLANE_DRIVER_ENTRY_POINT_PFX = "bagpipe.dataplane"


def instantiate_dataplane_drivers():
    LOG.debug("Building dataplane drivers...")

    if 'DATAPLANE_DRIVER' in cfg.CONF:
        LOG.warning("Config file is obsolete, should have a "
                    "DATAPLANE_DRIVER_IPVPN section instead of"
                    " DATAPLANE_DRIVER")

    drivers = {}
    for vpn_type in constants.VPN_TYPES:
        dp_config = cfg.CONF.get(constants.config_group(vpn_type))

        driver_name = dp_config.dataplane_driver
        LOG.debug("Instantiating dataplane driver for %s, with %s",
                  vpn_type, driver_name)
        try:
            driver_class = stevedore.driver.DriverManager(
                namespace='%s.%s' % (DATAPLANE_DRIVER_ENTRY_POINT_PFX,
                                     vpn_type),
                name=driver_name,
            ).driver

            drivers[vpn_type] = driver_class()
        except Exception as e:
            LOG.error("Error while instantiating dataplane"
                      " driver for %s with %s: %s", vpn_type, driver_name, e)
            LOG.error(traceback.format_exc())
            raise

    return drivers


class DataplaneDriver(lg.LookingGlassLocalLogger):
    __metaclass__ = abc.ABCMeta

    type = None

    dataplane_instance_class = None
    encaps = [exa.Encapsulation(exa.Encapsulation.Type.DEFAULT),
              exa.Encapsulation(exa.Encapsulation.Type.MPLS)]
    makebefore4break_support = False
    ecmp_support = False
    required_kernel = None

    driver_opts = []

    @log_decorator.log
    def __init__(self):
        lg.LookingGlassLocalLogger.__init__(self)

        cfg.CONF.register_opts(self.driver_opts,
                               constants.config_group(self.type))

        self.config = cfg.CONF.get(constants.config_group(self.type))

        assert issubclass(self.dataplane_instance_class, VPNInstanceDataplane)

        self.local_address = self.config.get("dataplane_local_address")

        if self.local_address is None:
            self.local_address = cfg.CONF.BGP.local_address

        self.log.info("Will use %s as local_address", self.local_address)

        # Linux kernel version check
        o = self._run_command("uname -r")
        self.kernel_release = o[0][0].split("-")[0]
        if self.required_kernel:
            if (version.StrictVersion(self.kernel_release) <
                    version.StrictVersion(self.required_kernel)):
                self.log.warning("%s requires at least Linux kernel %s"
                                 " (you are running %s)",
                                 self.__class__.__name__,
                                 self.required_kernel,
                                 self.kernel_release)

        # Flag to trigger cleanup all dataplane states on first call to
        # vif_plugged
        self.first_init = True

    @abc.abstractmethod
    def reset_state(self):
        pass

    @abc.abstractmethod
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
            self.log.info("First VPN instance init, reinitializing dataplane"
                          " state")
            try:
                self.reset_state()
            except Exception as e:
                self.log.error("Exception while resetting state: %s", e)

            try:
                self.initialize()
            except Exception as e:
                self.log.error("Exception while initializing dataplane"
                               " state: %s", e)
                raise

            self.first_init = False
        else:
            self.log.debug("(not reinitializing dataplane state)")

        return self.dataplane_instance_class(self, instance_id,
                                             external_instance_id,
                                             gateway_ip, mask,
                                             instance_label, **kwargs)

    def get_local_address(self):
        return self.local_address

    def supported_encaps(self):
        return self.__class__.encaps

    def _run_command(self, command, run_as_root=False, *args, **kwargs):
        return run_command.run_command(self.log, command, run_as_root,
                                       *args, **kwargs)

    def get_lg_map(self):
        encaps = []
        for encap in self.supported_encaps():
            encaps.append(repr(encap))
        return {
            "name": (lg.VALUE, self.__class__.__name__),
            "local_address": (lg.VALUE, self.local_address),
            "supported_encaps": (lg.VALUE, encaps),
            "config": (lg.VALUE, utils.osloconfig_json_serialize(self.config)),
            "kernel_release": (lg.VALUE, self.kernel_release)
        }


class VPNInstanceDataplane(lg.LookingGlassLocalLogger):
    __metaclass__ = abc.ABCMeta

    @log_decorator.log_info
    def __init__(self, dataplane_driver, instance_id, external_instance_id,
                 gateway_ip, mask, instance_label=None, **kwargs):
        lg.LookingGlassLocalLogger.__init__(self, repr(instance_id))
        self.driver = dataplane_driver
        self.config = dataplane_driver.config
        self.instance_id = instance_id
        self.external_instance_id = external_instance_id
        self.gateway_ip = gateway_ip
        self.mask = mask
        self.instance_label = instance_label

    @abc.abstractmethod
    def cleanup(self):
        pass

    @abc.abstractmethod
    def vif_plugged(self, mac_address, ip_address_prefix, localport, label):
        pass

    @abc.abstractmethod
    def vif_unplugged(self, mac_address, ip_address_prefix, localport, label,
                      last_endpoint=True):
        pass

    def update_fallback(self, fallback):
        if fallback is not None:
            self.log.warning("fallback  specified (%s) but not supported by"
                             " driver, ignoring", fallback)

    @abc.abstractmethod
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        pass

    @abc.abstractmethod
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):
        pass

    def _run_command(self, command, run_as_root=False, *args, **kwargs):
        return self.driver._run_command(command, run_as_root, *args, **kwargs)

    # Looking glass info ####

    def get_lg_local_info(self, path_prefix):
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
        self.log.warning("Dummy dataplane driver, won't do anything useful")

    @log_decorator.log_info
    def initialize(self):
        pass

    @log_decorator.log_info
    def reset_state(self):
        pass
