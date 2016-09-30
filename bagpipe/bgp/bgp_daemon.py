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

import copy

import os.path
import sys
import signal
import traceback

from logging import Logger
import logging.config

import ConfigParser
from optparse import OptionParser

from stevedore import driver as stevedore_driver

from daemon import runner

from bagpipe.bgp.common import looking_glass as lg

from bagpipe.bgp.engine.bgp_manager import Manager
from bagpipe.bgp.engine.exabgp_peer_worker import setup_exabgp_env

from bagpipe.bgp.rest_api import RESTAPI

from bagpipe.bgp.vpn import VPNManager
from bagpipe.bgp.vpn.ipvpn import IPVPN
from bagpipe.bgp.vpn.evpn import EVPN


# prefix for setuptools entry points for dataplane drivers
DATAPLANE_DRIVER_ENTRY_POINT_PFX = "bagpipe.dataplane"


def find_dataplane_drivers(dp_configs, common_config, bgp_config,
                           is_cleaning_up=False):
    drivers = dict()
    for vpn_type in dp_configs.iterkeys():
        dp_config = dp_configs[vpn_type]

        if 'dataplane_driver' not in dp_config:
            logging.error(
                "no dataplane_driver set for %s (%s)", vpn_type, dp_config)

        driver_name = dp_config["dataplane_driver"]
        logging.debug("Creating dataplane driver for %s, with %s",
                      vpn_type, driver_name)

        driver_class = stevedore_driver.DriverManager(
            namespace='%s.%s' % (DATAPLANE_DRIVER_ENTRY_POINT_PFX, vpn_type),
            name=driver_name,
            on_load_failure_callback=(lambda manager, entrypoint, exception:
                                      logging.error("Exception while loading "
                                                    "%s: %s", entrypoint,
                                                    exception))
        ).driver

        try:
            driver = driver_class(dp_config)
            # skipped on cleanup
            if not is_cleaning_up:
                driver.initialize()
            drivers[vpn_type] = driver
        except Exception as e:
            logging.error("Error while instantiating dataplane"
                          " driver for %s with %s: %s",
                          vpn_type, driver_class, e)
            logging.error(traceback.format_exc())
            break

    return drivers


class BgpDaemon(lg.LookingGlassMixin):

    def __init__(self, catchall_lg_log_handler, **kwargs):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/bagpipe-bgp/bagpipe-bgp.pid'
        self.pidfile_timeout = 5

        logging.info("BGP common configuration : %s", kwargs["common_config"])
        self.common_config = kwargs["common_config"]

        logging.info("BGP manager configuration : %s", kwargs["bgp_config"])
        self.bgp_config = kwargs["bgp_config"]

        logging.info("BGP dataplane dataplane_driver configuration : %s",
                     kwargs["dataplane_config"])
        self.dataplane_config = kwargs["dataplane_config"]

        logging.info("BGP API configuration : %s", kwargs["api_config"])
        self.api_config = kwargs["api_config"]

        self.catchall_lg_log_handler = catchall_lg_log_handler

    def run(self):
        logging.info("Starting BGP component...")

        logging.debug("Creating dataplane drivers")
        drivers = find_dataplane_drivers(self.dataplane_config,
                                         self.common_config,
                                         self.bgp_config)

        for vpn_type in self.dataplane_config.iterkeys():
            if vpn_type not in drivers:
                logging.error(
                    "Could not initiate any dataplane driver for %s", vpn_type)
                return

        logging.debug("Creating BGP manager")
        self.bgp_manager = Manager(self.bgp_config)

        logging.debug("Creating VPN manager")
        self.manager = VPNManager(self.common_config,
                                  self.bgp_manager,
                                  drivers)

        # BGP component REST API
        logging.debug("Creating REST API")
        rest_api = RESTAPI(self.api_config,
                           self,
                           self.manager,
                           self.catchall_lg_log_handler)
        rest_api.run()

    def stop(self, signum, _):
        logging.info("Received signal %d, stopping...", signum)
        self.manager.stop()
        self.bgp_manager.stop()
        logging.info("All threads now stopped...")
        exception = SystemExit("Terminated on signal %d" % signum)
        raise exception

    def get_log_local_info(self, path_prefix):
        return {
            "common": self.common_config,
            "dataplane": self.dataplane_config,
            "bgp": self.bgp_config
        }


def _load_config(config_file):
    parser = ConfigParser.SafeConfigParser()

    if (len(parser.read(config_file)) == 0):
        logging.error("Configuration file not found (%s)", config_file)
        exit()

    bgp_config = dict(parser.items("BGP"))

    try:
        common_config = dict(parser.items("COMMON"))
    except ConfigParser.NoSectionError:
        common_config = {}

    if 'dataplane_local_address' not in common_config:
        common_config['dataplane_local_address'] = bgp_config['local_address']

    common_config['root_helper'] = common_config.get("root_helper", "sudo")
    common_config['root_helper_daemon'] = (
        common_config.get("root_helper_daemon")
    )

    dataplane_config = dict()
    for vpn_type in [IPVPN, EVPN]:
        try:
            # copy common_config as a base for each dataplane config
            dp_config = copy.deepcopy(common_config)
            dp_config.update(dict(parser.items("DATAPLANE_DRIVER_%s" %
                                               vpn_type.upper())))
            dataplane_config[vpn_type] = dp_config
        except ConfigParser.NoSectionError:
            if vpn_type == IPVPN:  # backward compat for ipvpn
                dataplane_config[IPVPN] = dict(
                    parser.items("DATAPLANE_DRIVER"))
                logging.warning("Config file is obsolete, should have a "
                                "DATAPLANE_DRIVER_IPVPN section instead of"
                                " DATAPLANE_DRIVER")
            else:
                logging.error(
                    "Config file should have a DATAPLANE_DRIVER_EVPN section")

    api_config = dict(parser.items("API"))
    # TODO: add a default API config

    config = {"common_config": common_config,
              "bgp_config": bgp_config,
              "dataplane_config": dataplane_config,
              "api_config": api_config
              }

    return config


def daemon_main():
    usage = "usage: %prog [options] (see --help)"
    parser = OptionParser(usage)

    parser.add_option("--config-file", dest="config_file",
                      help="Set BGP component configuration file path",
                      default="/etc/bagpipe-bgp/bgp.conf")
    parser.add_option("--log-file", dest="log_file",
                      help="Set logging configuration file path",
                      default="/etc/bagpipe-bgp/log.conf")
    parser.add_option("--no-daemon", dest="daemon", action="store_false",
                      help="Do not daemonize", default=True)
    (options, _) = parser.parse_args()

    action = sys.argv[1]
    assert action == "start" or action == "stop"

    if not os.path.isfile(options.log_file):
        logging.basicConfig()
        print "no logging config file at %s" % options.log_file
        logging.warning("no logging config file at %s", options.log_file)
    else:
        logging.config.fileConfig(
            options.log_file, disable_existing_loggers=False)

    if action == "start":
        logging.root.name = "Main"
        logging.info("Starting...")
    else:  # stop
        logging.root.name = "Stopper"
        logging.info("Signal daemon to stop")

    catchall_log_handler = lg.LookingGlassLogHandler()

    # we inject this catch all log handler in all configured loggers
    for (logger_name, logger) in Logger.manager.loggerDict.iteritems():
        if isinstance(logger, Logger):
            if not logger.propagate and logger.parent is not None:
                logging.debug("Adding looking glass log handler to logger: %s",
                              logger_name)
                logger.addHandler(catchall_log_handler)
    logging.root.addHandler(catchall_log_handler)

    # logging_tree.printout()

    setup_exabgp_env()

    config = _load_config(options.config_file)

    daemon = BgpDaemon(catchall_log_handler, **config)

    try:
        if options.daemon:
            daemon_runner = runner.DaemonRunner(daemon)
            # This ensures that the logger file handler does not get closed
            # during daemonization
            daemon_runner.daemon_context.files_preserve = [
                logging.getLogger().handlers[0].stream]
            daemon_runner.daemon_context.signal_map = {
                signal.SIGTERM: daemon.stop
            }
            daemon_runner.do_action()
        else:
            signal.signal(signal.SIGTERM, daemon.stop)
            signal.signal(signal.SIGINT, daemon.stop)
            daemon.run()
    except Exception as e:
        logging.exception("Error while starting BGP daemon: %s", e)

    logging.info("BGP component main thread stopped.")


def cleanup_main():
    usage = "usage: %prog [options] (see --help)"
    parser = OptionParser(usage)

    parser.add_option("--config-file", dest="config_file",
                      help="Set BGP component configuration file path",
                      default="/etc/bagpipe-bgp/bgp.conf")
    parser.add_option("--log-file", dest="log_file",
                      help="Set logging configuration file path",
                      default="/etc/bagpipe-bgp/log.conf")
    (options, _) = parser.parse_args()

    if not os.path.isfile(options.log_file):
        print "no logging configuration file at %s" % options.log_file
        logging.basicConfig()
    else:
        logging.config.fileConfig(
            options.log_file, disable_existing_loggers=False)
        logging.root.name = "[BgpDataplaneCleaner]"

    logging.info("Cleaning BGP component dataplanes...")
    config = _load_config(options.config_file)

    drivers = find_dataplane_drivers(
        config["dataplane_config"], config["common_config"],
        config["bgp_config"], is_cleaning_up=True)
    for (vpn_type, dataplane_driver) in drivers.iteritems():
        logging.info("Cleaning BGP component dataplane for %s...", vpn_type)
        dataplane_driver.reset_state()

    logging.info("BGP component dataplanes have been cleaned up.")

if __name__ == '__main__':
    daemon_main()
