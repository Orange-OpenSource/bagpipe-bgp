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

import os.path
import sys
import signal
import traceback

from logging import Logger
import logging.config

from stevedore import driver as stevedore_driver

from oslo_config import cfg

from daemon import runner

from pbr import version as pbr_version

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import config

from bagpipe.bgp import constants

from bagpipe.bgp.engine.bgp_manager import Manager
from bagpipe.bgp.engine.exabgp_peer_worker import setup_exabgp_env

from bagpipe.bgp.rest_api import RESTAPI

from bagpipe.bgp.vpn import manager

# prefix for setuptools entry points for dataplane drivers
DATAPLANE_DRIVER_ENTRY_POINT_PFX = "bagpipe.dataplane"


def find_dataplane_drivers():
    if 'DATAPLANE_DRIVER' in cfg.CONF:
        logging.warning("Config file is obsolete, should have a "
                        "DATAPLANE_DRIVER_IPVPN section instead of"
                        " DATAPLANE_DRIVER")
    drivers = dict()
    for vpn_type in constants.VPN_TYPES:
        dp_config = cfg.CONF.get(constants.config_group(vpn_type))

        driver_name = dp_config.dataplane_driver
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
            drivers[vpn_type] = driver_class()
        except Exception as e:
            logging.error("Error while instantiating dataplane"
                          " driver for %s with %s: %s",
                          vpn_type, driver_class, e)
            logging.error(traceback.format_exc())
            break

    return drivers


class BgpDaemon(lg.LookingGlassMixin):

    def __init__(self, catchall_lg_log_handler):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/bagpipe-bgp/bagpipe-bgp.pid'
        self.pidfile_timeout = 5

        self.catchall_lg_log_handler = catchall_lg_log_handler

    def run(self):
        logging.info("Starting BGP component...")

        logging.debug("Creating dataplane drivers")
        drivers = find_dataplane_drivers()

        # FIXME: It is really needed/relevant
        # could be moved to find_dataplane_drivers ?
        for vpn_type in constants.VPN_TYPES:
            if vpn_type not in drivers:
                logging.error("Could not initiate any dataplane driver for %s",
                              vpn_type)
                return

        logging.debug("Creating VPN manager")
        self.manager = manager.VPNManager(drivers)

        # BGP component REST API
        logging.debug("Creating REST API")
        rest_api = RESTAPI(self,
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
            "common": cfg.CONF.COMMON,
            "dataplane": {vpn_type: constants.config_group(type)
                          for vpn_type in constants.VPN_TYPES},
            "bgp": cfg.CONF.BGP
        }


def setup_config():
    cfg.CONF(args=sys.argv[1:],
             project='bagpipe-bgp',
             default_config_files=['/etc/bagpipe-bgp/bgp.conf'],
             version=('%%(prog)s %s' %
                      pbr_version.VersionInfo('bagpipe-bgp')
                      .release_string()))


def daemon_main():
    setup_config()

    if not os.path.isfile(cfg.CONF.CLI.log_file):
        logging.basicConfig()
        print "no logging config file at %s" % cfg.CONF.CLI.log_file
        logging.warning("no logging config file at %s", cfg.CONF.CLI.log_file)
    else:
        logging.config.fileConfig(cfg.CONF.CLI.log_file,
                                  disable_existing_loggers=False)

    if cfg.CONF.CLI.action == "start":
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

    daemon = BgpDaemon(catchall_log_handler)

    try:
        if not cfg.CONF.CLI.no_daemon:
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
    setup_config()

    if not os.path.isfile(cfg.CONF.CLI.log_file):
        print "no logging configuration file at %s" % cfg.CONF.CLI.log_file
        logging.basicConfig()
    else:
        logging.config.fileConfig(cfg.CONF.CLI.log_file,
                                  disable_existing_loggers=False)
        logging.root.name = "[BgpDataplaneCleaner]"

    for (vpn_type, dataplane_driver) in find_dataplane_drivers():
        logging.info("Cleaning dataplane for %s...", vpn_type)
        dataplane_driver.reset_state()

    logging.info("BGP component dataplanes have been cleaned up.")

if __name__ == '__main__':
    daemon_main()
