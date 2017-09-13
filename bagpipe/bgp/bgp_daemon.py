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

from logging import Logger
import logging.config

# import logging_tree

import traceback

from daemon import runner
import signal

from ConfigParser import SafeConfigParser, NoSectionError
from optparse import OptionParser

from bagpipe.bgp.common import utils
from bagpipe.bgp.common.looking_glass import LookingGlass, \
    LookingGlassLogHandler

from bagpipe.bgp.engine.bgp_manager import Manager

from bagpipe.bgp.rest_api import RESTAPI

from bagpipe.bgp.vpn import VPNManager


def findDataplaneDrivers(dpConfigs, bgpConfig, isCleaningUp=False):
    drivers = dict()
    for vpnType in dpConfigs.iterkeys():
        dpConfig = dpConfigs[vpnType]

        if 'dataplane_driver' not in dpConfig:
            logging.error(
                "no dataplane_driver set for %s (%s)", vpnType, dpConfig)

        driverName = dpConfig["dataplane_driver"]
        logging.debug(
            "Creating dataplane driver for %s, with %s", vpnType, driverName)

        # FIXME: this is a hack, dataplane drivers should have a better way to
        #  access any item in the BGP dataplaneConfig
        if 'dataplane_local_address' not in dpConfig:
            dpConfig['dataplane_local_address'] = bgpConfig['local_address']

        for tentativeClassName in (driverName,
                                   'bagpipe.%s' % driverName,
                                   'bagpipe.bgp.%s' % driverName,
                                   'bagpipe.bgp.vpn.%s.%s' % (
                                       vpnType, driverName),
                                   ):
            try:
                if '.' not in tentativeClassName:
                    logging.debug(
                        "Not trying to import '%s'", tentativeClassName)
                    continue

                driverClass = utils.import_class(tentativeClassName)
                try:
                    logging.info("Found driver for %s, initiating...", vpnType)
                    # skip the init step if called for cleanup
                    driver = driverClass(dpConfig, not isCleaningUp)
                    drivers[vpnType] = driver
                    logging.info(
                        "Successfully initiated dataplane driver for %s with"
                        " %s", vpnType, tentativeClassName)
                except ImportError as e:
                    logging.debug(
                        "Could not initiate dataplane driver for %s with"
                        " %s: %s", vpnType, tentativeClassName, e)
                except Exception as e:
                    logging.error(
                        "Found class, but error while instantiating dataplane"
                        " driver for %s with %s: %s", vpnType,
                        tentativeClassName, e)
                    logging.error(traceback.format_exc())
                    break
                break
            except SyntaxError as e:
                logging.error(
                    "Found class, but syntax error while instantiating "
                    "dataplane driver for %s with %s: %s", vpnType,
                    tentativeClassName, e)
                break
            except Exception as e:
                logging.debug(
                    "Could not initiate dataplane driver for %s with %s (%s)",
                    vpnType, tentativeClassName, e)
    return drivers


class BgpDaemon(LookingGlass):

    def __init__(self, catchAllLGLogHandler, **kwargs):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/bagpipe-bgp/bagpipe-bgp.pid'
        self.pidfile_timeout = 5

        logging.info("BGP manager configuration : %s", kwargs["bgpConfig"])
        self.bgpConfig = kwargs["bgpConfig"]

        logging.info("BGP dataplane dataplaneDriver configuration : %s",
                     kwargs["dataplaneConfig"])
        self.dataplaneConfig = kwargs["dataplaneConfig"]

        logging.info("BGP API configuration : %s", kwargs["apiConfig"])
        self.apiConfig = kwargs["apiConfig"]

        self.catchAllLGLogHandler = catchAllLGLogHandler

    def run(self):
        logging.info("Starting BGP component...")

        logging.debug("Creating dataplane drivers")
        drivers = findDataplaneDrivers(self.dataplaneConfig, self.bgpConfig)

        for vpnType in self.dataplaneConfig.iterkeys():
            if vpnType not in drivers:
                logging.error(
                    "Could not initiate any dataplane driver for %s", vpnType)
                return

        logging.debug("Creating BGP manager")
        self.bgpManager = Manager(self.bgpConfig)

        logging.debug("Creating VPN manager")
        self.vpnManager = VPNManager(self.bgpManager, drivers)

        # BGP component REST API
        logging.debug("Creating REST API")
        bgpapi = RESTAPI(
            self.apiConfig, self, self.vpnManager, self.catchAllLGLogHandler)
        bgpapi.run()

    def stop(self, signum, frame):
        logging.info("Received signal %(signum)r, stopping...", vars())
        self.vpnManager.stop()
        self.bgpManager.stop()
        # would need to stop main thread ?
        logging.info("All threads now stopped...")
        exception = SystemExit("Terminated on signal %(signum)r" % vars())
        raise exception

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
            "dataplane": self.dataplaneConfig,
            "bgp": self.bgpConfig
        }


def _loadConfig(configFile):
    parser = SafeConfigParser()

    if (len(parser.read(configFile)) == 0):
        logging.error("Configuration file not found (%s)", configFile)
        exit()

    bgpConfig = parser.items("BGP")

    dataplaneConfig = dict()
    for vpnType in ['ipvpn', 'evpn']:
        try:
            dataplaneConfig[vpnType] = dict(
                parser.items("DATAPLANE_DRIVER_%s" % vpnType.upper()))
        except NoSectionError:
            if vpnType == "ipvpn":  # backward compat for ipvpn
                dataplaneConfig['ipvpn'] = dict(
                    parser.items("DATAPLANE_DRIVER"))
                logging.warning("Config file is obsolete, should have a "
                                "DATAPLANE_DRIVER_IPVPN section instead of"
                                " DATAPLANE_DRIVER")
            else:
                logging.error(
                    "Config file should have a DATAPLANE_DRIVER_EVPN section")

    apiConfig = parser.items("API")
    # TODO: add a default API config

    config = {"bgpConfig": dict(bgpConfig),
              "dataplaneConfig": dataplaneConfig,
              "apiConfig": dict(apiConfig)
              }

    return config


def daemon_main():
    usage = "usage: %prog [options] (see --help)"
    parser = OptionParser(usage)

    parser.add_option("--config-file", dest="configFile",
                      help="Set BGP component configuration file path",
                      default="/etc/bagpipe-bgp/bgp.conf")
    parser.add_option("--log-file", dest="logFile",
                      help="Set logging configuration file path",
                      default="/etc/bagpipe-bgp/log.conf")
    parser.add_option("--no-daemon", dest="daemon", action="store_false",
                      help="Do not daemonize", default=True)
    (options, _) = parser.parse_args()

    action = sys.argv[1]
    assert(action == "start" or action == "stop")

    if not os.path.isfile(options.logFile):
        logging.basicConfig()
        print "no logging configuration file at %s" % options.logFile
        logging.warning("no logging configuration file at %s", options.logFile)
    else:
        logging.config.fileConfig(
            options.logFile, disable_existing_loggers=False)

    if action == "start":
        logging.root.name = "Main"
        logging.info("Starting...")
    else:  # stop
        logging.root.name = "Stopper"
        logging.info("Signal daemon to stop")

    catchAllLogHandler = LookingGlassLogHandler()

    # we inject this catch all log handler in all configured loggers
    for (loggerName, logger) in Logger.manager.loggerDict.iteritems():
        if isinstance(logger, Logger):
            if (not logger.propagate and logger.parent is not None):
                logging.debug("Adding looking glass log handler to logger: %s",
                              loggerName)
                logger.addHandler(catchAllLogHandler)
    logging.root.addHandler(catchAllLogHandler)

    # logging_tree.printout()

    config = _loadConfig(options.configFile)

    bgpDaemon = BgpDaemon(catchAllLogHandler, **config)

    try:
        if options.daemon:
            daemon_runner = runner.DaemonRunner(bgpDaemon)
            # This ensures that the logger file handler does not get closed
            # during daemonization
            daemon_runner.daemon_context.files_preserve = [
                logging.getLogger().handlers[0].stream]
            daemon_runner.daemon_context.signal_map = {
                signal.SIGTERM: bgpDaemon.stop
            }
            daemon_runner.do_action()
        else:
            signal.signal(signal.SIGTERM, bgpDaemon.stop)
            signal.signal(signal.SIGINT, bgpDaemon.stop)
            bgpDaemon.run()
    except Exception as e:
        logging.exception("Error while starting BGP daemon: %s", e)

    logging.info("BGP component main thread stopped.")


def cleanup_main():
    usage = "usage: %prog [options] (see --help)"
    parser = OptionParser(usage)

    parser.add_option("--config-file", dest="configFile",
                      help="Set BGP component configuration file path",
                      default="/etc/bagpipe-bgp/bgp.conf")
    parser.add_option("--log-file", dest="logFile",
                      help="Set logging configuration file path",
                      default="/etc/bagpipe-bgp/log.conf")
    (options, _) = parser.parse_args()

    if not os.path.isfile(options.logFile):
        print "no logging configuration file at %s" % options.logFile
        logging.basicConfig()
    else:
        logging.config.fileConfig(
            options.logFile, disable_existing_loggers=False)
        logging.root.name = "[BgpDataplaneCleaner]"

    logging.info("Cleaning BGP component dataplanes...")
    config = _loadConfig(options.configFile)

    drivers = findDataplaneDrivers(
        config["dataplaneConfig"], config["bgpConfig"], isCleaningUp=True)
    for (vpnType, dataplaneDriver) in drivers.iteritems():
        logging.info("Cleaning BGP component dataplane for %s...", vpnType)
        dataplaneDriver.resetState()

    logging.info("BGP component dataplanes have been cleaned up.")

if __name__ == '__main__':
    daemon_main()
