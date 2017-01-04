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

import logging
import logging.config

from oslo_config import cfg

from daemon import runner

import pbr.version

from bagpipe.bgp.api import api
from bagpipe.bgp.common import config  # flake8: noqa
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.engine.exabgp_peer_worker import setup_exabgp_env

from bagpipe.bgp.vpn import dataplane_drivers as drivers


class BgpDaemon(lg.LookingGlassMixin):

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/bagpipe-bgp/bagpipe-bgp.pid'
        self.pidfile_timeout = 5

    def run(self):
        logging.info("Starting bagpipe-bgp...")
        self.pecan_api = api.PecanAPI()
        self.pecan_api.run()

    def stop(self, signum, _):
        logging.info("Received signal %d, stopping...", signum)
        self.pecan_api.stop()
        logging.info("All threads now stopped...")
        exception = SystemExit("Terminated on signal %d" % signum)
        raise exception


def setup_config():
    cfg.CONF(args=sys.argv[1:],
             project='bagpipe-bgp',
             default_config_files=['/etc/bagpipe-bgp/bgp.conf'],
             version=('%%(prog)s %s' %
                      pbr.version.VersionInfo('bagpipe-bgp')
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

    setup_exabgp_env()

    daemon = BgpDaemon()

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

    for vpn_type, dataplane_driver in (
            drivers.instantiate_dataplane_drivers().iteritems()):
        logging.info("Cleaning dataplane for %s...", vpn_type)
        dataplane_driver.reset_state()

    logging.info("BGP component dataplanes have been cleaned up.")

if __name__ == '__main__':
    daemon_main()
