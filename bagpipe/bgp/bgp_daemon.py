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

import sys
import signal

from oslo_log import log as logging

from oslo_config import cfg

from daemon import runner

import pbr.version

from bagpipe.bgp.api import api
from bagpipe.bgp.common import config  # flake8: noqa
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.engine.exabgp_peer_worker import setup_exabgp_env

from bagpipe.bgp.vpn import dataplane_drivers as drivers

import logging as python_logging

LOG = logging.getLogger(__name__)

BACKWARD_COMPAT_LOG_PATH = "/var/log/bagpipe-bgp/bagpipe-bgp.log"


class BgpDaemon(lg.LookingGlassMixin):

    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = '/var/run/bagpipe-bgp/bagpipe-bgp.pid'
        self.pidfile_timeout = 5

    def run(self):
        LOG.info("Starting bagpipe-bgp...")
        self.pecan_api = api.PecanAPI()
        self.pecan_api.run()

    def stop(self, signum, _):
        LOG.info("Received signal %d, stopping...", signum)
        self.pecan_api.stop()
        LOG.info("All threads now stopped...")
        raise SystemExit("Terminated on signal %d" % signum)


def setup_config():
    cfg.CONF(args=sys.argv[1:],
             project='bagpipe-bgp',
             default_config_files=['/etc/bagpipe-bgp/bgp.conf'],
             version=('%%(prog)s %s' %
                      pbr.version.VersionInfo('bagpipe-bgp')
                      .release_string()))


def setup_logging():
    # even in debug mode we don't want to much talk from these
    extra_log_level_defaults = [
        'bagpipe.bpg.engine.exa_bgp_peer_worker.exabgp=INFO',
        'bagpipe.bpg.common.looking_glass=WARNING'
    ]

    logging.set_defaults(default_log_levels=(logging.get_default_log_levels() +
                                             extra_log_level_defaults))

    logging.setup(cfg.CONF, "bagpipe-bpg")


def fix_log_file():
    # required to transition from past bagpipe-bgp version which were
    # using --log-file to specify the location of a file to configure logging
    if not cfg.CONF.ack_oslo_log:
        if (not cfg.CONF.log_file or
                cfg.CONF.log_file == '/etc/bagpipe-bgp/log.conf'):
            if not cfg.CONF.no_daemon:
                LOG.warning("now using oslo_log, will use %s as log file, "
                            "use --ack-oslo-log --log-file <path> to "
                            "specify another path" % BACKWARD_COMPAT_LOG_PATH)
                cfg.CONF.log_file = BACKWARD_COMPAT_LOG_PATH
        else:
            LOG.warning("now using oslo_log, will ignore --log-file option "
                        "unless you also set --ack-oslo-log, in which case "
                        "--log-file will specify a log file location" %
                        cfg.CONF.log_file)
            cfg.CONF.log_file = None


def daemon_main():
    logging.register_options(cfg.CONF)

    setup_config()

    fix_log_file()

    setup_logging()

    setup_exabgp_env()

    sys.argv[1:] = [cfg.CONF.action]
    daemon = BgpDaemon()

    try:
        if not cfg.CONF.no_daemon:
            daemon_runner = runner.DaemonRunner(daemon)
            # This ensures that the logger file handler does not get closed
            # during daemonization
            daemon_runner.daemon_context.files_preserve = [
                python_logging.getLogger().handlers[0].stream]
            daemon_runner.daemon_context.signal_map = {
                signal.SIGTERM: daemon.stop
            }
            daemon_runner.do_action()
        else:
            signal.signal(signal.SIGTERM, daemon.stop)
            signal.signal(signal.SIGINT, daemon.stop)
            if cfg.CONF.action == "stop":
                LOG.error("Can't use 'stop' with --no-daemon")
            else:
                daemon.run()
    except Exception as e:
        LOG.exception("Error while starting BGP daemon: %s", e)


def cleanup_main():
    logging.register_options(cfg.CONF)

    setup_config()

    fix_log_file()

    setup_logging()

    python_logging.root.name = "[BgpDataplaneCleaner]"

    for vpn_type, dataplane_driver in (
            drivers.instantiate_dataplane_drivers().iteritems()):
        LOG.info("Cleaning dataplane for %s...", vpn_type)
        dataplane_driver.reset_state()

    LOG.info("BGP component dataplanes have been cleaned up.")

if __name__ == '__main__':
    daemon_main()
