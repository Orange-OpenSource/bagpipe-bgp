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

import logging as python_logging
import sys
import signal

from oslo_config import cfg
from oslo_log import log as logging
import pbr.version

from bagpipe.bgp.api import api
from bagpipe.bgp.common import config  # flake8: noqa
from bagpipe.bgp.engine import exabgp_peer_worker
from bagpipe.bgp.vpn import dataplane_drivers as drivers


LOG = logging.getLogger(__name__)


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
    if (not cfg.CONF.ack_oslo_log and
            cfg.CONF.log_file and
            cfg.CONF.log_file != '/etc/bagpipe-bgp/log.conf'):
        LOG.warning("now using oslo_log, will ignore --log-file option "
                    "unless you also set --ack-oslo-log, in which case "
                    "--log-file will have to specify a log file location")
        cfg.CONF.log_file = None


def daemon_main():
    logging.register_options(cfg.CONF)

    setup_config()

    if cfg.CONF.action != "unset":
        LOG.warning("Running daemonized and using start/stop is not supported "
                    "anymore, use of systemd is your typical alternative")
        if cfg.CONF.action == "stop":
            sys.exit(-1)

    fix_log_file()

    setup_logging()

    exabgp_peer_worker.setup_exabgp_env()

    try:
        LOG.info("Starting bagpipe-bgp...")
        pecan_api = api.PecanAPI()

        def stop(signum, _):
            LOG.info("Received signal %d, stopping...", signum)
            pecan_api.stop()
            LOG.info("All threads now stopped...")
            raise SystemExit("Terminated on signal %d" % signum)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        pecan_api.run()
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
