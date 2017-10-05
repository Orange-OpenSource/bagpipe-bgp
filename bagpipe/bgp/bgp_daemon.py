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
        'bagpipe.bgp.engine.exa_bgp_peer_worker.exabgp=INFO',
        'bagpipe.bgp.common.looking_glass=WARNING',
        'bagpipe.bgp.engine.route_table_manager=INFO'
    ]

    logging.set_defaults(default_log_levels=(logging.get_default_log_levels() +
                                             extra_log_level_defaults))

    logging.setup(cfg.CONF, "bagpipe-bgp")


def fix_log_file():
    # assist transition from past bagpipe-bgp version which were
    # using --log-file to specify the location of a file to configure logging
    if (cfg.CONF.log_file and cfg.CONF.log_file.endswith('.conf')):
        cfg.CONF.log_file = None
        return ("now using oslo.log, specifying a log configuration file "
                "should be done with --log-config-append")


def daemon_main():
    logging.register_options(cfg.CONF)

    setup_config()

    if cfg.CONF.action != "unset":
        LOG.warning("Running daemonized and using start/stop is not supported "
                    "anymore, use of systemd is your typical alternative")
        if cfg.CONF.action == "stop":
            sys.exit(-1)

    log_file_warn = fix_log_file()

    setup_logging()

    if log_file_warn:
        LOG.warning(log_file_warn)

    exabgp_peer_worker.setup_exabgp_env()

    try:
        LOG.info("Starting bagpipe-bgp...")
        pecan_api = api.PecanAPI()

        cfg.CONF.log_opt_values(LOG, logging.INFO)

        def stop(signum, _):
            LOG.info("Received signal %d, stopping...", signum)
            pecan_api.stop()
            LOG.info("All threads now stopped...")
            sys.exit(0)

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
