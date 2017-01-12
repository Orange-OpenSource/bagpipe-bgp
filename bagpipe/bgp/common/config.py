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

from oslo_config import cfg
# from oslo_config import types as oslo_types

cli_opts = [
    cfg.BoolOpt("no-daemon", default=False),
    # this is required because, pre-oslo-log bagpipe-bgp was using --log-file
    # as the path to a configuration file to control logging:
    cfg.BoolOpt("ack-oslo-log",
                help=("oslo_log --log-file CLI parameter will "
                      "be usable only if this is set"),
                default=False),
    cfg.StrOpt("action", positional=True,
               choices=('start', 'stop')
               )
]

cfg.CONF.register_cli_opts(cli_opts)

bgp_opts = [
    cfg.IPOpt('local_address', required=True,
              help="IP address used for BGP peerings"),
    cfg.ListOpt('peers', default=[],  # NOTE(tmorin): use item_type=
                                      # oslo_types.IPAddress
                help="IP addresses of BGP peers"),
    cfg.IntOpt('my_as', min=1, max=2**16-1, required=True,
               help="Our BGP Autonomous System"),
    cfg.BoolOpt('enable_rtc', default=True,
                help="Enable RT Constraint (RFC4684)")
]

cfg.CONF.register_opts(bgp_opts, "BGP")
