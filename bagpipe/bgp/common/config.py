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

import socket

from oslo_config import cfg
from oslo_config import types

from pyroute2 import IPDB

class InterfaceAddress(types.ConfigType):
    # Option type for a config entry accepting whether an IP address
    # or an interface from which to derive the IP address

    # convert from IP version (4 or 6) to family number
    FAMILY_MAP = {
        4: socket.AF_INET,
        6: socket.AF_INET6,
    }

    def __init__(self, type_name="interface address value", version=4):
        super(InterfaceAddress, self).__init__(type_name=type_name)
        self.family = self.FAMILY_MAP[version]
        self.ip_address = types.IPAddress(version)

    def __call__(self, value):
        try:
            return self.ip_address(value)
        except ValueError:
            # pyroute2 call to take the first address of this interface having
            # the right IP version (family)
            # TODO(tmorin): use IPDB(plugins=("interfaces",)) is better, need
            # to wait for next pyroute2 release
            with IPDB() as ipdb:
                try:
                    interface = ipdb.interfaces[value]
                except KeyError:
                    raise ValueError("interface %s does not exist" % value)

                # we can't use an iterator if we want to access dictionaries
                # inside ipaddr
                for i in range(0, len(interface.ipaddr)):
                    addr = interface.ipaddr[i]
                    if addr['family'] == self.family:
                        return self.ip_address(addr['address'])

                raise ValueError("no IPv%s address found on interface %s",
                                 self.version, value)

    def _formatter(self, value):
        address = self(value)
        return "%s(%s)" % (address, value)

    def __repr__(self):
        return "InterfaceAddress"

    def __eq__(self, other):
        return self.__class__ == other.__class__


cli_opts = [
    cfg.StrOpt("action", positional=True, default='unset',
               choices=('start', 'stop', 'unset'),
               help=("(deprecated, can be omitted)"),
               deprecated_for_removal=True
               )
]

cfg.CONF.register_cli_opts(cli_opts)

bgp_opts = [
    cfg.Opt('local_address', required=True,
            type=InterfaceAddress(),
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
