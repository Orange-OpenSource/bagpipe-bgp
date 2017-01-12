# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2016 Orange
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

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


def get_device_mac(run_command_fn, dev_name, netns_name=None):
    """ Find device MAC address """
    if netns_name:
        command_prefix = "ip netns exec %s " % netns_name
    else:
        command_prefix = ""

    (output, _) = run_command_fn("%scat /sys/class/net/%s/address" %
                                 (command_prefix, dev_name))
    return output[0]


def set_device_mac(run_command_fn, dev_name, mac_address, netns_name=None):
    """ Set device MAC address """
    if netns_name:
        command_prefix = "ip netns exec %s " % netns_name
    else:
        command_prefix = ""

    run_command_fn("%s ip link set %s address %s" % (command_prefix,
                                                     dev_name, mac_address))
