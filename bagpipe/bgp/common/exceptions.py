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


class VPNNotFound(Exception):

    def __init__(self, vrf_id):
        self.message = "VRF %s could not be found" % vrf_id

    def __str__(self):
        return repr(self.message)


class MalformedIPAddress(Exception):

    def __init__(self, ip_address):
        self.message = "Address %s doesn't look valid" % ip_address

    def __str__(self):
        return repr(self.message)


class OVSBridgeNotFound(Exception):

    def __init__(self, bridge):
        self.message = "OVS bridge '%s' doesn't exist" % bridge

    def __str__(self):
        return str(self.message)


class OVSBridgePortNotFound(Exception):

    def __init__(self, interface, bridge):
        self.message = ("OVS Port %s doesn't exist on OVS Bridge %s" %
                        (interface, bridge))

    def __str__(self):
        return repr(self.message)


class RemotePEMACAddressNotFound(Exception):

    def __init__(self, ip_address):
        self.message = ("MAC address for %s could not be found. CAUTION:"
                        " Need direct MPLS/Eth connection" % ip_address)

    def __str__(self):
        return repr(self.message)


class APIException(Exception):
    pass
