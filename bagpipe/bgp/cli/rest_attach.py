#!/usr/bin/env python
#
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

import os
import sys

import re
import urllib2
import json

from optparse import OptionParser
from copy import copy

from netaddr.ip import IPNetwork

from bagpipe.bgp.common.run_command import runCommand
from bagpipe.bgp.common.net_utils import get_device_mac

import logging

DEFAULT_VPN_INSTANCE_ID = "bagpipe-test"

NS2VPN_INTERFACE_PREFIX = "tovpn-"
VPN2NS_INTERFACE_PREFIX = "tons-"

NS2VPN_DEFAULT_IFNAME = "tovpn"


LINUX_DEV_LEN = 15

# Needed so that the OVS bridge kernel interface can hava a high enough MTU
DEFAULT_MTU = 9000

logFormatter = logging.Formatter("[%(levelname)-5.5s]  %(message)s")
log = logging.getLogger()

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
log.addHandler(consoleHandler)

log.setLevel(logging.WARNING)


def create_veth_pair(vpn_interface, ns_interface, ns_name):
    runCommand(log, "ip netns exec %s ip link delete %s" % (ns_name,
                                                            ns_interface),
               raiseExceptionOnError=False,
               acceptableReturnCodes=[0, 1])
    # in case the interface was previously attached to OVS,
    # we need to remove that, or when then interface is re-created
    # OVS will take it back!
    runCommand(log, "ovs-vsctl del-port %s" % vpn_interface,
               raiseExceptionOnError=False,
               acceptableReturnCodes=[0, 1])
    runCommand(log, "ip link delete %s" % vpn_interface,
               raiseExceptionOnError=False,
               acceptableReturnCodes=[0, 1])
    runCommand(log, "ip link add %s type veth peer name %s netns %s" %
               (vpn_interface, ns_interface, ns_name),
               raiseExceptionOnError=False)
    runCommand(log, "ip link set dev %s up" % vpn_interface)
    runCommand(log, "ip link set dev %s mtu %d" % (vpn_interface, DEFAULT_MTU))
    runCommand(log, "ip netns exec %s ip link set dev %s up" %
               (ns_name, ns_interface))


def get_vpn2ns_if_name(namespace):
    return (VPN2NS_INTERFACE_PREFIX + namespace)[:LINUX_DEV_LEN]


def createSpecialNetNSPort(options):
    print "Will plug local namespace %s into network" % options.netns

    # create namespace
    runCommand(log, "ip netns add %s" %
               options.netns, raiseExceptionOnError=False)

    # create veth pair and move one into namespace
    if options.ovs_vlan:
        create_veth_pair(options.if2netns, "ns2vpn-raw", options.netns)

        runCommand(log, "ip netns exec %s ip link add link ns2vpn-raw "
                   "name %s type vlan id %d"
                   % (options.netns, options.if2vpn, options.ovs_vlan))
        runCommand(log, "ip netns exec %s ip link set %s up"
                   % (options.netns, options.if2vpn))
    else:
        create_veth_pair(options.if2netns, options.if2vpn, options.netns)

    if options.mac:
        runCommand(log, "ip netns exec %s ip link set %s address %s"
                   % (options.netns, options.if2vpn, options.mac))

    runCommand(log, "ip netns exec %s ip addr add %s dev %s" %
               (options.netns, options.ip, options.if2vpn),
               raiseExceptionOnError=False)

    runCommand(log, "ip netns exec %s ip route add default dev %s via %s" %
               (options.netns, options.if2vpn, options.gw_ip),
               raiseExceptionOnError=False)

    runCommand(log, "ip netns exec %s ip link set %s mtu 1420" %
               (options.netns, options.if2vpn),
               raiseExceptionOnError=False)


def main():
    usage = "usage: %prog [--attach|--detach] --network-type (ipvpn|evpn) "\
        "--port (<port>|netns) --ip <ip>[/<mask>] [options] (see --help)"
    parser = OptionParser(usage)

    parser.add_option("--attach", dest="operation",
                      action="store_const", const="attach",
                      help="attach local port")
    parser.add_option("--detach", dest="operation",
                      action="store_const", const="detach",
                      help="detach local port")

    parser.add_option("--network-type", dest="network_type",
                      help="network type (ipvpn or evpn)",
                      choices=["ipvpn", "evpn"])
    parser.add_option("--vpn-instance-id", dest="vpn_instance_id",
                      help="UUID for the network instance "
                      "(default: %default-(ipvpn|evpn))",
                      default=DEFAULT_VPN_INSTANCE_ID)
    parser.add_option("--port", dest="port",
                      help="local port to attach/detach (use special port "
                      "'netns[:if]' to have an interface to a local network "
                      "namespace attached/detached "
                      "[with 'if' as the name of the interface to the netns]")

    parser.add_option("--rt", dest="routeTargets",
                      help="route target [default: 64512:0] (can be "
                      "specified multiple times)", default=[], action="append")
    parser.add_option("--import-rt", dest="importOnlyRouteTargets",
                      help="import-only route target (can be specified"
                      "multiple times)", default=[], action="append")
    parser.add_option("--export-rt", dest="exportOnlyRouteTargets",
                      help="export-only route target (can be specified"
                      "multiple times)", default=[], action="append")

    parser.add_option("--ip", dest="ip",
                      help="IP prefix / mask (mask defaults to /24)")
    parser.add_option("--gateway-ip", dest="gw_ip",
                      help="IP address of network gateway (optional, "
                      "defaults to last IP in range)")
    parser.add_option("--mac", dest="mac",
                      help="MAC address (required for evpn if port"
                      " is not 'netns')")

    parser.set_defaults(advertiseSubnet=False)
    parser.add_option("--advertise-singleton", action="store_false",
                      dest="advertiseSubnet",
                      help="advertise IP address as a /32 (default)")

    parser.add_option("--advertise-subnet", action="store_true",
                      dest="advertiseSubnet",
                      help="advertise the whole IP subnet")

    parser.add_option("--ovs-preplug", action="store_true", dest="ovs_preplug",
                      default=False, help="should we prealably plug the port "
                      "into an OVS bridge")
    parser.add_option("--ovs-bridge", dest="bridge", default="br-int",
                      help="if preplug, specifies which OVS bridge to use"
                      " (default: %default)")
    parser.add_option("--ovs-vlan", dest="ovs_vlan", type='int',
                      help="if specified, only this VLAN from the OVS "
                      "interface will be attached to the VPN instance "
                      "(optional)")

    parser.add_option("--netns", dest="netns",
                      help="name of network namespace (optional, for use with"
                      " --port netns)")
    parser.add_option("--if2vpn", dest="if2vpn", default=NS2VPN_DEFAULT_IFNAME,
                      help="name of interface in netns toward VPN"
                      "defaults to %default "
                      "(optional, for use with --port netns)")

    parser.add_option("--readv-from-rt", dest="reAdvFromRTs",
                      help="enables route readvertisement from these RTs,"
                      " works in conjunction with --readv-to-rt",
                      default=[], action="append")

    parser.add_option("--readv-to-rt", dest="reAdvToRTs",
                      help="enables route readvertisement to these RTs,"
                      " works in conjunction with --readv-from-rt",
                      default=[], action="append")

    (options, _) = parser.parse_args()

    if not(options.operation):
        parser.error("Need to specify --attach or --detach")

    if not(options.port):
        parser.error("Need to specify --port <localport>")

    if not(options.network_type):
        parser.error("Need to specify --network-type")

    if not(options.ip):
        parser.error("Need to specify --ip")

    if (len(options.routeTargets) == 0 and
            not (options.importOnlyRouteTargets
                 or options.exportOnlyRouteTargets)):
        if options.network_type == "ipvpn":
            options.routeTargets = ["64512:512"]
        else:
            options.routeTargets = ["64512:513"]

    importRTs = copy(options.routeTargets or [])
    for rt in options.importOnlyRouteTargets:
        importRTs.append(rt)

    exportRTs = copy(options.routeTargets or [])
    for rt in options.exportOnlyRouteTargets:
        exportRTs.append(rt)

    if not re.match('.*/[0-9]+$', options.ip):
        options.ip = options.ip + "/24"

    if not(options.gw_ip):
        net = IPNetwork(options.ip)
        print "using %s as gateway address" % str(net[-2])
        options.gw_ip = str(net[-2])

    if options.vpn_instance_id == DEFAULT_VPN_INSTANCE_ID:
        options.vpn_instance_id = "%s-%s" % (
            options.network_type, options.vpn_instance_id)

    if options.port.startswith("netns"):

        if not options.netns:
            options.netns = options.vpn_instance_id

        try:
            (_, options.if2netns) = options.port.split(":")
        except:
            options.if2netns = get_vpn2ns_if_name(options.netns)

        if options.operation == "attach":
            createSpecialNetNSPort(options)

        options.port = options.if2netns
        if not options.mac:
            options.mac = get_device_mac(lambda *args: runCommand(log, *args),
                                         options.if2vpn, options.netns)

        print "Local port: %s (%s)" % (options.port, options.mac)
        runCommand(log, "ip link show %s" % options.port)

    local_port = {}
    if options.port[:5] == "evpn:":
        if (options.network_type == "ipvpn"):
            print "will plug evpn %s into the IPVPN" % options.port[5:]
            local_port['evpn'] = {'id': options.port[5:]}
        else:
            raise Exception("Can only plug an evpn into an ipvpn")
    else:
        local_port['linuxif'] = options.port

        # currently our only the MPLS OVS driver for ipvpn requires preplug
        if (options.ovs_preplug and options.network_type == "ipvpn"):
            print "pre-plugging %s into %s" % (options.port,
                                               options.bridge)
            runCommand(log, "ovs-vsctl del-port %s %s" %
                       (options.bridge, options.port),
                       raiseExceptionOnError=False)
            runCommand(log, "ovs-vsctl add-port %s %s" %
                       (options.bridge, options.port))

            local_port['ovs'] = {'port_name': options.port,
                                 'plugged': True}

            if options.ovs_vlan:
                local_port['ovs']['vlan'] = options.ovs_vlan

    if not options.mac:
        if options.network_type == IPVPN:
            options.mac = "52:54:00:99:99:22"
        else:
            parser.error("Need to specify --mac for an EVPN network "
                         "attachment if port is not 'netns'")

    readvertise = None
    if options.reAdvToRTs:
        readvertise = {"from_rt": options.reAdvFromRTs,
                       "to_rt": options.reAdvToRTs}

    json_data = json.dumps({"import_rt":  importRTs,
                            "export_rt":  exportRTs,
                            "local_port":  local_port,
                            "vpn_instance_id":  options.vpn_instance_id,
                            "vpn_type":    options.network_type,
                            "gateway_ip":  options.gw_ip,
                            "mac_address": options.mac,
                            "ip_address":  options.ip,
                            "advertise_subnet": options.advertiseSubnet,
                            "readvertise": readvertise
                            })

    print "request: %s" % json_data

    os.environ['NO_PROXY'] = "127.0.0.1"
    req = urllib2.Request("http://127.0.0.1:8082/%s_localport" %
                          options.operation, json_data,
                          {'Content-Type': 'application/json'})
    try:
        response = urllib2.urlopen(req)
        response_content = response.read()
        response.close()

        print "response: %d %s" % (response.getcode(), response_content)
    except urllib2.HTTPError as e:
        error_content = e.read()
        print "   %s" % error_content
        sys.exit("error %d, reason: %s" % (e.code, e.reason))
