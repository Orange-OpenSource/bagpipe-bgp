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

import errno
import socket

import netaddr
from oslo_config import cfg
from oslo_serialization import jsonutils
import pyroute2
from pyroute2 import netlink

from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp import constants as consts
from bagpipe.bgp.engine import exa
from bagpipe.bgp.vpn import dataplane_drivers as dp_drivers


ipr = pyroute2.IPRoute()

VRF_INTERFACE_PREFIX = "bvrf-"

RT_TABLE_BASE = 1000

RT_PROT_BAGPIPE = 19


# NOTE(tmorin): can this be removed ? (is jsonutils to_primitive() enough?)
def json_set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def sysctl(sysctl_path, val):
    if isinstance(sysctl_path, (tuple, list)):
        filename = ('/'.join(sysctl_path))
    else:
        filename = sysctl_path.replace('.', '/')
    filename = '/proc/sys/' + filename

    with open(filename, 'w') as f:
        f.write(str(val))


def proxy_arp(ifname, enable):
    sysctl(['net', 'ipv4', 'conf', ifname, 'proxy_arp'], int(enable))
    sysctl(['net', 'ipv4', 'conf', ifname, 'proxy_arp_pvlan'], int(enable))


class MPLSLinuxVRFDataplane(dp_drivers.VPNInstanceDataplane,
                            lg.LookingGlassMixin):

    def __init__(self, *args, **kwargs):
        dp_drivers.VPNInstanceDataplane.__init__(self, *args)

        # FIXME: maybe not thread safe ?
        self.ip = self.driver.ip

        self.vrf_if = ("%s%d" % (VRF_INTERFACE_PREFIX,
                                 self.instance_id))[:consts.LINUX_DEV_LEN]

        self.rt_table = RT_TABLE_BASE + self.instance_id

        self.log.info("VRF %d: Initializing VRF interface %s",
                      self.instance_id, self.vrf_if)

        self.flush_routes()

        self.log.debug("Creating VRF interface...")

        # Create VRF interface
        with self.ip.create(kind='vrf',
                            ifname=self.vrf_if,
                            vrf_table=self.rt_table,
                            reuse=True) as i:
            i.up()

        self.vrf_if_idx = i.index

        # Create ip rule for VRF route table
        # TODO: do in IPDB, when possible (check: what if
        #       rule exist, but is not known by IPDB?)
        for family in socket.AF_INET, socket.AF_INET6:
            ipr.flush_rules(family=family,
                            iifname=self.vrf_if)
            ipr.flush_rules(family=family,
                            oifname=self.vrf_if)

            ipr.rule('add', family=family,
                     priority=100, iifname=self.vrf_if, table=self.rt_table,
                     action='FR_ACT_TO_TBL')
            ipr.rule('add', family=family,
                     priority=100, oifname=self.vrf_if, table=self.rt_table,

                     action='FR_ACT_TO_TBL')

            # if VRF traffic does not match any route,
            # lookups must *not* fallback to main/default
            # routing table
            ipr.rule('add', family=family,
                     priority=101, iifname=self.vrf_if,
                     action='FR_ACT_UNREACHABLE')
            ipr.rule('add', family=family,
                     priority=101, oifname=self.vrf_if,
                     action='FR_ACT_UNREACHABLE')

    def add_route(self, route):
        route.update({'proto': RT_PROT_BAGPIPE})
        self.ip.routes.add(route).commit()

    def flush_routes(self):
        ipr.flush_routes(table=self.rt_table)

    @log_decorator.log_info
    def cleanup(self):
        # bring down and disconnect all interfaces from vrf interface
        with self.ip.interfaces[self.vrf_if_idx] as vrf:
            for interface in vrf.ports:
                with self.ip.interfaces[interface] as i:
                    i.down()
                vrf.del_port(interface)
            vrf.remove()
        ipr.flush_rules(iifname=self.vrf_if)
        ipr.flush_rules(oifname=self.vrf_if)
        self.flush_routes()

    @log_decorator.log_info
    def vif_plugged(self, mac_address, ip_address, localport, label):

        interface = localport['linuxif']

        if interface not in self.ip.interfaces:
            self.log.warning("interface %s not in interfaces, ignoring plug",
                             interface)
            return

        # ip link set dev localport master vrf_interface
        with self.ip.interfaces[self.vrf_if_idx] as vrf:
            vrf.add_port(interface)

        with self.ip.interfaces[interface] as i:
            i.up()

        # add static ARP entry toward interface (because we can)
        ipr.neigh('add',
                  dst=ip_address,
                  lladdr=mac_address,
                  ifindex=self.ip.interfaces[interface].index,
                  state=netlink.rtnl.ndmsg.states['permanent'])

        # Setup ARP proxying
        proxy_arp(interface, True)

        # Configure gateway address on this port
        # FIXME: that would need to be per vif port
        # Retrieve broadcast IP address
        broadcast_ip = str(netaddr.IPNetwork("%s/%s" % (self.gateway_ip,
                                                        self.mask)
                                             ).broadcast)

        try:
            ipr.addr('add', index=self.ip.interfaces[interface].index,
                     address=self.gateway_ip, mask=self.mask,
                     broadcast=broadcast_ip)
        except netlink.exceptions.NetlinkError as x:
            if x.code == errno.EEXIST:
                # the route already exists, fine
                self.log.warning("route %s already exists on %s",
                                 self.gateway_ip,
                                 interface)
                pass
            else:
                raise

        # Configure mapping for incoming MPLS traffic
        # with this port label
        req = {'family': pyroute2.common.AF_MPLS,
               'oif': self.ip.interfaces[interface].index,
               'dst': label,  # FIXME how to check for BoS?
               'via': {'family': socket.AF_INET,
                       'addr': ip_address}
               }

        try:
            self.add_route(req)
        except netlink.exceptions.NetlinkError as x:
            if x.code == errno.EEXIST:
                # the route already exists, fine
                self.log.warning("MPLS state for %d already exists", label)
                pass
            else:
                raise

    @log_decorator.log_info
    def vif_unplugged(self, mac_address, ip_address, localport, label,
                      last_endpoint=True):
        interface = localport['linuxif']

        if interface not in self.ip.interfaces:
            self.log.warning("interface %s not in interfaces, ignoring plug",
                             interface)
            return

        # bring the interface down, we don't want
        # traffic from this interface to leak out of the VRF
        with self.ip.interfaces[interface] as i:
            i.down()

        # Disable ARP proxying
        proxy_arp(interface, False)

        # ip link set dev localport master vrf_interface
        with self.ip.interfaces[self.vrf_if_idx] as i:
            i.del_port(interface)

        # Unconfigure gateway address on this port
        # FIXME: that would need to be per vif port
        # Retrieve broadcast IP address
        ip = netaddr.IPNetwork("%s/%s" % (self.gateway_ip, self.mask))
        broadcast_ip = str(ip.broadcast)

        ipr.addr('del', index=self.ip.interfaces[interface].index,
                 address=self.gateway_ip, mask=self.mask,
                 broadcast=broadcast_ip)

        with self.ip.routes.tables['mpls'][label] as r:
            r.remove()

    def _read_mpls_in(self, label):
        routes = [r for r in self.ip.routes.tables["mpls"]
                  if r['dst'] == label]
        assert len(routes) == 1
        res = (routes[0]['oif'], routes[0]['via']['addr'])
        self.log.debug("Found %s for %d with IPDB", res, label)
        return res

    def _nh(self, remote_pe, label, encaps):
        mpls = True
        if str(remote_pe) == self.driver.get_local_address():
            # FIXME: does not work yet, from this table,
            #        'gateway' is considered unreachable
            #        we could drop 'gateway' and just keep oif
            #        but this would only work for connected routes
            # if remote_pe is ourselves
            # we lookup the route for the label and deliver directly
            # to this oif/gateway
            # (oif, gateway) = self._read_mpls_in(label)
            # mpls = False
            gateway = '127.0.0.1'
            oif = self.ip.interfaces['lo'].index
        else:
            gateway = remote_pe
            oif = self.driver.mpls_interface_index

        nh = {'oif': oif}
        if gateway:
            nh['gateway'] = gateway

        if mpls:
            nh['encap'] = {'type': 'mpls',
                           'labels': [{'bos': 1,
                                       'label': label}]}
        self.log.debug("nh: %s", nh)
        return nh

    def _get_route(self, prefix):
        return self.ip.routes.tables[self.rt_table][prefix]

    @log_decorator.log_info
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        prefix = str(prefix)

        if prefix == "0.0.0.0/0":
            prefix = 'default'

        try:
            with self._get_route(prefix) as r:
                self.log.debug("a route to %s already exists, adding nexthop",
                               prefix)
                r.add_nh(self._nh(remote_pe, label, encaps))
        except KeyError:
            self.log.debug("no route to %s yet, creating", prefix)
            req = {'table': self.rt_table,
                   'dst': prefix,
                   'multipath': [self._nh(remote_pe, label, encaps)]}
            self.log.debug("adding route: %s", req)
            self.add_route(req)

    @log_decorator.log_info
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):
        prefix = str(prefix)

        if prefix == "0.0.0.0/0":
            prefix = 'default'

        try:
            with self._get_route(prefix) as r:
                # FIXME: encap info is missing here
                if r['multipath']:
                    r.del_nh(self._nh(remote_pe, label, None))
                else:  # last route
                    r.remove()

        except KeyError:
            self.log.warning("no route found on remove_dataplane_for"
                             "_remote_endpoint for %s", prefix)

    # Looking Glass ##

    def get_lg_map(self):
        return {"routes": (lg.SUBTREE, self.get_lg_routes),
                "route_table": (lg.VALUE, self.rt_table),
                "vrf_if": (lg.VALUE, self.vrf_if),
                }

    @log_decorator.log_info
    def get_lg_routes(self, path_prefix):
        routes = self.ip.routes.tables[self.rt_table]
        return [{r['dst']:
                 jsonutils.loads(jsonutils.dumps(r, default=json_set_default))}
                for r in routes]


class MPLSLinuxDataplaneDriver(dp_drivers.DataplaneDriver,
                               lg.LookingGlassMixin):

    """
    This dataplane driver relies on the MPLS stack in the Linux kernel,
    and on linux vrf interfaces.
    """

    required_kernel = "4.4"
    dataplane_instance_class = MPLSLinuxVRFDataplane
    type = consts.IPVPN
    ecmp_support = True

    driver_opts = [
        cfg.StrOpt("mpls_interface",
                   help=("Interface used to send/receive MPLS traffic. "
                         "Use '*gre*' to choose automatic creation of a tunnel"
                         " interface for MPLS/GRE encap")),
    ]

    def __init__(self, config):
        lg.LookingGlassLocalLogger.__init__(self)

        self.log.info("Initializing MPLSLinuxVRFDataplane")
        dp_drivers.DataplaneDriver.__init__(self, config)

        self.config = config
        self.ip = pyroute2.IPDB()

    @log_decorator.log_info
    def initialize(self):
        self._run_command("modprobe mpls_router")
        self._run_command("modprobe mpls_gso")
        self._run_command("modprobe mpls_iptunnel")
        self._run_command("modprobe vrf")

        sysctl('net.mpls.platform_labels', 2**20-1)

        if "*gre*" in self.config["mpls_interface"]:
            self.mpls_interface = "gre_wildcard"
            raise Exception("MPLS/GRE not supported yet")
        else:
            self.mpls_interface = self.config["mpls_interface"]

        sysctl('net.mpls.conf.%s.input' % self.mpls_interface, 1)

        self.mpls_interface_index = self.ip.interfaces[self.mpls_interface
                                                       ].index
        # for traffic from ourselves:
        sysctl('net.mpls.conf.lo.input', 1)

        # enable forwarding
        sysctl('net.ipv4.ip_forward', 1)

    @log_decorator.log_info
    def reset_state(self):
        # remove all VRF interfaces
        for itf in self.ip.interfaces.keys():
            if isinstance(itf, str) and itf.startswith(VRF_INTERFACE_PREFIX):
                # bring the interface vrf slave interfaces down,
                # we don't want traffic from these interfaces
                # to leak out of the VRF after removal of VRF interface
                for index in self.ip.interfaces[itf].ports:
                    with self.ip.interfaces[index] as port:
                        port.down()

                ipr.link('del', ifname=itf)
        # Flush all routes setup by us in past runs
        ipr.flush_routes(proto=RT_PROT_BAGPIPE)
        # Flush all MPLS routes redirecting traffic to network namespaces
        # (just in case, should be covered by the above)
        ipr.flush_routes(family=pyroute2.common.AF_MPLS)

    def supported_encaps(self):
        yield exa.Encapsulation(exa.Encapsulation.Type.MPLS)
        # we also accept route with no encap specified
        yield exa.Encapsulation(exa.Encapsulation.Type.DEFAULT)

    # Looking glass ####

    def get_lg_map(self):
        return {"mpls": (lg.SUBTREE, self.get_lg_mpls_routes),
                }

    def get_lg_mpls_routes(self, path_prefix):
        return [{r['dst']: json.loads(json.dumps(r, default=json_set_default))}
                for r in self.ip.routes.tables['mpls']]
