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

import json

from netaddr.ip import IPNetwork

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver
from bagpipe.bgp.vpn.ipvpn import IPVPN

from bagpipe.bgp.common.looking_glass import LookingGlass, \
    LookingGlassLocalLogger, LGMap

from bagpipe.bgp.common import logDecorator

from socket import AF_INET
from pyroute2.common import AF_MPLS

from pyroute2 import IPDB
from pyroute2 import IPRoute
from pyroute2.netlink.rtnl import ndmsg

ipr = IPRoute()

LINUX_DEV_LEN = 14
VRF_INTERFACE_PREFIX = "bvrf-"

RT_TABLE_BASE = 1000

RT_PROT_BAGPIPE = 19

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


class MPLSLinuxVRFDataplane(VPNInstanceDataplane, LookingGlass):

    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

        # FIXME: maybe not thread safe ?
        self.ip = self.driver.ip

        self.vrf_if = ("%s%d" % (VRF_INTERFACE_PREFIX,
                                 self.instanceId))[:LINUX_DEV_LEN]

        self.rt_table = RT_TABLE_BASE + self.instanceId

        self.log.info("VRF %d: Initializing VRF interface %s",
                      self.instanceId, self.vrf_if)

        self.flush_routes()
        ### make sure we don't fallback into other routing tables ##
        # FIXME: this leaves a window between flush and add default where
        #        traffic can leak
        self.ip.routes.add({'dst': 'default',
                            'table': self.rt_table,
                            'type': 'unreachable'}).commit()

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
        ipr.flush_rules(iifname=self.vrf_if)
        ipr.flush_rules(oifname=self.vrf_if)
        ipr.rule('add', priority=100, iifname=self.vrf_if, table=self.rt_table,
                 action='FR_ACT_TO_TBL')
        ipr.rule('add', priority=100, oifname=self.vrf_if, table=self.rt_table,
                 action='FR_ACT_TO_TBL')
        #FIXME: to do for v6 as well, or v6 traffic will leak...

        # an alternative to the unreachable route above, would be to use
        # an ip rule, but I haven't got this to work yet
        # the rules are always hit, whatever the priority
        #         ipr.rule('add', priority=101, iifname=self.vrf_if,
        #                  action='FR_ACT_UNREACHABLE')
        #         ipr.rule('add', priority=101, oifname=self.vrf_if,
        #                  action='FR_ACT_UNREACHABLE')
        # the commands above result in :
        # 101:    from all iif vrf-1 lookup main unreachable
        # 101:    from all oif vrf-1 lookup main unreachable
        # the "lookup main" is unexpected and the result is a failed lookup for the packet
        #
        #         self._runCommand("ip rule add prio 101 iif %s unreachable" %
        #                          self.vrf_if)
        #         self._runCommand("ip rule add prio 101 iif %s unreachable" %
        #                          self.vrf_if)

        #TODO: map instance Label ?
        #  relevant only if it is advertised, which we don't do yet

    def add_route(self, route):
        route.update({'proto': RT_PROT_BAGPIPE})
        self.ip.routes.add(route).commit()

    def flush_routes(self):
        ipr.flush_routes(table=self.rt_table)

    @logDecorator.logInfo
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

    @logDecorator.logInfo
    def vifPlugged(self, macAddress, ipAddress, localPort, label):

        interface = localPort['linuxif']

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
                  dst=ipAddress,
                  lladdr=macAddress,
                  ifindex=self.ip.interfaces[interface].index,
                  state=ndmsg.states['permanent'])

        # Setup ARP proxying
        proxy_arp(interface, True)

        # Configure gateway address on this port
        # FIXME: that would need to be per vif port
        # Retrieve broadcast IP address
        broadcastIP = str(IPNetwork("%s/%s" % (self.gatewayIP, self.mask)
                                    ).broadcast)

        ipr.addr('add', index=self.ip.interfaces[interface].index,
                 address=self.gatewayIP, mask=self.mask,
                 broadcast=broadcastIP)

        # Configure mapping for incoming MPLS traffic
        # with this port label
        req = {'family': AF_MPLS,
               'oif': self.ip.interfaces[interface].index,
               'dst': label,  #FIXME how to check for BoS?
               'via': {'family': AF_INET,
                       'addr': ipAddress}
               }

        self.add_route(req)

    @logDecorator.logInfo
    def vifUnplugged(self, macAddress, ipAddress, localPort, label,
                     lastEndpoint=True):
        interface = localPort['linuxif']

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
        ip = IPNetwork("%s/%s" % (self.gatewayIP, self.mask))
        broadcastIP = str(ip.broadcast)

        ipr.addr('del', index=self.ip.interfaces[interface].index,
                 address=self.gatewayIP, mask=self.mask,
                 broadcast=broadcastIP)

        with self.ip.routes.tables['mpls'][label] as r:
            r.remove()

    def _read_mpls_in(self, label):
        routes = [r for r in self.ip.routes.tables["mpls"]
                  if r['dst'] == label]
        assert(len(routes)==1)
        res = (routes[0]['oif'], routes[0]['via']['addr'])
        self.log.debug("Found %s for %d with IPDB", res, label)
        return res

    def _nh(self, remotePE, label, encaps):
        mpls = True
        if str(remotePE) == self.driver.getLocalAddress():
            try:
                # if remotePE is ourselves
                # we lookup the route for the label and deliver directly
                # to this oif/gateway
                (oif, gateway) = self._read_mpls_in(label)
                mpls = False
                # FIXME: does not work yet, from this table,
                #        'gateway' is considered unreachable
                #        we could drop 'gateway' and just keep oif
                #        but this would only work for connected routes
                raise Exception("local MPLS shortcut not supported yet")
            except Exception as e:
                self.log.debug(e)
                gateway = '127.0.0.1'
                oif = self.ip.interfaces['lo'].index
        else:
            gateway = remotePE
            oif = self.driver.mpls_interface_index

        nh = {'oif': oif}
        if gateway:
            nh['gateway'] = gateway

        if mpls:
            nh['encap'] =  {'type': 'mpls',
                            'labels': [{'bos': 1,
                                        'label': label}]}
        self.log.debug("nh: %s", nh)
        return nh

    def _getRoute(self, prefix):
        return self.ip.routes.tables[self.rt_table][prefix]

    @logDecorator.logInfo
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        prefix = str(prefix)
        try:
            with self._getRoute(prefix) as r:
                self.log.debug("a route to %s already exists, adding nexthop",
                               prefix)
                r.add_nh(self._nh(remotePE, label, encaps))
        except KeyError:
            self.log.debug("no route to %s yet, creating", prefix)
            req =  {'table': self.rt_table,
                    'dst': prefix,
                    'multipath': [self._nh(remotePE, label, encaps)]}
            self.log.debug("adding route: %s", req)
            self.add_route(req)

    @logDecorator.logInfo
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        prefix = str(prefix)
        try:
            with self._getRoute(prefix) as r:
                #FIXME: encap info is missing here
                if r['multipath']:
                    r.del_nh(self._nh(remotePE, label, None))
                else:
                    r.remove()
                # NOTE: if the nexthop wass a direct/local, how
                #       can we retrieve it since its probably gone now...?
                #       will route be 'dead', what if there were many..?
                #       use weight as a way to balance and as a refcount?
        except KeyError:
            self.log.debug("no route found on "
                           "removeDataplaneForRemoteEndpoint")

    ## LG ##

    def getLGMap(self):
        return {"routes": (LGMap.SUBTREE, self.getLGRoutes),
                "route_table": (LGMap.VALUE, self.rt_table),
                "vrf_if": (LGMap.VALUE, self.vrf_if),
                }

    @logDecorator.logInfo
    def getLGRoutes(self, pathPrefix):
        routes = self.ip.routes.tables[self.rt_table]
        return [{r['dst']: json.loads(json.dumps(r, default=json_set_default))}
                for r in routes]


class MPLSLinuxDataplaneDriver(DataplaneDriver, LookingGlass):

    """
    This dataplane driver relies on the MPLS stack in the Linux kernel,
    and on linux vrf interfaces.
    """

    requiredKernel = "4.4"
    dataplaneInstanceClass = MPLSLinuxVRFDataplane
    type = IPVPN
    ecmpSupport = True

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self)

        self.ip = IPDB()

        DataplaneDriver.__init__(self, config, init)

    @logDecorator.logInfo
    def _initReal(self, config):
        self.config = config

        self._runCommand("modprobe mpls_router")
        self._runCommand("modprobe mpls_gso")
        self._runCommand("modprobe mpls_iptunnel")
        self._runCommand("modprobe vrf")

        sysctl('net.mpls.platform_labels', 2**20-1)

        if "*gre*" in self.config["mpls_interface"]:
            self.mpls_interface = "gre_wildcard"
            raise Exception("MPLS/GRE not supported yet")
        else:
            self.mpls_interface = self.config["mpls_interface"]

        sysctl('net.mpls.conf.%s.input' % self.mpls_interface, 1)

        self.mpls_interface_index = self.ip.interfaces[self.mpls_interface
                                                       ].index
        #for traffic from ourselves:
        sysctl('net.mpls.conf.lo.input', 1)

        # enable forwarding
        sysctl('net.ipv4.ip_forward', 1)

    @logDecorator.logInfo
    def resetState(self):
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
        ipr.flush_routes(family=AF_MPLS)

    def supportedEncaps(self):
        yield Encapsulation(Encapsulation.Type.MPLS)
        # we also accept route with no encap specified
        yield Encapsulation(Encapsulation.Type.DEFAULT)

    #### Looking glass ####

    def getLGMap(self):
        return {
                "mpls": (LGMap.SUBTREE, self.getLGMPLSRoutes),
        }

    def getLGMPLSRoutes(self, pathPrefix):
        return [{r['dst']: json.loads(json.dumps(r, default=json_set_default))}
                for r in self.ip.routes.tables['mpls']]
