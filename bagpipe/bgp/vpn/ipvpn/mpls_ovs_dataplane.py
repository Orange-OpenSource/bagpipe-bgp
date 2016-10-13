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

import re

from distutils.version import StrictVersion

from netaddr.ip import IPNetwork

from oslo_config import cfg

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver
from bagpipe.bgp.vpn import dataplane_drivers
from bagpipe.bgp.vpn.ipvpn import IPVPN

from bagpipe.bgp.common import exceptions as exc
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import log_decorator
from bagpipe.bgp.common import net_utils

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation

DEFAULT_RULE_PRIORITY = 40000

DEFAULT_ARPNS_IF_MTU = 9000

#  grep 'define.*IFNAMSIZ' /usr/src/linux/include/uapi/linux/if.h
# define    IFNAMSIZ    16
# (minus 1 for trailing null)
LINUX_DEV_LEN = 15

OVSBR2ARPNS_INTERFACE_PREFIX = "toarpns"

# name of the veth device in the ARP proxy network namespace,
#  whose remote end is plugged in the OVS bridge
PROXYARP2OVS_IF = "ovs"

ARPNETNS_PREFIX = "arp-vrf"

NO_MPLS_PHY_INTERFACE = -1

VXLAN_TUNNEL = "vxlan"

OVS_DUMP_FLOW_FILTER = "| grep -v NXST_FLOW | perl -pe '"               \
    "s/ *cookie=[^,]+, duration=[^,]+, table=[^,]+, //;" \
    "s/ *n_bytes=[^,]+, //; "                            \
    "s/ *(hard|idle)_age=[^,]+, //g; "                   \
    "s/n_packets=([0-9]),/packets=$1    /; "             \
    "s/n_packets=([0-9]{2}),/packets=$1   /; "           \
    "s/n_packets=([0-9]{3}),/packets=$1  /; "            \
    "s/n_packets=([0-9]+),/packets=$1 /; "               \
    "'"

GATEWAY_MAC = "00:00:5e:00:43:64"

VRF_REGISTER = 0
LB_HOP_REGISTER = 1


def get_ovsbr2arpns_if(namespace_id):
    i = namespace_id.replace(ARPNETNS_PREFIX, "")
    return (OVSBR2ARPNS_INTERFACE_PREFIX + i)[:LINUX_DEV_LEN]


def join_s(*args):
    return ','.join(filter(None, args))


class MPLSOVSVRFDataplane(VPNInstanceDataplane, lg.LookingGlassMixin):

    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

        self.arp_netns = ("%s%d" % (ARPNETNS_PREFIX,
                                    self.instance_id))[:LINUX_DEV_LEN]

        # Initialize dict where we store info on OVS ports (port numbers and
        # bound IP address)
        self._ovs_port_info = dict()

        # Initialize dict where we store label, remote_pe and
        # lb_consistent_hash_order infos list per prefix for remote endpoints
        # load balancing
        self._lb_endpoints = dict()

        # Find ethX MPLS interface MAC address
        # NOTE(tmorin): this can be moved in dataplane driver class
        if not self.driver.use_gre:
            self.mpls_if_mac_address = net_utils.get_device_mac(
                self._run_command,
                self.driver.mpls_interface)
        else:
            self.mpls_if_mac_address = None

        self.bridge = self.driver.bridge

        self.fallback = None
        self.push_vlan_action = None

        if self.driver.proxy_arp:
            self._init_arp_netns()

    def _init_arp_netns(self):
        self.log.info("VRF %d: Initializing network namespace %s for ARP "
                      "proxing", self.instance_id, self.arp_netns)
        # Get names of veth pair devices between OVS and network namespace

        ovsbr_to_proxyarp_ns = get_ovsbr2arpns_if(self.arp_netns)

        if not self._arp_net_ns_exists():
            self.log.debug("VRF network namespace doesn't exist, creating...")
            # Create network namespace
            self._run_command("ip netns add %s" % self.arp_netns,
                              run_as_root=True)

            # Set up veth pair devices between OVS and ARP network namespace
            self._create_arp_netns_veth_pair(ovsbr_to_proxyarp_ns,
                                             PROXYARP2OVS_IF)

            # Force MAC address of netns-to-OVS port
            net_utils.set_device_mac(self._run_command,
                                     PROXYARP2OVS_IF,
                                     GATEWAY_MAC,
                                     self.arp_netns)

            # Retrieve broadcast IP address
            ip = IPNetwork("%s/%s" % (self.gateway_ip, self.mask))
            broadcast_ip = str(ip.broadcast)

            # Set up network namespace interface as gateway
            self._run_command("ip netns exec %s ip addr add %s/%s broadcast %s"
                              " dev %s" %
                              (self.arp_netns, self.gateway_ip,
                               self.mask, broadcast_ip, PROXYARP2OVS_IF),
                              run_as_root=True,
                              raise_on_error=True)

            # Setup IP forwarding
            self._run_command("ip netns exec %s sh -c \"echo 1 > /proc/sys"
                              "/net/ipv4/ip_forward\"" % self.arp_netns,
                              run_as_root=True,
                              shell=True)
            self._run_command("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                              "/ipv4/conf/all/forwarding\"" % self.arp_netns,
                              run_as_root=True,
                              shell=True)

            # Setup ARP proxying
            self._run_command("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                              "/ipv4/conf/%s/proxy_arp\"" %
                              (self.arp_netns, PROXYARP2OVS_IF),
                              run_as_root=True,
                              shell=True)
            self._run_command("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                              "/ipv4/conf/%s/proxy_arp_pvlan\"" %
                              (self.arp_netns, PROXYARP2OVS_IF),
                              run_as_root=True,
                              shell=True)
        else:
            self.log.debug("VRF network namespace already exists...")

        # OVS port number for the port toward the proxy ARP netns
        self.arp_net_nsport = self.driver.find_ovs_port(ovsbr_to_proxyarp_ns)

        # Map IP traffic from plugged ports to ARP/GW netns
        self._ovs_flow_add(self._vrf_match('nw_dst=%s' % self.gateway_ip),
                           'output:%s' % self.arp_net_nsport,
                           self.driver.vrf_table)

        # Map ARP traffic from plugged port to ARP/GW netns
        # (rule to flow ARP response from GW to plugged port is added in
        # vif_plugged)
        self._ovs_flow_add(self._vrf_match(None, proto="arp"),
                           'output:%s' % self.arp_net_nsport,
                           self.driver.vrf_table)

    @log_decorator.log_info
    def cleanup(self):
        if self._ovs_port_info:
            self.log.warning("OVS port numbers list for local ports plugged in"
                             " VRF is not empty, clearing...")
            self._ovs_port_info.clear()

        # Remove all flows for this instance
        for table in self.driver.all_tables.values():
            self._ovs_flow_del(None, table)

        if self.driver.proxy_arp:
            self.log.info("Cleaning VRF network namespace %s", self.arp_netns)
            # Detach network namespace veth pair device from OVS bridge
            self._run_command(
                "ovs-vsctl del-port %s %s" %
                (self.bridge, get_ovsbr2arpns_if(self.arp_netns)),
                run_as_root=True)
            # Delete network namespace (deletes the veth pair as well)
            self._run_command("ip netns delete %s" % self.arp_netns,
                              run_as_root=True)

    def _arp_net_ns_exists(self):
        """ Check if network namespace exist. """
        (_, code) = self._run_command("ip netns pids %s" % self.arp_netns,
                                      acceptable_return_codes=[0, 1],
                                      run_as_root=True)
        return code == 0

    def _create_arp_netns_veth_pair(self, ovsbr_to_proxyarp_ns,
                                    proxyarp_ns_to_ovsbr):
        """ Create a pair of veth devices, one end being created in the ARP
        netns """

        try:
            self._run_command("ip netns exec %s ip link del %s" %
                              (self.arp_netns, proxyarp_ns_to_ovsbr),
                              run_as_root=True,
                              raise_on_error=False,
                              acceptable_return_codes=[0, 1])
            self._run_command("ip link del %s" % ovsbr_to_proxyarp_ns,
                              run_as_root=True,
                              raise_on_error=False,
                              acceptable_return_codes=[0, 1])
            self._run_command("ip link add %s mtu 65535 type veth peer name "
                              "%s netns %s" % (ovsbr_to_proxyarp_ns,
                                               proxyarp_ns_to_ovsbr,
                                               self.arp_netns),
                              run_as_root=True,
                              acceptable_return_codes=[0, 2])
            self._run_command("ip link set dev %s up" % ovsbr_to_proxyarp_ns,
                              run_as_root=True)
            self._run_command("ip netns exec %s ip link set dev %s up" %
                              (self.arp_netns, proxyarp_ns_to_ovsbr),
                              run_as_root=True)
            self._run_command("ovs-vsctl del-port %s %s" %
                              (self.bridge, ovsbr_to_proxyarp_ns),
                              run_as_root=True,
                              raise_on_error=False,
                              acceptable_return_codes=[0, 1, 2])
            self._run_command("ovs-vsctl add-port %s %s" %
                              (self.bridge, ovsbr_to_proxyarp_ns),
                              run_as_root=True)
        except Exception:
            self._run_command("ovs-vsctl del-port %s %s" %
                              (self.bridge, ovsbr_to_proxyarp_ns),
                              run_as_root=True,
                              raise_on_error=False,
                              acceptable_return_codes=[0, 1, 2])
            self._run_command("ip netns exec %s ip link del %s" %
                              (self.arp_netns, proxyarp_ns_to_ovsbr),
                              run_as_root=True,
                              raise_on_error=False)
            self._run_command("ip link del %s" % ovsbr_to_proxyarp_ns,
                              run_as_root=True,
                              raise_on_error=False)
            raise

    @log_decorator.log
    def _extract_mac_address(self, output):
        """ Extract MAC address from command output """
        return re.search(r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", output,
                         re.IGNORECASE).group()

    def _find_remote_mac_address(self, remote_ip):
        """ Find MAC address for a remote IP address """
        # PING remote IP address
        (_, exit_code) = self._run_command("fping -r4 -t100 -q %s" % remote_ip,
                                           raise_on_error=False,
                                           acceptable_return_codes=[-1])
        if exit_code != 0:
            raise exc.RemotePEMACAddressNotFound(remote_ip)

        # Look in ARP cache to find remote MAC address
        (output, _) = self._run_command("ip neigh show to %s" % (remote_ip))

        if not output or "FAILED" in output[0]:
            raise exc.RemotePEMACAddressNotFound(remote_ip)

        return self._extract_mac_address(output[0])

    def _mtu_fixup(self, localport):
        '''
        This is a hack, proper MTUs should actually be configured in the
        hybrid vif driver

        --Obsolete--
        '''

        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            self.log.debug("No ovsbr_interfaces_mtu specified in config file,"
                           " not trying to fixup MTU")
            return

        try:
            itf = localport['ovs']['port_name']
        except KeyError:
            self.log.warning("No OVS port name provided, cannot fix MTU")
            return

        self.log.info("Will adjust %s if with MTU %s "
                      "(ovsbr_interfaces_mtu specified in config)", itf, mtu)

        (_, exit_code) = self._run_command("ip link show %s" % itf,
                                           raise_on_error=False,
                                           acceptable_return_codes=[0, 1])

        if exit_code != 0:
            self.log.warning("No %s if, not trying to fix MTU", itf)
        else:
            self._run_command("ip link set %s mtu %s" % (itf, mtu),
                              run_as_root=True)

    def _get_ovs_port_specifics(self, localport):
        """
        Returns a tuple of:
        - OVS port numbers:
            - First port number is the port for traffic from the VM.
            - Second port number is the port for traffic to the VM.
        - OVS actions and rules, based on whether or not a vlan is specified
          in localport:
            - OVS port match rule
            - OVS push vlan action
            - OVS strip vlan action
        - Port unplug action

        For OVS actions, if no VLAN is specified the localport match only
        matches the OVS port and actions are empty strings.
        """
        # Retrieve OVS port numbers and port unplug action
        try:
            port_unplug_action = None
            if ('ovs' in localport and localport['ovs']['plugged']):
                try:
                    port = localport['ovs']['port_number']
                except KeyError:
                    self.log.info("No OVS port number provided, trying to use"
                                  " a port name")
                    port = self.driver.find_ovs_port(
                        localport['ovs']['port_name'])
            else:
                port_name = ""
                try:
                    try:
                        port_name = localport['ovs']['port_name']
                    except KeyError as e:
                        port_name = localport['linuxif']
                except:
                    raise Exception("Trying to find which port to plug, but no"
                                    " portname was provided")

                try:
                    port = self.driver.find_ovs_port(port_name)
                except:
                    self._run_command("ovs-vsctl --may-exist add-port %s %s" %
                                      (self.bridge, port_name),
                                      run_as_root=True)
                    port = self.driver.find_ovs_port(port_name)
                self.log.debug("Corresponding port number: %s", port)

                # Set port unplug action
                port_unplug_action = "ovs-vsctl del-port %s %s" % (
                    self.bridge, port_name)

        except KeyError as e:
            self.log.error("Incomplete port specification: %s", e)
            raise Exception("Incomplete port specification: %s" % e)

        try:
            port2vm = localport['ovs']['to_vm_port_number']
        except KeyError:
            self.log.debug("No specific OVS port number provided for traffic "
                           "to VM, trying to use a port name")
            try:
                port2vm = self.driver.find_ovs_port(
                    localport['ovs']['to_vm_port_name'])
            except KeyError:
                self.log.debug("No specific OVS port found for traffic to VM")
                port2vm = port

        # Create OVS actions
        try:
            localport_match, push_vlan_action = (
                "in_port=%s,dl_vlan=%d" % (
                    port, int(localport['ovs']['vlan'])),
                "push_vlan:0x8100,mod_vlan_vid:%d," % int(
                    localport['ovs']['vlan'])
            )
        except KeyError:
            localport_match, push_vlan_action = (
                "in_port=%s" % port,
                None
            )

        return (port, port2vm, localport_match, push_vlan_action,
                port_unplug_action)

    @log_decorator.log_info
    def update_fallback(self, fallback=None):
        if fallback:
            self.fallback = fallback

        if not self.fallback:
            return

        vlan_action = ""
        if self.push_vlan_action:
            vlan_action = self.push_vlan_action

        for param in ('src_mac', 'dst_mac', 'ovs_port_number'):
            if not self.fallback.get(param):
                self.log.error("fallback specified without '%s'", param)
                return

        # use priority -1 so that the route only hits when the packet
        # does not matches any VRF route
        self._ovs_flow_add(self._vrf_match(None, proto=None),
                           'mod_dl_src=%s,mod_dl_dst=%s,%soutput:%d' %
                           (self.fallback.get('src_mac'),
                            self.fallback.get('dst_mac'),
                            vlan_action,
                            self.fallback.get('ovs_port_number')),
                           self.driver.vrf_table,
                           DEFAULT_RULE_PRIORITY-1)

    def _check_vlan_use(self, push_vlan_action):
        # checks that if a vlan_action is used, it is the same
        # for all interfaces plugged into the VRF,
        # and returns a string definition of (if any)
        # push and strip_vlan action to apply

        # on first plug we update
        if self.push_vlan_action is None:
            self.push_vlan_action = push_vlan_action
        else:
            # on a subsequent plug, we check
            if self.push_vlan_action != push_vlan_action:
                self.log.error("different VLAN for different interfaces: "
                               "%s vs %s", self.push_vlan_action,
                               push_vlan_action)
                raise Exception("can't specify a different VLAN for different"
                                " interfaces")

        if self.push_vlan_action is None:
            return ("", "")
        else:
            return (push_vlan_action, "strip_vlan,")

    @log_decorator.log
    def vif_plugged(self, mac_address, ip_address, localport, label):

        (ovs_port_from_vm, ovs_port_to_vm, localport_match,
         push_vlan_action, port_unplug_action) = (
            self._get_ovs_port_specifics(localport)
        )

        (push_vlan_action_str, strip_vlan_action_str) = (
            self._check_vlan_use(push_vlan_action))

        # need to update fallback, in case it was called before the
        # first vifPlugged call could define the push_vlan action
        self.update_fallback()

        # This is a hack used with previous versions of Openstack
        #  proper MTUs should actually be configured in the hybrid vif driver
        # Please consider this obsolete until it gets clean'd up
        self._mtu_fixup(localport)

        # Map traffic from plugged port to VRF
        actions = '%sset_field:%d->reg%d,resubmit(,%d)' % (
            strip_vlan_action_str, self.instance_id, VRF_REGISTER,
            self.driver.vrf_table
        )
        for proto in ('ip', 'arp'):
            self._ovs_flow_add(join_s(localport_match, proto),
                               actions,
                               self.driver.input_table)

        if self.driver.proxy_arp:
            # Map ARP and IP traffic from ARP/GW netns to plugged port

            # Map IP traffic from gateway to plugged port
            self._ovs_flow_add(
                join_s('in_port=%s' % self.arp_net_nsport,
                       'ip',
                       'nw_dst=%s' % ip_address),
                '%soutput:%s' % (push_vlan_action_str, ovs_port_to_vm),
                self.driver.input_table)

            # 'ovs_port_from_vm' is used to send ARP replies to the VM because
            # the interface plugged into the bridge may be an OVS patch port
            # with an OVS bridge doing MAC learning and we want this learning
            # bridge to learn the gw MAC via the right interface so that the
            # traffic from the VM to the gw will arrive on our OVS bridge
            # through 'ovs_from_from_vm'
            self._ovs_flow_add(
                join_s('in_port=%s' % self.arp_net_nsport,
                       'arp',
                       'dl_dst=%s' % mac_address),
                '%soutput:%s' % (push_vlan_action_str, ovs_port_from_vm),
                self.driver.input_table)

        # Map incoming MPLS traffic going to the VM port
        incoming_actions = ("%smod_dl_src:%s,mod_dl_dst:%s,output:%s" %
                            (push_vlan_action_str, GATEWAY_MAC,
                             mac_address, ovs_port_to_vm))

        self._ovs_flow_add(self._match_mpls_in(label),
                           "pop_mpls:0x0800,%s" % incoming_actions,
                           self.driver.encap_in_table)

        # additional incoming traffic rule for VXLAN
        if self.driver.vxlan_encap:
            self._ovs_flow_add(self._match_vxlan_in(label),
                               incoming_actions,
                               self.driver.encap_in_table)

        # Add OVS port number in list for local port plugged in VRF
        # FIXME: check check check, is linuxif the right key??
        self.log.debug("Adding OVS port %s with numbers (%s,%s) for address "
                       "%s to ports plugged in VRF list",
                       localport['linuxif'], ovs_port_from_vm, ovs_port_to_vm,
                       ip_address)
        self._ovs_port_info[localport['linuxif']] = {
            "localport_match": localport_match,
            "port_unplug_action": port_unplug_action,
        }

    def _match_mpls_in(self, label):
        return 'mpls,mpls_label=%d,mpls_bos=1' % label

    def _match_vxlan_in(self, vnid):
        return ('in_port=%s,tun_id=%d' %
                (self.driver.vxlan_tunnel_port_number, vnid))

    @log_decorator.log
    def vif_unplugged(self, mac_address, ip_address, localport, label,
                      last_endpoint=True):

        localport_match = self._ovs_port_info[
            localport['linuxif']]['localport_match']
        port_unplug_action = self._ovs_port_info[
            localport['linuxif']]['port_unplug_action']

        # Unmap incoming MPLS traffic going to the VM port
        self._ovs_flow_del(self._match_mpls_in(label),
                           self.driver.encap_in_table)

        # Unmap incoming VXLAN traffic...
        if self.driver.vxlan_encap:
            self._ovs_flow_del(self._match_vxlan_in(label),
                               self.driver.encap_in_table)

        # Unmap all traffic from plugged port
        if last_endpoint:
            self._ovs_flow_del(localport_match, self.driver.input_table)

        if self.driver.proxy_arp:
            # Unmap IP traffic from ARP/GW netns to plugged port
            self._ovs_flow_del(
                join_s('in_port=%s' % self.arp_net_nsport,
                       'ip',
                       'nw_dst=%s' % ip_address),
                self.driver.input_table)

            # Unmap ARP traffic from ARP/GW netns to plugged port
            self._ovs_flow_del(
                join_s('in_port=%s' % self.arp_net_nsport,
                       'arp',
                       'dl_dst=%s' % mac_address),
                self.driver.input_table)

        if last_endpoint:
            if port_unplug_action:
                # Run port unplug action if necessary (OVS port delete)
                self._run_command(port_unplug_action,
                                  run_as_root=True,
                                  acceptable_return_codes=[0, 1])

            # Remove OVS port number from list for local port plugged in VRF
            del self._ovs_port_info[localport['linuxif']]

    def _match_label_action(self, label, encaps):
        if (self.driver.vxlan_encap and
                Encapsulation(Encapsulation.Type.VXLAN) in encaps):
            return "set_field:%d->tunnel_id" % label
        else:
            return "push_mpls:0x8847,load:%s->OXM_OF_MPLS_LABEL[]" % label

    def _match_output_action(self, remote_pe, encaps):
        # Check if prefix is from a local VRF
        if self.driver.get_local_address() == str(remote_pe):
            self.log.debug("Local route, using a resubmit action")
            # For local traffic, we have to use a resubmit action
            if (self.driver.vxlan_encap and
                    Encapsulation(Encapsulation.Type.VXLAN) in encaps):
                return ("resubmit(%d,%d)" %
                        (self.driver.vxlan_tunnel_port_number,
                         self.driver.encap_in_table))
            else:
                return "resubmit(%d,%d)" % (self.driver.mpls_in_port(),
                                            self.driver.encap_in_table)
        else:
            if (self.driver.vxlan_encap and
                    Encapsulation(Encapsulation.Type.VXLAN) in encaps):
                self.log.debug("Will use a VXLAN encap for this destination")
                return "set_field:%s->tun_dst,output:%s" % (
                    str(remote_pe), self.driver.vxlan_tunnel_port_number)
            elif self.driver.use_gre:
                self.log.debug("Using MPLS/GRE encap")
                return "set_field:%s->tun_dst,output:%s" % (
                    str(remote_pe), self.driver.gre_tunnel_port_number)
            else:
                self.log.debug("Using bare MPLS encap")
                # Find remote router MAC address
                try:
                    remote_pe_mac_address = self._find_remote_mac_address(
                        remote_pe)
                    self.log.debug("MAC address found for remote router "
                                   "%(remote_pe)s: %(remote_pe_mac_address)s",
                                   locals())
                except exc.RemotePEMACAddressNotFound as e:
                    self.log.error("An error occured during setupDataplaneFor"
                                   "RemoteEndpoint: %s", e)
                    raise

                # Map traffic to remote IP address as MPLS on ethX to remote
                # router MAC address
                return "mod_dl_src:%s,mod_dl_dst:%s,output:%s" % (
                    self.mpls_if_mac_address, remote_pe_mac_address,
                    self.driver.ovs_mpls_if_port_number)

    def _match_default_route_prefix(self, prefix):
        return ('nw_dst=%s' % prefix if IPNetwork(prefix).prefixlen != 0
                else None)

    def _cookie(self, add=False):
        mask = ""
        if not add:
            mask = "/-1"
        return "cookie=%d%s" % (self.instance_id, mask)

    def _vrf_match(self, match, proto="ip"):
        return join_s('reg%d=%d' % (VRF_REGISTER, self.instance_id),
                      proto, match)

    def _vrf_lb_match(self, index, match):
        return self._vrf_match(join_s('reg%d=%d' % (LB_HOP_REGISTER, index),
                                      match))

    def _get_lb_flows_to_add(self, prefix, nw_dst_match):
        dec_ttl_action = ""
        if IPNetwork(prefix) not in IPNetwork("%s/%s" % (self.gateway_ip,
                                                         self.mask)):
            dec_ttl_action = "dec_ttl"

        flows_to_add = []
        for index, endpoint in enumerate(self._lb_endpoints[prefix]):
            label_action = self._match_label_action(endpoint['label'],
                                                    endpoint['encaps'])
            output_action = self._match_output_action(endpoint['remote_pe'],
                                                      endpoint['encaps'])

            lb_endpoint_flow = self._ovs_flow_add(
                self._vrf_lb_match(index, nw_dst_match),
                join_s(dec_ttl_action,
                       label_action,
                       output_action),
                self.driver.post_hash_vrf_table,
                return_flow=True)

            flows_to_add.append(('add', lb_endpoint_flow))

        return flows_to_add

    def _get_lb_flows_to_del(self, prefix, nw_dst_match):
        flows_to_del = []
        for index, _ in enumerate(self._lb_endpoints[prefix]):
            lb_endpoint_flow = self._ovs_flow_del(
                self._vrf_lb_match(index, nw_dst_match),
                self.driver.post_hash_vrf_table,
                return_flow=True)
            flows_to_del.append(('del', lb_endpoint_flow))

        return flows_to_del

    def _get_lb_multipath_flow_mod(self, prefix, nw_dst_match):
        self.log.debug('Prefix %s: nw_dst_match "%s", %s', prefix,
                       nw_dst_match, self._lb_endpoints[prefix])

        if self._lb_endpoints[prefix]:
            multipath_action = ('multipath(symmetric_l3l4+udp,1024,hrw,%d,0,'
                                'NXM_NX_REG%d[])' % (
                                    len(self._lb_endpoints[prefix]),
                                    LB_HOP_REGISTER
                                ))
            multipath_output = (
                'resubmit(,%d)' % self.driver.post_hash_vrf_table)

            lb_multipath_flow = self._ovs_flow_add(
                self._vrf_match(nw_dst_match),
                join_s(multipath_action, multipath_output),
                self.driver.vrf_table,
                return_flow=True)
            self.log.debug('Multipath flow: %s', lb_multipath_flow)
            if len(self._lb_endpoints[prefix]) > 1:
                return 'modify_strict', lb_multipath_flow
            else:
                return 'add', lb_multipath_flow
        else:
            lb_multipath_flow = (
                self._ovs_flow_del(self._vrf_match(nw_dst_match),
                                   self.driver.vrf_table,
                                   strict=True,
                                   return_flow=True)
            )
            return 'delete_strict', lb_multipath_flow

    @log_decorator.log_info
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps,
                                            lb_consistent_hash_order=0):
        # FIXME: use a priority depending on the prefix len
        #        to compensate the fact that "OpenFlow  leaves  behavior
        #        undefined when two or more flows with the same priority
        #        can match a single packet.  Some users expect ``sensible''
        #        behavior, such as more specific flows taking precedence
        #        over less specific flows, but OpenFlow does not specify
        #        this and Open vSwitch does not implement it.  Users should
        #        therefore  take  care  to  use  priorities  to ensure the
        #        behavior that they expect.
        lb_endpoint_info = {
            'label': label,
            'remote_pe': remote_pe,
            'encaps': encaps,
            'lb_consistent_hash_order': lb_consistent_hash_order
        }

        if (prefix in self._lb_endpoints and
                lb_endpoint_info in self._lb_endpoints[prefix]):
            return

        # Check if prefix is a default route
        nw_dst_match = self._match_default_route_prefix(prefix)

        lb_flows = list()
        if prefix in self._lb_endpoints:
            lb_flows.extend(self._get_lb_flows_to_del(prefix, nw_dst_match))
        else:
            self._lb_endpoints[prefix] = list()

        self._lb_endpoints[prefix].insert(lb_consistent_hash_order,
                                          lb_endpoint_info)

        lb_flows.append(self._get_lb_multipath_flow_mod(prefix, nw_dst_match))

        lb_flows.extend(self._get_lb_flows_to_add(prefix, nw_dst_match))

        self.driver._ovs_flow_mods(lb_flows)

    @log_decorator.log_info
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri, encaps,
                                             lb_consistent_hash_order=0):
        # Check if prefix is a default route
        nw_dst_match = self._match_default_route_prefix(prefix)

        if prefix in self._lb_endpoints:
            lb_flows = []

            lb_flows.extend(self._get_lb_flows_to_del(prefix, nw_dst_match))

            self._lb_endpoints[prefix].remove(
                {'label': label,
                 'remote_pe': remote_pe,
                 'encaps': encaps,
                 'lb_consistent_hash_order': lb_consistent_hash_order}
            )

            lb_flows.append(self._get_lb_multipath_flow_mod(prefix,
                                                            nw_dst_match))

            if self._lb_endpoints[prefix]:
                lb_flows.extend(self._get_lb_flows_to_add(prefix,
                                                          nw_dst_match))
            else:
                del self._lb_endpoints[prefix]

            self.driver._ovs_flow_mods(lb_flows)

    def _create_flow_match_from_tc(self, classifier):
        flow_match = ''
        if classifier.source_pfx:
            flow_match += ',nw_src=%s' % classifier.source_pfx
        if classifier.destination_pfx:
            flow_match += ',nw_dst=%s' % classifier.destination_pfx
        if classifier.source_port:
            if type(classifier.source_port) == tuple:
                port_min, port_max = classifier.source_port
                flow_match += ',tp_src=%d' % port_min
                flow_match += '/%d' % 65535 - (port_max - port_min)
            else:
                flow_match += ',tp_src=%d' % classifier.source_port
        if classifier.destination_port:
            if type(classifier.destination_port) == tuple:
                port_min, port_max = classifier.destination_port
                flow_match += ',tp_dst=%d' % port_min
                flow_match += '/%d' % 65535 - (port_max - port_min)
            else:
                flow_match += ',tp_dst=%d' % classifier.destination_port

        return flow_match

    @log_decorator.log_info
    def add_dataplane_for_traffic_classifier(self, classifier,
                                             redirect_to_instance_id):
        flow_match = self._create_flow_match_from_tc(classifier)

        # Add traffic redirection to redirection VRF
        self._ovs_flow_add(self._vrf_match('%s%s' % (classifier.protocol,
                                                     flow_match)),
                           'set_field:%d->reg%d,resubmit(,%d)' % (
                               redirect_to_instance_id, VRF_REGISTER,
                               self.driver.vrf_table
                               ),
                           self.driver.vrf_table)

    @log_decorator.log_info
    def remove_dataplane_for_traffic_classifier(self, classifier):
        flow_match = self._create_flow_match_from_tc(classifier)

        # Remove traffic redirection
        self._ovs_flow_del(self._vrf_match('%s%s' % (classifier.protocol,
                                                     flow_match)),
                           self.driver.vrf_table)

    def _ovs_flow_add(self, flow, actions, table, return_flow=False,
                      priority=DEFAULT_RULE_PRIORITY):
        return self.driver._ovs_flow_add(join_s(self._cookie(add=True),
                                                flow),
                                         actions, table, return_flow, priority)

    def _ovs_flow_del(self, flow, table, return_flow=False,
                      priority=DEFAULT_RULE_PRIORITY, strict=False):
        priority_spec = None
        if strict:
            priority_spec = "priority=%d" % priority
        return self.driver._ovs_flow_del(
            join_s(self._cookie(add=False),
                   priority_spec,
                   flow),
            table, return_flow)

    def get_lg_map(self):
        return {
            "flows": (lg.SUBTREE, self.get_lg_ovs_flows)
        }

    def get_lg_ovs_flows(self, path_prefix):
        return self.driver.get_lg_ovs_flows(path_prefix,
                                            self._cookie(add=False))


class MPLSOVSDataplaneDriver(DataplaneDriver, lg.LookingGlassMixin):

    """
    Dataplane driver using OpenVSwitch

    Based on an OpenVSwitch 2.4 MPLS kernel dataplane implementation.

    This driver was successfully tested with the OVS 2.4 DKMS module.

    This driver uses MPLS-over-GRE by default. However, note well that current
    OVS implementation of MPLS-over-GRE is not yet conformant with RFC4023,
    because of an intermediate Eth header (MPLS-over-Eth-over-GRE).

    If MPLS-over-GRE is disabled (with mpls_over_gre=False), this driver
    currently requires that the OVS bridge be associated to the address used as
    the local_address in bgp.conf, to allow the linux IP stack to use the same
    physical interface as the one on which MPLS packets are forwarded. This
    requires to configure the OVS bridge so that it passes packets from the
    physical interface to the linux IP stack if they are not MPLS, and packets
    from the linux IP stack to the physical device.

    Howto allow the use of the OVS bridge interface also as an IP
    interface of the Linux kernel IP stack:
        ovs-ofctl del-flows br-int
        ovs-ofctl add-flow br-int in_port=LOCAL,action=output:1
        ovs-ofctl add-flow br-int in_port=1,action=output:LOCAL

    (on a debian or ubuntu system, this can be done part of the ovs bridge
    definition in /etc/network/interfaces, as post-up commands)

    The 'vrf_table' (resp. 'input_table') config parameters can be
    used to specify which OVS table will host the rules for traffic from VRFs
    (resp. for incoming traffic). Beware, this dataplane driver will
    *not* take care of setting up rules so that MPLS traffic or the traffic
    from attached ports is matched against rules in these tables.
    """

    dataplane_instance_class = MPLSOVSVRFDataplane
    type = IPVPN
    ecmp_support = True
    required_ovs_version = "2.5.0"

    driver_opts = [
        cfg.StrOpt("mpls_interface",
                   help=("Interface used to send/receive MPLS traffic. "
                         "Use '*gre*' to choose automatic creation of a tunnel"
                         " port for MPLS/GRE encap")),
        # FIXME: default ?? // logic // obsolete
        cfg.BoolOpt("mpls_over_gre",
                    help=("Force the use of MPLS/GRE even with "
                          "mpls_interface specified")),
        cfg.BoolOpt("proxy_arp", default=True,
                    help=("A netns will be connected to each VRF, will "
                          "be setup with the gateway IP address, and will "
                          "reply to all ARP requests")),
        cfg.BoolOpt("vxlan_encap", default=False,
                    help=("Be ready to receive VPN traffic as VXLAN, and to "
                          "preferrably send traffic as VXLAN when advertised "
                          "by the remote end")),
        cfg.StrOpt("ovs_bridge", default="br-mpls"),
        cfg.IntOpt("input_table", default=0),
        cfg.IntOpt("ovs_table_id_start", default=1),
        cfg.StrOpt("gre_tunnel", default="mpls_gre",
                   help="OVS interface name for MPLS/GRE encap"),
        cfg.StrOpt("gre_tunnel_options",
                   help=("Options passed to OVS for GRE tunnel port creation"
                         " e.g. 'options:l3port=true options:... (future)'")),
        cfg.IntOpt("ovsbr_interfaces_mtu")
    ]

    def __init__(self, init=True):
        lg.LookingGlassLocalLogger.__init__(self)

        self.log.info("Initializing MPLSOVSVRFDataplane")
        DataplaneDriver.__init__(self)

        try:
            (o, _) = self._run_command("ovs-ofctl -V | head -1 |"
                                       " awk '{print $4}'")
            self.ovs_release = o[0]
            self.log.info("OVS version: %s", self.ovs_release)
        except:
            self.log.warning("Could not determine OVS release")
            self.ovs_release = None

        if (StrictVersion(self.ovs_release)
                < StrictVersion(self.required_ovs_version)):
            self.log.warning("%s requires at least OVS %s"
                             " (you are running %s)",
                             self.__class__.__name__,
                             self.required_ovs_version,
                             self.ovs_release)

        self.mpls_interface = self.config.mpls_interface

        try:
            self.use_gre = self.config.mpls_over_gre
        except KeyError:
            self.use_gre = not (self.mpls_interface and
                                self.mpls_interface != "*gre*")

        if not self.mpls_interface:
            if not self.use_gre:
                raise Exception("mpls_over_gre force-disabled, but no "
                                "mpls_interface specified")
            else:
                self.use_gre = True
                self.log.info("Defaulting to use of MPLS-over-GRE (no "
                              "mpls_interface specified)")
        elif self.mpls_interface == "*gre*":
            if not self.use_gre:
                raise Exception("mpls_over_gre force-disabled, but "
                                "mpls_interface set to '*gre', cannot "
                                "use bare MPLS")
            else:
                self.log.info("mpls_interface is '*gre*', will thus use "
                              "MPLS-over-GRE")
                self.use_gre = True
                self.mpls_interface = None
        else:
            if self.use_gre:
                self.log.warning("mpls_over_gre set to True, "
                                 "ignoring mpls_interface parameter")
                self.mpls_interface = None
            else:
                self.log.info("Will use bare MPLS on interface %s",
                              self.mpls_interface)

        self.bridge = self.config.ovs_bridge
        self.input_table = self.config.input_table

        if self.config.ovs_table_id_start == self.input_table:
            raise Exception("invalid ovs_table_id_start (%d): can't use tables"
                            " same as input table (%d)" % (
                                self.config.ovs_table_id_start,
                                self.config.input_table))

        self.encap_in_table = self.config.ovs_table_id_start
        self.vrf_table = self.config.ovs_table_id_start+1
        self.post_hash_vrf_table = self.config.ovs_table_id_start+2

        self.all_tables = {'incoming': self.input_table,
                           'vrf': self.vrf_table,
                           'vrf_post_hash': self.post_hash_vrf_table,
                           'encap_in': self.encap_in_table}

        # Used to control whether this VRF will support
        # receiving traffic as VXLAN
        self.vxlan_encap = self.config.vxlan_encap

        # unless useGRE is enabled, check that fping is installed
        if not self.use_gre:
            self._run_command("fping -v", raise_on_error=True)

        self.proxy_arp = self.config.proxy_arp

        if (not self.vxlan_encap and
                StrictVersion(self.ovs_release) < StrictVersion("2.4.0")):
            self.log.warning(
                "%s requires at least OVS 2.4.0 (you are running %s)",
                self.__class__.__name__, self.ovs_release)

        # Check if OVS bridge exist
        (_, exit_code) = self._run_command("ovs-vsctl br-exists %s" %
                                           self.bridge,
                                           run_as_root=True,
                                           raise_on_error=False)

        if exit_code == 2:
            raise exc.OVSBridgeNotFound(self.bridge)

        # Fixup OpenFlow versions
        self._run_command("ovs-vsctl set bridge %s "
                          "protocols=OpenFlow10,OpenFlow12,OpenFlow13"
                          ",OpenFlow14" % self.bridge,
                          run_as_root=True)

        if not self.use_gre:
            self.log.info("Will not force the use of GRE/MPLS, trying to bind "
                          "physical interface %s", self.mpls_interface)
            # Check if MPLS interface is attached to OVS bridge
            (output, _) = self._run_command("ovs-vsctl port-to-br %s" %
                                            self.mpls_interface,
                                            raise_on_error=False)
            if not output or output[0] != self.bridge:
                raise Exception("Specified mpls_interface %s is not plugged to"
                                " OVS bridge %s" % (self.mpls_interface,
                                                    self.bridge))
            else:
                self.ovs_mpls_if_port_number = self.find_ovs_port(
                    self.mpls_interface)

    def supported_encaps(self):
        if self.use_gre:
            yield Encapsulation(Encapsulation.Type.GRE)
            yield Encapsulation(Encapsulation.Type.DEFAULT)
            # we will accept routes with no encap
            # specified and force the use of GRE
        else:
            yield Encapsulation(Encapsulation.Type.MPLS)
            # we also accept route with no encap specified
            yield Encapsulation(Encapsulation.Type.DEFAULT)

        if self.vxlan_encap:
            yield Encapsulation(Encapsulation.Type.VXLAN)

    def mpls_in_port(self):
        if self.use_gre:
            return self.gre_tunnel_port_number
        else:
            return self.ovs_mpls_if_port_number

    @log_decorator.log_info
    def initialize(self):
        if self.use_gre:
            self.log.info("Setting up tunnel for MPLS/GRE (%s)",
                          self.config.gre_tunnel)

            self._run_command("ovs-vsctl del-port %s %s" % (self.bridge,
                                                            self.gre_tunnel),
                              run_as_root=True,
                              acceptable_return_codes=[0, 1])
            self._run_command("ovs-vsctl add-port %s %s -- set Interface %s"
                              " type=gre options:local_ip=%s "
                              "options:remote_ip=flow %s" %
                              (self.bridge, self.gre_tunnel, self.gre_tunnel,
                               self.get_local_address(),
                               self.config.gre_tunnel_options),
                              run_as_root=True)

            self.gre_tunnel_port_number = self.find_ovs_port(self.gre_tunnel)

        self._ovs_flow_add("in_port=%d,mpls" % self.mpls_in_port(),
                           "resubmit(,%d)" % self.encap_in_table,
                           self.input_table)

        if self.vxlan_encap:
            self.log.info("Enabling VXLAN encapsulation")

            self._run_command("ovs-vsctl del-port %s %s" % (self.bridge,
                                                            VXLAN_TUNNEL),
                              run_as_root=True,
                              acceptable_return_codes=[0, 1])
            self._run_command("ovs-vsctl add-port %s %s -- set Interface %s"
                              " type=vxlan options:local_ip=%s "
                              "options:remote_ip=flow options:key=flow" %
                              (self.bridge, VXLAN_TUNNEL, VXLAN_TUNNEL,
                               self.get_local_address()),
                              run_as_root=True)
            self.vxlan_tunnel_port_number = self.find_ovs_port(VXLAN_TUNNEL)

            self._ovs_flow_add("in_port=%d" % self.vxlan_tunnel_port_number,
                               "resubmit(,%d)" % self.encap_in_table,
                               self.input_table)

    @log_decorator.log_info
    def reset_state(self):
        # Flush all MPLS and ARP flows, if bridge exists

        (_, exit_code) = self._run_command("ovs-vsctl br-exists %s" %
                                           self.bridge,
                                           run_as_root=True,
                                           raise_on_error=False,
                                           acceptable_return_codes=[0, 2])
        if exit_code == 0:
            self.log.info("Cleaning up OVS rules")

            self._ovs_flow_del('mpls', self.input_table)
            if self.vxlan_encap:
                self._ovs_flow_del('in_port=%d' %
                                   self.find_ovs_port(VXLAN_TUNNEL),
                                   self.input_table)
                # the above won't clean up flows if the vxlan_tunnel interface
                # has changed...
                self._ovs_flow_del('tun_id=2/1',
                                   self.input_table)
                self._ovs_flow_del('tun_id=1/1',
                                   self.input_table)

            # clean input_table rule for plugged ports
            # NOTE(tmorin): would be cleaner using a cookie
            self._ovs_flow_del('ip', self.input_table)
            self._ovs_flow_del('arp', self.input_table)

            self._ovs_flow_del(None, self.encap_in_table)
            self._ovs_flow_del(None, self.vrf_table)
            self._ovs_flow_del(None, self.post_hash_vrf_table)

            if self.log.debug:
                self.log.debug("All our rules have been flushed")
                self._run_command("ovs-ofctl dump-flows %s" % self.bridge,
                                  run_as_root=True)
        else:
            self.log.info("No OVS bridge (%s), no need to cleanup OVS rules",
                          self.bridge)

        # Flush network namespaces for ARP responders and
        # corresponding veth pair devices
        cmd = r"ip netns list | cut '-d ' -f 1 | grep -v '\<q' | grep '%s'"
        (output, _) = self._run_command(cmd % ARPNETNS_PREFIX,
                                        raise_on_error=False,
                                        acceptable_return_codes=[0, 1])
        if not output:
            self.log.debug("No network namespaces configured")
        else:
            for namespace_id in output:
                self.log.info("Cleaning up netns %s", namespace_id)
                self._run_command("ip netns delete %s" % namespace_id,
                                  run_as_root=True,
                                  raise_on_error=False)
                self._run_command(
                    "ovs-vsctl del-port %s %s" % (
                        self.bridge,
                        get_ovsbr2arpns_if(namespace_id)),
                    run_as_root=True,
                    acceptable_return_codes=[0, 1, 2],
                    raise_on_error=False)
            if self.log.debug:
                self.log.debug("All network namespaces have been flushed")
                self._run_command("ip netns")

                self.log.debug("All network namespace veth pairs flushed")
                self._run_command("ifconfig")
                self._run_command("ovs-vsctl list-ports %s" % self.bridge,
                                  run_as_root=True,
                                  acceptable_return_codes=[0, 1])

    def _cleanup_real(self):
        self.log.warning("not implemented yet!")

    def find_ovs_port(self, dev_name):
        """ Find OVS port number from port name """
        (output, code) = self._run_command("ovs-vsctl get Interface %s "
                                           "ofport" % dev_name,
                                           run_as_root=True,
                                           acceptable_return_codes=[0, 1])
        if code == 1:
            raise Exception("OVS port not found for device %s, "
                            "(known by ovs-vsctl but not by ovs-ofctl?)"
                            % dev_name)
        else:
            try:
                port = int(output[0])
                if port == -1:
                    raise Exception("OVS port not found for device %s, (known"
                                    " by ovs-vsctl but not by ovs-ofctl?)"
                                    % dev_name)
                return port
            except:
                raise Exception("OVS port not found for device %s" % dev_name)

    def _ovs_flow_add(self, flow, actions, table, return_flow=False,
                      priority=DEFAULT_RULE_PRIORITY):
        ovs_flow = join_s("table=%d" % table,
                          "priority=%d" % priority,
                          flow,
                          "actions=%s" % actions)
        if not return_flow:
            self._run_command("ovs-ofctl add-flow %s --protocol OpenFlow14 "
                              "\"%s\"" % (self.bridge, ovs_flow),
                              run_as_root=True)
        else:
            return ovs_flow

    def _ovs_flow_mods(self, flow_mods):
        """ flow mods is an array of (operation, flow) tuples """
        stdin = "\n".join(["%s %s" % op_flow
                           for op_flow in flow_mods])
        self.log.debug('Flows:\n%s', stdin)
        self._run_command("ovs-ofctl --bundle add-flows %s --protocol "
                          "OpenFlow14 -" % self.bridge,
                          run_as_root=True,
                          stdin=stdin)

    def _ovs_flow_del(self, flow, table, return_flow=False):
        ovs_flow = join_s('table=%d' % table, flow)

        if not return_flow:
            self._run_command("ovs-ofctl del-flows %s --protocol OpenFlow14 "
                              "\"%s\"" % (self.bridge, ovs_flow),
                              run_as_root=True)
        else:
            return ovs_flow

    # Looking glass code ####

    def get_lg_map(self):
        return {
            "flows": (lg.SUBTREE, self.get_lg_ovs_flows),
            "ports": (lg.SUBTREE, self.get_lg_ovs_ports)
        }

    def get_log_local_info(self, path_prefix):
        d = {
            "ovs_bridge": self.bridge,
            "mpls_interface": self.mpls_interface,
            "gre": {'enabled': self.use_gre},
            "vxlan": {'enabled': self.vxlan_encap},
            "ovs_version": self.ovs_release,
            "tables": self.all_tables
        }

        if self.use_gre:
            d["gre"].update({'gre_tunnel_port': self.gre_tunnel})
        if self.vxlan_encap:
            d["gre"].update({'vxlan_tunnel_port': VXLAN_TUNNEL})
        return d

    def get_lg_ovs_flows(self, path_prefix, cookie_spec=None):
        output = {}
        for (table_name, table_id) in self.all_tables.items():
            output.update({
                "%s (%d)" % (table_name, table_id): self._run_command(
                    "ovs-ofctl dump-flows %s '%s' %s" % (
                        self.bridge,
                        join_s("table=%d" % table_id, cookie_spec),
                        OVS_DUMP_FLOW_FILTER),
                    run_as_root=True, shell=True
                    )[0]
            })
        return output

    def get_lg_ovs_ports(self, path_prefix):
        (output, _) = self._run_command(
            "ovs-ofctl show %s |grep addr" % self.bridge,
            run_as_root=True,
            acceptable_return_codes=[0, 1],
            shell=True)
        # FIXME: does it properly show the GRE tunnel interface ?
        return output
