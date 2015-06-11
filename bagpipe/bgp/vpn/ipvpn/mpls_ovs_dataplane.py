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

from netaddr.ip import IPNetwork

from distutils.version import StrictVersion

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver
from bagpipe.bgp.vpn.ipvpn import IPVPN
from bagpipe.bgp.common.looking_glass import LookingGlass, \
    LookingGlassLocalLogger, LGMap

from bagpipe.bgp.common import logDecorator
from bagpipe.bgp.common.utils import getBoolean

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation

import bagpipe.bgp.common.exceptions as exc

DEFAULT_OVS_BRIDGE = "br-mpls"
DEFAULT_OVS_TABLE = 0
RULE_PRIORITY = 40000

DEFAULT_ARPNS_IF_MTU = 9000

#  grep 'define.*IFNAMSIZ' /usr/src/linux/include/uapi/linux/if.h
# define    IFNAMSIZ    16
# (minus 1 for trailing null)
LINUX_DEV_LEN = 15

OVSBR2ARPNS_INTERFACE_PREFIX = "toarpns"

# name of the veth device in the ARP proxy network namespace,
#  whose remote end is plugged in the OVS bridge
PROXYARP2OVS_IF = "ovs"

ARPNETNS_PREFIX = "arp"

GRE_TUNNEL = "mpls_gre"
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


class MPLSOVSVRFDataplane(VPNInstanceDataplane, LookingGlass):

    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

        self.arpNetNS = ("%s-vrf%d" %
                         (ARPNETNS_PREFIX, self.instanceId))[:LINUX_DEV_LEN]

        # Initialize dict where we store info on OVS ports (port numbers and
        # bound IP address)
        self._ovsPortInfo = dict()

        # Find ethX MPLS interface MAC address
        if not self.driver.useGRE:
            self.mplsIfMacAddress = self._find_dev_mac_address(
                self.driver.mpls_interface)
        else:
            self.mplsIfMacAddress = None

        self.bridge = self.driver.bridge

        self.log.info("VRF %d: Initializing network namespace %s for ARP "
                      "proxing", self.instanceId, self.arpNetNS)
        # Get names of veth pair devices between OVS and network namespace
        ovsbr_to_proxyarp_ns = self.driver.get_ovsbr2arpns_if(
            self.arpNetNS)

        if not self._arpNetNsExists():
            self.log.debug("VRF network namespace doesn't exist, creating...")
            # Create network namespace
            self._runCommand("ip netns add %s" % self.arpNetNS)

            # Set up veth pair devices between OVS and ARP network namespace
            self._create_arpnetns_veth_pair(ovsbr_to_proxyarp_ns,
                                            PROXYARP2OVS_IF)

            # Retrieve broadcast IP address
            ip = IPNetwork("%s/%s" % (self.gatewayIP, self.mask))
            broadcastIP = str(ip.broadcast)

            # Set up network namespace interface as gateway
            self._runCommand("ip netns exec %s ip addr add %s/%s broadcast %s"
                             " dev %s" %
                             (self.arpNetNS, self.gatewayIP,
                              self.mask, broadcastIP, PROXYARP2OVS_IF),
                             raiseExceptionOnError=True)

            # Setup IP forwarding
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys"
                             "/net/ipv4/ip_forward\"" % self.arpNetNS)
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                             "/ipv4/conf/all/forwarding\"" % self.arpNetNS)

            # Setup ARP proxying
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                             "/ipv4/conf/%s/proxy_arp\"" %
                             (self.arpNetNS, PROXYARP2OVS_IF))
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net"
                             "/ipv4/conf/%s/proxy_arp_pvlan\"" %
                             (self.arpNetNS, PROXYARP2OVS_IF))
        else:
            self.log.debug("VRF network namespace already exists...")

        # OVS port number for the port toward the proxy ARP netns
        self.arpNetNSPort = self.driver.find_ovs_port(ovsbr_to_proxyarp_ns)

        # Find gateway ("network namespace to OVS" port) MAC address
        self.gwMacAddress = self._find_ns_dev_mac_address(
            self.arpNetNS, PROXYARP2OVS_IF)

        # Create OVS patch ports
        self.log.debug(
            "Creating VRF patch ports and mapping traffic to gateway...")
        self.patchPortIn = 'ipvpn%d-pp-in' % self.instanceId
        self.patchPortOut = 'ipvpn%d-pp-out' % self.instanceId
        self._runCommand("ovs-vsctl --may-exist add-port %s %s -- "
                         "set Interface %s type=patch options:peer=%s" %
                         (self.bridge, self.patchPortIn,
                          self.patchPortIn, self.patchPortOut))
        self._runCommand("ovs-vsctl --may-exist add-port %s %s -- "
                         "set Interface %s type=patch options:peer=%s" %
                         (self.bridge, self.patchPortOut,
                          self.patchPortOut, self.patchPortIn))

        self.patchPortInNumber = self.driver.find_ovs_port(self.patchPortIn)
        self.patchPortOutNumber = self.driver.find_ovs_port(self.patchPortOut)
        # Map traffic from patch port to gateway
        self._ovs_flow_add('in_port=%s,ip,nw_dst=%s' % (self.patchPortInNumber,
                                                        self.gatewayIP),
                           'output:%s' % self.arpNetNSPort,
                           self.driver.ovs_table_vrfs)

    @logDecorator.logInfo
    def cleanup(self):
        if self._ovsPortInfo:
            self.log.warning("OVS port numbers list for local ports plugged in"
                             " VRF is not empty, clearing...")
            self._ovsPortInfo.clear()

        self.log.info("Cleaning VRF patch ports")
        # Unmap traffic from patch port to gateway
        self._ovs_flow_del('in_port=%s,ip,nw_dst=%s' % (
            self.patchPortInNumber, self.gatewayIP),
            self.driver.ovs_table_vrfs)
        self._runCommand("ovs-vsctl del-port %s %s" %
                         (self.bridge, self.patchPortIn))
        self._runCommand("ovs-vsctl del-port %s %s" %
                         (self.bridge, self.patchPortOut))

        self.log.info("Cleaning VRF network namespace %s", self.arpNetNS)
        # Detach network namespace veth pair device from OVS bridge
        self._runCommand(
            "ovs-vsctl del-port %s %s" %
            (self.bridge, self.driver.get_ovsbr2arpns_if(self.arpNetNS)))
        # Delete network namespace
        self._runCommand("ip netns delete %s" % self.arpNetNS)
        # FIXME: need to also cleanup the veth interface

    def _arpNetNsExists(self):
        """ Check if network namespace exist. """
        (output, _) = self._runCommand("ip netns show")
        return (self.arpNetNS in output)

    def _create_arpnetns_veth_pair(self, ovsbr_to_proxyarp_ns,
                                   proxyarp_ns_to_ovsbr):
        """ Create a pair of veth devices, one end being created in the ARP
        netns """
        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            mtu = DEFAULT_ARPNS_IF_MTU
        self.log.info("Will create %s interface with MTU %s (see ovsbr"
                      "_interfaces_mtu in config)", ovsbr_to_proxyarp_ns, mtu)

        try:
            self._runCommand("ip netns exec %s ip link del %s" %
                             (self.arpNetNS, proxyarp_ns_to_ovsbr),
                             raiseExceptionOnError=False,
                             acceptableReturnCodes=[0, 1])
            self._runCommand("ip link del %s" % ovsbr_to_proxyarp_ns,
                             raiseExceptionOnError=False,
                             acceptableReturnCodes=[0, 1])
            self._runCommand("ip link add %s mtu %s type veth peer name %s "
                             "netns %s" % (ovsbr_to_proxyarp_ns, mtu,
                                           proxyarp_ns_to_ovsbr,
                                           self.arpNetNS),
                             acceptableReturnCodes=[0, 2])
            self._runCommand("ip link set dev %s up" % ovsbr_to_proxyarp_ns)
            self._runCommand("ip netns exec %s ip link set dev %s up" %
                             (self.arpNetNS, proxyarp_ns_to_ovsbr))
            self._runCommand("ovs-vsctl del-port %s %s" %
                             (self.bridge, ovsbr_to_proxyarp_ns),
                             raiseExceptionOnError=False,
                             acceptableReturnCodes=[0, 1, 2])
            self._runCommand("ovs-vsctl add-port %s %s" %
                             (self.bridge, ovsbr_to_proxyarp_ns))
        except Exception:
            self._runCommand("ovs-vsctl del-port %s %s" %
                             (self.bridge, ovsbr_to_proxyarp_ns),
                             raiseExceptionOnError=False,
                             acceptableReturnCodes=[0, 1, 2])
            self._runCommand("ip netns exec %s ip link del %s" %
                             (self.arpNetNS, proxyarp_ns_to_ovsbr),
                             raiseExceptionOnError=False)
            self._runCommand("ip link del %s" %
                             ovsbr_to_proxyarp_ns,
                             raiseExceptionOnError=False)
            raise

    @logDecorator.log
    def _extract_mac_address(self, output):
        """ Extract MAC address from command output """
        return re.search(r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", output,
                         re.IGNORECASE).group()

    def _find_dev_mac_address(self, dev_name):
        """ Find device MAC address """
        (output, _) = self._runCommand("ifconfig %s | grep HWaddr" % dev_name)

        return self._extract_mac_address(output[0])

    def _find_ns_dev_mac_address(self, ns_name, dev_name):
        """ Find device MAC address in specified network namespace """
        (output, _) = self._runCommand(
            "ip netns exec %s ifconfig %s | grep HWaddr" % (ns_name, dev_name))

        return self._extract_mac_address(output[0])

    def _find_remote_mac_address(self, remote_ip):
        """ Find MAC address for a remote IP address """
        # PING remote IP address
        (_, exitCode) = self._runCommand("fping -r4 -t100 -q %s" % remote_ip,
                                         raiseExceptionOnError=False,
                                         acceptableReturnCodes=[-1])
        if exitCode != 0:
            raise exc.RemotePEMACAddressNotFound(remote_ip)

        # Look in ARP cache to find remote MAC address
        (output, _) = self._runCommand("ip neigh show to %s" % (remote_ip))

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

        (_, exitCode) = self._runCommand("ip link show %s" % itf,
                                         raiseExceptionOnError=False,
                                         acceptableReturnCodes=[0, 1])

        if exitCode != 0:
            self.log.warning("No %s if, not trying to fix MTU", itf)
        else:
            self._runCommand("ip link set %s mtu %s" % (itf, mtu))

    def _get_ovs_port_specifics(self, localPort):
        """
        Returns a tuple of:
        - OVS port numbers:
            - First port number is the port for traffic from the VM.
            - Second port number is the port for traffic to the VM.
        - OVS actions and rules, based on whether or not a vlan is specified
          in localPort:
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
            if ('ovs' in localPort and localPort['ovs']['plugged']):
                try:
                    port = localPort['ovs']['port_number']
                except KeyError:
                    self.log.info("No OVS port number provided, trying to use"
                                  " a port name")
                    port = self.driver.find_ovs_port(
                        localPort['ovs']['port_name'])
            else:
                portName = ""
                try:
                    try:
                        portName = localPort['ovs']['port_name']
                    except KeyError as e:
                        portName = localPort['linuxif']
                except:
                    raise Exception("Trying to find which port to plug, but no"
                                    " portname was provided")

                try:
                    port = self.driver.find_ovs_port(portName)
                except:
                    self._runCommand("ovs-vsctl --may-exist add-port %s %s" %
                                     (self.bridge, portName))
                    port = self.driver.find_ovs_port(portName)
                self.log.debug("Corresponding port number: %s", port)

                # Set port unplug action
                port_unplug_action = "ovs-vsctl del-port %s %s" % (
                    self.bridge, portName)

        except KeyError as e:
            self.log.error("Incomplete port specification: %s", e)
            raise Exception("Incomplete port specification: %s" % e)

        try:
            port2vm = localPort['ovs']['to_vm_port_number']
        except KeyError:
            self.log.debug("No specific OVS port number provided for traffic "
                           "to VM, trying to use a port name")
            try:
                port2vm = self.driver.find_ovs_port(
                    localPort['ovs']['to_vm_port_name'])
            except KeyError:
                self.log.debug("No specific OVS port found for traffic to VM")
                port2vm = port

        # Create OVS actions
        try:
            localport_match, push_vlan_action, strip_vlan_action = (
                "in_port=%s,dl_vlan=%d" % (
                    port, int(localPort['ovs']['vlan'])),
                "push_vlan:0x8100,mod_vlan_vid:%d," % int(
                    localPort['ovs']['vlan']),
                "strip_vlan,"
            )
        except KeyError:
            localport_match, push_vlan_action, strip_vlan_action = (
                "in_port=%s" % port,
                "",
                ""
            )

        return (port, port2vm, localport_match, push_vlan_action,
                strip_vlan_action, port_unplug_action)

    @logDecorator.log
    def vifPlugged(self, macAddress, ipAddress, localPort, label):

        (ovs_port_from_vm, ovs_port_to_vm, localport_match,
         push_vlan_action, strip_vlan_action, port_unplug_action) = \
            self._get_ovs_port_specifics(localPort)

        # This is a hack used with previous versions of Openstack
        #  proper MTUs should actually be configured in the hybrid vif driver
        # Please consider this obsolete until it gets clean'd up
        self._mtu_fixup(localPort)

        # Map traffic from VM port to patch port
        self._ovs_flow_add('%s,ip' % localport_match,
                           '%soutput:%s' % (strip_vlan_action,
                                            self.patchPortOutNumber),
                           self.driver.ovs_table_vrfs)

        # Map ARP traffic from VM port to ARP proxy and response from ARP proxy
        # to VIF
        self._ovs_flow_add('%s,arp' % localport_match,
                           '%soutput:%s' % (strip_vlan_action,
                                            self.arpNetNSPort),
                           self.driver.ovs_table_vrfs)
        # 'ovs_port_from_vm' is used to send ARP replies to the VM because
        # the interface plugged into the bridge may be an OVS patch port with
        # an OVS bridge doing MAC learning and we want this learning bridge to
        # learn the gw MAC via the right interface so that the traffic from the
        # VM to the gw will arrive on our OVS bridge through 'ovs_from_from_vm'
        self._ovs_flow_add(
            'in_port=%s,arp,dl_dst=%s' % (self.arpNetNSPort, macAddress),
            '%soutput:%s' % (push_vlan_action, ovs_port_from_vm),
            self.driver.ovs_table_vrfs)

        # Map traffic from gateway to VM port (from VM port to gateway realized
        # through patch port)
        self._ovs_flow_add(
            'in_port=%s,ip,nw_dst=%s' % (self.arpNetNSPort, ipAddress),
            '%soutput:%s' % (push_vlan_action, ovs_port_to_vm),
            self.driver.ovs_table_vrfs)

        # Map incoming MPLS traffic going to the VM port
        incoming_actions = ("%smod_dl_src:%s,mod_dl_dst:%s,output:%s" %
                            (push_vlan_action, self.gwMacAddress,
                             macAddress, ovs_port_to_vm))

        self._ovs_flow_add(self._matchMPLSIn(label),
                           "pop_mpls:0x0800,%s" % incoming_actions,
                           self.driver.ovs_table_incoming)

        # addtional incoming traffic rule for VXLAN
        if self.driver.vxlanEncap:
            self._ovs_flow_add(self._matchVXLANIn(label),
                               incoming_actions,
                               self.driver.ovs_table_incoming)

        # Add OVS port number in list for local port plugged in VRF
        self.log.debug("Adding OVS port %s with numbers (%s,%s) for address "
                       "%s to ports plugged in VRF list",
                       localPort['linuxif'], ovs_port_from_vm, ovs_port_to_vm,
                       ipAddress)
        self._ovsPortInfo[localPort['linuxif']] = {
            "localport_match": localport_match,
            "port_unplug_action": port_unplug_action,
        }

    def _mplsInPort(self):
        if self.driver.useGRE:
            return self.driver.ovsGRETunnelPortNumber
        else:
            return self.driver.ovsMplsIfPortNumber

    def _matchMPLSIn(self, label):
        return ('in_port=%s,mpls,mpls_label=%d,mpls_bos=1' %
                (self._mplsInPort(), label))

    def _matchVXLANIn(self, vnid):
        return ('in_port=%s,tun_id=%d' %
                (self.driver.ovsVXLANTunnelPortNumber, vnid))

    @logDecorator.log
    def vifUnplugged(self, macAddress, ipAddress, localPort, label,
                     lastEndpoint=True):

        localport_match = self._ovsPortInfo[
            localPort['linuxif']]['localport_match']
        port_unplug_action = self._ovsPortInfo[
            localPort['linuxif']]['port_unplug_action']

        # Unmap incoming MPLS traffic going to the VM port
        self._ovs_flow_del(self._matchMPLSIn(label),
                           self.driver.ovs_table_incoming)

        # Unmap incoming VXLAN traffic...
        if self.driver.vxlanEncap:
            self._ovs_flow_del(self._matchVXLANIn(label),
                               self.driver.ovs_table_incoming)

        # Unmap all traffic from VM port to local or remote VMs
        if lastEndpoint:
            self._ovs_flow_del(
                '%s' % localport_match, self.driver.ovs_table_vrfs)

        # Unmap traffic from gateway to VM port
        self._ovs_flow_del(
            'in_port=%s,ip,nw_dst=%s' % (self.arpNetNSPort, ipAddress),
            self.driver.ovs_table_vrfs)

        # Unmap ARP traffic from ARP proxy to VM port
        self._ovs_flow_del(
            'in_port=%s,arp,dl_dst=%s' % (self.arpNetNSPort, macAddress),
            self.driver.ovs_table_vrfs)

        if lastEndpoint:
            if port_unplug_action:
                # Run port unplug action if necessary (OVS port delete)
                self._runCommand(port_unplug_action,
                                 acceptableReturnCodes=[0, 1])

            # Remove OVS port number from list for local port plugged in VRF
            del self._ovsPortInfo[localPort['linuxif']]

    @logDecorator.logInfo
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        dec_ttl_action = ""
        if IPNetwork(prefix) not in IPNetwork("%s/%s" % (self.gatewayIP,
                                                         self.mask)):
            dec_ttl_action = "dec_ttl"

        label_action = "push_mpls:0x8847,load:%s->OXM_OF_MPLS_LABEL[]" % label

        # Check if prefix is from a local VRF
        if self.driver.getLocalAddress() == str(remotePE):
            self.log.debug("Local route, using a resubmit action")
            # For local traffic, we have to use a resubmit action
            output_action = "resubmit:%s" % self._mplsInPort()
        else:
            if (self.driver.vxlanEncap and
                    Encapsulation(Encapsulation.Type.VXLAN) in encaps):
                self.log.debug("Will use a VXLAN encap for this destination")
                output_action = "set_field:%s->tun_dst,output:%s" % (
                    str(remotePE), self.driver.ovsVXLANTunnelPortNumber)
                label_action = "set_field:%d->tunnel_id" % label
                # OR set_field:0xfoo->tun_id ?
            elif self.driver.useGRE:
                self.log.debug("Using MPLS/GRE encap")
                output_action = "set_field:%s->tun_dst,output:%s" % (
                    str(remotePE), self.driver.ovsGRETunnelPortNumber)
            else:
                self.log.debug("Using bare MPLS encap")
                # Find remote router MAC address
                try:
                    remotePE_mac_address = self._find_remote_mac_address(
                        remotePE)
                    self.log.debug("MAC address found for remote router "
                                   "%(remotePE)s: %(remotePE_mac_address)s",
                                   locals())
                except exc.RemotePEMACAddressNotFound as e:
                    self.log.error("An error occured during setupDataplaneFor"
                                   "RemoteEndpoint: %s", e)

                # Map traffic to remote IP address as MPLS on ethX to remote
                # router MAC address
                output_action = "mod_dl_src:%s,mod_dl_dst:%s,output:%s" % (
                    self.mplsIfMacAddress, remotePE_mac_address,
                    self.driver.ovsMplsIfPortNumber)

        # Check if prefix is a default route
        nw_dst_match = ""
        if IPNetwork(prefix).prefixlen != 0:
            nw_dst_match = ',nw_dst=%s' % prefix

        self._ovs_flow_add(
            'ip,in_port=%s%s' % (self.patchPortInNumber, nw_dst_match),
            ','.join(filter(None, (dec_ttl_action,
                                   label_action,
                                   output_action))),
            self.driver.ovs_table_vrfs)

    @logDecorator.logInfo
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        # Check if prefix is a default route
        nw_dst_match = ""
        if IPNetwork(prefix).prefixlen != 0:
            nw_dst_match = ',nw_dst=%s' % prefix

        # Unmap traffic to remote IP address
        self._ovs_flow_del('ip,in_port=%s%s' % (self.patchPortInNumber,
                                                nw_dst_match),
                           self.driver.ovs_table_vrfs)
        # since multiple routes to the same prefix cannot co-exist in OVS
        # a delete action cannot selectively delete one next-hop
        # hence this driver does not support make-before-break

    def _ovs_flow_add(self, flow, actions, table):
        self.driver._ovs_flow_add("cookie=%d,priority=%d,%s" %
                                  (self.instanceId, RULE_PRIORITY, flow),
                                  actions, table)

    def _ovs_flow_del(self, flow, table):
        self.driver._ovs_flow_del(
            "cookie=%d/-1,%s" % (self.instanceId, flow), table)

    def getLGMap(self):
        return {
            "flows": (LGMap.SUBTREE, self.getLGOVSFlows)
        }

    def getLGOVSFlows(self, pathPrefix):
        tables = set([self.driver.ovs_table_incoming, self.driver.ovs_table_vrfs])
        output = []
        for table in tables:
            output += self._runCommand(
                "ovs-ofctl dump-flows %s 'table=%d,cookie=%d/-1'%s"
                % (self.bridge, table, self.instanceId, OVS_DUMP_FLOW_FILTER)
            )[0]
        return output


class MPLSOVSDataplaneDriver(DataplaneDriver, LookingGlass):

    """
    Dataplane driver using OpenVSwitch

    Based on an OpenVSwtich MPLS kernel dataplane implementation to be
    included in OVS 2.4.

    In the meantime, the master branch of openvswitch git repository can be
    used:
        https://github.com/openvswitch/ovs.git

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

    The 'ovs_table_vrfs' (resp. 'ovs_table_incoming') config parameters can be used
    to specify which OVS table will host the rules for traffic from VRFs
    (resp. for incoming traffic). Beware, this dataplane driver will
    *not* take care of setting up rules so that MPLS traffic or the traffic
    from attached ports is matched against rules in these tables.
    """

    dataplaneInstanceClass = MPLSOVSVRFDataplane
    type = IPVPN

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self)
        self.log.info("Initializing MPLSOVSVRFDataplane")

        try:
            (o, _) = self._runCommand("ovs-ofctl -V | head -1 |"
                                      " awk '{print $4}'")
            self.ovsRelease = o[0]
            self.log.info("OVS kernel module %s", self.ovsRelease)
        except:
            self.log.warning("Could not determine OVS release")
            self.ovsRelease = None

        self.config = config

        self.mpls_interface = config.get("mpls_interface", None)

        try:
            self.useGRE = getBoolean(config["mpls_over_gre"])
        except KeyError:
            self.useGRE = not (self.mpls_interface and
                               self.mpls_interface != "*gre*")

        if not self.mpls_interface:
            if not self.useGRE:
                raise Exception("mpls_over_gre force-disabled, but no "
                                "mpls_interface specified")
            else:
                self.useGRE = True
                self.log.info("Defaulting to use of MPLS-over-GRE (no "
                              "mpls_interface specified)")
        elif self.mpls_interface == "*gre*":
            if not self.useGRE:
                raise Exception("mpls_over_gre force-disabled, but "
                                "mpls_interface set to '*gre', cannot "
                                "use bare MPLS")
            else:
                self.log.info("mpls_interface is '*gre*', will thus use "
                              "MPLS-over-GRE")
                self.useGRE = True
                self.mpls_interface = None
        else:
            if self.useGRE:
                self.log.warning("mpls_over_gre set to True, "
                                 "ignoring mpls_interface parameter")
                self.mpls_interface = None
            else:
                self.log.info("Will use bare MPLS on interface %s",
                              self.mpls_interface)

        self.bridge = DEFAULT_OVS_BRIDGE
        try:
            self.bridge = config["ovs_bridge"]
        except KeyError:
            self.log.warning("No bridge configured, will use default: %s",
                             DEFAULT_OVS_BRIDGE)

        self.ovs_table_incoming = DEFAULT_OVS_TABLE
        try:
            self.ovs_table_incoming = int(config["ovs_table_incoming"])
        except KeyError:
            self.log.debug("No ovs_table_incoming configured, "
                           "will use default table %s", DEFAULT_OVS_TABLE)

        self.ovs_table_vrfs = DEFAULT_OVS_TABLE
        try:
            self.ovs_table_vrfs = int(config["ovs_table_vrfs"])
        except KeyError:
            self.log.debug("No ovs_table_vrfs configured, will use default"
                           " table %s", DEFAULT_OVS_TABLE)

        self.vxlanEncap = getBoolean(config.get("vxlan_encap", "False"))

        # check that fping is installed
        if not self.useGRE:
            self._runCommand("fping -v", raiseExceptionOnError=True)

        if (not self.vxlanEncap and
                StrictVersion(self.ovsRelease) < StrictVersion("2.3.90")):
            self.log.warning(
                "%s requires at least OVS 2.3.90 (you are running %s)",
                self.__class__.__name__, self.ovsRelease)

        DataplaneDriver.__init__(self, config, init)

    def supportedEncaps(self):
        if self.useGRE:
            yield Encapsulation(Encapsulation.Type.GRE)
            yield Encapsulation(Encapsulation.Type.DEFAULT)
            # we will accept routes with no encap
            # specified and force the use of GRE
        else:
            yield Encapsulation(Encapsulation.Type.MPLS)

        if self.vxlanEncap:
            yield Encapsulation(Encapsulation.Type.VXLAN)

    @logDecorator.logInfo
    def _initReal(self, config):
        # Check if OVS bridge exist
        (_, exitCode) = self._runCommand("ovs-vsctl br-exists %s" %
                                         self.bridge,
                                         raiseExceptionOnError=False)

        if exitCode == 2:
            raise exc.OVSBridgeNotFound(self.bridge)

        if not self.useGRE:
            self.log.info("Will not force the use of GRE/MPLS, trying to bind "
                          "physical interface %s", self.mpls_interface)
            # Check if MPLS interface is attached to OVS bridge
            (output, exitCode) = self._runCommand("ovs-vsctl port-to-br %s" %
                                                  self.mpls_interface,
                                                  raiseExceptionOnError=False)
            if not self.bridge == output[0]:
                raise Exception("Specified mpls_interface is not plugged to "
                                "OVS bridge %s" %
                                self.mpls_interface, self.bridge)
            else:
                self.ovsMplsIfPortNumber = self.find_ovs_port(
                    self.mpls_interface)
        else:
            self.log.info("Setting up tunnel for MPLS/GRE (%s)", GRE_TUNNEL)
            try:
                additional_tunnel_options = self.config["gre_tunnel_options"]
                # e.g. "options:l3port=true options:..."
            except:
                additional_tunnel_options = ""

            self._runCommand("ovs-vsctl del-port %s %s" % (self.bridge,
                                                           GRE_TUNNEL),
                             acceptableReturnCodes=[0, 1])
            self._runCommand("ovs-vsctl add-port %s %s -- set Interface %s"
                             " type=gre options:local_ip=%s "
                             "options:remote_ip=flow %s" %
                             (self.bridge, GRE_TUNNEL, GRE_TUNNEL,
                              self.getLocalAddress(),
                              additional_tunnel_options))

            self.ovsGRETunnelPortNumber = self.find_ovs_port(GRE_TUNNEL)

        if self.vxlanEncap:
            self.log.info("Enabling VXLAN encapsulation")

            self._runCommand("ovs-vsctl del-port %s %s" % (self.bridge,
                                                           VXLAN_TUNNEL),
                             acceptableReturnCodes=[0, 1])
            self._runCommand("ovs-vsctl add-port %s %s -- set Interface %s"
                             " type=vxlan options:local_ip=%s "
                             "options:remote_ip=flow options:key=flow" %
                             (self.bridge, VXLAN_TUNNEL, VXLAN_TUNNEL,
                              self.getLocalAddress()))
            self.ovsVXLANTunnelPortNumber = self.find_ovs_port(VXLAN_TUNNEL)

        # Fixup openflow version
        self._runCommand("ovs-vsctl set bridge %s "
                         "protocols=OpenFlow10,OpenFlow12,OpenFlow13" %
                         self.bridge)

    def get_ovsbr2arpns_if(self, namespaceId):
        i = namespaceId.replace(ARPNETNS_PREFIX, "")
        return (OVSBR2ARPNS_INTERFACE_PREFIX + i)[:LINUX_DEV_LEN]

    @logDecorator.logInfo
    def resetState(self):
        # Flush all MPLS and ARP flows, if bridge exists

        (_, exitCode) = self._runCommand("ovs-vsctl br-exists %s" %
                                         self.bridge,
                                         raiseExceptionOnError=False,
                                         acceptableReturnCodes=[0, 2])
        if exitCode == 0:
            self.log.info("Cleaning up OVS rules")
            self._ovs_flow_del('mpls', self.ovs_table_incoming)
            if self.vxlanEncap:
                self._ovs_flow_del('in_port=%d' %
                                   self.find_ovs_port(VXLAN_TUNNEL),
                                   self.ovs_table_incoming)
            self._ovs_flow_del('ip', self.ovs_table_vrfs)
            self._ovs_flow_del('arp', self.ovs_table_vrfs)
            if self.log.debug:
                self.log.debug("All our rules have been flushed")
                self._runCommand("ovs-ofctl dump-flows %s" % self.bridge)

        else:
            self.log.info("No OVS bridge (%s), no need to cleanup OVS rules",
                          self.bridge)

        # Flush all VRF patch ports
        cmd = "ovs-vsctl list-ports br-mpls | grep 'ipvpn.*-pp-'"
        (output, _) = self._runCommand(cmd, raiseExceptionOnError=False,
                                       acceptableReturnCodes=[0, 1])
        if not output:
            self.log.debug("No VRF patch ports configured")
        else:
            for patch_port in output:
                self._runCommand(
                    "ovs-vsctl del-port %s %s" % (self.bridge, patch_port),
                    acceptableReturnCodes=[0, 1, 2],
                    raiseExceptionOnError=False)

        # Flush all (except DHCP, router, LBaaS, ...) network namespaces and
        # corresponding veth pair devices
        cmd = r"ip netns | grep -v '\<q' | grep '%s'"
        (output, _) = self._runCommand(cmd % ARPNETNS_PREFIX,
                                       raiseExceptionOnError=False,
                                       acceptableReturnCodes=[0, 1])
        if not output:
            self.log.debug("No network namespaces configured")
        else:
            for namespaceId in output:
                self.log.info("Cleaning up netns %s", namespaceId)
                self._runCommand("ip netns delete %s" %
                                 namespaceId, raiseExceptionOnError=False)
                self._runCommand(
                    "ovs-vsctl del-port %s %s" % (
                        self.bridge,
                        self.get_ovsbr2arpns_if(namespaceId)),
                    acceptableReturnCodes=[0, 1, 2],
                    raiseExceptionOnError=False)
            if self.log.debug:
                self.log.debug("All network namespaces have been flushed")
                self._runCommand("ip netns")

                self.log.debug("All network namespace veth pairs flushed")
                self._runCommand("ifconfig")
                self._runCommand("ovs-vsctl list-ports %s" %
                                 self.bridge, acceptableReturnCodes=[0, 1])

    def _cleanupReal(self):
        self.log.warning("not implemented yet!")

    def find_ovs_port(self, dev_name):
        """ Find OVS port number from port name """
        (output, _) = self._runCommand("ovs-vsctl get Interface %s ofport" %
                                       dev_name, acceptableReturnCodes=[0, 1])
        try:
            return int(output[0])
        except:
            raise Exception("OVS port not found for device %s" % dev_name)

    def _ovs_flow_add(self, flow, actions, table):
        self._runCommand("ovs-ofctl add-flow %s --protocol OpenFlow13 "
                         "'table=%d,%s,actions=%s'" % (self.bridge,
                                                       table, flow, actions)
                         )

    def _ovs_flow_del(self, flow, table):
        self._runCommand("ovs-ofctl del-flows %s --protocol OpenFlow13 "
                         "'table=%d,%s'" % (self.bridge, table, flow)
                         )

    # Looking glass code ####

    def getLGMap(self):
        return {
            "flows": (LGMap.SUBTREE, self.getLGOVSFlows),
            "ports": (LGMap.SUBTREE, self.getLGOVSPorts)
        }

    def getLookingGlassLocalInfo(self, pathPrefix):
        d = {
            "ovs_bridge": self.bridge,
            "mpls_interface": self.mpls_interface,
            "ovs_table_vrfs": self.ovs_table_vrfs,
            "ovs_table_incoming": self.ovs_table_incoming,
            "gre": {'enabled': self.useGRE},
            "vxlan": {'enabled': self.vxlanEncap},
            "ovs_version": self.ovsRelease
        }
        if self.useGRE:
            d["gre"].update({'gre_tunnel_port': GRE_TUNNEL})
        if self.vxlanEncap:
            d["gre"].update({'vxlan_tunnel_port': VXLAN_TUNNEL})
        return d

    def getLGOVSFlows(self, pathPrefix):
        # TODO: filter to only get flows from our tables
        (output, _) = self._runCommand("ovs-ofctl dump-flows %s %s" %
                                       (self.bridge, OVS_DUMP_FLOW_FILTER))
        return output

    def getLGOVSPorts(self, pathPrefix):
        (output, _) = self._runCommand(
            "ovs-ofctl show %s |grep addr" % self.bridge)
        # FIXME: does it properly show the GRE tunnel interface
        return output
