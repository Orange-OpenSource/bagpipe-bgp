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
from bagpipe.bgp.common.looking_glass import LookingGlass, LookingGlassLocalLogger, LGMap

from exabgp.message.update.attribute.communities import Encapsulation

import bagpipe.bgp.common.exceptions as exc

DEFAULT_OVS_BRIDGE = "br-int"
DEFAULT_OVS_TABLE = 0
RULE_PRIORITY=40000

DEFAULT_ARPNS_IF_MTU=9000

LINUX_DEV_LEN = 14
OVSBR_INTERFACE_PREFIX = "tonsarp-"

# name of the veth device in the ARP proxy network namespace,
# whose remote end is plugged in the OVS bridge 
PROXYARP2OVS_IF = "ovs"

ARPNETNS_PREFIX = "arpns"

GRE_TUNNEL = "mpls_gre"
NO_MPLS_PHY_INTERFACE = -1

# Prefix used by the NOVA hybrid VIF driver 
# for the OVS port corresponding to the VM tap port
OVS_LINUXBR_INTERFACE_PREFIX = "qvo"

OVS_DUMP_FLOW_FILTER="| grep -v NXST_FLOW | perl -pe '"               \
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
        
        self.namespaceId = "%s%s" % (ARPNETNS_PREFIX, self._get_namespace_from_network())
        
        # Initialize dict where we store info on OVS ports (port numbers and bound IP address)
        self._ovsPortInfo = dict()
        
        # Find ethX MPLS interface MAC address
        if not self.driver.useGRE:
            self.mplsIfMacAddress = self._find_dev_mac_address(self.driver.mpls_interface)
        else:
            self.mplsIfMacAddress = None
        
        self.ovs_bridge = self.driver.ovs_bridge
        
        self.log.info("VRF %d: Initializing network namespace %s for ARP proxing" % (self.instanceId, self.namespaceId))
        # Get names of veth pair devices between OVS and network namespace
        ovsbr_to_proxyarp_ns = self.driver._get_ovsbr_to_proxyarpns_devname(self.namespaceId)
        
        if not self._namespace_exists():
            self.log.debug("VRF network namespace doesn't exist, creating...")
            # Create network namespace
            self._runCommand("ip netns add %s" % self.namespaceId)
            
            # Set up veth pair devices between OVS and ARP network namespace
            self._create_veth_pair(ovsbr_to_proxyarp_ns, PROXYARP2OVS_IF)
            
            # Retrieve broadcast IP address        
            ip = IPNetwork("%s/%s" % (self.gatewayIP, self.mask))
            broadcastIP = str(ip.broadcast)
        
            # Set up network namespace interface as gateway
            self._runCommand("ip netns exec %s ip addr add %s/%s broadcast %s dev %s" % 
                             (self.namespaceId, self.gatewayIP, self.mask, broadcastIP, PROXYARP2OVS_IF),
                             raiseExceptionOnError=True)
            
            # Setup IP forwarding 
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/ip_forward\"" % self.namespaceId)
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/all/forwarding\"" % self.namespaceId)
    
            # Setup ARP proxying
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/%s/proxy_arp\"" % (self.namespaceId, PROXYARP2OVS_IF))
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/%s/proxy_arp_pvlan\"" % (self.namespaceId, PROXYARP2OVS_IF))
        else:
            self.log.debug("VRF network namespace already exists...")

        # Find OVS port number corresponding to "OVS to network namespace" port name
        self.ovsToNsPortNumber = self.driver._find_ovs_port_number(ovsbr_to_proxyarp_ns)
        
        # Find gateway ("network namespace to OVS" port) MAC address
        self.gwMacAddress = self._find_ns_dev_mac_address(self.namespaceId, PROXYARP2OVS_IF)

        # Create OVS patch ports
        self.log.debug("Creating VRF patch ports and mapping traffic to gateway...")
        self.patchPortIn = 'ipvpn%d-pp-in' % self.instanceId
        self.patchPortOut = 'ipvpn%d-pp-out' % self.instanceId
        self._runCommand("ovs-vsctl --may-exist add-port %s %s -- set Interface %s type=patch options:peer=%s" % (self.ovs_bridge, self.patchPortIn, self.patchPortIn, self.patchPortOut))
        self._runCommand("ovs-vsctl --may-exist add-port %s %s -- set Interface %s type=patch options:peer=%s" % (self.ovs_bridge, self.patchPortOut, self.patchPortOut, self.patchPortIn))

        self.patchPortInNumber = self.driver._find_ovs_port_number(self.patchPortIn)
        self.patchPortOutNumber = self.driver._find_ovs_port_number(self.patchPortOut)
        # Map traffic from patch port to gateway
        self._ovs_flow_add('in_port=%s,ip,nw_dst=%s' % (self.patchPortInNumber, self.gatewayIP),
                           'output:%s' % self.ovsToNsPortNumber,
                           self.driver.ovs_table_vrfs)
    
    def cleanup(self):
        if self._ovsPortInfo:
            self.log.warning("OVS port numbers list for local ports plugged in VRF is not empty, clearing...")
            self._ovsPortInfo.clear()
        
        self.log.info("Cleaning VRF patch ports")
        # Unmap traffic from patch port to gateway
        self._ovs_flow_del('in_port=%s,ip,nw_dst=%s' % (self.patchPortInNumber, self.gatewayIP),
                           self.driver.ovs_table_vrfs)
        self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, self.patchPortIn))
        self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, self.patchPortOut))

        self.log.info("Cleaning VRF network namespace %s" % self.namespaceId)
        # Detach network namespace veth pair device from OVS bridge
        self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, self.driver._get_ovsbr_to_proxyarpns_devname(self.namespaceId)))
        # Delete network namespace
        self._runCommand("ip netns delete %s" % self.namespaceId)
        # FIXME: need to also cleanup the veth interface
        
        
    def _hack_localport_for_hybrid_vif_driver(self, localport):
        """
        Return the localport to use.
        
        If the localport looks like a Neutron port ('tap<uuid>'), then the real localport
        to use is 'qvo<uuid>'. Else we keep the localport unchanged.
        
        This is were we hardcode how the Openstack hybrid VIF driver creates a veth interface
        to connect a tap interface, through a linuxbridge, into OVS.
        """
        if re.match('tap[0-9a-f-]{11}',localport):
            new_localport = OVS_LINUXBR_INTERFACE_PREFIX + localport[3:]
            self.log.warning("Nova hybrid vif driver hack: mapping %s into %s" % (localport,new_localport))
            return new_localport
        else:
            return localport

    def _get_namespace_from_network(self):
        return self.externalInstanceId[:LINUX_DEV_LEN]

    def _namespace_exists(self):
        """ Check if network namespace exist. """
        (output, _) = self._runCommand("ip netns show")
        return (self.namespaceId in output)
    
    def _create_veth_pair(self, ovsbr_to_proxyarp_ns, proxyarp_ns_to_ovsbr):
        """ Create a pair of veth devices, one end being created in the ARP netns """
        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            mtu = DEFAULT_ARPNS_IF_MTU
        self.log.info("Will create %s interface with MTU %s (change with ovsbr_interfaces_mtu in ipvpn section of bagpipe config)" % (ovsbr_to_proxyarp_ns, mtu))

        try:
            self._runCommand("ip netns exec %s ip link del %s" % (self.namespaceId, proxyarp_ns_to_ovsbr), raiseExceptionOnError=False, acceptableReturnCodes=[0, 1])
            self._runCommand("ip link del %s" % ovsbr_to_proxyarp_ns, raiseExceptionOnError=False, acceptableReturnCodes=[0, 1])
            self._runCommand("ip link add %s mtu %s type veth peer name %s netns %s" % (ovsbr_to_proxyarp_ns, mtu, proxyarp_ns_to_ovsbr, self.namespaceId), acceptableReturnCodes=[0, 2])
            self._runCommand("ip link set dev %s up" % ovsbr_to_proxyarp_ns)
            self._runCommand("ip netns exec %s ip link set dev %s up" % (self.namespaceId, proxyarp_ns_to_ovsbr))
            self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, ovsbr_to_proxyarp_ns), raiseExceptionOnError=False, acceptableReturnCodes=[0, 1, 2])
            self._runCommand("ovs-vsctl add-port %s %s" % (self.ovs_bridge, ovsbr_to_proxyarp_ns))
        except Exception:
            self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, ovsbr_to_proxyarp_ns), raiseExceptionOnError=False, acceptableReturnCodes=[0, 1, 2])
            self._runCommand("ip netns exec %s ip link del %s" % (self.namespaceId, proxyarp_ns_to_ovsbr), raiseExceptionOnError=False)
            self._runCommand("ip link del %s" % ovsbr_to_proxyarp_ns, raiseExceptionOnError=False)
            raise
    
    def _extract_mac_address(self, output):
        """ Extract MAC address from command output """
        self.log.debug("Extracting MAC address from output: %s" % output)
        return re.search(r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", output, re.IGNORECASE).group()
    
    def _find_dev_mac_address(self, dev_name):
        """ Find device MAC address """
        (output, _) = self._runCommand("ifconfig %s | grep HWaddr" % dev_name)
        
        return self._extract_mac_address(output[0])
        
    def _find_ns_dev_mac_address(self, ns_name, dev_name):
        """ Find device MAC address in specified network namespace """
        (output, _) = self._runCommand("ip netns exec %s ifconfig %s | grep HWaddr" % (ns_name, dev_name))
        
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

    def _mtu_fixup(self, interface):
        '''
        This is a hack, proper MTUs should actually be configured in the hybrid vif driver
        '''
        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            mtu = 1500
        self.log.info("Will adjust %s interface with MTU %s (change with ovsbr_interfaces_mtu in ipvpn section of bagpipe config)" % (interface, mtu))

        (_, exitCode) = self._runCommand("ip link show %s" % interface, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])
        
        if exitCode != 0:
            self.log.warning("Interface %s does not exist, not trying to fix MTU" % interface)
        else:
            self._runCommand("ip link set %s mtu %s" % (interface, mtu))

    def _get_ovs_port_specifics(self, localPort):
        """
        Returns a tuple of:
        - OVS port numbers:
            - First port number is the port for traffic from the VM.
            - Second port number is the port for traffic to the VM.
        - OVS actions and rules, based on whether or not a vlan is specified in
          localPort:
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
                    self.log.info("No OVS port number provided, trying to use a port name")
                    port = self.driver._find_ovs_port_number(localPort['ovs']['port_name'])
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
                    port = self.driver._find_ovs_port_number(portName)
                except:
                    self._runCommand("ovs-vsctl add-port %s %s" % (self.ovs_bridge,portName))
                    port = self.driver._find_ovs_port_number(portName)
                self.log.debug("Corresponding port number: %s" % port)

                # Set port unplug action
                port_unplug_action = "ovs-vsctl del-port %s %s" % (self.ovs_bridge, portName)
                
        except KeyError as e:
            self.log.error("Incomplete port specification: %s" % e)
            raise Exception("Incomplete port specification: %s" % e)
        
        try:
            port2vm = localPort['ovs']['to_vm_port_number']
        except KeyError:
            self.log.debug("No specific OVS port number provided for traffic to VM, trying to use a port name")
            try:
                port2vm = self.driver._find_ovs_port_number(localPort['ovs']['to_vm_port_name'])
            except KeyError:
                self.log.debug("No specific OVS port found for traffic to VM")
                port2vm=port

        # Create OVS actions
        try:
            localport_match,push_vlan_action,strip_vlan_action = (
                "in_port=%s,dl_vlan=%d" % (port, int(localPort['ovs']['vlan'])),
                "push_vlan:0x8100,mod_vlan_vid:%d," % int(localPort['ovs']['vlan']),
                "strip_vlan,"
            )
        except KeyError:
            localport_match,push_vlan_action,strip_vlan_action = (
                "in_port=%s" % port,
                "",
                ""
            )

        return (port, port2vm, localport_match, push_vlan_action,
                strip_vlan_action, port_unplug_action)

    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        self.log.debug("vifPlugged: Plugging local port (%(localPort)s, %(ipAddress)s, %(label)d)" % locals())
        
        (ovs_port_from_vm, ovs_port_to_vm, localport_match,
         push_vlan_action, strip_vlan_action, port_unplug_action) = self._get_ovs_port_specifics(localPort)
        
        try:
            self._mtu_fixup(localPort['ovs']['port_name'])
        except KeyError:
            self.log.warning("No OVS port name provided, cannot fix MTU")
        
        # Map traffic from VM port to patch port
        self._ovs_flow_add('%s,ip' % localport_match,
                           '%soutput:%s' % (strip_vlan_action, self.patchPortOutNumber),
                           self.driver.ovs_table_vrfs)
        
        # Map ARP traffic from VM port to ARP proxy and response from ARP proxy to VIF
        self._ovs_flow_add('%s,arp' % localport_match,
                                  '%soutput:%s' % (strip_vlan_action,self.ovsToNsPortNumber),
                                  self.driver.ovs_table_vrfs)
        # 'ovs_port_from_vm' is used to send ARP replies to the VM because
        # the interface plugged into the bridge may be an OVS patch port with
        # an OVS bridge doing MAC learning and we want this learning bridge to 
        # learn the gw MAC via the right interface so that the traffic from the VM
        # to the gw will arrive on our OVS bridge through 'ovs_from_from_vm' 
        self._ovs_flow_add('in_port=%s,arp,dl_dst=%s' % (self.ovsToNsPortNumber, macAddress),
                                  '%soutput:%s' % (push_vlan_action,ovs_port_from_vm),
                                  self.driver.ovs_table_vrfs)

        # Map traffic from gateway to VM port (from VM port to gateway realized through patch port)
        self._ovs_flow_add('in_port=%s,ip,nw_dst=%s' % (self.ovsToNsPortNumber, ipAddress),
                                  '%soutput:%s' % (push_vlan_action,ovs_port_to_vm),
                                  self.driver.ovs_table_vrfs)

        # Map incoming MPLS traffic going to the VM port
        self._ovs_flow_add('in_port=%s,mpls,mpls_label=%d,mpls_bos=1' 
                                  % (self._inPort(), label),
                              'pop_mpls:0x0800,%smod_dl_src:%s,mod_dl_dst:%s,output:%s' 
                              % (push_vlan_action, self.gwMacAddress, macAddress, ovs_port_to_vm),
                              self.driver.ovs_table_mpls)
        
        # Add OVS port number in list for local port plugged in VRF
        self.log.debug("Adding OVS port %s with numbers (%s,%s) for address %s to ports plugged in VRF list" % (localPort['linuxif'], ovs_port_from_vm,ovs_port_to_vm, ipAddress))
        self._ovsPortInfo[localPort['linuxif']] = {
             "ip_address": ipAddress,
             "localport_match": localport_match,
             "vlan_specific": (push_vlan_action,strip_vlan_action),
             "port_unplug_action": port_unplug_action
             }
    
    def _inPort(self):
        if self.driver.useGRE:
            return self.driver.ovsGRETunnelPortNumber
        else:
            return self.driver.ovsMplsIfPortNumber
    
    def vifUnplugged(self, macAddress, ipAddress, localPort, label, lastEndpoint=True):
        self.log.debug("vifUnplugged: Unplugging local port (%(localPort)s, %(ipAddress)s, %(label)d)" % locals())

        localport_match = self._ovsPortInfo[localPort['linuxif']]['localport_match']
        port_unplug_action = self._ovsPortInfo[localPort['linuxif']]['port_unplug_action']
        
        # Unmap incoming MPLS traffic going to the VM port
        self._ovs_flow_del('in_port=%s,mpls,mpls_label=%d,mpls_bos=1' % (self._inPort(), label),
                         self.driver.ovs_table_mpls)

        # Unmap all traffic from VM port to local or remote VMs
        if lastEndpoint:
            self._ovs_flow_del('%s' % localport_match, self.driver.ovs_table_vrfs)

        # Unmap traffic from gateway to VM port
        self._ovs_flow_del('in_port=%s,ip,nw_dst=%s' % (self.ovsToNsPortNumber, ipAddress),
                         self.driver.ovs_table_vrfs)

        # Unmap ARP traffic from ARP proxy to VM port
        self._ovs_flow_del('in_port=%s,arp,dl_dst=%s' % (self.ovsToNsPortNumber, macAddress),
                         self.driver.ovs_table_vrfs)
        
        if lastEndpoint:
            if port_unplug_action:
                # Run port unplug action if necessary (OVS port delete)
                self._runCommand(port_unplug_action, acceptableReturnCodes=[0,1])

            # Remove OVS port number from list for local port plugged in VRF
            del self._ovsPortInfo[localPort['linuxif']]

    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri, encaps):
        self.log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" 
                 % (prefix, remotePE, label, self.driver.mpls_interface))

        dec_ttl_action = ""
        if IPNetwork(repr(prefix)) not in IPNetwork("%s/%s" % (self.gatewayIP, self.mask)):
            dec_ttl_action = "dec_ttl,"

        mpls_action = "%spush_mpls:0x8847,load:%s->OXM_OF_MPLS_LABEL[]" % (dec_ttl_action,label)

        # Check if prefix is from a local VRF
        if self.driver.getLocalAddress() == str(remotePE):
            self.log.debug("Local route, using a resubmit action")
            # For local traffic, we have to use a resubmit action
            output_action = "resubmit:%s" % self._inPort()
        else:
            if self.driver.useGRE:
                self.log.debug("Using MPLS/GRE encap")
                output_action="set_field:%s->tun_dst,output:%s" % (str(remotePE), self.driver.ovsGRETunnelPortNumber)
            else:
                self.log.debug("Using bare MPLS encap")
                # Find remote router MAC address
                try:
                    remotePE_mac_address = self._find_remote_mac_address(remotePE)
                    self.log.debug("MAC address found for remote router %(remotePE)s: %(remotePE_mac_address)s" % locals())
                except exc.RemotePEMACAddressNotFound as e:
                    self.log.error('An error occured during setupDataplaneForRemoteEndpoint: %s' % e)
                
                # Map traffic to remote IP address as MPLS on ethX to remote router MAC address
                output_action= "mod_dl_src:%s,mod_dl_dst:%s,output:%s" % (self.mplsIfMacAddress, remotePE_mac_address, self.driver.ovsMplsIfPortNumber)

        self.log.debug("OVS port numbers list for local port plugged in VRF: %s"
                       % self._ovsPortInfo)

        self._ovs_flow_add(
            'ip,in_port=%s,nw_dst=%s' % (self.patchPortInNumber, prefix),
            '%s,%s' % (mpls_action, output_action),
            self.driver.ovs_table_vrfs)
        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))

        # Unmap traffic to remote IP address
        self._ovs_flow_del('ip,in_port=%s,nw_dst=%s' % (self.patchPortInNumber, prefix),
                                      self.driver.ovs_table_vrfs)
        #TODO: find a way to only delete the OVS rule corresponding to the said remotePE and said label

    def _ovs_flow_add(self,flow,actions,table):
        self.driver._ovs_flow_add("cookie=%d,priority=%d,%s" % (self.instanceId, RULE_PRIORITY, flow),actions,table)
    
    def _ovs_flow_del(self,flow,table):
        self.driver._ovs_flow_del("cookie=%d/-1,%s" % (self.instanceId, flow),table)

    def getLGMap(self):
        return {
                "flows": (LGMap.SUBTREE, self.getLGOVSFlows)
                }
    
    def getLGOVSFlows(self, pathPrefix):
        tables=set([self.driver.ovs_table_mpls,self.driver.ovs_table_vrfs])
        output = []
        for table in tables:
            output += self._runCommand(
                       "ovs-ofctl dump-flows %s 'table=%d,cookie=%d/-1'%s" 
                       % (self.ovs_bridge,table,self.instanceId,OVS_DUMP_FLOW_FILTER)
                    )[0]
        return output



class MPLSOVSDataplaneDriver(DataplaneDriver, LookingGlass):
    """
    Dataplane driver using OpenVSwitch 
       
    Based on an OpenVSwtich MPLS kernel dataplane implementation to be 
    included in OVS 2.4.
    
    In the meantime, the master openvswitch git repository can be used:
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

    (on a debian or ubuntu system, this can be done part of the ovs bridge definition 
    in /etc/network/interfaces, as post-up commands)
    
    The 'ovs_table_mpls' (resp. 'ovs_table_vrfs') config parameters can be used
    to specify which OVS table will host the rules for traffic from VRFs 
    (resp. for incoming MPLS traffic). Beware, this dataplane driver will 
    *not* take care of setting up rules so that MPLS traffic or the traffic
    from attached ports is matched against rules in these tables.
    """
    
    dataplaneClass = MPLSOVSVRFDataplane

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self)
        self.log.info("Initializing MPLSOVSVRFDataplane")
        
        try:
            (o,_) = self._runCommand("ovs-ofctl -V | head -1 | awk '{print $4}'")
            self.ovsRelease=o[0]
        except:
            self.log.warning("No OVS kernel module loaded")
            self.ovsRelease=None
        
        if StrictVersion(self.ovsRelease) < StrictVersion("2.3.90"):
            self.log.warning("%s requires at least OVS 2.3.90 (you are running %s)" % 
                            (self.__class__.__name__,self.ovsRelease))
        
        self.log.info("OVS kernel module %s" % self.ovsRelease)
        
        self.config = config
        
        try:
            self.mpls_interface = self.config["mpls_interface"]
        except KeyError:
            self.mpls_interface = None
        
        try:
            self.useGRE = (config["mpls_over_gre"].lower() == "true")
        except:
            self.useGRE = False if (self.mpls_interface and self.mpls_interface != "*gre*") else True
        
        if not self.mpls_interface:
            if not self.useGRE:
                raise Exception("mpls_over_gre force-disabled, but no mpls_interface specified")
            else:
                self.useGRE = True
                self.log.info("Defaulting to use of MPLS-over-GRE (no mpls_interface specified)")
        elif self.mpls_interface == "*gre*":
            if self.useGRE == False:
                raise Exception("mpls_over_gre force-disabled, but mpls_interface set to '*gre', cannot use bare MPLS")
            else:
                self.log.info("mpls_interface is '*gre*', will thus use MPLS-over-GRE")
                self.useGRE = True
                self.mpls_interface = None
        else:
            if self.useGRE:
                self.log.warning("mpls_over_gre set to True, ignoring mpls_interface parameter")
                self.mpls_interface = None
            else:
                self.log.info("Will use bare MPLS on interface %s" % self.mpls_interface)
        
        self.ovs_bridge = DEFAULT_OVS_BRIDGE
        try:
            self.ovs_bridge = self.config["ovs_bridge"]
        except KeyError:
            self.log.warning("No ovs_bridge configured, will use default: %s" % DEFAULT_OVS_BRIDGE)
        
        self.ovs_table_mpls = DEFAULT_OVS_TABLE
        try:
            self.ovs_table_mpls = int(self.config["ovs_table_mpls"])
        except KeyError:
            self.log.debug("No ovs_table_mpls configured, will use default table %s" % DEFAULT_OVS_TABLE)
        
        self.ovs_table_vrfs = DEFAULT_OVS_TABLE
        try:
            self.ovs_table_vrfs = int(self.config["ovs_table_vrfs"])
        except KeyError:
            self.log.debug("No ovs_table_vrfs configured, will use default table %s" % DEFAULT_OVS_TABLE)
        
        # check that fping is installed
        self._runCommand("fping -v")
        
        DataplaneDriver.__init__(self, config, init)
    
    def supportedEncaps(self):
        if self.useGRE:
            return [Encapsulation(Encapsulation.GRE),
                    Encapsulation(Encapsulation.DEFAULT) # we will accept routes with no encap specified and force the use of GRE 
                    ]
        else:
            return [Encapsulation(Encapsulation.MPLS)]
    
    def _initReal(self, config):
        self.log.info("Really initializing MPLSOVSVRFDataplane")
        
        # Check if OVS bridge exist
        (_, exitCode) = self._runCommand("ovs-vsctl br-exists %s" % self.ovs_bridge, raiseExceptionOnError=False)
        
        if exitCode == 2:
            raise exc.OVSBridgeNotFound(self.ovs_bridge)
        
        if not self.useGRE:
            self.log.info("Will not force the use of GRE/MPLS, trying to bind physical interface %s" % self.mpls_interface)
            # Check if MPLS interface is attached to OVS bridge
            (output, exitCode) = self._runCommand("ovs-vsctl port-to-br %s" % self.mpls_interface, raiseExceptionOnError=False)
            if not self.ovs_bridge == output[0]:
                raise Exception("Specified mpls_interface is not plugged to OVS bridge %s" % self.mpls_interface, self.ovs_bridge)
            else:
                self.ovsMplsIfPortNumber = self._find_ovs_port_number(self.mpls_interface)
        else:
            self.log.info("Setting up tunnel for MPLS/GRE (%s)" % GRE_TUNNEL)
            try:
                additional_tunnel_options = self.config["gre_tunnel_options"] # e.g. "options:l3port=true options:..."
            except:
                additional_tunnel_options = ""
            
            self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, GRE_TUNNEL), acceptableReturnCodes=[0,1])
            self._runCommand("ovs-vsctl add-port %s %s -- set Interface %s type=gre options:local_ip=%s options:remote_ip=flow %s" % 
                                                  (self.ovs_bridge, GRE_TUNNEL, GRE_TUNNEL, self.getLocalAddress(), additional_tunnel_options))
            
            self.ovsGRETunnelPortNumber = self._find_ovs_port_number(GRE_TUNNEL)

        # Fixup openflow version
        self._runCommand("ovs-vsctl set bridge %s protocols=OpenFlow10,OpenFlow12,OpenFlow13" % self.ovs_bridge)
 
    def _get_ovsbr_to_proxyarpns_devname(self, namespaceId):
        i = namespaceId.replace(ARPNETNS_PREFIX, "")
        return (OVSBR_INTERFACE_PREFIX + i)[:LINUX_DEV_LEN]

    def resetState(self):
        # Flush all MPLS and ARP flows, if bridge exists

        (_, exitCode) = self._runCommand("ovs-vsctl br-exists %s" % self.ovs_bridge, raiseExceptionOnError=False, acceptableReturnCodes=[0,2])
        if exitCode == 0:
            self.log.info("Cleaning up OVS rules")
            self._ovs_flow_del('mpls',self.ovs_table_mpls)
            self._ovs_flow_del('ip',self.ovs_table_vrfs)
            self._ovs_flow_del('arp',self.ovs_table_vrfs)
            if self.log.debug:
                self.log.debug("----- All our rules have been flushed -----")
                self._runCommand("ovs-ofctl dump-flows %s" % self.ovs_bridge)
                
        else:
            self.log.info("No OVS bridge (%s), no need to cleanup OVS rules" % self.ovs_bridge)
        
        # Flush all VRF patch ports
        (output, _) = self._runCommand("ovs-vsctl list-ports br-mpls | grep 'ipvpn.*-pp-'", raiseExceptionOnError=False,
                                      acceptableReturnCodes=[0, 1])
        if not output:
            if self.log.debug:
                self.log.debug("----- No VRF patch ports configured -----")
        else:
            for patch_port in output:
                self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, patch_port),
                                 acceptableReturnCodes=[0, 1, 2], raiseExceptionOnError=False)
        
        # Flush all (except DHCP, router, LBaaS, ...) network namespaces and corresponding veth pair devices
        (output, _) = self._runCommand("ip netns | grep -v '\<q' | grep '%s'" % ARPNETNS_PREFIX, raiseExceptionOnError=False,
                                      acceptableReturnCodes=[0, 1])
        if not output:
            if self.log.debug:
                self.log.debug("----- No network namespaces configured -----")
        else:
            for namespaceId in output:
                self.log.info("Cleaning up netns %s" % namespaceId)
                self._runCommand("ip netns delete %s" % namespaceId, raiseExceptionOnError=False)
                self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, self._get_ovsbr_to_proxyarpns_devname(namespaceId)),
                                 acceptableReturnCodes=[0, 1, 2], raiseExceptionOnError=False)
            if self.log.debug:
                self.log.debug("----- All network namespaces have been flushed -----")
                self._runCommand("ip netns")
    
                self.log.debug("----- All network namespace veth pairs have been flushed -----")
                self._runCommand("ifconfig")
                self._runCommand("ovs-vsctl list-ports %s" % self.ovs_bridge, acceptableReturnCodes=[0,1])

    def _cleanupReal(self):
        self.log.warning("not implemented yet!")

    #### Looking glass code ####

    def getLGMap(self):
        return {
                "flows": (LGMap.SUBTREE, self.getLGOVSFlows),
                "ports": (LGMap.SUBTREE, self.getLGOVSPorts)
                }

    def getLookingGlassLocalInfo(self, pathPrefix):
        d = {
                "ovs_bridge": self.ovs_bridge,
                "mpls_interface": self.mpls_interface,
                "ovs_table_vrfs": self.ovs_table_vrfs,
                "ovs_table_mpls": self.ovs_table_mpls,
                "gre": { 'enabled': self.useGRE },
                "ovs_module_version": self.ovsRelease
                }
        if self.useGRE:
            d["gre"].update({'tunnel_port': GRE_TUNNEL})
        return d
    
    def getLGOVSFlows(self, pathPrefix):
        # TODO: filter to only get flows from our tables
        (output, _) = self._runCommand("ovs-ofctl dump-flows %s %s" % (self.ovs_bridge,OVS_DUMP_FLOW_FILTER))
        return output

    def getLGOVSPorts(self, pathPrefix):
        (output, _) = self._runCommand("ovs-ofctl show %s |grep addr" % self.ovs_bridge)
        # FIXME: does it properly show the GRE tunnel interface
        return output

    def _find_ovs_port_number(self, dev_name):
        """ Find OVS port number from port name """
        ovs_port_number = -1
        (output, _) = self._runCommand("ovs-ofctl show %s" % self.ovs_bridge)
        for line in output:
            if ("(%s)" % dev_name) in line:
                ovs_port_number = re.search(r"\d+", line).group()
                
        if ovs_port_number == -1:
            raise Exception("OVS port not found on %s for device %s" % (self.ovs_bridge, dev_name))
            
        return ovs_port_number

    def _ovs_flow_add(self,flow,actions,table):
        self._runCommand("ovs-ofctl add-flow %s --protocol OpenFlow13 'table=%d,%s,actions=%s'" 
                                     % (self.ovs_bridge, table, flow, actions)
                                     )
    def _ovs_flow_del(self,flow,table):
        self._runCommand("ovs-ofctl del-flows %s --protocol OpenFlow13 'table=%d,%s'" 
                                     % (self.ovs_bridge, table, flow)
                                     )
