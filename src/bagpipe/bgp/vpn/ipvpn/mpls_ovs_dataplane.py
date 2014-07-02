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


import logging

import re

from netaddr.ip import IPNetwork


from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver
from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap


import bagpipe.bgp.common.exceptions as exc
from bagpipe.bgp.common.run_command import runCommand

log = logging.getLogger(__name__)


DEFAULT_OVS_BRIDGE = "br-int"

LINUX_DEV_LEN = 14
OVSBR_INTERFACE_PREFIX = "tonsarp-"

# name of the veth device in the ARP proxy network namespace,
# whose remote end is plugged in the OVS bridge 
PROXYARP2OVS_IF = "ovs"

ARPNETNS_PREFIX = "arpns"

# Prefix used by the NOVA hybrid VIF driver 
# for the OVS port corresponding to the VM tap port
OVS_LINUXBR_INTERFACE_PREFIX = "qvo"


class MPLSOVSVRFDataplane(VPNInstanceDataplane, LookingGlass):
    
    def __init__(self, *args):
        VPNInstanceDataplane.__init__(self, *args)
        
        self.namespaceId = "%s%s" % (ARPNETNS_PREFIX, self._get_namespace_from_network())
        
        # Initialize dict where we store info on OVS ports (port numbers and bound IP address)
        self._ovsPortInfo = dict()
        
        # Find ethX MPLS interface MAC address
        self.mplsIfMacAddress = self._find_dev_mac_address(self.driver.mpls_interface)
        
        self.ovs_bridge = self.driver.ovs_bridge 
        
        # Find OVS port number corresponding to ethX MPLS interface 
        # TODO: move this in dataplane driver
        self.ovsMplsIfPortNumber = self._find_ovs_port_number(self.driver.mpls_interface)
    
    def initialize(self):
        log.info(" VRF %d: Initializing network namespace %s for ARP proxing" % (self.instanceId, self.namespaceId))
        # Get names of veth pair devices between OVS and network namespace
        ovsbr_to_proxyarp_ns = self.driver._get_ovsbr_to_proxyarpns_devname(self.namespaceId)
        
        if not self._namespace_exists():
            log.debug("VRF network namespace doesn't exist, creating...")
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
            log.debug("VRF network namespace already exists...")

        # Find OVS port number corresponding to "OVS to network namespace" port name
        self.ovsToNsPortNumber = self._find_ovs_port_number(ovsbr_to_proxyarp_ns)
        
        # Find gateway ("network namespace to OVS" port) MAC address
        self.gwMacAddress = self._find_ns_dev_mac_address(self.namespaceId, PROXYARP2OVS_IF)
        

    def cleanup(self):
        if self._ovsPortInfo:
            log.warning("OVS port numbers list for local ports plugged in VRF is not empty, clearing...")
            self._ovsPortInfo.clear()
        
        log.info("Cleaning VRF network namespace %s" % self.namespaceId)
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
            log.warning("Nova hybrid vif driver hack: mapping %s into %s" % (localport,new_localport))
            return new_localport
        else:
            return localport

    def _get_namespace_from_network(self):
        return self.vpnInstanceId[:LINUX_DEV_LEN]

    def _namespace_exists(self):
        """ Check if network namespace exist. """
        (output, _) = self._runCommand("ip netns show")
        return (self.namespaceId in output)
    
    def _create_veth_pair(self, ovsbr_to_proxyarp_ns, proxyarp_ns_to_ovsbr):
        """ Create a pair of veth devices, one end being created in the ARP netns """
        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            mtu = 1500
        log.info("Will create %s interface with MTU %s (change with ovsbr_interfaces_mtu in ipvpn section of bagpipe config)" % (ovsbr_to_proxyarp_ns, mtu))

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

    def _extract_mac_address(self, output):
        """ Extract MAC address from command output """
        log.debug("Extracting MAC address from output: %s" % output)
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
        (_, exitCode) = self._runCommand("fping -r4 -t100 -q %s" % remote_ip)
        if exitCode != 0:
            raise exc.RemotePEMACAddressNotFound(remote_ip)
        
        # Look in ARP cache to find remote MAC address
        (output, _) = self._runCommand("ip neigh show to %s dev %s" % (remote_ip, self.ovs_bridge))
        
        if "FAILED" in output[0]:
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
        log.info("Will adjust %s interface with MTU %s (change with ovsbr_interfaces_mtu in ipvpn section of bagpipe config)" % (interface, mtu))

        (_, exitCode) = self._runCommand("ip link show %s" % interface, raiseExceptionOnError=False)
        
        if exitCode != 0:
            raise Exception("Interface %s does not exist" % interface)
        
        self._runCommand("ip link set %s mtu %s" % (interface, mtu))

    def _vifPluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("_vifPluggedReal: Plugging local port (%(localPort)s, %(ipAddress)s, %(label)d)" % locals())

        self._mtu_fixup(self._hack_localport_for_hybrid_vif_driver(localPort))

        # Find OVS port number corresponding to Linux bridge attached interface
        localport = self._hack_localport_for_hybrid_vif_driver(localPort)
        ovs_port_number = self._find_ovs_port_number(localport)
            
        # Map ARP traffic from VIF to ARP proxy and response from ARP proxy to VIF
        self._runCommand("ovs-ofctl add-flow %s 'in_port=%s,arp,actions=output:%s'" % (self.ovs_bridge, ovs_port_number, self.ovsToNsPortNumber))
        self._runCommand("ovs-ofctl add-flow %s 'in_port=%s,arp,arp_tha=%s,actions=output:%s'" % (self.ovs_bridge, self.ovsToNsPortNumber, macAddress, ovs_port_number))

        # Map traffic from VIF to gateway and response from gateway to VIF
        self._runCommand("ovs-ofctl add-flow %s 'in_port=%s,ip,nw_dst=%s,actions=output:%s'" % (self.ovs_bridge, ovs_port_number, self.gatewayIP, self.ovsToNsPortNumber))
        self._runCommand("ovs-ofctl add-flow %s 'in_port=%s,ip,nw_dst=%s,actions=output:%s'" % (self.ovs_bridge, self.ovsToNsPortNumber, ipAddress, ovs_port_number))

        # Map incoming MPLS traffic going to the VM
        self._runCommand("ovs-ofctl add-flow %s 'priority=65535,in_port=%s,mpls,mpls_label=%d,actions=pop_mpls:0x0800,mod_dl_src:%s,mod_dl_dst:%s,output:%s'" % (self.ovs_bridge, self.ovsMplsIfPortNumber, label, self.gwMacAddress, macAddress, ovs_port_number))
        
        # Add OVS port number in list for local port plugged in VRF
        log.debug("Adding OVS port %s with number %s for address %s to ports plugged in VRF list" % (localport, ovs_port_number, ipAddress))
        ovs_port_dict = dict()
        ovs_port_dict["port_number"] = ovs_port_number
        ovs_port_dict["ip_address"] = ipAddress
        self._ovsPortInfo[localport] = ovs_port_dict
        
    
    def _vifUnpluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("_vifUnpluggedReal: Unplugging local port (%(localPort)s, %(ipAddress)s, %(label)d)" % locals())

        # Find OVS port number corresponding to Linux bridge attached interface
        localport = self._hack_localport_for_hybrid_vif_driver(localPort)
        ovs_port_number = self._ovsPortInfo[localport]["port_number"]
        
        # FIXME: what about local VMs ??
        # do we properly clean up the resubmit flow in setupDataplaneForRemoteEndpoint?
        
        # Unmap incoming MPLS traffic going to the VM
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,mpls,mpls_label=%d'" % (self.ovs_bridge, self.ovsMplsIfPortNumber, label))

        # Unmap traffic to local or remote VMs as MPLS from ethX 
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,ip'" % (self.ovs_bridge, ovs_port_number))

        # Unmap traffic from VIF to gateway and response from gateway to VIF
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,ip,nw_dst=%s'" % (self.ovs_bridge, ovs_port_number, self.gatewayIP))
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,ip,nw_dst=%s'" % (self.ovs_bridge, self.ovsToNsPortNumber, ipAddress))

        # Unmap ARP traffic from VIF to ARP proxy and response from ARP proxy to VIF
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,arp'" % (self.ovs_bridge, ovs_port_number))
        self._runCommand("ovs-ofctl del-flows %s 'in_port=%s,arp,arp_tha=%s'" % (self.ovs_bridge, self.ovsToNsPortNumber, macAddress))

        # Remove OVS port number from list for local port plugged in VRF 
        del self._ovsPortInfo[localport]


    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, self.driver.mpls_interface))

        dec_ttl_action = ""
        if IPNetwork(repr(prefix)) not in IPNetwork("%s/%s" % (self.gatewayIP, self.mask)):
            dec_ttl_action = "dec_ttl,"

        # Check if prefix locally added
        if self.driver.local_address == str(remotePE):
            # For local traffic, we have to use a resubmit action
            log.debug("OVS port numbers list for local port plugged in VRF: %s" % self._ovsPortInfo)
            for port_info in self._ovsPortInfo.values():
                # FIXME: not sufficient in the case where a whole prefix is bound to a VRF (enough when /32 are)
                if port_info["ip_address"] != prefix:
                    self._runCommand("ovs-ofctl add-flow %s --protocol OpenFlow13 'priority=65535,ip,in_port=%s,nw_dst=%s actions=%spush_mpls:0x8847,load:%s->OXM_OF_MPLS_LABEL[],resubmit:%s'" 
                                     % (self.ovs_bridge, port_info["port_number"], prefix, dec_ttl_action, label, self.ovsMplsIfPortNumber))
        else:
            try:
                # Find remote router MAC address
                remotePE_mac_address = self._find_remote_mac_address(remotePE)
                log.debug("MAC address found for remote router %(remotePE)s: %(remotePE_mac_address)s" % locals())
        
                # Map traffic to remote IP address as MPLS on ethX to remote router MAC address
                log.debug("OVS port numbers list for local port plugged in VRF: %s" % self._ovsPortInfo)
                for port_info in self._ovsPortInfo.values():
                    self._runCommand("ovs-ofctl add-flow %s --protocol OpenFlow13 'priority=65535,ip,in_port=%s,nw_dst=%s actions=%spush_mpls:0x8847,load:%s->OXM_OF_MPLS_LABEL[],mod_dl_src:%s,mod_dl_dst:%s,output:%s'" 
                                     % (self.ovs_bridge, port_info["port_number"], prefix, dec_ttl_action, label, self.mplsIfMacAddress, remotePE_mac_address, self.ovsMplsIfPortNumber))
            except exc.RemotePEMACAddressNotFound as e:
                log.error('An error occured during setupDataplaneForRemoteEndpoint: %s' % e)

        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri):
        log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s, %s)" % (prefix, remotePE, label, dataplaneInfo, self.driver.mpls_interface))

        # Check if prefix locally removed
        if self.driver.local_address == str(remotePE):
            # Unmap local traffic from other VMs from the VM as MPLS on ethX
            for ovs_linuxbr_info in self._ovsPortInfo.values():
                self._runCommand("ovs-ofctl del-flows %s 'ip,in_port=%s,nw_dst=%s'" % (self.ovs_bridge, ovs_linuxbr_info["port_number"], prefix))
        else:
            try:
                # Find remote router MAC address
                remotePE_mac_address = self._find_remote_mac_address(remotePE)
                log.debug("MAC address %(remotePE_mac_address)s found for remote router %(remotePE)s" % locals())
        
                # Unmap traffic to remote IP address as MPLS on ethX from remote router MAC address
                for ovs_linuxbr_info in self._ovsPortInfo.values():
                    self._runCommand("ovs-ofctl del-flows %s 'ip,in_port=%s,nw_dst=%s'" % (self.ovs_bridge, ovs_linuxbr_info["port_number"], prefix))
            except exc.RemotePEMACAddressNotFound as e:
                log.error('An error occured during removeDataplaneForRemoteEndpoint: %s' % e)




class MPLSOVSDataplaneDriver(DataplaneDriver, LookingGlass):
    """
    Dataplane driver using OpenVSwitch 
       
    Based on an OpenVSwtich MPLS implementation to be included in OVS 2.2.
    
    In the meantime, the master openvswitch git repository can be used:
	https://github.com/openvswitch/ovs.git
   
    Currently, the code is tweaked to work with the Openstack Nova hybrid VIF driver:
    if the provided localport is recognized as an Openstack tap<uuid> port, 
    the actual port which the driver will bind to the VRF will be the
    corresponding qvo<uuid> port, which is assumed to be already plugged into the OVS
    bridge.
    
    This driver currently requires that the OVS bridge be associated to the address
    used as the local_address in bgp.conf, to allow the linux IP stack to use the same
    physical interface as the one on which MPLS packets are forwarded. This requires
    to configure the OVS bridge so that it passes packets from the physical interface
    to the linux IP stack if they are not MPLS, and packets from the linux IP stack to 
    the physical device.
    
    Howto allow the use of the OVS bridge interface also as an IP 
    interface of the Linux kernel IP stack:
        ovs-ofctl del-flows br-int
        ovs-ofctl add-flow br-int in_port=LOCAL,action=output:1
        ovs-ofctl add-flow br-int in_port=1,action=output:LOCAL

    (on a debian or ubuntu system, this can be done part of the ovs bridge definition 
    in /etc/network/interfaces, as post-up commands)
    """
    
    dataplaneClass = MPLSOVSVRFDataplane

    def __init__(self, config, init=True):
        log.info("Initializing MPLSOVSVRFDataplane")
        
        self.config = config
        self.mpls_interface = self.config["mpls_interface"]
        
        try:
            self.ovs_bridge = self.config["ovs_bridge"]
        except KeyError:
            log.warning("No ovs_bridge defined, will use default: %s" % DEFAULT_OVS_BRIDGE)
            self.ovs_bridge = DEFAULT_OVS_BRIDGE
        
        # check that fping is installed
        self._runCommand("fping -v")
        
        DataplaneDriver.__init__(self, config, init)

        
    def _initReal(self, config):
        log.info("Really initializing MPLSOVSVRFDataplane")
        
        self.local_address = self.config["local_address"]
        
        # Check if OVS bridge exist
        (_, exitCode) = self._runCommand("ovs-vsctl br-exists %s" % self.ovs_bridge, raiseExceptionOnError=False)
        
        if exitCode == 2:
            raise exc.OVSBridgeNotFound(self.ovs_bridge)
        
        # Check if MPLS interface is attached to OVS bridge
        (output, exitCode) = self._runCommand("ovs-vsctl port-to-br %s" % self.mpls_interface, raiseExceptionOnError=False)
        if not self.ovs_bridge in output:
            raise exc.OVSBridgePortNotFound(interface=self.mpls_interface, bridge=self.ovs_bridge)

        # Fixup openflow version
        self._runCommand("ovs-vsctl set bridge %s protocols=OpenFlow10,OpenFlow12,OpenFlow13" % self.ovs_bridge)
        
        # flag to trigger cleanup all dataplane states on first call to vifPlugged
        self.firstVRFInit = True  # FIXME: this should be done in the super class
 
    def _get_ovsbr_to_proxyarpns_devname(self, namespaceId):
        i = namespaceId.replace(ARPNETNS_PREFIX, "")
        return (OVSBR_INTERFACE_PREFIX + i)[:LINUX_DEV_LEN]

    def resetState(self):
        # Flush all MPLS and ARP flows
        self._runCommand("ovs-ofctl del-flows %s 'mpls'" % self.ovs_bridge, raiseExceptionOnError=False) 
        self._runCommand("ovs-ofctl del-flows %s 'ip'" % self.ovs_bridge, raiseExceptionOnError=False) 
        self._runCommand("ovs-ofctl del-flows %s 'arp'" % self.ovs_bridge, raiseExceptionOnError=False) 

        if log.debug:
            log.debug("----- All MPLS flows have been flushed -----")
            self._runCommand("ovs-ofctl dump-flows %s" % self.ovs_bridge)
        
        # Flush all (except DHCP, router, LBaaS, ...) network namespaces and corresponding veth pair devices
        (output, _) = self._runCommand("ip netns | grep -v '\<q' | grep '%s'" % ARPNETNS_PREFIX, raiseExceptionOnError=False,
                                      acceptableReturnCodes=[0, 1])
        if not output:
            if log.debug:
                log.debug("----- No network namespaces configured -----")
        else:
            for namespaceId in output:
                log.info("Cleaning up netns %s" % namespaceId)
                self._runCommand("ip netns delete %s" % namespaceId, raiseExceptionOnError=False)
                self._runCommand("ovs-vsctl del-port %s %s" % (self.ovs_bridge, self._get_ovsbr_to_proxyarpns_devname(namespaceId)),
                                 acceptableReturnCodes=[0, 1, 2], raiseExceptionOnError=False)

            if log.debug:
                log.debug("----- All network namespaces have been flushed -----")
                self._runCommand("ip netns")
    
                log.debug("----- All network namespace veth pairs have been flushed -----")
                self._runCommand("ifconfig")
                self._runCommand("ovs-vsctl list-ports %s" % self.ovs_bridge)

    def _initializeInstanceReal(self, vrfDataplane):
        
        log.info("Prepare for initializing VRF %d..." % vrfDataplane.instanceId)
        
        # reset dataplane state on first call to vifPlugged
        if self.firstVRFInit:
            log.info("First VRF init, resetting MPLS dataplane state")
            try:
                self.resetState()
            except Exception as e:
                log.error("Exception while resetting dataplane state: %s" % e)
            self.firstVRFInit = False
        else:
            log.debug("(not resetting MPLS dataplane state)")
    

    def _cleanupReal(self):
        log.warning("not implemented yet!")


    def _runCommand(self, command, *args, **kwargs):
        # if config['path_to_ip'] is set, use the value as the path to the ip tool
        #   e.g config['path_to_ip'] = /usr/local/sbin/ip
        # ditto for mpls tool
        for tool in ['ip', 'mpls']:
            if command.startswith(tool + " ") and ('path_to_' + tool) in self.config:
                command = command.replace(tool + " ", self.config['path_to_' + tool] + " ")

        if (("debug" in self.config) and self.config["debug"] == "1"):
            log.info("debug mode / would have run: %s" % command)
            return ([""], 0)
        else:
            return runCommand(log, command, *args, **kwargs)

    #### Looking glass code ####

    def getLGMap(self):
        return {
                "flows": (LGMap.SUBTREE, self.getLGOVSFlows),
                "ports": (LGMap.SUBTREE, self.getLGOVSPorts)
                }

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
                "ovs_bridge": self.ovs_bridge,
                "mpls_interface": self.mpls_interface 
                }
    
    def getLGOVSFlows(self, pathPrefix):
        (output, _) = self._runCommand("ovs-ofctl dump-flows %s| perl -pe 's/ *cookie=0x0, duration=[^,]+, table=0, //; s/ *n_bytes=[^,]+, //; s/ *(hard|idle)_age=[^,]+, //g'" % self.ovs_bridge)
        return output

    def getLGOVSPorts(self, pathPrefix):
        (output, _) = self._runCommand("ovs-ofctl show %s |grep addr" % self.ovs_bridge)
        return output

