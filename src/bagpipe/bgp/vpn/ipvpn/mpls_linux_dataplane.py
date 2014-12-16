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


from netaddr.ip import IPNetwork

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass, LookingGlassLocalLogger


from bagpipe.bgp.common.run_command import runCommand


BRIDGE_NAME_PREFIX = "bns"
BRIDGE_INTERFACE_PREFIX = "bn-"
LINUX_DEV_LEN = 14
NAMESPACE_INTERFACE_PREFIX = "ns-"


class MPLSLinuxVRFDataplane(VPNInstanceDataplane, LookingGlass):
    '''
    Dataplane driver using MPLS code at github.com/i-maravic/MPLS-Linux.git, mpls-new branch (based on Linux 3.7rc4)
    '''
    
    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)
        
        self.namespaceId = self._get_namespace_from_network()
        
        self.log.info("VRF %d: Initializing network namespace %s" % (self.instanceId, self.namespaceId))
        if self._namespace_exists():
            self.log.debug("VRF network namespace already exists, flushing MPLS routes...")
            # Flush all MPLS routes in network namespace
            (output, _) = self._runCommand("ip netns exec %s ip route show" % self.namespaceId) 
            for line in output:
                if "mpls" in line:
                    self._runCommand("ip netns exec %s ip route del %s" % (self.namespaceId, line))
        else:
            self.log.debug("VRF network namespace doesn't exist, creating...")
            # Create network namespace
            self._runCommand("ip netns add %s" % self.namespaceId)
        
            # Set up mpls0 interface
            self._runCommand("ip netns exec %s ip link set mpls0 up" % self.namespaceId)
            
            # Set up veth pair devices
            (tap_dev, ns_dev) = self._create_veth_pair()
            
            # Retrieve broadcast IP address        
            ip = IPNetwork("%s/%s" % (self.gatewayIP, self.mask))
            broadcastIP = str(ip.broadcast)
        
            # Set up bridge network namespace interface as gateway
            self._runCommand("ip netns exec %s ip addr add %s/%s broadcast %s dev %s" % 
                             (self.namespaceId, self.gatewayIP, self.mask, broadcastIP, ns_dev),
                             raiseExceptionOnError=False)
            
            # Setup IP forwarding 
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/ip_forward\"" % self.namespaceId)
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/all/forwarding\"" % self.namespaceId)
    
            # Setup ARP proxying
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/%s/proxy_arp\"" % (self.namespaceId, ns_dev))
            self._runCommand("ip netns exec %s sh -c \"echo 1 > /proc/sys/net/ipv4/conf/%s/proxy_arp_pvlan\"" % (self.namespaceId, ns_dev)) 
            
            # Create bridge and adds tap interface on it
            self._create_namespace_bridge(tap_dev)

    def cleanup(self):
        bridge_name = self._get_bridge_name()

        # self.log.info("Cleaning routes that redirect traffic to network namespace %s" % self.namespaceId)
        self.log.warning("Cleaning routes that redirect traffic to network namespace %s  (NOT IMPLEMENTED CORRECTLY YET!)" % self.namespaceId)
        # FIXME: bogus!! will in fact delete all MPLS routes, including for other VRFs !!
        (output, returnCode) = self._runCommand("ip -M route show") 
        for line in output:
            if "netns" in line:
                self._runCommand("ip -M route del %s" % line)

        self.log.info("Cleaning VRF bridge %(bridge_name)s" % locals())
        self._runCommand("ip link set %(bridge_name)s down" % locals())
        self._runCommand("brctl delbr %(bridge_name)s" % locals())

        self.log.info("Cleaning VRF namespace %s" % self.namespaceId)
        self._runCommand("ip netns delete %s" % self.namespaceId)
                
                
    def _get_bridge_dev_name(self):
        return (BRIDGE_INTERFACE_PREFIX + self.namespaceId)[:LINUX_DEV_LEN]

    def _get_namespace_from_network(self):
        return self.externalInstanceId[:LINUX_DEV_LEN]

    def _get_ns_dev_name(self):
        return (NAMESPACE_INTERFACE_PREFIX + self.namespaceId)[:LINUX_DEV_LEN]

    def _get_bridge_name(self):
        return (BRIDGE_NAME_PREFIX + self.namespaceId)[:LINUX_DEV_LEN]

    def _namespace_exists(self):
        """ Check if network namespace exist. """
        (output, _) = self._runCommand("ip netns show")
        return (self.namespaceId in output)
    
    def _create_veth_pair(self):
        """ Create a pair of veth devices """
        bridge_to_ns = self._get_bridge_dev_name()
        ns_to_bridge = self._get_ns_dev_name()
        
        self._runCommand("ip link add %s type veth peer name %s netns %s" % (bridge_to_ns, ns_to_bridge, self.namespaceId))
        self._runCommand("ip link set dev %s up" % bridge_to_ns)
        self._runCommand("ip netns exec %s ip link set dev %s up" % (self.namespaceId, ns_to_bridge))
        
        return (bridge_to_ns, ns_to_bridge)
        
    def _bridge_exists(self, bridge):
        """Check if bridge exists."""
        # TODO: this code generate an ERROR self.log even when this is not a real error
        #       should use acceptableReturnCodes of _runCommand
        try:
            self._runCommand("ip link show dev %(bridge)s" % locals())
        except Exception:
            return False
        return True
    
    def _create_namespace_bridge(self, interface):
        """ Create bridge and add 'interface' to it """
        bridge_name = self._get_bridge_name()
        
        if not self._bridge_exists(bridge_name):
            self.log.debug("Starting bridge %(bridge_name)s" % locals())
            self._runCommand("brctl addbr %(bridge_name)s" % locals())
            self._runCommand("brctl setfd %(bridge_name)s 0" % locals())
            self._runCommand("brctl stp %(bridge_name)s off" % locals())
            self._runCommand("ip link set %(bridge_name)s up" % locals())

            self._runCommand("brctl addif %(bridge_name)s %(interface)s" % locals())
            self.log.debug("Bridge %(bridge_name)s started with interface %(interface)s added" % locals())
 
    
    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        self.log.debug("vifPlugged(%s, %s, %d)" % (ipAddress, localPort, label))

        if "lo" in localPort:
            self.log.debug("vifPlugged: Plugging loopback interface")
            self._runCommand("ip netns exec %s ip link set %s up" % (self.namespaceId, localPort))
            self._runCommand("ip netns exec %s ip addr add %s/32 dev %s" % (self.namespaceId, ipAddress, localPort), raiseExceptionOnError=False)
        else:
            self.log.debug("vifPlugged: Plugging local port %s" % localPort)
            bridge_name = self._get_bridge_name()
            
            # Attach VIF on network namespace bridge
            self._runCommand("brctl addif %(bridge_name)s %(localPort)s" % locals(), raiseExceptionOnError=False)
            
        # Add ip route to redirect traffic to the correct namespace depending on MPLS label
        self._runCommand("ip -M route add %d mpls pop 1 netns %s" % (label, self.namespaceId))

        if self.log.debug:
            self._runCommand("ip -M route show")
            self._runCommand("ip netns exec %s ip route show" % self.namespaceId)
        
    
    def vifUnplugged(self, macAddress, ipAddress, localPort, label, lastEnpoint=True):
        self.log.debug("vifUnplugged(%s, %s, %d)" % (ipAddress, localPort, label))

        # Remove ip route to disable traffic redirection to namespace depending on MPLS label
        self._runCommand("ip -M route del %d mpls pop 1 netns %s" % (label, self.namespaceId))

        if "lo" in localPort:
            self.log.debug("vifUnplugged: Unplugging loopback interface")
            self._runCommand("ip netns exec %s ip link set %s down" % (self.namespaceId, localPort))
            self._runCommand("ip netns exec %s ip addr del %s/32 dev %s" % (self.namespaceId, ipAddress, localPort))
        else:
            self.log.debug("vifUnplugged: Unplugging local port %s" % localPort)
            bridge_name = self._get_bridge_name()
            
            # Detach VIF from network namespace bridge
            self._runCommand("brctl delif %(bridge_name)s %(localPort)s" % locals(), raiseExceptionOnError=False)


    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, encaps):
        self.log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, self.driver.mpls_interface))

        self._runCommand("ip netns exec %s ip route replace %s mpls push %d global dev %s %s" % (self.namespaceId, prefix, label, self.driver.mpls_interface, remotePE))

        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))

        self._runCommand("ip netns exec %s ip route del %s mpls push %d global dev %s %s" % (self.namespaceId, prefix, label, self.driver.mpls_interface, remotePE))




class MPLSLinuxDataplaneDriver(DataplaneDriver, LookingGlass):
    """
    This dataplane driver relies on the MPLS stack for the Linux kernel at:
         https://github.com/i-maravic/iproute2/tree/mpls-new
         
    This kernel module is based on a Linux 3.7x version.
    
    This driver requires the corresponding iproute utility at:
         https://github.com/i-maravic/iproute2/tree/mpls-new
    
    This driver should be considered **obsolete** as this MPLS stack seems unmaintained.
    It wasn't tested against the most recent evolutions of bagpipe-bgp and may not fully work.
    """
    
    dataplaneClass = MPLSLinuxVRFDataplane

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self)
        self.log.info("Initializing MPLSLinuxVRFDataplaneDriver")
        
        DataplaneDriver.__init__(self, config, init)
        
    def _initReal(self, config):
        self.config = config
        self.log.info("Really initializing MPLSLinuxVRFDataplaneDriver")
        
        self._runCommand("modprobe mpls")
        
        if "*gre*" in self.config["mpls_interface"]:
            self.mpls_interface = "gre_wildcard"
            self._runCommand("ip tunnel add %s mode gre local %s remote 0.0.0.0" % (self.mpls_interface, self.getLocalAdress()), raiseExceptionOnError=False) 
            self._runCommand("ip link set %s up" % self.mpls_interface)
            self._runCommand("ip link set %s mpls on" % self.mpls_interface)
        else:
            self.mpls_interface = self.config["mpls_interface"]
            self._runCommand("ip link set %s mpls on" % self.mpls_interface)
        
        self._runCommand("ip link set mpls0 up")
        self._runCommand("ip link set lo mpls on")

    def resetState(self):
        # Flush all MPLS routes redirecting traffic to network namespaces
        (output, _) = self._runCommand("ip -M route show") 
        for line in output:
            if "netns" in line:
                self._runCommand("ip -M route del %s" % line)
            
        if self.log.debug:
            self.log.debug("----- All MPLS routes have been flushed -----")
            self._runCommand("ip -M route show")
        
        # Flush all namespaces MPLS routes
        (output, _) = self._runCommand("ip netns show")
        namespace_list = output
        if not namespace_list:
            if self.log.debug:
                self.log.debug("----- No namespaces are configured -----")
        else:
            for namespaceId in output:
                for line in self._runCommand("ip netns exec %s ip route show" % namespaceId)[0]:
                    if "mpls" in line:
                        self._runCommand("ip netns exec %s ip route del %s" % (namespaceId, line))
                    
                if self.log.debug:
                    self.log.debug("----- Namespace %s MPLS routes have been flushed -----" % namespaceId)
                    self._runCommand("ip netns exec %s ip route show" % namespaceId)
            

    def _cleanupReal(self):
        self.log.warning("not implemented yet!")
#         self._runCommand("ip link set %s mpls off" % self.mpls_interface)
#         if "*gre*" in self.config["mpls_interface"]:
#             self._runCommand("ip link set %s down" % self.mpls_interface)
#             self._runCommand("ip tunnel del %s" % self.mpls_interface)
#         self._runCommand("ip link set mpls0 down") 
        # self._runCommand("modprobe -r mpls")


    def _runCommand(self, command, *args, **kwargs):
        # if config['path_to_ip'] is set, use the value as the path to the ip tool
        #   e.g config['path_to_ip'] = /usr/local/sbin/ip
        # ditto for mpls tool
        for tool in ['ip', 'mpls']:
            if command.startswith(tool + " ") and ('path_to_' + tool) in self.config:
                command = command.replace(tool + " ", self.config['path_to_' + tool] + " ")

        if (("debug" in self.config) and self.config["debug"] == "1"):
            self.log.info("debug mode / would have run: %s" % command)
            return [""]
        else:
            return runCommand(self.log, command, *args, **kwargs)



