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

from netaddr.ip import IPNetwork

import subprocess, shlex
import os

from threading import Thread
from threading import Lock

from bagpipe.bgp.common import utils

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from bagpipe.bgp.common.looking_glass import LookingGlass


from bagpipe.bgp.common.run_command import runCommand

log = logging.getLogger(__name__)


class MPLSLinux32VRFDataplane(VPNInstanceDataplane, LookingGlass):
    
    def __init__(self, *args):
        VPNInstanceDataplane.__init__(self, *args)
        self._runCommand("ip route flush table %d" % self.instanceId)
    
    def initialize(self): 
        log.info("Initialize")    
    
    def _vifPluggedReal(self, macAddress, ipAddress, localPort, label):
        
        nhlfe_key = self.getNHLFEKey()

        # Retrieve network and broadcast IP addresses        
        ip = IPNetwork("%s/%s" % (ipAddress, self.mask))
        networkIP = str(ip.network)
        broadcastIP = str(ip.broadcast)
        
        self._runCommand("ip link set %(localPort)s up" % locals())
        
        # Add MPLS dataplane for traffic going to this VIF
        self._runCommand("mpls labelspace set %(localPort)s 0" % locals())
        self._runCommand("mpls nhlfe add key 0x%(nhlfe_key)x instructions nexthop %(localPort)s %(ipAddress)s" % locals())
        self._runCommand("mpls ilm   add label gen %(label)d labelspace 0" % locals())
        self._runCommand("mpls xc    add ilm_label gen %(label)d ilm_labelspace 0 nhlfe_key 0x%(nhlfe_key)x" % locals())

        # Add ip route to let traffic between VMs on a same host take a shortcut, without going through MPLS encap
        # Added only if sets of import/export RTs have a non-zero intersection
        # if (self.rtIntersection):  
        self._runCommand("ip route add table %d %s dev %s" % (self.instanceId, ipAddress, localPort))

        # Add ip rule so that traffic from this VIF is routed in the right ip route table
        ip_rule_entry = self.getIPRuleEntry()
        self._runCommand("ip rule add priority %(ip_rule_entry)d iif %(localPort)s lookup %(instanceId)d" % locals() + self.__dict__)
        ip_rule_entry_2 = self.getIPRuleEntry()
        self._runCommand("ip rule add priority %(ip_rule_entry_2)d iif %(localPort)s unreachable" % locals())  # # FIXME: to be tested
        
        self._setupARPProxying(localPort, ipAddress, networkIP, broadcastIP)
        
        if log.debug:
            self._runCommand("mpls show")
            self._runCommand("ip route show table %d" % self.instanceId)
        
        # store info so that we find it at vifUnplug time
        self.dataplanePortsData[localPort]['nhlfe_key'] = nhlfe_key
        self.dataplanePortsData[localPort]['ip_rule_entry'] = ip_rule_entry
        self.dataplanePortsData[localPort]['ip_rule_entry_2'] = ip_rule_entry_2
        
    def _vifUnpluggedReal(self, macAddress, ipAddress, localPort, label):
            
        nhlfe_key = self.dataplanePortsData[localPort]['nhlfe_key']
        ip_rule_entry = self.dataplanePortsData[localPort]['ip_rule_entry']
        ip_rule_entry_2 = self.dataplanePortsData[localPort]['ip_rule_entry_2']
        
        self._runCommand("mpls xc    delete ilm_label gen %(label)d ilm_labelspace 0 nhlfe_key 0x%(nhlfe_key)x" % locals())
        self._runCommand("mpls ilm   delete label gen %(label)d labelspace 0" % locals())
        self._runCommand("mpls nhlfe delete key 0x%(nhlfe_key)x" % locals())
        
        self._runCommand("ip rule delete priority %(ip_rule_entry)d" % locals())
        self._runCommand("ip rule delete priority %(ip_rule_entry_2)d iif %(localPort)s unreachable" % locals())  # # FIXME: see above, to be tested
       
        # disable ARP proxying
        process = self.dataplanePortsData[localPort]['fakeARPDprocess']
        thread = self.dataplanePortsData[localPort]['fakeARPDthread'] 
        self._killFakeARPd(localPort, thread, process)
        
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label):
        log.info("setupDataplaneForRemoteEndpoint(%(instanceId)d,%(prefix)s,%(remotePE)s,%(label)d)" % locals())
        
        vrfId = self.instanceId
        nhlfe_key = self.getNHLFEKey()
        
        self._runCommand("mpls nhlfe add key 0x%(nhlfe_key)x instructions push gen %(label)d nexthop gre_wildcard %(remotePE)s" % locals())
        self._runCommand("ip route add table %(instanceId)d %(prefix)s dev lo mpls 0x%(nhlfe_key)x" % locals())
        
        return nhlfe_key

        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo):
        log.info("removeDataplaneForRemoteEndpoint(%(prefix)s,%(remotePE)s,%(label)d, %(dataplaneInfo)s)" % locals())

        vrfId = self.instanceId
        nhlfe_key = dataplaneInfo

        self._runCommand("ip route delete table %(instanceId)d %(prefix)s dev lo mpls 0x%(nhlfe_key)x" % locals())
        self._runCommand("mpls nhlfe delete key 0x%(nhlfe_key)x" % locals())


    def _setupARPProxying(self, localPort, ipAddress, networkIP, broadcastIP):
        log.info("MPLSLinuxVRFDataplaneDriverFakeARPd: setting up fake ARP resolver")

        # farpd will complain if we haven't set an address on the interface, so let's set one
        self._runCommand("ip addr add %s/%s dev %s" % (self.gatewayIP, self.mask, localPort), raiseExceptionOnError=False)
                
        # remove the routes below from the 'local' table
        self._runCommand("ip route del table local broadcast %s dev %s  proto kernel  scope link  src %s" % (networkIP, localPort, self.gatewayIP), raiseExceptionOnError=False)
        self._runCommand("ip route del table local local %s dev %s  proto kernel  scope host  src %s" % (self.gatewayIP, localPort, self.gatewayIP), raiseExceptionOnError=False)
        self._runCommand("ip route del table local broadcast %s dev %s  proto kernel  scope link  src %s" % (broadcastIP, localPort, self.gatewayIP), raiseExceptionOnError=False)
        
        # remove the route from the 'main' table        
        self._runCommand("ip route del table main %s/%s dev %s" % (networkIP, self.mask, localPort), raiseExceptionOnError=False)
        
        # we also need to disable linux rp_filter (or the paranoid-mode will drop the packets coming from the VM because there is not route for their source IP) 
        self._runCommand("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter" % locals())
        self._runCommand("echo 0 > /proc/sys/net/ipv4/conf/%(localPort)s/rp_filter" % locals())
        
        # run "arpd -i localPort -d" and keep track of the process
        thread = Thread(target=runFakeARPd, args=(localPort, self.dataplanePortsData[localPort]))
        self.dataplanePortsData[localPort]['fakeARPDthread'] = thread
                     
        thread.start()

    def _killFakeARPd(self, localPort, thread, process):
             
        log.info("Killing fakeARPd process for port %s (process %d)" % (localPort, process.pid))
        
        process.kill()
        thread.join()

    def cleanup(self):
        self._runCommand("ip route flush table %d" % self.instanceId)
        
        for port in self.dataplanePortsData:
            self._killFakeARPd(port)


class MPLSLinux32DataplaneDriver(DataplaneDriver, LookingGlass):
    """
    This dataplane driver relies on the MPLS stack for the Linux kernel that can be found at:
         https://github.com/i-maravic/MPLS-Linux/tree/master
         
    This kernel module is based on a Linux 3.2rc4 version.
    
    This driver requires the corresponding iproute utility at:
         https://github.com/i-maravic/iproute2/tree/master 
    
    This driver should be considered **obsolete** as this MPLS stack seems unmaintained.
    It wasn't tested against the most recent evolutions of bagpipe-bgp and may not fully work.
    """

    dataplaneClass = MPLSLinux32VRFDataplane

    def __init__(self, config, init=True):
        DataplaneDriver.__init__(self, config, init)
        
        self.lock = Lock()
        
    def _initReal(self, config):
        self.nhlfe_key = 20
        self.ip_rule_entry = 10000
        
        log.info("Initializing MPLSLinuxVRFDataplaneDriver")
        
        self._runCommand("modprobe mpls")
        self._runCommand("modprobe mpls4")
        
        self._runCommand("ip tunnel add gre_wildcard mode gre local %s remote 0.0.0.0" % config['local_address']) 
        self._runCommand("ip link set gre_wildcard up")
        self._runCommand("mpls labelspace set gre_wildcard 0")
        
        # for all interfaces that are not openstack ifs, do a lookup in local
        # incomplete code, but this is ok, this driver is obsolete anyways...
        interfaces = ["lo", "eth0", "eth1", "eth2"]
        for interface in interfaces:
            self._runCommand("ip rule add priority 1 iif %(interface)s lookup local" % locals())
        
        self._runCommand("ip rule delete priority 0", raiseExceptionOnError=False)

        # enable MPLS debugging in debug mode
        if 'mpls_dataplane_debug' in config and config['mpls_dataplane_debug'] is True:
            self._runCommand("echo 1 > /proc/sys/net/mpls/debug" % locals())
        else:
            self._runCommand("echo 0 > /proc/sys/net/mpls/debug" % locals())
        
        # flag to trigger cleanup all MPLS states on first call to vifPlugged
        self.firstVRFInit = True 
 
    def resetState(self):

        if log.debug:
            self._runCommand("mpls show")

        for line in self._runCommand("mpls xc")[0]:
            (_xc, _entry, _ilm_label, _gen, labelvalue, _ilm_labelspace, labelspace, _nhlfe_key, key) = line.split(" ", 8)
            self._runCommand("mpls xc del ilm_label gen %(labelvalue)s ilm_labelspace %(labelspace)s nhlfe_key %(key)s" % locals())

        for line in self._runCommand("mpls ilm")[0]:
            if len(line) == 0 or line.startswith(" ") or line.startswith("\t"):
                continue
            (_ILM, _entry, _label, _gen, label, _labelspace, labelspace, _all_the_rest_) = line.split(" ", 7)
            self._runCommand("mpls ilm del label gen %(label)s labelspace %(labelspace)s" % locals())
   
        for line in self._runCommand("mpls nhlfe")[0]:
            if len(line) == 0 or line.startswith(" ") or line.startswith("\t"): continue 
            (_NHLFE, _entry, _key, key, _all_the_rest_) = line.split(" ", 4)
            self._runCommand("mpls nhlfe del key %(key)s" % locals())
    
        if log.debug:
            self._runCommand("mpls show")
            
            
    @utils.synchronized
    def getNHLFEKey(self):
        nhlfe_key = self.nhlfe_key
        self.nhlfe_key += 1
        return nhlfe_key
    
    @utils.synchronized
    def getIPRuleEntry(self):
        entry = self.ip_rule_entry
        self.ip_rule_entry += 1
        return entry
    
    def _cleanupReal(self):
        # TODO: revert our "ip rule" rules, unload modules etc.
        self._runCommand("ip rule add priority 0 from all lookup local")
        for interface in ['lo', 'eth0', 'eth1', 'eth2']: 
            self._runCommand("ip rule delete priority 1 iif %(interface)s lookup local" % locals())


    def _initializeInstanceReal(self, vrfDataplane):
        
        log.info("Prepare for initializing VRF %d..." % vrfDataplane.instanceId)
        
        # reset MPLS state on first call to vifPlugged
        if self.firstVRFInit:
            log.info("First VRF init, resetting dataplane state")
            try:
                self.resetState()
            except Exception as e:
                log.error("Exception while resetting dataplane state: %s" % e)
            self.firstVRFInit = False
        else:
            log.debug("(not resetting dataplane state)")

    
    def _runCommand(self, command, *args, **kwargs):
        # if config['path_to_ip'] is set, use the value as the path to the ip tool
        #   e.g config['path_to_ip'] = /usr/local/sbin/ip
        # ditto for mpls tool
        for tool in ['ip', 'mpls']:
            if command.startswith(tool + " ") and ('path_to_' + tool) in self.config:
                command = command.replace(tool + " ", self.config['path_to_' + tool], 1)
                
        if (("debug" in self.config) and self.config["debug"] == "1"):
            log.info("debug mode / would have run: %s" % command)
            return [""]
        else:
            return runCommand(log, command, *args, **kwargs)
    

                
def runFakeARPd(localPort, data):
    log.info("Starting fakeARPd on port %s" % localPort)
    
    # OUTPUT = open('/dev/null', 'w')
    if log.debug:
        ofile = '/tmp/farpd.%s.log' % os.getpid()
    else:
        ofile = '/dev/null'
        
    OUTPUT = open(ofile, 'w') 

    command = "farpd -d -i %s" % localPort
    log.debug("farpd command: %s" % command)
    log.debug("logging to %s" % ofile)
    
    process = subprocess.Popen(shlex.split(command), stdout=OUTPUT, stderr=OUTPUT, close_fds=True)
    
    log.info("fakeARPd on port %s is process %d" % (localPort, process.pid))
    
    data['process'] = process

                


BRIDGE_NAME_PREFIX = "bns"
BRIDGE_INTERFACE_PREFIX = "bn-"
LINUX_DEV_LEN = 14
NAMESPACE_INTERFACE_PREFIX = "ns-"


class MPLSLinuxVRFDataplane(VPNInstanceDataplane, LookingGlass):
    '''
    Dataplane driver using MPLS code at github.com/i-maravic/MPLS-Linux.git, mpls-new branch (based on Linux 3.7rc4)
    '''
    
    def __init__(self, *args):
        VPNInstanceDataplane.__init__(self, *args)
        
        self.namespaceId = self._get_namespace_from_network()
        
    def initialize(self): 
        log.info("VRF %d: Initializing network namespace %s" % (self.instanceId, self.namespaceId))
        
        if self._namespace_exists():
            log.debug("VRF network namespace already exists, flushing MPLS routes...")
            # Flush all MPLS routes in network namespace
            (output, _) = self._runCommand("ip netns exec %s ip route show" % self.namespaceId) 
            for line in output:
                if "mpls" in line:
                    self._runCommand("ip netns exec %s ip route del %s" % (self.namespaceId, line))
        else:
            log.debug("VRF network namespace doesn't exist, creating...")
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

        # log.info("Cleaning routes that redirect traffic to network namespace %s" % self.namespaceId)
        log.warning("Cleaning routes that redirect traffic to network namespace %s  (NOT IMPLEMENTED CORRECTLY YET!)" % self.namespaceId)
        # FIXME: bogus!! will in fact delete all MPLS routes, including for other VRFs !!
        (output, returnCode) = self._runCommand("ip -M route show") 
        for line in output:
            if "netns" in line:
                self._runCommand("ip -M route del %s" % line)

        log.info("Cleaning VRF bridge %(bridge_name)s" % locals())
        self._runCommand("ip link set %(bridge_name)s down" % locals())
        self._runCommand("brctl delbr %(bridge_name)s" % locals())

        log.info("Cleaning VRF namespace %s" % self.namespaceId)
        self._runCommand("ip netns delete %s" % self.namespaceId)
                
                
    def _get_bridge_dev_name(self):
        return (BRIDGE_INTERFACE_PREFIX + self.namespaceId)[:LINUX_DEV_LEN]

    def _get_namespace_from_network(self):
        return self.vpnInstanceId[:LINUX_DEV_LEN]

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
        # TODO: this code generate an ERROR log even when this is not a real error
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
            log.debug("Starting bridge %(bridge_name)s" % locals())
            self._runCommand("brctl addbr %(bridge_name)s" % locals())
            self._runCommand("brctl setfd %(bridge_name)s 0" % locals())
            self._runCommand("brctl stp %(bridge_name)s off" % locals())
            self._runCommand("ip link set %(bridge_name)s up" % locals())

            self._runCommand("brctl addif %(bridge_name)s %(interface)s" % locals())
            log.debug("Bridge %(bridge_name)s started with interface %(interface)s added" % locals())
 
    
    def _vifPluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("_vifPluggedReal(%s, %s, %d)" % (ipAddress, localPort, label))

        if "lo" in localPort:
            log.debug("_vifPluggedReal: Plugging loopback interface")
            self._runCommand("ip netns exec %s ip link set %s up" % (self.namespaceId, localPort))
            self._runCommand("ip netns exec %s ip addr add %s/32 dev %s" % (self.namespaceId, ipAddress, localPort), raiseExceptionOnError=False)
        else:
            log.debug("_vifPluggedReal: Plugging local port %s" % localPort)
            bridge_name = self._get_bridge_name()
            
            # Attach VIF on network namespace bridge
            self._runCommand("brctl addif %(bridge_name)s %(localPort)s" % locals(), raiseExceptionOnError=False)
            
        # Add ip route to redirect traffic to the correct namespace depending on MPLS label
        self._runCommand("ip -M route add %d mpls pop 1 netns %s" % (label, self.namespaceId))

        if log.debug:
            self._runCommand("ip -M route show")
            self._runCommand("ip netns exec %s ip route show" % self.namespaceId)
        
    
    def _vifUnpluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("_vifUnpluggedReal(%s, %s, %d)" % (ipAddress, localPort, label))

        # Remove ip route to disable traffic redirection to namespace depending on MPLS label
        self._runCommand("ip -M route del %d mpls pop 1 netns %s" % (label, self.namespaceId))

        if "lo" in localPort:
            log.debug("_vifUnpluggedReal: Unplugging loopback interface")
            self._runCommand("ip netns exec %s ip link set %s down" % (self.namespaceId, localPort))
            self._runCommand("ip netns exec %s ip addr del %s/32 dev %s" % (self.namespaceId, ipAddress, localPort))
        else:
            log.debug("_vifUnpluggedReal: Unplugging local port %s" % localPort)
            bridge_name = self._get_bridge_name()
            
            # Detach VIF from network namespace bridge
            self._runCommand("brctl delif %(bridge_name)s %(localPort)s" % locals(), raiseExceptionOnError=False)


    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label):
        log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, self.driver.mpls_interface))

        self._runCommand("ip netns exec %s ip route replace %s mpls push %d global dev %s %s" % (self.namespaceId, prefix, label, self.driver.mpls_interface, remotePE))

        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo):
        log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s, %s)" % (prefix, remotePE, label, dataplaneInfo, self.driver.mpls_interface))

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
        log.info("Initializing MPLSLinuxVRFDataplaneDriver")
        
        DataplaneDriver.__init__(self, config, init)
        
    def _initReal(self, config):
        self.config = config
        log.info("Really initializing MPLSLinuxVRFDataplaneDriver")
        
        self._runCommand("modprobe mpls")
        
        if "*gre*" in self.config["mpls_interface"]:
            self.mpls_interface = "gre_wildcard"
            self._runCommand("ip tunnel add %s mode gre local %s remote 0.0.0.0" % (self.mpls_interface, self.config['gre_src_address']), raiseExceptionOnError=False) 
            self._runCommand("ip link set %s up" % self.mpls_interface)
            self._runCommand("ip link set %s mpls on" % self.mpls_interface)
        else:
            self.mpls_interface = self.config["mpls_interface"]
            self._runCommand("ip link set %s mpls on" % self.mpls_interface)
        
        self._runCommand("ip link set mpls0 up")
        self._runCommand("ip link set lo mpls on")

        # flag to trigger cleanup all MPLS states on first call to vifPlugged
        self.firstVRFInit = True 
 
    def resetState(self):
        # Flush all MPLS routes redirecting traffic to network namespaces
        (output, _) = self._runCommand("ip -M route show") 
        for line in output:
            if "netns" in line:
                self._runCommand("ip -M route del %s" % line)
            
        if log.debug:
            log.debug("----- All MPLS routes have been flushed -----")
            self._runCommand("ip -M route show")
        
        # Flush all namespaces MPLS routes
        (output, _) = self._runCommand("ip netns show")
        namespace_list = output
        if not namespace_list:
            if log.debug:
                log.debug("----- No namespaces are configured -----")
        else:
            for namespaceId in output:
                for line in self._runCommand("ip netns exec %s ip route show" % namespaceId)[0]:
                    if "mpls" in line:
                        self._runCommand("ip netns exec %s ip route del %s" % (namespaceId, line))
                    
                if log.debug:
                    log.debug("----- Namespace %s MPLS routes have been flushed -----" % namespaceId)
                    self._runCommand("ip netns exec %s ip route show" % namespaceId)
            

    def _initializeInstanceReal(self, vrfDataplane):
        
        log.info("Prepare for initializing VRF %d..." % vrfDataplane.instanceId)
        
        # reset MPLS state on first call to vifPlugged
        if self.firstVRFInit:
            log.info("First VRF init, resetting MPLS dataplane state")
            try:
                self.resetState()
            except Exception as e:
                log.error("Exception while resetting MPLS state: %s" % e)
            self.firstVRFInit = False            
        else:
            log.debug("(not resetting MPLS dataplane state)")
    

    def _cleanupReal(self):
        log.warning("not implemented yet!")
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
            log.info("debug mode / would have run: %s" % command)
            return [""]
        else:
            return runCommand(log, command, *args, **kwargs)



