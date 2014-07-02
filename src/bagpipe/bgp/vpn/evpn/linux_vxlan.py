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

import logging

from distutils.version import StrictVersion

from bagpipe.bgp.common.run_command import runCommand

#from bagpipe.bgp.common.looking_glass import LookingGlass

from bagpipe.bgp.vpn.dataplane_drivers import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from exabgp.message.update.attribute.communities import Encapsulation

log = logging.getLogger(__name__)


BRIDGE_NAME_PREFIX = "evpn---"
VXLAN_INTERFACE_PREFIX = "vxlan--"
LINUX_DEV_LEN = 14


class LinuxVXLANEVIDataplane(VPNInstanceDataplane):
    
    def __init__(self,*args):
        VPNInstanceDataplane.__init__(self,*args)
        
        self.bridge_name = (BRIDGE_NAME_PREFIX + self.vpnInstanceId)[:LINUX_DEV_LEN]
        self.vxlan_if_name = (VXLAN_INTERFACE_PREFIX + self.vpnInstanceId)[:LINUX_DEV_LEN]
            
    def initialize(self): 
        log.info("Initialize")
    
        if not self._interface_exists(self.bridge_name):
            log.debug("Starting bridge %s" % self.bridge_name)
            
            # Create bridge
            self._runCommand("brctl addbr %s" % self.bridge_name)
            self._runCommand("brctl setfd %s 0" % self.bridge_name)
            self._runCommand("brctl stp %s off" % self.bridge_name)
            self._runCommand("ip link set %s up" % self.bridge_name)
            
            self._create_and_plug_vxlan_if()
            
            log.debug("Bridge %s and VXLAN interface %s created" % (self.bridge_name,self.vxlan_if_name))

    def cleanup(self):
        log.info("Cleaning EVI bridge and VXLAN interface %s" % self.bridge_name)
        
        self._cleanup_vxlan_if()
        
        self._runCommand("ip link set %s down" % self.bridge_name, raiseExceptionOnError=False)
        self._runCommand("brctl delbr %s" % self.bridge_name, raiseExceptionOnError=False)

    def _create_and_plug_vxlan_if(self):
        log.debug("Creating and plugging VXLAN interface %s",self.vxlan_if_name)
        # Create VXLAN interface
        self._runCommand("ip link add %s type vxlan id %d nolearning proxy" % (self.vxlan_if_name,
                                                                                      self.instanceLabel)
                                                                                      #self.config['out_interface'])  #FIXME: check if "dev %s" is needed
                         )
        
        self._runCommand("ip link set %s up" % self.vxlan_if_name)
        
        # Plug VXLAN interface into bridge
        self._runCommand("brctl addif %s %s" % (self.bridge_name,self.vxlan_if_name))
        
    def _cleanup_vxlan_if(self):
        # Unplug VXLAN interface from Linux bridge
        self._unplug_from_bridge(self.vxlan_if_name)
        
        # Remove VXLAN interface
        self._runCommand("ip link set %s down" % self.vxlan_if_name)
        self._runCommand("ip link del %s" % self.vxlan_if_name)
        
    def _interface_exists(self, bridge):
        """Check if bridge exists."""
        (_,exitCode) = self._runCommand("ip link show dev %s" % bridge, raiseExceptionOnError=False, acceptableReturnCodes=[-1])
        return (exitCode == 0)
    
    def _unplug_from_bridge(self,interface):
        if self._interface_exists(self.bridge_name):
            self._runCommand("brctl delif %s %s" % (self.bridge_name, interface))

    def _vifPluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("Plugging localPort %s into EVPN bridge %s" % (localPort,self.bridge_name))
        self._runCommand("brctl addif %s %s" % (self.bridge_name,localPort), raiseExceptionOnError=False)
    
    def _vifUnpluggedReal(self, macAddress, ipAddress, localPort, label):
        log.debug("Unplugging localPort %s from EVPN bridge %s" % (localPort,self.bridge_name))
        self._unplug_from_bridge(localPort)

    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        mac = prefix
        ip = nlri.ip
        vni = nlri.etag
        
        # populate bridge forwarding db
        self._runCommand("bridge fdb replace %s dev %s dst %s vni %s" % (mac,self.vxlan_if_name,remotePE, vni))
        
        # populate ARP cache
        self._runCommand("ip neighbor replace %s lladdr %s dev %s nud permanent" % (ip,mac,self.vxlan_if_name) )
        
        self._fdbDump()
        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri):
        log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s, %s)" % (prefix, remotePE, label, dataplaneInfo, nlri))
        
        mac = prefix
        ip = nlri.ip
        vni = nlri.etag
        
        self._fdbDump()
        
        self._runCommand("ip neighbor del %s lladdr %s dev %s nud permanent" % (ip,mac,self.vxlan_if_name) )
        self._runCommand("bridge fdb del %s dev %s dst %s vni %s" % (mac,self.vxlan_if_name,remotePE,vni))
        
        self._fdbDump()

 
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("EVI %(instanceId)d: addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
        
        vni = nlri.etag
        
        self._runCommand("bridge fdb append %s dev %s dst %s vni %s" % ("ff:ff:ff:ff:ff:ff",self.vxlan_if_name,remotePE, vni))
        
        self._fdbDump() 
         
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("EVI %(instanceId)d: removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
    
        vni = nlri.etag
        
        self._fdbDump()
        
        self._runCommand("bridge fdb delete %s dev %s dst %s vni %s" % ("ff:ff:ff:ff:ff:ff",self.vxlan_if_name,remotePE, vni))
        
        self._fdbDump()

    def _fdbDump(self):
        if log.debug:
            log.debug("bridge fdb dump: %s" % self._runCommand("bridge fdb show dev %s" % self.vxlan_if_name)[0])

    #### Looking glass ####

    def getLookingGlassLocalInfo(self,pathPrefix):
        return {
                "linux_bridge": self.bridge_name,
                "vxlan_if": self.vxlan_if_name
                }



class LinuxVXLANDataplaneDriver(DataplaneDriver):
    """
    E-VPN Dataplane driver relying on the Linux kernel linuxbridge
    VXLAN implementation.
    """
    
    dataplaneClass = LinuxVXLANEVIDataplane
    requiredKernel = "3.10.0"
    encapsulation = Encapsulation.VXLAN
    
    def __init__(self, config, init=True):
        log.info("Initializing MPLSLinuxEVIDataplaneDriver")
        
        DataplaneDriver.__init__(self, config, init)
        
    def _initReal(self, config):
        self.config = config
        log.info("Really initializing MPLSLinuxEVIDataplaneDriver")
        
        o = self._runCommand("uname -r")
        kernelRelease=o[0][0].split("-")[0]
        
        if StrictVersion(kernelRelease) < StrictVersion(LinuxVXLANDataplaneDriver.requiredKernel):
            raise Exception("LinuxVXLANDataplaneDriver requires at least Linux kernel %s (you are running %s)" % (LinuxVXLANDataplaneDriver.requiredKernel,kernelRelease))
        
        self._runCommand("modprobe vxlan")
        
        # flag to trigger cleanup all dataplane states on first call to vifPlugged
        self.firstEVIInit = True  # TODO: move this to superclass after _initReal call
 
    def resetState(self):
        log.debug("Resetting %s dataplane" % self.__class__.__name__)

        # delete all EVPN bridges
        for bridge in self._runCommand("brctl show | tail -n +2 | awk '{print $1}'| grep '%s'" % BRIDGE_NAME_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % bridge)
            self._runCommand("brctl delbr %s" % bridge)
        
        # delete all VXLAN interfaces
        for interface in self._runCommand("ip link show | awk '{print $2}' | tr -d ':' | grep '%s'" % VXLAN_INTERFACE_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % interface)
            self._runCommand("ip link delete %s" % interface)

    def _initializeInstanceReal(self, vrfDataplane):
        
        log.info("Prepare for initializing EVI %d..." % vrfDataplane.instanceId)
        
        # reset dataplane state on first call to vifPlugged
        if self.firstEVIInit:
            log.info("First EVI init, resetting dataplane state")
            try:
                self.resetState()
            except Exception as e:
                log.error("Exception while resetting state: %s" % e)
            self.firstEVIInit = False
        else:
            log.debug("(not resetting dataplane state)")


    def _cleanupReal(self):
        # FIXME: need to refine what would be different
        self.resetState()


    def _runCommand(self,command,*args,**kwargs):
        # if config['path_to_ip'] is set, use the value as the path to the ip tool
        #   e.g config['path_to_ip'] = /usr/local/sbin/ip
        # ditto for mpls tool
        for tool in ['ip','mpls']:
            if command.startswith(tool+" ") and ('path_to_'+tool) in self.config:
                command = command.replace( tool+" ", self.config['path_to_'+tool]+" ")

        if ( ("debug" in self.config) and self.config["debug"]=="1"):
            log.info("debug mode / would have run: %s" % command)
            return ([""],0)
        else:
            return runCommand(log,command,*args,**kwargs)


######################################################################################################################
# VXLAN dataplane for Openstack hybrid vif driver 
######################################################################################################################
#
# This driver is intended for use only with the penstack hybrid vif driver 
# relying on both a linuxbridge and OVS.
# 
# Intial interfaces and bridges built by the hybrid vif driver:
#
#                                                                     veth pair
#  [VM]---(tap interface tap*UUID*)---[linux bridge qbr*UUID*]--(qvb*UUID* |qvo*UUID* )---[OVS]
#
# We plug a VXLAN link into the linux bridge:
#
#  [VM]---(tap interface tap*UUID*)---[linux bridge qbr*UUID*]--(qvb*UUID* |qvo*UUID* )---[OVS]
#                                              |
#                                          (vxlan--*UUID*)
#
# (*UUID* is a portion of the neutron port uuid)

LINUXBR_PREFIX = "qbr"
OVS_TO_LINUXBR_INTERFACE_PREFIX = "qvo"

#  This driver does not support more than one localPort being plugged into it (one linux bridge per-VM).
#  Thus, we can keep track of whether or not a port is plugged in (self.plugged), and if no port is currently plugged in 
#  do nothing in removeDataplaneForRemoteEndpoint (and avoid the "bridge fdb delete" command failing)

class LinuxVXLANEVIHybridDataplane(LinuxVXLANEVIDataplane):
    
    def __init__(self,*args):
        self.plugged = False
        self.bridge_name = ""
        self.vxlan_if_name = None
        VPNInstanceDataplane.__init__(self,*args)
    
    def initialize(self): 
        log.info("Initialize: nothing to do, everything is done in plug")

    def cleanup(self):
        log.info("Cleanup: nothing to do, everything is done in unplug")
        
    def _get_linuxbr_name(self, localport):
        return (LINUXBR_PREFIX + localport[3:])[:LINUX_DEV_LEN]
    
    def _get_vxlan_if_name(self, localport):
        return (VXLAN_INTERFACE_PREFIX + localport[3:])[:LINUX_DEV_LEN]
    
    def _get_ovs2linuxbr_interface_name(self, localport):
        return (OVS_TO_LINUXBR_INTERFACE_PREFIX + localport[3:])[:LINUX_DEV_LEN]
    
    def _mtu_fixup(self,interface):
        # This is a hack, proper MTUs should actually be configured in the hybrid vif driver
        try:
            mtu = self.config["ovsbr_interfaces_mtu"]
        except KeyError:
            mtu = 1500
        log.info("Will adjust %s interface with MTU %s (ovsbr_interfaces_mtu parameter in bgp.conf)" % (interface, mtu))
        self._runCommand("ip link set %s mtu %s" % (interface,mtu))
    
    
    def _vifPluggedReal(self, macAddress, ipAddress, localport, label):
        log.debug("_vifPluggedReal(%s, %s, %d)" % ( ipAddress, localport, label))
        
        if self.plugged:
            log.error("Second plug on a LinuxVXLANEVIHybridDataplane VPN which is supposed to be plugged only once.")

        self.bridge_name = self._get_linuxbr_name(localport)

        if not re.match('tap[0-9a-f-]{11}',localport):
            log.warning("This dataplane driver is made to work with the NOVA Hybrid VIF driver; now assuming that %s is plugged into %s" % (localport,self.bridge_name))

        if not self._interface_exists(self.bridge_name):
            raise Exception("Bridge %s does not exist"% self.bridge_name)

        if self._interface_exists(self._get_ovs2linuxbr_interface_name(localport)):
            # fixup MTU of the interfaces to the OVS bridge (until this is properly done in Openstack hybrid VIF driver)
            self._mtu_fixup(self._get_ovs2linuxbr_interface_name(localport))
        else:
            log.warning("Interface between OVS and Linuxbridge %s does not exist, will not fix MTU"% self.bridge_name)

        # Create VXLAN interface
        self.vxlan_if_name = self._get_vxlan_if_name(localport)

        self._create_and_plug_vxlan_if()
        
        self.plugged = True
    
    def _vifUnpluggedReal(self, macAddress, ipAddress, localport, label):
        log.debug("_vifUnpluggedReal(%s, %s, %d)" % ( ipAddress, localport, label))

        LinuxVXLANEVIDataplane._cleanup_vxlan_if(self)

        self.vxlan_if_name = None
        self.bridge_name = ""
        self.plugged = False
    
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        assert(self.plugged)
        
        LinuxVXLANEVIDataplane.setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri)
    
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri):
        log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s, %s)" % (prefix, remotePE, label, dataplaneInfo, nlri))
        
        if not self.plugged:
            log.info("removeDataplaneForRemoteEndpoint useless to apply, since we are not plugged yet")
            return
        
        LinuxVXLANEVIDataplane.removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, dataplaneInfo, nlri)
    
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("EVI %(instanceId)d: addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
        
        assert(self.plugged)
        
        LinuxVXLANEVIDataplane.addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri)
    
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        log.info("EVI %(instanceId)d: removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
    
        if not self.plugged:
            log.info("removeDataplaneForBroadcastEndpoint useless to apply, since we are not plugged yet")
            return
    
        LinuxVXLANEVIDataplane.removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri)




class LinuxVXLANHybridDataplaneDriver(DataplaneDriver):
    """
    Special dataplane driver inheriting from the LinuxVXLANDataplaneDriver, modified
    to work with the Nova hybrid VIF driver, where the VM tap interface is already
    plugged into a per-VM linux bridge.
    
    In that case, our driver won't touch the bridge, and the VXLAN encap interface
    is not created at EVI initialization time, but only at port plug time.  
    
    (There is also a hack to workaround an ancient issue when the MTU of OVS to linuxbridge
    interface was not configured with a proper MTU, causing the linux kernel IP interface 
    for the OVS bridge to have a wrong MTU, itself causing VXLAN packets fragmentation.)
    """
    
    #FIXME: lots of duplicate code to duplicate from the LinuxVXLANDataplaneDriver
    
    dataplaneClass = LinuxVXLANEVIHybridDataplane
    requiredKernel = "3.10.0"
    encapsulation = Encapsulation.VXLAN
    
    def __init__(self, config, init=True):
        log.info("Initializing LinuxVXLANHybridDataplaneDriver")
        
        DataplaneDriver.__init__(self, config, init)
        
    def _initReal(self, config):
        self.config = config
        log.info("Really initializing LinuxVXLANHybridDataplaneDriver")
        
        o = self._runCommand("uname -r")
        kernelRelease=o[0][0].split("-")[0]
        
        if StrictVersion(kernelRelease) < StrictVersion(LinuxVXLANDataplaneDriver.requiredKernel):
            raise Exception("LinuxVXLANHybridDataplaneDriver requires at least Linux kernel %s (you are running %s)" % (LinuxVXLANHybridDataplaneDriver.requiredKernel,kernelRelease))
        
        self._runCommand("modprobe vxlan")
        
        # Flag to trigger cleanup all EVI states on first call to vifPlugged
        self.firstEVIInit = True
 
    def resetState(self):
        log.debug("Resetting %s dataplane" % self.__class__.__name__)

        # Delete all EVPN bridges
        for bridge in self._runCommand("brctl show | tail -n +2 | awk '{print $1}'| grep '%s'" % BRIDGE_NAME_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % bridge)
            self._runCommand("brctl delbr %s" % bridge)
        
        # Delete all VXLAN interfaces
        for interface in self._runCommand("ip link show | awk '{print $2}' | tr -d ':' | grep '%s'" % VXLAN_INTERFACE_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % interface)
            self._runCommand("ip link delete %s" % interface)


    def _initializeInstanceReal(self, vrfDataplane):
        
        log.info("Prepare for initializing EVI %d..." % vrfDataplane.instanceId)
        
        # reset dataplane state on first call to vifPlugged
        if self.firstEVIInit:
            log.info("First EVI init, resetting dataplane state")
            try:
                self.resetState()
            except Exception as e:
                log.error("Exception while resetting state: %s" % e)
            self.firstEVIInit = False            
        else:
            log.debug("(not resetting dataplane state)")


    def _cleanupReal(self):
        # FIXME: need to refine what would be different
        self.resetState()


    def _runCommand(self,command,*args,**kwargs):
        # if config['path_to_ip'] is set, use the value as the path to the ip tool
        #   e.g config['path_to_ip'] = /usr/local/sbin/ip
        # ditto for mpls tool
        for tool in ['ip','mpls']:
            if command.startswith(tool+" ") and ('path_to_'+tool) in self.config:
                command = command.replace( tool+" ", self.config['path_to_'+tool]+" ")

        if ( ("debug" in self.config) and self.config["debug"]=="1"):
            log.info("debug mode / would have run: %s" % command)
            return ([""],0)
        else:
            return runCommand(log,command,*args,**kwargs)

