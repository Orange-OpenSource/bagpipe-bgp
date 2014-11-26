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

from bagpipe.bgp.common.run_command import runCommand

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger

from bagpipe.bgp.vpn.evpn import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from exabgp.message.update.attribute.communities import Encapsulation

BRIDGE_NAME_PREFIX = "evpn---"
VXLAN_INTERFACE_PREFIX = "vxlan--"
LINUX_DEV_LEN = 14

class LinuxVXLANEVIDataplane(VPNInstanceDataplane):
    
    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)
        
        if 'linuxbr' in kwargs:
            self.bridge_name = kwargs.get('linuxbr')
        else:
            self.bridge_name = (BRIDGE_NAME_PREFIX + self.externalInstanceId)[:LINUX_DEV_LEN]
        
        self.vxlan_if_name = (VXLAN_INTERFACE_PREFIX + self.externalInstanceId)[:LINUX_DEV_LEN]
        
        self.log.info("EVI %d: Initializing bridge %s" % (self.instanceId, self.bridge_name))
        if not self._interface_exists(self.bridge_name):
            self.log.debug("Starting bridge %s" % self.bridge_name)
            
            # Create bridge
            self._runCommand("brctl addbr %s" % self.bridge_name)
            self._runCommand("brctl setfd %s 0" % self.bridge_name)
            self._runCommand("brctl stp %s off" % self.bridge_name)
            self._runCommand("ip link set %s up" % self.bridge_name)
            
            self.log.debug("Bridge %s created" % self.bridge_name)
            
        self._create_and_plug_vxlan_if()
        
        self.log.debug("VXLAN interface %s plugged on bridge %s" % (self.vxlan_if_name, self.bridge_name))
        
        self._cleaningUp = False

    def cleanup(self):
        self.log.info("Cleaning EVI bridge and VXLAN interface %s" % self.bridge_name)
        
        self._cleaningUp = True
        
        self._cleanup_vxlan_if()
        
        # Delete only EVPN Bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self._runCommand("ip link set %s down" % self.bridge_name, raiseExceptionOnError=False)
            self._runCommand("brctl delbr %s" % self.bridge_name, raiseExceptionOnError=False)

    def _create_and_plug_vxlan_if(self):
        self.log.debug("Creating and plugging VXLAN interface %s",self.vxlan_if_name)
        # Create VXLAN interface
        self._runCommand("ip link add %s type vxlan id %d nolearning proxy" % (self.vxlan_if_name,
                                                                                      self.instanceLabel)
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
            self._runCommand("brctl delif %s %s" % (self.bridge_name, interface),acceptableReturnCodes=[0,1])

    def setGatewayPort(self,linuxif):
        gw_ip=self.gatewayIP
        gw_mac="01:00:00:00:00:00"   #FIXME
        
        self._runCommand("brctl addif %s %s" %
                         (self.bridge_name,linuxif),
                         raiseExceptionOnError=False)
        
        self._runCommand("bridge fdb replace %s dev %s" % 
                         (gw_mac,linuxif))
        
        self._runCommand(
            "ip neighbor replace %s lladdr %s dev %s nud permanent" %
            (gw_ip,gw_mac,linuxif)
            )
        
    def gatewayPortDown(self,linuxif):
        self._runCommand("brctl delif %s %s" %
                         (self.bridge_name,linuxif),
                         raiseExceptionOnError=False)
        #TODO: need to cleanup bridge fdb and ip neigh ?

    def setBridgeName(self, linuxbr):
        self.bridge_name = linuxbr
        
    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        # Plug localPort only into EVPN bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Plugging localPort %s into EVPN bridge %s" % (localPort['linuxif'],self.bridge_name))
            self._runCommand("brctl addif %s %s" % (self.bridge_name,localPort['linuxif']), raiseExceptionOnError=False)
    
    def vifUnplugged(self, macAddress, ipAddress, localPort, label):
        # Unplug localPort only from EVPN bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Unplugging localPort %s from EVPN bridge %s" % (localPort['linuxif'],self.bridge_name))
            self._unplug_from_bridge(localPort['linuxif'])

    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri, encaps):
        self.log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning up, do nothing") 
            return
        
        mac = prefix
        ip = nlri.ip
        vni = nlri.etag
        
        # populate bridge forwarding db
        self._runCommand("bridge fdb replace %s dev %s dst %s vni %s" % (mac,self.vxlan_if_name,remotePE, vni))
        
        # populate ARP cache
        self._runCommand("ip neighbor replace %s lladdr %s dev %s nud permanent" % (ip,mac,self.vxlan_if_name) )
        
        self._fdbDump()
        
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning up, do nothing") 
            return
        
        mac = prefix
        ip = nlri.ip
        vni = nlri.etag
        
        self._fdbDump()
        
        self._runCommand("ip neighbor del %s lladdr %s dev %s nud permanent" % (ip,mac,self.vxlan_if_name) )
        self._runCommand("bridge fdb del %s dev %s dst %s vni %s" % (mac,self.vxlan_if_name,remotePE,vni))
        
        self._fdbDump()
 
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        self.log.info("EVI %(instanceId)d: addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
        
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning up, do nothing") 
            return
        
        vni = nlri.etag
        
        # 00:00:00:00:00 usable as default since kernel commit 58e4c767046a35f11a55af6ce946054ddf4a8580 (2013-06-25)
        self._runCommand("bridge fdb append %s dev %s dst %s vni %s" % ("00:00:00:00:00:00",self.vxlan_if_name,remotePE, vni))
        
        self._fdbDump() 
         
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.info("EVI %(instanceId)d: removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
    
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning up, do nothing") 
            return
    
        vni = nlri.etag
        
        self._fdbDump()
        
        self._runCommand("bridge fdb delete %s dev %s dst %s vni %s" % ("00:00:00:00:00:00",self.vxlan_if_name,remotePE, vni))
        
        self._fdbDump()

    def _fdbDump(self):
        if self.log.debug:
            self.log.debug("bridge fdb dump: %s" % self._runCommand("bridge fdb show dev %s" % self.vxlan_if_name)[0])

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
    requiredKernel = "3.11.0"
    encaps = [Encapsulation(Encapsulation.VXLAN)]
    
    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self,__name__)

        self.log.info("Initializing %s" % self.__class__.__name__)
        
        DataplaneDriver.__init__(self, config, init)
        
    def _initReal(self, config):
        self.config = config
        self.log.info("Really initializing %s" % self.__class__.__name__)
        
        o = self._runCommand("uname -r")
        kernelRelease=o[0][0].split("-")[0]
        
        if StrictVersion(kernelRelease) < StrictVersion(LinuxVXLANDataplaneDriver.requiredKernel):
            raise Exception("%s requires at least Linux kernel %s (you are running %s)" % 
                           (self.__class__.__name__,LinuxVXLANDataplaneDriver.requiredKernel,kernelRelease))
        
        self._runCommand("modprobe vxlan")
        
    def resetState(self):
        self.log.debug("Resetting %s dataplane" % self.__class__.__name__)

        # delete all EVPN bridges
        for bridge in self._runCommand("brctl show | tail -n +2 | awk '{print $1}'| grep '%s'" % BRIDGE_NAME_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % bridge)
            self._runCommand("brctl delbr %s" % bridge)
        
        # delete all VXLAN interfaces
        for interface in self._runCommand("ip link show | awk '{print $2}' | tr -d ':' | grep '%s'" % VXLAN_INTERFACE_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % interface)
            self._runCommand("ip link delete %s" % interface)

    def _cleanupReal(self):
        # FIXME: need to refine what would be different
        self.resetState()

    def _runCommand(self,command,*args,**kwargs):
        return runCommand(self.log,command,*args,**kwargs)


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

    def cleanup(self):
        self.log.info("Cleanup: nothing to do, everything is done in unplug")
        
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
        self.log.info("Will adjust %s interface with MTU %s (ovsbr_interfaces_mtu parameter in bgp.conf)" % (interface, mtu))
        self._runCommand("ip link set %s mtu %s" % (interface,mtu))
    
    
    def vifPlugged(self, macAddress, ipAddress, localport, label):
        self.log.debug("vifPlugged(%s, %s, %d)" % ( ipAddress, localport['linuxif'], label))
        
        if self.plugged:
            self.log.error("Second plug on a LinuxVXLANEVIHybridDataplane VPN which is supposed to be plugged only once.")
            
        try:
            self.bridge_name = localport['linuxbr']
        except KeyError:
            self.log.warning("port attach request should specify the linux bridge")
            self.bridge_name = self._get_linuxbr_name(localport['linuxbr'])

        if not re.match('tap[0-9a-f-]{11}',localport):
            self.log.warning("This dataplane driver is made to work with the NOVA Hybrid VIF driver; now assuming that %s is plugged into %s" % (localport,self.bridge_name))

        if not self._interface_exists(self.bridge_name):
            raise Exception("Bridge %s does not exist"% self.bridge_name)

        if self._interface_exists(self._get_ovs2linuxbr_interface_name(localport)):
            # fixup MTU of the interfaces to the OVS bridge (until this is properly done in Openstack hybrid VIF driver)
            self._mtu_fixup(self._get_ovs2linuxbr_interface_name(localport))
        else:
            self.log.warning("Interface between OVS and Linuxbridge %s does not exist, will not fix MTU"% self.bridge_name)

        # Create VXLAN interface
        self.vxlan_if_name = self._get_vxlan_if_name(localport)

        self._create_and_plug_vxlan_if()
        
        self.plugged = True
    
    def vifUnplugged(self, macAddress, ipAddress, localport, label):
        self.log.debug("vifUnplugged(%s, %s, %d)" % ( ipAddress, localport['linuxif'], label))

        LinuxVXLANEVIDataplane._cleanup_vxlan_if(self)

        self.vxlan_if_name = None
        self.bridge_name = ""
        self.plugged = False
    
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("setupDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        assert(self.plugged)
        
        LinuxVXLANEVIDataplane.setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri)
    
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):
        self.log.info("removeDataplaneForRemoteEndpoint(%s, %s, %d, %s)" % (prefix, remotePE, label, nlri))
        
        if not self.plugged:
            self.log.info("removeDataplaneForRemoteEndpoint useless to apply, since we are not plugged yet")
            return
        
        LinuxVXLANEVIDataplane.removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri)
    
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.info("EVI %(instanceId)d: addDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
        
        assert(self.plugged)
        
        LinuxVXLANEVIDataplane.addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri)
    
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        self.log.info("EVI %(instanceId)d: removeDataplaneForBroadcastEndpoint: %(remotePE)s, label %(label)d !" % dict(locals(),**self.__dict__))
    
        if not self.plugged:
            self.log.info("removeDataplaneForBroadcastEndpoint useless to apply, since we are not plugged yet")
            return
    
        LinuxVXLANEVIDataplane.removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri)




class LinuxVXLANHybridDataplaneDriver(LinuxVXLANDataplaneDriver):
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
    
    dataplaneClass = LinuxVXLANEVIHybridDataplane
    
    def resetState(self):
        self.log.debug("Resetting %s dataplane" % self.__class__.__name__)
        
        # delete all VXLAN interfaces
        for interface in self._runCommand("ip link show | awk '{print $2}' | tr -d ':' | grep '%s'" % VXLAN_INTERFACE_PREFIX, raiseExceptionOnError=False, acceptableReturnCodes=[0,1])[0]:
            self._runCommand("ip link set %s down" % interface)
            self._runCommand("ip link delete %s" % interface)
