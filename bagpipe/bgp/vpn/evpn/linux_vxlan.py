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

from distutils.version import StrictVersion

from bagpipe.bgp.common import logDecorator

from bagpipe.bgp.common.run_command import runCommand

from bagpipe.bgp.common.looking_glass import LookingGlassLocalLogger

from bagpipe.bgp.vpn.evpn import VPNInstanceDataplane
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from bagpipe.exabgp.message.update.attribute.communities import Encapsulation

BRIDGE_NAME_PREFIX = "evpn---"
VXLAN_INTERFACE_PREFIX = "vxlan--"
LINUX_DEV_LEN = 14


class LinuxVXLANEVIDataplane(VPNInstanceDataplane):

    def __init__(self, *args, **kwargs):
        VPNInstanceDataplane.__init__(self, *args)

        if 'linuxbr' in kwargs:
            self.bridge_name = kwargs.get('linuxbr')
        else:
            self.bridge_name = (
                BRIDGE_NAME_PREFIX + self.externalInstanceId)[:LINUX_DEV_LEN]

        self.vxlan_if_name = (
            VXLAN_INTERFACE_PREFIX + self.externalInstanceId)[:LINUX_DEV_LEN]

        self.log.info("EVI %d: Initializing bridge %s",
                      self.instanceId, self.bridge_name)
        if not self._interface_exists(self.bridge_name):
            self.log.debug("Starting bridge %s", self.bridge_name)

            # Create bridge
            self._runCommand("brctl addbr %s" % self.bridge_name)
            self._runCommand("brctl setfd %s 0" % self.bridge_name)
            self._runCommand("brctl stp %s off" % self.bridge_name)
            self._runCommand("ip link set %s up" % self.bridge_name)

            self.log.debug("Bridge %s created", self.bridge_name)

        self._create_and_plug_vxlan_if()

        self.log.debug("VXLAN interface %s plugged on bridge %s",
                       self.vxlan_if_name, self.bridge_name)

        self._cleaningUp = False

    @logDecorator.logInfo
    def cleanup(self):
        self.log.info("Cleaning EVI bridge and VXLAN interface %s",
                      self.bridge_name)

        self._cleaningUp = True

        self._cleanup_vxlan_if()

        # Delete only EVPN Bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self._runCommand("ip link set %s down" %
                             self.bridge_name, raiseExceptionOnError=False)
            self._runCommand("brctl delbr %s" %
                             self.bridge_name, raiseExceptionOnError=False)

    def _create_and_plug_vxlan_if(self):
        self.log.debug("Creating and plugging VXLAN interface %s",
                       self.vxlan_if_name)

        if self._interface_exists(self.vxlan_if_name):
            self._remove_vxlan_if()

        dstPortSpec = ""
        if self.driver.vxlanDestPort:
            dstPortSpec = "dstport %d" % self.driver.vxlanDestPort

        # Create VXLAN interface
        self._runCommand(
            "ip link add %s type vxlan id %d nolearning proxy %s" %
            (self.vxlan_if_name, self.instanceLabel, dstPortSpec)
        )

        self._runCommand("ip link set %s up" % self.vxlan_if_name)

        # Plug VXLAN interface into bridge
        self._runCommand("brctl addif %s %s" % (self.bridge_name,
                                                self.vxlan_if_name))

    def _cleanup_vxlan_if(self):
        if self._is_vxlan_if_on_bridge():
            # Unplug VXLAN interface from Linux bridge
            self._unplug_from_bridge(self.vxlan_if_name)
            self._remove_vxlan_if()

    def _remove_vxlan_if(self):
        # Remove VXLAN interface
        self._runCommand("ip link set %s down" % self.vxlan_if_name)
        self._runCommand("ip link del %s" % self.vxlan_if_name)

    def _is_vxlan_if_on_bridge(self):
        (output, _) = self._runCommand(
            "brctl show %s | grep '%s' | sed -e 's/\s\+//g'" %
            (self.bridge_name, VXLAN_INTERFACE_PREFIX))

        return True if (output == self.vxlan_if_name) else False

    def _interface_exists(self, interface):
        """Check if interface exists."""
        (_, exitCode) = self._runCommand("ip link show dev %s" % interface,
                                         raiseExceptionOnError=False,
                                         acceptableReturnCodes=[-1])
        return (exitCode == 0)

    def _unplug_from_bridge(self, interface):
        if self._interface_exists(self.bridge_name):
            self._runCommand("brctl delif %s %s" %
                             (self.bridge_name, interface),
                             acceptableReturnCodes=[0, 1])

    def setGatewayPort(self, linuxif):
        gw_ip = self.gatewayIP
        gw_mac = "01:00:00:00:00:00"  # FIXME

        self._runCommand("brctl addif %s %s" %
                         (self.bridge_name, linuxif),
                         raiseExceptionOnError=False)

        self._runCommand("bridge fdb replace %s dev %s" %
                         (gw_mac, linuxif))

        self._runCommand(
            "ip neighbor replace %s lladdr %s dev %s nud permanent" %
            (gw_ip, gw_mac, linuxif)
        )

    def gatewayPortDown(self, linuxif):
        self._runCommand("brctl delif %s %s" %
                         (self.bridge_name, linuxif),
                         raiseExceptionOnError=False)
        # TODO: need to cleanup bridge fdb and ip neigh ?

    def setBridgeName(self, linuxbr):
        self.bridge_name = linuxbr

    @logDecorator.logInfo
    def vifPlugged(self, macAddress, ipAddress, localPort, label):
        # Plug localPort only into EVPN bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Plugging localPort %s into EVPN bridge %s",
                           localPort['linuxif'], self.bridge_name)
            self._runCommand("brctl addif %s %s" %
                             (self.bridge_name, localPort['linuxif']),
                             raiseExceptionOnError=False)

    @logDecorator.logInfo
    def vifUnplugged(self, macAddress, ipAddress, localPort, label,
                     lastEndpoint=True):
        # Unplug localPort only from EVPN bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Unplugging localPort %s from EVPN bridge %s",
                           localPort['linuxif'], self.bridge_name)
            self._unplug_from_bridge(localPort['linuxif'])

    @logDecorator.log
    def setupDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri,
                                        encaps):
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning"
                           " up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = label

        # populate bridge forwarding db
        self._runCommand("bridge fdb replace %s dev %s dst %s vni %s" %
                         (mac, self.vxlan_if_name, remotePE, vni))

        # populate ARP cache
        self._runCommand("ip neighbor replace %s lladdr %s dev %s nud "
                         "permanent" % (ip, mac, self.vxlan_if_name))

        self._fdbDump()

    @logDecorator.log
    def removeDataplaneForRemoteEndpoint(self, prefix, remotePE, label, nlri):

        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning"
                           " up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = label

        self._fdbDump()

        self._runCommand("ip neighbor del %s lladdr %s dev %s nud permanent" %
                         (ip, mac, self.vxlan_if_name))
        self._runCommand("bridge fdb del %s dev %s dst %s vni %s" %
                         (mac, self.vxlan_if_name, remotePE, vni))

        self._fdbDump()

    @logDecorator.log
    def addDataplaneForBroadcastEndpoint(self, remotePE, label, nlri, encaps):
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning"
                           " up, do nothing")
            return

        vni = label

        # 00:00:00:00:00 usable as default since kernel commit
        # 58e4c767046a35f11a55af6ce946054ddf4a8580 (2013-06-25)
        self._runCommand("bridge fdb append 00:00:00:00:00:00 dev %s dst %s "
                         "vni %s" % (self.vxlan_if_name, remotePE, vni))

        self._fdbDump()

    @logDecorator.log
    def removeDataplaneForBroadcastEndpoint(self, remotePE, label, nlri):
        if self._cleaningUp:
            self.log.debug("setupDataplaneForRemoteEndpoint: instance cleaning"
                           " up, do nothing")
            return

        vni = label

        self._fdbDump()

        self._runCommand("bridge fdb delete 00:00:00:00:00:00 dev %s dst %s "
                         "vni %s" % (self.vxlan_if_name, remotePE, vni))

        self._fdbDump()

    def _fdbDump(self):
        if self.log.debug:
            self.log.debug("bridge fdb dump: %s", self._runCommand(
                "bridge fdb show dev %s" % self.vxlan_if_name)[0])

    # Looking glass ####

    def getLookingGlassLocalInfo(self, pathPrefix):
        return {
            "linux_bridge": self.bridge_name,
            "vxlan_if": self.vxlan_if_name
        }


class LinuxVXLANDataplaneDriver(DataplaneDriver):

    """
    E-VPN Dataplane driver relying on the Linux kernel linuxbridge
    VXLAN implementation.
    """

    dataplaneInstanceClass = LinuxVXLANEVIDataplane
    requiredKernel = "3.11.0"
    encaps = [Encapsulation(Encapsulation.VXLAN)]

    def __init__(self, config, init=True):
        LookingGlassLocalLogger.__init__(self, __name__)

        self.log.info("Initializing %s", self.__class__.__name__)

        self.vxlanDestPort = int(config.get("vxlan_dst_port", None))

        DataplaneDriver.__init__(self, config, init)

    def _initReal(self, config):
        self.config = config
        self.log.info("Really initializing %s", self.__class__.__name__)

        o = self._runCommand("uname -r")
        kernelRelease = o[0][0].split("-")[0]

        if (StrictVersion(kernelRelease) <
                StrictVersion(LinuxVXLANDataplaneDriver.requiredKernel)):
            raise Exception("%s requires at least Linux kernel %s (you are"
                            " running %s)" %
                            (self.__class__.__name__,
                             LinuxVXLANDataplaneDriver.requiredKernel,
                             kernelRelease))

        self._runCommand("modprobe vxlan")

    def resetState(self):
        self.log.debug("Resetting %s dataplane", self.__class__.__name__)

        # delete all EVPN bridges
        cmd = "brctl show | tail -n +2 | awk '{print $1}'| grep '%s'"
        for bridge in self._runCommand(cmd % BRIDGE_NAME_PREFIX,
                                       raiseExceptionOnError=False,
                                       acceptableReturnCodes=[0, 1])[0]:
            self._runCommand("ip link set %s down" % bridge)
            self._runCommand("brctl delbr %s" % bridge)

        # delete all VXLAN interfaces
        cmd = "ip link show | awk '{print $2}' | tr -d ':' | grep '%s'"
        for interface in self._runCommand(cmd % VXLAN_INTERFACE_PREFIX,
                                          raiseExceptionOnError=False,
                                          acceptableReturnCodes=[0, 1])[0]:
            self._runCommand("ip link set %s down" % interface)
            self._runCommand("ip link delete %s" % interface)

    def _cleanupReal(self):
        # FIXME: need to refine what would be different
        self.resetState()

    def _runCommand(self, command, *args, **kwargs):
        return runCommand(self.log, command, *args, **kwargs)
