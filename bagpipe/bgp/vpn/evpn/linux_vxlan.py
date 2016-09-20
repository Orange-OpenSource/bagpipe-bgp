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


from bagpipe.bgp.common import log_decorator

from bagpipe.bgp.common.run_command import run_command

from bagpipe.bgp.common import looking_glass as lg

from bagpipe.bgp.vpn.evpn import VPNInstanceDataplane
from bagpipe.bgp.vpn.evpn import EVPN
from bagpipe.bgp.vpn.dataplane_drivers import DataplaneDriver

from exabgp.bgp.message.update.attribute.community.extended.encapsulation \
    import Encapsulation

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
                BRIDGE_NAME_PREFIX + self.external_instance_id)[:LINUX_DEV_LEN]

        self.vxlan_if_name = (
            VXLAN_INTERFACE_PREFIX + self.external_instance_id)[:LINUX_DEV_LEN]

        self.log.info("EVI %d: Initializing bridge %s",
                      self.instance_id, self.bridge_name)
        if not self._interface_exists(self.bridge_name):
            self.log.debug("Starting bridge %s", self.bridge_name)

            # Create bridge
            self._run_command("brctl addbr %s" % self.bridge_name,
                              run_as_root=True)
            self._run_command("brctl setfd %s 0" % self.bridge_name,
                              run_as_root=True)
            self._run_command("brctl stp %s off" % self.bridge_name,
                              run_as_root=True)
            self._run_command("ip link set %s up" % self.bridge_name,
                              run_as_root=True)

            self.log.debug("Bridge %s created", self.bridge_name)

        self._create_and_plug_vxlan_if()

        self.log.debug("VXLAN interface %s plugged on bridge %s",
                       self.vxlan_if_name, self.bridge_name)

        self._cleaning_up = False

    @log_decorator.log_info
    def cleanup(self):
        self.log.info("Cleaning EVI bridge and VXLAN interface %s",
                      self.bridge_name)

        self._cleaning_up = True

        self._cleanup_vxlan_if()

        # Delete only EVPN Bridge (Created by dataplane driver)
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self._run_command("ip link set %s down" % self.bridge_name,
                              run_as_root=True,
                              raise_on_error=False)
            self._run_command("brctl delbr %s" % self.bridge_name,
                              run_as_root=True,
                              raise_on_error=False)

    def _create_and_plug_vxlan_if(self):
        self.log.debug("Creating and plugging VXLAN interface %s",
                       self.vxlan_if_name)

        if self._interface_exists(self.vxlan_if_name):
            self._remove_vxlan_if()

        dst_port_spec = ""
        if self.driver.vxlan_dest_port:
            dst_port_spec = "dstport %d" % self.driver.vxlan_dest_port

        # Create VXLAN interface
        self._run_command(
            "ip link add %s type vxlan id %d local %s nolearning proxy %s" %
            (self.vxlan_if_name, self.instance_label,
             self.driver.get_local_address(), dst_port_spec),
            run_as_root=True
        )

        self._run_command("ip link set %s up" % self.vxlan_if_name,
                          run_as_root=True)

        # Plug VXLAN interface into bridge
        self._run_command("brctl addif %s %s" % (self.bridge_name,
                                                 self.vxlan_if_name),
                          run_as_root=True)

    def _cleanup_vxlan_if(self):
        if self._is_vxlan_if_on_bridge():
            # Unplug VXLAN interface from Linux bridge
            self._unplug_from_bridge(self.vxlan_if_name)

        self._remove_vxlan_if()

    def _remove_vxlan_if(self):
        # Remove VXLAN interface
        self._run_command("ip link set %s down" % self.vxlan_if_name,
                          run_as_root=True)
        self._run_command("ip link del %s" % self.vxlan_if_name,
                          run_as_root=True)

    def _is_vxlan_if_on_bridge(self):
        (output, _) = self._run_command(
            "brctl show %s | grep '%s' | sed -e 's/\s\+//g'" %
            (self.bridge_name, VXLAN_INTERFACE_PREFIX))

        return True if (output == self.vxlan_if_name) else False

    def _interface_exists(self, interface):
        """Check if interface exists."""
        (_, exit_code) = self._run_command("ip link show dev %s" % interface,
                                           raise_on_error=False,
                                           acceptable_return_codes=[-1])
        return (exit_code == 0)

    def _unplug_from_bridge(self, interface):
        if self._interface_exists(self.bridge_name):
            self._run_command("brctl delif %s %s" %
                              (self.bridge_name, interface),
                              run_as_root=True,
                              acceptable_return_codes=[0, 1])

    def set_gateway_port(self, linuxif):
        gw_ip = self.gateway_ip
        gw_mac = "01:00:00:00:00:00"  # FIXME

        self._run_command("brctl addif %s %s" %
                          (self.bridge_name, linuxif),
                          run_as_root=True,
                          raise_on_error=False)

        self._run_command("bridge fdb replace %s dev %s" %
                          (gw_mac, linuxif),
                          run_as_root=True)

        self._run_command(
            "ip neighbor replace %s lladdr %s dev %s nud permanent" %
            (gw_ip, gw_mac, linuxif),
            run_as_root=True
        )

    def gateway_port_down(self, linuxif):
        self._run_command("brctl delif %s %s" %
                          (self.bridge_name, linuxif),
                          run_as_root=True,
                          raise_on_error=False)
        # TODO: need to cleanup bridge fdb and ip neigh ?

    def set_bridge_name(self, linuxbr):
        self.bridge_name = linuxbr

    @log_decorator.log_info
    def vif_plugged(self, mac_address, ip_address, localport, label):
        # Plug localport only if bridge was created by us
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Plugging localport %s into EVPN bridge %s",
                           localport['linuxif'], self.bridge_name)
            self._run_command("brctl addif %s %s" %
                              (self.bridge_name, localport['linuxif']),
                              run_as_root=True,
                              raise_on_error=False)

        self._run_command("bridge fdb replace %s dev %s" %
                          (mac_address, localport['linuxif']),
                          run_as_root=True)

    @log_decorator.log_info
    def vif_unplugged(self, mac_address, ip_address, localport, label,
                      last_endpoint=True):
        # unplug localport only if bridge was created by us
        if BRIDGE_NAME_PREFIX in self.bridge_name:
            self.log.debug("Unplugging localport %s from EVPN bridge %s",
                           localport['linuxif'], self.bridge_name)
            self._unplug_from_bridge(localport['linuxif'])

    @log_decorator.log
    def setup_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                            nlri, encaps):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = label

        # populate bridge forwarding db
        self._run_command("bridge fdb replace %s dev %s dst %s vni %s" %
                          (mac, self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        # populate ARP cache
        if ip is not None:
            self._run_command("ip neighbor replace %s lladdr %s dev %s nud "
                              "permanent" % (ip, mac, self.vxlan_if_name),
                              run_as_root=True)
        else:
            self.log.warning("No IP in E-VPN route, ARP will not work for this"
                             "IP/MAC")

        self._fdb_dump()

    @log_decorator.log
    def remove_dataplane_for_remote_endpoint(self, prefix, remote_pe, label,
                                             nlri):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        mac = prefix
        ip = nlri.ip
        vni = label

        self._fdb_dump()

        self._run_command("ip neighbor del %s lladdr %s dev %s nud permanent" %
                          (ip, mac, self.vxlan_if_name),
                          run_as_root=True)
        self._run_command("bridge fdb del %s dev %s dst %s vni %s" %
                          (mac, self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    @log_decorator.log
    def add_dataplane_for_bum_endpoint(self, remote_pe, label, nlri, encaps):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        vni = label

        # 00:00:00:00:00 usable as default since kernel commit
        # 58e4c767046a35f11a55af6ce946054ddf4a8580 (2013-06-25)
        self._run_command("bridge fdb append 00:00:00:00:00:00 dev %s dst %s "
                          "vni %s" % (self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    @log_decorator.log
    def remove_dataplane_for_bum_endpoint(self, remote_pe, label, nlri):
        if self._cleaning_up:
            self.log.debug("setup_dataplane_for_remote_endpoint: instance"
                           " cleaning up, do nothing")
            return

        vni = label

        self._fdb_dump()

        self._run_command("bridge fdb delete 00:00:00:00:00:00 dev %s dst %s "
                          "vni %s" % (self.vxlan_if_name, remote_pe, vni),
                          run_as_root=True)

        self._fdb_dump()

    def _fdb_dump(self):
        if self.log.debug:
            self.log.debug("bridge fdb dump: %s", self._run_command(
                "bridge fdb show dev %s" % self.vxlan_if_name)[0])

    # Looking glass ####

    def get_log_local_info(self, path_prefix):
        return {
            "linux_bridge": self.bridge_name,
            "vxlan_if": self.vxlan_if_name
        }


class LinuxVXLANDataplaneDriver(DataplaneDriver):

    """
    E-VPN Dataplane driver relying on the Linux kernel linuxbridge
    VXLAN implementation.
    """

    dataplane_instance_class = LinuxVXLANEVIDataplane
    type = EVPN
    required_kernel = "3.11.0"
    encaps = [Encapsulation(Encapsulation.Type.VXLAN)]

    def __init__(self, config, init=True):
        lg.LookingGlassLocalLogger.__init__(self, __name__)

        self.log.info("Initializing %s", self.__class__.__name__)

        try:
            self.vxlan_dest_port = int(config.get("vxlan_dst_port", 0)) or None
        except ValueError:
            raise Exception("Could not parse specified vxlan_dst_port: %s" %
                            config["vxlan_dst_port"])

        DataplaneDriver.__init__(self, config, init)

    def _init_real(self, config):
        self.config = config
        self.log.info("Really initializing %s", self.__class__.__name__)

        self._run_command("modprobe vxlan",
                          run_as_root=True)

    def reset_state(self):
        self.log.debug("Resetting %s dataplane", self.__class__.__name__)

        # delete all EVPN bridges
        cmd = "brctl show | tail -n +2 | awk '{print $1}'| grep '%s'"
        for bridge in self._run_command(cmd % BRIDGE_NAME_PREFIX,
                                        raise_on_error=False,
                                        acceptable_return_codes=[0, 1])[0]:
            self._run_command("ip link set %s down" % bridge,
                              run_as_root=True)
            self._run_command("brctl delbr %s" % bridge,
                              run_as_root=True)

        # delete all VXLAN interfaces
        cmd = "ip link show | awk '{print $2}' | tr -d ':' | grep '%s'"
        for interface in self._run_command(cmd % VXLAN_INTERFACE_PREFIX,
                                           raise_on_error=False,
                                           acceptable_return_codes=[0, 1])[0]:
            self._run_command("ip link set %s down" % interface,
                              run_as_root=True)
            self._run_command("ip link delete %s" % interface,
                              run_as_root=True)

    def _cleanup_real(self):
        # FIXME: need to refine what would be different
        self.reset_state()
