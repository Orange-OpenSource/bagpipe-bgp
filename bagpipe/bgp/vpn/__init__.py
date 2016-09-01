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


from threading import Lock

import re
import logging

from bagpipe.bgp.vpn.ipvpn import IPVPN
from bagpipe.bgp.vpn.ipvpn import VRF
from bagpipe.bgp.vpn.evpn import EVPN
from bagpipe.bgp.vpn.evpn import EVI

import bagpipe.bgp.common.exceptions as exc

from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import utils
from bagpipe.bgp.common import logDecorator
from bagpipe.bgp.common.run_command import runCommand

from bagpipe.bgp.vpn.label_allocator import LabelAllocator
from bagpipe.bgp.vpn.rd_allocator import RDAllocator

from exabgp.bgp.message.update.attribute.community.extended \
    import RouteTargetASN2Number as RouteTarget


log = logging.getLogger(__name__)


def convertRouteTargets(orig_list):
    assert(isinstance(orig_list, list))
    list_ = []
    for rt in orig_list:
        if rt == '':
            continue
        try:
            asn, nn = rt.split(':')
            list_.append(RouteTarget(int(asn), int(nn)))
        except Exception:
            raise Exception("Malformed route target: '%s'" % rt)
    return list_


class VPNManager(lg.LookingGlassMixin):

    """
    Creates, and keeps track of, VPN instances (VRFs and EVIs) and passes
    plug/unplug calls to the right VPN instance.
    """

    type2class = {IPVPN: VRF,
                  EVPN: EVI
                  }

    @logDecorator.log
    def __init__(self, bgpManager, dataplaneDrivers):
        '''
        dataplaneDrivers is a dict from vpn type to each dataplane driver,
        e.g. { "ipvpn": driverA, "evpn": driverB }
        '''

        self.bgpManager = bgpManager

        self.dataplaneDrivers = dataplaneDrivers

        # Init VPN instance identifiers
        self.instanceId = 1

        # VPN instance dict
        self.vpnInstances = {}

        logging.debug("Creating label allocator")
        self.labelAllocator = LabelAllocator()

        logging.debug("Creating route distinguisher allocator")
        self.rdAllocator = RDAllocator(self.bgpManager.getLocalAddress())

        # dict containing info how an ipvpn is plugged
        # from an evpn  (keys: ipvpn instances)
        self._evpn_ipvpn_ifs = {}

        self.lock = Lock()

    def _formatIpAddressPrefix(self, ipAddress):
        if re.match(r'([12]?\d?\d\.){3}[12]?\d?\d\/[123]?\d', ipAddress):
            address = ipAddress
        elif re.match(r'([12]?\d?\d\.){3}[12]?\d?\d', ipAddress):
            address = ipAddress + "/32"
        else:
            raise exc.MalformedIPAddress

        return address

    @utils.synchronized
    def getInstanceId(self):
        iid = self.instanceId
        self.instanceId += 1
        return iid

    @logDecorator.logInfo
    def _attach_evpn2ipvpn(self, localPort, ipvpnInstance):
        """ Assuming localPort indicates no real interface but only
        an EVPN, this method will create a pair of twin interfaces, one
        to plug in the EVPN, the other to plug in the IPVPN.

        The localPort dict will be modified so that the 'linuxif' indicates
        the name of the interface to plug in the IPVPN.

        The EVPN instance will be notified so that it forwards traffic
        destinated to the gateway on the interface toward the IPVPN.
        """
        assert('evpn' in localPort)

        if 'id' not in localPort['evpn']:
            raise Exception("Missing parameter 'id' :an external EVPN "
                            "instance id must be specified for an EVPN "
                            "attachment")

        try:
            evpn = self.vpnInstances[localPort['evpn']['id']]
        except:
            raise Exception("The specified evpn instance does not exist (%s)"
                            % localPort['evpn'])

        if (evpn.type != EVPN):
            raise Exception("The specified instance to plug is not an evpn"
                            "instance (is %s instead)" % evpn.type)

        if ipvpnInstance in self._evpn_ipvpn_ifs:
            (evpn_if, ipvpn_if, evpn, managed) = \
                self._evpn_ipvpn_ifs[ipvpnInstance]

            if not (localPort['evpn']['id'] == evpn.externalInstanceId):
                raise Exception('Trying to plug into an IPVPN a new E-VPN '
                                'while one is already plugged in')
            else:
                # do nothing
                log.warning('Trying to plug an E-VPN into an IPVPN, but it was'
                            ' already done')
                localPort['linuxif'] = ipvpn_if
                return

        #  detect if this evpn is already plugged into an IPVPN
        if evpn.hasGatewayPort():
            raise Exception("Trying to plug E-VPN into an IPVPN, but this EVPN"
                            " is already plugged into an IPVPN")

        if ('linuxif' in localPort and localPort['linuxif']):
            raise Exception("Cannot specify an attachment with both a linuxif "
                            "and an evpn")

        if 'ovs_port_name' in localPort['evpn']:
            try:
                assert(localPort['ovs']['plugged'])
                assert(localPort['ovs']['port_name'] or
                       localPort['ovs']['port_number'])
            except:
                raise Exception("Using ovs_port_name in EVPN/IPVPN attachment"
                                " requires specifying the corresponding OVS"
                                " port, which must also be pre-plugged")

            evpn_if = localPort['evpn']['ovs_port_name']

            # we assume in this case that the E-VPN interface is already
            # plugged into the E-VPN bridge
            managed = False
        else:
            evpn_if = "evpn%d-ipvpn%d" % (
                evpn.instanceId, ipvpnInstance.instanceId)
            ipvpn_if = "ipvpn%d-evpn%d" % (
                ipvpnInstance.instanceId, evpn.instanceId)

            # FIXME: do it only if not existing already...
            log.info("Creating veth pair %s %s ", evpn_if, ipvpn_if)

            # delete the interfaces if they exist already
            runCommand(log, "ip link delete %s" %
                       evpn_if, acceptableReturnCodes=[0, 1])
            runCommand(log, "ip link delete %s" %
                       ipvpn_if, acceptableReturnCodes=[0, 1])

            runCommand(log, "ip link add %s type veth peer name %s mtu 65535" %
                       (evpn_if, ipvpn_if))

            runCommand(log, "ip link set %s up" % evpn_if)
            runCommand(log, "ip link set %s up" % ipvpn_if)
            managed = True

        localPort['linuxif'] = ipvpn_if

        evpn.setGatewayPort(evpn_if, ipvpnInstance)

        self._evpn_ipvpn_ifs[ipvpnInstance] = (
            evpn_if, ipvpn_if, evpn, managed)

    @logDecorator.logInfo
    def _detach_evpn2ipvpn(self, ipvpn):
        """
        Symmetric to _attach_evpn2ipvpn
        """
        (evpn_if, ipvpn_if, evpnInstance,
         managed) = self._evpn_ipvpn_ifs[ipvpn]

        if not ipvpn.hasEnpoint(ipvpn_if):
            # TODO: check that this evpn instance is still up and running
            evpnInstance.gatewayPortDown(evpn_if)

            # cleanup veth pair
            if managed:
                runCommand(log, "ip link delete %s" % evpn_if)

            del self._evpn_ipvpn_ifs[ipvpn]

    def _cleanup_evpn2ipvpn(self, ipvpn):
        (_, ipvpn_if, _, managed) = self._evpn_ipvpn_ifs[ipvpn]

        # cleanup veth pair
        if managed:
            runCommand(log, "ovs-vsctl del-port %s" % ipvpn_if)
            runCommand(log, "ip link delete %s" % ipvpn_if)

    @logDecorator.logInfo
    def _createVPNInstance(self, externalInstanceId, instanceType, importRTs,
                           exportRTs, gatewayIP, mask, readvertise,
                           attractTraffic, **kwargs):
        instanceId = self.getInstanceId()
        log.info("Create and start new VPN instance %d for external "
                 "instance identifier %s", instanceId, externalInstanceId)
        try:
            vpnInstanceFactory = VPNManager.type2class[instanceType]
        except KeyError:
            log.error("Unsupported instanceType for VPNInstance: %s",
                      instanceType)
            raise Exception("Unsupported instance type: %s" % instanceType)

        try:
            dataplaneDriver = self.dataplaneDrivers[instanceType]
        except KeyError:
            log.error("No dataplane driver for VPN type %s",
                      instanceType)
            raise Exception("No dataplane driver for VPN type %s" %
                            instanceType)

        vpnInstance = vpnInstanceFactory(
            self, dataplaneDriver,
            externalInstanceId, instanceId, importRTs, exportRTs,
            gatewayIP, mask, readvertise, attractTraffic, **kwargs)

        # Update VPN instance list
        self.vpnInstances[externalInstanceId] = vpnInstance

        vpnInstance.start()

        return vpnInstance

    @logDecorator.logInfo
    def plugVifToVPN(self, externalInstanceId, instanceType, importRTs,
                     exportRTs, macAddress, ipAddress, gatewayIP,
                     localPort, linuxbr, advertiseSubnet, readvertise,
                     attractTraffic, lbConsistentHashOrder):

        # Verify and format IP address with prefix if necessary
        try:
            ipAddressPrefix = self._formatIpAddressPrefix(ipAddress)
        except exc.MalformedIPAddress:
            raise

        # Convert route target string to RouteTarget dictionary
        importRTs = convertRouteTargets(importRTs)
        exportRTs = convertRouteTargets(exportRTs)

        if readvertise:
            try:
                readvertise = {k: convertRouteTargets(readvertise[k])
                               for k in ['from_rt', 'to_rt']}
            except KeyError as e:
                raise Exception("Wrong 'readvertise' parameters: %s" % e)

        if attractTraffic:
            try:
                attractTraffic['redirect_rts'] = (
                    convertRouteTargets(attractTraffic['redirect_rts']))
            except KeyError as e:
                raise Exception("Wrong 'attractTraffic' parameters: %s" % e)

        # retrieve network mask
        mask = int(ipAddressPrefix.split('/')[1])

        # Retrieve VPN instance or create new one if does not exist
        try:
            vpnInstance = self.vpnInstances[externalInstanceId]
            if (vpnInstance.type != instanceType):
                raise Exception("Trying to plug port on an existing instance "
                                "of a different type (existing: %s, asked: %s)"
                                % (vpnInstance.type, instanceType))
        except KeyError:
            if instanceType == EVPN and linuxbr:
                kwargs = {'linuxbr': linuxbr}
            else:
                kwargs = {}

            vpnInstance = self._createVPNInstance(
                externalInstanceId, instanceType, importRTs, exportRTs,
                gatewayIP, mask, readvertise, attractTraffic, **kwargs)

        # Check if new route target import/export must be updated
        if not ((set(vpnInstance.importRTs) == set(importRTs)) and
                (set(vpnInstance.exportRTs) == set(exportRTs))):
            vpnInstance.updateRouteTargets(importRTs, exportRTs)

        if instanceType == IPVPN and 'evpn' in localPort:
            # special processing for the case where what we plug into
            # the ipvpn is not an existing interface but an interface
            # to create, connected to an existing evpn instance
            self._attach_evpn2ipvpn(localPort, vpnInstance)

        # Plug VIF to VPN instance
        vpnInstance.vifPlugged(macAddress, ipAddressPrefix, localPort,
                               advertiseSubnet, lbConsistentHashOrder)

    @logDecorator.logInfo
    def unplugVifFromVPN(self, externalInstanceId, macAddress, ipAddress,
                         localPort, readvertise):

        # Verify and format IP address with prefix if necessary
        try:
            ipAddressPrefix = self._formatIpAddressPrefix(ipAddress)
        except exc.MalformedIPAddress:
            raise

        # Retrieve VPN instance or raise exception if does not exist
        try:
            vpnInstance = self.vpnInstances[externalInstanceId]
        except KeyError:
            log.error("Try to unplug VIF from non existing VPN instance %s",
                      externalInstanceId)
            raise exc.VPNNotFound(externalInstanceId)

        # Unplug VIF from VPN instance
        vpnInstance.vifUnplugged(macAddress, ipAddressPrefix, readvertise)

        if vpnInstance.type == IPVPN and 'evpn' in localPort:
            self._detach_evpn2ipvpn(vpnInstance)

        if vpnInstance.stopIfEmpty():
            del self.vpnInstances[externalInstanceId]

    @logDecorator.logInfo
    def redirectTrafficToVPN(self, redirectedId, redirectedType, redirectRT):
        externalInstanceId = "redirect-to-%s-%s" % (redirectedType,
                                                    redirectRT.replace(":", "_"))

        log.info("Retrieve VPN instance %s for traffic redirection to route "
                 "target %s", externalInstanceId, redirectRT)

        # Retrieve redirect VPN instance or create new one if does not exist
        try:
            redirectInstance = self.vpnInstances[externalInstanceId]
            if (redirectInstance.type != redirectedType):
                raise Exception("Trying to redirect traffic to an existing "
                                "instance of a different type (existing: %s, "
                                "asked: %s)"
                                % (redirectInstance.type, redirectedType))
        except KeyError:
            # Convert route target string to RouteTarget dictionary
            importRTs = convertRouteTargets([redirectRT])

            redirectInstance = self._createVPNInstance(
                externalInstanceId, redirectedType, importRTs, [],
                "127.0.0.1", "24", None, None)

        redirectInstance.registerRedirectedInstance(redirectedId)

        return redirectInstance

    @logDecorator.logInfo
    def stopRedirectTrafficToVPN(self, redirectedId, redirectedType,
                                 redirectRT):
        externalInstanceId = "redirect-to-%s-%s" % (redirectedType,
                                                    redirectRT.replace(":", "_"))

        # Retrieve redirect VPN instance or raise exception if does not exist
        try:
            redirectInstance = self.vpnInstances[externalInstanceId]
        except KeyError:
            log.error("Try to stop traffic redirection to non existing VPN "
                      "instance %s", externalInstanceId)
            raise exc.VPNNotFound(externalInstanceId)

        redirectInstance.unregisterRedirectedInstance(redirectedId)

        if redirectInstance.stopIfNoRedirectedInstance():
            del self.vpnInstances[externalInstanceId]

    @logDecorator.logInfo
    def stop(self):
        for vpnInstance in self.vpnInstances.itervalues():
            vpnInstance.stop()
            # Cleanup veth pair
            if (vpnInstance.type == IPVPN and
                    self._evpn_ipvpn_ifs.get(vpnInstance)):
                self._cleanup_evpn2ipvpn(vpnInstance)
        for vpnInstance in self.vpnInstances.itervalues():
            vpnInstance.join()

    # Looking Glass hooks ####

    def getLGMap(self):
        class DataplaneLGHook(lg.LookingGlassMixin):

            def __init__(self, vpnManager):
                self.vpnManager = vpnManager

            def getLGMap(self):
                return {
                    "drivers": (lg.COLLECTION, (
                        self.vpnManager.getLGDataplanesList,
                        self.vpnManager.getLGDataplaneFromPathItem)),
                    "ids": (lg.DELEGATE, self.vpnManager.labelAllocator)
                }
        dataplaneHook = DataplaneLGHook(self)
        return {
            "instances": (lg.COLLECTION, (self.getLGVPNList,
                                             self.getLGVPNFromPathItem)),
            "dataplane": (lg.DELEGATE, dataplaneHook)
        }

    def getLGVPNList(self):
        return [{"id": id,
                 "name": instance.name}
                for (id, instance) in self.vpnInstances.iteritems()]

    def getLGVPNFromPathItem(self, pathItem):
        return self.vpnInstances[pathItem]

    def getVPNInstancesCount(self):
        return len(self.vpnInstances)

    # LookingGLass ########

    def getLGDataplanesList(self):
        return [{"id": i} for i in self.dataplaneDrivers.iterkeys()]

    def getLGDataplaneFromPathItem(self, pathItem):
        return self.dataplaneDrivers[pathItem]
