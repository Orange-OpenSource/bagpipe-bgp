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
import uuid
import time

import urllib

import traceback

import re
import json

from bottle import request, response, abort, Bottle

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap, \
    NoSuchLookingGlassObject, LookingGlassReferences

log = logging.getLogger(__name__)

LOOKING_GLASS_BASE = "looking-glass"


class APIException(Exception):
    pass


class RESTAPI(LookingGlass):

    """BGP component REST API."""

    # Random generated sequence number
    BGP_SEQ_NUM = int(uuid.uuid4())

    def __init__(self, config, daemon, vpnManager, catchAllLGLogHandler):
        self.config = config
        self.daemon = daemon

        self.vpnManager = vpnManager
        self.catchAllLGLogHandler = catchAllLGLogHandler

        self.bottle = Bottle()

        # Wrapping route callbacks (instead of using decorator) to url
        self.bottle.get("/ping", callback=self.ping)
        self.bottle.post("/attach_localport", callback=self.attach_localport)
        self.bottle.post("/detach_localport", callback=self.detach_localport)

        self.bottle.get("/%s<path:path>" %
                        LOOKING_GLASS_BASE, callback=self.looking_glass)
        self.bottle.get("/%s" %
                        LOOKING_GLASS_BASE, callback=self.looking_glass_root)

        self.bottle.error_handler[500] = self.error500

        self.startTime = time.time()

        LookingGlassReferences.setRoot(LOOKING_GLASS_BASE)
        LookingGlassReferences.setReferencePath(
            "BGP_WORKERS", ["bgp", "workers"])
        LookingGlassReferences.setReferencePath(
            "VPN_INSTANCES", ["vpns", "instances"])

    def ping(self):
        log.debug(
            'Ping received, returning sequence number: %d', self.BGP_SEQ_NUM)
        return "%d" % self.BGP_SEQ_NUM

    def _check_attach_parameters(self, params, attach):
        log.debug("checking params: %s", params)
        paramList = ('vpn_instance_id', 'mac_address', 'ip_address',
                     'local_port')
        if attach:
            paramList += ('vpn_type', 'import_rt', 'export_rt', 'gateway_ip')

        for paramName in paramList:
            if paramName not in params:
                log.warning("Mandatory parameter '%s' is missing", paramName)
                abort(400, "Mandatory parameter '%s' is missing" % paramName)

        # if local_port is not a dict, then assume it designates a linux
        # interface
        if (isinstance(params['local_port'], str)
                or isinstance(params['local_port'], unicode)):
            params['local_port'] = {'linuxif': params['local_port']}

        # if import_rt or export_rt are strings, convert them into lists
        for param in ('import_rt', 'export_rt'):
            if isinstance(params[param], str) or isinstance(params[param],
                                                            unicode):
                try:
                    params[param] = re.split(',+ *', params[param])
                except:
                    abort(400, "Unable to parse string into a list: '%s'" %
                          params[param])

        if not ('linuxif' in params['local_port'] or
                'evpn' in params['local_port']):
            abort(400, "Mandatory key is missing in local_port parameter"
                  "(linuxif, or evpn)")

        if not isinstance(params.get('advertise_subnet', False), bool):
            abort(400, "'advertise_subnet' must be a boolean")

        return params

    def attach_localport(self):
        """
        'vpn_instance_id: external VPN instance identifier (all ports with same
                         vpn_instance_id will be plugged in the same VPN
                         instance
        'vpn_type': type of the VPN instance ('ipvpn' or 'evpn')
        'import_rt': list of import Route Targets (or comma-separated string)
        'export_rt': list of export Route Targets (or comma-separated string)
        'gateway_ip': IP address of gateway for this VPN instance
        'mac_address': MAC address of endpoint to connect to the VPN instance
        'ip_address': IP/mask of endpoint to connect to the VPN instance
        'advertise_subnet': optional, if set to True then VRF will advertise
                            the whole subnet (defaults to False, readvertise
                            ip_address as a singleton (/32)
        'linuxbr': Name of a linux bridge to which the linuxif is already
                 plugged-in (optional)
        'local_port': local port to plug to the VPN instance
            should be a dict containing any of the following key,value pairs
            {
                'linuxif': 'tap456abc', # name of a linux interface
                                        # - if OVS information is provided it
                                        #   does not have to be an existing
                                        #    interface
                                        # -  not needed/not used if 'evpn' plug
                                        #    is used
                'ovs': {                     # optional
                        # whether or not interface is already plugged into the
                        # OVS bridge:
                        'plugged': True,
                        # name of a linux interface to be plugged into the OVS
                        # bridge (optional and ignored if port_number is
                        # provided):
                        'port_name': 'qvo456abc',
                        # OVS port number (optional if 'port_name' provided):
                        'port_number': '7',
                        # the VLAN id for VM traffic (optional)
                        'vlan': '42',
                        # optional specification of a distinct port to send
                        # traffic to the VM(only applies if a vlan is
                        # specified) :
                        'to_vm_port_number'
                        'to_vm_port_name'
                       },
                'evpn': {  # for an ipvpn attachement...
                     'id': 'xyz'  # specifies the vpn_instance_id of an evpn
                                  # that will be attached to the ipvpn
                     'ovs_port_name': 'qvb456abc' # optional, if provided,
                                                  # and if ovs/port_name is
                                                  # also provided, then the
                                                  # interface name will be
                                                  # assumed as already plugged
                                                  # into the evpn
                    }
            }
            if local_port is not a list, it is assumed to be a name of a linux
            interface (string)
        'readvertise': {  # optional, used to re-advertise addresses...
            'from_rt': [list of RTs]  # ...received on these RTs
            'to_rt': [list of RTs] # ...toward these RTs
        }
        'fallback': # (optional) if provided, on a VRF lookup miss,
                    # the MAC destination address will be
                    # rewritten to this MAC before being
                    # sent back where it came from
                    {
                    'src_mac': 'aa:bb:cc:dd:ee:ff'  # new source MAC
                    'dst_mac': 'aa:bb:cc:dd:ee:00'  # new destination MAC
                    'ovs_port_name': 'patch_foo'
                    'ovs_port_number': 4               # (unsupported yet)
                    'ovs_resubmit': '(<port>,<table>)' # (unsupported yet)
        }
        """

        try:
            attach_params = request.json
        except Exception:
            log.error('attach_localport: No local port details received')
            abort(400, 'No local port details received')

        attach_params = self._check_attach_parameters(attach_params, True)

        try:
            log.debug('Local port attach received: %s', attach_params)
            self.vpnManager.plugVifToVPN(attach_params['vpn_instance_id'],
                                         attach_params['vpn_type'],
                                         attach_params['import_rt'],
                                         attach_params['export_rt'],
                                         attach_params['mac_address'],
                                         attach_params['ip_address'],
                                         attach_params['gateway_ip'],
                                         attach_params['local_port'],
                                         attach_params.get('linuxbr'),
                                         attach_params.get('advertise_subnet',
                                                           False),
                                         attach_params.get('readvertise'),
                                         attach_params.get('fallback'))
        except APIException as e:
            log.warning('attach_localport: API parameter error: %s', e)
            abort(400, "API parameter error: %s" % e)
        except Exception as e:
            log.error('attach_localport: An error occurred during local port'
                      ' plug to VPN: %s', e)
            log.info(traceback.format_exc())
            abort(500, 'An error occurred during local port plug to VPN')

    def detach_localport(self):

        try:
            detach_params = request.json
        except Exception:
            log.error('detach_localport: No local port details received')
            abort(400, 'No local port details received')

        detach_params = self._check_attach_parameters(detach_params, False)

        try:
            log.debug('Local port detach received: %s', detach_params)
            self.vpnManager.unplugVifFromVPN(detach_params['vpn_instance_id'],
                                             detach_params['mac_address'],
                                             detach_params['ip_address'],
                                             detach_params['local_port'],
                                             detach_params.get(
                                                 'advertise_subnet', False),
                                             )
        except APIException as e:
            log.warning('detach_localport: API parameter error: %s', e)
            abort(400, "API parameter error: %s" % e)
        except Exception as e:
            log.error('detach_localport: An error occurred during local port'
                      ' unplug from VPN: %s', e)
            log.info(traceback.format_exc())
            abort(500, 'An error occurred during local port unplug from VPN')

    def looking_glass_root(self):
        return self.looking_glass('/')

    def looking_glass(self, path):
        urlPathElements = [urllib.unquote(elem)
                           for elem in path.split('/') if elem is not '']

        pathPrefix = "%s://%s/%s" % (
            request.environ['wsgi.url_scheme'],  # http
            request.environ['HTTP_HOST'],
            LOOKING_GLASS_BASE
        )
        log.debug("pathPrefix: %s", pathPrefix)
        log.debug("urlPathElements: %s", urlPathElements)

        try:
            lgInfo = self.getLookingGlassInfo(pathPrefix, urlPathElements)

            log.debug("lgInfo: %s...", repr(lgInfo)[:40])

            if lgInfo is None:
                raise NoSuchLookingGlassObject(pathPrefix, urlPathElements[0])

            response.content_type = 'application/json'
            return json.dumps(lgInfo)
        except NoSuchLookingGlassObject as e:
            log.info('looking_glass: %s', repr(e))
            abort(404, repr(e))
        except Exception as e:
            log.error('looking_glass: An error occurred: %s', e)
            log.error(traceback.format_exc())
            abort(500, 'Server error')

    # Looking glass hooks #################

    def getLGMap(self):
        return {
            "summary":  (LGMap.SUBITEM, self.getLGSummary),
            "config":   (LGMap.DELEGATE, self.daemon),
            "bgp":      (LGMap.DELEGATE, self.vpnManager.bgpManager),
            "vpns":     (LGMap.DELEGATE, self.vpnManager),
            "logs":     (LGMap.SUBTREE, self.getLogs),
        }

    def getLGSummary(self):
        return {
            "BGP_established_peers":
                self.vpnManager.bgpManager.getEstablishedPeersCount(),
            "local_routes_count":
                self.vpnManager.bgpManager.routeTableManager.
                getLocalRoutesCount(),
            "received_routes_count":
                self.vpnManager.bgpManager.routeTableManager.
                getReceivedRoutesCount(),
            "vpn_instances_count": self.vpnManager.getVPNInstancesCount(),
            "warnings_and_errors": len(self.catchAllLGLogHandler),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self.startTime))
        }

    def getLogs(self, pathPrefix):
        return [{'level': record.levelname,
                 'time':
                 self.catchAllLGLogHandler.formatter.formatTime(record),
                 'name': record.name,
                 'message': record.msg}
                for record in self.catchAllLGLogHandler.getRecords()]

    def error500(self, error):
        log.error("Bottle catched an error: %s", error.exception)
        log.error(traceback.format_exc())
        return "Server Error"

    def run(self):
        # TODO: make looking-glass available to remote hosts
        self.bottle.run(host=self.config.get("api_host", "localhost"),
                        port=self.config.get("api_port", 8082),
                        quiet=True,
                        debug=True)
