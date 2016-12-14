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

import pbr.version

from bottle import request, response, abort, Bottle

from oslo_config import cfg

from bagpipe.bgp.common import constants as consts

from bagpipe.bgp.common import looking_glass as lg

log = logging.getLogger(__name__)

LOOKING_GLASS_BASE = "looking-glass"


common_opts = [
    cfg.IPOpt("host", default="127.0.0.1",
              help="IP address on which the API server should listen"),
    cfg.IntOpt("port", default=8082,
               help="Port on which the API server should listen")
]

cfg.CONF.register_opts(common_opts, "API")


class APIException(Exception):
    pass


def json_serialize(obj):
    if (isinstance(obj, cfg.ConfigOpts) or
            isinstance(obj, cfg.ConfigOpts.GroupAttr)):
        return {json_serialize(k): json_serialize(v)
                for k, v in obj.iteritems()}
    return obj


class RESTAPI(lg.LookingGlassMixin):

    """BGP component REST API."""

    # Random generated sequence number
    BGP_SEQ_NUM = int(uuid.uuid4())

    def __init__(self, daemon, vpn_manager, catchall_lg_log_handler):
        self.daemon = daemon

        self.manager = vpn_manager
        self.catch_all_lg_log_handler = catchall_lg_log_handler

        self.bottle = Bottle()

        # Wrapping route callbacks (instead of using decorator) to url
        self.bottle.get("/ping", callback=self.ping)
        self.bottle.post("/attach_localport", callback=self.attach_localport)
        self.bottle.post("/detach_localport", callback=self.detach_localport)

        self.bottle.get("/%s<path:path>" % LOOKING_GLASS_BASE,
                        callback=self.looking_glass)
        self.bottle.get("/%s" % LOOKING_GLASS_BASE,
                        callback=self.looking_glass_root)

        self.bottle.error_handler[500] = self.error500

        self.start_time = time.time()

        lg.set_references_root(LOOKING_GLASS_BASE)
        lg.set_reference_path("BGP_WORKERS", ["bgp", "workers"])
        lg.set_reference_path("VPN_INSTANCES", ["vpns", "instances"])
        lg.set_reference_path("DATAPLANE_DRIVERS",
                              ["vpns", "dataplane", "drivers"])

    def ping(self):
        log.debug('Ping received, returning sequence number: %d',
                  self.BGP_SEQ_NUM)
        return "%d" % self.BGP_SEQ_NUM

    def _check_attach_parameters(self, params, attach):
        log.debug("checking params: %s", params)
        param_list = ('vpn_instance_id', 'mac_address', 'ip_address',
                      'local_port')
        if attach:
            param_list += ('vpn_type', 'import_rt', 'export_rt', 'gateway_ip')

        for param_name in param_list:
            if param_name not in params:
                log.warning("Mandatory parameter '%s' is missing", param_name)
                abort(400, "Mandatory parameter '%s' is missing" % param_name)

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

        if len(params['local_port'].get('linuxif', '')) > consts.LINUX_DEV_LEN:
            abort(400, "interface name '%s' exceeds the maximum length (%d)" %
                  (params['local_port'].get('linuxif', ''),
                   consts.LINUX_DEV_LEN))

        if not isinstance(params.get('advertise_subnet', False), bool):
            abort(400, "'advertise_subnet' must be a boolean")

        if not params.get('readvertise') and params.get('attract_traffic'):
            abort(400, "'attract_traffic' must be used in conjunction with "
                  "'readvertise")

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
                    },
            }
            if local_port is not a list, it is assumed to be a name of a linux
            interface (string)
        'readvertise': {  # optional, used to re-advertise addresses...
            'from_rt': [list of RTs]  # ...received on these RTs
            'to_rt': [list of RTs] # ...toward these RTs
        },
        'attract_traffic': { # optional, will result in the VRF to attract
                               traffic, matching the classifier, from any VRF
                               importing redirection route target
            'classifier': {
                'sourcePrefix': IP/mask,
                'destinationPrefix': IP/mask,
                'sourcePort': Port number or port range,
                'destinationPort': Port number or port range,
                'protocol': IP protocol
            },
            'redirect_rts': a FlowSpec route for the classifier will be
                            toward these Route Targets, with an action
                            consisting in redirecting to a VRF with an RT
                            of "readvertise: to_rt"
        },
        'lb_consistent_hash_order': # optional, will result in the VRF to load
                                      balance traffic between all plugged
                                      ports, based on this relative order
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

            self.manager.plug_vif_to_vpn(
                attach_params['vpn_instance_id'],
                attach_params['vpn_type'],
                attach_params['import_rt'],
                attach_params['export_rt'],
                attach_params['mac_address'],
                attach_params['ip_address'],
                attach_params['gateway_ip'],
                attach_params['local_port'],
                attach_params.get('linuxbr'),
                attach_params.get('advertise_subnet', False),
                attach_params.get('readvertise'),
                attach_params.get('attract_traffic'),
                attach_params.get('lb_consistent_hash_order', 0),
                attach_params.get('fallback'),
            )
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
            self.manager.unplug_vif_from_vpn(
                detach_params['vpn_instance_id'],
                detach_params['mac_address'],
                detach_params['ip_address'],
                detach_params['local_port'],
                detach_params.get('advertise_subnet', False)
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
        url_path_elements = [urllib.unquote(elem)
                             for elem in path.split('/') if elem is not '']

        path_prefix = "%s://%s/%s" % (
            request.environ['wsgi.url_scheme'],  # http
            request.environ['HTTP_HOST'],
            LOOKING_GLASS_BASE
        )
        log.debug("path_prefix: %s", path_prefix)
        log.debug("url_path_elements: %s", url_path_elements)

        try:
            lg_info = self.get_looking_glass_info(path_prefix,
                                                  url_path_elements)

            log.debug("lg_info: %s...", repr(lg_info)[:40])
            log.debug("lg_info: %s", repr(lg_info))

            if lg_info is None:
                raise lg.NoSuchLookingGlassObject(path_prefix,
                                                  url_path_elements[0])

            response.content_type = 'application/json'
            return json.dumps(lg_info, default=json_serialize)
        except lg.NoSuchLookingGlassObject as e:
            log.info('looking_glass: %s', repr(e))
            abort(404, repr(e))
        except Exception as e:
            log.error('looking_glass: An error occurred: %s', e)
            log.error(traceback.format_exc())
            abort(500, 'Server error')

    # Looking glass hooks #################

    def get_lg_map(self):
        return {
            "summary":  (lg.SUBITEM, self.get_lg_summary),
            "config":   (lg.SUBTREE, self.get_lg_config),
            "bgp":      (lg.DELEGATE, self.manager.bgp_manager),
            "vpns":     (lg.DELEGATE, self.manager),
            "logs":     (lg.SUBTREE, self.get_logs)
        }

    def get_lg_config(self, path_prefix):
        return cfg.CONF

    def get_lg_summary(self):
        return {
            "BGP_established_peers":
                self.manager.bgp_manager.get_established_peers_count(),
            "local_routes_count":
                self.manager.bgp_manager.rtm.
                get_local_routes_count(),
            "received_routes_count":
                self.manager.bgp_manager.rtm.
                get_received_routes_count(),
            "vpn_instances_count": self.manager.get_vpn_instances_count(),
            "warnings_and_errors": len(self.catch_all_lg_log_handler),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self.start_time)),
            "version":  (pbr.version.VersionInfo('bagpipe-bgp')
                         .release_string())
        }

    def get_logs(self, path_prefix):
        return [{'level': record.levelname,
                 'time':
                 self.catch_all_lg_log_handler.formatter.formatTime(record),
                 'name': record.name,
                 'message': record.msg}
                for record in self.catch_all_lg_log_handler.get_records()]

    def error500(self, error):
        log.error("Bottle catched an error: %s", error.exception)
        log.error(traceback.format_exc())
        return "Server Error"

    def run(self):
        # TODO: make looking-glass available to remote hosts
        self.bottle.run(host=cfg.CONF.API.host,
                        port=cfg.CONF.API.port,
                        quiet=True,
                        debug=True)
