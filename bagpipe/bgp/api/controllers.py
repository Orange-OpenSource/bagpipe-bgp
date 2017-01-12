import pbr
import re
import time
import uuid

import traceback

import pecan
from pecan import request

from oslo_config import cfg

from bagpipe.bgp.common import exceptions as exc
from bagpipe.bgp.common import looking_glass as lg
from bagpipe.bgp.common import utils
from bagpipe.bgp.vpn import manager as vpn_manager

from oslo_log import log as logging
import logging as python_logging

LOG = logging.getLogger(__name__)

LOOKING_GLASS_BASE = "looking-glass"


def expose(*args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return pecan.expose(*args, **kwargs)


def when(index, *args, **kwargs):
    """Helper function so we don't have to specify json for everything."""
    kwargs.setdefault('content_type', 'application/json')
    kwargs.setdefault('template', 'json')
    return index.when(*args, **kwargs)


class PingController(object):

    def __init__(self):
        # Random generated sequence number
        self.sequence = int(uuid.uuid4())

    @expose(generic=True)
    def index(self):
        return self.sequence


class VPNManagerController(object):

    def __init__(self):
        self.manager = vpn_manager.VPNManager.get_instance()

    @staticmethod
    def stop():
        vpn_manager.VPNManager.get_instance().stop()


def check_attach_parameters(params, attach):
    LOG.debug("checking params: %s", params)
    paramList = ('vpn_instance_id', 'mac_address', 'ip_address',
                 'local_port')
    if attach:
        paramList += ('vpn_type', 'import_rt', 'export_rt', 'gateway_ip')

    for paramName in paramList:
        if paramName not in params:
            LOG.warning("Mandatory parameter '%s' is missing", paramName)
            pecan.abort(400,
                        "Mandatory parameter '%s' is missing" % paramName)

    # if local_port is not a dict, then assume it designates a linux
    # interface
    if (isinstance(params['local_port'], str) or
            isinstance(params['local_port'], unicode)):
        params['local_port'] = {'linuxif': params['local_port']}

    # if import_rt or export_rt are strings, convert them into lists
    for param in ('import_rt', 'export_rt'):
        if isinstance(params[param], str) or isinstance(params[param],
                                                        unicode):
            try:
                params[param] = re.split(',+ *', params[param])
            except:
                pecan.abort(400, "Unable to parse string into a list: '%s'" %
                            params[param])

    if not ('linuxif' in params['local_port'] or
            'evpn' in params['local_port']):
        pecan.abort(400, "Mandatory key is missing in local_port parameter"
                    "(linuxif, or evpn)")

    if not isinstance(params.get('advertise_subnet', False), bool):
        pecan.abort(400, "'advertise_subnet' must be a boolean")

    return params


class AttachController(VPNManagerController):

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @when(index, method='POST')
    def process(self):
        try:
            attach_params = request.json
        except Exception:
            LOG.error('attach_localport: No local port details received')
            pecan.abort(400, 'No local port details received')

        attach_params = check_attach_parameters(attach_params, True)

        try:
            LOG.debug('Local port attach received: %s', attach_params)

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
        except exc.APIException as e:
            LOG.warning('attach_localport: API parameter error: %s', e)
            pecan.abort(400, "API parameter error: %s" % e)
        except Exception as e:
            LOG.error('attach_localport: An error occurred during local port'
                      ' plug to VPN: %s', e)
            LOG.info(traceback.format_exc())
            pecan.abort(500, 'An error occurred during local port plug to VPN')


class DetachController(VPNManagerController):

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @when(index, method='POST')
    def process(self):
        try:
            detach_params = request.json
        except Exception:
            LOG.error('detach_localport: No local port details received')
            pecan.abort(400, 'No local port details received')

        detach_params = check_attach_parameters(detach_params, attach=False)

        try:
            LOG.debug('Local port detach received: %s', detach_params)
            self.manager.unplug_vif_from_vpn(
                detach_params['vpn_instance_id'],
                detach_params['mac_address'],
                detach_params['ip_address'],
                detach_params['local_port'],
                detach_params.get('advertise_subnet', False)
            )
        except exc.APIException as e:
            LOG.warning('detach_localport: API parameter error: %s', e)
            pecan.abort(400, "API parameter error: %s" % e)
        except Exception as e:
            LOG.error('detach_localport: An error occurred during local port'
                      ' unplug from VPN: %s', e)
            LOG.info(traceback.format_exc())
            pecan.abort(500, 'An error occurred during local port unplug from '
                        'VPN')


class LookingGlassController(VPNManagerController,
                             lg.LookingGlassMixin):

    def __init__(self):
        super(LookingGlassController, self).__init__()

        self.start_time = time.time()

        lg.set_references_root(LOOKING_GLASS_BASE)
        lg.set_reference_path("BGP_WORKERS", ["bgp", "workers"])
        lg.set_reference_path("VPN_INSTANCES", ["vpns", "instances"])
        lg.set_reference_path("DATAPLANE_DRIVERS",
                              ["vpns", "dataplane", "drivers"])

        self.catchall_lg_log_handler = lg.LookingGlassLogHandler()

        for (logger_name, logger) in (
                python_logging.Logger.manager.loggerDict.iteritems()):
            if isinstance(logger, python_logging.Logger):
                if not logger.propagate and logger.parent is not None:
                    LOG.debug("Adding looking glass log handler to "
                              "logger: %s", logger_name)
                    logger.addHandler(self.catchall_lg_log_handler)
        python_logging.root.addHandler(self.catchall_lg_log_handler)

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='GET')
    def process(self, *url_path_elements):

        path_prefix = "%s://%s/%s" % (
            request.scheme,  # http
            request.host,
            LOOKING_GLASS_BASE,
        )

        try:
            lg_info = self.get_looking_glass_info(path_prefix,
                                                  url_path_elements)
            if lg_info is None:
                raise lg.NoSuchLookingGlassObject(path_prefix,
                                                  url_path_elements[0])
            return lg_info
        except lg.NoSuchLookingGlassObject as e:
            LOG.info('looking_glass: %s', repr(e))
            pecan.abort(404, repr(e))
        except Exception as e:
            LOG.error('looking_glass: An error occurred: %s', e)
            LOG.error(traceback.format_exc())
            pecan.abort(500, 'Server error')

    @when(index, method='DELETE')
    @when(index, method='POST')
    @when(index, method='PUT')
    def not_supported(self):
        pecan.abort(405)

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
        return {section: utils.osloconfig_json_serialize(cfg.CONF[section])
                for section in ('COMMON', 'API', 'BGP',
                                'DATAPLANE_DRIVER_IPVPN',
                                'DATAPLANE_DRIVER_EVPN')
                }

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
            "warnings_and_errors": len(self.catchall_lg_log_handler),
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self.start_time)),
            "version":  (pbr.version.VersionInfo('bagpipe-bgp')
                         .release_string())
        }

    def get_logs(self, path_prefix):
        return [{'level': record.levelname,
                 'time':
                 self.catchall_lg_log_handler.formatter.formatTime(record),
                 'name': record.name,
                 'message': record.msg}
                for record in self.catchall_lg_log_handler.get_records()]


class RootController(object):

    @expose(generic=True)
    def index(self):
        return {}

    @when(index, method='POST')
    @when(index, method='PUT')
    @when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    ping = PingController()
    attach_localport = AttachController()
    detach_localport = DetachController()

    def stop(self):
        VPNManagerController.stop()

# there is a '-' in the LOOKING_GLASS_BASE name, so we have to use pecan.route
pecan.route(RootController, LOOKING_GLASS_BASE, LookingGlassController())
