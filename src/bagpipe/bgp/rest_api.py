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

import traceback

import json

from bottle import request, response, abort, Bottle

from bagpipe.bgp.common.looking_glass import LookingGlass, LGMap, NoSuchLookingGlassObject, LookingGlassReferences

log = logging.getLogger(__name__)

LOOKING_GLASS_BASE = "looking-glass"

class RESTAPI(object,LookingGlass):
    """BGP component REST API."""
    
    # Random generated sequence number 
    BGP_SEQ_NUM = uuid.uuid4().int
    
    def __init__(self, config, daemon, vpnManager, lgLogHandler):
        self.config = config
        self.daemon = daemon
        
        self.vpnManager = vpnManager
        self.LGLogHandler = lgLogHandler
        
        self.bottle = Bottle()
        
        # Wrapping route callbacks (instead of using decorator) to url
        self.bottle.get("/ping", callback=self.ping)
        self.bottle.post("/attach_localport", callback=self.attach_localport)
        self.bottle.post("/detach_localport", callback=self.detach_localport)
        
        self.bottle.get("/%s<path:path>" % LOOKING_GLASS_BASE, callback=self.looking_glass)
        self.bottle.get("/%s"            % LOOKING_GLASS_BASE, callback=self.looking_glass_root)
        
        self.bottle.error_handler[500] = self.error500
        
        self.startTime = time.time()
        
        LookingGlassReferences.setRoot(LOOKING_GLASS_BASE)
        LookingGlassReferences.setReferencePath("BGP_WORKERS",["bgp","workers"])


    def ping(self):
        log.debug('Ping received, returning sequence number: %d', self.BGP_SEQ_NUM)
        return "%d" % self.BGP_SEQ_NUM
    
    def attach_localport(self):
        localport_details = {}

        try:
            localport_details = request.json
        except Exception:
            log.error('attach_localport: No local port details received')
            abort(400, 'No local port details received')
        
        for paramName in ('vpn_instance_id','import_rt','export_rt','ip_address','gateway_ip','local_port'):
            if not localport_details.has_key(paramName):
                log.error('attach_localport: Mandatory parameter "%s" is missing' % paramName)
                abort(400, 'Mandatory parameter "%s" is missing ' % paramName)

        try:
            log.debug('Local port attach received: %s', localport_details)
            self.vpnManager.plugVifToVPN(localport_details['vpn_instance_id'],
                                         localport_details['vpn_type'],
                                         localport_details['import_rt'],
                                         localport_details['export_rt'],
                                         localport_details['mac_address'],
                                         localport_details['ip_address'],
                                         localport_details['gateway_ip'],
                                         localport_details['local_port'])
        except Exception as e:
            log.error('attach_localport: An error occurred during local port plug to VPN: %s' % e)
            log.info(traceback.format_exc())
            abort(400, 'An error occurred during local port plug to VPN')

    def detach_localport(self):
        localport_details = {}

        try:
            localport_details = request.json
        except Exception:
            log.error('detach_localport: No local port details received')
            abort(400, 'No local port details received')
        
        for paramName in ('vpn_instance_id','ip_address','local_port'):
            if not localport_details.has_key(paramName):
                log.error('detach_localport: Mandatory parameter "%s" is missing' % paramName)
                abort(400, 'Mandatory parameter "%s" is missing ' % paramName)

        try:
            log.debug('Local port detach received: %s', localport_details)
            self.vpnManager.unplugVifFromVPN(localport_details['vpn_instance_id'],
                                             localport_details['mac_address'],
                                             localport_details['ip_address'],
                                             localport_details['local_port'])
        except Exception as e:
            log.error('detach_localport: An error occurred during local port unplug from VPN: %s' % e)
            log.info(traceback.format_exc())
            abort(400, 'An error occurred during local port unplug from VPN')

    def looking_glass_root(self):
        return self.looking_glass('/')

    def looking_glass(self,path):
        urlPathElements = filter(lambda x: (x is not ''), path.split('/') )
        
        pathPrefix = "%s://%s/%s" % (
                                   request.environ['wsgi.url_scheme'], # http
                                   request.environ['HTTP_HOST'],
                                   LOOKING_GLASS_BASE
                                   )
        log.debug("pathPrefix: %s" % pathPrefix)
        log.debug("urlPathElements: %s" % urlPathElements)

        try:
            lgInfo = self.getLookingGlassInfo(pathPrefix,urlPathElements)
        
            log.debug("lgInfo: %s" % repr(lgInfo))
        
            if lgInfo is None:
                raise NoSuchLookingGlassObject(pathPrefix,urlPathElements[0])
        
            response.content_type = 'application/json'
            return json.dumps(lgInfo)
        except NoSuchLookingGlassObject as e:
            log.info('looking_glass: %s' % repr(e) )
            abort(404, repr(e) )
        except Exception as e:
            log.error('looking_glass: An error occurred: %s' % e)
            log.error(traceback.format_exc())
            abort(500, 'Server error')
    
    ########## Looking glass hooks #################
    
    def getLGMap(self):
        return {
                "summary":  (LGMap.SUBITEM,  self.getLGSummary),
                "config":   (LGMap.DELEGATE, self.daemon),
                "bgp":      (LGMap.DELEGATE, self.vpnManager.bgpManager),
                "vpns":     (LGMap.DELEGATE, self.vpnManager),
                "logs":     (LGMap.SUBTREE,  self.getLogs),
                }
    
    def getLGSummary(self):
        return {
                "BGP_established_peers": self.vpnManager.bgpManager.getEstablishedPeersCount(),
                "local_routes_count":    self.vpnManager.bgpManager.routeTableManager.getLocalRoutesCount(),
                "received_routes_count": self.vpnManager.bgpManager.routeTableManager.getReceivedRoutesCount(),
                "vpn_instances_count":   self.vpnManager.getVPNWorkersCount(),
                "warnings_and_errors":   len(self.LGLogHandler.getLogs()),
                "start_time":            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.startTime))
                }

    ####################################################
    
    def error500(self,error):
        log.error("Bottle catched an error: %s" % error.exception)
        log.error(traceback.format_exc())
        return "Server Error"


    def run(self):
        #self.bottle.run(host=self.config["api_host"],  #FIXME: make only the LG available from remote hosts other than 127.0.0.1
        self.bottle.run(host="0.0.0.0",
                     port=self.config["api_port"], 
                     debug=True)



