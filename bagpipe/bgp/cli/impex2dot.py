import os
import urllib2
import json

from optparse import OptionParser

BAGPIPE_PORT = 8082
LOOKING_GLASS_BASE = "looking-glass"


def request(options, args):
    target_url = "http://%s:%d/%s/%s" % (options.server, options.port,
                                         options.prefix, "/".join(args))
    try:
        os.environ['NO_PROXY'] = options.server
        response = urllib2.urlopen(target_url)

        if response.getcode() == 200:
            return json.load(response)
    except:
        raise


def normalize(rtstring):
    return (rtstring
            .replace("target:", "rt:")
            .replace(":", "_")
            .replace("-", "_")
            .replace("64512_", ""))


RT_STYLE = 'color="orange",textcolor="orange"'


def get_all(options):
    rts = set()
    vrfs = set()

    for vrf in request(options, ["vpns", "instances"]):
        vrf_id = normalize(vrf['id'])
        vrfs.add(vrf_id)
        for rt_i in request(options, ["vpns", "instances", vrf_id,
                                      "route_targets", "import"]):
            rts.add(normalize(rt_i))
        for rt_e in request(options, ["vpns", "instances", vrf_id,
                                      "route_targets", "export"]):
            rts.add(normalize(rt_e))
        try:
            readvertise = request(options, ["vpns", "instances", vrf_id,
                                            "readvertise"])
            if len(readvertise):
                rts.add(normalize(readvertise['to'][0]))
                rts.add(normalize(readvertise['from'][0]))
        except urllib2.HTTPError as e:
            if e.code != 404:
                raise
    return (rts, vrfs)


def main():
    usage = """ %prog [options]"""
    parser = OptionParser(usage)

    parser.add_option(
        "--server", dest="server", default="127.0.0.1",
        help="IP address of BaGPipe BGP (optional, default: %default)")

    parser.add_option(
        "--port", dest="port", type="int", default=BAGPIPE_PORT,
        help="Port of BaGPipe BGP (optional, default: %default)")

    parser.add_option(
        "--prefix", dest="prefix", default=LOOKING_GLASS_BASE,
        help="Looking-glass URL Prefix (optional, default: %default)")

    (options, _) = parser.parse_args()

    ports = set()
    dests = set()
    print 'digraph import_export {'

    (rts, vrfs) = get_all(options)
    print '   subgraph rts {'
    print '       rank=same;'
    for rt in rts:
        label = rt.replace('_', '\\n').upper()
        print '        %s [shape="circle",label="%s",%s];' % (rt, label,
                                                              RT_STYLE)
    print '    }'

    print '    subgraph vrfs {'
    print '       rank=same;'
    for vrf in vrfs:
        print '        vrf_%s [label="VRF\\n%s", shape="box"];' % (vrf, vrf)
    print '    }'

    for vrf_id in vrfs:

        for rt_i in request(options, ["vpns", "instances", vrf_id,
                                      "route_targets", "import"]):
            print '        %s -> vrf_%s [%s];' % (normalize(rt_i), vrf_id,
                                                  RT_STYLE)
        for rt_e in request(options, ["vpns", "instances", vrf_id,
                                      "route_targets", "export"]):
            print '        vrf_%s -> %s [%s];' % (vrf_id, normalize(rt_e),
                                                  RT_STYLE)
        try:
            readvertise = request(options, ["vpns", "instances", vrf_id,
                                            "readvertise"])
            if len(readvertise):
                print ('        %s -> %s [label="via\\n%s",style=dashed,%s];' %
                       (normalize(readvertise['from'][0]),
                        normalize(readvertise['to'][0]),
                        vrf_id,
                        RT_STYLE))
        except urllib2.HTTPError as e:
            if e.code != 404:
                raise
        for port in request(options, ["vpns", "instances",
                                      vrf_id, "ports"]).iterkeys():
            print ('        vrf_%s -> %s  [style=dashed,dir=none,'
                   'color="gray",weight=3];' % (vrf_id, normalize(port)))
            ports.add(normalize(port))

    for port in ports:
        print '    %s [style=invis,height=0,width=0,fixedsize=true];' % port
        if port.startswith('to_'):
            dest = port.split('_')[1]
            print ('    %s -> %s [style=dashed,dir=none,color="gray"'
                   ',weight=3];' %
                   (port, dest))
            dests.add(dest)

    for dest in dests:
        print '    %s [shape="square",color="gray"];' % dest

    print '}'
