import os
import urllib2
import json

from optparse import OptionParser

BAGPIPE_PORT = 8082
LOOKING_GLASS_BASE = "looking-glass"


def request(options, server, args):
    target_url = "http://%s:%d/%s/%s" % (server, options.port,
                                         options.prefix, "/".join(args))
    try:
        os.environ['NO_PROXY'] = server
        os.environ['no_proxy'] = server
        response = urllib2.urlopen(target_url)

        if response.getcode() == 200:
            return json.load(response)
    except urllib2.HTTPError as e:
        if e.code == 404:
            return {}
        print "Error requesting %s" % target_url
        raise
    except:
        print "Error requesting %s" % target_url
        raise


def normalize(string):
    return (string
            .replace("target:", "rt:")
            .replace(":", "_")
            .replace("-", "_")
            .replace(".", "_"))

RT_TXT_STYLE = 'color="orange",fontcolor="orange"'
RT_STYLE = 'color="orange",fontcolor="orange",arrowhead=onormal'
RT_STYLE_REDIR_FROM_RT = ('color="orange",fontcolor="orange",style=dashed,'
                          'arrowhead=diamond,arrowtail=oinv,headclip=false,'
                          'dir=both')
RT_STYLE_REDIR_TO_RT = ('color="orange",fontcolor="orange",style=dashed,'
                        'arrowhead=onormal,tailclip=false,dir=both,'
                        'arrowtail=oinv')
RT_STYLE_FLOWSPEC = 'color="red",fontcolor="red",style=dotted'
RT_STYLE_FLOWSPEC_INTER = ('color="red",fontcolor="red",style=dotted,'
                           'arrowhead=none,dir=both,arrowtail=oinv')
RT_STYLE_FLOWSPEC_ACTION = 'color="red",fontcolor="red",style=dashed'
PORT_LINK_STYLE = 'style=dashed,dir=none,color="gray",weight=3'


def get_all(options):
    rts = set()
    vpns = set()

    for server in options.servers:
        for vpn in request(options, server, ["vpns", "instances"]):
            vpn_id = vpn['id']
            type = vpn['name'][:3]
            vpns.add((server, vpn_id, type))
            for rt_i in request(options, server, ["vpns", "instances", vpn_id,
                                                  "route_targets", "import"]):
                rts.add(normalize(rt_i))
            for rt_e in request(options, server, ["vpns", "instances", vpn_id,
                                                  "route_targets", "export"]):
                rts.add(normalize(rt_e))

            readvertise = request(options, server, ["vpns", "instances",
                                                    vpn_id, "readvertise"])
            if readvertise:
                rts.add(normalize(readvertise['to'][0]))
                rts.add(normalize(readvertise['from'][0]))

                attract = readvertise.get('attract_traffic', None)
                if attract:
                    rts |= set([normalize(rt)
                                for rt in attract['redirect_rts']])

    return (rts, vpns)


def vpn_uid(server, vpn):
    return "vpn_%s__%s" % (normalize(server), normalize(vpn))


def vpn_short(vpn):
    if len(vpn) > 11:
        return vpn[:4]+".."+vpn[-5:]
    else:
        return vpn


def main():
    usage = """ %prog [options]

Example: bagpipe-impex2dot --server s1 --server s2 | dot -Tpdf > impex.pdf
    """
    parser = OptionParser(usage)

    parser.add_option(
        "--server", dest="servers", default=[], action="append",
        help="IP address of a BaGPipe BGP instances (default: 127.0.0.1)")

    parser.add_option(
        "--port", dest="port", type="int", default=BAGPIPE_PORT,
        help="Port of BaGPipe BGP (optional, default: %default)")

    parser.add_option(
        "--prefix", dest="prefix", default=LOOKING_GLASS_BASE,
        help="Looking-glass URL Prefix (optional, default: %default)")

    (options, _) = parser.parse_args()

    if len(options.servers) == 0:
        options.servers = ["127.0.0.1"]

    ports = set()
    dests = set()
    print 'digraph import_export {'

    print '   node [fontname="Helvetica"];'
    print '   edge [fontname="Helvetica"];'
    print '   nodesep=0.55;'

    (rts, vpns) = get_all(options)
    print '   subgraph rts {'
    print '       rank=same;'
    for rt in rts:
        label = rt.upper().replace('_', '\\n')
        print '        %s [shape="circle",label="%s",%s];' % (rt, label,
                                                              RT_TXT_STYLE)
    print '    }'

    print '    subgraph ipvpns {'
    print '        rank=same;'
    for (server, vpn, _) in filter(lambda x: x[2] == 'VRF', vpns):
        print ('        %s [label="{<0>VRF\\n%s\\n[%s]|<readv>}",'
               'shape="record"];' % (vpn_uid(server, vpn), vpn_short(vpn),
                                     server))
    print '    }'

    print '    subgraph evpns {'
    for (server, vpn, _) in filter(lambda x: x[2] == 'EVI', vpns):
        print ('        %s [label="EVI\\n%s\\n[%s]",'
               'shape="box"];' % (vpn_uid(server, vpn), vpn_short(vpn),
                                  server))
    print '    }'

    for (server, vpn, _) in vpns:
        print '    /* %s:%s */' % (server, vpn)
        uid = vpn_uid(server, vpn)

        for rt_i in request(options, server, ["vpns", "instances", vpn,
                                              "route_targets", "import"]):
            print '    %s -> %s:0 [%s];' % (normalize(rt_i), uid,
                                            RT_STYLE)

        for rt_e in request(options, server, ["vpns", "instances", vpn,
                                              "route_targets", "export"]):
            print '    %s:0 -> %s [%s];' % (uid, normalize(rt_e),
                                            RT_STYLE)

        readvertise = request(options, server, ["vpns", "instances",
                                                vpn, "readvertise"])
        if readvertise:
            readv = "%s:readv" % vpn_uid(server, vpn)
            print ('    %s -> %s [label="",%s];' %
                   (normalize(readvertise['from'][0]),
                    readv,
                    RT_STYLE_REDIR_FROM_RT))
            print ('    %s -> %s [label="",%s];' %
                   (readv,
                    normalize(readvertise['to'][0]),
                    RT_STYLE_REDIR_TO_RT))

            attract = readvertise.get('attract_traffic', None)
            if attract:
                intermediate = "%s_%s_attract" % (normalize(server),
                                                  normalize(vpn))
                print ('    %s [style=invis,height=0,width=0,'
                       'fixedsize=true,rank=1]' % intermediate)

                redir_rt = attract['redirect_rts'][0]

                # readv -> intermediate
                print ('    %s -> %s [label="flow",%s];' %
                       (readv, intermediate,
                        RT_STYLE_FLOWSPEC_INTER))

                # intermediate -> flowspec route RT
                print ('    %s -> %s [label="",weight=50,%s];' %
                       (intermediate, normalize(redir_rt),
                        RT_STYLE_FLOWSPEC))

                # intermediate -> flowspec route redirect action  RT
                print ('    %s -> %s [label="action",%s,arrowhead=none'
                       ',weight=20];' %
                       (intermediate, normalize(readvertise['to'][0]),
                        RT_STYLE_FLOWSPEC_ACTION))

        for port in request(options, server, ["vpns", "instances",
                                              vpn, "ports"]).iterkeys():
            print ('    %s -> port_%s_%s [%s,weight=5];' % (uid,
                                                            normalize(server),
                                                            normalize(port),
                                                            PORT_LINK_STYLE))
            ports.add((server, normalize(port)))

        # possible link between an E-VPN and an IPVPN ?
        ipvpn = request(options, server, ["vpns", "instances",
                                          vpn, "gateway_port", "ipvpn"])
        if ipvpn:
            ipvpn_id = ipvpn['external_instance_id']
            print ('    %s -> %s [weight=500];' % (uid,
                                                   vpn_uid(server, ipvpn_id))
                   )

    for (server, port) in ports:
        print ('    port_%s_%s [label="",style=invis,height=0,width=0,'
               'fixedsize=true];' % (normalize(server),
                                     normalize(port)))
        if port.startswith('to_'):
            dest = port.split('_')[1]
            print ('    port_%s_%s -> dest_%s_%s [style=dashed,'
                   'dir=none,color="gray"'
                   ',weight=5];' %
                   (server, normalize(port), normalize(server), dest))
            dests.add((server, dest))

    for (server, dest) in dests:
        print ('    dest_%s_%s [label="%s\\n[%s]",shape="square",'
               'color="gray"];' % (normalize(server),
                                   normalize(dest), dest, server))

    print '}'
