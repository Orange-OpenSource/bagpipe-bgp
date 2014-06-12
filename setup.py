#!/usr/bin/env python

import setuptools
import sys

Name = 'bagpipe-bgp'
Url = ''
Version = '1.39'
License = 'Apache 2.0'
Author = 'Orange Labs'
AuthorEmail = 'thomas.morin@orange.com'
Maintainer = 'Thomas Morin'
Summary = 'BaGPipe BGP'
ShortDescription = "Lightweight implementation of BGP IP VPN and E-VPN"
Description = ShortDescription

config_path = '/etc/bagpipe-bgp/'
init_path = '/etc/init.d'

DataFiles = [
    (config_path, ['config/bgp.conf.template',
                   'config/log.conf.template',
                   'config/log.conf.debug-template']),
    (init_path, ['etc/init.d/bagpipe-bgp','etc/init.d/bagpipe-fakerr']),
    ('%s/bin' % sys.prefix, ['bin/bagpipe-fakerr']), # kludge: I don't know how to point to the 
                                                     # --prefix location given to setup.py as an argument
]


EagerResources = [
]

setuptools.setup(
    name=Name,
    version=Version,
    url=Url,
    author=Author,
    author_email=AuthorEmail,
    description=ShortDescription,
    long_description=Description,
    license=License,
    classifiers=[
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Telecommunications Industry',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
    include_package_data=False,
    install_requires=[
        "bottle >= 0.11.3",
        "python-daemon >= 1.5.5",
        "lockfile >= 0.8",
        "netaddr >= 0.7.7"
    ],
    packages=[
              'bagpipe',
              'bagpipe.bgp',
              'bagpipe.bgp.engine',
              'bagpipe.bgp.common',
              'bagpipe.bgp.vpn',
              'bagpipe.bgp.vpn.ipvpn',
              'bagpipe.bgp.vpn.evpn',
              'exabgp',
              'exabgp.message',
              'exabgp.message.update',
              'exabgp.message.update.attribute',
              'exabgp.network',
              'exabgp.structure',
              'exabgp.rib',
              ],
    package_dir={'bagpipe': 'src/bagpipe',
                 'bagpipe.bgp': 'src/bagpipe/bgp',
                 'bagpipe.bgp.engine': 'src/bagpipe/bgp/engine',
                 'bagpipe.bgp.common': 'src/bagpipe/bgp/common',
                 'bagpipe.bgp.vpn': 'src/bagpipe/bgp/vpn',
                 'bagpipe.bgp.vpn.ipvpn': 'src/bagpipe/bgp/vpn/ipvpn',
                 'bagpipe.bgp.vpn.evpn': 'src/bagpipe/bgp/vpn/evpn',
                 'exabgp': 'exabgp/lib/exabgp',
                 'exabgp.message': 'exabgp/lib/exabgp/message',
                 'exabgp.message.update': 'exabgp/lib/exabgp/message/update',
                 'exabgp.message.update.attribute': 'exabgp/lib/exabgp/message/update/attribute',
                 'exabgp.network': 'exabgp/lib/exabgp/network',
                 'exabgp.rib': 'exabgp/lib/exabgp/rib',
                 'exabgp.structure': 'exabgp/lib/exabgp/structure',
                 'leak': 'exabgp/lib/leak',
                 'netlink': 'exabgp/lib/netlink'},
    scripts=[
             'bin/bagpipe-looking-glass',
             'bin/bagpipe-rest-attach',
             'bin/bagpipe-bgp',
             'bin/bagpipe-bgp-cleanup',
             ],
    data_files=DataFiles,
    eager_resources=EagerResources,
    test_suite="tests.unit",
)
