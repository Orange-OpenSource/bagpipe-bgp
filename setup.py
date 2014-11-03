#!/usr/bin/env python

import setuptools
import sys

config_path = '/etc/bagpipe-bgp/'
init_path = '/etc/init.d'

DataFiles = [
    (config_path, ['config/bgp.conf.template',
                   'config/log.conf.template',
                   'config/log.conf.console-template',
                   'config/log.conf.debug-template']),
    (init_path, ['etc/init.d/bagpipe-bgp','etc/init.d/bagpipe-fakerr']),
    ('%s/bin' % sys.prefix, ['bin/bagpipe-fakerr']), # kludge: I don't know how to point to the 
                                                     # --prefix location given to setup.py as an argument
]

setuptools.setup(
    name='bagpipe-bgp',
    version='1.60',
    url="https://github.com/Orange-OpenSource/bagpipe-bgp",
    author='Orange Labs',
    maintainer="Thomas Morin",
    author_email='thomas.morin@orange.com',
    description='BaGPipe BGP',
    long_description="Lightweight implementation of BGP IP VPN and E-VPN",
    license='Apache 2.0',
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
    install_requires=[
        "bottle >= 0.11.3",
        "python-daemon >= 1.5.5",
        "lockfile >= 0.8",
        "netaddr >= 0.7.7"
	# python-testtools ?
    # distutils
    ],
    packages=setuptools.find_packages(where='src'),
    package_dir={'':'src'},
    scripts=[
             'bin/bagpipe-looking-glass',
             'bin/bagpipe-rest-attach',
             'bin/bagpipe-bgp',
             'bin/bagpipe-bgp-cleanup',
             ],
    data_files=DataFiles,
    #eager_resources=[],
    test_suite="bagpipe.bgp.tests",
)
