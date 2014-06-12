#!/bin/bash
#
# Copyright 2014 Orange

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
	echo "*** WARNING: This script must be run as root ***" 1>&2
	exit 1
fi


echo "*** Installing BaGPipe BGP component ***"

python setup.py install

echo -e "\n*** Creating BaGPipe BGP component service ***"
update-rc.d bagpipe-bgp defaults 80

logfile=/etc/bagpipe-bgp/log.conf
if [ ! -f "$logfile" ]; then
	cp /etc/bagpipe-bgp/log.conf.template $logfile
fi

confFile=/etc/bagpipe-bgp/bgp.conf
oldConf=/etc/bagpipe-bgp/bgp_conf.ini
if [ ! -f $confFile -a -f $oldConf ]; then
	mv -v $oldConf $confFile
fi

# still need to investigate why setup.py won't do it
chmod +x /usr/bin/bagpipe-fakerr

case $1 in
    "manual")
		echo -e "\n\n*** WARNING: BaGPipe BGP component service must be started manually ***"
		;;
    "auto"|"")
		echo -e "\n\n*** Starting BaGPipe BGP component service ***"
		service bagpipe-bgp restart
	
		if [ $? -ne 0 ]; then
		    echo -e "\nAn error occurred when starting BGP component service\n"
		    exit 1
		fi
		;;
    *) echo "Unsupported option! Supported options are 'auto' and 'manual'.";
	exit 1 ;;
esac

echo -e "*** BaGPipe BGP component ready ! ***\n"
