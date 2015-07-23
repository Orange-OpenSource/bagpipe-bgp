#!/bin/bash

# Save trace setting
XTRACE=$(set +o | grep xtrace)
set +o xtrace

# Set config files, create data dirs, etc
function configure_bagpipe {
	# Put config files in ``/etc/bagpipe-bgp`` for everyone to find
	if [[ ! -d $BAGPIPE_CONF_DIR ]]; then
		sudo mkdir -p $BAGPIPE_CONF_DIR
	fi
	sudo chown $STACK_USER $BAGPIPE_CONF_DIR

	if is_service_enabled b-bgp; then
		# build the config file from scratch
		create_bagpipe_conf
	fi
}

# Create a new bgp.conf file
function create_bagpipe_conf {
	# (Re)create ``bgp.conf``
	cp -p $BAGPIPE_DIR/config/bgp.conf.template $BAGPIPE_CONF
	iniset $BAGPIPE_CONF BGP local_address ${BAGPIPE_HOST_IP:-$HOST_IP}
	iniset $BAGPIPE_CONF BGP peers "$BAGPIPE_BGP_PEERS"
	iniset $BAGPIPE_CONF DATAPLANE_DRIVER_IPVPN dataplane_driver ${BAGPIPE_DATAPLANE_DRIVER_IPVPN:-DummyDataplaneDriver}
	iniset $BAGPIPE_CONF DATAPLANE_DRIVER_IPVPN mpls_interface $BAGPIPE_MPLS_IFACE
	iniset $BAGPIPE_CONF DATAPLANE_DRIVER_IPVPN ovs_bridge $BAGPIPE_MPLS_BR
	iniset $BAGPIPE_CONF DATAPLANE_DRIVER_EVPN dataplane_driver ${BAGPIPE_DATAPLANE_DRIVER_EVPN:-DummyDataplaneDriver}

	# copy log config template depending
	cp $BAGPIPE_DIR/config/log.conf.debug-template $BAGPIPE_LOG_CONF

	# configure the log conf so that stuff is also logged to the console
	iniset $BAGPIPE_LOG_CONF handlers keys rotatingFile,console
	iniset $BAGPIPE_LOG_CONF handler_console class StreamHandler
	iniset $BAGPIPE_LOG_CONF handler_console args "(sys.stdout,)"
	iniset $BAGPIPE_LOG_CONF handler_console formatter standard
	iniset $BAGPIPE_LOG_CONF handler_rotatingFile args "('$DEST/logs/bagpipe-bgp.log','a',1024*1024*5,5)"
	sed -i s/handlers=rotatingFile/handlers=rotatingFile,console/ $BAGPIPE_LOG_CONF
}

# Initialize databases, etc.

function init_bagpipe {
	if [[ $BAGPIPE_DATAPLANE_DRIVER_IPVPN == *"MPLSOVSDataplaneDriver"* ]]
		init_bagpipe_ovsmpls
	else
		echo "IP VPN driver not MPLSOVSDataplaneDriver, let's not init OVS MPLS bridge ($BAGPIPE_DATAPLANE_DRIVER_IPVPN)"
	fi
}


function init_bagpipe_ovsmpls {

	:> $BAGPIPE_BR_RESET_SCRIPT

	if [ -n "$BAGPIPE_MPLS_IFACE" ]; then

		cat >> $BAGPIPE_BR_RESET_SCRIPT <<EOF

echo "Setting up $BAGPIPE_MPLS_BR OVS bridge and associated IP interface $BAGPIPE_INTERNAL_PORT based on current $BAGPIPE_MPLS_IFACE settings"
MPLS_IFACE_IP=\`ip addr show $BAGPIPE_MPLS_IFACE | grep 'inet ' | awk '{ print \$2 }'\`

if [ -z "\$MPLS_IFACE_IP" ]; then
	echo "Failure retrieving IP config of BaGPipe MPLS interface ($BAGPIPE_MPLS_IFACE): perhaps $BAGPIPE_MPLS_BR was configured already ?"
	echo "Try to setup $BAGPIPE_MPLS_IFACE before trying again.."
	return 0
fi

if [ "\`ip route  | grep default | awk '{ print \$5 }'\`" == "$BAGPIPE_MPLS_IFACE" ]; then
	GW_IP=\`ip route  | grep default | awk '{ print \$3 }'\`
fi

#echo "adding bridge $BAGPIPE_MPLS_BR with interface $BAGPIPE_MPLS_IFACE"
sudo ip addr flush dev $BAGPIPE_MPLS_IFACE
sudo ovs-vsctl del-br $BAGPIPE_MPLS_BR || true
sudo ovs-vsctl --may-exist add-br $BAGPIPE_MPLS_BR
# sudo ovs-vsctl -- --may-exist add-br $BAGPIPE_MPLS_BR -- set bridge $BAGPIPE_MPLS_BR datapath_type=netdev
sudo ovs-vsctl --may-exist add-port $BAGPIPE_MPLS_BR $BAGPIPE_MPLS_IFACE
#echo "adding iface $BAGPIPE_INTERNAL_PORT to bridge $BAGPIPE_MPLS_BR"
#when devstack is run on a VM deployed on openstack, by default, openstack will forbid this VM to use another MAC address than the one it has allocated
#use a port with the same MAC as the one used by BAGPIPE_MPLS_IFACE
MAC=\`ip link show dev $BAGPIPE_MPLS_IFACE | grep link/ether | awk '{ print \$2 }'\`
sudo ovs-vsctl -- --may-exist add-port $BAGPIPE_MPLS_BR $BAGPIPE_INTERNAL_PORT -- set interface $BAGPIPE_INTERNAL_PORT type=internal -- set interface $BAGPIPE_INTERNAL_PORT mac=\"\$MAC\"
	sudo ip link set dev $BAGPIPE_INTERNAL_PORT address \$MAC
#echo "setting ip and port on $BAGPIPE_INTERNAL_PORT"
sudo ip addr add \$MPLS_IFACE_IP dev $BAGPIPE_INTERNAL_PORT
sudo ip link set $BAGPIPE_INTERNAL_PORT up
sudo ip link set $BAGPIPE_MPLS_BR up
if [ -n "\$GW_IP" ]; then
	#echo "adding route to $\GW_IP"
	sudo ip route add default via \$GW_IP
fi

# map traffic to/from the bagpipe port from/to the physical interface,
# traffic from the phy interface only goes to internal port as a last
# resort (if it did not match an MPLS rule)
BAGPIPE_MPLS_IFACE_PORT_NUMBER=\`sudo ovs-ofctl show $BAGPIPE_MPLS_BR | grep "($BAGPIPE_MPLS_IFACE)" | awk '-F(' '{print \$1}' | tr -d ' '\`
BAGPIPE_INTERNAL_PORT_NUMBER=\`sudo ovs-ofctl show $BAGPIPE_MPLS_BR | grep "($BAGPIPE_INTERNAL_PORT)" | awk '-F(' '{print \$1}' | tr -d ' '\`
sudo ovs-ofctl add-flow $BAGPIPE_MPLS_BR priority=0,in_port=\$BAGPIPE_MPLS_IFACE_PORT_NUMBER,action=output:\$BAGPIPE_INTERNAL_PORT_NUMBER
sudo ovs-ofctl add-flow $BAGPIPE_MPLS_BR in_port=\$BAGPIPE_INTERNAL_PORT_NUMBER,action=output:\$BAGPIPE_MPLS_IFACE_PORT_NUMBER
# remove the default 'NORMAL' rule
sudo ovs-ofctl del-flows $BAGPIPE_MPLS_BR --strict priority=0

EOF

	else

		cat >> $BAGPIPE_BR_RESET_SCRIPT <<EOF

sudo ovs-vsctl del-br $BAGPIPE_MPLS_BR || true
sudo ovs-vsctl --may-exist add-br $BAGPIPE_MPLS_BR
#sudo ovs-vsctl --may-exist set-br $BAGPIPE_MPLS_BR datapath_type=netdev
sudo ovs-vsctl del-port $BAGPIPE_MPLS_BR eth0 || true
sudo ovs-vsctl del-port $BAGPIPE_MPLS_BR eth1 || true
# remove the default 'NORMAL' rule
sudo ovs-ofctl del-flows $BAGPIPE_MPLS_BR --strict priority=0

EOF

	fi

	source $BAGPIPE_BR_RESET_SCRIPT
}

# Start the BGP component
function start_bagpipe_bgp {
	if is_service_enabled b-bgp ; then
		screen_it b-bgp "sudo bagpipe-bgp start --no-daemon --log-file=$BAGPIPE_LOG_CONF"

		echo "Waiting for bagpipe-bgp to start..."
		if ! wait_for_service $SERVICE_TIMEOUT http://$BAGPIPE_SERVICE_HOST:$BAGPIPE_SERVICE_PORT; then
				die $LINENO "bagpipe-bgp did not start"
		fi
	fi
}

# Start the FakeRR component
function start_bagpipe_fakerr {
	if is_service_enabled b-fakerr ; then
		screen_it b-fakerr "echo 'from bagpipe.bgp.fakerr import application' | sudo twistd -n -y /dev/stdin"
	fi
}

function start_bagpipe {
	start_bagpipe_bgp
	start_bagpipe_fakerr
}

function stop_bagpipe_bgp {
	screen_stop b-bgp
}

function stop_bagpipe_fakerr {
	screen_stop b-fakerr
}

# Stop running processes (non-screen)
function stop_bagpipe {
	stop_bagpipe_bgp
	stop_bagpipe_fakerr
}

# Remove residual data files, anything left over from previous runs that a
# clean run would need to clean up
function cleanup_bagpipe {
	if is_service_enabled b-bgp ; then
		sudo bagpipe-bgp-cleanup --log-file=$BAGPIPE_LOG_CONF_CLEANUP

		MPLS_IFACE_IP=`ip addr show $BAGPIPE_INTERNAL_PORT | grep 'inet ' | awk '{ print $2 }'`
		GW_IP=`ip route  | grep default | awk '{ print $3 }'`
		sudo ovs-vsctl del-br $BAGPIPE_MPLS_BR
		sudo ip addr add $MPLS_IFACE_IP dev $BAGPIPE_MPLS_IFACE
		sudo ip route add default via $GW_IP
	fi
}

if [[ "$1" == "source" ]]; then
		# no-op
		:
elif [[ "$1" == "stack" && "$2" == "install" ]]; then
		echo_summary "Installing Bagpipe"
		#FIXME: there must be a better way...
		grep -iv pbr $BAGPIPE_DIR/requirements.txt >> $DEST/requirements/global-requirements.txt
		setup_develop $BAGPIPE_DIR
elif [[ "$1" == "stack" && "$2" == "post-config" ]]; then
		echo_summary "Configuring Bagpipe"
		configure_bagpipe
		# Initializing before neutron starts to move the single interface in br-mpls
		init_bagpipe
elif [[ "$1" == "stack" && "$2" == "extra" ]]; then
		echo_summary "Starting Bagpipe"
		start_bagpipe
fi
if [[ "$1" == "unstack" ]]; then
		echo_summary "Stopping Bagpipe"
		stop_bagpipe
		cleanup_bagpipe
fi
if [[ "$1" == "clean" ]]; then
		cleanup_bagpipe
fi

set +x
$xtrace
