BaGPipe BGP
===========

[![Join the chat at https://gitter.im/Orange-OpenSource/bagpipe-bgp](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/Orange-OpenSource/bagpipe-bgp?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

BaGPipe BGP is a lightweight implementation of BGP VPNs (IP VPNs and E-VPNs), targeting
deployments on servers hosting VMs, in particular for Openstack/KVM platforms.

The goal is *not* to fully implement BGP specifications, but only the subset 
of specifications required to implement IP VPN VRFs and E-VPN EVIs ([RFC4364](http://tools.ietf.org/html/rfc4364) 
a.k.a RFC2547bis, [RFC7432](http://tools.ietf.org/html/rfc7432)/[draft-ietf-bess-evpn-overlay](http://tools.ietf.org/html/draft-ietf-bess-evpn-overlay),
 and [RFC4684](http://tools.ietf.org/html/RFC4684)).

BaGPipe BGP is designed to use encapsulations over IP (such as MPLS-over-GRE or VXLAN), 
and thus does not require the use of LDP. Bare MPLS over Ethernet is also supported and 
can be used if servers/routers have direct Ethernet connectivity.

Typical Use
-----------

BaGPipe-BGP has been designed to provide VPN (IP VPN or E-VPN) connectivity 
to VMs running on a local server.

The target is to provide VPN connectivity to VMs deployed by Openstack. 
A typical target architecture is to have BaGPipe-BGP be driven by Openstack 
Neutron components:

* the [bagpipe driver for the BGP VPN interconnection service plugin](https://github.com/openstack/networking-bgpvpn)
* the [bagpipe ML2 mechanism driver](https://github.com/openstack/networking-bagpipe) using E-VPN

BaGPipe-BGP can also be used standalone (e.g. for testing purposes), 
with for instance VMs tap interfaces or veth interfaces to network namespaces (see [below](#netns-example)).

Installation
------------

Installation can be done with `python setup.py install`.

Running `install.sh` will take care of this and will *also* install startup scripts
in `/etc/init.d` and sample config files in `/etc/bagpipe-bgp`.


<a name="bgprr"></a>
BGP and Route Reflection
------------------------

If you only want to test how to interconnect one server running bagpipe-bgp and an 
IP/MPLS router, you don't need to setup a BGP Route Reflector. But to use BaGPipe 
BGP on more than one server, the current code currently requires setting up a 
BGP Route Reflector (see [Caveats](#caveats)).

The term "BGP Route Reflector" refers to a BGP implementation that redistribute routes 
between iBGP peers [RFC4456](http://tools.ietf.org/html/RFC4456).

When using bagpipe-bgp on more than one server, we thus need each instance of BaGPipe BGP
to be configured to peer with at least one route reflector (see [Configuration](#config)).

We provide a tool that can be used to emulate a route reflector to interconnect **2** 
BaGPipe BGP implementations, typically for test purposes (see [Fake RR](#fakerr)).

For more than 2 servers running BaGPipe BGP, you will need a real BGP implementation
supporting RFC4364 and BGP route reflection (and ideally also RFC4684). 

Different options can be considered:

 * A router from for instance, Alcatel-Lucent, Cisco or Juniper can be used; some of these vendors
   also provide their OSes as virtual machines

 * BGP implementations in other opensource projects would possibly be suitable, but we did not explore i
   these exhaustively:

    * there has been some work to allow the use of OpenContrail's BGP implementation as a Route Reflector; 
      although this is currently unfinished, we have done rough hacks to confirm the feasibility and the
      interoperability

    * [GoBGP](http://osrg.github.io/gobgp/) team has sucessfully deployed a setup with [GoBGP as a RR for bagpipe-bgp PE implementations,
      with E-VPN](https://github.com/osrg/gobgp/blob/master/docs/sources/evpn.md)

    * we have sucessfully used OpenBSD BGPd as an IP VPN RR for bagpipe-bgp

    * Quagga is supposed to support IP VPNs (untested AFAIK)


<a name="config"></a>
Configuration
-------------

The bagpipe-bgp daemon config file default location is: `/etc/bagpipe-bgp/bgp.conf`.

The `install.sh` script will install a template as an example configuration.

It needs to be customized, at least for the following:

* local_address: the local address to use for BGP sessions and traffic encapsulation
* peers: the list of BGP peers, it depends on 
the BGP setup that you have chosen (see above [BGP Route Reflection](#bgprr))  
* dataplane configuration, if you really want packets to get through (see [Dataplane configuration](#dpconfig))

Example with two servers and relying on bagpipe fake route reflector:

* On server A (local_address=10.0.0.1):
  * run bagpipe-fakerr 
  * run bagpipe-bgp with peers=127.0.0.1 (server A will thus connect to the 
  locally running fake route-reflector)
* On server B (local_address=10.0.0.2):
  * run bagpipe-bgp with peers=10.0.0.1 

<a name="dpconfig"></a>
### Dataplane driver configuration ###

Note well that the dataplane drivers proposed in the sample config file are 
_dummy_ drivers that will **not** actually drive any dataplane state.
To have traffic really forwarded into IP VPNs or E-VPNs, you need to select 
real dataplane drivers.

For instance, you can use the `mpls_ovs_dataplane.MPLSOVSDataplaneDriver` for IP VPN, 
and the `linux_vxlan.LinuxVXLANDataplaneDriver` for E-VPN.

**Note well** that there are specific constraints on which dataplane drivers can 
currently be used for IP VPNs:

* the MPLSOVSDataplaneDriver can be used on most recent Linux kernels, but 
  requires an OpenVSwitch with suitable MPLS code (OVS 2.4 with DKMS module was tested);
  this driver can do bare-MPLS or MPLS-over-GRE (but see [Caveats](#caveats) for MPLS-over-GRE);
  for bare MPLS, this driver requires the OVS bridge to be associated with 
  an IP address, and that VRF interfaces be plugged into OVS prior to 
  calling BaGPipe BGP API to attach them (details in
   [mpls\_ovs\_dataplane.py](bagpipe/bgp/vpn/ipvpn/mpls_ovs_dataplane.py#L578))

* (the MPLSLinuxDataplaneDriver is based on an unmaintained MPLS stack for the Linux 
3.7 kernel, and should be considered *obsolete* ; see [mpls\_linux\_dataplane.py](bagpipe/bgp/vpn/ipvpn/mpls_linux_dataplane.py#L245))

For E-VPN, the `linux_vxlan.LinuxVXLANDataplaneDriver` is usable without any 
particular additional configuration, and simply requires a Linux kernel >=3.10
with VXLAN compiled-in or provided as a module ([linux_vxlan.py](bagpipe/bgp/vpn/evpn/linux_vxlan.py#L269)).

Usage
-----

### BaGPipe BGP daemon ###

If init scripts are installed, the daemon is typically started with:
`service bagpipe-bgp start`
 
It can also be started directly with the `bagpipe-bgp` command (`--help`
to see what parameters can be used; e.g. `--no-deamon`).

It outputs logs in `/var/log/bagpipe-bgp/bagpipe-bgp.log`.

<a name="fakerr"></a>
### BaGPipe Fake BGP Route Reflector ###

If you choose to use our fake BGP Route Reflector (see [BGP Route Reflection](#bgprr)), you 
can start it whether with the `bagpipe-fakerr` command, or if you have 
startup scripts installed, with `service bagpipe-bgp start`.

There isn't anything to configure, logs will be in syslog.

This tool is not a BGP implementation and simply plugs together two TCP connections face to face.

### REST API tool for interface attachments ###

The `bagpipe-rest-attach` tool allows to exercise the REST API through the command line to attach and detach interfaces from ip VPN VRFs and E-VPN EVIs.

See `bagpipe-rest-attach --help`.

#### IP VPN example with a VM tap interface ####

This example assumes that there is a pre-existing tap interface 'tap42'.

* on server A, plug tap interface tap42, MAC de:ad:00:00:be:ef, IP 11.11.11.1 into an IP VPN VRF with route-target 64512:77:

        bagpipe-rest-attach --attach --port tap42 --mac de:ad:00:00:be:ef --ip 11.11.11.1 --gateway-ip 11.11.11.254 --network-type ipvpn --rt 64512:77

* on server B, plug tap interface tap56, MAC ba:d0:00:00:ca:fe, IP 11.11.11.2 into an IP VPN VRF with route-target 64512:77:

        bagpipe-rest-attach --attach --port tap56 --mac ba:d0:00:00:ca:fe --ip 11.11.11.2 --gateway-ip 11.11.11.254 --network-type ipvpn --rt 64512:77


Note that this example is a schoolbook example only, but does not actually 
work unless you try to use one of the two MPLS Linux dataplane drivers.

Note also that, assuming that VMs are behind these tap interfaces, these 
VMs will need to have proper IP configuration. When BaGPipe BGP is use 
standalone, no DHCP service is provided, and the IP configuration will 
have to be static. 

<a name="netns-example"></a>
#### Another IP VPN example... ####

In this example, the bagpipe-rest-attach tool will build for you a network
namespace and a properly configured pair of veth interfaces, and will plug
one of the veth to the VRF:

* on server A, plug a netns interface with IP 12.11.11.1 into a new IP VPN VRF named "test", with route-target 64512:78

        bagpipe-rest-attach --attach --port netns --ip 12.11.11.1 --network-type ipvpn --vpn-instance-id test --rt 64512:78

* on server B, plug a netns interface with IP 12.11.11.2 into a new IP VPN VRF named "test", with route-target 64512:78

        bagpipe-rest-attach --attach --port netns --ip 12.11.11.2 --network-type ipvpn --vpn-instance-id test --rt 64512:78

For this last example, assuming that you have configured bagpipe-bgp to use the `MPLSOVSDataplaneDriver` for IP VPN, you will actually
be able to have traffic exchanged between the network namespaces:

    ip netns exec test ping 12.11.11.2
    PING 12.11.11.2 (12.11.11.2) 56(84) bytes of data.
    64 bytes from 12.11.11.2: icmp_req=6 ttl=64 time=1.08 ms
    64 bytes from 12.11.11.2: icmp_req=7 ttl=64 time=0.652 ms


#### An E-VPN example ####

In this example, similarly as the previous one, the bagpipe-rest-attach tool 
will build for you a network namespace and a properly configured pair of
veth interfaces, and will plug one of the veth to the E-VPN instance:

* on server A, plug a netns interface with IP 12.11.11.1 into a new E-VPN named "test2", with route-target 64512:79

        bagpipe-rest-attach --attach --port netns --ip 12.11.11.1 --network-type evpn --vpn-instance-id test2 --rt 64512:79

* on server B, plug a netns interface with IP 12.11.11.2 into a new E-VPN named "test2", with route-target 64512:79

        bagpipe-rest-attach --attach --port netns --ip 12.11.11.2 --network-type evpn --vpn-instance-id test2 --rt 64512:79

For this last example, assuming that you have configured bagpipe-bgp to use the `linux_vxlan.LinuxVXLANDataplaneDriver` for E-VPN, you will actually
be able to have traffic exchanged between the network namespaces:

    ip netns exec test2 ping 12.11.11.2
    PING 12.11.11.2 (12.11.11.2) 56(84) bytes of data.
    64 bytes from 12.11.11.2: icmp_req=1 ttl=64 time=1.71 ms
    64 bytes from 12.11.11.2: icmp_req=2 ttl=64 time=1.06 ms


### Looking glass ###

The REST API (default port 8082) provide troubleshooting information, in read-only, through the /looking-glass URL.

It can be accessed with a browser: e.g. http://10.0.0.1:8082/looking-glass or http://127.0.0.1:8082/looking-glass (a browser extension to nicely display JSON data is recommended).

It can also be accessed with the `bagpipe-looking-glass` utility:

    # bagpipe-looking-glass 
    bgp:  (...)
    vpns:  (...)
    config:  (...)
    logs:  (...)
    summary: 
      warnings_and_errors: 2
      start_time: 2014-06-11 14:52:32
      local_routes_count: 1
      BGP_established_peers: 0
      vpn_instances_count: 1
      received_routes_count: 0
<!-- -->

    # bagpipe-looking-glass bgp peers
    * 192.168.122.1 (...)
      state: Idle
<!-- -->

    # bagpipe-looking-glass bgp routes
    match:IPv4/mpls-vpn,*: 
      * RD:192.168.122.101:1 12.11.11.1/32 MPLS:[129-B]: 
          attributes: 
            next_hop: 192.168.122.101
            extended_community: target:64512:78
          afi-safi: IPv4/mpls-vpn
          source: VRF 1 (...)
          route_targets: 
            * target:64512:78
    match:IPv4/rtc,*:
      * RTC<64512>:target:64512:78: 
          attributes:
            next_hop: 192.168.122.101
          afi-safi: IPv4/rtc
          source: BGPManager (...)
    match:L2VPN/evpn,*: -


Design overview
---------------

The main components of BaGPipe-BGP are:

* the engine dispatching events related to BGP routes between workers
* a worker for each BGP peers
* a VPN manager managing the life-cycle of VRFs, EVIs
* a worker for each IP VPN VRF, or E-VPN EVI
* a REST API:
  * to attach/detach interfaces to VRFs and control the parameters for 
    said VRFs
  * to access internal information useful for troubleshooting (/looking-glass/ URL sub-tree) 

### Publish/Subscribe design ###

The engine dispatching events related to BGP routes is designed with a publish/subscribe
pattern based on the principles in [RFC4684](http://tools.ietf.org/html/rfc4684). 
Workers (a worker can be a BGP peer or a local worker responsible for an IP VPN VRF) publish 
BGP VPN routes with specified Route Targets, and subscribe to the Route Targets that they need 
to receive. The engine takes care of propagating advertisement and withdrawal events between 
the workers, based on subscriptions and BGP semantics (e.g. no redistribution between BGP 
peers sessions).

### Best path selection ###

The core engine does not do any BGP best path selection. For routes received from external 
BGP peers, best path selection happens in the VRF workers. For routes that local workers 
advertise, no best path selection is done because two distinct workers will never advertise 
a route of same BGP NLRI.

### Multi-threading ###

For implementation convenience, the design choice was made to use Python native threads 
and python Queues to manage the API, local workers, and BGP peers workloads:

* the engine (RouteTableManager) is running as a single thread
* each local VPN worker has its own thread to process route events
* each BGP peer worker has two threads to process outgoing route events, and 
receive socket data, plus a few timers.
* VPN port attachement actions are done in the main thread handling initial 
setup and API calls, these calls are protected by Python locks

### Non-persistency of VPN and port attachements ###

The BaGPipe BGP daemon, as currently designed, does not persist information 
on VPNs (VRFs or EVIs) and the ports attached to them. On a restart, the 
component responsible triggering the attachement of interfaces to VPNs, can
detect the restart of the BGP daemon and re-trigger these attachements.

### BGP Implementation ###

The BGP protocol implementation extends an reuses BGP code from [ExaBGP](http://code.google.com/p/exabgp).
Information about what was modified in ExaBGP is in [README.exabgp](README.exabgp).
BaGPipe BGP only reuses the low-level Connection and Protocol classes, with additions to 
encode and decode NLRI and attribute specific to BGP VPN extensions. 

Non-goals for this BGP implementation:

* full-fledged BGP implementation
* redistribution of routes between BGP peers (hence, no route reflection, no eBGP)
* accepting incoming BGP connections
* scaling to a number of routes beyond the number of routes required to route
  traffic in/out of VMs hosted on a server running BaGPipe

### Dataplanes ###

BaGPIpe BGP was designed to allow for a modular dataplane implementation.
For each type of VPN (IP VPN, E-VPN) a dataplane driver is chosen through configuration.
A dataplane driver is responsible for setting up forwarding state for incoming and
outgoing traffic based on port attachement information and BGP routes.

(see [Dataplane driver configuration](#dpconfig))

<a name="caveats"></a>
Caveats 
-------

* release early, release often: not everything is perfect yet
* BGP implementation not written for compliancy
  * the BaGPipe BGP daemon does not listen for incoming BGP connections
  * the state machine, in particular retry timers are certainly not compliant yet
  * however, interop testing has been done with a fair amount of implementations
* MPLS-over-GRE is supported for IP VPNs, but is not yet standard
  (OpenVSwitch currently does MPLS-o-Ethernet-o-GRE and not MPLS-o-GRE)

Unit Tests
----------

Unit tests can be run with:

        nosetests

A report of unit tests coverage can be produced with:

        nosetests --with-coverage --cover-package=bagpipe.bgp --cover-html 

License
-------

Apache 2.0 license (except additions and modifications to ExaBGP, licensed as 3-Clause BSD license).

See [LICENSE](LICENSE) file.
