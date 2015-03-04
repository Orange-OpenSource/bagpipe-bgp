Examples
========

Each example script is executed as 

    <script> <server1> <server2>

where each of server1 and server2 are linux boxes or VMs with bagpipe-bgp 
installed and ssh access setup with public key authentication.

Proposed examples:

* basic: does a VPN with two netns endpoints and a ping, for both IPVPN 
  and E-VPN 
* chain-example1: does a destination-based IP service chain between two VMs 
  in two networks
* chain-example2: does a destination-based IP service chain between two VMs 
  in two networks (variant)

