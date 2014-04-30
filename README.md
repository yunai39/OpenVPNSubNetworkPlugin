OpenVPNSubNetworkPlugin
=======================

A plugin to allow you to define sub network for user based an the certificate name

For now this plugin is in a test state. If you would like to give you opinion on it feel free to do so. 

Description
===========

This plugin is to allow openvpn to provide ip address to different kind of user. Usually you would use the default the client-conf-dir. But that mean that you will need to have every single user prepared before they actualy ever connect to the server.  With this plugin, configuration file are created on client connection. This way you do not have to plan before hand for every single user that will connect to the VPN. 

Principle
=========
There is a small configuration file:

    #10.0.2.0#^CAPC*#255.255.255.0#
    #10.0.1.0#^FRPC*#255.255.255.0#

So we have two subnet, 10.0.2.0/24 and 10.0.1.0/24 (you can go up to /16 netmask)
Every certificat where the common_name respect the regex will go to the related subnet

For the plugin to work, you will need:
- a subnet to cover every single sub-subnet
- Topology subnet
- client-config-directive
- No ifconfig-pool-persist

Installation
============
With gcc use the build to generate the simple.so:

    $ build simple
    
Copy the simple.so into a sub folder.
Then in the server.conf, add the following 

    # simple.so is the lib you created throught build
    # /etc/openvpn/clientConf/ is the folder where the configuratino will be generated, be-careful to have the right to edit them
    plugin /etc/openvpn/plugin/simple.so /etc/openvpn/plugin/plugin.conf /etc/openvpn/clientConf/

TODO
====
- Maybe add a default subnet
- Correct the Bug with why does the network info disappear (Weird behaviour might be related to my VM, but I cause segementation fault if I'm not careful enough)
- Handle error (Which for now is pretty much absent)

