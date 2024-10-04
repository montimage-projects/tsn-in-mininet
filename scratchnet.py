#!/usr/bin/env python

"""
Build a simple network from scratch, using mininet primitives.
This is more complicated than using the higher-level classes,
but it exposes the configuration details and allows customization.

For most tasks, the higher-level API will be preferable.
"""

from time import sleep

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import Link
from mininet.log import setLogLevel, info
from mininet.cli import CLI


def scratchNet():
    "Create network from scratch using brctl."
    
    info( "*** Creating nodes\n" )
    switch = Node( 's0', inNamespace=True )
    h0 = Node( 'h0' )
    h1 = Node( 'h1' )

    info( "*** Creating links\n" )
    Link( h0, switch )
    Link( h1, switch )

    info( "*** Configuring hosts\n" )
    h0.setIP( '192.168.123.1/24' )
    h1.setIP( '192.168.123.2/24' )
    info( str( h0 ) + '\n' )
    info( str( h1 ) + '\n' )

    info( "*** Starting network\n" )

    switch.cmd( 'brctl delbr br0' )
    switch.cmd( 'brctl addbr br0' )
    for intf in switch.intfs.values():
        # put into promiscuous mode, so the switch will see all incoming packets
        switch.cmd( 'ip link set dev %s promisc on' % intf )
        # assign the interface to the switch
        switch.cmd( 'brctl addif br0 %s' % intf )
    
    # bring up the switch
    switch.cmd( 'ip link set dev br0 up' )
    switch.cmdPrint('brctl show br0')
    switch.cmdPrint('brctl showmacs br0')


    info( "*** Running test\n" )
    h0.cmdPrint( 'ping -c1 ' + h1.IP() )
    
    info( "*** Running iperf3\n" )
    h0.cmd('timeout 60 iperf3 --server --daemon --one-off --port 6666')
    h1.cmdPrint("iperf3 -c %s --udp --length 100 -p 6666 -t 3" % h0.IP())
    
    switch.cmdPrint('ifconfig')
    info( "*** Stopping network\n" )
    switch.cmd( 'ip link set dev br0 down' )
    switch.cmd( 'brctl delbr br0' )
    switch.deleteIntfs()
    info( '\n' )


if __name__ == '__main__':
    setLogLevel( 'debug' )
    info( '*** Scratch network demo (kernel datapath)\n' )

    Mininet.init()
    scratchNet()
    