#!/usr/bin/python3

# Setup a simple Time synchronisation testbed using Linuxptp. The testbed is emulated using mininet.
# It has 2 hosts connected via a bridge.
#    h1 <----> switch <-----> h2
# 
# Switch is created using brctl command (sudo apt install bridge-utils) 
#
#
# Contact:
#   huunghia.nguyen@montimage.com
#
# References:
#   https://tsn.readthedocs.io/timesync.html

from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.link import Link

def topology():
    
    info( "*** Creating nodes\n" )
    switch = Node( 's1', inNamespace=True )
    h1 = Node( 'h1' )
    h2 = Node( 'h2' )

    info( "*** Creating links\n" )
    Link( h1, switch )
    Link( h2, switch )

    info( "*** Configuring hosts\n" )
    h1.setIP( '192.168.123.1/24' )
    h2.setIP( '192.168.123.2/24' )
    info( str( h1 ) + '\n' )
    info( str( h2 ) + '\n' )


    info( "*** Starting network\n" )

    #switch.cmd( 'brctl delbr br0' )
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

    
    # Test connectivity between hosts
    h1.cmdPrint( 'ping -c1', h2.IP() )
    h1.cmdPrint('ifconfig')
    h1.cmdPrint('ls -lrat')
   
    
    #-m: print messages to stdout.
    #-S: software time stamping
    #-E: end-to-end mechanism
    
    h1.cmd('ptp4l -E -i h1-eth0 -S -m  --step_threshold=1 &')
    
    #-s: slave only
    h2.cmd('ptp4l -E -i h2-eth0 -S -m  --step_threshold=1 -s &')
    
    #-G 5: Sets the duration of the capture to 5 seconds. 
    #     After 5 seconds, tcpdump will rotate to a new capture file.
    #-W 1: Limits the number of files to 1, which ensures that after 5 seconds, 
    #     tcpdump will stop instead of rotating to a new file.
    switch.cmd('tcpdump -w switch.pcap  --time-stamp-precision=nano -G 5 -W1 ')
    # clean the network
    info( "*** Stopping network\n" )
    h2.cmdPrint('ls -lrat ')
    switch.cmd( 'ip link set dev br0 down' )
    switch.cmd( 'brctl delbr br0' )
    switch.deleteIntfs()

if __name__ == '__main__':
    setLogLevel( 'debug' )

    Mininet.init()
    topology()

    info( 'bye' )