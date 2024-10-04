#!/usr/bin/python3

# 
#
#
# https://duerrfk.github.io/posts/2019/04/10/software_tsn_switch.html


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

    info( "*** Enabling TSN network\n" )
    # class 0: traffic from h1
    switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 6666 -j CLASSIFY --set-class 0:1')
    switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 7777 -j CLASSIFY --set-class 0:0')

    for intf in switch.intfs.values():
        None
        # set number of TX queues to 2
        switch.cmd('ethtool -L %s tx 2' % intf)
        # Change queueing policy

        switch.cmdPrint('tc qdisc replace dev %s parent root handle 100 taprio \
            num_tc 2 \
            map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
            queues 1@0 1@1 \
            base-time 1 \
            sched-entry S 01 80000000 \
            sched-entry S 02 20000000 \
            clockid CLOCK_TAI' % intf)

    # enable forwarding
    switch.cmd('echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables')
    switch.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    
    # Test connectivity between hosts
    print(h1.cmd( 'ping -c1', h2.IP() ))
    
    # run processes of h1 in background
    h2.cmd('timeout 60 iperf3 --server --daemon --one-off --port 6666')
    h2.cmd('timeout 60 iperf3 --server --daemon --one-off --port 7777')
    #
    h2.cmd('timeout 60 tcpdump -w h2.pcap --time-stamp-precision=nano udp &')
    
    #switch.cmd('timeout 60 tcpdump -i s1-veth1 -w switch.pcap --time-stamp-precision=nano udp &')
    
    # run first iperf3 in background
    h1.cmd("iperf3 -c %s --udp --length 100 -p 6666 -t 1 &" % h2.IP())
    h1.cmd('iperf3 -c %s --udp --length 100 -p 7777 -t 1'   % h2.IP())

    #
    switch.cmdPrint('ifconfig -a')
    for intf in switch.intfs.values():
        switch.cmd('tc -s -d class show dev %s' % intf)

    info( "*** Stopping network\n" )
    h2.cmdPrint('ls -lrat ')
    switch.cmd( 'ip link set dev br0 down' )
    switch.cmd( 'brctl delbr br0' )
    switch.deleteIntfs()
    info( '\n' )


if __name__ == '__main__':
    setLogLevel( 'debug' )

    Mininet.init()
    topology()