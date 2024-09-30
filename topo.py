#!/usr/bin/python3
from mininet.net import Mininet
from mininet.node import Node,Controller, RemoteController, OVSKernelSwitch, UserSwitch, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink
from mininet.util import custom
from mininet.node import RemoteController


def topology():
    net = Mininet(controller = None)
    #net = Mininet(controller=RemoteController)

    # Instantiate network members
    h1 = net.addHost('h1',mac='00:00:00:00:00:01')
    h2 = net.addHost('h2',mac='00:00:00:00:00:02')
    h3 = net.addHost('h3',mac='00:00:00:00:00:03')
    h4 = net.addHost('h4',mac='00:00:00:00:00:04')
    s1 = net.addSwitch('s1')

    # Create topology links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)

    #net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    # Start the network
    net.start()

    # Instantiate QoS rules
    # As per documented in http://www.openvswitch.org//support/dist-docs/ovs-vswitchd.conf.db.5.txt -> noop queue is used so that tc can configure the queue without trouble
    '''
    s1.cmd('sudo ovs-vsctl -- \
            set port s1-eth4 qos=@newqos -- \
            --id=@newqos create qos type=linux-noop \
            other-config:min-rate=1 \
            queues:1=@q1 \
            queues:2=@q2 \
            queues:3=@q3 \
            queues:4=@q4 \
            queues:5=@q5 \
            queues:6=@q6 \
            queues:7=@q7 -- \
            --id=@q1 create queue other-config:min-rate=1 -- \
            --id=@q2 create queue other-config:min-rate=1 -- \
            --id=@q3 create queue other-config:min-rate=1 -- \
            --id=@q4 create queue other-config:min-rate=1 -- \
            --id=@q5 create queue other-config:min-rate=1 -- \
            --id=@q6 create queue other-config:min-rate=1 -- \
            --id=@q7 create queue other-config:min-rate=1')
    
    # Allowing L2/L3 switching
    s1.cmd('sudo ovs-ofctl add-flow s1 actions=output:normal')
    '''

    # https://duerrfk.github.io/posts/2019/04/10/software_tsn_switch.html
    '''
    # class 0: traffic from h1
    s1.cmd('iptables -t mangle -A POSTROUTING --mac-source {} -j CLASSIFY --set-class 0:0'.format( h1.MAC() ))
    # class 1: traffic from h2
    s1.cmd('iptables -t mangle -A POSTROUTING --mac-source {} -j CLASSIFY --set-class 0:1'.format( h2.MAC() ))

    # Change queueing policy
    s1.cmd('tc qdisc replace dev eth0 parent root handle 100 taprio \
        num_tc 2 \
        map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
        queues 1@0 1@1 \
        base-time 1554445635681310809 \
        sched-entry S 01 800000 \
        sched-entry S 02 200000 \
        clockid CLOCK_TAI')
    '''

    # Test connectivity between hosts
    print (h1.cmd( 'ping -c1', h4.IP() ))

    CLI(net)

    net.stop()


if __name__ == '__main__':
    # setLogLevel( 'info' )
    topology()