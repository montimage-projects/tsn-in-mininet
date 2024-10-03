#!/usr/bin/python3

# 
#
#
# https://duerrfk.github.io/posts/2019/04/10/software_tsn_switch.html


from mininet.net import Mininet
from mininet.node import Node, Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, TCLink
from mininet.util import custom



def topology():
    net = Mininet(controller = Controller)
    #net = Mininet(controller=RemoteController)

    #info( '*** Adding controller\n' )
    net.addController( 'c0' )
    
    # Instantiate network members
    h1 = net.addHost('h1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02')
    s1 = net.addSwitch('s1')

    # Create topology links
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # Start the network
    net.start()

    
    # class 0: traffic from h1
    s1.cmd('iptables -t mangle -A POSTROUTING -p udp --dport 6666 -j CLASSIFY --set-class 0:1')
    s1.cmd('iptables -t mangle -A POSTROUTING -p udp --dport 7777 -j CLASSIFY --set-class 0:0')

    # Change queueing policy
    s1.cmd('tc qdisc replace dev s1-eth2 parent root handle 100 taprio \
        num_tc 2 \
        map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
        queues 1@0 1@1 \
        base-time 1554445635681310809 \
        sched-entry S 01 800000 \
        sched-entry S 02 200000 \
        clockid CLOCK_TAI')

    #CLI(net)
    
    # Test connectivity between hosts
    print(h1.cmd( 'ping -c1', h2.IP() ))
    
    # run processes of h1 in background
    h2.cmd('iperf3 --server --daemon --one-off --port 6666')
    h2.cmd('iperf3 --server --daemon --one-off --port 7777')
    h2.popen('tcpdump -udp -w /home/mmt/share_vbox/h2.pcap')
    
    # run first iperf3 in background
    h1.popen(f"iperf3 -c { h2.IP() } -u -b 1000K -p 6666 -t 5")
    h1.cmd(  f'iperf3 -c { h2.IP() } -u -b 1000K -p 7777 -t 5')

    #CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel( 'debug' )
    topology()