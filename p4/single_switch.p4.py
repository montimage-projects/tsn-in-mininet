#!/usr/bin/python3

# Setup a simple TSN testbed using taprio qdisc. The testbed is emulated using mininet.
# It has 2 hosts connected via a bridge.
#    h1 <----> switch <-----> h2
# 
# TAPRIO is set at each output port of the switch.
# Switch is created using brctl command (sudo apt install bridge-utils) 
#
#
# Contact:
#   huunghia.nguyen@montimage.com
#
# References:
#   https://duerrfk.github.io/posts/2019/04/10/software_tsn_switch.html
#   https://gist.github.com/jeez/bd3afeff081ba64a695008dd8215866f
#   https://tsn.readthedocs.io/qdiscs.html

from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.link import Link
import time

# to plot statistic
from scapy.all import rdpcap, UDP
import matplotlib.pyplot as plt
# avoid showing plot window
import matplotlib as mpl
mpl.use('Agg')

def topology():
    
    info( "*** Creating nodes\n" )
    switch = Node( 's1', inNamespace=False )
    h1 = Node( 'h1' )
    h2 = Node( 'h2' )

    info( "*** Creating links\n" )
    Link( h1, switch, intfName1="eth", intfName2="h1-eth" )
    Link( h2, switch, intfName1="eth", intfName2="h2-eth" )

    info( "*** Configuring hosts\n" )
    h1.setIP( '192.168.123.1/24' )
    h2.setIP( '192.168.123.2/24' )

    #configure host
    h1.setDefaultRoute("dev eth")
    h2.setDefaultRoute("dev eth")
    
    #disable offloading which may cause incorrect TCP checksum
    for off in ["rx", "tx", "sg", "gso"]:
        cmd = "ethtool --offload eth %s off" % off
        h1.cmd(cmd)
        h2.cmd(cmd)

    info( str( h1 ) + '\n' )
    info( str( h2 ) + '\n' )


    info( "*** Starting network\n" )

    #fixed MAC of in/out ports
    switch.setMAC("00:00:00:00:00:11", "h1-eth")
    switch.setMAC("00:00:00:00:00:22", "h2-eth")
    
    #bring lo up to be able to connect to thrift at localhost:9090
    #switch.cmdPrint("ip link set dev lo up")
    
    switch.cmdPrint("ifconfig")
    
    # debug
    #switch.cmd("simple_switch -i 1@h1-eth -i 2@h2-eth  --log-console --pcap=. basic.json &")
    #switch.cmd("simple_switch -i 1@h1-eth -i 2@h2-eth basic.json &")
    # no debug, optimally compiled
    switch.cmd("/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch -i 1@h1-eth -i 2@h2-eth basic.json &")
    # wait for the switch
    time.sleep(2)
    #switch.cmdPrint("telnet localhost 9090")
    #return
    
    # check the switch is online
    #switch.cmdPrint("lsof -i")


    info( "*** Enabling TSN network\n" )
    # Use iptables to set priority of packet skb based on packet's destination port
    # "--set-class" might sound confusing as it actually set priority of the packet
    # 
    # We have 2 classes of priorities:
    #  - class/priority 0 (0:0): UDP packets having dst port = 7777
    #  - class/priority 1 (0:1): UDP packets having dst port = 6666
    #
    # the outgoing packets will nerver be classified
    #  https://github.com/p4lang/behavioral-model/issues/965
    #switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 6666 -j CLASSIFY --set-class 0:1')
    #switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 7777 -j CLASSIFY --set-class 0:0')

    for intf in switch.intfs.values():
        None
        # set number of TX queues to 2
        switch.cmd('ethtool -L %s tx 2' % intf)
        
        
        # Change queueing policy
        #
        # "num_tc 2": there are 2 traffic classes
        #
        # "map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1": maps skb priorities 0..15 to a specified traffic class (TC)
        # - map priority 0 (first bit from the left) to TC1
        # - map priority 1 to TC0
        # - and priorities 2-15 to TC1 (16 mappings for 16 possible traffic classes).
        #
        # "queues 1@0 1@1": map traffic classes to TX queues of the network device.
        # Its values use the format count@offset
        # - map the firs traffic class (TC0) to 1 queue strating at offset 0 (first queue)
        # - map the second traffic class (TC1) to 1 queue starting at offset 1 (second queue)
        
        switch.cmdPrint('tc qdisc replace dev %s parent root handle 100 taprio \
            num_tc 2 \
            map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
            queues 1@0 1@1 \
            base-time 1 \
            sched-entry S 01 200000 \
            sched-entry S 02 800000 \
            clockid CLOCK_TAI' % intf)

    # enable packet forwarding
    switch.cmd('echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables')
    switch.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # Test connectivity between hosts
    print(h1.cmd( 'ping -c1', h2.IP() ))


    # run processes in background: start iperf3 server & tcpdump
    h2.cmd('timeout 60 iperf3 --server --daemon --one-off --port 6666')
    h2.cmd('timeout 60 iperf3 --server --daemon --one-off --port 7777')
    #
    h2.cmd('timeout 60 tcpdump -w h2.pcap --time-stamp-precision=nano udp &')
    h2.cmdPrint("ifconfig -a")
    # run first iperf3 in background
    # --bitrate 0: as fast as possible
    # --length 1460: send 1460 bytes on each packet
    h1.cmd("iperf3 -c %s --udp --length 16 --bitrate 0 -p 6666 -t 1 &" % h2.IP())
    h1.cmd('iperf3 -c %s --udp --length 16 --bitrate 0 -p 7777 -t 1'   % h2.IP())

    ##show statistic
    switch.cmdPrint('ifconfig -a')
    for intf in switch.intfs.values():
        switch.cmdPrint('tc -s -d qdisc show dev %s' % intf)

    ## clean the network
    info( "*** Stopping network\n" )
    switch.deleteIntfs()


def plot_packet_arrival_times(pcap_file):
    # Read the PCAP file
    packets = rdpcap(pcap_file)
    
    # Dictionary to store the arrival times per UDP destination port
    port_arrival_times = {}

    print("loading packets' timestamp ...")
    first_time = 0
    # range of 5 ms
    RANGE = [500*1000000, 505*1000000]
    # Iterate over the packets
    for pkt in packets:
        # Check if the packet has a UDP layer
        if UDP in pkt:
            # Extract the packet timestamp and destination port
            arrival_time = pkt.time # e.g., 1712073023.619379
            arrival_time = int( arrival_time * 1000000 * 1000) # in nanosecond
            
            # take into account only the packets arriving in RANGE
            if first_time == 0:
                first_time = arrival_time
            
            #use offset to plot
            offset = arrival_time - first_time
            
            # take into account only packets in RANGE
            if offset < RANGE[0]:
                continue
            if  offset > RANGE[1]:
                break;

            offset -= RANGE[0]

            dst_port = pkt[UDP].dport

            # Add the arrival time to the list for the destination port
            if dst_port not in port_arrival_times:
                port_arrival_times[dst_port] = []
            port_arrival_times[dst_port].append(offset)

    print("plotting ...")
    # Plotting
    plt.figure(figsize=(10, 6))
    
    # Create a colormap for the different ports
    colors = {7777: "red", 6666: "blue"}
    
    # Assign a color for each port and plot its vertical lines
    for port in port_arrival_times:
        times = port_arrival_times[port]
        color = colors[port]  # Get the color from the colormap based on index
        plt.vlines(times, ymin=0, ymax=1, colors=color, alpha=0.6, label=f'Port {port}')

    # Formatting the plot
    plt.title('Packet Arrival Times by UDP Destination Port')
    plt.xlabel('Arrival Time (us)')
    plt.ylabel('packet')
    plt.legend(loc='upper right', bbox_to_anchor=(1.15, 1))
    plt.grid(True)
    plt.savefig( "single_switch.arrival_time.png", dpi=30, format='png', bbox_inches='tight')


if __name__ == '__main__':
    setLogLevel( 'debug' )

    Mininet.init()
    topology()

    plot_packet_arrival_times("h2.pcap")
    info( 'bye' )