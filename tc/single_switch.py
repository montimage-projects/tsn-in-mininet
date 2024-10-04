#!/usr/bin/python3

# Setup a simple TSN testbed using taprio qdisc. The testbed is emulated using mininet.
# It has 2 hosts connected via a bridge.
#    h1 <----> switch <-----> h2
# 
# TAPRIO is set at each output port of the switch.
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

# to plot statistic
from scapy.all import rdpcap, UDP
import matplotlib.pyplot as plt
# avoid showing plot window
import matplotlib as mpl
mpl.use('Agg')

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
    
    # Use iptables to set priority of packet skb based on packet's destination port
    # "--set-class" might sound confusing as it actually set priority of the packet
    # 
    # We have 2 classes of priorities:
    #  - class/priority 0 (0:0): UDP packets having dst port = 7777
    #  - class/priority 1 (0:1): UDP packets having dst port = 6666
    switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 6666 -j CLASSIFY --set-class 0:1')
    switch.cmdPrint('iptables -t mangle -A POSTROUTING -p udp --dport 7777 -j CLASSIFY --set-class 0:0')

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
            sched-entry S 01 80000000 \
            sched-entry S 02 20000000 \
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
    
    #switch.cmd('timeout 60 tcpdump -i s1-veth1 -w switch.pcap --time-stamp-precision=nano udp &')
    
    # run first iperf3 in background
    h1.cmd("iperf3 -c %s --udp --length 100 -p 6666 -t 1 &" % h2.IP())
    h1.cmd('iperf3 -c %s --udp --length 100 -p 7777 -t 1'   % h2.IP())

    #show statistic
    switch.cmdPrint('ifconfig -a')
    for intf in switch.intfs.values():
        switch.cmd('tc -s -d class show dev %s' % intf)


    # clean the network
    info( "*** Stopping network\n" )
    h2.cmdPrint('ls -lrat ')
    switch.cmd( 'ip link set dev br0 down' )
    switch.cmd( 'brctl delbr br0' )
    switch.deleteIntfs()

def plot_packet_arrival_times(pcap_file):
    # Read the PCAP file
    packets = rdpcap(pcap_file)
    
    # Dictionary to store the arrival times per UDP destination port
    port_arrival_times = {}

    first_time = 0
    RANGE = [500*1000000, 1000*1000000]
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
            
            offset = arrival_time - first_time
            if offset < RANGE[0]:
                continue
            if  offset > RANGE[1]:
                break;

            dst_port = pkt[UDP].dport

            # Add the arrival time to the list for the destination port
            if dst_port not in port_arrival_times:
                port_arrival_times[dst_port] = []
            port_arrival_times[dst_port].append(arrival_time)

    # Plotting
    plt.figure(figsize=(10, 6))
    
    # Create a colormap for the different ports
    ports = list(port_arrival_times.keys())
    colors = ["red", "blue"]
    
    # Assign a color for each port and plot its vertical lines
    for idx, port in enumerate(ports):
        times = port_arrival_times[port]
        color = colors[idx]  # Get the color from the colormap based on index
        plt.vlines(times, ymin=0, ymax=port, colors=color, alpha=0.6, label=f'Port {port}')

    # Formatting the plot
    plt.title('Packet Arrival Times by UDP Destination Port')
    plt.xlabel('Arrival Time (us)')
    plt.ylabel('UDP Destination Port')
    plt.legend(loc='upper right', bbox_to_anchor=(1.15, 1))
    plt.grid(True)
    plt.savefig( "single_switch.arrival_time.pdf", dpi=30, format='pdf', bbox_inches='tight')


if __name__ == '__main__':
    setLogLevel( 'debug' )

    Mininet.init()
    topology()

    plot_packet_arrival_times("h2.pcap")
    info( 'bye' )