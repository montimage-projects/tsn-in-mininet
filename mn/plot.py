#!/usr/bin/python3

import datetime
# to plot statistic
from scapy.all import rdpcap, UDP
import matplotlib.pyplot as plt
# avoid showing plot window
import matplotlib as mpl
mpl.use('Agg')

def plot_packet_arrival_times(pcap_file):
    # Read the PCAP file
    packets = rdpcap(pcap_file)
    
    # Dictionary to store the arrival times per UDP destination port
    port_arrival_times = {}

    print(datetime.datetime.now(), "loading packets' timestamp ...")
    first_time = 0
    # range of 5 ms
    RANGE = [200*1000000, 205*1000000]
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
                break

            offset -= RANGE[0]

            dst_port = pkt[UDP].dport

            # Add the arrival time to the list for the destination port
            if dst_port not in port_arrival_times:
                port_arrival_times[dst_port] = []
            port_arrival_times[dst_port].append(offset)

    print(datetime.datetime.now(), "plotting ...")
    # Plotting
    plt.figure(figsize=(10, 6))
    
    # Create a colormap for the different ports
    colors = {7777: "red", 6666: "blue"}
    
    # Assign a color for each port and plot its vertical lines
    for port in port_arrival_times:
        times = port_arrival_times[port]
        color = colors[port]  # Get the color from the colormap based on index
        plt.vlines(times, ymin=0, ymax=1, colors=color, label=f'Port {port}')

    # Formatting the plot
    plt.title('Packet Arrival Times by UDP Destination Port')
    plt.xlabel('Arrival Time (ns)') # nanosecond
    plt.ylabel('packet')
    plt.legend(loc='upper right', bbox_to_anchor=(1.15, 1))
    plt.grid(True)
    plt.savefig( "single_switch.arrival_time.pdf", dpi=30, format='pdf', bbox_inches='tight')


if __name__ == '__main__':
    print(datetime.datetime.now(), 'plotting h2.pcap' )
    plot_packet_arrival_times("h2.pcap")
    print(datetime.datetime.now(), 'bye' )