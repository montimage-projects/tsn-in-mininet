from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from tsn_mininet import TSNSwitch, TSNHost

import argparse
from time import sleep

parser = argparse.ArgumentParser(description='Mininet demo of a TSN network')

parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                    type=str, action="store", required=False, default="simple_switch")
parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                    type=int, action="store", default=9090)
parser.add_argument('--num-hosts', help='Number of hosts to connect to switch',
                    type=int, action="store", default=3)
parser.add_argument('--json', help='Path to JSON config file',
                    type=str, action="store", required=False, default="basic.json")
parser.add_argument('--pcap-dump', help='Dump packets on interfaces to pcap files',
                    type=str, action="store", required=False, default=False)
parser.add_argument('--enable-debugger', help='Enable debugger (Please ensure debugger support is enabled in behavioral exe, as it is disabled by default)',
                    action="store_true", required=False, default=False)

args = parser.parse_args()

class SingleSwitchTopo(Topo):
    "Single switch connected to n (< 256) hosts."
    def __init__(self, sw_path, json_path, thrift_port, pcap_dump, enable_debugger, n, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1',
                                sw_path = sw_path,
                                json_path = json_path,
                                thrift_port = thrift_port,
                                pcap_dump = pcap_dump,
                                enable_debugger = enable_debugger)

        for h in range(n):
            index = h+1
            host = self.addHost('h%d' % index,
                                ip = "10.0.%d.10/24" % index,
                                mac = '00:00:00:00:00:%02x' %index)
            self.addLink(host, switch)

def main():
    num_hosts = args.num_hosts
    mode = args.mode

    topo = SingleSwitchTopo(args.behavioral_exe,
                            args.json,
                            args.thrift_port,
                            args.pcap_dump,
                            args.enable_debugger,
                            num_hosts)

    net = Mininet(topo = topo,
                  host = TSNHost,
                  switch = TSNSwitch,
                  controller = None)

    net.start()

    #print info of each host
    for n in range(num_hosts):
        h = net.get('h%d' % (n + 1))
        h.describe()

    #wait for BMv2
    sleep(1)

    sw_mac = ["00:00:00:00:00:%02x" % (n+1) for n in range(num_hosts)]
    sw_addr = ["10.0.%d.10" % (n+1) for n in range(num_hosts)]

    #setup route table
    switch = net.get("s1")
    for h in range(num_hosts):
        port = (h + 1)
        ip   = sw_addr[h]
        mac  = sw_mac[h]
        switch.cmdPrint("echo 'table_add ipv4_lpm ipv4_forward %s/24 => %s %d' | simple_switch_CLI" % 
            (ip, mac, port))

    # init ARP table on each host
    #  so that the host knows MAC of other hosts
    for n in range(num_hosts):
        h = net.get('h%d' % (n + 1))
        h.setDefaultRoute("dev eth0")
        for i in range(num_hosts):
            if n != i:
                h.setARP(sw_addr[i], sw_mac[i])


    info("Ready !")

    h1 = net.get('h1')
    h1.cmd('timeout 60 iperf3 --server --daemon --one-off --port 6666')
    h1.cmd('timeout 60 iperf3 --server --daemon --one-off --port 7777')
    #
    h1.cmd('timeout 60 tcpdump -w h2.pcap --time-stamp-precision=nano udp &')
    #h1.cmdPrint("ifconfig -a")
    
    h2 = net.get("h2")
    h3 = net.get("h3")
    # run first iperf3 in background
    # --bitrate 0: as fast as possible
    h2.cmd("iperf3 -c %s --udp --bitrate 0 -p 6666 -t 5 &" % h1.IP())
    h3.cmd('iperf3 -c %s --udp --bitrate 0 -p 7777 -t 5'   % h1.IP())

    
    ##show statistic
    #switch.cmdPrint('ifconfig -a')
    for intf in switch.intfs.values():
        switch.cmdPrint('tc -s -d qdisc show dev %s' % intf)
    
    #sleep(2)
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'debug' )
    main()