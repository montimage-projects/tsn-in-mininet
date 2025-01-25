
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.link import Link
from mininet.cli import CLI

import time, json, argparse
from p4_mininet import P4Host, P4Switch


class ExerciseTopo(Topo):
    """
    The mininet topology class.
    """
    def __init__(self, topo_file, log_dir, **opts):
        Topo.__init__(self, **opts)
        
        self.popen_processes = []
        
        with open(topo_file, 'r') as f:
            topo = json.load(f)

        self.topo = topo

        hosts    = topo['hosts']
        switches = topo['switches']
        links    = self.parse_links(topo['links'])

        host_links = []
        switch_links = []

        # assumes host always comes first for host<-->switch links
        for link in links:
            if link['node1'][0] == 'h':
                host_links.append(link)
            else:
                switch_links.append(link)

        for sw, params in switches.items():
            if "config" in params:
                switchClass = P4Switch
            else:
                # add default switch
                switchClass = None

            self.addSwitch(sw, json_file="tc.json", log_dir=log_dir, cls=switchClass,
                **params )

        for link in host_links:
            host_name = link['node1']
            sw_name, sw_port = self.parse_switch_node(link['node2'])
            params = hosts[host_name]
            self.addHost(host_name, inNamespace=True, cls=P4Host, **params)
            self.addLink(host_name, sw_name,
                         delay=link['latency'], bw=link['bandwidth'],
                         port2=sw_port)

        for link in switch_links:
            sw1_name, sw1_port = self.parse_switch_node(link['node1'])
            sw2_name, sw2_port = self.parse_switch_node(link['node2'])
            self.addLink(sw1_name, sw2_name,
                        port1=sw1_port, port2=sw2_port,
                        delay=link['latency'], bw=link['bandwidth'])


    def parse_switch_node(self, node):
        assert(len(node.split('-')) == 2)
        sw_name, sw_port = node.split('-')
        try:
            sw_port = int(sw_port[1:])
        except:
            raise Exception('Invalid switch node in topology file: {}'.format(node))
        return sw_name, sw_port

    def parse_links(self, unparsed_links):
        """ Given a list of links descriptions of the form [node1, node2, latency, bandwidth]
            with the latency and bandwidth being optional, parses these descriptions
            into dictionaries and store them as self.links
        """
        links = []
        for link in unparsed_links:
            # make sure each link's endpoints are ordered alphabetically
            s, t, = link[0], link[1]
            
            if s > t:
                s,t = t,s

            link_dict = {'node1'   : s,
                        'node2'    : t,
                        'latency'  :'0ms',
                        'bandwidth':None
                        }
            if len(link) > 2:
                link_dict['latency'] = self.format_latency(link[2])
            if len(link) > 3:
                link_dict['bandwidth'] = link[3]

            if link_dict['node1'][0] == 'h':
                assert link_dict['node2'][0] == 's', 'Hosts should be connected to switches, not ' + str(link_dict['node2'])

            links.append(link_dict)
        return links

    def execute_command_on_node(self, host, command):
        info(f"  {host.name} is executing: {command}\n")
        proc = host.popen("bash", "-c", command)
        # remember its handle so that we can stop it when existing
        self.popen_processes.append( proc )

    def stop_popen_processes(self):
        for proc in self.popen_processes:
            proc.terminate()

    def program_switches(self, net):
        """ 
        Execute any commands provided in the topology.json file on each Mininet switch
        """
        switches = self.topo['switches']
        for sw_name, sw_dict in switches.items():
            sw = net.get(sw_name)
            if "commands" in sw_dict:
                for cmd in sw_dict["commands"]:
                    self.execute_command_on_node(sw, cmd)

    def program_hosts(self, net):
        """ 
        Execute any commands provided in the topology.json file on each Mininet host
        """
        hosts = self.topo['hosts']
        for host_name, host_info in list(hosts.items()):
            h = net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    self.execute_command_on_node(h, cmd)


if __name__ == '__main__':
    setLogLevel( 'debug' )
    setLogLevel( 'info' )

        # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Emulate a PTP time synchronsiation network using mininet.")
    parser.add_argument("--topo-file", help="Path to the JSON containing topology defintion.")
    parser.add_argument("--enter-cli", help="Whether enter in mininet CLI", action="store_true", default=False)
    
    args = parser.parse_args()

    topo = ExerciseTopo(log_dir="./logs", topo_file=args.topo_file)
    net = Mininet(topo=topo, controller=None)

    net.start()
    
    time.sleep(1)
    # some programming that must happen after the net has started
    topo.program_switches(net)
    topo.program_hosts(net)


    time.sleep(1)
    if args.enter_cli:
        CLI(net)
    else:
        info('sleep 180 sec, then exit\n')
        time.sleep(180)
    
    topo.stop_popen_processes()
    net.stop()
    info( 'bye\n' )