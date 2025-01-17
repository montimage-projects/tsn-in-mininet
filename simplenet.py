from mininet.net import Mininet
from mininet.node import OVSController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

def simpleNetwork():
    # Set log level to 'info' to get helpful information on the console
    setLogLevel('info')

    # Create an empty network
    net = Mininet(controller=OVSController, link=TCLink)

    # Add the controller
    info('*** Adding controller\n')
    net.addController('c0')

    # Add hosts
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')

    # Add a switch
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')

    # Create links between the hosts and the switch
    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    # Start the network
    info('*** Starting network\n')
    net.start()

    # Test connectivity
    info('*** Testing connectivity\n')
    net.pingAll()

    # Run iperf3 server on host h2
    info('*** Starting iperf3 server on h2\n')
    h2.cmd('iperf3 -s &')  # Start iperf3 server in the background

    # Run iperf3 client on host h1
    info('*** Running iperf3 client on h1\n')
    result = h1.cmd('iperf3 -c 10.0.0.2 -t 10')  # Run iperf3 client

    # Print iperf3 results
    info('*** iperf3 test result:\n')
    info(result)

    # Open Mininet CLI for manual interaction if needed
    CLI(net)

    # Stop the network
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    simpleNetwork()
