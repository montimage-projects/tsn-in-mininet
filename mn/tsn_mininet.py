from mininet.log import setLogLevel, info, error, debug

from p4_mininet import P4Switch, P4Host

"""
Host subclass that uses a VLAN tag for the default interface

Dependencies:
    This class depends on the "vlan" package
    $ sudo apt-get install vlan

Reference:
  https://github.com/mininet/mininet/blob/master/examples/vlanhost.py

"""
class TSNHost( P4Host ):
    "Host connected to VLAN interface"

    # pylint: disable=arguments-differ
    def config( self, vlan=100, **params ):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""

        r = super( TSNHost, self ).config( **params )
        info("Configuring VLAN for host {}.\n".format(self.name))
        
        intf = self.defaultIntf()
        
        return r


        # remove IP from default, "physical" interface
        self.cmd( 'ifconfig %s inet 0' % intf )
        # create VLAN interface
        self.cmd( 'vconfig add %s %d' % ( intf, vlan ) )
        # assign the host's IP to the VLAN interface
        self.cmd( 'ifconfig %s.%d inet %s' % ( intf, vlan, params['ip'] ) )
        # update the intf name and host's intf map
        newName = '%s.%d' % ( intf, vlan )
        # update the (Mininet) interface to refer to VLAN interface name
        intf.name = newName
        # add VLAN interface to host's name to intf map
        self.nameToIntf[ newName ] = intf

        return r
        
class TSNSwitch( P4Switch ):
    "P4 virtual Switch using TAPRIO qdisc"
    def start( self, controllers ):
        """Configure TAPRIO qdisc on each port of the switch
        """
        r = super( TSNSwitch, self ).start( controllers )
        info("Configuring QDISC for switch {}.\n".format(self.name))
        #for each connected port
        for port, intf in self.intfs.items():
            # ignore localhost
            if intf.name == "lo":
                info("Ignore localhost")
                continue

            # set number of TX queues to 2
            self.cmd('ethtool -L %s tx 2' % intf.name)
            

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
            
            self.cmdPrint('tc qdisc replace dev %s parent root handle 100 taprio \
                num_tc 2 \
                map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
                queues 1@0 1@1 \
                base-time 1 \
                sched-entry S 01 800000 \
                sched-entry S 02 200000 \
                clockid CLOCK_TAI' % intf.name)

            # limit egress speed by introducing a delay
            # not work
            #self.cmdPrint('tc qdisc add dev %s root netem delay 1ms' % intf.name)
        return r
