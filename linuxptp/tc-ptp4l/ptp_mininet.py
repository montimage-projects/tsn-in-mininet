
from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error, debug
from sys import exit

import os
import tempfile

def mkdir(newpath):
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    return newpath

class PTPHost(Host):
    def config(self, **params):
        r = super(Host, self).config(**params)

        self.defaultIntf().rename("eth0")

        for off in ["rx", "tx", "sg"]:
            cmd = "/sbin/ethtool --offload eth0 %s off" % off
            self.cmd(cmd)

        # disable IPv6
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        self.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

        return r

    def describe(self):
        print("**********")
        print(self.name)
        print("default interface: %s\t%s\t%s" %(
            self.defaultIntf().name,
            self.defaultIntf().IP(),
            self.defaultIntf().MAC()
        ))
        print("**********")

class PTPSwitch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__(self, name, 
                 log_dir = "./logs",
                 config = "configs/E2E-TC.cfg", # config file of the transparent clock
                 override_ports = {},
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        
        #as we will modife override_ports latter 
        #  so we need to clone it to avoid propagating this modification to other switches
        self.override_ports = dict(override_ports)
        self.config_file = config
        self.log_dir     = log_dir

    @classmethod
    def setup(cls):
        pass

    def config_intfs(self ):
        info("**Configuring ports for switch {}.\n".format(self.name))
        #for each connected port
        for port, intf in self.intfs.items():
            # ignore localhost
            if intf.name == "lo":
                continue

            self.cmd("ifconfig {} 11.1.{}.{}".format(intf.name, self.device_id, port + 1))

            for off in ["rx", "tx", "sg"]:
                self.cmd("/sbin/ethtool --offload {} {} off".format(intf.name, off))

    def start(self, controllers):
        """
        Configure the switch as a transparent clock
        """
        
        info("**Configuring transparent clock for switch {}.\n".format(self.name))

        self.config_intfs()

        args = ["ptp4l", "-f", self.config_file]
        
        #for each connected port
        for port, intf in self.intfs.items():
            # ignore localhost
            if intf.name == "lo":
                info("Ignore localhost\n")
                continue
            # append to set of ports
            if port not in self.override_ports:
                self.override_ports[port] = intf.name

        for i in self.override_ports:
            name = self.override_ports[i]
            args.append( "-i %s" % name )

        logfile = "{}/ptp4l.{}.log".format(mkdir(self.log_dir), self.name)
        # start ptp4l and obtain its pid
        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())

        debug("PID of TC clock in switch {} PID is {}.\n".format(self.name, pid))

        #remember pid
        self.ptp_pid = pid
        
    def stop(self):
        "Terminate P4 switch."
        self.cmd('kill %d' % self.ptp_pid)
        self.cmd('wait')
        self.deleteIntfs()
