
from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error, debug
from sys import exit

from time import sleep
import os
import tempfile
import psutil
import subprocess

def check_listening_on_port(port):
    for c in psutil.net_connections(kind='inet'):
        if c.status == 'LISTEN' and c.laddr[1] == port:
            return True
    return False

def mkdir(newpath):
    if not os.path.exists(newpath):
        os.makedirs(newpath)
    return newpath


class P4Host(Host):
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

class P4Switch(Switch):
    """P4 virtual switch"""
    device_id = 0

    def __init__(self, name, 
                 json_file = "tc.json",
                 log_dir   = "./logs",
                 config    = "configs/s1.txt", # config file of the P4 switch
                 override_ports = {},
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        
        self.json_file   = json_file
        self.config_file = config
        self.log_dir     = log_dir
        
        self.device_id   = P4Switch.device_id
        self.thrift_port = 9090 + self.device_id
        
        #as we will modife override_ports latter 
        #  so we need to clone it to avoid propagating this modification to other switches
        self.override_ports = dict(override_ports)
        
        # increase this id for each P4 switch to obtain an unique ID
        P4Switch.device_id += 1
        
        # ensure this port is free
        if check_listening_on_port(self.thrift_port):
            error('%s cannot bind port %d because it is bound by another process\n' % (self.name, self.thrift_port))
            exit(1)

    @classmethod
    def setup(cls):
        pass

    def program_switch_cli(self):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """

        info('Configuring P4 switch %s with file %s\n' % (self.name, self.config_file))
        with open(self.config_file, 'r') as fin:
            cli_outfile = '%s/p4s.%s_cli_output.log'%(self.log_dir, self.name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen(['simple_switch_CLI', 
                    '--thrift-port', str(self.thrift_port)],
                    stdin=fin, stdout=fout)

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

    def check_switch_started(self, pid):
        """While the process is running (pid exists), we check if the Thrift
        server has been started. If the Thrift server is ready, we assume that
        the switch was started successfully. This is only reliable if the Thrift
        server is started at the end of the init process"""
        while True:
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            if check_listening_on_port(self.thrift_port):
                return True
            sleep(0.5)

    def start(self, controllers):
        """
        Configure the switch as a transparent clock
        """
        
        info("**Configuring transparent clock for switch {}.\n".format(self.name))

        self.config_intfs()
        
        bmv2_exec = "simple_switch"
        bmv2_exec = "/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch"
        if os.getenv("BMV2_SWITCH_EXE") is not None:
            bmv2_exec = os.getenv("BMV2_SWITCH_EXE")
            
        args = [bmv2_exec, self.json_file]
        args.append("--device-id %d"%( self.device_id ))
        # print log to console which will be then redirected to file
        args.append("--log-console")
        ## log level
        ## supported values  'trace', 'debug', 'info', 'warn', 'error', off';
        ## default is 'trace'
        args.append("--log-level debug") 
        # dump traffic to pcap files
        args.append("--pcap %s"%( mkdir("./pcaps") ))
        # TCP port to config the switch
        args.append("--thrift-port %d" %( self.thrift_port ))
        # log using IPC
        args.append("--nanolog ipc:///tmp/bm-%d-log.ipc"%( self.device_id ))

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
            args.append( "-i %s@%s" %(i, name ))


        logfile = "{}/p4s.{}.log".format( mkdir(self.log_dir), self.name)
        # start switch and obtain its pid
        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())

        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
            
        debug("PID of P4 switch {} PID is {}.\n".format(self.name, pid))

        # configure the routing tables
        self.program_switch_cli()

        #remember pid
        self.p4_pid = pid
        
    def stop(self):
        "Terminate P4 switch."
        self.cmd('kill %d' % self.p4_pid)
        self.cmd('wait')
        self.deleteIntfs()
