# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from mininet.net import Mininet
from mininet.node import Switch, Host
from mininet.log import setLogLevel, info, error, debug
from mininet.moduledeps import pathCheck
from sys import exit
import os
import tempfile
import socket

SWITCH_START_TIMEOUT = 10 # second
setLogLevel( 'debug' )
print("*****Overriding P4Switch+P4Host*****")

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

    def __init__(self, name, sw_path = None, json_path = None,
                 thrift_port = None,
                 pcap_dump = False,
                 log_console = False,
                 verbose = False,
                 device_id = None,
                 enable_debugger = False,
                 cpu_affinity = "0-2", #linux CPU cores assigned to the switch
                 renice = -10, # linux priority of the switch process
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        assert(sw_path)
        assert(json_path)
        # make sure that the provided sw_path is valid
        pathCheck(sw_path)
        # make sure that the provided JSON file exists
        if not os.path.isfile(json_path):
            error("Invalid JSON file.\n")
            exit(1)
        self.sw_path = sw_path
        self.json_path = json_path
        self.verbose = verbose
        logfile = "/tmp/p4s.{}.log".format(self.name)
        self.output = open(logfile, 'w')
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.enable_debugger = enable_debugger
        self.log_console = log_console
        self.cpu_affinity = cpu_affinity
        self.renice = renice
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1
        self.nanomsg = "ipc:///tmp/bm-{}-log.ipc".format(self.device_id)

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """While the process is running (pid exists), we check if the Thrift
        server has been started. If the Thrift server is ready, we assume that
        the switch was started successfully. This is only reliable if the Thrift
        server is started at the end of the init process"""
        while True:
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(0.5)
                result = sock.connect_ex(("localhost", self.thrift_port))
            finally:
                sock.close()
            if result == 0:
                return  True

    def start(self, controllers):
        "Start up a new P4 switch"
        info("Starting P4 switch {}.\n".format(self.name))
        args = ["nice", "-n", str(self.renice), self.sw_path]
        for port, intf in self.intfs.items():
            if not intf.IP():
                args.extend(['-i', str(port) + "@" + intf.name])
        if self.pcap_dump:
            args.append("--pcap %s" % self.pcap_dump)
            # args.append("--useFiles")
        if self.thrift_port:
            args.extend(['--thrift-port', str(self.thrift_port)])
        if self.nanomsg:
            args.extend(['--nanolog', self.nanomsg])
        args.extend(['--device-id', str(self.device_id)])
        P4Switch.device_id += 1
        args.append(self.json_path)
        if self.enable_debugger:
            args.append("--debugger")
        if self.log_console:
            args.append("--log-console")
        logfile = "logs/p4s.{}.log".format(self.name)
        print(' '.join(args) + "\n")

        pid = None
        with tempfile.NamedTemporaryFile() as f:
            # self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
            self.cmd(' '.join(args) + ' >' + logfile + ' 2>&1 & echo $! >> ' + f.name)
            pid = int(f.read())
        debug("P4 switch {} PID is {}.\n".format(self.name, pid))
        if not self.check_switch_started(pid):
            error("P4 switch {} did not start correctly.\n".format(self.name))
            exit(1)
        info("P4 switch {} has been started.\n".format(self.name))
        
        #remember pid
        self.pid = pid

        #stick to a CPU
        # e.g., taskset -cp 0,4 9030
        #  will assign process pid = 9030 to CPU cores 0 and 4
        #self.cmd("taskset -cp %s %d" %( self.cpu_affinity, self.pid ))
        
        #change priority of the process
        # e.g., renice -n  -12 -p 9030
        #self.cmd("renice -n %d -p %d" % ( self.renice, self.pid ))
        #self.start_qdisk( controllers )

    "P4 virtual Switch using TAPRIO qdisc"
    def start_qdisk( self, controllers ):
        """Configure TAPRIO qdisc on each port of the switch
        """
        info("**Configuring QDISC for switch {}.\n".format(self.name))
        #for each connected port
        for port, intf in self.intfs.items():
            # ignore localhost
            if intf.name == "lo":
                info("Ignore localhost")
                continue

            # set number of TX queues to 2
            self.cmdPrint('ethtool -L %s tx 2' % intf.name)
            

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
        
    def stop(self):
        "Terminate P4 switch."
        self.output.flush()
        self.cmd('kill %d' % self.pid)
        self.cmd('wait')
        self.deleteIntfs()

    def attach(self, intf):
        "Connect a data port"
        assert(0)

    def detach(self, intf):
        "Disconnect a data port"
        assert(0)
