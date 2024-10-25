#build is not a file target, 
.PHONY: all
#default target
.DEFAULT_GOAL := all


clean:
	rm -rf basic.json basic.p4i *.pcap __pycache__

%.json: %.p4
	# compile P4 code
	p4c --target  bmv2  --arch  v1model $<

compile: basic.json

all: basic.json
	#a simple_switch which is disabled debug, output messages to increase performance
	sudo python3 topo.py --behavioral-exe /home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch
	# use default simple_switch
	#sudo python3 topo.py