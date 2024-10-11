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
	sudo python3 topo.py