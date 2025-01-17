
BMV2_SWITCH_EXE = simple_switch_grpc
NO_P4 = true
P4C_ARGS = --p4runtime-file $(basename $@).p4info --p4runtime-format text

#build is not a file target, 
.PHONY: all
#default target
.DEFAULT_GOAL := all


clean:
	rm -rf basic.json basic.p4i
	# remove veth if existing
	sudo ip link del h1-eth || true
	sudo ip link del h2-eth || true

%.json: %.p4
	# compile P4 code
	p4c --target  bmv2  --arch  v1model $<

compile: basic.json

all: basic.json
	sudo python3 single_switch.p4.py
