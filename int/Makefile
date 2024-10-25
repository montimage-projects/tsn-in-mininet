
BMV2_SWITCH_EXE = simple_switch_grpc
BMV2_SWITCH_EXE=/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch

include ../utils/Makefile


run: build
	# override existing P4Switch class
	cp ./p4_mininet.py  ../utils
	
	# dump pcap files
	#sudo python3 ../utils/run_exercise.py -t $(TOPO) $(run_args)
	
	# without dumping pcap files
	sudo python3 ../utils/run_exercise.py -t $(TOPO) $(run_args) --pcap-dir=False