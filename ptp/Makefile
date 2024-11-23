
BMV2_SWITCH_EXE = simple_switch_grpc
BMV2_SWITCH_EXE=/home/mmt/hn/behavioral-model/targets/simple_switch/.libs/simple_switch
#BMV2_SWITCH_EXE=/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch

include ../utils/Makefile

run:
	# override existing P4Switch class
	cp ./p4_mininet.py  ../utils
	
	sudo python3 ../utils/run_exercise.py -t $(TOPO) $(run_args)
