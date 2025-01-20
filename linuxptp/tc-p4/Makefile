P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(basename $@).p4.p4info.txt
P4C_ARGS += --emit-externs

#export BMV2_SWITCH_EXE=/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<
	
all: tc.json
	rm -rf logs
	mkdir logs
	sudo python3 main.py

clean:
	sudo mn -c
	rm tc.p4.p4info.txt tc.json

draw:
	cat logs/ptp4l.slave.log | python ../plot/parse.py > ptp.dat
	gnuplot ../plot/gnu.plot

