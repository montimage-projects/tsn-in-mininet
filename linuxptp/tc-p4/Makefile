P4C = p4c-bm2-ss
P4C_ARGS += --p4runtime-files $(basename $@).p4.p4info.txt
P4C_ARGS += --emit-externs

#export BMV2_SWITCH_EXE=/home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch

%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<
	
all: tc.json
	rm -rf logs
	mkdir logs
	sudo python3 main.py --topo-file ./topos/3-virtuals.json --enter-cli
	#sudo python3 main.py --topo-file ./topos/10-switches.json --enter-cli

clean:
	sudo mn -c
	rm tc.p4.p4info.txt tc.json topos/*.pdf
	sudo rm -rf pcaps logs __pycache__

	
draw:
	python3 ../plot.py --log-file logs/ptp4l.slave.log


%.pdf: %.json tc.json
	#rm -rf logs
	mkdir -p logs
	
	# ensure time sync is disable
	ssh pi@10.42.0.110 "sudo timedatectl set-ntp 0" || true
	ssh pi@10.42.0.110 "sudo killall ptp4l" || true
	ssh pi@10.42.0.110 "nohup bash -c 'sudo timeout -- 350 /usr/local/sbin/ptp4l -i enxb827ebcf092b -f /home/pi/configs/slave.cfg' > /tmp/ptp.slave.txt 2>&1 &"
	
	sudo python3 main.py --topo-file $<
	
	scp pi@10.42.0.110:/tmp/ptp.slave.txt $<.slave.log
	
	python3 ../plot.py --log-file $<.slave.log --output-file $@
	cd topos && python3 plot-all.py

test: topos/1-switch.pdf topos/2-switches.pdf topos/5-switches.pdf topos/10-switches.pdf  topos/20-switches.pdf

test-1-switch: topos/1-switch.pdf


test-10-switches: tc.json
	#rm -rf logs
	mkdir -p logs
	# ensure time sync is disable
	ssh pi@10.42.0.110 "sudo timedatectl set-ntp 0" || true
	ssh pi@10.42.0.110 "sudo killall ptp4l" || true
	ssh pi@10.42.0.110 "nohup bash -c 'sudo /usr/local/sbin/ptp4l -i enxb827ebcf092b -f /home/pi/configs/slave.cfg' > /tmp/ptp.slave.txt 2>&1 &"
	
	sudo python3 main.py --topo-file ./topos/10-switches.json --enter-cli
