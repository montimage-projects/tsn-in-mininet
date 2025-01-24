all:
	rm -rf logs
	mkdir logs
	sudo python3 main.py --topo-file ./topos/3-virtuals.json --enter-cli

clean:
	sudo mn -c
	rm topos/*.pdf
	sudo rm -rf pcaps logs __pycache__
	
draw:
	python3 ../plot.py --log-file logs/ptp4l.slave.log

	
%.pdf: %.json
	rm -rf logs
	mkdir logs
	
	ssh pi@10.42.0.110 "nohup bash -c 'sudo timeout -- 200 /usr/local/sbin/ptp4l -i enxb827ebcf092b -f /home/pi/configs/slave.cfg' > /tmp/ptp.slave.txt 2>&1 &"
	
	sudo python3 main.py --topo-file $<
	
	ssh pi@10.42.0.110 "sudo killall ptp4l"
	scp pi@10.42.0.110:/tmp/ptp.slave.txt logs/ptp4l.slave.log
	
	python3 ../plot.py --log-file logs/ptp4l.slave.log --output-file $@

test: topos/1-switch.pdf topos/10-switches.pdf