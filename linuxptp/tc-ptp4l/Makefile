all:
	rm -rf logs
	mkdir logs
	sudo python3 main.py --topo-file ./topos/1-switch.json --enter-cli

clean:
	sudo mn -c

draw:
	python3 ../plot.py --log-file logs/ptp4l.slave.log

	
%.pdf: %.json
	rm -rf logs
	mkdir logs
	sudo python3 main.py --topo-file $<
	python3 ../plot.py --log-file logs/ptp4l.slave.log --output-file $@

test: topos/1-switch.pdf topos/10-switches.pdf