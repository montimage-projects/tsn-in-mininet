all:
	rm -rf logs
	mkdir logs
	sudo python3 main.py

clean:
	sudo mn -c

draw:
	cat logs/ptp4l.slave.log | python plot/parse.py > ptp.dat
	gnuplot plot/gnu.plot
