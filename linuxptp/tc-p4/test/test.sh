#!/bin/bash

function do_test(){
	cd ..
	pwd
	make clean
	make test
}

rm -rf topos-* *.pdf

for i in $(seq 1 10);
do
	date
	echo test $i
	
	(do_test)

	cp -r ../topos topos-$i

	date
	echo sleep 10 seconds
	sleep 10
	pwd
done

python3 plot-all-tests.py