#!/bin/bash

# see https://duerrfk.github.io/posts/2019/04/10/software_tsn_switch.html


tc qdisc replace dev enp2s0f1 parent root handle 100 taprio \
num_tc 2 \
map 1 0 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \
queues 1@0 1@1 \
base-time 1554445635681310809 \
sched-entry S 01 800000 sched-entry S 02 200000 \
clockid CLOCK_TAI