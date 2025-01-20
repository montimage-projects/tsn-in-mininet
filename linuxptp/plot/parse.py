# Vincent Jordan
# 2020.10.12
# Run with:
# journalctl -u ptp4l.service | grep "master offset" | python3 parse_ptp.py
import re
import fileinput
import sys
minKernelTime = 0;
maxKernelTime = 1000;
pattern = '^(.*)ptp4l\[(.+)\]: master offset\s+(-?[0-9]+) s([012]) freq\s+([+-]\d+) path delay\s+(-?\d+)$'
test_string = 'ptp4l[214733.206]: master offset     -28767 s0 freq  -25546 path delay    130743'
# Gnuplot data header
firstTime = 0
print('# time, offset, freq, pathDelay')
for line in fileinput.input():
    # Regex search
    res = re.search(pattern, line)
# if pattern was matched
    if res:
        # Capture result
        timeAndHost  = res.group(1)
        kernelTime   = res.group(2)
        masterOffset = res.group(3)
        state        = res.group(4)
        freq         = res.group(5)
        pathDelay    = res.group(6)

        #shift X to the first value
        if firstTime == 0:
            firstTime = float(kernelTime)
        kernelTime = float(kernelTime) - firstTime
         
        #if (state == '2') and (float(kernelTime) > minKernelTime) and (float(kernelTime) < maxKernelTime):
        print(kernelTime, masterOffset, freq, pathDelay)
