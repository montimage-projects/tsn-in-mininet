This folder contains a simple example of timesynch using Linuxptp. 

The network is emulated using Mininet. It consists of 3 switches in which we setup transparent clocks.
The network topology is as below:

```
master (h1) -- s1 ----- s2 ----- s3 -- (h2) slaver
```

The transparent clocks are implemented using P4

# Requirements

- mininet
- linuxptp

# Execution

run `make all`