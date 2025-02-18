This folder contains a simple example of timesynch using Linuxptp. 

The network is emulated using Mininet. It consists of n P4 switches in which we setup transparent clocks.
The network topology is as below:

```
PTP server (h1) -- s1 ----- s2 ----- ... --- sn -- (h2) PTP client
```

The transparent clocks are implemented using P4

# Requirements

- mininet
- linuxptp

# Execution

run `make all`

## Start Grafana GUI

```bash
docker run --network=host -d -p 3000:3000 --name=grafana --env GF_DASHBOARDS_MIN_REFRESH_INTERVAL=1s grafana/grafana-enterprise
```

## Start Collector

```bash
sudo python collector/collector.py --nic enp0s31f6
```