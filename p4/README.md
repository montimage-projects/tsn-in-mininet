# Installation

## Mininet

- [Documentation](https://mininet.org/download/)

```bash
sudo apt-get install mininet
```

## P4 compiler

- [Documentation](https://github.com/p4lang/p4c?tab=readme-ov-file#installing-packaged-versions-of-p4c)

```bash
source /etc/lsb-release
echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${DISTRIB_RELEASE}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
curl -fsSL https://download.opensuse.org/repositories/home:p4lang/xUbuntu_${DISTRIB_RELEASE}/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null
sudo apt-get update
sudo apt install p4lang-p4c
```

## BMv2


- To get a better performance, BMv2 needs to be compiled and installed from its source code. See a tuto [here](https://github.com/p4lang/behavioral-model/blob/main/docs/performance.md#suggested-setup-to-run-the-benchmark-consistently)

```bash
git clone https://github.com/p4lang/behavioral-model.git bmv2
cd bmv2
# the moment I patched BMv2
git checkout 199af48
# apply the patch
git am ../behavioral-model.patch
# compile
./install_deps.sh
./autogen.sh
./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger
make -j
sudo make install
```

## Run

```bash
make clean
make
```

## Tested environment

The test was done in a laptop Dell Precision 3570.

```bash
$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 20.04.6 LTS
Release:	20.04
Codename:	focal

$ uname -a
Linux montimage-Precision-3570 5.15.0-105-generic #115~20.04.1-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
montimage@montimage-Precision-3570:~/hn/tsn-in-mininet/p4$ mn --version
2.3.0.dev6

$ p4c --version
p4c 1.2.4.2 (SHA: 624c6be80 BUILD: RELEASE)

$ /home/montimage/hn/behavioral-model/targets/simple_switch/.libs/simple_switch  --version
1.15.0-199af48e
montimage@montimage-Precision-3570:~/hn/tsn-in-mininet/p4$ python3 --version
Python 3.8.10
```