# Installation

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
./install_deps.sh
./autogen.sh
./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger
make -j
# cd mininet
# python3 stress_test_ipv4.py
```