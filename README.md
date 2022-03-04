# pcap.c

#install pcap

sudo apt install libpcap-dev

#install bridgr-utils

sudo apt install bridge-utils

#compile

gcc device.c -lpcap -o device
