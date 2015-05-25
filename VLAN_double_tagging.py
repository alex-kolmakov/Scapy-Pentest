import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *
double_tagged = Ether(dst='ff:ff:ff:ff:ff:ff', src='00:01:02:03:04:05')/ \
                Dot1Q(vlan=1)/Dot1Q(vlan=10)/ \
                IP(dst='255.255.255.255', src='192.168.0.1')/ICMP()
sendp(double_tagged)