#! /usr/bin/env python
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # for the suppressing scapy warnings
from scapy.all import *

scan_dst = raw_input('Enter target`s IP address: ')

packet=IP(dst=scan_dst)/TCP(dport=range(1,10),flags="S")
test  = sr1(IP(dst=scan_dst)/ICMP(), verbose=0)
responded, unanswered = sr(packet, timeout=10, verbose=0) # verbose for silent packet sending

if test.ttl < 65:
	print 'Remote host appears to be linux'
else:
	print 'Remote host appears to be windows'

print "List of all open ports in "+scan_dst
for a in responded:
	if a[1][1].flags==18:
		print a[1].sport