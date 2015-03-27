import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # for the suppressing scapy warnings
from scapy.all import *
scan_dst = '212.20.34.177'
packet=IP(dst=scan_dst)/TCP(dport=[80,443,22],flags="S")
responded, unanswered = sr(packet, timeout=10, verbose=0) # verbose for silent packet sending
print "List of all open ports in "+scan_dst
for a in responded:
	if a[1][1].flags==18:
		print a[1].sport