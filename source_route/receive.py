#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers, split_layers
from scapy.all import Packet
from scapy.all import IP, UDP, Raw, Ether
from scapy.fields import *

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class Hop(Packet):
    fields_desc = [ ShortField("portId", None) ]
    def extract_padding(self, p):
        return "", p

class Telemetry(Packet):
    fields_desc = [ ByteField("count", None),
                    IntField("maxBytes", None),
                    PacketListField("hops", [], Hop, count_from=lambda pkt:pkt.count) ]
    
bind_layers(UDP, Telemetry, dport=4321)
    
def handle_pkt(pkt):
    hexdump(pkt)
    pkt.show2()
    sys.stdout.flush()

def main():
    iface = get_if()
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
