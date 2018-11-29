#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

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

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

class Telemetry(Packet):
   fields_desc = [ BitField("count", 0, 8),
                   IntField("maxBytes", 0) ]
   
bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)
bind_layers(UDP, Telemetry, dport=4321)

def main():

    if len(sys.argv)<2:
        print 'usage: send.py <destination>'
        exit(1)
        
    iface = get_if()
    addr = socket.gethostbyname(sys.argv[1])

    while True:
        print
        s = str(raw_input('Type space separated port nums '
                          '(example: "2 3 2 2 1") or "q" to quit: '))
        if s == "q":
            break;
        print

        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
        i = 0
        for p in s.split(" "):
            try:
                pkt = pkt / SourceRoute(bos=0, port=int(p))
                i = i+1
            except ValueError:
                pass
        if pkt.haslayer(SourceRoute):
            pkt.getlayer(SourceRoute, i).bos = 1

        pkt = pkt / IP(dst=addr)
        pkt = pkt / UDP(sport=1234, dport=4321)
        pkt = pkt / Telemetry()
        hexdump(pkt)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)
    
if __name__ == '__main__':
    main()
