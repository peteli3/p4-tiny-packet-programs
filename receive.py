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

class TPPHeader(Packet):
    fields_desc = [ 
        BitField("tpp_len", 0, 32),
        BitField("mem_len", 0, 32),
        BitField("mem_mode", 0, 32),
        BitField("mem_sp", 0, 32),
        BitField("mem_hop_len", 0, 32),
        BitField("tpp_checksum", 0, 32),
        BitField("insns_valid", 0, 1),
        BitField("num_insns", 0, 7)
    ]

class TPPInsn(Packet):
    fields_desc = [ 
        BitField("bos", 0, 1),
        BitField("insn", 0, 31)
    ]

class TPPMemory(Packet):
    fields_desc = [ 
        BitField("bos", 0, 1),
        BitField("value", 0, 31)
    ]

bind_layers(UDP, TPPHeader, dport=0x6666)
bind_layers(TPPHeader, TPPInsn, insns_valid=1)
bind_layers(TPPInsn, TPPInsn, bos=0)
bind_layers(TPPInsn, TPPMemory, bos=1)
bind_layers(TPPMemory, TPPMemory, bos=0)

def handle_pkt(pkt):
    hexdump(pkt)
    pkt.show2()
    sys.stdout.flush()

def main():
    iface = get_if()
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter="udp and port 0x6666", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
