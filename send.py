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

FIXED_MEM_SLOTS = 12


class SourceRoute(Packet):
    fields_desc = [
        BitField("bos", 0, 1),
        BitField("port", 0, 15)
    ]


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


def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def compute_tpp_size(insns, memory=FIXED_MEM_SLOTS):
    """ returns tpp size in bytes

    :arg insns: is the # of instructions
    :arg memory: is the # of memory slots
    """

    insn_section_bytes = 4 * insns
    mem_section_bytes = 4 * memory

    return insn_section_bytes + mem_section_bytes


def build_tpp_packet(pkt, insns, initial_memory):

    bind_layers(UDP, TPPHeader, dport=0x6666)
    bind_layers(TPPHeader, TPPInsn, insns_valid=1)
    bind_layers(TPPInsn, TPPInsn, bos=0)
    bind_layers(TPPInsn, TPPMemory, bos=1)
    bind_layers(TPPMemory, TPPMemory, bos=0)

    pkt = pkt / TPPHeader(
        tpp_len=compute_tpp_size(len(insns)),
        mem_len=(4*FIXED_MEM_SLOTS),
        mem_mode=1,
        mem_sp=9,
        mem_hop_len=4,
        tpp_checksum=64578677,
        insns_valid=1,
        num_insns=len(insns)
    )

    # do exactly the # of instructions given
    for opcode in insns:
        pkt = pkt / TPPInsn(
            bos=0,
            insn=opcode,
        )
    pkt.getlayer(TPPInsn, len(insns)).bos = 1

    # initialize up to predefined fixed memory
    for i in range(FIXED_MEM_SLOTS):
        value_to_insert = 0
        if i < len(initial_memory):
            value_to_insert = initial_memory[i]

        pkt = pkt / TPPMemory(
            bos=0,
            value=value_to_insert
        )
    pkt.getlayer(TPPMemory, FIXED_MEM_SLOTS).bos = 1

    return pkt


def main():

    bind_layers(Ether, SourceRoute, type=0x1234)
    bind_layers(SourceRoute, SourceRoute, bos=0)
    bind_layers(SourceRoute, IP, bos=1)

    if len(sys.argv) < 2:
        print('usage: send.py <dst-addr>')
        print('-> no dst-addr found, defaulting to 10.0.2.2 (test topo h2)')
        sys.argv.append("10.0.2.2") # for testing
        # exit(1)

    # CONFIG tpp instruction seq, use binary! e.g. 0b110110101010
    insns = [
        0b0000000000010010000000011001101,
        0b0100000000010010000000011001101,
        0b0110000000010010000000011001101,
        0b1000000000010010000000011001101,
        0b1010000000010010000000011001101,
    ]
    assert len(insns) <= 5

    # CONFIG tpp starting mem here, use hex! e.g. 0x433452351ab2
    # stored exactly how you read it here (growing downward)
    initial_memory = [
        0,
        1,
        2,
        3,
        4,
        5,
        600,
        420,
        0x11111
    ]
    assert len(initial_memory) <= FIXED_MEM_SLOTS

    iface = get_if()
    addr = socket.gethostbyname(sys.argv[1])

    while True:
        print
        s = str(raw_input(
            'Type space separated port nums '
            '(example: "2 3 2 2 1") or "q" to quit: '
        ))
        if s == "q":
            break;
        print

        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
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
        pkt = pkt / UDP(sport=1234, dport=0x6666)
        pkt = build_tpp_packet(pkt, insns, initial_memory)

        hexdump(pkt)
        pkt.show2()
        sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
