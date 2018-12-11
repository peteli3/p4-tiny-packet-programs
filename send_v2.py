#!/usr/bin/env python
import argparse
import json
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, Raw
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

FIXED_MEM_SLOTS = 20

INSTR_MAP = {
    "PUSH"  : 0b000,
    "LOAD"  : 0b001,
    "POP"   : 0b010,
    "STORE" : 0b011,
    "CEXEC" : 0b100,
    "CSTORE": 0b101,
    "CMPEXEC": 0b110
}

REGISTER_MAP = {
    "Switch:SwitchID"        : 0b00000,
    "Switch:L2Counter"       : 0b00001,
    "Switch:L3Counter"       : 0b00010,
    "Switch:FlowTableVerNum" : 0b00011,
    "Switch:Timestamp"       : 0b00100,
    "Port:LinkUtilization"   : 0b01000,
    "Port:BytesReceived"     : 0b01001,
    "Port:BytesDropped"      : 0b01010,
    "Port:BytesEnqueued"     : 0b01011,
    "Queue:BytesEnqueued"    : 0b10000,
    "Queue:BytesDropped"     : 0b10001,
    "Packet:InputPort"       : 0b11001,
    "Packet:OutputPort"      : 0b11010,
    "Packet:Queue"           : 0b11011,
    "Packet:MatchedFlowEntry": 0b11100,
    "Packet:AltRoutes"       : 0b11101,
}


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
        mem_sp=len(initial_memory)-1,
        mem_hop_len=4,
        tpp_checksum=64578677,
        insns_valid=1,
        num_insns=len(insns)
    )

    # do exactly the # of instructions given
    for i, opcode in enumerate(insns):
        pkt = pkt / TPPInsn(
            bos=0 if i < len(insns) - 1 else 1,
            insn=opcode,
        )

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
        print('usage: send.py <filename of JSON formatted data>')
        exit(1)

    with open(sys.argv[1]) as f:
        json_data = json.load(f)

    # Get all instructions as a list of lists
    insns = [convert_tpp_instr(instr) for instr in json_data["instructions"]]
    assert len(insns) <= 5

    # CONFIG tpp starting mem here, use hex! e.g. 0x433452351ab2
    # stored exactly how you read it here (growing downward)
    initial_memory = [convert_numeric_val(val) for val in json_data["initial_mem"]]
    assert len(initial_memory) <= FIXED_MEM_SLOTS

    iface = get_if()
    addr = socket.gethostbyname(json_data["ethernetDstAddr"])

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

def convert_tpp_instr(instr):
    """
    Converts an instruction from texual form to encoded form.

    :arg instr: list of instruction terms, e.g. ["PUSH", "Packet:Queue"]
    """
    assert instr[0] in INSTR_MAP

    encoded_instr = INSTR_MAP[instr[0]]

    if instr[0] == "PUSH":
        from_register = instr[1]
        if from_register in REGISTER_MAP:
            from_register = REGISTER_MAP[from_register]
        else:
            from_register = convert_numeric_val(from_register)

        encoded_instr = (encoded_instr << 28) | (from_register << 20)
    
    elif instr[0] == "LOAD":
        from_register, to_loc = instr[1], convert_numeric_val(instr[2])
        if from_register in REGISTER_MAP:
            from_register = REGISTER_MAP[from_register]
        else:
            from_register = convert_numeric_val(from_register)

        encoded_instr = (encoded_instr << 28) | (from_register << 20) | (to_loc << 12)

    elif instr[0] == "POP":
        to_register = instr[1]
        if to_register in REGISTER_MAP:
            to_register = REGISTER_MAP[to_register]
        else:
            to_register = convert_numeric_val(to_register)

        encoded_instr = (encoded_instr << 28) | (to_register << 20)

    elif instr[0] == "STORE":
        to_register, from_loc = instr[1], convert_numeric_val(instr[2])
        if to_register in REGISTER_MAP:
            to_register = REGISTER_MAP[to_register]
        else:
            to_register = convert_numeric_val(to_register)

        encoded_instr = (encoded_instr << 28) | (to_register << 20) | (from_loc << 12)

    elif instr[0] == "CEXEC":
        register, loc = instr[1], convert_numeric_val(instr[2])
        if register in REGISTER_MAP:
            register = REGISTER_MAP[register]
        else:
            register = convert_numeric_val(register)

        encoded_instr = (encoded_instr << 28) | (register << 20) | (loc << 12)
    
    elif instr[0] == "CSTORE":
        register, old_loc, new_loc = instr[1], convert_numeric_val(instr[2]), convert_numeric_val(instr[3])
        if register in REGISTER_MAP:
            register = REGISTER_MAP[register]
        else:
            register = convert_numeric_val(register)

        encoded_instr = (encoded_instr << 28) | (register << 20) | (old_loc << 12) | (new_loc << 4)

    else:
        raise ValueError("Unrecognized instruction")

    return encoded_instr

def convert_numeric_val(numeric_val):
    """
    Converts a number into an int decimal representation, regardless
    of whether it is already an int or a string representing a hex
    or binary value.

    :arg numeric_val: an int or a string of a hex or binary value
                      (e.g. "0x123" or "0b101")
    """
    if type(numeric_val) is int:
        return numeric_val
    elif numeric_val[1] == "x":
        return int(numeric_val, 16)
    else:
        return int(numeric_val, 2)

if __name__ == '__main__':
    main()
