
/* -*- P4_16 -*- */



parser TPPParser(
    packet_in packet,
    inout metadata meta,
    inout headers hdrs
) {
    state start {
        transition select(hdrs.udp.dstPort) {
            PORT_TPP: parse_tpp;
            default: accept;
        }
    }

    state parse_tpp {
        packet.extract(hdrs.tpp_header);
        transition parse_tpp_insns;
    }

    state parse_tpp_insns {
        packet.extract(hdrs.tpp_insns.next);
        transition select(hdrs.tpp_insns.last.bos) {
            0: parse_tpp_insns;
            1: parse_tpp_memory;
        }
    }

    state parse_tpp_memory {
        packet.extract(hdrs.tpp_mem.next);
        transition select(hdrs.tpp_mem.last.bos) {
            0: parse_tpp_memory;
            1: accept;
        }
    }

}

control TPPIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    table debug {
        key = {
            hdr.tpp_header.tpp_len: exact;
            hdr.tpp_header.mem_len: exact;
            hdr.tpp_header.mem_mode: exact;
            hdr.tpp_header.mem_sp: exact;
            hdr.tpp_header.mem_hop_len: exact;
            hdr.tpp_header.tpp_checksum: exact;
            hdr.tpp_header.insns_valid: exact;
            hdr.tpp_header.num_insns: exact;
            hdr.tpp_insns[0].insn[30:28]: exact;
            hdr.tpp_insns[1].insn: exact;
            hdr.tpp_insns[2].insn: exact;
            hdr.tpp_insns[3].insn: exact;
            hdr.tpp_insns[4].insn: exact;
            hdr.tpp_mem[0].value: exact;
            hdr.tpp_mem[1].value: exact;
            hdr.tpp_mem[2].value: exact;
            hdr.tpp_mem[3].value: exact;
        }
        actions = {}
    }

    bit<28> cur_insn;
    bit<4>  cur_insn_opcode;

    action drop() {
        mark_to_drop();
    }

    // push: use pkt_location = pkt.tpp_header.mem_sp
    // load: use pkt_location = arg 2
    action move_value_to_pkt(bit<32> value, bit<32> pkt_location) {
        drop();
    }

    action move_value_from_pkt() {

    }

    table tpp_insn_action {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            move_value_to_pkt;
            drop; // testing only
            NoAction;
        }
        default_action = NoAction();
    }

    action apply_insn(bit<31> opcode) {
        bit<3> insn_encoding = opcode[30:28];
    }

    apply {
        
        if (hdr.tpp_header.isValid()) {
            // only run first 5 insns
            
            debug.apply();
            if (hdr.tpp_insns[0].isValid()) {
                cur_insn_opcode = (bit<4>) hdr.tpp_insns[0].insn[30:28];
                cur_insn = (bit<28>) hdr.tpp_insns[0].insn[27:0];
                tpp_insn_action.apply();
            }

            if (hdr.tpp_insns[1].isValid()) {
                apply_insn(hdr.tpp_insns[1].insn);
            }

            if (hdr.tpp_insns[2].isValid()) {
                apply_insn(hdr.tpp_insns[2].insn);
            }

            if (hdr.tpp_insns[3].isValid()) {
                apply_insn(hdr.tpp_insns[3].insn);
            }

            if (hdr.tpp_insns[4].isValid()) {
                apply_insn(hdr.tpp_insns[4].insn);
            }
        }
    }

}

control TPPEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    apply {

    }

}

control TPPDeparser(
    packet_out packet, 
    in headers hdr
) {
    apply {
        packet.emit(hdr.tpp_header);
        packet.emit(hdr.tpp_insns);
        packet.emit(hdr.tpp_mem);
    }
}
