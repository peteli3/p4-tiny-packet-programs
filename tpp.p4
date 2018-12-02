
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

    // use this!
    register<bit<32>>(50) switch_reg;

    // these are one-time use only!
    bit<4> cur_insn_opcode;
    // each of these instruction operands are 8 bits to satisfy p4c!
    bit<8> cur_insn_rd;
    bit<8> cur_insn_rs1;
    bit<8> cur_insn_rs2;
    bool cexec_stop;

    action drop() {
        mark_to_drop();
    }

    action parse_tpp_insn(bit<8> insn_index) {
        bit<31> insn = hdr.tpp_insns[insn_index].insn;
        cur_insn_opcode = (bit<4>) insn[30:28];
        cur_insn_rd = insn[27:20];
        cur_insn_rs1 = insn[19:12];
        cur_insn_rs2 = insn[11:4];
        // last 3 bits are dont-cares
    }

    action clear_tpp_insn_registers() {
        cur_insn_opcode = 0;
        cur_insn_rd = 0;
        cur_insn_rs1 = 0;
        cur_insn_rs2 = 0;
    }

    // push: use pkt_location = pkt.tpp_header.mem_sp
    // load: use pkt_location = rs1
    action move_value_to_pkt() {
        if (cur_insn_opcode == TPP_PUSH) {
            // push logic here
            hdr.tpp_mem[10].value = 420;

        } else if (cur_insn_opcode == TPP_LOAD) {
            // load logic here
            hdr.tpp_mem[11].value = 500;
        }
    }

    action move_value_from_pkt() {
        if (cur_insn_opcode == TPP_POP) {
            // pop logic here
            hdr.tpp_mem[8].value = 6969;

        } else if (cur_insn_opcode == TPP_STORE) {
            // store logic here
            hdr.tpp_mem[9].value = 7826359;
        }
    }

    action cexec() {
        // cexec logic here
        drop();
    }

    action cstore() {
        // cstore logic here
        drop();
    }

    // USE THIS AS TABLE TEMPLATE for multiple insns!
    table tpp_insn_action {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            move_value_to_pkt;
            move_value_from_pkt;
            cexec;
            cstore;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }
    // USE ABOVE AS TABLE TEMPLATE

    apply {
        
        if (hdr.tpp_header.isValid()) {
            
            debug.apply();

            // only run first 5 insns
            if (hdr.tpp_insns[0].isValid()) {
                parse_tpp_insn((bit<8>) 0);
                tpp_insn_action.apply();
                clear_tpp_insn_registers();
            }

            // TODO to enable these: make a separate table for each
            // THEN!! populate the tpp-runtime.json with same rules!
            /* 
            if (hdr.tpp_insns[1].isValid()) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action1.apply();
                clear_tpp_insn_registers();
            }
            
            
            if (hdr.tpp_insns[2].isValid()) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action2.apply();
                clear_tpp_insn_registers();
            }

            if (hdr.tpp_insns[3].isValid()) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action3.apply();
                clear_tpp_insn_registers();
            }

            if (hdr.tpp_insns[4].isValid()) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action4.apply();
                clear_tpp_insn_registers();
            }
            */
        }
    }

}

control TPPEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    apply {}

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
