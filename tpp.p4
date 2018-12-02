
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
            hdr.tpp_insns[0].insn: exact;
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
    action push_to_pkt() {
        // push logic here
        switch_reg.write(hdr.tpp_header.mem_sp, (bit<32>) 420);
    }

    action load_to_pkt() {

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
            push_to_pkt;
            load_to_pkt;
            move_value_from_pkt;
            cexec;
            cstore;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }
    // USE ABOVE AS TABLE TEMPLATE

    action read_tpp_memory() {
        switch_reg.write(0, (bit<32>) hdr.tpp_mem[0].value);
        switch_reg.write(1, (bit<32>) hdr.tpp_mem[1].value);
        switch_reg.write(2, (bit<32>) hdr.tpp_mem[2].value);
        switch_reg.write(3, (bit<32>) hdr.tpp_mem[3].value);
        switch_reg.write(4, (bit<32>) hdr.tpp_mem[4].value);
        switch_reg.write(5, (bit<32>) hdr.tpp_mem[5].value);
        switch_reg.write(6, (bit<32>) hdr.tpp_mem[6].value);
        switch_reg.write(7, (bit<32>) hdr.tpp_mem[7].value);
        switch_reg.write(8, (bit<32>) hdr.tpp_mem[8].value);
        switch_reg.write(9, (bit<32>) hdr.tpp_mem[9].value);
        switch_reg.write(10, (bit<32>) hdr.tpp_mem[10].value);
        switch_reg.write(11, (bit<32>) hdr.tpp_mem[11].value);
        switch_reg.write(12, (bit<32>) hdr.tpp_mem[12].value);
        switch_reg.write(13, (bit<32>) hdr.tpp_mem[13].value);
        switch_reg.write(14, (bit<32>) hdr.tpp_mem[14].value);
        switch_reg.write(15, (bit<32>) hdr.tpp_mem[15].value);
        switch_reg.write(16, (bit<32>) hdr.tpp_mem[16].value);
        switch_reg.write(17, (bit<32>) hdr.tpp_mem[17].value);
        switch_reg.write(18, (bit<32>) hdr.tpp_mem[18].value);
        switch_reg.write(19, (bit<32>) hdr.tpp_mem[19].value);
        switch_reg.write(20, (bit<32>) hdr.tpp_mem[20].value);
    }

    action write_tpp_memory() {
        bit<32> to_write;
        switch_reg.read(to_write, 9);
        hdr.tpp_mem[9].value = (bit<31>) to_write;
    }

    apply {
        
        if (hdr.tpp_header.isValid()) {
            
            debug.apply();
            read_tpp_memory();

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
            write_tpp_memory();
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
