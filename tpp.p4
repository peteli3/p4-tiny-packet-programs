
/* -*- P4_16 -*- */

const bit<8> MAX_MEM_SLOTS = 50;

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

    register<bit<32>>(50) tpp_mem_reg;
    register<bit<32>>(50) switch_reg;

    // these are one-time use only!
    bit<4> cur_insn_opcode;
    // each of these instruction operands are 8 bits to satisfy p4c!
    bit<8> cur_insn_rd;
    bit<8> cur_insn_rs1;
    bit<8> cur_insn_rs2;
    bool cexec_stop = false; // needs to be reset after each entire TPP pkt!
    bool cstore = false; // needs to be reset after each cstore
    bit<32> num_sp_decs = 0;
    bit<32> just_popped = 0;
    bit<32> just_cstored = 0;

    table tpp_debug {
        key = {
            cur_insn_opcode: exact;
            cur_insn_rd: exact;
            cur_insn_rs1: exact;
            cur_insn_rs2: exact;
            cexec_stop: exact;
            cstore: exact;
            num_sp_decs: exact;
            just_popped: exact;
            just_cstored: exact;
        }
        actions = {}
    }

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
            hdr.tpp_mem[6].value: exact;
            hdr.tpp_mem[7].value: exact;
            hdr.tpp_mem[8].value: exact;
            hdr.tpp_mem[9].value: exact;
            hdr.tpp_mem[10].value: exact;
            hdr.tpp_mem[11].value: exact;
            hdr.tpp_mem[12].value: exact;
            hdr.tpp_mem[13].value: exact;
            hdr.tpp_mem[18].value: exact;
        }
        actions = {}
    }

    action drop() {
        mark_to_drop();
    }

    action parse_tpp_insn(bit<8> insn_index) {
        bit<31> insn = hdr.tpp_insns[insn_index].insn;
        cur_insn_opcode = (bit<4>) insn[30:28];
        cur_insn_rd = insn[27:20];
        cur_insn_rs1 = insn[19:12];
        cur_insn_rs2 = insn[11:4];
        // last 4 bits (insn[3:0]) are dont-cares FOR NOW
        // TODO: we can use last 4 bits for if-else insn!
    }

    action clear_tpp_insn_registers() {
        cur_insn_opcode = 0;
        cur_insn_rd = 0;
        cur_insn_rs1 = 0;
        cur_insn_rs2 = 0;
    }

    action tpp_push() {
        bit<32> val;
        hdr.tpp_header.mem_sp = hdr.tpp_header.mem_sp + 1;
        switch_reg.read(val, (bit<32>) cur_insn_rd);
        tpp_mem_reg.write(hdr.tpp_header.mem_sp, val);
    }

    action tpp_load() {
        // INVARIANT: cur_insn_rs1 < MAX_MEM_SLOTS
        // TODO: cur_insn_rd tells u which switch_reg to read
        tpp_mem_reg.write((bit<32>) cur_insn_rs1, (bit<32>) 69696969);
    }

    action tpp_pop() {
        bit<32> stack_top_val;
        tpp_mem_reg.read(stack_top_val, hdr.tpp_header.mem_sp);
        switch_reg.write((bit<32>) cur_insn_rd, stack_top_val);
        hdr.tpp_header.mem_sp = hdr.tpp_header.mem_sp - 1;
        num_sp_decs = num_sp_decs + 1;
        just_popped = stack_top_val; // for debugging
    }

    action tpp_store() {
        // INVARIANT: cur_insn_rs1 < MAX_MEM_SLOTS
        bit<32> pkt_val;
        tpp_mem_reg.read(pkt_val, (bit<32>) cur_insn_rs1);
        switch_reg.write((bit<32>) cur_insn_rd, pkt_val);
        just_popped = pkt_val; // for debugging
    }

    action tpp_cexec() {
        bit<32> switch_val;
        switch_reg.read(switch_val, (bit<32>) cur_insn_rd);
        bit<32> pkt_val;
        tpp_mem_reg.read(pkt_val, (bit<32>) cur_insn_rs1);
        cexec_stop = (switch_val == pkt_val);
    }

    action tpp_cstore_eval_predicate() {
        bit<32> switch_val;
        switch_reg.read(switch_val, (bit<32>) cur_insn_rd);
        bit<32> pkt_val;
        tpp_mem_reg.read(pkt_val, (bit<32>) cur_insn_rs1);
        cstore = (switch_val == pkt_val);
    }

    action tpp_cstore_store() {
        bit<32> pkt_val;
        tpp_mem_reg.read(pkt_val, (bit<32>) cur_insn_rs2);
        switch_reg.write((bit<32>) cur_insn_rd, pkt_val);
        just_cstored = pkt_val;
    }

    // USE THIS AS TABLE TEMPLATE for multiple insns!
    table tpp_insn_action {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }
    // USE ABOVE AS TABLE TEMPLATE

    table tpp_insn_action0 {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table tpp_insn_action1 {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table tpp_insn_action2 {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table tpp_insn_action3 {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    table tpp_insn_action4 {
        key = {
            cur_insn_opcode: exact;
        }
        actions = {
            tpp_push;
            tpp_load;
            tpp_pop;
            tpp_store;
            tpp_cexec;
            tpp_cstore_eval_predicate;
            drop;
            NoAction;
        }
        default_action = NoAction();
    }

    action read_tpp_memory() {
        // if # mem slots changes, modify this
        tpp_mem_reg.write(0, (bit<32>) hdr.tpp_mem[0].value);
        tpp_mem_reg.write(1, (bit<32>) hdr.tpp_mem[1].value);
        tpp_mem_reg.write(2, (bit<32>) hdr.tpp_mem[2].value);
        tpp_mem_reg.write(3, (bit<32>) hdr.tpp_mem[3].value);
        tpp_mem_reg.write(4, (bit<32>) hdr.tpp_mem[4].value);
        tpp_mem_reg.write(5, (bit<32>) hdr.tpp_mem[5].value);
        tpp_mem_reg.write(6, (bit<32>) hdr.tpp_mem[6].value);
        tpp_mem_reg.write(7, (bit<32>) hdr.tpp_mem[7].value);
        tpp_mem_reg.write(8, (bit<32>) hdr.tpp_mem[8].value);
        tpp_mem_reg.write(9, (bit<32>) hdr.tpp_mem[9].value);
        tpp_mem_reg.write(10, (bit<32>) hdr.tpp_mem[10].value);
        tpp_mem_reg.write(11, (bit<32>) hdr.tpp_mem[11].value);
        tpp_mem_reg.write(12, (bit<32>) hdr.tpp_mem[12].value);
        tpp_mem_reg.write(13, (bit<32>) hdr.tpp_mem[13].value);
        tpp_mem_reg.write(14, (bit<32>) hdr.tpp_mem[14].value);
        tpp_mem_reg.write(15, (bit<32>) hdr.tpp_mem[15].value);
        tpp_mem_reg.write(16, (bit<32>) hdr.tpp_mem[16].value);
        tpp_mem_reg.write(17, (bit<32>) hdr.tpp_mem[17].value);
        tpp_mem_reg.write(18, (bit<32>) hdr.tpp_mem[18].value);
        tpp_mem_reg.write(19, (bit<32>) hdr.tpp_mem[19].value);
        tpp_mem_reg.write(20, (bit<32>) hdr.tpp_mem[20].value);
    }


    action flush_tpp_memory_to_pkt() {
        bit<32> to_write;

        // if # mem slots changes, modify this
        tpp_mem_reg.read(to_write, 0);
        hdr.tpp_mem[0].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 1);
        hdr.tpp_mem[1].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 2);
        hdr.tpp_mem[2].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 3);
        hdr.tpp_mem[3].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 4);
        hdr.tpp_mem[4].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 5);
        hdr.tpp_mem[5].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 6);
        hdr.tpp_mem[6].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 7);
        hdr.tpp_mem[7].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 8);
        hdr.tpp_mem[8].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 9);
        hdr.tpp_mem[9].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 10);
        hdr.tpp_mem[10].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 11);
        hdr.tpp_mem[11].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 12);
        hdr.tpp_mem[12].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 13);
        hdr.tpp_mem[13].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 14);
        hdr.tpp_mem[14].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 15);
        hdr.tpp_mem[15].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 16);
        hdr.tpp_mem[16].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 17);
        hdr.tpp_mem[17].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 18);
        hdr.tpp_mem[18].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 19);
        hdr.tpp_mem[19].value = (bit<31>) to_write;
        tpp_mem_reg.read(to_write, 20);
        hdr.tpp_mem[20].value = (bit<31>) to_write;
    }

    action cleanup_tpp() {
        hdr.tpp_header.mem_sp = hdr.tpp_header.mem_sp + num_sp_decs;
        cexec_stop = false;
    }

    apply {
        
        if (hdr.tpp_header.isValid()) {
            
            read_tpp_memory();

            // for testing purposes
            switch_reg.write(18, 0x101010);

            // only run first 5 insns
            if (hdr.tpp_insns[0].isValid() && !cexec_stop) {
                parse_tpp_insn((bit<8>) 0);
                tpp_insn_action0.apply();
                debug.apply();

                if (cstore) {
                    // do the deed
                    tpp_cstore_store();
                    tpp_debug.apply();
                    cstore = false;
                }
                clear_tpp_insn_registers();
            }

            // TODO to enable these: make a separate table for each
            // THEN!! populate the tpp-runtime.json with same rules!
            if (hdr.tpp_insns[1].isValid()  && !cexec_stop) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action1.apply();
                clear_tpp_insn_registers();
            }
            
            
            if (hdr.tpp_insns[2].isValid()  && !cexec_stop) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action2.apply();
                clear_tpp_insn_registers();
            }

            if (hdr.tpp_insns[3].isValid()  && !cexec_stop) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action3.apply();
                clear_tpp_insn_registers();
            }

            if (hdr.tpp_insns[4].isValid()  && !cexec_stop) {
                parse_tpp_insn((bit<8>) 1);
                tpp_insn_action4.apply();
                clear_tpp_insn_registers();
            }

            flush_tpp_memory_to_pkt();
            cleanup_tpp();
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
