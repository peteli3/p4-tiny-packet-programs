
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
        transition accept;
    }

}

control TPPEgress(
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
        }
        actions = {}
    }

    apply {
        debug.apply();
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
