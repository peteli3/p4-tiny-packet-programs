
/* -*- P4_16 -*- */



parser TPPParser(
    packet_in packet,
    inout metadata meta,
    inout headers hdrs
) {
    state start {
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
