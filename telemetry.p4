
/* -*- P4_16 -*- */



parser TelemetryParser(packet_in packet,
                       inout metadata meta,
                       inout headers hdrs) 
{

    bit<8> num_left;

    state start {
        transition select(hdrs.udp.dstPort) {
            PORT_TELEMETRY: parse_telemetry;
            default: accept;
        }
    }

    state parse_telemetry {
        packet.extract(hdrs.telemetry);
        num_left = hdrs.telemetry.count;
        transition parse_hops_outer;
    }

    state parse_hops_outer {
        transition select (num_left) {
            0: accept;
            default: parse_hops_inner;
        }
    }

    state parse_hops_inner {
        packet.extract(hdrs.hops.next);
        num_left = num_left - 1;
        transition parse_hops_outer;
    }

}


control TelemetryEgress(inout headers hdr,
                        inout metadata meta,
                        inout standard_metadata_t standard_metadata) 
{
    
    table debug {
        key = {
            hdr.telemetry.count: exact;
            hdr.telemetry.maxBytes: exact;
            hdr.hops[0].portId: exact;
            standard_metadata.packet_length: exact;
        }
        actions = {}
    }

    apply {
        // make space for hop
        if (hdr.telemetry.count != 0) {
            hdr.hops.push_front(1);
        }

        // update packet length tracking for hops
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
        hdr.udp.len = hdr.udp.len + 2;

        // update telemetry header
        hdr.telemetry.count = hdr.telemetry.count + 1;
        bit<32> old_estimate = 3 * (hdr.telemetry.maxBytes >> 2);
        bit<32> contrib = (standard_metadata.packet_length >> 2);
        hdr.telemetry.maxBytes = old_estimate + contrib;

        // update hops
        hdr.hops[0].setValid();
        hdr.hops[0].portId = (bit<16>) standard_metadata.egress_port;
    }
}

control TelemetryDeparser(packet_out packet, 
                          in headers hdr) 
{
    apply {
        packet.emit(hdr.telemetry);
        packet.emit(hdr.hops);
    }
}
