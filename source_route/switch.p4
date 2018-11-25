/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "telemetry.p4"

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    TelemetryParser() telemetryParser;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRC_ROUTE: parse_src_route;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_src_route {
        packet.extract(hdr.src_routes.next);
        transition select(hdr.src_routes.last.bos) {
            0: parse_src_route;
            default: parse_ipv4;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        telemetryParser.apply(packet, meta, hdr);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action src_route_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.src_routes[0].port;
        hdr.src_routes.pop_front(1);
    }

    action src_route_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    apply {
        if (hdr.src_routes[0].isValid()){
            if (hdr.src_routes[0].bos == 1){
                src_route_finish();
            }
            src_route_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        } else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    TelemetryEgress() telemetryEgress;
    apply {
        telemetryEgress.apply(hdr, meta, standard_metadata);
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    TelemetryDeparser() telemetryDeparser;
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.src_routes);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        telemetryDeparser.apply(packet, hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
