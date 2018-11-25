/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_SRC_ROUTE = 0x1234;
const bit<8> PROTO_UDP = 0x11;
const bit<16> PORT_TELEMETRY = 4321;

const bit<32> MAX_TUNNEL_ID = 1 << 16;
const bit<32> MAX_HOPS = 16;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header telemetry_t {
    bit<8> count;
    bit<32> maxBytes;
}

header hop_t {
    bit<16> portId;
}

header src_route_t {
    bit<1> bos;
    bit<15> port;
}

header myTunnel_t {
    bit<16> protoId;
    bit<16> dstId;
}

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    src_route_t[MAX_HOPS] src_routes;
    myTunnel_t myTunnel;
    ipv4_t ipv4;
    udp_t udp;
    telemetry_t telemetry;
    hop_t[MAX_HOPS] hops;
}

