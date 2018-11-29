/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRC_ROUTE = 0x1234;
const bit<8> PROTO_UDP = 0x11;
const bit<16> PORT_TPP = 0x6666;
const bit<32> MAX_HOPS = 16;

const bit<32> MAX_INSTRUCTIONS = 5;
const bit<32> MAX_PACKET_DATA = 50;

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

header src_route_t {
    bit<1> bos;
    bit<15> port;
}

// tpp headers

header tpp_insn_t {
    bit<32> instruction;
}

header packet_data_t {
    bit<32> packet_data;
}

header tpp_t {
    bit<64> tppLen;
    bit<64> packetMemLen;
    bit<64> packetMemAddrMode; // TODO
    bit<64> hopNum;
    bit<64> perHopMemLen;
}

struct metadata {
}

struct headers {
    ethernet_t ethernet;
    src_route_t[MAX_HOPS] src_routes;
    ipv4_t ipv4;
    udp_t udp;

    // tpp definitions
    tpp_t tpp;
    tpp_insn_t[MAX_INSTRUCTIONS] tpp_insns;
    packet_data_t[MAX_PACKET_DATA] packet_data;
}

