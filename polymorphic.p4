/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SRCROUTING    = 0x1234;

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

const bit<16> TYPE_IPV6          = 0x86DD;

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

#define MAX_HOPS 9

/*
 * STUDENT TODO ROADMAP
 *
 * This starter intentionally remains the verified three-path baseline. It
 * compiles before any experiment code is added. Complete the extension in
 * stages and keep every stage compilable:
 *
 *   M1: define PolyShim, protected_data and saved inner-IPv4 headers;
 *   M2: parse UDP dport 5000 with exactly 16 protected bytes;
 *   M3: add sequence/CRC metadata and an ingress scheduling table;
 *   M4: set mcast_grp and build IPv4/IPv6/SR outer headers in MyEgress;
 *   M5: add destination-gateway register state and 2-out-of-3 adjudication;
 *   M6: restore the original IPv4 packet and emit it at host-facing port 1.
 *
 * The field contract and pseudocode are in STUDENT_TODO.md. Do not paste a
 * complete solution here first: implement and validate one milestone at a
 * time so a failing stage can be located from pcap and counter evidence.
 */

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header srcRoute_t {
    bit<1>    bos;
    bit<15>   port;
}

header arp_t {
    bit<16> htype; // format of hardware address
    bit<16> ptype; // format of protocol address
    bit<8>  hlen; // length of hardware address
    bit<8>  plen; // length of protocol address
    bit<16> oper; // request or reply operation
    macAddr_t sha; //src mac address
    ip4Addr_t spa; //src ip address
    macAddr_t tha; // dst mac address
    ip4Addr_t tpa; // dst ip address
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t{
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payLoadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> pkt_length;
    bit<16> checksum;
}

struct metadata {
    ip4Addr_t   dst_ipv4; // dst ip

    // TODO M3-M6: add packet role, sequence, modality, CRC and restore metadata.
}

struct headers {
    ethernet_t  ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t       arp;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    tcp_t       tcp;
    udp_t       udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP : parse_arp;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }
    
    state parse_srcRouting {
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos) {
            1: parse_ipv4;
            default: parse_srcRouting;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }
    
    state parse_ipv6{
	packet.extract(hdr.ipv6);
	transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);

        // TODO M2: only the fixed UDP/5000 experiment format continues to
        // PolyShim/protected-data parsing. Ordinary UDP must remain accepted.
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
        mark_to_drop(standard_metadata);
    }
    
    action srcRoute_nhop() {
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
	
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    action ipv6_forward(macAddr_t dstAddr,egressSpec_t port){
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }
    
    table ipv6_lpm{
    	key = {
	    hdr.ipv6.dstAddr: lpm;
	}
	actions = {
	    ipv6_forward;
	    drop;
	    NoAction;
	}		
	size = 1024;	
	default_action = drop();
    }

    action send_arp_reply(macAddr_t macAddr) {
        hdr.ethernet.dstAddr = hdr.arp.sha;      // Ethernet target address = ARP source MAC address
        hdr.ethernet.srcAddr = macAddr; 	  // Ethernet source address = the action argument macAddr

        hdr.arp.oper         = ARP_OPER_REPLY;   // modify the ARP packet type to reply
        // set the fields to reply
        hdr.arp.tha          = hdr.arp.sha;      // ARP target MAC address = ARP source MAC address
        hdr.arp.tpa          = hdr.arp.spa;      // ARP target IP address = ARP source IP address
        hdr.arp.sha          = macAddr;          // ARP source MAC address = the action argument macAddr
        hdr.arp.spa          = meta.dst_ipv4;           // ARP source IP address = ARP target IP address

        standard_metadata.egress_spec = standard_metadata.ingress_port; // return to the port it comes from
    }

    table arp_match {
        key = {
            hdr.arp.oper           : exact;
            hdr.arp.tpa            : lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }
        const default_action = drop();
    }

    apply {
        /*
         * TODO M3: check destination-gateway traffic before ordinary routing.
         * TODO M3: check source-gateway schedule before ipv4_lpm.
         * TODO M5: destination processing must either emit exactly one restored
         * packet or drop; outer packets must never reach a host unchanged.
         */
        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }
        
        else if(hdr.ethernet.etherType == TYPE_IPV4) {
            ipv4_lpm.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_ARP) {
            arp_match.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV6){
	    ipv6_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        /*
         * TODO M4: for scheduled multicast replicas, use egress_port to build:
         *   2 -> outer IPv4, modality_id 1
         *   3 -> outer IPv6, modality_id 2
         *   4 -> Source Routing, modality_id 3
         * All three replicas must retain one sequence number and one inner IPv4.
         */
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // TODO M1/M4/M6: emit newly introduced outer/PolyShim/inner headers in
        // wire order. Header validity decides which modality is serialized.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
