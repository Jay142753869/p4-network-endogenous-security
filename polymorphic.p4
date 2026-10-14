/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_SRCROUTING    = 0x1234;

const bit<16> TYPE_IPV4          = 0x800;
const bit<16> TYPE_ARP           = 0x0806;

const bit<16> TYPE_IPV6          = 0x86DD;

const bit<16> POLY_MAGIC        = 0x504f; // ASCII "PO"
const bit<8>  POLY_IP_PROTOCOL  = 253;
const bit<16> POLY_UDP_PORT     = 5000;
const bit<16> POLY_MCAST_GROUP  = 10;
const bit<32> INSTANCE_REPLICATION = 5; // BMv2 simple_switch PRE instance type

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

#define MAX_HOPS 9
#define STATE_SLOTS 1024

const bit<2> VOTE_PENDING = 0;
const bit<2> VOTE_MAJORITY = 1;
const bit<2> VOTE_NO_MAJORITY = 2;

error {
    InvalidPolyShim,
    UnsupportedInnerIPv4
}

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

// M1: 14-byte shim shared by all three outer modalities.
header polyShim_t {
    bit<16> magic;
    bit<8>  direction;       // 0: h1 -> h2, 1: h2 -> h1
    bit<32> sequence_number;
    bit<8>  modality_id;
    bit<32> source_crc32;
    bit<16> inner_ether_type; // TYPE_IPV4 for this experiment
}

header protected_data_t {
    bit<128> value;          // exactly 16 bytes, in wire order
}

struct metadata {
    ip4Addr_t   dst_ipv4; // dst ip

    bit<1>      scheduled;
    bit<8>      packet_direction;
    bit<32>     sequence_number;
    bit<1>      adjudication_accept; // M6 hook: only the deciding current copy
    // Per-packet scratch only; persistent state is in MyIngress registers.
    bit<32> vote_slot;
    bit<32> vote_observed_crc;
    bit<32> vote_newest;
    bit<1>  vote_newest_valid;
    bit<32> vote_delta;
    bit<32> vote_age;
    bit<1>  vote_admissible;
    bit<1>  vote_valid;
    bit<8>  vote_direction;
    bit<32> vote_tag;
    bit<32> vote_crc1;
    bit<32> vote_crc2;
    bit<8>  vote_mode1;
    bit<8>  vote_mode2;
    bit<8>  vote_seen;
    bit<8>  vote_mode_bit;
    bit<2>  vote_candidates;
    bit<1>  vote_decided;
    bit<2>  vote_status;
    bit<32> vote_winner;
}

struct headers {
    ethernet_t  ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    arp_t       arp;
    ipv4_t      ipv4;
    ipv6_t      ipv6;
    polyShim_t  poly;
    ipv4_t      inner_ipv4;  // independent of the ordinary/outer hdr.ipv4
    tcp_t       tcp;
    udp_t       udp;
    protected_data_t protected_data;
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
            1: parse_sr_payload;
            default: parse_srcRouting;
        }
    }

    state parse_sr_payload {
        // Original SR carries IPv4 (first nibble 4); the new SR modality
        // carries PolyShim directly. Lookahead does not consume either one.
        transition select(packet.lookahead<bit<16>>()) {
            POLY_MAGIC: parse_poly;
            default: parse_ipv4;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        meta.dst_ipv4 = hdr.arp.tpa;  //save dst ip
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // The experiment uses a fixed 20-byte IPv4 header, without fragments.
        // Keep options/fragments opaque for ordinary IPv4 forwarding.
        transition select(hdr.ipv4.version, hdr.ipv4.ihl,
                          hdr.ipv4.flags & 3w1, hdr.ipv4.fragOffset) {
            (4, 5, 0, 0): parse_ipv4_payload;
            default: accept;
        }
    }

    state parse_ipv4_payload {
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            POLY_IP_PROTOCOL: parse_poly;
            default: accept;
        }
    }
    
    state parse_ipv6{
	packet.extract(hdr.ipv6);
	transition select(hdr.ipv6.nextHdr) {
            POLY_IP_PROTOCOL: parse_poly;
            default: accept;
        }
    }

    state parse_poly {
        packet.extract(hdr.poly);
        verify(hdr.poly.magic == POLY_MAGIC &&
               hdr.poly.inner_ether_type == TYPE_IPV4,
               error.InvalidPolyShim);
        transition parse_inner_ipv4;
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        // Never overwrite hdr.ipv4: intermediate IPv4 routing and TTL updates
        // must operate on the outer header, leaving the inner packet intact.
        verify(hdr.inner_ipv4.version == 4 && hdr.inner_ipv4.ihl == 5 &&
               (hdr.inner_ipv4.flags & 3w1) == 0 &&
               hdr.inner_ipv4.fragOffset == 0 && hdr.inner_ipv4.protocol == 17,
               error.UnsupportedInnerIPv4);
        transition parse_udp;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);

        // M2: UDP length includes its 8-byte header and 16 protected bytes.
        // All other UDP payloads remain untouched, including ordinary SR UDP.
        transition select(hdr.udp.dstPort, hdr.udp.pkt_length) {
            (POLY_UDP_PORT, 24): parse_protected_data;
            default: accept;
        }
    }

    state parse_protected_data {
        packet.extract(hdr.protected_data);
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

    // BMv2 initializes both slots to zero. Slots are direction 0 / 1, and
    // each switch owns its own array. Store the last allocated sequence.
    register<bit<32>>(2) sequence_register;

    register<bit<1>>(STATE_SLOTS) slot_valid;
    register<bit<8>>(STATE_SLOTS) slot_direction;
    register<bit<32>>(STATE_SLOTS) seq_tag;
    register<bit<32>>(STATE_SLOTS) crc_candidate_1;
    register<bit<32>>(STATE_SLOTS) crc_candidate_2;
    register<bit<8>>(STATE_SLOTS) mode_candidate_1;
    register<bit<8>>(STATE_SLOTS) mode_candidate_2;
    register<bit<8>>(STATE_SLOTS) seen_modes;
    register<bit<2>>(STATE_SLOTS) candidate_counts;
    register<bit<1>>(STATE_SLOTS) decided;
    register<bit<2>>(STATE_SLOTS) decision_status;
    register<bit<32>>(STATE_SLOTS) decided_crc;
    // Each switch is one destination direction; these two entries also keep
    // serial-number freshness checks explicitly separated by direction.
    register<bit<32>>(2) latest_sequence;
    register<bit<1>>(2) latest_valid;

    counter(5, CounterType.packets) good_count;
    counter(5, CounterType.packets) bad_count;
    counter(1, CounterType.packets) no_majority_count;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action start_polymorphic(bit<8> packet_direction) {
        meta.scheduled = 1;
        meta.packet_direction = packet_direction;
    }

    table polymorphic_schedule {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dstPort: exact;
        }
        actions = {
            start_polymorphic;
            NoAction;
        }
        size = 16;
        const default_action = NoAction();
    }

    action prepare_polymorphic() {
        // Save before ordinary routing changes TTL/MAC. The outer IPv4 will
        // only be built by M4; never emit the same original IPv4 twice.
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.ipv4.setInvalid();
        @atomic {
            sequence_register.read(meta.sequence_number,
                                   (bit<32>)meta.packet_direction);
            // bit<32> addition: first is 1; 0xffffffff wraps to 0.
            meta.sequence_number = meta.sequence_number + 1;
            sequence_register.write((bit<32>)meta.packet_direction,
                                    meta.sequence_number);
        }
        hdr.poly.setValid();
        hdr.poly.magic = POLY_MAGIC;
        hdr.poly.direction = meta.packet_direction;
        hdr.poly.sequence_number = meta.sequence_number;
        hdr.poly.modality_id = 0; // pending M4, not an on-wire modality
        // CRC-32/ISO-HDLC, 232 bits in this exact order, no payload/padding.
        // max=2^32 (64-bit argument) preserves all 32 CRC bits, including
        // 0xffffffff; max=0xffffffff would incorrectly reduce that result.
        hash(hdr.poly.source_crc32, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.inner_ipv4.srcAddr,
               hdr.inner_ipv4.dstAddr,
               hdr.inner_ipv4.protocol,
               hdr.udp.srcPort,
               hdr.udp.dstPort,
               hdr.protected_data.value },
             (bit<64>)0x100000000);
        hdr.poly.inner_ether_type = TYPE_IPV4;
        standard_metadata.mcast_grp = POLY_MCAST_GROUP;
    }

    action adjudicate_polymorphic() {
        // Recompute from the received inner bytes; source_crc32 is never read.
        hash(meta.vote_observed_crc, HashAlgorithm.crc32, (bit<32>)0,
             { hdr.inner_ipv4.srcAddr,
               hdr.inner_ipv4.dstAddr,
               hdr.inner_ipv4.protocol,
               hdr.udp.srcPort,
               hdr.udp.dstPort,
               hdr.protected_data.value },
             (bit<64>)0x100000000);
        meta.vote_slot = hdr.poly.sequence_number & 1023;
        meta.vote_mode_bit = (bit<8>)(8w1 << (hdr.poly.modality_id - 1));
        // One BMv2 action holds all register locks across reads, branching,
        // writes and counter accounting. Never split this transaction.
        @atomic {
            latest_sequence.read(meta.vote_newest, (bit<32>)hdr.poly.direction);
            latest_valid.read(meta.vote_newest_valid, (bit<32>)hdr.poly.direction);
            slot_valid.read(meta.vote_valid, meta.vote_slot);
            slot_direction.read(meta.vote_direction, meta.vote_slot);
            seq_tag.read(meta.vote_tag, meta.vote_slot);
            crc_candidate_1.read(meta.vote_crc1, meta.vote_slot);
            crc_candidate_2.read(meta.vote_crc2, meta.vote_slot);
            mode_candidate_1.read(meta.vote_mode1, meta.vote_slot);
            mode_candidate_2.read(meta.vote_mode2, meta.vote_slot);
            seen_modes.read(meta.vote_seen, meta.vote_slot);
            candidate_counts.read(meta.vote_candidates, meta.vote_slot);
            decided.read(meta.vote_decided, meta.vote_slot);
            decision_status.read(meta.vote_status, meta.vote_slot);
            decided_crc.read(meta.vote_winner, meta.vote_slot);

            meta.vote_delta = hdr.poly.sequence_number - meta.vote_newest;
            meta.vote_age = meta.vote_newest - hdr.poly.sequence_number;
            meta.vote_admissible = 1;
            // Serial-number arithmetic: half-range is ambiguous and rejected;
            // out-of-order copies are accepted only within the latest 1024.
            if (meta.vote_newest_valid == 1 &&
                meta.vote_delta >= 0x80000000 && meta.vote_age >= STATE_SLOTS) {
                meta.vote_admissible = 0;
            }
            // A switch is configured for one destination direction. Refuse
            // cross-direction slot reuse even under a bad role configuration.
            if (meta.vote_valid == 1 && meta.vote_direction != hdr.poly.direction) {
                meta.vote_admissible = 0;
            }
            if (meta.vote_admissible == 1) {
                if (meta.vote_valid == 0 || meta.vote_tag != hdr.poly.sequence_number) {
                    meta.vote_valid = 1;
                    meta.vote_direction = hdr.poly.direction;
                    meta.vote_tag = hdr.poly.sequence_number;
                    meta.vote_crc1 = 0;
                    meta.vote_crc2 = 0;
                    meta.vote_mode1 = 0;
                    meta.vote_mode2 = 0;
                    meta.vote_seen = 0;
                    meta.vote_candidates = 0;
                    meta.vote_decided = 0;
                    meta.vote_status = VOTE_PENDING;
                    meta.vote_winner = 0;
                }
                // Duplicate modes never write state or account statistics.
                if ((meta.vote_seen & meta.vote_mode_bit) == 0) {
                    meta.vote_seen = meta.vote_seen | meta.vote_mode_bit;
                    if (meta.vote_status == VOTE_PENDING) {
                        if (meta.vote_candidates == 0) {
                            meta.vote_crc1 = meta.vote_observed_crc;
                            meta.vote_mode1 = hdr.poly.modality_id;
                            meta.vote_candidates = 1;
                        } else if (meta.vote_candidates == 1) {
                            if (meta.vote_observed_crc == meta.vote_crc1) {
                                meta.vote_decided = 1;
                                meta.vote_status = VOTE_MAJORITY;
                                meta.vote_winner = meta.vote_observed_crc;
                                meta.adjudication_accept = 1;
                            } else {
                                meta.vote_crc2 = meta.vote_observed_crc;
                                meta.vote_mode2 = hdr.poly.modality_id;
                                meta.vote_candidates = 2;
                            }
                        } else {
                            meta.vote_decided = 1;
                            if (meta.vote_observed_crc == meta.vote_crc1 ||
                                meta.vote_observed_crc == meta.vote_crc2) {
                                meta.vote_status = VOTE_MAJORITY;
                                meta.vote_winner = meta.vote_observed_crc;
                                meta.adjudication_accept = 1;
                            } else {
                                meta.vote_status = VOTE_NO_MAJORITY;
                                meta.vote_winner = 0;
                                no_majority_count.count(0);
                            }
                        }
                    }
                    if (meta.adjudication_accept == 1) {
                        // Account the earlier candidates exactly once when
                        // the winner becomes known, not at candidate arrival.
                        if (meta.vote_crc1 == meta.vote_winner) {
                            good_count.count((bit<32>)meta.vote_mode1);
                        } else {
                            bad_count.count((bit<32>)meta.vote_mode1);
                        }
                        if (meta.vote_candidates == 2) {
                            if (meta.vote_crc2 == meta.vote_winner) {
                                good_count.count((bit<32>)meta.vote_mode2);
                            } else {
                                bad_count.count((bit<32>)meta.vote_mode2);
                            }
                        }
                        good_count.count((bit<32>)hdr.poly.modality_id);
                    } else if (meta.vote_status == VOTE_MAJORITY) {
                        // New, late third mode: statistics only, no accept.
                        if (meta.vote_observed_crc == meta.vote_winner) {
                            good_count.count((bit<32>)hdr.poly.modality_id);
                        } else {
                            bad_count.count((bit<32>)hdr.poly.modality_id);
                        }
                    }
                    slot_valid.write(meta.vote_slot, meta.vote_valid);
                    slot_direction.write(meta.vote_slot, meta.vote_direction);
                    seq_tag.write(meta.vote_slot, meta.vote_tag);
                    crc_candidate_1.write(meta.vote_slot, meta.vote_crc1);
                    crc_candidate_2.write(meta.vote_slot, meta.vote_crc2);
                    mode_candidate_1.write(meta.vote_slot, meta.vote_mode1);
                    mode_candidate_2.write(meta.vote_slot, meta.vote_mode2);
                    seen_modes.write(meta.vote_slot, meta.vote_seen);
                    candidate_counts.write(meta.vote_slot, meta.vote_candidates);
                    decided.write(meta.vote_slot, meta.vote_decided);
                    decision_status.write(meta.vote_slot, meta.vote_status);
                    decided_crc.write(meta.vote_slot, meta.vote_winner);
                    if (meta.vote_newest_valid == 0 ||
                        (meta.vote_delta != 0 && meta.vote_delta < 0x80000000)) {
                        latest_sequence.write((bit<32>)hdr.poly.direction,
                                              hdr.poly.sequence_number);
                        latest_valid.write((bit<32>)hdr.poly.direction, 1);
                    }
                }
            }
        }
    }

    // Fail closed for unmatched gateway arrivals and, until M6, all decisions.
    action hold_polymorphic() {
        mark_to_drop(standard_metadata);
        exit;
    }

    table polymorphic_destination {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.poly.direction: exact;
            hdr.poly.modality_id: exact;
        }
        actions = {
            adjudicate_polymorphic;
            hold_polymorphic;
            NoAction;
        }
        size = 16;
        // The controller sets this to hold only on S1/S2. Intermediate
        // reverse paths legitimately use egress port 1, so port != role.
        default_action = NoAction();
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
        meta.adjudication_accept = 0;
        // Parser rejection on v1model does not automatically drop a packet.
        if (standard_metadata.parser_error != error.NoError) {
            drop();
            exit;
        }
        meta.scheduled = 0;
        meta.packet_direction = 0;
        standard_metadata.mcast_grp = 0;

        if (hdr.poly.isValid()) {
            // Only complete, structurally consistent experiment copies may
            // continue to ordinary intermediate routing. Never schedule them.
            if (hdr.poly.magic != POLY_MAGIC ||
                hdr.poly.inner_ether_type != TYPE_IPV4 ||
                hdr.poly.direction > 1 ||
                hdr.poly.modality_id < 1 || hdr.poly.modality_id > 3 ||
                !hdr.inner_ipv4.isValid() || !hdr.udp.isValid() ||
                !hdr.protected_data.isValid() ||
                hdr.inner_ipv4.version != 4 || hdr.inner_ipv4.ihl != 5 ||
                (hdr.inner_ipv4.flags & 3w5) != 0 ||
                hdr.inner_ipv4.fragOffset != 0 ||
                hdr.inner_ipv4.protocol != 17 || hdr.inner_ipv4.totalLen != 44 ||
                hdr.udp.dstPort != POLY_UDP_PORT || hdr.udp.pkt_length != 24) {
                drop();
                exit;
            }
            if (!((hdr.poly.modality_id == 1 &&
                   hdr.ethernet.etherType == TYPE_IPV4 && hdr.ipv4.isValid() &&
                   hdr.ipv4.protocol == POLY_IP_PROTOCOL &&
                   !hdr.srcRoutes[0].isValid()) ||
                  (hdr.poly.modality_id == 2 &&
                   hdr.ethernet.etherType == TYPE_IPV6 && hdr.ipv6.isValid() &&
                   hdr.ipv6.version == 6 && hdr.ipv6.nextHdr == POLY_IP_PROTOCOL) ||
                  (hdr.poly.modality_id == 3 &&
                   hdr.ethernet.etherType == TYPE_SRCROUTING &&
                   hdr.srcRoutes[0].isValid() && !hdr.ipv4.isValid()))) {
                drop();
                exit;
            }
            if (polymorphic_destination.apply().hit) {
                // M6 hook: only adjudication_accept==1 may be restored here.
                // M5 still drops every copy, retaining the winner metadata.
                hold_polymorphic();
            }
        }

        // M3: fixed Ethernet/IPv4/UDP input only, before ordinary routing can
        // decrement TTL or overwrite MAC addresses. Padding may follow it.
        if (standard_metadata.ingress_port == 1 &&
            hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_IPV4 &&
            hdr.ipv4.isValid() && hdr.udp.isValid() &&
            hdr.protected_data.isValid() && !hdr.poly.isValid() &&
            !hdr.inner_ipv4.isValid() && !hdr.ipv6.isValid() &&
            !hdr.srcRoutes[0].isValid() &&
            hdr.ipv4.version == 4 && hdr.ipv4.ihl == 5 &&
            (hdr.ipv4.flags & 3w5) == 0 && hdr.ipv4.fragOffset == 0 &&
            hdr.ipv4.protocol == 17 && hdr.ipv4.totalLen == 44 &&
            hdr.udp.dstPort == POLY_UDP_PORT && hdr.udp.pkt_length == 24 &&
            standard_metadata.packet_length >= 58) {
            polymorphic_schedule.apply();
        }
        if (meta.scheduled == 1) {
            // Reject a misconfigured action parameter before register access.
            if (meta.packet_direction > 1) {
                drop();
                exit;
            }
            prepare_polymorphic();
            exit;
        }

        // TODO M5: destination-gateway processing must precede ordinary SR
        // termination / routing and emit at most one restored packet.
        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                if (hdr.poly.isValid()) {
                    // Fail closed if a terminal SR destination rule is absent.
                    drop();
                    exit;
                }
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }
        
        else if(hdr.ethernet.etherType == TYPE_IPV4 && hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_ARP && hdr.arp.isValid()) {
            arp_match.apply();
        }
        else if(hdr.ethernet.etherType == TYPE_IPV6 && hdr.ipv6.isValid()){
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
    action clear_outer_headers() {
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.srcRoutes[0].setInvalid();
        hdr.srcRoutes[1].setInvalid();
        hdr.srcRoutes[2].setInvalid();
        hdr.srcRoutes[3].setInvalid();
        hdr.srcRoutes[4].setInvalid();
        hdr.srcRoutes[5].setInvalid();
        hdr.srcRoutes[6].setInvalid();
        hdr.srcRoutes[7].setInvalid();
        hdr.srcRoutes[8].setInvalid();
    }

    action encapsulate_ipv4(ip4Addr_t source, ip4Addr_t destination) {
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.poly.modality_id = 1;
        hdr.ipv4.setValid();
        hdr.ipv4.version = 4;
        hdr.ipv4.ihl = 5;
        hdr.ipv4.diffserv = 0;
        hdr.ipv4.totalLen = 78;
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags = 0;
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.protocol = POLY_IP_PROTOCOL;
        hdr.ipv4.hdrChecksum = 0; // MyComputeChecksum runs after Egress
        hdr.ipv4.srcAddr = source;
        hdr.ipv4.dstAddr = destination;
    }

    action encapsulate_ipv6(ip6Addr_t source, ip6Addr_t destination) {
        hdr.ethernet.etherType = TYPE_IPV6;
        hdr.poly.modality_id = 2;
        hdr.ipv6.setValid();
        hdr.ipv6.version = 6;
        hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
        hdr.ipv6.payLoadLen = 58;
        hdr.ipv6.nextHdr = POLY_IP_PROTOCOL;
        hdr.ipv6.hopLimit = 64;
        hdr.ipv6.srcAddr = source;
        hdr.ipv6.dstAddr = destination;
    }

    action encapsulate_sr(bit<15> first_port, bit<15> second_port) {
        hdr.ethernet.etherType = TYPE_SRCROUTING;
        // Like the original SR sender, forwarding is entirely port-stack
        // driven and the Ethernet destination is broadcast.
        hdr.ethernet.dstAddr = 0xffffffffffff;
        hdr.poly.modality_id = 3;
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].bos = 0;
        hdr.srcRoutes[0].port = first_port;
        hdr.srcRoutes[1].setValid();
        hdr.srcRoutes[1].bos = 0;
        hdr.srcRoutes[1].port = second_port;
        hdr.srcRoutes[2].setValid();
        hdr.srcRoutes[2].bos = 1;
        hdr.srcRoutes[2].port = 1;
    }

    apply {
        if (meta.scheduled == 1) {
            if (standard_metadata.instance_type != INSTANCE_REPLICATION ||
                !hdr.poly.isValid() || !hdr.inner_ipv4.isValid() ||
                !hdr.udp.isValid() || !hdr.protected_data.isValid() ||
                hdr.poly.direction > 1) {
                mark_to_drop(standard_metadata);
                exit;
            }
            clear_outer_headers();
            // The next-hop MACs match the existing IPv4/IPv6 route actions.
            if (hdr.poly.direction == 0) {
                hdr.ethernet.srcAddr = 0x080000000100;
                hdr.ethernet.dstAddr = 0x080000001100;
            } else {
                hdr.ethernet.srcAddr = 0x080000000200;
                hdr.ethernet.dstAddr = 0x080000001200;
            }
            // PRE already selected the port; Egress only chooses its format.
            if (standard_metadata.egress_port == 2) {
                if (hdr.poly.direction == 0) {
                    encapsulate_ipv4(0x0a000101, 0x0a000202);
                } else {
                    encapsulate_ipv4(0x0a000202, 0x0a000101);
                }
            } else if (standard_metadata.egress_port == 3) {
                if (hdr.poly.direction == 0) {
                    encapsulate_ipv6(0xfe800000000000000000000000001234,
                                     0xfe800000000000000000000000005678);
                } else {
                    encapsulate_ipv6(0xfe800000000000000000000000005678,
                                     0xfe800000000000000000000000001234);
                }
            } else if (standard_metadata.egress_port == 4) {
                // Port 4 at the source gateway was already consumed by PRE.
                // These are the remaining S31/S32/destination gateway ports.
                if (hdr.poly.direction == 0) {
                    encapsulate_sr(2, 2);
                } else {
                    encapsulate_sr(1, 1);
                }
            } else {
                mark_to_drop(standard_metadata);
            }
        }
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
        // M1: invalid headers emit no bytes. hdr.ipv4 is ordinary IPv4 or
        // outer IPv4; only hdr.inner_ipv4 stores the encapsulated original.
        // TODO M4/M6: set/invalidate the appropriate instances on encapsulation
        // and restoration, keeping this wire order.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.poly);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.protected_data);
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
