/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "int.p4.inc"

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_VLAN = 0x8100;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_h {
    bit<3> pcp;
    bit<1> dei;
    bit<12> vid;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen; //feature2_t
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// tcp header
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

#define MAX_TCP_OPTION_WORD 10
header tcp_option_t{
   bit<32> data;
}

/* UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udpTotalLen;
    bit<16> checksum;
}

struct metadata {
    /* empty */
    int_metadata _int;
}

struct headers {
    ethernet_t   ethernet;
    vlan_h       vlan;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;

   tcp_option_t[MAX_TCP_OPTION_WORD] tcp_opt;
   int_headers _int;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    //local variable to count TCP options in number of words
    bit<4> tcp_opt_cnt = 0;

    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_VLAN: parse_vlan; 
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan {
        log_msg("Parsing VLAN=====");
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType){
            //TYPE_VLAN: parse_vlan; //vlan in vlan 
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);

        //jump over TCP options
        tcp_opt_cnt = hdr.tcp.dataOffset;

        //exclude 5 words (=20 bytes) of the fixed tcp header that is defined in tcp_t
        if( tcp_opt_cnt > 5 )
            tcp_opt_cnt = tcp_opt_cnt - 5;
        else
            tcp_opt_cnt = 0;
        //log_msg("====TCP data offset = {}", {tcp_opt_cnt});
        transition select( tcp_opt_cnt ){
            0       : parse_int_over_tcp;
            default : parse_tcp_option;
        }
    }

    state parse_int_over_tcp {
        int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.tcp.srcPort, hdr.ipv4.dstAddr, hdr.tcp.dstPort, hdr._int, meta._int, standard_metadata, false );
        transition accept;
    }
 
    state parse_tcp_option {
        packet.extract( hdr.tcp_opt.next );
        tcp_opt_cnt = tcp_opt_cnt - 1;
        transition select( tcp_opt_cnt ){
            0      : parse_int_over_tcp;
            default: parse_tcp_option;
        }
    }


    state parse_udp {
        packet.extract(hdr.udp);
        int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.udp.srcPort, hdr.ipv4.dstAddr, hdr.udp.dstPort, hdr._int, meta._int, standard_metadata, false );
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

    /* default table and its actions for packet forwarding */
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
        default_action = drop();
    }
    
    //table to update priority-code-point field in VLAN
    // by default, pcp is zero
    action default_priority(){
        hdr.vlan.pcp = 0;
    }
    
    action set_priority(bit<3> pcp){
        hdr.vlan.pcp = pcp;
    }
    table priority_tbl {
        //use UDP dst port to identify packet
        key = {
           hdr.udp.dstPort: exact;
        }
        actions = {
            set_priority;
            default_priority;
        }
        size = 1024;
        default_action = default_priority();
    }
    
    apply {
         if (hdr.ipv4.isValid() ){
            ipv4_lpm.apply();

            //INT work over IP so we put here its ingress
            int_ingress.apply( hdr._int, meta._int, standard_metadata );
         }

         //force to enable VLAN if VLAN does not exist
         if( hdr.ethernet.etherType != TYPE_VLAN ){
             hdr.vlan.setValid();
             hdr.vlan.etherType = hdr.ethernet.etherType;
             hdr.ethernet.etherType = TYPE_VLAN;
         }

         //PCP is configured via priority_tbl
         //if( hdr.udp.dstPort == 6666 )
         //    hdr.vlan.pcp = 1;
         //else
         //    hdr.vlan.pcp = 0;
             

         priority_tbl.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

         int_egress.apply( hdr._int, meta._int, standard_metadata );

         if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_EGRESS_CLONE) {
             //reset priority to copy to INT
             //standard_metadata.priority = 0;
             hdr.ipv4.dscp = INT_IPv4_DSCP;
             //hdr.ipv4.dstAddr =  0x0a001E02; //10.0.30.2 IP of INT collector
             hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
             return;
         }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
         update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            hdr.ipv4.ecn,
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
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);

        packet.emit(hdr.tcp_opt);
        int_deparser.apply( packet, hdr._int );
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;