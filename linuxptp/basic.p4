/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_VLAN = 0x8100;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

const bit<16> PTP_SYNC    = 319;
const bit<16> PTP_MESSAGE = 320;


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

header ptp_t {
    bit<4>  transportSpecific;
    bit<4>  messageType;
    bit<4>  reserve_1;
    bit<4>  versionPTP;
    bit<16> messageLength;
    bit<8>  domainNumber;
    bit<8>  reserve_2;
    bit<16> flagField;
    bit<64> correctionField;
    bit<32> reserve_3;
    bit<80> sourcePortIdentity;
    bit<16> sequenceId;
    bit<8> controlField;
    bit<8> logMessageInterval;
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
    ptp_t        ptp;

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
        int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.tcp.srcPort, hdr.ipv4.dstAddr, hdr.tcp.dstPort, hdr._int, meta._int, standard_metadata );
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
        int_parser.apply( packet, hdr.ipv4.dscp, hdr.ipv4.srcAddr, hdr.udp.srcPort, hdr.ipv4.dstAddr, hdr.udp.dstPort, hdr._int, meta._int, standard_metadata );
        
        transition select(hdr.udp.dstPort) {
           PTP_SYNC    : parse_ptp;
           PTP_MESSAGE : parse_ptp;
           default     : accept;
        }
    }

    state parse_ptp {
        packet.extract(hdr.ptp);
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
    action multicast(bit<16> grp) {
        log_msg("set multicast group = {}", {grp});
        //standard_metadata.mcast_grp = grp;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            multicast;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    table unicast {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
         if (hdr.ipv4.isValid() ){
            if( hdr.ipv4.dstAddr == 0xE0000181 ){ //224.0.1.129
                unicast.apply();
            }
            else ipv4_lpm.apply();

            //INT work over IP so we put here its ingress
            int_ingress.apply( hdr._int, meta._int, standard_metadata );

            //PTPv2
            /*
            if( hdr.udp.isValid() ){
               hdr.udp.dstPort = 319;
               hdr.ptp.setValid();
               hdr.ptp.versionPTP = 2;
               hdr.ptp.messageLength = 32;
               hdr.ptp.sequenceId = 3;
            }*/
         }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    apply {
         // Prune multicast packet to ingress port to preventing loop
         if (std_meta.egress_port == std_meta.ingress_port){
            mark_to_drop(std_meta);
            return;
         }
            
         int_egress.apply( hdr._int, meta._int, std_meta );


         //update output packet size in transit
         if( INT_IN_TRANSIT(meta._int.int_node )){
             hdr.ipv4.dscp = INT_IPv4_DSCP;
             //hdr.ipv4.dstAddr =  0x0a001E02; //10.0.30.2 IP of INT collector
             hdr.ipv4.totalLen = hdr.ipv4.totalLen + (bit<16>)meta._int.insert_byte_cnt;
         }

         // sink
         if( INT_IN_SINK(meta._int.int_node) && std_meta.instance_type == PKT_INSTANCE_TYPE_NORMAL){
             hdr.ipv4.dscp = meta._int.dscp;
             // restore length fields of IPv4 header and UDP header
             hdr.ipv4.totalLen = hdr.ipv4.totalLen - meta._int.total_int_length + 12;
         }
         
         if( hdr.ptp.isValid() ){
             //modif ptp field
             //hdr.ptp.correctionField = 1111;
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
        packet.emit(hdr.tcp_opt);
        packet.emit(hdr.udp);

        int_deparser.apply( packet, hdr._int );
        packet.emit(hdr.ptp);
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