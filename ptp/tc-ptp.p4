/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*
E2E transparent clock with two-steps (with follow up) over UDP
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_VLAN = 0x8100;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;

/*
UDP ports for PTP frames:

Port | Message Type     | Examples
------------------------------------------------------------
319  | Event Messages   | Sync, Delay_Req, Pdelay_Req/Resp
320  | General Messages | Follow_Up, Delay_Resp, Management

*/

const bit<16> PTP_PORT_319 = 319;
const bit<16> PTP_PORT_320 = 320;

const bit<4> PTP_MSG_SYNC = 0x0;
const bit<4> PTP_MSG_F_UP = 0x8;

extern void ptp_counter_init(in bit<32> size);
extern void ptp_store_arrival_time(in bit<64> clockId, in bit<16> portId, in bit<16> seqId);
extern void ptp_capture_departure_time(in bit<64> clockId, in bit<16> portId, in bit<16> seqId);
extern void ptp_get_delay_time(in bit<64> clockId, in bit<16> portId, in bit<16> seqId, out bit<64> delay);

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
    //bit<64> correctionField;
    bit<48> correctionNs;
    bit<16> correctionSubNs;
    bit<32> reserve_3;
    bit<64> clockId;
    bit<16> portId;
    bit<16> sequenceId;
    bit<8> controlField;
    bit<8> logMessageInterval;
}

/*
A sync and its follow_up messages are correlated using clockID (64bits) + portID (16bit) + sequenceID (16bit)
=> a key of 96bits 
*/
struct ptp_key_t {
    bit<80> sourcePortIdentity;
    bit<16> sequenceId;
}

struct metadata {
    /* empty */
    //int_metadata _int;
}

struct headers {
    ethernet_t   ethernet;
    vlan_h       vlan;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    ptp_t        ptp;

   tcp_option_t[MAX_TCP_OPTION_WORD] tcp_opt;

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
            default : parse_tcp_option;
        }
    }

    state parse_tcp_option {
        packet.extract( hdr.tcp_opt.next );
        tcp_opt_cnt = tcp_opt_cnt - 1;
        transition select( tcp_opt_cnt ){
            default: parse_tcp_option;
        }
    }


    state parse_udp {
        packet.extract(hdr.udp);
        
        transition select(hdr.udp.dstPort) {
           PTP_PORT_319 : parse_ptp;
           PTP_PORT_320 : parse_ptp;
           default      : accept;
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

    //ptp_key_t ptp_key;
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
         ptp_counter_init(10); //can store at most 10 sync messages
         if (hdr.ipv4.isValid() ){
            if( hdr.ipv4.dstAddr == 0xE0000181 ){ //224.0.1.129
                unicast.apply();
            }
            else ipv4_lpm.apply();

            //PTPv2
            // if we got a PTP packet
            if( hdr.udp.isValid() ){
               //ptp_key.sourcePortIdentity = hdr.ptp.sourcePortIdentity;
               //ptp_key.sequenceId         = hdr.ptp.sequenceId;
               
               // if we see a sync message (which needs to be sent on UDP port 319
               if ( hdr.ptp.messageType == PTP_MSG_SYNC && hdr.udp.dstPort == PTP_PORT_319 ){
                  //rember its arrival time
                  ptp_store_arrival_time( hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId );
                  //require to capture its departure time
                  ptp_capture_departure_time( hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId );
               }
            }
         }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    bit<64> correctionNs;
    
    apply {
         // Prune multicast packet to ingress port to preventing loop
         if (std_meta.egress_port == std_meta.ingress_port){
            mark_to_drop(std_meta);
            return;
         }
         
         //PTPv2
         // if we got a PTP packet
         if( hdr.udp.isValid() ){
            //ptp_key.sourcePortIdentity = hdr.ptp.sourcePortIdentity;
            //ptp_key.sequenceId         = hdr.ptp.sequenceId;
            
            // if we see a follow_up message (which needs to be sent on UDP port 320)
            if ( hdr.ptp.messageType == PTP_MSG_F_UP && hdr.udp.dstPort == PTP_PORT_320 ){
               //get delay of sync message
               ptp_get_delay_time( hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId, correctionNs );
               
               log_msg("ptp delay = {}", {correctionNs});
               //add delay of its sync message to the correctionField
               hdr.ptp.correctionNs = hdr.ptp.correctionNs + (bit<48>)correctionNs;
            }
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