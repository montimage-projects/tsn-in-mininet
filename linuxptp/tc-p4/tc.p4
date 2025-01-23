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
const bit<16> TYPE_PTP  = 0x88F7; //PTPV2 over Ethernet
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

const bit<4> PTP_MSG_SYNC           = 0x0;
const bit<4> PTP_MSG_FOLLOW_UP      = 0x8;
const bit<4> PTP_MSG_DELAY_REQUEST  = 0x1;
const bit<4> PTP_MSG_DELAY_RESPONSE = 0x9;

/**
Get the timestamp of the current packet when it arrived at its input NIC
*/
extern void get_ingress_mac_tstamp(out bit<64> tx_tstamp);

/**
Initialize a circular table within a given capacity.
- Each element of the table is used to store ingress_mac_tstamp and egress_mac_tstamp of a packet.
- Each element is distinguished by a 3-tuple (clockId, portId, seqId) 
*/
extern void ptp_counter_init(in bit<32> capacity);

/**
Add an element into the circular table to store ingress_mac_tstamp of the current packet.
*/
extern void ptp_store_ingress_mac_tstamp(in bit<64> clockId, in bit<16> portId, in bit<16> seqId);

/**
Get the ingress_mac_tstamp which was stored when calling the function ptp_store_ingress_mac_tstamp.
*/
extern void ptp_get_ingress_mac_tstamp(in bit<64> clockId, in bit<16> portId, in bit<16> seqId, out bit<64> rx_tstamp);

/**
Tell BMv2 (simple_switch) to capture the egress_mac_tstamp of the current packet.
The egress_mac_tstamp represents the moment the packet is sent out of its output NIC.
Thus (egress_mac_tstamp - ingress_mac_tstamp) represents the interval the packet sejourn in BMv2.
*/
extern void ptp_capture_egress_mac_tstamp(in bit<64> clockId, in bit<16> portId, in bit<16> seqId);

/**
Get the egress_mac_tstamp which was required to be captured when calling ptp_capture_egress_mac_tstamp.
Note: this function will blocks until goting egress_mac_tstamp (i.e., until the packet was sent).
*/
extern void ptp_get_egress_mac_tstamp(in bit<64> clockId, in bit<16> portId, in bit<16> seqId, out bit<64> tx_tstamp);



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
    //correctionField;
    bit<48> correctionNs;
    bit<16> correctionSubNs;
    bit<32> reserve_3;
    bit<64> clockId;
    bit<16> portId;
    bit<16> sequenceId;
    bit<8> controlField;
    bit<8> logMessageInterval;
    bit<48> tsSeconds;
    bit<32> tsNanoSeconds;
}

header ptp_res_t {
    bit<64> requestClockId;
    bit<16> requestPortId;
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
    ptp_res_t    ptp_res;

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
        //log_msg("start parsing");
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_VLAN: parse_vlan; 
            TYPE_IPV4: parse_ipv4;
            TYPE_PTP : parse_ptp;
            default: accept;
        }
    }

    state parse_vlan {
        //log_msg("Parsing VLAN=====");
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.etherType){
            //TYPE_VLAN: parse_vlan; //vlan in vlan 
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        //log_msg("parsing IPv4");
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        //log_msg("parsing TCP");
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
            0       : accept; //no option
            default : parse_tcp_option;
        }
    }

    state parse_tcp_option {
        packet.extract( hdr.tcp_opt.next );
        tcp_opt_cnt = tcp_opt_cnt - 1;
        transition select( tcp_opt_cnt ){
            0      : accept; //no more option
            default: parse_tcp_option;
        }
    }


    state parse_udp {
        //log_msg("parsing UDP");
        packet.extract(hdr.udp);
        
        transition select(hdr.udp.dstPort) {
           PTP_PORT_319 : parse_ptp;
           PTP_PORT_320 : parse_ptp;
           default      : accept;
        }
    }

    state parse_ptp {
        //log_msg("parsing PTP");
        packet.extract(hdr.ptp);
        transition select(hdr.ptp.messageType) {
            PTP_MSG_DELAY_RESPONSE : parse_ptp_response;
            default                : accept;
        }
    }

    state parse_ptp_response {
        //log_msg("parsing PTP Response");
        packet.extract(hdr.ptp_res);
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
    action mac_forward(macAddr_t srcAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
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
    table mac_unicast {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            mac_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    apply {
         ptp_counter_init(10); //can store at most 10 sync messages
         
         //when we have an IP packet
         if (hdr.ipv4.isValid() ){
            if( hdr.ipv4.dstAddr == 0xE0000181 ){ //224.0.1.129
                unicast.apply();
            }
            else ipv4_lpm.apply();
         }
         // when we have an Ethernet packet 
         else if( hdr.ethernet.isValid() ){
            mac_unicast.apply();
         }
         
         //PTPv2
         // if we got a PTP packet
         if( hdr.ptp.isValid() ){
            //ptp_key.sourcePortIdentity = hdr.ptp.sourcePortIdentity;
            //ptp_key.sequenceId         = hdr.ptp.sequenceId;
            
            // if we see a sync message (which needs to be sent on UDP port 319
            if ( hdr.ptp.messageType == PTP_MSG_SYNC 
              || hdr.ptp.messageType == PTP_MSG_DELAY_REQUEST  ){
               //rember its arrival time
               //log_msg("ptp_store_arrival_time({}, {}, {})", {hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId});
               ptp_store_ingress_mac_tstamp( hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId );
               //require to capture its departure time
               ptp_capture_egress_mac_tstamp( hdr.ptp.clockId, hdr.ptp.portId, hdr.ptp.sequenceId );
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
    bit<64> ingressNs;
    bit<64> egressNs;
    bit<64> correctionNs;
    
    bit<64> clockId;
    bit<16> portId;
    
    apply {
         // Prune multicast packet to ingress port to preventing loop
         if (std_meta.egress_port == std_meta.ingress_port){
            mark_to_drop(std_meta);
            return;
         }
         
         //PTPv2
         // if we got a PTP packet
         if( hdr.ptp.isValid() ){
            //ptp_key.sourcePortIdentity = hdr.ptp.sourcePortIdentity;
            //ptp_key.sequenceId         = hdr.ptp.sequenceId;
            
            // if we see a follow_up message
            if ( hdr.ptp.messageType == PTP_MSG_FOLLOW_UP 
              || hdr.ptp.messageType == PTP_MSG_DELAY_RESPONSE  
              ){
               // by default we use the clockId and portId of the actual packet to correlate
               clockId = hdr.ptp.clockId;
               portId  = hdr.ptp.portId;
            
               // in case of delay_req and delay_res messages,
               //  the master will report clockId and portId of delay_req message
               //  at the end of delay_res message.
               //  => Thus delay_res message contains 2 clockId values: 
               //   one is of master, another (at the end) is belong to the slave who
               //   requested (via delay_req message)
               if ( hdr.ptp.messageType == PTP_MSG_DELAY_RESPONSE ){
                   clockId = hdr.ptp_res.requestClockId;
                   portId  = hdr.ptp_res.requestPortId;
               }
               //get delay of sync message
               ptp_get_ingress_mac_tstamp( clockId, portId, hdr.ptp.sequenceId, ingressNs );
               ptp_get_egress_mac_tstamp(  clockId, portId, hdr.ptp.sequenceId, egressNs );
               
               correctionNs = egressNs - ingressNs;
               //log_msg("ptp delay = {}", {correctionNs});
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
        packet.emit(hdr.ptp_res);
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