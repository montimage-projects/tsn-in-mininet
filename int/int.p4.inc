#ifndef __INBAND_NETWORK_TELEMETRY_V1__
#define __INBAND_NETWORK_TELEMETRY_V1__

#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL         0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE  1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE   2
#define PKT_INSTANCE_TYPE_COALESCED      3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION    5
#define PKT_INSTANCE_TYPE_RESUBMIT       6

const bit<6>  INT_IPv4_DSCP             = 0x20;   // indicates an INT header in the packet
const bit<16> INT_SHIM_HEADER_LEN_BYTES = 4;
const bit<8>  INT_TYPE_HOP_BY_HOP       = 1;

header int_shim_t {
   bit<8> int_type;
   bit<8> rsvd1;
   bit<8> len;    // the length of all INT headers and its data in 4-byte words
   bit<6> dscp;   // copy DSCP here
   bit<2> rsvd3;
}

const bit<16> INT_HEADER_LEN_BYTES = 8;
const bit<4>  INT_VERSION          = 2; //currently we support version 2.0

header int_header_t {
   bit<4>  ver;
   bit<2>  rep;
   bit<1>  c;
   bit<1>  e;
   bit<1>  m;
   bit<7>  rsvd1;
   bit<3>  rsvd2;
   bit<5>  hop_metadata_len;   // the length of the metadata added by a single INT node (4-byte words)
   bit<8>  remaining_hop_cnt;  // how many switches can still add INT metadata
   bit<16> instruction_mask;   
   bit<16> rsvd3;
}

const bit<16> INT_ALL_HEADER_LEN_BYTES = INT_SHIM_HEADER_LEN_BYTES + INT_HEADER_LEN_BYTES;

header int_switch_id_t {
   bit<32> switch_id;
}

header int_port_ids_t {
   bit<16> ingress_port_id;
   bit<16> egress_port_id;
}

header int_hop_latency_t {
   bit<32> hop_latency;
}

header int_q_occupancy_t {
   bit<8>  q_id;
   bit<24> q_occupancy;
}

header int_ingress_tstamp_t {
   bit<64> ingress_tstamp;
}

header int_egress_tstamp_t {
   bit<64> egress_tstamp;
}

header int_level2_port_ids_t {
   bit<16> ingress_port_id;
   bit<16> egress_port_id;
}

header int_egress_port_tx_util_t {
   bit<32> egress_port_tx_util;
}

header int_q_ingress_packets_t{
   bit<8> q_id;
   bit<24> value;
}

#define INT_NODE_NONE     0b000
#define INT_NODE_SOURCE   0b001
#define INT_NODE_SINK     0b010
#define INT_NODE_TRANSIT  0b100

const bit<8> CLONE_FIELD  = 1;
struct int_metadata{
   //the fields being marked will be copied when the current packet is cloned
   //  other fields will be reset to zero
   @field_list(CLONE_FIELD)
   bit<3>  int_node;          // is INT functionality enabled, if yes it will act as source, transit or sink node

   @field_list(CLONE_FIELD)
   bit<32> switch_id;         // INT switch id is configured by network controller

   // these 2 belows are used in egress stage, thus no need to remember them
   bit<16> insert_byte_cnt;   // counter of inserted INT bytes
   bit<8>  int_hdr_word_len;  // counter of inserted INT words

   // currently not used
   bit<16> sink_reporting_port;    // on which port INT reports must be send to INT collector

   @field_list(CLONE_FIELD)
   bit<48> ingress_tstamp;    // remember ingress timestamp from Ingress pipeline to Egress pipeline

   // this field cannot be obtained at ingress stage, thus, no need to remember it
   bit<48> egress_tstamp;

   @field_list(CLONE_FIELD)
   bit<16> ingress_port;     // remember ingress port from Ingress pipeline to Egress pipeline

   @field_list(CLONE_FIELD)
   bit<9> egress_port;       //egress port of the original packet

   @field_list(CLONE_FIELD)
   bit<19> enq_qdepth;

   @field_list(CLONE_FIELD)
   bit<6>  dscp; //backup the original IPv4 DSCP

   //4-tuples to identify the flows to perform INT
   bit<32> src_ip;
   bit<32> dst_ip;
   bit<16> src_port;
   bit<16> dst_port;


   @field_list(CLONE_FIELD)
   bit<16> total_int_length; //number of additional bytes that have been introduced by all INT nodes in the packet by INT
}


#define INT_IN_SOURCE( bit )  ( bit & INT_NODE_SOURCE  != 0 )
#define INT_IN_TRANSIT( bit ) ( bit & INT_NODE_TRANSIT != 0 )
#define INT_IN_SINK( bit )    ( bit & INT_NODE_SINK    != 0 )
#define IS_IN_INT_NODE( bit ) ( bit != INT_NODE_NONE )

// Enough room for previous 4 nodes worth of data
header int_data_t{
   varbit<1600> data;
}

struct int_headers {
   // INT headers (60bytes)
   int_shim_t                shim;         //4 bytes
   int_header_t              int_header;   //8 bytes
    
   // local INT node metadata  //48 bytes
   int_egress_port_tx_util_t egress_port_tx_util;
   int_egress_tstamp_t       egress_tstamp;
   int_hop_latency_t         hop_latency;
   int_ingress_tstamp_t      ingress_tstamp;
   int_port_ids_t            port_ids;
   int_level2_port_ids_t     level2_port_ids;
   int_q_occupancy_t         q_occupancy;
   int_switch_id_t           switch_id;

   // INT metadata of previoudes
   int_data_t                previous_data;
}

error
{
	INTShimLenTooShort,
	INTVersionNotSupported
}

/**
 * Parse an INT packet to get info.
 *
 * This parser must be always called even on a node which is not INT-enabled
 *   (neither source, nor transit, nor sink).
 * This is caused by the fact that we only know latter whether this node is INT-enabled or not,
 *   at the ingress.
 * Consequently, if this parser was not called, and latter we know that this node is source (or transit/sink)
 *   then we do not have any info on the packet to do INT.
 */
parser int_parser(packet_in packet, in bit<6> dscp, 
      in bit<32> src_ip, in bit<16> src_port, in bit<32> dst_ip, in bit<16> dst_port,
      out int_headers hdr, inout int_metadata meta, in standard_metadata_t std_meta ) {

   bit<32> hop_data_len;

   state start {
      log_msg("\n\n==INT new packet arrived =============");
      //remember the original dscp so that we can restore it when sinking its packet
      meta.dscp     = dscp;
      meta.src_ip   = src_ip;
      meta.src_port = src_port;
      meta.dst_ip   = dst_ip;
      meta.dst_port = dst_port;

      //by default, we suppose that no INT in this packet
      meta.int_node = INT_NODE_NONE;
      meta.insert_byte_cnt = 0;

      // in case of frame clone for the INT sink reporting
      // ingress timestamp is not available on Egress pipeline
      meta.ingress_tstamp = std_meta.ingress_global_timestamp;
      log_msg("==ingress_timestamp: {}", {meta.ingress_tstamp});
      meta.ingress_port   = (bit<16>)std_meta.ingress_port;

      transition select(dscp){
         INT_IPv4_DSCP: parse_int;
         default      : accept; 
      }
   }

   state parse_int {
      packet.extract( hdr.shim );
      packet.extract( hdr.int_header );

      meta.dscp = hdr.shim.dscp;
      meta.total_int_length = ((bit<16>)hdr.shim.len << 2);

      //parse previous INT data
      // no need to see what are inside
      // only parse to be able to ignore them when sink
      hop_data_len = (bit<32>) hdr.shim.len;
      if( hop_data_len > 3 )
         //3 words (12 bytes) of INT fixed headers (SHIM + INT_HEADER)
         hop_data_len = hop_data_len - 3;
      else 
         hop_data_len = 0;
      log_msg("==INT.parser: parsing {} words (= {} bits) of previous data", {hop_data_len, ( hop_data_len * 8 * 4) });

      transition select( hop_data_len){
         0      : accept;
         default: parse_previous_int_data;
      }
   }

   state parse_previous_int_data {
      //hop_data_len 'unit is words => 4 bytes => num bit = 8 * 4 
      packet.extract( hdr.previous_data, (bit<32>)( hop_data_len * 8 * 4) );
      transition accept;
   }
}



/**
 * This control is called to configure INT source
 */
control __config_source(inout int_headers hdr, inout int_metadata meta, in standard_metadata_t std_meta) {
   // Configure parameters of INT source node
   // max_hop - how many INT nodes can add their INT node metadata
   // hope_metadata_len - how INT metadata words are added by a single INT node
   // ins_mask - instruction_mask defining which information (INT headers types) must added to the packet
   action set_source(bit<8> max_hop, bit<5> hop_metadata_len, bit<16> ins_mask) {
      log_msg("==INT== source: max_hop: {}, hop_metadata_len: {}, ins_mask: {}",{max_hop, hop_metadata_len, ins_mask});
      meta.int_node = meta.int_node | INT_NODE_SOURCE;

      //when INT is enable, we add 2 headers: SHIM, INT into packets
      // According to the P4_16 spec, pushed elements are invalid, so we need
      // to call setValid(). Older bmv2 versions would mark the new header(s)
      // valid automatically (P4_14 behavior), but starting with version 1.11,
      // bmv2 conforms with the P4_16 spec.
      hdr.shim.setValid();  //mark this header is valid so that it will be emited into packets
      hdr.shim.int_type = INT_TYPE_HOP_BY_HOP;
      hdr.shim.len      = (bit<8>)INT_ALL_HEADER_LEN_BYTES>>2;
      hdr.shim.dscp     = meta.dscp;
      //note: do note set dscp here as it was set in int_parser
      
      hdr.int_header.setValid();  //mark this header is valid so that it will be emited into packets
      hdr.int_header.ver   = INT_VERSION;
      hdr.int_header.rep   = 0;
      hdr.int_header.c     = 0;
      hdr.int_header.e     = 0;
      hdr.int_header.rsvd1 = 0;
      hdr.int_header.rsvd2 = 0;
      hdr.int_header.hop_metadata_len  = hop_metadata_len;
      hdr.int_header.remaining_hop_cnt = max_hop;  //will be decreased immediately by 1 within transit process
      hdr.int_header.instruction_mask  = ins_mask;
   }
   
   // INT source must be configured per each flow which must be monitored using INT
   // Flow is defined by src IP, dst IP, src TCP/UDP port, dst TCP/UDP port 
   // When INT source configured for a flow then a node adds INT shim header and first INT node metadata headers
   table tb_int_config_source {
      actions = {
         set_source;
      }
      key = {
         //ternary matching takes into account mask, 
         // e.g., 192.168.1.1 &&&& 0xFFFFFF00 to match IP in range 192.168.1.0 to 192.168.1.255
         meta.src_ip    : ternary;
         meta.src_port  : ternary;
         meta.dst_ip    : ternary;
         meta.dst_port  : ternary;
      }
      size = 127;
   }

   apply {
      log_msg("==INT== __config_source dscp={}, src_ip={}", {hdr.shim.dscp, meta.src_ip});
      tb_int_config_source.apply();
   }
}

/**
 * This control is called by any node when an INT packet passing throught it
 */

const bit<32> REPORT_MIRROR_SESSION_ID = 1;
control __config_int( inout int_headers hdr, inout int_metadata meta, inout standard_metadata_t std_meta ) {
   action set_sink(bit<16> sink_reporting_port) {
      meta.int_node = meta.int_node | INT_NODE_SINK;
      meta.sink_reporting_port = sink_reporting_port;
      log_msg("==INT== tb_int_config sink_reporting_port={}", {sink_reporting_port});
   }

   action set_transit( bit<32> switch_id ) {
      // mark this node as TRANSITE only when the packet is in INT
      meta.int_node = meta.int_node | INT_NODE_TRANSIT;
      meta.switch_id = switch_id;
      log_msg("==INT== tb_int_config switch_id={}", {switch_id});
   }

   //table used to activate/desactivate INT sink for particular egress port of the switch
   table tb_int_config_sink {
       actions = {
           set_sink;
       }
   }
   table tb_int_config {
       actions = {
           set_transit;
       }
   }
   apply {
      tb_int_config.apply();
      tb_int_config_sink.apply();
   }
}



control int_ingress(inout int_headers hdr, inout int_metadata meta, inout standard_metadata_t std_meta) {
   apply {
      //apply INT source logic on INT monitored flow
      __config_source.apply( hdr, meta, std_meta);

      //shim isValid() when it is present
      // (it was created by source node that is either the current node or the one in the packet path)
      // => the current packet is INT

      if(! hdr.shim.isValid() )
         return;

      __config_int.apply( hdr, meta, std_meta);

      //remember meta data which will be copied to egress
      meta.enq_qdepth  = std_meta.enq_qdepth;
      meta.egress_port = std_meta.egress_port;

      if( INT_IN_SINK( meta.int_node )){
         /***
          * Calling clone_preserving_field_list during execution of the ingress
          * or egress control will cause the packet to be cloned, sometimes
          * also called mirroring, i.e. zero or more copies of the packet are
          * made, and each will later begin egress processing as an independent
          * packet from the original packet.  The original packet continues
          * with its normal next steps independent of the clone(s).
          *
          * More: https://github.com/p4lang/p4c/blob/1b47d14d072887bdc3970ed84e6bccee37a69981/p4include/v1model.p4#L632
          */
         clone_preserving_field_list(CloneType.I2E, REPORT_MIRROR_SESSION_ID, CLONE_FIELD);
         log_msg("===Just after calling clone_preserving_field_list" );
      }
   }
}

control __clear_int_header(inout int_headers hdr, inout int_metadata meta, inout standard_metadata_t std_meta) {

   apply {
        // remove INT headers from the current packet
      log_msg("==INT.sink removes INT header");
      // remove int data
      hdr.shim.setInvalid();
      hdr.int_header.setInvalid();
 
      // remove INT data added in INT sink by invalidate them
      hdr.switch_id.setInvalid();
      hdr.port_ids.setInvalid();
      hdr.ingress_tstamp.setInvalid();
      hdr.egress_tstamp.setInvalid();
      hdr.hop_latency.setInvalid();
      hdr.level2_port_ids.setInvalid();
      hdr.q_occupancy.setInvalid();
      hdr.egress_port_tx_util.setInvalid();
     
      //remove the previous INT data also
      hdr.previous_data.setInvalid();
   }
}


control __send_report(inout int_headers hdr, inout int_metadata meta, inout standard_metadata_t std_meta) {

   apply {
        // prepare an INT report for the INT collector
        //__report.apply(hdr, meta, standard_metadata);
        log_msg("==CLONED packet");
        //TODO:
        // - change IP dst to the INT collector
        // - appendother
   }
}


control __get_egress_meta(in standard_metadata_t std_meta, inout int_metadata meta) {

   apply {
      meta.egress_tstamp = std_meta.egress_global_timestamp;
   }
}

control __set_int_stat(inout int_headers hdr, inout int_metadata meta) {

        action int_set_header_0() {
            hdr.switch_id.setValid();
            log_msg("==INT== set switch_id");
            hdr.switch_id.switch_id = meta.switch_id; //switch_id was recorded in __transit_activate
        }
        action int_set_header_1() {
            hdr.port_ids.setValid();
            //hdr.port_ids.ingress_port_id = (bit<16>)standard_metadata.ingress_port;
            hdr.port_ids.ingress_port_id = meta.ingress_port;  //ingress_port was recorded in int_parser
            hdr.port_ids.egress_port_id  = (bit<16>)meta.egress_port;
            
        }
        action int_set_header_2() {
            hdr.hop_latency.setValid();
            hdr.hop_latency.hop_latency = (bit<32>)(meta.egress_tstamp - meta.ingress_tstamp); //a timestamp, in microseconds
        }
        action int_set_header_3() {
            hdr.q_occupancy.setValid();
            // no such metadata in v1model
            hdr.q_occupancy.q_id  = 0;
            hdr.q_occupancy.q_occupancy = (bit<24>)meta.enq_qdepth;
        }
        action int_set_header_4() {
            hdr.ingress_tstamp.setValid();
            bit<64> _timestamp = (bit<64>)meta.ingress_tstamp;  
            hdr.ingress_tstamp.ingress_tstamp = hdr.ingress_tstamp.ingress_tstamp + 1000 * _timestamp;
        }
        action int_set_header_5() {
            hdr.egress_tstamp.setValid();
            bit<64> _timestamp = (bit<64>)meta.egress_tstamp;
            hdr.egress_tstamp.egress_tstamp = hdr.egress_tstamp.egress_tstamp + 1000 * _timestamp;
        }
        action int_set_header_6() {
            hdr.level2_port_ids.setValid();
            // no such metadata in v1model
            hdr.level2_port_ids.ingress_port_id = 0;
            hdr.level2_port_ids.egress_port_id  = 0;
        }
        action int_set_header_7() {
            hdr.egress_port_tx_util.setValid();
            // no such metadata in v1model
            hdr.egress_port_tx_util.egress_port_tx_util = 0;
        }

        action add_1() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 1;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 4;
        }

        action add_2() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 2;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 8;
        }

        action add_3() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 3;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 12;
        }

        action add_4() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 4;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 16;
        }


        action add_5() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 5;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 20;
        }

        action add_6() {
            meta.int_hdr_word_len = meta.int_hdr_word_len + 6;
            meta.insert_byte_cnt = meta.insert_byte_cnt + 24;
        }

        // hdr.switch_id     0
        // hdr.port_ids       1
        // hdr.hop_latency    2
        // hdr.q_occupancy    3
        // hdr.ingress_tstamp  4
        // hdr.egress_tstamp   5
        // hdr.level2_port_ids   6
        // hdr.egress_port_tx_util   7

        action int_set_header_0003_i0() {
            ;
        }
        action int_set_header_0003_i1() {
            int_set_header_3();
            add_1();
        }
        action int_set_header_0003_i2() {
            int_set_header_2();
            add_1();
        }
        action int_set_header_0003_i3() {
            int_set_header_5();
            int_set_header_2();
            add_3();
        }
        action int_set_header_0003_i4() {
            int_set_header_1();
            add_1();
        }
        action int_set_header_0003_i5() {
            int_set_header_3();
            int_set_header_1();
            add_2();
        }
        action int_set_header_0003_i6() {
            int_set_header_2();
            int_set_header_1();
            add_2();
        }
        action int_set_header_0003_i7() {
            int_set_header_3();
            int_set_header_2();
            int_set_header_1();
            add_3();
        }
        action int_set_header_0003_i8() {
            int_set_header_0();
            add_1();
        }
        action int_set_header_0003_i9() {
            int_set_header_3();
            int_set_header_0();
            add_2();
        }
        action int_set_header_0003_i10() {
            int_set_header_2();
            int_set_header_0();
            add_2();
        }
        action int_set_header_0003_i11() {
            int_set_header_3();
            int_set_header_2();
            int_set_header_0();
            add_3();
        }
        action int_set_header_0003_i12() {
            int_set_header_1();
            int_set_header_0();
            add_2();
        }
        action int_set_header_0003_i13() {
            int_set_header_3();
            int_set_header_1();
            int_set_header_0();
            add_3();
        }
        action int_set_header_0003_i14() {
            int_set_header_2();
            int_set_header_1();
            int_set_header_0();
            add_3();
        }
        action int_set_header_0003_i15() {
            int_set_header_3();
            int_set_header_2();
            int_set_header_1();
            int_set_header_0();
            add_4();
        }
        action int_set_header_0407_i0() {
            ;
        }

        action int_set_header_0407_i1() {
            int_set_header_7();
            add_1();
        }
        action int_set_header_0407_i2() {
            int_set_header_6();
            add_1();
        }
        action int_set_header_0407_i3() {
            int_set_header_7();
            int_set_header_6();
            add_2();

        }
        action int_set_header_0407_i4() {
            int_set_header_5();
            add_2();
        }
        action int_set_header_0407_i5() {
            int_set_header_7();
            int_set_header_5();
            add_3();
        }
        action int_set_header_0407_i6() {
            int_set_header_6();
            int_set_header_5();
            add_3();
        }
        action int_set_header_0407_i7() {
            int_set_header_7();
            int_set_header_6();
            int_set_header_5();
            add_4();
        }
        action int_set_header_0407_i8() {
            int_set_header_4();
            add_2();
        }
        action int_set_header_0407_i9() {
            int_set_header_7();
            int_set_header_4();
            add_3();
        }
        action int_set_header_0407_i10() {
            int_set_header_6();
            int_set_header_4();
            add_3();
        }
        action int_set_header_0407_i11() {
            int_set_header_7();
            int_set_header_6();
            int_set_header_4();
            add_4();
        }
        action int_set_header_0407_i12() {
            int_set_header_5();
            int_set_header_4();
            add_4();
        }
        action int_set_header_0407_i13() {
            int_set_header_7();
            int_set_header_5();
            int_set_header_4();
            add_5();
        }
        action int_set_header_0407_i14() {
            int_set_header_6();
            int_set_header_5();
            int_set_header_4();
            add_5();
        }
        action int_set_header_0407_i15() {
            int_set_header_7();
            int_set_header_6();
            int_set_header_5();
            int_set_header_4();
            add_6();
        }


        table tb_int_inst_0003 {
            actions = {
                int_set_header_0003_i0;
                int_set_header_0003_i1;
                int_set_header_0003_i2;
                int_set_header_0003_i3;
                int_set_header_0003_i4;
                int_set_header_0003_i5;
                int_set_header_0003_i6;
                int_set_header_0003_i7;
                int_set_header_0003_i8;
                int_set_header_0003_i9;
                int_set_header_0003_i10;
                int_set_header_0003_i11;
                int_set_header_0003_i12;
                int_set_header_0003_i13;
                int_set_header_0003_i14;
                int_set_header_0003_i15;
            }
            key = {
                hdr.int_header.instruction_mask: ternary;
            }
            const entries = {
                0x0000 &&& 0xF000 : int_set_header_0003_i0();
                0x1000 &&& 0xF000 : int_set_header_0003_i1();
                0x2000 &&& 0xF000 : int_set_header_0003_i2();
                0x3000 &&& 0xF000 : int_set_header_0003_i3();
                0x4000 &&& 0xF000 : int_set_header_0003_i4();
                0x5000 &&& 0xF000 : int_set_header_0003_i5();
                0x6000 &&& 0xF000 : int_set_header_0003_i6();
                0x7000 &&& 0xF000 : int_set_header_0003_i7();
                0x8000 &&& 0xF000 : int_set_header_0003_i8();
                0x9000 &&& 0xF000 : int_set_header_0003_i9();
                0xA000 &&& 0xF000 : int_set_header_0003_i10();
                0xB000 &&& 0xF000 : int_set_header_0003_i11();
                0xC000 &&& 0xF000 : int_set_header_0003_i12();
                0xD000 &&& 0xF000 : int_set_header_0003_i13();
                0xE000 &&& 0xF000 : int_set_header_0003_i14();
                0xF000 &&& 0xF000 : int_set_header_0003_i15();
            }
            
        }

        table tb_int_inst_0407 {
            actions = {
                int_set_header_0407_i0;
                int_set_header_0407_i1;
                int_set_header_0407_i2;
                int_set_header_0407_i3;
                int_set_header_0407_i4;
                int_set_header_0407_i5;
                int_set_header_0407_i6;
                int_set_header_0407_i7;
                int_set_header_0407_i8;
                int_set_header_0407_i9;
                int_set_header_0407_i10;
                int_set_header_0407_i11;
                int_set_header_0407_i12;
                int_set_header_0407_i13;
                int_set_header_0407_i14;
                int_set_header_0407_i15;
            }
            key = {
                hdr.int_header.instruction_mask: ternary;
            }
            const entries = {
                0x0000 &&& 0x0F00 : int_set_header_0407_i0();
                0x0100 &&& 0x0F00 : int_set_header_0407_i1();
                0x0200 &&& 0x0F00 : int_set_header_0407_i2();
                0x0300 &&& 0x0F00 : int_set_header_0407_i3();
                0x0400 &&& 0x0F00 : int_set_header_0407_i4();
                0x0500 &&& 0x0F00 : int_set_header_0407_i5();
                0x0600 &&& 0x0F00 : int_set_header_0407_i6();
                0x0700 &&& 0x0F00 : int_set_header_0407_i7();
                0x0800 &&& 0x0F00 : int_set_header_0407_i8();
                0x0900 &&& 0x0F00 : int_set_header_0407_i9();
                0x0A00 &&& 0x0F00 : int_set_header_0407_i10();
                0x0B00 &&& 0x0F00 : int_set_header_0407_i11();
                0x0C00 &&& 0x0F00 : int_set_header_0407_i12();
                0x0D00 &&& 0x0F00 : int_set_header_0407_i13();
                0x0E00 &&& 0x0F00 : int_set_header_0407_i14();
                0x0F00 &&& 0x0F00 : int_set_header_0407_i15();
            }
        }


        action int_hop_cnt_increment() {
            hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        }
        action int_hop_exceeded() {
            hdr.int_header.e = 1w1;
        }

        action int_update_shim_ac() {
            hdr.shim.len = hdr.shim.len + (bit<8>)meta.int_hdr_word_len;
            meta.total_int_length = ((bit<16>)hdr.shim.len) << 2;
        }

        apply {
            log_msg("==INT transit, remaining_hop: {}", {hdr.int_header.remaining_hop_cnt});
            //TODO: check if hop-by-hop INT or destination INT

            // check if INT transit can add a new INT node metadata
            if (hdr.int_header.remaining_hop_cnt == 0 || hdr.int_header.e == 1) {
                int_hop_exceeded();
                return;
            }

            int_hop_cnt_increment();
            log_msg("==INT transit, instruction mask: {}", {hdr.int_header.instruction_mask});

            // add INT node metadata headers based on INT instruction_mask
            tb_int_inst_0003.apply();
            tb_int_inst_0407.apply();

            if (hdr.shim.isValid()) 
                int_update_shim_ac();
      }
}



control int_egress(inout int_headers hdr, inout int_metadata meta, inout standard_metadata_t std_meta) {
   apply {

      //we can be here 2 times:
      // - first time for the original packet,
      // - second time for the cloned packet that will be sent to INT collector using UDP

      // no INT
      if( ! IS_IN_INT_NODE( meta.int_node ))
          return;

      log_msg("===INT egress, shim: {}, int_node: {}, instance_type={}", {hdr.shim.int_type, meta.int_node, std_meta.instance_type});

      // remember the packet metadata: egress time, queue at the egress
      __get_egress_meta.apply( std_meta, meta );

      // when INT is enable, any node is transit node
      // => set stat in INT header
      __set_int_stat.apply( hdr, meta );


      // continue processing only for sink node
      if( ! INT_IN_SINK( meta.int_node ))
         return;

      // if we get a normal packet => clone it
      if (std_meta.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
         //remove INT
         __clear_int_header.apply( hdr, meta, std_meta );
      }
      else {
         __send_report.apply( hdr, meta, std_meta );
      }
   }
}


control int_deparser(packet_out packet, in int_headers hdr) {
   apply {
      log_msg("==INT_depasser: shim valid: {}, shim type: {}", {hdr.shim.isValid(), hdr.shim.int_type});
      // INT headers
      //"emit(header)" function appends the header to the packet_out only if the header is valid

      packet.emit(hdr.shim);
      packet.emit(hdr.int_header);

      // local INT node metadata
      packet.emit(hdr.switch_id);           //bit 1
      packet.emit(hdr.port_ids);            //bit 2
      packet.emit(hdr.hop_latency);         //bit 3
      packet.emit(hdr.q_occupancy);         // bit 4
      packet.emit(hdr.ingress_tstamp);      // bit 5
      packet.emit(hdr.egress_tstamp);       // bit 6
      packet.emit(hdr.level2_port_ids);     // bit 7
      packet.emit(hdr.egress_port_tx_util); // bit 8
      //previous INT data
      packet.emit(hdr.previous_data);
   }
}

#endif

