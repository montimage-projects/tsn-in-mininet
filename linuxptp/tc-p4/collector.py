from scapy.all import *
from scapy.layers.l2 import Ether

import argparse, sys

# Define constants for PTPv2 protocol
# EtherType for PTPv2 over Ethernet
PTP_ETHERTYPE = 0x88F7

PTP_MSG_TYPE_SYNC           = 0x0
PTP_MSG_TYPE_FOLLOW_UP      = 0x8
PTP_MSG_TYPE_DELAY_REQUEST  = 0x1
PTP_MSG_TYPE_DELAY_RESPONSE = 0x9

# standard size of each message
PTP_MSG_LEN_FOLLOW_UP = 44
# 44 bytes + 10 bytes of request IDs (8bytes of clockId + 2 bytes of portId)
PTP_MSG_LEN_DELAY_RESPONSE = 54

class PTP(Packet):
    fields_desc = [ 
        BitField("transportSpecific", 0, 4),
        BitField("messageType", 0, 4),
        BitField("reserve_1", 0, 4),
        BitField("versionPTP", 0, 4),
        BitField("messageLength", 0, 16),
        BitField("domainNumber", 0, 8),
        BitField("reserve_2", 0, 8),
        BitField("flagField", 0, 16),
        BitField("correctionNs", 0, 48),
        BitField("correctionSubNs", 0, 16),
        BitField("reserve_3", 0, 32),
        BitField("clockId", 0, 64),
        BitField("portId", 0, 16),
        BitField("sequenceId", 0, 16),
        BitField("controlField", 0, 8),
        BitField("logMessageInterval", 0, 8),
        BitField("tsSeconds", 0, 48),
        BitField("tsNanoSeconds", 0, 32),
    ]

class PtpDelayResponse(Packet):
    fields_desc = [ 
        BitField("requestClockId", 0, 64),
        BitField("requestPortId", 0, 16)
    ]

PTP_TLV_INT_TYPE  = 0x0010
class TLV(Packet):
    fields_desc = [ 
        BitField("tlvType", 0, 16),
        BitField("tlvLength", 0, 16),
        # Value field will be dynamically parsed based on the length
        FieldListField("tlvData", [], ByteField("", 0), length_from=lambda pkt: pkt.tlvLength)  # Value (variable length)
    ]

class INT(Packet):
    fields_desc = [ 
        BitField("switchId", 0, 64),
        BitField("ingressTstamp", 0, 64), #timestamp in nanosecond
        BitField("egressTstamp", 0, 64)   #timestamp in nanosecond
    ]


bind_layers(Ether, PTP, type=PTP_ETHERTYPE)
bind_layers(PTP, PtpDelayResponse, messageType=PTP_MSG_TYPE_DELAY_RESPONSE)

# Parse multiple TLVs to retrieve INT reports from the raw payload
def parse_int_reports(rawPayload):
    offset  = 0
    reports = []
    # parse all TLV extension elements
    while offset < len(rawPayload):
        # Extract the current TLV
        tlv = TLV(rawPayload[offset:])
        
        print(f"TLV type: {tlv.tlvType}")
        
        # Move the offset by the TLV header size (4 bytes) + TLV length
        offset += 4 + tlv.tlvLength
        
        #parse our inband-network telemetry report
        if tlv.tlvType == PTP_TLV_INT_TYPE:
            report = INT(bytes(tlv.tlvData))
            #print(report.switchId, report.ingressTstamp, report.ingressTstamp)
            reports.append( report )

    return reports

# Function to analyze the packet
def analyze_packet(packet):
    if Ether in packet:
        eth = packet[Ether]
        if eth.type == PTP_ETHERTYPE:  # Check for PTPv2 EtherType
            print("PTPv2 Packet Detected!")
            print(f"Source MAC: {eth.src}")
            print(f"Destination MAC: {eth.dst}")
            print(f"EtherType: {hex(eth.type)}")
            
            # no PTP
            if PTP not in packet:
                return
                
            ptp = packet[PTP]
                
            print(f"PTP length : {ptp.messageLength}")

            # no more data
            if not Raw in packet:
                return

            # we are interested in only follow_up and delay_response messages
            if ptp.messageType not in [PTP_MSG_TYPE_FOLLOW_UP, PTP_MSG_TYPE_DELAY_RESPONSE]:
                return
            
            ptpMsgLen = PTP_MSG_LEN_FOLLOW_UP
            if ptp.messageType == PTP_MSG_TYPE_DELAY_RESPONSE:
                ptpMsgLen = PTP_MSG_LEN_DELAY_RESPONSE
            
            
            # there is no TLV extensions
            if ptpMsgLen >= ptp.messageLength:
                return
            
            tlvRawLen = ptp.messageLength - ptpMsgLen
            rawPayload = packet[Raw].load
            reports = parse_int_reports( rawPayload[0:tlvRawLen] )
            print(reports)

# Main entry point
if __name__ == "__main__":
        # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Sniff packets from a given network and extract its PTP protocol.")
    parser.add_argument("--nic", default="eth0", help="Network interface to be sniffed")
    
    args = parser.parse_args()
    interface = args.nic

    try:
        print(f"Sniffing on interface: {interface}")
        # Filter for Ethernet frames with PTP EtherType
        #sniff(iface=interface, filter=f"ether proto {PTP_ETHERTYPE}", prn=analyze_packet)
        
        #read the pcap file and extract the features for each packet
        all_packets = rdpcap("pcaps/s3-eth2_out.pcap")
        # for each packet in the pcap file
        i = 0
        for packet in all_packets:
            print(i, "-" * 50)
            analyze_packet(packet)
            i += 1
            if i > 10:
                break

    except:
        raise
    finally:
        print("\nStopped sniffing.")
