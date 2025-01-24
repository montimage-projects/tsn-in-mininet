from scapy.all import Packet, rdpcap, sniff, bind_layers, Raw, BitField, ByteField, FieldListField
from scapy.layers.l2 import Ether

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

import argparse, sys, time

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
        BitField("switchId", 0, 16),
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
            print("-" * 50)
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
            analyse_reports(reports)

def analyse_reports(reports):
    elem = dict()
    elem["time"] = int(time.time() * 1000)  # Current time in miliseconds since epoch
    
    # get delay of each switch
    for report in reports:
        elem[ report.switchId ] = report.egressTstamp - report.ingressTstamp
    
    push_stat_to_http_server( elem )

# Lock to safely update the shared number
number_lock = threading.Lock()
# Global variables for tracking statistics
data_history = []  # List to store historical bandwidth data points
MAX_HISTORY_LENGTH = 100  # Maximum number of data points to store

def push_stat_to_http_server( elem ):
    with number_lock:
        # append element to tail of queue
        data_history.append( elem )
            # Trim history to the maximum length
        if len(data_history) > MAX_HISTORY_LENGTH:
            data_history.pop(0)


## HTTP server to expose data to grafana
# Custom HTTP handler
class CustomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global data_history

        json_data = ""
        # Read the shared number safely
        with number_lock:
            json_data = json.dumps( data_history )

        # Respond with the current number in JSON format
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json_data.encode("utf-8"))

# Function to run the HTTP server in a separate thread
def run_http_server(ip, port):

    server = HTTPServer((ip, port), CustomHandler)
    print(f"HTTP server is running on port {port}...")
    server.serve_forever()

def start_http_server_thread(ip, port):
    # Start the HTTP server in a separate thread
    server_thread = threading.Thread(target=run_http_server, args=(ip, port))
    # Allow the program to exit even if the thread is running
    server_thread.daemon = True
    server_thread.start()
## end HTTP server

# Main entry point
if __name__ == "__main__":
        # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Sniff packets from a given network and extract its PTP protocol.")
    parser.add_argument("--nic", default="eth0", help="Network interface to be sniffed")
    parser.add_argument("--ip",   default="127.0.0.1", help="IP of HTTP server to expose stats to Grafana")
    parser.add_argument("--port", default=4000, help="Port number of HTTP server to expose stats to Grafana")

    args = parser.parse_args()
    interface = args.nic

    try:
        start_http_server_thread( args.ip, args.port )

        print(f"Sniffing on interface: {interface}")
        # Filter for Ethernet frames with PTP EtherType
        sniff(iface=interface, filter=f"ether proto {PTP_ETHERTYPE}", prn=analyze_packet)
        
        #read the pcap file and extract the features for each packet
        #all_packets = rdpcap("pcaps/s3-eth2_out.pcap")
        # for each packet in the pcap file

        #i = 0
        #for packet in all_packets:
        #    print(i, "-" * 50)
        #    analyze_packet(packet)
        #    i += 1
        #    if i > 10:
        #        break

    except:
        raise
    finally:
        print("\nStopped sniffing.")
