from scapy.all import *

# Define the PTPv2 Header structure (based on IEEE 1588)
class PTPv2(Packet):
    name = "PTPv2"
    MSG_TYPES = {
        0x0: "Sync",
        0x2: "PdelayReqest",
        0x3: "PdelayResponse",
        0x8: "FollowUp",
        0xA: "PdelayResponseFollowUp",
    }

    fields_desc = [
        BitField("transportSpecific", 1, 4),
        BitField("messageType", 0, 4, MSG_TYPES),  # 4-bit message type
        BitField("reserved_1", 1, 4),
        BitField("versionPTP", 2, 4),  # 4-bit version of PTP (usually 2)
        ShortField("messageLength", 34),  # Length of the PTP message
        ByteField("domainNumber", 0),  # PTP domain number
        ByteField("reserved_2", 0),  # Reserved
        ShortField("flagField", 0), 
        LongField("correctionField", 0),  # Correction field (64 bits)
        IntField("reserved_3", 0),  # Reserved
        LongField("sourcePortIdentity", 0x123456789ABC),  # Source Port Identity
        ShortField("sequenceId", 1),  # Sequence ID
        ByteField("controlField", 0),  # Control field
        ByteField("logMessageInterval", 0)  # Log message interval
    ]
    '''
    fields_desc = [
        BitField("majorSdoId", 1, 4),
        BitEnumField("messageType", 0, 4, MSG_TYPES),
        XBitField("minorVersionPTP", 0, 4),
        BitField("versionPTP", 0x2, 4),
        ShortField("messageLength", 34),
        ByteField("domainNumber", 0),
        XByteField("minorSdoId", 0),
        FlagsField("flags", 0, 16, FLAGS),
        LongField("correctionField", 0),
        XIntField("messageTypeSpecific", 0),
        LongField("sourcePortIdentity", None),
        ShortField("sequenceId", 0),
        XByteField("controlField", 0),
        SignedByteField("logMessageInterval", -3),
    ]
    '''
# Register the custom PTPv2 protocol in Scapy
bind_layers(UDP, PTPv2, sport=319)  # PTP over UDP uses source port 319

# Create a PTP over UDP packet
def create_ptp_udp_packet():
    # Ethernet layer
    eth = Ether(dst="01:1B:19:00:00:00", src="00:11:22:33:44:55")
    # IP layer
    ip = IP(src="10.0.1.1", dst="10.0.2.2")
    # UDP layer
    udp = UDP(sport=319, dport=319)  # PTP uses port 319 for event messages
    # PTPv2 layer
    ptp = PTPv2(
        messageType=0,  # Sync message
        versionPTP=2,  # PTP version 2
        sequenceId=1001,  # Example sequence ID
        sourcePortIdentity=0x123456789ABCDEF,  # Example source port identity
    )
    # Combine layers
    pkt = eth / ip / udp / ptp
    return pkt

# Send the PTP over UDP packet
if __name__ == "__main__":
    ptp_packet = create_ptp_udp_packet()
    ptp_packet.show()  # Display the packet structure
    #sendp(ptp_packet, iface="eth0")  # Send packet on interface 'eth0'
    
    pcap_file = "ptp_packet.pcap"  # File name to save the packet
    wrpcap(pcap_file, ptp_packet)  # Save the packet to a PCAP file
