from scapy.all import sniff, IP, TCP, UDP, ICMP

print("=" * 60)
print("       CODEALPHA - BASIC NETWORK SNIFFER")
print("=" * 60)

print("\nSelect Protocol:")
print("1. All")
print("2. TCP")
print("3. UDP")
print("4. ICMP")

choice = input("\nEnter your choice (1-4): ")

filters = {
    "1": None,
    "2": "tcp",
    "3": "udp",
    "4": "icmp"
}

if choice not in filters:
    print("Invalid choice. Exiting.")
    exit()

protocol_filter = filters[choice]

print("\nCapturing 10 packets...")
print()

packet_count = 0


def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_length = len(packet)

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"

    else:
        protocol = "Other"
        source_port = "-"
        destination_port = "-"

    if packet.payload:
        payload_present = "Yes"
        payload_length = len(bytes(packet.payload))
    else:
        payload_present = "No"
        payload_length = 0

    print("-" * 60)
    print(f"Packet Number    : {packet_count}")
    print(f"Source IP        : {source_ip}")
    print(f"Destination IP   : {destination_ip}")
    print(f"Protocol         : {protocol}")
    print(f"Source Port      : {source_port}")
    print(f"Destination Port : {destination_port}")
    print(f"Packet Length    : {packet_length} bytes")
    print(f"Payload Present  : {payload_present}")
    print(f"Payload Length   : {payload_length} bytes")


sniff(
    filter=protocol_filter,
    prn=analyze_packet,
    count=10
)

print("\n" + "=" * 60)
print("Packet capture completed.")
print(f"Total IP packets analyzed: {packet_count}")
print("=" * 60)