
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

def analyze_packet(packet):

    if IP in packet:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)

        print("\n========== PACKET CAPTURED ==========")
        print("Timestamp:", timestamp)
        print("Source IP:", source_ip)
        print("Destination IP:", destination_ip)
        print("Packet Size:", packet_size, "bytes")

        if TCP in packet:
            print("Protocol: TCP")
            print("Source Port:", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif UDP in packet:
            print("Protocol: UDP")
            print("Source Port:", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif ICMP in packet:
            print("Protocol: ICMP")

        else:
            print("Protocol: Other IP")

        print("=====================================")


print("====================================")
print("       NETWORK PACKET SNIFFER")
print("====================================")
print("Interface: eth0")
print("Capturing up to 20 packets...")
print("Maximum duration: 30 seconds")
print("Press Ctrl+C to stop early.")

try:
    sniff(
        iface="eth0",
        prn=analyze_packet,
        count=20,
        timeout=30,
        store=False
    )

except PermissionError:
    print("Permission denied. Run using sudo.")

except KeyboardInterrupt:
    print("\nCapture stopped by user.")

print("\nPacket capture completed.")
