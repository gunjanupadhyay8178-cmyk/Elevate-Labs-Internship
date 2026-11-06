
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
from collections import defaultdict, deque
import sqlite3
import os
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.path.join(BASE_DIR, "Captured_Data")
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "packets.db")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    packet_size INTEGER
)
""")
conn.commit()

# Detection settings
PORT_THRESHOLD = 10
PORT_WINDOW = 10

FLOOD_THRESHOLD = 20
FLOOD_WINDOW = 5

port_activity = defaultdict(deque)
packet_activity = defaultdict(deque)

alerted_scans = set()
alerted_floods = set()


def analyze_packet(packet):

    if IP not in packet:
        return

    now = time.monotonic()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src = packet[IP].src
    dst = packet[IP].dst
    size = len(packet)

    protocol = "OTHER"
    sport = None
    dport = None

    if TCP in packet:
        protocol = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    # Store packet in SQLite
    cursor.execute("""
        INSERT INTO packets (
            timestamp, source_ip, destination_ip,
            protocol, source_port, destination_port,
            packet_size
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp, src, dst, protocol,
        sport, dport, size
    ))

    conn.commit()

    print(f"[SAVED] {protocol} | {src} -> {dst} | {size} bytes")

    # Flood detection: packets within 5 seconds
    packet_activity[src].append(now)

    while packet_activity[src] and now - packet_activity[src][0] > FLOOD_WINDOW:
        packet_activity[src].popleft()

    if len(packet_activity[src]) > FLOOD_THRESHOLD:
        if src not in alerted_floods:
            print(f"[ALERT] HIGH TRAFFIC BURST from {src}")
            alerted_floods.add(src)

    # Port scan detection: unique TCP SYN destination ports
    if TCP in packet and (int(packet[TCP].flags) & 0x02):
        port_activity[src].append((now, dport))

    while port_activity[src] and now - port_activity[src][0][0] > PORT_WINDOW:
        port_activity[src].popleft()

    unique_ports = {port for _, port in port_activity[src]}

    if len(unique_ports) >= PORT_THRESHOLD:
        if src not in alerted_scans:
            print(f"[ALERT] POSSIBLE PORT SCAN from {src}")
            print("Unique destination ports:", len(unique_ports))
            alerted_scans.add(src)


print("NETWORK PACKET SNIFFER - TIME WINDOW DETECTION")
print("Interface: eth0")
print("Port scan: 10 unique ports / 10 seconds")
print("Traffic burst: More than 20 packets / 5 seconds")

try:
    sniff(
        iface="eth0",
        prn=analyze_packet,
        count=200,
        timeout=120,
        store=False
    )

except KeyboardInterrupt:
    print("\nCapture stopped.")

finally:
    conn.close()
    print("\nCapture completed.")
