import sqlite3
import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime
import os

# Database and output paths
DB_PATH = "Captured_Data/packets.db"
OUTPUT_DIR = "Reports"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Connect to database
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Fetch packet data
cursor.execute("""
    SELECT timestamp, source_ip, protocol, packet_size
    FROM packets
""")

packets = cursor.fetchall()
conn.close()

if not packets:
    print("No packet data found!")
    exit()

timestamps = [row[0] for row in packets]
source_ips = [row[1] for row in packets]
protocols = [row[2] for row in packets]

# 1. Protocol Distribution
protocol_counts = Counter(protocols)

plt.figure(figsize=(8, 6))
plt.pie(
    protocol_counts.values(),
    labels=protocol_counts.keys(),
    autopct="%1.1f%%"
)
plt.title("Network Protocol Distribution")
plt.savefig(f"{OUTPUT_DIR}/protocol_distribution.png")
plt.close()

# 2. Top 10 Source IPs
ip_counts = Counter(source_ips)
top_ips = ip_counts.most_common(10)

plt.figure(figsize=(10, 6))
plt.bar(
    [ip for ip, count in top_ips],
    [count for ip, count in top_ips]
)
plt.title("Top 10 Source IP Addresses")
plt.xlabel("Source IP")
plt.ylabel("Packet Count")
plt.xticks(rotation=45, ha="right")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/top_source_ips.png")
plt.close()

# 3. Packet Capture Timeline
from matplotlib.dates import DateFormatter, MinuteLocator

parsed_times = []

for timestamp in timestamps:
    try:
        parsed_times.append(datetime.fromisoformat(timestamp))
    except ValueError:
        continue

if parsed_times:
    time_counts = Counter(
        time.replace(second=0, microsecond=0)
        for time in parsed_times
    )

    sorted_times = sorted(time_counts.keys())

    plt.figure(figsize=(12, 6))
    plt.plot(
        sorted_times,
        [time_counts[t] for t in sorted_times],
        marker="o"
    )

    plt.title("Network Packet Capture Timeline")
    plt.xlabel("Time")
    plt.ylabel("Packet Count")
    plt.gca().xaxis.set_major_formatter(
        DateFormatter("%H:%M")
    )
    plt.gca().xaxis.set_major_locator(
        MinuteLocator(interval=5)
    )
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{OUTPUT_DIR}/packet_timeline.png", dpi=300)
    plt.close()

print(f"Total packets analyzed: {len(packets)}")
print("Visualizations generated successfully!")
