import re
import csv
import os
from collections import Counter

LOG_FILE = "Sample_Logs/apache_access.log"
OUTPUT_FILE = "Reports/apache_analysis.csv"

os.makedirs("Reports", exist_ok=True)

pattern = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>.*?)\] '
    r'"(?P<method>\S+) (?P<path>\S+) '
    r'(?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

events = []

with open(LOG_FILE, "r", errors="replace") as file:
    for line in file:
        match = pattern.search(line)

        if match:
            events.append({
                "timestamp": match.group("timestamp"),
                "source_ip": match.group("ip"),
                "method": match.group("method"),
                "path": match.group("path"),
                "status": match.group("status"),
                "size": match.group("size")
            })

with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "timestamp", "source_ip",
            "method", "path", "status", "size"
        ]
    )
    writer.writeheader()
    writer.writerows(events)

status_counts = Counter(e["status"] for e in events)
not_found = [e for e in events if e["status"] == "404"]
ip_counts = Counter(e["source_ip"] for e in events)

print("APACHE LOG ANALYSIS COMPLETED")
print("-----------------------------")
print("Total requests:", len(events))
print("Successful requests:", status_counts["200"])
print("Not found (404):", status_counts["404"])
print("Unique source IPs:", len(ip_counts))
print("404 requests:", len(not_found))

print("\nRepeated 404 activity:")
for ip, count in Counter(e["source_ip"] for e in not_found).items():
    if count >= 3:
        print(f"Possible path enumeration: {ip} - {count} requests")

print("\nReport saved:", OUTPUT_FILE)
