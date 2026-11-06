import re
import csv
import os

LOG_FILE = "Sample_Logs/auth.log"
OUTPUT_FILE = "Reports/ssh_analysis.csv"

os.makedirs("Reports", exist_ok=True)

failed_pattern = re.compile(
    r"(?P<timestamp>\S+)\s+\S+\s+sshd-session\[\d+\]: "
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

success_pattern = re.compile(
    r"(?P<timestamp>\S+)\s+\S+\s+sshd-session\[\d+\]: "
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)

events = []

with open(LOG_FILE, "r", errors="replace") as file:
    for line in file:

        match = failed_pattern.search(line)

        if match:
            events.append({
                "timestamp": match.group("timestamp"),
                "username": match.group("username"),
                "source_ip": match.group("ip"),
                "port": match.group("port"),
                "status": "FAILED"
            })
            continue

        match = success_pattern.search(line)

        if match:
            events.append({
                "timestamp": match.group("timestamp"),
                "username": match.group("username"),
                "source_ip": match.group("ip"),
                "port": match.group("port"),
                "status": "SUCCESS"
            })

with open(OUTPUT_FILE, "w", newline="") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "timestamp", "username",
            "source_ip", "port", "status"
        ]
    )

    writer.writeheader()
    writer.writerows(events)

failed = sum(e["status"] == "FAILED" for e in events)
successful = sum(e["status"] == "SUCCESS" for e in events)

print("SSH LOG ANALYSIS COMPLETED")
print("--------------------------")
print("Total authentication events:", len(events))
print("Failed logins:", failed)
print("Successful logins:", successful)
print("Unique source IPs:", len(set(e["source_ip"] for e in events)))
print("Report saved:", OUTPUT_FILE)
