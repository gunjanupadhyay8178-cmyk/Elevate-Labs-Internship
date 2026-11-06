import pandas as pd
import os

SSH_FILE = "Reports/ssh_analysis.csv"
APACHE_FILE = "Reports/apache_analysis.csv"
OUTPUT_FILE = "Reports/intrusion_detection_report.csv"

os.makedirs("Reports", exist_ok=True)

ssh = pd.read_csv(SSH_FILE)
apache = pd.read_csv(APACHE_FILE)

alerts = []

# SSH failed login analysis
failed_ssh = ssh[ssh["status"] == "FAILED"]

for ip, count in failed_ssh.groupby("source_ip").size().items():
    if count >= 5:
        alerts.append({
            "source_ip": ip,
            "alert_type": "Possible SSH Brute Force",
            "event_count": count,
            "severity": "HIGH"
        })

# Apache repeated 404 analysis
not_found = apache[apache["status"] == 404]

for ip, count in not_found.groupby("source_ip").size().items():
    if count >= 3:
        alerts.append({
            "source_ip": ip,
            "alert_type": "Possible HTTP Path Enumeration",
            "event_count": count,
            "severity": "MEDIUM"
        })

# Save detection report
columns = ["source_ip", "alert_type", "event_count", "severity"]
report = pd.DataFrame(alerts, columns=columns)
report.to_csv(OUTPUT_FILE, index=False)

print("INTRUSION DETECTION ANALYSIS")
print("----------------------------")
print("SSH failed attempts:", len(failed_ssh))
print("Apache 404 requests:", len(not_found))
print("Total alerts generated:", len(report))

if not report.empty:
    print("\nDetection Results:")
    print(report.to_string(index=False))
else:
    print("\nNo detection threshold reached.")

print("\nReport saved:", OUTPUT_FILE)
