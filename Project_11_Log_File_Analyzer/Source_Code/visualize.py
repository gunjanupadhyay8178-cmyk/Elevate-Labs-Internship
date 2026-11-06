import pandas as pd
import matplotlib.pyplot as plt
import os

os.makedirs("Reports", exist_ok=True)

# Load actual project data
ssh = pd.read_csv("Reports/ssh_analysis.csv")
apache = pd.read_csv("Reports/apache_analysis.csv")
alerts = pd.read_csv("Reports/intrusion_detection_report.csv")

# 1. SSH Authentication Chart
ssh_counts = ssh["status"].value_counts()

plt.figure(figsize=(7, 5))
ssh_counts.plot(kind="bar")
plt.title("SSH Authentication Analysis")
plt.xlabel("Login Status")
plt.ylabel("Number of Events")
plt.tight_layout()
plt.savefig("Reports/ssh_authentication.png")
plt.close()

# 2. Apache HTTP Status Chart
http_counts = apache["status"].value_counts().sort_index()

plt.figure(figsize=(7, 5))
http_counts.plot(kind="bar")
plt.title("Apache HTTP Status Code Analysis")
plt.xlabel("HTTP Status Code")
plt.ylabel("Number of Requests")
plt.tight_layout()
plt.savefig("Reports/apache_status_codes.png")
plt.close()

# 3. Intrusion Detection Alerts Chart
if not alerts.empty:
    alert_counts = alerts.groupby("alert_type")["event_count"].sum()

    plt.figure(figsize=(8, 5))
    alert_counts.plot(kind="bar")
    plt.title("Intrusion Detection Alerts")
    plt.xlabel("Alert Type")
    plt.ylabel("Detected Events")
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig("Reports/intrusion_alerts.png")
    plt.close()

print("VISUALIZATION COMPLETED")
print("-----------------------")
print("SSH chart: Reports/ssh_authentication.png")
print("Apache chart: Reports/apache_status_codes.png")
print("Alert chart: Reports/intrusion_alerts.png")
