# Network Packet Sniffer with Anomaly Detection

## 1. Project Overview

This project is a Python-based Network Packet Sniffer developed using Scapy. It captures live network traffic, extracts packet information, stores captured data in an SQLite database, and identifies suspicious network activity.

## 2. Objectives

- Capture live network packets.
- Identify TCP, UDP, and ICMP protocols.
- Extract source IP, destination IP, ports, and packet size.
- Store packet information in SQLite.
- Detect possible port scanning and high traffic bursts.
- Visualize network traffic using Matplotlib.

## 3. Tools and Technologies

- Python
- Scapy
- SQLite
- Matplotlib
- Kali Linux
- Nmap

## 4. Project Features

**Packet Capture:** Captures live network traffic through the eth0 interface.

**Packet Analysis:** Extracts timestamps, IP addresses, protocols, port numbers, and packet sizes.

**Database Storage:** Stores captured packet records in an SQLite database.

**Port Scan Detection:** Identifies possible port scanning based on 10 unique TCP SYN destination ports within 10 seconds.

**Traffic Burst Detection:** Generates an alert when more than 20 packets from a source IP are observed within 5 seconds.

**Data Visualization:** Generates protocol distribution, top source IP, and packet timeline graphs.

## 5. Testing and Results

The sniffer was tested using normal network traffic and a controlled Nmap SYN scan against an authorized lab machine.

- Successfully captured TCP, UDP, and ICMP packets.
- Stored 1,793 packet records in SQLite at the final verification.
- Detected a possible port scan.
- Detected a high traffic burst.
- Generated three Matplotlib visualizations.

The controlled Nmap scan reported 30 filtered TCP ports with no response. No open ports were identified during this test.

## 6. Project Structure

```text
Project_7_Network_Packet_Sniffer/
├── Source_Code/
│   ├── sniffer.py
│   ├── sniffer_basic.py
│   └── visualize.py
├── Screenshots/
├── Captured_Data/
│   └── packets.db
├── Reports/
│   ├── protocol_distribution.png
│   ├── top_source_ips.png
│   └── packet_timeline.png
├── Documentation/
└── README.md
```

## 7. How to Run

Install the required dependencies:

```bash
sudo apt install python3-scapy python3-matplotlib
```

Run the packet sniffer:

```bash
sudo python3 Source_Code/sniffer.py
```

Generate visualizations:

```bash
python3 Source_Code/visualize.py
```

## 8. Conclusion

This project provided practical experience in network traffic capture, packet analysis, database integration, basic anomaly detection, and network traffic visualization. It helped demonstrate how packet-level information can support basic network monitoring and security analysis.
