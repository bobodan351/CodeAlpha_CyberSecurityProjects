# CodeAlpha Task 4: Network Intrusion Detection System

## Project Overview

A complete Network Intrusion Detection System (NIDS) built with Suricata, featuring real-time monitoring, automatic threat response, and web-based visualization.

## Components

| Component | Technology | Purpose |
|-----------|-----------|---------|
| NIDS Engine | Suricata 8.0.4 | Real-time traffic analysis |
| Monitor | Python 3 | Alert processing and display |
| Auto-Block | Python + iptables | Automatic IP blocking |
| Dashboard | HTML/CSS/JS | Web visualization |

## Detection Rules (10 Custom Rules)

1. Ping Detection - ICMP echo requests
2. SSH Monitoring - Port 22 connections
3. HTTP Traffic - Web activity on port 80
4. Port Scan - SYN flood detection
5. SQL Injection - SELECT/FROM patterns in URLs
6. XSS Attempts - script tags in requests
7. Directory Traversal - ../ path manipulation
8. SSH Brute Force - Multiple SSH attempts
9. Suspicious User Agents - sqlmap detection
10. Data Exfiltration - Large POST uploads

## Quick Start

### Step 1: Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

### Step 2: Start Monitor (Optional - basic alerts)
sudo python3 monitor.py

### Step 3: Start Auto-Blocker (Recommended)
sudo python3 blocker.py

### Step 4: Open Dashboard
firefox dashboard.html

## Testing

Generate test traffic to see alerts:

Test ping detection:
ping -c 3 8.8.8.8

Test port scan:
sudo nmap -sS localhost

Test web attacks:
curl "http://localhost/?id=1 OR 1=1"
curl "http://localhost/?search=scriptalert(1)/script"

## File Structure

CodeAlpha_NIDS/
├── README.md              - This file
├── monitor.py             - Basic alert monitor
├── blocker.py             - Auto-blocking monitor
├── dashboard.html         - Web visualization
├── blocked_ips.log        - Auto-generated block log
└── screenshots/           - Add your screenshots here

## Expected Output

Suricata Console:
Notice: suricata: This is Suricata version 8.0.4 RELEASE
Info: detect: 10 rules successfully loaded
Info: runmodes: eth0: creating 2 threads

Blocker.py Output:
CodeAlpha NIDS - Auto-blocking Monitor
Ping detected from 10.0.2.15
HTTP traffic detected from 10.0.2.15
Port scan detected from 10.0.2.15

BLOCKING IP: 10.0.2.15
Blocked successfully!

## Requirements

- Kali Linux / Ubuntu
- Suricata 8.0+
- Python 3.7+
- Root/sudo access

## Author

[Lawal Daniel Adebola]
CodeAlpha Cyber Security Intern
Date: April 2026
