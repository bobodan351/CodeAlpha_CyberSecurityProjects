#!/usr/bin/env python3
"""
CodeAlpha NIDS - Auto-blocking Monitor
Blocks IPs after 3 suspicious alerts
"""

import json
import time
import os
import subprocess
from collections import defaultdict

LOG_FILE = '/var/log/suricata/eve.json'
BLOCKED_IPS = set()
ATTACK_COUNTS = defaultdict(int)

def block_ip(ip):
    """Block IP using iptables"""
    if ip in BLOCKED_IPS:
        return
    
    print(f"\n🚫 BLOCKING IP: {ip}")
    print(f"   Reason: 3+ suspicious activities detected")
    
    try:
        subprocess.run(
            ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
            check=True
        )
        BLOCKED_IPS.add(ip)
        
        # Log to file
        with open('blocked_ips.log', 'a') as f:
            f.write(f"{time.ctime()}: Blocked {ip}\n")
            
        print(f"   ✅ Blocked successfully!")
        
    except Exception as e:
        print(f"   ❌ Failed: {e}")

def watch_and_block():
    print("=" * 60)
    print("🔍 CodeAlpha NIDS - Auto-blocking Monitor")
    print("=" * 60)
    print(f"Log file: {LOG_FILE}")
    print("Auto-block: After 3 alerts from same IP")
    print("Press Ctrl+C to stop\n")
    
    # Check log exists
    if not os.path.exists(LOG_FILE):
        print(f"❌ Error: {LOG_FILE} not found!")
        print("Start Suricata first!")
        return
    
    with open(LOG_FILE, 'r') as f:
        f.seek(0, 2)  # Go to end
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    src_ip = event['src_ip']
                    signature = event['alert']['signature']
                    
                    print(f"⚠️  [{src_ip}] {signature[:50]}...")
                    
                    # Count attacks
                    ATTACK_COUNTS[src_ip] += 1
                    
                    # Block after 3 alerts
                    if ATTACK_COUNTS[src_ip] == 3:
                        block_ip(src_ip)
                        
            except json.JSONDecodeError:
                pass

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("⚠️  Run with: sudo python3 blocker.py")
        print()
    
    try:
        watch_and_block()
    except KeyboardInterrupt:
        print(f"\n\n{'=' * 60}")
        print("📊 SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total unique attackers: {len(ATTACK_COUNTS)}")
        print(f"Blocked IPs: {len(BLOCKED_IPS)}")
        if BLOCKED_IPS:
            print(f"Blocked: {', '.join(BLOCKED_IPS)}")
        print(f"{'=' * 60}")
