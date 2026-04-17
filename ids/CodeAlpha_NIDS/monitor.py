#!/usr/bin/env python3
import json
import time
import os

LOG_FILE = '/var/log/suricata/eve.json'

def watch_alerts():
    print("🔍 NIDS Monitor Started")
    print("Watching:", LOG_FILE)
    print("Press Ctrl+C to stop\n")
    
    # Check if log file exists
    if not os.path.exists(LOG_FILE):
        print(f"❌ Error: {LOG_FILE} not found!")
        print("Make sure Suricata is running first.")
        return
    
    # Open log file
    with open(LOG_FILE, 'r') as f:
        # Go to end of file (don't show old alerts)
        f.seek(0, 2)
        
        print("✅ Watching for new alerts...\n")
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            
            try:
                event = json.loads(line)
                if event.get('event_type') == 'alert':
                    alert = event['alert']
                    print("=" * 60)
                    print(f"🚨 {alert['signature']}")
                    print(f"   Time: {event['timestamp']}")
                    print(f"   From: {event['src_ip']}:{event.get('src_port', 'N/A')}")
                    print(f"   To:   {event['dest_ip']}:{event.get('dest_port', 'N/A')}")
                    print(f"   Protocol: {event.get('proto', 'N/A')}")
                    print("=" * 60)
            except Exception as e:
                pass

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("⚠️  Warning: Not running as root. May not be able to read logs.")
        print("Run with: sudo python3 monitor.py")
        print()
    
    try:
        watch_alerts()
    except KeyboardInterrupt:
        print("\n\n👋 Monitor stopped.")
