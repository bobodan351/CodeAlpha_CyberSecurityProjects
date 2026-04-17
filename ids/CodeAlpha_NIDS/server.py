#!/usr/bin/env python3
"""
CodeAlpha NIDS - Dashboard Server
Serves alerts from Suricata log to dashboard.html
"""

from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
import json
import os
from threading import Thread
import time

app = Flask(__name__)
CORS(app)

LOG_FILE = '/var/log/suricata/eve.json'
alerts_cache = []

def read_alerts():
    """Read new alerts from Suricata log"""
    global alerts_cache
    
    if not os.path.exists(LOG_FILE):
        return []
    
    new_alerts = []
    try:
        with open(LOG_FILE, 'r') as f:
            # Read last 50 lines
            lines = f.readlines()[-50:]
            
            for line in lines:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        alert = {
                            'time': event.get('timestamp', 'Unknown'),
                            'signature': event['alert'].get('signature', 'Unknown'),
                            'src_ip': event.get('src_ip', 'Unknown'),
                            'dest_ip': event.get('dest_ip', 'Unknown'),
                            'severity': event['alert'].get('severity', 0)
                        }
                        new_alerts.append(alert)
                except:
                    pass
    except:
        pass
    
    alerts_cache = new_alerts[-20:]  # Keep last 20
    return alerts_cache

@app.route('/')
def dashboard():
    """Serve the dashboard HTML"""
    return send_from_directory('.', 'dashboard.html')

@app.route('/alerts')
def get_alerts():
    """API endpoint for alerts"""
    alerts = read_alerts()
    return jsonify(alerts)

@app.route('/stats')
def get_stats():
    """Get statistics"""
    alerts = read_alerts()
    return jsonify({
        'total': len(alerts),
        'blocked': 0  # You can enhance this later
    })

if __name__ == '__main__':
    print("=" * 60)
    print("CodeAlpha NIDS Dashboard Server")
    print("=" * 60)
    print("Open: http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    # Check if running as root (for reading logs)
    if os.geteuid() != 0:
        print("\nWarning: Not running as root.")
        print("May not be able to read Suricata logs.")
        print("Run with: sudo python3 server.py\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
