# device_client.py
import requests
import socket
import time
import json
from datetime import datetime

SERVER_URL = "http://127.0.0.1:8000"  # change to coordinator IP for network runs

def make_alert(device_id, alert_type="benign", details=None, metrics=None):
    payload = {
        "device_id": device_id,
        "type": alert_type,
        "details": details or {"msg": "normal"},
        "metrics": metrics or {},
        "source": "temp-node",
        "ts": datetime.utcnow().isoformat() + "Z"
    }
    return payload

def send_alert(payload):
    try:
        r = requests.post(f"{SERVER_URL}/alert", json=payload, timeout=5)
        print("Server response:", r.status_code, r.json())
    except Exception as e:
        print("Failed to send alert:", e)

def demo():
    dev_id = socket.gethostname()
    # benign alert
    a1 = make_alert(dev_id, "benign", {"msg": "normal traffic"}, {"packets_sent": 120, "packets_failed": 1})
    send_alert(a1)
    time.sleep(1)
    # suspicious scan
    a2 = make_alert(dev_id, "scan", {"msg": "port scan"}, {"scan_count": 40, "packets_sent": 200, "packets_failed": 10})
    send_alert(a2)

if __name__ == "__main__":
    demo()
