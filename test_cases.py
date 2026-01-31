import requests
import time

SERVER_URL = "http://127.0.0.1:8000"

# Helper functions
def register_device(device_id):
    payload = {"device_id": device_id, "public_key": "fake_key"}
    resp = requests.post(f"{SERVER_URL}/register", json=payload)
    print(f"[Register] {device_id} ->", resp.json())

def send_alert(device_id, alert_type, metrics=None):
    payload = {
        "device_id": device_id,
        "type": alert_type,
        "metrics": metrics or {}
    }
    resp = requests.post(f"{SERVER_URL}/alert", json=payload)
    print(f"[Alert] {device_id} ({alert_type}) ->", resp.json())
    return resp.json()

def get_trust(device_id):
    resp = requests.get(f"{SERVER_URL}/trust/{device_id}")
    return resp.json()


def run_simulation():
    print("\n=== CIDN Simulation: Multiple Devices ===")

    # Step 1: Register multiple devices
    devices = ["Laptop_A", "Phone_B", "IoT_Camera", "Attacker_PC"]
    for d in devices:
        register_device(d)

    time.sleep(1)

    # Step 2: Normal alerts (benign devices send good traffic)
    for i in range(3):
        send_alert("Laptop_A", "benign")
        send_alert("Phone_B", "benign")
        time.sleep(0.5)

    # Step 3: IoT camera misbehaves intermittently
    send_alert("IoT_Camera", "benign")
    send_alert("IoT_Camera", "malicious_scan", {"scan_count": 15})
    send_alert("IoT_Camera", "benign")

    # Step 4: Attacker sends repeated malicious alerts
    for i in range(5):
        send_alert("Attacker_PC", "packet_drop", {"packets_sent": 100, "packets_failed": 80})
        time.sleep(0.5)

    # Step 5: Fetch trust levels
    print("\n=== Final Trust Levels ===")
    for d in devices:
        trust = get_trust(d)
        print(trust)

        # log into blockchain for dashboard
        requests.post(f"{SERVER_URL}/log_test", json={
            "test": f"Trust of {d}",
            "status": f"{trust}"
        })

    print("\n[Test] Results logged into blockchain. Open /dashboard to view.")


if __name__ == "__main__":
    run_simulation()
