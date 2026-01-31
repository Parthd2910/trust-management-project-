import psutil
import requests
import subprocess
import time
import socket
import re

SERVER_URL = "http://127.0.0.1:8000"  # CIDN server (laptop)
TIMEOUT = 300  # auto-stop after 5 minutes (set None for infinite run)


# ---- Network utilities ----
def get_local_subnet():
    """Return the local subnet (e.g. 192.168.0.0/24)."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        parts = local_ip.split(".")
        return ".".join(parts[:3]) + ".0/24"
    except Exception:
        return "192.168.0.0/24"


def discover_devices(limit=20):
    """Ping sweep to find active devices (limited for demo)."""
    subnet = get_local_subnet()
    print(f"[Monitor] 🔍 Scanning subnet {subnet} ...")
    devices = []

    for i in range(1, limit + 1):
        ip = subnet.replace("0/24", str(i))
        try:
            output = subprocess.check_output(
                ["ping", "-n", "1", "-w", "200", ip],
                stderr=subprocess.DEVNULL
            )
            if "TTL=" in output.decode(errors="ignore"):
                devices.append(ip)
        except:
            pass
    return devices


# ---- CIDN interaction ----
def register_device(ip):
    payload = {"device_id": ip, "public_key": "auto_discovered"}
    try:
        resp = requests.post(f"{SERVER_URL}/register", json=payload, timeout=5)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def send_alert(ip, alert_type, metrics):
    alert = {"device_id": ip, "type": alert_type, "metrics": metrics}
    try:
        resp = requests.post(f"{SERVER_URL}/alert", json=alert, timeout=5)
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def get_trust(ip):
    try:
        resp = requests.get(f"{SERVER_URL}/trust/{ip}", timeout=5)
        return resp.json()
    except:
        return None


# ---- Monitor loop ----
def monitor_loop():
    seen = set()
    start_time = time.time()

    while True:
        # Auto-stop after TIMEOUT
        if TIMEOUT and time.time() - start_time > TIMEOUT:
            print(f"[Monitor] ⏹️ Auto-stopped after {TIMEOUT} seconds")
            break

        devices = discover_devices(limit=10)
        for ip in devices:
            if ip not in seen:
                reg = register_device(ip)
                print(f"[Monitor] 📝 Registered {ip}: {reg}")
                seen.add(ip)

            # Fake "traffic stats"
            net_io = psutil.net_io_counters()
            sent, recv, drop = net_io.packets_sent, net_io.packets_recv, net_io.errout
            metrics = {
                "packets_sent": sent,
                "packets_recv": recv,
                "packets_failed": drop
            }

            # Simple trust check
            drop_rate = (drop / (sent + 1)) * 100
            if drop_rate > 5:
                resp = send_alert(ip, "packet_drop", metrics)
            else:
                resp = send_alert(ip, "benign", metrics)

            print(f"[Monitor] Alert sent for {ip}: {resp}")

            trust_info = get_trust(ip)
            if trust_info:
                print(f"[Monitor] 🔐 {ip} trust: {trust_info}")

        time.sleep(15)  # wait before next scan


if __name__ == "__main__":
    monitor_loop()
