import json
import base64
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from blockchain import Blockchain

logger = logging.getLogger("cidn")

class CIDN:
    """
    CIDN coordinates devices, verifies alerts, evaluates behavior-based rules,
    updates trust, and logs events to the blockchain.
    """

    def __init__(self, ca, blockchain=None):
        self.ca = ca
        self.devices = {}  # device_id -> device object or str
        self.trust = {}    # device_id -> trust score [0..1]
        self.revoked = set()
        self.blockchain = blockchain or Blockchain()

        # parameters (tunable)
        self.initial_trust = 0.5
        self.scan_threshold = 10          # scans per monitoring window considered suspicious
        self.packet_drop_threshold = 0.5  # forwarding rate below this is suspicious
        self.high_penalty = 0.4
        self.medium_penalty = 0.2
        self.recovery_rate = 0.05  # per benign event

    # ---- device lifecycle ----
    def add_device(self, device_obj_or_id, cert=None):
        """
        Add a device. Accepts either a Device object (with private key) or just a device_id (string).
        """
        if isinstance(device_obj_or_id, str):
            dev_id = device_obj_or_id
        else:
            dev_id = device_obj_or_id.device_id

        self.devices[dev_id] = device_obj_or_id
        self.trust[dev_id] = self.initial_trust
        self.blockchain.add_block({"event": "register", "device_id": dev_id, "trust": self.trust[dev_id]})
        logger.info(f"[CIDN] ✅ Device {dev_id} added with trust {self.trust[dev_id]}")
        return True

    # ---- alert ingestion & verification ----
    # cidn.py

    # cidn.py

    def receive_alert(self, alert: dict):
        device_id = alert.get("device_id")
        event_type = alert.get("type")

        if not device_id or device_id not in self.trust:
            print(f"[CIDN] ❌ Unknown device {device_id} attempted alert")
            return False

        if self.ca.is_revoked(device_id):
            print(f"[CIDN] ❌ Device {device_id} certificate revoked, rejecting alert")
            return False

        # --- Benign ---
        if event_type == "benign":
            self.trust[device_id] = min(1.0, self.trust[device_id] + 0.05)
            self.blockchain.add_block({"event": "benign_alert", "device_id": device_id, "trust": self.trust[device_id]})
            print(f"[CIDN] ✅ Benign alert from {device_id}, trust ↑ {self.trust[device_id]}")
            return True

        # --- Malicious types ---
        malicious_types = {"malicious", "scan", "malicious_scan", "ddos", "packet_drop"}
        if event_type in malicious_types:
            self.trust[device_id] = max(0.0, self.trust[device_id] - 0.3)
            self.blockchain.add_block({"event": f"{event_type}_alert", "device_id": device_id, "trust": self.trust[device_id]})
            print(f"[CIDN] ⚠️ {event_type} alert from {device_id}, trust ↓ {self.trust[device_id]}")

            # Auto-revoke if trust too low
            if self.trust[device_id] <= 0.1:
                self.ca.revoke_certificate(device_id)
                print(f"[CIDN] ❌ Device {device_id} trust too low → revoked")
                return False
            return True

        # --- Unknown ---
        print(f"[CIDN] ❓ Unknown alert type {event_type} from {device_id}")
        return False


    # ---- evaluation rules ----
    def evaluate_and_update(self, device_id, alert_payload):
        metrics = alert_payload.get("metrics", {})
        msg_type = alert_payload.get("type", "").lower()
        details = alert_payload.get("details", {})

        if "malicious" in str(details).lower() or "malware" in str(details).lower():
            self.adjust_trust(device_id, -self.high_penalty, reason="malicious_keyword")
        elif msg_type in ["info", "benign", "heartbeat"]:
            self.adjust_trust(device_id, +self.recovery_rate, reason="benign_event")

        scan_count = int(metrics.get("scan_count", 0))
        if scan_count >= self.scan_threshold:
            self.adjust_trust(device_id, -self.high_penalty, reason=f"scan_count={scan_count}")

        packets_sent = int(metrics.get("packets_sent", 0))
        packets_failed = int(metrics.get("packets_failed", 0))
        if packets_sent > 0:
            forwarding_rate = (packets_sent - packets_failed) / packets_sent
            if forwarding_rate < self.packet_drop_threshold:
                self.adjust_trust(device_id, -self.high_penalty, reason=f"forwarding_rate={forwarding_rate:.2f}")
            elif forwarding_rate < 0.8:
                self.adjust_trust(device_id, -self.medium_penalty, reason=f"forwarding_rate={forwarding_rate:.2f}")
            else:
                self.adjust_trust(device_id, +self.recovery_rate, reason=f"forwarding_rate={forwarding_rate:.2f}")

        if self.trust.get(device_id, 0) <= 0:
            self.revoke_device(device_id)

    def adjust_trust(self, device_id, delta, reason=""):
        old = self.trust.get(device_id, self.initial_trust)
        new = max(0.0, min(1.0, old + delta))
        self.trust[device_id] = new
        logger.info(f"[CIDN] 🔎 Trust of {device_id} changed {old:.2f} -> {new:.2f} (reason: {reason})")
        self.blockchain.add_block({"event": "trust_update", "device_id": device_id, "old": old, "new": new, "reason": reason})
        return new

    def revoke_device(self, device_id):
        if self.ca.revoke_certificate(device_id):
            self.revoked.add(device_id)
            self.blockchain.add_block({"event": "revoke", "device_id": device_id})
            logger.warning(f"[CIDN] 🔒 Device {device_id} revoked and logged.")

    # Utility
    def get_trust(self, device_id):
        return self.trust.get(device_id, None)

    def list_devices(self):
        return [
            {
                "device_id": dev_id,
                "trust": self.trust.get(dev_id, 0),
                "revoked": dev_id in self.revoked or self.ca.is_revoked(dev_id)
            }
            for dev_id in self.trust
        ]
