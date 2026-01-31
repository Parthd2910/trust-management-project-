import uuid
import json
import os
from datetime import datetime


class CertificateAuthority:
    def __init__(self, storage_file="certs.json"):
        self.storage_file = storage_file
        self.issued_certs = {}  # device_id -> cert
        self.load()

    def register_device(self, device_id, pub_key_pem):
        cert = {
            "cert_id": str(uuid.uuid4()),
            "device_id": device_id,
            "public_key_pem": pub_key_pem,
            "revoked": False,
            "issued_at": datetime.utcnow().isoformat() + "Z"
        }
        self.issued_certs[device_id] = cert
        self.save()
        print(f"[CA] ✅ Registered {device_id} with provided public key")
        return cert

    def revoke_certificate(self, device_id):
        cert = self.issued_certs.get(device_id)
        if cert and not cert["revoked"]:
            cert["revoked"] = True
            self.save()
            print(f"[CA] ❌ Certificate revoked for {device_id}")
            return True
        return False

    def is_revoked(self, device_id):
        cert = self.issued_certs.get(device_id)
        return cert["revoked"] if cert else True

    def has_device(self, device_id):
        return device_id in self.issued_certs

    def get_public_key_pem(self, device_id):
        cert = self.issued_certs.get(device_id)
        return cert["public_key_pem"] if cert else None

    # Persistence
    def save(self):
        with open(self.storage_file, "w") as f:
            json.dump(self.issued_certs, f, indent=2)

    def load(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, "r") as f:
                self.issued_certs = json.load(f)
