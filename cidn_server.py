from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from certificate_authority import CertificateAuthority
from cidn import CIDN
from blockchain import Blockchain
import scapy.all as scapy
from scapy.all import ARP, Ether, srp

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Core system
ca = CertificateAuthority()
blockchain = Blockchain()
cidn = CIDN(ca, blockchain)

# ---------------- Device Discovery ----------------
def discover_devices(ip_range="192.168.0.1/24"):
    devices = []
    try:
        arp_req = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast / arp_req
        answered = srp(arp_req_broadcast, timeout=2, verbose=False)[0]

        for _, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
    except Exception as e:
        print("[Discovery Error]", e)

    return devices

# ---------------- Endpoints ----------------

@app.post("/register")
def register_device(payload: dict):
    device_id = payload.get("device_id")
    public_key = payload.get("public_key", "fake_public_key")

    if not device_id:
        return JSONResponse(content={"error": "Missing device_id"}, status_code=400)

    cert = ca.register_device(device_id, public_key)
    cidn.add_device(device_id)
    return {"certificate": cert, "public_key": public_key}


@app.post("/alert")
def receive_alert(alert: dict):
    result = cidn.receive_alert(alert)
    return {"status": "ok"} if result else {"status": "rejected"}


@app.get("/devices")
def list_devices():
    return cidn.list_devices()


@app.get("/trust/{device_id}")
def get_trust(device_id: str):
    trust_score = cidn.get_trust(device_id)
    if trust_score is None:
        return {"error": "Device not found"}
    return {"device_id": device_id, "trust": trust_score}


@app.get("/ledger")
def get_ledger():
    return [block.to_dict() for block in cidn.blockchain.chain]


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    devices = cidn.list_devices()
    ledger = [block.to_dict() for block in cidn.blockchain.chain][::-1]  # newest first
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "devices": devices,
        "ledger": ledger
    })


@app.get("/discover")
def auto_discover(ip_range: str = "192.168.0.1/24"):
    """
    Discover devices and auto-register them in CIDN.
    """
    discovered = discover_devices(ip_range)
    registered = []

    for d in discovered:
        mac = d["mac"]
        if not ca.has_device(mac):
            cert = ca.register_device(mac, "fake_public_key")
            cidn.add_device(mac)
            registered.append(cert)

    return {"discovered": discovered, "registered": registered}


# ---------------- Test Logging Endpoint ----------------
@app.post("/log_test")
def log_test(payload: dict):
    """
    Allows test_cases.py to log results directly into the blockchain.
    These will then appear in the dashboard under Ledger.
    """
    cidn.blockchain.add_block({
        "event": "test_result",
        "test": payload.get("test"),
        "status": payload.get("status")
    })
    return {"status": "logged"}
