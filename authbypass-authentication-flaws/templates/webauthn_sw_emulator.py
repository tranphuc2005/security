#!/usr/bin/env python3
# FIDO2/WebAuthn server-side emulator: register + login with a software key (no authenticator).
# Usage: python webauthn_sw_emulator.py <base_url> <rpid> <username>
# Example: python webauthn_sw_emulator.py https://fido.example.com fido.example.com user@test.vn
# Deps: pip install cbor2 cryptography
# Readback: register/login -> returnCode 0 = server accepts software keys (attestation unverified).
# Error ladder: 1202 CBOR sai | 1104 id khong phai base64url | 9999 generic (challenge/encoding sai)
#              1315 signature sai | 0 = OK
import sys, json, hashlib, struct, base64
import urllib.request
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

BASE, RPID, USER = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3]

def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')

def post(path, obj):
    req = urllib.request.Request(f"{BASE}{path}", json.dumps(obj).encode(),
        {"Content-Type": "application/json"}, method="POST")
    return json.loads(urllib.request.urlopen(req, timeout=15).read())

priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key().public_numbers()
cose = cbor2.dumps({1: 2, 3: -7, -1: 1,
    -2: pub.x.to_bytes(32, 'big'), -3: pub.y.to_bytes(32, 'big')})
cred_id = bytes(range(32))
rph = hashlib.sha256(RPID.encode()).digest()
auth_data = rph + struct.pack('>BI', 0x41, 0) + b'\x00'*16 \
    + struct.pack('>H', len(cred_id)) + cred_id + cose
att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

opt = post("/attestation/options", {"username": USER, "displayName": USER,
    "attestation": "direct", "authenticatorSelection": {}})
cd = json.dumps({"type": "webauthn.create", "challenge": opt["challenge"],
    "origin": f"https://{RPID}", "crossOrigin": False}).encode()
reg = post("/attestation/result", {"id": b64u(cred_id), "rawId": b64u(cred_id),
    "type": "public-key",
    "response": {"attestationObject": b64u(att_obj),
        "clientDataJSON": b64u(cd), "transports": ["usb"]}})
print("register:", reg)

ao = post("/assertion/options", {"username": USER})
ad = rph + struct.pack('>BI', 0x05, 1)
acd = json.dumps({"type": "webauthn.get", "challenge": ao["challenge"],
    "origin": f"https://{RPID}"}).encode()
sig = priv.sign(ad + hashlib.sha256(acd).digest(), ec.ECDSA(hashes.SHA256()))
login = post("/assertion/result", {"id": b64u(cred_id), "rawId": b64u(cred_id),
    "type": "public-key",
    "response": {"authenticatorData": b64u(ad), "clientDataJSON": b64u(acd),
        "signature": b64u(sig), "userHandle": b64u(b"user")}})
print("login:", login)
