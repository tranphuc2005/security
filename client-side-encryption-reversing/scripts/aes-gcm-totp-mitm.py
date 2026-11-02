#!/usr/bin/env python3
"""
mitmproxy addon: 2-way decrypt/re-encrypt for client-side encrypted APIs.
Template for AES-256-GCM + TOTP scheme (e.g., MB Bank pattern).

Architecture:
  Browser → Burp (8080) → mitmproxy (8081, upstream) → Target server

  - Encrypted requests ({"dataEnc": "..."}) are decrypted and logged (body unchanged)
  - Plaintext requests (modified in Burp Repeater) are re-encrypted before forwarding
  - Response bodies are logged

Usage:
  mitmdump -s aes-gcm-totp-mitm.py -p 8081
  # Then in Burp: Project Options → Connections → Upstream Proxy Servers
  #   Host: online.mbbank.com.vn, Proxy host: 127.0.0.1, Proxy port: 8081
"""
import json, base64, hashlib, hmac, struct, time, os
from mitmproxy import http, ctx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# === CONFIG ===
TARGET_HOST = "online.mbbank.com.vn"
ENC_FIELD = "dataEnc"
TOTP_KEY = b"77f567425cc9064fc899dc35ad1d912481565a8b9273fcc2216d245d403e6fab"
TOTP_PERIOD = 30
TOTP_DIGITS = 8
# Fields that identify a plaintext API request that SHOULD be encrypted.
# CRITICAL: Only include fields EXCLUSIVE to encrypted requests (userId, password, etc).
# Do NOT include sessionId, refNo, deviceIdCommon — they appear in ALL requests
# (including non-encrypted ones like getCaptchaImage), causing false positives
# that break the login flow by encrypting requests the server expects as plaintext.
PLAIN_FIELDS = {"userId", "password", "captcha", "ibAuthen2faString"}
# === END CONFIG ===


def totp_code():
    counter = int(time.time() // TOTP_PERIOD)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(TOTP_KEY, msg, hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    code = (((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16)
            | (digest[offset + 2] << 8) | digest[offset + 3])
    return str(code % 10**TOTP_DIGITS).zfill(TOTP_DIGITS).encode()


def decrypt(dataenc_b64):
    raw = base64.b64decode(dataenc_b64)
    prefix, suffix, nonce = raw[0:12], raw[12:24], raw[24:36]
    ct = raw[36:-20]
    key = prefix + totp_code() + suffix
    return AESGCM(key).decrypt(nonce, ct, None).decode()


def encrypt(data_dict):
    raw = json.dumps(data_dict).encode()
    prefix, suffix, nonce = os.urandom(12), os.urandom(12), os.urandom(12)
    key = prefix + totp_code() + suffix
    ct = AESGCM(key).encrypt(nonce, raw, None)
    return base64.b64encode(
        prefix + suffix + nonce + ct + hashlib.sha1(raw).digest()
    ).decode()


def is_encrypted(body_str):
    try:
        obj = json.loads(body_str)
        return isinstance(obj, dict) and ENC_FIELD in obj
    except (json.JSONDecodeError, TypeError):
        return False


def is_plain_request(body_str):
    """Check if body looks like a plaintext API request (has known fields)."""
    try:
        obj = json.loads(body_str)
        if not isinstance(obj, dict):
            return False
        return bool(obj.keys() & PLAIN_FIELDS)
    except (json.JSONDecodeError, TypeError):
        return False


def request(flow: http.HTTPFlow):
    if TARGET_HOST not in flow.request.pretty_host:
        return
    ct = flow.request.headers.get("content-type", "")
    if not ct.startswith("application/json"):
        return
    if not flow.request.content:
        return

    body_str = flow.request.get_text()

    # Case 1: Encrypted body → decrypt for logging + re-encrypt with fresh TOTP
    # (original TOTP may have expired during Burp transit, >30s)
    if is_encrypted(body_str):
        try:
            obj = json.loads(body_str)
            plaintext = decrypt(obj[ENC_FIELD])
            ctx.log.info(f"[DECRYPT] {flow.request.method} {flow.request.path}")
            try:
                ctx.log.info(json.dumps(json.loads(plaintext), indent=2, ensure_ascii=False))
            except json.JSONDecodeError:
                ctx.log.info(plaintext)
            # Re-encrypt with fresh TOTP and replace body
            new_dataenc = encrypt(json.loads(plaintext))
            flow.request.set_text(json.dumps({ENC_FIELD: new_dataenc}))
            ctx.log.info("[RE-ENCRYPT] Fresh TOTP applied")
        except Exception as e:
            ctx.log.error(f"[DECRYPT] Error on {flow.request.path}: {e}")
            # Can't decrypt → forward original (may fail if TOTP expired)

    # Case 2: Plaintext body (user modified in Burp) → re-encrypt
    elif is_plain_request(body_str):
        try:
            obj = json.loads(body_str)
            dataenc = encrypt(obj)
            flow.request.set_text(json.dumps({ENC_FIELD: dataenc}))
            ctx.log.info(f"[ENCRYPT] {flow.request.method} {flow.request.path}")
            ctx.log.info(json.dumps(obj, indent=2, ensure_ascii=False))
        except Exception as e:
            ctx.log.error(f"[ENCRYPT] Error on {flow.request.path}: {e}")


def response(flow: http.HTTPFlow):
    if TARGET_HOST not in flow.request.pretty_host:
        return
    if not flow.response.content:
        return
    ct = flow.response.headers.get("content-type", "")
    if not ct.startswith("application/json"):
        return
    ctx.log.info(f"[RESPONSE] {flow.request.method} {flow.request.path} ({flow.response.status_code})")
    try:
        resp = json.loads(flow.response.get_text())
        ctx.log.info(json.dumps(resp, indent=2, ensure_ascii=False)[:500])
    except Exception:
        ctx.log.info(flow.response.get_text()[:500])
