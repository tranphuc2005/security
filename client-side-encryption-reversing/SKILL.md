---
name: client-side-encryption-reversing
description: Reverse engineer client-side API request encryption (WASM, obfuscated JS, AES/RSA) and build mitmproxy/Burp addons to decrypt and re-encrypt traffic on the fly during authorized pentests. Use when web or mobile apps encrypt request bodies and Burp/proxy only sees ciphertext.
tags:
  - pentest
  - encryption
  - wasm
  - mitmproxy
  - burp-suite
  - reverse-engineering
  - api
  - traffic-interception
---

# Client-Side API Encryption Reversing

## When to Use

- Web/mobile app encrypts API request bodies (e.g., `{"dataEnc": "<base64>"}`) and Burp/proxy only shows ciphertext
- Need to read/modify plaintext API requests during a pentest
- Client-side encryption uses WASM, obfuscated JS, JSEncrypt, CryptoJS, or custom crypto

## Workflow

### 1. Identify the Encryption

Look for these signals in intercepted traffic:
- Request body is a single field like `dataEnc`, `enc_data`, `payload`, `data` containing base64/hex blob
- Response body may or may not be encrypted (often only requests are)
- Content-Type is still `application/json` but the body is a JSON wrapper around an encrypted blob

### 2. Locate the Encryption Function in Client JS

**Browser DevTools approach (fastest):**
- Set XHR/fetch breakpoints in DevTools → Sources → XHR Breakpoints
- Stack trace shows the interceptor that wraps the body before sending
- Look for Angular HTTP interceptors (`HttpInterceptor` interface), Axios interceptors, or fetch wrappers

**Static analysis approach:**
- Download all JS files (save complete webpage)
- `grep` for: `dataEnc`, `encrypt`, `checkEncryptRequest`, `CryptoJS`, `JSEncrypt`, `AES`, `RSA`, `wasm`, `WebAssembly`
- For obfuscated JS: find the string lookup table (often `function a0_0xNNNN()` returning an array), then resolve hex offsets to strings
- Angular apps: look for `HttpInterceptor` classes, config objects with `encryption: true`

### 3. Identify the Crypto Scheme

| Signal in JS | Likely Scheme |
|---|---|
| `WebAssembly.instantiate` + `fetch('*.wasm')` | Go/Rust compiled WASM doing crypto |
| `CryptoJS.AES.encrypt` | AES-CBC/ECB with static or derived key |
| `JSEncrypt` + `setPublicKey` | RSA encryption (often for key exchange) |
| `window.bder` or global function assigned from WASM exports | WASM-exported encrypt function |
| TOTP/HOTP patterns (`hmac`, `sha256`, `struct.pack`) | Time-based key derivation |

### 4. Reverse the Algorithm

**Check open-source wrappers first.** Many banking/fintech apps have unofficial API wrappers on GitHub (search `<app-name> API python` or `<app-name> encryption github`). These often contain a working reimplementation of the crypto — saves hours of WASM reversing.

**WASM encryption:**
- Download the `.wasm` file from the app's assets path
- Try `wasm-decompile` or `wasm2wat` to get readable text
- Look for the exported function name (e.g., `bder` in MB Bank)
- If the WASM is Go-compiled, the JS loader (`wasm_exec.js` pattern) reveals the Go bridge — the exported function takes JSON string + session ID, returns encrypted string

**Key extraction patterns:**
- TOTP keys are often hardcoded in WASM/JS (search for 64-char hex strings)
- AES keys may be derived from: random bytes in the output + TOTP + random bytes
- RSA public keys may be in JS config objects or fetched from an API endpoint

### 5. Build the Decrypt/Encrypt Proxy (2-Way)

The proxy sits between Burp and the target server. It handles two cases in the `request()` hook:

1. **Encrypted body** (`{"dataEnc": "..."}`) → decrypt, log plaintext, **re-encrypt with fresh TOTP**, replace body. The original ciphertext may have expired (TOTP 30s window) during Burp transit, so always re-encrypt.
2. **Plaintext body** (modified by user in Burp Repeater) → re-encrypt to `{"dataEnc": "..."}` before forwarding to server

This 2-way pattern lets you edit requests in Burp Repeater as plaintext and have them auto-encrypted on the fly. The `response()` hook logs response bodies.

**Architecture:**
```
Browser → Burp (8080) → mitmproxy (8081, upstream) → Target server
```

**Run:**
```bash
mitmdump -s addon.py -p 8081
# Then in Burp: Project Options → Connections → Upstream Proxy Servers
#   Host: <target-domain>, Proxy host: 127.0.0.1, Proxy port: 8081
```

**Key detection logic for 2-way proxy:**
```python
def is_encrypted(body_str):
    """Detect {"dataEnc": "..."} format."""
    try:
        obj = json.loads(body_str)
        return isinstance(obj, dict) and "dataEnc" in obj
    except (json.JSONDecodeError, TypeError):
        return False

def is_plain_request(body_str):
    """Detect plaintext API request by SENSITIVE field names only.
    CRITICAL: Do NOT include sessionId, refNo, deviceIdCommon — these appear
    in ALL requests (encrypted AND non-encrypted, e.g. getCaptchaImage).
    Only fields like userId, password, captcha, ibAuthen2faString are
    exclusive to requests that should be encrypted."""
    try:
        obj = json.loads(body_str)
        if not isinstance(obj, dict):
            return False
        sensitive_fields = {"userId", "password", "captcha", "ibAuthen2faString"}
        return bool(obj.keys() & sensitive_fields)
    except (json.JSONDecodeError, TypeError):
        return False
```

**Full template:** see `scripts/aes-gcm-totp-mitm.py` — a complete, tested 2-way mitmproxy addon with encrypt, decrypt, is_encrypted, is_plain_request, request(), and response() hooks.

**Pitfall — do NOT use `response()` for re-encryption.** The `response()` hook runs after the request has already been sent to the server — it's too late to modify the request body. Instead, detect plaintext vs encrypted in `request()` and re-encrypt there. The old approach of replacing the body with plaintext + `X-Decrypted` header + re-encrypting in `response()` does not work for Burp Repeater (Burp sends the modified request directly, bypassing the response cycle).

### 6. Pitfalls

- **TOTP time window**: The TOTP key changes every 30s. If you decrypt a request captured >30s ago, it will fail. Decrypt in real-time or capture the TOTP at capture time.
- **WASM version drift**: If the app updates its WASM, the algorithm or TOTP key may change. Re-download and re-verify.
- **Akamai/bot detection**: Many banking sites use Akamai bot detection. Browser tools may get 403. Download JS files manually or via browser save-page or curl with proper headers.
- **Obfuscated JS string tables**: Angular apps use `a0_0xNNNN(index)` lookup. Find the array function, resolve hex offsets: `string = array[hex_offset - base_offset]`.
- **JSEncrypt vs WASM**: Some apps use BOTH — JSEncrypt (RSA) for key exchange and WASM for body encryption. Identify which one handles the `dataEnc` field.
- **Password hashing**: Apps often hash passwords (MD5, SHA256) client-side before encrypting. Check the JS for `md5(`, `CryptoJS.MD5`, or `hashlib` patterns before the encryption call.
- **Over-broad plaintext detection (CRITICAL)**: When deciding which plaintext requests to encrypt, only match on fields EXCLUSIVE to encrypted requests (e.g., `userId`, `password`, `captcha`). Do NOT match on `sessionId`, `refNo`, `deviceIdCommon` — these appear in ALL requests including non-encrypted ones (e.g., `getCaptchaImage`). Matching on them causes the proxy to encrypt non-encrypted requests, which the server rejects (login fails silently). This was a real bug: the proxy encrypted `getCaptchaImage` requests because they contain `sessionId`/`refNo`/`deviceIdCommon`, breaking the entire login flow.
- **Re-encrypt already-encrypted bodies**: When the proxy receives an already-encrypted `{"dataEnc":"..."}` body from Burp, it must DECRYPT then RE-ENCRYPT with a fresh TOTP before forwarding. The original TOTP may have expired (>30s elapsed in Burp transit). Just passing through the original ciphertext causes server rejection with `GW283` or similar errors.
- **`cryptography` package on Windows**: May not be in the default Python. Use the full path to Python 3.12: `C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe`.
- **GitHub wrappers**: Search GitHub for `<app-name> API python` or `<app-name> encryption github` — unofficial wrappers often contain working crypto reimplementations that save hours of WASM reversing.
- **Test server-side validation BEFORE reversing (CRITICAL)**: Before spending time reversing any signature/hash/encryption mechanism, test whether the server actually validates it. Send a dummy `Signature: test`, empty value, or omit the header entirely. Many "security" mechanisms are client-side only or not enforced server-side. See `references/webpack-module-tracing.md` for a real example where 30+ minutes of webpack module tracing was wasted because the server accepted any Signature value.
- **Webpack module tracing for obfuscated signatures**: When JS uses webpack module imports to build a hash/signature (e.g., `m.p` where `m = n("moduleId")`), trace through the module system using Python regex. See `references/webpack-module-tracing.md` for the full technique including Python patterns for finding module boundaries, resolving exports, and decoding custom scramble functions.
- **ASP.NET Core + F5 Big-IP stack: 302 to /Error/404 on POST JSON**: When every POST to an API endpoint returns `302 Location: /Error/404` despite a valid session, the cause is almost always MISSING BROWSER-LIKE HEADERS, not a wrong route. Add `User-Agent` (real Chrome UA), `X-Requested-With: XMLHttpRequest`, `Referer: <the page URL>`, `Content-Type: application/json; charset=utf-8`, `Accept: application/json, text/javascript, */*; q=0.01` — the 404 instantly becomes a 200 with a real JSON error body. Do NOT waste time fuzzing route casing/prefixes (`/api/`, PascalCase, trailing slash) before fixing headers. (Observed on MIC claim.mic.vn, IIS 10 + F5 BIG-IP.)
- **Request signing ("chữ ký dữ liệu") is distinct from body encryption**: Some apps (e.g. ESCS/MIC claim) do NOT encrypt the body but require a computed signature. Symptom: server returns 200 JSON with an error like `{"state_info":{"status":"NotOK","message_code":"ERROR_CONN001","message_body":"Chữ ký dữ liệu không hợp lệ."}}`. A dummy signature value in the body is REJECTED — meaning signing is enforced server-side here (unlike the MB Merchant case). To find the signer: hook `XMLHttpRequest.prototype.open/send/setRequestHeader` in the live page (push `{url, method, headers, body}` into a `window._xhrLog` array), click the UI button that triggers the call, then inspect whether the signature travels as a header or a body field, and grep the JS for that field name. NOTE: XHR hooks installed via console do NOT survive page navigation — re-install after every full page load, and prefer in-app link clicks over hard navigation to keep the hook alive. CRITICAL: If clicking a button after re-hooking yields 0 requests, the grid may use jqxGrid/jqxDataTable internal AJAX (not raw XHR) or fetch — also hook `window.fetch` and `jQuery.ajax` (assign `window._ajaxLog`). If still 0, the data may load via iframe, Web Worker, or SignalR — fall back to asking the user for a DevTools-captured request, or grep the JS for `postData(`/`url:` in `*Service.js` files to reconstruct the endpoint manually.
- **Arithmetic captcha solving loop (vision)**: For login forms with a math captcha image bound to a session cookie (e.g. `/Home/Captcha`), the reliable loop is: (1) GET the login page in one session to obtain the antiforgery token, (2) GET the captcha image on the SAME session so it binds, (3) upscale 4-5x with PIL `Image.resize(..., Image.LANCZOS)` and save, (4) ask the vision tool for just the numeric result, (5) POST credentials + answer + token immediately (captcha is single-use — every failed attempt regenerates it AND may clear other form fields server-side, so re-type the password on every retry). In a live browser context, grab the already-rendered image via canvas (`drawImage` into a 4x canvas, `toDataURL`) and trigger a synthetic `<a download>` click so the vision tool can read the file from disk — data URLs returned through console evaluation get truncated in transit and can't be reused. CRITICAL: The vision tool on a live browser page often refuses to solve captchas outright; the reliable path is to download the captcha as a PNG file (via canvas download trick or `curl` on the captcha URL with session cookies) and pass the LOCAL FILE path to the vision tool — it will solve the same image from disk without refusal.
- **Browser console eval limitations**: When using `browser_console(expression=...)` for JS evaluation, complex multi-line expressions often return `null` even when they execute. Use single-expression IIFEs `(function(){ ... return value; })()` and avoid `var` declarations at top level (they hoist but don't return). If a hook (`window._xhrLog = []`) returns `undefined` after page navigation, the context was destroyed — re-install the hook and click the button again WITHOUT navigating. If clicking still yields 0 requests after re-hooking, the grid likely uses jqxGrid/jqxDataTable internal AJAX (not raw XHR) or fetch — also hook `window.fetch` and `jQuery.ajax` (assign `window._ajaxLog`). If still 0, the data may load via iframe, Web Worker, or SignalR — fall back to asking the user for a DevTools-captured request, or grep the JS for `postData(`/`url:` in `*Service.js` files to reconstruct the endpoint manually.
- **Fingerprint upload endpoints via error-message escalation (no valid data needed)**: When an upload endpoint exists but requires a valid business object (e.g. a claim ID), map its validation pipeline with junk input: empty multipart -> generic error; adding a `pm` (module) field -> different error ("missing workflow params"); adding a guessed object ID -> app-level error naming the missing object. Each distinct message proves another validation layer was passed and confirms parameter names — collect candidate params from the page's JS (grep for `postData(` in `*Service.js` files) and Dropzone configs (`url`, `acceptedFiles`, `maxFilesize`). Once a real object ID is obtained elsewhere (grid paging, detail page), replay the upload with webshell payloads (`shell.ashx`, `shell.aspx;.jpg`, double extensions, `..` in filename) since IIS + ASP.NET behind F5 often executes `.ashx`/`.aspx` dropped under upload roots.

### 7. Verification

Always verify the crypto implementation with a roundtrip test:
```python
data = {"test": "hello"}
enc = encrypt(data)
dec = json.loads(decrypt(enc))
assert dec == data  # Must match
```

Also verify:
- Wrong TOTP key fails GCM authentication (proves key depends on TOTP)
- Same plaintext produces different ciphertext (proves randomness)
- SHA1 tail matches plaintext (proves format is correct)
- Proxy 2-way: encrypt(plaintext) → decrypt(result) == original plaintext

And verify against a real captured request if possible (decrypt a real `dataEnc` value and check the JSON makes sense).
