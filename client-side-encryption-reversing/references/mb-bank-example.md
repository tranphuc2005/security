# MB Bank (online.mbbank.com.vn) — Worked Example

## Target

MB Bank retail e-banking at `online.mbbank.com.vn`. Angular frontend with Go-compiled WASM encryption.

## Encryption Architecture

### Two encryption layers:

1. **WASM (primary)** — `assets/wasm/main.wasm` (Go compiled)
   - `scripts.ba8ab7d8244dd35b.js` contains the Go WASM loader (`globalObject.init()`)
   - Loads `main.wasm` via `fetch()`, instantiates with `WebAssembly.instantiate()`
   - WASM exports function `bder(jsonString, sessionId)` → assigned to `window.bder`
   - App init: `appService.appContext.encrypt = window.bder; delete window.bder;`
   - All API requests with sensitive fields wrapped: `{"dataEnc": encrypt(JSON.stringify(body), sessionId)}`

2. **JSEncrypt (RSA, secondary)** — class `_0xcf0f3c` in `main.*.js`
   - `randomString()` generates 30-char random key
   - `encrypt(plaintext, publicKey)` = RSA encrypt
   - Used by `checkEncryptRequest()` which checks if body contains `userId`, `password`, or `captcha`

### Obfuscation

Angular `main.*.js` uses string array obfuscation:
- `function a0_0x2882()` returns array of ~14,000 strings
- `a0_0xab4f(hex_offset)` resolves to `array[hex_offset - 0x1dc]`
- Each scope has its own alias: `_0x2868a1 = a0_0xab4f`, then `_0x357ea6 = _0x299c31 = _0x1471f7 = a0_0xab4f`

### Algorithm (reverse-engineered via mbbank-lib GitHub)

**AES-256-GCM with TOTP-derived key:**

```
Key = random_prefix(12 bytes) + TOTP(8 bytes ASCII) + random_suffix(12 bytes) = 32 bytes
Nonce = 12 random bytes
Ciphertext = AES-256-GCM(key, nonce, plaintext)
SHA1_tail = SHA1(plaintext)

Output = base64(random_prefix + random_suffix + nonce + ciphertext + SHA1_tail)
```

**TOTP:**
- Algorithm: HMAC-SHA256
- Key: `77f567425cc9064fc899dc35ad1d912481565a8b9273fcc2216d245d403e6fab` (hardcoded in WASM)
- Period: 30 seconds
- Digits: 8

**Base64-decoded format:**

| Offset | Size | Content |
|--------|------|---------|
| 0-11   | 12   | random_prefix (first 12 bytes of AES key) |
| 12-23  | 12   | random_suffix (last 12 bytes of AES key) |
| 24-35  | 12   | AES-GCM nonce |
| 36-N   | var  | AES-GCM ciphertext + 16-byte auth tag |
| N-20-N | 20   | SHA1 of plaintext |

### Login request fields (before encryption):

```json
{
  "userId": "<phone number>",
  "password": "<MD5 of password>",
  "captcha": "<captcha text>",
  "sessionId": "",
  "refNo": "<userId>-<YYYYMMDDHHMMSS>",
  "deviceIdCommon": "<uuid-like>",
  "ibAuthen2faString": "c7a1beebb9400375bb187daa33de9659"
}
```

- Password is MD5-hashed client-side before encryption
- `ibAuthen2faString` is hardcoded: `c7a1beebb9400375bb187daa33de9659`
- `Authorization` header: `Basic RU1CUkVUQUlMV0VCOlNEMjM0ZGZnMzQlI0BGR0AzNHNmc2RmNDU4NDNm`

### API endpoints:

| Endpoint | Encrypted |
|----------|-----------|
| `POST /api/retail_web/internetbanking/v2.0/doLogin` | Yes |
| `POST /api/retail-internetbankingms/getCaptchaImage` | No |
| `POST /api/retail-accountms/accountms/getBalance` | Yes |
| `POST /api/retail-transactionms/transactionms/get-account-transaction-history` | Yes |

### Config object (from main.*.js):

```javascript
{
  production: true,
  name: 'ebanking-retail',
  apiEndpoint: 'https://online.mbbank.com.vn/api',
  encryption: true,  // <-- enables dataEnc encryption
  captcha: true,
  sessionTimeout: 1000,
  httpClientTimeOut: 300000
}
```

## Key files in the JS bundle

- `scripts.ba8ab7d8244dd35b.js` — Go WASM loader, `globalObject.init()`, fetches `main.wasm`
- `main.6c8a551bd1624e3b.js` — Angular app, HTTP interceptor, `checkEncryptRequest()`, `dataEnc` wrapping
- `assets/wasm/main.wasm` — Go-compiled WASM with `bder()` export (NOT in saved files, must download from server)

## Discovery path

1. Search GitHub for `mbbank` → found `thedtvn/MBBank` Python wrapper with `NativeBackend` (AES-GCM + TOTP) and `WASMBackend` (wasmtime emulation)
2. Downloaded client JS files from saved webpage
3. Grepped `main.*.js` for `dataEnc`, `encrypt`, `checkEncryptRequest`, `appContext`, `bder`
4. Confirmed `scripts.*.js` contains Go WASM loader pattern: `new Go()`, `fetch('assets/wasm/main.wasm')`, `WebAssembly.instantiate`
5. Confirmed `main.*.js` HTTP interceptor wraps body: `{"dataEnc": this.appService.appContext.encrypt(JSON.stringify(body), sessionId)}`
6. Verified `NativeBackend` algorithm (AES-256-GCM + TOTP) matches by roundtrip test
7. Built mitmproxy addon for Burp integration

## 2-Way Proxy Pattern (proxy_mb_encrypt.py)

The user's preferred proxy architecture follows the same pattern as their `proxy_resign.py` (a mitmproxy addon for re-signing requests). The proxy sits between Burp and the target:

```
mitmdump -s proxy_mb_encrypt.py -p 8081
# Burp → Project Options → Connections → Upstream Proxy Servers:
#   Host: online.mbbank.com.vn, Proxy host: 127.0.0.1, Proxy port: 8081
```

Two detection paths in `request()` hook:
1. **Encrypted body** (`is_encrypted()` checks for `{"dataEnc": "..."}`) → decrypt, log plaintext, **re-encrypt with fresh TOTP**, replace body. The original TOTP may have expired (>30s in Burp transit), so always re-encrypt.
2. **Plaintext body** (`is_plain_request()` checks for sensitive field names like `userId`, `password`, `captcha`) → re-encrypt to `{"dataEnc": "..."}` and replace body before forwarding.

**CRITICAL pitfall — over-broad plaintext detection**: Do NOT include `sessionId`, `refNo`, `deviceIdCommon` in the plaintext detection field set. These fields appear in ALL requests (encrypted AND non-encrypted, e.g., `getCaptchaImage`). If the proxy detects them as "should be encrypted", it will encrypt non-encrypted requests, which the server rejects — breaking the entire login flow. Only match on fields EXCLUSIVE to encrypted requests: `userId`, `password`, `captcha`, `ibAuthen2faString`.

This lets you edit requests in Burp Repeater as plaintext JSON and have them auto-encrypted on the fly.

**Critical**: Do NOT use `response()` hook for re-encryption. The request is already sent by the time `response()` fires. Both decrypt and re-encrypt must happen in `request()`.

## Pitfalls specific to MB Bank

- **Akamai bot detection**: `online.mbbank.com.vn` returns 403 to automated browsers. Download JS via browser save-page or curl with headers.
- **TOTP time window**: Decrypt must happen in real-time (within 30s of capture). Captured requests older than 30s cannot be decrypted.
- **main.wasm not in saved page**: The WASM file must be downloaded separately from `https://online.mbbank.com.vn/assets/wasm/main.wasm`. However, the algorithm is fully reverse-engineered from `mbbank-lib` — WASM analysis is NOT needed.
- **Python version**: `cryptography` package requires Python 3.12+ on this machine. Use `C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe` explicitly.
- **`checkEncryptRequest` fields**: The Angular interceptor only encrypts requests containing `userId`, `password`, or `captcha` fields. Other API calls (balance, transaction history) are also encrypted if they match the `ENCRYPT_API` list or pass `checkEncryptRequest()`.
