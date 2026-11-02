# Flutter SSL Pin Bypass — Binary Patch Approach (No Frida Needed)

When Frida is unstable (crashes, disconnects) or you want a persistent solution that survives app restarts, patch the SPKI pin hash directly in the APK's `libapp.so` binary. This requires NO runtime instrumentation.

## When to Use This Instead of Frida

- frida-server crashes on the target device (e.g., SIGSEGV in gdbus on Samsung S25 / Android 15)
- Frida spawn (`-f`) fails with `setArgV0` error on Android 15
- You need a persistent solution that survives app restarts
- You don't need runtime hooks (just SSL bypass)

## Step-by-Step

### 1. Extract libapp.so

```bash
apktool d base.apk -o base_decoded
# libapp.so is at: base_decoded/lib/arm64-v8a/libapp.so
```

### 2. Find the SPKI pin hash

```bash
# Search for base64 strings that look like SPKI hashes (44 chars ending with =)
strings -t x base_decoded/lib/arm64-v8a/libapp.so | grep -E "^[A-Za-z0-9+/]{43}=$"

# Also search for ssl_pin related strings to confirm pinning is present
strings base_decoded/lib/arm64-v8a/libapp.so | grep -i "ssl_pin"
# Expected: ssl_pins_sha256, ssl_pin_rejected, ssl_pin_expired_but_accepted, presentedPin, allowedPins
```

### 3. Get the target SPKI hash

#### Option A: Direct connection (no proxy) — use the real server's SPKI

```bash
echo | openssl s_client -connect api.target.com:443 -servername api.target.com 2>/dev/null \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

#### Option B: Burp proxy — use Burp's MITM certificate SPKI

```bash
echo | openssl s_client -proxy <burp_ip>:<burp_port> -connect api.target.com:443 -servername api.target.com 2>/dev/null \
  | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
```

**CRITICAL: The replacement SPKI hash MUST be exactly 44 bytes (43 base64 chars + '=' padding).**
If the hash is 43 bytes (e.g., a leading `/` was lost during copy/paste), the binary patch will shift all subsequent bytes, corrupting the Dart snapshot and crashing the app. Always verify: `len(old_pin) == len(new_pin) == 44`.

### 4. Patch the binary

```python
import shutil
src = "base_decoded/lib/arm64-v8a/libapp.so"
shutil.copy2(src, src + ".bak")  # backup!

with open(src, "rb") as f:
    data = f.read()

old_pin = b"wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI="  # original pin from libapp.so
new_pin = b"/ZQ6CfjjVQ+eqhwW76xVG6TF/+JDzrIRJ3Kq3BTMWKI="  # Burp MITM SPKI (must be 44 bytes!)

assert len(old_pin) == len(new_pin) == 44, f"Length mismatch: {len(old_pin)} vs {len(new_pin)}"

pos = data.find(old_pin)
assert pos >= 0, "Pin not found in libapp.so"

patched = data[:pos] + new_pin + data[pos+len(old_pin):]
with open(src, "wb") as f:
    f.write(patched)
print(f"Patched at offset 0x{pos:x}: {old_pin.decode()} -> {new_pin.decode()}")
```

### 5. Rebuild, align, sign, install

```bash
# APKTool path on this system: C:\Users\Admin\AppData\Local\hermes\tools\apktool.jar
java -jar "C:\Users\Admin\AppData\Local\hermes\tools\apktool.jar" b base_decoded -o base_patched.apk

# zipalign
zipalign -v -p 4 base_patched.apk base_patched_aligned.apk

# Sign (generate debug keystore if needed)
keytool -genkey -v -keystore debug.keystore -storepass android -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
# Sign
apksigner sign --ks debug.keystore --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out base_patched_signed.apk base_patched_aligned.apk

# Install
adb uninstall com.target.app
adb install base_patched_signed.apk
```

### 6. Configure proxy (if using Burp)

```bash
# Set system proxy for Burp interception
adb shell settings put global http_proxy <burp_ip>:8080

# Or clear proxy for direct connection
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port
```

### 7. Get mitmproxy's MITM SPKI (if using mitmproxy variant)

```bash
# Get mitmproxy CA cert and compute its SPKI hash
cat ~/.mitmproxy/mitmproxy-ca-cert.pem | openssl x509 -noout -pubkey \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl base64
# Output example: lDuT2+mr8piWo54/ykUNFmlTtaZR5I7KHglGvfuCs18=

# Then patch libapp.so with this SPKI instead of Burp's or the server's
# Rebuild APK with mitmproxy SPKI, install, set proxy to mitmproxy
```

## PITFALL: System proxy alone does NOT work with Flutter

**Flutter's `dart:io HttpClient` ignores Android system proxy settings.** Setting `adb shell settings put global http_proxy host:port` will NOT redirect Flutter traffic to your proxy. The app connects directly to the server, bypassing the proxy entirely.

If you patched libapp.so with a **proxy SPKI** (Burp or mitmproxy), but only set system proxy (no iptables), the app will:
1. Connect directly to the real server (ignoring the proxy)
2. Server presents its real certificate (with real SPKI)
3. App expects proxy SPKI (which you patched in) → **SSL pin mismatch → connection fails**

**Solution:** When using a proxy SPKI, you MUST also set up iptables REDIRECT + adb reverse to force traffic through the proxy:

```bash
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082'"
adb reverse tcp:8082 tcp:8082
```

Or better: use the **server's real SPKI** variant (no proxy needed at all) if you just need the app to function.

## PITFALL: mitmproxy transparent mode does NOT work on Windows

`mitmdump --mode transparent` requires WinDivert admin access on Windows and fails with `PermissionError: [WinError 5]`. Use `--mode reverse:https://api.target.com` instead, which works without admin privileges.

## PITFALL: iptables REDIRECT to localhost:PORT fails when proxy is on PC

When the proxy (mitmproxy/Burp) runs on the PC (not on the device), `iptables REDIRECT --to-port 8083` redirects to localhost:8083 **on the device** — where nothing is listening. Use `adb reverse tcp:8083 tcp:8083` to bridge device localhost:8083 to PC localhost:8083.

## Verification: Dio logcat logging

Flutter apps using the Dio HTTP package log full request/response details to logcat. This is invaluable for verifying API calls without a proxy:

```bash
adb logcat -s flutter | grep -E "Request|Response|POST|GET|http|DioError|connection"
```

Example log format:
```
╔╣ Request ║ POST
║  https://api.target.com/path
╟ Accept: application/json
╟ X-Custom-Header: value
╟ content-type: multipart/form-data
╟ citizen_id: 555555
╟ face_image: Instance of 'MultipartFile'
╚══════════════════════════════════════════════════════════════════════════════════════════╝
```

If you see requests in logcat but NOT in your proxy, the app is bypassing the proxy (Flutter ignores system proxy). Use iptables REDIRECT + adb reverse to fix.

## Choosing the Right SPKI Hash (Three Variants)

You must rebuild the APK for each variant — the SPKI hash in libapp.so determines what certificate the app will accept:

| Variant | Use When | SPKI Source | Proxy Needed? |
|---|---|---|---|
| **Server's real SPKI** (RECOMMENDED) | You just need the app to work (no traffic interception) | `openssl s_client` to the real server | No — direct connection |
| **Burp's MITM SPKI** | You need to intercept traffic via Burp | Burp's CA cert | Yes — iptables REDIRECT + adb reverse |
| **mitmproxy's MITM SPKI** | You need to intercept traffic via mitmproxy | mitmproxy's CA cert | Yes — iptables REDIRECT + adb reverse |

**CRITICAL: If you patch with a proxy SPKI but only set system proxy (no iptables REDIRECT), the app will FAIL.** Flutter's `dart:io HttpClient` ignores Android system proxy settings — the app connects directly to the server, but the server's real cert doesn't match the proxy SPKI you patched in. You MUST use iptables REDIRECT + adb reverse to force traffic through the proxy when using a proxy SPKI.

**RECOMMENDED APPROACH: Patch with server's real SPKI for direct connection.** This is the simplest, most reliable method — no Frida, no proxy, no iptables, no mitmproxy. The app connects directly to the server with SSL pin matching. Use this when you just need the app to function (e.g., for login testing, API exploration via logcat).

**VERIFIED (Android 15, Samsung S25, Flutter v1.1.31):** Patched libapp.so with server's real SPKI (`P+ZBdoU+C4izwzXfZvVTEkC0xLEovi8Qc6X7jKI05/o=`), no proxy, no Frida. App connected directly to server, login succeeded. RaspGuard (Talsec FreeRASP) detected repack+root but only logged to Datadog — did NOT block login.

## Finding ALL SPKI Hashes in libapp.so (Multiple Pins)

Flutter apps may embed **multiple SPKI hashes** in `libapp.so`. They can appear in two patterns:

1. **Comma-separated chain** (e.g., `P+ZBdoU+...=,hETpgVva...=,cGuxAXyF...=`): Multiple pins for backup cert rotation. All hashes in the chain must be patched.
2. **Standalone hash** (isolated, not comma-separated): May be a separate pin for a different domain/endpoint. Patch this too.

**Search for ALL base64 strings of 43 chars + `=` padding:**

```python
import re
data = open('libapp.so', 'rb').read()
for m in re.finditer(rb'[A-Za-z0-9+/]{43}=', data):
    s = m.group()
    if not any(c in s for c in [b'-', b'_']):  # filter non-base64 chars
        offset = m.start()
        context = data[max(0,offset-5):offset+50]
        print(f"offset=0x{offset:08x}: {s.decode()}  context: {context[:60]}")
```

**To identify which hash is the real server SPKI**, connect to the API server directly (no proxy):

```bash
echo | openssl s_client -connect api.target.com:443 -servername api.target.com 2>/dev/null \
  | openssl x509 -noout -pubkey | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl base64
# Match output against hashes found in libapp.so
```

If the API server is unreachable from the PC (firewall, geo-block), check if a related domain shares the same cert/SPKI. Also try resolving the domain from the device.

**To compute Burp CA SPKI** (needed for Burp proxy interception):

```bash
# Download Burp CA cert via proxy (curl may fail with MSYS paths — use Python)
curl -x http://127.0.0.1:8080 -sk "http://burp/cert" -o burp_ca.der
# Or via Python urllib (more reliable on MSYS/Windows):
python3 -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
proxy = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
opener = urllib.request.build_opener(proxy, urllib.request.HTTPSHandler(context=ctx))
resp = opener.open('http://burp/cert', timeout=5)
with open('burp_ca.der', 'wb') as f: f.write(resp.read())
"
# Compute SPKI (MSYS openssl may return empty hash for Windows paths — use Python subprocess):
python3 -c "
import hashlib, base64, subprocess
r1 = subprocess.run(['openssl','x509','-inform','DER','-in','burp_ca.der','-pubkey','-noout'], capture_output=True)
r2 = subprocess.run(['openssl','pkey','-pubin','-outform','DER'], input=r1.stdout, capture_output=True)
print(base64.b64encode(hashlib.sha256(r2.stdout).digest()).decode())
"
```

**Always patch ALL SPKI hashes found in libapp.so, not just one.** The logcat message `ssl_pin_rejected: host=api.target.com presentedPin=XXXXX allowedPins=3` tells you exactly how many pins the app checks. If `allowedPins=3`, you must patch ALL 3 pins to the proxy's SPKI. If you only patch 1 (or a subset), the app will still reject the proxy's certificate because the remaining unpatched pins don't match.

**How to trigger the `ssl_pin_rejected` diagnostic:** Set up iptables DNAT (targeting only the API server IP) to redirect the app's HTTPS traffic to mitmproxy, then check logcat:

```bash
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <API_SERVER_IP> --dport 443 -j DNAT --to-destination <PC_IP>:8888'"
mitmdump --listen-host 0.0.0.0 --listen-port 8888 --set block_global=false
# Start app, trigger API call, then check logcat:
adb shell "logcat -d" | grep "ssl_pin_rejected"
# Output: ssl_pin_rejected: host=api.target.com presentedPin=lDuT2+mr8piWo54/ykUNFmlTtaZR5I7KHglGvfuCs18= allowedPins=3
```

The `presentedPin` is the SPKI of the certificate mitmproxy presented (i.e., your mitmproxy CA SPKI). The `allowedPins=N` tells you how many pins are in the app's allowlist. If you patched 1 pin but `allowedPins=3`, you need to find and patch the other 2 as well.

**Diagnostic: `allowedPins=N` in logcat** — when the app rejects a certificate, it logs the presented pin (the proxy's SPKI) and the number of allowed pins. This tells you exactly how many pins to patch:

```python
old_hashes = [
    b'P+ZBdoU+C4izwzXfZvVTEkC0xLEovi8Qc6X7jKI05/o=',  # server SPKI (in comma chain)
    b'hETpgVvaLC0bvcGG3t0cuqiHvr4XyP2MTwCiqhgRWwU=',  # backup pin (in comma chain)
    b'cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=',  # backup pin (in comma chain)
    b'wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=',  # standalone pin
]
new_hash = b'jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ='  # Burp CA SPKI
for old in old_hashes:
    data = data.replace(old, new_hash)
```

## Rebuilding the APK (Windows/MSYS-Specific)

**PITFALL: `zip` command is not available on MSYS/git-bash.** Use Python's `zipfile` module to update `libapp.so` inside the APK:

```python
import zipfile
patched_libapp = open('libapp.so', 'rb').read()
with zipfile.ZipFile('base.apk', 'r') as zin:
    with zipfile.ZipFile('base_patched.apk', 'w') as zout:
        for item in zin.namelist():
            data = zin.read(item)
            if item == 'lib/arm64-v8a/libapp.so':
                data = patched_libapp  # replace
            zout.writestr(zin.getinfo(item), data)
```

**PITFALL: `apksigner` on Windows is a `.bat` wrapper that doesn't work in MSYS bash.** Use `java -jar` directly:

```bash
# NOT: apksigner sign ...  (bat wrapper fails in MSYS)
# YES: java -jar with Windows path:
java -jar "C:\\Users\\Admin\\AppData\\Local\\Android\\Sdk\\build-tools\\36.1.0\\lib\\apksigner.jar" \
  sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android \
  --ks-key-alias androiddebugkey --out base_patched_signed.apk base_patched_aligned.apk

# zipalign works as a direct exe:
"C:\\Users\\Admin\\AppData\\Local\\Android\\Sdk\\build-tools\\36.1.0\\zipalign.exe" -f 4 base_patched.apk base_patched_aligned.apk
```

## Installing Burp CA as System Cert (Android 15 / Samsung S25)

```bash
# Compute cert hash filename (use Windows openssl path on MSYS)
HASH=$("C:/Program Files/Git/usr/bin/openssl.exe" x509 -inform DER -in burp_ca.der -noout -subject_hash_old)
openssl x509 -inform DER -in burp_ca.der -out burp_ca.pem
cp burp_ca.pem "${HASH}.0"

# Push and install to system store + user store
adb push "${HASH}.0" /data/local/tmp/
adb shell "su -c 'mount -o rw,remount /system'"
adb shell "su -c 'cp /data/local/tmp/${HASH}.0 /system/etc/security/cacerts/'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/${HASH}.0'"
adb shell "su -c 'mount -o ro,remount /system'"
# Also install to Android 14+ user cert store:
adb shell "su -c 'mkdir -p /data/misc/user/0/cacerts-added && cp /data/local/tmp/${HASH}.0 /data/misc/user/0/cacerts-added/ && chmod 644 /data/misc/user/0/cacerts-added/${HASH}.0'"
```

**PITFALL: System CA install alone does NOT fix Java-level SSL errors for all SDKs.** Even after installing Burp CA, SDKs like Datadog may still fail with `Trust anchor for certification path not found` because they use their own trust store or check `NetworkSecurityConfig`. This is expected — Flutter (Dart) traffic is intercepted via the binary-patched SPKI, and Java SDK errors can be ignored as they don't affect app functionality.

## Frida Server Crash on Samsung S25 (Both 17.9.6 and 17.9.11)

**Both frida-server 17.9.6 AND 17.9.11 crash with SIGSEGV in gdbus thread on Samsung S25 (SM-S721B, Android 15).** The `--policy-softener=internal --ignore-crashes` flags do NOT prevent the crash. The crash happens when attaching to a Flutter app process:

```
Cmdline: /data/local/tmp/frida-server --policy-softener=internal --ignore-crashes
signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000078
Abort message: '../../../libsoup/libsoup/server/soup-server-connection.c:716: could not get remote address: Transport endpoint is not connected'
```

**Also: Frida `-f` (spawn) fails on Android 15** with `unable to locate android.os.Process.setArgV0() slot; please file a bug`. Workaround: start the app via `adb shell am start`, then attach with `frida -U -p <PID>`.

**When Frida is unavailable, use the binary patch approach** (patch SPKI hashes in libapp.so — this is the reliable method for Samsung S25 / Android 15).

## Verification After Binary Patch

```bash
# Set proxy to Burp
adb shell settings put global http_proxy <PC_IP>:8080

# Start app and check logcat
adb shell "am start -n com.target.app/.MainActivity"
adb shell "logcat -d" | grep -i "flutter\|ssl\|cert\|pin\|handshake"

# Success indicators:
# - "startup: done" in Flutter logs (app loaded successfully)
# - "remote_config: activated" (API calls working through proxy)
# - NO "ssl_pin_rejected" or "HandshakeException" in logs
# - RaspGuard "threat detected — privileged_access (root/jailbreak)" is OK (detection-only, not blocking)
# - RaspGuard "DeviceIntegrityGate: flags=[hooks, app_integrity]" is OK (detection-only)

# Failure indicators:
# - "HandshakeException: SSLCertVerificationError" → SPKI hash mismatch
# - "ssl_pin_rejected" → pin hash not patched or wrong hash
# - App shows "No network connection" → proxy unreachable or wrong SPKI
# - Datadog "Trust anchor for certification path not found" → Java SDK trust store issue (ignorable)
```

## Advantages Over Frida Runtime Patching

1. **No Frida dependency** — works even when frida-server crashes or is unavailable (e.g., SIGSEGV in gdbus on Samsung S25 / Android 15 — affects BOTH 17.9.6 and 17.9.11)
2. **Persistent** — survives app restarts, no need to re-attach
3. **Stable** — no SIGSEGV crashes from Frida hooks
4. **Simple** — only modifies 44-byte strings in libapp.so
5. **No proxy setup needed** (with server SPKI variant) — direct connection just works

## Disadvantages

1. **Need to repack for different proxy** — if switching between direct connection and Burp, you need to rebuild the APK with a different SPKI hash
2. **APK signature changes** — the app is re-signed with a debug key, which may trigger anti-tampering checks (RaspGuard/Talsec FreeRASP detects this but typically only logs to Datadog, does NOT block login)
3. **No runtime hooks** — cannot hook SSL_write/SSL_read for traffic monitoring (use Burp/mitmproxy proxy with proxy SPKI variant instead)
4. **No traffic interception** (with server SPKI variant) — app connects directly to server, you can only see requests/responses via logcat (if the app logs them)

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| App crashes after install (SIGSEGV) | SPKI hash length mismatch (43 instead of 44 bytes) | Verify `len(new_pin) == 44`. A leading `/` or `+` may have been lost during copy |
| App shows "No network connection" | SPKI hash doesn't match server or proxy cert | Re-check: direct connection needs server's real SPKI; Burp needs Burp's MITM SPKI; mitmproxy needs mitmproxy's MITM SPKI |
| App connects with proxy SPKI but proxy shows no traffic | Flutter ignores system proxy (dart:io HttpClient) | Use iptables REDIRECT + adb reverse to force traffic through proxy. System proxy alone does NOT work with Flutter |
| "Connection refused" after iptables REDIRECT | Proxy is on PC, not device — REDIRECT targets localhost:PORT on device | Add `adb reverse tcp:PORT tcp:PORT` to bridge device localhost to PC localhost |
| mitmproxy `--mode transparent` fails on Windows | Requires WinDivert admin access | Use `--mode reverse:https://api.target.com` instead |
| RaspGuard logs "app_integrity (repackaged/tampered)" | APK was re-signed with debug key | In some versions: only logs to Datadog, does NOT block. In v1.1.31+ (enforcement mode): BLOCKS app with "Unable to open application" screen. If blocked, see `references/raspguard-bypass.md` for smali + libapp.so string patch |
| RaspGuard logs "privileged_access (root/jailbreak)" | Device is rooted | In some versions: only logs to Datadog, does NOT block. In v1.1.31+ (enforcement mode): BLOCKS app. If blocked, see `references/raspguard-bypass.md` |
| FaceLogin shows green checkmark but login fails | Liveness check passed but API call failed or response not received | Check logcat for Dio error logs: `adb logcat -s flutter \| grep -E "DioError\|connection\|Response"` |
| App sends API request but no response in logcat | Response not logged by Dio, or connection failed silently | Check `adb logcat -s flutter` for DioError or connection errors. Check device `/proc/PID/net/tcp` for connection states |
| mitmproxy `--mode transparent` fails on Windows | Requires WinDivert admin access | Use `--mode reverse:https://api.target.com` instead |
| reflutter patched APK crashes | reflutter corrupts libflutter.so | Use this binary patch approach instead (only patches libapp.so) |
| `apksigner` not found | Wrong path | Use full path: `java -jar "C:\Users\Admin\AppData\Local\Android\Sdk\build-tools\35.0.0\lib\apksigner.jar" sign ...` |
| `zipalign` not found | Wrong path | Use full path: `"C:\Users\Admin\AppData\Local\Android\Sdk\build-tools\35.0.0\zipalign.exe" ...` |

## Verified Setup

- Device: Samsung S25 (SM-S721B, Android 15, rooted)
- App: Flutter v1.1.31 with `ssl_pins_sha256` in libapp.so (Dart-layer SPKI pinning)
- Frida 17.9.11 (crashes without `--policy-softener=internal --ignore-crashes` flags)
- Binary patch approach works with three SPKI variants:
  1. **Server's real SPKI** (direct connection, no proxy) — RECOMMENDED for app functionality testing
  2. **Burp's MITM SPKI** (Burp proxy + iptables REDIRECT + adb reverse) — for traffic interception with Burp GUI
  3. **mitmproxy's MITM SPKI** (mitmproxy reverse proxy + iptables REDIRECT + adb reverse) — for scripted traffic capture
- RaspGuard (Talsec FreeRASP) detects APK repack + root. In v1.1.31 enforcement mode, it BLOCKS the app ("Chưa thể mở ứng dụng" screen). Bypass requires BOTH smali patch (return empty threat list) + libapp.so string patch (same-length replacement of `privileged_access` and `rasp_threat:` strings). See `references/raspguard-bypass.md` for full technique.
- APK tools: APKTool 2.11.1 at `C:\Users\Admin\AppData\Local\hermes\tools\apktool.jar`, apksigner/zipalign at `C:\Users\Admin\AppData\Local\Android\Sdk\build-tools\35.0.0\`
- API endpoint discovered via logcat: `POST /api/v1/auth/face` (multipart: citizen_id + face_image)
- FaceLogin liveness check: MiniFASNet-V2 model (live > 0.5 = pass), runs locally on device
- App logs full Dio HTTP requests to logcat (`adb logcat -s flutter`) — useful for API analysis without proxy
