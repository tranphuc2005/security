# Flutter Traffic Interception — Full Working Setup (Android 15)

Tested on: Samsung S25 (SM-S721B), Android 15, rooted, Frida 17.9.6,
Flutter app with Dio HTTP client, BoringSSL via system libssl.so.

## Two Verified Approaches

### Approach A: Burp Suite + iptables REDIRECT (SIMPLER — recommended)

When BoringSSL hooks are active (SSL_CTX_set_custom_verify mode=0, SSL_get_verify_result→0,
X509_verify_cert→1) AND the SPKI pin hash in libapp.so is patched to match Burp's SPKI,
Burp Suite successfully intercepts Flutter HTTPS traffic. This is simpler than mitmproxy
reverse mode and provides Burp's full HTTP History GUI.

```
┌─────────────────────────────────────────────────────────────┐
│ Android Device (rooted)                                     │
│                                                             │
│  Flutter App (Dio + BoringSSL)                              │
│    │                                                        │
│    ▼ HTTPS (port 443)                                       │
│  iptables REDIRECT: 443 → localhost:8080                    │
│  iptables REDIRECT: 80  → localhost:8080                    │
│    │                                                        │
│    ▼ localhost:8080                                         │
│  adb reverse: device:8080 → host:8080                       │
│                                                             │
│  Frida hooks (active in process):                           │
│    ├─ SSL_CTX_set_custom_verify → mode=0 (SSL_VERIFY_NONE)  │
│    ├─ SSL_CTX_set_verify → mode=0                           │
│    ├─ SSL_set_verify → mode=0                               │
│    ├─ SSL_get_verify_result → return 0 (X509_V_OK)          │
│    ├─ SSL_CTX_set_cert_verify_callback → noop               │
│    ├─ X509_verify_cert → return 1                           │
│    └─ SPKI pin hash patched in libapp.so (memory)           │
│                                                             │
│  CA certs installed:                                        │
│    ├─ /system/etc/security/cacerts/9a5ba575.0 (Burp CA)     │
│    └─ /apex/com.android.conscrypt/cacerts/9a5ba575.0        │
└──────────────────────────┬──────────────────────────────────┘
                           │ adb reverse (USB)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Host (Windows)                                              │
│                                                             │
│  Burp Suite on 0.0.0.0:8080                                │
│    └─ "Support invisible proxying" enabled                  │
│    └─ TLS termination with Burp CA                          │
│    └─ HTTP History with full request/response               │
│                                                             │
│  Frida (frida-tools 17.9.6)                                 │
│    └─ frida -U -f com.target.app -l bypass.js               │
└─────────────────────────────────────────────────────────────┘
```

**Why this works with BoringSSL hooks:** The Frida script hooks SSL_CTX_set_custom_verify
and SSL_get_verify_result at the native BoringSSL level, disabling TLS certificate
verification entirely. Burp's CA doesn't even need to be trusted by the app — the hooks
make the app accept any certificate. The SPKI pin patch in libapp.so ensures the Dart-layer
pinning check also passes (the pin hash is replaced with Burp's SPKI hash).

**Key advantage over mitmproxy:** No need to know the API server hostname in advance.
Burp intercepts ALL HTTPS traffic to ALL servers, not just one reverse-proxied target.
The HTTP History GUI provides full request/response inspection, repeater, and scanner.

### Approach B: mitmproxy reverse proxy (for scripted capture or multiple servers)

```
┌─────────────────────────────────────────────────────────────┐
│ Android Device (rooted)                                     │
│                                                             │
│  Flutter App (Dio)                                          │
│    │                                                        │
│    ▼ HTTPS (port 443)                                       │
│  iptables REDIRECT: 443 → localhost:8082                    │
│    │                                                        │
│    ▼ localhost:8082                                         │
│  adb reverse: device:8082 → host:8082                       │
│                                                             │
│  Frida hooks:                                               │
│    ├─ TrustManagerImpl.verifyChain → return chain as-is     │
│    ├─ SSLContext.init → inject TrustAll manager              │
│    ├─ SSL_CTX_set_custom_verify → mode=0 (SSL_VERIFY_NONE)  │
│    ├─ SSL_get_verify_result → return 0 (X509_V_OK)          │
│    └─ X509_verify_cert → return 1                           │
│                                                             │
│  CA certs installed:                                        │
│    ├─ /system/etc/security/cacerts/<hash>.0                 │
│    ├─ /apex/com.android.conscrypt/cacerts/<hash>.0          │
│    └─ /data/misc/user/0/cacerts-added/<hash>.0             │
└──────────────────────────┬──────────────────────────────────┘
                           │ adb reverse (USB)
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Host (Windows)                                              │
│                                                             │
│  mitmproxy --mode reverse:https://api.target.com:443        │
│    └─ Listens on 0.0.0.0:8082                               │
│    └─ Terminates TLS (using mitmproxy CA)                   │
│    └─ Forwards to real server                               │
│    └─ Captures all traffic in traffic.mitm                  │
│                                                             │
│  Frida (frida-tools 17.9.6)                                 │
│    └─ frida -U -f com.target.app -l bypass.js               │
└─────────────────────────────────────────────────────────────┘
```

## Why This Works

1. **iptables REDIRECT** captures ALL outbound 443 traffic at kernel level —
   Flutter's dart:io HttpClient cannot bypass this (unlike system proxy settings
   which Flutter ignores).

2. **adb reverse** maps the device's redirect port to the host's proxy port
   without needing WiFi proxy configuration.

3. **Burp Suite (Approach A):** With BoringSSL hooks active, the app accepts any
   TLS certificate. Burp terminates TLS, decrypts traffic, and provides HTTP History.
   Enable "Support invisible proxying" in Proxy > Options > Listener > Request handling.

4. **mitmproxy (Approach B):** `--mode reverse:https://target-server` acts as a
   TLS-terminating reverse proxy. It presents its own certificate (signed by mitmproxy
   CA) to the app, decrypts the traffic, then re-encrypts and forwards to the real
   server. This is the ONLY mitmproxy mode that works with Flutter on Windows
   (transparent mode requires WinDivert admin access).

5. **Frida hooks** ensure the app trusts the proxy's certificate by bypassing
   SSL_CTX_set_custom_verify, SSL_get_verify_result, and X509_verify_cert.

6. **CA cert installation** in all three stores (system, Conscrypt, user) ensures
   the system trust chain accepts the proxy's CA (needed for non-Flutter native
   plugins like Firebase that use the Java SSL stack).

## Why Other Approaches Failed

| Approach | Why It Failed |
|---|---|
| Burp Suite (system proxy) | Flutter ignores Android system proxy settings (dart:io HttpClient) |
| mitmproxy --mode transparent | Requires WinDivert admin on Windows (`PermissionError: [WinError 5]`) |
| reflutter (patched APK) | Crashes app with native crash in `FlutterJNI.attachToNative` |
| Frida hooks only (no proxy) | Captures SSL_write/SSL_read data in console but no GUI, no request/response correlation |
| System proxy + Frida | Flutter Dio ignores system proxy — traffic goes direct to server |
| Burp WITHOUT BoringSSL hooks | Burp receives raw TLS connections but can't decrypt — Flutter's BoringSSL rejects Burp's CA. Must use Frida BoringSSL hooks to disable cert verification. |
| Burp WITHOUT SPKI pin patch | App rejects Burp's cert at Dart layer (`ssl_pin_rejected`). Must patch SPKI pin hash in libapp.so memory. |

**NOTE:** Burp Suite WITH BoringSSL hooks + SPKI pin patch DOES work (Approach A above).
The key insight is that BoringSSL hooks disable TLS verification at the native level,
so Burp's CA doesn't need to be trusted — the app accepts any certificate.

## Step-by-Step Setup (Approach A: Burp Suite)

### 1. Install Burp CA cert on device

```bash
# Get Burp CA hash
BURP_HASH=$(openssl x509 -inform PEM -in burp-ca.crt -subject_hash_old | head -1)
# Example: 9a5ba575

# Push and install in all three cert stores
adb push burp-ca.crt /sdcard/burp_ca.pem
adb shell "su -c 'cp /sdcard/burp_ca.pem /system/etc/security/cacerts/${BURP_HASH}.0'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/${BURP_HASH}.0'"
adb shell "su -c 'cp /sdcard/burp_ca.pem /apex/com.android.conscrypt/cacerts/${BURP_HASH}.0'"
adb shell "su -c 'chmod 644 /apex/com.android.conscrypt/cacerts/${BURP_HASH}.0'"
adb shell "su -c 'chcon u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts/${BURP_HASH}.0'"
```

### 2. Configure Burp Suite

```
1. Burp Suite → Proxy → Options → Add Listener
   - Bind to port: 8080
   - Bind to address: All interfaces (0.0.0.0)
2. Proxy → Options → Request handling
   - Check "Support invisible proxying" (enables transparent proxy mode)
3. Proxy → Options → Certificate
   - Use Burp's default CA (or import your own)
```

### 3. Set up iptables REDIRECT + adb reverse on device

```bash
# Clear old rules
adb shell "su -c 'iptables -t nat -F OUTPUT'"

# Redirect ALL 443 and 80 traffic to local port 8080
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080'"
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080'"

# Map device port 8080 to host port 8080 (where Burp listens)
adb reverse tcp:8080 tcp:8080
```

**Selective redirect (only target API server, avoid breaking other apps):**

If redirecting ALL 443 traffic breaks other apps (Firebase, Datadog, Google services), redirect only traffic to the specific API server IP:

```bash
# Resolve API server IP first
adb shell "ping -c 1 api.target.com"  # or: nslookup api.target.com

# Redirect only traffic to that IP
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <server_ip> --dport 443 -j DNAT --to-destination <proxy_ip>:<proxy_port>'"

# Example: redirect only dev-sunsite-api.sungroup.com.vn (42.96.60.248) to mitmproxy
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 42.96.60.248 --dport 443 -j DNAT --to-destination 192.168.0.117:8888'"
```

Note: DNAT (not REDIRECT) is needed when redirecting to a different host (proxy on PC). REDIRECT only works for localhost ports. With DNAT, `adb reverse` is NOT needed — the traffic goes directly to the PC's IP.

### 4. Run Frida SSL bypass + launch app

```bash
# Use the template script from templates/flutter-spki-memory-patch.js
# (BoringSSL hooks + SPKI memory patch, NO Java hooks)
frida -U -f com.target.app -l flutter-spki-memory-patch.js
```

### 5. Verify traffic interception

```bash
# Check Burp connections from device
netstat -an | grep ":8080 " | grep ESTABLISHED
# Should show: TCP 192.168.1.x:8080  192.168.1.y:zzzzz  ESTABLISHED

# Check Flutter Dio logs
adb logcat -s flutter | grep -E "Request|Response|POST|GET|http"

# Check for ssl_pin_rejected (should be ABSENT if pin patch worked)
adb logcat -s flutter | grep ssl_pin
```

## Step-by-Step Setup (Approach B: mitmproxy)

### 1. Install mitmproxy CA cert on device

```bash
# Get mitmproxy CA hash
MITM_HASH=$(openssl x509 -inform PEM -in ~/.mitmproxy/mitmproxy-ca-cert.pem -subject_hash_old | head -1)

# Push and install in all three cert stores
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/mitmproxy_ca.pem
adb shell "su -c 'cp /sdcard/mitmproxy_ca.pem /system/etc/security/cacerts/${MITM_HASH}.0'"
adb shell "su -c 'chmod 644 /system/etc/security/cacerts/${MITM_HASH}.0'"
adb shell "su -c 'cp /sdcard/mitmproxy_ca.pem /apex/com.android.conscrypt/cacerts/${MITM_HASH}.0'"
adb shell "su -c 'chmod 644 /apex/com.android.conscrypt/cacerts/${MITM_HASH}.0'"
adb shell "su -c 'chcon u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts/${MITM_HASH}.0'"
adb shell "su -c 'cp /sdcard/mitmproxy_ca.pem /data/misc/user/0/cacerts-added/${MITM_HASH}.0'"
adb shell "su -c 'chmod 644 /data/misc/user/0/cacerts-added/${MITM_HASH}.0'"
```

### 2. Start mitmproxy in reverse proxy mode

```bash
# Determine the API server hostname from the app (check Dio logs or strings in libapp.so)
# Example: dev-sunsite-api.sungroup.com.vn

mitmdump --mode reverse:https://api.target.com \
  --listen-port 8082 \
  --set ssl_insecure=true \
  -w traffic.mitm
```

### 3. Set up iptables REDIRECT + adb reverse on device

```bash
# Clear old rules
adb shell "su -c 'iptables -t nat -F OUTPUT'"

# Redirect all 443 and 80 traffic to local port 8082
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082'"
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8082'"

# Map device port 8082 to host port 8082 (where mitmproxy listens)
adb reverse tcp:8082 tcp:8082
```

### 4. Run Frida SSL bypass + launch app

```bash
# Use the template script from templates/flutter-ssl-bypass.js
# (BoringSSL hooks + Java SSL + RootBeer bypass)
frida -U -f com.target.app -l flutter-ssl-bypass.js
```

### 5. Verify traffic interception

```bash
# Check mitmproxy log for captured requests
tail -f mitmproxy.log
# Should show: "client connect", "server connect", "GET/POST https://...", "<< 200 OK"

# Check Flutter Dio logs (app logs full request/response details)
adb logcat -s flutter | grep -E "Request|Response|POST|GET|http"
```

## Multiple API Servers

If the app communicates with multiple API servers (e.g., api.target.com + cdn.target.com):

- **Burp Suite (Approach A):** Handles multiple servers automatically — all HTTPS traffic
  is intercepted regardless of destination. No configuration needed.
- **mitmproxy (Approach B):** Reverse mode only handles one server. Solutions:
  1. Multiple mitmproxy instances on different ports
  2. mitmproxy addon script that routes based on SNI
  3. Use Burp Suite (Approach A) instead

## Frida Session Management

### Keeping Frida alive during app interaction

```bash
# PROBLEM: `timeout 60 frida -U -f com.app -l bypass.js` kills the app when timeout expires
# SOLUTION: Run Frida in background without timeout, or spawn app separately

# Option 1: Background Frida (keeps app alive after Frida exits)
frida -U -f com.target.app -l bypass.js > frida_output.txt 2>&1 &
# App stays alive after Frida disconnects. Memory patches persist in process RAM.

# Option 2: Spawn app separately, then attach Frida
adb shell am start -n com.target.app/.MainActivity
sleep 2
frida -U -n com.target.app -l bypass.js
# Attach mode — hooks don't persist after detach, but memory patches do.

# Option 3: Long timeout (Frida stays connected for full session)
timeout 300 frida -U -f com.target.app -l bypass.js > frida_output.txt 2>&1 &
```

### Frida "Connection terminated" — NOT a crash

When the Frida CLI process exits (timeout, pipe issue, background process management),
it prints "Connection terminated". This does NOT mean the app crashed. The app continues
running with:
- **Memory patches (SPKI pin hash):** Persist in process RAM until app is killed
- **Interceptor.replace hooks (BoringSSL):** Trampolines remain installed in the process
- **Interceptor.attach hooks:** May or may not persist after detach

To verify the app is still running:
```bash
adb shell ps -A | grep <package>
```

### Restarting frida-server

frida-server crashes frequently on heavy hook scripts. Symptoms:
- `frida-ps -U` hangs or shows no output
- `frida -U -f` shows "Failed to spawn: need Gadget to attach on jailed Android"

```bash
# Restart frida-server
adb shell "su -c 'killall frida-server 2>/dev/null; sleep 1; setsid /data/local/tmp/frida-server >/dev/null 2>&1 &'"

# Verify it's running
frida-ps -U | head -3
```

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Client TLS handshake failed. The client does not trust the proxy's certificate." | Proxy CA not installed or Frida hooks not active | Install CA in all 3 stores + verify Frida hooks loaded. With BoringSSL hooks active, CA trust is not required (hooks disable verification). |
| Burp shows connections but no HTTP History | "Support invisible proxying" not enabled in Burp | Proxy → Options → Listener → Request handling → Check "Support invisible proxying" |
| Burp shows no connections from device | iptables rules or adb reverse not set up | `adb shell "su -c 'iptables -t nat -L OUTPUT -n'"` + `adb reverse --list` |
| mitmproxy shows connections but no HTTP requests | TLS handshake failing | Check Frida output for "BYPASS" messages — if no bypass, hooks aren't working |
| App shows "Không có kết nối mạng" (no network) | Traffic not reaching proxy | Verify iptables rules + adb reverse |
| Frida "Java undefined" | Flutter app, Java VM not ready at spawn | Use retry loop with `typeof Java === 'undefined'` check (or skip Java hooks entirely — see v2 template) |
| mitmproxy "Transparent mode on Windows is unsupported" | Wrong mode | Use `--mode reverse:https://server` not `--mode transparent` |
| App crashes after reflutter patch | reflutter corrupts libflutter.so | Don't use reflutter — use Burp + iptables approach (Approach A) or mitmproxy reverse (Approach B) |
| Frida "Connection terminated" | Frida CLI process exited (timeout/pipe) | NOT a crash. App continues running. Verify: `adb shell ps -A \| grep <package>`. Memory patches persist. |
| `timeout 60 frida` kills app | timeout sends SIGTERM to frida which kills spawned app | Use `frida -U -f ... &` (background) or spawn separately + attach |
| `ssl_pin_rejected` in logcat despite BoringSSL hooks | App has Dart-layer SPKI pinning in libapp.so | Runtime memory patch: find pin hash in libapp.so and overwrite with proxy's SPKI (see §4.1.1 of SKILL.md) |
| ESTABLISHED Burp connections but no HTTP requests in History | BoringSSL hooks not active (Frida disconnected) or pin not patched | Re-run Frida bypass script. Verify SSL_WRITE logs in Frida output. Check `adb logcat -s flutter \| grep ssl_pin` — should be empty. |

## Approach C: Binary Patch (No Frida) + ADB Reverse + DNAT to Localhost (No-Frida, No-Root-Frida)

**Use when:** Frida is unavailable/crashes (Samsung S25 SIGSEGV), the server blocks the device's IP but allows the PC's IP, and Windows Firewall blocks the device from TCP-connecting to the PC.

This is the verified working approach for Flutter apps with Dart-layer SPKI pinning when Frida cannot be used. No runtime instrumentation needed — the SPKI pin is patched directly in libapp.so.

```
┌─────────────────────────────────────────────────────────────┐
│ Android Device (rooted, NO Frida)                           │
│                                                             │
│  Flutter App (Dio + Dart-layer SPKI pinning)                │
│    │                                                        │
│  libapp.so SPKI pins patched → mitmproxy CA SPKI            │
│  RaspGuard/Talsec bypass via smali patches (3 layers)       │
│    │                                                        │
│    ▼ HTTPS to 42.96.60.248:443 (server blocks device IP)   │
│  iptables DNAT: 42.96.60.248:443 → 127.0.0.1:8443          │
│    │                                                        │
│    ▼ localhost:8443                                         │
│  adb reverse: device:8443 → host:8443 (USB tunnel)          │
│  (bypasses Windows Firewall — no inbound TCP needed)        │
└──────────────────────────┬──────────────────────────────────┘
                           │ ADB USB tunnel
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ Host (Windows)                                              │
│                                                             │
│  mitmdump --mode reverse:https://api.target.com:443         │
│    └─ Listens on 0.0.0.0:8443                               │
│    └─ Terminates TLS with mitmproxy CA (matches patched SPKI)│
│    └─ Forwards to real server (PC IP is not blocked)        │
│    └─ Captures all traffic in traffic.mitm                  │
└─────────────────────────────────────────────────────────────┘
```

**Why ADB reverse is needed (not just DNAT to PC IP):**

- `iptables DNAT --to-destination <PC_IP>:<PORT>` sends traffic to the PC's IP, but **Windows Firewall blocks all inbound TCP from the device** by default.
- `adb shell "nc <PC_IP> <PORT>"` from device → timeout (even though `ping <PC_IP>` works — ICMP allowed, TCP blocked).
- Adding a Windows Firewall rule requires admin privileges (`netsh advfirewall` fails without elevation).
- **ADB reverse** tunnels through USB, completely bypassing Windows Firewall: `adb reverse tcp:8443 tcp:8443` maps device `localhost:8443` to PC `localhost:8443` via the ADB USB connection.
- DNAT target is `127.0.0.1:8443` (NOT the PC IP), so traffic goes to device localhost → ADB reverse → PC.

**Why this works without Frida:** The SPKI pins in libapp.so are patched to match mitmproxy's CA SPKI. When mitmproxy terminates TLS, it presents a certificate whose SPKI matches the patched pins. No runtime hooks needed — the pin check passes natively.

### Step-by-Step Setup (Approach C)

#### 1. Patch libapp.so with mitmproxy CA SPKI

```bash
# Get mitmproxy CA SPKI hash
python3 -c "
import base64, hashlib, subprocess
r1 = subprocess.run(['openssl','x509','-in','$HOME/.mitmproxy/mitmproxy-ca-cert.pem','-pubkey','-noout'], capture_output=True, text=True)
r2 = subprocess.run(['openssl','pkey','-pubin','-outform','DER'], input=r1.stdout.encode(), capture_output=True)
print(base64.b64encode(hashlib.sha256(r2.stdout).digest()).decode())
"
# Output: lDuT2+mr8piWo54/ykUNFmlTtaZR5I7KHglGvfuCs18=

# Patch ALL SPKI pins in libapp.so to mitmproxy CA SPKI
python3 -c "
data = bytearray(open('base_decoded/lib/arm64-v8a/libapp.so', 'rb').read())
mitm_spki = b'lDuT2+mr8piWo54/ykUNFmlTtaZR5I7KHglGvfuCs18='  # from step above
# Find all 44-char base64 strings ending with '=' and replace
# (or replace known original pins)
original_pins = [
    b'wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=',
    b'P+ZBdoU+C4izwzXfZvVTEkC0xLEovi8Qc6X7jKI05/o=',
    b'hETpgVvaLC0bvcGG3t0cuqiHvr4XyP2MTwCiqhgRWwU=',
    b'cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=',
]
for pin in original_pins:
    count = data.count(pin)
    if count > 0:
        data = data.replace(pin, mitm_spki)
        print(f'Patched: {pin.decode()[:20]}... ({count}x)')
print(f'mitmproxy SPKI count: {data.count(mitm_spki)}')
open('base_decoded/lib/arm64-v8a/libapp.so', 'wb').write(data)
"
```

#### 2. Patch RaspGuard/Talsec (if app has RaspGuard — see references/raspguard-bypass.md)

3 layers: smali scan bypass, libapp.so threat strings, Talsec native engine init bypass.

#### 3. Rebuild + sign + install APK

```bash
java -jar "$APKTOOL" b base_decoded -o base_mitm.apk
zipalign -f -v 4 base_mitm.apk base_mitm_aligned.apk
cmd.exe /c "$APKSIGNER sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out base_mitm_signed.apk base_mitm_aligned.apk"
adb uninstall com.target.app
adb install base_mitm_signed.apk
```

#### 4. Start mitmproxy on PC

```bash
mitmdump --mode reverse:https://api.target.com:443 --listen-port 8443 --set ssl_insecure=true -w traffic.mitm
```

#### 5. Set up ADB reverse + iptables DNAT on device

```bash
# ADB reverse: device localhost:8443 → PC:8443 (bypasses Windows Firewall)
adb reverse tcp:8443 tcp:8443

# iptables DNAT: redirect API server traffic to device localhost (→ ADB reverse → PC mitmproxy)
adb shell "su -c 'iptables -t nat -F OUTPUT'"  # clear old rules
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <API_SERVER_IP> --dport 443 -j DNAT --to-destination 127.0.0.1:8443'"

# Verify: device should be able to connect to 127.0.0.1:8443
adb shell "su -c 'echo test | timeout 3 toybox nc 127.0.0.1 8443 && echo OK || echo FAIL'"
# Should print: OK

# Verify: DNAT redirect works (connecting to server IP:443 should reach mitmproxy)
adb shell "su -c 'echo test | timeout 3 toybox nc <API_SERVER_IP> 443 && echo DNAT_OK || echo DNAT_FAIL'"
# Should print: DNAT_OK
```

#### 6. Launch app and verify

```bash
adb shell "am start -n com.target.app/.MainActivity"
sleep 10

# Check logcat for API calls (Flutter Dio logs full requests)
adb shell "logcat -d" | grep "flutter" | grep -iE "Request|POST|Response|DioError|ssl_pin"

# Success indicators:
# - "POST https://api.target.com/..." — app is making API calls
# - "<< 401 Unauthorized" or "<< 200 OK" — server is responding (through mitmproxy)
# - NO "ssl_pin_rejected" — SPKI patch is working
# - NO "DioExceptionType.connectionTimeout" — traffic is flowing
# - mitmproxy log shows: "POST https://api.target.com/... << 401/200"

# Failure indicators:
# - "DioExceptionType.connectionTimeout" — DNAT or ADB reverse not set up, or mitmproxy not running
# - "ssl_pin_rejected" — SPKI hash mismatch (wrong CA SPKI in libapp.so)
# - "RaspGuard: threat detected" — RaspGuard bypass not applied or incomplete
```

#### 7. Cleanup

```bash
adb shell "su -c 'iptables -t nat -F OUTPUT'"  # remove DNAT rules
adb reverse --remove-all  # remove ADB reverse
# Kill mitmproxy (Ctrl+C or taskkill)
```

### Approach C vs Approach A/B

| Feature | A (Burp+Frida) | B (mitmproxy+Frida) | C (Binary Patch+ADB Reverse) |
|---|---|---|---|
| Frida required | Yes | Yes | **No** |
| Frida crashes (Samsung S25) | Problematic | Problematic | **Not applicable** |
| Captures all HTTPS | Yes (all servers) | Yes (one server) | One server (reverse mode) |
| Burp GUI (Repeater/Scanner) | Yes | No | No (use mitmweb for GUI) |
| SPKI patch needed | Runtime (memory) | Runtime (memory) | **Binary (permanent)** |
| RaspGuard bypass | Frida hooks | Frida hooks | **Smali + libapp.so patches** |
| Server IP blocking | Not handled | Not handled | **Handled (PC connects, not device)** |
| Windows Firewall | Needs inbound from device | Needs inbound from device | **Bypassed (ADB USB tunnel)** |
| Setup complexity | Medium | Medium | High (rebuild APK) |

**Choose Approach C when:**
- Frida crashes on the device (Samsung S25 / Android 15 SIGSEGV)
- Server blocks the device's IP but allows the PC's IP
- Windows Firewall blocks the device from TCP-connecting to the PC
- You need a persistent solution (survives app restarts, no Frida re-attach)

## Removing the Setup (Cleanup)

```bash
# Remove iptables rules
adb shell "su -c 'iptables -t nat -F OUTPUT'"

# Remove adb reverse
adb reverse --remove-all

# Remove system proxy (if set)
adb shell settings put global http_proxy :0

# Kill mitmproxy (if used)
# (Ctrl+C or taskkill //F //IM mitmdump.exe)

# Close Burp Suite (if used)
# (Proxy → Options → Remove listener on 8080)
```
