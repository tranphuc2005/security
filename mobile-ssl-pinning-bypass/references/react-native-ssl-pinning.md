# React Native SSL Pinning Analysis and Bypass

## Overview

React Native apps typically implement SSL pinning via the `react-native-ssl-public-key-pinning` library (package: `com.sslpublickeypinning`). Unlike Flutter (where pins are compiled into `libapp.so`), React Native loads SPKI pins **dynamically from the JS bundle at runtime** — the native module receives a `ReadableMap` of domains to pin arrays from JS and constructs an OkHttp `CertificatePinner`.

This means: (1) pins are NOT hardcoded in smali, (2) the JS bundle must be analyzed to find them, (3) the smali can be patched to skip pin initialization entirely.

## Detection

### Identify the library in APK

```bash
# Decompile APK
apktool d target.apk -o target_decoded

# Check for the SSL pinning module
grep -rl "sslpublickeypinning\|SslPublicKeyPinning\|CertificatePinner" target_decoded/smali* 2>/dev/null

# Check for cert files in assets
ls target_decoded/assets/cert/  # e.g., uat.pem

# Check for SSL pinning config in JS bundle
strings -n 5 target_decoded/assets/index.android.bundle | grep -iP "disableSslPinning|initializeSslPinning|isSslPinningAvailable|publicKeyHashes"
```

### Key smali files

| File | Purpose |
|---|---|
| `SslPublicKeyPinningModule.smali` | Main module: `initialize()`, `disable()`, `initializeCertificatePinner()` |
| `NativeSslPublicKeyPinningSpec.smali` | Abstract spec: `initialize(ReadableMap, Promise)`, `disable(Promise)` |
| `a.smali` | Lambda: hooks into OkHttp `NetworkingModule.customClientBuilder` |
| `cb/g.smali` | OkHttp `CertificatePinner` (obfuscated) |
| `cb/z.smali` | OkHttp `OkHttpClient` (obfuscated) |

### How pinning works (flow)

```
JS calls: SslPublicKeyPinning.initialize({ domain: { publicKeyHashes: ["base64hash"], expirationDate: "2025-12-31", includeSubdomains: true } })
    -> SslPublicKeyPinningModule.initialize(ReadableMap, Promise)
    -> initializeCertificatePinner(ReadableMap)
    -> For each domain: read "publicKeyHashes" array, prepend "sha256/", call CertificatePinner.Builder.add(hostname, pins[])
    -> certificatePinner = builder.build() (stored as static field)
    -> Installed via NetworkingModule.customClientBuilder -> OkHttpClient.certificatePinner(pinner)
```

## Hermes JS Bundle Analysis

React Native apps compiled with Hermes produce bytecode (`index.android.bundle`). `strings` still extracts readable strings:

```bash
# Extract API URLs
strings -n 8 assets/index.android.bundle | grep -oP 'https?://[a-zA-Z0-9._:/-]+' | sort -u

# Find API domains (filter out mozilla/w3.org/react)
strings -n 5 assets/index.android.bundle | grep -iP 'edufy|seabank|api\.' | sort -u

# Find SSL pinning config functions
strings -n 5 assets/index.android.bundle | grep -iP 'disableSslPinning|initializeSslPinning|isSslPinningAvailable'

# Find auth-related strings
strings -n 8 assets/index.android.bundle | grep -iP 'Authentication|/api/|login|register|otp|biometric|token|Bearer'

# Extract domain from cert file in assets
openssl x509 -in assets/cert/uat.pem -text -noout | grep -A1 "Subject Alternative Name"
```

## Bypass Methods

### Method 1: Patch smali `initializeCertificatePinner` (no root, APK repack)

Patch `SslPublicKeyPinningModule.smali` to make `initializeCertificatePinner` a no-op:

```smali
.method private static initializeCertificatePinner(Lcom/facebook/react/bridge/ReadableMap;)V
    .locals 0
    return-void
.end method
```

This prevents any pins from being registered. Rebuild with apktool + zipalign + apksigner.

### Method 2: Frida hook (runtime, no repack)

```javascript
Java.perform(function() {
    try {
        var SslPinningModule = Java.use('com.sslpublickeypinning.SslPublicKeyPinningModule');
        SslPinningModule.getCertificatePinner.implementation = function() { return null; };
        SslPinningModule.initializeCertificatePinner.implementation = function(map) {};
    } catch(e) {}
    // Also hook OkHttp CertificatePinner.check as fallback (class may be obfuscated)
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}
});
```

### Method 3: System proxy (no iptables needed)

React Native uses OkHttp which **respects Android system proxy settings** (unlike Flutter which ignores them):

```bash
adb shell settings put global http_proxy <PC_IP>:8080
# No iptables REDIRECT or adb reverse needed
```

Use NSC + Method 1 or 2 together (NSC alone does not bypass CertificatePinner).

## Critical Pitfalls

### PITFALL: Smali patch must remove ALL original method body (VerifyError)

When patching `initializeCertificatePinner` to a no-op, you must **replace the entire method body** — not just insert `return-void` before the old code. If you leave the original code after `return-void`, the smali assembler includes it as unreachable code with register references that exceed `.locals 0`, causing a runtime `VerifyError`:

```
Error: Exception in HostObject::get for prop 'SslPublicKeyPinning':
  java.lang.VerifyError: Verifier rejected class com.sslpublickeypinning.SslPublicKeyPinningModule:
  initializeCertificatePinner(ReadableMap): register index out of range (1 >= 1)
```

The app continues to run (JS catches the error), but SSL pinning is NOT initialized — which is actually the desired outcome (pinning disabled). However, the error may cause unexpected behavior in other code paths that reference the module.

**Correct patch** — replace the ENTIRE method body from `.method` to `.end method`:

```smali
.method private static initializeCertificatePinner(Lcom/facebook/react/bridge/ReadableMap;)V
    .locals 0

    # PATCHED: SSL pinning disabled
    return-void
.end method
```

Use `patch` or a text editor to replace from `.method private static initializeCertificatePinner` through the next `.end method` — do NOT just insert `return-void` at the top and leave the rest.

### PITFALL: targetSdk 35+ requires network_security_config.xml for user CA trust

React Native apps with `targetSdk=35` (Android 15) do NOT trust user-installed CA certificates by default. Even with SSL pinning disabled, mitmproxy's CA will be rejected by the system trust store. You MUST add a `network_security_config.xml`:

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

And reference it in `AndroidManifest.xml`:
```xml
<application android:networkSecurityConfig="@xml/network_security_config" ...>
```

Rebuild + sign + install the APK with both patches (smali no-op + NSC).

### PITFALL: mitmproxy reverse proxy for server-IP-blocked scenarios

Unlike Flutter (which ignores system proxy), React Native OkHttp respects Android system proxy. However, if the app's server blocks the device IP but allows the PC IP, use the same ADB reverse + DNAT + mitmproxy approach as Flutter:

```bash
# 1. Start mitmproxy reverse proxy on PC
mitmdump --mode reverse:https://api.target.com:443 --listen-port 8443 --set ssl_insecure=true

# 2. ADB reverse (bypasses Windows Firewall)
adb reverse tcp:8443 tcp:8443

# 3. iptables DNAT (redirect only API server traffic)
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <API_SERVER_IP> --dport 443 -j DNAT --to-destination 127.0.0.1:8443'"

# 4. Install mitmproxy CA as system cert (see main SKILL.md §2.5)
```

## Verification: Confirming Traffic Flows Through Proxy

After installing the patched APK, verify the bypass works end-to-end:

### Step 1: Check app connects to proxy (not direct)

```bash
# Get the app PID
PID=$(adb shell "pidof com.target.app" | tr -d '\r')

# Check /proc/PID/net/tcp for connections to proxy IP:port
# Look for remote address matching PC_IP:PROXY_PORT (e.g., C0A80120:1F90 = 192.168.1.32:8080)
# Hex format: little-endian IP, big-endian port
# C0A80120 = 192.168.1.32, 1F90 = 8080
adb shell "su -c 'cat /proc/$PID/net/tcp'" | grep -v "00000000:0000\|0100007F"
adb shell "su -c 'cat /proc/$PID/net/tcp6'" | grep -v "00000000000000000000000000000000"
```

If you see ESTABLISHED connections (state 01) to the proxy IP:port from the app's UID, the app is routing through the proxy. To find the app's UID: `adb shell "su -c 'cat /proc/$PID/status'" | grep Uid` — the numeric UID (e.g., 10343) appears in the 4th column of `/proc/PID/net/tcp`.

### Step 2: Check ReactNativeJS logs for API calls

```bash
# React Native apps log API calls to logcat with tag "ReactNativeJS"
# These logs show the actual API URLs being called — definitive proof the bypass works
adb shell "logcat -d" | grep "ReactNativeJS" | tail -20
```

Look for `network_XMLHttpRequest_https://...` entries showing API URLs and response times. This is the definitive confirmation that SSL pinning is bypassed and traffic is flowing through the proxy.

Example successful output:
```
ReactNativeJS: 'network_XMLHttpRequest_https://api.target.com/api/v1/SystemSettings/GetByKey?key=...':
ReactNativeJS:   { startTime: 41729706.43, endTime: 41732060.36, totalTime: 2353.92 }
ReactNativeJS:   responseURL: 'https://api.target.com/api/v1/SystemSettings/GetConfigAvt'
```

### Step 3: Check for SSL errors

```bash
# No SSL errors should appear if bypass is working
adb shell "logcat -d" | grep -iE "SSL|pinning|CertificatePinner|javax.net.ssl|SSLPeerUnverified" | grep "$PID"
```

If no SSL errors AND ReactNativeJS shows API calls with response data, the bypass is confirmed working.

### Step 4: Verify login screen appears (end-to-end test)

The ultimate proof that SSL bypass works is the app reaching its login screen (or main UI). Use `uiautomator dump` to check what's on screen:

```bash
adb shell "uiautomator dump /sdcard/ui.xml"
adb shell "cat /sdcard/ui.xml" | python3 -c "
import sys, xml.etree.ElementTree as ET
data = sys.stdin.read()
root = ET.fromstring(data)
for node in root.iter('node'):
    text = node.get('text', '')
    if text.strip():
        print(f'text=\"{text}\"')
"
```

If you see login form elements (e.g., "Đăng nhập", "Nhập tên tài khoản", "Nhập mật khẩu"), the SSL bypass is fully working — the app loaded its config from the API server through the proxy.

If the app shows a loading spinner (e.g., "Đang tải dữ liệu..."), do NOT immediately blame the SSL patch. Follow the diagnostic checklist in the "App Stuck on Loading" section below — check WiFi first, then test the original unpatched app.

### Diagnostic flowchart for "app stuck on loading"

```
App shows loading spinner after SSL patch
│
├── Check logcat for ReactNativeJS API calls
│   ├── API calls present (network_XMLHttpRequest_https://...) → SSL bypass works, loading is app logic
│   └── Only "Running <appname>" → no API calls at all
│       ├── Check /proc/PID/net/tcp → zero ESTABLISHED connections?
│       │   ├── YES → device has no network (WiFi down, no route)
│       │   │   └── Fix: adb shell "ip addr show wlan0" → look for NO-CARRIER
│       │   └── NO (connections to proxy) → app making requests but hanging
│       │       └── Check proxy (Burp/mitmproxy) is running and listening
│       └── Test ORIGINAL unpatched app (install base.apk, no proxy)
│           ├── Also hangs? → NOT a patch issue (server down, WiFi down, app version)
│           └── Works fine? → patch broke something (re-examine smali)
```

## Complete Build and Install Pipeline (Windows)

Tested on Windows with APKTool 2.11.1, Android SDK build-tools 35.0.0, debug.keystore:

```bash
# 1. Decompile (if not already done)
java -jar "C:/Users/Admin/AppData/Local/hermes/tools/apktool.jar" d target.apk -o target_decoded

# 2. Patch smali (see Method 1 above)
# Edit SslPublicKeyPinningModule.smali: replace initializeCertificatePinner body with return-void

# 3. Verify network_security_config.xml trusts user CA
# (see PITFALL: targetSdk 35+ above)

# 4. Build patched APK
java -jar "C:/Users/Admin/AppData/Local/hermes/tools/apktool.jar" b target_decoded -o target_patched.apk --use-aapt2

# 5. Zipalign
"C:/Users/Admin/AppData/Local/Android/Sdk/build-tools/35.0.0/zipalign.exe" -f -p 4 target_patched.apk target_aligned.apk

# 6. Sign with debug.keystore (use Windows backslash paths for apksigner)
"C:/Users/Admin/AppData/Local/Android/Sdk/build-tools/35.0.0/apksigner.bat" sign \
  --ks "C:\Users\Admin\pentest\sunsite_redteam\debug.keystore" \
  --ks-pass pass:android \
  --ks-key-alias androiddebugkey \
  --key-pass pass:android \
  --out target_signed.apk target_aligned.apk

# 7. Install
adb -s <DEVICE_SERIAL> uninstall com.target.app
adb -s <DEVICE_SERIAL> install target_signed.apk

# 8. Set proxy to Burp/mitmproxy
adb shell settings put global http_proxy <PC_IP>:8080

# 9. Launch and verify (see Verification section above)
adb shell am start -n com.target.app/.MainActivity
```

NOTE: apksigner on Windows requires backslash paths for the keystore (`C:\Users\...`), while bash commands use forward slashes. Using `/c/Users/...` with apksigner causes `FileNotFoundException`.

## Critical Debugging: "App Stuck on Loading" After SSL Patch

### PITFALL: App stuck on "Đang tải dữ liệu..." (Loading data...) — check device network FIRST, not SSL patch

When a patched React Native app shows a loading spinner indefinitely after launch, the instinct is to blame the SSL patch. **Always verify device network connectivity first** — the original unpatched app will also hang on the same loading screen if the device has no internet.

**Diagnostic checklist (run in this order):**

```bash
# 1. Check WiFi status — NO-CARRIER means WiFi is disconnected
adb shell "ip addr show wlan0" | head -3
# If you see: <NO-CARRIER,BROADCAST,MULTICAST,UP,LOWER_UP> → WiFi is DOWN

# 2. Check DNS resolution from device
adb shell "ping -c 2 -W 3 google.com"    # "unknown host" = DNS broken
adb shell "ping -c 2 -W 3 8.8.8.8"       # "Network is unreachable" = no route

# 3. Test API server directly from PC (bypasses device entirely)
curl -k "https://api.target.com/api/v1/health" -w "HTTP: %{http_code}" -s

# 4. Check if the ORIGINAL (unpatched) app also hangs
# Install original APK, launch without proxy — if it also hangs, it's NOT the patch
```

**Key insight:** `wlan0: <NO-CARRIER>` means the device WiFi adapter is disconnected. The app's JS bundle loads (logcat shows `ReactNativeJS: Running "elearning"`) but no API calls are made — the app sits at "Đang tải dữ liệu..." waiting for network. Zero TCP connections in `/proc/PID/net/tcp` confirms this.

**This was observed on Samsung S25 (SM-S721B, Android 15) with com.vn.seabank v1.0.0:** The patched APK was incorrectly blamed for the app hanging, but the original APK also hung — the real cause was WiFi disconnection. After WiFi reconnection, the patched app worked correctly and API traffic flowed through the proxy.

### PITFALL: App stuck on loading after `pm clear` — server returning 401/404 on config endpoints

After `adb shell pm clear com.target.app`, the app may get stuck on a loading spinner (e.g., "Đang tải dữ liệu...") even though the SSL patch is working correctly. The cause: the app makes initial config API calls (e.g., `GetByKey`, `GetConfigAvt`) that return 401 (requires auth) or 404 (not found) when there is no cached session/token. The JS error handler does not gracefully dismiss the loading screen in this scenario.

**Key diagnostics:**
- ReactNativeJS logs show API calls ARE being made (status 401, 404) — SSL bypass is working
- The app previously worked (showed login screen) when it had cached data from a prior install
- After `pm clear`, cached config/token is wiped, and the app cannot proceed past loading
- Installing the patched APK WITHOUT `pm clear` (preserving cached data) allows the app to proceed normally

**Fix: Do NOT `pm clear` when reinstalling a patched APK.** Use `adb install -r` (reinstall over existing data) to preserve the cached config. The SSL patch only affects smali code, not app data. If data must be cleared, the app may need the server to return 200 on all config endpoints.

### PITFALL: React Native connectivity check (clients3.google.com/generate_204) blocks app on loading screen

Many React Native apps check internet connectivity by requesting `https://clients3.google.com/generate_204` (Google's connectivity check endpoint) before making any API calls. If this request times out (30s default), the app logs `ReactNativeJS: No Internet Connection! Please check your network.` and returns a custom HTTP status **455** to all subsequent API calls, blocking the app on the loading screen indefinitely.

**Symptoms:**
- Logcat shows `ReactNativeJS: Running "<appname>"` but NO API calls for 30s
- After 30s: `ReactNativeJS: No Internet Connection! Please check your network.` + `ReactNativeJS: 'handleErrors response', { status: 455 }`
- App stuck on loading spinner (e.g., "Đang tải dữ liệu...")
- Zero TCP connections in `/proc/PID/net/tcp`
- Device CAN ping the API server and Google (`ping -c 2 google.com` works)
- But `clients3.google.com/generate_204` XMLHttpRequest hangs (no endTime in ReactNativeJS perf logs)

**This is NOT an SSL issue.** The SSL bypass is working correctly. The connectivity check fails because:
1. Proxy was recently cleared (`settings put global http_proxy :0`) but OkHttp cached the old proxy — app sends SYN_SENT to old proxy IP:port even after proxy is cleared
2. DNS resolution for `clients3.google.com` fails on the device's network
3. The app's `XMLHttpRequest` to Google goes through OkHttp which may respect a stale proxy setting

**Fix:**
```bash
# 1. Clear proxy completely
adb shell "settings delete global http_proxy"
adb shell "settings delete global global_http_proxy_host"
adb shell "settings delete global global_http_proxy_port"
adb shell "settings put global http_proxy :0"

# 2. FORCE-STOP the app (critical — OkHttp caches proxy at client creation time)
adb shell "am force-stop com.target.app"

# 3. Relaunch
adb shell "monkey -p com.target.app -c android.intent.category.LAUNCHER 1"
```

**Diagnostic:** Check if `clients3.google.com/generate_204` has an `endTime` in ReactNativeJS perf logs. If it has `startTime` but no `endTime`, the connectivity check is hanging. Check `/proc/PID/net/tcp6` for SYN_SENT connections to the old proxy IP:port (hex `1F90` = 8080).

### PITFALL: OkHttp caches proxy settings — force-stop after proxy changes

React Native's OkHttp client reads the system proxy setting at client creation time (when `NetworkingModule` initializes). If you change the proxy setting while the app is running, or after `pm clear`, the OkHttp client may still use the old proxy. Symptoms: app sends `SYN_SENT` to old proxy IP:port (visible in `/proc/PID/net/tcp6`) even though `settings get global http_proxy` returns `:0`.

**Fix:** Always `adb shell am force-stop com.target.app` after changing proxy settings, then relaunch. Do NOT rely on the app picking up proxy changes at runtime.

### PITFALL: App needs cached data from previous install to proceed past loading screen

Some React Native apps cache initial configuration (colors, images, login config) in MMKV/AsyncStorage on first launch. On subsequent launches, the app reads cached config first, then fetches fresh config in the background. If the cache is wiped (`pm clear`), the app must fetch ALL config from the server before rendering the UI. If any config endpoint returns an error (401, 404, timeout), the app's JS may hang on the loading screen indefinitely.

**Workaround for pentesting:** Install the patched APK over the existing app (without clearing data):
```bash
adb install -r seabank_ssl_bypass_signed.apk  # reinstall, preserve data
# Do NOT use: adb shell pm clear com.target.app
```

### PITFALL: Do NOT toggle proxy settings once SSL bypass is working

Once the proxy is set and the app is loading correctly (API calls flowing through Burp/mitmproxy), **do NOT change the proxy settings**. This is the single most common cause of "app suddenly stopped working" during pentest sessions. Each toggle of `settings put global http_proxy` / `settings delete global http_proxy` requires a force-stop + relaunch, and `:0` (port 0) breaks OkHttp silently.

**What happens when you toggle proxy:**
1. `settings put global http_proxy :0` (clearing to port 0) → OkHttp reads proxy as `:0`, tries to connect to port 0, all requests fail with "No Internet Connection" (status 455)
2. `settings delete global http_proxy` (deleting) → OkHttp has no proxy, connects directly to server (bypasses Burp entirely)
3. Re-setting proxy after clearing → `global_http_proxy_host` and `global_http_proxy_port` may persist with OLD values, causing OkHttp to connect to the OLD proxy IP (SYN_SENT to wrong IP:port)
4. Force-stopping and relaunching after proxy change → OkHttp re-reads proxy at client creation time, but if `global_http_proxy_host` still has old value, it uses that

**The golden rule for proxy management during React Native SSL pentest:**

```bash
# ONE-TIME SETUP (do this once, then leave it alone):
# 1. Set proxy
adb shell settings put global http_proxy <PC_IP>:8080
# 2. Install patched APK (WITHOUT pm clear)
adb install -r target_ssl_bypass_signed.apk
# 3. Launch app
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
# 4. DONE. Do NOT touch proxy settings again.
```

**If you MUST change proxy (e.g., PC IP changed, switching from Burp to mitmproxy):**
```bash
# 1. Delete ALL proxy-related settings (not just http_proxy)
adb shell settings delete global http_proxy
adb shell settings delete global global_http_proxy_host
adb shell settings delete global global_http_proxy_port
# 2. Set the NEW proxy
adb shell settings put global http_proxy <NEW_PC_IP>:8080
# 3. FORCE-STOP the app (critical — OkHttp caches proxy at creation time)
adb shell am force-stop com.target.app
# 4. Relaunch
adb shell monkey -p com.target.app -c android.intent.category.LAUNCHER 1
```

**NEVER do these (they break the app):**
- `settings put global http_proxy :0` — sets proxy to port 0, OkHttp fails silently
- Toggle proxy on/off to "test" — each toggle requires force-stop + relaunch
- `pm clear` after setting proxy — wipes cached app data, app gets stuck on loading
- Change proxy while app is running — OkHttp won't pick up the change, uses stale proxy

**Diagnostic for stale proxy:** If the app has SYN_SENT connections to the WRONG IP:port (check `/proc/PID/net/tcp6`), the proxy setting is stale. Decode the remote address: hex IP (little-endian) + hex port (big-endian). Port `1F90` = 8080. If the IP doesn't match the current PC IP, the proxy setting is stale — follow the "MUST change proxy" steps above.

### PITFALL: ReactNativeBlobUtil secondary SSL path (usually inactive)

Some React Native apps include `ReactNativeBlobUtil` (or `react-native-fetch-blob`) which has its own SSL/TLS path separate from OkHttp's `CertificatePinner`:

- `com.ReactNativeBlobUtil.m.c(OkHttpClient)` creates a custom `SSLContext` with a `TrustManager` from static field `m.a`
- It sets a permissive `HostnameVerifier` (always returns `true`) via inner class `m$a`
- Called from `k.smali` when `b.f` (a Boolean config flag from JS) is `true`
- If `m.a` is null, `m.c()` throws `IllegalStateException("Use of own trust manager but none defined")`

**Detection:**
```bash
grep -rn "ReactNativeBlobUtil/m;->a:" target_decoded/smali/  # Check if TrustManager is ever set
grep -rn "ReactNativeBlobUtil/m;->c(" target_decoded/smali/  # Check if custom SSL path is called
```

**Impact:** In most apps, `m.a` is never set (no `sput-object` writes to it) and `b.f` is `false` — so `m.c()` is never reached. Patching `initializeCertificatePinner` is sufficient. If `b.f` IS true and `m.a` IS set, additionally patch `m.c()` or hook `SSLContext.init` via Frida.

## Frida SSL Bypass Script — Complete Hook Checklist for React Native

When writing a Frida SSL bypass script for a React Native app, you MUST hook ALL of the following layers. Missing any one causes the app to hang on a loading spinner (TLS handshake fails silently, no error in logcat). This is the #1 cause of "Frida script loaded but app still spinning" in React Native pentests.

### Complete Frida hook checklist (7 layers)

| # | Layer | Class | Method | Why Required |
|---|---|---|---|---|
| 1 | RASP (if present) | `ga.c` or custom | `n()` + all sub-checks → false | Prevents RASP block screen |
| 2 | SecurityModule (RN→JS) | `com.*.security.SecurityModule` | `securityCheck()` → all-false WritableMap | Stops JS-side security flag |
| 3 | TrustManager | `javax.net.ssl.SSLContext` | `init()` → inject TrustAll | Custom TrustManager bypass |
| 4 | **Conscrypt** | `com.android.org.conscrypt.TrustManagerImpl` | `checkTrustedRecursive()` → empty ArrayList | **Android system TLS verification — MISSING = app hangs** |
| 5 | HostnameVerifier | `javax.net.ssl.HttpsURLConnection` | `setDefaultHostnameVerifier()` → always true | Hostname check bypass |
| 6 | SslPublicKeyPinning | `com.sslpublickeypinning.SslPublicKeyPinningModule` | `initialize()` → `promise.resolve(null)` | RN SSL pinning module |
| 7 | OkHttp CertificatePinner (obfuscated) | `db.g` (or `okhttp3.CertificatePinner` standard) | `check()` / `a()` → no-op | OkHttp cert pin check |

### PITFALL: Frida bypass script missing Conscrypt + standard OkHttp = app hangs on loading

**Symptom:** Frida prints `[+] RASP hooked`, `[+] TrustManager hooked`, `[+] SslPublicKeyPinningModule hooked` — but app stays on loading spinner (e.g., "Đang tải dữ liệu..."). No SSL errors in logcat. No API calls in ReactNativeJS logs.

**Root cause:** The Frida script hooks the app-level SSL pinning (SslPublicKeyPinningModule, obfuscated `db.g`) and custom TrustManager, but does NOT hook:
1. **`com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive()`** — Android's system-level TLS chain verification. Every HTTPS connection goes through Conscrypt. Without this hook, the system rejects the proxy's MITM cert at the lowest layer — before OkHttp or the app's pinning logic even sees it. The connection simply hangs (no exception thrown to the app layer, just a timeout).
2. **`okhttp3.CertificatePinner.check()` (standard, non-obfuscated)** — React Native bundles BOTH a standard `okhttp3.CertificatePinner` AND an obfuscated copy (`db.g`). If you only hook `db.g`, the standard CertificatePinner still runs and rejects the cert.
3. **`okhttp3.internal.tls.OkHostnameVerifier.verify()`** — OkHttp's internal hostname verification. Without this hook, the hostname doesn't match the MITM cert's CN/SAN → connection rejected.

**Fix:** Add ALL missing hooks to the Frida script. The Python wrapper (`ssl_bypass.py`) in the same project had these hooks but the CLI script (`ssl_bypass.js`) was missing them — always double-check BOTH scripts match:

```javascript
// Conscrypt TrustManagerImpl (CRITICAL — without this, all TLS hangs)
try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.checkTrustedRecursive.overload('java.util.List', 'java.lang.String', 'java.lang.String').implementation = function() {
        return Java.use('java.util.ArrayList').$new();
    };
    console.log('[+] Conscrypt TrustManagerImpl hooked');
} catch(e) { console.log('[-] Conscrypt: ' + e); }

// Standard OkHttp CertificatePinner (may exist alongside obfuscated db.g)
// Hook via delayed classloader enumeration (OkHttp loads late in RN)
setTimeout(function() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    var CP = Java.ClassFactory.get(loader).use('okhttp3.CertificatePinner');
                    CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
                    try { CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {}; } catch(e) {}
                    console.log('[+] okhttp3.CertificatePinner hooked');
                } catch(e) {}
                try {
                    var OHV = Java.ClassFactory.get(loader).use('okhttp3.internal.tls.OkHostnameVerifier');
                    OHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() { return true; };
                    console.log('[+] OkHostnameVerifier hooked');
                } catch(e) {}
                try {
                    var ObfCP = Java.ClassFactory.get(loader).use('db.g');
                    ObfCP.a.overload('java.lang.String', 'java.util.List').implementation = function() {};
                    console.log('[+] db.g hooked via classloader');
                } catch(e) {}
            },
            onComplete: function() { console.log('[*] Classloader enumeration done'); }
        });
    });
}, 2000);
```

### PITFALL: Frida script and Python wrapper can diverge — always sync both

When maintaining both `ssl_bypass.js` (CLI) and `ssl_bypass.py` (Python wrapper), ensure they hook the SAME classes. A common workflow is to prototype in Python (easier debugging with `send()` + `on_message`), then copy to JS for CLI use. But hooks added to the Python version (`ssl_bypass.py`) often don't get backported to the JS version (`ssl_bypass.js`). Always diff the two files:

```bash
# Check which hooks are in .py but missing from .js
grep -oP "Java\.use\('[^']+'\)" ssl_bypass.py | sort -u > /tmp/py_hooks.txt
grep -oP "Java\.use\('[^']+'\)" ssl_bypass.js | sort -u > /tmp/js_hooks.txt
diff /tmp/py_hooks.txt /tmp/js_hooks.txt
# Lines only in py_hooks.txt = missing from .js
```

### Complete working Frida bypass script template (RN + custom RASP + obfuscated OkHttp)

```javascript
// React Native SSL + RASP Bypass — Complete (7 layers)
// Hook order: RASP → SecurityModule → TrustManager → Conscrypt → HostnameVerifier → SslPinning → OkHttp(both)

Java.perform(function() {
    // 1. RASP (custom, e.g., ga.c)
    try {
        var RASP = Java.use('ga.c');
        RASP.n.implementation = function() { return false; };
        ['v','o','r','u','t','w','x','s','q','e','f','g','h','i','j','k','l','m','b','c','d','a'].forEach(function(m) {
            try { RASP[m].implementation = function() { return false; }; } catch(e) {}
        });
        console.log('[+] RASP hooked');
    } catch(e) { console.log('[-] RASP: ' + e); }

    // 2. SecurityModule (RN→JS bridge)
    try {
        var SecMod = Java.use('com.vn.seabank.security.SecurityModule');
        SecMod.securityCheck.implementation = function(promise) {
            var m = Java.use('com.facebook.react.bridge.Arguments').createMap();
            ['isRooted','frida','objection','magisk','shamiko','zygisk','hook','debugger','debuggerModeEnable'].forEach(function(k) {
                m.putBoolean(k, false);
            });
            promise.resolve(m);
        };
        console.log('[+] SecurityModule hooked');
    } catch(e) { console.log('[-] SecurityModule: ' + e); }

    // 3. TrustManager
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'org.wooyin.TrustAll',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var TrustAllArray = [TrustManager.$new()];
    SSLContext.init.overloads.forEach(function(ov) {
        ov.implementation = function(a, b, c) { this.init(a, TrustAllArray, c); };
    });
    console.log('[+] TrustManager hooked');

    // 4. Conscrypt (CRITICAL — without this, TLS hangs silently)
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.checkTrustedRecursive.overload('java.util.List', 'java.lang.String', 'java.lang.String').implementation = function() {
            return Java.use('java.util.ArrayList').$new();
        };
        console.log('[+] Conscrypt hooked');
    } catch(e) { console.log('[-] Conscrypt: ' + e); }

    // 5. HostnameVerifier
    try {
        var HV = Java.registerClass({
            name: 'org.wooyin.HV',
            implements: [Java.use('javax.net.ssl.HostnameVerifier')],
            methods: { verify: function() { return true; } }
        });
        Java.use('javax.net.ssl.HttpsURLConnection').setDefaultHostnameVerifier(HV.$new());
        console.log('[+] HostnameVerifier hooked');
    } catch(e) { console.log('[-] HV: ' + e); }

    // 6. SslPublicKeyPinningModule
    try {
        var SslPinning = Java.use('com.sslpublickeypinning.SslPublicKeyPinningModule');
        SslPinning.initialize.implementation = function(readableMap, promise) {
            console.log('[+] Blocking SslPublicKeyPinning.initialize()');
            promise.resolve(null);
        };
        console.log('[+] SslPublicKeyPinningModule hooked');
    } catch(e) { console.log('[-] SslPublicKeyPinningModule: ' + e); }

    // 7. Obfuscated OkHttp CertificatePinner (db.g) — initial attempt
    try {
        var ObfCP = Java.use('db.g');
        ObfCP.a.overload('java.lang.String', 'java.util.List').implementation = function() {};
        console.log('[+] db.g hooked');
    } catch(e) { console.log('[-] db.g: ' + e); }
});

// 7b. Delayed classloader enumeration for standard OkHttp + OkHostnameVerifier + db.g
setTimeout(function() {
    Java.perform(function() {
        Java.enumerateClassLoaders({
            onMatch: function(loader) {
                try {
                    var CP = Java.ClassFactory.get(loader).use('okhttp3.CertificatePinner');
                    CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
                    try { CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function() {}; } catch(e) {}
                    console.log('[+] okhttp3.CertificatePinner hooked');
                } catch(e) {}
                try {
                    var OHV = Java.ClassFactory.get(loader).use('okhttp3.internal.tls.OkHostnameVerifier');
                    OHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() { return true; };
                    console.log('[+] OkHostnameVerifier hooked');
                } catch(e) {}
                try {
                    var ObfCP = Java.ClassFactory.get(loader).use('db.g');
                    ObfCP.a.overload('java.lang.String', 'java.util.List').implementation = function() {};
                    console.log('[+] db.g hooked via classloader');
                } catch(e) {}
                try {
                    var SslPinning = Java.ClassFactory.get(loader).use('com.sslpublickeypinning.SslPublicKeyPinningModule');
                    SslPinning.initialize.implementation = function(readableMap, promise) { promise.resolve(null); };
                    console.log('[+] SslPublicKeyPinningModule hooked via classloader');
                } catch(e) {}
            },
            onComplete: function() { console.log('[*] Classloader enumeration done'); }
        });
    });
}, 2000);
```

### PITFALL: RASP check in MainApplication.onCreate runs before Frida hooks attach

**Symptom:** Frida script loads and hooks RASP correctly, but the app STILL shows the RASP block screen. The hooks arrived too late — the RASP check already ran during `MainApplication.onCreate()` before `Java.perform()` executed.

**Root cause:** When using `frida -U -f com.app -l bypass.js`, Frida pauses the app at spawn, loads the script, then resumes. However, `Java.perform()` is asynchronous — it schedules the hooks on the Java thread, but `MainApplication.onCreate()` may execute before the hooks are installed. The race condition means RASP checks run unhooked.

**Fix — Hook `Application.onCreate` to install RASP hooks BEFORE the app's onCreate logic runs:**

```javascript
// Hook Application.onCreate BEFORE MainApplication.onCreate
var Application = Java.use('android.app.Application');
Application.onCreate.implementation = function() {
    // Install RASP hooks HERE — before any app code runs
    try {
        var RASP = Java.use('ga.c');
        RASP.n.implementation = function() { return false; };
        console.log('[+] RASP hooked in Application.onCreate (early)');
    } catch(e) { console.log('[-] RASP early hook: ' + e); }
    // Call original onCreate AFTER hooks are installed
    this.onCreate();
};
```

This ensures the RASP hooks are installed before `MainApplication.onCreate()` calls `ga.c.n()` to run security checks. The `Application.onCreate` hook runs first (it's the parent class), installs the hooks, then calls `this.onCreate()` which proceeds to the app's custom logic with hooks already active.

## Frida 17.x Specific Issues

### PITFALL: Frida 17 Python wrapper throws "Java is not defined" — use frida CLI instead

In Frida 17.x (confirmed 17.9.11), the Python `frida` module may throw `ReferenceError: 'Java' is not defined` when running scripts that use `Java.perform()`. This is a known bug (frida/frida#3473, #3495) — the Java bridge is not injected into the global scope when using the Python API, even though the same script works perfectly via the `frida` CLI.

**Symptom:**
```
[*] Spawning com.target.app...
[ERROR] ReferenceError: 'Java' is not defined
```
The script loads, the app spawns, but no hooks are installed.

**Fix:** Use the `frida` CLI tool instead of the Python wrapper:
```bash
# CORRECT (Frida 17.x): frida CLI works
frida -U -f com.target.app -l ssl_bypass.js

# WRONG (Frida 17.x): Python wrapper may fail
# python3 ssl_bypass.py  # -> "Java is not defined"
```

If you MUST use Python (e.g., for automation), check `typeof Java !== 'undefined'` before `Java.perform()` and use a retry loop:
```javascript
function tryJava(attempt) {
    if (typeof Java === 'undefined' || !Java.available) {
        if (attempt < 15) setTimeout(function() { tryJava(attempt + 1); }, 2000);
        return;
    }
    Java.perform(function() { /* hooks here */ });
}
setTimeout(function() { tryJava(1); }, 1000);
```

### PITFALL: Frida CLI `--no-pause` flag removed in Frida 17

The `--no-pause` flag (used in Frida 16.x to auto-resume the spawned process) has been removed in Frida 17.x. Using it causes: `frida: error: unrecognized arguments: --no-pause`.

**Fix:** Simply omit `--no-pause` — Frida 17 auto-resumes after script load by default:
```bash
# CORRECT (Frida 17.x):
frida -U -f com.target.app -l ssl_bypass.js

# WRONG (Frida 17.x):
# frida -U -f com.target.app -l ssl_bypass.js --no-pause  # error
```

### PITFALL: Objection fails in MSYS/git-bash terminal on Windows

On Windows with MSYS/git-bash, `objection` throws `NoConsoleScreenBufferError: Found xterm-256color, while expecting a Windows console`. The `prompt_toolkit` library requires a native Windows console.

**Fix:** Run objection from `cmd.exe` or PowerShell, not git-bash. Or use `winpty objection ...` if available.

### PITFALL: `timeout` command kills spawned app when Frida exits

Using `timeout 60 frida -U -f com.app -l bypass.js` kills the Frida process on timeout, which kills the spawned app. To keep the app alive after Frida exits:
- Spawn app separately: `adb shell am start -n com.app/.MainActivity`, then attach: `frida -U -n com.app -l bypass.js`
- Or use `frida -U -f com.app -l bypass.js &` (background) — but monitor output via process logs

## Custom RASP Detection in React Native Apps (not Talsec/Promon)

Some React Native apps implement **custom RASP detection** in Java rather than using third-party libraries like Talsec/Promon. This is distinct from the Talsec freeRASP pattern (which uses `libts.so` native checks). Custom RASP is pure Java and can be bypassed with Frida hooks.

### Detection pattern

```
MainApplication.onCreate()
  -> new SecurityClass(this).masterCheck()  // returns boolean
  -> if true: set flag
MainActivity.onCreate()
  -> if (flag) showBlockScreen()  // replaces React root view with warning layout
```

### Example: com.vn.seabank (SeaBank/iLearn) custom RASP

Class `ga.C1908c` (obfuscated from `SecurityChecker`) implements these checks:

| Method | Checks For | Detection Method |
|---|---|---|
| `n()` | Master check (OR of all) | Returns true if ANY sub-check is true |
| `v()` | Root | su binary paths, Magisk/SuperSU packages, `getprop ro.debuggable/ro.secure`, `su -c id` |
| `r()` | Frida | Port 27042/27043 scan, "frida" in /proc/self/maps |
| `u()` | Objection/frida-agent | "objection"/"frida-agent"/"frida-server"/"gadget" in /proc/self/maps |
| `t()` | Magisk | Package names + binary paths (/sbin/magisk, /data/adb/magisk) |
| `w()` | Shamiko | /data/adb/modules/shamiko, /data/adb/shamiko |
| `x()` | Zygisk | "zygisk" in /proc/self/maps |
| `s()` | Xposed/LSPosed | "xposed"/"lsposed"/"edxposed"/"riru" in /proc/self/maps |
| `o()` | Debugger | `Debug.isDebuggerConnected()`, `Debug.waitingForDebugger()` |
| `q()` | Emulator | Build.FINGERPRINT/MODEL/MANUFACTURER/BRAND/DEVICE/PRODUCT |
| `e()` | Frida (detailed) | "frida"/"gadget"/"gum-js-loop" in /proc/self/maps |
| `f()` | Frida port | TCP connect to 127.0.0.1:27042 and 27043 |

### Frida bypass for custom RASP

Hook the master check method to return false, plus all sub-checks as defense in depth:

```javascript
Java.perform(function() {
    var RASP = Java.use('ga.c');  // obfuscated class name
    RASP.n.implementation = function() { return false; };
    ['v','o','r','u','t','w','x','s','q','e','f','g','h','i','j','k','l','m','b','c','d','a'].forEach(function(m) {
        try { RASP[m].implementation = function() { return false; }; } catch(e) {}
    });
});

// Also hook SecurityModule.securityCheck() if present (returns WritableMap to JS)
var SecMod = Java.use('com.vn.seabank.security.SecurityModule');
SecMod.securityCheck.implementation = function(promise) {
    var m = Java.use('com.facebook.react.bridge.Arguments').createMap();
    ['isRooted','frida','objection','magisk','shamiko','zygisk','hook','debugger','debuggerModeEnable'].forEach(function(k) {
        m.putBoolean(k, false);
    });
    promise.resolve(m);
};
```

### Finding the RASP class in decompiled APK

```bash
# Decompile DEX files (APK may have corrupted zip header — use Python zipfile, not unzip)
python -c "import zipfile; z=zipfile.ZipFile('app.apk','r'); z.extract('classes.dex','out/'); z.extract('classes2.dex','out/')"

# Decompile with JADX
jadx -d decompiled/ out/classes.dex out/classes2.dex

# Search for root/frida detection strings
grep -rl "isDebuggerConnected\|/proc/self/maps\|27042\|frida\|magisk\|shamiko\|zygisk" decompiled/sources/

# Search for the block screen text
grep -rl "không đáp ứng\|bị can thiệp\|bảo mật" decompiled/sources/
```

### How to read the Android UI for error diagnosis

When the app shows a blocking/security screen, use `uiautomator dump` to read the on-screen text:

```bash
adb shell uiautomator dump /sdcard/ui.xml
adb shell cat /sdcard/ui.xml | tr '>' '\n' | grep "text=" | grep -v 'text=""'
```

This reveals the exact error message, which tells you whether the block is from SSL pinning, RASP detection, or network issues.

### APK with corrupted zip header — use Python zipfile instead of unzip/jar

Some Android APKs have extra bytes at the beginning (APK Signature Scheme v4) that break `unzip` and `jar` on Windows/MSYS:
```
warning [app.apk]: 232172 extra bytes at beginning or within zipfile
error [app.apk]: start of central directory not found; zipfile corrupt.
```

**Fix:** Python's `zipfile` module handles this correctly:
```bash
python -c "
import zipfile
z = zipfile.ZipFile('app.apk', 'r')
z.extract('classes.dex', 'output_dir/')
z.extract('classes2.dex', 'output_dir/')
print('Total entries:', len(z.namelist()))
"
```
Then decompile the extracted DEX files with JADX:
```bash
jadx -d decompiled/ output_dir/classes.dex output_dir/classes2.dex
```

## Obfuscated OkHttp Class Names — How to Find Them

React Native apps often obfuscate OkHttp class names with R8/ProGuard. The standard `okhttp3.CertificatePinner` class name won't exist — you must find the obfuscated name from decompiled code.

### Finding obfuscated CertificatePinner

```bash
# Search JADX decompiled output for CertificatePinner-like patterns
grep -rl "SSLPeerUnverifiedException\|CertificatePinner\|sha256/" decompiled/sources/

# The obfuscated class will have:
# - "sha256/" prefix on pins (same as CertificatePinner)
# - Methods taking (String, List) for the check() method
# - References to javax.net.ssl.SSLPeerUnverifiedException
# - Variable names like "certificatePinner" in the SslPublicKeyPinningModule
```

### Worked example: com.vn.seabank obfuscation map

| Original | Obfuscated | JADX rename |
|---|---|---|
| `okhttp3.CertificatePinner` | `db.g` | `C1744g` |
| `CertificatePinner.check(String, List)` | `db.g.a(String, List)` | `C1744g.a(String, List)` |
| `okhttp3.OkHttpClient` | (varies) | (varies) |

### Frida hook for obfuscated CertificatePinner

```javascript
// Use the two-letter obfuscated name, NOT the JADX rename
try {
    var ObfCP = Java.use('db.g');  // NOT 'db.C1744g' or 'okhttp3.CertificatePinner'
    ObfCP.a.overload('java.lang.String', 'java.util.List').implementation = function() {};
    console.log('[+] Obfuscated CertificatePinner hooked');
} catch(e) { console.log('[-] db.g: ' + e); }
```

If the class isn't found via the default classloader, enumerate classloaders:
```javascript
Java.enumerateClassLoaders({
    onMatch: function(loader) {
        try {
            var CP = Java.ClassFactory.get(loader).use('db.g');
            CP.a.overload('java.lang.String', 'java.util.List').implementation = function() {};
            console.log('[+] db.g hooked via classloader');
        } catch(e) {}
    },
    onComplete: function() {}
});
```

## Key Differences from Flutter

| Aspect | Flutter | React Native |
|---|---|---|
| Networking stack | dart:io + BoringSSL (native) | OkHttp (Java) |
| Pin location | Hardcoded in `libapp.so` | Dynamic, loaded from JS bundle at runtime |
| Pin format | Raw base64 SPKI hash (44 chars) | `sha256/` + base64 SPKI hash |
| Bypass approach | Binary patch libapp.so or Frida memory patch or BoringSSL hooks | Smali patch `initializeCertificatePinner` or Frida hook `getCertificatePinner` |
| Proxy interception | iptables REDIRECT + adb reverse (ignores system proxy) | Standard system proxy works (or ADB reverse + DNAT if server blocks device IP) |
| Root detection | RaspGuard/Talsec (common) | Rare |
| JS bundle analysis | N/A (Dart compiled) | `strings` on `index.android.bundle` reveals API URLs, auth endpoints |
| Smali patch risk | N/A (patches libapp.so binary) | Must remove ALL original method body or VerifyError (see pitfall above) |
| Preferred bypass | Frida memory patch or binary patch (complex) | APK smali patch (simple, no root/Frida needed — preferred when no RASP present) |
| Secondary SSL path | None (single BoringSSL stack) | ReactNativeBlobUtil may have custom SSLContext (usually inactive, see above) |
