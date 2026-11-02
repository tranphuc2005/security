# Flutter Dart-Layer SPKI Pinning Bypass — Runtime Memory Patch

Tested on: Samsung S25 (SM-S721B), Android 15, rooted, Frida 17.9.6,
Flutter app v1.1.31+1 with `ssl_pins_sha256` in libapp.so, Burp Suite proxy.

## Problem

Standard Flutter SSL bypass (BoringSSL hooks on `libssl.so` + Java `TrustManagerImpl`)
is NOT sufficient when the app implements SPKI pinning in compiled Dart code.

The app embeds base64-encoded SHA256 hashes of allowed SubjectPublicKeyInfo (SPKI)
in `libapp.so` (the Dart AOT snapshot). During TLS handshake, Dart code:
1. Extracts the server certificate's SPKI
2. Computes SHA256 hash
3. Compares against embedded pins (`ssl_pins_sha256`)
4. Rejects if no match (`ssl_pin_rejected`)

This check happens AFTER BoringSSL verification, so even with `SSL_CTX_set_custom_verify`
mode=0 and `X509_verify_cert` returning 1, the Dart layer rejects the proxy's certificate.

## Detection

### Static (offline, on APK)

```bash
# Extract libapp.so
unzip base.apk lib/arm64-v8a/libapp.so -d /tmp/apk_extract

# Search for pin-related Dart strings
grep -c "ssl_pins_sha256" libapp.so       # 1+ = Dart pinning present
grep -c "ssl_pin_rejected" libapp.so      # 1+ = rejection logging present
grep -c "ssl_pins_signature" libapp.so    # may also be present
grep -c "SecureSocket_RegisterBadCertificateCallback" libapp.so
grep -c "SecureSocket_MarkAsTrusted" libapp.so

# Find SPKI pin hashes (base64, 44 chars with padding)
strings -n 20 libapp.so | grep -E "^[A-Za-z0-9+/]{43}=$"

# Find pin offset (for confirmation)
grep -boa "wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=" libapp.so
# Output: 307461:wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=
```

### Dynamic (runtime, via logcat)

```bash
# When the bypass fails (BoringSSL hooks active but Dart pinning still rejects),
# the app logs to logcat:
adb logcat -s flutter | grep -i "ssl_pin"
# Output: ssl_pin_rejected: host=api.target.com presentedPin=jSZoy... allowedPins=3
```

The `presentedPin` value is the SPKI hash of YOUR proxy's certificate.
The `allowedPins` count tells you how many pins are embedded.

## Why Standard Bypasses Fail

| Method | Why It Fails |
|---|---|
| BoringSSL hooks (SSL_CTX_set_custom_verify, X509_verify_cert) | Dart pin check runs AFTER BoringSSL verification passes |
| TrustManagerImpl.verifyChain hook | Java-layer; Flutter Dart code uses its own SSL stack via JNI |
| OkHttp3 CertificatePinner hook | App uses Dio (Dart HTTP), not OkHttp for API calls |
| reflutter (patch libflutter.so) | Patches BoringSSL, not Dart pinning; also crashes app |
| APK repack (patch libapp.so on disk) | Dart VM integrity check detects modified snapshot → app crashes on launch |

## Solution: Frida Runtime Memory Patch

### Overview

1. Find the original SPKI pin hash (base64 string) in `libapp.so` process memory
2. Overwrite it with the proxy's SPKI hash at runtime
3. Also hook BoringSSL + Java SSL (belt-and-suspenders)
4. No APK modification needed — pure runtime patch

### Computing the Proxy's SPKI Hash

```bash
# Burp CA cert is installed on device at /system/etc/security/cacerts/<hash>.0
# Extract it and compute the SPKI hash:

# Method 1: From device system store
adb shell "su -c 'cat /system/etc/security/cacerts/9a5ba575.0'" | \
  openssl x509 -noout -pubkey | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl base64
# Output: jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=

# Method 2: From Burp's CA export
openssl x509 -in burp-ca.crt -noout -pubkey | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | openssl base64

# Method 3: From mitmproxy CA
openssl x509 -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout -pubkey | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | openssl base64
```

### The Memory Patch Technique

```javascript
// Key steps (see templates/flutter-spki-memory-patch.js for full script):

var ORIGINAL_PIN = "wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=";
var BURP_PIN = "jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=";

// 1. Find libapp.so module
var libapp = Process.findModuleByName("libapp.so");

// 2. Convert pin string to hex pattern for Memory.scanSync
var pin_pattern = "";
for (var i = 0; i < ORIGINAL_PIN.length; i++) {
    pin_pattern += ('0' + ORIGINAL_PIN.charCodeAt(i).toString(16)).slice(-2) + " ";
}
pin_pattern = pin_pattern.trim();

// 3. Scan for the pin hash in libapp.so memory
//    NOTE: Memory.scanSync CAN scan read-only (r--) pages without Memory.protect.
//    If full scan throws access violation, fall back to page-by-page scanning.
var matches = Memory.scanSync(libapp.base, libapp.size, pin_pattern);
// → Found 1 match(es) for original pin

// 4. CRITICAL: Protect ONLY the 4KB page containing the pin, NOT entire libapp.so
//    Memory.protect(libapp.base, libapp.size, 'rwx') → SIGSEGV in datadog-context!
var page_size = Process.pageSize;
var page_base = matches[0].address.and(ptr(page_size - 1).not());
Memory.protect(page_base, page_size, 'rwx');

// 5. Overwrite with proxy's SPKI hash
matches[0].address.writeUtf8String(BURP_PIN);
// → Patched pin at 0x79c9474105
```

### CRITICAL PITFALLS (learned from crashes)

1. **NEVER `Memory.protect(libapp.base, libapp.size, 'rwx')`** — protecting the ENTIRE libapp.so as RWX corrupts Dart AOT JIT code pages, causing SIGSEGV in `datadog-context` threads. Only protect the specific 4KB page containing the pin hash.

2. **NEVER scan all memory regions (`Process.enumerateRanges`)** — the pin string appears in heap copies outside libapp.so (e.g., at `0x70000d3c00`). Patching those copies causes SIGBUS in `datadog-context` threads. Only scan within `libapp.so`'s address range.

3. **NEVER use Java hooks (`TrustManagerImpl`, `SSLContext.init`) on Flutter apps with RaspGuard** — `Java.perform()` causes race conditions resulting in SIGBUS in `datadog-context` and `EmojiCompatInit` threads. Use ONLY BoringSSL native hooks + memory patch. Native Android plugins (Firebase, Datadog) use the system SSL stack already covered by BoringSSL hooks.

4. **`Memory.scanSync` on read-only pages** — the full `Memory.scanSync(libapp.base, libapp.size, pattern)` may throw `access violation accessing 0x...` on certain guarded pages. This is OK — wrap in try/catch and fall back to page-by-page scanning with `Process.pageSize` chunks. You do NOT need `Memory.protect` before scanning — only before writing.

### Why APK Repack Fails (and Memory Patch Doesn't)

| Approach | Integrity Check | Result |
|---|---|---|
| APK repack (patch libapp.so file) | Dart VM snapshot integrity check | App crashes on launch (`pid has died`) |
| APK repack with ZIP_STORED for .so | Same integrity check | Still crashes |
| Frida runtime memory patch | No file modification — patch is in RAM only | Works — app runs normally |

The Dart VM stores the AOT snapshot as a mmap'd region with integrity verification.
Modifying the file changes the on-disk hash, which the VM checks at load time.
Runtime memory patching happens AFTER the snapshot is loaded and verified.

### RaspGuard Anti-Tamper

Some Flutter apps include RaspGuard (Runtime Application Self-Protection):

```
RaspGuard: started
RaspGuard: threat detected — privileged_access (root/jailbreak)
RaspGuard: threat detected — app_integrity (repackaged/tampered)
```

In testing, RaspGuard warnings did NOT block app execution — the app continued
running with the bypass active. The threat detection appears to be logging-only,
not enforcement. If RaspGuard does enforce (crash/exit), hook the RaspGuard
class via Java.enumerateLoadedClasses or patch the threat strings in memory.

**CRITICAL UPDATE (v1.1.31 enforcement mode):** Newer versions of Talsec FreeRASP
DO block the app. The app shows a blocking screen ("Chưa thể mở ứng dụng" /
"Unable to open application" / "Please close suspicious software"). The blocking
happens in Dart code (not Java), so patching the Java MethodChannel handler alone
is NOT sufficient. You must patch BOTH: (1) smali — return empty threat list from
the `scan` MethodChannel handler, (2) libapp.so — same-length string replacement
of `privileged_access (root/jailbreak)`, `privileged_access`, and `rasp_threat: `
with `x` strings of the same byte length. Do NOT patch package name strings
(e.g., `com.topjohnwu.magisk`) — this causes SIGSEGV in Dart's string hash table.
See `references/raspguard-bypass.md` for the full technique.

### Full Bypass Stack (for Flutter apps with Dart-layer SPKI pinning)

For a Flutter app with Dart-layer SPKI pinning, you need:

1. **BoringSSL native hooks** — SSL_CTX_set_custom_verify, SSL_set_verify, SSL_get_verify_result, X509_verify_cert on system libssl.so (use Interceptor.replace with NativeCallback, NOT Interceptor.attach)
2. **Memory patch** — replace SPKI pin hash in libapp.so (page-specific Memory.protect, NOT whole-module)
3. **Traffic interception** — iptables REDIRECT 443→8080 + adb reverse + Burp/mitmproxy
4. **CA cert installation** — proxy CA in system + Conscrypt + user cert stores

**CRITICAL: Do NOT use Java SSL hooks (TrustManagerImpl, SSLContext.init) on Flutter apps with RaspGuard.** `Java.perform()` causes SIGBUS in `datadog-context` and `EmojiCompatInit` threads due to race conditions. Native Android plugins (Firebase, Datadog) use the system SSL stack which is already covered by BoringSSL hooks. The working v2 script (templates/flutter-spki-memory-patch.js) uses ONLY BoringSSL hooks + memory patch — no Java hooks at all.

### Verification
### Verification of successful memory patch

Successful bypass with the v2 script (no Java hooks, page-specific protect) shows:

```
[BYPASS] libssl.so base=0x7a590d6000 size=0x95000
[BYPASS] SSL_CTX_set_custom_verify hooked -> mode=0
[BYPASS] SSL_CTX_set_verify hooked -> mode=0
[BYPASS] SSL_set_verify hooked -> mode=0
[BYPASS] SSL_get_verify_result replaced -> 0
[BYPASS] SSL_CTX_set_cert_verify_callback hooked
[BYPASS] X509_verify_cert replaced -> 1
[BYPASS] SSL_write hooked @ 0x7a591483f0
[BYPASS] SSL_read hooked @ 0x7a59147fc4
[BYPASS] [+] BYPASS: BoringSSL hooks installed
[BYPASS] SSL_WRITE: POST /v1/projects/.../namespaces/firebase:fetch HTTP/1.1  ← traffic captured!
[BYPASS] libapp.so base=0x79c9429000 size=0x9c1000
[BYPASS] Scanning libapp.so for pin hash...
[BYPASS] Found 1 match(es) for original pin
[BYPASS] Patched pin at 0x79c9474105 -> jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=
[BYPASS] [+] BYPASS: Patched SPKI pin hash in libapp.so (1 locations)
```

Key indicators of success:
- `SSL_WRITE` log shows HTTP traffic (Firebase, API calls) — BoringSSL hooks working
- `Patched pin at 0x...` — memory patch applied
- NO `ssl_pin_rejected` in logcat (`adb logcat -s flutter | grep ssl_pin`)
- App does NOT crash (no SIGBUS/SIGSEGV in logcat)
- RaspGuard warnings (`privileged_access`, `hooks`, `app_integrity`) appear but do NOT block execution
```bash
adb logcat -s flutter | grep ssl_pin
# (no output = success)
```

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `access violation accessing 0x...` during scanSync | Some libapp.so pages are guarded | Wrap in try/catch, fall back to page-by-page scanning with `Process.pageSize` chunks. Do NOT call `Memory.protect` on entire libapp.so — only protect the specific 4KB page before writing |
| `SIGSEGV in datadog-context` after memory patch | `Memory.protect(libapp.base, libapp.size, 'rwx')` corrupted Dart AOT JIT code pages | Use page-specific protection: `var page_base = address.and(ptr(pageSize-1).not()); Memory.protect(page_base, 4096, 'rwx')` |
| `SIGBUS in datadog-context` or `EmojiCompatInit` | Java hooks (`TrustManagerImpl`, `SSLContext.init`) cause race conditions in Flutter apps with RaspGuard | Remove ALL Java hooks. Use ONLY BoringSSL native hooks + memory patch |
| `SIGBUS` after patching pins at addresses outside libapp.so | All-memory scan (`Process.enumerateRanges`) found heap copies of the pin string | Do NOT scan all memory regions. Only scan within `libapp.so` address range |
| `Found 0 match(es) for original pin` | libapp.so not loaded yet, or pin is in different format | Defer patch with `setTimeout(..., 800)`; retry loop every 1s. libapp.so loads at spawn time but may not be immediately available |
| App crashes after patch | RaspGuard integrity check or Dart snapshot hash | Use runtime patch (not APK repack); if RaspGuard enforces, hook RaspGuard class |
| `ssl_pin_rejected` still in logs | Pin hash not found or not overwritten | Verify ORIGINAL_PIN matches the hash in libapp.so; verify BURP_PIN is the proxy's SPKI hash |
| `Connection terminated` in Frida | frida-server crashed or app killed | Restart frida-server: `adb shell "su -c 'setsid /data/local/tmp/frida-server >/dev/null 2>&1 &'"` |
| Frida "need Gadget to attach on jailed Android" | frida-server not running | Start frida-server on device, verify with `frida-ps -U` |
| BoringSSL hooks load but pin still rejected | Hooks are on libssl.so but Dart pin check is separate | You MUST do the memory patch — BoringSSL hooks alone are not enough |
| Memory.protect fails on some pages | Some pages may be guarded | Fall back to page-by-page scanning: iterate with `Process.pageSize` chunks, protect+scan each |

### Environment Details (verified setup)

- Device: Samsung S25 (SM-S721B), Android 15, rooted
- Frida: 17.9.6 (client + server matching)
- App: Flutter v1.1.31+1 with Dio HTTP client, RaspGuard anti-tamper
- Proxy: Burp Suite on 0.0.0.0:8080, iptables REDIRECT 443→8080, adb reverse tcp:8080
- CA: Burp CA (hash 9a5ba575.0) in system + Conscrypt cert stores
- SPKI pin found at libapp.so offset 307461 (base64 string, 44 chars)
- Only 1 pin hash in the binary (allowedPins=3 in log, but only 1 unique hash found)
