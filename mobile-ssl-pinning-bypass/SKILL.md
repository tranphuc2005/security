---
name: mobile-ssl-pinning-bypass
description: >-
  Mobile SSL pinning bypass playbook. Use when intercepting HTTPS traffic from mobile applications that implement certificate pinning, public key pinning, or SPKI hash pinning on Android and iOS, including React Native, Flutter, and Xamarin frameworks.
---

# SKILL: Mobile SSL Pinning Bypass — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSL pinning bypass techniques for mobile platforms. Covers Android and iOS bypass methods (Frida, Objection, Xposed, SSL Kill Switch), framework-specific bypasses (Flutter, React Native, Xamarin), and troubleshooting non-standard pinning implementations. Base models miss framework-specific hook points and multi-layer pinning configurations.

## 0. PRE-FLIGHT CHECKLIST (run BEFORE attempting bypass)

Before trying any bypass method, verify the toolchain is ready. Skipping this is the #1 cause of mysterious "hooks don't work" failures.

### 0.1 Tool Verification (one-shot, read-only)

```bash
# === ADB + DEVICE ===
adb devices                          # device must show "device" not "unauthorized"
adb shell getprop ro.build.version.release   # Android version (determines CA trust rules)
adb shell "which su"                 # empty = no root; "/system/bin/su" = rooted

# === FRIDA — most critical check ===
frida --version                      # CLIENT version (on host)
adb shell "su -c '/data/local/tmp/frida-server --version'"  # SERVER version (on device)
# CRITICAL: client and server MAJOR+MINOR must match (e.g. 17.9.x == 17.9.x).
# Mismatch (e.g. client 17.5.1 vs server 17.9.6) causes silent hook failures
# or crashes on newer API calls. Fix: pip install --upgrade frida==<server_version>

# === FRIDA SERVER RUNNING ON DEVICE? ===
adb shell "ps -A | grep frida"       # if empty, start it:
# adb shell "su -c '/data/local/tmp/frida-server &'"

# === OBJECTION (wraps Frida, easier for one-shot bypass) ===
objection version 2>&1 | head -1     # or: objection --help | head -1

# === APK REPACKAGING (for no-root / Network Security Config approach) ===
which apktool jadx apksigner zipalign  # all three needed for repatch flow
java -version 2>&1 | head -1         # Java 11+ required for apksigner

# === PROXY ===
# Burp Suite: start manually, note proxy port (default 8080)
# mitmproxy: mitmproxy --version
```

### 0.2 Frida Version Mismatch — the #1 Silent Failure

Frida client (host) and frida-server (device) MUST be the same version. A mismatch causes hooks to silently not attach, or the app to crash with no useful error.

```bash
# Diagnose:
echo "CLIENT: $(frida --version)"
echo "SERVER: $(adb shell "su -c '/data/local/tmp/frida-server --version'" 2>/dev/null)"

# Fix option A — upgrade client to match server (preferred, server is harder to update):
pip install --upgrade frida==<server_version> frida-tools

# Fix option B — downgrade server to match client:
# Download matching frida-server-X.x.x-android-arm64 from https://github.com/frida/frida/releases
# adb push frida-server-<version>-android-arm64 /data/local/tmp/frida-server
# adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
# adb shell "su -c 'kill $(pgrep frida-server)'"  # kill old
# adb shell "su -c '/data/local/tmp/frida-server &'"
```

### 0.3 Tool Install Reference (if missing)

See `references/tool-install.md` for full install commands for MobSF, QARK, Androguard, APKiD, Drozer, reflutter — these complement SSL bypass with static analysis and Flutter-specific bypass.

---

## 0.4 RELATED ROUTING

Before going deep, consider loading:

- [android-pentesting-tricks](../android-pentesting-tricks/SKILL.md) for broader Android testing beyond SSL bypass
- [ios-pentesting-tricks](../ios-pentesting-tricks/SKILL.md) for broader iOS testing beyond SSL bypass
- [api-sec](../api-sec/SKILL.md) once traffic is intercepted for API-level testing

---

## 1. SSL PINNING TYPES

| Pinning Type | What Is Pinned | Resilience | Common In |
|---|---|---|---|
| Certificate pinning | Exact leaf certificate (DER/PEM) | Low (breaks on cert rotation) | Legacy apps |
| Public key pinning | Subject Public Key Info | Medium (survives cert renewal if key unchanged) | Modern apps |
| SPKI hash pinning | SHA-256 of SPKI | Medium (same as public key) | OkHttp, AFNetworking |
| CA pinning | Intermediate or root CA cert | High (any cert from that CA works) | Enterprise apps |
| Multi-pin (backup pins) | Primary + backup pins | High (fallback pins) | HPKP-aware apps |

### How Pinning Works

```
TLS Handshake
│
├── Server presents certificate chain
│
├── Standard validation (system trust store)
│   └── Passes? continue : connection fails
│
└── Pin validation (app-level check)
    ├── Extract server cert/pubkey/SPKI hash
    ├── Compare against embedded pins
    └── Match found? → allow : → reject connection
```

---

## 2. ANDROID BYPASS METHODS

### 2.1 Frida Universal SSL Bypass

```javascript
// Hooks TrustManager, OkHttp, Volley, Retrofit, Conscrypt
Java.perform(function() {

    // ── TrustManagerImpl (Android system) ──
    try {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.verifyChain.implementation = function() {
            console.log('[Bypass] TrustManagerImpl.verifyChain');
            return arguments[0]; // return untouched chain
        };
    } catch(e) {}

    // ── X509TrustManager (custom implementations) ──
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function() {},
            checkServerTrusted: function() {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function(km, tm, sr) {
        console.log('[Bypass] SSLContext.init');
        this.init(km, [TrustManager.$new()], sr);
    };

    // ── OkHttp3 CertificatePinner ──
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[Bypass] OkHttp3 CertificatePinner.check: ' + arguments[0]);
        };
        // check$okhttp variant (OkHttp 4.x)
        try { CP['check$okhttp'].implementation = function() {}; } catch(e) {}
    } catch(e) {}

    // ── Retrofit / OkHttp interceptor ──
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient$Builder');
        OkHttpClient.certificatePinner.implementation = function(pinner) {
            console.log('[Bypass] OkHttpClient.Builder.certificatePinner');
            return this; // return builder without pinner
        };
    } catch(e) {}

    // ── Volley (HurlStack) ──
    try {
        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        HurlStack.createConnection.implementation = function(url) {
            console.log('[Bypass] Volley HurlStack: ' + url);
            var conn = this.createConnection(url);
            // Remove hostname verifier
            conn.setHostnameVerifier(Java.use(
                'javax.net.ssl.HttpsURLConnection').getDefaultHostnameVerifier());
            return conn;
        };
    } catch(e) {}

    // ── Conscrypt / BoringSSL (modern Android) ──
    try {
        var Conscrypt = Java.use('org.conscrypt.ConscryptFileDescriptorSocket');
        Conscrypt.verifyCertificateChain.implementation = function() {
            console.log('[Bypass] Conscrypt verifyCertificateChain');
        };
    } catch(e) {}

    // ── Apache HttpClient (legacy) ──
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;',
            '[Ljava.lang.String;', 'boolean').implementation = function() {
            console.log('[Bypass] Apache AbstractVerifier');
        };
    } catch(e) {}

    // ── HostnameVerifier ──
    try {
        var HV = Java.use('javax.net.ssl.HttpsURLConnection');
        HV.setDefaultHostnameVerifier.implementation = function(v) {
            console.log('[Bypass] Ignoring custom HostnameVerifier');
        };
    } catch(e) {}

    console.log('[+] Android universal SSL bypass loaded');
});
```

### 2.2 Objection (One Command)

```bash
objection -g com.target.app explore --startup-command "android sslpinning disable"
```

### 2.3 Network Security Config (Debug Override)

```xml
<!-- AndroidManifest.xml: android:networkSecurityConfig="@xml/network_security_config" -->

<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <base-config>
    <trust-anchors>
      <certificates src="system" />
      <certificates src="user" />     <!-- Trust user-installed CAs -->
    </trust-anchors>
  </base-config>
</network-security-config>
```

Workflow: decompile APK → add/modify config → repackage → re-sign → install.

```bash
apktool d target.apk -o target_dir
# Edit res/xml/network_security_config.xml
# Add reference in AndroidManifest.xml if missing
apktool b target_dir -o target_patched.apk
zipalign -v 4 target_patched.apk target_aligned.apk
apksigner sign --ks my-key.keystore target_aligned.apk
adb install target_aligned.apk
```

### 2.4 Xposed / LSPosed Modules

| Module | Method | Scope | Root Required |
|---|---|---|---|
| JustTrustMe | Hooks TrustManager + OkHttp | Per-app | Yes (Xposed) |
| SSLUnpinning | Hooks certificate validation | Per-app | Yes (LSPosed) |
| TrustMeAlready | Global TrustManager bypass | System-wide | Yes (LSPosed) |

### 2.5 Magisk + System CA Installation

```bash
# Install proxy CA as system cert (Android 7+ requires this for system-level trust)
# Method 1: MagiskTrustUserCerts module
# Moves user CAs to /system/etc/security/cacerts/ via Magisk overlay

# Method 2: Manual (requires root)
adb push burp_ca.pem /sdcard/
adb shell
su
mount -o remount,rw /system
cp /sdcard/burp_ca.pem /system/etc/security/cacerts/9a5ba575.0  # hash-named
chmod 644 /system/etc/security/cacerts/9a5ba575.0
mount -o remount,ro /system

# Get correct hash filename:
openssl x509 -inform PEM -subject_hash_old -in burp_ca.pem | head -1
# Output: 9a5ba575 → filename is 9a5ba575.0

# CRITICAL: Android 14+ (API 34+) uses a SEPARATE Conscrypt trust store.
# Installing in /system/etc/security/cacerts/ alone is NOT enough.
# You must ALSO copy to /apex/com.android.conscrypt/cacerts/:
cp /sdcard/burp_ca.pem /apex/com.android.conscrypt/cacerts/$(openssl x509 -inform PEM -subject_hash_old -in /sdcard/burp_ca.pem | head -1).0
chmod 644 /apex/com.android.conscrypt/cacerts/*.0

# Also copy to user cert store (for apps that check both):
mkdir -p /data/misc/user/0/cacerts-added/
cp /sdcard/burp_ca.pem /data/misc/user/0/cacerts-added/$(openssl x509 -inform PEM -subject_hash_old -in /sdcard/burp_ca.pem | head -1).0
chmod 644 /data/misc/user/0/cacerts-added/*.0
chcon u:object_r:system_security_cacerts_file:s0 /apex/com.android.conscrypt/cacerts/*.0
```

### 2.6 Manual Decompile → Patch → Repackage

```bash
# Step 1: Decompile
jadx -d decompiled/ target.apk

# Step 2: Find pinning code
grep -r "CertificatePinner\|X509TrustManager\|checkServerTrusted\|ssl" decompiled/

# Step 3: Identify pinning implementation and patch
# Use smali editing for precise control:
apktool d target.apk
# Edit smali files to NOP out pinning checks
# Look for invoke-virtual {checkServerTrusted} and replace with return-void

# Step 4: Repackage and sign
apktool b target_dir -o patched.apk
apksigner sign --ks debug.keystore patched.apk
```

---

## 3. iOS BYPASS METHODS

### 3.1 Frida (SecTrust Hooks)

```javascript
// Hook core iOS SSL validation functions
var SecTrustEvaluateWithError = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
Interceptor.attach(SecTrustEvaluateWithError, {
    onLeave: function(retval) {
        retval.replace(ptr(1));
    }
});

var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
Interceptor.attach(SecTrustEvaluate, {
    onLeave: function(retval) {
        retval.replace(ptr(0));
    }
});

// Hook SSLHandshake (lower-level)
var SSLHandshake = Module.findExportByName('Security', 'SSLHandshake');
if (SSLHandshake) {
    Interceptor.attach(SSLHandshake, {
        onLeave: function(retval) {
            if (retval.toInt32() === -9807) { // errSSLXCertChainInvalid
                retval.replace(ptr(0));
            }
        }
    });
}

// Hook NSURLSession delegate method
try {
    var cls = ObjC.classes.NSURLSession;
    // Hook URLSession:didReceiveChallenge:completionHandler: on delegates
    ObjC.enumerateLoadedClasses({
        onMatch: function(name) {
            try {
                var methods = ObjC.classes[name].$ownMethods;
                for (var i = 0; i < methods.length; i++) {
                    if (methods[i].indexOf('didReceiveChallenge') !== -1 &&
                        methods[i].indexOf('completionHandler') !== -1) {
                        console.log('[SSL] Found delegate: ' + name + ' ' + methods[i]);
                    }
                }
            } catch(e) {}
        },
        onComplete: function() {}
    });
} catch(e) {}
```

### 3.2 Objection (One Command)

```bash
objection -g com.target.app explore --startup-command "ios sslpinning disable"
```

### 3.3 SSL Kill Switch 2 (Jailbreak Tweak)

```bash
# Install via Cydia/Sileo
# Package: com.nablac0d3.sslkillswitch2
# Disables SSL pinning system-wide or per-app via Settings toggle

# Hooks:
# - SecTrustEvaluate
# - SSLHandshake
# - SSLSetSessionOption
# - tls_helper_create_peer_trust
```

### 3.4 Library-Specific Hooks

| Library | iOS Hook Point | Frida Approach |
|---|---|---|
| AFNetworking | `AFSecurityPolicy.evaluateServerTrust:forDomain:` | Return YES |
| Alamofire | `ServerTrustManager.evaluate(_:forHost:)` | Skip evaluation |
| TrustKit | `TSKPinningValidator verifyPublicKeyPin:` | Return success |
| NSURLSession | `URLSession:didReceiveChallenge:completionHandler:` | Call completionHandler with .useCredential |

### 3.5 Manual Binary Patch

```bash
# Find pinning function in binary
strings decrypted_binary | grep -i "pin\|cert\|trust"
# Disassemble and find the validation function
# Replace comparison/branch instruction with NOP or unconditional pass

# LLDB runtime modification
lldb -n TargetApp
(lldb) breakpoint set -n "SecTrustEvaluateWithError"
(lldb) breakpoint command add 1
> thread return 1
> continue
> DONE
```

---

## 4. FRAMEWORK-SPECIFIC BYPASSES

### 4.1 Flutter

Flutter uses Dart's `dart:io` library with BoringSSL. Standard Java-layer Frida hooks (TrustManager, OkHttp) do NOT work for Flutter's own HTTPS traffic — you must hook BoringSSL at the native level.

**CRITICAL: Where BoringSSL functions live**

On modern Android (12+), Flutter apps link against the **system `libssl.so`** (BoringSSL), NOT a statically-linked copy inside `libflutter.so`. The old guidance to scan `libflutter.so` for SSL exports is wrong for most modern Flutter apps.

```javascript
// CORRECT: find SSL functions in system libssl.so (not libflutter.so)
// Use Module.findExportByName(null, name) for system-wide search,
// or Process.findModuleByName('libssl.so').findExportByName(name)

// Key functions to hook (all in libssl.so on Android):
var libssl = Process.findModuleByName('libssl.so');
if (libssl) {
    // 1. SSL_CTX_set_custom_verify — Flutter's primary cert verification entry point
    var ctx_custom_verify = libssl.findExportByName('SSL_CTX_set_custom_verify');
    if (ctx_custom_verify) {
        Interceptor.attach(ctx_custom_verify, {
            onEnter: function(args) {
                args[1] = ptr(0); // SSL_VERIFY_NONE
            }
        });
    }

    // 2. SSL_CTX_set_verify — standard verify mode setter
    var ctx_verify = libssl.findExportByName('SSL_CTX_set_verify');
    if (ctx_verify) {
        Interceptor.attach(ctx_verify, {
            onEnter: function(args) { args[1] = ptr(0); }
        });
    }

    // 3. SSL_set_verify — per-connection verify mode
    var ssl_verify = libssl.findExportByName('SSL_set_verify');
    if (ssl_verify) {
        Interceptor.attach(ssl_verify, {
            onEnter: function(args) { args[1] = ptr(0); }
        });
    }

    // 4. SSL_get_verify_result — return X509_V_OK (0)
    var get_verify = libssl.findExportByName('SSL_get_verify_result');
    if (get_verify) {
        Interceptor.attach(get_verify, {
            onLeave: function(retval) { retval.replace(0); }
        });
    }

    // 5. ssl_verify_peer_chain — BoringSSL internal chain verification
    var peer_chain = libssl.findExportByName('ssl_verify_peer_chain');
    if (peer_chain) {
        Interceptor.attach(peer_chain, {
            onLeave: function(retval) { retval.replace(1); }
        });
    }

    // 6. SSL_CTX_set_cert_verify_callback — custom cert verification callback
    var cert_cb = libssl.findExportByName('SSL_CTX_set_cert_verify_callback');
    if (cert_cb) {
        Interceptor.attach(cert_cb, { onEnter: function(args) {} });
    }
}

// Also hook libcrypto.so for X509 chain verification
var libcrypto = Process.findModuleByName('libcrypto.so');
if (libcrypto) {
    var x509_verify = libcrypto.findExportByName('X509_verify_cert');
    if (x509_verify) {
        Interceptor.attach(x509_verify, {
            onLeave: function(retval) { retval.replace(1); }
        });
    }
}

// Traffic monitoring: hook SSL_write to see outgoing HTTP requests
var ssl_write = libssl ? libssl.findExportByName('SSL_write') : null;
if (!ssl_write) ssl_write = Module.findExportByName(null, 'SSL_write');
if (ssl_write) {
    Interceptor.attach(ssl_write, {
        onEnter: function(args) {
            try {
                var len = args[2].toInt32();
                if (len > 0 && len < 4096) {
                    var buf = Memory.readUtf8String(args[1], len);
                    if (buf && (buf.indexOf('GET ') === 0 || buf.indexOf('POST ') === 0)) {
                        console.log('[>>>] ' + buf.substring(0, 500));
                    }
                }
            } catch(e) {}
        }
    });
}
```

**PITFALL: `Process.findModuleByName('libflutter.so')` returns null at spawn time.** Flutter engine loads lazily. Use `setTimeout(function(){...}, 1000)` to defer native hooks, or enumerate modules after spawn:

```javascript
// CORRECT: defer native hooks — libssl.so loads early, libflutter.so loads late
setTimeout(function() {
    var libssl = Process.findModuleByName('libssl.so');  // available at spawn
    // var libflutter = Process.findModuleByName('libflutter.so');  // may be null!
    // hook libssl functions here...
}, 1000);
```

**PITFALL: `Module.findExportByName` vs `module.findExportByName`.** In Frida 17.x, `Module.findExportByName(moduleName, exportName)` is the correct static call. Do NOT use `module.enumerateExports().filter(...)` — it returns an array, not a function, and will throw `TypeError: not a function`.

**PITFALL: Still hook Java SSL layers too.** Flutter apps often have native Android plugins (Firebase, Datadog, etc.) that use Java HTTP clients. Hook TrustManagerImpl + SSLContext.init + OkHttp CertificatePinner in addition to native BoringSSL hooks. See §2.1.

**CRITICAL: Flutter `dart:io HttpClient` does NOT respect Android system proxy settings.** Setting `adb shell settings put global http_proxy host:port` will NOT redirect Flutter traffic to Burp/mitmproxy. Flutter Dio HTTP client also ignores proxy settings.

**Traffic Interception Methods (ranked by reliability):**

1. **mitmproxy reverse proxy + iptables REDIRECT + adb reverse** (BEST — tested working on Android 15 / Flutter Dio):
   ```bash
   # Step 1: Start mitmproxy in reverse proxy mode targeting the API server
   mitmdump --mode reverse:https://api.target.com --listen-port 8082 --set ssl_insecure=true -w traffic.mitm

   # Step 2: Install mitmproxy CA cert as system cert (see §2.5 for hash method)
   openssl x509 -inform PEM -in ~/.mitmproxy/mitmproxy-ca-cert.pem -subject_hash_old | head -1
   # Push and install to /system/etc/security/cacerts/, /apex/com.android.conscrypt/cacerts/, /data/misc/user/0/cacerts-added/

   # Step 3: Set up iptables REDIRECT on device (root required)
   adb shell "su -c 'iptables -t nat -F OUTPUT'"
   adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082'"
   adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8082'"

   # Step 4: Set up adb reverse (maps device localhost:8082 → host:8082)
   adb reverse tcp:8082 tcp:8082

   # Step 5: Run Frida SSL bypass script + launch app
   frida -U -f com.target.app -l bypass.js
   ```
   **Why this works:** iptables REDIRECT captures ALL outbound 443 traffic at kernel level (Flutter can't bypass it). adb reverse maps the device's redirect port to the host running mitmproxy. mitmproxy reverse mode terminates TLS (using its own CA, which we installed) and forwards to the real server. Frida hooks ensure the app trusts mitmproxy's CA.

2. **VPN-based proxy** (ProxyDroid, HTTP Toolkit — routes ALL device traffic through VPN tunnel)

3. **Frida SSL_write hook** (captures traffic in Frida console — no proxy needed, but no GUI, and only captures requests not responses reliably)

4. **reflutter** (patches BoringSSL in libflutter.so — CAUTION: may crash the app, see pitfall below)

**PITFALL: reflutter may crash Flutter apps.** reflutter patches `libflutter.so` to redirect traffic and disable SSL verification, but the patched APK can crash with a native crash in `FlutterJNI.attachToNative`. Test on a copy first. If it crashes, fall back to the mitmproxy reverse proxy approach (method 1 above).

**Burp Suite with iptables REDIRECT + BoringSSL hooks (VERIFIED WORKING):** When Frida BoringSSL hooks are active (SSL_CTX_set_custom_verify mode=0, SSL_get_verify_result→0, X509_verify_cert→1) AND the SPKI pin hash in libapp.so is patched to match Burp's SPKI, Burp DOES intercept Flutter HTTPS traffic via iptables REDIRECT + adb reverse. Setup: `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080` + `adb reverse tcp:8080 tcp:8080` + Burp on `0.0.0.0:8080`. The BoringSSL hooks disable TLS verification so Burp's CA doesn't even need to be in the trust store (though installing it is still recommended for non-Flutter native plugins like Firebase). Enable "Support invisible proxying" in Burp Proxy > Options > Listener > Request handling for transparent connections. This approach is simpler than mitmproxy reverse mode and provides Burp's full HTTP History GUI.

**PITFALL: `iptables REDIRECT --to-port` redirects ALL HTTPS traffic, breaking Firebase, Datadog, and Google services.** When you redirect all port 443 traffic to the proxy, SDKs that use Java HTTP clients (Firebase Remote Config, Datadog, Google Play Services) also get redirected. Their TLS connections fail because they don't have the proxy's CA in their trust store, causing the app to hang on splash screen ("firebase: remote_config fetch failed", "Datadog: Trust anchor for certification path not found"). **Fix: use `iptables DNAT --to-destination <PC_IP>:<PORT>` targeting ONLY the API server's IP**, leaving other HTTPS traffic untouched:

```bash
# Get the API server IP (resolve from device or host)
nslookup api.target.com  # e.g., 42.96.60.248

# DNAT only the API server's traffic to mitmproxy on PC
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 42.96.60.248 --dport 443 -j DNAT --to-destination 192.168.0.117:8888'"

# mitmproxy runs on PC in regular proxy mode (NOT transparent mode — transparent fails on Windows)
mitmdump --listen-host 0.0.0.0 --listen-port 8888 --set block_global=false

# Clean up when done:
adb shell "su -c 'iptables -t nat -D OUTPUT -p tcp -d 42.96.60.248 --dport 443 -j DNAT --to-destination 192.168.0.117:8888'"
```

This approach: (1) captures Flutter Dio traffic to the API server (Dio connects directly, DNAT redirects to mitmproxy), (2) leaves Firebase/Datadog/GMS traffic untouched (they connect directly to their servers), (3) works on Windows (no WinDivert needed — regular proxy mode, not transparent).

**NOTE: With DNAT, mitmproxy must run in regular proxy mode (not transparent/reverse mode).** If mitmproxy returns 502 Bad Gateway, it means mitmproxy couldn't connect to the upstream server — check mitmproxy logs for the specific error.

**NOTE: With DNAT targeting the API server, you still need to patch ALL SPKI pins** to the mitmproxy CA SPKI. The logcat message `ssl_pin_rejected: host=api.target.com presentedPin=XXXX allowedPins=N` tells you exactly how many pins to patch. If `allowedPins=3`, patch all 3 (plus any standalone pins) to the mitmproxy CA SPKI.

**Chaining mitmproxy (SSL bypass) → Burp (GUI inspection):** mitmproxy can act as a reverse proxy (terminating TLS with the patched SPKI) and forward traffic to Burp for GUI inspection. Use `--set upstream_proxy=http://127.0.0.1:8080` (NOT `--mode upstream:...` which conflicts with `--mode reverse:...`). The `--mode` flag can only be specified once — combine reverse mode with upstream proxy via the `--set` option:

```bash
# Chain: Device → mitmproxy:9091 (reverse, SSL pin bypass) → Burp:8080 (GUI) → Server
mitmdump --mode reverse:https://api.target.com -p 9091 \
  --set block_global=false --ssl-insecure \
  --set upstream_proxy=http://127.0.0.1:8080
# Then: iptables DNAT on device: -d <API_IP> --dport 443 -j DNAT --to <PC_IP>:9091
```

This gives you both SSL bypass (mitmproxy presents cert matching patched SPKI) AND Burp's HTTP History GUI (upstream proxy). Without the chain, mitmproxy alone captures traffic but you only see it in the CLI log — no GUI for repeater/scanner.

**PITFALL: mitmproxy `--mode` flag can only be used once.** Combining `--mode reverse:https://server` with `--mode upstream:http://burp:8080` fails with `Cannot spawn multiple servers on the same address`. Use `--set upstream_proxy=http://host:port` instead of a second `--mode`.

**PITFALL: DNAT to PC IP fails when Windows Firewall blocks inbound from device.** `iptables DNAT --to-destination <PC_IP>:<PORT>` sends traffic to the PC's IP, but Windows Firewall blocks all inbound TCP from the device by default. `nc <PC_IP> <PORT>` from device times out, even though `adb shell ping <PC_IP>` works (ICMP allowed, TCP blocked). **Fix: use DNAT to `127.0.0.1:PORT` + `adb reverse tcp:PORT tcp:PORT`** — ADB reverse tunnels through USB, bypassing Windows Firewall entirely:

```bash
# Step 1: ADB reverse (maps device localhost:8443 → PC:8443 via USB tunnel)
adb reverse tcp:8443 tcp:8443

# Step 2: DNAT to localhost (NOT to PC IP) — traffic goes to device localhost:8443, then ADB reverse forwards to PC:8443
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d <API_SERVER_IP> --dport 443 -j DNAT --to-destination 127.0.0.1:8443'"

# Step 3: mitmproxy on PC in reverse mode (receives traffic from ADB reverse tunnel)
mitmdump --mode reverse:https://api.target.com:443 --listen-port 8443 --set ssl_insecure=true

# This approach: (1) captures Flutter Dio traffic, (2) bypasses Windows Firewall (ADB USB tunnel),
# (3) bypasses server IP blocking (mitmproxy on PC connects to server, not device),
# (4) works with binary-patched SPKI (no Frida needed — patch libapp.so with mitmproxy CA SPKI)
```

**VERIFIED (Android 15, Samsung S25, Flutter v1.1.31, no Frida):** Binary-patched SPKI (mitmproxy CA) + ADB reverse + DNAT to localhost + mitmproxy reverse mode. Server (42.96.60.248:443) blocked device IP entirely (TCP SYN_SENT timeout) but allowed PC IP (HTTP 200). Windows Firewall blocked device → PC TCP on all ports. ADB reverse bypassed both: device → localhost:8443 → (ADB USB) → PC:8443 → mitmproxy → server:443. App login API call succeeded (POST /api/v1/auth/face → 401 response in 613ms, previously timed out after 3 minutes).

**PITFALL: Leftover iptables DNAT rules can cause ADB disconnection.** If using WiFi ADB, a broad DNAT rule (without `-d <specific_IP>`) may redirect ADB traffic, causing the device to become unreachable via `adb`. Always use `-d <API_SERVER_IP>` to target only the API server, and clean up rules after testing. If the device disconnects, reboot it to clear iptables (rules are not persistent across reboots).

**PITFALL: Frida CLI "Connection terminated" is NOT an app crash.** The `frida` CLI process may exit (timeout, pipe issue, or background process management) while the app continues running with all hooks and memory patches still active. Memory patches (SPKI pin hash in libapp.so) persist in the process's RAM until the app is killed — Frida does NOT need to stay connected for the patch to remain. BoringSSL hooks via `Interceptor.replace` also persist in the process after Frida disconnects (the trampolines remain installed). To verify the app is still running: `adb shell ps -A | grep <package>`. If you need to re-attach Frida (e.g., to install new hooks), use `frida -U -n <package>` (attach to running process) instead of `frida -U -f <package>` (spawn new). However, `Interceptor.replace` hooks from a spawn session may NOT persist after detach — only memory patches are guaranteed to persist. If BoringSSL hooks are needed throughout, keep Frida connected or use `frida -U -f ... --no-pause` with a long timeout.

**PITFALL: Frida spawn with `timeout` kills the app when timeout expires.** Using `timeout 60 frida -U -f com.app -l bypass.js` kills the Frida process, which kills the spawned app. To keep the app alive after Frida exits, use `frida -U -f com.app -l bypass.js &` (background, no timeout) or spawn the app separately (`adb shell am start -n com.app/.MainActivity`) and then attach with `frida -U -n com.app`.

**PITFALL: `frida-server` crashes frequently on heavy hook scripts.** If `frida-ps -U` hangs or `frida -U -f` shows "Failed to spawn: need Gadget to attach on jailed Android", frida-server has died. Restart: `adb shell "su -c 'killall frida-server 2>/dev/null; sleep 1; setsid /data/local/tmp/frida-server >/dev/null 2>&1 &'"` then verify with `frida-ps -U | head -3`.

**VERIFIED WORKING: Burp Suite + iptables REDIRECT for Flutter traffic interception (alternative to mitmproxy reverse mode):**

When BoringSSL hooks are active (SSL_CTX_set_custom_verify mode=0, SSL_get_verify_result→0, X509_verify_cert→1) AND the SPKI pin hash in libapp.so is patched to match Burp's SPKI, Burp Suite successfully intercepts Flutter HTTPS traffic via iptables REDIRECT + adb reverse. This is simpler than mitmproxy reverse mode and provides Burp's full HTTP History GUI.

Setup:
```bash
# 1. iptables REDIRECT on device (root required)
adb shell "su -c 'iptables -t nat -F OUTPUT'"
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080'"
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080'"

# 2. adb reverse (maps device localhost:8080 to host:8080)
adb reverse tcp:8080 tcp:8080

# 3. Burp Suite on 0.0.0.0:8080 (enable "Support invisible proxying" in Proxy > Options)
# 4. Install Burp CA as system cert (see §2.5)
# 5. Run Frida bypass script (BoringSSL hooks + SPKI memory patch)
frida -U -f com.target.app -l bypass.js
```

Verified on Android 15, Flutter v1.1.31+1 with Dart-layer SPKI pinning, Frida 17.9.6. App login succeeded, API traffic intercepted, 3+ ESTABLISHED Burp connections from device. BoringSSL hooks disable TLS verification so Burp's CA doesn't even need to be in the trust store (though installing it is still recommended for non-Flutter native plugins like Firebase that use the Java SSL stack).

**PITFALL: `Java` is undefined at Frida spawn time for Flutter apps.** When using `frida -U -f`, the Java VM may not be initialized when the script loads. Use a retry loop:
```javascript
function tryJava(attempt) {
    if (typeof Java === 'undefined' || !Java.available) {
        if (attempt < 15) setTimeout(function() { tryJava(attempt + 1); }, 2000);
        return;
    }
    Java.perform(function() { /* hooks here */ });
}
setTimeout(function() { tryJava(1); }, 2000);
```

**PITFALL: `libflutter.so` may have 0 SSL exports/symbols (stripped BoringSSL).** Do NOT rely on finding SSL functions inside `libflutter.so`. Hook the **system `libssl.so`** instead — modern Flutter apps on Android 12+ use the system SSL library. Verify by checking if `TrustManagerImpl.verifyChain` triggers (if it does, the app uses Java/system SSL stack, not static BoringSSL). In this session, `libflutter.so` had 531 symbols but 0 SSL-related — all SSL went through system `libssl.so`.

**CRITICAL: Some Flutter apps use rustls (Rust TLS) instead of BoringSSL for certificate verification.** Modern Flutter (Dart 3.12+) may statically link **rustls 0.23.x** + **rustls-webpki 0.103.x** (Rust TLS library) into `libflutter.so` for certificate chain verification, while still using BoringSSL for low-level crypto primitives (AES, RSA). This means:
- System `libssl.so` hooks (SSL_CTX_set_custom_verify, SSL_get_verify_result, etc.) will NOT intercept the app's certificate verification — the app's TLS connections to its API servers use rustls, not system BoringSSL.
- S3/CDN traffic (images, static assets) MAY still be intercepted because those connections use system BoringSSL (via Dart's HttpClient which falls back to system SSL for non-pinned connections).
- The symptom: mitmproxy captures S3 image requests (200 OK, `user-agent: Dart/3.12 (dart:io)`) but the app's API domain (e.g., `lamb.mbageas.life`) shows "Client TLS handshake failed. The client does not trust the proxy's certificate."

**How to detect rustls in a Flutter app:**
```bash
# Search libflutter.so for rustls strings
strings -t x libflutter.so | grep -i "rustls\|webpki\|verify_cert"
# Expected if rustls is present:
# rustls-0.23.37/src/webpki/verify.rs
# rustls-webpki-0.103.10/src/verify_cert.rs
# rustls-0.23.37/src/webpki/server_verifier.rs
# rustls-0.23.37/src/client/client_conn.rs
# ureq-3.3.0/src/tls/rustls.rs

# Search for rustls error strings (indicates cert verification is in Rust)
strings libflutter.so | grep -i "invalid peer certificate\|certificate parsing failed\|UnknownIssuer\|CertNotValidForName"
```

**How to hook rustls when system BoringSSL hooks don't work:**
1. The rustls `verify_cert` function is statically linked in `libflutter.so` but symbols are stripped — `Module.findExportByName("libflutter.so", "ssl_verify_peer_cert")` returns null.
2. Find the string `"invalid peer certificate: "` in `libflutter.so` memory at runtime using `Memory.scanSync` — it's in the `.rodata` section.
3. Find `SecurityContext_SetTrustedCertificatesBytes` and `SecureSocket_Handshake` strings — these are Dart VM native API functions that manage trusted certificates.
4. **Best approach: patch `assets/certs.ts`** (the app's trusted CA bundle) to include the mitmproxy CA cert, then rebuild APK. This makes the app's rustls trust store include your CA. Note: this alone may NOT be sufficient if the app also uses Dart-level `onBadCertificate` callback for additional pinning.
5. **Alternative: binary-patch `libflutter.so`** to NOP the rustls `verify_cert` function (requires finding the function via cross-reference from the `"invalid peer certificate: "` string in `.rodata` to the code that references it in `.text`).

**Frida 17.x API: use `module.findExportByName(name)` not `Module.findExportByName(moduleName, name)`.** In Frida 17.x, `Module.findExportByName(moduleName, name)` may return `undefined` (not a function) for some modules, causing `TypeError: not a function` when passed to `Interceptor.attach`. The correct approach:
```javascript
// CORRECT (Frida 17.x): use module instance method
var libssl = Process.findModuleByName("libssl.so");
var exports = libssl.enumerateExports();
var addr = exports.find(function(e) { return e.name === "SSL_CTX_set_custom_verify"; }).address;
Interceptor.attach(addr, { ... });

// WRONG (causes TypeError in Frida 17.x):
var addr = Module.findExportByName("libssl.so", "SSL_CTX_set_custom_verify");
// May return undefined, then Interceptor.attach(addr, ...) throws TypeError
```

**Frida 17.x: `Process.findRangeByAddress` is NOT a function.** Do not use `Process.findRangeByAddress(addr)` to check memory protections — it doesn't exist in Frida 17.x. Use `Process.findModuleByAddress(addr)` (which exists) if you need to identify which module an address belongs to.

**VERIFIED WORKING STACK (Android 15, Flutter Dio, Frida 17.9.6, mitmproxy 12.2.2, Windows host):**

The combination of Frida (hooks system `libssl.so` + Java `TrustManagerImpl`) + mitmproxy reverse proxy + iptables REDIRECT + adb reverse + mitmproxy CA in system/Conscrypt stores was confirmed working. App login succeeded, API traffic decrypted and captured (POST /api/v1/auth/face → 200 OK, GET /api/v1/worker/* → 200 OK). See `references/flutter-traffic-interception.md` for the full end-to-end recipe with architecture diagram, step-by-step commands, and troubleshooting table.

**How to verify the bypass is working:**
1. Frida output shows `[+] BYPASS #1: TrustManagerImpl.verifyChain` (or `SSLContext.init`)
2. mitmproxy log shows `client connect` → `server connect` → `GET/POST https://...` → `<< 200 OK`
3. Flutter logcat (`adb logcat -s flutter`) shows Dio request/response logs with full headers and body
4. App UI proceeds past login (no timeout or "no network" error)

**Dio HTTP client logging:** Flutter apps using the Dio package log full request/response details to logcat. Use `adb logcat -s flutter` to see API endpoints, headers, form data, and response bodies — invaluable for debugging when proxy interception isn't working yet. Example log format:
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

**Complete working script template:** See `templates/flutter-spki-memory-patch.js` — combines memory patch + BoringSSL hooks + Java SSL + root detection bypass. Tested on Android 15, Flutter app with `ssl_pins_sha256` in libapp.so, Frida 17.9.6.

**Detailed technique and troubleshooting:** See `references/flutter-dart-spki-pinning.md` — covers detection, memory patch internals, SPKI hash computation, RaspGuard anti-tamper, and why APK repack fails.

**RaspGuard (Talsec FreeRASP) enforcement bypass:** See `references/raspguard-bypass.md` — when RaspGuard blocks the app (shows "Unable to open application" screen), you need a smali patch (return empty threat list from MethodChannel) + libapp.so string patch (same-length replacement of `privileged_access (root/jailbreak)` and `rasp_threat: ` strings). Required when the app shows a blocking screen after SSL pin bypass.

**CRITICAL: Talsec freeRASP can KILL frida-server (not just detect it).** Unlike detection-only RaspGuard, Talsec's native library `libts.so` contains `scan_for_frida_server_all_ports` — a function that actively scans for and terminates the frida-server process. Symptoms: `frida -U -p PID` connects, prints a few hook messages, then "Connection terminated" — and `adb shell "su -c 'ps -A | grep frida'"` shows frida-server is dead. Renaming the frida-server binary or using `--policy-softener=internal --ignore-crashes` does NOT help because Talsec scans by port, not by process name. **Fix: APK-patch Talsec out of the smali before running Frida.** See `references/talsec-freerasp-apk-patching.md` for the complete 6-patch approach (NOP freerasp plugin registration, NOP Talsec.start(), comment out `System.loadLibrary("ts")`, neutralize RootBeerNative, skip isRootChecker branch). Verification script: `scripts/verify-talsec-patches.sh`.

**PITFALL: Memory.scanSync on libts.so causes SIGSEGV.** Do NOT use `Memory.scanSync(libts.base, libts.size, ...)` in Frida scripts to search for strings in `libts.so` — some memory regions are guarded and cause `Error: access violation accessing 0x...`. Only use `Interceptor.attach` on exported functions. If you need to find strings in libts.so, use `strings` on the .so file on disk before injecting.

**PITFALL: Frida spawn (`-f`) fails on Android 15 with `unable to locate android.os.Process.setArgV0()`.** Use `adb shell am start` to launch the app, then attach by PID: `frida -U -p $(adb shell pidof com.target.app) -l bypass.js`.

**No-Frida binary patch approach:** See `references/flutter-binary-patch-no-frida.md` — patch SPKI hash directly in libapp.so (no runtime instrumentation needed). Use when frida-server crashes or is unstable. Three SPKI variants: (1) server's real SPKI for direct connection (RECOMMENDED — no proxy needed), (2) Burp's MITM SPKI for Burp interception, (3) mitmproxy's MITM SPKI for mitmproxy interception. **CRITICAL: If you patch with a proxy SPKI, you MUST use iptables REDIRECT + adb reverse — Flutter ignores system proxy settings, so setting `http_proxy` alone will cause SSL pin mismatch (app connects direct to server, server's real cert doesn't match proxy SPKI).** Includes steps for both direct connection (server's real SPKI) and Burp proxy (Burp's MITM SPKI).

**Full traffic interception setup guide:** See `references/flutter-traffic-interception.md` for the complete mitmproxy reverse proxy + iptables + adb reverse + Frida setup, including architecture diagram, step-by-step instructions, troubleshooting, and cleanup. Includes three approaches: (A) Burp + Frida + iptables REDIRECT, (B) mitmproxy + Frida + iptables REDIRECT, (C) Binary patch (no Frida) + ADB reverse + DNAT to localhost — for when Frida crashes, server blocks device IP, or Windows Firewall blocks device→PC TCP.

**Working Frida script (BoringSSL + Java SSL, no Dart pinning):** See `templates/flutter-ssl-bypass.js` for a complete script that hooks Java SSL + native BoringSSL + RootBeer + traffic monitoring, tested on Android 15 / Flutter app. The template uses `module.findExportByName(name)` (Frida 17.x compatible) and a `tryJava()` retry loop for Flutter apps where Java VM initializes late.

### 4.1.1 Flutter Dart-Layer SPKI Pinning (ssl_pins_sha256)

Some Flutter apps embed SPKI pin hashes directly in compiled Dart code (`libapp.so`) as base64 strings. The pin check happens in Dart, NOT in BoringSSL — so hooking `SSL_CTX_set_custom_verify` and `TrustManagerImpl` is NOT sufficient. The app rejects the proxy's certificate with a log like:

```
ssl_pin_rejected: host=api.target.com presentedPin=jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ= allowedPins=3
```

**How to detect Dart-layer SPKI pinning:**

```bash
# Extract libapp.so from APK
unzip base.apk lib/arm64-v8a/libapp.so -d /tmp/apk_extract

# Search for pin-related strings
strings libapp.so | grep -i "ssl_pin"          # ssl_pins_sha256, ssl_pin_rejected, ssl_pins_signature
grep -c "ssl_pins_sha256" libapp.so             # binary search (1+ = Dart pinning present)

# Find the SPKI pin hash (base64, 44 chars ending with =)
strings -n 20 libapp.so | grep -E "^[A-Za-z0-9+/]{43}=$"
# Or search for a known pin:
grep -boa "wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=" libapp.so   # returns byte offset

# Find Dart SSL function names
grep -boa "SecureSocket_RegisterBadCertificateCallback" libapp.so
grep -boa "SecureSocket_MarkAsTrusted" libapp.so
```

**Bypass method: Frida runtime memory patch (NO APK repack needed)**

Instead of patching libapp.so on disk (which triggers integrity checks and crashes), patch the pin hash **in process memory at runtime** using Frida's `Memory.scanSync` + `Memory.protect` + `writeUtf8String`:

1. Wait for `libapp.so` to load (defer with `setTimeout`)
2. Call `Memory.protect(libapp.base, libapp.size, 'rwx')` — make the read-only Dart snapshot writable
3. Convert the original pin string to a hex byte pattern
4. `Memory.scanSync(libapp.base, libapp.size, pattern)` — find the pin in memory
5. `address.writeUtf8String(BURP_PIN)` — overwrite with proxy's SPKI hash

**CRITICAL: Do NOT call `Memory.protect(libapp.base, libapp.size, 'rwx')` on the entire libapp.so.** This corrupts Dart AOT JIT code pages and causes SIGSEGV in `datadog-context` threads. Instead, use page-specific protection: after `Memory.scanSync` finds the pin address, compute the page-aligned base (`address.and(ptr(pageSize - 1).not())`) and protect ONLY that 4KB page with `Memory.protect(page_base, 4096, 'rwx')` before calling `writeUtf8String`. `Memory.scanSync` CAN scan read-only (`r--`) pages without `Memory.protect` — the access violation error only occurs on certain guarded pages, and a page-by-page fallback scan handles those.

**CRITICAL: Do NOT scan all memory regions (`Process.enumerateRanges`) for the pin hash.** The pin string may appear in memory regions outside libapp.so (e.g., heap copies at `0x70000d3c00`). Patching those copies causes SIGBUS in `datadog-context` threads. Only scan and patch within `libapp.so`'s address range.

**CRITICAL: Do NOT use Java hooks (`TrustManagerImpl`, `SSLContext.init`, etc.) on Flutter apps with RaspGuard.** `Java.perform()` causes race conditions resulting in SIGBUS in `datadog-context` and `EmojiCompatInit` threads. The working approach uses ONLY BoringSSL native hooks + the memory patch — no Java SSL hooks at all. Native Android plugins (Firebase, Datadog) use the system SSL stack which is already covered by the BoringSSL hooks.

**Computing the proxy's SPKI hash:**

```bash
# Extract Burp's CA cert from device system store and compute its SPKI hash
adb shell "su -c 'cat /system/etc/security/cacerts/9a5ba575.0'" | \
  openssl x509 -noout -pubkey | \
  openssl pkey -pubin -outform der | \
  openssl dgst -sha256 -binary | \
  openssl base64
# Output: jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=
```

**Complete working script (v2):** See `templates/flutter-spki-memory-patch.js` — BoringSSL hooks (Interceptor.replace with NativeCallback) + page-specific memory patch. NO Java hooks (they cause SIGBUS in datadog/EmojiCompat threads on Flutter apps with RaspGuard). NO all-memory scan (causes SIGBUS from heap copy patches). NO whole-module Memory.protect (causes SIGSEGV from Dart JIT corruption). Tested on Android 15, Flutter app with `ssl_pins_sha256` in libapp.so, Frida 17.9.6.

**Detailed technique and troubleshooting:** See `references/flutter-dart-spki-pinning.md` — covers detection, memory patch internals, SPKI hash computation, RaspGuard anti-tamper, and why APK repack fails.

**RaspGuard (Talsec FreeRASP) enforcement bypass:** See `references/raspguard-bypass.md` — when RaspGuard blocks the app (shows "Unable to open application" screen), you need a smali patch (return empty threat list from MethodChannel) + libapp.so string patch (same-length replacement of `privileged_access (root/jailbreak)` and `rasp_threat: ` strings). Required when the app shows a blocking screen after SSL pin bypass.

**CRITICAL: Talsec freeRASP can KILL frida-server (not just detect it).** Unlike detection-only RaspGuard, Talsec's native library `libts.so` contains `scan_for_frida_server_all_ports` — a function that actively scans for and terminates the frida-server process. Symptoms: `frida -U -p PID` connects, prints a few hook messages, then "Connection terminated" — and `adb shell "su -c 'ps -A | grep frida'"` shows frida-server is dead. Renaming the frida-server binary or using `--policy-softener=internal --ignore-crashes` does NOT help because Talsec scans by port, not by process name. **Fix: APK-patch Talsec out of the smali before running Frida.** See `references/talsec-freerasp-apk-patching.md` for the complete 6-patch approach (NOP freerasp plugin registration, NOP Talsec.start(), comment out `System.loadLibrary("ts")`, neutralize RootBeerNative, skip isRootChecker branch). Verification script: `scripts/verify-talsec-patches.sh`.

**PITFALL: Memory.scanSync on libts.so causes SIGSEGV.** Do NOT use `Memory.scanSync(libts.base, libts.size, ...)` in Frida scripts to search for strings in `libts.so` — some memory regions are guarded and cause `Error: access violation accessing 0x...`. Only use `Interceptor.attach` on exported functions. If you need to find strings in libts.so, use `strings` on the .so file on disk before injecting.

**PITFALL: Frida spawn (`-f`) fails on Android 15 with `unable to locate android.os.Process.setArgV0()`.** Use `adb shell am start` to launch the app, then attach by PID: `frida -U -p $(adb shell pidof com.target.app) -l bypass.js`.

**No-Frida binary patch approach:** See `references/flutter-binary-patch-no-frida.md` — patch SPKI hash directly in libapp.so (no runtime instrumentation needed). Use when frida-server crashes or is unstable. Three SPKI variants: (1) server's real SPKI for direct connection (RECOMMENDED — no proxy needed), (2) Burp's MITM SPKI for Burp interception, (3) mitmproxy's MITM SPKI for mitmproxy interception. **CRITICAL: If you patch with a proxy SPKI, you MUST use iptables REDIRECT + adb reverse — Flutter ignores system proxy settings, so setting `http_proxy` alone will cause SSL pin mismatch (app connects direct to server, server's real cert doesn't match proxy SPKI).** Includes steps for both direct connection (server's real SPKI) and Burp proxy (Burp's MITM SPKI).

**PITFALL: APK repack (patching libapp.so on disk) causes crashes.** Replacing the pin hash in the APK file and repackaging with zipalign + apksigner causes the app to crash on launch (`INSTALL_FAILED_INVALID_APK: Failed to extract native libraries` if .so is compressed; native crash `pid has died` even with `ZIP_STORED`). The Dart VM performs integrity checks on the snapshot. Runtime memory patching avoids this entirely.

**PITFALL: RaspGuard anti-tamper may detect root/Frida.** Some Flutter apps include RaspGuard (Runtime Application Self-Protection, Talsec FreeRASP). It logs `RaspGuard: threat detected — privileged_access (root/jailbreak)` and `app_integrity (repackaged/tampered)`. In testing, these warnings did NOT block app execution — the app continued running with the bypass active. If RaspGuard does block execution, hook the RaspGuard class via `Java.enumerateLoadedClasses` or patch the threat strings in libapp.so memory. **VERIFIED on Samsung S25 / Android 15 / Flutter v1.1.31 with Talsec FreeRASP**: RaspGuard detected both repack and root, logged to Datadog, but login and API calls succeeded normally. RaspGuard is a detection-only control in this app, not a blocking control.

**CRITICAL: RaspGuard (Talsec FreeRASP) CAN block the app — version-dependent.** In v1.1.31 of the SUNSite app, RaspGuard was upgraded from detection-only to **enforcement mode**: it shows a blocking screen ("Chưa thể mở ứng dụng" / "Unable to open application" / "Please close suspicious software") and prevents app usage. The blocking happens in Dart code (not Java), so patching the Java MethodChannel handler alone is NOT sufficient. **Three layers must be bypassed**: (1) Java `scan` MethodChannel (`sunsite/dev_integrity`) — return empty ArrayList, (2) Dart threat strings in libapp.so — same-length replacement of `privileged_access (root/jailbreak)` and `rasp_threat: `, (3) Talsec native engine init (`talsec.app/freerasp/methods` channel, `start` method) — remove `Ln2/g;->a()` call in `n2/d.smali`. Without Layer 3, RaspGuard still detects root via `libts.so` native checks and blocks the app after ~5 seconds. See `references/raspguard-bypass.md` for the full 3-layer bypass technique. **Do NOT assume RaspGuard is detection-only — always test by checking the app UI after patching SSL pinning. If the app shows a blocking screen, you need the RaspGuard bypass.**

**Verification of successful memory patch:**

```
[*] libapp.so memory protected as RWX
[*] Found 1 match(es) for original pin
[*] Patched pin at 0x79c8865105 -> jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=
[+] BYPASS #3: Patched SPKI pin hash in libapp.so (1 locations)
```

If the app no longer logs `ssl_pin_rejected` and traffic appears in Burp/mitmproxy, the bypass is working.

---

### 4.2 React Native

React Native uses platform networking: OkHttp on Android, NSURLSession on iOS. SSL pinning is typically implemented via the `react-native-ssl-public-key-pinning` library (package: `com.sslpublickeypinning`), which wraps OkHttp's `CertificatePinner`.

**CRITICAL difference from Flutter:** React Native loads SPKI pins **dynamically from the JS bundle at runtime** (not hardcoded in native code). The native module `SslPublicKeyPinningModule.initializeCertificatePinner(ReadableMap)` receives pin hashes from JS and constructs the `CertificatePinner`. This means: (1) pins are NOT in smali, (2) the JS bundle must be analyzed to find them, (3) the smali can be patched to skip pin initialization entirely.

**CRITICAL: React Native OkHttp respects Android system proxy settings** (unlike Flutter's dart:io HttpClient which ignores them). This means `adb shell settings put global http_proxy <PC_IP>:8080` works — no iptables REDIRECT or adb reverse needed for traffic interception.

| Platform | Networking Stack | Bypass Method |
|---|---|---|
| Android | OkHttp3 | Patch `initializeCertificatePinner` smali to no-op, OR Frida hook `getCertificatePinner()` |
| iOS | NSURLSession | Standard SecTrust hooks (§3.1) |
| Android (Hermes) | Same OkHttp | Same hooks — Hermes is just a JS engine, networking is still OkHttp |

**Detection:**
```bash
# Find the SSL pinning library in decompiled APK
grep -rl "sslpublickeypinning\|SslPublicKeyPinning" smali* 2>/dev/null
# Check for cert files in assets
ls assets/cert/  # e.g., uat.pem — extract domain: openssl x509 -in assets/cert/uat.pem -text -noout | grep "Subject Alternative Name"
# Find SSL config functions in Hermes JS bundle
strings -n 5 assets/index.android.bundle | grep -iP "disableSslPinning|initializeSslPinning|publicKeyHashes"
```

**Method 1 — Patch smali (no root, APK repack):** Patch `SslPublicKeyPinningModule.smali` → `initializeCertificatePinner` to `return-void` (prevents any pins from being registered). The `certificatePinner` static field stays null, so OkHttp's `CertificatePinner` is never set.

**Method 2 — Frida hook (runtime):** Hook `SslPublicKeyPinningModule.getCertificatePinner()` to return null, and `initializeCertificatePinner(ReadableMap)` to do nothing. Also hook `okhttp3.CertificatePinner.check()` as fallback. Note: OkHttp classes may be obfuscated (e.g., `cb/g` = CertificatePinner, `cb/z` = OkHttpClient) — check smali for actual class names.

**Method 3 — Objection:** `objection -g com.target.app explore --startup-command "android sslpinning disable"` — hooks `okhttp3.CertificatePinner.check` and `TrustManager`. Works for non-obfuscated OkHttp. If classes are obfuscated, use Method 2 with correct class names.

**Detailed analysis and bypass guide:** See `references/react-native-ssl-pinning.md` — covers Hermes JS bundle analysis, smali structure, obfuscated class mapping, and a full worked example (com.vn.seabank / SeABank Academy / Edufy).

```javascript
// React Native Android — same as OkHttp bypass
Java.perform(function() {
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) { console.log('OkHttp3 not found, trying okhttp2...'); }

    try {
        var CP2 = Java.use('com.squareup.okhttp.CertificatePinner');
        CP2.check.overload('java.lang.String', 'java.util.List').implementation = function() {};
    } catch(e) {}

    // Hook react-native-ssl-public-key-pinning module (if present)
    try {
        var SslPinningModule = Java.use('com.sslpublickeypinning.SslPublicKeyPinningModule');
        SslPinningModule.getCertificatePinner.implementation = function() { return null; };
        SslPinningModule.initializeCertificatePinner.implementation = function(map) {};
    } catch(e) {}
});
```

### 4.3 Xamarin

```csharp
// Xamarin pinning typically via:
// ServicePointManager.ServerCertificateValidationCallback
// or custom HttpClientHandler
```

```javascript
// Frida bypass for Xamarin (Mono runtime)
// Hook Mono method: System.Net.ServicePointManager.set_ServerCertificateValidationCallback
var mono_method = Module.findExportByName('libmonosgen-2.0.so',
    'mono_runtime_invoke');
// More practical: hook the managed callback at CIL level
// Use Frida's Mono bridge or objection's built-in Xamarin support

// Objection has built-in Xamarin bypass:
// objection -g com.target.app explore
// > android sslpinning disable   (covers Xamarin on Android)
```

---

## 5. CERTIFICATE TRANSPARENCY & HPKP

| Technology | Status | Impact on Testing |
|---|---|---|
| Certificate Transparency (CT) | Active, enforced by browsers | Mobile apps rarely enforce CT; not a bypass obstacle |
| HPKP (HTTP Public Key Pinning) | Deprecated (2018) | Legacy apps may still check; remove header from proxy response |
| Expect-CT header | Deprecated (2024) | Minimal impact on mobile testing |
| CT in mobile apps | Rare | Only Google apps enforce via custom CT checks |

---

## 6. TROUBLESHOOTING

### 6.1 Common Failures

| Symptom | Cause | Fix |
|---|---|---|
| Bypass script loaded but traffic still fails | Multiple pinning layers | Hook ALL layers: TrustManager + OkHttp + custom checks |
| "Client certificate required" | Mutual TLS (mTLS) | Extract client cert from app bundle/keychain, import into proxy |
| Connection works but no HTTP traffic | Non-HTTP protocol (MQTT, gRPC, WebSocket) | Use Wireshark or protocol-specific proxy |
| App crashes after bypass | Anti-tampering detects hooks | Bypass integrity checks first, then SSL |
| Proxy CA not trusted | Android 7+ user CA restrictions | Install CA as system cert (Magisk module) |
| Flutter app ignores hooks | BoringSSL not hooked at native layer | Use reflutter or native BoringSSL hooks (§4.1) |
| Flutter app ignores system proxy | dart:io HttpClient doesn't use Android proxy settings | Use reflutter, VPN-based proxy, or iptables redirect (§4.1) |
| `Process.findModuleByName('libflutter.so')` returns null | Flutter engine loads lazily, not available at spawn | Use `setTimeout(..., 1000)` or hook `libssl.so` instead (available at spawn) |
| `module.enumerateExports().filter(...)` throws TypeError | Returns array, not function — Frida 17.x API change | Use `module.findExportByName(name)` or `Module.findExportByName(moduleName, name)` |
| `RootBeer` Java class ClassNotFoundException | Flutter apps load RootBeer via separate classloader | Use `Java.enumerateClassLoaders()` + `Java.ClassFactory.get(loader).use(...)` |
| Certificate chain validation timeout | OCSP stapling mismatch | Disable OCSP checks or mock OCSP responder |
| Hooks load silently but don't intercept | Frida client/server version mismatch | Match versions — see §0.2 (pip install frida==<server_ver>) |
| `frida-ps -U` hangs then times out | frida-server not running on device | `adb shell "su -c '/data/local/tmp/frida-server &'"` |
| `cryptography` version conflict after pip install | androguard/apkid upgrades cryptography beyond mitmproxy limit | Pin: `pip install cryptography==46.0.7 && pip install mitmproxy` |
| `Java` undefined in Frida script | Flutter apps: Java VM not initialized at spawn time | Use `typeof Java === 'undefined'` check + retry loop with `setTimeout` (see §4.1 pitfall) |
| `TypeError: not a function` in Frida 17.x | `Module.findExportByName(moduleName, name)` deprecated; use `module.findExportByName(name)` | Use `libssl.findExportByName('SSL_write')` not `Module.findExportByName('libssl.so', 'SSL_write')` |
| reflutter patched APK crashes on launch | Native crash in `FlutterJNI.attachToNative` — reflutter corrupts libflutter.so | Fall back to mitmproxy reverse proxy + iptables REDIRECT approach (§4.1, §8) |
| Burp receives TLS but can't decrypt Flutter traffic | Burp lacks transparent proxy support for raw TLS connections | Use `mitmdump --mode reverse:https://target-server` instead of Burp |
| mitmproxy `--mode transparent` fails on Windows | Requires WinDivert admin access; `PermissionError: [WinError 5]` | Use `--mode reverse:https://target-server` (no admin needed) |
| libflutter.so has 0 SSL symbols | BoringSSL symbols stripped from libflutter.so | Hook system `libssl.so` instead — modern Flutter uses system SSL library |
| `ssl_pin_rejected` in logcat despite BoringSSL hooks | App has Dart-layer SPKI pinning in libapp.so (not just BoringSSL) | Runtime memory patch: find pin hash in libapp.so and overwrite with proxy's SPKI (§4.1.1). Use v2 script (templates/flutter-spki-memory-patch.js) — NO Java hooks, page-specific Memory.protect only |
| `ssl_pin_rejected: presentedPin=XXXX allowedPins=3` | App has MULTIPLE SPKI pins — you only patched one | Patch ALL pins found in libapp.so to the proxy's SPKI. `allowedPins=N` tells you exactly how many pins to patch. Search: `strings libapp.so \| grep -E "^[A-Za-z0-9+/]{43}=$"` and patch each one |
| `SIGSEGV in datadog-context` after memory patch | `Memory.protect(libapp.base, libapp.size, 'rwx')` corrupted Dart AOT JIT code pages | Use page-specific protection: `var page_base = address.and(ptr(pageSize-1).not()); Memory.protect(page_base, 4096, 'rwx')` |
| `SIGBUS in datadog-context` or `EmojiCompatInit` after Java hooks | `Java.perform()` causes race conditions in Flutter apps with RaspGuard | Remove ALL Java hooks. Use ONLY BoringSSL native hooks + memory patch (see v2 template) |
| `SIGBUS` after patching pins at addresses outside libapp.so | All-memory scan (`Process.enumerateRanges`) found heap copies of the pin string | Do NOT scan all memory regions. Only scan within `libapp.so` address range |
| `Memory.scanSync` throws `access violation accessing 0x...` | Some libapp.so pages are guarded | Wrap in try/catch, fall back to page-by-page scanning. Do NOT call `Memory.protect` on entire libapp.so — only protect the specific 4KB page before writing |
| `SIGSEGV in datadog-context` after memory patch | `Memory.protect(libapp.base, libapp.size, 'rwx')` corrupted Dart AOT JIT code pages | Use page-specific protection: `var page_base = address.and(ptr(pageSize-1).not()); Memory.protect(page_base, 4096, 'rwx')` |
| `SIGBUS in datadog-context` or `EmojiCompatInit` | Java hooks (`TrustManagerImpl`, `SSLContext.init`) cause race conditions in Flutter apps with RaspGuard | Remove ALL Java hooks. Use ONLY BoringSSL native hooks + memory patch |
| `SIGBUS` after patching pins at addresses outside libapp.so | All-memory scan (`Process.enumerateRanges`) found heap copies of the pin string | Do NOT scan all memory regions. Only scan within `libapp.so` address range |
| APK repack with patched libapp.so crashes on launch | Dart VM integrity check detects modified snapshot | Use Frida runtime memory patch instead (§4.1.1) — no file modification |
| Frida CLI `frida -U -f` hangs with `head` pipe | Frida CLI + pipe buffering issue on Windows/MSYS | Use `timeout 90 frida -U -f com.app -l script.js > output.txt &` instead of piping to `head` |
| Python `import frida` fails in hermes venv | Frida installed in system Python, not venv | Use full path: `C:\Users\Admin\AppData\Local\Programs\Python\Python312\python.exe` |
| Frida "Connection terminated" but app still running | Frida CLI process exited (timeout/pipe) but app continues with hooks+patches active | Memory patches persist in process RAM after Frida disconnects. Verify with `adb shell ps -A \| grep <package>`. Re-attach with `frida -U -n <package>` if needed |
| `timeout 60 frida -U -f` kills app when timeout expires | `timeout` sends SIGTERM to frida which kills spawned app | Use `frida -U -f ... &` (background, no timeout) or spawn app separately via `adb shell am start` then attach with `frida -U -n` |
| frida-server dies after heavy script | frida-server crash from memory access or hook conflicts | Restart: `adb shell "su -c 'killall frida-server 2>/dev/null; sleep 1; setsid /data/local/tmp/frida-server >/dev/null 2>&1 &'"`. Verify: `frida-ps -U \| head -3` |
| "Failed to spawn: need Gadget to attach on jailed Android" | frida-server not running | Start frida-server, verify with `frida-ps -U` |
| BoringSSL hooks + pin patch work but Burp shows no HTTP History | Burp "Support invisible proxying" not enabled, or iptables/adb reverse not set up | Enable Proxy > Options > Listener > Request handling > Support invisible proxying. Verify: `adb shell "su -c 'iptables -t nat -L OUTPUT -n'"` and `adb reverse --list` |
| React Native app: SSL pinning via `com.sslpublickeypinning` module | Pins loaded dynamically from JS bundle at runtime, not hardcoded in smali | Patch `initializeCertificatePinner` smali to `return-void` (no pins set). See `references/react-native-ssl-pinning.md` |
| React Native app: `VerifyError: register index out of range` after smali patch | `initializeCertificatePinner` patched with `.locals 0` + `return-void` but original method body left after `return-void` as unreachable code | Replace the ENTIRE method body from `.method` to `.end method` — do NOT just insert `return-void` at the top. The unreachable code has register refs exceeding `.locals 0`. See `references/react-native-ssl-pinning.md` PITFALL section |
| React Native app: `intercept()` method still throws `SSLPeerUnverifiedException` | `SslPublicKeyPinningModule.intercept()` catches and re-throws `SSLPeerUnverifiedException`. But with `certificatePinner=null` (from patched `initializeCertificatePinner`), `lambda$initializeCustomClientBuilder$0` skips both `.certificatePinner()` and `.addInterceptor()` — interceptor never registered | No action needed. The `intercept()` method is never called because the interceptor is never added to OkHttp builder. Patch is correct as-is |
| React Native app stuck on loading spinner after SSL patch | Device WiFi disconnected (`wlan0: NO-CARRIER`). App loads JS bundle but makes zero API calls. Original unpatched app also hangs. | Check `adb shell "ip addr show wlan0"` for NO-CARRIER. Verify `ping google.com` from device. Test original APK without proxy — if it also hangs, it's network not SSL. See references/react-native-ssl-pinning.md "App Stuck on Loading" section |
| React Native app: ReactNativeBlobUtil secondary SSL path | `com.ReactNativeBlobUtil.m.c()` creates custom SSLContext with TrustManager from static field `m.a`. Called when config flag `b.f=true`. | Usually inactive (`m.a` never set, `b.f=false`). Check: `grep -rn "ReactNativeBlobUtil/m;->a:" smali/` for `sput-object`. If inactive, patching `initializeCertificatePinner` is sufficient. If active, also patch `m.c()` or Frida-hook `SSLContext.init` |
| React Native app stuck on loading after `pm clear` | App caches config in MMKV/AsyncStorage. After `pm clear`, config endpoints return 401/404, JS error handler can't dismiss loading screen | Do NOT `pm clear`. Use `adb install -r` to preserve cached data. SSL patch only affects smali, not app data. See references/react-native-ssl-pinning.md |
| React Native app: `intercept()` still throws `SSLPeerUnverifiedException` | Not an issue — `intercept()` is never called because `certificatePinner=null` means `lambda$initializeCustomClientBuilder$0` skips `.addInterceptor()` | No action needed. Patch is correct as-is |
| React Native app: "No Internet Connection" (status 455) after proxy toggle | `settings put global http_proxy :0` sets proxy to port 0, OkHttp fails silently. `global_http_proxy_host` persists old value after `settings delete global http_proxy` | Delete ALL three: `settings delete global http_proxy` + `settings delete global global_http_proxy_host` + `settings delete global global_http_proxy_port`, then set new proxy, then `am force-stop` + relaunch. See "Do NOT toggle proxy settings" pitfall in references/react-native-ssl-pinning.md |
| React Native app: SYN_SENT to wrong IP:port after proxy change | OkHttp caches proxy at client creation time; `global_http_proxy_host` persists old value | `am force-stop` + relaunch. Check `/proc/PID/net/tcp6` for SYN_SENT to port 1F90 (8080). Decode hex IP (little-endian). See "Do NOT toggle proxy settings" pitfall |
| React Native app stuck on loading, logcat shows `status: 455` and "No Internet Connection" | App's connectivity check (`clients3.google.com/generate_204`) timed out (30s). OkHttp cached stale proxy setting. NOT an SSL issue | Force-stop app after proxy changes: `adb shell am force-stop com.target.app`. Clear proxy fully: `settings delete global http_proxy` + `settings put global http_proxy :0`. See references/react-native-ssl-pinning.md "connectivity check" pitfall |
| React Native app: SYN_SENT to old proxy IP:port after proxy cleared | OkHttp reads system proxy at client creation time; runtime proxy changes not picked up | `adb shell am force-stop com.target.app` then relaunch. Check `/proc/PID/net/tcp6` for SYN_SENT to port 1F90 (8080) |
| React Native app: custom RASP (not Talsec) blocks app with "Thiết bị không đáp ứng yêu cầu bảo mật" | App has custom Java RASP class (e.g., `ga.c`) checking root/frida/magisk/shamiko/zygisk/xposed/debugger/emulator. `MainApplication.onCreate()` calls `masterCheck()` → if true, `MainActivity` shows block screen instead of React UI | Frida hook RASP class `masterCheck()` → return false. Also hook all sub-checks. Hook `SecurityModule.securityCheck()` → return all-false WritableMap. See `references/react-native-ssl-pinning.md` "Custom RASP Detection" section |
| React Native app: Frida hooks loaded but app still spinning on loading | Frida script missing Conscrypt `TrustManagerImpl.checkTrustedRecursive()` + standard `okhttp3.CertificatePinner` + `OkHostnameVerifier`. Only hooks app-level pinning (SslPublicKeyPinningModule, db.g) but not system TLS layer → all HTTPS hangs silently | Add Conscrypt hook (`checkTrustedRecursive` → empty ArrayList) + standard OkHttp CertificatePinner.check() + OkHostnameVerifier.verify() → return true. See `references/react-native-ssl-pinning.md` "Complete Hook Checklist" (7 layers) |
| React Native app: RASP block screen shows despite Frida hooks installed | `MainApplication.onCreate()` calls RASP `masterCheck()` BEFORE `Java.perform()` hooks attach (race condition at spawn) | Hook `android.app.Application.onCreate` to install RASP hooks BEFORE calling `this.onCreate()`. See `references/react-native-ssl-pinning.md` "RASP check in MainApplication.onCreate" pitfall |
| Frida 17 Python wrapper: `ReferenceError: 'Java' is not defined` | Frida 17 (#3473, #3495) — Java bridge not injected in global scope via Python API | Use `frida` CLI instead of Python wrapper: `frida -U -f com.app -l bypass.js`. Or add retry loop checking `typeof Java !== 'undefined'` before `Java.perform()` |
| Frida 17 CLI: `--no-pause` flag not recognized | Flag removed in Frida 17.x | Omit `--no-pause` — Frida 17 auto-resumes by default |
| Objection: `NoConsoleScreenBufferError` on Windows MSYS/git-bash | `prompt_toolkit` requires native Windows console, not MSYS terminal | Run from `cmd.exe` or PowerShell. Or use frida CLI directly instead of objection |
| APK with corrupted zip header — `unzip`/`jar` fail to extract DEX | APK Signature Scheme v4 extra bytes break standard zip parsers on MSYS/Windows | Use Python `zipfile.ZipFile(apk, 'r').extract(...)` — handles the extra bytes correctly. Then `jadx -d out/ classes.dex classes2.dex` |
| OkHttp classes obfuscated in decompiled APK | R8/ProGuard renames `okhttp3.CertificatePinner` to e.g. `db.g` (method `check` → `a`) | Find obfuscated name by searching jadx output for `SSLPeerUnverifiedException`/`sha256/` references. Use `Java.use('db.g')` in Frida (use obfuscated name, not JADX rename). Enumerate classloaders if not found via default loader |
| "Connection refused" after iptables REDIRECT | Proxy on PC, not device — REDIRECT targets device localhost | Add `adb reverse tcp:PORT tcp:PORT` to bridge device localhost to PC localhost |
| App hangs on splash with `iptables REDIRECT --to-port` (all 443) | Firebase/Datadog/GMS traffic also redirected, their TLS fails (proxy CA not trusted by Java SDKs) | Use `iptables DNAT -d <API_SERVER_IP> --dport 443` targeting ONLY the API server, leaving other HTTPS untouched |
| App reaches FaceLogin but API call times out (DioError: connectionTimeout) | Server blocks device IP (TCP SYN_SENT, 100% packet loss on ping) but allows PC IP | Use ADB reverse + DNAT to localhost: `adb reverse tcp:8443 tcp:8443` + `iptables -t nat -A OUTPUT -p tcp -d <SERVER_IP> --dport 443 -j DNAT --to-destination 127.0.0.1:8443` + `mitmdump --mode reverse:https://api.target.com:443 --listen-port 8443`. PC connects to server, device connects to PC via ADB USB tunnel. See Approach C in references/flutter-traffic-interception.md |
| Device can't TCP connect to PC (Windows Firewall blocks inbound) | `nc <PC_IP> <PORT>` from device times out, but `ping <PC_IP>` works (ICMP allowed, TCP blocked) | Use `adb reverse tcp:PORT tcp:PORT` to tunnel through USB — bypasses Windows Firewall entirely. DNAT to `127.0.0.1:PORT` (not to PC IP) |
| mitmproxy returns 502 Bad Gateway (`[WinError 121] semaphore timeout`) | mitmproxy transparent mode failed (WinDivert) or couldn't connect upstream | Use regular proxy mode (`mitmdump --listen-port 8888`) + DNAT (not REDIRECT). Check mitmproxy logs for upstream connection errors |
| `ssl_pin_rejected: presentedPin=XXXX allowedPins=N` | App has N SPKI pins; you only patched 1 | Patch ALL N pins to proxy SPKI. Use `strings libapp.so \| grep -E "^[A-Za-z0-9+/]{43}=$"` to find all pins |
| RaspGuard logs "app_integrity" or "privileged_access" | APK repack + rooted device | Talsec FreeRASP detection. In older versions: detection-only (logs to Datadog, does NOT block). In v1.1.31+ enforcement mode: BLOCKS app with "Unable to open application" screen. If blocked, see `references/raspguard-bypass.md` for smali + libapp.so string patch technique |
| App shows blocking screen after SSL bypass ("Unable to open application" / "Please close suspicious software") | RaspGuard (Talsec FreeRASP) in enforcement mode — Dart code independently detects root and blocks | Patch ALL THREE layers: (1) smali — return empty ArrayList from scan MethodChannel (`sunsite/dev_integrity`), (2) libapp.so — same-length string replacement of `privileged_access (root/jailbreak)` → `xxxx...` and `rasp_threat: ` → `xxxx...`, (3) smali — remove `Ln2/g;->a()` call in Talsec `start` method (`talsec.app/freerasp/methods` channel, handler in `n2/d.smali`). Do NOT patch package name strings (causes SIGSEGV). See `references/raspguard-bypass.md` |
| Talsec freeRASP KILLS frida-server (not just detects) | `libts.so` contains `scan_for_frida_server_all_ports` that scans ports and terminates frida-server process. Frida attaches, prints hooks, then "Connection terminated" — `ps -A \| grep frida` shows server dead | APK-patch Talsec out of smali BEFORE running Frida: (1) NOP freerasp plugin registration in `GeneratedPluginRegistrant.smali`, (2) NOP `W4/A4.a()` Talsec.start(), (3) comment out `System.loadLibrary("ts")` in `BNatives.smali`, (4) neutralize `RootBeerNative.checkForRoot()`, (5) skip `isRootChecker` branch in `N3/a.smali`. See `references/talsec-freerasp-apk-patching.md` |
| `Error: access violation accessing 0x...` in Frida when hooking libts.so | `Memory.scanSync(libts.base, libts.size, ...)` hits guarded memory pages in libts.so | Do NOT use Memory.scanSync on libts.so. Only use `Interceptor.attach` on exported functions. Use `strings` on the .so file on disk to find strings before injecting |
| Frida spawn `-f` fails: `unable to locate android.os.Process.setArgV0()` | Android 15 compatibility issue in Frida 17.x spawn mechanism | Start app separately via `adb shell am start -n com.app/.MainActivity`, then attach by PID: `frida -U -p $(adb shell pidof com.app) -l bypass.js` |
| frida-server SIGSEGV in gdbus thread on Android 15 | frida-server 17.9.x crashes on Samsung S25 / Android 15 due to gdbus/libsoup bug — affects BOTH 17.9.6 and 17.9.11, `--policy-softener=internal --ignore-crashes` does NOT help | Use binary patch approach (patch SPKI in libapp.so, no Frida needed). See `references/flutter-binary-patch-no-frida.md` |
| Frida spawn `-f` fails: `unable to locate android.os.Process.setArgV0()` | Android 15 compatibility issue in Frida 17.9.x | Start app separately via `adb shell am start -n com.app/.MainActivity`, then attach by PID: `frida -U -p $(adb shell pidof com.app) -l bypass.js`. NOTE: even attach may crash frida-server with SIGSEGV on Samsung S25 — use binary patch instead |
| Frida disconnects after 45-120s but app still works | Frida CLI/server crash, but hooks persist in memory | BoringSSL `Interceptor.replace` hooks persist after Frida disconnects. Verify app is alive: `adb shell pidof com.app`. No need to re-attach unless installing new hooks |
| Binary-patched APK crashes (SIGSEGV) after SPKI replacement | SPKI hash length mismatch (43 vs 44 bytes) | Verify `len(new_pin) == 44`. A leading `/` or `+` may be lost during copy. Always use Python `assert len(old) == len(new) == 44` |
| reflutter patched APK crashes on launch (SIGSEGV) | reflutter corrupts libflutter.so snapshot | Use binary patch of libapp.so instead (only modifies 44-byte SPKI string). See `references/flutter-binary-patch-no-frida.md` |

### 6.2 Diagnostic Steps

```bash
# Verify proxy CA is installed correctly
# Android:
adb shell "ls /system/etc/security/cacerts/ | grep $(openssl x509 -subject_hash_old -in ca.pem | head -1)"

# iOS: Settings → General → About → Certificate Trust Settings

# Check if target app is actually using SSL (vs. plain HTTP)
# Wireshark filter: tcp.port == 443 and ip.addr == <device_ip>

# Check if Frida is hooking the right process
frida-ps -U | grep target

# Verbose Frida output for debugging hooks
frida -U -f com.target.app -l bypass.js --debug
```

---

## 7. SSL PINNING BYPASS DECISION TREE

```
Need to intercept mobile app HTTPS traffic
│
├── Platform?
│   ├── Android ↓
│   │   ├── Rooted device available?
│   │   │   ├── Yes → Frida universal bypass (§2.1) [FIRST TRY]
│   │   │   │   ├── Works? → done
│   │   │   │   └── Fails? → add Conscrypt + Volley hooks
│   │   │   ├── Still fails? → LSPosed + TrustMeAlready (§2.4)
│   │   │   └── Still fails? → install CA as system cert (§2.5)
│   │   └── No root?
│   │       ├── Debug build? → Network Security Config (§2.3)
│   │       └── Release build? → decompile + patch + repackage (§2.6)
│   │
│   └── iOS ↓
│       ├── Jailbroken device available?
│       │   ├── Yes → Objection ios sslpinning disable (§3.2) [FIRST TRY]
│       │   │   ├── Works? → done
│       │   │   └── Fails? → Frida SecTrust hooks (§3.1)
│       │   ├── Still fails? → SSL Kill Switch 2 (§3.3)
│       │   └── Still fails? → library-specific hooks (§3.4)
│       └── No jailbreak?
│           ├── Re-sign with Frida gadget → run Frida hooks
│           └── Binary patch → sideload (§3.5)
│
├── Framework-specific app?
│   ├── Flutter → native BoringSSL hooks on libssl.so (§4.1) [FIRST TRY if Frida available]
│   │   ├── Frida crashes/unavailable? → binary patch libapp.so (NO Frida needed, see references/flutter-binary-patch-no-frida.md)
│   │   │   ├── Need app to function only? → patch with server's real SPKI (RECOMMENDED, no proxy needed)
│   │   │   ├── Need traffic interception? → patch with proxy SPKI + iptables REDIRECT + adb reverse
│   │   │   └── APK repack crashes? → use Frida runtime memory patch instead (§4.1.1)
│   │   ├── SSL hooks work? → also hook Java SSL for native plugins
│   │   ├── Need full traffic capture? → Burp + iptables REDIRECT + adb reverse (§4.1, §8) [SIMPLEST — verified working with BoringSSL hooks + pin patch]
│   │   ├── Burp not capturing? → ensure "Support invisible proxying" enabled + iptables rules active + adb reverse set
│   │   ├── Need mitmproxy instead? → mitmproxy reverse proxy + iptables REDIRECT + adb reverse (§4.1, §8)
│   │   ├── Server blocks device IP but allows PC IP? → ADB reverse + DNAT to localhost + mitmproxy reverse (Approach C in references/flutter-traffic-interception.md) — NO Frida needed, binary patch only
│   │   ├── reflutter crashes app? → fall back to Burp/mitmproxy + iptables approach
│   │   ├── `ssl_pin_rejected` in logcat? → app has Dart-layer SPKI pinning → runtime memory patch (§4.1.1)
│   │   └── APK repack crashes? → use Frida runtime memory patch instead (§4.1.1)
│   ├── React Native → patch `initializeCertificatePinner` smali (§4.2, references/react-native-ssl-pinning.md) [FIRST TRY — no root needed]
│   │   ├── Need runtime bypass? → Frida hook `getCertificatePinner()` + `okhttp3.CertificatePinner.check()` (§4.2)
│   │   ├── OkHttp classes obfuscated? → find actual class names in smali (e.g., `cb/g` = CertificatePinner)
│   │   ├── System proxy works (no iptables/adb reverse needed — OkHttp respects Android proxy settings)
│   │   └── Also check Hermes JS bundle for API URLs, auth endpoints, SSL config: `strings -n 8 assets/index.android.bundle`
│   └── Xamarin → Objection or Mono runtime hooks (§4.3)
│
├── Bypass works but issues remain?
│   ├── Client cert required? → extract + import to proxy (§6.1)
│   ├── Non-HTTP protocol? → protocol-specific tooling (§6.1)
│   └── App crashes? → fix anti-tampering first (§6.1)
│
└── All methods fail?
    ├── Analyze traffic at network level (Wireshark/tcpdump)
    ├── Check for custom proprietary protocol
    └── Consider iptables + transparent proxy approach
```

---

## 8. PROXY SETUP QUICK REFERENCE

| Proxy Tool | Best For | SSL Bypass Integration |
|---|---|---|
| Burp Suite | Full HTTP analysis | Import CA to device |
| mitmproxy | Scripted interception | `mitmproxy --set confdir=~/.mitmproxy` |
| Charles Proxy | macOS-native, easy setup | Built-in CA installation |
| Proxyman | macOS/iOS native | Direct iOS device support |
| HTTP Toolkit | Quick Android setup | Automated CA + Frida bypass |

```bash
# Android proxy setup
adb shell settings put global http_proxy <host_ip>:8080

# Remove proxy
adb shell settings put global http_proxy :0

# iOS proxy: Settings → Wi-Fi → Configure Proxy → Manual

# CRITICAL: Flutter apps do NOT respect Android system proxy settings!
# dart:io HttpClient ignores http_proxy. For Flutter traffic capture:
#
#   1. mitmproxy reverse proxy + iptables REDIRECT + adb reverse (BEST, see §4.1):
#      mitmdump --mode reverse:https://api.target.com --listen-port 8082 --set ssl_insecure=true
#      adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082'"
#      adb reverse tcp:8082 tcp:8082
#      # Also install mitmproxy CA cert as system cert (see §2.5)
#      # Also run Frida SSL bypass (TrustManagerImpl + SSLContext.init hooks)
#
#   2. reflutter (patches BoringSSL in libflutter.so — CAUTION: may crash app)
#
#   3. VPN-based proxy (HTTP Toolkit, ProxyDroid — routes all traffic via VPN)
#
#   4. Frida SSL_write hook (captures traffic in console — no proxy, no GUI)
#
#   5. adb reverse (works for native Android HTTP clients, NOT for Flutter)
#      adb reverse tcp:8080 tcp:8080  # host:8080 accessible as device:8080
#
#   NOTE: Burp Suite CAN intercept Flutter traffic when BoringSSL hooks are active.
#   With SSL_CTX_set_custom_verify mode=0 + SPKI pin patch, Burp receives and
#   decrypts Flutter HTTPS via iptables REDIRECT. Enable "Support invisible
#   proxying" in Proxy > Options > Listener > Request handling.
#   This is the SIMPLEST setup — verified working on Android 15 / Flutter Dio.
#
#   NOTE: mitmproxy --mode transparent does NOT work on Windows (needs WinDivert admin).
#   Use --mode reverse:https://target-server instead.
```
