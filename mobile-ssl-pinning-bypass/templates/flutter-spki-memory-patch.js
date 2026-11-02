// Flutter Dart-Layer SPKI Pinning Bypass — Frida Script (v2)
// For: Flutter apps with ssl_pins_sha256 in libapp.so (Dart AOT snapshot)
// Tested on: Android 15, Flutter v1.1.31+1, Frida 17.9.6, Burp Suite proxy
//
// This script handles the case where standard BoringSSL hooks are NOT sufficient
// because the app implements SPKI pinning in compiled Dart code (libapp.so).
//
// Layers:
//   1. BoringSSL hooks: SSL_CTX_set_custom_verify, SSL_set_verify, SSL_get_verify_result, X509_verify_cert
//   2. Runtime memory patch: replace SPKI pin hash in libapp.so (page-specific Memory.protect)
//
// CRITICAL LESSONS (learned from crashes):
//   - NO Java hooks (TrustManagerImpl, SSLContext.init) — causes SIGBUS in datadog/EmojiCompat threads
//   - NO Memory.protect on entire libapp.so — corrupts Dart AOT JIT pages → SIGSEGV
//   - NO all-memory scan (Process.enumerateRanges) — patches heap copies → SIGBUS
//   - Page-specific Memory.protect ONLY on the 4KB page containing the pin hash
//   - Memory.scanSync CAN scan r-- pages without Memory.protect (only need protect before write)
//
// PREREQUISITES:
//   - Proxy CA cert installed in system + Conscrypt stores (see SKILL.md §2.5)
//   - iptables REDIRECT + adb reverse set up (see references/flutter-traffic-interception.md)
//   - Frida server running on device: adb shell "su -c '/data/local/tmp/frida-server &'"
//
// USAGE:
//   1. Find the app's SPKI pin hash:
//      unzip base.apk lib/arm64-v8a/libapp.so -d /tmp/apk
//      strings -n 20 /tmp/apk/lib/arm64-v8a/libapp.so | grep -E "^[A-Za-z0-9+/]{43}=$"
//      # Or: grep -boa "wHtGLKEK..." /tmp/apk/lib/arm64-v8a/libapp.so
//
//   2. Compute your proxy's SPKI hash:
//      adb shell "su -c 'cat /system/etc/security/cacerts/9a5ba575.0'" | \
//        openssl x509 -noout -pubkey | openssl pkey -pubin -outform der | \
//        openssl dgst -sha256 -binary | openssl base64
//
//   3. Update ORIGINAL_PIN and PROXY_PIN below
//
//   4. Run:
//      frida -U -f com.target.app -l flutter-spki-memory-patch.js

// === CONFIGURATION — UPDATE THESE FOR YOUR TARGET ===
var ORIGINAL_PIN = "wHtGLKEKg4yRppRu7VKwzIQX+xLK6W0GCvthp2Rh/lI=";  // App's SPKI pin (from libapp.so)
var PROXY_PIN    = "jSZoyIt4q830Y8O7NhrBrLeNeWNTvHT6F9DsUFZDLDQ=";  // Your proxy's SPKI hash
// =====================================================

var TAG = "[BYPASS]";
function log(msg) { console.log(TAG + " " + msg); }
function bypass(msg) { console.log(TAG + " [+] BYPASS: " + msg); }

function findExport(mod, name) {
    try { if (mod && typeof mod.findExportByName === 'function') return mod.findExportByName(name); } catch(e) {}
    return null;
}

// === 1. BoringSSL hooks (system libssl.so) ===
function hookBoringSSL() {
    try {
        var libssl = Process.findModuleByName("libssl.so");
        if (!libssl) { log("libssl.so not found, retrying..."); setTimeout(hookBoringSSL, 1000); return; }
        log("libssl.so base=" + libssl.base + " size=0x" + libssl.size.toString(16));

        // SSL_CTX_set_custom_verify → mode=0 (SSL_VERIFY_NONE)
        var ssl_ctx_set_custom_verify = findExport(libssl, 'SSL_CTX_set_custom_verify');
        if (ssl_ctx_set_custom_verify) {
            Interceptor.replace(ssl_ctx_set_custom_verify, new NativeCallback(function(ctx, mode, cb) {}, 'void', ['pointer', 'int', 'pointer']));
            log("SSL_CTX_set_custom_verify hooked -> mode=0");
        }

        // SSL_CTX_set_verify → mode=0
        var ssl_ctx_set_verify = findExport(libssl, 'SSL_CTX_set_verify');
        if (ssl_ctx_set_verify) {
            Interceptor.replace(ssl_ctx_set_verify, new NativeCallback(function(ctx, mode, cb) {}, 'void', ['pointer', 'int', 'pointer']));
            log("SSL_CTX_set_verify hooked -> mode=0");
        }

        // SSL_set_verify → mode=0
        var ssl_set_verify = findExport(libssl, 'SSL_set_verify');
        if (ssl_set_verify) {
            Interceptor.replace(ssl_set_verify, new NativeCallback(function(ssl, mode, cb) {}, 'void', ['pointer', 'int', 'pointer']));
            log("SSL_set_verify hooked -> mode=0");
        }

        // SSL_get_verify_result → return 0 (X509_V_OK)
        var ssl_get_verify_result = findExport(libssl, 'SSL_get_verify_result');
        if (ssl_get_verify_result) {
            Interceptor.replace(ssl_get_verify_result, new NativeCallback(function(ssl) { return 0; }, 'long', ['pointer']));
            log("SSL_get_verify_result replaced -> 0");
        }

        // SSL_CTX_set_cert_verify_callback → noop
        var ssl_ctx_set_cert_verify_cb = findExport(libssl, 'SSL_CTX_set_cert_verify_callback');
        if (ssl_ctx_set_cert_verify_cb) {
            Interceptor.replace(ssl_ctx_set_cert_verify_cb, new NativeCallback(function(ctx, cb, arg) {}, 'void', ['pointer', 'pointer', 'pointer']));
            log("SSL_CTX_set_cert_verify_callback hooked");
        }

        // X509_verify_cert → return 1 (success)
        var x509_verify_cert = findExport(libssl, 'X509_verify_cert');
        if (!x509_verify_cert) x509_verify_cert = findExport(Process.findModuleByName("libcrypto.so"), 'X509_verify_cert');
        if (x509_verify_cert) {
            Interceptor.replace(x509_verify_cert, new NativeCallback(function(ctx) { return 1; }, 'int', ['pointer']));
            log("X509_verify_cert replaced -> 1");
        }

        // SSL_write traffic monitoring
        var ssl_write = findExport(libssl, 'SSL_write');
        if (ssl_write) {
            Interceptor.attach(ssl_write, {
                onEnter: function(args) {
                    try {
                        var len = args[2].toInt32();
                        if (len > 0 && len < 4096) {
                            var data = args[1].readUtf8String(len);
                            if (data && (data.indexOf("POST") === 0 || data.indexOf("GET") === 0)) {
                                log("SSL_WRITE: " + data.substring(0, 200));
                            }
                        }
                    } catch(e) {}
                }
            });
            log("SSL_write hooked @ " + ssl_write);
        }

        // SSL_read
        var ssl_read = findExport(libssl, 'SSL_read');
        if (ssl_read) {
            Interceptor.attach(ssl_read, { onLeave: function(rv) {} });
            log("SSL_read hooked @ " + ssl_read);
        }

        bypass("BoringSSL hooks installed");
    } catch(e) {
        log("hookBoringSSL error: " + e);
    }
}

// === 2. Memory patch: Replace SPKI pin hash in libapp.so ===
function patchPinHash() {
    try {
        var libapp = Process.findModuleByName("libapp.so");
        if (!libapp) { log("libapp.so not found yet, will retry..."); return false; }
        log("libapp.so base=" + libapp.base + " size=0x" + libapp.size.toString(16));

        // Convert pin string to hex pattern
        var pin_pattern = "";
        for (var i = 0; i < ORIGINAL_PIN.length; i++) {
            pin_pattern += ('0' + ORIGINAL_PIN.charCodeAt(i).toString(16)).slice(-2) + " ";
        }
        pin_pattern = pin_pattern.trim();

        // Scan libapp.so for the pin hash
        // NOTE: Memory.scanSync CAN scan r-- pages. If full scan throws access violation
        // on guarded pages, fall back to page-by-page scanning.
        log("Scanning libapp.so for pin hash...");
        var matches = [];
        try {
            matches = Memory.scanSync(libapp.base, libapp.size, pin_pattern);
        } catch(e) {
            log("Full scan failed (" + e + "), trying page-by-page...");
            var page_size = Process.pageSize;
            var offset = 0;
            while (offset < libapp.size) {
                var chunk_size = Math.min(page_size * 64, libapp.size - offset);
                var chunk_base = libapp.base.add(offset);
                try {
                    var chunk_matches = Memory.scanSync(chunk_base, chunk_size, pin_pattern);
                    matches = matches.concat(chunk_matches);
                } catch(e2) {}
                offset += chunk_size;
            }
        }
        log("Found " + matches.length + " match(es) for original pin");

        var patched = 0;
        for (var i = 0; i < matches.length; i++) {
            try {
                // CRITICAL: Protect ONLY the 4KB page containing the pin, NOT entire libapp.so.
                // Memory.protect(libapp.base, libapp.size, 'rwx') corrupts Dart AOT JIT pages → SIGSEGV.
                var page_size = Process.pageSize;
                var page_base = matches[i].address.and(ptr(page_size - 1).not());
                Memory.protect(page_base, page_size, 'rwx');
                matches[i].address.writeUtf8String(PROXY_PIN);
                log("Patched pin at " + matches[i].address + " -> " + PROXY_PIN);
                patched++;
            } catch(e) {
                log("Failed to patch at " + matches[i].address + ": " + e);
            }
        }

        if (patched > 0) {
            bypass("Patched SPKI pin hash in libapp.so (" + patched + " locations)");
            return true;
        }
        log("No pins found in libapp.so");
        return false;
    } catch(e) {
        log("patchPinHash error: " + e);
        return false;
    }
}

// === MAIN ===
log("Flutter SPKI Memory Patch bypass loaded (v2 — no Java hooks, page-specific protect)");
log("Original pin: " + ORIGINAL_PIN);
log("Proxy pin:    " + PROXY_PIN);

// Run BoringSSL hooks and pin patch immediately (libssl.so and libapp.so load at spawn time)
hookBoringSSL();
patchPinHash();

// Retry pin patch if libapp.so not loaded yet
var retries = 0;
var interval = setInterval(function() {
    retries++;
    if (retries > 10) { clearInterval(interval); return; }
    patchPinHash();
}, 1000);

log("All hooks scheduled.");
