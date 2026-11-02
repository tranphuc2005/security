// Flutter SSL Pinning Bypass — Frida Script (tested on Android 15, Flutter Dio, Frida 17.9.x)
//
// Hooks BOTH system libssl.so (native SSL) AND Java SSL layers.
// Also attempts to hook BoringSSL inside libflutter.so (if symbols are not stripped).
// Includes root detection bypass (RootBeer) and traffic monitoring.
//
// Usage:
//   frida -U -f com.target.app -l flutter-ssl-bypass.js
//
// For full traffic interception, combine with:
//   mitmdump --mode reverse:https://api.target.com --listen-port 8082 --set ssl_insecure=true
//   adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082'"
//   adb reverse tcp:8082 tcp:8082
//   (Also install mitmproxy CA cert as system cert — see SKILL.md §2.5)

var bypass_count = 0;

function bypass(msg) { bypass_count++; console.log('[+] BYPASS #' + bypass_count + ': ' + msg); }
function log(msg) { console.log('[*] ' + msg); }

function findExport(mod, name) {
    try {
        if (mod && typeof mod.findExportByName === 'function') return mod.findExportByName(name);
    } catch(e) {}
    return null;
}

// === 1. NATIVE SSL BYPASS (system libssl.so — works at spawn time) ===
setTimeout(function() {
    log('Native SSL hooks loading...');

    var libssl = Process.findModuleByName('libssl.so');
    var libcrypto = Process.findModuleByName('libcrypto.so');

    if (libssl) log('libssl.so @ ' + libssl.base + ' size=' + libssl.size);
    else { log('libssl.so NOT FOUND'); return; }
    if (libcrypto) log('libcrypto.so @ ' + libcrypto.base);

    var hooks = [
        {n: 'SSL_CTX_set_custom_verify', t: 'set_verify'},
        {n: 'SSL_CTX_set_verify', t: 'set_verify'},
        {n: 'SSL_set_verify', t: 'set_verify'},
        {n: 'SSL_get_verify_result', t: 'ret0'},
        {n: 'ssl_verify_peer_cert', t: 'ret1'},
        {n: 'SSL_CTX_set_cert_verify_callback', t: 'log'}
    ];

    hooks.forEach(function(h) {
        var addr = findExport(libssl, h.n);
        if (addr) {
            if (h.t === 'set_verify') {
                Interceptor.attach(addr, {
                    onEnter: function(args) { args[1] = ptr(0); bypass(h.n + ' mode->0'); }
                });
            } else if (h.t === 'ret0') {
                Interceptor.attach(addr, {
                    onLeave: function(rv) { var o = rv.toInt32(); rv.replace(0); if (o !== 0) bypass(h.n + ' ' + o + '->0'); }
                });
            } else if (h.t === 'ret1') {
                Interceptor.attach(addr, {
                    onLeave: function(rv) { var o = rv.toInt32(); rv.replace(1); if (o !== 1) bypass(h.n + ' ' + o + '->1'); }
                });
            } else {
                Interceptor.attach(addr, { onEnter: function(args) { bypass(h.n + ' called'); } });
            }
            log(h.n + ' hooked');
        } else {
            log(h.n + ' not found in libssl.so');
        }
    });

    // X509_verify_cert in libcrypto.so
    if (libcrypto) {
        var x509 = findExport(libcrypto, 'X509_verify_cert');
        if (x509) {
            Interceptor.attach(x509, {
                onLeave: function(rv) { var o = rv.toInt32(); rv.replace(1); if (o !== 1) bypass('X509_verify_cert ' + o + '->1'); }
            });
            log('X509_verify_cert hooked');
        }
    }

    // === TRAFFIC CAPTURE via SSL_write/SSL_read ===
    var ssl_write = findExport(libssl, 'SSL_write');
    var ssl_read = findExport(libssl, 'SSL_read');

    if (ssl_write) {
        Interceptor.attach(ssl_write, {
            onEnter: function(args) {
                try {
                    var len = args[2].toInt32();
                    if (len > 0 && len < 8192) {
                        var buf = Memory.readUtf8String(args[1], len);
                        if (buf && (buf.indexOf('GET ') === 0 || buf.indexOf('POST ') === 0 ||
                            buf.indexOf('PUT ') === 0 || buf.indexOf('DELETE ') === 0 ||
                            buf.indexOf('PATCH ') === 0 || buf.indexOf('HTTP') !== -1)) {
                            console.log('\n[>>> REQUEST >>>]');
                            console.log(buf.substring(0, 1000));
                            console.log('[<<< END >>>]\n');
                        }
                    }
                } catch(e) {}
            }
        });
        log('SSL_write hooked @ ' + ssl_write);
    }

    if (ssl_read) {
        Interceptor.attach(ssl_read, {
            onEnter: function(args) { this.buf = args[1]; this.len = args[2].toInt32(); },
            onLeave: function(rv) {
                try {
                    var read = rv.toInt32();
                    if (read > 0 && read < 8192) {
                        var buf = Memory.readUtf8String(this.buf, read);
                        if (buf && (buf.indexOf('HTTP') !== -1 || buf.indexOf('{') !== -1)) {
                            console.log('\n[<<< RESPONSE <<<]');
                            console.log(buf.substring(0, 1000));
                            console.log('[<<< END <<<]\n');
                        }
                    }
                } catch(e) {}
            }
        });
        log('SSL_read hooked @ ' + ssl_read);
    }
}, 500);

// === 2. JAVA SSL BYPASS (with retry — Java may not be available at spawn time for Flutter) ===
// PITFALL: When using frida -U -f, the Java VM may not be initialized when the script loads.
// Use typeof Java === 'undefined' check + retry loop.
function tryJava(attempt) {
    attempt = attempt || 1;
    try {
        if (typeof Java === 'undefined' || !Java.available) {
            if (attempt < 15) {
                log('Java not available, retry ' + attempt + '/15...');
                setTimeout(function() { tryJava(attempt + 1); }, 2000);
            }
            return;
        }
        Java.perform(function() {
            log('Java SSL hooks loading...');

            // TrustManagerImpl (conscrypt) — THE KEY HOOK for Flutter apps using system SSL
            try {
                var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
                TMI.verifyChain.implementation = function() {
                    bypass('TrustManagerImpl.verifyChain');
                    return arguments[0];
                };
                log('TrustManagerImpl hooked');
            } catch(e) { log('TrustManagerImpl: ' + e); }

            // Custom TrustManager
            try {
                var X509TM = Java.use('javax.net.ssl.X509TrustManager');
                var TrustAll = Java.registerClass({
                    name: 'com.bypass.TrustAll',
                    implements: [X509TM],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                SSLContext.init.overload(
                    '[Ljavax.net.ssl.KeyManager;',
                    '[Ljavax.net.ssl.TrustManager;',
                    'java.security.SecureRandom'
                ).implementation = function(km, tm, sr) {
                    bypass('SSLContext.init -> TrustAll');
                    this.init(km, [TrustAll.$new()], sr);
                };
                log('SSLContext.init hooked');
            } catch(e) { log('SSLContext: ' + e); }

            // OkHttp3 CertificatePinner
            try {
                var CP = Java.use('okhttp3.CertificatePinner');
                CP.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                    bypass('OkHttp3 CertificatePinner: ' + arguments[0]);
                };
                try { CP['check$okhttp'].implementation = function() {}; } catch(e) {}
                log('OkHttp3 CertificatePinner hooked');
            } catch(e) { log('OkHttp3: ' + e); }

            // HttpsURLConnection
            try {
                var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
                HUC.setDefaultHostnameVerifier.implementation = function(v) { bypass('setDefaultHostnameVerifier'); };
                log('HttpsURLConnection hooked');
            } catch(e) {}

            // WebViewClient
            try {
                var WVC = Java.use('android.webkit.WebViewClient');
                WVC.onReceivedSslError.implementation = function(v, h, e) { bypass('WebView SSL -> proceed'); h.proceed(); };
                log('WebViewClient hooked');
            } catch(e) {}

            // RootBeer (root detection bypass)
            try {
                var RB = Java.use('com.scottyab.rootbeer.RootBeer');
                RB.isRooted.implementation = function() { bypass('RootBeer -> false'); return false; };
                log('RootBeer hooked');
            } catch(e) {}

            try {
                var RBN = Java.use('com.scottyab.rootbeer.RootBeerNative');
                RBN.checkForRoot.implementation = function() { bypass('RootBeerNative -> 0'); return 0; };
                log('RootBeerNative hooked');
            } catch(e) {}
        });
    } catch(e) {
        log('Java error: ' + e);
        if (attempt < 15) setTimeout(function() { tryJava(attempt + 1); }, 2000);
    }
}

// === 3. libflutter.so CHECK (loads late, may have stripped BoringSSL) ===
// PITFALL: libflutter.so may have 0 SSL exports/symbols (stripped BoringSSL).
// On modern Android 12+, Flutter uses system libssl.so, not static BoringSSL.
// This section is a best-effort check — if 0 symbols found, system libssl.so hooks are sufficient.
setTimeout(function() {
    var libflutter = Process.findModuleByName('libflutter.so');
    if (libflutter) {
        log('libflutter.so @ ' + libflutter.base + ' size=' + libflutter.size);
        var names = ['ssl_crypto_x509_session_verify_cert_chain', 'SSL_CTX_set_custom_verify',
                     'SSL_set_verify', 'SSL_CTX_set_verify', 'SSL_get_verify_result',
                     'ssl_verify_peer_cert'];
        var found = 0;
        names.forEach(function(name) {
            var addr = findExport(libflutter, name);
            if (addr) {
                found++;
                log('  libflutter.so: ' + name + ' @ ' + addr);
                if (name === 'ssl_crypto_x509_session_verify_cert_chain' || name === 'ssl_verify_peer_cert') {
                    Interceptor.attach(addr, { onLeave: function(rv) { var o = rv.toInt32(); rv.replace(1); bypass('flutter ' + name + ' ' + o + '->1'); } });
                } else if (name.indexOf('set_verify') !== -1 || name.indexOf('set_custom_verify') !== -1) {
                    Interceptor.attach(addr, { onEnter: function(args) { args[1] = ptr(0); } });
                } else if (name === 'SSL_get_verify_result') {
                    Interceptor.attach(addr, { onLeave: function(rv) { rv.replace(0); } });
                }
            }
        });
        if (found === 0) log('  libflutter.so: 0 SSL symbols (stripped — system libssl.so hooks are sufficient)');
    } else {
        log('libflutter.so not loaded (system libssl.so hooks are active)');
    }
}, 3000);

// Start Java hooks
setTimeout(function() { tryJava(1); }, 2000);

log('Script loaded. Waiting for hooks...');
