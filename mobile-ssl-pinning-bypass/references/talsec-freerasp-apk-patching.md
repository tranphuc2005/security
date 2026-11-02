# Talsec freeRASP APK Patching — Disable RASP Before Running Frida

> **When to use:** Talsec freeRASP actively kills frida-server (not just detects it). When `frida -U -p PID` connects but immediately gets "Connection terminated" and `ps -A | grep frida` shows frida-server is dead, Talsec's native library (`libts.so`) has scanned for and killed the frida-server process. APK patching disables Talsec at the smali level so Frida can run freely.

## Detection

### Signs Talsec freeRASP is present

```bash
# In libapp.so (Flutter Dart strings):
strings -n 6 libapp.so | grep -i "talsec\|freerasp"
# Expected: package:freerasp/src/..., talsec.app/freerasp/methods, _$TalsecConfigToJson

# In libts.so (native Talsec library):
strings -n 8 libts.so | grep -i "frida\|LIBFRIDA\|scan_for_frida"
# Expected: LIBFRIDA, /memfd:frida-agent, scan_for_frida_server_all_ports

# In smali (Java layer):
grep -r "talsec\|freerasp\|Talsec" smali/ --include="*.smali" -l
# Expected: j3/b.smali (plugin), m3/c.smali (method channel handler), X0/a.smali (pigeon API)

# In GeneratedPluginRegistrant.smali:
grep -n "freerasp\|j3/b\|root_checker" smali/io/flutter/plugins/GeneratedPluginRegistrant.smali
```

### Talsec behavior: frida-server killing

Talsec's `libts.so` contains `scan_for_frida_server_all_ports` — a native function that scans all ports for frida-server's listener and kills it. This is more aggressive than passive detection:

```
# frida-server running, app launched, Frida attaches...
frida -U -p 3389 -l bypass.js
# Output: Connected to SM S721B
# Output: === Bypass Script Starting ===
# Output: [+] libts.so found at: 0x794d43e000
# Output: Error: access violation accessing 0x794dacb000  (Memory.scanSync on libts.so)
# Output: Connection terminated

# After Frida disconnects:
adb shell "su -c 'ps -A | grep frida'"
# (empty — frida-server was killed by Talsec)
```

**Key difference from detection-only RaspGuard:** Talsec doesn't just log threats — it actively terminates frida-server's process. Renaming frida-server binary or using `--policy-softener=internal --ignore-crashes` does NOT help because Talsec scans by port, not by process name.

## APK Patching Approach (6 patches)

### Overview

| # | File | Patch | Effect |
|---|------|-------|--------|
| 1 | `GeneratedPluginRegistrant.smali` | NOP `new-instance Lj3/b;` + `invoke-direct Lj3/b;-><init>()V` | Talsec Flutter plugin never registered |
| 2 | `GeneratedPluginRegistrant.smali` | NOP `new-instance LN3/a;` + `invoke-direct LN3/a;-><init>()V` | root_checker_plus plugin never registered |
| 3 | `W4/A4.smali` | Method `a(Context, Lo3/l;)` → `.locals 0` + `return-void` | Talsec.start() returns immediately, no native init |
| 4 | `androidx/security/BNatives.smali` | Comment out `System.loadLibrary("ts")` | libts.so never loaded, native frida scanner never runs |
| 5 | `RootBeerNative.smali` | `checkForRoot()` → `const/4 v0, 0x0; return v0` | RootBeer native check always returns 0 (not rooted) |
| 6 | `N3/a.smali` | `if-eqz v2, :cond_17` → `goto :cond_17` | isRootChecker always skips root checking logic |

### Patch 1+2: GeneratedPluginRegistrant.smali

The Flutter plugin registrant registers all plugins in sequence. Find the freerasp and root_checker_plus blocks and replace the `new-instance` + `invoke-direct` + `invoke-virtual` with `nop`:

```smali
# BEFORE (freerasp registration):
    :try_start_12
    iget-object v1, p0, LR7/c;->d:LM2/a;
    new-instance v2, Lj3/b;
    invoke-direct {v2}, Lj3/b;-><init>()V
    invoke-virtual {v1, v2}, LM2/a;->a(LX7/c;)V
    :try_end_12
    .catch Ljava/lang/Exception; {:try_start_12 .. :try_end_12} :catch_12

# AFTER:
    :try_start_12
    nop
    nop
    nop
    :try_end_12
    .catch Ljava/lang/Exception; {:try_start_12 .. :try_end_12} :catch_12
```

Same pattern for root_checker_plus (`LN3/a` instead of `Lj3/b`).

**How to find the right block:** Search for the error string in the catch handler:
```bash
grep -n "freerasp\|root_checker" smali/io/flutter/plugins/GeneratedPluginRegistrant.smali
```

### Patch 3: W4/A4.smali (Talsec.start)

`W4/A4.a(Context, Lo3/l;)` is the Talsec initialization method called from `m3/c.smali` when the Dart side sends `"start"` via the `talsec.app/freerasp/methods` method channel. Replace the entire method body with early return:

```smali
# BEFORE:
.method public static a(Landroid/content/Context;Lo3/l;)V
    .locals 10
    .line 1
    const-string v0, "context"
    ...  (700+ lines of init code)

# AFTER:
.method public static a(Landroid/content/Context;Lo3/l;)V
    .locals 0
    return-void
    ...  (original code left as unreachable, harmless)
```

### Patch 4: BNatives.smali (libts.so loader)

`androidx/security/BNatives` is the class that loads `libts.so` via `System.loadLibrary("ts")`. Comment out the load call:

```smali
# BEFORE:
    const-string v0, "ts"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

# AFTER:
    # Do NOT load libts.so - Talsec native library disabled
    # const-string v0, "ts"
    # invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

**How to find:** `grep -rn 'loadLibrary.*"ts"' smali/ --include="*.smali"` — look for `const-string v0, "ts"` followed by `System.loadLibrary`.

### Patch 5: RootBeerNative.smali

Replace native method declarations with Java implementations that return 0/false:

```smali
# BEFORE:
.method public native checkForRoot([Ljava/lang/Object;)I
.end method

.method public native setLogDebugMessages(Z)I
.end method

# AFTER:
.method public checkForRoot([Ljava/lang/Object;)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method

.method public setLogDebugMessages(Z)I
    .locals 1
    const/4 v0, 0x0
    return v0
.end method
```

### Patch 6: N3/a.smali (root_checker_plus)

The `onMethodCall` method checks if the method name is `"isRootChecker"` and branches to root checking logic. Force-skip the branch:

```smali
# BEFORE:
    invoke-static {v0, v2}, LU8/h;->a(Ljava/lang/Object;Ljava/lang/Object;)Z
    move-result v2
    if-eqz v2, :cond_17

# AFTER:
    invoke-static {v0, v2}, LU8/h;->a(Ljava/lang/Object;Ljava/lang/Object;)Z
    move-result v2
    goto :cond_17
```

### Rebuild and Sign

```bash
# Rebuild APK
java -jar apktool.jar b base_decoded -o patched.apk

# Sign with uber-apk-signer (auto-generates debug keystore)
java -jar uber-apk-signer.jar -a patched.apk
# Output: patched-aligned-debugSigned.apk

# Verify patches
jarsigner -verify patched-aligned-debugSigned.apk
# Expected: "jar verified."

# Install
adb uninstall com.target.app
adb install patched-aligned-debugSigned.apk
```

## Post-Patch Frida Usage

After patching, Talsec no longer kills frida-server. Frida can attach normally:

```bash
# Start frida-server (it will survive now)
adb shell "su -c '/data/local/tmp/frida-server --policy-softener=internal --ignore-crashes &'"

# Launch app
adb shell "am start -n com.target.app/.MainActivity"
sleep 2

# Attach Frida (spawn may still fail on Android 15 — use attach by PID)
PID=$(adb shell "pidof com.target.app")
frida -U -p $PID -l ssl_bypass.js
```

## Pitfalls

### Memory.scanSync on libts.so causes SIGSEGV

Do NOT use `Memory.scanSync(libts.base, libts.size, ...)` in Frida scripts to search for strings in libts.so. Some memory regions in libts.so are guarded and cause access violations:

```
Error: access violation accessing 0x794dacb000
    at hookTalsecNative (bypass.js:66)
```

**Fix:** Only use `Interceptor.attach` on exported functions. Do NOT scan libts.so memory regions. If you need to find strings, use `strings` command on the .so file on disk instead.

### Frida spawn fails on Android 15

`frida -U -f com.target.app` fails with `unable to locate android.os.Process.setArgV0()`. This is an Android 15 compatibility issue in Frida 17.x.

**Fix:** Launch app via `am start`, then attach by PID:
```bash
adb shell "am start -n com.target.app/.MainActivity"
sleep 2
frida -U -p $(adb shell pidof com.target.app) -l bypass.js
```

### Talsec class names are obfuscated

Talsec classes appear with obfuscated names in smali. The mapping varies per app. Key classes to look for:

| Obfuscated (varies) | Real class | How to identify |
|---------------------|-----------|-----------------|
| `j3/b` | FreeraspPlugin | `GeneratedPluginRegistrant` registers it, error string "freerasp" |
| `j3/e` | TalsecScreenProtector | String "TalsecScreenProtector" in smali |
| `m3/c` | Talsec method channel handler | String "talsec.app/freerasp/methods" |
| `W4/A4` | Talsec.start() | Called from `m3/c.smali`, string "Unable to run Talsec - context is null" |
| `X0/a` | TalsecPigeonApi | String "dev.flutter.pigeon.freerasp.TalsecPigeonApi.onMalwareDetected" |
| `N3/a` | RootCheckerPlusPlugin | `GeneratedPluginRegistrant` error string "root_checker_plus" |
| `V4/s` | RootBeer logging | String "RootBeer" in smali |
| `com/scottyab/rootbeer/RootBeerNative` | RootBeer native | `loadLibrary("toolChecker")` + `checkForRoot` native method |
| `androidx/security/BNatives` | libts.so loader | `loadLibrary("ts")` in static init |

### Multiple protection layers may coexist

A Flutter app can have ALL of these simultaneously:
- Talsec freeRASP (RASP: Frida detection, root detection, hook detection, emulator detection)
- RootBeer (root detection via `libtoolChecker.so`)
- Dart-level SSL pinning (`ssl_pinning.dart`, `onBadCertificateWrapper`, `SslPinningHelper`)
- Checksum interceptor (`ChecksumManager` — request integrity verification)
- reCAPTCHA Enterprise (`recaptcha_interceptor.dart`)
- Custom headers (`x-client-id`, `x-secret-key`, `Authorization: Bearer`)

APK patching disables Talsec + RootBeer. SSL pinning still needs Frida hooks (BoringSSL in libflutter.so or system libssl.so). Checksum and reCAPTCHA interceptors need separate analysis.

## Verification Script

See `scripts/verify-talsec-patches.sh` for a verification script that checks all 6 patches are present in decoded smali and the rebuilt APK is signed correctly.
