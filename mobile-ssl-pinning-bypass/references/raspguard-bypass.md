# RaspGuard (Talsec FreeRASP) Enforcement Bypass

When RaspGuard blocks the app with a "Chưa thể mở ứng dụng" / "Unable to open application" / "Please close suspicious software" screen, SSL pin bypass alone is not enough. You must also bypass RaspGuard's root/tamper detection.

## When to Use This

- App shows a blocking screen after SSL pin bypass (app starts, splash shows, then blocks)
- Logcat shows `RaspGuard: threat detected — privileged_access (root/jailbreak)` followed by app blocking
- Logcat shows `RaspGuard: no completion signal within 8s — channel may be suppressed`
- App uses Talsec FreeRASP (look for `com.aheaditec.talsec` in smali, `RaspGuard` strings in libapp.so)

## How RaspGuard Works (Flutter + Talsec FreeRASP)

RaspGuard has TWO detection layers:

### Layer 1: Java (smali) — MethodChannel "scan"

The app registers a Flutter MethodChannel (e.g., `sunsite/dev_integrity`) with a handler class (e.g., `E4/a.smali`). The Dart code calls `scan` via this channel. The Java handler checks:

- Root paths: `/data/adb/magisk`, `/data/adb/modules`, `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/su/bin/su`, `/system/app/Superuser.apk`
- Frida files: `/data/local/tmp/re.frida.server`, `/data/local/tmp/frida-server`
- `/proc/self/maps` scan for: `frida`, `gum-js-loop`, `gadget`, `linjector`
- `/proc/self/task/*/comm` scan for frida thread names
- `/proc/self/status` TracerPid (debugger detection)
- `Debug.isDebuggerConnected()`
- App signature verification (SHA-256 of signing cert vs expected hash)
- Package names: `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.devadvance.rootcloak`, `com.chelpus.lackypatch`, `com.dimonvideo.luckypatcher`, `com.lbe.parallel`, `com.lody.virtual`, `com.saurik.substrate`

Threats found are added to an `ArrayList` and returned via `MethodChannel$Result.success(arrayList)`.

### Layer 2: Dart (libapp.so) — Independent root detection

Dart code in `libapp.so` independently checks for root (not just via MethodChannel). It reads the threat strings from the string pool and logs `RaspGuard: threat detected — privileged_access (root/jailbreak)`. If the threat list is non-empty, Dart shows the blocking screen.

**Key insight:** Patching ONLY the Java smali (Layer 1) is NOT sufficient. The Dart code (Layer 2) independently detects root and blocks the app. You must patch BOTH layers.

## Bypass Technique

### Step 1: Patch smali (Layer 1 — Java MethodChannel)

Find the MethodChannel handler class (look for `sunsite/dev_integrity` or similar in smali, or `com.aheaditec.talsec` package). In the `onMethodCall` method, find the `scan` branch:

```smali
# Original: after "scan" method match, creates ArrayList and runs root checks
new-instance p1, Ljava/util/ArrayList;
invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V
const-string v7, "/data/adb/magisk"    # root scan starts here
```

Patch to return empty list immediately:

```smali
new-instance p1, Ljava/util/ArrayList;
invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

# RaspGuard bypass: return empty threat list immediately
invoke-interface {p2, p1}, Lio/flutter/plugin/common/MethodChannel$Result;->success(Ljava/lang/Object;)V
return-void

const-string v7, "/data/adb/magisk"    # dead code after return-void
```

This makes the Java `scan` method return an empty threat list, but Dart code still detects root independently.

### Step 2: Patch libapp.so strings (Layer 2 — Dart root detection)

Patch the threat detection strings in `libapp.so` with same-length replacements. **CRITICAL: replacements MUST be the exact same byte length** — Dart string pool uses length-prefixed entries; changing length corrupts the pool and causes SIGSEGV.

```python
data = bytearray(open('libapp.so', 'rb').read())

# Patch threat strings (same length, same byte count)
patches = {
    b'privileged_access (root/jailbreak)': b'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',  # 34 bytes
    b'privileged_access': b'xxxxxxxxxxxxxxxxx',  # 17 bytes
    b'rasp_threat: ': b'xxxxxxxxxxxxx',  # 13 bytes
}

for old, new in patches.items():
    assert len(old) == len(new), f"Length mismatch: {len(old)} vs {len(new)}"
    count = data.count(old)
    if count > 0:
        data = data.replace(old, new)
        print(f"Patched {old.decode()}: {count} occurrences")
```

**CRITICAL: Do NOT patch package name strings** (e.g., `com.topjohnwu.magisk` → `com.topjohnwu.xxxxxxx`). While same-length, these strings are referenced by Dart code in ways that cause hash table lookups to fail, resulting in SIGSEGV. Only patch the threat detection result strings (`privileged_access`, `rasp_threat:`), NOT the detection input strings (package names, file paths).

**CRITICAL: Do NOT patch `RaspGuard.start` or `RaspGuard: started`** — these are log messages, not threat detection strings. Patching them has no effect on blocking behavior.

### Step 3: Also patch SSL pin (if needed)

If the app also has SPKI pinning (check libapp.so for base64 strings of 44 chars ending with `=`), patch those too. See `references/flutter-binary-patch-no-frida.md` for the SPKI patch technique.

### Step 4: Rebuild, sign, install

```bash
# APKTool path (Windows/MSYS):
java -jar "C:\Users\Admin\AppData\Local\hermes\tools\apktool.jar" b base_decoded -o base_patched.apk

# zipalign (use .exe on Windows, not .bat):
"C:\Users\Admin\AppData\Local\Android\Sdk\build-tools\35.0.0\zipalign" -f -v 4 base_patched.apk base_aligned.apk

# Sign (use .bat via cmd.exe on Windows):
cmd.exe /c "C:\Users\Admin\AppData\Local\Android\Sdk\build-tools\35.0.0\apksigner.bat sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out base_signed.apk base_aligned.apk"

# Install
adb uninstall com.target.app
adb install base_signed.apk
```

## How to Identify RaspGuard in an App

### Static analysis (smali)

```bash
# Find Talsec/RaspGuard classes
grep -rnl "aheaditec\|talsec\|RaspGuard\|freerasp" smali/

# Find MethodChannel name
grep -rn "MethodChannel.*init\|setMethodCallHandler" smali/com/target/  # look for channel name string

# Find "scan" method
grep -rn '"scan"' smali/

# Find root detection paths
grep -rn '/system/bin/su\|/data/adb/magisk\|frida-server\|TracerPid\|isDebuggerConnected' smali/
```

### Static analysis (libapp.so)

```bash
# Find RaspGuard strings
strings libapp.so | grep -i "raspguard\|rasp_threat\|privileged_access\|talsec\|freerasp"

# Find threat detection strings
strings libapp.so | grep "privileged_access (root"
strings libapp.so | grep "rasp_threat:"

# Find root detection package names
strings libapp.so | grep -E "com\.topjohnwu|eu\.chainfire|com\.devadvance|com\.chelpus|com\.dimonvideo|com\.lbe\.|com\.lody\.|com\.saurik"
```

### Dynamic analysis (logcat)

```bash
adb logcat -s flutter | grep -i "raspguard\|threat\|privileged"
# Output patterns:
# [I] RaspGuard: started
# [W] RaspGuard: threat detected — privileged_access (root/jailbreak)
# [W] RaspGuard: no completion signal within 8s — channel may be suppressed
```

## Troubleshooting

| Issue | Cause | Fix |
|---|---|---|
| App still blocks after smali patch | Dart code independently detects root (Layer 2) | Also patch libapp.so strings (Step 2) |
| App crashes (SIGSEGV) after libapp.so patch | String length mismatch in Dart string pool | Verify `len(old) == len(new)` for every patch. Do NOT change string lengths |
| App crashes after patching package name strings | Dart hash table lookup fails on modified strings | Only patch threat RESULT strings (`privileged_access`, `rasp_threat:`), NOT detection INPUT strings (package names, file paths) |
| `RaspGuard: no completion signal within 8s` in logcat | Java scan method patched (returns empty) but Dart timeout fires | This is OK — the app still proceeds. The timeout message means Dart waited for the scan result and got it (empty list), but also has its own independent check. As long as the blocking screen doesn't appear, the bypass works |
| Frida still detected even after smali patch | Smali patch only bypasses Java scan; Frida detection also in Dart | Patch `/proc/self/maps` scan strings in libapp.so, or remove frida-server binary from device |
| `apksigner.bat` not found in MSYS/bash | Windows .bat wrapper doesn't work in MSYS | Use `cmd.exe /c "path\to\apksigner.bat ..."` |
| App signature verification fails after repack | RaspGuard checks signing cert SHA-256 in smali (E4/a.smali) | The smali patch (Step 1) bypasses this — the `scan` method returns empty list before reaching signature check |

### Step 2b: Patch Talsec native engine init (Layer 3 — CRITICAL)

**If Steps 1+2 are not enough (app still blocks after ~5 seconds), there is a THIRD layer.** The Talsec FreeRASP SDK has its own MethodChannel (`talsec.app/freerasp/methods`) separate from the app's own integrity channel (`sunsite/dev_integrity`). When Dart code calls `start` on this channel, the Java handler initializes the Talsec native engine (`Ln2/g;->a()`) which performs independent root detection via `libts.so` (checking `/proc/self/maps`, `/proc/self/task`, `frida` strings, `TracerPid`, etc.).

**Symptom:** App starts, splash screen shows, RaspGuard logs `threat detected — xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (patched string from Step 2), then after ~5 seconds the app blocks with "Chưa thể mở ứng dụng". The `no completion signal within 8s` message may also appear.

**Diagnostic:** Search smali for the Talsec MethodChannel:

```bash
# Find the Talsec MethodChannel handler
grep -rn "talsec.app/freerasp/methods" smali/
# Expected: smali/k2.1/b.smali or similar — registers MethodChannel with handler class

# Find the handler class (implements MethodCallHandler)
grep -rn "MethodCallHandler" smali/k2.1/ smali/n2/ smali/l2/
# Expected: smali/n2/d.smali — implements MethodCallHandler

# Find the "start" method handler in that class
grep -n '"start"' smali/n2/d.smali
# Expected: const-string v1, "start" followed by Ln2/g;->a(Context;Lp2/k;)V call
```

**Fix:** In the Talsec MethodChannel handler class (e.g., `n2/d.smali`), find the `onMethodCall` method, locate the `"start"` case, and **remove the `invoke-static {v0, p1}, Ln2/g;->a(Landroid/content/Context;Lp2/k;)V` call** — keep only the `success()` return:

```smali
# Original (in n2/d.smali, onMethodCall, "start" case):
:cond_7
:try_start_2
const-string v0, "config"
invoke-virtual {p1, v0}, Lio/flutter/plugin/common/MethodCall;->argument(Ljava/lang/String;)Ljava/lang/Object;
move-result-object p1
check-cast p1, Ljava/lang/String;
invoke-static {p1}, LS/q;->Q(Ljava/lang/String;)Lp2/k;
move-result-object p1
iget-object v0, p0, Ln2/d;->q:Landroid/content/Context;
if-eqz v0, :cond_8
invoke-static {v0, p1}, Ln2/g;->a(Landroid/content/Context;Lp2/k;)V    # <-- REMOVE THIS LINE
invoke-interface {p2, v3}, Lio/flutter/plugin/common/MethodChannel$Result;->success(Ljava/lang/Object;)V
goto/16 :goto_7

# Patched:
:cond_7
:try_start_2
const-string v0, "config"
invoke-virtual {p1, v0}, Lio/flutter/plugin/common/MethodCall;->argument(Ljava/lang/String;)Ljava/lang/Object;
move-result-object p1
check-cast p1, Ljava/lang/String;
invoke-static {p1}, LS/q;->Q(Ljava/lang/String;)Lp2/k;
move-result-object p1
iget-object v0, p0, Ln2/d;->q:Landroid/content/Context;
if-eqz v0, :cond_8
# Talsec bypass: skip Ln2/g;->a (root detection init), return success directly
invoke-interface {p2, v3}, Lio/flutter/plugin/common/MethodChannel$Result;->success(Ljava/lang/Object;)V
goto/16 :goto_7
```

This prevents the Talsec native engine from starting, so it never performs root detection. The Dart code receives `success` for the `start` call and proceeds normally. The `no completion signal within 8s` message will still appear (Dart's timeout for a separate callback), but it does NOT block the app.

**How to identify the Talsec MethodChannel handler class:**

```bash
# Search for the Talsec channel name in smali
grep -rn "talsec.app/freerasp" smali/
# This finds the class that registers the channel (e.g., k2.1/b.smali)

# The handler class is passed to setMethodCallHandler
# Look for the class that implements MethodCallHandler
grep -rn "implements.*MethodCallHandler" smali/k2.1/ smali/n2/ smali/l2/
# Expected: smali/n2/d.smali

# Verify the handler has a "start" method
grep -n '"start"' smali/n2/d.smali
# Also check for: "getAppIcon", "storeExternalId", "removeExternalId",
# "isScreenCaptureBlocked", "blockScreenCapture", "addToWhitelist"
# These are Talsec API methods
```

**PITFALL: The Talsec channel registration and the handler class may be in DIFFERENT smali files.** The channel name string (`talsec.app/freerasp/methods`) appears in the registration class (e.g., `k2.1/b.smali`), but the actual `onMethodCall` handler with the `start` method is in a separate class (e.g., `n2/d.smali`). Search for `Ln2/g;->a` (the Talsec native init call) across ALL smali files to find where to patch:

```bash
# Find the Talsec native init call across all smali
grep -rn "Ln2/g;->" smali/
# Look for: invoke-static {v0, p1}, Ln2/g;->a(Landroid/content/Context;Lp2/k;)V
# This is the call to REMOVE in the "start" method handler
```

**VERIFIED (SUNSite v1.1.31):** The Talsec channel `talsec.app/freerasp/methods` is registered in `k2.1/b.smali`, but the `onMethodCall` handler with the `start` method is in `n2/d.smali`. The `Ln2/g;->a` call is in `n2/d.smali` at the `:cond_7` label (after `"start"` string comparison). Patching `n2/d.smali` to skip `Ln2/g;->a` and return `success()` directly bypasses Talsec native engine init. After patching, logcat shows `RaspGuard: no completion signal within 8s — channel may be suppressed` (expected — Dart timeout fires but does NOT block the app).

**All THREE layers are required for full RaspGuard bypass:**

| Layer | What | Where | How |
|---|---|---|---|
| 1 | Java scan MethodChannel | `E4/a.smali` (or similar, channel `sunsite/dev_integrity`) | Return empty ArrayList before root scan |
| 2 | Dart threat strings | `libapp.so` | Same-length replacement of `privileged_access`, `rasp_threat:` |
| 3 | Talsec native engine init | `n2/d.smali` (channel `talsec.app/freerasp/methods`, method `start`) | Remove `Ln2/g;->a()` call, return success directly |

Without Layer 3, RaspGuard still detects root via the Talsec native engine (`libts.so`) and blocks the app after ~5 seconds, even with Layers 1 and 2 bypassed.

## What NOT to Patch in libapp.so

| String | Why Not | Effect if Patched |
|---|---|---|
| `com.topjohnwu.magisk` | Package name used in detection loop | SIGSEGV — Dart hash table lookup fails |
| `eu.chainfire.supersu` | Package name | SIGSEGV |
| `com.devadvance.rootcloak` | Package name | SIGSEGV |
| `RaspGuard.start` | Log message, not detection | No effect on blocking |
| `RaspGuard: started` | Log message | No effect on blocking |
| `RaspGuard: no completion signal within 8s` | Log message | No effect on blocking |

## What TO Patch in libapp.so

| String | Length | Replacement | Effect |
|---|---|---|---|
| `privileged_access (root/jailbreak)` | 34 | `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (34 x's) | Dart threat detection returns "xxxxxxxx..." instead of "privileged_access", which doesn't match any threat type → no block |
| `privileged_access` | 17 | `xxxxxxxxxxxxxxxxx` (17 x's) | Same — neutralizes the threat type identifier |
| `rasp_threat: ` | 13 | `xxxxxxxxxxxxx` (13 x's) | Neutralizes threat logging prefix |

## Verified Setup

- Device: Samsung S25 (SM-S721B, Android 15, rooted via KernelSU Next)
- App: Flutter v1.1.31 with Talsec FreeRASP (RaspGuard) in enforcement mode
- RaspGuard strings in libapp.so: `RaspGuard.start` at 0x5d9ba, `rasp_threat: ` at 0x34314, `privileged_access (root/jailbreak)` at 0x595f2
- MethodChannel: `sunsite/dev_integrity` with handler class `E4/a.smali`
- smali patch: return empty ArrayList before root scan in `onMethodCall` method
- libapp.so patches: 3 strings (privileged_access x2, rasp_threat x1), all same-length
- Also patched: SSL SPKI pin at offset 0x4b2d3 (see `references/flutter-binary-patch-no-frida.md`)
- Result: App opens successfully, FaceLogin works, API calls succeed through Burp proxy
- RaspGuard still logs `threat detected — xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` (patched string) but does NOT block

## KernelSU / Magisk Hide Alternatives

If you prefer not to patch the APK, root hiding might work (but is less reliable):

- **Magisk DenyList**: `magisk --denylist add com.target.app` — hides root for that app
- **KernelSU Next**: No built-in denylist. `ksud profile` only manages SELinux policies, not root visibility
- **Zygisk-Sui**: Has denylist support via Sui manager app, but database may be empty by default
- **`pm hide`**: `adb shell "su -c 'pm hide com.topjohnwu.magisk'"` — hides Magisk app from package manager queries
- **Bind mount**: `adb shell "su -c 'mount --bind /dev/null /system/bin/su'"` — hides su binary globally (not per-app)

None of these alone bypass RaspGuard — the Dart code checks multiple vectors (su binary, package names, /proc/self/maps, TracerPid). The binary patch approach is more reliable.
