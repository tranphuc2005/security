# Mobile Pentest Tool Install Reference

Install commands for tools that complement SSL pinning bypass with static analysis,
Flutter bypass, and dynamic component testing. Verified on Windows 10/11 with
Python 3.12 + pip, Docker Desktop, and Android SDK build-tools.

## Quick Install (all at once)

```bash
# Core Python tools (pip)
pip install frida==<server_version> frida-tools objection androguard apkid reflutter drozer qark

# MobSF (Docker — needs Docker Desktop running first)
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -d --name mobsf -p 8000:8000 -p 1337:1337 opensecurity/mobile-security-framework-mobsf:latest
# Web UI: http://localhost:8000  |  API: http://localhost:1337
```

## Per-Tool Details

### Frida + frida-server (version match is CRITICAL)

```bash
# Client (host):
pip install frida==17.9.6 frida-tools    # pin to match server version

# Server (device) — must be same version:
# Download from https://github.com/frida/frida/releases
#   frida-server-17.9.6-android-arm64
adb push frida-server-17.9.6-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"    # start in background

# Verify:
frida --version                                          # host
adb shell "su -c '/data/local/tmp/frida-server --version'"  # device
# Both must print the same X.Y version.
```

### Objection (wraps Frida for one-command bypass)

```bash
pip install objection
# Usage: objection -g com.target.app explore --startup-command "android sslpinning disable"
```

### Androguard (Python APK analysis — manifests, certs, permissions)

```bash
pip install androguard
# CLI: androguard analyze target.apk
# Python: from androguard.core.apk import APK
```

### APKiD (detect packers/protectors/obfuscators)

```bash
pip install apkid
# Usage: apkid target.apk
```

### reflutter (Flutter SSL bypass — patches BoringSSL in Flutter engine)

```bash
pip install reflutter
# Usage: reflutter target.apk
# Outputs patched APK that redirects traffic to your proxy + disables SSL verify
```

### Drozer (dynamic analysis — exported components, content providers, intents)

```bash
pip install drozer
# Requires a drozer agent APK on the device + adb port forward:
#   adb forward tcp:31415 tcp:31415
# Usage: drozer console connect
```

### QARK (static analysis — Android vulnerability scanner)

```bash
pip install qark
# Usage: qark --apk target.apk
```

### MobSF (Mobile Security Framework — full static + dynamic analysis, Docker)

```bash
# Requires Docker Desktop running
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -d --name mobsf -p 8000:8000 -p 1337:1337 \
  opensecurity/mobile-security-framework-mobsf:latest
# Upload APK via web UI at http://localhost:8000
# REST API at http://localhost:1337 (for automation)
```

## Dependency Conflict Pitfall (cryptography)

Installing androguard can upgrade `cryptography` beyond what mitmproxy accepts
(e.g. cryptography 49.0.0 vs mitmproxy 12.x requiring <=46.1). Fix:

```bash
# After installing androguard/apkid, re-pin cryptography:
pip install cryptography==46.0.7
# Then verify mitmproxy still works:
mitmproxy --version
```

If installing drozer AFTER androguard, drozer may downgrade cryptography itself
(drozer requires cryptography <47), which resolves the conflict automatically.

## Already-Present Tools (verify, don't reinstall)

On a typical Android pentest host these should already be installed:

| Tool | Check | Location |
|---|---|---|
| ADB | `adb version` | Android SDK platform-tools |
| JADX | `jadx --version` | C:\Tools\jadx-1.x\bin\ |
| APKTool | `apktool --version` | C:\Tools\ or ~/AppData/Local/hermes/tools/ |
| apksigner | `apksigner --version` | Android SDK build-tools/35.0.0/ |
| zipalign | `zipalign --version` | Android SDK build-tools/35.0.0/ |
| keytool | `keytool -help` | Java JDK bin/ |
| Ghidra | launch ghidraRun.bat | C:\Tools\ghidra_x.x_PUBLIC\ |
| Burp Suite | launch from Start Menu | BurpSuitePro |
| scrcpy | `scrcpy --version` | WinGet: Genymobile.scrcpy |
