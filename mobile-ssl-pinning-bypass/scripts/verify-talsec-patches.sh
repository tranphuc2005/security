#!/bin/bash
# Verify Talsec freeRASP + RootBeer APK patches
# Usage: bash verify-talsec-patches.sh /path/to/decoded_apk /path/to/signed.apk
# Checks all 6 patches are present in smali source and APK is signed.

DECODED="${1:-./base_decoded}"
SIGNED="${2:-./mbal_patched-aligned-debugSigned.apk}"
APKSIGNER="${APKSIGNER:-}"
PASS=0; FAIL=0

check() { if [ "$1" = "0" ]; then echo "  OK: $2"; PASS=$((PASS+1)); else echo "  FAIL: $2"; FAIL=$((FAIL+1)); fi; }

echo "=== Talsec + RootBeer Patch Verification ==="
echo ""

# [1] freerasp plugin (j3/b) registration NOP'd
echo "[1] freerasp plugin (j3/b) registration removed"
grep -c "Lj3/b;-><init>()V" "$DECODED/smali/io/flutter/plugins/GeneratedPluginRegistrant.smali" 2>/dev/null | grep -q "^0$"
check $? "Lj3/b init call removed from GeneratedPluginRegistrant"

# [2] root_checker_plus (N3/a) registration NOP'd
echo "[2] root_checker_plus (N3/a) registration removed"
grep -c "LN3/a;-><init>()V" "$DECODED/smali/io/flutter/plugins/GeneratedPluginRegistrant.smali" 2>/dev/null | grep -q "^0$"
check $? "LN3/a init call removed from GeneratedPluginRegistrant"

# [3] W4/A4 Talsec init returns void
echo "[3] W4/A4 Talsec init returns void immediately"
sed -n '/\.method public static a(Landroid\/content\/Context;Lo3\/l;)V/,/\.end method/p' "$DECODED/smali/W4/A4.smali" | head -5 | grep -q "return-void"
check $? "W4/A4.a() has early return-void"

# [4] BNatives does not load libts.so
echo "[4] BNatives does not load libts.so"
ACTIVE=$(grep "loadLibrary" "$DECODED/smali/androidx/security/BNatives.smali" 2>/dev/null | grep -cv "^[[:space:]]*#")
test "$ACTIVE" -eq 0 2>/dev/null
check $? "No active System.loadLibrary(\"ts\") in BNatives"

# [5] RootBeerNative.checkForRoot returns 0
echo "[5] RootBeerNative.checkForRoot returns 0"
sed -n '/\.method public checkForRoot/,/\.end method/p' "$DECODED/smali/com/scottyab/rootbeer/RootBeerNative.smali" 2>/dev/null | grep -q "const/4 v0, 0x0"
check $? "checkForRoot returns 0"

# [6] N3/a isRootChecker branch forced to skip
echo "[6] N3/a isRootChecker branch forced to skip"
grep -q "goto :cond_17" "$DECODED/smali/N3/a.smali" 2>/dev/null
check $? "isRootChecker always jumps to :cond_17"

echo ""
echo "--- APK build & signature ---"

# [7] Signed APK exists
echo "[7] Signed APK exists"
test -f "$SIGNED"
check $? "$(basename "$SIGNED") present"

# [8] classes.dex in APK
echo "[8] classes.dex compiled"
unzip -l "$SIGNED" 2>/dev/null | grep -q "classes.dex"
check $? "classes.dex in APK"

# [9] classes2.dex in APK
echo "[9] classes2.dex compiled"
unzip -l "$SIGNED" 2>/dev/null | grep -q "classes2.dex"
check $? "classes2.dex in APK"

# [10] APK signature
echo "[10] APK signature verified"
jarsigner -verify "$SIGNED" 2>&1 | grep -q "jar verified"
check $? "jarsigner verification passed"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
