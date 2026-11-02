# DBMS_XMLGEN Boolean Oracle Details

## Core Insight
Oracle `DBMS_XMLGEN.GETXML('SELECT ...')` returns XML text if the SELECT returns >=1 row, and `NULL` if it returns 0 rows. This makes it a clean boolean channel for blind SQLi when you can observe whether the response contains XML or not.

## Working Probe
```sql
LENGTH(DBMS_XMLGEN.GETXML('SEL'||'ECT 1 c FROM dual))>0
-- Returns TRUE if dual has a row, FALSE otherwise.
```

## Why Split 'SELECT'?
Some WAFs block the literal `SELECT`. Splitting into `'SEL'||'ECT'` bypasses simple keyword filters. This is a common pattern in Oracle injection through PL/SQL contexts.

## Reading the Boolean
The injected string is typically evaluated inside a server-side CASE expression that maps TRUE/FALSE to distinct marker strings. Count occurrences of the TRUE marker in the response to read the boolean.

## What Doesn't Work
- `COUNT(*)` inside `GETXML` often returns length=0 even when rows exist. Use `SELECT 1 c FROM ...` instead.
- `WITH FUNCTION` (CTE with PL/SQL function) — Oracle rejects this inside `DBMS_XMLGEN.GETXML`.
- `DBMS_SCHEDULER.CREATE_JOB` — may pass WAF but fails at runtime without `CREATE EXTERNAL JOB` granted to the current schema.
- `DBMS_JAVA.RUNJAVA` — WAF learns patterns quickly; split/REPLACE/TRANSLATE workarounds get blocked.

## Escaping Rules
- In Python strings building SQL: double single-quotes for SQL literals: `''TABLE_NAME''`.
- Oracle empty string `''` is `NULL`. Use `' '` (space) if you need a string less than all printable names.

## Performance Notes
- One boolean request costs ~0.3–0.8s round-trip.
- Binary search on ASCII 33–126 needs ~7 requests per character (log2(94) ≈ 6.6).
- A 20-character name needs ~140 requests ≈ 2–4 minutes at 0.3s/req.
