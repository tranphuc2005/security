# Spring Data JPA Sort Parameter SQLi Analysis

> Session-derived reference for testing `sort` parameters on Spring Data REST / Spring Boot APIs.
> Companion to [SKILL.md](../SKILL.md) and [SCENARIOS.md](../SCENARIOS.md).

## Background

Spring Data JPA's `Sort.by()` parser splits the `sort` query parameter on commas. Each segment becomes a `Sort.Order` object with a `property` name and optional `direction` (asc/desc). The `property` name is matched against **Java entity field names**, not raw SQL column names. This has major implications for SQLi testing.

## Parsing behavior (observed)

Input: `sort=updated_date,desc||CAST(1 AS CHAR)`

Spring parses this as TWO sort orders:
1. `property=updated_date, direction=DESC` (but `desc` can be consumed as direction)
2. `property=desc || CAST(1 AS CHAR), direction=ASC` (the `||CAST(...)` part becomes a literal property name string)

The response JSON echoes back the parsed sort object, confirming app-layer parsing:
```json
"sort": [
  {"direction": "ASC", "property": "updated_date", ...},
  {"direction": "ASC", "property": "desc || CAST(1 AS CHAR)", ...}
]
```

This echo-back is the key diagnostic: the server reflects the parsed property name in the response, proving the input never reaches SQL ORDER BY as a raw expression.

## Testing methodology

### Step 1: Baseline with valid sort
```
sort=updated_date,desc
```
Expect: 200 OK with JSON data. Note the response structure.

### Step 2: Echo-back test
```
sort=updated_date,desc,SLEEP(5)
```
If the response echoes `SLEEP(5)` as a property name → Spring Sort.by() parser is consuming the input at the app layer. The `SLEEP(5)` string never reaches SQL.

### Step 3: Timing test (confirm)
```
sort=updated_date,desc,SLEEP(5)
```
If no time delay (~2s baseline) → function call was treated as a property name string, not evaluated by SQL.

### Step 4: WAF vs app-layer error differentiation

Different HTTP responses indicate different layers:

| Response | Meaning |
|---|---|
| 200 + JSON with echoed property name | App-layer parse OK; property may be invalid but no SQL error |
| 404 + generic HTML error page (e.g., F5 "page can't be displayed") | WAF/reverse proxy blocked the request before it reached the app |
| 500 + JSON {"error":"server_error"} | App processed but hit an unhandled exception — could indicate SQL error |
| 401 + JSON {"errorCode":"410"} | Auth token expired — cannot test, need fresh token |

### Step 5: Invalid property name test
```
sort=this_column_does_not_exist_xyz,desc
```
If 200 OK with echoed property name → Spring accepts any string as property name. The actual SQL error (invalid column) only surfaces when data is returned AND the ORDER BY clause is executed. If the query returns 0 rows (empty content), ORDER BY may be skipped entirely → no SQL error even with invalid column names.

**This is the critical pitfall**: An endpoint that returns 0 rows will never trigger an SQL ORDER BY error, making it look non-injectable when it might be injectable with data present.

## When the sort param IS injectable

The sort parameter CAN reach SQL ORDER BY directly when:
1. The app uses **native queries** (`@Query(value="...ORDER BY :sort", nativeQuery=true)`) with string concatenation
2. The app manually parses sort params and builds SQL strings (not using Spring Data's Sort object)
3. The app passes the raw sort string to a JdbcTemplate query with string concatenation
4. **Spring Data Projections** or custom repository implementations bypass Sort.by() safety

In these cases, test with:
```
sort=1                  -- positional ORDER BY (MySQL/PostgreSQL)
sort=(SELECT 1)         -- subquery in ORDER BY
sort=CASE WHEN 1=1 THEN updated_date ELSE updated_date END  -- conditional
```

## Token expiry pitfall

When testing authenticated API endpoints:
- Bearer tokens may expire mid-testing (observed: MB Capital tokens expire in ~30min)
- Response `errorCode: 410` / "Access token is expired" means ALL subsequent tests return auth error, not SQL error
- Must obtain a fresh token before continuing SQLi tests
- Always verify token validity with a baseline request before drawing conclusions about SQLi

## MB Capital (online.mbcapital.com.vn) specifics

- API host: `api-public.mbbank.com.vn`
- Login endpoint: `POST /ms/fundsystem-authorization/investor/token` (form-urlencoded, OAuth2 style)
- Login body: `username=<id>&password=<pw>` (password sent as plaintext, no client-side encryption observed)
- Auth: `Authorization: Basic <base64>` header with clientId:clientSecret (decoded: `6lVpYmO86071SnmDmuG9aeggGhSk5Fpk:wA7bGoe8VImdmnZo`)
- Token: `Authorization: Bearer <token>` for API calls
- Sort param on SIP search: uses Spring Data Sort.by() → NOT directly injectable
- WAF: F5 Big-IP (generic HTML 404 page on blocked requests)
- Frontend: Angular (not WASM-encrypted like parent MB Bank app)
