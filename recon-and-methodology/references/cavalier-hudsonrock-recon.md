# Hudson Rock Cavalier — stealer-log intelligence layer (field-proven)

Session: mbcapital.com.vn / mbamc.com.vn ecosystem (2026-09). Extends
`recon-and-methodology` §2: when OSINT recon shows infostealer compromise on the org
(financial-sector targets especially), pivot through Cavalier (Hudson Rock) BEFORE
assuming credentials are invisible.

The user's CLI lives at `C:\Users\Admin\pentest\cavalier\cavalier_cli.py` (token-based
JWT flow; commands: domain/urls/cookies/apps/av/assets/employees/stealer).

## 1. API pattern the CLI truncates

`cavalier_cli.py` caps stealer output at 6000 chars — fine for `dir_tree`, but it silently
cuts the `credentials` array. Call the API directly for full plaintext:

```python
import urllib.request, json
def req(path, method='POST', body=None, jwt=None):
    headers = {'User-Agent':'Mozilla/5.0','Content-Type':'application/json'}
    if jwt: headers['Authorization'] = 'Bearer ' + jwt
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request('https://cavalier.hudsonrock.com'+path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read().decode())

# 1. Login with permanent token -> get session JWT:
j = req('/api/auth/token-login','POST',{'token': TOKEN})
jwt = j['token']

# 2. Domain stats & leaked URL discovery (unauthenticated / session token):
# Note: domain-search endpoints accept POST with {domains: [apex]}
counts = req('/api/domain-search/count','POST',{'domains':['target.com']})
urls = req('/api/domain-search/urls','POST',{'domains':['target.com']})
# -> yields employees_urls (OWA, VPN, SSO paths) & clients_urls (portals, logins)

# 3. List compromised employee machines (NEEDS JWT in Authorization header):
emp = req('/api/employees','POST',{'domains':['target.com']}, jwt=jwt)

# 4. Fetch machine details and full plaintext credentials (NEEDS JWT):
for m in emp.get('data', []):
    sid = m['stealer_id']
    detail = req('/api/employees/stealer','POST',{'stealerId': sid, 'domains':['target.com']}, jwt=jwt)
    creds = detail.get('data', {}).get('credentials', [])
```

Response fields that matter: `credentials` (url/username/PASSWORD in plaintext,
password_strength), `cookies` (domain -> cookie name/value/expiry), `computer_name`,
`operating_system`, `installed_software`, `field_visibility` (check `password: full`).

## 2. Workflow that worked

1. `domain <apex>` first: stealer counts, employee vs client split, families, timeline,
   sensitive URLs (OWA/SSO/HRIS/Oracle EBS login paths appear here — internal hostname gold).
2. Run the SAME commands on SIBLING apexes found via Shodan `org:` search (e.g. mbamc.com.vn
   for mbcapital.com.vn) — the sister domain had 15 infected employee machines vs 4, plus
   leaked internal URLs: hris., oracle. (E-Business Suite AppsLocalLogin.jsp), qltn.,
   matkhau.:9251/authorization.do, hotro.:8100.
3. `employees <apex>` -> list of stealer_ids with computer_name/date. Fetch each via
   `/api/employees/stealer` and print the `credentials` array (table: URL | username |
   password | strength).
4. Some logs return empty `credentials` but full `cookies` — still check cookie domains
   (`microsoftonline.com`, `google.com`, corporate domains) for session tokens.
5. `most_common_gmail` per machine is free attribution (maps corporate email <-> personal
   Google account) — useful for phishing-path analysis even without live creds.

## 3. What to extract for the report

- Username + plaintext password table per service, flagging Microsoft Online / OWA / SSO
  entries FIRST (single password often unlocks mail + VPN + SSO).
- Password pattern analysis per user (e.g. `123456` -> `123456c@` -> `123456Cc@` ->
  `123456Ccc@` variants) -> password-spray candidate list for other portals.
- Default-password detection across training/LMS portals (`123456`, `123`) = org-wide
  provisioning habit, not one user's weakness.
- Antivirus field: "Windows Defender only" on employee machines = endpoint-maturity signal.

## 4. Pitfalls

- **Env-var override mimics token expiry (field-verified 2026-09)**: the CLI embeds a
  working fallback token, but `export $(grep ... api_keys.env | xargs)` can load a
  CORRUPTED `CAVALIER_TOKEN` (mangled bytes in the env file) that overrides it — JWT
  exchange then fails with `Invalid token`, which looks exactly like expiry. Diagnostic
  order: run `env -u CAVALIER_TOKEN python cavalier_cli.py <cmd> <domain>` FIRST. If it
  works, the env var is the problem — unset it for all subsequent calls; don't request
  a new token. (One-line health check for the token itself:
  POST /api/auth/token-login {token} → expects `{"token": "..."}`.)
- stealer_id values contain spaces/brackets (`[VN]42.114.121.69`,
  `VN[83C84... ] [2022-05-30T19_02_42...]`) — pass them EXACTLY as returned, no trimming.
- `employees` on the main apex can return `[]` while `domain <apex>` shows employees>0 —
  the association lives under a sibling domain (check `urls` data for which corporate
  domains the stolen URLs reference).
- API errors come back as HTTP 200 with `{"success": false}` — check `.get('success')`.
- CLI output redirect (`> file`) then `json.load` fails: the CLI truncation breaks JSON
  validity; use the raw API calls instead for machine-readable results.
- **JWT Requirement on /api/employees (field-verified)**: While `/api/domain-search/*` accepts the session
  key directly, `/api/employees` and `/api/employees/stealer` strictly require the session JWT obtained
  via `/api/auth/token-login` in the `Authorization: Bearer` header. Requesting without it returns
  `HTTP 401 Unauthorized`.
- **Corporate vs. Personal URL mapping**: To filter out massive amounts of noise (personal Gmail, Facebook,
  shopping logins) inside the `credentials` array, filter entries where `uzbrussel` or the target domain
  string is present in `url` or `username`. This instantly isolates corporate SSO/VPN/OWA credentials.
- **`employees` cmd prints only 4000 chars** (`[:4000]` in the CLI) — the JSON is cut mid-record
  and `json.load` fails with "Expecting property name". For machine-readable output use the raw
  `/api/employees` call (§1) or regex-extract fields (`stealer_id`/`stealer_family`/
  `date_compromised` via `re.findall` over key-value pairs) instead of parsing the truncated dump.
- **`urls` output = internal-topology intel layer**: rank the returned `employees_urls`/
  `clients_urls` by their hit counts — OWA logon.aspx (34 hits), hris./home.aspx (24),
  oracle./oa_html/appslocallogin.jsp (10), matkhau.:9251/authorization.do, hotro.:8100.
  Hostnames that are NXDOMAIN externally = split-horizon/internal-only → they become the
  phishing/AiTM target list, and the odd ports (9251, 8100) constrain internal access mapping.
- **Dead-DNS subs found in `urls` output (field-verified 2026-09, second session)**: same
  pattern recurred on a VN telco target — `kpi.`, `cskh.`, `owa.`, `autodiscover.` were
  NXDOMAIN today but present in `clients_urls`/`employees_urls` with real hit counts.
  These are the Host-header-brute wordlist: probe them on the target's shared web /24s
  (the IPs already hosting 10+ live subs) since vhosts often outlive the DNS record.
- **`apps`/`av` output = spray-surface prioritization**: `sensitive_apps` returns keyword
  hits like `auth`/`owa`/`sso` — their presence means stolen creds/cookies exist FOR those
  exact services; rank password-spray targets in that order (OWA first: EWS Basic auth
  usually lacks MFA). `av` field percentages ("Not Found"/"None" ≈ no AV) gauge endpoint
  maturity for the report's exec summary.
- **Compromise-recency check**: `lastUserCompromised`/`lastEmployeeCompromised` timestamps
  in `domain <apex>` output — a date within days/weeks of the run means fresh creds are
  likely still valid; quote it in the report as the spray-success likelihood signal.
