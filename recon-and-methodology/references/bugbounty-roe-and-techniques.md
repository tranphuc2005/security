# Bug Bounty ROE + Field Techniques (session-verified)

## Intigriti program access (field-proven: Posti program)

Program pages are Angular/Stencil SPAs. The JSON API endpoints
(`/api/core/public/programs/<uuid>/detail`) return the SPA error page for
unauthenticated curl — do NOT burn time on them. Use the real browser:

1. `browser_navigate` to the program detail URL
2. Dismiss cookie banner if present (click "Accept All" or "Reject All")
3. `browser_click` the "Expand all" button in the Assets table
4. `browser_snapshot full=true` — if the asset table is truncated, use
   `browser_vision` with a question asking to enumerate every row + tier
5. Record: tier assignment per asset, asset TYPE (URL/iOS/Android), bounty
   ranges (Low/High/Critical/Exceptional × amount), and the RoE block:
   - required User-Agent string (e.g. `Bug-Bounty-Intigriti - <username> -`)
   - required request header (e.g. `X-Bug-Bounty-Intigriti: <username>`)
   - automated tooling rate cap (commonly max 2 req/s)
   - program-specific rules (webshops: test payment bypass allowed but never
     complete a real purchase; no intentional disruption)

Apply the header/UA to EVERY request from the first probe onward. The user's
Intigriti username must replace `<username>` — ask once when starting active
testing; placeholder is acceptable for passive-only recon.

## Unauthenticated token issuer probe pattern (field-proven)

POST `https://auth-service.<target>/api/v1/anonymous_token` (no body needed)
returned a fully-signed RS256 JWT pair (id_token + role_tokens[].token):

- header: `{"alg":"RS256","kid":"auth.<target>.openid.connect/v1","typ":"JWT"}`
- payload: iss, aud=anonymous, sub=Anonymous-<uuid>, role.type=anonymous
- The issuer is normal by design (guest tracking) — the LEAD is testing whether
  sibling APIs accept it. On the tracking API the token was rejected with
  `{"error":"invalid_token","error_description":"The token could not be verified"}`
  → audience mismatch, either by design or a real integration bug. Verdict
  requires a real account to compare behavior. Do not report prematurely.

Related surface probing (status codes only, unauthenticated):
- `/api/v1/token` POST with `{}` → 422 (accepts JSON — different contract to explore later)
- `/api/v1/login` without params → 422
- `/api/v1/login?redirect_uri=<bypasses>` → all 400/403 (suffix, @-userinfo,
  traversal, protocol-relative, unicode-dot) — allowlist is tight
- Baseline legit login: 302 → PingFederate `/uas/oauth2/authorization?client_id=<uuid>&response_type=code&scope=openid+userinfo&redirect_uri=<callback>/oidc_callback&state=<uuid>`
- `oidc_callback?code=test` → 400 (state/code validated)

## OAuth redirect_uri bypass test battery (all failed = hardened, field case)

1. suffix: `https://legit.evil.com/`
2. userinfo: `https://legit@evil.com/`
3. traversal: `https://legit.com/../evil.com`
4. protocol-relative: `//evil.com`
5. unicode dots: `https%3A%2F%2Flegit%2E%2Eevil%2Ecom`
6. bare evil domain
Expect 400/403 for all — record as "validated" in the report (positive finding
for the target's security posture, not a bug).

## F5 BIG-IP cookie decode (worked example)

Cookie: `BIGipServer~PSTILB07_MESE-DMZ~console.target.com_pool=rd20o00000000000000000000ffffc0a88102o6913`

```python
import socket, struct
parts = cookie.split("o")           # ['rd20', '<hex>', '6913']
hexip = parts[1][-8:]               # last 8 hex chars = IPv4-mapped
ip   = socket.inet_ntoa(struct.pack("<I", int(hexip, 16)))   # 192.168.129.2
port = int(parts[2], 16)                                     # 26899
```
Also captures the pool name (`~<app>~<vhost>_pool`) → DMZ naming convention.
Severity: info/low unless combined with other leaks.

## Split-horizon DNS leak sweep

Resolve the full CT-logged hostname list and flag any answer in RFC1918 space:
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`. Field case: dagster.* hosts in
a cloud-platform domain returned 10.x IPs in all four environments (dev/prd/
stg/tst) via public DNS. Reportable as infrastructure disclosure.

## Posti program — reference case summary (2026-09)

- Scope: 43 Tier-2 assets + 2 out-of-scope; RoE header/UA mandatory; ≤2 rps
- Stack: PingFederate auth (todentaminen.posti.fi/uas/), auth-service.posti.fi
  (token issuer), api.posti.fi (nginx, OpenAPI spec at /tracking/7/api.json),
  F5 BIG-IP LB (console.posti.com), AWS API Gateway (gateway.posti.fi),
  QuickSight in scope
- CT logs yielded 1000 hostnames; Wayback yielded auth endpoints + sequential
  numeric invoice/tracking IDs (IDOR test list for account phase)
- Split-horizon leak: dagster.*.posticloud.fi → 10.x via public DNS
- Third-party: esign.posti.com → posti.assently.com; admin.postikuori → Azure
  Front Door + Next.js /signin?callbackUrl= (open-redirect candidate, untested)

## Social Deal program — SPA login reverse-engineering case (2026-09)

- Platform: PHP/Laminas (Apigility) on api.socialdeal.nl, jQuery+Vue frontend,
  static assets on media.socialdeal.nl, payments via Mollie
- Program FAQ publishes shared test accounts; the FAQ password differed from
  what the user pasted — BOTH variants failed with "wrong password". Server
  distinguishes invalid-format email vs wrong password, so the account emails
  were confirmed valid with zero lockout risk. Stop after ~5 attempts and ask
  the triage contact to rotate shared credentials instead of guessing.
- Correct login contract (found in `desktop.js` handler `ajaxLogin`):
  `POST /login/` form-encoded, params `username` (or `login_email`) + `password`,
  headers `X-Requested-With: XMLHttpRequest` + `Referer: /login/`. Response on
  success: `{"redirectUrl": ...}`; on failure: typed JSON error naming the bad
  field (`email` invalid format vs `password` wrong) — param names can be
  derived by watching which field the error flips to across payload variants
  (`email` → 400 invalid-email, `login_email` → accepted, password error).
- The login modal is JS-injected (not in page source) — client-side email
  validation rejected automation-typed input before any server call, so the
  browser flow wasted effort. The curl path sidesteps the modal entirely.
- Lockout claim ("locks after 5 failed attempts") appeared only in the UI
  error text; the API level showed no rate limiting. Do not trust UI copy —
  but still self-limit attempts on shared test accounts.
- IDOR lead from scope asset itself: `/orderlist/<12-hex>/<12-hex>/` — dual
  hex ID structure to enumerate once a session exists.

## User workflow preferences (bug bounty sessions)

- Rank candidate attack paths by ROI (probability × payout) and state what's
  needed to proceed for each — the user picks the next vector, not the agent.
- Run the no-authentication work first; user supplies accounts later.
- When offering next steps, group them into "no-account needed" vs
  "needs account" so the user can choose without blocking.