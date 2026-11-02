---
name: bugbounty-engagement
description: >-
  Bug bounty engagement workflow: program scope extraction from platforms
  (Intigriti/HackerOne/Bugcrowd), RoE compliance (required headers, user-agent,
  rate limits), passive-first recon ordering with completeness self-audit, and
  target triage (API doc portals, OpenAPI spec verification, LB cookie leaks).
  Use when the user names a bug bounty program or asks for redteam work on a
  program target.
---

# SKILL: Bug Bounty Engagement

> Program-intake layer for bounty work. The generic recon/vuln playbook lives in `recon-and-methodology` — load both for bounty targets; do not duplicate playbook content here.

## 1. Authorization model (decide once, don't re-ask)

- Target has a public program (Intigriti/HackerOne/Bugcrowd/YesWeHack/VDP) → authorized; run the full loop below.
- Target has NO public program → passive/OSINT only. State the constraint once, plainly; do NOT ask the user to prove authorization for each target.
- User states the target is in a **PRIVATE/invite-only program** → treat as authorized for hunting, but scope/RoE pages are inaccessible BY DESIGN: private programs do not appear in platform directories and profile URLs 404. Do NOT re-run the §1.5 existence ladder (platform searches, security.txt hunting) for it — field lesson (2026-09, UZ Brussel): the agent re-verified Intigriti/H1/Bugcrowd/YesWeHack AFTER the user explicitly said "private program" — a wasted turn. Skip straight to hunting on the already-recon'd assets under generic platform RoE as baseline: no automated scanners, ≤2–5 req/s, no destructive tests, no scanner-found submissions.

### 1.5 Phase 0 — confirm the program actually exists (5 min, BEFORE any recon)

Never assume a program exists because the user frames the target as "bug bounty" — verify first. Field lesson (2026-09, UZ Brussel): a full redteam recon + CVE-probe pass ran productively for an entire session before the bounty question surfaced, and the org had NO program — everything found was unsellable. Ordered checks (all cheap, all unauthenticated):
1. **Intigriti public programs search** (SPA): browser → program list → type target name in Search → `browser_console(expression="document.body.innerText")` → "No results"?
2. **Platform profile 404 checks** (curl status): `hackerone.com/<target>`, `bugcrowd.com/<target>`, `yeswehack.com/programs/<target>`.
3. **security.txt** on apex + www.
4. **Sitemap crawl for a disclosure page**: enterprise CMS (Liferay) = sitemapindex → fetch CHILD sitemaps for real page URLs (grepping the INDEX for page keywords returns nothing); grep pages for disclosure/veilig/meldpunt. A contact/"Meldpunten" page with only DPO/whistleblower/feedback channels = no security intake exists.
5. **Search fallback**: `curl -X POST https://html.duckduckgo.com/html/ --data "q=..."` — also surfaces the program detail URL for §2.
If NO program: report with evidence, warn DPO-email disclosure = no bounty + no safe harbour (active testing = legal exposure), offer pivot to same-sector programs surfaced in step 1 (methodology carries over ~90%). Full recipe + UZ Brussel → UZ Leuven example: [references/program-existence-verification.md](./references/program-existence-verification.md)

## 2. Program intake (scope + RoE)

### Intigriti program pages (SPA — field-verified recipe)
1. `curl` / web_extract on the program URL returns only the SPA shell; the public REST endpoint (`/api/core/public/programs/<uuid>/detail`) requires auth. Do not burn time here.
2. `browser_navigate` the public program URL; dismiss the cookie banner first.
3. **Full text in one call (field-proven 2026-09, Social Deal)**: `browser_console(expression="document.body.innerText")` returns the ENTIRE program text — description, bounty tiers, RoE, assets, in/out-of-scope, FAQ, activity — with no truncation. Prefer this over Expand-all+snapshot (truncates ~460 lines) and over browser_vision.
4. If a table still needs structure: click **Expand all**, snapshot; if output truncates do NOT re-snapshot — one `browser_vision` call with a targeted question reads all rows in a single call.
5. Mine the FAQ for shared test credentials (usernames/passwords + "do not change password" clauses) and self-registration email constraints (e.g. must use @intigriti.me, '+' rejected by the system).
6. Mine the description for stack hints — "worst-case scenarios" sections leak infra (e.g. "AWS ASG EC2 Linux PHP 7.4/8.1, MariaDB, NuxtJS, per-domain ASGs with DB access") → this shapes the whole recon.
7. Record per-asset: tier, type (URL / Android / iOS), and the OUT-OF-SCOPE list — out-of-scope hosts matter as much as in-scope; huge OOS lists (user enum, CSRF, rate-limit, clickjacking, email spoofing, CORS non-sensitive...) prune wasted effort early.

### RoE compliance (bake into every probe)
- Intigriti pattern (Posti): header `X-Bug-Bounty-Intigriti: <username>`, UA `Bug-Bounty-Intigriti - <username> -`, automated tooling ≤ 2 req/s.
- Attach the RoE header + UA to EVERY curl/ffuf/nuclei/httpx call — violations void safe harbour.
- Capture behavior clauses: e.g. webshops — may demo an unpaid order, must NOT complete a real purchase; no intentional disruption (demonstrate plausibility, stop before impact).

## 3. Passive-first ordering + completeness pitfall

When policy limits a target to passive recon, run the FULL passive tier — "passive-only" must not degrade into "partial passive":
- crt.sh transiently 502s — retry later in the same session instead of silently dropping the highest-yield CT source.
- waybackurls/gau and GitHub dorks are passive and are NOT excluded by a passive-only constraint.
- Before reporting, self-audit coverage against the loaded playbook and list anything skipped honestly — users explicitly audit framework adherence ("did you follow the framework?").

## 4. Target triage order

Quick `curl -sI` pass across all in-scope hosts (short timeouts, RoE headers) to bucket by backend:
- AWS APIGW (`x-amzn-*` headers, `MissingAuthenticationTokenException`) → gateway; enumerate documented routes from public docs before any fuzzing.
- nginx static docs portal → mine it (§5).
- F5 BIG-IP (`BIGipServer` cookie) → decode with the §6 pitfall in mind.
- Next.js storefront → business logic, middleware bypass, checkout flow clauses.

## 5. Vendor API documentation portals (highest-yield endpoint source)

Company API portals (api.<target>.com landing pages) ship static per-API doc pages that enumerate the entire API estate INCLUDING non-production hosts:

```bash
# 1) harvest doc-page links from the portal index
curl -sk https://api.target.com/ | grep -oE 'href="[^"]*\.html"' | sort -u

# 2) grep EVERY doc page for company-domain URLs → surfaces UAT bases, legacy hosts, OAuth endpoints
for p in api-authentication.html api-orders.html api-tracking.html; do
  curl -sk "https://api.target.com/$p"; done \
  | grep -oE 'https?://[^"'"'"'<> ]+' | grep -iE 'target|legacy-brand' | sort -u
```

Field-verified (Posti, 2026-09): one docs portal yielded the public OpenAPI spec (`/tracking/7/api.json`), a UAT base path (`/parcel-uat/`), a legacy plain-HTTP host, the GLUE token endpoint, and the gateway-auth token endpoint — all without active probing.
Pitfall: `/openapi.json` on such portals may return the HTML landing page with HTTP 200 — verify content-type, not status code.

## 6. F5 BIG-IP persistence cookie decode — ENDIAN PITFALL

Cookie shapes: `BIGipServer<pool>=rd<r>o<ip-hex>o<port-hex>` (route-domain) or `<uint32>.<uint32>.<uint32>` (decimal).
Observed (Posti console.posti.com): `rd20o00000000000000000000ffffc0a88102o6913`
- Hex tail `c0a88102` read in network order → 192.168.129.2 (private).
- Little-endian reinterpretation → 2.129.168.192 (public RIPE space).
- Port `6913` → hex 26899 vs decimal 6913.

⚠️ Never report a decoded IP:port without confirming against a canonical F5 decoder — the two readings imply completely different findings (internal LB vs a public backend). Severity is low either way (info disclosure); `Httponly` is honored case-insensitively (RFC 6265), so browser-side theft is mitigated — the leak is that anyone reading the response sees LB topology.

## 6.5 Whitelabel NuxtJS sibling apps + JS-bundle API mapping (field-proven 2026-09, Social Deal/whynot.com)

Whitelabel platforms (one Nuxt app served under multiple brands: socialdeal.nl ↔ whynot.com) share the same API layer — recon ONE brand to map the whole estate.

**Bundle → API client mapping (works on any webpack/Nuxt build):**
```bash
# 1) Download referenced _nuxt/*.js bundles (respect rate limit: sleep 0.5-0.6 between pulls)
grep -oE '(src|href)="[^"]*\.js[^"]*"' page.html | sort -u

# 2) Find the proxy paths the SSR server exposes for internal APIs:
grep -ohE '\$config\.[a-zA-Z]+Url' *.js | sort -u        # → baseApiUrl, walletApiUrl, metaBaseApiUrl...
grep -ohE 'proxy:\{path:"[^"]+"' *.js | sort -u          # → /api-wallet, /api-meta, /api-availability

# 3) Map each frontend proxy to the class of API:
grep -oE '\{baseURL:e\.\$config\.[a-zA-Z]+,proxy:\{path:"[^"]+"' bundle.js   # baseURL↔proxy pairing

# 4) Enumerate API methods per client: {key:"claim",value:function(data){return this.post("/claim/",data)}}
grep -oE '\{key:"[a-z]+",value:function\(data\)\{return this\.(get|post)\("[^"]+"' *.js
```

**Probe the SSR proxy paths directly** — they're the auth boundary on the public host:
- 301 → `http://internal-name.<brand>.local/path/` = internal hostname leak (low; note it, move on)
- `Vary: Authorization` + JSON 404 errors = Laravel-style API mounted; POST returning **500 (not 401) without auth** = endpoint exists and crashes pre-auth → try JSON type-juggling payloads (`[]`, `""`, nested objects) for error-based info
- Runtime config values ($config.*) are injected only in the SSR HTML payload, minified as single letters (`walletApiUrl:iq`) — grep HTML for `var iq="..."` style assignments; plain regex over the raw HTML misses them because of URL-encoding (\u002F)

**Anonymous JWT from Set-Cookie (capture the raw token):**
- Sites mint an anonymous JWT on first GET (e.g. `wl_tokens` Domain=.apex SameSite=None). The cookie VALUE is often literal-masked in HTML (`eyJ0eX...vbl9` contains real `...` dots) — capture it from `-D hdr.txt` response HEADERS, never from the page body.
- `base64 -d` each `.`-segment: payload `{"iss":"api.<brand>","group":"website","aud":"website","data":{"identifier":408932347}}` — a large increasing identifier is an enum candidate (test: swap identifier, replay to sibling APIs). RS256 means no offline forgery; check for public key/jwks before attempting alg confusion.
- Minified config vars (clientId:dfj) resolve by scanning the HTML var-assignment table — write a small python script (regex `\b<var>\s*=\s*"..."` over the raw HTML); a shell python heredoc on Windows git-bash may be blocked, use a saved .py file instead.

## 6.6 Headless Auth0 PKCE login + Vite/React SPA API mapping (field-proven 2026-09, GlobalSign Atlas)

Modern SaaS portals front everything with an Auth0 tenant and serve a Vite/React SPA — no browser needed, curl gets you an authenticated API session in ~8 requests:

1. `/.well-known/openid-configuration` on the auth host → confirm tenant + enabled grants. Try the `password-realm` grant against `/oauth/token` FIRST (one request); `unauthorized_client` → fall back to the PKCE chain.
2. Never guess the callback: any `redirect_uri` mismatch returns a 403 page that **prints the mismatch detail**, so probing wrong paths is free — the bare origin (e.g. exactly `https://app.tld`) is usually the allowed callback for SPA tenants.
3. PKCE chain (cookie jar across ALL steps, Chrome UA): GET `/authorize` → 302 `/u/login/identifier?state=` → GET page, extract the **form** `name="state"` value (DIFFERS from the URL `state` — this is the #1 pitfall) → POST identifier (+`js-available=true&webauthn-available=true&is-brave=false&webauthn-platform-available=false&passkey-available=false`) → 302 `/u/login/password?state=` → POST credentials → 302 `/authorize/resume?state=` → GET → 302 back with `?code=` → POST `/oauth/token` JSON with `code_verifier`. Use the portal's own `audience` from its config (SPA is a public client: no client_secret, PKCE required).
4. API map from the bundle: portal root is a tiny Vite shell → `/config.js` (runtime env: ALL API bases, Auth0 client_id/audience, LaunchDarkly, sometimes a plaintext **CLIENT_SECRET** — report) → `assets/*.js` chunks. Grep chunks for backtick template literals containing `{placeholder}` (`orders/{order_id}`, `accounts/{account_id}/...`) and for base-resolver calls like `Se('account-mgmt/v1','API_BASE_URL')` to pair path↔base.
5. Probe matrix with the Bearer token: same API often reachable on two hosts (`api.tld/account-mgmt/v1/*` and `api.portal.tld/v1/*`). FastAPI-style error bodies (`description_key`) are an internal error taxonomy; test mass-assignment fields (always re-GET after a 204 — silent ignore is common), self-escalation via `PATCH /users/:id/roles` (usually blocked), and invitation role fields (role NAME vs role ID produce different, misleading errors — and that error split doubles as an email-format oracle).

Full curl chain + GlobalSign specifics: [references/globalsign-auth0-session-notes.md](./references/globalsign-auth0-session-notes.md)

## 7. Session output shape

Deliver: scope table → per-host recon table (host / stack / notes) → prioritized attack paths (RCE-focused per user profile) → next-step menu (content discovery / JS analysis / OpenAPI fuzz / wayback pull). Save under the target's workspace subfolder (see `pentest-workspace` convention).

Session-specific worked examples: [references/posti-session-notes.md](./references/posti-session-notes.md) (docs-portal mining, BIG-IP decode), [references/socialdeal-session-notes.md](./references/socialdeal-session-notes.md) (Nuxt whitelabel API mapping, anonymous JWT capture, FAQ cred mining), [references/program-existence-verification.md](./references/program-existence-verification.md) (Phase-0 program existence check + no-program pivot, UZ Brussel case).