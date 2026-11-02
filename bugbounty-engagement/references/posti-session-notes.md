# Session Notes — Posti Bug Bounty (Intigriti), 2026-09-04

Reference for the intake/triage patterns in SKILL.md — condensed field observations.

## Program facts
- Platform: Intigriti, program `posti/postibugbounty`, program UUID `6c8455c8-66b7-4360-bc6d-45b854c6fa85`
- 45 asset rows: 43 Tier 2 (41 URL + 1 Android `fi.itella.posti.android` + 1 iOS `410789057`), 2 out-of-scope
- Bounty: Low €100 / Medium €200 / High €500 / Critical €1000 / Exceptional €2000
- RoE: header `X-Bug-Bounty-Intigriti: <username>`, UA `Bug-Bounty-Intigriti - <username> -`, ≤ 2 req/s, safe harbour applied
- Behavior clauses: demo unpaid orders in webshops but never complete a purchase; no intentional disruption; no disclosure to third parties

## Scope buckets after header pass (`curl -sI`, 12s timeout)
- AWS APIGW: gateway.posti.fi (403 MissingAuthenticationTokenException)
- Spring behind CloudFront: auth-service.posti.fi (404 root), todentaminen.posti.fi (200, ALB cookies AWSALB/AWSALBCORS)
- nginx/1.28.0 static portal: api.posti.fi (200)
- F5 BIG-IP: console.posti.com (200, BIGipServer cookie leak, `Server: Posti/1638-09-06`)
- Next.js: shop.posti.fi (`x-powered-by: Next.js`)
- CSP-heavy marketing: pro.posti.fi (Contentful + Salesforce + kindly.ai chatbot, 'unsafe-eval' in script-src)
- S3+CF static: mfa.posti.fi, cdn.posti.fi (403), nextshipping.posti.fi (200)
- No A-record response: partnerservice.posti.fi, piicc.posti.fi
- AWS ELB: orgadmin-ext.prd.account.posticloud.fi (403)
- id.posti.fi: 404 on `/` — path discovery needed before anything else

## Endpoint harvest from api.posti.fi docs portal (passive, no fuzzing)
- OpenAPI spec: `https://api.posti.fi/tracking/7/api.json` (OpenAPI 3.1, bearer-key security)
- OAuth token: `https://oauth2.posti.com/oauth/token` (client_credentials, HTTP Basic)
- Gateway auth: `https://gateway-auth.posti.fi/api/v1/token` (POST → 400 "Missing client credentials")
- Gateway base: `https://gateway.posti.fi/2025-04` (+ `/labelless/{sendingCode}` routes from docs)
- UAT base: `https://connect.posti.fi/parcel-uat/v1/errandCodes/JJFI6543210000012345` (returned app error page)
- Legacy plain-HTTP host: `http://interfaces.itella.com`
- GLUE token: `https://ecom-api.posti.com/auth/token` (UAT: argon.ecom-api.posti.com)
- OAuth dynamic registration: `https://krypton.api.posti.fi/oauth/register` (HTTP 000 from this network)
- Tracking number format: `JJFI` + 16 digits
- Pitfall hit: `https://api.posti.fi/openapi.json` returns the HTML landing page with 200 — verify content-type before parsing

## F5 BIG-IP cookie (endian pitfall live example)
Cookie: `BIGipServer~PSTILB07_MESE-DMZ~console.posti.com_pool=rd20o00000000000000000000ffffc0a88102o6913`
- Network-order hex `c0a88102` → 192.168.129.2 (private) — the plausible internal-LB reading
- Little-endian → 2.129.168.192 (RIPE public) — would imply a public backend; verify with a canonical decoder before reporting
- Port `6913`: hex-interpretation 26899 vs decimal 6913 — same ambiguity
- Flags: `Httponly; Secure` (HttpOnly honored case-insensitively per RFC 6265)

## Unverified leads for next session
- QuickSight asset (`quicksight.aws.a…`, truncated in UI) — check public dashboard sharing
- Content discovery on id.posti.fi / auth-service.posti.fi (404 roots; CSP `frame-ancestors https://todentaminen.posti.fi` implies embedded iframe auth)
- todentaminen.posti.fi CSP `frame-src *.posti.fi *.posticloud.fi *.netposti.fi *.omaposti.* *.itella.* *.postinext.*` → subdomain takeover on any of these wildcards enables auth-flow phishing
- wayback/gau + GitHub dorks still pending from the completeness audit