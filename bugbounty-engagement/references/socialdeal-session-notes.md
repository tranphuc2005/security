# Social Deal (Intigriti) — session notes 2026-09-04

## Program snapshot
- Platform: Intigriti, public/open. Tier 2: Low €25 / Med €50 / High €200 / Crit €350 / Excep €750.
- Validation SLA bonus €25 (Excep/Crit 2 days, High 5). €50 fix-verify bonus.
- Scope: www.socialdeal.nl, socialdeal.nl/inspirations/bluemonday/, www.whynot.com/, one orderlist URL, Android app.nl.socialdeal, iOS 910898851.
- Stack (from program description): AWS ASG + EC2 Linux, PHP 7.4/8.1, MariaDB, NuxtJS (Tier 2/3), per-domain ASGs with DB access / internal APIs.
- RoE: max 2 req/s, NO automated scanners (IP block), self-register with @intigriti.me (+ rejected in emails).
- Test creds (do NOT change password): intigriti-1@socialdeal.nl / rR7R281kz%!F ; intigriti-2@socialdeal.nl / r92x%4bRbMys. Reservations: book ≥5 working days ahead, auto-reset after 2.
- Big out-of-scope list: username/email enumeration, CSRF-low, rate-limit issues, clickjacking/iframes, email spoofing/SPF/DMARC, API-key disclosure w/o impact, CORS non-sensitive, missing headers/cookie flags, blind SSRF w/o impact, upload w/o proof, subdomain takeover w/o full takeover, self-XSS, same-site scripting, reverse tabnabbing; mobile: no pinning/root-detection/obfuscation requirements, runtime hacks needing jailbreak.

## Infra map (verified)
- www.socialdeal.nl → AWS ELB public-production-default-1472906072.eu-west-1.elb.amazonaws.com (18.202.3.21, 63.34.198.50), Apache, PHP; cookie `Socialdeal` secure+HttpOnly; PHP 7.4-era session name.
- images.socialdeal.nl → CloudFront; media.socialdeal.nl → CDN for /js and /web/js bundles (vue.min.js, jquery 1.12.4, bootstrap 3.4.1, components/desktop/library hashed bundles).
- whynot.com → whitelabel NuxtJS (2.1MB SSR page), cookie `wl_tokens` Domain=.whynot.com SameSite=None + `browser_unique`.
- wallet.whynot.com → AWS ELB landing "Bedankt. Het domein is nu gekoppeld." — domain-claim page, NOT a bug.
- Subdomain guesses (partners/api/admin/cms/staging/be/de/app...) → NXDOMAIN (wildcard-free).

## Key techniques / results
- Intigriti SPA: `browser_console(document.body.innerText)` after cookie-dismiss returns the whole program (FAQ creds, stack hints, full OOS) in one call.
- Nuxt bundle mining (b2.js): `$config.{baseApiUrl,walletApiUrl,metaBaseApiUrl,availabilityUrl,inspirationsUrl}` + `proxy:{path:"/api-*"}` pairs; API client methods like `claim → POST /claim/`, `authLogin → GET /auth/auto-login/`.
- Frontend proxies: /api-meta → 301 http://meta-api.socialdeal.local/api-meta/ ; /api-availability → 301 http://availability.whynot.local/... (internal .local hostnames leak). /api-wallet → Laravel-style JSON 404, `Vary: Authorization`; POST /api-wallet/claim/ → 500 empty body unauthenticated.
- Anonymous JWT `wl_tokens` (RS256, iss api.whynot.nl, aud website, data.identifier 408932347 increasing) — raw value only obtainable from Set-Cookie response header (HTML shows it literal-masked with `...` inside).
- Google Maps key masked server-side (`AIzaSy...4WFA`), maps JS endpoint returns 200 even masked; key disclosure is OOS anyway — do not chase.
- www.socialdeal.nl: /account/ 200 for guests (login page only, not an unauth data bug); robots.txt Disallow harvest: /partners/*, /account/*, /cart/add/*, /bedrijf/*/deal/, /login/*, /inloggen/*; /partners/login → 301 → 404; /.env + /composer.json → 403 (Apache rules); wp-admin/wp-login.php → 301 (no WP confirmed).

## Open leads (for next session)
1. Register @intigriti.me account; walk purchase flow with provided creds; IDOR on /orderlist/<guid1>/<guid2>/ (two-GUID pattern — try altering).
2. With a logged-in session, capture real /api-wallet + /auth/auto-login/ requests in browser (SSR proxies only expose the boundary; params unknown).
3. /api-wallet/claim/ JSON type-juggling (arrays, empty string, nested) for error-based leaks pre-auth.
4. JWT: look for jwks/public key; test RS256→HS256 confusion only with proof of key fetchability.
5. Laravel-style API on socialdeal.nl: enumerate /api/* namespaces carefully ≤2 req/s.

## Workspace artifacts
C:\Users\Admin\pentest\socialdeal\: program.md, recon-findings.md, whynot.html, hdr.txt, wl_token.txt, nuxt/*.js (bundles), extract_cfg.py.
