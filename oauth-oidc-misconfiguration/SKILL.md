---
name: oauth-oidc-misconfiguration
description: >-
  OAuth and OIDC misconfiguration testing playbook. Use when reviewing redirect URI handling, state and nonce validation, PKCE, token audience, callback binding, and identity-provider trust flaws.
---

# SKILL: OAuth and OIDC Misconfiguration — Redirects, PKCE, Scopes, and Token Binding

> **AI LOAD INSTRUCTION**: Use this skill when the target uses OAuth 2.0 or OpenID Connect and you need a focused misconfiguration checklist: redirect URI validation, state and nonce handling, PKCE enforcement, token audience, and account binding mistakes.

## 1. WHEN TO LOAD THIS SKILL

Load when:

- The app supports `Login with Google`, GitHub, Microsoft, Okta, or other IdPs
- You see `authorize`, `callback`, `redirect_uri`, `code`, `state`, `nonce`, or `code_challenge`
- Mobile or SPA clients rely on OAuth or OIDC flows

For token cryptography and JWT header abuse, also load:

- [jwt oauth token attacks](../jwt-oauth-token-attacks/SKILL.md)

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| `state` handling | missing, static, predictable, or not bound to user session |
| `redirect_uri` validation | prefix match, open redirect chaining, path confusion, localhost leftovers |
| PKCE | missing for public clients, code verifier not enforced, downgraded flow |
| OIDC `nonce` | missing or not validated on ID token return |
| token audience and issuer | weak `aud` / `iss` checks, cross-client token reuse |
| account binding | callback binds attacker identity to victim session |
| scope handling | broader scopes granted than the user or client should receive |

## 3. QUICK TRIAGE

1. Map the full flow: authorize, callback, token exchange, logout.
2. Replay callback flows with altered `state`, `nonce`, and `redirect_uri`.
3. Compare SPA, mobile, and web clients for weaker validation.
4. Check whether one provider account can be rebound to another local account.

## 3.5 HEADLESS AUTH0 SPA LOGIN VIA CURL (field-proven)

Modern Auth0-protected SPAs usually disable the password/ROPC grant (`unauthorized_client`).
You can still obtain a Bearer token for API testing with pure curl — full 7-step PKCE
Universal Login walkthrough, the redirect_uri error-oracle trick, and gotchas:

- [references/headless-auth0-login.md](./references/headless-auth0-login.md)

The resulting token's claims (`permissions`, custom `ns|account_id`) double as a free
BFLA/tenant-model map for the downstream API.

Keycloak variant (no PKCE needed — the app gateway exchanges the code; API calls need
BOTH `Authorization: Bearer` and `sessionId` headers; the token response's `userInform`
leaks the org model for free): [references/headless-keycloak-login.md](./references/headless-keycloak-login.md)

## 3.6 KEYCLOAK RECON CHECKLIST (field-proven, pre-auth)

1. **Never guess client_id — capture it from the app's real redirect chain**:
   `curl -skL -o /dev/null -w '%{url_effective}' https://app.example.com/` — the final
   URL IS the authorize request (client_id, realm, scope, code_challenge_method). A
   guessed client_id produces misleading 400s on every subsequent redirect test.
2. Realm-enumeration oracle: `/auth/realms/<name>/.well-known/openid-configuration`
   → 200 = realm exists, 404 = not. Sweep dev/test/staff/internal/employee names on
   BOTH the prod SSO host and any `-dev` SSO host — they often resolve to the SAME
   Keycloak instance (identical realm set).
3. redirect_uri strictness (with the REAL client_id): attacker.com,
   victim.com.attacker.com (suffix), a sibling prod subdomain, and a custom scheme
   (`app://cb`) — every one should return 400.
4. ROPC probe: `POST <realm>/protocol/openid-connect/token` with
   `grant_type=password&client_id=<real>` → `unauthorized_client` = correctly disabled
   for a public client; `invalid_grant`/token response = enabled → spray surface.
   (Note: a WRONG client_id yields `invalid_client` — retry with the captured one
   before concluding anything.)
5. Self-registration: GET
   `.../protocol/openid-connect/registrations?client_id=<real>&redirect_uri=<real>&response_type=code`
   — if it renders the LOGIN page instead of a registration form, registration is OFF.
6. `master` realm + `/auth/admin/master/console/` reachable = the admin brute-force
   surface. Keycloak version usually stays hidden when the welcome page is themed —
   don't burn time hunting it; the probe results above are the actionable signal.

## 4. RELATED ROUTES

- CORS or cross-origin token exposure: [cors cross origin misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)
- XML federation or enterprise SSO: [saml sso assertion attacks](../saml-sso-assertion-attacks/SKILL.md)
- CSRF-heavy login or binding bugs: [csrf cross site request forgery](../csrf-cross-site-request-forgery/SKILL.md)