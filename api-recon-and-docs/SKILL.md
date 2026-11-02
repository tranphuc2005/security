---
name: api-recon-and-docs
description: >-
  API reconnaissance and documentation review playbook. Use when discovering endpoints, schemas, versions, OpenAPI specs, hidden docs, and surface area for API testing.
---

# SKILL: API Recon and Docs — Endpoints, Schemas, and Version Surface

> **AI LOAD INSTRUCTION**: Use this skill first when the target is a REST, mobile, or GraphQL API and you need to enumerate endpoints, documentation, versions, and hidden surface area before exploitation.

## 1. PRIMARY GOALS

1. Discover all reachable API entrypoints.
2. Extract schemas, optional fields, and role differences.
3. Identify old versions, mobile paths, GraphQL endpoints, and undocumented parameters.

## 2. RECON CHECKLIST

### JavaScript and client mining

```bash
curl https://target/app.js | grep -oE '(/api|/rest|/graphql)[^"'\'' ]+' | sort -u
```

### SPA / micro-frontend API map extraction (verified on GlobalSign Atlas, MIC BPM, Hudson Rock Cavalier, Honda Loyalty UAT 2026)
For React/Vite or Vue single-spa + Webpack/Vite Module Federation frontends, the full API surface is recoverable without auth:
1. Fetch the entry HTML → grab `config.js` / `remotes.js` (often public, sometimes leaks client secrets — check for `CLIENT_SECRET`, `clientSecret` keys) and the bootstrap chunk list (`/assets/*.js`, `mf-manifest.json` per remote).
2. Download all chunks; grep for base-url resolver patterns (`BASE_URL`, `baseURL`, `API_SERVICE`), endpoint templates (backtick strings with `${BASE}` and `{placeholder}` path params — often OpenAPI-derived, e.g. `orders/{order_id}/files`), and interceptor code for exact auth headers (MIC BPM: custom `sessionId` header alongside Bearer).
3. Module Federation: `mf-manifest.json` lists every exposed JS asset — download all for the deepest endpoint set (payments MFE yielded 138 endpoints at MIC BPM).
4. **Mobile-app webview SPAs are a bonus target**: when the mobile app opens a webview (e.g. lucky-draw/loyalty), the SPA bundle exposes the *gateway* API surface the native app never shows in Burp. Honda: `hvn-sdk-uat.honda.com.vn/assets/index-*.js` → gateway host + `api/master-data-service/*`, `api/transaction-service/reward-360/*`, `api/user/share-login`. Lazy chunks (`assets/<Name>-<hash>.js`) carry per-feature services (`GameService`, `GiftSerialService`, `urls-*.js` is the endpoint map). Get the SPA's auth token from the app API that provisions the webview (Honda: `POST /api/loyalty/webview-url` → HS256 JWT with phone+memberId) — captured in Burp history.
5. Headless login when ROPC/password grant is disabled: replay Authorization Code + PKCE with curl (authorize → /u/login/identifier → /u/login/password → /authorize/resume → code → token). Discover allowed callbacks by reading Auth0 `Callback URL mismatch` errors until one redirects (302). For Keycloak: parse login form `action`, POST credentials with cookies, take `code` from redirect, exchange at the app's token bridge (e.g. POST /api/keycloak/v2/users/token {authCode, redirectUri}).
6. **Token-exchange flows**: some platforms expose a `/tokenaccess` page that accepts a query-param token → POST `/api/auth/token-login {token}` → returns JWT Bearer. Cache JWT for 24h. **Field naming pitfall**: backend may expect camelCase (`stealerId`) even when frontend uses snake_case in variable names — always probe with variations if 400 "field required" appears. (See [Hudson Rock Cavalier API reference](references/hudsonrock-cavalier-api.md) for complete endpoints, reverse-engineered payloads, and CLI client).
7. **Gateway `/` → 302 `/swagger`**: AWS/NGINX API gateways often redirect root to a swagger UI even when `/swagger/v1/swagger.json` 404s — try doc paths on both the gateway host and any sibling `portal-gw`/`sdk-gw` hostnames (Honda: `hvn-sdk-gw-loyaltyos-uat` 302→/swagger, sibling `hvn-portal-gw-loyaltyos-uat` serves `/file/get-file/<uuid>` assets).

### Common documentation and schema paths

```text
/swagger.json
/openapi.json
/api-docs
/docs
/.well-known/
/graphql
/gql
```

### Version and product drift

```text
/api/v1/
/api/v2/
/api/mobile/v1/
/legacy/
```

## 3. WHAT TO EXTRACT FROM DOCS

- optional and undocumented fields
- admin-only request examples
- deprecated endpoints that may still be active
- schema hints like `additionalProperties: true`
- parameter names tied to filtering, sorting, IDs, roles, or tenancy

## 4. NEXT ROUTING

| Finding | Next Skill |
|---|---|
| object IDs everywhere | [api authorization and bola](../api-authorization-and-bola/SKILL.md) |
| JWT, OAuth, role claims | [api auth and jwt abuse](../api-auth-and-jwt-abuse/SKILL.md) |
| GraphQL or hidden fields | [graphql and hidden parameters](../graphql-and-hidden-parameters/SKILL.md) |
| strong auth boundary but suspicious business flow | [business logic vulnerabilities](../business-logic-vulnerabilities/SKILL.md) |