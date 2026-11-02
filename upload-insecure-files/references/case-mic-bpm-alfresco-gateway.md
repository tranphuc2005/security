# Case study: Enterprise Java file-service behind API gateway (MIC BPM, Sep 2026)

Session-specific detail from a real assessment. Reuse as a checklist when a
target matches the profile: SPA frontend + Keycloak/OIDC + Apache APISIX +
F5 BIG-IP + Spring microservices + Alfresco-style content store.

## 1. Target profile fingerprint

- SPA login page served by gateway; `mf-manifest.json` / `remoteEntry.js`
  = module-federation micro-frontends (Vite) — enumerate them, each MFE's
  `main-*.js` exposes that domain's full endpoint map and axios base names.
- Error envelope `{"httpStatus":400,"code":"MEA000001","clientMessageId":...,"path":"/svc/v1/...","data":null}` = Spring custom exception handler.
- Generic Tomcat 400 HTML page only on malformed URI (e.g. raw ghost chars in
  query) — confirms Tomcat behind the gateway even when all API errors are JSON.

## 2. Headless Keycloak/OIDC login (reusable)

Works for both Auth0 and Keycloak login forms when only browser creds exist:

```
1. GET  /realms/<r>/protocol/openid-connect/auth?client_id=<id>&redirect_uri=<app>&response_type=code&scope=openid
        → save cookies, extract <form action=...> (contains session_code)
2. POST form action with username/password (url-encoded, cookies) → 302 Location: <app>?code=...
3. Exchange code at the APP's own token endpoint, NOT Keycloak's:
     Auth0 SPA:  POST <auth0-domain>/oauth/token {grant_type:authorization_code, code_verifier, code, redirect_uri, client_id}
     Keycloak:   POST <app>/api/keycloak/v2/users/token {authCode, redirectUri}
   → returns {token (JWT), sessionId, refresh_token}
4. Authenticated API calls need BOTH `Authorization: Bearer <token>` AND the
   app-specific session header (here: `sessionId: <uuid>`).
```

Password grant / ROPC was disabled on both — the browser-form replay above is
the reliable fallback. Tokens lived ~30 min; re-run the flow to refresh.
For Auth0, refresh_token rotates on each use (old one dies: invalid_grant).

## 3. Custom Alfresco-like file service behavior (verified)

Endpoints (the ONLY real ones; everything else 404):

```
POST /api/alfresco/v1/files/upload?autoRename=true|false   (multipart, field "files")
GET  /api/alfresco/v1/files/download-stream?nodeId=<uuid>  (Accept: application/octet-stream)
```

- Field name for upload is `files` (plural). Import/batch endpoints elsewhere
  in the app use field name `file` (singular) — wrong field name = generic
  "User input error", not "missing parameter".
- Upload response: `[{id, name, legacyName}]` — `name` is BASENAME-SANITIZED;
  `legacyName` echoes the raw submitted name (traversal strings included) but
  is NOT used for storage. Filename traversal is dead on this service.
- Download always: `Content-Type: application/octet-stream`,
  `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`. No inline render. `?filename=`, `?inline=`,
  `?disposition=`, `?contentType=`, `?format=` all ignored.
- nodeId is the ONLY lookup key: UUIDv7 (time-ordered). Traversal, URLs,
  `workspace://SpacesStore/...`, `.jsp` suffixes appended to a valid uuid —
  all 404. Range header honored (200 full, ignores range).
- IDOR: download accepts ANY valid nodeId with only a Bearer token; verified
  by replaying a nodeId from another user's captured request → bytes served.
- Extension blocklist (blocked): jsp php php3 phtml asp aspx cgi pl sh jar
  shtml shtm xml(properties fine, web.xml blocked)
- Allowed (notable): jspx jspf jspa do action ashx asmx cfm rb war ear class
  groovy ftl vm jsp2 jsf jws bsh nsp tag xsd xsl wsdl dtd json yaml yml
  properties log svg eps mvg m3u8 tar zip pdf docx xlsx
- `.war`/`.ear` upload OK but NOT deployed (guessed app URLs → SPA fallback).
- `.exe` upload → gateway 503 (F5 HTML error page), i.e. WAF-level block,
  distinguishable from app-level `MEC000007 Forbidden` (400 JSON).

## 4. WAF behavior (F5 BIG-IP in front)

- Literal `%pipe%` ANYWHERE in request body → connection killed (curl HTTP:000).
  Bypass: PostScript octal escapes `\160\151\160\145` = `pipe` (upload OK),
  also NUL/tab/newline inside the keyword.
- Traversal in query params (`..%2f`, `%252e`) → connection killed.
  Raw ghost chars (阮/丯) in query → Tomcat 400 page (passes WAF, dies at Tomcat).
- `X-Frame-Options` appears TWICE with conflicting values
  (`SAMEORIGIN` + `allow all`) and typo'd `X-XSS-Protectios` — F5 config bug,
  worth one line in a report (header injection defense weakened).
- APISIX normalizes `/api/svc/v1/../../other/v1/endpoint` → routes to other
  service (works, but auth context unchanged — normalization, not a bypass).

## 5. Spring gateway 404 vs catch-all

- Truly unmapped path → `{"code":"404","message":"Không tìm thấy API ..."}`
- Mapped path, wrong verb → `"Request method 'X' is not supported"`
- CRITICAL: ALL paths under an existing prefix (e.g. `/files/<anything>`) return
  the "method not supported" error — do NOT enumerate sub-routes this way;
  extract real routes from the JS bundle (`S0+\`/...\`` template strings).

## 6. Endpoint extraction from module-federation JS bundles

```
GET /config/remotes.js               → list of MFE names + remoteEntry URLs
GET /fe/<mfe>/mf-manifest.json       → exposes[] with js asset lists
GET /fe/<mfe>/assets/main-*.js       → grep `S0+\`...\`` for endpoint templates
```

The gateway shell bundle defines `BASE_API` maps (`/api/<domain>/v1`).
Search bodies for `${S0}/...` and constants like `S0="api/<domain>/v1"`.
POST search endpoints accept `{}` and return paginated data (totalElements cap
observed 10000). Branch/tenant scoping enforced server-side via JWT claims
(filter params for other tenants returned 0 rows, not errors).

## 7. What stalled RCE here (honest negative map)

STORE-stage achieved (war, jspx, gs.eps with %pipe% payload all persisted);
no PROCESS trigger exists on the file service (no transform/rendition/preview
endpoint), and SERVE is attachment-only. The remaining untested trigger is a
business "print" endpoint (`/payments/v1/termination-contract/print?typeFile=`)
whose exact id-parameter format couldn't be derived from the JS alone —
needs one captured browser request to reproduce. Lesson: when the JS bundle
hides the parameter contract (server-built query), stop fuzzing param names
and capture ONE real UI request instead — cheaper than 30 blind probes.
