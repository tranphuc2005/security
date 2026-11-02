# Headless Keycloak Login via curl (form login → gateway token exchange)

Field-proven on MIC BPM (auth-bpm.mic.vn, realm `bpm`, client `oauth`), 2026-09.
Simpler than Auth0 PKCE: the portal's own gateway endpoint exchanges the auth code
for the API token — no code_verifier needed.

## Flow (3 requests)

```bash
# 1. GET login page → session cookies + form action (contains session_code, changes per load)
curl -s -c jar.txt \
  'https://KC_HOST/realms/REALM/protocol/openid-connect/auth?client_id=CLIENT&redirect_uri=<APP_URL>&response_type=code&scope=openid'
ACTION=$(grep -oE 'action="[^"]+"' lp.html | head -1 | cut -d'"' -f2 | sed 's/&amp;/\&/g')

# 2. POST credentials (Keycloak form action URL-encodes everything)
curl -s -b jar.txt -c jar.txt -D h.txt \
  --data-urlencode "username=$USER" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "login=Sign In" "$ACTION"
# 302 → Location: <APP>/?session_state=..&code=<AUTH_CODE>

# 3. Exchange code at the APP's gateway (NOT Keycloak /token — that client is public,
#    gateway injects the client_secret server-side)
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"authCode":"<AUTH_CODE>","redirectUri":"<APP_URL>"}' \
  '<APP>/api/keycloak/v2/users/token'
# → {"data":{"sessionId":"..","token":"eyJ..","userInform":{...}}}
```

## Then: call the API with TWO headers

Keycloak-backed enterprise apps often check both the JWT and a server-side session:

```
Authorization: Bearer <data.token>
sessionId: <data.sessionId>
```

## Gotchas

- The `code` in step 2 is single-use and short-lived; exchange immediately.
- `userInform` in the token response leaks org model for free: branchId, departmentCode,
  positionCode, hrCode → the authorization scoping dimensions to test for BOLA.
- Keycloak login is NOT rate-limited aggressively in default realms but Cloudflare/F5 in
  front may be; wrong-password returns the generic "Tài khoản hoặc mật khẩu không chính
  xác"-style message (no user enumeration — verify before claiming).
- Token lifetime ~15–30 min. No refresh_token is returned by the gateway exchange —
  when `401 Unauthorized` starts appearing on endpoints that worked, just redo the 3-step
  login (cheap) or hit the app's own refresh endpoint if one exists
  (e.g. `/api/keycloak/v1/users/refresh-token`, requires `sid` param).
- ROPC probe is worth 1 request: `grant_type=password&client_id=<public-client>` → usually
  `unauthorized_client` in prod.
- The well-known config (`/realms/<r>/.well-known/openid-configuration`) leaks supported
  grant types incl. uma-ticket, device_code, token-exchange — each is a test surface.
