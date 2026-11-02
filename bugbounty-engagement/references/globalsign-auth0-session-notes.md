# GlobalSign Atlas session notes (2026-09) — Auth0 SPA + Vite bundle mapping

Field-proven worked example backing SKILL.md §6.6. Target: atlas.globalsign.com (GMO GlobalSign Atlas portal, Intigriti program). All requests plain curl, git-bash on Windows, RoE headers omitted here for brevity.

## 1. Recon chain that worked

1. `curl https://auth.atlas.globalsign.com/.well-known/openid-configuration` — Auth0 tenant confirmed; `grant_types_supported` shows what's enabled. Try `password-realm` grant FIRST (1 request): here → `unauthorized_client: Grant type ... not allowed` → fall back to PKCE.
2. Portal root `https://atlas.globalsign.com` returns a 302/tiny Vite shell (`/assets/index-*.js`) → `/config.js` → bootstrap chunk → `pages-*.js` chunks. CloudFront + Cloudflare in front; curl works fine with a Chrome UA.
3. `GET /config.js` = runtime env config: every API base (`api.atlas`, `api.portal.atlas`, BSS host, TWO raw `*.execute-api.eu-central-1.amazonaws.com` URLs), Auth0 client_id/audience, LaunchDarkly id, LogRocket, and **a plaintext `CLIENT_SECRET` for a secondary OAuth service (UBI Secure)** — reportable as-is.
4. Endpoint map from chunks: regex template literals containing `{placeholder}` (`orders/{order_id}`, `accounts/{account_id}/quotes/{quote_id}`) plus the `Se('account-mgmt/v1','API_BASE_URL')`-style pairings → base+path table without touching the API.

## 2. Headless Auth0 PKCE login (full curl chain, no browser)

```bash
JAR=pk.txt; CI='<client_id from config.js>'; APP='https://app.tld'   # allowed callback
# verifier/challenge: openssl sha256, urlsafe base64 (tr '+/' '-_', strip '=')
# STEP A — find allowed callback cheaply: wrong redirect_uri → 403 page LEAKS it:
#   "Callback URL mismatch. https://app.tld/login is not in the list of allowed callback URLs"
#   → trial the bare origin; SPA tenants commonly allow exactly https://app.tld
# STEP B — chain (persist cookies every step, UA = real Chrome):
# 1 GET /authorize?response_type=code&client_id=$CI&redirect_uri=$APP&scope=openid+profile+email+offline_access&audience=$AUD&state=st1&nonce=nn1&code_challenge=$CH&code_challenge_method=S256
#     → 302 /u/login/identifier?state=URL_STATE
# 2 GET that page → extract FORM state: name="state" value="..." (DIFFERS from URL state — must use the form one)
# 3 POST /u/login/identifier?state=$FORM  data: state=$FORM&username=...&js-available=true&webauthn-available=true&is-brave=false&webauthn-platform-available=false&passkey-available=false
#     → 302 /u/login/password?state=...  (reuse this state value)
# 4 POST /u/login/password?state=$ST  data: state=$ST&username=...&password=...
#     → 302 /authorize/resume?state=RESUME
# 5 GET /authorize/resume?state=$RESUME → 302 $APP/?code=CODE&state=st1
# 6 POST /oauth/token (JSON): {grant_type:authorization_code, client_id:$CI, code_verifier:$V, code:$CODE, redirect_uri:$APP}
#     → access_token + refresh_token. Audience = config.js AUTH0.AUDIENCE.
```

Pitfalls: form-state ≠ URL-state; cookie jar must span all steps; a `/callback` path guess 403s — the error page tells you the truth; CF rate limits are generous (~300/5min) but do exist.

## 3. Portal API probe matrix (Bearer access_token)

- `api.tld/account-mgmt/v1/{account,users,invitations,roles,subaccounts}` and `api.portal.tld/v1/{...}` both alive.
- FastAPI-style errors: `{"id":"...","description":"...","description_key":"request.validation.error...."}` — description_key = free internal error taxonomy; fabricate IDs → 500 `internal.server.error` with tracking id (low info-leak finding).
- Self role escalation `PATCH /users/:id/roles` → correctly blocked (`user.cannot.update.own.role`); need a 2nd account to test cross-user.
- Mass assignment `PATCH /v1/account` with `is_internal_account`/`is_service_provider` → **204 but silently ignored** — 204 ≠ success, ALWAYS re-GET to verify.
- Invitation flow: payload `{email, roles:[<role-id from /roles>], language:'en_sg'}` — wrong shape gives misleading errors: `internal.server.error` (unknown field) vs `Invited user has no roles assigned to them` (role name instead of id). That error difference also = weak email-format oracle.
- bss.api host: DNS not publicly resolvable — only reachable via gateway paths (502 through api host); don't burn time.

## 4. Outcome

- Reportable: plaintext client_secret in public config.js; HS256 listed in id_token alg values (note-only, needs client secret); fabricated-ID 500s with internal error ids.
- Blocked properly: password grants, self-escalation, mass assignment, cross-tenant user listing.
- Workspace: C:\Users\Admin\pentest\globalsign\ (token.json, pk.txt, chunk files).
