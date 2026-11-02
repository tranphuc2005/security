# Headless Auth0 SPA Login via curl (PKCE Universal Login)

Field-proven on GlobalSign Atlas (auth.atlas.globalsign.com), 2026-09. Gets a full
access_token + refresh_token for API IDOR/BFLA testing WITHOUT a browser or the
password grant (which most production Auth0 tenants disable).

## Prerequisites / recon first

- client_id: from the SPA bundle (`config.js`, `window.__PORTAL_APP_CONFIG__`, or grep the JS for `client_id`).
- audience: same source (`AUDIENCE` key). Omitting audience still logs in but yields an opaque token for the wrong API.
- redirect_uri: NOT guessable — brute candidates and read the error oracle (below).
- scopes: copy the SPA's scope string (often `openid profile email offline_access`).

## Callback-URL error oracle

Wrong `redirect_uri` → HTTP 403 with an Auth0 error page. Grep the body:

```bash
curl -s 'https://AUTH0_DOMAIN/authorize?...&redirect_uri=<CANDIDATE>' | \
  grep -oE '<strong>[^<]+</strong>: [^<]{0,160}'
# → "unauthorized_client: Callback URL mismatch. <URL> is not in the list of allowed callback URLs"
```

The error page echoes the exact offending URL. Binary-search candidates:
`/callback`, `/callback/`, bare origin, `/login`, `/authorize`, `/auth/callback`.
A candidate that returns **302** (redirect to /u/login/identifier) instead of 403 is allowlisted.
The page also leaks a TRACKING ID and links `manage.auth0.com/#/logs/` (info-level finding).

## The 7-step flow (all form-urlencoded unless noted)

```
1. PKCE pair:
   verifier  = base64url(random 32 bytes, strip '=')
   challenge = base64url(sha256(verifier), strip '=')

2. GET  /authorize?response_type=code&client_id=..&redirect_uri=..&scope=..&audience=..
        &state=st1&nonce=nn1&code_challenge=<challenge>&code_challenge_method=S256
   → 302 Location: /u/login/identifier?state=<STATE>
   → save Set-Cookies: did, auth0, did_compat, auth0_compat

3. GET /u/login/identifier?state=<STATE>
   → parse hidden field: <input name="state" value="<STATE2>">  (may differ from #2)

4. POST /u/login/identifier
      state=<STATE2>&username=<email>&js-available=true&webauthn-available=true
      &is-brave=false&webauthn-platform-available=false&passkey-available=false
   Headers: Content-Type: application/x-www-form-urlencoded
            Origin: https://<auth0-domain>
   → 302 to /u/login/password?state=<STATE3>

5. POST /u/login/password
      state=<STATE3>&username=<enc>&password=<enc>
   Headers: + Referer: https://<auth0-domain>/u/login/password?state=<STATE3>
   → 302 to /authorize/resume?state=<RESUME_STATE>

6. GET /authorize/resume?state=<RESUME_STATE>
   → 302 to <redirect_uri>?code=<AUTH_CODE>&state=st1

7. POST /oauth/token  (JSON body)
      {"grant_type":"authorization_code","client_id":..,"code":<AUTH_CODE>,
       "code_verifier":<verifier>,"redirect_uri":<same redirect_uri>}
   → {"access_token","refresh_token","id_token","scope","expires_in","token_type"}
```

## Gotchas

- Always form-encode `state` (base64url alphabet contains `-`/`_` but the value is long;
  use urlencode with safe='').
- Keep the cookie jar across steps 2–6 (`-b jar -c jar`); Cloudflare `__cf_bm` may appear.
- Send `Origin` on the login POSTs, `Referer` on the password step; a real browser UA helps.
- If step 4 redirects back to identifier with an error, credentials are wrong — the state is fine.
- `code` is single-use; if the token exchange fails, redo the whole flow (cheap).
- ROPC probe is worth 1 request first: POST /oauth/token with
  `grant_type=http://auth0.com/oauth/grant-type/password-realm` — if it works you skip
  steps 2–6 entirely. Usually returns `unauthorized_client` in prod.

## Multi-account (A/B) headless testing — field-proven workflow

Testing two tenants cross-wise (IDOR) means running this flow twice in one session.
Collisions are the #1 time-waster — namespace EVERY artifact per account:

- PKCE verifier: `pkce_A.txt` / `pkce_B.txt`. **Never reuse another account's verifier** —
  the token exchange fails with `{"error":"invalid_grant","error_description":"Failed to
  verify code verifier"}` and you must redo the entire flow. (Lost verifier = full re-login;
  the `code` is single-use and bound to its challenge.)
- Cookie jars: `ckA.txt` / `ckB.txt`; header dumps: `hA1.txt`/`hB1.txt`... (a shared
  header file silently feeds you the WRONG account's state/Location on the next parse).
- Wrap the whole 7-step flow in one `login(email, password, tag)` function; call it freely
  whenever a token dies.

Access tokens expire in ~30 minutes. Mid-session `Unauthorized` on an endpoint that worked
before = expired token, not a new finding. Either re-login or refresh:

```json
POST /oauth/token {"grant_type":"refresh_token","refresh_token":<RT>,"client_id":<CID>}
```

Note: these tenants revoke the old refresh_token immediately on rotation — a replayed RT
returns `invalid_grant`. That's secure (no finding), but it means: **save the NEW token
file after every refresh** or you're locked out and must re-login.

Authorization-request extras worth testing while you're at it: Auth0 org invitations are
passed as `&invitation=<id>&organization=<org_id>` on /authorize. Portal-level invitation
IDs (e.g. `uinv_...`) usually DON'T map to Auth0 ticket IDs — a valid portal invite still
returns `error=invalid_request: invitation not found or already used`. The real ticket ID
only exists in the invitation email link; to complete an accept-invitation-as-other-user
test you need the actual email, not the API response.

Slow endpoints exist: invitation POST (synchronous email dispatch) took ~19s in practice —
set curl `-m 60` or you'll read HTTP:000 as a failure.

## What the token gives you

Decode the access_token payload: Auth0 RBAC deployments embed
`permissions: [...]` (the API's full permission model — free BFLA map) and often custom
namespaced claims (`atlas|account_id`, `crm_contact_id`, entitlements) that reveal the
tenant model. Then walk the API permission-gated endpoints testing BOLA/BFLA
(pair with idor-broken-object-authorization skill). Check refresh-token rotation by
replaying the old refresh_token — rotation + immediate revocation = secure, no finding.
