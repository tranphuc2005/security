# Web Server Source Audit: Stale Auth-State Flags (Rewrite-Remap Auth Bypass)

Class of bug: a request passes auth checks for context A (setting a one-shot "auth
already checked" flag), then an internal rewrite remaps it to context B that has
STRONGER auth requirements. The flag is not cleared on remap, so context B's auth
is short-circuited. Verified live in OpenLiteSpeed 1.9.2 (src/http/httpreq.cpp,
`HttpReq::postRewriteProcess`). Same family as CVE-2024-23334 (OLS path-confusion
via rewrite into protected dirs).

## Where to look in any web server / framework source

1. Find the "auth checked" state flag (grep: `AUTH_CHECKED`, `m_iContextState`,
   `auth_done`, `authenticated` in request/session state structs).
2. Find every site that SETS the flag (auth entry point) and every site that
   CLEARS it. Any code path that changes the effective security context
   (rewrite, internal redirect, remap, include, subrequest) must clear it.
3. Audit each clear site for dead code — the classic bug is assigning the new
   value BEFORE comparing it to the old one:

```c
m_pContext = pNewCtx;          // assign first...
if (pNewCtx != m_pContext)     // ...always false (self-compare) → dead code
    clear_flag(CONTEXT_AUTH_CHECKED);  // never runs
```

4. Check the auth entry point's short-circuit: `if (!getState(AUTH_CHECKED))`
   returning early means a stale flag silently skips ALL auth of the new context.

## Verified trace (OpenLiteSpeed 1.9.2)

- `src/http/httpreq.cpp:2154-2162` `postRewriteProcess()` — dead-code clear
  (assign at 2154, self-compare at 2158). Contrast with correct pattern in
  `processContext()` line 2257-2258 which saves `pOldCtx` first.
- `src/http/httpsession.cpp:2299-2308` `processContextRewrite()` — return 0
  routes to HSPS_HKPT_URI_MAP (no re-auth) instead of HSPS_CHECK_AUTH_ACCESS.
- `src/http/httpsession.cpp:2391` `processContextAuth()` — short-circuits on
  `CONTEXT_AUTH_CHECKED | KEEP_AUTH_INFO` still set from context A.
- Other callers of postRewriteProcess: `processVHostRewrite()` (~line 1954) —
  vhost-level rewrite, same dead-code exposure.

## Exploit preconditions (matters for live PoC / bug bounty triage)

- Rewrite rule must remap a public URI to a file path inside a protected context
  (admin-configured, same as CVE-2024-23334). Without such a rule the bug is
  not triggerable — verify config BEFORE claiming impact on a live target.
- Direct request to protected context must return 401; request via rewrite path
  returns 200 + content = confirmed bypass.

## Suggested fix pattern

```c
const HttpContext *pOldCtx = m_pContext;  // save OLD before assigning
m_pContext = pNewCtx;
m_pHttpHandler = pNewCtx->getHandler();
m_pMimeType = NULL;
if (pNewCtx != pOldCtx)
    m_iContextState &= ~CONTEXT_AUTH_CHECKED;
```

## Live-target workflow notes (OLS WebAdmin via ngrok tunnel)

- Fingerprint: `Server: LiteSpeed` + admin UI cookie `LSUI<hash>` + X-Powered-By
  PHP/5.6.40 → it's the WebAdmin console, not a content vhost.
- ngrok free tier shows an interstitial; bypass with header
  `ngrok-skip-browser-warning: 1` or a custom User-Agent in curl/python.
- A single ngrok tunnel exposes ONE backend port. If the tunnel points at the
  admin listener (:7080, revealed by `Alt-Svc: h3=":7080"`), traffic goes to the
  WebAdmin vhost, NOT Example vhost — `/protected/` returns 404 (not 401) until
  you map the tunnel domain to the right vhost (WebAdmin → Listeners → HTTPS →
  Virtual Host Mappings, then Graceful Restart).
- Default Example vhost config: `dist/conf/vhosts/Example/vhconf.conf` —
  protected context uses realm `SampleProtectedArea`, `required user test`.
- Building the PoC requires a rewrite rule (vhost Rewrite tab) +
  `RewriteRule ^/leak/(.*)$ /protected/$1` + a real file inside the protected
  docroot — WebAdmin UI alone cannot create files on disk.
- When driving the WebAdmin UI with browser tools: custom `<select>` dropdowns
  (js-select styling) often fail element clicks with "Could not compute box
  model" — set `select.value` + dispatch a `change` event via browser_console
  instead. SPA hash routes (`index.php#!/i/...`) survive re-navigation but the
  ngrok interstitial re-appears after session loss — click "Visit Site" then
  re-login.
