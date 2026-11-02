# Laravel + Voyager CMS admin recon (field-proven 2026-10, crm-test.honda.com.vn)

Fingerprint: `/admin/login` titled "Admin - CRM - Content Management System", `voyager-assets?path=css/app.css`,
cookies `XSRF-TOKEN` + `laravel_session` (encrypted, HttpOnly), `Server: Apache`. Voyager JS bundle
(voyager-assets app.js) carries library version strings for fingerprinting.

## 1. Login via curl (client-side MD5 + session-bound CSRF)
- Inline jQuery transforms the password BEFORE submit:
  `targetPw.val(md5(targetPw.val()))` inside `$("form#form-login").one("submit", ...)`.
  Posting the RAW password returns the generic "Địa chỉ email hoặc mật khẩu không đúng!" even for
  VALID creds. Always read the login page inline JS first (grep `md5(`, `sha(`, `btoa(`,
  `\.one\("submit"`) and replicate the transform: `HASH=$(echo -n 'pass' | md5sum | cut -d' ' -f1)`.
- CSRF `_token` is session-bound: GET /admin/login with `-c jar`, extract `_token" value="..."`,
  POST with `-b jar -c jar`. Token from a different jar → 302 back to /admin/login (silent fail).
- Response reading: POST → 302 Location /admin/login = auth failure; POST without CSRF → **419**.
- ~8-line helper loop: fresh GET → grep token → POST with `-L` (see pentest/honda_crm session).

## 2. Menu/permission dump from /admin/profile (the big one)
`GET /admin/profile` embeds `<custom-admin-menu>` whose Vue props leak the ENTIRE admin surface for
ANY authenticated role:
- `:items="[...]"`   → full menu tree, ~372 routes with resolved hrefs (HTML-escaped JSON, `&quot;`)
- `:per="[...]"`     → every permission row of your role: `pivot.role_id` (numeric role ID!) +
  permission keys `view_/add_/edit_/delete_/export_/publish_<module>`
- `:restricted="[...]"` → routes OTHER roles can access = ready-made BOLA / forbidden-directory
  candidate list; plus `:sysadmin="0"` flag.
Parse recipe (regex `[^"]*` capture FAILS on this payload — use balanced scan):
```python
m = re.search(r':items="', src); i = m.end(); buf = []
while src[i] != '"': buf.append(src[i]); i += 1
data = json.loads(html.unescape(''.join(buf)))
```
`menu − restricted` diff = routes your role sees in nav but that are gated for others → probe each
with your cookie for 200/403/500.

## 3. Status-code map for probe loops
| Signal | Meaning |
|---|---|
| 403 + "không có quyền truy cập chức năng này" | Laravel role gate works (positive finding) |
| 302 → /admin/login (no cookie) | auth middleware only |
| 419 | CSRF missing/expired on POST |
| 000 in curl loops | timeout — MUST set `--max-time 15`; some restricted routes hang the socket (one returned 500 after 4s, others stall indefinitely) |
Voyager media endpoints (`/admin/media/files|upload|crop|rename_file|...`) are gate-blocked for
content-editor roles even though their JS ships on every page (POST returns the "không có quyền"
HTML, not JSON).

## 4. State-changing JSON XHR endpoints (block-player pattern)
`POST /admin/<module>/player-report/block/{id}` needs: session cookie + `X-Requested-With:
XMLHttpRequest` + `X-CSRF-TOKEN: <token>` headers + JSON body → 302 with meta-refresh back to the
filtered list; verify by re-GETting the list (row flips to "Đã block").
- Same route with body `_token` form field instead of header → 405.
- CSRF token also available from `<meta name="csrf-token" content="...">` on every authed page —
  no need to re-scrape forms.
- UI modal reveals route template: `data-action=".../block/__PLAYER_ID__"` + `button.data('id')`.
- **Mutation cost**: block had NO unblock endpoint in the UI — the change is effectively permanent
  on the client's test data. Prefer read-only probes first; confirm with the user before
  create/upload/block POSTs on client systems (one gift-create upload attempt was user-denied).

## 5. Targets that paid off / check next time
- `*/export` CSV: 200 on all module pages; dumps customer PII (CCCD, phone, name) scoped by role.
  Filter params (identity_number/campaign_id) sanitized in this build — `'` and `%2527` probes
  returned 200 with no error.
- Gift create upload (`POST /admin/<module>/gift/create`, multipart, field `image`,
  accept=".jpg,.jpeg,.png"): server rejects non-image polyglot with JSON `errors.image` — the
  client-side accept is NOT the validator. Next steps: GIF-header+PHP polyglot named `.png`,
  double extension, lying Content-Type, before concluding server-side validation is solid.
- `/admin/activities/{dealerId}/countNotViewed|latest|read|readAll` (XHR JSON): when the session
  has no dealer (`var dealerId = ""` in page JS) →
  `{"success":false,"error":"Dealer ID is not matched"}` — dealer-ID enumeration candidate.
- Probe results file pattern: `pentest/<target>/probe_results.txt` (one `code path` line per
  route), cookie jars per account, profile.html kept as the menu-dump source.
