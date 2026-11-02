# ASP.NET Core MVC recon (field-proven)

Target class: ASP.NET Core MVC apps behind IIS + F5 BIG-IP. Field case: MIC claim.mic.vn
(ESCS claims platform), authenticated recon with a valid user session.

## Fingerprint

```
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Set-Cookie: .AspNetCore.Antiforgery.<rand>=...
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=...
Set-Cookie: BIGipServer<pool>=!...          <- F5 BIG-IP persistence
```

## Endpoint discovery — JS service files beat ffuf

These apps centralize every AJAX call in per-feature `*Service.js` files that wrap a shared
`Service.js` `postData("<url>", obj)` helper. Attribute-routed MVC action names rarely appear
in generic wordlists, so directory brute-force misses them. Instead:

```bash
# 1. render the authenticated page, list the JS it pulls
grep -oE 'src="[^"]*Service\.js[^"]*"' page.html | sort -u

# 2. fetch each service file, extract the routes
for f in $(grep -oE 'src="([^"]*Service\.js)[^"]*"' page.html | sed -E 's/src="([^"]*)".*/\1/'); do
  curl -sk --cookie cookies.txt "https://target$f"
done | grep -oE 'postData\("[^"]+"' | sort -u
```

One page (`/carclaim/carcompensation`) yielded ~120 real routes, e.g.:

```
/carclaim/CarCompensation/paging
/carclaim/CarCompensation/luuThongTinOCRBaoGiaGara
/carclaim/carinvestigation/downloadzipfile
/admin/usermanagement/getpaging
/admin/usermanagement/importExcelDanhSachNsd
/upload/uploadfile
/common/ExportExcelV2
```

Also dump the page's `<a href>` list for the controller area map (`/carclaim`, `/motoclaim`,
`/healthclaim`, `/otherclaim`, `/manager`, `/admin`, `/dashboard`, `/report`).

## Response-shape table — read before concluding "route doesn't exist"

| Request | Response | Meaning |
|---|---|---|
| POST JS-route, bare `{}` JSON, no antiforgery | `302 → /Error/404` | Route exists, request shape rejected (missing antiforgery cookie/header, wrong casing, or model-binding failed). NOT a real 404. |
| POST route that truly doesn't exist | `302 → /Error/404` | Identical — so you CANNOT distinguish by status alone. |
| POST `/common/ExportExcelV2` with `{}` | `500 System.NullReferenceException` + stack trace | Route hit, model binding partially worked, handler threw. Leaks source path + namespace. |
| POST `/upload/uploadfile`, bare file | `200 {"state_info":{"status":"NotOK","message_code":"99","message_body":"Đã có lỗi xảy ra"}}` | Handler reached, generic failure (missing required form fields). |
| POST `/upload/uploadfile`, file + `pm/ma_doi_tac/ma_chi_nhanh/so_id` | `200 {... "message_code":"500","message_body":"Chọn hồ sơ bồi thường cần upload tài liệu - 123"}` | Handler reached, validation on `so_id` failed — specific message confirms field names are right. |

Key discipline: because wrong-shape and non-existent both return `302 → /Error/404`, the ONLY
way to confirm a route is to replay the EXACT verb + content-type + body the JS sends, captured
from a real browser XHR (DevTools / browser tool), not guessed. Guessing params against a
`302 → /Error/404` wall burns the whole session (this exact trap cost a full MIC session).

Practical unblock order when script replay hits the 302 wall:

1. **Replay the browser's exact XHR.** Hermes browser tools refuse `document.cookie` /
   XHR-intercept expressions without `browser.allow_unsafe_evaluate: true` in config.yaml —
   set it once, or ask the user for ONE captured DevTools request. Then copy the request
   VERBATIM into python `requests`: full cookie set (incl. `BIGipServer*` — F5 ASM ties the
   flow to it), `X-Requested-With: XMLHttpRequest`, `RequestVerificationToken` header,
   content-type, and body. Do NOT recompose headers from memory: dropping any of these flips
   responses to 302/404 or RSTs the connection.
2. **Drive the UI instead.** browser_navigate + browser_click through the search form works
   with plain cookies (verified: full login → dashboard → `/carclaim/carcompensation` grid
   rendered, session `Lê Thị Bích Thảo`, real data). Read business ids (`so_id`) from the
   rendered grid markup in the snapshot — no XHR replay needed.
3. **Don't iterate blind.** ~30 guessed variants (casing, /api prefix, content-type, GET vs
   POST, trailing slash, query-string) all returned the identical 302 — that loop is the
   smell to stop and switch to (1) or (2).

## Quick-wins

- **Verbose stack-trace leak (info disclosure)**: any endpoint that takes a complex body and
  isn't guarded against null → `500` with full trace. The MIC trace leaked
  `C:\GitLab-Runner\builds\pyu85zrWT\0\root\mic-claim\CLAIM\ESCS\Controllers\CommonController.cs:line 537`
  → build-server path, repo name (`mic-claim`), namespace (`ESCS.Controllers`), controller
  (`CommonController`), and line number. Reportable + free controller map for further fuzzing.
- **Upload → RCE path**: `/upload/uploadfile` (Dropzone, client-side accept list
  `.jpg .png .jpeg .gif .svg .doc .docx .pdf .xls .xlsx .xml`, maxFilesize 50MB). Client-side
  extension list is cosmetic — server-side validation is what matters. To test it you need a
  VALID `so_id` (claim record id) because the handler validates the record before touching the
  file. Get one from a real list endpoint (`.../paging`) replayed with the exact JS body, then
  fuzz filename: `shell.aspx`, `shell.ashx`, `shell.aspx:.jpg`, double-ext, path traversal in
  the filename field. `.ashx` is the highest-value drop on IIS (single-file handler, no
  web.config needed).
- **Antiforgery**: POSTs need the `.AspNetCore.Antiforgery.*` cookie (set on GET) and often the
  `RequestVerificationToken` header from the page's hidden `__RequestVerificationToken` input.
  The app's own `Service.js` sends it as a header — replicate that, not just the cookie.

## MIC-specific notes (delete when generalizing)

- Auth cookie: long encrypted `TO3148F7E7566652` (capture into `cookies.txt` for replay).
- Login: `/dang-nhap`, math captcha `/Home/Captcha` (see authbypass skill's
  math-captcha-session-flow.md).
- Working dir: `C:\Users\Admin\pentest\mic_claim\` (login_full.py, login_post.py, cookies.txt,
  dumped *Service.js files).
