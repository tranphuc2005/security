# Case study: MIC claim.mic.vn — Dropzone upload endpoint on ASP.NET Core/IIS (Sep 2026)

Target class: ASP.NET Core MVC claims platform (ESCS) behind IIS 10 + F5 BIG-IP,
authenticated Dropzone-based upload at `POST /upload/uploadfile`.

## Endpoint fingerprint

- Client-side accept list (cosmetic only):
  `.jpg .png .jpeg .gif .svg .doc .docx .pdf .xls .xlsx .xml`, maxFilesize 50MB,
  Dropzone `parallelUploads=50`.
- Required multipart form fields (attached by the app's `UploadService.js` `setParam`):
  `pm` (module code, e.g. `CAR_CLAIM`), `ma_doi_tac`, `ma_chi_nhanh`, `so_id` (claim
  record id), plus module-specific extras (`loai`, ...). `url_api` can override the
  default `/upload/uploadfile` per call site — grep the page's JS for `url_api:` to find
  alternate upload handlers that may have weaker validation.

## Validation-oracle pattern (how to know you're reaching the handler)

Response envelope is always `{state_info:{status,message_code,message_body},...}`:

| Request | message_code | message_body | Meaning |
|---|---|---|---|
| bare file, no fields | `99` | `Đã có lỗi xảy ra` | handler reached, generic catch |
| file + fields, `pm` missing/unknown | `500` | `Lỗi truyền tham số quy trình phần mềm!` | `pm` gates the workflow branch |
| file + `pm=CAR_CLAIM` + fake `so_id` | `500` | `Chọn hồ sơ bồi thường cần upload tài liệu - <so_id>` | field names correct; record validation BEFORE file touch |

Lesson: the changing `message_body` is a free oracle — iterate fields until the error
mentions the business object, THEN fuzz the file. Fuzzing filename/extension against the
`99` error is blind.

## Blocking dependency (what stalled RCE)

The handler validates `so_id` against the claims DB before storing the file, so extension
fuzzing needs a VALID claim id. List endpoints that return them
(`/carclaim/CarCompensation/paging` etc.) sit behind the ASP.NET MVC antiforgery wall:
script replay with `{}` JSON → `302 → /Error/404` (see
recon-and-methodology/references/aspnet-mvc-recon.md — the 302-to-404 trap).

Two ways past, in order of cost:

1. **Replay the browser's exact XHR.** The blocker in-session was that Hermes browser tools
   refuse `document.cookie` / XHR-intercept expressions without
   `browser.allow_unsafe_evaluate: true` in config.yaml. With that flag (or one
   user-captured request from DevTools), copy the real `paging` request — verb, content-type,
   `RequestVerificationToken` header, full cookie set incl. `BIGipServer*` — into python
   `requests` verbatim. Do NOT recompose headers from memory: F5 ASM ties the flow to the
   exact header set; dropping `X-Requested-With: XMLHttpRequest` or the BIGip cookie
   flips responses to 302/404 or RSTs the connection.
2. **Drive the UI** (browser_click through the search form) and read `so_id` values from the
   rendered grid's `data-*` attributes / row markup in the snapshot — no XHR replay needed.

## Then the standard IIS upload battery

`shell.ashx` first (single-file handler, no web.config needed), then
`shell.aspx`, `shell.aspx:.jpg`, `shell.asp;.jpg`, double-ext, case toggles, trailing
dot/space, and filename-field traversal (`../../x.ashx`) — accept list is client-side so
server behavior is what matters. Retrieval path mapping via the app's own file endpoints
(`/carclaim/carinvestigation/getfiles`, `downloadzipfile`) — see the main SKILL.md §11
(path discovery is half the chain).
