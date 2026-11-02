# F5 ASM, Spring Gateway Swagger, DrayTek & SNI Probing — field notes (banking target, VN)

## 1. F5 ASM status-code false positives
- Dotfile/backup probes (/.env /.git/config /backup.zip /web.zip /.DS_Store) ALL return
  **HTTP 200** behind F5 ASM — body is a ~730-byte generic HTML error page
  ("This page can't be displayed. Contact support... incident ID is: N/A."). WAF block, NOT the file.
- /actuator, /actuator/health, /actuator/env → 200 + same error page (blocked), while
  /v3/api-docs and /v3/api-docs/swagger-config pass unfiltered on the SAME host.
- Rule: existence decisions need body + Content-Type + size — never status code alone.
  A ~730B text/html error page on a JSON API = WAF. HEAD also says 200; only the body discriminates.

## 2. Spring Boot gateway: swagger-config group enumeration
- GET /v3/api-docs → `{"openapi":"3.0.1",...,"paths":{},...}` — looks EMPTY. Don't stop.
- GET /v3/api-docs/swagger-config → `{"urls":[{"url":"/v3/api-docs/<group>","name":<group>}...]}`
- Enumerate every group: administration, adminnews, auth, chat, filestorage, news, websocket
  → 165 endpoint specs readable unauth. All real calls 401 (auth at gateway) but full route
  map + DTO schemas leaked.
- /swagger-ui.html → 401, but /swagger-ui/index.html → 200.
- High-value leaked paths: /api/v1/authentication/sso/{app,web}/{login,logout,refresh_token},
  /api/v1/ecm/{uploadFile,downloadFile,loadFileInfo}, /api/v1/accounts/*, /api/v1/phoneBook/*.

## 3. Angular SPA: microservice gateway route mining
- main.<hash>.js holds the gateway route table as string literals:
  "/iam/api", "/customer/api", "/survey/api", "/system/api", "/storage/api", "/notification/api"
  plus app routes ("/authentication/login", "/dashboard").
- Gateway prefix + trailing slash → 200 SPA index (fallback). POST to a real proxied path
  (/iam/api/authentication/login) → nginx **405 = route exists, proxied**. 405 is an existence oracle.
- One app bundle yielded 510 route literals (approval-batch, adjustment-invoice, annual-leaves,
  access-control/api, ...). Grep `"/[a-zA-Z0-9/_.-]{3,}"` from main.js after fetching it via its
  exact hashed filename from index.html.

## 4. DrayTek legacy edge via Shodan apex-variant pivot
- Shodan `hostname:<apex>` on EVERY apex variant (.com.vn AND .vn) surfaced a legacy ISP IP
  (101.99.14.243, CMC Telecom) hosting stale names admin./amc./mail.<domain> + mail./smtp./pop.<apex2>
  — all NXDOMAIN in live DNS today. Shodan's index = historical hostname→IP map; dead DNS names
  still point at live legacy edge devices.
- Port 80: ANY Host header → 302 /weblogin.htm, title "Vigor Login Page" (~9.5KB, no firmware
  string in HTML — pull model/firmware from login page JS / status endpoints).
- Port 443: TLS handshake fails with `unsafe legacy renegotiation disabled` (openssl 3.x) —
  the error itself is the DrayTek signature. Shodan history showed default cert www.draytek.com.
  WORKING FIX (curl --ciphers 'DEFAULT:@SECLEVEL=0' still fails, code=000 — don't waste time):
  Python stdlib with `ctx.options |= 0x4` (OP_LEGACY_SERVER_CONNECT) completes the handshake.
- Port 21 also open ("220 FTP version 1.0").

## 4b. DrayTek login mechanism & CVE matrix (firmware Apr 2025, Vigor 2912)

Reverse of weblogin.htm JS — POST /cgi-bin/wlogin.cgi, form-urlencoded:
- `aa` = Base64(username), `ab` = Base64(password) — the JS `encode()` is PLAIN Base64, not crypto
- `sslgroup` = -1, `sFormAuthStr` = any random 15-char string (client-generated, server accepts any)
- Response re-serves weblogin.htm with state in JS vars: `iFrmLgErr=2` wrong creds, `mode=3`
  incorrect, **`mode=4` max login reached → LOCKOUT EXISTS, spray slowly**, `mode=5` no buffer,
  `mode=7` account disabled.
- Firmware date oracle: `var buildtime="Apr  8 2025 03:10:18"` inside weblogin.htm — core version
  is hidden but build date maps patch posture (post-2024 builds have the famous unauth RCEs patched).
- FTP: 331 for EVERY username (no user-enum oracle); shares the user DB with HTTP login.

CVE probe results on Apr-2025 firmware (all patched — negative results are intel):
- CVE-2020-8515 (mainfunction.cgi/cvm RCE): 404, endpoint removed
- CVE-2024-23334 (/www/js/draytek.js traversal): 404
- default creds admin/{empty,admin,1234,123456,password,draytek}: iFrmLgErr=2
- XSS in mode param: server hardcodes mode=0, no reflection
- X-Forwarded-For/X-Real-IP 127.0.0.1 bypass: still 302; OPTIONS/PUT/TRACE: 400
- Auth-gated endpoints that exist: /cgi-bin/{wlogin,sslvpn,vpn,dhcp,qos,cvm}.cgi,
  /index.htm, /status.htm, /sslvpn.htm — sslvpn.cgi is the pivot prize (SSL-VPN portal).
- Realistic vectors on current firmware: credential reuse from stealer logs + slow spray.
  Same IP also runs SYN-proxy: random ports (12345/55555) accept CONNECT too — only
  21/80/443 verified at application layer.

## 5. SNI-required probing matrix (enterprise DDoS shields)
- nmap connect-scan on 17 IPs: ALL 39 ports "open" in 5.63s = SYN-proxy shield. Superset only.
- Raw-IP TLS probe: only 4 IPs answer; hostname+SNI probe: 9 vhosts answer.
  → always probe vhosts by hostname, never by IP alone.
- Timeout WITH correct SNI (vpn gateways, mail/autodiscover, lync/xmpp/sip, password portals)
  = firewall IP-allowlist → classify "exists, allowlisted", never retry-loop.

## 6. Misc
- Public-site link "Portal Nội bộ" → portal.<domain> (NXDOMAIN externally = internal-only host).
- BIGipServerCMV_pool_8443 cookie (ASP.NET MVC 5.2 host, X-AspNetMvc-Version leaked) →
  decode last 8 hex of part 2 = little-endian internal pool IP.
- Wayback CDX 429s for ~1h windows — schedule retry, don't skip.
- Cavalier/Hudson Rock: verify token with one auth call before relying on it mid-run
  (token in api_keys.env; env-file corruption produces "Invalid token" at JWT exchange).

## 7. Cavalier sibling-apex intel layer (field-verified 2026-09, mbamc.com.vn)

Running Hudson Rock on the SIBLING apex produced the session's best internal-topology intel:
- `domain <sibling-apex>` → 22 infections, 15 employees; `urls` output ranks INTERNAL hosts
  by stolen-browser visit counts: OWA logon.aspx (34 hits), hris./hris/home.aspx (24),
  oracle./oa_html/appslocallogin.jsp (10) = Oracle EBS, qltn. (10), matkhau.:9251/authorization.do (4),
  hotro.:8100/ (2). These hostnames are NXDOMAIN externally = split-horizon/internal-only —
  they become the phishing/AiTM target list, and the odd ports (9251, 8100) constrain any
  future internal access mapping.
- CLI trap: the CLI's `employees` cmd prints only 4000 chars — JSON gets cut mid-record and
  `json.load` fails on the redirect. Parse with a tolerant regex (extract stealer_id/family/
  date via `re.findall` over key-value pairs) or call the raw API per §1 of
  cavalier-hudsonrock-recon.md.

## 8. Report generation pattern (user's preferred deliverable)

User wants ONE consolidated .md per target. Pattern that worked (gen_report.py in the
target workspace): script reads raw tool outputs (resolved.txt, apidocs_*.json, wayback,
cavalier dumps) and EMITS the report — never hand-write numbers. Two parse fixes were
required and are generalizable:
- dnsx output carries ANSI codes → strip `\x1b\[[0-9;]*m` before regex, else count = 0.
- Cavalier employees JSON truncation → regex-extract fields instead of json.load.
- Final report sections: tóm tắt điểm nhấp (ROI table) → subdomain/DNS → port scan (with
  SYN-proxy caveat) → hidden endpoints → OSINT/Cavalier → WAF/infra → next steps
  (ROI-ranked) → data-file index → explicit GAPS list. Cross-check every count against
  the raw file in a verification pass before shipping.
