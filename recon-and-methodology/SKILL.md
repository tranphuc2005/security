---
name: recon-and-methodology
description: >-
  Reconnaissance and methodology playbook. Use when mapping assets, discovering endpoints, fingerprinting technology, and building a structured testing plan for a new target.
---

# SKILL: Recon and Methodology — Expert Bug Bounty Playbook

> **AI LOAD INSTRUCTION**: Systematic recon and bug-finding methodology from top bug hunters. Covers subdomain enumeration, endpoint discovery, tech fingerprinting, and the hunter's mental model for finding bugs that others miss. Key insight: most high-severity bugs are found through systematic coverage, not just clever payloads.

---

## 1. RECON HIERARCHY

```
Target Selection
└── Scope Definition (in-scope assets)
    └── Asset Discovery (subdomains, IPs, domains)
        └── Tech Fingerprinting (what's running)
            └── Endpoint Discovery (attack surface)
                └── Vulnerability Testing (per vulnerability type)
```

---

## 2. SUBDOMAIN ENUMERATION (CRITICAL FIRST STEP)

### Passive (no DNS queries to target)
```bash
# Subfinder (aggregates multiple sources):
subfinder -d target.com -o subdomains.txt

# Amass passive:
amass enum -passive -d target.com

# Certsh (certificate transparency):
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
# ⚠️ crt.sh has frequent 502 windows. If it fails: retry once after ~60s, then DON'T
# skip CT data — fall back to a DoH dictionary sweep (stdlib-only, no tools needed):
#   for s in www api dev staging admin portal careers investors login cdn assets mail \
#            vpn sso auth cms app static docs support news media shop partners; do
#     curl -s "https://dns.google/resolve?name=$s.target.com&type=A"
#   done | jq -r 'select(.Answer) | .Question.name + " -> " + (.Answer[]?.data // "")'
# (~30-50 common names per domain, worked on an enterprise target where crt.sh was
# fully down and subfinder was not installed.)

# 🔑 Domain-relation pivot (field-proven): internal hostnames leaked in 404 pages,
# error pages, and OneTrust/dataDomainScript config often reveal a SECOND apex domain
# (e.g. www.target.com 404 page leaked corporate.prod.tccc-nextgen.com -> sweep that
# apex too; it exposed an AWS API Gateway endpoint not under the main domain).

# SecurityTrails API, Shodan:
# DEFAULT intel-source set for every recon session (user expectation, 2026-09): CT logs +
# subfinder + SecurityTrails (subdomains AND historical A) + Shodan (hostname:<apex> per
# apex variant, ssl:<apex>, per-IP host lookup for ASN) + Hudson Rock Cavalier (stealer
# intel — verify token with one auth call BEFORE relying on it mid-run).
# Web: https://securitytrails.com/list/apex_domain/target.com
# Full field-proven workflow & queries: see [references/shodan-securitytrails-recon.md](./references/shodan-securitytrails-recon.md)
# Stealer-log intelligence (Hudson Rock Cavalier — plaintext creds, cookies, internal URLs): see [references/cavalier-hudsonrock-recon.md](./references/cavalier-hudsonrock-recon.md)
# API Integration (field-proven):
# Subdomains:
#   curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/domain/<domain>/subdomains"
# Historical DNS (A records pivot - uncovers decommissioned/legacy IPs):
#   curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "https://api.securitytrails.com/v1/history/<domain>/dns/a"
# Shodan IP / Domain search:
#   shodan search "hostname:<domain>" / "ssl:<domain>"
#   shodan host <ip> (banners, products, versions, unmapped services e.g. IoT/CCTV/RDP)
```

### Wayback CDX — passive endpoint goldmine (field-proven)

Wayback Machine is fully passive and repeatedly yielded the best leads of any single source:
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=HOST/*&output=text&fl=original&collapse=urlkey&limit=500"
# Run per interesting host (auth hosts, api portals). What it yields that nothing else does:
# - undocumented auth endpoints (e.g. /api/v1/login?redirect_uri=..., /api/v1/anonymous_token)
# - OpenAPI/spec paths published historically (e.g. /tracking/7/api.json)
# - SEQUENTIAL NUMERIC IDs in real URLs (invoice/1125660449, tracking/27218850994) →
#   this is your pre-built IDOR test list; capture it in the recon report before any account testing.
# - UAT/legacy hosts still referenced in old docs (parcel-uat/, interfaces.legacy-domain)
# NOTE: web.archive.org occasionally returns a "Temporarily Offline" HTML page instead of
# CDX data — detect it by the absence of a URL scheme in output and retry later.
```

### Passive-only mode (no authorization / unowned target)

When the target is NOT in a public bounty program and authorization is unverified, run the whole session in PASSIVE-ONLY mode and say so explicitly to the user up front. Passive-only still covers a lot (field-proven on an enterprise target):

```
□ Headers: curl -sI main + each subdomain (Server, Via, x-cache, security headers)
□ robots.txt + sitemap.xml + security.txt (well-known)
□ HTML source grep: tech stack (AEM/WordPress/React...), internal hostnames,
  CDN/telemetry scripts (rum.hlx.page, adobedtm, OneTrust dataDomainScript)
□ DoH dictionary sweep (see §2) on the main apex + any leaked related apex
□ TLS cert mining via openssl s_client (SANs reveal hidden infra: e.g.
  login.target.com cert showed *.us1.gigya.com → SAP Customer Data Cloud)
□ WordPress: /wp-json/ namespaces leak plugin list without touching anything;
  /wp-json/wp/v2/users shows whether user enum is blocked (401 = hardened)
□ API gateways: a bare 403 with x-amz-apigw-id = AWS API Gateway behind CDN (auth required)
```

**Self-review the coverage at the end**: reconcile what was done against the playbook sections — passive items skipped due to transient tool failure (e.g. crt.sh 502) or forgetfulness (waybackurls/gau, GitHub dorks) should be either retried or explicitly listed as gaps in the report, not silently omitted. Legal boundary to state in the report: no port scans, no dir brute, no nuclei, no credential attacks.

### Active (DNS brute force + resolution)
```bash
# Massdns + wordlist:
massdns -r /path/to/resolvers.txt -t A -o S -w output.txt \
  <(cat wordlist.txt | sed 's/$/.target.com/')

# ffuf for subdomain brute:
ffuf -w subdomains-wordlist.txt -u https://FUZZ.target.com \
  -mc 200,301,302,403 -H "Host: FUZZ.target.com"

# DNSx for bulk resolution:
cat subdomains.txt | dnsx -a -resp -o resolved.txt

# Recommended wordlist: SecLists/Discovery/DNS/
```

### Cloudflare-fronted target + wildcard DNS (field-proven 2026-10, epu.edu.vn)

When the apex is behind Cloudflare AND a wildcard `*.apex` A-record points at the CF edge, EVERY
subdomain "resolves" — 404 misses become invisible and a naive resolve step reports ~100% live.
Rules that make this tractable:
- **404 = host does not exist.** A CF host with no matching origin/vhost returns the CF 404/1016,
  not a connection failure. "Resolves to 104.x/172.6x CF edge" means "unknown"; only count a host
  as real when it returns a non-CF-404 app response.
- **Origin discovery beats subdomain brute.** Wildcard + CF means brute force adds nothing. Pivot
  to origins: SecurityTrails `/v1/history/<apex>/dns/a` (pre-CF real IPs), `shodan domain <apex>`
  (A/CNAME table — non-CF rows are live origins), `shodan host <ip>` (Hostnames field groups all
  apexes on an IP → catches shared VPS / third-party SaaS). Non-CF rows in a dnsx sweep are the
  real origin servers.
- **Direct-to-origin probing**: `curl -H "Host: <sub>" http://<origin-ip>/` often returns IIS/
  Apache "404 Not Found" (binding mismatch) — that 404 still PROVES reachability + WAF bypass.
- **Secondary apex discovery**: third-party scripts/analytics on the main site leak a SECOND apex
  owned by the same org (e.g. `track.epu.io.vn` → sweep `epu.io.vn`). Grep rendered HTML for every
  `https?://…` and treat a new apex as a fresh target.
- **Control-IP SYN-proxy test**: to prove a connect-scan is shield-poisoned, scan a KNOWN-DEAD
  neighbour IP in the same /24. If it too reports ~100 open ports (incl. garbage low ports), the
  ISP SYN-ACKs everything — discard connect-scan output, use `shodan host <ip>` for ground truth.

Full field notes + origin-IP table + stack fingerprints: [references/cloudflare-wildcard-origin-recon.md](./references/cloudflare-wildcard-origin-recon.md)

### Virtual Host Discovery
```bash
# ffuf vhost mode:
ffuf -w wordlist.txt -u https://target.com \
  -H "Host: FUZZ.target.com" -mc 200,301,403

# gobuster vhost:
gobuster vhost -u https://target.com -w wordlist.txt
```

---

## 3. SERVICE AND PORT DISCOVERY

```bash
# Fast port scan (common ports):
nmap -T4 -F target.com -oN ports.txt

# Comprehensive scan on resolved subdomains:
cat resolved_ips.txt | nmap -iL - --open -p 80,443,8080,8443,8888,3000,5000 -oG scan.txt

# httpx for HTTP probing:
cat subdomains.txt | httpx -title -tech-detect -status-code -o live_hosts.txt

# masscan for speed on large IP ranges:
masscan -p 80,443,8080,8443 10.0.0.0/8 --rate=1000
```

### ⚠️ SYN-Proxy / Anti-DDoS False Positives (field-verified)

Banking/telco/large-enterprise ranges commonly run SYN-proxy DDoS shields: the edge completes EVERY TCP handshake for ANY port, then discards. Connect scans and `nmap -sV` then report nearly all ports "open" while version detection hangs forever (>10 min/host observed). Never report scan output from such ranges without application-layer verification.

- **Sanity check**: if an IP known to host only a website shows 20+ open ports → you are behind SYN-proxy; reclassify ALL connect-scan results as UNVERIFIED.
- **Python stdlib connect-probe fallback**: when nmap -sV hangs on SYN-proxy shields, a threaded Python `socket.connect()` sweep (~20 workers, 2s timeout) over a curated port list finishes in seconds — but note it suffers the SAME false-positive problem (every port "connects"); treat its output as a superset to filter, not ground truth.
- **Verify by response, not handshake**: only an application-layer answer counts — SMTP/SSH banner on connect, valid protocol probe (Redis PING→+PONG, DNS TCP query, HTTP HEAD) for silent protocols, TLS cert + HTTP status for 443. Full verification ladder + per-protocol probe bytes: [references/synproxy-portscan-verification.md](./references/synproxy-portscan-verification.md)
- **Instant ConnectionReset ≠ dead port**: mail relays behind IP allowlists reset immediately on connect — mark "exists, allowlisted", never loop retries against them.
- **Rate-amplified scans INFLATE shield FPs (field-verified 2026-10, VN finance edge)**: same IPs where a curated `-T4` 47-port scan showed only 443, `-T5 -p- --min-rate 3000` reported ~216 "open" ports/IP including garbage low ports (17/qotd, 129/pwdgen, 85/mit-ml-dev) — the shield SYN-ACKs more under high rate. Garbage low ports in an open list = shield telltale; rerun curated `-T4` and trust only that. Also `-T5` vs `-T4` on silent-drop targets: each unreplied port costs the full timeout either way, so rate flags don't save you (44s/IP at -T5 vs minutes at -T4 without min-rate — use `--min-rate` with `-T4`+curated ports instead).
- **100%-empty-banner test**: threaded connect sweep where EVERY port connects but EVERY recv() is zero-length = SYN-proxy shield (real SMTP owes a `220` greeting, SSH owes `SSH-2.0` within seconds). Mixed empty/populated banners = real host.
- **DNS as app-layer probe for shield-classified IPs**: `nslookup <known-name> @<target-IP>` timing out while DoH resolves the same name proves the "open" 53/tcp is fake-open. Same principle extends to any protocol with a mandatory greeting.
- **UDP `open|filtered` = silent DROP, not a finding** — report nothing unless a UDP service actually answers.
- **Per-IP output files for multi-IP full sweeps** (`-oN full_<ip>.txt` in a for-loop, not one `-iL` run): a mid-run Nmap pcap crash (`Error from pcap_next_ex: interface disappeared`, seen on Windows after adapter reset) otherwise discards the ENTIRE sweep including already-completed hosts.
- **Nmap (Windows binary) can't read MSYS paths** — `-iL /c/Users/...` fails with "cannot find the path specified" while the same path works for curl/grep. Always pass native `C:\...` paths to nmap flags (`-iL`, `-oN`, `-oG`); MSYS paths are fine for everything else in the pipeline.
- **Tooling pattern**: run heavy nmap in background with `--max-retries 1 --host-timeout Nm`; in parallel a threaded banner-grabber (~200 workers, 5s timeouts) finishes Ladder 1–2 checks in seconds.
- **Windows gotchas**: ProjectDiscovery httpx vs the Python httpx library share the name — `httpx` on PATH may resolve to the Python CLI (`Usage: httpx [OPTIONS] URL`, errors on `-silent`/`-title`). Fix: call the PD binary explicitly by path (`~/go/bin/httpx.exe`) or check `httpx --version` output shape first; same applies to `ffuf` → use `~/go/bin/ffuf.exe`. Also: `~/go/bin/*.exe` tools can't read MSYS paths — `/tmp/x.txt` resolves to `C:\tmp\x.txt`, so pass Windows-style paths (`C:\...\file.txt`) or files inside the workdir; with `CERT_NONE`, Python's `ssl.getpeercert()` returns `{}` — use `getpeercert(binary_form=True)` or shell out to `openssl s_client | openssl x509` for cert details/SANs.
- **dnsx writes ANSI color codes** into its `-o` output file (`\x1b[35m` around record types/IPs) — downstream regex/`jq`/`comm` parses silently return 0 matches and report generators then ship "0 resolved / 0 IPs". Strip before parsing: `re.sub(r'\x1b\[[0-9;]*m','',line)`; cross-check report numbers against a recount of the source files, never trust the generator's own parse.
- **`subfinder` has no `-passive` flag** — passive is the default; use `-all` for recursive sources, `timeout 60` to cap.
- **shodan CLI needs `shodan init $SHODAN_API_KEY` once per host** before `shodan domain <d>` / `shodan host <ip>` work; the `domain` subcommand prints DNS records (A/MX/NS/TXT incl. SPF+DMARC) — parse those directly for the report instead of a separate dig. `shodan host <ip>` "Ports:" list = ground truth when naabu/nmap is SYN-proxy-poisoned (see SYN-proxy section).
- **ffuf help-text trap**: when ffuf errors (bad flag/path), it prints the full usage banner to stdout — piping stdout into a results file contaminates it with banner lines ("https://example.org/", "-ac ..."). Always send ffuf errors to stderr/`2>/dev/null` and sanity-check result files for `example.org`/`Fuzz Faster U Fool` lines before reporting.
- **MSYS `for ... done | grep` pitfalls**: `grep -E ':(80|443|...)$'` with a 100+-port alternation can hit the 60s foreground timeout on 60k-line files — do the port-bucket filtering in execute_code (Python set membership) instead of shell regex.
- **SNI-required hosts (field-verified 2026-09)**: probing a vhost by bare IP answers on only ~1/4 of the hosts that answer with correct SNI. Always probe by hostname (let the resolver map, or set SNI explicitly). And a timeout WITH correct SNI on vpn/mail/autodiscover/lync hosts = firewall IP-allowlist → "exists, allowlisted", never retry-loop.
- **ISP tarpit variant (field-verified 2026-09, VN telco target)**: some ISP-edge shields don't just SYN-proxy — they SYN-ACK EVERY port on EVERY IP of the whole /24 (naabu reported ~65k open host:port across 79 IPs, including 65000/1337). Same fix: never report connect-scan output; ground truth = Shodan `host <ip>` Ports list + httpx-confirmed 80/443 + protocol banner grabs only.
- **"Request Rejected" WAF page ≠ 200 content**: F5/AWAF-style filters answer blocked probes with HTTP 200 + a tiny "Request Rejected ... support ID" HTML body. When summarizing live hosts, split them: `grep 'Request Rejected'` → waf_protected list (don't count as real app); the app is still there behind the WAF — note it for bypass work (chunked TE, unicode, Host-header origin hits on shared IPs).
- **Dead-DNS subs that still matter**: subs that are NXDOMAIN today but appear in stealer-log URLs (Cavalier employees_urls/clients_urls — e.g. kpi./cskh./owa./autodiscover.) are vhost candidates — keep a "dead but interesting" section in the report and Host-header-brute them on the shared web IPs (the /24s that host 10+ live subs).

### Workflow: inventory tools BEFORE scripting

At session start of any recon task, probe availability/version of expected tools in ONE shell loop (`for t in nmap subfinder gobuster ffuf nuclei ...; do command -v $t; done`) instead of assuming a Kali-style install. Adapt the plan to what exists: e.g., no dnsx/httpx-PD → resolve via Google DNS-over-HTTPS + Python stdlib. Reusable passive pipeline in [scripts/passive_recon.py](./scripts/passive_recon.py) (crt.sh ∪ subfinder → DoH A/CNAME resolution → ipinfo/RDAP ASN + netrange; stdlib only, generic template). This avoids half-written scripts failing mid-run on missing binaries and surfaces version quirks early. Passive results (CT logs also expose stale records like admin./owa./-dr hosts → split-horizon DNS inference).

### Windows gotchas that recur in recon sessions (2026-09)

- **`httpx` name collision**: on this host `httpx` resolves to the Python library CLI
  (`httpx [OPTIONS] URL`), NOT ProjectDiscovery httpx — PD flags (`-title -tech-detect
  -silent`) error out. Fallback that worked: Python stdlib probe script (socket+ssl,
  ~20 workers, GET + headers + title parse) — see §3 verification scripts.
- **dnsx writes ANSI color codes** into its output file (`\x1b[35m`) — any downstream
  regex/`jq` parse silently fails. Always strip: `re.sub(r'\x1b\[[0-9;]*m', '', line)`
  before parsing, or run dnsx with `-silent` and pipe through `sed` on capture.
- **`subfinder` has no `-passive` flag** (errors: "flag provided but not defined") —
  passive is already the default; use `-all` for recursive sources, `timeout 60` to cap.
- **Report generators parsing raw tool output** must cross-check numbers against the
  source files (recount, don't trust the generator): one session shipped "0 resolve"
  in a report because dnsx ANSI codes broke the regex — caught only by re-verification.

### execute_code + curl pitfalls (Windows/MSYS host, recurring)

- f-strings swallow curl `-w "%{http_code}"` braces → NameError mid-script. Double the braces inside f-strings (`%{{http_code}}`) or build commands via string concatenation.
- `set()` results are not subscriptable — use `sorted(s)[:10]`, never `s[:10]`.
- Large responses (CT logs, Wayback CDX) get clipped mid-record when pulled into the sandbox — filter/dedupe server-side with `jq`/`grep`/`sort -u` in the shell pipeline instead of transferring full JSON through terminal().
- Concurrency note: 8 workers × DoH queries finish a 1000-host sweep in <60s; bug-bounty rate limits apply to TARGET requests, not to dns.google/web.archive.org.

---

## 4. WEB TECHNOLOGY FINGERPRINTING

```bash
# Wappalyzer (browser extension) or:
whatweb https://target.com

# httpx with tech detection:
httpx -u https://target.com -tech-detect

# Check headers manually:
curl -sI https://target.com | grep -i "server\|x-powered-by\|x-generator\|cf-ray"

# Fingerprint from:
- Server header: nginx/1.18, Apache/2.4, IIS/10.0
- X-Powered-By: PHP/7.4, ASP.NET
- Cookies: PHPSESSID (PHP), JSESSIONID (Java), _rails_session (Rails)
- HTML comments: <!-- Drupal 9 -->
- Meta generator: <meta name="generator" content="WordPress 6.2">
- JS framework files: /static/js/angular.min.js
- NuxtJS/whitelabel (field-proven): /_nuxt/<hash>.js bundles; runtime config in SSR HTML `window.__NUXT__` payload (minified single-letter vars — URL-encoded \u002F defeats naive grep, decode first); frontend proxies /api-<name> expose internal API topology (`proxy:{path:"/api-wallet"}` in bundles → internal hostnames via 301 to *.local)
```

### ASP.NET Core MVC recon (field-proven on IIS 10 + F5 BIG-IP)

Fingerprint: `Server: Microsoft-IIS/10.0` + `X-Powered-By: ASP.NET` + cookies
`.AspNetCore.Antiforgery.*`, `.AspNetCore.Mvc.CookieTempDataProvider`, `BIGipServer*` (F5).
Two behaviours that shape recon:

1. **JS service files are the endpoint map.** These apps centralize every AJAX call in
   per-feature `*Service.js` files that wrap a shared `Service.js` `postData("<url>", obj)`
   helper. Grep the rendered page for `src="...Service.js"`, fetch each, and extract
   `postData("<url>"` — one page yielded ~120 real controller/action routes
   (`/carclaim/CarCompensation/paging`, `/admin/usermanagement/getpaging`, `/upload/uploadfile`).
   This beats ffuf for route discovery because attribute-routed MVC actions don't appear in
   any wordlist.
2. **Hitting a route with the wrong shape → `302 → /Error/404`, NOT 404/405.** POSTing a
   JS-discovered route with a bare `{}` JSON body (or wrong casing, or missing the antiforgery
   cookie/header) redirects to `/Error/404` instead of returning a useful error. Don't read
   that as "route doesn't exist" — it means the route exists but rejected the request shape.
   The discriminator: a route that truly doesn't exist behaves identically, so confirm by
   replaying the EXACT verb + content-type + body the JS sends, captured from a real browser
   XHR, not guessed.

Quick-wins on this stack:
- **Verbose stack-trace leak**: POST an endpoint that takes a body with an empty/invalid one
  (e.g. `POST /common/ExportExcelV2` with `{}`) → `500` with full `System.NullReferenceException`
  stack trace leaking the absolute source path (`C:\GitLab-Runner\builds\...\Controllers\
  CommonController.cs:line 537`) and namespace. Info-disclosure finding + free controller map.
- **Upload endpoints** (`/upload/uploadfile`, Dropzone) usually need extra form fields the JS
  attaches (`pm`, `ma_doi_tac`, `so_id`, ...). A bare file POST returns a generic
  `{"state_info":{"status":"NotOK","message_code":"99"}}`; a POST with fields but a bad `so_id`
  returns a *specific* validation message ("Chọn hồ sơ bồi thường cần upload tài liệu - 123")
  — use the changing message to confirm you're reaching the handler before fuzzing extensions.

Full pattern + response-shape table: [references/aspnet-mvc-recon.md](./references/aspnet-mvc-recon.md)

### SharePoint on-prem recon (field-proven 2026-09, portal.evnhanoi.vn)
Fingerprint = FedAuth base64 cookie + `X-OfficeDefaultPage` on 404s + `/_api`, `/_vti_bin`, `/_layouts/15`, `/Pages/*.aspx`. Authenticated GETs (`currentuser`, `web/lists`, `siteusers`, `webs`, `lists/getbytitle('...')/items?$top=`) commonly dump the whole intranet directory + PII for ANY authed user; write digest comes from regexing `__REQUESTDIGEST` in a .aspx page when `/_api/contextinfo` 404s. CKFinder v3 hides behind a single `/ckfinder/connector?command=...` .NET binary (Init/GetFolders 200; mutating cmds 400 err109 = missing params, not blocked). These hosts sit behind flaky LB — ~30-50% of identical requests randomly return 404/SSL-WRONG_VERSION_NUMBER, so EVERY probe loop needs retries or findings flap. Full runbook + response shapes: [references/sharepoint-onprem-recon.md](./references/sharepoint-onprem-recon.md)

### Same-vendor platform replay (class-level technique, field-proven 2026-09)

When you hold a pentest report for one tenant of a vendor product, replay the whole findings
matrix against every other tenant of the same vendor — the code ships the same bugs; only the
WAF posture, removed endpoints, and API path prefix differ. Core procedure: fetch the SPA
`main.<hash>.bundle.js` → `grep -oE "[a-z0-9]+\.api/[a-z]+"` (service map) + `grep -oE 'svUrl\+"[^"]+"'`
(real routes); decode any JWT you hold — the `aud` claim IS the microservice inventory; then replay
each finding with the tenant prefix swapped, logging CONFIRMED / FIXED / WAF-BLOCKED.
Applied to Trinam/DTTT eLearning (SeaBank ilearn → EVN lms.evnhanoi.vn): 5/8 confirmed unauth
(path traversal in file.api, PII by GUID, admin enum, SignalR CORS, sso.html postMessage), 2 removed,
1 WAF-blocked. Full matrix + per-tenant notes: [references/same-vendor-lms-replay.md](./references/same-vendor-lms-replay.md)
(Also note: this SKILL.md previously had the "Recon → plan → execute" section duplicated — curator
may consolidate.)

### Recon → plan → execute workflow for enterprise redteam

Turning a passive recon report into a ROI-ranked attack plan, executing cheap unauth
CVE probes first, re-ranking when everything comes back patched, and reporting
negative results as intel: [references/enterprise-redteam-recon-to-execution.md](./references/enterprise-redteam-recon-to-execution.md)

### Laravel + Voyager CMS admin (field-proven 2026-10)

Fingerprint `voyager-assets?path=` + `laravel_session` cookie + "Content Management System" titles.
Client-side MD5 password transform breaks raw-credential curl logins; `/admin/profile` Vue props
leak the full 372-route menu + role_id + restricted-list for ANY authed role. Status map (419/403/
302/000) and JSON-XHR mutation pattern: [references/laravel-voyager-admin-recon.md](./references/laravel-voyager-admin-recon.md)

### Swagger/OpenAPI spec mining (field-proven 2026-09)

A public `/swagger.json` or `/v1/swagger.json` under an API host is a full endpoint map — pull and mine it systematically:
```bash
curl -sk https://api.target.com/<ctx>/v1/swagger.json -o spec.json
jq -r '.paths | keys[]' spec.json > endpoints.txt          # full path list
jq -r '.paths|to_entries[]|.key+" => "+(.value|keys|join(","))' spec.json \
  | grep -iE 'post|put|delete|upload|export|import'        # mutating endpoints
jq -r '.definitions|keys[]' spec.json                      # request-body schemas → field names for fuzzing
jq -r '.securityDefinitions' spec.json                     # auth scheme (Bearer/Basic/apiKey)
```
Triage order inside the spec: (1) `file`-type/`multipart` params → upload-shell tests; (2) query params named `OrderBy`, `OrderByDesc`, `SearchTerm`, `sort`, `filter` → SQLi (OrderBy injection is almost never parameterized); (3) `{id}`/`{uuid}` path params on DELETE/PUT → IDOR; (4) `/api/test`, `/api/migration/*`, `/api/debug` → dev leftovers; (5) `*-excel`/`*-pdf` export endpoints → server-side processing, param injection. A 401 on a spec'd endpoint = it exists and needs auth — not a miss.
- **Vietnamese-enterprise swagger**: specs often expose domain verbs (ghichiso/bangke/phancong/kyso...) — translate the nouns to understand the workflow and which PUT chain (nhan-vien-xac-nhan → doi-truong-xac-nhan → phong-kinh-doanh-xac-nhan) is the privilege boundary to attack.

### Recon → plan → execute workflow for enterprise redteam

Turning a passive recon report into a ROI-ranked attack plan, executing cheap unauth
CVE probes first, re-ranking when everything comes back patched, and reporting
negative results as intel: [references/enterprise-redteam-recon-to-execution.md](./references/enterprise-redteam-recon-to-execution.md)

**2026-09 banking-target session (VN) — F5 ASM, Spring swagger, DrayTek, SNI probing: full detail in [references/f5-asm-swagger-draytek-recon.md](./references/f5-asm-swagger-draytek-recon.md). Key traps:**
- F5 ASM returns **HTTP 200 + ~730B HTML error page** for blocked paths (/.env, /.git/config, /actuator/*) — status code lies; check body+size+Content-Type. Spring /v3/api-docs can pass the same WAF that blocks /actuator.
- Spring gateway /v3/api-docs may look empty (`paths:{}`) — fetch /v3/api-docs/swagger-config to enumerate API groups, then each group's spec (165 unauth-readable endpoints on one target). /swagger-ui.html 401 but /swagger-ui/index.html 200.
- Angular main.<hash>.js string literals = gateway route table (/iam/api, /survey/api ...). nginx **405 on POST = route exists/proxied** (existence oracle); 200 index.html = SPA fallback.
- Shodan `hostname:` search on **every apex variant** (.com.vn AND .vn) — surfaces legacy ISP IPs hosting NXDOMAIN'd names (admin./amc./mail.) that are still-live DrayTek edge devices (302 /weblogin.htm + `unsafe legacy renegotiation` TLS error = DrayTek signature). DrayTek follow-up: TLS fix is `ctx.options |= 0x4` in Python (curl SECLEVEL=0 fails); login = POST /cgi-bin/wlogin.cgi with aa/ab = Base64(user/pass), error codes in re-served JS vars (mode=4 = lockout exists → spray slowly); firmware date oracle = `var buildtime=` in weblogin.htm; full CVE probe matrix + login reverse: [references/f5-asm-swagger-draytek-recon.md](./references/f5-asm-swagger-draytek-recon.md).
- Probe vhosts **by hostname+SNI, never bare IP**: raw-IP TLS answered on 4/17 IPs vs 9 with SNI. Timeout-with-SNI on vpn/mail/lync hosts = IP allowlist, classify "exists, allowlisted".

### TLS Certificate as Recon Source
Grab certs from every live 443 host even when the site serves nothing useful:
```bash
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```
What to mine:
- **SANs** → additional hostnames / related domains not in DNS brute results
- **EV subject fields** → legal entity name, registration number, street address
- **Expired-but-still-served certs** → abandoned services whose DNS is still published
- **Wrong-hostname wildcard** (e.g., parent-company `*.bank.com.vn` served on a subsidiary vhost) → shared infrastructure and misconfigured vhosts
- **Issuer + validity window** → renewal cadence hints at ops maturity
- **Wildcard cert ≠ new hosts**: a `*.target.com` Sectigo DV cert served on every
  subdomain adds NOTHING beyond the apex — don't over-report SANs as new intel.

### Tableau Server fingerprint & attack surface (field-proven 2026-09)

`Title: Tableau` or Tableau JS markers on a corp subdomain = Tableau Server — attack surface beyond the viz UI:
- **REST/vizportal API**: `/vizportal/api/web/v1/getSessionInfo`, `/vizportal/api/web/v1/auth/signin`, `/vizportal/api/rest/v1/` — classic Tableau REST auth surface
- **GraphQL metadata**: `/api/exp/metadata/graphql` (proxies `/relationship-service-war/graphql`) — returns 401 JSON when exists; try introspection once authed
- **Admin routes often exposed**: `/addUser/`, `/removeUser/`, `/authn-service/authenticate/`, `/vizql/showadminview/{datasources/DatasourceOwnerPanel,lenses/AskDataUsageAnalytics,views/WhoHasSeen}`
- **`/en/embeddedAuth.html?path=<urlencoded>`** — takes an arbitrary internal path → open-redirect / SSRF candidate
- Crawl noise warning: katana on Tableau pulls ~700 `/content-exploration/search-microview/*` JS-internal paths — filter aggressively, they're client-side route names not server endpoints; also leaks `localhost:9411/api/v2/spans` (Zipkin) in bundles.

### Exchange & VPN-Gateway Fingerprinting via Error Pages (field-proven)

**Exchange on-prem behind F5 BIG-IP**: `/owa/` and `/ecp/` are often path-filtered
(TCP reset right after the request is sent), but sibling vdirs still answer — and the
**401 response itself leaks everything, no credentials needed**:
- `GET /ews/exchange.asmx` and `GET /autodiscover/autodiscover.xml` → 401 carrying
  `X-OWA-Version: 15.2.2562.37` (15.1.x=Ex2016, 15.2.x=Ex2019, 15.20.x=SE; build date
  maps to CU — builds ≥ 2021-04 mean the ProxyLogon/ProxyShell family is patched),
  `X-FEServer: VEXCHMAIL01A` (internal FE hostname → AD naming convention), and
  `WWW-Authenticate: Negotiate, NTLM, Basic realm=...` + `X-OAuth-Enabled: True`
  (spray surface: EWS Basic auth is the cleanest password-spray route when the OWA UI
  itself is blocked).
- Mixed reset-vs-401 across vdirs = path-level ACL on the BIG-IP: probe
  /owa/ /ecp/ /ews/ /autodiscover/ /mapi/ individually instead of assuming the whole
  server is dark. A reset on /owa/ does NOT mean Exchange is unreachable.

**Pulse Secure / Ivanti Connect Secure (ICS)**:
- The welcome.cgi title is usually CUSTOMIZED (company name) — version does NOT leak
  there. Version signals: `Copyright (c) <YEAR> by Ivanti Inc` inside
  `/dana-na/auth/lasterror.cgi` (2022 ≈ 22.x train); `DSBrowserID`/`DSSIGNIN`/`DSIVS`
  cookies confirm ICS.
- Unauthenticated CVE probe set (one curl each, non-destructive). A 403 that returns
  the HTML login page = endpoint exists, patch/WAF blocks it — NOT a miss; 404-style
  JSON would mean a different story:
  `POST /api/v1/tuition/user/passwd-less` → 403 = CVE-2023-46805 patched;
  `POST /api/v1/tuition/node/status` → 403 = CVE-2024-21887 patched;
  `/dana/html5acc/guacamole/` traversal variant → 403 = CVE-2024-3400 patched;
  `POST /dana-ws/saml20.ws` → 403 = CVE-2024-21893 patched.
- **Client → server version inference**: public `software.<domain>` directory listings
  host the installers enterprises ship to staff. The newest client build
  (e.g. `ps-pulse-win-22.8r4-b38767.msi`) tracks the server train; the full listing
  history (9.1r8 → 22.2r1 → 22.6 → 22.8r7) reveals upgrade cadence = patch posture.
  `.Trash-1000/info/*.trashinfo` files timestamp the upgrades. When all 2024 CVE probes
  return 403 AND the client train is current, RE-RANK password spray + AiTM phishing
  above further CVE hunting instead of rabbit-holing on version disclosure.

---

## 5. ENDPOINT DISCOVERY

### Directory Brute Force
```bash
# ffuf (fastest):
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200,301,302,403 -t 50 -o dirs.txt

# Gobuster:
gobuster dir -u https://target.com -w wordlist.txt -x php,html,js,json

# feroxbuster (recursive):
feroxbuster -u https://target.com -w wordlist.txt -x php,html,txt -r
```

### Parameter Discovery
```bash
# Arjun (hidden parameter finder):
arjun -u https://target.com/api/endpoint

# x8:
x8 -u https://target.com/api/endpoint -w params-wordlist.txt
```

### JavaScript Source Mining
```bash
# Extract endpoints from JS files:
gau target.com | grep '\.js$' | httpx -mc 200 | xargs -I{} curl -s {} | \
  grep -oE '"/[a-zA-Z0-9/_-]+"' | sort -u

# LinkFinder:
python3 linkfinder.py -i https://target.com -d -o output.html

# GetAllURLs (gau):
gau target.com | sort -u > all_urls.txt

# Wayback URLs:
waybackurls target.com | sort -u > wayback_urls.txt
```

### SPA Bundle Opensource & License Extraction (field-proven)

Modern SPAs (Create React App, Angular CLI, Vite, Webpack) build artifacts with distinct patterns to uncover third-party open-source components and backend environments:

1. **Webpack / CRA License Artifacts**:
   - Webpack builds often emit `<main_chunk>.js.LICENSE.txt` alongside bundle files (e.g. `main.319e29b1.js.LICENSE.txt`).
   - Directly reveals embedded libraries, authors, and exact versions without minification noise (e.g. `DOMPurify 3.4.13`, `classnames`, `moment`).
2. **Angular CLI / esbuild Artifacts**:
   - Check CSS variable namespaces in HTML/styles: `--bs-*` (Bootstrap), `--mat-*` (Angular Material), `--p-*` (PrimeNG/PrimeVue).
   - Zone.js string patterns in `polyfills-*.js` or chunk files (`Zone.js (Polyfilling Promise)`) identify Angular standalone builds.
3. **Environment & Sandbox Leakage in Bundles**:
   - Grep compiled chunks for sandbox, UAT, or internal API domains:
     `grep -oiE 'https?://[a-zA-Z0-9\.\-]+\.(org|com|vn)[a-zA-Z0-9/_\-\.]*' <chunk>.js`
   - Frequently exposes non-production hosts used by developers that bypassed security controls (e.g., `api-sandbox.bank.com.vn`, `applite-uat.vendor.vn`).

### API Endpoint Discovery
```bash
# Common API paths:
ffuf -u https://target.com/FUZZ -w /SecLists/Discovery/Web-Content/api/api-endpoints.txt

# Swagger/OpenAPI:
test: /swagger.json /api-docs /openapi.json /v2/api-docs /.well-known/ /docs/
# Spring gateway trap (2026-09): /v3/api-docs may return a valid-but-EMPTY spec
# ({"paths":{}}). Immediately fetch /v3/api-docs/swagger-config → {"urls":[...]} lists
# every API GROUP spec (/v3/api-docs/<group>) — 165 unauth-readable endpoint specs on one
# target. Also: /swagger-ui.html → 401 while /swagger-ui/index.html → 200.

# GraphQL:
test: /graphql /gql /v1/graphql /api/graphql
```

### Angular SPA gateway-route mining (field-proven 2026-09)

Angular `main.<hash>.js` bundles embed the backend gateway route table as plain string
literals. Fetch index.html → get exact hashed main.js filename → grep `"/[a-zA-Z0-9/_.-]{3,}"`:
one app leaked 510 route literals (approval-batch, adjustment-invoice, annual-leaves,
access-control/api, /iam/api, /survey/api, /storage/api ...). Interpretation rules:
- Gateway prefix + trailing slash → 200 SPA index.html = fallback, not the API
- POST to a real proxied path → nginx **405 = route EXISTS and is proxied** (existence oracle)
- **Spring-style JSON 404 body (`{"timestamp":...,"path":...,"status":404,"requestId":...}`) = you are INSIDE a live Spring gateway context**, even when the path itself 404s (e.g. `/amcapi/v3/api-docs` → this JSON while `/amcapi/actuator/*` gets F5-blocked): the gateway context is alive, try group enumeration + sibling prefixes before giving up
- 404 = not routed. Full pattern + examples: [references/f5-asm-swagger-draytek-recon.md](./references/f5-asm-swagger-draytek-recon.md)

---

## 6. SOURCE CODE RECON

### GitHub / GitLab Exposure
```bash
# trufflehog (secret scanner in git history):
trufflehog git https://github.com/target-org/target-repo

# gitleaks:
gitleaks detect --source /path/to/cloned/repo

# Manual GitHub search:
# site:github.com "target.com" "api_key" OR "secret" OR "password"
# site:github.com "target.com" ".env" OR "config.php" OR "db_password"

# GitHub dorks:
# "target.com" extension:env
# "target.com" filename:*.config password
# org:target-org secret OR password OR apikey
```

### WordPress / CMS quick fingerprint (passive)

```
/wp-json/                          → site name, REST namespaces (plugin inventory:
                                     wordfence, yoast, tribe/events, ai1wm, auth0, wpmudev...)
/wp-json/wp/v2/users               → 401 = user enumeration hardened; 200 = leak
X-Pingback: /xmlrpc.php header     → xmlrpc.php likely still enabled (brute/pingback abuse)
/wp-content/cache/minify/*         → minify plugins hide theme/plugin paths & versions
```

### Exposed Environment Files
**⚠️ WAF false-positive (F5 ASM, field-verified 2026-09):** behind F5 ASM every dotfile/backup
probe (/.env /.git/config /backup.zip /web.zip /.DS_Store) returns **HTTP 200** with a
~730-byte generic HTML error body ("This page can't be displayed... incident ID is: N/A").
200 ≠ file exists — verify body + Content-Type + size before reporting. Same WAF returns
200+error-page for /actuator/* while /v3/api-docs passes unfiltered on the same host.

```
# Check common paths:
https://target.com/.env
https://target.com/.git/config
https://target.com/config.json
https://target.com/config.yaml
https://target.com/credentials.json
https://target.com/secrets.json
https://target.com/wp-config.php
https://target.com/backup.sql
https://target.com/backup.zip
```

---

## 7. ZSEANO'S TESTING METHODOLOGY

### Core Philosophy
1. **Go deep on one program** rather than spread across many — learn the application thoroughly
2. **Build a profile of the company** — tech stack, developers, processes
3. **Look where others don't** — check error pages, admin paths, old versions, mobile API
4. **Follow the filter** — if input is filtered somewhere, that functionality exists and may be bypassed

### Testing Sequence (One Page / Feature)
```
For each input point:
1. Non-malicious HTML tags (<h2>, <img>) → are they reflected?
2. Incomplete tags → what happens? (<iframe src=//evil.com )
3. Encoding tests → %0d, %0a, %09, <%00
4. Observe the OUTPUT too (not just response) — where does your input appear?
5. Test same input in ALL similarly-structured pages (shared code → shared vuln)
6. Check if the same parameter exists in mobile/API endpoint (less protected)
```

### Parameter Insights
```
- Each parameter tells a story: "what does this do server-side?"
- Filename → OS interaction → Path Traversal / CMDi
- URL/location → HTTP fetch → SSRF
- Template/HTML parameter → render function → SSTI
- XML field → parser → XXE
- SQL filter → query → SQLi
- User-content → storage → Stored XSS
```

---

## 8. BUG BOUNTY PLATFORM ROE COMPLIANCE (apply BEFORE any request touches the target)

- **Intigriti**: ALL requests need header `X-Bug-Bounty-Intigriti: <username>` + User-Agent `Bug-Bounty-Intigriti - <username> -`; per-program rate caps (commonly max 2 req/s) and special rules (webshop purchase boundaries, no-disruption clause) are stated on the program page. ⚠️ Field lesson (2026-09 GlobalSign/Intigriti session): the header must go on request #1 — including Auth0 login flows, API calls via curl/execute_code, and every JS-chunk fetch — not just the browser session. Set the ROE headers once in your shared curl/HTTP helper before the first request; retrofitting after hundreds of logged requests means non-compliant traffic already happened.
- **Extract scope with a REAL BROWSER**: program pages are SPAs and platform JSON APIs 403 unauthenticated requests (browser_navigate → full snapshot → click "Expand all" to reveal every asset row; fall back to browser_vision to read truncated tables).
- Capture scope, tiers, bounty amounts and RoE into the recon report file BEFORE testing; list out-of-scope paths explicitly.
- Request header values in scope tables often hide mandatory headers — expand rows before assuming only URLs are in scope.
- Field-tested specifics (JWT issuer probes, BIG-IP decode, Posti case): see [references/bugbounty-roe-and-techniques.md](./references/bugbounty-roe-and-techniques.md)

### SPA login forms that block browser automation (field-proven)

Vue/jQuery-controlled login modals often fail under browser automation: typed values don't register with the framework's event handlers, so client-side validation (\"enter a valid email\") blocks submission before any server request — burning zero real login attempts but zero progress. Don't retry the UI; extract the real submit path instead:

1. **Pull the site's JS bundles** and grep for the submit handler: `ajaxLogin`, `doFormSubmit`, `postJSON`, `$.ajax(` — the handler reveals the transport (`$.postJSON($form.attr(\"action\"), $form.serialize())` → POST to the form's own action URL).
2. **Reproduce with curl** (skip the UI entirely):
   ```bash
   curl -sk -X POST "https://target.com/login/" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Requested-With: XMLHttpRequest" \
     -H "Referer: https://target.com/login/" \
     --data-urlencode "username=<email>" --data-urlencode "password=<pw>"
   ```
   `X-Requested-With: XMLHttpRequest` + `Referer` are commonly required (CSRF-lite). If the modal HTML isn't in the page source, the form is injected at runtime — the action URL is usually still the page path itself (`/login/` → POST `/login/`).
3. **Discover param names via the error response**: an Apigility/Laminas-style JSON error reports WHICH field failed: `{"field":"email","errors":["email"],"valid":["password"]}` means the `email` param name was recognized but invalid format; switch to `login_email` / `username` variants until the failing field flips to `password` — that's the correct param set.
4. **Field-level errors = email validity oracle**: \"invalid email format\" vs \"wrong password\" responses confirm the account email exists without hitting lockout counters (lockout usually counts password failures). This also catches stale credentials fast: both test-account passwords wrong → ask the triage contact to rotate instead of burning attempts.
5. Log every attempt in the progress file; never exceed ~5 password attempts per account even when the API doesn't enforce the lockout the UI claims.

### High-Value Target Selection
```
✓ Programs with large scope (*.target.com)
✓ Programs that pay for P2/P3 (not just RCE)
✓ Programs with recent tech changes (migrations = new bugs)
✓ Programs with active development (new features = new attack surface)
× Avoid: frozen/old codebases with well-known CVEs (already claimed)
× Avoid: strict programs with narrow scope (less surface)
```

### High-Value Feature Focus (by bug probability)
```
Priority 1: Authentication, password reset, 2FA → account takeover
Priority 2: File upload, profile edit, API endpoints → stored XSS, IDOR
Priority 3: Admin panels, user management → BFLA, privilege escalation
Priority 4: Payment flows, subscription → business logic
Priority 5: Import/export, template rendering → XXE, SSTI
```

---

## 9. NUCLEI TEMPLATES (AUTOMATED SCANNING)

```bash
# Run all on target:
nuclei -u https://target.com -t /nuclei-templates/ -o nuclei-results.txt

# Specific categories:
nuclei -u https://target.com -t cves/ -severity critical,high
nuclei -u https://target.com -t exposures/
nuclei -u https://target.com -t misconfiguration/

# On subdomain list:
cat subdomains.txt | nuclei -t exposures/ -t misconfiguration/ -o exposed.txt
```

---

## 10. COMMON MISCONFIGURATIONS (QUICK WINS)

```
□ CORS: Access-Control-Allow-Origin: * with credentials → CSRF + data theft
□ S3 bucket public: curl https://target.s3.amazonaws.com/
□ Directory listing: response contains "Index of /"
□ .git exposed: curl https://target.com/.git/config
□ .env exposed: curl https://target.com/.env
□ Debug mode: stack traces in production (source code exposure)
□ Default credentials: admin:admin, admin:password on admin panels
□ phpinfo.php: curl https://target.com/phpinfo.php
□ Backup files: config.bak, database.sql.gz, app.zip
□ GraphQL introspection enabled: POST /graphql {"query":"{__schema{types{name}}}"}
□ Admin panels: /admin /manager /console /phpmyadmin /wp-admin
□ Split-horizon DNS leak: public DNS returns RFC1918 IPs (10.x / 172.16-31.x / 192.168.x) for internal hostnames (e.g. dagster.prd.<cloud-domain> → 10.14.47.142) — infra disclosure, reportable as info/low; sweep resolved CT hosts for private ranges
□ F5 BIG-IP cookie disclosure: `BIGipServer<pool>=rd<N>o<hex>o<hex>` → last 8 hex chars of part 2 = little-endian internal IP, part 3 = hex port; pool name leaks DMZ naming convention
□ Unauthenticated token issuers: POST .../anonymous_token-style endpoints return signed JWTs — decode header/payload (alg, kid, iss, aud, role claims); probe role params (?role=admin, body {"role":...}); then test sibling APIs with the token — rejection ("could not be verified") may be audience mismatch by design, verify with a real account before reporting
□ Next-auth callbackUrl: /signin?callbackUrl=... on admin portals — classic open-redirect candidate
□ PingFederate footprint: /uas/oauth2/authorization path + client_id in 302 Location; follow-up checks: PKCE enforcement, state validation, per-client redirect_uri allowlist
□ Runtime config.js on SPA shells (field-proven): /config.js or window.__PORTAL_APP_CONFIG__
  maps EVERY backend service (portal API, payment gateway, CLM inventory/scanner, notifications,
  user-admin — often raw AWS execute-api URLs) plus third-party keys. Leaked OAuth
  CLIENT_SECRETs for "confidential" clients are reportable even when the referenced
  endpoint is NXDOMAIN/dead (e.g. a UBI Secure secret on a legacy host).
□ Angular-container runtime config (field-proven 2026-10): `/assets/env.js` is the envsubst
  variant of the above — a tiny JS file (`window.env = {...}`) rewritten from env vars at
  container start. One fetch yielded `apiUrl` (the real backend host), `ssoClientId`,
  `ssoFeUrl` and `ssoReturnUrl` for the whole SSO flow. Cheap check on every Angular host:
  GET /assets/env.js; also try /assets/config.js, /assets/environment.js.
□ LOGIN PAGES leak auth architecture — read them as recon, not just as a form. Grep the page
  HTML + submit-handler JS for the IdP config: `apiKey`/`authDomain`/`projectId` (Firebase),
  `clientId`/`domain`/`audience` (Auth0), `region`/`userPoolId` (Cognito), `realm`/`url`
  (Keycloak), `email_domain`, `freeRegisterAble`. A Firebase `apiKey` + open self-signup flag
  on a corporate LMS is itself a finding (no WAF, free account enumeration).
□ Third-party auth delegation changes your whole test plan: if the form delegates to
  Firebase/Auth0/Cognito, the app's own `/auth/login` is a dead session-sync route and
  spraying it yields nothing. See the credential-spraying skill for the branch-tracing method.
□ AWS API Gateway error-shape fingerprinting: "Missing Authentication Token" (no auth) vs
  "IncompleteSignatureException" (Bearer rejected) vs "Invalid key=value pair (missing
  equal-sign)... SHA-256/Base64" (SigV4 required — JWT Bearer will never work there) vs
  `{"message":null}` (route exists behind IAM authorizer). Fingerprint BEFORE spending time.
□ Internal secret-key names in error bodies (e.g. "Could not find a secret with key
  'SG-<ORG>-PK-PROD'" from a payment gateway) = architecture info-disclosure (low).
□ Bearer JWT claims = free recon: decode `permissions: [...]`, custom `ns|account_id`,
  entitlements, org_id — the API's own authorization model, feed into BFLA testing.
```

---

## 11. QUICK REFERENCE TOOLS

| Category | Tool |
|---|---|
| Subdomain enum | subfinder, amass, massdns |
| Port scan | nmap, masscan, naabu |
| HTTP probe | httpx (PD — call `~/go/bin/httpx.exe` on this host) |
| DNS resolve | dnsx (strips ANSI before parsing) |
| Dir brute | ffuf, feroxbuster, gobuster, dirsearch |
| Web crawl | katana, hakrawler |
| JS mining | LinkFinder, gau, waybackurls |
| Secret scan | trufflehog, gitleaks |
| Parameter fuzz | arjun, x8 |
| Vuln scan | nuclei |
| Proxy/intercept | Burp Suite Pro |
| JWT attacks | jwt_tool |
| SQLi | sqlmap |
| XSS | dalfox, XSStrike |
| SSRF | SSRFmap, Gopherus |
| OSINT intel | shodan CLI, SecurityTrails API, Cavalier/HudsonRock |

---

## 12. JAVA MIDDLEWARE FINGERPRINT MATRIX

| Middleware | Detection Path | Key Indicators |
|---|---|---|
| Apache Tomcat | `/manager/html`, `/manager/status` | Default creds: `tomcat:tomcat`, `admin:admin` |
| JBoss / WildFly | `/jmx-console/`, `/web-console/` | JMX MBean access, WAR deployment |
| WebLogic | `/console/`, `/wls-wsat/` | T3 protocol on 7001/7002, IIOP |
| Spring Boot Actuator | `/actuator/`, `/actuator/env`, `/actuator/heapdump` | JSON endpoint listing, heap dump contains secrets |
| Spring Boot (alt paths) | `/actuator/jolokia`, `/actuator/gateway/routes` | Jolokia JMX bridge, Gateway route injection |
| Jenkins | `/script`, `/manage` | Groovy console, API token in cookie |
| GlassFish | `/common/`, `/theme/` | Admin on 4848, default empty password |
| Jetty | `/jolokia/` | JMX access |
| Resin | `/resin-admin/` | Admin panel |

### Hosting Control Panels (DirectAdmin / cPanel / Plesk / Webmin)

See `references/control-panel-fingerprinting.md` for the full matrix: signature headers, login paths, version-disclosure endpoints, and the key technique of extracting skin/UI version from the SPA JS bundle when the core version is hidden from unauthenticated users (e.g. DirectAdmin Evolution skin `0.26.1` exposed via `evo/index.<hash>.js` while core DA version stays hidden).

Key quick-wins:
- DirectAdmin: `Server: DirectAdmin Daemon`, `X-Directadmin: Unauthorized`, `/CMD_LOGIN`, `/evo/login` (Evolution), `/CMD_API_ACCOUNT_USER` → 401 confirms API up
- cPanel: `Server: cpsrvd/<version>` leaks directly
- Webmin: `Server: MiniServ/<version>` leaks directly
- DirectAdmin core version is intentionally HIDDEN unauthenticated — don't waste time; report skin version instead

### Spring Boot Actuator Exploitation Priority

```
/actuator/env          → Leak environment variables (DB creds, API keys)
/actuator/heapdump     → Download JVM heap → search for passwords in memory
/actuator/jolokia      → JMX → possible RCE via MBean manipulation
/actuator/gateway/routes → Spring Cloud Gateway → SpEL injection (CVE-2022-22947)
/actuator/configprops  → All configuration properties
/actuator/mappings     → All URL mappings (hidden endpoints)
/actuator/beans        → All Spring beans
/actuator/threaddump   → Thread dump (may leak session tokens / secrets in stack frames)
```

---

## 13. INFORMATION LEAK DETECTION CHECKLIST

### Version Control & Backup Leaks

```
/.git/HEAD                    → Git repository exposed
/.svn/entries                 → SVN metadata
/.svn/wc.db                   → SVN SQLite database
/.hg/requires                 → Mercurial
/.bzr/README                  → Bazaar
/.DS_Store                    → macOS directory listing
```

### Backup File Patterns

```
/backup.zip    /backup.tar.gz    /backup.sql
/wwwroot.rar   /www.zip          /web.zip
/db.sql        /database.sql     /dump.sql
/config.php.bak    /config.php~    /config.php.swp
/.config.php.swp   /wp-config.php.bak
/.env          /.env.bak         /.env.production
```

### API Documentation & Debug

```
/swagger-ui.html              → Swagger/OpenAPI
/swagger-ui/                  → Swagger UI
/api-docs                     → API documentation
/graphql                      → GraphQL playground
/graphiql                     → GraphQL IDE
/debug/                       → Debug endpoints
/phpinfo.php                  → PHP configuration
/server-status                → Apache status
/server-info                  → Apache info
/nginx_status                 → Nginx status
```

### Cloud & Infrastructure

```
/.aws/credentials             → AWS credentials
/.docker/config.json          → Docker registry auth
/robots.txt                   → Disallowed paths (hint list)
/sitemap.xml                  → Full URL listing
/crossdomain.xml              → Flash cross-domain policy
/.well-known/                 → Various well-known URIs
```
