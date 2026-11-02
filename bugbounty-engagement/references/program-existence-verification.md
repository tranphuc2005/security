# Program Existence Verification — confirm a bug bounty program BEFORE recon

Field-verified 2026-09, UZ Brussel (uzbrussel.be). A full passive recon + unauth
CVE-probe session (Ivanti fingerprinting, Exchange 401-header leak, Keycloak
hardening checks, stealer-log intelligence) produced solid findings — then the
user asked for bug bounty, and no program existed anywhere. The recon value was
redteam-only. Cost: one session of effort mis-directed relative to the goal.

## The 5-step verification ladder (5 minutes, run in order)

### 1. Intigriti public program search (SPA — use the browser)
- `browser_navigate` → `https://www.intigriti.com/researchers/bug-bounty-programs`
- Type the target name into the Search box, submit, then
  `browser_console(expression="document.body.innerText")` → contains "No results"?
- **Search partial org words** ("brussel", "leuven", the sector) — this is ALSO the
  discovery step for the pivot target list (same-sector programs paying bounties).
- Gotchas: the public REST endpoints (`api.intigriti.com/...`) 404 without auth —
  don't bother. The cookie banner does not block the search box.

### 2. Platform profile 404 checks (curl, one line each)
```bash
curl -s -o /dev/null -w "%{http_code}" https://hackerone.com/<target>     # 404 = none
curl -s -o /dev/null -w "%{http_code}" https://bugcrowd.com/<target>      # 404 = none
curl -s -o /dev/null -w "%{http_code}" https://yeswehack.com/programs/<target>
```

### 3. security.txt
```bash
curl -sk -o /dev/null -w "%{http_code}" https://<target>/.well-known/security.txt   # + www.
```

### 4. Sitemap crawl for a disclosure page
- Enterprise CMS (Liferay) serves a **sitemapindex** — the index lists CHILD sitemap
  URLs only. Fetch the child sitemaps to get real page URLs; grepping the index for
  page keywords returns nothing (classic false-negative).
- ~500 child sitemaps fetched with a 16-thread Python `urllib` pool (CERT_NONE
  context, 25s timeouts) = ~35s for ~1700 page URLs. Grep for
  `disclos|meldpunt|veilig|security|kwets|vulnerab`.
- A "Meldpunten"/contact page listing only DPO / whistleblower / feedback channels
  = organization has NO security intake. Only disclosure route = DPO email
  (e.g. gegevensbescherming@<target>) — goodwill only: **no bounty, no safe
  harbour**. Flag the legal exposure of active testing explicitly in the report.

### 5. Search fallback (when browser search engines are blocked)
```bash
curl -s "https://html.duckduckgo.com/html/" --data "q=<target> \"responsible disclosure\"" \
  -H "User-Agent: Mozilla/5.0" | grep -oE 'result__a[^>]*>[^<]*'
```
Also surfaces the program detail-page URL (e.g.
`app.intigriti.com/programs/<org>/<program>/detail`) — feed that into the
§2 intake recipe (`document.body.innerText` full-text read).

## Outcome handling

**No program found** → stop, report the evidence table (platform / status), state
the DPO-email-only path + its risks, and propose the pivot: the same-sector
programs that DID surface in step 1. Recon tooling and methodology transfer
nearly 1:1 — subdomains, Exchange/ADFS hosts (autodiscover, sts), eCRF
(REDCap-analog), extranet, PACS portals are the standard hospital-perimeter
asset set.

**Program found** → proceed to §2 intake (scope + RoE) BEFORE any target request,
per the ROE-compliance rules.

## Worked example — UZ Brussel → UZ Leuven (2026-09)

| Check | UZ Brussel result |
|---|---|
| Intigriti search "uzbrussel" / "brussel" | No results |
| H1 / Bugcrowd / YesWeHack profiles | 404 / 404 / 404 |
| security.txt (apex + www + VUB parent) | 404 |
| Sitemap crawl (1693 URLs) | no disclosure page; Meldpunten = DPO/whistleblower/feedback only |
| DDG search | no program; surfaced Intigriti blog + program pages |

Pivot surfaced by the same search: **UZ Leuven** (€50–€5.000; Tier 1 includes
autodiscover/Exchange, ecrf, extranet, sts/ADFS, splunk HF; interests: "leaking
of personal and medical data", "administrative access"), **eHealth Hub VZN KUL**
(≤€2.000), **Nexuzhealth Web PACS** (≤€1.000; patient PACS login = DOB + study
code → enumeration/IDOR surface).

UZ Leuven RoE specifics worth noting for Intigriti-wide patterns: @intigriti.me
email REQUIRED for submissions, header `X-Intigri-Username: {Username}`-style
request header (exact name per program page), max 5 req/s, automated scanners
BANNED (scanner-found submissions rejected), zero-day 14-day cooldown clause.
⚠️ The RoE header NAME differs across Intigriti programs (Posti used
`X-Bug-Bounty-Intigriti`) — always read the CURRENT program page's "Rules of
engagement" block instead of reusing a previous program's header.
