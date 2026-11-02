# Enterprise Redteam Recon → Plan → Execute Workflow (field-proven, UZ Brussel 2026-09)

Pattern for authorized enterprise redteam against a hospital-scale org (works for any
large org with VPN gateways, SSO, Exchange, and a mix of prod/test environments).

## 1. Recon report → attack plan (the handoff that matters)

Write RECON_REPORT.md first (passive: subdomains, Shodan, CT logs, stealer intel,
split-horizon leaks), then convert it into REDTEAM_PLAN.md with a strict structure:

```
PHASE 0 — passive prep (downloads, cookie decode, cred intel, phishing infra)
PHASE 1 — initial access vectors V1..Vn, each with exact URLs + CVE names + fallback
PHASE 2 — post-foothold pivot map (internal RFC1918 targets from DNS leaks)
PHASE 3 — objectives (data, persistence, exfil channels)
THỨ TỰ THỰC HIỆN — ROI-ranked execution order
```

Why: a written plan forces ranking by expected value BEFORE tool time, and gives a
diffable artifact when reality diverges (it will).

## 2. Execute in probe-first order — every CVE gets a cheap unauth check first

One curl per CVE before any exploitation attempt. Record status + body shape:

| Probe | Result read |
|---|---|
| ICS `/api/v1/tuition/user/passwd-less` POST | 403 + HTML login page = patched |
| ICS guacamole traversal variant | 403 = patched |
| F5 `/mgmt/` | 302 → gated, not exposed |
| Keycloak redirect_uri variants | 400 = strict |
| Laravel `/.env`, `/_ignition/health-check` | 404 = clean |

**The decisive move this session: after ~10 negative probes, RE-RANK and pivot.**
All major CVE paths blocked + client versions current + cookie encryption on = a
well-patched org. The remaining vectors (password spray via EWS Basic auth, AiTM
phishing of the customized VPN login page, M365 attacks) are credential-centric, not
CVE-centric. Burn the report section listing "đã loại bỏ" (ruled out) — negative
results are intel, and re-ranking IS the deliverable, not a failure.

## 3. Key artifacts that keep paying off

- `software.<domain>` public directory listing = free version + patch-cadence intel
  (client installers track server train; `.Trash-1000/info/*.trashinfo` dates upgrades).
- Exchange 401 headers from /ews/ + /autodiscover/ even when /owa/ resets:
  X-OWA-Version (exact build → CU → CVE-era), X-FEServer (internal hostname),
  WWW-Authenticate list (Basic = spray surface).
- Stealer-log URL inventory (Cavalier): which login page do the most infected
  employees actually use? That page is the phishing template (12 machines on the
  Pulse welcome.cgi → it's the AiTM target, not a generic OWA clone).

## 4. Report back with re-ranked vectors

EXECUTION_REPORT.md sections: per-vector verdict (patched/clean/open), the ONE
significant finding (here: Exchange build + hostname + auth methods leaked via 401),
and the new priority list with justification. Store artifacts next to reports in the
target directory (pentest/<target>/).

## Pitfalls hit this session

- Recursive crawl of Apache listings with .Trash-1000/self-referential dirs loops —
  cap depth AND dedupe visited paths, fetch the listing body per directory fresh.
- `curl -w '%{http_code}'` inside f-strings/quotes in MSYS: escape braces.
- Python multi-line via `python -c` with repr() mangles newlines on MSYS — use
  execute_code (direct Python) instead of terminal round-trips for requests-based probes.
- Some Exchange vdirs reset connections (path-level ACL on BIG-IP) while siblings
  answer 401 — never conclude "server dark" from one path.
- OWA probes need a browser User-Agent AND the right path; default curl UA on /owa/
  root got a 302, but logon.aspx needed exact URL + UA to behave predictably.
