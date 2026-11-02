# Cloudflare + wildcard-DNS targets: origin recon (field-proven 2026-10, epu.edu.vn)

Context: apex `epu.edu.vn` behind Cloudflare with a wildcard `*.epu.edu.vn` A record → every
subdomain "resolves" to the CF edge, so subdomain brute gives nothing and 404s are invisible.
What actually moved the needle.

## 1. Origin IP discovery (the real recon step)
Wildcard + CF kills brute force. Pivot to origins instead:
- **SecurityTrails historical A**: `GET /v1/history/<apex>/dns/a` with `APIKEY:` header →
  `records[].values[].ip` lists the PRE-Cloudflare real IPs (plus CNAMEs). This is the single
  best origin source. Also `GET /v1/domain/<apex>/subdomains?include_inactive=true` (paginate
  with `&page=2` — the API returns 100/page).
- **`shodan domain <apex>`** → full A/CNAME table; any row pointing at a NON-CF IP is a live
  origin (e.g. `admin.examenglish A 14.225.44.221`, `vpn A 183.91.6.225`).
- **`shodan host <ip>`** → `Hostnames:` field groups every apex sharing that IP (catches
  shared-VPS / third-party-SaaS hosting, e.g. cert `supperadmin.vuaclass.com` on an EPU host).
- **dnsx sweep** (`dnsx -l subs -a -resp`): filter OUT `104.2x/172.6x/2606:4700` (CF edge) —
  whatever survives is the real origin set.

Resulting EPU origin map (example of the output shape): CMC Telecom `183.91.13.114-117`
(IIS 8.5 origin cluster), VNPT VPS `14.225.44.221` (Yii2/PHP7.4), SonicWall `183.91.6.225`
+ `14.238.33.242`, Asterisk PBX `118.70.186.89`, DrayTek Vigor `117.6.242.76`.

## 2. Direct-to-origin probing
`curl -H "Host: <sub>" http://<origin-ip>/` → often IIS/Apache `404 Not Found`. That 404 is
NOT a miss: it proves you are talking to the ORIGIN, bypassing the CF WAF. Probe both 80 and
443 (`-k`, Host header). Non-standard-port services (SonicWall 4433, DrayTek 4443) answer on
the origin IP directly.

## 3. Secondary apex discovery via third-party scripts
Rendered HTML of the main SPA leaked `https://track.epu.io.vn/script.js` (an analytics tag) →
whole new apex `epu.io.vn` with its own subs `prompt` (AI gateway), `qr` (QR generator),
`jest`, `track` (Next.js). Rule: grep rendered HTML for every `https?://…` and treat any new
apex as a fresh recon target.

## 4. Control-IP test to confirm a SYN-proxy / ISP shield
nmap reported ~100 "open" ports on BOTH target IPs (and garbage low ports 7/9/13/21…).
Proof it was a shield, not reality: scan a KNOWN-DEAD neighbour IP in the same /24
(`14.225.44.250`) — it also reported ~100 open ports. App-layer probes on those ports
returned `000`. Conclusion: discard all connect-scan output; use `shodan host <ip>` for
ground-truth ports. (App-layer on the dead IP should be empty; if it "opens" everything,
you're behind the shield.)

## 5. Stack fingerprints captured this session
| Stack | Discriminator |
|---|---|
| Yii2 (advanced) | cookie `advanced-backend` + `_csrf-backend`; form `LoginForm[username]`; POST w/o CSRF → 400 |
| OJS | theme asset `?v=3.4.0.8`; `/index.php/<journal>/login` 200, `/admin`→302 |
| BazaCMS (VN CMS) | `/ContentV2/css/Baza.css`; URL `/chi-tiet-tin/<slug>-<catid>-<id>.html`; `/Account/Login`→500 |
| SonicWall SSL-VPN | `Server: SonicWALL`, meta `id="sslvpnLogin"`, `/api/sonicos/`→403; port 4433 |
| DrayTek Vigor | cert `CN=Vigor Router`; title "Vigor Login Page"; port 4443; CVE-2022-32548 |
| SvelteKit | `_app/immutable/entry/{start,app}.<hash>.js` + `data-sveltekit-preload-data` |
| base44 / Caddy+uvicorn SPA | `via: 1.1 Caddy` + `x-render-origin-server: uvicorn`; `base44_access_token` |
| Asterisk PBX origin | TLS cert `CN=phone1.neutral, issuer Asterisk Private CA` |
| Internal-host leak | custom header `server-interact: EPU-SRV-WEB06` |

## 6. Pitfalls
- crt.sh returned 502 and web.archive.org CDX returned 429 for the whole session → CT + Wayback
  data was unavailable; note it as a gap and retry later rather than assuming no records exist.
- Cloudflare WAF blocked a probe containing a double-quote (`q=test"` → `000`) — a `000` is a
  WAF/transport block, not a "no result"; don't read it as SQLi evidence.
