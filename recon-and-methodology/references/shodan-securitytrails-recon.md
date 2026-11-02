# Shodan + SecurityTrails API Recon Workflow (field-proven)

Session: mbcapital.com.vn full ecosystem mapping (2026-09). Reference to the
`recon-and-methodology` §2 passive enumeration — this file extends it with the
concrete API pivot chain.

## 0. Credentials location (user environment)

API keys live in `C:\Users\Admin\pentest\api_keys.env`:

```bash
export $(grep -v '^#' /c/Users/Admin/pentest/api_keys.env | xargs)
# SHODAN_API_KEY (plan: dev — 100 query credits/mo, 100 scan credits)
# SECURITYTRAILS_API_KEY (32-char, ST-internal format c_xxx)
# verify: curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" https://api.securitytrails.com/v1/ping
#         python3 -c "import shodan,os; print(shodan.Shodan(os.environ['SHODAN_API_KEY']).info()['plan'])"
```

Shodan CLI may not be installed; `python3 -m pip install shodan` and use the Python lib —
same key. (If `pip` bare fails on Windows Store Python, use `python3 -m pip`.)

## 1. SecurityTrails endpoints that matter

```
GET /v1/domain/<apex>/subdomains          # current subdomains (incl. NXDOMAIN-but-historical: sip., lyncdiscover., admin., old.)
GET /v1/history/<apex>/dns/a              # historical A records w/ first_seen/last_seen -> legacy IP pivot
GET /v1/history/<sub>.<apex>/dns/a         # per-sub history (find decommissioned hosts still DNS-published)
GET /v1/domain/<apex>                     # whois + related domains
```

Key trick: ST subdomain list ⊃ live DNS list. Diff them; the NXDOMAIN entries
(sip/lyncdiscover/admin) fingerprint the corp stack (Skype for Business → Microsoft tenant).
Resolve the stragglers — `old.mbcapital.com.vn` still resolved to a 2018-2021 legacy IP
while the apex had migrated: stale vhost = unmonitored attack surface.

## 2. Shodan queries for an ecosystem sweep

```python
api.search('hostname:mbcapital.com.vn')            # exact hostnames in reverse DNS
api.search('ssl:mbcapital.com.vn')                 # cert SAN matches (catches non-reverse-DNS hosts)
api.search('org:"Military commercial join stock bank"', limit=100)  # ASN/org siblings
api.host(ip)                                        # per-IP: ports, banners, hostnames, asn, isp
```

The `org:` search is the goldmine — it surfaced sibling domains on the same bank ASN the
passive tools never listed: `mbbank.com.vn`, `mbamc.com.vn`, `digiinvest.vn` on
103.12.105.x, plus Tomcat on 8446, nginx on 8083, exposed ntpd/53 hosts. One sweep =
the whole corporate footprint beyond the target apex.

## 3. Shodan as SYN-proxy false-positive oracle

When nmap -sS/-sT from a residential/VPN host shows EVERY port open on every IP (classic
middlebox DPI-ACK), Shodan's independent scan results cut through it: the same IPs showed
ONLY 443 (and 80/443 for cloud) with clean banners (nginx/Apache 2.4.53/F5). Cross-check
`api.host(ip).data[*].port` against your scan: ports Shodan never sees on a heavily-scanned
IP range are almost certainly SYN-proxy artifacts — report them as UNVERIFIED, not "open".

## 4. Third-party hosting pivot (mail/edge hosts on other ISPs)

`hostname:` search found `mail.mbcapital.com.vn` ALSO reverse-resolving from an FPT
residential IP `118.70.128.35` with weird ports 92/3333/4444 — a NAT'd on-prem edge:

- Port 92 `/doc/index.html` + `hui_chunk.js` + `vueDepends.js` = Hikvision Web Client
  fingerprint ("hui" = Hikvision UI kit, Common/static/theme pattern). Hikvision-family
  devices on non-standard HTTP ports.
- 3333/4444 "Access Denied" 403 = Hikvision/Dahua port-mapping convention.

Lesson: for every IP found, run `api.host()` and read banners — a corp hostname on a
residential ASN = branch-office device (camera/NVR/router), usually the softest target.
Similarly `app.mbcapital.com.vn` → Azure App Gateway v2 (404 on default host → Host-header
fuzz candidate), `mail.dvkh.*` → VCCorp `aibizmail.com` (3rd-party mail SaaS).

## 5. Historical IP → Shodan current state

Feed every IP from ST history back through `api.host()`:
- `103.28.37.47` (2018-2021 apex): now NhanHoa shared host — Exim 4.98, BIND 9.11.4-P2,
  OpenSSH 7.4, ports 2222/7080 (DirectAdmin convention). Old apex migrated away but
  `old.sub` still points there → verify leftover vhosts/`Server:` headers.
- `115.146.127.226` (2021-2022): CMC, SMB/NetBIOS/LLMNR/UPNP exposed (5353/5357/137/445)
  + nginx 80/443 + 5000/5001. Windows-looking box reachable on file shares from internet —
  even if not live-scan-allowed, note it as legacy exposure in the report.

## 6. Report structure that worked

Table per host: subdomain | IP | ASN/ISP | verified ports | banner/tech | role.
Then sections: opensource stack per app (from bundle mining), leaked endpoints (sandbox/UAT
in JS), and a "redteam coordinates" list ordering findings by EOL-software / legacy-IP /
third-party-edge / UAT-exposure. User expects the merged inventory + attack angles, not raw dumps.

## 7. Apex-variant sweep + sibling-apex pivot (field-verified 2026-09, mbamc)

- **Query EVERY apex variant**: `hostname:mbamc.com.vn` AND `hostname:mbamc.vn` — the
  `.vn` variant surfaced a legacy ISP IP (101.99.14.243, CMC Telecom) hosting FIVE
  dead-DNS names (admin./amc./mail./smtp./pop.) that the `.com.vn` search never showed.
  That IP ran the live DrayTek router — highest-value finding of the session.
- **Sibling apex check via Cavalier**: run the stealer-intel domain query on the SIBLING
  apex too — mbamc.com.vn carried 22 infections while the primary target apex had
  fewer; the sibling also leaked 6 internal-only hostnames (OWA, Oracle EBS, HRIS).
- **ASN attribution per IP** (`api.host(ip).asn/org`): 103.12.104-105.x = AS131364
  "Military commercial join stock bank" — proof the subsidiary shares the parent bank's
  IP space (cross-org attack surface note for the report). Viettel/CMC/unknown ASNs
  flag third-party hosting worth banner-grabbing.
