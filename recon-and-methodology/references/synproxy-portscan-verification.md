# SYN-Proxy Port Scan Verification Playbook

Derived from a live engagement against a DDoS-shielded banking range (AS131364, 103.12.104.0/22, Vietnam, 2026-08). Reusable for any target class behind anti-DDoS / SYN-proxy edges (banks, telcos, large enterprises).

## Why scans lie here

SYN-proxy devices (anti-DDoS appliances, some CDN/WAF edges) answer SYN for ANY destination port with SYN-ACK on behalf of the backend. The client completes the handshake; the device then either forwards to a matching rule or silently discards/resets. Result: every port looks "open" to connect scans AND to nmap service detection, which waits for application data that never arrives.

Field symptoms observed:
- 28 common ports reported "open" on all 14 target IPs — including an Azure App Gateway IP that truly serves only 80/443
- `nmap -Pn -T4 -sV --version-light` ran >10 minutes without finishing a single host (killed)
- Plain `socket.connect()` "succeeded" on 3306/27017/3389/5900 where nothing external listens

## Verification ladder (only application-layer response = REAL service)

### Ladder 0 — sanity check
Pick an IP known to expose ONLY a website. If the scan shows 20+ open ports on it, you are behind SYN-proxy. Reclassify ALL connect-scan "open" results as UNVERIFIED until proven otherwise.

### Ladder 1 — chatty protocols (greeting arrives without any probe)
| Port | Expected greeting if real |
|---|---|
| 21 FTP | `220 ...` |
| 22 SSH | `SSH-2.0-...` |
| 25/587 SMTP | `220 mail... ESMTP` |
| 110 POP3 | `+OK ...` |
| 143 IMAP | `* OK ...` |
| 3306 MySQL | binary handshake containing server version string |
| 3389 RDP | X.224 connect-response |
| 5900 VNC | `RFB 00x.00y` |

Empty recv() after connect (+probe) => fake-open (SYN-proxy artifact).

### Ladder 2 — silent protocols need valid probes
| Port | Probe bytes |
|---|---|
| 80/8080/8000/8888/9000/9200 | `HEAD / HTTP/1.0\r\nHost: x\r\n\r\n` |
| 53 TCP | length-prefixed DNS query: `\x8a\x2a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00` + QNAME + `\x00\x01\x00\x01` |
| 6379 Redis | `PING\r\n` → expect `+PONG` |
| 5432 PostgreSQL | SSLRequest `\x00\x08\x04\xd2\x16\x2f` → expect `S` or `N` |
| 1433 MSSQL | TDS prelogin stub `\x12\x01\x00\x2f\x00\x00\x00\x00\x00\x00\x15\x06\x00\xff\xff\x13\xa7` |
| 8009 AJP | ping `\x12\x01\x00\x0eAB\x00` |
| 27017 MongoDB | OP_QUERY isMaster BSON blob |
| 443 TLS | wrap in SSL context requiring a peer cert, then send HTTP HEAD inside the tunnel |

### Ladder 3 — allowlist discrimination
Mail/banking infra commonly permits only partner IPs:
- SMTP answering **instant ConnectionReset on connect** = reached a real filter, NOT a dead/fake port. Mark "exists, IP-allowlisted".
- DNS/TCP that times out (not refused) after a long wait = filtered path, same conclusion.
Retry such checks ONCE with 30–45s timeouts; never loop them (avoid rate-based blocking of your source IP).

### Ladder 4 — cross-plane confirmation
CONFIRMED only when it answers at application layer:
- 443 real ⟺ `https://host/` returns an HTTP status (any code — 200/403/502 — proves liveness)
- Server header + page title double as the tech fingerprint for reporting

## Parallelization pattern that worked
Run heavy nmap in BACKGROUND (with `--max-retries 1 --host-timeout Nm`) while a threaded Python banner-grabber (150–250 workers, 4–5s timeouts) does Ladder 1–2 in seconds. Treat nmap -sV output as untrusted on shielded ranges regardless.

## Python / tooling gotchas
- With `CERT_NONE` verify mode, `ssl.SSLSocket.getpeercert()` returns `{}`. Use `getpeercert(binary_form=True)` (hash it) or shell out:
  `echo | openssl s_client -connect H:443 -servername H 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName`
- TLS certs leak extra intel: expired-but-published certs (dead services), wrong-hostname wildcards shared across vhosts, EV subject fields revealing legal entity + address.
- `httpx` name collision: ProjectDiscovery httpx vs the Python httpx library CLI share the name. Check `httpx --version` output shape before assuming PD flags (`-title -tech-detect`) exist.
- crt.sh JSON endpoint (`https://crt.sh/?q=%25.DOMAIN&output=json`) is the cheapest supplement to subfinder; it also surfaces stale/dead records (DR hosts, admin., owa.) useful for split-horizon DNS inference.

## Case study digest (mbcapital.com.vn)
- Passive: subfinder 19 ∪ crt.sh +3 = 22 hosts; 17 resolved → 14 unique IPs; 12 IPs inside AS131364 103.12.104.0/22; `app.` on Azure with cert expired 09/2023 + 502 backend; `mail.dvkh` CNAME→Bizfly/VNPT.
- Active verification: only 9 hosts answered HTTPS with real apps (Apache/PHP 7.4 corporate site; FCS + FMS Vue SPAs; MBBank Mini App + pilot React apps; MBEETRADER React serving `*.mbbank.com.vn` wildcard cert on wrong hostname). SMTP relays reset connections instantly (IP allowlist). Everything else = SYN-proxy artifacts.
- Full report artifact: `C:\Users\Admin\mbcapital_recon_report.md`
