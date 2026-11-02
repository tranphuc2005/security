#!/usr/bin/env python3
"""
Passive subdomain + DNS + IP-intel recon (NO active scanning).
Usage: set DOMAIN below, then:  python passive_recon.py
Pipeline: local subfinder (if installed, optional) -> crt.sh CT logs
          -> Google DoH A/CNAME resolution -> ipinfo.io + RDAP.net netrange
Stdlib only. Run authorization/scope checks before any FOLLOW-UP active testing.
Generic template: no lab-specific values hardcoded (per user preference).
"""
import json
import ssl
import subprocess
import urllib.request
from pathlib import Path

DOMAIN = "example.com"  # <-- SET TARGET HERE
OUT_DIR = Path.home()
UA = {"User-Agent": "Mozilla/5.0 (compatible; osint-recon)"}
CTX = ssl.create_default_context()


def get(url, timeout=40):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read().decode("utf-8", "replace")


def collect_subdomains():
    subs = {DOMAIN}
    # Optional local subfinder — skip silently if not installed
    try:
        out = subprocess.run(
            ["subfinder", "-d", DOMAIN, "-all", "-silent"],
            capture_output=True, text=True, timeout=120,
        ).stdout
        subs |= {ln.strip().lower() for ln in out.splitlines() if ln.strip()}
    except Exception:
        pass
    # Certificate Transparency logs
    try:
        rows = json.loads(get(f"https://crt.sh/?q=%.{DOMAIN}&output=json"))
        for row in rows:
            for h in row.get("name_value", "").split("\n"):
                h = h.strip().lstrip("*.").lower()
                if h.endswith(DOMAIN):
                    subs.add(h)
    except Exception as e:
        print(f"[!] crt.sh failed: {e!r}")
    return sorted(subs)


def resolve(host):
    """Return (ips, cname) via Google DNS-over-HTTPS."""
    ips, cname = [], ""
    j = json.loads(get(f"https://dns.google/resolve?name={host}&type=A", timeout=15))
    for a in j.get("Answer") or []:
        if a.get("type") == 1:
            ips.append(a["data"])
        elif a.get("type") == 5:
            cname = a["data"].rstrip(".")
    return sorted(set(ips)), cname


def ip_intel(ip):
    info = {}
    try:
        j = json.loads(get(f"https://ipinfo.io/{ip}/json", timeout=20))
        info.update(org=j.get("org"), country=j.get("country"), city=j.get("city"))
    except Exception:
        pass
    try:
        j = json.loads(get(f"https://rdap.org/ip/{ip}", timeout=20))
        info.update(netrange=f"{j.get('startAddress')} - {j.get('endAddress')}",
                    netname=j.get("name"))
    except Exception:
        pass
    return info


def main():
    subs = collect_subdomains()
    print(f"[+] {len(subs)} candidate subdomains")
    dns = {}
    for h in subs:
        try:
            ips, cname = resolve(h)
            if ips:
                dns[h] = {"ips": ips, "cname": cname}
        except Exception:
            pass
    uniq_ips = sorted({ip for v in dns.values() for ip in v["ips"]})
    print(f"[+] {len(dns)} resolved hosts, {len(uniq_ips)} unique IPs")
    intel = {ip: ip_intel(ip) for ip in uniq_ips}

    result = {"domain": DOMAIN, "subdomains": subs,
              "resolved": dns, "ip_intel": intel}
    out = OUT_DIR / f"{DOMAIN}_passive_recon.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"[+] wrote {out}\n")

    for h, v in dns.items():
        extra = f"  CNAME->{v['cname']}" if v["cname"] else ""
        print(f"  {h:42s} {', '.join(v['ips'])}{extra}")
    print("\n  IP INTEL:")
    for ip, info in intel.items():
        print(f"    {ip:18s} org={info.get('org','?')}  range={info.get('netrange','?')}")


if __name__ == "__main__":
    main()
