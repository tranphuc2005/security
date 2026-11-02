# Webpack Module Tracing for Obfuscated Signature/Hash Functions

## When to Use

When a web app (Angular, React, Vue) uses webpack-bundled JS and has a custom
Signature or hash function that references module variables (e.g., `m.p`) that
are not immediately visible in the current file's scope. This technique traces
webpack module imports across files to resolve obfuscated function behavior.

## Scenario

MB Merchant Admin (103.12.104.124) uses Angular with webpack. The login API
requires a `Signature` header computed by `hashValue(body)`:

```js
hashValue(t){
  var e = function(t,e){
    // scramble function: shuffles characters in a string using seed
    for(var n=t.length,i=[],r=0;r<n;r++) i[r]=t.charAt(r);
    for(r=0;r<n;r++){
      var o=e*(r+245)+e%53831, a=e*(r+249)+e%23873;
      var s=o%n, c=a%n;
      var l=i[s]; i[s]=i[c]; i[c]=l;
      e=(o+a)%6796851;
    }
    var d=String.fromCharCode(127);
    return i.join("").split("%").join(d)
      .split("#1").join("%").split("#0").join("#").split(d);
  }("%trf%gtrrinte%ppSoyetnidanSsgdni", 824070);

  // e = ['stringify', 'toString', 'end', 'appendStr']
  const n = JSON[e[0]](t) + m.p;  // JSON.stringify(body) + m.p (salt)
  return (new Xe.a)[e[3]](n)[e[2]]()[e[1]]();
  // = CryptoJS.MD5(n).appendStr().end().toString()
  // ≈ CryptoJS.MD5(JSON.stringify(body) + m.p).toString()
}
```

The variable `m` is a webpack module import. `m.p` is a salt string whose value
must be traced through the module system.

## Tracing Technique

### Step 1: Identify which webpack module the function belongs to

```python
import re
with open('main.js', 'r') as f:
    js = f.read()

idx = js.index('hashValue(t){')

# Find all webpack module boundaries: "moduleId":function(t,e,n){
mod_pattern = re.compile(r'"([a-zA-Z0-9_+/]+)":function\(t,e,n\)\{')
modules = list(mod_pattern.finditer(js[:idx]))

# The LAST module start before hashValue is the containing module
last_mod = modules[-1]
print(f"hashValue is in module '{last_mod.group(1)}'")
```

### Step 2: Find which file the module is in

Webpack splits code across chunks. The module containing `hashValue` may be in
`main.js` or `vendor.js`. Search both:

```bash
grep -c "hashValue" main.js vendor.js
```

### Step 3: Find all `m=n("moduleId")` imports within the containing module

```python
mod_start = js.index('"O7+o":function')  # containing module
mod_content = js[mod_start:idx+500]

# Find all variable assignments from webpack require
imports = re.findall(r',([a-zA-Z]{1,3})=n\("([^"]+)"\)', mod_content)
# Returns: [('m', 'f0Cb'), ('m', 'SLWe'), ...]
```

### Step 4: Find which module exports property `p`

```bash
# Search for n.d(e,"p",...) in the module definition
grep -oP 'SLWe:function\(t,e,n\)\{"use strict".{20000,25000}' main.js \
  | grep -oP 'n\.d\(e,"p",.{0,50}'
# Result: n.d(e,"p",(function(){return a.m}))
```

### Step 5: Resolve the export chain

```
SLWe exports "p" → a.m
a = n("8NTh") → module 8NTh
8NTh exports "m" → f
const f = ... (search in 8NTh module body)
```

Key Python pattern for tracing all `n.d(e,"p")` exports:
```python
p_exports = list(re.finditer(r'n\.d\(e,"p"', js))
for m in p_exports:
    start = m.start()
    before = js[max(0,start-200):start]  # find module name
    after = js[start:start+200]          # find return value
    mod_match = re.search(r'"([^"]+)":function\(t,e,n\)', before)
    ret_match = re.search(r'n\.d\(e,"p",\(function\(\)\{return\s+([^}]+)\}\)\)', after)
    print(f"Module '{mod_match.group(1)}', p returns: {ret_match.group(1)}")
```

### Step 6: Decode the scramble function

The scramble function is a custom string deobfuscator. Replicate it in Python:

```python
def scramble(t, e):
    n = len(t)
    i = list(t)
    for r in range(n):
        o = e * (r + 245) + e % 53831  # params vary per function
        a = e * (r + 249) + e % 23873
        s = o % n
        c = a % n
        i[s], i[c] = i[c], i[s]
        e = (o + a) % 6796851
    d = chr(127)
    result = ''.join(i)
    result = result.replace('%', d)
    result = result.replace('#1', '%')
    result = result.replace('#0', '#')
    return result.split(d)

# Decode: scramble("%trf%gtrrinte%ppSoyetnidanSsgdni", 824070)
# → ['stringify', 'toString', 'end', 'appendStr']
```

## Key Insight: Test Server-Side Validation FIRST

Before spending time reversing any signature/hash mechanism, test whether the
server actually validates it:

```bash
# Test with dummy signature
curl -sk -X POST "https://target/api/login" \
  -H "Content-Type: application/json" \
  -H "Signature: test" \
  -d '{"data":{"userName":"admin","password":"hash"}}'

# Test with empty signature
curl -sk -X POST "https://target/api/login" \
  -H "Content-Type: application/json" \
  -H "Signature: " \
  -d '{"data":{"userName":"admin","password":"hash"}}'

# Test WITHOUT signature header at all
curl -sk -X POST "https://target/api/login" \
  -H "Content-Type: application/json" \
  -d '{"data":{"userName":"admin","password":"hash"}}'
```

**MB Merchant Admin result:** All three returned the same response
(`soaErrorCode:20310`). The server does NOT validate the Signature header.
The entire module-tracing effort was unnecessary. **Always test this first.**

## Angular Config File Locations

Angular apps often expose configuration at predictable paths:

```
/assets/configuration/configuration.json    ← MB Merchant Admin (found)
/assets/config.json
/assets/config/config.json
/assets/environments/environment.prod.json
/assets/environment.json
/config.json
```

These files may contain:
- Backend API URLs (including internal/unlisted ones)
- IP addresses of internal services
- Hardcoded fallback values
- Third-party service URLs
- IFrame URLs (sometimes HTTP, not HTTPS)

Always check for these BEFORE digging into JS reverse engineering.
