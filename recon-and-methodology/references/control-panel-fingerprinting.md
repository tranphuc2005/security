# Control Panel Fingerprinting

Techniques for fingerprinting hosting control panels (DirectAdmin, cPanel, Plesk, Webmin, etc.) — especially when the core version is hidden from unauthenticated users.

## DirectAdmin (port 2222)

### Signature
- **Server header**: `Server: DirectAdmin Daemon`
- **Auth header**: `X-Directadmin: Unauthorized` (when not logged in)
- **Login path**: `/CMD_LOGIN`, `/evo/login` (Evolution skin), or `/` (302 → `/evo/`)
- **Redirect**: `/` → 302 Location: `/evo/`

### Version Disclosure

**Core version** — usually hidden from unauthenticated users:
- `/CMD_API_VERSION` → 302 redirect (requires auth)
- `/CMD_API_ACCOUNT_USER` → 401 (confirms API is running but blocked)
- No version in `Server` header or `X-Directadmin` header

**Evolution skin version** — extractable from JS bundle:
1. Download the SPA JS bundle: `/evo/index.<hash>.js`
2. Search for version string: `grep -oE '"version":"[^"]+"'`
3. Search for build metadata: `grep -oE 'commit:"[^"]+",date:"[^"]+"'`
4. Pattern in Evolution 0.26.x: `{version:"0.26.1"}` + `{commit:"<sha>",date:"2024-11-14",stage:"development"}`

### Endpoint Recon
| Path | Status (unauthed) | Notes |
|------|-------------------|-------|
| `/CMD_LOGIN` | 200 | Login form (HTML) |
| `/CMD_SHOW_LOGIN` | 302 | Legacy redirect |
| `/CMD_API_VERSION` | 302 | Auth required |
| `/CMD_API_ACCOUNT_USER` | 401 | API accessible but blocked |
| `/CMD_TICKET` | 302 | Auth required |
| `/CMD_PLUGINS` | 302 | Auth required |
| `/CHANGELOG.txt` | 302 | Auth required |
| `/README.txt` | 302 | Auth required |

### Headers of Interest
- `X-Frame-Options: sameorigin` — clickjacking protection
- `X-Language-Default` / `X-Language-List` — language support (newer DA)
- `X-Valid: yes` — present on `/CMD_LOGIN` responses

## cPanel (port 2082/2083)

### Signature
- **Server header**: `cpsrvd/<version>`
- **Login path**: `/login/`, `/cpsess*/`
- **Cookie**: `cpsession`

### Version Disclosure
- **cpsrvd version** in `Server` header (e.g. `cpsrvd/11.104.0.37`)
- `/cpanel` — redirects to login
- `/json-api/version` — may expose version

## Plesk (port 8443)

### Signature
- **Server header**: Sometimes `Plesk*` or nginx
- **Login path**: `/login_up.php`, `/admin/`
- **Page title**: "Plesk"

### Version Disclosure
- HTML source: `[Plesk <version>]` in comments
- `/login_up.php` — form may contain version in hidden fields
- `/favicon.ico` — Plesk favicon specific to version ranges

## Webmin (port 10000)

### Signature
- **Server header**: `MiniServ/<version>`
- **Login path**: `/`, `/session_login.cgi`
- **Page title**: "Webmin" or "Usermin"

### Version Disclosure
- `Server: MiniServ/<version>` — direct version leak
- `/unauthenticated/` — some versions expose version info

## General Approach

1. Check `Server` header first — many panels leak version there
2. Check HTML `<title>` and `generator` meta tags
3. Download JS/CSS bundles and search for version patterns
4. Try common API paths for the panel type
5. Check `/favicon.ico` — some panels have version-specific icons
6. Check `/robots.txt` for disallowed paths (may reveal admin endpoints)