# Rails + React SPA Recon Methodology

## Tech Fingerprinting Signals

### Rails (Server-side)
| Signal | What to look for |
|--------|-----------------|
| Cookie | `_<app>_session` (e.g. `_flywheel_session`) — Rails encrypted session cookie |
| CSRF | `csrf-token` meta tag + `authenticity_token` hidden input in forms |
| Form | `name="authenticity_token"`, `name="fw_token"` (Flywheel-specific) |
| New Relic | `NREUM.info` in HTML — `bam.nr-data.net` beacon |
| Asset pipeline | Webpack hashed filenames: `main-<hash>.js`, `vendors-<hash>.js` |
| Page meta | `<meta content='sessions new' name='page'>` — Rails controller/action |

### React (Client-side)
| Signal | What to look for |
|--------|-----------------|
| React Router | `path: "/sites"`, `path: "/clients/:clientSlug"` in JS bundles |
| Mount point | `<div id="app">` or `ReactDOM.render(...)` |
| Components | Separate bundle: `components-<hash>.js` |
| Webpack | `runtime-<hash>.js` + chunked bundles (`1511-<hash>.js`) |

### Cloudflare
| Signal | What to look for |
|--------|-----------------|
| Challenge | Page title "Just a moment...", "Performing security verification" |
| Cookie | `cf_clearance` — required for bypassing challenge |
| Cookies | `__cf_bm` — bot management |
| IP | 172.64.0.0/13, 104.16.0.0/12 (Cloudflare ranges) |

## Recon Workflow

### Step 1: Passive Fingerprint (HTML)
```
curl -s -A "Mozilla/5.0 ..." "https://target.com/login" | tee login.html

# Extract:
grep -oP '<title>[^<]*</title>' login.html           # Page title
grep -oP "name='csrf-token' content='[^']*'" login.html  # CSRF token
grep -oP 'src="[^"]*\.js[^"]*"' login.html          # JS bundles
grep -oP 'href="[^"]*\.css[^"]*"' login.html         # CSS bundles
grep -oP 'content="[^"]*" name="page"' login.html     # Rails page metadata
```

### Step 2: Download & Analyze JS Bundles
```
# Download all bundles
for url in $(grep -oP 'src="[^"]*\.js[^"]*"' login.html | sed 's/.*src="//;s/"//'); do
  curl -s "$url" -o "js/$(basename $url)"
done

# Extract React Router paths
grep -oP 'path\s*:\s*["'"'"'][^"'"'"']+["'"'"']' js/*.js | sort -u

# Extract API-ish paths
grep -oP '["'"'"'](/api/[^"'"'"']+)["'"'"']' js/*.js | sort -u

# Extract internal hosts/URLs
grep -oP 'https?://[a-z0-9\-\.]*(?:\.wpengine|\.flywheel|\.internal)[^"'"'"']*' js/*.js | sort -u
```

### Step 3: Route Discovery (React Router)
Routes found in bundles often include:
- `/:org/:orgSlug/:siteSlug/domains/` — parameterized site routes
- `/clients`, `/clients/:clientSlug` — client management
- `/billing-information`, `/subscriptions-and-billing` — billing
- `/dashboard/:orgSlug` — org dashboard
- `/sites`, `/sites/plugins`, `/sites/stats` — site management
- `/settings`, `/portal` — account settings
- `/tickets`, `/site_search` — support/search
- `/org/:orgSlug/clients/:clientSlug/invoice/:token/edit` — invoicing

### Step 4: Cloudflare Bypass via Curl
If you have a valid `cf_clearance` cookie (from a real browser session):
```
curl -b "cf_clearance=...; __cf_bm=..." \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..." \
  "https://target.com/dashboard"
```

**Note**: `cf_clearance` expires. For long sessions, maintain a cookies.txt in Netscape format.

### Step 5: Authenticated Recon
```
# Login with CSRF token
curl -c cookies.txt -b cookies.txt -L \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "authenticity_token=<CSRF>&login_form[username]=...&login_form[password]=..." \
  "https://target.com/login"

# Access dashboard
curl -b cookies.txt "https://target.com/dashboard"
```

## Post-Auth Attack Surface (Phase 5+)

### High-Value Routes (IDOR / Priv-Esc targets)
- `/clients/:clientSlug` — resource IDOR
- `/org/:orgSlug/clients/:clientSlug/invoice/:token/edit` — multi-tenant billing
- `/sites/:siteSlug/domains/` — site configuration
- `/billing-information` — payment data
- `/settings` — account modification

### Service Integrations (from JS bundles)
- **Intercom**: `/intercom_poll`, `/product_updates`, `/tickets` — support chat
- **Stripe**: billing/payment processing
- **New Relic**: APM monitoring (bam.nr-data.net)

### Auth Token Patterns
- Rails `_flywheel_session` — encrypted session cookie
- `user_id` cookie — base64 encoded? Look for decode patterns in JS
- `shadower_id` — analytics tracking