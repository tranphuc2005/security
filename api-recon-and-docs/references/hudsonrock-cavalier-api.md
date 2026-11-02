# Hudson Rock Cavalier API — infostealer recon client

Platform: https://cavalier.hudsonrock.com (Cybercrime Intelligence / infostealer data).
Auth: token-exchange flow (magic-link style), NOT a static API key.

## Auth flow
1. Admin visits `/tokenaccess?token=<ACCESS_TOKEN>` (token valid ~3 months).
2. Page JS POSTs `/api/auth/token-login` with `{"token": <ACCESS_TOKEN>}`.
3. Response: `{"success":true,"token":"<JWT>","user":{...role...}}` → JWT used as `Authorization: Bearer <JWT>` for all API calls.
4. JWT is a standard JWT (exp ~25h) — must be re-exchanged from access token regularly.
5. CLI caches JWT for 25h; re-exchange on expiry automatically.

## API endpoints (discovered from JS bundle / live probing, all under `https://cavalier.hudsonrock.com`)

### Company/domain recon
- `POST /api/domain-search/count` — body `{"domains":["example.com"],"keyword_suggestions":true}` → `{stealers, employees, parties, clients, androids, externalCount, assets, lastEmployeeCompromised, keyword_suggestions, litellm}`
- `POST /api/domain-search/urls` — body `{"domains":["x.com"]}` → `{employees_urls, clients_urls, employees_count, clients_count}` (webmail/internal URLs stolen)
- `POST /api/domain-search/cookies` — body `{"domains":["x.com"],"limit":10}` → cookie domains (gmail, linkedin, openai, facebook, adobe, zoom...)
- `POST /api/domain-search/stealer-families` — body `{"domains":["x.com"]}` → `{total, RedLine, Vidar, Raccoon,...}`
- `POST /api/domain-search/timeline` — body `{"domains":["x.com"],"timeframe":"all"}` → per-year employee/client compromise counts
- `POST /api/domain-search/password-strength` — body `{"domains":["x.com"]}` → employee/user counts, last compromised
- `POST /api/domain-search/applications` — body `{"domains":["x.com"]}` → sensitive apps (webmail etc.)
- `POST /api/domain-search/antivirus` — body `{"domains":["x.com"]}` → AV installed on compromised machines
- `POST /api/domain-search/assets` — body `{"domains":["x.com"]}` → asset counts (employees/users/thirdParties)
- `POST /api/domain-search/map` — body `{"domains":["x.com"]}` → geo map data
- `GET /api/domain-search/ai-supply-chain/<domain>` — AI supply chain findings (found:false if none)

### Employees / stealer logs
- `POST /api/employees` — body `{"domains":["x.com"]}` → list of stealer infection records: `{stealer_id, stealer_family, ip, computer_name, date_compromised, date_uploaded, location{country,region,city,lat,lng}, most_common_gmail, google_profile, can_search_by_stealer}`
- `POST /api/employees/stealer` — body `{"stealerId":"<STEALER_ID>","domains":["x.com"]}` → full credential dump for one infection. **NOTE: field is camelCase `stealerId`**, NOT `stealer_id` — backend returns 400 "Stealer ID is required" if snake_case used.

### Related / keyword / companies
- `GET /api/autocomplete/keyword-search-suggestions?query=<kw>` → `[{"url_part","occurrence","score"}]`
- `GET /api/companies` → registered companies (domains, apks, alert_emails)
- `POST /api/companies/government-domains` (body {}) → gov domains list
- `GET /api/companies/related-domains?keyword=<kw>` — requires `keyword`, returns related domains
- `GET /api/config/search-types` → available search types + permissions (visibility check)
- `GET /api/account/api-permissions` → permission categories

## CLI
`C:\Users\Admin\pentest\cavalier\cavalier_cli.py`
```
python cavalier_cli.py domain mcredit.vn       # summary (count, urls, families, timeline, apps, av, assets)
python cavalier_cli.py employees mcredit.vn    # all stealer infection records
python cavalier_cli.py stealer <STEALER_ID> <domain>  # full credential dump
python cavalier_cli.py urls|cookies|apps|av|assets|timeline|families <domain>
python cavalier_cli.py keyword <kw>
python cavalier_cli.py companies
```
Key in `C:\Users\Admin\pentest\api_keys.env` as `CAVALIER_TOKEN=...`.

## Redteam usage notes
- `count.lastEmployeeCompromised` + `employees` gives a map of when/where target staff machines were infected → prioritize password-spray on the webmail/VPN URLs from `urls`.
- `stealer` dump gives full credential material (email/password/logins/session context) — use for credential stuffing and pivoting, respecting scope.
- Geodata (region/city/lat/lng) on each stealer record helps attribute the infected machine.
- Token expires ~3 months; user must provide a fresh `/tokenaccess?token=` link to re-arm.