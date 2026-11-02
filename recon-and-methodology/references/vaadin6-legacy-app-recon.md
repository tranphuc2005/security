# Legacy Vaadin 6 app recon — session notes (UZ Brussel laboguide, 2026-09-16)

## Context
Hospital recon. Two sibling hosts behind BigIP/Tomcat: `labogids.uzbrussel.be` and `laboguide.uzbrussel.be`, app "Laboratoriumgids" (lab manual for care providers). Finding: full unauthenticated access to an internal care-provider application.

## Version leak (no server header)
Bootstrap page `/<appUri>/` embeds:
```js
vaadin.vaadinConfigurations["laboguide-325080134"] = {appUri:'/laboguide', standalone: true,
  themeUri:"/laboguide/VAADIN/themes/laboguide",
  versionInfo : {vaadinVersion:"6.8.5",applicationVersion:"NONVERSIONED"}, ...}
```
→ exact Vaadin version + real appUri + theme name in one read.

## Mirror-host trap (cost ~6 wasted probes)
`labogids.` returned the identical 2788-byte bootstrap page for EVERY path — including `/laboguide/VAADIN/widgetsets/.../nocache.js` and `styles.css`. The real app lived on `laboguide.uzbrussel.be`.
Discriminator: `GET /laboguide/VAADIN/themes/laboguide/styles.css` → laboguide. returns 9937 bytes of real CSS; labogids. returns the HTML bootstrap page.

## UIDL probe ladder
1. `POST https://host/<appUri>/UIDL/` body `1\n{}` → `for(;;);[{...appError:"Cookies disabled"}]` = endpoint alive
2. `GET /<appUri>/` with cookie jar (JSESSIONID + BIGipServer pool cookie) → session created
3. `POST /<appUri>/UIDL/?restartApplication` → `for(;;);[{...appError:"Invalid security key"}]` = server processes crafted payloads
4. The widgetset JS performs the real handshake — for full app interaction use browser automation (navigate to app URL; Vaadin renders fully; accessibility snapshot lists every tree node)

## The finding
Fresh unauthenticated session is auto-assigned profile "Zorgverstrekker" (care provider). The "Mijn huidig profiel" dialog is a pure view selector (Patiënt vs Zorgverstrekker) — no login anywhere. Accessible without auth:
- Entire lab manual: 1366 analyses (tabs Patient/Afname/Interpretatie/Analyse/Contact)
- Contact tab: head-of-department names, internal phone/fax, departmental emails (e.g. secretariaat.klinischebiologie@uzbrussel.be)
- Documenten tab: full changelog with hundreds of dated entries (2024→2026)

## Report framing for hospital/private programs
Programs commonly exclude "vulnerabilities that only work on software that no longer receive security updates" — Vaadin 6 in 2026 qualifies. Frame as **unauthenticated access to an internal care-provider application / missing authorization**, never as "old Vaadin version".

## Same-session adjacent captures
- Exchange 2019 behind BigIP: `/owa/` + `/ecp/` RST connections, but `/ews/exchange.asmx` + `/autodiscover/autodiscover.xml` return 401 with `X-OWA-Version: 15.2.2562.37`, `X-FEServer: VEXCHMAIL01A`, Negotiate/NTLM/Basic/OAuth → fingerprint via the 401 virtual dirs.
- BigIP persistence cookie `BIGipServer<pool>=!<base64blob>` (leading `!`) = F5 cookie encryption enabled → the rd-hex IP:port decode does NOT apply; only the pool-name prefix leaks (e.g. `lwww01x.app~lwww01x_pool`).
- Keycloak/SPA: `curl -skL -o /dev/null -w '%{url_effective}' https://app/` lands on the IdP authorize URL with the real client_id, redirect_uri, scope, PKCE method in the query string — no JS bundle analysis needed.
