# WebAuthn/FIDO2 server testing — session walkthrough (fido-test.mbbank.com.vn, 2026-09)

## Target profile
- 54.255.235.168 = fido-test.mbbank.com.vn (AWS EC2 ap-southeast-1), nginx, cert OV *.mbbank.com.vn
- App = FIDO2 Interop v1.2 — official FIDO Alliance conformance tool. Frontend HTML is the
  unmodified open-source tool (comments "CHANGE ME TO YOUR SERVERS URL" intact),
  `window.serverURL = 'https://fido-test.mbbank.com.vn'`.
- Backend: Java/Spring Boot FIDO server. Verbatim default Spring error on malformed JSON
  ({"timestamp":...,"status":500,"error":"Internal Server Error","path":"/attestation/options"}).
- Endpoints (POST JSON only; GET/PUT/DELETE → 405; OPTIONS preflight from foreign origin → 403):
  /attestation/options  /attestation/result  /assertion/options  /assertion/result
- No swagger/actuator/.git/admin. Only 80+443 open. TLS1.2/1.3 only. Server header hides version.

## Response vocabulary (returnCode oracle)
| rc | meaning |
|----|---------|
| 0 | OK (status:"ok"; attestation/result also returns systemId:"CONFORMANCE") |
| 1002 | "username was not registered" (assertion/options, unknown user) |
| 1021 | missing username (attestation/options) |
| 1104 | "id is not base64url encode" |
| 1202 | "attestationObject is not a valid CBOR MAP" |
| 1315 | "R-1.F-20, response.signature containing unverifiable signature" |
| 9999 | "No permissions" — generic: wrong challenge OR wrong encoding (std b64) OR wrong session |

## What the server DID verify (don't assume it's wide open)
- Challenge bound: valid-shape attestation with wrong/foreign challenge → 9999
- Signature verified: register key A, sign assertion with key B → 1315
- Strict base64url encoding: std base64 in response fields → 9999
- rpIdHash in authenticatorData must match rp.id
## What it did NOT verify
- Attestation: fmt=none + self-chosen COSE key accepted → any software keypair can register+login.

## Proof flow (curl + python, no browser)
1. POST /attestation/options {"username":"t@x.vn","displayName":"T","attestation":"direct",
   "authenticatorSelection":{}} → challenge=b64("911cde97-...") (36 bytes ASCII UUID), user.id=UUIDv4.
   Repeated calls → NEW user.id each time (no per-username persistence on options).
2. authData = sha256("fido-test.mbbank.com.vn") + pack('>BI',0x41,0) + b'\x00'*16
   + pack('>H',32) + credId + COSE_ES256_key ; attObj = cbor2.dumps({"fmt":"none","attStmt":{},"authData":authData})
   → POST /attestation/result → {"returnCode":0,"systemId":"CONFORMANCE","status":"ok",...}
3. POST /assertion/options {"username":"t@x.vn"} → challenge + allowCredentials[0].id = our credId
4. authData = rpIdHash + pack('>BI',0x05,1); sig = ECDSA(authData+sha256(clientDataJSON))
   → POST /assertion/result → {"returnCode":0,"userData":{...},"fidoId":"<UUID>","status":"ok"}

## Enum / info-disclosure findings
- Unknown user: POST /assertion/options → 1002 "username was not registered" (explicit oracle)
- Known user: POST /attestation/options → excludeCredentials:[{"id":"<credential ID>"}] leaks
  credential IDs for ANY registered username (user.id itself is fresh UUID per call, not stable).
- No rate limit: 10x attestation/options + 5x assertion/options back-to-back, all 200, no throttle.

## Shodan intel on the host
Ports 80/443 only (no SYN-proxy), hostname ec2-54-255-235-168.ap-southeast-1.compute.amazonaws.com,
jQuery CVEs (client-side only, trivial). TLS1.2/1.3.

## Report framing
The headline finding is CONTEXTUAL: a FIDO Alliance conformance test tool (systemId CONFORMANCE)
served under a bank's production domain. Software-key register+login works by design on a
conformance server — severity explodes only if this codebase/diagram feeds the production FIDO
path. Report as: test infra exposure (High-contextual) + user enumeration (Low) + no rate limit (Low).
