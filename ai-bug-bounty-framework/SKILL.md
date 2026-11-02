---
name: ai-bug-bounty-framework
description: "AI Bug Bounty & Vulnerability Research Framework — systematic methodology for authorized bug bounty testing: scope extraction, recon, attack surface mapping, hypothesis-driven validation, minimal PoC, structured reporting. Use for any bug bounty or authorized web/API security engagement."
---

# AI Bug Bounty & Vulnerability Research Framework

Systematic, technology-agnostic methodology for AI-assisted security research and **authorized** bug bounty testing.

## Mission & Core Operating Principle

> **Understand target architecture → map attack surface → form hypotheses → validate vulnerabilities → prove impact with minimal evidence → report accurately.**

### Core Workflow
```
SCOPE → ASSETS & RECON → ATTACK SURFACE MAP → HYPOTHESIS FORMATION
→ CONTROLLED VALIDATION → IMPACT PROOF → MINIMAL EVIDENCE → STRUCTURED REPORT
```

### Prohibited Workflow
```
SCAN EVERYTHING → EXPLOIT EVERYTHING → LOOK FOR IMPACT   ❌
```

---

## Phase 0 — Scope, Authorization & Policy Compliance (MANDATORY FIRST)

### 0.1 Policy Rules Extraction
Extract and store before any test:
- Program name and platform (HackerOne, Bugcrowd, Intigriti, self-hosted)
- In-scope targets (domains, wildcards, mobile apps, APIs, IP ranges)
- Out-of-scope targets & forbidden vuln classes (DoS, spam, social engineering)
- Required HTTP headers / User-Agent strings
- Rate limits and testing windows
- Safe Harbor and disclosure terms

### 0.2 Asset Classification
- `IN_SCOPE` — authorized for testing
- `OUT_OF_SCOPE` — do not interact
- `THIRD_PARTY` — external SaaS integrated with target (policy check required)
- `CUSTOMER_ASSET` — customer-hosted instances (strict isolation)
- `UNKNOWN` — halt active testing until ownership confirmed

```
Rule: IF Asset == UNKNOWN OR OUT_OF_SCOPE -> DO NOT SEND ACTIVE REQUESTS.
```

---

## Phase 1 — OPSEC, Traffic Control & Safety

### 1.1 Traffic Identification
```http
User-Agent: <Program-Required-User-Agent-Or-Researcher-ID>
X-Bug-Bounty: Researcher-<Username>
```

### 1.2 Rate Control Priority
```
Explicit Program Rate Limit → Platform Default → Conservative Baseline (<= 5 req/sec)
```

### 1.3 Evasion Rules
- Do NOT use IP rotation / proxy chaining / WAF evasion to bypass rate limits or bans.
- VPN/privacy proxies only for researcher identity or regional context if authorized.

### 1.4 Logging & Audit Trail
Log every finding:
`Timestamp | Target | Endpoint | Method | Payload | Response Code | Account Context | Object IDs | Proof Steps`

---

## Phase 2 — Reconnaissance & Asset Mapping

### 2.1 Passive Recon
- DNS & subdomains: crt.sh (Certificate Transparency), passive DNS
- Source code leaks: GitHub/GitLab public repos, hardcoded creds, API keys
- Historical data: Wayback Machine, Common Crawl, gau, AlienVault OTX
- Dangling assets: CNAME → unclaimed S3/Heroku/Azure/GitHub Pages = Subdomain Takeover candidates

### 2.2 Active Fingerprinting (context for testing rules)
- Protocols: HTTP/1.1, HTTP/2, HTTP/3, WebSockets, gRPC
- Frameworks: Express, Spring, Laravel, Rails, Django, ASP.NET, Next.js
- CMS: WordPress, Shopify, Magento
- Auth providers: Auth0, Okta, Firebase, custom OAuth/OIDC/SAML
- Cloud/CDN: CloudFront, Cloudflare, Akamai, Azure CDN, GCP LB

---

## Phase 3 — Attack Surface & API Discovery

### 3.1 Route Mapping
```
/  /login  /register  /oauth/*  /account  /settings  /profile
/admin  /internal  /management  /api/v1  /api/v2  /graphql  /swagger  /docs
```

### 3.2 JavaScript Bundle Analysis
Extract from JS bundles & source maps:
- Hidden API routes, staging endpoints
- Unlinked parameters, feature flags
- Embedded tokens, client secrets, env configs
- Client-side validation/encryption logic

### 3.3 API Classification
- REST: endpoints, methods, params, body schemas, auth headers
- GraphQL: introspection, queries, mutations, subscriptions, depth
- WebSockets/gRPC: event names, message structures, handshake auth

---

## Phase 4 — Authentication & Identity

### 4.1 Auth Workflows
- Registration / Login / Logout edge cases
- Password reset & email verification: token entropy, referrer leak, host header injection
- MFA: bypass, response manipulation, OTP race conditions
- Session lifecycle: expiration, revocation on logout, concurrent sessions

### 4.2 OAuth 2.0 / OIDC / SAML
- OAuth: missing/weak `state` (CSRF), `redirect_uri` manipulation (path traversal, param pollution, open redirect bypass), scope escalation, response_type tampering, account linking flaws → ATO
- SAML: XML Signature Wrapping (XSW), assertion tampering, missing signature validation

---

## Phase 5 — Authorization, Multi-Tenancy & Data Isolation (highest-value surface)

### 5.1 Horizontal (IDOR / BFLA)
Account A vs Account B objects: read private resources, modify data, delete objects, cancel subscriptions.

### 5.2 Vertical (Privilege Escalation)
Standard user → admin endpoints, role assignment, billing, logs, global config.

### 5.3 Mass Assignment & HPP
Inject on POST/PUT/PATCH: `"is_admin": true`, `"role": "admin"`, `"email_verified": true`, `"tenant_id": "victim_id"`. HPP to override security checks.

### 5.4 Multi-Tenant Isolation
Cross-tenant access: data, databases, files, API keys, webhook configs, background jobs.

---

## Phase 6 — Business Logic & State Integrity

### 6.1 Workflow/State Machine Bypass
- Skip steps: `Cart → Confirmation` (skip payment)
- Manipulate transitions: revert paid order to unpaid
- Price/quantity manipulation: negative quantities, float truncation

### 6.2 Race Conditions
Concurrent requests (HTTP/2 single-frame) on: balance withdrawal, coupon redemption, inventory, upvotes, OTP/rate-limit bypass.

### 6.3 Subscription & Resource Abuse
Trial resets, feature-flag manipulation, quota bypass.

---

## Phase 7 — Injection & Server-Side Vulns

### 7.1 SSRF
```
Potential Endpoint → Confirm OOB Request → Controllability → Destination Class → Impact
```
- Use canary domains (interactsh, Burp Collaborator)
- Avoid aggressive cloud metadata (169.254.169.254) scanning unless validated & permitted

### 7.2 Code & Command Injection
- SQLi: headers, JSON keys, limit/offset clauses
- RCE: command injection, unsafe deserialization, SSTI
- XXE: file read, internal SSRF via XML parsers

### 7.3 File Upload
Unrestricted extensions, MIME spoofing, path traversal in filenames, SVG XSS, image processing library exploits.

---

## Phase 8 — Technology-Specific Modules (activate ONLY after fingerprinting)

- **Module A — GraphQL:** introspection, authz flaws on deep mutations, batching/nested DoS (non-destructive)
- **Module B — Node.js/Express:** prototype pollution (`__proto__`, `constructor.prototype`), SSRF via URL parser bugs
- **Module C — Cloud/Serverless:** public S3/Blob ACLs, Firebase/Supabase rule bypass, exposed `.env` / metadata leaks
- **Module D — AI/LLM:** direct & indirect prompt injection, insecure output handling (XSS/cmd exec), training data extraction, system prompt disclosure

---

## Phase 9 — Exploitation, Chaining & Stop Conditions

### 9.1 Minimal PoC Rule
```
Discovered Vulnerability → Construct Minimal PoC → Validate Impact → STOP
```

### 9.2 Controlled Chaining (only to prove business impact)
- Permitted: CSRF + Self-XSS = Stored XSS; IDOR + missing admin auth = ATO
- Prohibited: pivoting deep into internal network, extracting production DBs without explicit authorization

### 9.3 Mandatory Stop Conditions — halt & preserve logs when:
1. Reaching out-of-scope or third-party infrastructure
2. Risk of data destruction / service degradation / production impact
3. Accessing sensitive PII, credentials, or production secrets
4. Working PoC demonstrating max impact achieved

---

## Phase 10 — Evidence & Reporting

### 10.1 Report Structure
```
Title: [Vuln Class] in [Endpoint/Component] leads to [Impact]
Summary: overview + business risk
Severity: CVSS v3.1/v4.0 score + rationale
Affected Asset: domain, endpoint, version, API path
Prerequisites: Account A (role), Account B (role)
Steps to Reproduce: 1. ... 2. ... 3. ...
Proof of Concept: minimal HTTP request/response pairs, curl/snippet
Impact Analysis: technical + real-world business impact
Suggested Remediation: direct technical fix guidance
```

### 10.2 Redaction
Redact all tokens, session cookies, passwords, PII, and secrets from reports/screenshots before submission.

---

## 20 Core Directives (AI Operating Rules)

1. Always verify asset scope before generating/executing active vectors.
2. Never assume third-party/customer assets on the platform are in scope.
3. Program policy & rules of engagement supersede all general techniques.
4. Technology fingerprinting is a hypothesis generator, not proof of vulnerability.
5. No indiscriminate, high-volume automated vulnerability scanning.
6. Tailor payloads to target architecture and framework.
7. Prioritize AuthN, AuthZ, IDOR, and Business Logic for SaaS targets.
8. Use researcher-controlled accounts for cross-account testing.
9. Minimal, non-destructive PoC payloads always.
10. No destructive exploits, service disruption, or data deletion.
11. Respect rate limits; never bypass them via IP proxies.
12. Do not assume SSRF = cloud metadata/Kubernetes access.
13. Validate each link in a vuln chain independently before reporting.
14. Never claim speculative impact without supporting evidence.
15. Protect credentials, tokens, secrets, customer data uncovered.
16. Every finding must be 100% deterministic and reproducible.
17. Stop testing immediately once security impact is verified.
18. Apply tech-specific modules only after positive fingerprinting.
19. Prefer targeted manual logic analysis over generic fuzzing.
20. Goal = verifiable evidence of impact, NOT maximum system compromise.

## Final Operating Loop
```
1. Extract Scope & Rules → 2. Classify Assets → 3. Fingerprint Technology →
4. Map Surface & Endpoints → 5. Form Hypotheses → 6. Validate via Minimal PoC →
7. Confirm Business Impact → 8. Redact & Produce Report
```
