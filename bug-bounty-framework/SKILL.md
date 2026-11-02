---
name: bug-bounty-framework
description: >
  AI Bug Bounty & Vulnerability Research Framework — hệ thống methodology
  toàn diện cho bug bounty: từ scope, recon, attack surface, OAuth, auth,
  IDOR, business logic, race condition, SSRF, injection, GraphQL, cloud,
  AI/LLM, đến chaining và reporting.
---

# AI Bug Bounty & Vulnerability Research Framework

## Mission & Core Operating Principle

> **Understand target architecture → map attack surface → form hypotheses → validate vulnerabilities → prove impact with minimal evidence → report accurately.**

### Core Workflow
```
SCOPE
  ↓
ASSETS & RECON
  ↓
ATTACK SURFACE MAP
  ↓
HYPOTHESIS FORMATION
  ↓
CONTROLLED VALIDATION
  ↓
IMPACT PROOF
  ↓
MINIMAL EVIDENCE
  ↓
STRUCTURED REPORT
```

### Prohibited Workflow
```
SCAN EVERYTHING → EXPLOIT EVERYTHING → LOOK FOR IMPACT
```

---

# Phase 0 — Scope, Authorization & Policy Compliance

## 0.1 Policy Rules Extraction
- Program name & platform (HackerOne, Bugcrowd, Intigriti, Self-hosted)
- In-scope targets (Domains, Wildcards, Mobile apps, APIs, IP ranges)
- Out-of-scope targets & forbidden classes (DoS, Spam, Social Engineering)
- Required HTTP Headers / User-Agent strings
- Rate limits & testing windows
- Safe Harbor & Disclosure terms

## 0.2 Asset Classification & Scope Matrix
- `IN_SCOPE`: Authorized for systematic testing
- `OUT_OF_SCOPE`: Do not interact
- `THIRD_PARTY`: External SaaS/Services (Requires policy check)
- `CUSTOMER_ASSET`: Customer-hosted instances (Strict isolation)
- `UNKNOWN`: Halt until ownership confirmed

---

# Phase 1 — OPSEC, Traffic Control & Safety Constraints

## 1.1 Traffic Identification
```http
User-Agent: <Program-Required-User-Agent-Or-Researcher-ID>
X-Bug-Bounty: Researcher-<Username>
```

## 1.2 Rate Control
`Explicit Program Rate Limit -> Platform Default Policy -> Conservative Baseline (<= 5 req/sec)`

## 1.3 Rules on Evasion
- **Do NOT** use IP rotation, proxy chaining, or WAF evasion to bypass rate limits
- Privacy proxies/VPNs only for researcher identity/regional context if authorized

## 1.4 Logging
`Timestamp | Target | Endpoint | HTTP Method | Request Payload | Response Code | Account Context | Target Object IDs | Proof Steps`

---

# Phase 2 — Reconnaissance & Asset Mapping

## 2.1 Passive Recon
- **DNS & Subdomains:** crt.sh, Passive DNS, DNS dumps
- **Source Code:** GitHub/GitLab leaks, hardcoded credentials, internal endpoints
- **Historical:** Wayback Machine, Common Crawl, Gau, AlienVault OTX
- **Dangling Assets:** CNAME → unclaimed S3/Heroku/Azure/GitHub Pages (Subdomain Takeover)

## 2.2 Active Recon & Fingerprinting
- Protocol detection (HTTP/1.1, HTTP/2, HTTP/3, WebSockets, gRPC)
- Server/Framework (Node.js/Express, Spring, Laravel, Rails, Django, ASP.NET, Next.js)
- CMS (WordPress, Shopify, Magento)
- Auth provider (Auth0, Okta, Firebase, Custom OAuth/OIDC/SAML)
- Cloud & CDN (CloudFront, Cloudflare, Akamai, Azure CDN, GCP LB)

---

# Phase 3 — Attack Surface & API Discovery

## 3.1 Route Mapping
```
/ | /login | /register | /oauth/*
/account | /settings | /profile
/admin | /internal | /management
/api/v1 | /api/v2 | /graphql | /swagger | /docs
```

## 3.2 JS Bundle Analysis
- Hidden API routes & staging endpoints
- Unlinked parameter names & feature flags
- Embedded API tokens, client secrets, env configs
- Client-side validation & encryption routines

## 3.3 API Surface Classification
- **REST:** Endpoints, methods, params, schemas, auth headers
- **GraphQL:** Introspection, queries, mutations, subscriptions, depth
- **WebSockets/gRPC:** Event names, message structures, handshake auth

---

# Phase 4 — Authentication & Identity Management

## 4.1 Auth Workflows
- Registration / Login / Logout flows
- Password Reset & Email Verification (token entropy, referrer leak, host header injection)
- MFA bypass (response manipulation, race conditions on OTP)
- Session lifecycle (token expiration, revocation, concurrent session limits)

## 4.2 OAuth 2.0 / OIDC / SAML
- **OAuth/OIDC:**
  - CSRF via missing/weak `state` parameter
  - `redirect_uri` manipulation (path traversal, parameter pollution, open redirect)
  - Scope escalation & response_type tampering (`token` vs `code`)
  - Account linking/unlinking → ATO
- **SAML:** XML Signature Wrapping (XSW), assertion tampering, missing signature validation

---

# Phase 5 — Authorization, Multi-Tenancy & Data Isolation

## 5.1 Horizontal Authorization (IDOR / BFLA)
- **Read:** Fetching private resources, exports, user profiles
- **Create/Update:** Modifying resources, changing emails, configs
- **Delete:** Removing objects, canceling subscriptions

## 5.2 Vertical Authorization (Priv Esc)
- Admin API endpoints & management actions
- Role assignment & privilege modifications
- System-wide billing, logs, global config flags

## 5.3 Mass Assignment & Parameter Pollution
- Inject: `"is_admin": true`, `"role": "admin"`, `"email_verified": true`, `"tenant_id": "victim_id"`
- HTTP Parameter Pollution (HPP) to override security checks

## 5.4 Multi-Tenant Data Isolation
Cross-tenant: data, databases, files, API keys, webhooks, background jobs

---

# Phase 6 — Business Logic & State Integrity

## 6.1 Workflow & State Machine Bypass
- Can steps be skipped? (Cart → Confirmation)
- State manipulation? (Revert paid order to unpaid)
- Price/Quantity manipulation (negative, floating point truncation)

## 6.2 Race Conditions
HTTP/2 Single-Frame or parallel execution on:
- Balance withdrawal / Coupon codes / Reward points
- Inventory reservation / Upvoting / Friend requests
- OTP/MFA rate-limit bypass

## 6.3 Subscription & Resource Abuse
- Trial resets, feature-flag manipulation, API call quota bypass

---

# Phase 7 — Injection & Server-Side Vulnerabilities

## 7.1 SSRF
```
Endpoint → Confirm OOB → Controllability → Destination → Impact
```
- Use canary domains / interactsh / Burp Collaborator
- Avoid aggressive `169.254.169.254` scanning unless validated

## 7.2 Code & Command Injections
- **SQLi:** Headers, JSON keys, limit/offset clauses
- **RCE:** Command injection, unsafe deserialization, SSTI
- **XXE:** File read, internal SSRF via XML parsers

## 7.3 File Upload
- Unrestricted extension, MIME spoofing, path traversal, SVG XSS, ImageTragick

---

# Phase 8 — Technology-Specific Modules

## Module A: GraphQL
- Introspection access
- Auth flaws on deep mutations/queries
- Query batching / Nested query DoS (non-destructive)

## Module B: Node.js / Express
- Prototype Pollution (`__proto__`, `constructor.prototype`)
- Unhandled promise rejections, SSRF via URL parser bugs

## Module C: Cloud Native & Serverless
- Public S3/Blob storage misconfigs (Read/Write ACLs)
- Firebase/Supabase unauthenticated DB rule bypass
- Exposed env vars (`.env`, Cloud metadata leaks)

## Module D: AI / LLM Integrations
- Direct & Indirect Prompt Injection
- Insecure Output Handling → XSS or Command Execution
- Training data extraction & System Prompt disclosure

---

# Phase 9 — Exploitation, Chaining & Stop Conditions

## 9.1 Minimal PoC Rule
```
Discovered Vulnerability → Construct Minimal PoC → Validate Impact → STOP
```

## 9.2 Controlled Chaining
- *Permitted:* CSRF + Self-XSS = Stored XSS
- *Permitted:* Low-Priv IDOR + Missing Auth on Admin = ATO
- *Prohibited:* Deep internal network pivot or prod DB extraction without authorization

## 9.3 Mandatory Stop Conditions
1. Reaching OOS assets or third-party infra
2. Data destruction, service degradation, or production impact
3. Accessing sensitive PII, customer credentials, or prod secrets
4. Achieving PoC that demonstrates max impact

---

# Phase 10 — Evidence & Reporting Standard

## 10.1 Report Structure
```
Title: [Vuln Class] in [Endpoint] leads to [Impact]

Summary: Overview & business risk
Severity: CVSS v3.1/v4.0 with rationale
Affected Asset: Domain, Endpoint, Mobile Version, API Path

Prerequisites:
- Account A (Role)
- Account B (Role)

Steps to Reproduce:
1. Step 1
2. Step 2
3. Step 3

Proof of Concept:
- Minimal HTTP Request/Response pairs
- Minimal curl command / code snippet

Impact Analysis:
- Technical Impact
- Real-World Business Impact

Suggested Remediation
```

## 10.2 Sensitive Data Redaction
Redact tokens, cookies, passwords, PII, and secrets from reports/screenshots.

---

# 20 Core Directives

```
RULE 1:  Always verify asset scope before generating active attack vectors.
RULE 2:  Never assume third-party or customer assets are in scope.
RULE 3:  Program policy supersedes all general testing techniques.
RULE 4:  Tech fingerprinting is hypothesis generation, not proof of vuln.
RULE 5:  Do not execute indiscriminate, high-volume automated scanning.
RULE 6:  Tailor payloads specifically to target architecture.
RULE 7:  Prioritize Auth, Authz, IDOR, Business Logic for SaaS.
RULE 8:  Use researcher-controlled accounts for cross-account testing.
RULE 9:  Always employ minimal, non-destructive PoC payloads.
RULE 10: Do not attempt destructive exploits, service disruption, or deletion.
RULE 11: Respect rate limits; do not bypass using IP proxies.
RULE 12: Do not assume SSRF = Cloud Metadata or K8s access.
RULE 13: Validate each link in a vuln chain independently before reporting.
RULE 14: Never claim speculative impact without supporting evidence.
RULE 15: Protect credentials, tokens, secrets, and customer data.
RULE 16: Ensure every finding is 100% deterministic and reproducible.
RULE 17: Immediately stop testing once impact is verified.
RULE 18: Apply tech-specific modules only after positive fingerprinting.
RULE 19: Prefer targeted manual logic analysis over generic payload fuzzing.
RULE 20: Goal = Verifiable evidence of impact, NOT maximum compromise.
```

---

# Final AI Operating Loop

```
1. Extract Scope & Rules → 2. Classify Assets → 3. Fingerprint Technology →
4. Map Surface & Endpoints → 5. Form Vulnerability Hypotheses →
6. Validate via Minimal PoC → 7. Confirm Business Impact → 8. Redact & Produce Report.
```