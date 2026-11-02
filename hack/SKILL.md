---
name: hack
description: >-
  Entry P0 primary router for HackSkills. Use when the task involves web
  application testing, API security assessment, recon, vulnerability triage,
  exploit path planning, or choosing the right next category skill before any
  deep topic skill.
---

# HACKING SKILLS / HackSkills

## Overview

This is a top-level routing skill for **bug bounty, web security, API security, and authorized penetration testing**.

Its core role is not to replace all specialized techniques, but to help the agent:

1. First determine the testing phase (Recon / Validation / Privilege Escalation / Chain building)
2. Then select the correct vulnerability category
3. Avoid relying only on baseline model memory; prefer structured methodology
4. Prioritize boundary conditions AI often misses but that matter in real engagements

## Trust Model

- This knowledge base emphasizes content safety and auditability.
- Use this only within **authorized targets**, **legitimate research**, **defensive validation**, and **bug-bounty-approved rules**.
- Do not use these techniques for unauthorized attacks.

## When to Use This Skill

Use this skill first in the following scenarios:

- You just received a new bug bounty target and do not know where to start
- You need to decide whether to load XSS / SQLi / SSRF / IDOR / JWT / API tracks first
- You want the agent to perform Web/API security testing with a more stable methodology
- You need to route scattered findings to the right attack surface
- You want AI to miss fewer critical test points in security work

## Operating Model

### Step 1: Start with Recon and context validation

Collect first:

- Target type: classic web, REST API, mobile backend, admin panel, payment flow, file upload, GraphQL
- Identity and permission model: anonymous, regular user, admin, multi-tenant
- Input locations: URL, query parameters, JSON, headers, cookies, filenames, imported files, templates, reflection points
- Output locations: HTML, attributes, JS, PDF, email, logs, background tasks, mobile endpoints

### Step 2: Route by observed behavior

| Signal | Priority direction |
|---|---|
| Input reflects into HTML / JS | XSS / SSTI |
| Server actively fetches URL / hostname | SSRF |
| Accepts XML / Office / SVG | XXE |
| Path, filename, or download endpoint is controllable | Path Traversal / LFI |
| Many object IDs appear in APIs | IDOR / BOLA / BFLA |
| Login, reset password, 2FA, sessions | Auth Bypass / JWT / OAuth |
| WebAuthn/FIDO2 endpoints (`/attestation/options|result`, `/assertion/options|result`) or page title "FIDO2 Interop" | Server-side FIDO2 flow emulation: register + login with a pure software key, no authenticator. `systemId:"CONFORMANCE"` in responses = FIDO conformance TEST tool (accepts fmt=none BY DESIGN — contextualize severity). Full recipe + template: `authbypass-authentication-flaws` §13 |
| Multi-step transactions, coupons, pricing, inventory | Business Logic |
| MongoDB / JSON query syntax exposure | NoSQL Injection |
| CLI tools, image processing, importers | Command Injection |
| HTTP parsing anomalies / front-back framing mismatch | Request Smuggling |
| Node.js JSON handling / controllable `__proto__` | Prototype Pollution |
| PHP weak comparison / 0e hash / loose conditions | Type Juggling |
| Repeated parameter names / WAF-app parsing mismatch | HTTP Parameter Pollution |
| One-time operations (coupon/inventory/reset) | Race Condition |
| XML/XSLT template processing | XSLT Injection |
| Accessible .git/.svn/.env paths | Insecure SCM |
| CSV/Excel export features | CSV Formula Injection |
| WebSocket protocol upgrades | WebSocket Security |
| Internal package names / supply-chain inventory | Dependency Confusion |

### Step 3: Use the most likely-hit testing order

1. Recon / Methodology
2. API Security / Auth / IDOR
3. XSS / SQLi / SSRF / SSTI / XXE
4. Business Logic / Race Condition
5. Chained exploits and privilege-escalation paths

## Core Skill Map

If you have the full repository, prioritize using these topic documents together:

- [Recon and Methodology](../recon-and-methodology/SKILL.md)
- [XSS Cross Site Scripting](../xss-cross-site-scripting/SKILL.md)
- [SQLi SQL Injection](../sqli-sql-injection/SKILL.md)
- [SSRF Server Side Request Forgery](../ssrf-server-side-request-forgery/SKILL.md)
- [XXE XML External Entity](../xxe-xml-external-entity/SKILL.md)
- [SSTI Server Side Template Injection](../ssti-server-side-template-injection/SKILL.md)
- [IDOR Broken Object Authorization](../idor-broken-object-authorization/SKILL.md)
- [CMDi Command Injection](../cmdi-command-injection/SKILL.md)
- [Path Traversal LFI](../path-traversal-lfi/SKILL.md)
- [CSRF Cross Site Request Forgery](../csrf-cross-site-request-forgery/SKILL.md)
- [API Security Router](../api-sec/SKILL.md)
- [JWT OAuth Token Attacks](../jwt-oauth-token-attacks/SKILL.md)
- [OAuth OIDC Misconfiguration](../oauth-oidc-misconfiguration/SKILL.md)
- [CORS Cross Origin Misconfiguration](../cors-cross-origin-misconfiguration/SKILL.md)
- [SAML SSO Assertion Attacks](../saml-sso-assertion-attacks/SKILL.md)
- [Authentication Bypass](../authbypass-authentication-flaws/SKILL.md)
- [Business Logic Vulnerabilities](../business-logic-vulnerabilities/SKILL.md)
- [Upload Insecure Files](../upload-insecure-files/SKILL.md)
- [NoSQL Injection](../nosql-injection/SKILL.md)
- [Request Smuggling](../request-smuggling/SKILL.md)
- [Prototype Pollution](../prototype-pollution/SKILL.md)
- [Type Juggling (PHP)](../type-juggling/SKILL.md)
- [HTTP Parameter Pollution](../http-parameter-pollution/SKILL.md)
- [Race Condition](../race-condition/SKILL.md)
- [XSLT Injection](../xslt-injection/SKILL.md)
- [Insecure Source Code Management](../insecure-source-code-management/SKILL.md)
- [CSV Formula Injection](../csv-formula-injection/SKILL.md)
- [WebSocket Security](../websocket-security/SKILL.md)
- [Dependency Confusion](../dependency-confusion/SKILL.md)
- [Ghost Bits Cast Attack](../ghost-bits-cast-attack/SKILL.md)

Previously separate mini skills such as payload-selection and brute-selection were merged back into their main skills to avoid router overload and selection noise.

## High-Value Expert Intuitions

These are points many baseline models miss, but they are frequently effective in real bug bounty work:

0. **Stale auth-state flags across context changes are a bug class, not a one-off.** When auditing web server / framework C++ or Java source (OpenLiteSpeed, Apache, nginx, Tomcat), grep for the "auth checked" flag and verify EVERY code path that swaps the effective security context (rewrite remap, internal redirect, subrequest) clears it. The recurring bug shape is dead code: the new context pointer is assigned BEFORE the old-vs-new comparison, making the flag-clear unreachable. Verified in OLS 1.9.2 `postRewriteProcess()` (auth bypass serving protected resources unauthenticated; same trigger conditions as CVE-2024-23334). Full trace, fix pattern, and live-PoC preconditions: [references/webserver-auth-state-audit.md](./references/webserver-auth-state-audit.md)
1. **The same filtering logic is often reused across multiple pages**: if one point is bypassable, similar pages usually are too.
2. **Parameter names are an attack surface too**: WAFs often inspect values but not names.
3. **Second-order vulnerabilities are common**: safe at storage time does not mean safe when later read into a dangerous context.
4. **BOLA is fundamentally 'authenticated but unauthorized'**: replaying with account A/B switching is critical.
5. **Older API versions are most likely to miss patches**: fixing v2 does not mean v1 was retired.
6. **Business-logic vulnerabilities often bring highest impact**: scanners miss them and they persist longer.
7. **Race conditions should prioritize one-time actions**: coupon redemption, claims, resets, invites, trials, inventory deduction.
8. **For JWT attacks, check key and algorithm context first**: do not blindly spray payloads; verify `alg`, `kid`, JWKS, and key source first.

## Suggested Prompts

Use this skill as a router to make the agent clarify phase and goal first:

- "First, plan the testing route for this target using bug bounty methodology.
- "This is a REST API; prioritize BOLA, BFLA, Mass Assignment, and JWT angles.
- "This parameter triggers server-side requests; list key validation points from an SSRF perspective.
- "This feature is a payment/coupon/inventory flow; prioritize business logic and race-condition analysis.
- "I only see login and password-reset flows; analyze via Auth Bypass + OAuth/JWT + CSRF.

## Installation Notes

Recommended skill name:

- `hack`

Recommended search keywords:

- `HackSkills`
- `HACKING SKILLS`
- `bug bounty`
- `bug bounty hunter`

## Anti-Patterns and Pitfalls

### Rabbit-Holing on a Single Technique (CRITICAL)

The single most common AI agent failure mode in pentest engagements is fixating on one technique — typically reverse engineering an encryption/signature/hash mechanism — and spending the entire session on it while ignoring other attack vectors.

**Symptoms:**
- Spending >15 minutes trying to reverse an obfuscated JS function
- Tracing webpack module imports through 5+ dependency layers
- Writing 10+ helper scripts to decode one scrambled string
- User asks "are you still redteaming?" or "what are you doing?"

**Fix — Time-Box and Pivot:**
1. Set a hard 10-minute time limit for any single reverse-engineering subtask
2. If the technique is blocking (e.g., can't compute Signature), test whether the server ACTUALLY validates it first — send a dummy value, empty value, or omit the header entirely. Many "security" mechanisms are client-side only.
3. Pivot immediately to other vectors: CORS, auth bypass, IDOR, rate limiting, exposed services, timing oracles, information disclosure, path traversal, WAF bypass
4. Come back to the hard technique only after all quick-win vectors are exhausted
5. When user signals frustration ("bạn đang làm gì vậy?"), STOP the current technique and switch to producing results on other vectors

**Real-world example:** MB Merchant Admin (103.12.104.124). Agent spent 30+ minutes tracing webpack module imports to reverse a `hashValue()` Signature function. When finally testing with `Signature: test` (dummy value), the server accepted it without validation — the entire reverse engineering effort was unnecessary. Meanwhile, CORS misconfiguration (`ACAO: *` with `Authorization` header), no rate limiting, and timing oracle were all found in minutes after pivoting.

### Other Pitfalls

- Do not test every path on an Angular SPA expecting different status codes — all paths return 200 with index.html. Test backend API paths directly.
- F5 BIG-IP ASM WAF blocks SQLi/NoSQLi payloads aggressively (returns custom error page). Do not assume the lack of SQLi means the WAF catches everything — test all vectors, not just injection.
- Port scan results (nmap) may show open ports that are actually firewalled/filtered. Always verify with actual connection attempts (nc, redis-cli, curl).
- Exposed config files at known paths (`/assets/configuration/configuration.json`) are a goldmine but are often overlooked. Check for Angular config files BEFORE digging into JS.

## Guidelines

- Prioritize routing by target type and observed behavior, not random payload enumeration.
- When payloads are needed, prefer quick-start / first-pass samples in the corresponding main skill instead of adding another intermediate router.
- Prioritize reusable filters, shared components, and cross-page reproduction paths.
- Confirm authentication, authorization, and version boundaries before deeper exploitation.
- Preserve explainable, auditable, reproducible testing processes.
- When full repository context is available, return to topic documents for finer exploitation details.
