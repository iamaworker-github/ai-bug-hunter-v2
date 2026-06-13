---
name: web2-vuln-classes
description: 33 vulnerability classes with deep-dive methodologies, real HackerOne report data, bypass techniques, and automation
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - idor
  - ssrf
  - xss
  - sqli
  - sql injection
  - oauth
  - graphql
  - business logic
  - race condition
  - file upload
  - ssti
  - jwt
  - auth bypass
  - account takeover
  - subdomain takeover
  - cors
  - csrf
  - xxe
  - lfi
  - rfi
  - path traversal
  - command injection
  - http smuggling
  - request smuggling
  - cache poisoning
  - cache deception
  - mfa bypass
  - 2fa bypass
  - saml
  - openid
  - sso
  - api testing
  - mobile
  - android
  - ios
  - information disclosure
  - pii
  - dos
  - denial of service
  - clickjacking
  - authorization bypass
  - privilege escalation
  - nosql injection
  - websocket
  - ldap injection
  - open redirect
  - file disclosure
  - lfi
  - deserialization
  - php unserialize
  - java deserialization
  - pickle
  - pop chain
  - gadget chain
  - memory corruption
  - buffer overflow
  - use after free
  - crypto weakness
  - cryptographic
  - llm security
  - prompt injection
  - ai security
  - crlf injection
  - content spoofing
  - session fixation
  - prototype pollution
  - xml injection
  - secrets leak
  - sensitive data
  - data leak
  - secrets exposure
  - backmeup
  - juicy files
---

# Web2 Vulnerability Classes — Deep-Dive Index

This skill contains **33 deep-dive methodology files** covering every vulnerability class with real HackerOne report data, step-by-step testing, bypass techniques, automation, and exploit chains.

Use the index below to navigate to the relevant deep-dive file for full methodology.

---

## Quick Reference — Deep-Dive Files

| # | Vulnerability | File | Reports Analyzed | Payout Range |
|---|---|---|---|---|
| 1 | **SSRF** | `ssrf-deep-dive.md` | 309 | $512 - $30,000+ |
| 2 | **XSS** | `xss-deep-dive.md` | 394 | $500 - $20,000 |
| 3 | **SQL Injection** | `sqli-deep-dive.md` | 305 | $1,000 - $25,000 |
| 4 | **RCE** | `rce-deep-dive.md` | 331 | $2,000 - $30,000 |
| 5 | **IDOR** | `idor-deep-dive.md` | 251 | $500 - $12,500 |
| 6 | **Account Takeover (ATO)** | `ato-deep-dive.md` | 232 | $500 - $35,000 |
| 7 | **API Security** | `api-deep-dive.md` | 111+ | $500 - $40,000 |
| 8 | **Information Disclosure** | `infodisclosure-deep-dive.md` | 345 | $500 - $10,000 |
| 9 | **DoS / Denial of Service** | `dos-deep-dive.md` | 320 | $500 - $12,500 |
| 10 | **File Reading / LFI / Path Traversal** | `filereading-deep-dive.md` | 387 | $500 - $12,000 |
| 11 | **MFA / 2FA Bypass** | `mfa-deep-dive.md` | 90 | $100 - $10,000 |
| 12 | **Mobile App Security** | `mobile-deep-dive.md` | 182 | $500 - $10,000 |
| 13 | **OAuth Attacks** | `oauth-deep-dive.md` | 80 | $500 - $4,000 |
| 14 | **OpenID / SSO / SAML** | `openid-deep-dive.md` | 28 | $500 - $10,500 |
| 15 | **Open Redirect** | `openredirect-deep-dive.md` | 272 | $250 - $3,000 |
| 16 | **Race Conditions** | `racecondition-deep-dive.md` | 79 | $100 - $5,000 |
| 17 | **SSTI** | `ssti-deep-dive.md` | 5+ | $2,000 - $10,000 |
| 18 | **File Upload** | `upload-deep-dive.md` | 152 | $250 - $5,000 |
| 19 | **XXE** | `xxe-deep-dive.md` | 55 | $500 - $6,000 |
| 20 | **CSRF** | `csrf-deep-dive.md` | 475 | $500 - $10,000 |
| 21 | **GraphQL** | `graphql-deep-dive.md` | 71 | $500 - $12,500 |
| 22 | **Subdomain Takeover** | `subdomain-deep-dive.md` | 216 | $200 - $3,000 |
| 23 | **Business Logic** | `businesslogic-deep-dive.md` | 200 | $500 - $12,000 |
| 24 | **HTTP Request Smuggling** | `smuggling-deep-dive.md` | 50 | $500 - $7,500 |
| 25 | **Web Cache Poisoning/Deception** | `webcache-deep-dive.md` | 30 | $500 - $9,700 |
| 26 | **Clickjacking** | `clickjacking-deep-dive.md` | 135 | $200 - $3,000 |
| 27 | **Authorization Bypass** | `authorization-deep-dive.md` | 806 | $500 - $18,000 |
| 28 | **Deserialization** | `deserialization-deep-dive.md` | 100+ | $500 - $17,376 |
| 29 | **Memory Corruption** | `memory-corruption-deep-dive.md` | 30+ | $1,000 - $30,000 |
| 30 | **Crypto Weaknesses** | `crypto-deep-dive.md` | 50+ | $500 - $10,000 |
| 31 | **LLM/AI Security** | `llm-security-deep-dive.md` | 20+ | $500 - $5,000 |
| 32 | **Other Classes** | `other-classes-deep-dive.md` | 100+ | $100 - $10,000 |
| 33 | **Secrets Leak (BACK-ME-UP)** | `secrets-leak-deep-dive.md` | 162 patterns | $500 - $30,000 |

---

## Additional Sections (Included Here)

### A. Authentication Bypass (General)
### Vectors
- Password reset token leakage
- 2FA/MFA bypass (see `mfa-deep-dive.md` for 15+ patterns)
- Session fixation
- JWT weaknesses (`alg:none`, KID injection, weak HMAC secret)
- SAML attacks (see `openid-deep-dive.md`)
- OAuth misconfigurations (see `oauth-deep-dive.md`)

### Payout: $1,000 - $10,000

### B. Cloud/Infra Misconfig
### AWS
- S3 bucket listing/access
- IAM privilege escalation
- EC2 metadata SSRF
- Lambda function injection

### GCP
- Storage bucket enumeration
- IAM misconfig
- Cloud Functions auth bypass

### Azure
- Blob storage public access
- Key Vault enumeration
- Azure AD misconfig

### Payout: $500 - $20,000

### C. CORS Misconfig
### Testing
- Origin reflection
- Wildcard origin with credentials
- Preflight bypass
- Dynamic origin validation

### D. Command Injection
### Testing
- Parameter injection
- Header injection
- File upload filename injection
- Blind out-of-band detection

### Payout: $2,000 - $15,000

### E. NoSQL Injection
### MongoDB Payloads
- `' || 1==1 //`
- `{"$gt": ""}`
- `{"$ne": ""}`
- `'; return true; var foo='`

### F. WebSocket Vulnerabilities
### Testing
- Origin validation
- Message injection
- CSWSH (Cross-Site WebSocket Hijacking)
- No rate limiting on messages

### G. LDAP Injection
### Payloads
- `*)(uid=*))(|(uid=*`
- `admin*)((|userPassword=*)`
- `*` (bypass authentication)

---

## Report Data Sources

**v2 New:** BACK-ME-UP engine integrated — automated sensitive data leakage detection with 162 extension patterns, regex matching, and secrets-agent.

All deep-dive files are based on real HackerOne reports from:
- [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) — ~5,100+ top reports across 28 bug types
- [marcotuliocnd/bugbounty-disclosed-reports](https://github.com/marcotuliocnd/bugbounty-disclosed-reports) — 9,833 disclosed reports (grep-able dump at `/tmp/bb-reports/complete_dump.txt`)
- [codebygk/hackerone-bug-bounty-reports](https://github.com/codebygk/hackerone-bug-bounty-reports) — organized by CWE (167 categories), severity, asset type, program (315)
- [pwnpanda/Bug_Bounty_Reports](https://github.com/pwnpanda/Bug_Bounty_Reports) — ~106 curated reports across 37 vulnerability categories
- External skill zips: IDOR advanced techniques (Filament/Livewire, JWT-claim, multi-tenant SaaS, WAF stealth) and SQL injection payload library (NoSQL, Android, 12-tier payload system, WAF bypass decision tree)

**Total unique H1 reports analyzed: ~15,000+**
