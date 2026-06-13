---
name: hackerone-mcp
description: MCP client for HackerOne - search disclosed reports, get program stats, check scope
tools:
  - WebFetch
  - WebSearch
  - Bash
  - Read
triggers:
  - hackerone
  - h1
  - hackerone reports
  - h1 disclosed
  - h1 program
  - skills hackerone
---

# HackerOne MCP Client

## What It Does
Connects OpenCode to HackerOne's API and disclosed reports data to provide program intelligence, similar report search, and scope management.

## Features
1. Program Stats - Get total paid, avg bounty, response time
2. Disclosed Reports Search - Find similar bugs in same program
3. Scope Check - Verify asset is in scope
4. Researcher Comparison - See what top hunters found

## Data Sources
- HackerOne GraphQL API (with username/password or API token)
- Public disclosed reports at hackerone.com/reports
- Internal 9,833 report dump at /tmp/bb-reports/complete_dump.txt

## Python Client (mcp/hackerone-mcp/client.py)
```bash
# Get program stats (requires HACKERONE_USERNAME + HACKERONE_API_TOKEN)
python3 client.py program uber

# Search disclosed reports (uses local dump + API)
python3 client.py search "IDOR api/users" --limit 10

# Check if domain appears in scope
python3 client.py scope target.com

# Find similar reports by description
python3 client.py similar "IDOR in user profile parameter"
```

## Commands
- /h1-program <program>: Get program stats and scope
- /h1-search <query>: Search disclosed reports
- /h1-similar <finding>: Find similar reports

## Setup
Add to opencode.json:
HACKERONE_USERNAME=your-username
HACKERONE_API_TOKEN=your-token

## Local Report Search (always available)
Use the 9,833 report dump without any setup:
grep -i "keyword" /tmp/bb-reports/complete_dump.txt | head -20
