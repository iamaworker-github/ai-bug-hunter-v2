---
name: burp-mcp-client
description: MCP client for Burp Suite - AI reads your Burp proxy history in real time to find vulnerabilities
tools:
  - Bash
  - WebFetch
  - Read
triggers:
  - burp
  - burp suite
  - burp traffic
  - burp proxy
  - skills burp
---

# Burp Suite MCP Client

## What It Does
Connects OpenCode to Burp Suite's REST API, allowing the AI to read your live proxy traffic, identify interesting endpoints, and test them automatically.

## Setup
1. Install Burp Suite (Professional or Community)
2. Enable REST API in Burp: Extensions → APIs → REST API
3. Set API key in opencode.json or env:
   BURP_API_URL=http://127.0.0.1:1337
   BURP_API_KEY=your-key-here

## Python Client (mcp/burp-mcp-client/client.py)
```bash
# Fetch last 50 proxy entries
python3 client.py history

# Fetch last 100
python3 client.py history --limit 100

# Check scope
python3 client.py scope

# Send request to repeater
python3 client.py repeater --url "https://target.com/api/user?id=1" --method GET

# Auto-scan: rank interesting requests
python3 client.py scan
```

## Commands
- /burp-scan: Run the AI against current Burp proxy history
- /burp-live: Watch Burp proxy in real-time, flag interesting requests
- /burp-send: Send a crafted request through Burp's repeater
