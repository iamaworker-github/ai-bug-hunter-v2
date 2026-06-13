---
name: caido-mcp-client
description: MCP client for Caido - AI reads Caido proxy traffic for vulnerability analysis
tools:
  - Bash
  - WebFetch
  - Read
triggers:
  - caido
  - caido proxy
  - caido traffic
  - skills caido
---

# Caido MCP Client

## What It Does
Connects OpenCode to Caido's API, allowing the AI to read your Caido proxy history and analyze traffic.

## Setup
1. Install Caido (caido.io)
2. Enable API in Caido settings
3. Set config in opencode.json:
   CAIDO_API_URL=http://127.0.0.1:8080
   CAIDO_API_KEY=your-key-here

## Python Client (mcp/caido-mcp-client/client.py)
```bash
# Fetch last 50 proxy entries
python3 client.py history

# Fetch last 100
python3 client.py history --limit 100

# Check scope
python3 client.py scope

# Auto-scan: rank interesting requests
python3 client.py scan
```
