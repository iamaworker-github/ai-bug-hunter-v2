# AI Bug Hunter v2

### AI-Powered Bug Bounty Hunting — Recon to Report, in your Terminal

**33 vulnerability classes · BACK-ME-UP secrets scanner · 30+ commands**  
**100% Free with OpenCode Zen (deepseek-v4-flash-free)**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agents](https://img.shields.io/badge/agents-9-blueviolet?style=flat-square)](agents/)
[![Skills](https://img.shields.io/badge/skill_domains-12-3776AB?style=flat-square)](skills/)
[![Classes](https://img.shields.io/badge/vuln_classes-33-brightgreen?style=flat-square)](skills/web2-vuln-classes/)
[![MCP Clients](https://img.shields.io/badge/mcp_clients-3-blue?style=flat-square)](mcp/)

---

## What Is This?

AI Bug Hunter v2 is a professional **standalone** bug bounty hunting toolkit. Give it a target — it handles recon, tests for 33 vulnerability classes, validates findings through a strict gate, and writes submission-ready reports for HackerOne, Bugcrowd, Intigriti, and Immunefi.

**v2 Exclusive Features:**
- **33 vuln classes** (13 more than original) — each with deep-dive methodology
- **BACK-ME-UP engine** — 10 parallel URL collectors, 162 extension patterns, scope-filtered secrets leak detection
- **Payload library** — 20-class unified payload reference
- **Exploit chains** — 20 real H1 attack chains
- **Methodology cheatsheet** — 33-class quick reference

---

## Quick Start

```bash
git clone https://github.com/iamaworker-github/ai-bug-hunter-v2.git
cd ai-bug-hunter-v2
chmod +x install.sh install_tools.sh

# Install scanning tools (subfinder, httpx, nuclei, etc.)
./install_tools.sh

# Install standalone command
./install.sh --agent standalone

# Set your AI provider (Zen is free)
export ZEN_API_KEY="your-zen-api-key"   # get at https://opencode.ai/zen
ai-bug-hunter-v2 setup                   # choose Zen (option 1)
ai-bug-hunter-v2 recon target.com
ai-bug-hunter-v2 hunt  target.com
ai-bug-hunter-v2 validate "finding"
ai-bug-hunter-v2 report
```

---

## AI Providers

Auto-detected in priority order. Set only the one you want to use.

| Provider | Cost | Env Var | Setup |
|:---|:---|:---|:---|
| **OpenCode Zen** | **FREE** (deepseek-v4-flash-free) | `ZEN_API_KEY` | [opencode.ai/zen](https://opencode.ai/zen) |
| **Ollama** | 100% free · local | `OLLAMA_HOST` | `ollama pull qwen2.5:14b` |
| **Groq** | Free tier | `GROQ_API_KEY` | [console.groq.com](https://console.groq.com) |
| **DeepSeek** | Cheap ($0.001/1K) | `DEEPSEEK_API_KEY` | [platform.deepseek.com](https://platform.deepseek.com) |
| **Claude** | Paid | `ANTHROPIC_API_KEY` | [console.anthropic.com](https://console.anthropic.com) |
| **OpenAI** | Paid | `OPENAI_API_KEY` | [platform.openai.com](https://platform.openai.com) |
| **Grok/xAI** | Paid | `XAI_API_KEY` | [x.ai](https://x.ai) |

```bash
# Quick start with Zen (free)
export ZEN_API_KEY="zen_..."
ai-bug-hunter-v2 recon target.com

# Or use Ollama (free, local)
ai-bug-hunter-v2 setup   # choose Ollama
ai-bug-hunter-v2 recon target.com
```

---

## All 30+ Commands

| Command | Category | What it does |
|---------|----------|-------------|
| `setup` | Setup | One-time config wizard |
| `providers` | Setup | Show providers + API key status |
| `models` | Setup | List available models |
| `status` | Setup | Show pipeline status |
| `recon <target>` | Core | Full recon — subdomains, live hosts, URLs, tech |
| `hunt <target>` | Core | Active vulnerability testing (33 classes) |
| `validate` | Core | 7-Question Gate — kill weak findings |
| `triage [finding]` | Core | 2-minute go/no-go check |
| `report` | Core | Submission-ready report (H1/Bugcrowd/Immunefi) |
| `chain <finding>` | Core | Build A→B→C exploit chains |
| `chat` | Core | Interactive AI shell |
| `autopilot <target> [mode]` | Autopilot | Full autonomous hunt loop |
| `pickup <target>` | Autopilot | Resume previous hunt |
| `surface <target>` | Autopilot | Ranked attack surface |
| `remember [details]` | Autopilot | Save to cross-session memory |
| `memory-gc` | Autopilot | Rotate memory files |
| `scope <asset>` | Recon | Verify scope |
| `scope-aggregate <program>` | Recon | Pull all in-scope assets |
| `intel <target>` | Recon | CVEs + disclosed reports |
| `takeover <target>` | Recon | Subdomain takeover candidates |
| `cloud-recon <target>` | Recon | S3/Azure/GCP buckets |
| `secrets-hunt <target>` | Recon | Leaked creds in JS/GitHub |
| `secrets-leak <target>` | Recon | BACK-ME-UP: 10 collectors → 162 patterns |
| `param-discover <url>` | Recon | Hidden HTTP parameters |
| `bypass-403 <url>` | Recon | 403/401 bypass techniques |
| `scan-cves <target>` | Recon | Nuclei CVE sweep |
| `arsenal` | Recon | List installed tools |
| `web3-audit <contract>` | Web3 | Smart contract audit |
| `token-scan <contract>` | Web3 | Meme coin rug pull analysis |
| `breach-check [target]` | Extra | Check for breached credentials |

---

## 33 Vulnerability Classes

SSRF · XSS · SQLi · RCE · IDOR · ATO · API Security · Info Disclosure · DoS · LFI  
MFA/2FA · Mobile · OAuth · OpenID/SSO · Open Redirect · Race Conditions · SSTI  
File Upload · XXE · CSRF · GraphQL · Subdomain Takeover · Business Logic  
HTTP Smuggling · Web Cache · Clickjacking · Authorization Bypass · Deserialization  
Memory Corruption · Crypto Weaknesses · LLM/AI Security · Extra Classes  
**Secrets Leak (v2)** · **Exploit Chains** · **Payload Library**

Each class has a dedicated deep-dive file with methodology, payloads, and real-world examples from 15,000+ analyzed H1 reports.

---

## 9 AI Agents

| Agent | Role |
|-------|------|
| **recon-agent** | Fast recon — subdomains, live hosts, URLs, tech, params |
| **recon-ranker** | Attack surface ranking — prioritize endpoints by value |
| **validator** | 7-Question Gate + 4 validation gates |
| **chain-builder** | Exploit chain builder — A→B→C attack paths |
| **report-writer** | Professional impact-first reports |
| **autopilot-agent** | Full hunt loop orchestrator |
| **secrets-scanner** | BACK-ME-UP secrets leak detection |
| **web3-auditor** | Smart contract security auditor |
| **token-auditor** | Crypto token rug-pull analysis |

---

## 12 Skill Domains

- **bug-bounty** — Master workflow
- **web2-recon** — Recon pipeline
- **web2-vuln-classes** — 33 classes + payloads + chains
- **bb-methodology** — 5-phase workflow
- **security-arsenal** — Payloads + cheatsheet + nestjs-security
- **triage-validation** — 7-Question Gate
- **report-writing** — Report templates
- **web3-audit** — 10 DeFi classes
- **meme-coin-audit** — 8 rug pull signals
- **osint-ctf** — OSINT techniques
- **nestjs-security** — NestJS security testing

---

## BACK-ME-UP (v2 Exclusive)

10 URL collectors running in parallel → scope filter → 162 extension patterns → secrets detection.

```bash
bash tools/backmeup.sh -d target.tld
```

Collectors: `gau` · `gauplus` · `waybackurls` · `katana` · `gospider` · `hakrawler` · `cariddi` · `crawley` · `waymore`

Scope filter auto-removes 3rd party URLs. 162 patterns cover `.git/config`, `.env`, `.pem`, `.key`, `swagger.json`, CI/CD tokens, and more.

---

## MCP Integrations

| Client | Usage |
|--------|-------|
| **Burp Suite** | `python3 mcp/burp-mcp-client/client.py scan` |
| **Caido** | `python3 mcp/caido-mcp-client/client.py history --limit 100` |
| **HackerOne** | `python3 mcp/hackerone-mcp/client.py search "IDOR api" --limit 10` |

---

## Architecture

```
ai-bug-hunter-v2 (Standalone CLI — brain.py + engine.py)
       ↓
  Multi-Provider LLM (Zen / Ollama / Groq / DeepSeek / Claude / OpenAI / Grok)
       ↓
  Skills Engine (12 domains, 33 vuln classes)
       ↓
  AI Agent (recon / validator / chain-builder / autopilot / etc.)
       ↓
  Tool Executor (30+ commands)
    ├─ BACK-ME-UP (10 URL collectors → scope filter → 162 patterns)
    ├─ Cloud recon (S3Scanner / cloud_enum / CloudFail)
    ├─ Secrets hunting (trufflehog / gitleaks / noseyparker)
    ├─ Vuln scanners (nuclei / dalfox / sqlmap)
    ├─ Post-hunt (validate / report / chain)
    └─ Web3 audit
       ↓
  Memory (cross-session learning)
```

---

## Option C — Docker

```bash
docker build -t ai-bug-hunter-v2 .
docker run -it --rm \
  -e ZEN_API_KEY="your-zen-api-key" \
  -v $PWD/output:/workspace/output \
  ai-bug-hunter-v2
```

Inside the container:
```bash
ai-bug-hunter-v2 setup
ai-bug-hunter-v2 recon target.com
ai-bug-hunter-v2 hunt target.com
```

All tools pre-installed (subfinder, httpx, nuclei, katana, ffuf, gau, etc.). Runs as root by default.

## Install Dependencies

```bash
# Required
pip3 install requests

# Optional (for Ollama)
pip3 install ollama

# Security tools (recommended)
chmod +x install_tools.sh && ./install_tools.sh
```

## Requirements

- Python 3.8+
- Go tools: subfinder, httpx, nuclei, katana, ffuf, gau (install via `install_tools.sh`)

---

## License
MIT — For authorized security testing only. Test only within approved bug bounty program scope.
