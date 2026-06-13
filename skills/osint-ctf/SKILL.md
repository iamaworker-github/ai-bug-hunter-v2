---
name: osint-ctf
description: OSINT techniques, Google dorking, CTF challenge solving methodology
tools:
  - WebSearch
  - WebFetch
  - Bash
  - Read
triggers:
  - osint
  - ctf
  - google dork
  - shodan
  - recon
  - intelligence
---

# OSINT & CTF Methodology

## Google Dorking
### Common Dorks
```
site:target.com intitle:"index of"
site:target.com inurl:admin
site:target.com ext:pdf
site:target.com inurl:api
site:target.com inurl:wp-admin
site:target.com filetype:env
site:target.com intitle:"Dashboard" "login"
```

### Sensitive Data
```
site:target.com ext:sql
site:target.com ext:log
site:target.com ext:bak
site:target.com ext:swp
site:target.com "password" filetype:env
site:github.com target.com "API_KEY"
```

## GitHub OSINT
```bash
# Search org repos
org:target-org type:code "password"
org:target-org type:code "api_key"
org:target-org type:code "aws_secret"

# Search commits
git clone https://github.com/target-org/target-repo.git
cd target-repo && git log --all --oneline | head -50
git log --all -p --diff-filter=D -S "password"
git log --all --oneline --grep="fix" --grep="security" --all-match
```

## Shodan Queries
```
ssl:"target.com"
org:"Target Org"
http.title:"target"
http.favicon.hash:hash_value
```

## CTF Challenge Solving
### Web Challenges
- Directory enumeration
- Parameter pollution
- JWT manipulation
- SQL injection
- SSTI
- File upload bypass
- LFI/RFI
- SSRF

### Crypto Challenges
- Frequency analysis
- XOR bruteforce
- RSA attacks (Wiener, Hastad, common modulus)
- Padding oracle
- Hash length extension

### Reverse Engineering
- Static analysis (Ghidra, IDA)
- Dynamic analysis (gdb, ltrace)
- Deobfuscation
- Packer detection/removal

### Forensics
- File carving (binwalk, foremost)
- Memory analysis (volatility)
- PCAP analysis (wireshark, tshark)
- Steganography (zsteg, steghide, stegsolve)

### Binary Exploitation
- Buffer overflow (ret2win, ret2libc)
- Format string
- Heap exploitation
- ROP chain building
