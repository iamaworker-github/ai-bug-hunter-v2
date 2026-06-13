#!/usr/bin/env python3
"""
OpenCode Bug Bounty - Report Generator
HackerOne / Bugcrowd / Intigriti markdown reports
"""
import sys, json, datetime
from pathlib import Path

REPORTS_DIR = Path("reports")

TEMPLATES = {
    "hackerone": """**Summary:**
{summary}

**Impact:**
{impact}

**Steps to Reproduce:**
{steps}

**Proof of Concept:**
```
Request:
{request}

Response:
{response}
```

**Suggested CVSS:** {cvss}

**Suggested Fix:**
{fix}
""",
    "bugcrowd": """# {title}

## Vulnerability Description
{description}

## Proof of Concept
### Steps to Replicate
{steps}

### Request/Response
```
{request}

{response}
```

## Business Impact
{impact}

## Remediation Advice
{fix}
""",
    "intigriti": """**Title:** {title}

**Description:**
{description}

**Impact:**
{impact}

**Steps to Reproduce:**
{steps}

**Proof of Concept:**
```
{request}

{response}
```

**CVSS Score:**
{cvss}
""",
    "immunefi": """**Title:** {title}

**Severity:** {severity}

**Summary:**
{summary}

**Vulnerability Details:**
{description}

**Impact:**
{impact}

**Proof of Concept:**
```
{poc}
```

**Recommended Fix:**
{fix}
"""
}

def generate_report(target, finding_type, platform="hackerone"):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now().strftime("%Y-%m-%d")
    filename = REPORTS_DIR / f"{target}-{finding_type}-{now}.md"

    print(f"[*] Report generator for {target}")
    print(f"[*] Platform: {platform}")
    print("Enter report details (Ctrl+D to finish multiline):")

    title = input("  Title: ") or f"{finding_type} in {target}"
    summary = input("  Summary (one-liner): ")
    impact = input("  Impact statement: ")
    
    print("  Steps to reproduce (end with empty line):")
    steps_lines = []
    while True:
        line = input("    ")
        if not line:
            break
        steps_lines.append(line)
    steps = "\n".join(f"  {i+1}. {l}" for i, l in enumerate(steps_lines))

    print("  Request (end with empty line):")
    req_lines = []
    while True:
        line = input("    ")
        if not line:
            break
        req_lines.append(line)
    request_text = "\n".join(req_lines)

    print("  Response (end with empty line):")
    resp_lines = []
    while True:
        line = input("    ")
        if not line:
            break
        resp_lines.append(line)
    response_text = "\n".join(resp_lines)

    cvss = input("  CVSS vector: ")
    fix = input("  Suggested fix: ")

    data = {
        "title": title,
        "summary": summary,
        "impact": impact,
        "steps": steps,
        "request": request_text,
        "response": response_text,
        "cvss": cvss,
        "fix": fix,
        "description": summary,
        "severity": "High",
        "poc": f"Request:\n{request_text}\n\nResponse:\n{response_text}",
    }

    template = TEMPLATES.get(platform, TEMPLATES["hackerone"])
    report = template.format(**data)

    filename.write_text(report)
    print(f"\n[+] Report saved to {filename}")
    return filename

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Target: ")
    finding_type = sys.argv[2] if len(sys.argv) > 2 else input("Finding type: ")
    platform = sys.argv[3] if len(sys.argv) > 3 else input("Platform (hackerone/bugcrowd/intigriti/immunefi): ") or "hackerone"
    generate_report(target, finding_type, platform)
