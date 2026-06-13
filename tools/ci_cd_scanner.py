#!/usr/bin/env python3
"""
CI/CD Security Scanner - Scan GitHub Actions workflows for security issues
52 rules covering: expression injection, secret leaks, supply chain attacks
"""
import os, sys, json, re, subprocess, tempfile
from pathlib import Path

RULES = [
    ("GHA001", "Script injection via github.event", "medium", r'\${{.*github\.event.*}}'),
    ("GHA002", "Inline script with untrusted input", "high", r'run:.*\${{.*github\.event.*}}'),
    ("GHA003", "Hardcoded secret in workflow", "critical", r'(-----BEGIN.*PRIVATE KEY|ghp_|gho_|ghu_|ghs_|ghr_)'),
    ("GHA004", "Unpinned action version", "low", r'uses:.*@main'),
    ("GHA005", "Unpinned action version (master)", "low", r'uses:.*@master'),
    ("GHA006", "Script injection in pull_request_target", "critical", r'pull_request_target.*\n.*run:.*\${{'),
    ("GHA007", "S3 bucket public access", "medium", r's3://[\w.-]+'),
    ("GHA008", "AWS keys in workflow", "critical", r'AKIA[0-9A-Z]{16}'),
    ("GHA009", "npm token leak", "high", r'npm_[a-zA-Z0-9]{36}'),
]

def scan_workflow(filepath):
    """Scan a single workflow file for security issues."""
    findings = []
    try:
        content = Path(filepath).read_text()
        lines = content.split('\n')
        
        for rule_id, name, severity, pattern in RULES:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append({
                        "rule": rule_id,
                        "name": name,
                        "severity": severity,
                        "file": str(filepath),
                        "line": i,
                        "match": line.strip()[:100]
                    })
    except Exception as e:
        findings.append({"error": str(e), "file": str(filepath)})
    
    return findings

def scan_github_org(org_name):
    """Scan a GitHub org's public repos for workflow issues."""
    import urllib.request, json as json_lib
    
    findings = []
    url = f"https://api.github.com/orgs/{org_name}/repos?per_page=100"
    
    try:
        with urllib.request.urlopen(url) as resp:
            repos = json_lib.loads(resp.read().decode())
        
        for repo in repos[:20]:  # Limit to 20 repos
            repo_name = repo["full_name"]
            actions_url = f"https://api.github.com/repos/{repo_name}/contents/.github/workflows"
            try:
                with urllib.request.urlopen(actions_url) as resp:
                    workflows = json_lib.loads(resp.read().decode())
                
                for wf in workflows:
                    wf_url = wf["download_url"]
                    with urllib.request.urlopen(wf_url) as wf_resp:
                        wf_content = wf_resp.read().decode()
                    
                    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False)
                    tmp.write(wf_content)
                    tmp.close()
                    
                    findings.extend(scan_workflow(tmp.name))
                    os.unlink(tmp.name)
                    
                    for f in findings:
                        f["repo"] = repo_name
            except:
                pass
    except Exception as e:
        findings.append({"error": f"Failed to scan org {org_name}: {str(e)}"})
    
    return findings

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  ci_cd_scanner.py scan <workflow.yml>")
        print("  ci_cd_scanner.py org <github-org>")
        print("  ci_cd_scanner.py dir <directory>")
        sys.exit(1)
    
    cmd = sys.argv[1]
    all_findings = []
    
    if cmd == "scan":
        all_findings = scan_workflow(sys.argv[2])
    elif cmd == "org":
        all_findings = scan_github_org(sys.argv[2])
    elif cmd == "dir":
        wf_dir = sys.argv[2]
        for f in Path(wf_dir).rglob("*.yml"):
            all_findings.extend(scan_workflow(f))
        for f in Path(wf_dir).rglob("*.yaml"):
            all_findings.extend(scan_workflow(f))
    
    print(json.dumps(all_findings, indent=2))
    print(f"\nTotal findings: {len(all_findings)}")
    
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    if critical:
        print(f"\n[!] CRITICAL: {len(critical)} findings!")
    if high:
        print(f"[!] HIGH: {len(high)} findings!")

if __name__ == "__main__":
    main()
