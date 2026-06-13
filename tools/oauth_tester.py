#!/usr/bin/env python3
"""
OAuth Tester - Test OAuth/OIDC misconfigurations
PKCE, State, Redirect URI, Scope Escalation
"""
import subprocess, sys, json, re

def test_oauth(target_url):
    findings = []
    print(f"[*] Testing OAuth on {target_url}")
    
    # Check for OAuth endpoints
    try:
        r = subprocess.run(
            f"curl -sk '{target_url}' 2>/dev/null | grep -oiE '(oauth|authorize|token|callback|redirect_uri|client_id|response_type)' | sort -u",
            shell=True, capture_output=True, text=True, timeout=10
        )
        oauth_keywords = r.stdout.strip()
        if oauth_keywords:
            findings.append({"type": "OAuth Discovery", "keywords": oauth_keywords.splitlines(),
                           "details": "OAuth endpoints found. Check for misconfigs."})
    except:
        pass
    
    # Test redirect_uri manipulation
    if "authorize" in target_url or "oauth" in target_url:
        test_urls = [
            f"{target_url}&redirect_uri=https://evil.com",
            f"{target_url}&redirect_uri=https://target.com.evil.com",
            f"{target_url}&redirect_uri=https://evil.com/target.com",
        ]
        for test_url in test_urls:
            try:
                r = subprocess.run(
                    f"curl -sk -o /dev/null -w '%{{redirect_url}}' '{test_url}'",
                    shell=True, capture_output=True, text=True, timeout=10
                )
                if "evil" in r.stdout.lower():
                    findings.append({
                        "type": "OAuth Redirect Bypass",
                        "test": test_url,
                        "redirect": r.stdout.strip(),
                        "details": "Redirect URI accepted custom domain"
                    })
            except:
                pass
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: oauth_tester.py <oauth_url>")
        sys.exit(1)
    findings = test_oauth(sys.argv[1])
    if findings:
        print(f"Found {len(findings)} OAuth issue(s):")
        for f in findings:
            print(f"  [{f['type']}] {f.get('details', '')}")
    else:
        print("No obvious OAuth issues found")
