#!/usr/bin/env python3
"""
IDOR Scanner - Object-level and field-level IDOR via parameter swapping
"""
import subprocess, sys, json, re
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def test_idor(base_url, params_to_test=None):
    findings = []
    parsed = urlparse(base_url)
    query_params = parse_qs(parsed.query)
    
    if not params_to_test:
        params_to_test = list(query_params.keys())
    
    for param in params_to_test:
        original_values = query_params.get(param, [])
        for orig_val in original_values:
            # Try various mutations
            mutations = [
                str(int(orig_val) + 1) if orig_val.isdigit() else None,
                str(int(orig_val) - 1) if orig_val.isdigit() and int(orig_val) > 0 else None,
                orig_val.replace(orig_val[-1], chr(ord(orig_val[-1]) + 1)) if len(orig_val) > 0 else None,
                "admin",
                "00000000-0000-0000-0000-000000000000",
            ]
            
            for mutation in mutations:
                if not mutation or mutation == orig_val:
                    continue
                
                new_params = query_params.copy()
                new_params[param] = [mutation]
                new_query = urlencode(new_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    r = subprocess.run(
                        f"curl -sk -o /dev/null -w '%{{http_code}}' '{test_url}'",
                        shell=True, capture_output=True, text=True, timeout=10
                    )
                    if r.stdout.strip() == "200":
                        # Check response size to confirm data difference
                        r2 = subprocess.run(
                            f"curl -sk '{test_url}' 2>/dev/null | wc -c",
                            shell=True, capture_output=True, text=True, timeout=10
                        )
                        orig_size = subprocess.run(
                            f"curl -sk '{base_url}' 2>/dev/null | wc -c",
                            shell=True, capture_output=True, text=True, timeout=10
                        )
                        if r2.stdout.strip() != orig_size.stdout.strip():
                            findings.append({
                                "type": "IDOR",
                                "param": param,
                                "original": orig_val,
                                "mutation": mutation,
                                "url": test_url,
                                "status": "potential"
                            })
                except:
                    pass
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: idor_scanner.py <url>")
        sys.exit(1)
    findings = test_idor(sys.argv[1])
    if findings:
        print(f"Found {len(findings)} potential IDOR(s):")
        for f in findings:
            print(f"  [{f['param']}] {f['original']} -> {f['mutation']}: {f['url']}")
    else:
        print("No obvious IDOR found")
