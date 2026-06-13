#!/usr/bin/env python3
"""
OpenCode Bug Bounty - Smart Contract Auditor
Check Solidity contracts for 10 DeFi bug classes
"""
import sys, re
from pathlib import Path

REENTRANCY_PATTERNS = [
    r"\.call\{value:",
    r"\.transfer\(",
    r"\.send\(",
]

ACCESS_CONTROL_PATTERNS = [
    r"function\s+\w+\s*\([^)]*\)\s*(public|external)\s",
]

CHECKS_EFFECTS_PATTERN = r"(\.call|\.transfer|\.send).*[\s\S]{0,100}(balance|withdraw|deduct|sub)"

def audit_contract(filepath):
    findings = []
    code = Path(filepath).read_text()
    name = Path(filepath).name
    
    print(f"[*] Auditing {name}...")
    
    # 1. Reentrancy
    for pattern in REENTRANCY_PATTERNS:
        matches = list(re.finditer(pattern, code))
        for m in matches:
            pos = code.rfind('\n', 0, m.start()) + 1
            line_no = code[:m.start()].count('\n') + 1
            # Check if state change happens after external call
            after_call = code[m.end():m.end()+500]
            if re.search(r'(=|-=|\\+=)', after_call, re.I):
                findings.append({
                    "class": "Reentrancy",
                    "line": line_no,
                    "pattern": m.group(),
                    "severity": "High",
                    "detail": "External call before state change - check for reentrancy"
                })
    
    # 2. Access Control
    for match in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*(public|external)", code):
        func_name = match.group(1)
        pos = match.start()
        before_func = code[max(0, pos-200):pos]
        has_modifier = bool(re.search(r'(onlyOwner|onlyRole|hasRole|require\(.*msg\.sender)', before_func))
        if not has_modifier and func_name not in ['constructor', 'receive', 'fallback']:
            line_no = code[:pos].count('\n') + 1
            findings.append({
                "class": "Access Control",
                "line": line_no,
                "function": func_name,
                "severity": "Medium",
                "detail": f"Function '{func_name}' missing access control modifier"
            })
    
    # 3. Unchecked Math
    if not re.search(r"^\s*pragma\s+solidity\s+\^?0\.8", code, re.M):
        for match in re.finditer(r"(\w+)\s*(\+|-|\*)\s*=", code):
            line_no = code[:match.start()].count('\n') + 1
            findings.append({
                "class": "Math/Overflow",
                "line": line_no,
                "pattern": match.group(),
                "severity": "Medium" if re.search(r"0\.8", code) else "High",
                "detail": "Unchecked arithmetic operation"
            })
    
    # Summary
    print(f"\n[+] Audit complete. Found {len(findings)} potential issues:")
    for f in findings:
        print(f"  [{f['severity']}] {f['class']} (line {f['line']}): {f['detail']}")
    
    return findings

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: smart_contract_auditor.py <contract.sol>")
        sys.exit(1)
    audit_contract(sys.argv[1])
