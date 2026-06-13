#!/usr/bin/env python3
"""
OpenCode Bug Bounty - 4-Gate Validator
Scope, Impact, Duplicate, CVSS
"""
import sys, json
from pathlib import Path

def validate_finding(finding):
    print("=" * 50)
    print("VALIDATION GATES")
    print("=" * 50)

    # Gate 0: Scope
    print("\n[Gate 0] SCOPE CHECK")
    in_scope = input("  Is this in scope? (y/n): ").lower().startswith('y')
    if not in_scope:
        print("  VERDICT: KILL (out of scope)")
        return "KILL"

    # Gate 1: Reality
    print("\n[Gate 1] REALITY CHECK")
    real_bug = input("  Can an attacker do this RIGHT NOW? (y/n): ").lower().startswith('y')
    if not real_bug:
        print("  VERDICT: KILL (not a real bug)")
        return "KILL"

    # Gate 2: Impact
    print("\n[Gate 2] IMPACT CHECK")
    impact = input("  Rate impact (critical/high/medium/low/info): ").lower()
    if impact in ["info", "low"]:
        chain = input("  Can this be chained with another bug? (y/n): ").lower().startswith('y')
        if chain:
            print("  VERDICT: CHAIN REQUIRED")
            return "CHAIN REQUIRED"
        else:
            print("  VERDICT: KILL (low impact, no chain)")
            return "KILL"
    if impact == "medium":
        print("  VERDICT: DOWNGRADE or proceed")
    
    # Gate 3: Reproducibility
    print("\n[Gate 3] REPRODUCIBILITY")
    reproducible = input("  Can you reproduce this consistently? (y/n): ").lower().startswith('y')
    if not reproducible:
        print("  VERDICT: KILL (not reproducible)")
        return "KILL"

    # CVSS
    print("\n[CVSS CALCULATION]")
    print("  Network Vulnerability Scoring System 3.1")
    av = input("  Attack Vector (N/A/L/P): ").upper() or "N"
    ac = input("  Attack Complexity (L/H): ").upper() or "L"
    pr = input("  Privileges Required (N/L/H): ").upper() or "N"
    ui = input("  User Interaction (N/R): ").upper() or "N"
    s = input("  Scope (U/C): ").upper() or "U"
    c = input("  Confidentiality (N/L/H): ").upper() or "H"
    i = input("  Integrity (N/L/H): ").upper() or "H"
    a = input("  Availability (N/L/H): ").upper() or "H"

    vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
    print(f"\n  Vector: {vector}")

    print("\n  VERDICT: PASS - proceed to report writing")
    return "PASS"

def validate_finding_from_file(filepath):
    print(f"[*] Reading finding from {filepath}")
    with open(filepath) as f:
        finding = f.read()
    print(finding[:500])
    return validate_finding({"content": finding})

if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = validate_finding_from_file(sys.argv[1])
    else:
        print("Interactive Validation Mode")
        finding_text = input("Paste finding description (or press Enter to read from file): ")
        if not finding_text:
            result = validate_finding({})
        else:
            result = validate_finding({"content": finding_text})
    print(f"\nFinal Verdict: {result}")
