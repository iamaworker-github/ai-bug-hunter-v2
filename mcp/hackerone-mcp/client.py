#!/usr/bin/env python3
"""HackerOne MCP Client — program stats, disclosed reports search, scope check."""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

H1_USERNAME = os.environ.get("HACKERONE_USERNAME", "")
H1_TOKEN = os.environ.get("HACKERONE_API_TOKEN", "")
REPORT_DUMP = "/tmp/bb-reports/complete_dump.txt"
GRAPHQL_URL = "https://api.hackerone.com/graphql"


def _graphql(query, variables=None):
    if not H1_USERNAME or not H1_TOKEN:
        return {"error": "Set HACKERONE_USERNAME and HACKERONE_API_TOKEN env vars"}
    payload = {"query": query, "variables": variables or {}}
    auth = f"{H1_USERNAME}:{H1_TOKEN}"
    b64 = base64.b64encode(auth.encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64}",
    }
    req = urllib.request.Request(GRAPHQL_URL, data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}


def cmd_program(name):
    q = """query Program($handle: String!) {
        program(handle: $handle) {
            name handle
            stats { total_paid bounty_average response_time }
            scope { in_scope out_of_scope }
        }
    }"""
    result = _graphql(q, {"handle": name})
    if "error" in result:
        print(json.dumps(result))
        return
    print(json.dumps(result.get("data", result), indent=2))


def cmd_search(query, limit=10):
    results = []
    if os.path.exists(REPORT_DUMP):
        try:
            out = subprocess.run(
                ["rg", "-i", query, REPORT_DUMP, "-m", str(limit)],
                capture_output=True, text=True, timeout=10
            )
            for line in out.stdout.strip().split("\n")[:limit]:
                if line.strip():
                    results.append(line.strip()[:300])
        except Exception:
            pass
    # Also try H1 API
    api_q = """query SearchReports($query: String!, $limit: Int!) {
        reports(query: $query, limit: $limit) { edges { node { title severity url } } }
    }"""
    api_result = _graphql(api_q, {"query": query, "limit": limit})
    api_reports = []
    if "error" not in api_result:
        for edge in api_result.get("data", {}).get("reports", {}).get("edges", []):
            n = edge.get("node", {})
            api_reports.append({"title": n.get("title", ""), "severity": n.get("severity", ""), "url": n.get("url", "")})
    print(json.dumps({
        "local_dump_matches": len(results),
        "local_samples": results[:5],
        "api_results": api_reports,
    }, indent=2))


def cmd_scope_check(domain):
    results = {"domain": domain, "in_programs": []}
    if os.path.exists(REPORT_DUMP):
        try:
            out = subprocess.run(
                ["rg", "-i", re.escape(domain), REPORT_DUMP, "-m", "5"],
                capture_output=True, text=True, timeout=10
            )
            if out.stdout.strip():
                results["found_in_reports"] = out.stdout.strip()[:500]
        except Exception:
            pass
    print(json.dumps(results, indent=2))


def cmd_similar(finding_text, limit=5):
    if not os.path.exists(REPORT_DUMP):
        print(json.dumps({"error": "Report dump not found at " + REPORT_DUMP}))
        return
    terms = finding_text.strip().split()
    results = []
    try:
        for term in terms[:3]:
            out = subprocess.run(
                ["rg", "-i", term, REPORT_DUMP, "-m", str(limit)],
                capture_output=True, text=True, timeout=10
            )
            for line in out.stdout.strip().split("\n")[:limit]:
                if line.strip():
                    results.append(line.strip()[:300])
    except Exception:
        pass
    print(json.dumps({"query": finding_text, "similar_reports": results[:10], "count": len(results[:10])}, indent=2))


def main():
    import base64  # noqa: needed in _graphql
    parser = argparse.ArgumentParser(description="HackerOne MCP Client")
    parser.add_argument("action", choices=["program", "search", "scope", "similar"])
    parser.add_argument("query", nargs="?", help="Program name or search term")
    parser.add_argument("--limit", type=int, default=10, help="Result limit")
    args = parser.parse_args()

    if args.action == "program":
        if not args.query:
            print(json.dumps({"error": "Program name required"}))
            sys.exit(1)
        cmd_program(args.query)
    elif args.action == "search":
        if not args.query:
            print(json.dumps({"error": "Search query required"}))
            sys.exit(1)
        cmd_search(args.query, args.limit)
    elif args.action == "scope":
        if not args.query:
            print(json.dumps({"error": "Domain required"}))
            sys.exit(1)
        cmd_scope_check(args.query)
    elif args.action == "similar":
        if not args.query:
            print(json.dumps({"error": "Finding text required"}))
            sys.exit(1)
        cmd_similar(args.query, args.limit)


if __name__ == "__main__":
    main()
