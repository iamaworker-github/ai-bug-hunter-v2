#!/usr/bin/env python3
"""Caido MCP Client — fetch proxy history via Caido GraphQL API."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

CAIDO_API_URL = os.environ.get("CAIDO_API_URL", "http://127.0.0.1:8080")
CAIDO_API_KEY = os.environ.get("CAIDO_API_KEY", "")


def _graphql(query, variables=None):
    url = f"{CAIDO_API_URL}/graphql"
    headers = {"Content-Type": "application/json"}
    if CAIDO_API_KEY:
        headers["Authorization"] = f"Bearer {CAIDO_API_KEY}"
    payload = {"query": query, "variables": variables or {}}
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}


def cmd_history(limit=50):
    q = """query GetHistory($limit: Int) {
        proxyHistory(limit: $limit) {
            id url method statusCode mimeType
            request response
        }
    }"""
    result = _graphql(q, {"limit": limit})
    if "error" in result:
        print(json.dumps(result))
        return
    data = result.get("data", {}).get("proxyHistory", result.get("data", {}).get("history", []))
    entries = []
    for item in data:
        entries.append({
            "id": item.get("id", ""),
            "url": item.get("url", ""),
            "method": item.get("method", ""),
            "statusCode": item.get("statusCode", item.get("status", 0)),
            "mimeType": item.get("mimeType", ""),
            "request": str(item.get("request", ""))[:300],
            "response": str(item.get("response", ""))[:300],
        })
    print(json.dumps({"count": len(entries), "entries": entries}, indent=2))


def cmd_scope():
    q = """query GetScope {
        scope { include exclude }
    }"""
    result = _graphql(q)
    print(json.dumps(result.get("data", result), indent=2))


def cmd_scan():
    result = _graphql("""query GetHistory($limit: Int) {
        proxyHistory(limit: $limit) { id url method statusCode request }
    }""", {"limit": 100})
    data = result.get("data", {}).get("proxyHistory", [])
    interesting = []
    for m in data:
        url = m.get("url", "")
        method = m.get("method", "GET")
        status = m.get("statusCode", 0)
        score = 0
        reasons = []
        if status in (200, 201, 302):
            score += 1
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 1
        if any(p in url.lower() for p in ["admin", "api", "internal", "debug", "graphql", "swagger"]):
            score += 2
            reasons.append("sensitive path")
        if score >= 2:
            interesting.append({"url": url, "method": method, "status": status, "score": score, "reasons": reasons})
    interesting.sort(key=lambda x: x["score"], reverse=True)
    print(json.dumps({"count": len(interesting), "findings": interesting[:15]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Caido MCP Client")
    parser.add_argument("action", nargs="?", default="history",
                        choices=["history", "scope", "scan"])
    parser.add_argument("--limit", type=int, default=50, help="History limit")
    args = parser.parse_args()

    if args.action == "history":
        cmd_history(args.limit)
    elif args.action == "scope":
        cmd_scope()
    elif args.action == "scan":
        cmd_scan()


if __name__ == "__main__":
    main()
