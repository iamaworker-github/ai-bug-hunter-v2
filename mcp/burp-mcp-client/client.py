#!/usr/bin/env python3
"""Burp Suite MCP Client — fetch proxy history, scope, send to repeater."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BURP_API_URL = os.environ.get("BURP_API_URL", "http://127.0.0.1:1337")
BURP_API_KEY = os.environ.get("BURP_API_KEY", "")


def _req(method, path, data=None):
    url = f"{BURP_API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if BURP_API_KEY:
        headers["Authorization"] = f"Bearer {BURP_API_KEY}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()}"}
    except Exception as e:
        return {"error": str(e)}


def cmd_history(limit=50):
    result = _req("GET", f"/burp/api/v2/proxy/history?limit={limit}")
    if "error" in result:
        print(json.dumps(result))
        return
    entries = []
    for item in result.get("messages", result.get("data", [])):
        entries.append({
            "url": item.get("url", ""),
            "method": item.get("method", ""),
            "status": item.get("statusCode", item.get("status", 0)),
            "request": item.get("request", "")[:500],
            "response": item.get("response", "")[:500],
        })
    print(json.dumps({"count": len(entries), "entries": entries}, indent=2))


def cmd_scope():
    result = _req("GET", "/burp/api/v2/target/scope")
    print(json.dumps(result, indent=2))


def cmd_repeater(url, method="GET", headers=None, body=""):
    payload = {
        "url": url,
        "method": method.upper(),
        "headers": headers or {},
        "body": body,
    }
    result = _req("POST", "/burp/api/v2/repeater", payload)
    print(json.dumps(result, indent=2))


def cmd_scan():
    hist = _req("GET", "/burp/api/v2/proxy/history?limit=100")
    if "error" in hist:
        print(json.dumps({"error": "Cannot fetch history"}, indent=2))
        return
    messages = hist.get("messages", hist.get("data", []))
    interesting = []
    for m in messages:
        url = m.get("url", "")
        method = m.get("method", "GET")
        status = m.get("statusCode", m.get("status", 0))
        params = m.get("params", {})
        score = 0
        reasons = []
        if status in (200, 201, 302):
            score += 1
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            score += 1
        if any(p in url.lower() for p in ["admin", "api", "internal", "debug", "test", "v1", "v2", "graphql"]):
            score += 2
            reasons.append("sensitive path")
        if params and any(v in str(params).lower() for v in ["id", "user", "token", "file", "url", "redirect"]):
            score += 2
            reasons.append("interesting params")
        if score >= 2:
            interesting.append({"url": url, "method": method, "status": status, "score": score, "reasons": reasons})
    interesting.sort(key=lambda x: x["score"], reverse=True)
    print(json.dumps({"count": len(interesting), "findings": interesting[:15]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Burp Suite MCP Client")
    parser.add_argument("action", nargs="?", default="history",
                        choices=["history", "scope", "repeater", "scan"])
    parser.add_argument("--url", help="URL for repeater")
    parser.add_argument("--method", default="GET", help="HTTP method for repeater")
    parser.add_argument("--limit", type=int, default=50, help="History limit")
    args = parser.parse_args()

    if args.action == "history":
        cmd_history(args.limit)
    elif args.action == "scope":
        cmd_scope()
    elif args.action == "repeater":
        if not args.url:
            print(json.dumps({"error": "--url required for repeater"}))
            sys.exit(1)
        cmd_repeater(args.url, args.method)
    elif args.action == "scan":
        cmd_scan()


if __name__ == "__main__":
    main()
