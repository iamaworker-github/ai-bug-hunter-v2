#!/usr/bin/env python3
"""
Cookie/Session Manager - Store and manage auth profiles for authenticated hunting.
Supports multiple sessions (normal user, admin user, API tokens) for side-by-side comparison.
"""
import json, os, sys, base64, urllib.parse, subprocess
from pathlib import Path

AUTH_DIR = Path(".private")

def ensure_auth_dir():
    AUTH_DIR.mkdir(exist_ok=True)
    # Add to .gitignore
    gitignore = Path(".gitignore")
    if gitignore.exists():
        content = gitignore.read_text()
        if ".private/" not in content:
            gitignore.write_text(content + "\n.private/\n")

def save_session(target, profile_name, cookies=None, headers=None, bearer=None):
    """Save an auth session for a target."""
    ensure_auth_dir()
    target_dir = AUTH_DIR / target
    target_dir.mkdir(exist_ok=True)
    
    session = {
        "target": target,
        "profile": profile_name,
        "cookies": cookies or {},
        "headers": headers or {},
        "bearer": bearer,
        "created": str(Path(target_dir / f"{profile_name}.json").stat().st_mtime) if (target_dir / f"{profile_name}.json").exists() else None
    }
    
    with open(target_dir / f"{profile_name}.json", "w") as f:
        json.dump(session, f, indent=2)
    
    print(f"[+] Session saved: {target}/{profile_name}")
    return session

def load_session(target, profile_name="default"):
    """Load an auth session."""
    session_file = AUTH_DIR / target / f"{profile_name}.json"
    if not session_file.exists():
        print(f"[-] No session found: {target}/{profile_name}")
        return None
    
    with open(session_file) as f:
        return json.load(f)

def list_sessions(target=None):
    """List all saved sessions."""
    ensure_auth_dir()
    sessions = []
    
    if target:
        target_dir = AUTH_DIR / target
        if target_dir.exists():
            for f in target_dir.glob("*.json"):
                sessions.append(f"{target}/{f.stem}")
    else:
        for d in AUTH_DIR.iterdir():
            if d.is_dir():
                for f in d.glob("*.json"):
                    sessions.append(f"{d.name}/{f.stem}")
    
    return sessions

def curl_with_auth(target_dir, profile_name="default"):
    """Generate curl -H flags from saved session."""
    session = load_session(target_dir, profile_name)
    if not session:
        return ""
    
    args = []
    if session.get("bearer"):
        args.append(f'-H "Authorization: Bearer {session["bearer"]}"')
    if session.get("cookies"):
        cookie_str = "; ".join([f"{k}={v}" for k, v in session["cookies"].items()])
        args.append(f'-H "Cookie: {cookie_str}"')
    if session.get("headers"):
        for k, v in session["headers"].items():
            args.append(f'-H "{k}: {v}"')
    
    return " ".join(args)

def compare_responses(url, session_a="default", session_b="admin"):
    """Compare responses between two sessions (e.g., normal user vs admin)."""
    import subprocess
    
    auth_a = curl_with_auth(url, session_a)
    auth_b = curl_with_auth(url, session_b)
    
    if not auth_a or not auth_b:
        print("[-] Both sessions required for comparison")
        return None
    
    result_a = subprocess.run(
        f"curl -sk {auth_a} '{url}' 2>/dev/null",
        shell=True, capture_output=True, text=True, timeout=15
    )
    
    result_b = subprocess.run(
        f"curl -sk {auth_b} '{url}' 2>/dev/null",
        shell=True, capture_output=True, text=True, timeout=15
    )
    
    diff = {
        "url": url,
        "session_a": session_a,
        "session_b": session_b,
        "status_a": result_a.stdout[:200] if result_a.stdout else "",
        "status_b": result_b.stdout[:200] if result_b.stdout else "",
        "length_a": len(result_a.stdout),
        "length_b": len(result_b.stdout),
        "diff_detected": result_a.stdout != result_b.stdout,
    }
    
    if diff["diff_detected"]:
        print(f"[!] Response difference detected: {url}")
        print(f"    {session_a}: {diff['length_a']} bytes")
        print(f"    {session_b}: {diff['length_b']} bytes")
    else:
        print(f"[-] Same response for both sessions: {url}")
    
    return diff

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  cookie_manager.py save <target> <profile> --cookie 'key=val;key2=val2'")
        print("  cookie_manager.py save <target> <profile> --bearer <token>")
        print("  cookie_manager.py load <target> <profile>")
        print("  cookie_manager.py list [target]")
        print("  cookie_manager.py compare <url> <profile_a> <profile_b>")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    if cmd == "save":
        target = sys.argv[2]
        profile = sys.argv[3]
        cookies = {}
        headers = {}
        bearer = None
        
        for i, arg in enumerate(sys.argv[4:], 4):
            if arg == "--cookie" and i + 1 < len(sys.argv):
                for pair in sys.argv[i+1].split(";"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        cookies[k.strip()] = v.strip()
            elif arg == "--bearer" and i + 1 < len(sys.argv):
                bearer = sys.argv[i+1]
            elif arg == "--header" and i + 1 < len(sys.argv):
                k, v = sys.argv[i+1].split(":", 1)
                headers[k.strip()] = v.strip()
        
        save_session(target, profile, cookies, headers, bearer)
    
    elif cmd == "load":
        target = sys.argv[2]
        profile = sys.argv[3] if len(sys.argv) > 3 else "default"
        session = load_session(target, profile)
        if session:
            print(json.dumps(session, indent=2))
    
    elif cmd == "list":
        target = sys.argv[2] if len(sys.argv) > 2 else None
        sessions = list_sessions(target)
        if sessions:
            print("Saved sessions:")
            for s in sessions:
                print(f"  - {s}")
        else:
            print("No sessions saved")
    
    elif cmd == "compare":
        url = sys.argv[2]
        session_a = sys.argv[3] if len(sys.argv) > 3 else "default"
        session_b = sys.argv[4] if len(sys.argv) > 4 else "admin"
        compare_responses(url, session_a, session_b)
    
    elif cmd == "curl":
        target = sys.argv[2]
        profile = sys.argv[3] if len(sys.argv) > 3 else "default"
        url = sys.argv[4] if len(sys.argv) > 4 else None
        flags = curl_with_auth(target, profile)
        if url:
            print(f"curl -sk {flags} '{url}'")
        else:
            print(flags)

if __name__ == "__main__":
    main()
