#!/bin/bash
# auth_hunt.sh - Auth-aware hunting script
# Carries auth cookies through httpx, katana, ffuf, nuclei

TARGET="$1"
PROFILE="${2:-default}"
AUTH_DIR=".private/$TARGET"

if [ ! -f "$AUTH_DIR/$PROFILE.json" ]; then
    echo "[-] No auth session for $TARGET/$PROFILE"
    echo "    Run: python3 tools/cookie_manager.py save $TARGET $PROFILE --cookie '...'"
    exit 1
fi

# Extract cookie from session
COOKIE=$(python3 -c "
import json
with open('$AUTH_DIR/$PROFILE.json') as f:
    s = json.load(f)
if s.get('cookies'):
    print('; '.join([f'{k}={v}' for k,v in s['cookies'].items()]))
elif s.get('bearer'):
    print(f'Bearer {s[\"bearer\"]}')
")

if [ -z "$COOKIE" ]; then
    echo "[-] No auth credentials in session"
    exit 1
fi

echo "[+] Auth loaded for $TARGET/$PROFILE"
echo "[*] Running auth-aware tools..."

# httpx with auth
if command -v httpx &>/dev/null; then
    echo "[*] httpx with auth..."
    httpx -l recon/$TARGET/live.txt -H "Cookie: $COOKIE" -o recon/$TARGET/live_auth.txt -silent 2>/dev/null
fi

# katana with auth
if command -v katana &>/dev/null; then
    echo "[*] katana with auth..."
    katana -list recon/$TARGET/live.txt -H "Cookie: $COOKIE" -o recon/$TARGET/urls_auth.txt -silent 2>/dev/null
fi

# nuclei with auth
if command -v nuclei &>/dev/null; then
    echo "[*] nuclei with auth..."
    nuclei -l recon/$TARGET/live.txt -H "Cookie: $COOKIE" -severity high,critical -o findings/$TARGET/nuclei_auth.txt -silent 2>/dev/null
fi

# ffuf with auth (if endpoints provided)
if [ -f "recon/$TARGET/endpoints.txt" ] && command -v ffuf &>/dev/null; then
    echo "[*] ffuf with auth..."
    ffuf -u "https://$TARGET/FUZZ" -w recon/$TARGET/endpoints.txt -H "Cookie: $COOKIE" -mc 200,403 -o findings/$TARGET/ffuf_auth.json -of json -s 2>/dev/null
fi

echo "[+] Auth-aware scan complete for $TARGET"
