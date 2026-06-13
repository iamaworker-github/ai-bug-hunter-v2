# Auth Sessions - Authenticated Hunting

## Why Auth Matters
Most paying bugs (IDOR, BOLA, mass assignment, auth bypass) require authentication. Without cookies/session, you're testing only the public surface.

## Quick Start
```bash
# Save a normal user session
python3 tools/cookie_manager.py save target.tld default --cookie "session=abc123;csrf=xyz789"

# Save an admin session
python3 tools/cookie_manager.py save target.tld admin --cookie "session=def456;csrf=xyz789"

# Compare responses between normal and admin
python3 tools/cookie_manager.py compare https://target.tld/api/users default admin

# Generate curl flags for a session
python3 tools/cookie_manager.py curl target.tld default
# Output: -H "Cookie: session=abc123;csrf=xyz789"
```

## Session Profiles
Each target can have multiple profiles:
- `default` — normal user session
- `admin` — admin/privileged session
- `victim` — secondary test account
- Custom named profiles

## How Tools Use Auth
The cookie_manager.py outputs curl-compatible flags:
```bash
# Direct use
python3 tools/cookie_manager.py curl target.tld default --url https://target.tld/api/users

# In scripts
AUTH=$(python3 tools/cookie_manager.py curl target.tld default)
curl -sk $AUTH 'https://target.tld/api/protected'
```

## Security
- Sessions stored in `.private/target/profile.json`
- `.private/` is in .gitignore — never committed
- Delete profile: `rm -rf .private/target/`
