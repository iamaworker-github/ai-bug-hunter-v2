FROM kalilinux/kali-rolling:latest

LABEL description="AI Bug Hunter v2 — All-in-One Docker Image"
LABEL maintainer="iamaworker"

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin:/root/.local/bin
ENV ZEN_API_KEY=""
ENV TERM=xterm-256color
ENV PIP_REQUIRE_VIRTUALENV=false

# System deps + security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq \
    python3 python3-pip python3-venv \
    golang-go \
    nmap dnsutils ca-certificates \
    ripgrep sqlmap \
    && rm -rf /var/lib/apt/lists/*

# ── Go-based security tools ─────────────────────────────────────────────
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install github.com/tomnomnom/anew@master && \
    go install github.com/haccer/subjack@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/owasp-amass/amass/v4@latest && \
    go install github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install github.com/bp0lr/gauplus@latest && \
    go install github.com/s0rg/crawley@latest && \
    go install github.com/sa7mon/s3scanner@latest && \
    go install github.com/lobuhi/byp4xx@latest && \
    go install github.com/sw33tLie/bbscope@latest && \
    go install github.com/eth0izzle/shhgit@latest && \
    go install github.com/tillson/git-hound@latest && \
    go install github.com/projectdiscovery/interactsh-client@latest && \
    go install github.com/d3mondev/puredns/v2@latest && \
    go install github.com/projectdiscovery/shuffledns@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/michenriksen/aquatone@latest && \
    go install github.com/s0md3v/smap@latest

# ── Python packages (agents, recon, scanning, OSINT, SAST) ──────────────
RUN pip3 install --no-cache-dir --break-system-packages \
    ollama langgraph langchain-ollama \
    arjun theHarvester crosslinked cewler \
    jwt-tool dnsreaper noseyparker \
    wafw00f ghauri scoutsuite maigret \
    pywhat sublert semgrep \
    apkleaks objection 2>/dev/null || true

# ── waymore (BACK-ME-UP dep) ────────────────────────────────────────────
RUN pip3 install git+https://github.com/xnl-h4ck3r/waymore.git --break-system-packages 2>/dev/null || true

# ── sisakulint (GitHub Actions SAST) ─────────────────────────────────────
RUN OS=$(uname -s | tr '[:upper:]' '[:lower:]') && \
    ARCH=$(uname -m) && \
    [ "$ARCH" = "x86_64" ] && ARCH="amd64" || true && \
    [ "$ARCH" = "aarch64" ] && ARCH="arm64" || true && \
    LATEST=$(curl -sI https://github.com/sisaku-security/sisakulint/releases/latest \
      | awk -F'/tag/v' '/[Ll]ocation:/ {print $2}' | tr -d '\r') && \
    LATEST="${LATEST#v}" && \
    curl -fsSL "https://github.com/sisaku-security/sisakulint/releases/download/v${LATEST}/sisakulint_${LATEST}_${OS}_${ARCH}.tar.gz" \
      -o /tmp/sisakulint.tar.gz && \
    tar -xzf /tmp/sisakulint.tar.gz -C /tmp/ && \
    mv /tmp/sisakulint /usr/local/bin/sisakulint && \
    rm -f /tmp/sisakulint.tar.gz

# ── trufflehog ──────────────────────────────────────────────────────────
RUN curl -fsSL https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_$(uname -s)_$(uname -m).tar.gz \
      -o /tmp/trufflehog.tar.gz && \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin/ trufflehog && \
    rm -f /tmp/trufflehog.tar.gz

# ── Git repos (cloudfail, log4j-scan, fuxploider, SecLists) ────────────
RUN mkdir -p /opt/tools && \
    git clone --depth 1 https://github.com/m0rtem/CloudFail.git /opt/tools/cloudfail && \
    git clone --depth 1 https://github.com/fullhunt/log4j-scan.git /opt/tools/log4j-scan && \
    git clone --depth 1 https://github.com/almandin/fuxploider.git /opt/tools/fuxploider && \
    git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/tools/XSStrike && \
    git clone --depth 1 https://github.com/initstring/cloud_enum.git /opt/tools/cloud_enum && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    pip3 install -r /opt/tools/cloud_enum/requirements.txt --break-system-packages 2>/dev/null || true && \
    pip3 install -r /opt/tools/XSStrike/requirements.txt --break-system-packages 2>/dev/null || true && \
    ln -sf /opt/tools/*/*.py /usr/local/bin/ 2>/dev/null || true

# Add /opt/tools to PATH
ENV PATH=$PATH:/opt/tools:/opt/tools/cloudfail:/opt/tools/log4j-scan:/opt/tools/fuxploider:/opt/tools/XSStrike:/opt/tools/cloud_enum

# ── OneRuleToRuleThemAll (hashcat rule) ──────────────────────────────────
RUN mkdir -p /usr/share/hashcat/rules && \
    curl -fsSL https://raw.githubusercontent.com/NotSoSecure/password_cracking_rules/master/OneRuleToRuleThemAll.rule \
      -o /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# ── nuclei templates ────────────────────────────────────────────────────
RUN nuclei -update-templates 2>/dev/null || true

# ── Copy project ────────────────────────────────────────────────────────
WORKDIR /workspace
COPY . .

# Python deps
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Standalone CLI
RUN bash install.sh --agent standalone

# Make scripts executable
RUN chmod +x scripts/*.sh tools/*.py tools/*.sh mcp/*/client.py 2>/dev/null || true

# Default
CMD ["bash", "-c", "ai-bug-hunter-v2 --help 2>/dev/null || python3 engine.py --help; echo ''; echo 'AI Bug Hunter v2 ready — run: ai-bug-hunter-v2 recon <target>'; exec bash"]
