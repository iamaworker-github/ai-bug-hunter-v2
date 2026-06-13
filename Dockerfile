FROM kalilinux/kali-rolling:latest

LABEL description="AI Bug Hunter v2 — All-in-One Docker Image"
LABEL maintainer="iamaworker"

# Prevent interactive install prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin:/root/.local/bin
ENV ZEN_API_KEY=""
ENV TERM=xterm-256color

# Install system deps + security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq \
    python3 python3-pip python3-venv \
    golang-go \
    nmap dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools (recon + scanning)
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
    go install github.com/haccer/subjack@latest && \
    go install github.com/gitleaks/gitleaks/v8@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go install github.com/owasp-amass/amass/v4@latest && \
    go install github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install github.com/bp0lr/gauplus@latest && \
    go install github.com/s0rg/crawley@latest && \
    go install github.com/tomnomnom/anew@master

# Install waymore (BACK-ME-UP dependency)
RUN pip3 install git+https://github.com/xnl-h4ck3r/waymore.git --break-system-packages 2>/dev/null || true

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Copy project
WORKDIR /workspace
COPY . .

# Install Python dependencies
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Install standalone CLI (ai-bug-hunter-v2 command)
RUN bash install.sh --agent standalone

# Make all scripts executable
RUN chmod +x scripts/*.sh tools/*.py tools/*.sh mcp/*/client.py 2>/dev/null || true

# Default: show help and drop into shell
CMD ["bash", "-c", "ai-bug-hunter-v2 --help 2>/dev/null || python3 engine.py --help; echo ''; echo 'AI Bug Hunter v2 ready — run: ai-bug-hunter-v2 recon <target>'; exec bash"]
