FROM kalilinux/kali-rolling:latest

LABEL description="OpenCode Bug Bounty v2 — All-in-One Docker Image"
LABEL maintainer="iamaworker"

# Prevent interactive install prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/root/go
ENV PATH=$PATH:$GOPATH/bin:/usr/local/go/bin

# Install system deps + security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git jq \
    python3 python3-pip python3-venv \
    golang-go \
    nmap \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools
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
    go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest && \
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest && \
    go install github.com/d3mondev/puredns/v2@latest

# Update nuclei templates
RUN nuclei -update-templates 2>/dev/null || true

# Install OpenCode CLI
RUN curl -fsSL https://opencode.ai/install | bash

# Copy bug bounty project
WORKDIR /workspace
COPY . .

# Make scripts executable
RUN chmod +x scripts/*.sh tools/*.py tools/*.sh mcp/*/client.py 2>/dev/null || true

# Default: start opencode
CMD ["opencode"]
