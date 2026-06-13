#!/bin/bash
set -e

echo "========================================"
echo "  Installing External Security Tools"
echo "========================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    PKG_MGR="brew"
elif command -v apt &>/dev/null; then
    PKG_MGR="apt"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    echo "[!] Could not detect package manager"
    echo "    Please install Go first: https://go.dev/dl/"
    exit 1
fi

# Install Go if missing
if ! command -v go &>/dev/null; then
    echo "[*] Installing Go..."
    if [ "$PKG_MGR" = "brew" ]; then
        brew install go
    elif [ "$PKG_MGR" = "apt" ]; then
        sudo apt install -y golang-go
    else
        echo "[!] Please install Go manually: https://go.dev/dl/"
        exit 1
    fi
fi

export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Install tools
echo "[*] Installing recon tools..."

install_go_tool() {
    local name=$1
    local pkg=$2
    if ! command -v $name &>/dev/null; then
        echo "  Installing $name..."
        go install $pkg@latest 2>/dev/null || echo "  [!] Failed to install $name"
    else
        echo "  [+] $name already installed"
    fi
}

install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "ffuf" "github.com/ffuf/ffuf/v2"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace"
install_go_tool "subjack" "github.com/haccer/subjack"
install_go_tool "gitleaks" "github.com/gitleaks/gitleaks/v8"

# Install nuclei templates
if command -v nuclei &>/dev/null; then
    echo "[*] Updating nuclei templates..."
    nuclei -update-templates 2>/dev/null || true
fi

# Python tools
if command -v pip3 &>/dev/null; then
    echo "[*] Installing Python tools..."
    pip3 install arjun 2>/dev/null || echo "  [!] arjun install failed"
    pip3 install wafw00f 2>/dev/null || echo "  [!] wafw00f install failed"
fi

echo ""
echo "========================================"
echo "  Tools installed!"
echo "========================================"
echo ""
echo "  Installed: subfinder, httpx, nuclei, dnsx,"
echo "  naabu, katana, ffuf, gau, assetfinder,"
echo "  waybackurls, qsreplace, subjack, gitleaks"
echo ""
echo "  Add API keys (optional but recommended):"
echo "    export CHAOS_API_KEY=\"your-key\""
echo "    # Add to ~/.config/subfinder/config.yaml"
echo "========================================"
