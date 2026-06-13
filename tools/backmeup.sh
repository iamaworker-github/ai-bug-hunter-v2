#!/bin/bash
black='\e[38;5;016m'
bluebg='\e[48;5;038m'${black}
red='\e[31m'
redbg='\e[30;41m'${black}
lightred='\e[91m'
blink='\e[5m'
lightblue='\e[38;5;109m'
green='\e[32m'
greenbg='\e[48;5;038m'${black}
yellow='\e[33m'
logo='\033[0;36m'
end='\e[0m'
description="BACK-ME-UP integrated into OpenCode Bug Bounty v2 - Sensitive Data Leakage detection via 162 extension patterns"
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )"
OUTPUT_BASE="$BASE_DIR/findings"

declare -A tools='(
["curl"]="apt install curl -y -qq"
["git"]="apt install git -y -qq"
["pip3"]="apt install python3-pip -y -qq"
["hakrawler"]="go install github.com/hakluke/hakrawler@latest"
["cariddi"]="go install github.com/edoardottt/cariddi/cmd/cariddi@latest"
["gospider"]="go install github.com/jaeles-project/gospider@latest"
["crawley"]="go install -v github.com/s0rg/crawley/cmd/crawley@latest"
["waymore"]="pip3 install git+https://github.com/xnl-h4ck3r/waymore.git -v --break-system-packages"
["katana"]="go install github.com/projectdiscovery/katana/cmd/katana@latest"
["waybackurls"]="go install github.com/tomnomnom/waybackurls@latest"
["gauplus"]="go install github.com/bp0lr/gauplus@latest"
["gau"]="go install github.com/lc/gau/v2/cmd/gau@latest"
["httpx"]="go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
["anew"]="go install github.com/tomnomnom/anew@master"
)'

function help(){
    printf "\nDescription: ${description}\n"
    printf "\nUsage:\n"
    printf "\t-c/--check\t\t:\tCheck installed prerequisite tools\n"
    printf "\t-i/--install\t\t:\tInstall all prerequisite tools\n"
    printf "\t-d/--domain\t\t:\tTarget domain.tld\n"
    printf "\t-h/--help\t\t:\tHelp\n"
}

function check_install(){
    if go version &> /dev/null; then
        printf " [+] go : `go version | awk '{print $3}'`\n"
    fi
    for i in "${!tools[@]}"; do
        if ! command -v $i &> /dev/null; then
            printf " [-] $i : NOT INSTALLED\n"
        else
            printf " [+] $i : INSTALLED\n"
        fi
    done
}

function install(){
    for i in ${!tools[@]}; do
        if ! command -v $i &> /dev/null; then
            printf "Installing $i...\n"
            ${tools[$i]} &>/dev/null
        fi
    done
}

function regex_template(){
    echo '([^.]+)\.REGEX$'
    echo '([^.]+)\.REGEX\.[0-9]+$'
    echo '([^.]+)\.REGEX[0-9]+$'
    echo '([^.]+)\.REGEX[a-z][A-Z][0-9]+$'
    echo '([^.]+)\.REGEX\.[a-z][A-Z][0-9]+$'
    echo '([^.]+)\.REGEX\?(.*)=(.*)$'
}

function generate_regex() {
    EXT_FILE="$(dirname "$BASE_DIR")/tools/ext.txt"
    if [[ -e "$EXT_FILE" ]]; then
        ext_file=$(cat "$EXT_FILE" | sed "s/\./\\\./g")
        for extension in $ext_file; do
            regex_template | sed "s/REGEX/${extension}/g"
        done
    fi
}

function found(){
    TARGET=$1
    OUTPUT_DIR="$OUTPUT_BASE/$TARGET"
    if [ -d "$OUTPUT_DIR" ] && [ -f "$OUTPUT_DIR/${TARGET}_urls_all.txt" ]; then
        cat "$BASE_DIR/.hold_regex.txt" 2>/dev/null | while IFS= read -r rr || [[ -n ${rr} ]]; do
            grep -ai "${rr}" "$OUTPUT_DIR/${TARGET}_urls_all.txt" 2>/dev/null >> "$OUTPUT_DIR/${TARGET}_possible_leaked_data.txt"
        done
        sort -u -o "$OUTPUT_DIR/${TARGET}_possible_leaked_data.txt" "$OUTPUT_DIR/${TARGET}_possible_leaked_data.txt" 2>/dev/null
        printf "[+] Leaked data scan complete: $(wc -l < "$OUTPUT_DIR/${TARGET}_possible_leaked_data.txt" 2>/dev/null || echo 0) potential findings\n"
        printf "[+] Results saved: findings/$TARGET/\n"
    fi
}

function collect(){
    TARGET=$1
    OUTPUT_DIR="$OUTPUT_BASE/$TARGET"
    mkdir -p "$OUTPUT_DIR"
    
    echo "[*] Collecting URLs for $TARGET..."
    
    # Run each tool if available
    command -v gau &>/dev/null && echo "$TARGET" | gau --subs --threads 50 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_gau.txt" &
    command -v gauplus &>/dev/null && echo "$TARGET" | gauplus -subs -t 50 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_gauplus.txt" &
    command -v waybackurls &>/dev/null && echo "$TARGET" | waybackurls 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_waybackurls.txt" &
    command -v katana &>/dev/null && echo "$TARGET" | katana -passive -c 30 -silent 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_katana.txt" &
    command -v gospider &>/dev/null && gospider -s "https://${TARGET}" --quiet --depth 3 --concurrent 30 --threads 50 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_gospider.txt" &
    command -v hakrawler &>/dev/null && echo "https://${TARGET}" | hakrawler -d 3 -t 5 -subs 2>/dev/null | sort -u > "$OUTPUT_DIR/${TARGET}_hakrawler.txt" &
    
    wait
    
    # Consolidate + filter scope
    SCOPE_FILE="$OUTPUT_DIR/${TARGET}_urls_all.txt"
    cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort -u > "$SCOPE_FILE"
    
    # Filter: only keep URLs containing target domain (in-scope)
    scope_filter "$TARGET" "$SCOPE_FILE" "$OUTPUT_DIR/${TARGET}_urls_scope.txt"
    
    echo "[✓] URL collection complete: $(wc -l < "$OUTPUT_DIR/${TARGET}_urls_scope.txt" 2>/dev/null || echo 0) in-scope URLs"
}

function scope_filter(){
    TARGET="$1"
    INPUT="$2"
    OUTPUT="$3"
    
    # Keep only URLs where domain ends with .target.tld or is target.tld
    # Removes: googleapis.com, cdnjs.cloudflare.com, facebook.com, etc.
    grep -Eo "(https?://[a-zA-Z0-9.-]*\.)?${TARGET}(/[a-zA-Z0-9./?=&_%-]*)?|https?://${TARGET}(:[0-9]+)?(/.*)?$" "$INPUT" 2>/dev/null | sort -u > "$OUTPUT" 2>/dev/null
    
    # Also keep same-domain relative paths if any
    grep -E "^/" "$INPUT" 2>/dev/null >> "$OUTPUT" 2>/dev/null
    
    IN_COUNT=$(wc -l < "$INPUT" 2>/dev/null || echo 0)
    OUT_COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
    REMOVED=$((IN_COUNT - OUT_COUNT))
    
    if [ "$REMOVED" -gt 0 ]; then
        echo "[*] Scope filter: removed $REMOVED out-of-scope URLs (3rd party)"
    fi
    
    # Replace input with filtered version
    cp "$OUTPUT" "$INPUT" 2>/dev/null
}

function run(){
    TARGET="$2"
    
    case $1 in
        '-c'|'--check')
            check_install
            ;;
        '-i'|'--install')
            install
            check_install
            ;;
        '-d'|'--domain')
            if [[ -z "$TARGET" ]]; then
                echo "[-] No target specified"
                help
                exit 1
            fi
            generate_regex > "$BASE_DIR/.hold_regex.txt"
            collect "$TARGET"
            find "$OUTPUT_BASE" -type f -empty -delete 2>/dev/null
            found "$TARGET"
            ;;
        '-h'|'--help'|*)
            help
            ;;
    esac
}

run "$@"
