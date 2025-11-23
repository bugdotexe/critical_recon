#!/bin/bash

RED="\e[31m"
RESET="\e[0m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

BANNER() {
echo -e "[+] World \e[31mOFF\e[0m,Terminal \e[32mON \e[0m"
echo -e " █████                             █████           █████"
echo -e "░░███                             ░░███           ░░███ "
echo -e " ░███████  █████ ████  ███████  ███████   ██████  ███████"
echo -e " ░███░░███░░███ ░███  ███░░███ ███░░███  ███░░███░░░███░ "
echo -e " ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███  "
echo -e " ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███  "
echo -e " ████████  ░░████████░░███████░░████████░░██████   ░░█████ "
echo -e "░░░░░░░░    ░░░░░░░░  ░░░░░███ ░░░░░░░░  ░░░░░░     ░░░░░  "
echo -e "[+] Patient Predator Strategy - Make \e[31mCritical\e[0m great again"
}

# Configuration
CONFIG() {
    DOMAIN=$1
    OUTPUT=$2
    
    # Ensure Organized Directory Structure
    mkdir -p "$OUTPUT"/{passive,active,live,scanning,archives,js,endpoints,cloud,intel,reports}
    
    # Tool configurations
    HAKTRAILS_COOKIE="/root/cookie.txt"
    SUBDOMAIN_WORDLIST="/home/bugdotexe/findsomeluck/recon/wordlists/subdomains-top1million-5000.txt"
    GITHUB_TOKEN=${GITHUB_TOKEN:-""}
    SHODAN_API=${SHODAN_API:-""}
    VIRUSTOTAL_API=${VIRUSTOTAL_API:-""}
    
    # Strategy configurations
    MAX_DEPTH=2
    PARALLEL_JOBS=10
    TIMEOUT=30
}

# Phase 1: Intelligence Gathering
INTELLIGENCE_GATHERING() {
    notice "Starting Patient Predator Intelligence Gathering for: $DOMAIN"
    
    # ASN and IP Space Analysis
    notice "Performing ASN and IP space analysis"
    amass intel -whois -d "$DOMAIN" -o "$OUTPUT/intel/asn_info.txt" 2>/dev/null || true
    curl -s "https://api.bgpview.io/search?query_term=$DOMAIN" | jq -r '.data.ipv4_prefixes[]?.prefix' 2>/dev/null | anew "$OUTPUT/intel/ip_ranges.txt" >/dev/null
    
    # Certificate Transparency Deep Dive
    notice "Deep certificate transparency analysis"
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' 2>/dev/null | \
        grep -E "([a-zA-Z0-9]+\.)?$DOMAIN" | sort -u | anew "$OUTPUT/passive/crt_deep.sub" >/dev/null
    
    # Cloud Infrastructure Mapping
    notice "Cloud infrastructure enumeration"
    echo "$DOMAIN" | while read domain; do
        echo "aws.amazon.com" | grep -i "$domain" && echo "Potential AWS infrastructure" | anew "$OUTPUT/cloud/cloud_providers.txt" >/dev/null
        echo "azure.com" | grep -i "$domain" && echo "Potential Azure infrastructure" | anew "$OUTPUT/cloud/cloud_providers.txt" >/dev/null
        echo "googlecloud.com" | grep -i "$domain" && echo "Potential GCP infrastructure" | anew "$OUTPUT/cloud/cloud_providers.txt" >/dev/null
    done
    
    # GitHub Reconnaissance
    if [[ -n "$GITHUB_TOKEN" ]]; then
        notice "GitHub organization and repository reconnaissance"
        github-subdomains -t "$GITHUB_TOKEN" -d "$DOMAIN" | anew "$OUTPUT/intel/github_recon.txt" >/dev/null
    fi
    
    success "Intelligence gathering completed"
}

# Enhanced Passive Enumeration with Error Handling
PASSIVE_ENUM() {
    notice "Starting enhanced passive subdomain enumeration"

    # HAKTRAILS
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} haktrailsfree "
    if [ -f "$HAKTRAILS_COOKIE" ]; then
        echo "$DOMAIN" | haktrailsfree -c "$HAKTRAILS_COOKIE" --silent | anew "$OUTPUT/passive/haktrails.sub"
        echo -e "${GREEN}[+] PASSIVE@hakktrails~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/haktrails.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    fi
    echo -e

    # CERT
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} cert "
    sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
    openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' \
    -connect "$DOMAIN:443" ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | anew "$OUTPUT/passive/cert.sub"
    echo -e "${GREEN}[+] PASSIVE@cert~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/cert.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # CRT.SH
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} crt.sh "
    curl -s "https://crt.sh?q=$DOMAIN&output=json" | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | sort -u | anew "$OUTPUT/passive/crtsh.sub"
    echo -e "${GREEN}[+] PASSIVE@crt.sh~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/crtsh.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # VIRUSTOTAL
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} virustotal "
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=33fa7261693b5212e8018303d976050d12558802f71a6e796e3530f8c933bc2c&domain=$DOMAIN" | jq -r '.domain_siblings[]' | sort -u | anew "$OUTPUT/passive/virustotal.sub"
    echo -e "${GREEN}[+] PASSIVE@virustotal~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/virustotal.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # WEBARCHIVE
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} web.archive "
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | anew "$OUTPUT/passive/webarchive.sub"
    echo -e "${GREEN}[+] PASSIVE@web.archive~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/webarchive.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # SUBFINDER
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} subfinder "
    subfinder -silent -all -recursive -d "$DOMAIN" -o "$OUTPUT/passive/subfinder.sub"
    echo -e "${GREEN}[+] PASSIVE@subfinder~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/subfinder.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # ASSETFINDER
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} assetfinder "
    assetfinder -subs-only "$DOMAIN" | anew "$OUTPUT/passive/assetfinder.sub"
    echo -e "${GREEN}[+] PASSIVE@assetfinder~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/assetfinder.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # CHAOS
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} chaos "
    chaos -silent -key 7e42cd92-b317-420b-8eac-dbd5eb1c5516 -d "$DOMAIN" | anew "$OUTPUT/passive/chaos.sub"
    echo -e "${GREEN}[+] PASSIVE@chaos~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/chaos.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # SHOSUBGO
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} shosubgo "
    shosubgo -s PiILLI6oJS0U5nCHRXwNHcmMMHTWNPqU1337 -d "$DOMAIN" -o "$OUTPUT/passive/shosubgo.sub"
    echo -e "${GREEN}[+] PASSIVE@shosubgo~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/shosubgo.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # GITLAB
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} gitlab "
    gitlab-subdomains -t glpat-DaFJSWdR2_mjUStZjmUz-W86MQp1Omdoa3d1Cw.01.12168p8t31337 -d "$DOMAIN" | anew "$OUTPUT/passive/gitlab.sub"
    echo -e "${GREEN}[+] PASSIVE@gitlab~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/gitlab.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # GITHUB
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} github "
    if [ ! -z "${GITHUB_TOKEN:-}" ]; then
        github-subdomains -t "$GITHUB_TOKEN" -d "$DOMAIN" -o "$OUTPUT/passive/github.sub"
        echo -e "${GREEN}[+] PASSIVE@github~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/github.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    fi
    echo -e

    # AMASS
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} amass "
    amass enum -passive -d "$DOMAIN" -timeout 12 -o "$OUTPUT/passive/amass.tmp"
    cat "$OUTPUT/passive/amass.tmp" 2>/dev/null | anew "$OUTPUT/passive/amass.sub"
    rm -f "$OUTPUT/passive/amass.tmp"
    echo -e "${GREEN}[+] PASSIVE@amass~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/amass.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # FINDOMAIN
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} findomain "
    findomain -t "$DOMAIN" -q | anew "$OUTPUT/passive/findomain.sub"
    echo -e "${GREEN}[+] PASSIVE@findomain~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/findomain.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # BBOT
    echo -e "${GREEN}[+] Passive Subdomain Enumeration~#${RESET} bbot "
    mkdir -p "$OUTPUT/bbot"
    bbot -t "$DOMAIN" -p subdomain-enum -o "$OUTPUT/bbot" -om subdomains
    find "$OUTPUT/bbot" -name "subdomains.txt" -exec cat {} + | anew "$OUTPUT/passive/bbot.sub"
    echo -e "${GREEN}[+] PASSIVE@bbot~# Found${RESET} ${RED}$(cat "$OUTPUT/passive/bbot.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # Additional Passive Sources
    notice "Gathering additional passive intelligence"
    
    # Certificate Transparency (ctfr)
    if command -v ctfr &> /dev/null; then
        ctfr -d "$DOMAIN" -o "$OUTPUT/passive/ctfr.sub" 2>/dev/null
    fi
    
    # Wayback Machine with deeper analysis
    waybackurls "$DOMAIN" | grep -E "([a-zA-Z0-9]+\.)?$DOMAIN" | cut -d'/' -f3 | sort -u | anew "$OUTPUT/passive/wayback_deep.sub" >/dev/null
}

# Enhanced Active Enumeration with Permutation
ACTIVE_ENUM() {
    notice "Starting intelligent active subdomain enumeration"
    
    # Merge all passive results for active testing
    cat "$OUTPUT"/passive/*.sub 2>/dev/null | sort -u > "$OUTPUT/all_passive_subs.txt"
    
    local passive_count=$(wc -l < "$OUTPUT/all_passive_subs.txt" 2>/dev/null || echo 0)
    notice "Testing ${CYAN}$passive_count${RESET} passive subdomains with active methods"

    #ALTERX
    echo -e "${GREEN}[+] Active Subdomain Enumeration~#${RESET} alterx "
    cat "$OUTPUT/all_passive_subs.txt" | alterx -silent | anew "$OUTPUT/active/alterx.subs"
    echo -e "${GREEN}[+] ACTIVE@alterx~# Found${RESET} ${RED}$(cat "$OUTPUT/active/alterx.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    
    # GOBUSTER
    echo -e "${GREEN}[+] Active Subdomain Enumeration~#${RESET} gobuster "
    gobuster dns --domain "$DOMAIN" --wordlist "$SUBDOMAIN_WORDLIST" -q --nc --wildcard | awk '{print $1}' | anew "$OUTPUT/active/gobuster.sub"
    echo -e "${GREEN}[+] ACTIVE@gobuster~# Found${RESET} ${RED}$(cat "$OUTPUT/active/gobuster.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # FFUF
    echo -e "${GREEN}[+] Virtual host fuzzing~#${RESET} ffuf "
    ffuf -c -r -u "https://$DOMAIN/" -H "Host: FUZZ.${DOMAIN}" -w "$SUBDOMAIN_WORDLIST" -o "$OUTPUT/active/ffuf.json" -s
    cat "$OUTPUT/active/ffuf.json" 2>/dev/null | jq -r '.results[].host' | anew "$OUTPUT/active/ffuf.sub"
    echo -e "${GREEN}[+] ACTIVE@ffuf~# Found${RESET} ${RED}$(cat "$OUTPUT/active/ffuf.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # MKSUB
    echo -e "${GREEN}[+] Active Subdomain Enumeration~#${RESET} mksub "
    mksub -d "$DOMAIN" -l 2 -w "$SUBDOMAIN_WORDLIST" -r "^[a-zA-Z0-9\.-_]+$" | dnsx -silent | anew "$OUTPUT/active/mksub.sub"
    echo -e "${GREEN}[+] ACTIVE@mksub~# Found${RESET} ${RED}$(cat "$OUTPUT/active/mksub.sub" 2>/dev/null | wc -l)${RESET} ${GREEN}subdomains${RESET}"
    echo -e

    # DNS Brute Force with multiple techniques
    notice "Performing DNS brute force with permutation"
    
    # AltDNS permutation if available
    if command -v altdns &> /dev/null && [[ -f "$OUTPUT/all_passive_subs.txt" ]]; then
        altdns -i "$OUTPUT/all_passive_subs.txt" -o "$OUTPUT/active/permutations.txt" -w /usr/share/wordlists/altdns_words.txt 2>/dev/null
        cat "$OUTPUT/active/permutations.txt" 2>/dev/null | dnsx -silent | anew "$OUTPUT/active/permutations_resolved.sub"
    fi
    
    # DNSx for bulk resolution
    if [[ -f "$OUTPUT/all_passive_subs.txt" ]]; then
        cat "$OUTPUT/all_passive_subs.txt" | dnsx -silent -retry 2 | anew "$OUTPUT/active/dnsx_resolved.sub"
    fi
}

# Technology Stack Fingerprinting
TECH_STACK_ANALYSIS() {
    notice "Technology stack fingerprinting"
    
    if [[ -f "$OUTPUT/live/httpx_final.probe" ]]; then
        # WhatWeb for detailed technology analysis
        if command -v whatweb &> /dev/null; then
            whatweb -i "$OUTPUT/live/httpx_final.probe" --log-verbose="$OUTPUT/scanning/whatweb.txt" 2>/dev/null &
        fi
        
        # WebAnalyze for technology identification
        if command -v webanalyze &> /dev/null; then
            webanalyze -hosts "$OUTPUT/live/httpx_final.probe" -crawl 1 -output "$OUTPUT/scanning/webanalyze.json" 2>/dev/null &
        fi
        
        wait
        success "Technology stack analysis completed"
    fi
}

# JavaScript Intelligence Gathering
JS_INTELLIGENCE() {
    notice "JavaScript file analysis and intelligence gathering"
    
    # Extract JavaScript files from live hosts
    if [[ -f "$OUTPUT/live/httpx_final.probe" ]]; then
        cat "$OUTPUT/live/httpx_final.probe" | grep -E "\.js($|\?)" | anew "$OUTPUT/js/js_urls.txt" >/dev/null
        
        # Download and analyze JavaScript files
        if [[ -f "$OUTPUT/js/js_urls.txt" ]]; then
            mkdir -p "$OUTPUT/js/raw"
            
            # Extract endpoints and secrets from JS files
            cat "$OUTPUT/js/js_urls.txt" | while read url; do
                filename=$(echo "$url" | sed 's|https\?://||' | tr '/' '_')
                curl -s "$url" -o "$OUTPUT/js/raw/${filename}.js" 2>/dev/null
            done
            
            # Extract patterns from JS files
            find "$OUTPUT/js/raw" -name "*.js" -exec grep -E "(api|endpoint|url|token|key|secret|password)" {} \; 2>/dev/null | \
                anew "$OUTPUT/js/secrets_patterns.txt" >/dev/null
        fi
    fi
}

# Enhanced Live Host Detection with Intelligent Filtering
LIVE_DETECTION() {
    notice "Enhanced live host detection with intelligent filtering"
    
    # Merge all discovered subdomains
    cat "$OUTPUT"/passive/*.sub "$OUTPUT"/active/*.sub 2>/dev/null | sort -u > "$OUTPUT/all_discovered_subs.txt"
    
    local total_subs=$(wc -l < "$OUTPUT/all_discovered_subs.txt" 2>/dev/null || echo 0)
    notice "Testing ${CYAN}$total_subs${RESET} discovered subdomains for live hosts"
    
    echo -e "${GREEN}[+] Checking live subdomains~#${RESET} httpx "
    
    # First pass: Quick HTTP/S check
    cat "$OUTPUT/all_discovered_subs.txt" | httpx -silent -random-agent -timeout 5 -threads 50 \
        -ports 80,443,8080,8443,3000,5000,8000,8008,8088,8888,10443 \
        -o "$OUTPUT/live/httpx_quick.probe" 2>/dev/null
    
    # Second pass: Detailed analysis on live hosts
    if [[ -f "$OUTPUT/live/httpx_quick.probe" ]]; then
        cat "$OUTPUT/live/httpx_quick.probe" | httpx -silent -random-agent -timeout 10 \
            -status-code -content-length -title -tech-detect -cdn \
            -server -method -follow-redirects -cname -asn \
            -json -o "$OUTPUT/live/httpx_detailed.json" 2>/dev/null
        
        # Extract URLs from JSON for further processing
        cat "$OUTPUT/live/httpx_detailed.json" | jq -r '.url' 2>/dev/null | anew "$OUTPUT/live/httpx_final.probe" >/dev/null
        
        local live_count=$(wc -l < "$OUTPUT/live/httpx_final.probe" 2>/dev/null || echo 0)
        success "Found ${GREEN}$live_count${RESET} live hosts out of $total_subs discovered subdomains"
        
        # Generate live hosts summary
        cat "$OUTPUT/live/httpx_detailed.json" | jq -r '"\(.url) [\(.status_code)] [\(.tech)]"' 2>/dev/null | \
            sort -u > "$OUTPUT/live/hosts_summary.txt"
            
        # Original live detection with headers (keeping your original functionality)
        cat "$OUTPUT/all_discovered_subs.txt" | httpx -ports 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888,9000 \
        -silent -random-agent -sc -td -ct -cl -server \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "Base-Url: 127.0.0.1" \
        -H "Client-IP: 127.0.0.1" \
        -H "Http-Url: 127.0.0.1" \
        -H "Proxy-Host: 127.0.0.1" \
        -H "Proxy-Url: 127.0.0.1" \
        -H "Real-Ip: 127.0.0.1" \
        -H "Redirect: 127.0.0.1" \
        -H "Referer: 127.0.0.1" \
        -H "Referrer: 127.0.0.1" \
        -H "Refferer: 127.0.0.1" \
        -H "Request-Uri: 127.0.0.1" \
        -H "Uri: 127.0.0.1" \
        -H "Url: 127.0.0.1" \
        -H "X-Client-IP: 127.0.0.1" \
        -H "X-Custom-IP-Authorization: 127.0.0.1" \
        -H "X-Forward-For: 127.0.0.1" \
        -H "X-Forwarded-By: 127.0.0.1" \
        -H "X-Forwarded-For-Original: 127.0.0.1" \
        -H "X-Forwarded-For: 127.0.0.1" \
        -H "X-Forwarded-Host: 127.0.0.1" \
        -H "X-Forwarded-Port: 443" \
        -H "X-Forwarded-Port: 4443" \
        -H "X-Forwarded-Port: 80" \
        -H "X-Forwarded-Port: 8080" \
        -H "X-Forwarded-Port: 8443" \
        -H "X-Forwarded-Scheme: http" \
        -H "X-Forwarded-Scheme: https" \
        -H "X-Forwarded-Server: 127.0.0.1" \
        -H "X-Forwarded: 127.0.0.1" \
        -H "X-Forwarder-For: 127.0.0.1" \
        -H "X-Host: 127.0.0.1" \
        -H "X-Http-Destinationurl: 127.0.0.1" \
        -H "X-Http-Host-Override: 127.0.0.1" \
        -H "X-Original-Remote-Addr: 127.0.0.1" \
        -H "X-Original-Url: 127.0.0.1" \
        -H "X-Originating-IP: 127.0.0.1" \
        -H "X-Proxy-Url: 127.0.0.1" \
        -H "X-Real-Ip: 127.0.0.1" \
        -H "X-Remote-Addr: 127.0.0.1" \
        -H "X-Remote-IP: 127.0.0.1" \
        -H "X-Rewrite-Url: 127.0.0.1" \
        -H "X-True-IP: 127.0.0.1" \
        -favicon -title -cname -asn -srd "$OUTPUT/response" | anew "$OUTPUT/live/live_assets.web"

        # Extracting Port information
        cat "$OUTPUT/live/live_assets.web" | awk '{print $1}' | sed 's/https\?:\/\///' | anew "$OUTPUT/live/open.port"
        
        echo -e "${GREEN}[+] LIVE RESULTS SAVED:${RESET}"
        echo -e "    - Web Data: $OUTPUT/live/live_assets.web"
        echo -e "    - Open Ports: $OUTPUT/live/open.port"
        echo -e "    - Detailed JSON: $OUTPUT/live/httpx_detailed.json"
        echo -e "    - Hosts Summary: $OUTPUT/live/hosts_summary.txt"
    fi
}

# Endpoint Discovery and Analysis
# Enhanced Endpoint Discovery and Analysis with Patient Predator Strategy
ENDPOINT_DISCOVERY() {
    notice "Starting Patient Predator endpoint discovery and analysis"
    
    # Create organized directory structure for endpoint analysis
    mkdir -p "$OUTPUT"/{crawling,js_analysis,endpoints,parameters,secrets}
    
    if [[ -f "$OUTPUT/live/httpx_final.probe" ]]; then
        local live_hosts_count=$(wc -l < "$OUTPUT/live/httpx_final.probe")
        notice "Processing $live_hosts_count live hosts for endpoint discovery"
        
        # Use live hosts as base URLs for crawling
        cp "$OUTPUT/live/httpx_final.probe" "$OUTPUT/crawling/live_hosts.txt"
        
        # Phase 1: Multi-Tool Intelligent Crawling
        notice "Phase 1: Multi-tool intelligent crawling"
        
        # GAU - Fast initial crawl
        notice "Running URL crawling: gau"
        cat "$OUTPUT/crawling/live_hosts.txt" | gau --threads 10 --subs | sort -u | anew "$OUTPUT/crawling/gau.urls"
        local gau_count=$(wc -l < "$OUTPUT/crawling/gau.urls" 2>/dev/null || echo 0)
        success "GAU found: $gau_count URLs"
        
        # WAYMORE - Comprehensive crawling
        notice "Running URL crawling: waymore"
        waymore -iL "$OUTPUT/crawling/live_hosts.txt" -mode U -oU "$OUTPUT/crawling/waymore.tmp" -c 5
        cat "$OUTPUT/crawling/waymore.tmp" 2>/dev/null | sort -u | anew "$OUTPUT/crawling/waymore.urls"
        local waymore_count=$(wc -l < "$OUTPUT/crawling/waymore.urls" 2>/dev/null || echo 0)
        success "Waymore found: $waymore_count URLs"
        rm -f "$OUTPUT/crawling/waymore.tmp"
        
        # KATANA - Advanced crawling with JavaScript analysis
        notice "Running URL crawling: katana"
        katana -silent -xhr -aff -kf -jsl -fx -td -d 3 -jc -list "$OUTPUT/crawling/live_hosts.txt" -o "$OUTPUT/crawling/katana.urls"
        local katana_count=$(wc -l < "$OUTPUT/crawling/katana.urls" 2>/dev/null || echo 0)
        success "Katana found: $katana_count URLs"
        
        # GOSPIDER - Spidering with JavaScript execution
        notice "Running URL crawling: gospider"
        gospider --subs --include-subs --js --delay 2 -S "$OUTPUT/crawling/live_hosts.txt" -o "$OUTPUT/crawling/gospider_output"
        cat "$OUTPUT/crawling/gospider_output"/* 2>/dev/null | awk '$NF ~ /^https?:\/\// {print $NF}' | sort -u | anew "$OUTPUT/crawling/gospider.urls"
        local gospider_count=$(wc -l < "$OUTPUT/crawling/gospider.urls" 2>/dev/null || echo 0)
        success "Gospider found: $gospider_count URLs"
        
        # HAKCRAWLER - Additional crawling perspective
        notice "Running URL crawling: hakrawler"
        cat "$OUTPUT/crawling/live_hosts.txt" | hakrawler -insecure -u -d 2 -subs | anew "$OUTPUT/crawling/hakrawler.urls"
        local hakrawler_count=$(wc -l < "$OUTPUT/crawling/hakrawler.urls" 2>/dev/null || echo 0)
        success "Hakrawler found: $hakrawler_count URLs"
        
        # Phase 2: JavaScript Intelligence Extraction
        notice "Phase 2: JavaScript intelligence extraction"
        
        # Merge all URLs first
        notice "Consolidating all discovered URLs"
        cat "$OUTPUT"/crawling/*.urls 2>/dev/null | sort -u | uro > "$OUTPUT/crawling/all_urls.raw"
        local total_urls=$(wc -l < "$OUTPUT/crawling/all_urls.raw" 2>/dev/null || echo 0)
        success "Total unique URLs discovered: $total_urls"
        
        # Multiple methods for JS file discovery
        notice "Extracting JavaScript files via multiple methods"
        
        # Method 1: Direct .js filtering
        cat "$OUTPUT/crawling/all_urls.raw" | grep -E "\.js($|\?)" | anew "$OUTPUT/js_analysis/js_urls.txt"
        
        # Method 2: getJS tool
        if command -v getJS &> /dev/null; then
            cat "$OUTPUT/crawling/all_urls.raw" | getJS | anew "$OUTPUT/js_analysis/js_urls.txt"
        fi
        
        # Method 3: subJS tool  
        if command -v subJS &> /dev/null; then
            cat "$OUTPUT/crawling/all_urls.raw" | subJS | anew "$OUTPUT/js_analysis/js_urls.txt"
        fi
        
        # Method 4: Katana JS detection
        cat "$OUTPUT/crawling/katana.urls" 2>/dev/null | grep -E "\.js" | anew "$OUTPUT/js_analysis/js_urls.txt"
        
        # Deduplicate JS URLs
        sort -u "$OUTPUT/js_analysis/js_urls.txt" > "$OUTPUT/js_analysis/js_urls.deduped.txt"
        mv "$OUTPUT/js_analysis/js_urls.deduped.txt" "$OUTPUT/js_analysis/js_urls.txt"
        
        local js_count=$(wc -l < "$OUTPUT/js_analysis/js_urls.txt" 2>/dev/null || echo 0)
        success "Found $js_count unique JavaScript files"
        
        # Download JavaScript files for analysis
        if [[ $js_count -gt 0 ]]; then
            notice "Downloading JavaScript files for deep analysis"
            mkdir -p "$OUTPUT/js_analysis/files"
            
            # Download with wget - continue, no-clobber, timeout
            wget -nc --timeout=10 --tries=2 -i "$OUTPUT/js_analysis/js_urls.txt" -P "$OUTPUT/js_analysis/files/" 2>/dev/null &
            
            # Alternative download with curl for better error handling
            cat "$OUTPUT/js_analysis/js_urls.txt" | xargs -P 3 -I {} sh -c 'curl -s "{}" -o "$OUTPUT/js_analysis/files/$(echo {} | sed "s|https\?://||" | tr "/" "_" | tr -d "?&=")" 2>/dev/null' &
            
            wait
            
            local downloaded_js=$(find "$OUTPUT/js_analysis/files" -name "*.js" 2>/dev/null | wc -l)
            success "Downloaded $downloaded_js JavaScript files"
            
            # Advanced JavaScript Analysis
            notice "Performing advanced JavaScript analysis"
            
            # Extract endpoints from JS files
            notice "Extracting endpoints from JavaScript files"
            find "$OUTPUT/js_analysis/files" -name "*.js" -exec cat {} \; 2>/dev/null | \
                grep -Eo "(https?://[^\"' ]+|/[^\"' ]*)" | \
                grep -vE "(//|\.css|\.png|\.jpg|\.jpeg|\.gif|\.ico)" | \
                sort -u | anew "$OUTPUT/endpoints/js_endpoints.txt"
            
            # Extract API endpoints and patterns
            notice "Extracting API patterns from JavaScript"
            find "$OUTPUT/js_analysis/files" -name "*.js" -exec cat {} \; 2>/dev/null | \
                grep -Eo "(api|v[0-9])/[^\"' ]*" | \
                sort -u | anew "$OUTPUT/endpoints/api_patterns.txt"
            
            # Secret/key extraction
            notice "Searching for secrets and keys in JavaScript"
            find "$OUTPUT/js_analysis/files" -name "*.js" -exec grep -E "(api[_-]?key|secret|token|password|auth|key|pass)" {} \; 2>/dev/null | \
                anew "$OUTPUT/secrets/js_secrets.txt"
            
            # URL patterns from JS variables
            notice "Extracting URL patterns from JavaScript variables"
            find "$OUTPUT/js_analysis/files" -name "*.js" -exec grep -E "(url|endpoint|base|api|host)[=:]['\"][^'\"]+" {} \; 2>/dev/null | \
                sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | \
                sort -u | anew "$OUTPUT/endpoints/js_variables.txt"
        fi
        
        # Phase 3: Comprehensive Endpoint Analysis
        notice "Phase 3: Comprehensive endpoint analysis"
        
        # Merge all endpoints
        cat "$OUTPUT/crawling/all_urls.raw" "$OUTPUT/endpoints/js_endpoints.txt" 2>/dev/null | \
            sort -u | uro > "$OUTPUT/endpoints/final_urls.txt"
        
        local final_count=$(wc -l < "$OUTPUT/endpoints/final_urls.txt" 2>/dev/null || echo 0)
        success "Final unique URLs: $final_count"
        
        # Extract parameters
        notice "Extracting and analyzing URL parameters"
        cat "$OUTPUT/endpoints/final_urls.txt" | grep "?" | \
            unfurl keys | sort -u | anew "$OUTPUT/parameters/all_parameters.txt"
        
        local param_count=$(wc -l < "$OUTPUT/parameters/all_parameters.txt" 2>/dev/null || echo 0)
        success "Found $param_count unique parameters"
        
        # Categorize endpoints
        notice "Categorizing endpoints by type and sensitivity"
        
        # API endpoints
        cat "$OUTPUT/endpoints/final_urls.txt" | grep -E "(api|v[0-9]|graphql|rest)" | \
            anew "$OUTPUT/endpoints/api_urls.txt"
        
        # Administrative endpoints
        cat "$OUTPUT/endpoints/final_urls.txt" | grep -E "(admin|login|dashboard|manager|control|portal)" | \
            anew "$OUTPUT/endpoints/admin_urls.txt"
        
        # File endpoints
        cat "$OUTPUT/endpoints/final_urls.txt" | grep -E "\.(pdf|doc|docx|xls|xlsx|txt|csv)" | \
            anew "$OUTPUT/endpoints/file_urls.txt"
        
        # Interesting extensions
        cat "$OUTPUT/endpoints/final_urls.txt" | grep -E "\.(json|xml|yml|yaml|config|bak|old|backup|tar|gz)" | \
            anew "$OUTPUT/endpoints/interesting_urls.txt"
        
        # Authentication endpoints
        cat "$OUTPUT/endpoints/final_urls.txt" | grep -E "(login|signin|auth|oauth|sso|logout|register|signup)" | \
            anew "$OUTPUT/endpoints/auth_urls.txt"
        
        # Phase 4: Parameter Intelligence
        notice "Phase 4: Parameter intelligence analysis"
        
        # Extract parameters with context
        cat "$OUTPUT/endpoints/final_urls.txt" | grep "?" | while read url; do
            echo "$url" | unfurl format "%p?%q#%f"
        done | anew "$OUTPUT/parameters/parameter_context.txt"
        
        # Identify interesting parameters
        notice "Identifying high-value parameters"
        cat "$OUTPUT/parameters/all_parameters.txt" | grep -E -i \
            "(id|user|token|key|email|password|file|redirect|url|admin|auth|session|code|cmd|command|exec)" | \
            anew "$OUTPUT/parameters/interesting_parameters.txt"
        
        # Create parameter wordlist for fuzzing
        cat "$OUTPUT/parameters/all_parameters.txt" | anew "$OUTPUT/parameters/parameter_wordlist.txt"
        
        local interesting_params=$(wc -l < "$OUTPUT/parameters/interesting_parameters.txt" 2>/dev/null || echo 0)
        success "Identified $interesting_params interesting parameters"
        
        # Phase 5: Generate Endpoint Intelligence Report
        notice "Generating endpoint intelligence report"
        
        local api_endpoints=$(wc -l < "$OUTPUT/endpoints/api_urls.txt" 2>/dev/null || echo 0)
        local admin_endpoints=$(wc -l < "$OUTPUT/endpoints/admin_urls.txt" 2>/dev/null || echo 0)
        local auth_endpoints=$(wc -l < "$OUTPUT/endpoints/auth_urls.txt" 2>/dev/null || echo 0)
        
        cat > "$OUTPUT/endpoints/endpoint_intelligence_report.md" << EOF
# Patient Predator Endpoint Intelligence Report
## Domain: $DOMAIN
## Date: $(date)

## Discovery Metrics
- Total URLs Discovered: $final_count
- JavaScript Files Identified: $js_count
- Unique Parameters: $param_count
- API Endpoints: $api_endpoints
- Admin Endpoints: $admin_endpoints
- Authentication Endpoints: $auth_endpoints

## Key Files for Testing
- All URLs: $OUTPUT/endpoints/final_urls.txt
- API Endpoints: $OUTPUT/endpoints/api_urls.txt
- Admin Endpoints: $OUTPUT/endpoints/admin_urls.txt
- Authentication Endpoints: $OUTPUT/endpoints/auth_urls.txt
- Interesting Parameters: $OUTPUT/parameters/interesting_parameters.txt

## Tool Results
- GAU: $gau_count
- Waymore: $waymore_count
- Katana: $katana_count
- Gospider: $gospider_count
- Hakrawler: $hakrawler_count

## JavaScript Analysis
- JS Files Downloaded: $downloaded_js
- JS Secrets Found: $(wc -l < "$OUTPUT/secrets/js_secrets.txt" 2>/dev/null || echo 0)
- JS Endpoints Extracted: $(wc -l < "$OUTPUT/endpoints/js_endpoints.txt" 2>/dev/null || echo 0)

## Next Steps for Testing
1. Priority: Test authentication endpoints for flaws
2. Focus: API endpoints for authorization issues
3. Examine: Admin endpoints for access control vulnerabilities
4. Fuzz: Interesting parameters for injection flaws
5. Review: JavaScript secrets for exposed credentials

## Patient Predator Strategy
This comprehensive endpoint discovery employed multiple crawling techniques and deep JavaScript analysis to identify high-value targets. Focus on endpoints that control application logic and user data.
EOF

        success "Endpoint discovery completed!"
        echo
        echo -e "${GREEN}=== ENDPOINT DISCOVERY SUMMARY ===${RESET}"
        echo -e "Total URLs: ${CYAN}$final_count${RESET}"
        echo -e "JavaScript Files: ${YELLOW}$js_count${RESET}"
        echo -e "Unique Parameters: ${MAGENTA}$param_count${RESET}"
        echo -e "API Endpoints: ${RED}$api_endpoints${RESET}"
        echo -e "Admin Endpoints: ${RED}$admin_endpoints${RESET}"
        echo
        echo -e "${GREEN}Key files for testing:${RESET}"
        echo -e "  All URLs: ${CYAN}$OUTPUT/endpoints/final_urls.txt${RESET}"
        echo -e "  API Endpoints: ${YELLOW}$OUTPUT/endpoints/api_urls.txt${RESET}"
        echo -e "  Admin Endpoints: ${RED}$OUTPUT/endpoints/admin_urls.txt${RESET}"
        echo -e "  Parameters: ${MAGENTA}$OUTPUT/parameters/interesting_parameters.txt${RESET}"
        echo
        
    else
        warn "No live hosts found for endpoint discovery"
    fi
}

# Vulnerability Scanning Preparation
VULN_SCAN_PREP() {
    notice "Preparing for vulnerability scanning"
    
    # Create organized target lists for different scanners
    if [[ -f "$OUTPUT/live/httpx_final.probe" ]]; then
        # Nuclei targets
        cp "$OUTPUT/live/httpx_final.probe" "$OUTPUT/scanning/nuclei_targets.txt"
        
        # Naabu port scanning targets
        cat "$OUTPUT/live/httpx_final.probe" | sed 's|https\?://||' | cut -d'/' -f1 | anew "$OUTPUT/scanning/naabu_targets.txt" >/dev/null
        
        # Custom wordlist generation based on target
        if [[ -f "$OUTPUT/endpoints/all_urls.txt" ]]; then
            cat "$OUTPUT/endpoints/all_urls.txt" | unfurl paths | sort -u > "$OUTPUT/scanning/custom_paths.txt"
        fi
        
        success "Vulnerability scanning preparation completed"
    fi
}

# Final Reporting
FINAL_REPORT() {
    notice "Generating Patient Predator reconnaissance report"
    
    local total_subs=$(cat "$OUTPUT/all_discovered_subs.txt" 2>/dev/null | wc -l || echo 0)
    local live_hosts=$(cat "$OUTPUT/live/httpx_final.probe" 2>/dev/null | wc -l || echo 0)
    local endpoints=$(cat "$OUTPUT/endpoints/all_urls.txt" 2>/dev/null | wc -l || echo 0)
    local js_files=$(find "$OUTPUT/js/raw" -name "*.js" 2>/dev/null | wc -l || echo 0)
    
    echo -e "${BOLD}=== PATIENT PREDATOR RECONNAISSANCE REPORT ===${RESET}"
    echo -e "Domain: ${CYAN}$DOMAIN${RESET}"
    echo -e "Output Directory: ${YELLOW}$OUTPUT${RESET}"
    echo -e ""
    echo -e "${BOLD}DISCOVERY METRICS:${RESET}"
    echo -e "  Total Subdomains Discovered: ${YELLOW}$total_subs${RESET}"
    echo -e "  Live Hosts: ${GREEN}$live_hosts${RESET}"
    echo -e "  Endpoints Discovered: ${MAGENTA}$endpoints${RESET}"
    echo -e "  JS Files Analyzed: ${BLUE}$js_files${RESET}"
    echo -e ""
    echo -e "${BOLD}KEY FILES:${RESET}"
    echo -e "  Live Hosts: ${CYAN}$OUTPUT/live/httpx_final.probe${RESET}"
    echo -e "  Hosts Summary: ${CYAN}$OUTPUT/live/hosts_summary.txt${RESET}"
    echo -e "  All Endpoints: ${MAGENTA}$OUTPUT/endpoints/all_urls.txt${RESET}"
    echo -e "  Interesting Params: ${YELLOW}$OUTPUT/endpoints/interesting_params.txt${RESET}"
    echo -e ""
    echo -e "${BOLD}NEXT STEPS - PATIENT PREDATOR STRATEGY:${RESET}"
    echo -e "  1. ${GREEN}Review Technology Stack:${RESET} cat $OUTPUT/live/hosts_summary.txt"
    echo -e "  2. ${GREEN}Vulnerability Scan:${RESET} nuclei -l $OUTPUT/scanning/nuclei_targets.txt"
    echo -e "  3. ${GREEN}Port Scanning:${RESET} naabu -l $OUTPUT/scanning/naabu_targets.txt"
    echo -e "  4. ${GREEN}Manual Testing:${RESET} Review $OUTPUT/endpoints/interesting_params.txt"
    echo -e "  5. ${GREEN}JS Analysis:${RESET} Check $OUTPUT/js/secrets_patterns.txt"
    echo -e ""
    echo -e "${BOLD}Remember: Patient predators wait for the right moment to strike!${RESET}"
    
    # Save report to file
    cat > "$OUTPUT/reports/recon_summary.md" << EOF
# Patient Predator Reconnaissance Report
## Domain: $DOMAIN
## Date: $(date)

## Discovery Metrics
- Total Subdomains: $total_subs
- Live Hosts: $live_hosts  
- Endpoints: $endpoints
- JS Files: $js_files

## Next Steps
1. Review technology stack: \`cat $OUTPUT/live/hosts_summary.txt\`
2. Run vulnerability scan: \`nuclei -l $OUTPUT/scanning/nuclei_targets.txt\`
3. Perform port scanning: \`naabu -l $OUTPUT/scanning/naabu_targets.txt\`
4. Manual testing of interesting parameters
5. Analyze JavaScript files for secrets

## Strategy
The Patient Predator methodology emphasizes thorough reconnaissance and waiting for the perfect moment to strike. All data has been organized for systematic analysis.
EOF
    
    success "Full reconnaissance completed! Report saved to: $OUTPUT/reports/recon_summary.md"
}

# Main Execution Flow
main() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <domain> <output_directory>"
        echo "Example: $0 example.com /path/to/output"
        exit 1
    fi
    
    BANNER
    CONFIG "$1" "$2"
    
    notice "Initializing Patient Predator reconnaissance against: $DOMAIN"
    notice "Output directory: $OUTPUT"
    
    # Execute strategy phases
    INTELLIGENCE_GATHERING
    PASSIVE_ENUM
    ACTIVE_ENUM
    LIVE_DETECTION
    TECH_STACK_ANALYSIS
    JS_INTELLIGENCE
    ENDPOINT_DISCOVERY
    VULN_SCAN_PREP
    FINAL_REPORT
}

# Error handling and cleanup
trap 'warn "Script interrupted. Saving progress..."; FINAL_REPORT; exit 1' INT TERM

main "$@"
