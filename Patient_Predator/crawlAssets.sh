#!/bin/bash

# --- Patient Predator Crawling Strategy ---
# Enhanced with intelligent crawling, JavaScript analysis, and endpoint extraction

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
RESET="\e[0m"

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

BANNER() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                   PATIENT PREDATOR CRAWLING                  ║"
    echo "║                 Intelligent Endpoint Discovery               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# Configuration
CONFIG() {
    DOMAIN=$1
    OUTPUT=$2
    
    # Create organized directory structure
    mkdir -p "$OUTPUT"/{raw,processed,js,endpoints,parameters,archives,secrets}
    
    # Target URL formatting
    if [[ "$DOMAIN" =~ ^https?:// ]]; then
        TARGET="$DOMAIN"
    else
        TARGET="https://$DOMAIN"
    fi
    
    # Tool configurations
    CRAWL_DEPTH=3
    PARALLEL_JOBS=5
    TIMEOUT=30
    
    success "Configuration loaded for: $DOMAIN"
    debug "Output directory: $OUTPUT"
}

# Intelligence-Driven Crawling
INTELLIGENT_CRAWLING() {
    notice "Starting Patient Predator intelligent crawling"
    
    # GAU - Fast initial crawl
    notice "Running URL crawling: gau"
    echo "$DOMAIN" | gau --threads 10 --subs | sort -u | anew "$OUTPUT/raw/gau.urls"
    local gau_count=$(wc -l < "$OUTPUT/raw/gau.urls" 2>/dev/null || echo 0)
    success "GAU found: $gau_count URLs"
    
    # WAYMORE - Comprehensive crawling
    notice "Running URL crawling: waymore"
    waymore -i "$DOMAIN" -mode U -oU "$OUTPUT/raw/waymore.tmp" -c 10
    cat "$OUTPUT/raw/waymore.tmp" 2>/dev/null | sort -u | anew "$OUTPUT/raw/waymore.urls"
    local waymore_count=$(wc -l < "$OUTPUT/raw/waymore.urls" 2>/dev/null || echo 0)
    success "Waymore found: $waymore_count URLs"
    rm -f "$OUTPUT/raw/waymore.tmp"
    
    # KATANA - Advanced crawling with JavaScript analysis
    notice "Running URL crawling: katana"
    katana -silent -xhr -aff -kf -jsl -fx -td -d "$CRAWL_DEPTH" -jc -u "$TARGET" -o "$OUTPUT/raw/katana.urls"
    local katana_count=$(wc -l < "$OUTPUT/raw/katana.urls" 2>/dev/null || echo 0)
    success "Katana found: $katana_count URLs"
    
    # GOSPIDER - Spidering with JavaScript execution
    notice "Running URL crawling: gospider"
    gospider --subs --include-subs --js --delay 2 -s "$TARGET" -o "$OUTPUT/raw/gospider_output"
    cat "$OUTPUT/raw/gospider_output"/* 2>/dev/null | awk '$NF ~ /^https?:\/\// {print $NF}' | sort -u | anew "$OUTPUT/raw/gospider.urls"
    local gospider_count=$(wc -l < "$OUTPUT/raw/gospider.urls" 2>/dev/null || echo 0)
    success "Gospider found: $gospider_count URLs"
    
    # HAKCRAWLER - Additional crawling perspective
    notice "Running URL crawling: hakrawler"
    echo "$TARGET" | hakrawler -insecure -u -d 2 -subs | anew "$OUTPUT/raw/hakrawler.urls"
    local hakrawler_count=$(wc -l < "$OUTPUT/raw/hakrawler.urls" 2>/dev/null || echo 0)
    success "Hakrawler found: $hakrawler_count URLs"
}

# JavaScript Intelligence Extraction
JS_INTELLIGENCE() {
    notice "Starting JavaScript intelligence extraction"
    
    # Merge all URLs first
    notice "Consolidating all discovered URLs"
    cat "$OUTPUT"/raw/*.urls 2>/dev/null | sort -u | uro > "$OUTPUT/processed/all_urls.raw"
    local total_urls=$(wc -l < "$OUTPUT/processed/all_urls.raw" 2>/dev/null || echo 0)
    success "Total unique URLs discovered: $total_urls"
    
    # Multiple methods for JS file discovery
    notice "Extracting JavaScript files via multiple methods"
    
    # Method 1: Direct .js filtering
    cat "$OUTPUT/processed/all_urls.raw" | grep -E "\.js($|\?)" | anew "$OUTPUT/js/js_urls.txt"
    
    # Method 2: getJS tool
    if command -v getJS &> /dev/null; then
        cat "$OUTPUT/processed/all_urls.raw" | getJS | anew "$OUTPUT/js/js_urls.txt"
    fi
    
    # Method 3: subJS tool  
    if command -v subJS &> /dev/null; then
        cat "$OUTPUT/processed/all_urls.raw" | subJS | anew "$OUTPUT/js/js_urls.txt"
    fi
    
    # Method 4: Katana JS detection
    cat "$OUTPUT/raw/katana.urls" 2>/dev/null | grep -E "\.js" | anew "$OUTPUT/js/js_urls.txt"
    
    # Deduplicate JS URLs
    sort -u "$OUTPUT/js/js_urls.txt" > "$OUTPUT/js/js_urls.deduped.txt"
    mv "$OUTPUT/js/js_urls.deduped.txt" "$OUTPUT/js/js_urls.txt"
    
    local js_count=$(wc -l < "$OUTPUT/js/js_urls.txt" 2>/dev/null || echo 0)
    success "Found $js_count unique JavaScript files"
    
    # Download JavaScript files for analysis
    if [[ $js_count -gt 0 ]]; then
        notice "Downloading JavaScript files for deep analysis"
        mkdir -p "$OUTPUT/js/files"
        
        # Download with wget - continue, no-clobber, timeout
        wget -nc --timeout=10 --tries=2 -i "$OUTPUT/js/js_urls.txt" -P "$OUTPUT/js/files/" 2>/dev/null &
        
        # Alternative download with curl for better error handling
        cat "$OUTPUT/js/js_urls.txt" | xargs -P 3 -I {} sh -c 'curl -s "{}" -o "$OUTPUT/js/files/$(echo {} | sed "s|https\?://||" | tr "/" "_" | tr -d "?&=")" 2>/dev/null' &
        
        wait
        
        local downloaded_js=$(find "$OUTPUT/js/files" -name "*.js" 2>/dev/null | wc -l)
        success "Downloaded $downloaded_js JavaScript files"
        
        # JavaScript analysis
        ANALYZE_JAVASCRIPT
    fi
}

# Advanced JavaScript Analysis
ANALYZE_JAVASCRIPT() {
    notice "Performing advanced JavaScript analysis"
    
    # Extract endpoints from JS files
    notice "Extracting endpoints from JavaScript files"
    find "$OUTPUT/js/files" -name "*.js" -exec cat {} \; 2>/dev/null | \
        grep -Eo "(https?://[^\"' ]+|/[^\"' ]*)" | \
        grep -vE "(//|\.css|\.png|\.jpg|\.jpeg|\.gif|\.ico)" | \
        sort -u | anew "$OUTPUT/endpoints/js_endpoints.txt"
    
    # Extract API endpoints and patterns
    notice "Extracting API patterns from JavaScript"
    find "$OUTPUT/js/files" -name "*.js" -exec cat {} \; 2>/dev/null | \
        grep -Eo "(api|v[0-9])/[^\"' ]*" | \
        sort -u | anew "$OUTPUT/endpoints/api_patterns.txt"
    
    # Secret/key extraction
    notice "Searching for secrets and keys in JavaScript"
    find "$OUTPUT/js/files" -name "*.js" -exec grep -E "(api[_-]?key|secret|token|password|auth|key|pass)" {} \; 2>/dev/null | \
        anew "$OUTPUT/secrets/js_secrets.txt"
    
    # URL patterns from JS variables
    notice "Extracting URL patterns from JavaScript variables"
    find "$OUTPUT/js/files" -name "*.js" -exec grep -E "(url|endpoint|base|api|host)[=:]['\"][^'\"]+" {} \; 2>/dev/null | \
        sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | \
        sort -u | anew "$OUTPUT/endpoints/js_variables.txt"
}

# Endpoint Analysis and Processing
ENDPOINT_ANALYSIS() {
    notice "Performing comprehensive endpoint analysis"
    
    # Merge all endpoints
    cat "$OUTPUT/processed/all_urls.raw" "$OUTPUT/endpoints/js_endpoints.txt" 2>/dev/null | \
        sort -u | uro > "$OUTPUT/processed/final_urls.txt"
    
    local final_count=$(wc -l < "$OUTPUT/processed/final_urls.txt" 2>/dev/null || echo 0)
    success "Final unique URLs: $final_count"
    
    # Extract parameters
    notice "Extracting and analyzing URL parameters"
    cat "$OUTPUT/processed/final_urls.txt" | grep "?" | \
        unfurl keys | sort -u | anew "$OUTPUT/parameters/all_parameters.txt"
    
    local param_count=$(wc -l < "$OUTPUT/parameters/all_parameters.txt" 2>/dev/null || echo 0)
    success "Found $param_count unique parameters"
    
    # Categorize endpoints
    notice "Categorizing endpoints by type"
    
    # API endpoints
    cat "$OUTPUT/processed/final_urls.txt" | grep -E "(api|v[0-9]|graphql|rest)" | \
        anew "$OUTPUT/endpoints/api_urls.txt"
    
    # Administrative endpoints
    cat "$OUTPUT/processed/final_urls.txt" | grep -E "(admin|login|dashboard|manager|control)" | \
        anew "$OUTPUT/endpoints/admin_urls.txt"
    
    # File endpoints
    cat "$OUTPUT/processed/final_urls.txt" | grep -E "\.(pdf|doc|docx|xls|xlsx|txt|csv)" | \
        anew "$OUTPUT/endpoints/file_urls.txt"
    
    # Interesting extensions
    cat "$OUTPUT/processed/final_urls.txt" | grep -E "\.(json|xml|yml|yaml|config|bak|old|backup)" | \
        anew "$OUTPUT/endpoints/interesting_urls.txt"
}

# Parameter Intelligence
PARAMETER_INTELLIGENCE() {
    notice "Performing parameter intelligence analysis"
    
    # Extract parameters with context
    cat "$OUTPUT/processed/final_urls.txt" | grep "?" | while read url; do
        echo "$url" | unfurl format "%p?%q#%f"
    done | anew "$OUTPUT/parameters/parameter_context.txt"
    
    # Identify interesting parameters
    notice "Identifying high-value parameters"
    cat "$OUTPUT/parameters/all_parameters.txt" | grep -E -i \
        "(id|user|token|key|email|password|file|redirect|url|admin|auth|session|code)" | \
        anew "$OUTPUT/parameters/interesting_parameters.txt"
    
    # Create parameter wordlist for fuzzing
    cat "$OUTPUT/parameters/all_parameters.txt" | anew "$OUTPUT/parameters/parameter_wordlist.txt"
    
    local interesting_params=$(wc -l < "$OUTPUT/parameters/interesting_parameters.txt" 2>/dev/null || echo 0)
    success "Identified $interesting_params interesting parameters"
}

# Generate Intelligence Report
GENERATE_REPORT() {
    notice "Generating Patient Predator crawling intelligence report"
    
    local total_urls=$(wc -l < "$OUTPUT/processed/final_urls.txt" 2>/dev/null || echo 0)
    local js_files=$(wc -l < "$OUTPUT/js/js_urls.txt" 2>/dev/null || echo 0)
    local downloaded_js=$(find "$OUTPUT/js/files" -name "*.js" 2>/dev/null | wc -l)
    local endpoints=$(wc -l < "$OUTPUT/endpoints/api_urls.txt" 2>/dev/null || echo 0)
    local params=$(wc -l < "$OUTPUT/parameters/all_parameters.txt" 2>/dev/null || echo 0)
    
    cat > "$OUTPUT/crawling_intelligence_report.md" << EOF
# Patient Predator Crawling Intelligence Report
## Domain: $DOMAIN
## Date: $(date)

## Discovery Metrics
- Total URLs Discovered: $total_urls
- JavaScript Files Identified: $js_files
- JavaScript Files Downloaded: $downloaded_js
- API Endpoints Found: $endpoints
- Unique Parameters: $params

## Key Files
- Final URLs: $OUTPUT/processed/final_urls.txt
- JavaScript URLs: $OUTPUT/js/js_urls.txt
- API Endpoints: $OUTPUT/endpoints/api_urls.txt
- Admin Endpoints: $OUTPUT/endpoints/admin_urls.txt
- Parameters: $OUTPUT/parameters/all_parameters.txt

## Tool Results
- GAU: $(wc -l < "$OUTPUT/raw/gau.urls" 2>/dev/null || echo 0)
- Waymore: $(wc -l < "$OUTPUT/raw/waymore.urls" 2>/dev/null || echo 0)
- Katana: $(wc -l < "$OUTPUT/raw/katana.urls" 2>/dev/null || echo 0)
- Gospider: $(wc -l < "$OUTPUT/raw/gospider.urls" 2>/dev/null || echo 0)
- Hakrawler: $(wc -l < "$OUTPUT/raw/hakrawler.urls" 2>/dev/null || echo 0)

## Next Steps
1. Review high-value endpoints: $OUTPUT/endpoints/admin_urls.txt
2. Test interesting parameters: $OUTPUT/parameters/interesting_parameters.txt
3. Analyze JavaScript secrets: $OUTPUT/secrets/js_secrets.txt
4. Fuzz API endpoints with discovered parameters

## Patient Predator Strategy
This crawl employed multiple tools and techniques to comprehensively map the application attack surface. Focus on endpoints with administrative functionality and parameters that control application logic.
EOF

    success "Crawling intelligence report generated: $OUTPUT/crawling_intelligence_report.md"
    
    # Print summary
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║                    CRAWLING COMPLETED                        ║${RESET}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${GREEN}║ URLs: $total_urls | JS Files: $js_files | Params: $params ${RESET}"
    echo -e "${GREEN}║                                                            ║${RESET}"
    echo -e "${GREEN}║ Next: Review $OUTPUT/endpoints/admin_urls.txt              ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
    echo
}

# Main execution flow
main() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <domain> <output_directory>"
        echo "Example: $0 example.com /path/to/crawling_output"
        exit 1
    fi
    
    BANNER
    CONFIG "$1" "$2"
    
    INTELLIGENT_CRAWLING
    JS_INTELLIGENCE
    ENDPOINT_ANALYSIS
    PARAMETER_INTELLIGENCE
    GENERATE_REPORT
    
    success "Patient Predator crawling strategy completed!"
}

# Run main function
main "$@"
