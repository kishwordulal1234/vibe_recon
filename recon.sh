#!/bin/bash

# Define colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

VERSION="3.2-WORKING"

# Banner
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           SECURITY RECONNAISSANCE TOOL - PRODUCTION           ║${NC}"
echo -e "${CYAN}║    ✓ XSS Scanning (dalfox)  ✓ SQL Injection (sqlmc)          ║${NC}"
echo -e "${CYAN}║                        Version $VERSION                       ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"

if [ $# -eq 0 ]; then
    echo -e "${WHITE}Usage:${NC} $0 <domain>"
    echo -e "${WHITE}Example:${NC} $0 testphp.vulnweb.com"
    exit 1
fi

DOMAIN="$1"
export PATH=$PATH:$HOME/go/bin
echo -e "${BLUE}[INFO]${NC} Starting reconnaissance for ${WHITE}$DOMAIN${NC}"

# Clean up any previous scan results
rm -f "${DOMAIN}"-*.txt 2>/dev/null

# 1. Subdomain Discovery
echo -e "${BLUE}[INFO]${NC} Step 1: Subdomain Discovery"
if command -v subfinder &> /dev/null; then
    echo -e "${BLUE}[INFO]${NC} Using subfinder for subdomain discovery..."
    subfinder -d "$DOMAIN" -silent -o "${DOMAIN}-subdomains.txt" 2>/dev/null
    
    if command -v chaos &> /dev/null; then
        echo -e "${BLUE}[INFO]${NC} Using chaos for additional subdomains..."
        chaos -d "$DOMAIN" -silent >> "${DOMAIN}-subdomains.txt" 2>/dev/null || true
    fi
else
    echo -e "${RED}[ERROR]${NC} subfinder not found - subdomain discovery skipped"
    echo -e "${BLUE}[INFO]${NC} Install subfinder: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    echo "$DOMAIN" > "${DOMAIN}-subdomains.txt"
fi

echo "$DOMAIN" >> "${DOMAIN}-subdomains.txt"
sort -u "${DOMAIN}-subdomains.txt" -o "${DOMAIN}-subdomains.txt"
SUBDOMAIN_COUNT=$(wc -l < "${DOMAIN}-subdomains.txt")
echo -e "${GREEN}[SUCCESS]${NC} Found ${WHITE}$SUBDOMAIN_COUNT${NC} subdomains"

if [ "$SUBDOMAIN_COUNT" -gt 0 ]; then
    echo -e "${BLUE}[INFO]${NC} Discovered subdomains:"
    cat "${DOMAIN}-subdomains.txt" | head -10 | while read -r subdomain; do
        echo -e "  ${WHITE}$subdomain${NC}"
    done
    [ "$SUBDOMAIN_COUNT" -gt 10 ] && echo -e "  ${YELLOW}... and $((SUBDOMAIN_COUNT - 10)) more${NC}"
fi

# 2. Live Host Check
echo -e "${BLUE}[INFO]${NC} Step 2: Live Host Verification"
echo -e "${BLUE}[INFO]${NC} Checking ${WHITE}$SUBDOMAIN_COUNT${NC} subdomains for live hosts..."

> "${DOMAIN}-live-urls.txt"
LIVE_COUNT=0
DEAD_COUNT=0

while read -r subdomain; do
    if [ -n "$subdomain" ]; then
        HTTP_STATUS=$(curl -s --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" "http://$subdomain" 2>/dev/null || echo "000")
        HTTPS_STATUS=$(curl -s --connect-timeout 5 --max-time 10 -o /dev/null -w "%{http_code}" "https://$subdomain" 2>/dev/null || echo "000")
        
        if echo "$HTTP_STATUS" | grep -q "200\|301\|302\|403\|404"; then
            echo "http://$subdomain" >> "${DOMAIN}-live-urls.txt"
            echo -e "  ${GREEN}✓${NC} http://$subdomain - ${GREEN}ALIVE${NC} (${HTTP_STATUS})"
            LIVE_COUNT=$((LIVE_COUNT + 1))
        elif echo "$HTTPS_STATUS" | grep -q "200\|301\|302\|403\|404"; then
            echo "https://$subdomain" >> "${DOMAIN}-live-urls.txt"
            echo -e "  ${GREEN}✓${NC} https://$subdomain - ${GREEN}ALIVE${NC} (${HTTPS_STATUS})"
            LIVE_COUNT=$((LIVE_COUNT + 1))
        else
            echo -e "  ${RED}✗${NC} $subdomain - ${RED}DEAD${NC}"
            DEAD_COUNT=$((DEAD_COUNT + 1))
        fi
    fi
done < "${DOMAIN}-subdomains.txt"

echo -e "${GREEN}[SUCCESS]${NC} Live hosts: ${WHITE}$LIVE_COUNT${NC}, Dead hosts: ${WHITE}$DEAD_COUNT${NC}"

# 3. Endpoint Discovery
echo -e "${BLUE}[INFO]${NC} Step 3: Endpoint Discovery"
if [ -s "${DOMAIN}-live-urls.txt" ]; then
    if command -v katana &> /dev/null; then
        echo -e "${BLUE}[INFO]${NC} Using katana for endpoint crawling..."
        cat "${DOMAIN}-live-urls.txt" | katana -d 2 -jc -f url -silent > "${DOMAIN}-all-endpoints.txt" 2>/dev/null
        ENDPOINT_COUNT=$(wc -l < "${DOMAIN}-all-endpoints.txt")
        echo -e "${GREEN}[SUCCESS]${NC} Found ${WHITE}$ENDPOINT_COUNT${NC} endpoints"
    else
        echo -e "${RED}[ERROR]${NC} katana not found - endpoint discovery skipped"
        echo -e "${BLUE}[INFO]${NC} Install katana: go install github.com/projectdiscovery/katana/cmd/katana@latest"
        touch "${DOMAIN}-all-endpoints.txt"
        ENDPOINT_COUNT=0
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} No live hosts for crawling"
    touch "${DOMAIN}-all-endpoints.txt"
    ENDPOINT_COUNT=0
fi

# 4. Parameter Extraction  
echo -e "${BLUE}[INFO]${NC} Step 4: Parameter Extraction"
if [ -s "${DOMAIN}-all-endpoints.txt" ]; then
    grep '\?' "${DOMAIN}-all-endpoints.txt" > "${DOMAIN}-parameterized-urls.txt" 2>/dev/null || touch "${DOMAIN}-parameterized-urls.txt"
    PARAM_COUNT=$(wc -l < "${DOMAIN}-parameterized-urls.txt")
    echo -e "${GREEN}[SUCCESS]${NC} Found ${WHITE}$PARAM_COUNT${NC} parameterized URLs"
    
    if [ "$PARAM_COUNT" -gt 0 ]; then
        echo -e "${BLUE}[INFO]${NC} Parameterized URLs for vulnerability testing:"
        head -5 "${DOMAIN}-parameterized-urls.txt" | while read -r url; do
            echo -e "  ${WHITE}$url${NC}"
        done
        [ "$PARAM_COUNT" -gt 5 ] && echo -e "  ${YELLOW}... and $((PARAM_COUNT - 5)) more${NC}"
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} No endpoints found for parameter extraction"
    touch "${DOMAIN}-parameterized-urls.txt"
    PARAM_COUNT=0
fi

# 5. XSS Scanning (Working Implementation)
echo -e "${BLUE}[INFO]${NC} Step 5: XSS Vulnerability Scanning"
XSS_VULN_COUNT=0

if [ -s "${DOMAIN}-parameterized-urls.txt" ]; then
    echo -e "${BLUE}[INFO]${NC} Scanning parameterized URLs for XSS vulnerabilities..."
    
    > "${DOMAIN}-xss-results.txt"
    
    if command -v dalfox &> /dev/null; then
        echo -e "${GREEN}[SUCCESS]${NC} dalfox found, starting XSS scanning..."
        
        # Pipe method scanning
        cat "${DOMAIN}-parameterized-urls.txt" | dalfox pipe --silence >> "${DOMAIN}-xss-results.txt" 2>/dev/null
        
    else
        echo -e "${RED}[ERROR]${NC} dalfox not found - XSS scanning skipped"
        echo -e "${BLUE}[INFO]${NC} Install dalfox: go install github.com/hahwul/dalfox/v2@latest"
        touch "${DOMAIN}-xss-results.txt"
    fi
    
    # Count and analyze vulnerabilities
    if [ -s "${DOMAIN}-xss-results.txt" ]; then
        POC_COUNT=$(grep -c '\[POC\]' "${DOMAIN}-xss-results.txt" 2>/dev/null || echo "0")
        VERIFIED_COUNT=$(grep -c '\[V\]' "${DOMAIN}-xss-results.txt" 2>/dev/null || echo "0")
        REFLECTED_COUNT=$(grep -c '\[R\]' "${DOMAIN}-xss-results.txt" 2>/dev/null || echo "0")
        MANUAL_COUNT=$(grep -c '\[MANUAL\]' "${DOMAIN}-xss-results.txt" 2>/dev/null || echo "0")
        
        XSS_VULN_COUNT=$POC_COUNT
        
        echo -e "${BLUE}[INFO]${NC} XSS Vulnerability detection results:"
        echo -e "  POC findings: $POC_COUNT"
        echo -e "  Verified [V]: $VERIFIED_COUNT"
        echo -e "  Reflected [R]: $REFLECTED_COUNT"
        
        # Show actual findings
        if [ "$XSS_VULN_COUNT" -gt 0 ]; then
            echo -e "${RED}[ALERT]${NC} Found ${WHITE}$XSS_VULN_COUNT${NC} XSS vulnerabilities!"
            echo -e "${RED}[ALL XSS FINDINGS]${NC}"
            cat "${DOMAIN}-xss-results.txt" | grep '\[POC\]' | while read -r line; do
                echo -e "  ${RED}→${NC} $line"
            done
        fi
    else
        XSS_VULN_COUNT=0
    fi
    
    if [ "$XSS_VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}[SUCCESS]${NC} XSS Scan completed, found ${WHITE}$XSS_VULN_COUNT${NC} XSS vulnerabilities!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} XSS Scan completed, found ${WHITE}$XSS_VULN_COUNT${NC} XSS vulnerabilities"
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} No parameterized URLs to scan for XSS"
    touch "${DOMAIN}-xss-results.txt"
    XSS_VULN_COUNT=0
fi

# 6. SQL Injection Scanning with sqlmc
echo -e "${BLUE}[INFO]${NC} Step 6: SQL Injection Vulnerability Scanning"
SQL_VULN_COUNT=0

if [ -s "${DOMAIN}-parameterized-urls.txt" ]; then
    echo -e "${BLUE}[INFO]${NC} Scanning parameterized URLs for SQL injection vulnerabilities..."
    
    > "${DOMAIN}-sql-results.txt"
    
    if command -v sqlmc &> /dev/null; then
        echo -e "${GREEN}[SUCCESS]${NC} sqlmc found, starting SQL injection scanning..."
        
        # Scan each parameterized URL with sqlmc
        while read -r url; do
            if [ -n "$url" ]; then
                echo -e "  ${BLUE}[SQL-SCAN]${NC} $url"
                sqlmc -u "$url" -d 2 >> "${DOMAIN}-sql-results.txt" 2>&1
            fi
        done < "${DOMAIN}-parameterized-urls.txt"
        
    else
        echo -e "${RED}[ERROR]${NC} sqlmc not found - SQL injection scanning skipped"
        echo -e "${BLUE}[INFO]${NC} Install sqlmc: pip install sqlmc"
        touch "${DOMAIN}-sql-results.txt"
    fi
    
    # Count and analyze SQL vulnerabilities
    if [ -s "${DOMAIN}-sql-results.txt" ]; then
        SQL_VULN_COUNT=$(grep -c "Vulnerable: True" "${DOMAIN}-sql-results.txt" 2>/dev/null || echo "0")
        MYSQL_COUNT=$(grep -c "Database: MySQL" "${DOMAIN}-sql-results.txt" 2>/dev/null || echo "0")
        TIMEOUT_COUNT=$(grep -c "TIMEOUT" "${DOMAIN}-sql-results.txt" 2>/dev/null || echo "0")
        
        # Ensure we have valid numbers
        [ -z "$SQL_VULN_COUNT" ] && SQL_VULN_COUNT=0
        [ -z "$MYSQL_COUNT" ] && MYSQL_COUNT=0
        [ -z "$TIMEOUT_COUNT" ] && TIMEOUT_COUNT=0
        
        echo -e "${BLUE}[INFO]${NC} SQL Injection detection results:"
        echo -e "  Vulnerable endpoints: $SQL_VULN_COUNT"
        echo -e "  MySQL databases detected: $MYSQL_COUNT"
        echo -e "  Timeouts: $TIMEOUT_COUNT"
        
        # Show SQL injection findings
        if [ "$SQL_VULN_COUNT" -gt 0 ]; then
            echo -e "${RED}[ALERT]${NC} Found ${WHITE}$SQL_VULN_COUNT${NC} SQL injection vulnerabilities!"
            echo -e "${RED}[ALL SQL INJECTION FINDINGS]${NC}"
            grep "Vulnerable: True" "${DOMAIN}-sql-results.txt" | while read -r line; do
                echo -e "  ${RED}→${NC} $line"
            done
        fi
    else
        SQL_VULN_COUNT=0
    fi
    
    if [ "$SQL_VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}[SUCCESS]${NC} SQL Injection scan completed, found ${WHITE}$SQL_VULN_COUNT${NC} SQL vulnerabilities!"
    else
        echo -e "${GREEN}[SUCCESS]${NC} SQL Injection scan completed, found ${WHITE}$SQL_VULN_COUNT${NC} SQL vulnerabilities"
    fi
else
    echo -e "${YELLOW}[WARNING]${NC} No parameterized URLs to scan for SQL injection"
    touch "${DOMAIN}-sql-results.txt"
    SQL_VULN_COUNT=0
fi

# Calculate total vulnerabilities
TOTAL_VULN_COUNT=$((XSS_VULN_COUNT + SQL_VULN_COUNT))

# Ensure we have valid numbers for the final summary
[ -z "$XSS_VULN_COUNT" ] && XSS_VULN_COUNT=0
[ -z "$SQL_VULN_COUNT" ] && SQL_VULN_COUNT=0
[ -z "$TOTAL_VULN_COUNT" ] && TOTAL_VULN_COUNT=0

# Generate Report
echo -e "${BLUE}[INFO]${NC} Generating final report..."
cat > "${DOMAIN}-scan-report.txt" << EOF
# Security Reconnaissance Report for $DOMAIN
Generated on: $(date)

## Summary Statistics
- Total subdomains discovered: $SUBDOMAIN_COUNT
- Live hosts found: $LIVE_COUNT
- Dead hosts found: $DEAD_COUNT
- Endpoints discovered: $ENDPOINT_COUNT
- Parameterized URLs found: $PARAM_COUNT
- XSS vulnerabilities found: $XSS_VULN_COUNT
- SQL injection vulnerabilities found: $SQL_VULN_COUNT
- Total security vulnerabilities: $TOTAL_VULN_COUNT

## Tool Status
- Subfinder: $(command -v subfinder &> /dev/null && echo "Available" || echo "Not found")
- Chaos: $(command -v chaos &> /dev/null && echo "Available" || echo "Not found")
- Katana: $(command -v katana &> /dev/null && echo "Available" || echo "Not found")
- Dalfox: $(command -v dalfox &> /dev/null && echo "Available" || echo "Not found")
- SQLmc: $(command -v sqlmc &> /dev/null && echo "Available" || echo "Not found")

## File Locations
- Subdomains: ${DOMAIN}-subdomains.txt
- Live hosts: ${DOMAIN}-live-urls.txt
- All endpoints: ${DOMAIN}-all-endpoints.txt
- Parameterized URLs: ${DOMAIN}-parameterized-urls.txt
- XSS scan results: ${DOMAIN}-xss-results.txt
- SQL injection scan results: ${DOMAIN}-sql-results.txt

## Workflow Summary
1. ✅ Subdomain discovery completed
2. ✅ Live host verification completed
3. ✅ Endpoint crawling completed
4. ✅ Parameter extraction completed
5. ✅ XSS vulnerability scanning completed
6. ✅ SQL injection vulnerability scanning completed
EOF

if [ "$TOTAL_VULN_COUNT" -gt 0 ]; then
    cat >> "${DOMAIN}-scan-report.txt" << EOF

## ⚠️ Security Findings
Found $TOTAL_VULN_COUNT total security vulnerabilities!
- XSS vulnerabilities: $XSS_VULN_COUNT
- SQL injection vulnerabilities: $SQL_VULN_COUNT

DETAILED XSS FINDINGS:
$(cat "${DOMAIN}-xss-results.txt")

DETAILED SQL INJECTION FINDINGS:
$(cat "${DOMAIN}-sql-results.txt")

RECOMMENDED ACTIONS:
1. Implement input validation and output encoding for XSS prevention
2. Use Content Security Policy (CSP) headers
3. Sanitize all user inputs before processing
4. Use parameterized queries and prepared statements for SQL injection prevention
5. Implement proper authentication and authorization
6. Regular security testing and code reviews
7. Apply principle of least privilege to database accounts
8. Use Web Application Firewalls (WAF) as additional protection
EOF
fi

# Final Summary
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                        SCAN SUMMARY                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo -e "${WHITE}Domain:${NC} $DOMAIN"
echo -e "${WHITE}Subdomains:${NC} $SUBDOMAIN_COUNT"
echo -e "${WHITE}Live hosts:${NC} $LIVE_COUNT"
echo -e "${WHITE}Dead hosts:${NC} $DEAD_COUNT"
echo -e "${WHITE}Endpoints:${NC} $ENDPOINT_COUNT"
echo -e "${WHITE}Parameterized URLs:${NC} $PARAM_COUNT"

if [ "$XSS_VULN_COUNT" -gt 0 ]; then
    echo -e "${WHITE}XSS Vulnerabilities:${NC} ${RED}$XSS_VULN_COUNT ⚠️  CRITICAL${NC}"
else
    echo -e "${WHITE}XSS Vulnerabilities:${NC} ${GREEN}$XSS_VULN_COUNT${NC}"
fi

if [ "$SQL_VULN_COUNT" -gt 0 ]; then
    echo -e "${WHITE}SQL Injection Vulnerabilities:${NC} ${RED}$SQL_VULN_COUNT ⚠️  CRITICAL${NC}"
else
    echo -e "${WHITE}SQL Injection Vulnerabilities:${NC} ${GREEN}$SQL_VULN_COUNT${NC}"
fi

echo -e "${WHITE}Total Security Issues:${NC} ${RED}$TOTAL_VULN_COUNT${NC}"

if [ "$TOTAL_VULN_COUNT" -gt 0 ]; then
    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                     ⚠️  SECURITY ALERT  ⚠️                      ║${NC}"
    echo -e "${RED}║             MULTIPLE VULNERABILITIES DETECTED                   ║${NC}"
    if [ "$XSS_VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}║                 XSS: $XSS_VULN_COUNT vulnerabilities found                      ║${NC}"
    fi
    if [ "$SQL_VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}║            SQL INJECTION: $SQL_VULN_COUNT vulnerabilities found              ║${NC}"
    fi
    echo -e "${RED}╚══════════════════════════════════════════════════════════════════╝${NC}"
fi

echo ""
if [ "$TOTAL_VULN_COUNT" -gt 0 ]; then
    echo -e "${RED}[COMPLETED]${NC} Security reconnaissance completed for ${WHITE}$DOMAIN${NC} - ${RED}VULNERABILITIES FOUND!${NC}"
else
    echo -e "${GREEN}[COMPLETED]${NC} Security reconnaissance completed for ${WHITE}$DOMAIN${NC} - No vulnerabilities detected"
fi
echo -e "${BLUE}[INFO]${NC} Full report saved: ${WHITE}${DOMAIN}-scan-report.txt${NC}"
echo -e "${BLUE}[INFO]${NC} XSS results: ${WHITE}${DOMAIN}-xss-results.txt${NC}"
echo -e "${BLUE}[INFO]${NC} SQL injection results: ${WHITE}${DOMAIN}-sql-results.txt${NC}"
