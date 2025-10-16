#!/bin/bash

###############################################################################
# Imunify360 Ansible Configuration Validation Script
# Validates both main.yml and imunify_firewall.yml configurations
###############################################################################

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Timeout for imunify360-agent commands
TIMEOUT=10

# Output functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_pass() {
    echo -e "${GREEN}✓ PASS:${NC} $1"
    ((PASS_COUNT++))
}

print_fail() {
    echo -e "${RED}✗ FAIL:${NC} $1"
    ((FAIL_COUNT++))
}

print_warn() {
    echo -e "${YELLOW}⚠ WARN:${NC} $1"
    ((WARN_COUNT++))
}

print_info() {
    echo -e "${BLUE}ℹ INFO:${NC} $1"
}

###############################################################################
# Helper function to get config value using jq
###############################################################################
get_config_value() {
    local path=$1
    echo "$IMUNIFY_CONFIG" | jq -r "$path" 2>/dev/null
}

###############################################################################
# Load Imunify360 Configuration
###############################################################################
load_imunify_config() {
    print_info "Loading Imunify360 configuration..."
    
    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_fail "jq is not installed. Please install jq to run this script."
        echo "Install with: apt-get install jq (Debian/Ubuntu) or yum install jq (CentOS/RHEL)"
        exit 1
    fi
    
    # Check if imunify360-agent command exists
    if ! command -v imunify360-agent &> /dev/null; then
        print_fail "imunify360-agent command not found"
        echo "Please ensure Imunify360 is installed and the command is in PATH"
        exit 1
    fi
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_fail "This script must be run as root to access Imunify360 configuration"
        echo "Please run with: sudo $0"
        exit 1
    fi
    
    # Check if Imunify360 service is running
    if ! systemctl is-active --quiet imunify360 2>/dev/null; then
        print_warn "Imunify360 service is not running. Attempting to retrieve config anyway..."
    fi
    
    # Get config with timeout
    print_info "Executing: imunify360-agent config show --json (timeout: ${TIMEOUT}s)"
    IMUNIFY_CONFIG=$(timeout $TIMEOUT imunify360-agent config show --json 2>&1)
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 124 ]; then
        print_fail "Command timed out after ${TIMEOUT} seconds"
        echo "The imunify360-agent is taking too long to respond."
        echo "Try increasing the timeout or check if the service is healthy."
        exit 1
    elif [ $EXIT_CODE -ne 0 ]; then
        print_fail "Failed to retrieve Imunify360 configuration (exit code: $EXIT_CODE)"
        echo ""
        echo "Error output:"
        echo "$IMUNIFY_CONFIG"
        echo ""
        echo "Troubleshooting:"
        echo "1. Check if Imunify360 is properly installed: imunify360-agent version"
        echo "2. Check service status: systemctl status imunify360"
        echo "3. Try running manually: imunify360-agent config show --json"
        exit 1
    elif [ -z "$IMUNIFY_CONFIG" ]; then
        print_fail "Imunify360 returned empty configuration"
        exit 1
    fi
    
    # Validate JSON
    if ! echo "$IMUNIFY_CONFIG" | jq empty 2>/dev/null; then
        print_fail "Invalid JSON received from imunify360-agent"
        echo "Output received:"
        echo "$IMUNIFY_CONFIG" | head -20
        exit 1
    fi
    
    print_pass "Configuration loaded successfully"
    echo ""
}

###############################################################################
# Check A1: main.yml - GPG Keys
###############################################################################
check_gpg_keys() {
    print_header "A1. GPG Repository Keys (main.yml)"
    
    if [ -f /etc/apt/trusted.gpg.d/RPM-GPG-KEY-CloudLinux.gpg ]; then
        print_pass "CloudLinux GPG key is installed"
    else
        print_fail "CloudLinux GPG key is missing"
    fi
    echo ""
}

###############################################################################
# Check A2: main.yml - Duplicate Repo Removed
###############################################################################
check_duplicate_repo() {
    print_header "A2. Duplicate Repository Removal (main.yml)"
    
    if [ ! -f /etc/apt/sources.list.d/imunify-cloudways.list ]; then
        print_pass "Duplicate imunify-cloudways.list is removed"
    else
        print_fail "Duplicate imunify-cloudways.list still exists"
    fi
    echo ""
}

###############################################################################
# Check A3: main.yml - modsecurity-crs Removed
###############################################################################
check_modsecurity_crs() {
    print_header "A3. modsecurity-crs Package (main.yml)"
    
    if ! dpkg -l | grep -q modsecurity-crs 2>/dev/null; then
        print_pass "modsecurity-crs package is removed"
    else
        print_fail "modsecurity-crs package is still installed"
    fi
    echo ""
}

###############################################################################
# Check A4: main.yml - Whitelist Directory
###############################################################################
check_whitelist_directory() {
    print_header "A4. Whitelist Directory (main.yml)"
    
    if [ -d /etc/imunify360/whitelist ]; then
        print_pass "Whitelist directory exists"
        
        # Check permissions
        PERMS=$(stat -c %a /etc/imunify360/whitelist 2>/dev/null)
        if [ "$PERMS" == "755" ]; then
            print_pass "Whitelist directory permissions are correct (755)"
        else
            print_fail "Whitelist directory permissions are $PERMS (expected 755)"
        fi
    else
        print_fail "Whitelist directory does not exist"
    fi
    echo ""
}

###############################################################################
# Check A5: main.yml - Apache imunify360.conf Removed
###############################################################################
check_apache_imunify_conf() {
    print_header "A5. Apache imunify360.conf Removal (main.yml)"
    
    if [ ! -L /etc/apache2/conf-enabled/imunify360.conf ]; then
        print_pass "Apache imunify360.conf symlink is removed"
    else
        print_fail "Apache imunify360.conf symlink still exists"
    fi
    echo ""
}

###############################################################################
# Check A6: main.yml - Configuration Files
###############################################################################
check_config_files() {
    print_header "A6. Configuration Files (main.yml)"
    
    declare -A config_files=(
        ["/etc/modsecurity/modsecurity.conf"]="ModSecurity config"
        ["/etc/monit/conf.cloudways/imunify360.conf"]="Monit config"
        ["/etc/monit/services.cloudways/imunify360"]="Monit service"
        ["/etc/imunify360/whitelist/cloudways.txt"]="Cloudways whitelist"
        ["/etc/imunify360/whitelist/api-gateway.txt"]="API Gateway whitelist"
        ["/etc/nginx/conf.d/imunify360.conf"]="Nginx config"
    )
    
    for file in "${!config_files[@]}"; do
        if [ -f "$file" ]; then
            print_pass "${config_files[$file]} exists: $file"
        else
            print_fail "${config_files[$file]} missing: $file"
        fi
    done
    echo ""
}

###############################################################################
# Check A7: main.yml - Admin User Configuration
###############################################################################
check_admin_user() {
    print_header "A7. Admin User Configuration (main.yml)"
    
    if [ -f /etc/sysconfig/imunify360/auth.admin ]; then
        ADMIN_USER=$(cat /etc/sysconfig/imunify360/auth.admin 2>/dev/null | tr -d '\n')
        if [ "$ADMIN_USER" == "platformops" ]; then
            print_pass "Admin user is set to 'platformops'"
        else
            print_fail "Admin user is '$ADMIN_USER' (expected 'platformops')"
        fi
    else
        print_fail "Admin user configuration file not found"
    fi
    echo ""
}

###############################################################################
# Check A8: main.yml - Shorewall Rules
###############################################################################
check_shorewall_rules() {
    print_header "A8. Shorewall Rules (main.yml)"
    
    if [ -f /etc/shorewall/rules ]; then
        print_info "Checking Shorewall rules..."
        
        # Check for MW rules
        declare -a mw_ips=(
            "54.85.213.165"
            "52.5.120.0"
            "34.206.160.85"
            "3.226.139.209"
            "52.201.17.112"
        )
        
        for ip in "${mw_ips[@]}"; do
            if grep -q "$ip" /etc/shorewall/rules; then
                print_pass "Shorewall rule exists for $ip"
            else
                print_warn "Shorewall rule missing for $ip"
            fi
        done
        
        # Check for staging-specific rules
        HOSTNAME=$(hostname)
        if [[ "$HOSTNAME" == *"cloudwaysstagingapps.com"* ]]; then
            if grep -q "3.22.200.253" /etc/shorewall/rules; then
                print_pass "Staging-specific rule exists (3.22.200.253)"
            else
                print_fail "Staging-specific rule missing"
            fi
        fi
    else
        print_warn "Shorewall rules file not found"
    fi
    echo ""
}

###############################################################################
# Check A9: main.yml - Imunify License
###############################################################################
check_imunify_license() {
    print_header "A9. Imunify License (main.yml)"
    
    LICENSE_STATUS=$(get_config_value '.license.status')
    if [ "$LICENSE_STATUS" == "true" ]; then
        print_pass "Imunify360 license is active"
        
        LICENSE_TYPE=$(get_config_value '.license.license_type')
        print_info "License type: $LICENSE_TYPE"
        
        LICENSE_ID=$(get_config_value '.license.id')
        print_info "License ID: ${LICENSE_ID:0:20}..."
    else
        print_fail "Imunify360 license is not active"
    fi
    echo ""
}

###############################################################################
# Check A10: main.yml - Ansible Facts
###############################################################################
check_ansible_facts() {
    print_header "A10. Ansible Facts (main.yml)"
    
    if [ -f /etc/ansible/facts.d/packages.fact ]; then
        if grep -q "^imunify360=enable" /etc/ansible/facts.d/packages.fact; then
            print_pass "Ansible facts updated with imunify360=enable"
        else
            print_fail "Ansible facts missing imunify360=enable entry"
        fi
    else
        print_fail "Ansible facts file not found"
    fi
    echo ""
}

###############################################################################
# Check B1: imunify_firewall.yml - Build Type
###############################################################################
check_build_type() {
    print_header "B1. Build Type Detection (imunify_firewall.yml)"
    
    if grep -q nginx /etc/sysconfig/imunify360/integration.conf 2>/dev/null; then
        BUILD_TYPE="coraza"
        print_info "Build type: Coraza/Nginx (build_type.rc == 0)"
    else
        BUILD_TYPE="generic_modsec"
        print_info "Build type: Generic ModSec/Apache (build_type.rc != 0)"
    fi
    echo ""
}

###############################################################################
# Check B2: imunify_firewall.yml - Firewall Disabled File
###############################################################################
check_firewall_disabled() {
    print_header "B2. Firewall Disabled File (imunify_firewall.yml)"
    
    if [ ! -f /var/imunify360/firewall_disabled ]; then
        print_pass "Firewall disabled file is removed"
    else
        print_fail "Firewall disabled file exists"
    fi
    echo ""
}

###############################################################################
# Check B3: imunify_firewall.yml - Whitelist Files
###############################################################################
check_whitelist_files() {
    print_header "B3. Whitelist Files (imunify_firewall.yml)"
    
    for file in ALLOW_SSH.txt MYSQL.txt; do
        if [ -f "/etc/imunify360/whitelist/$file" ]; then
            print_pass "Whitelist file exists: $file"
        else
            print_fail "Whitelist file missing: $file"
        fi
    done
    echo ""
}

###############################################################################
# Check B4: imunify_firewall.yml - Coraza Configurations
###############################################################################
check_coraza_configs() {
    print_header "B4. Coraza-Specific Configurations (imunify_firewall.yml)"
    
    if [ "$BUILD_TYPE" == "coraza" ]; then
        # Coraza build - these configs SHOULD exist
        
        # body_limit.conf
        if [ -f /etc/imunify360-wafd/modsecurity.d/body_limit.conf ]; then
            print_pass "Coraza body_limit.conf exists"
        else
            print_fail "Coraza body_limit.conf missing"
        fi
        
        # zz_imunify360.conf disabled
        if [ ! -L /etc/apache2/conf-enabled/zz_imunify360.conf ]; then
            print_pass "zz_imunify360.conf is disabled (Coraza)"
        else
            print_fail "zz_imunify360.conf is still enabled (should be disabled for Coraza)"
        fi
        
        # custom-env.custom
        if [ -f /etc/imunify360-wafd/modsecurity.d/custom-env.custom ]; then
            print_pass "Coraza custom-env.custom exists"
        else
            print_fail "Coraza custom-env.custom missing"
        fi
        
        # Verify Generic ModSec configs DO NOT exist
        if [ ! -L /etc/apache2/conf-enabled/imunify_redirect_page.conf ]; then
            print_pass "Generic ModSec redirect page correctly absent (Coraza build)"
        else
            print_warn "imunify_redirect_page.conf is enabled (unexpected for Coraza)"
        fi
        
    else
        # Generic ModSec build - Coraza configs should NOT exist
        
        if [ ! -f /etc/imunify360-wafd/modsecurity.d/body_limit.conf ]; then
            print_pass "Coraza body_limit.conf correctly absent (Generic ModSec build)"
        else
            print_warn "Coraza body_limit.conf exists (unexpected for Generic ModSec)"
        fi
        
        if [ ! -f /etc/imunify360-wafd/modsecurity.d/custom-env.custom ]; then
            print_pass "Coraza custom-env.custom correctly absent (Generic ModSec build)"
        else
            print_warn "Coraza custom-env.custom exists (unexpected for Generic ModSec)"
        fi
    fi
    echo ""
}

###############################################################################
# Check B5: imunify_firewall.yml - Generic ModSec Configurations
###############################################################################
check_generic_modsec_configs() {
    print_header "B5. Generic ModSec Configurations (imunify_firewall.yml)"
    
    if [ "$BUILD_TYPE" == "generic_modsec" ]; then
        # Generic ModSec build - Apache configs SHOULD exist
        
        # Check if zz_imunify360.conf is enabled (should be enabled for Generic ModSec)
        if [ -L /etc/apache2/conf-enabled/zz_imunify360.conf ]; then
            print_pass "zz_imunify360.conf is enabled (Generic ModSec)"
        else
            print_fail "zz_imunify360.conf is not enabled (should be enabled for Generic ModSec)"
        fi
        
        # Check if imunify_redirect_page.conf file exists in conf-available
        if [ -f /etc/apache2/conf-available/imunify_redirect_page.conf ]; then
            print_pass "imunify_redirect_page.conf file exists in conf-available"
        else
            print_fail "imunify_redirect_page.conf file missing from conf-available"
        fi
        
        # Check if imunify_redirect_page.conf is enabled (symlink exists)
        if [ -L /etc/apache2/conf-enabled/imunify_redirect_page.conf ]; then
            print_pass "imunify_redirect_page.conf is enabled"
        else
            print_fail "imunify_redirect_page.conf is not enabled"
        fi
        
        # Verify WAF daemon configs DO NOT exist (they shouldn't for Generic ModSec)
        if [ ! -f /etc/imunify360-wafd/modsecurity.d/custom-env.conf ]; then
            print_pass "WAF daemon configs correctly absent (Apache-based ModSec)"
        else
            print_warn "WAF daemon custom-env.conf exists (unexpected for Generic ModSec)"
        fi
        
    else
        # Coraza build - Generic ModSec configs should NOT exist
        
        if [ ! -L /etc/apache2/conf-enabled/zz_imunify360.conf ]; then
            print_pass "zz_imunify360.conf correctly disabled (Coraza build)"
        else
            print_warn "zz_imunify360.conf is enabled (unexpected for Coraza)"
        fi
        
        if [ ! -f /etc/apache2/conf-available/imunify_redirect_page.conf ]; then
            print_pass "imunify_redirect_page.conf correctly absent (Coraza build)"
        else
            print_warn "imunify_redirect_page.conf exists (unexpected for Coraza)"
        fi
    fi
    echo ""
}

###############################################################################
# Check B6: imunify_firewall.yml - Apache env Module
###############################################################################
check_apache_env_module() {
    print_header "B6. Apache env Module (imunify_firewall.yml)"
    
    if command -v apache2ctl &> /dev/null; then
        if apache2ctl -M 2>/dev/null | grep -q env_module; then
            print_pass "Apache env_module is enabled"
        else
            print_fail "Apache env_module is not enabled"
        fi
    else
        print_warn "apache2ctl not found"
    fi
    echo ""
}

###############################################################################
# Check B7: imunify_firewall.yml - Memory-Based Configurations
###############################################################################
check_memory_configs() {
    print_header "B7. Memory-Based Configurations (imunify_firewall.yml)"
    
    MEMORY_BYTES=$(free -b | awk '/^Mem:/ {print $2}')
    MEMORY_GB=$(awk "BEGIN {printf \"%.2f\", $MEMORY_BYTES/1073741824}")
    print_info "System Memory: ${MEMORY_GB}GB"
    
    # Get configuration values
    RULESET=$(get_config_value '.items.MOD_SEC.ruleset')
    UNIFIED_LOGGER=$(get_config_value '.items.FIREWALL.unified_access_logger')
    HYPERSCAN=$(get_config_value '.items.MALWARE_SCANNING.hyperscan')
    
    # Check ruleset
    if [ "$MEMORY_BYTES" -gt 2147483648 ]; then
        print_info "Memory > 2GB: Expecting FULL ruleset"
        if [ "$RULESET" == "FULL" ]; then
            print_pass "ModSec ruleset is FULL"
        else
            print_fail "ModSec ruleset is '$RULESET' (expected FULL)"
        fi
    else
        print_info "Memory ≤ 2GB: Expecting MINIMAL ruleset"
        if [ "$RULESET" == "MINIMAL" ]; then
            print_pass "ModSec ruleset is MINIMAL"
        else
            print_fail "ModSec ruleset is '$RULESET' (expected MINIMAL)"
        fi
    fi
    
    # Check unified logger
    if [ "$MEMORY_BYTES" -gt 2147483648 ]; then
        if [ "$UNIFIED_LOGGER" == "true" ]; then
            print_pass "Unified access logger is enabled (high memory)"
        else
            print_fail "Unified access logger is disabled (should be enabled)"
        fi
    else
        if [ "$UNIFIED_LOGGER" == "false" ]; then
            print_pass "Unified access logger is disabled (low memory)"
        else
            print_warn "Unified access logger is enabled (may impact performance)"
        fi
    fi
    
    # Check hyperscan
    if [ "$MEMORY_BYTES" -gt 2147483648 ]; then
        if [ "$HYPERSCAN" == "true" ]; then
            print_pass "Hyperscan is enabled (high memory)"
        else
            print_fail "Hyperscan is disabled (should be enabled)"
        fi
    else
        if [ "$HYPERSCAN" == "false" ]; then
            print_pass "Hyperscan is disabled (low memory)"
        else
            print_warn "Hyperscan is enabled (may consume too much memory)"
        fi
    fi
    echo ""
}

###############################################################################
# Check B8: imunify_firewall.yml - General Configurations
###############################################################################
check_general_configs() {
    print_header "B8. General Imunify Configurations (imunify_firewall.yml)"
    
    # App-specific ruleset
    APP_SPECIFIC=$(get_config_value '.items.MOD_SEC.app_specific_ruleset')
    if [ "$APP_SPECIFIC" == "true" ]; then
        print_pass "App-specific ruleset is enabled"
    else
        print_fail "App-specific ruleset: $APP_SPECIFIC (expected true)"
    fi
    
    # CMS account compromise prevention
    CMS_PREVENTION=$(get_config_value '.items.MOD_SEC.cms_account_compromise_prevention')
    if [ "$CMS_PREVENTION" == "true" ]; then
        print_pass "CMS account compromise prevention is enabled"
    else
        print_fail "CMS prevention: $CMS_PREVENTION (expected true)"
    fi
    
    # WebShield
    WEBSHIELD=$(get_config_value '.items.WEBSHIELD.enable')
    if [ "$WEBSHIELD" == "true" ]; then
        print_pass "WebShield is enabled"
    else
        print_fail "WebShield: $WEBSHIELD (expected true)"
    fi
    
    # Enhanced DOS
    ENHANCED_DOS=$(get_config_value '.items.ENHANCED_DOS.enabled')
    if [ "$ENHANCED_DOS" == "true" ]; then
        print_pass "Enhanced DOS protection is enabled"
    else
        print_fail "Enhanced DOS: $ENHANCED_DOS (expected true)"
    fi
    
    # PAM module
    PAM_ENABLED=$(get_config_value '.items.PAM.enable')
    if [ "$PAM_ENABLED" == "true" ]; then
        print_pass "PAM module is enabled"
    else
        print_fail "PAM module: $PAM_ENABLED (expected true)"
    fi
    echo ""
}

###############################################################################
# Check B9: imunify_firewall.yml - DOS Port Limits
###############################################################################
check_port_limits() {
    print_header "B9. DOS Port Limits (imunify_firewall.yml)"
    
    # Enhanced DOS port limit for 3306
    ENHANCED_LIMIT=$(get_config_value '.items.ENHANCED_DOS.port_limits."3306"')
    if [ "$ENHANCED_LIMIT" == "10000" ]; then
        print_pass "Enhanced DOS port limit for 3306 is 10000"
    else
        print_fail "Enhanced DOS 3306: $ENHANCED_LIMIT (expected 10000)"
    fi
    
    # DOS port limit for 3306
    DOS_LIMIT=$(get_config_value '.items.DOS.port_limits."3306"')
    if [ "$DOS_LIMIT" == "10000" ]; then
        print_pass "DOS port limit for 3306 is 10000"
    else
        print_fail "DOS 3306: $DOS_LIMIT (expected 10000)"
    fi
    echo ""
}

###############################################################################
# Check B10: imunify_firewall.yml - Service Status
###############################################################################
check_services() {
    print_header "B10. Service Status (imunify_firewall.yml)"
    
    # Imunify360 service
    if systemctl is-active --quiet imunify360 2>/dev/null; then
        print_pass "Imunify360 service is running"
    else
        print_fail "Imunify360 service is not running"
    fi
    
    # Imunify360-wafd (if Coraza)
    if [ "$BUILD_TYPE" == "coraza" ]; then
        if systemctl is-active --quiet imunify360-wafd 2>/dev/null; then
            print_pass "Imunify360 WAFD service is running"
        else
            print_fail "Imunify360 WAFD service is not running"
        fi
    fi
    
    # Apache2
    if systemctl is-active --quiet apache2 2>/dev/null; then
        print_pass "Apache2 service is running"
    else
        print_fail "Apache2 service is not running"
    fi
    
    # Nginx (if Coraza)
    if [ "$BUILD_TYPE" == "coraza" ]; then
        if systemctl is-active --quiet nginx 2>/dev/null; then
            print_pass "Nginx service is running"
        else
            print_fail "Nginx service is not running"
        fi
    fi
    echo ""
}

###############################################################################
# Check B11: imunify_firewall.yml - Version
###############################################################################
check_version() {
    print_header "B11. Imunify360 Version (imunify_firewall.yml)"
    
    VERSION=$(get_config_value '.version')
    if [ -n "$VERSION" ] && [ "$VERSION" != "null" ]; then
        print_info "Imunify360 version: $VERSION"
    else
        print_fail "Unable to retrieve version"
    fi
    echo ""
}

###############################################################################
# Summary Report
###############################################################################
print_summary() {
    print_header "Validation Summary"
    
    TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT))
    
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}"
    echo -e "${RED}Failed: $FAIL_COUNT${NC}"
    echo -e "${YELLOW}Warnings: $WARN_COUNT${NC}"
    echo -e "Total Checks: $TOTAL"
    echo ""
    
    if [ $FAIL_COUNT -eq 0 ]; then
        echo -e "${GREEN}✓ All critical checks passed!${NC}"
        exit 0
    else
        echo -e "${RED}✗ Some checks failed. Please review the output above.${NC}"
        exit 1
    fi
}

###############################################################################
# Main Execution
###############################################################################
main() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║  Imunify360 Ansible Configuration Validation Script      ║
║  Validates: main.yml + imunify_firewall.yml              ║
║  Version 3.0                                              ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        print_warn "This script should be run as root for complete validation"
        echo ""
    fi
    
    # Load Imunify360 configuration
    load_imunify_config
    
    # Section A: main.yml checks
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  SECTION A: main.yml Validation${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    check_gpg_keys
    check_duplicate_repo
    check_modsecurity_crs
    check_whitelist_directory
    check_apache_imunify_conf
    check_config_files
    check_admin_user
    check_shorewall_rules
    check_imunify_license
    check_ansible_facts
    
    # Section B: imunify_firewall.yml checks
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  SECTION B: imunify_firewall.yml Validation${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    check_build_type
    check_firewall_disabled
    check_whitelist_files
    check_coraza_configs
    check_generic_modsec_configs
    check_apache_env_module
    check_memory_configs
    check_general_configs
    check_port_limits
    check_services
    check_version
    
    # Print summary
    print_summary
}

# Run main function
main

