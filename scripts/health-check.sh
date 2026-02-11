#!/bin/bash

# =====================================================
# NIDS Sensor Health Check Script
# =====================================================
# Purpose: Verify operational status of all security components
# Usage: ./health-check.sh [--json] [--quiet]
# Output: Human-readable or JSON format status report
# Exit codes: 0 = healthy, 1 = degraded, 2 = critical
# =====================================================

set -euo pipefail

# Color codes for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERFACE="eth0"
SURICATA_EVE_LOG="/var/log/suricata/eve.json"
WAZUH_LOG="/var/ossec/logs/ossec.log"

# Counters
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARNING=0

# Parse arguments
JSON_OUTPUT=false
QUIET_MODE=false

for arg in "$@"; do
    case $arg in
        --json)
            JSON_OUTPUT=true
            ;;
        --quiet|-q)
            QUIET_MODE=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --json       Output results in JSON format"
            echo "  --quiet, -q  Suppress non-critical output"
            echo "  --help, -h   Show this help message"
            exit 0
            ;;
    esac
done

# =====================================================
# Helper Functions
# =====================================================

print_header() {
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}$1${NC}"
        echo -e "${BLUE}========================================${NC}"
    fi
}

print_check() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "${BLUE}[$CHECKS_TOTAL] $1${NC}"
    fi
}

print_pass() {
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "${GREEN}✓ $1${NC}"
    fi
}

print_fail() {
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "${RED}✗ $1${NC}"
    fi
}

print_warn() {
    CHECKS_WARNING=$((CHECKS_WARNING + 1))
    if [[ "$QUIET_MODE" == false ]]; then
        echo -e "${YELLOW}⚠ $1${NC}"
    fi
}

# =====================================================
# Health Check Functions
# =====================================================

check_suricata() {
    print_check "Checking Suricata NIDS Engine..."
    
    if systemctl is-active --quiet suricata; then
        print_pass "Suricata: ACTIVE"
        
        # Check rule count
        if command -v suricatasc &> /dev/null; then
            RULE_COUNT=$(suricatasc -c ruleset-stats 2>/dev/null | grep -oP 'loaded": \K[0-9]+' | head -1 || echo "0")
            if [[ "$RULE_COUNT" -gt 40000 ]]; then
                print_pass "Rules loaded: $RULE_COUNT signatures"
            else
                print_warn "Rules loaded: $RULE_COUNT (expected >40,000)"
            fi
        fi
        
        return 0
    else
        print_fail "Suricata: NOT RUNNING"
        return 1
    fi
}

check_wazuh() {
    print_check "Checking Wazuh Agent Status..."
    
    if systemctl is-active --quiet wazuh-agent; then
        print_pass "Wazuh Agent: ACTIVE"
        
        # Check last connection
        if [[ -f "$WAZUH_LOG" ]]; then
            LAST_CONN=$(grep "Connected to" "$WAZUH_LOG" 2>/dev/null | tail -1 | awk '{print $1, $2}' || echo "Unknown")
            if [[ "$LAST_CONN" != "Unknown" ]]; then
                print_pass "Last connection: $LAST_CONN"
            fi
        fi
        
        return 0
    else
        print_fail "Wazuh Agent: NOT RUNNING"
        return 1
    fi
}

check_network() {
    print_check "Verifying Network Interface..."
    
    if ip link show "$INTERFACE" &> /dev/null; then
        if ip link show "$INTERFACE" | grep -q "state UP"; then
            print_pass "Interface $INTERFACE: UP"
            
            # Check promiscuous mode (for SPAN port)
            if ip link show "$INTERFACE" | grep -q "PROMISC"; then
                print_pass "Promiscuous mode: ENABLED (SPAN active)"
            else
                print_warn "Promiscuous mode: DISABLED (not capturing mirrored traffic)"
            fi
            
            return 0
        else
            print_fail "Interface $INTERFACE: DOWN"
            return 1
        fi
    else
        print_fail "Interface $INTERFACE: NOT FOUND"
        return 1
    fi
}

check_logs() {
    print_check "Verifying Log Generation..."
    
    if [[ -f "$SURICATA_EVE_LOG" ]]; then
        LOG_SIZE=$(du -h "$SURICATA_EVE_LOG" | cut -f1)
        LOG_AGE=$(($(date +%s) - $(stat -c %Y "$SURICATA_EVE_LOG")))
        
        print_pass "Eve.json size: $LOG_SIZE"
        
        if [[ $LOG_AGE -lt 300 ]]; then  # Less than 5 minutes old
            print_pass "Last modified: $LOG_AGE seconds ago (active)"
        else
            print_warn "Last modified: $LOG_AGE seconds ago (stale?)"
        fi
        
        return 0
    else
        print_fail "Eve.json: NOT FOUND"
        return 1
    fi
}

check_pihole() {
    print_check "Checking Pi-hole DNS Filter..."
    
    if systemctl is-active --quiet pihole-FTL; then
        print_pass "Pi-hole FTL: ACTIVE"
        
        # Check if web interface is accessible
        if curl -sf http://localhost:8080/admin/ &> /dev/null; then
            print_pass "Web interface: ACCESSIBLE (port 8080)"
        fi
        
        return 0
    else
        print_warn "Pi-hole FTL: NOT RUNNING (optional component)"
        return 0  # Not critical
    fi
}

check_nginx() {
    print_check "Checking Nginx Reverse Proxy..."
    
    if systemctl is-active --quiet nginx; then
        print_pass "Nginx: ACTIVE"
        
        # Test configuration
        if nginx -t &> /dev/null; then
            print_pass "Configuration: VALID"
        else
            print_warn "Configuration: ISSUES DETECTED"
        fi
        
        return 0
    else
        print_warn "Nginx: NOT RUNNING (optional component)"
        return 0  # Not critical
    fi
}

check_system_resources() {
    print_check "Checking System Resources..."
    
    # CPU temperature (Raspberry Pi specific)
    if command -v vcgencmd &> /dev/null; then
        TEMP=$(vcgencmd measure_temp | grep -oP '\d+\.\d+')
        if (( $(echo "$TEMP < 70" | bc -l) )); then
            print_pass "CPU Temperature: ${TEMP}°C (normal)"
        elif (( $(echo "$TEMP < 80" | bc -l) )); then
            print_warn "CPU Temperature: ${TEMP}°C (elevated)"
        else
            print_fail "CPU Temperature: ${TEMP}°C (critical!)"
        fi
    fi
    
    # Memory usage
    MEM_USAGE=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    if [[ $MEM_USAGE -lt 80 ]]; then
        print_pass "Memory usage: ${MEM_USAGE}% (normal)"
    else
        print_warn "Memory usage: ${MEM_USAGE}% (high)"
    fi
    
    # Disk space
    DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [[ $DISK_USAGE -lt 80 ]]; then
        print_pass "Disk usage: ${DISK_USAGE}% (normal)"
    else
        print_warn "Disk usage: ${DISK_USAGE}% (high)"
    fi
}

# =====================================================
# Main Execution
# =====================================================

main() {
    START_TIME=$(date +%s)
    
    if [[ "$JSON_OUTPUT" == false ]]; then
        print_header "NIDS SENSOR HEALTH CHECK"
        echo "Timestamp: $(date)"
        echo ""
    fi
    
    # Run all checks
    check_suricata
    echo ""
    check_wazuh
    echo ""
    check_network
    echo ""
    check_logs
    echo ""
    check_pihole
    echo ""
    check_nginx
    echo ""
    check_system_resources
    
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    
    # Determine overall status
    if [[ $CHECKS_FAILED -gt 0 ]]; then
        STATUS="CRITICAL"
        EXIT_CODE=2
    elif [[ $CHECKS_WARNING -gt 0 ]]; then
        STATUS="DEGRADED"
        EXIT_CODE=1
    else
        STATUS="HEALTHY"
        EXIT_CODE=0
    fi
    
    # Output results
    if [[ "$JSON_OUTPUT" == true ]]; then
        cat << EOF
{
  "timestamp": "$(date -Iseconds)",
  "status": "$STATUS",
  "checks": {
    "total": $CHECKS_TOTAL,
    "passed": $CHECKS_PASSED,
    "failed": $CHECKS_FAILED,
    "warnings": $CHECKS_WARNING
  },
  "duration_seconds": $DURATION
}
EOF
    else
        echo ""
        echo -e "${BLUE}========================================${NC}"
        echo -e "${BLUE}HEALTH CHECK SUMMARY${NC}"
        echo -e "${BLUE}========================================${NC}"
        echo "Status: $STATUS"
        echo "Total checks: $CHECKS_TOTAL"
        echo "Passed: $CHECKS_PASSED"
        echo "Failed: $CHECKS_FAILED"
        echo "Warnings: $CHECKS_WARNING"
        echo "Duration: ${DURATION}s"
        echo ""
        
        if [[ "$STATUS" == "HEALTHY" ]]; then
            echo -e "${GREEN}✓ All critical systems operational${NC}"
        elif [[ "$STATUS" == "DEGRADED" ]]; then
            echo -e "${YELLOW}⚠ System operational with warnings${NC}"
        else
            echo -e "${RED}✗ Critical failures detected${NC}"
        fi
    fi
    
    exit $EXIT_CODE
}

# Run main function
main
