#!/bin/bash

# =====================================================
# NIDS Uptime Monitor & Logger
# =====================================================
# Purpose: Track service uptime and log failures
# Usage: Run via cron every 5 minutes
# Cron: */5 * * * * /path/to/uptime-monitor.sh
# Logs: /var/log/nids-uptime.log
# =====================================================

set -euo pipefail

# Configuration
LOG_FILE="/var/log/nids-uptime.log"
STATUS_FILE="/tmp/nids-status.json"
ALERT_EMAIL=""  # Set to receive email alerts (requires mailutils)

# Services to monitor
declare -A SERVICES=(
    ["suricata"]="critical"
    ["wazuh-agent"]="critical"
    ["pihole-FTL"]="important"
    ["nginx"]="important"
)

# =====================================================
# Helper Functions
# =====================================================

log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_FILE"
}

send_alert() {
    local message=$1
    
    # Log to file
    log_message "ALERT" "$message"
    
    # Send email if configured
    if [[ -n "$ALERT_EMAIL" ]] && command -v mail &> /dev/null; then
        echo "$message" | mail -s "NIDS Alert: Service Failure" "$ALERT_EMAIL"
    fi
}

# =====================================================
# Service Monitoring
# =====================================================

check_services() {
    local all_ok=true
    local status_json="{"
    local failed_services=()
    
    for service in "${!SERVICES[@]}"; do
        local priority="${SERVICES[$service]}"
        
        if systemctl is-active --quiet "$service"; then
            status_json+="\"$service\":\"up\","
            log_message "INFO" "$service is running"
        else
            status_json+="\"$service\":\"down\","
            all_ok=false
            failed_services+=("$service ($priority)")
            
            if [[ "$priority" == "critical" ]]; then
                send_alert "CRITICAL: $service is not running!"
            else
                log_message "WARN" "$service is not running (priority: $priority)"
            fi
        fi
    done
    
    # Check additional metrics
    local cpu_temp="N/A"
    if command -v vcgencmd &> /dev/null; then
        cpu_temp=$(vcgencmd measure_temp | grep -oP '\d+\.\d+')
    fi
    
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    local disk_usage=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    # Build JSON status
    status_json+="\"timestamp\":\"$(date -Iseconds)\","
    status_json+="\"uptime\":\"$(uptime -p)\","
    status_json+="\"cpu_temp\":\"$cpu_temp\","
    status_json+="\"mem_usage\":\"$mem_usage\","
    status_json+="\"disk_usage\":\"$disk_usage\""
    status_json+="}"
    
    # Save status to file
    echo "$status_json" > "$STATUS_FILE"
    
    # Log summary
    if $all_ok; then
        log_message "INFO" "All services operational"
    else
        log_message "ERROR" "Failed services: ${failed_services[*]}"
    fi
}

# =====================================================
# Uptime Calculation
# =====================================================

calculate_uptime() {
    if [[ ! -f "$LOG_FILE" ]]; then
        echo "No uptime data available yet"
        return
    fi
    
    local total_checks=$(grep -c "INFO.*All services operational" "$LOG_FILE" 2>/dev/null | tr -d "\n" || echo 0)
    local failed_checks=$(grep -c "ERROR.*Failed services" "$LOG_FILE" 2>/dev/null | tr -d "\n" || echo 0)
    local total=$((${total_checks:-0} + ${failed_checks:-0}))
    
    if [[ $total -eq 0 ]]; then
        echo "No checks recorded yet"
        return
    fi
    
    local uptime_pct=$(awk "BEGIN {printf \"%.2f\", ($total_checks / $total) * 100}")
    
    echo "=== UPTIME STATISTICS ==="
    echo "Total checks: $total"
    echo "Successful: $total_checks"
    echo "Failed: $failed_checks"
    echo "Uptime: ${uptime_pct}%"
    echo "Period: $(head -1 "$LOG_FILE" | awk '{print $1, $2}') to $(tail -1 "$LOG_FILE" | awk '{print $1, $2}')"
}

# =====================================================
# Service Recovery
# =====================================================

attempt_recovery() {
    local service=$1
    
    log_message "WARN" "Attempting to restart $service..."
    
    if systemctl restart "$service"; then
        log_message "INFO" "Successfully restarted $service"
        send_alert "Recovery: $service has been restarted and is now running"
        return 0
    else
        send_alert "CRITICAL: Failed to restart $service - manual intervention required"
        return 1
    fi
}

# =====================================================
# Main Execution
# =====================================================

main() {
    # Ensure log file exists
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 644 "$LOG_FILE"
        log_message "INFO" "Uptime monitoring started"
    fi
    
    # Check if running as root (required for service checks)
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root (use sudo or cron with root)"
        exit 1
    fi
    
    # Parse arguments
    case "${1:-monitor}" in
        monitor)
            check_services
            ;;
        status)
            if [[ -f "$STATUS_FILE" ]]; then
                cat "$STATUS_FILE" | jq '.' 2>/dev/null || cat "$STATUS_FILE"
            else
                echo "No status data available. Run monitor first."
            fi
            ;;
        stats)
            calculate_uptime
            ;;
        recover)
            if [[ -z "${2:-}" ]]; then
                echo "Usage: $0 recover <service-name>"
                exit 1
            fi
            attempt_recovery "$2"
            ;;
        log)
            tail -n 50 "$LOG_FILE"
            ;;
        help)
            cat << 'EOF'
NIDS Uptime Monitor

Usage:
  uptime-monitor.sh [COMMAND]

Commands:
  monitor    Run monitoring check (default, use in cron)
  status     Show current system status
  stats      Calculate uptime statistics
  recover    Attempt to restart a service
  log        Show recent log entries
  help       Show this help message

Examples:
  # Run monitoring check
  sudo ./uptime-monitor.sh monitor

  # View current status
  ./uptime-monitor.sh status

  # Calculate uptime
  ./uptime-monitor.sh stats

  # Attempt service recovery
  sudo ./uptime-monitor.sh recover suricata

  # View logs
  ./uptime-monitor.sh log

Cron Setup (run every 5 minutes):
  */5 * * * * /opt/nids/scripts/uptime-monitor.sh monitor

Email Alerts:
  Set ALERT_EMAIL variable in script to receive email notifications
  Requires: sudo apt install mailutils
EOF
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"
