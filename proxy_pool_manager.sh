#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - GoProxy Pool Manager
# ============================================================================
# Manages ~1,000 GoProxy instances (ports 4000-4999) with real-time monitoring
# Integrates with PHP APIs for authentication, traffic tracking, and control
# Supports graceful reload, health monitoring, and automatic failover
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config/saas-config.conf"
PROXY_LIST_FILE="${SCRIPT_DIR}/proxy.txt"
PID_DIR="${SCRIPT_DIR}/pids"
LOG_DIR="${SCRIPT_DIR}/logs"

# Default configuration (overridden by config file)
START_PORT=4000
END_PORT=4999
MAX_PROXIES=1000
HEALTH_CHECK_INTERVAL=30
RESTART_DELAY=5

# API endpoints for GoProxy integration (based on working reference)
API_BASE_URL="http://127.0.0.1:8889/api/internal"
AUTH_URL="${API_BASE_URL}/auth.php"
TRAFFIC_URL="${API_BASE_URL}/traffic.php"
CONTROL_URL="${API_BASE_URL}/control.php"

# Output configuration (like reference system)
OUTPUT_HOST="nixproxy.com"  # Change this to your domain
PROXY_OUTPUT_FILE="proxypool.txt"

# GoProxy configuration (enhanced from reference)
AUTH_CACHE_DURATION=300
TRAFFIC_MODE="fast"
TRAFFIC_INTERVAL=5
CONTROL_SLEEP=30
PROXY_START_TIMEOUT=10
MAX_RETRY_ATTEMPTS=3

# Global variables for tracking
STARTED_PROCESSES=""
STARTED_PORTS=""
CLEANUP_ON_EXIT=true

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "${LOG_DIR}/manager.log"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "${LOG_DIR}/manager.log"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "${LOG_DIR}/manager.log"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "${LOG_DIR}/manager.log"
}

# Load configuration
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_info "Configuration loaded from $CONFIG_FILE"
    else
        log_warning "Configuration file not found: $CONFIG_FILE"
    fi
}

# Initialize directories
init_directories() {
    mkdir -p "$PID_DIR" "$LOG_DIR/users" "$LOG_DIR/system"
    log_info "Directories initialized"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if ! command -v proxy >/dev/null 2>&1; then
        missing_deps+=("goproxy")
    fi
    
    if ! command -v curl >/dev/null 2>&1; then
        missing_deps+=("curl")
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

# Validate proxy list file
validate_proxy_list() {
    if [[ ! -f "$PROXY_LIST_FILE" ]]; then
        log_error "Proxy list file not found: $PROXY_LIST_FILE"
        log_error "Please create proxy.txt with upstream proxies (format: host:port:user:pass)"
        exit 1
    fi
    
    local proxy_count=$(grep -v '^#' "$PROXY_LIST_FILE" | grep -v '^$' | wc -l)
    if [[ $proxy_count -eq 0 ]]; then
        log_error "No valid proxies found in $PROXY_LIST_FILE"
        exit 1
    fi
    
    log_info "Found $proxy_count upstream proxies in $PROXY_LIST_FILE"
}

# Parse proxy line and extract components (enhanced from reference)
parse_proxy_line() {
    local proxy_line="$1"
    local -n result=$2

    # Skip comments and empty lines
    if [[ "$proxy_line" =~ ^#.*$ ]] || [[ -z "$proxy_line" ]]; then
        return 1
    fi

    # Parse format: host:port:user:pass (same as reference)
    # Handle complex usernames with colons (like session-based proxies)
    local host port username password

    # Split by colons, but handle complex usernames
    IFS=':' read -ra parts <<< "$proxy_line"

    if [[ ${#parts[@]} -lt 4 ]]; then
        log_warning "Invalid proxy format: $proxy_line (expected host:port:username:password)"
        return 1
    fi

    host="${parts[0]}"
    port="${parts[1]}"

    # Rejoin username parts (in case username contains colons)
    username=""
    for ((i=2; i<${#parts[@]}-1; i++)); do
        if [[ -n "$username" ]]; then
            username="${username}:${parts[i]}"
        else
            username="${parts[i]}"
        fi
    done

    password="${parts[-1]}"  # Last part is always password

    # Validate components
    if [[ -z "$host" || -z "$port" || -z "$username" || -z "$password" ]]; then
        log_warning "Invalid proxy components in: $proxy_line"
        return 1
    fi

    # Validate host format (basic check)
    if [[ ! "$host" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        log_warning "Invalid host format: $host"
        return 1
    fi

    result[host]="$host"
    result[port]="$port"
    result[user]="$username"
    result[pass]="$password"

    return 0
}

# Construct auth URL with proper URL encoding (from reference)
construct_auth_url() {
    local host=$1
    local port=$2
    local username=$3
    local password=$4

    # Basic URL encoding for special characters in username/password
    local encoded_username=$(printf '%s' "$username" | sed 's/@/%40/g; s/:/%3A/g; s/ /%20/g')
    local encoded_password=$(printf '%s' "$password" | sed 's/@/%40/g; s/:/%3A/g; s/ /%20/g')

    # Use the SaaS auth URL format instead of simple upstream
    local auth_url="${AUTH_URL}?upstream=http://${encoded_username}:${encoded_password}@${host}:${port}"

    echo "$auth_url"
}

# Start single GoProxy instance (enhanced from reference)
start_proxy_instance() {
    local local_port="$1"
    local upstream_host="$2"
    local upstream_port="$3"
    local upstream_user="$4"
    local upstream_pass="$5"

    local pid_file="${PID_DIR}/proxy_${local_port}.pid"
    local log_file="${LOG_DIR}/users/port_${local_port}.log"

    # Check if port is already in use
    if is_port_in_use "$local_port"; then
        log_warning "Port $local_port is already in use"
        return 1
    fi

    # Check if already running via PID file
    if [[ -f "$pid_file" ]] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        log_warning "Proxy already running on port $local_port"
        return 0
    fi

    # Construct auth URL (like reference system)
    local auth_url=$(construct_auth_url "$upstream_host" "$upstream_port" "$upstream_user" "$upstream_pass")

    log_info "Starting GoProxy on port $local_port -> $upstream_host:$upstream_port"
    log_info "Auth URL: $auth_url"

    # Try multiple attempts (like reference)
    local attempt=1
    while [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; do
        log_info "Attempt $attempt/$MAX_RETRY_ATTEMPTS to start proxy on port $local_port"

        # Execute proxy command with error capture (enhanced from reference)
        local proxy_output
        local proxy_exit_code

        proxy_output=$(proxy http -p ":$local_port" \
            --auth-url "$auth_url" \
            --auth-nouser \
            --auth-cache "$AUTH_CACHE_DURATION" \
            --traffic-url "$TRAFFIC_URL" \
            --traffic-mode "$TRAFFIC_MODE" \
            --traffic-interval "$TRAFFIC_INTERVAL" \
            --control-url "$CONTROL_URL" \
            --control-sleep "$CONTROL_SLEEP" \
            --sniff-domain \
            --log-file "$log_file" \
            --daemon 2>&1)
        proxy_exit_code=$?

        if [[ $proxy_exit_code -eq 0 ]]; then
            # Wait for startup and verify
            sleep 2

            if is_port_in_use "$local_port"; then
                # Find and store PID
                local goproxy_pid=$(pgrep -f ":${local_port}" | head -1)
                if [[ -n "$goproxy_pid" ]]; then
                    echo "$goproxy_pid" > "$pid_file"

                    # Add to tracking variables
                    STARTED_PROCESSES="$STARTED_PROCESSES $goproxy_pid"
                    STARTED_PORTS="$STARTED_PORTS $local_port"

                    # Add to output file (like reference)
                    echo "${OUTPUT_HOST}:${local_port}" >> "$PROXY_OUTPUT_FILE"

                    log_success "Proxy successfully started on port $local_port (PID: $goproxy_pid)"

                    # Update database with proxy status
                    update_proxy_status "$local_port" "$upstream_host" "$upstream_port" "active"
                    return 0
                else
                    log_warning "Port $local_port is in use but couldn't find GoProxy PID"
                fi
            else
                log_warning "Proxy command succeeded but port $local_port is not in use"
            fi
        else
            log_warning "Proxy command failed with exit code $proxy_exit_code"
            log_warning "Output: $proxy_output"
        fi

        ((attempt++))
        if [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; then
            log_info "Retrying in 2 seconds..."
            sleep 2
        fi
    done

    log_error "Failed to start proxy on port $local_port after $MAX_RETRY_ATTEMPTS attempts"
    return 1
}

# Check if port is in use (from reference)
is_port_in_use() {
    local port=$1
    if command -v netstat >/dev/null 2>&1; then
        netstat -ln | grep -q ":$port "
    elif command -v ss >/dev/null 2>&1; then
        ss -ln | grep -q ":$port "
    else
        # Fallback: try to bind to port
        (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null
    fi
}

# Find next available port (from reference)
find_available_port() {
    local start_port=$1
    local max_port=${2:-$END_PORT}

    for ((port=start_port; port<=max_port; port++)); do
        if ! is_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
    done

    return 1
}

# Stop single GoProxy instance
stop_proxy_instance() {
    local local_port="$1"
    local pid_file="${PID_DIR}/proxy_${local_port}.pid"
    
    if [[ ! -f "$pid_file" ]]; then
        log_warning "PID file not found for port $local_port"
        return 0
    fi
    
    local pid=$(cat "$pid_file")
    
    if kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping GoProxy on port $local_port (PID: $pid)"
        
        # Graceful shutdown
        if kill -TERM "$pid" 2>/dev/null; then
            # Wait for graceful shutdown
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                sleep 1
                ((count++))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                log_warning "Force killing GoProxy on port $local_port"
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
        
        log_success "GoProxy stopped on port $local_port"
    else
        log_warning "GoProxy process not running for port $local_port"
    fi
    
    rm -f "$pid_file"
    update_proxy_status "$local_port" "" "" "inactive"
}

# Update proxy status in database (if available)
update_proxy_status() {
    local local_port="$1"
    local upstream_host="$2"
    local upstream_port="$3"
    local status="$4"
    
    # Only update if database connection is available
    if command -v mysql >/dev/null 2>&1 && [[ -n "${DB_USER:-}" ]]; then
        mysql -u "${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "
            INSERT INTO upstream_proxies (host, port, local_port, status, last_check)
            VALUES ('$upstream_host', $upstream_port, $local_port, '$status', NOW())
            ON DUPLICATE KEY UPDATE 
                status = VALUES(status),
                last_check = VALUES(last_check)
        " 2>/dev/null || log_warning "Could not update database for port $local_port"
    fi
}

# Start all proxy instances
start_all_proxies() {
    log_info "Starting all proxy instances..."
    
    local current_port=$START_PORT
    local started_count=0
    local failed_count=0
    
    while IFS= read -r proxy_line; do
        if [[ $current_port -gt $END_PORT ]]; then
            log_warning "Reached maximum port limit ($END_PORT)"
            break
        fi
        
        declare -A proxy_info
        if parse_proxy_line "$proxy_line" proxy_info; then
            if start_proxy_instance "$current_port" "${proxy_info[host]}" "${proxy_info[port]}" "${proxy_info[user]}" "${proxy_info[pass]}"; then
                ((started_count++))
            else
                ((failed_count++))
            fi
            ((current_port++))
        fi
        
        # Rate limit startup to avoid overwhelming system
        sleep 0.1
        
    done < "$PROXY_LIST_FILE"
    
    log_success "Proxy startup completed: $started_count started, $failed_count failed"
}

# Stop all proxy instances
stop_all_proxies() {
    log_info "Stopping all proxy instances..."
    
    local stopped_count=0
    
    for pid_file in "$PID_DIR"/proxy_*.pid; do
        if [[ -f "$pid_file" ]]; then
            local port=$(basename "$pid_file" .pid | sed 's/proxy_//')
            stop_proxy_instance "$port"
            ((stopped_count++))
        fi
    done
    
    log_success "Stopped $stopped_count proxy instances"
}

# Health check for all instances
health_check() {
    log_info "Performing health check on all proxy instances..."
    
    local healthy_count=0
    local unhealthy_count=0
    
    for pid_file in "$PID_DIR"/proxy_*.pid; do
        if [[ -f "$pid_file" ]]; then
            local port=$(basename "$pid_file" .pid | sed 's/proxy_//')
            local pid=$(cat "$pid_file")
            
            if kill -0 "$pid" 2>/dev/null; then
                # Process is running, test connectivity
                if curl -s --connect-timeout 5 --proxy "127.0.0.1:$port" "http://httpbin.org/ip" >/dev/null 2>&1; then
                    ((healthy_count++))
                else
                    log_warning "Proxy on port $port is not responding"
                    ((unhealthy_count++))
                fi
            else
                log_warning "Proxy process not running for port $port"
                rm -f "$pid_file"
                ((unhealthy_count++))
            fi
        fi
    done
    
    log_info "Health check completed: $healthy_count healthy, $unhealthy_count unhealthy"
}

# Graceful reload (SIGHUP handler)
graceful_reload() {
    log_info "Received SIGHUP - performing graceful reload..."
    
    # Re-read configuration
    load_config
    
    # Get current running ports
    local running_ports=()
    for pid_file in "$PID_DIR"/proxy_*.pid; do
        if [[ -f "$pid_file" ]]; then
            local port=$(basename "$pid_file" .pid | sed 's/proxy_//')
            local pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                running_ports+=("$port")
            fi
        fi
    done
    
    # Parse new proxy list
    local new_ports=()
    local current_port=$START_PORT
    
    while IFS= read -r proxy_line; do
        if [[ $current_port -gt $END_PORT ]]; then
            break
        fi
        
        declare -A proxy_info
        if parse_proxy_line "$proxy_line" proxy_info; then
            new_ports+=("$current_port")
            ((current_port++))
        fi
    done < "$PROXY_LIST_FILE"
    
    # Stop removed proxies
    for port in "${running_ports[@]}"; do
        if [[ ! " ${new_ports[*]} " =~ " $port " ]]; then
            log_info "Stopping removed proxy on port $port"
            stop_proxy_instance "$port"
        fi
    done
    
    # Start new proxies
    current_port=$START_PORT
    while IFS= read -r proxy_line; do
        if [[ $current_port -gt $END_PORT ]]; then
            break
        fi
        
        declare -A proxy_info
        if parse_proxy_line "$proxy_line" proxy_info; then
            if [[ ! " ${running_ports[*]} " =~ " $current_port " ]]; then
                log_info "Starting new proxy on port $current_port"
                start_proxy_instance "$current_port" "${proxy_info[host]}" "${proxy_info[port]}" "${proxy_info[user]}" "${proxy_info[pass]}"
            fi
            ((current_port++))
        fi
    done < "$PROXY_LIST_FILE"
    
    log_success "Graceful reload completed"
}

# Signal handlers
trap 'graceful_reload' SIGHUP
trap 'log_info "Received SIGTERM - shutting down..."; stop_all_proxies; exit 0' SIGTERM
trap 'log_info "Received SIGINT - shutting down..."; stop_all_proxies; exit 0' SIGINT

# Show usage
show_usage() {
    cat << EOF
Usage: $0 {start|stop|restart|reload|status|health|help}

Commands:
    start     - Start all proxy instances
    stop      - Stop all proxy instances  
    restart   - Stop and start all proxy instances
    reload    - Graceful reload (re-read proxy.txt)
    status    - Show status of all proxy instances
    health    - Perform health check on all instances
    help      - Show this help message

Configuration:
    Config file: $CONFIG_FILE
    Proxy list:  $PROXY_LIST_FILE
    PID dir:     $PID_DIR
    Log dir:     $LOG_DIR

Signals:
    SIGHUP    - Graceful reload
    SIGTERM   - Graceful shutdown
    SIGINT    - Graceful shutdown

EOF
}

# Show status of all instances
show_status() {
    echo "Proxy Pool Manager Status"
    echo "========================="
    echo "Config file: $CONFIG_FILE"
    echo "Proxy list:  $PROXY_LIST_FILE"
    echo "Port range:  $START_PORT-$END_PORT"
    echo
    
    local running_count=0
    local total_count=0
    
    for port in $(seq $START_PORT $END_PORT); do
        local pid_file="${PID_DIR}/proxy_${port}.pid"
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Port $port: RUNNING (PID: $pid)"
                ((running_count++))
            else
                echo "Port $port: DEAD (stale PID file)"
                rm -f "$pid_file"
            fi
            ((total_count++))
        fi
    done
    
    echo
    echo "Summary: $running_count/$total_count instances running"
}

# Main function
main() {
    # Initialize
    load_config
    init_directories
    check_dependencies
    
    case "${1:-help}" in
        start)
            validate_proxy_list
            start_all_proxies
            ;;
        stop)
            stop_all_proxies
            ;;
        restart)
            stop_all_proxies
            sleep 2
            validate_proxy_list
            start_all_proxies
            ;;
        reload)
            validate_proxy_list
            graceful_reload
            ;;
        status)
            show_status
            ;;
        health)
            health_check
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            echo "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
