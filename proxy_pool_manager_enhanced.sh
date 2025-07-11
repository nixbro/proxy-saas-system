#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Enhanced Proxy Pool Manager v2.0
# ============================================================================
# 
# Universal proxy manager that works with both free and commercial GoProxy
# Intelligent feature detection and adaptive configuration
# Enhanced error handling, monitoring, and recovery
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/saas-config.conf"
ENV_FILE="$SCRIPT_DIR/.env"
PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs"
LOCK_FILE="$SCRIPT_DIR/proxy_manager.lock"

# Default configuration
PROXY_START_PORT=4000
PROXY_END_PORT=4010
MAX_RETRY_ATTEMPTS=3
RESTART_DELAY=2
HEALTH_CHECK_INTERVAL=30
GOPROXY_VERSION="free"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Enhanced logging functions
log_info() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${BLUE}[INFO]${NC} $timestamp - $1" | tee -a "${LOG_DIR}/manager.log"
}

log_success() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${GREEN}[SUCCESS]${NC} $timestamp - $1" | tee -a "${LOG_DIR}/manager.log"
}

log_warning() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${YELLOW}[WARNING]${NC} $timestamp - $1" | tee -a "${LOG_DIR}/manager.log"
}

log_error() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${RED}[ERROR]${NC} $timestamp - $1" | tee -a "${LOG_DIR}/manager.log"
}

log_debug() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    [[ "${DEBUG:-false}" == "true" ]] && echo -e "${CYAN}[DEBUG]${NC} $timestamp - $1" | tee -a "${LOG_DIR}/manager.log"
}

# Lock management
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log_error "Another instance is already running (PID: $lock_pid)"
            exit 1
        else
            log_warning "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo $$ > "$LOCK_FILE"
    log_debug "Lock acquired (PID: $$)"
}

release_lock() {
    rm -f "$LOCK_FILE"
    log_debug "Lock released"
}

# Cleanup on exit
cleanup() {
    log_info "Performing cleanup..."
    release_lock
}

trap cleanup EXIT

# Load configuration with validation
load_config() {
    log_info "Loading configuration..."
    
    # Load environment file
    if [[ -f "$ENV_FILE" ]]; then
        source "$ENV_FILE"
        log_debug "Environment file loaded: $ENV_FILE"
        
        # Extract GoProxy version
        GOPROXY_VERSION=$(grep "GOPROXY_VERSION=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2 || echo "free")
        log_info "GoProxy version detected: $GOPROXY_VERSION"
    else
        log_warning "Environment file not found: $ENV_FILE"
    fi
    
    # Load SaaS configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE" 2>/dev/null || log_warning "Failed to load config file"
        log_debug "Configuration file loaded: $CONFIG_FILE"
    else
        log_warning "Configuration file not found: $CONFIG_FILE"
    fi
    
    # Adjust port range based on version
    if [[ "$GOPROXY_VERSION" == "commercial" ]]; then
        PROXY_END_PORT=${PROXY_END_PORT:-4999}
        log_info "Commercial version: Using extended port range (4000-$PROXY_END_PORT)"
    else
        PROXY_END_PORT=4010
        log_info "Free version: Using limited port range (4000-$PROXY_END_PORT)"
    fi
}

# Initialize directories
init_directories() {
    log_info "Initializing directories..."
    
    local dirs=("$PID_DIR" "$LOG_DIR" "$LOG_DIR/users" "$LOG_DIR/system")
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_debug "Created directory: $dir"
        fi
    done
    
    log_success "Directories initialized"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."
    
    local missing_deps=()
    
    # Check GoProxy
    if ! command -v proxy >/dev/null 2>&1; then
        missing_deps+=("goproxy")
    else
        local version=$(proxy --version 2>&1 | head -1 || echo "unknown")
        log_success "GoProxy found: $version"
        
        # Detect capabilities
        if proxy http --help 2>&1 | grep -q "log-file"; then
            log_info "Commercial features detected"
            if [[ "$GOPROXY_VERSION" != "commercial" ]]; then
                log_warning "Commercial GoProxy detected but configured as free"
            fi
        else
            log_info "Free version detected"
            if [[ "$GOPROXY_VERSION" == "commercial" ]]; then
                log_warning "Free GoProxy detected but configured as commercial"
                GOPROXY_VERSION="free"
            fi
        fi
    fi
    
    # Check other dependencies
    for cmd in curl netstat; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    
    log_success "All dependencies satisfied"
    return 0
}

# Start a single proxy instance with intelligent configuration
start_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    local log_file="$LOG_DIR/proxy_${port}.log"
    
    log_info "Starting proxy instance on port $port"
    
    # Remove existing PID file if process is not running
    if [[ -f "$pid_file" ]]; then
        local old_pid=$(cat "$pid_file" 2>/dev/null || echo "")
        if [[ -n "$old_pid" ]] && ! kill -0 "$old_pid" 2>/dev/null; then
            rm -f "$pid_file"
            log_debug "Removed stale PID file for port $port"
        fi
    fi
    
    local attempt=1
    while [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; do
        log_debug "Attempt $attempt/$MAX_RETRY_ATTEMPTS to start proxy on port $port"
        
        # Build command based on GoProxy version and capabilities
        local proxy_cmd="proxy http -p \":$port\""
        
        # Add features based on version
        if [[ "$GOPROXY_VERSION" == "commercial" ]]; then
            # Commercial features (if available)
            if [[ -n "${AUTH_URL:-}" ]]; then
                proxy_cmd+=" --auth-url \"$AUTH_URL\""
                proxy_cmd+=" --auth-nouser"
                proxy_cmd+=" --auth-cache ${AUTH_CACHE_DURATION:-300}"
            fi
            
            if [[ -n "${TRAFFIC_URL:-}" ]]; then
                proxy_cmd+=" --traffic-url \"$TRAFFIC_URL\""
                proxy_cmd+=" --traffic-mode ${TRAFFIC_MODE:-fast}"
                proxy_cmd+=" --traffic-interval ${TRAFFIC_INTERVAL:-5}"
            fi
            
            # Only add log-file if it's supported
            if proxy http --help 2>&1 | grep -q "log-file"; then
                proxy_cmd+=" --log-file \"$log_file\""
            fi
        fi
        
        # Always add daemon mode
        proxy_cmd+=" --daemon"
        
        log_debug "Executing: $proxy_cmd"
        
        # Execute the command
        if eval "$proxy_cmd" >/dev/null 2>&1; then
            # Wait a moment for the process to start
            sleep 1
            
            # Find the PID
            local proxy_pid=$(pgrep -f "proxy.*:$port" | head -1)
            
            if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
                echo "$proxy_pid" > "$pid_file"
                log_success "Proxy started on port $port (PID: $proxy_pid)"
                return 0
            else
                log_warning "Proxy process not found after start attempt"
            fi
        else
            log_warning "Proxy command failed on attempt $attempt"
        fi
        
        if [[ $attempt -lt $MAX_RETRY_ATTEMPTS ]]; then
            log_debug "Retrying in $RESTART_DELAY seconds..."
            sleep $RESTART_DELAY
        fi
        
        ((attempt++))
    done
    
    log_error "Failed to start proxy on port $port after $MAX_RETRY_ATTEMPTS attempts"
    return 1
}

# Stop a single proxy instance
stop_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            
            # Wait for graceful shutdown
            local count=0
            while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
                sleep 1
                ((count++))
            done
            
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
                log_warning "Force killed proxy on port $port"
            else
                log_info "Gracefully stopped proxy on port $port"
            fi
        fi
        rm -f "$pid_file"
    fi
    
    # Also kill any remaining proxy processes on this port
    pkill -f "proxy.*:$port" 2>/dev/null || true
}

# Start all proxy instances
start_all_proxies() {
    log_info "Starting proxy pool (ports $PROXY_START_PORT-$PROXY_END_PORT)"
    
    local started_count=0
    local failed_count=0
    local total_ports=$((PROXY_END_PORT - PROXY_START_PORT + 1))
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        if start_proxy_instance "$port"; then
            ((started_count++))
        else
            ((failed_count++))
        fi
        
        # Progress indicator
        local progress=$((((port - PROXY_START_PORT + 1) * 100) / total_ports))
        log_debug "Progress: $progress% ($started_count started, $failed_count failed)"
    done
    
    log_info "Proxy pool startup complete: $started_count/$total_ports started successfully"
    
    if [[ $started_count -eq 0 ]]; then
        log_error "No proxy instances started successfully"
        return 1
    elif [[ $failed_count -gt 0 ]]; then
        log_warning "$failed_count proxy instances failed to start"
    fi
    
    return 0
}

# Stop all proxy instances
stop_all_proxies() {
    log_info "Stopping all proxy instances..."

    local stopped_count=0

    # Stop individual instances
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        if [[ -f "$pid_file" ]]; then
            stop_proxy_instance "$port"
            ((stopped_count++))
        fi
    done

    # Kill any remaining proxy processes
    if pgrep -f "proxy http" >/dev/null 2>&1; then
        log_warning "Killing remaining proxy processes..."
        pkill -f "proxy http" 2>/dev/null || true
        sleep 2
    fi

    # Clean up PID files
    rm -f "$PID_DIR"/proxy_*.pid

    log_success "Stopped $stopped_count proxy instances"
}

# Check status of proxy instances
status_proxies() {
    log_info "Checking proxy instance status..."

    local running_count=0
    local total_count=$((PROXY_END_PORT - PROXY_START_PORT + 1))

    echo "Port Status Report:"
    echo "=================="

    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        local status="STOPPED"
        local pid=""

        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                status="RUNNING"
                ((running_count++))

                # Check if port is actually listening
                if netstat -ln 2>/dev/null | grep -q ":$port "; then
                    status="RUNNING (LISTENING)"
                else
                    status="RUNNING (NOT LISTENING)"
                fi
            else
                status="DEAD (stale PID)"
                rm -f "$pid_file"
            fi
        fi

        printf "Port %d: %-20s" "$port" "$status"
        [[ -n "$pid" ]] && printf " (PID: %s)" "$pid"
        echo
    done

    echo "=================="
    echo "Summary: $running_count/$total_count proxy instances running"

    return 0
}

# Main execution
main() {
    # Acquire lock to prevent multiple instances
    acquire_lock

    # Initialize
    init_directories
    load_config

    case "${1:-}" in
        start)
            log_info "Starting Proxy SaaS System (Enhanced Manager v2.0)"
            check_dependencies || exit 1
            start_all_proxies
            ;;
        stop)
            log_info "Stopping Proxy SaaS System"
            stop_all_proxies
            ;;
        restart)
            log_info "Restarting Proxy SaaS System"
            stop_all_proxies
            sleep 2
            check_dependencies || exit 1
            start_all_proxies
            ;;
        status)
            status_proxies
            ;;
        *)
            echo "Enhanced Proxy Pool Manager v2.0"
            echo "Usage: $0 {start|stop|restart|status}"
            echo ""
            echo "Features:"
            echo "  - Intelligent GoProxy version detection"
            echo "  - Adaptive configuration (free/commercial)"
            echo "  - Enhanced error handling and recovery"
            echo "  - Comprehensive logging and monitoring"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
