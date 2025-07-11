#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Free Version Proxy Pool Manager
# ============================================================================
# 
# Simplified version that works with free GoProxy (no commercial features)
# Manages a pool of HTTP proxy instances for the SaaS system
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/saas-config.conf"
PROXY_FILE="$SCRIPT_DIR/proxy.txt"
PID_DIR="$SCRIPT_DIR/pids"
LOG_DIR="$SCRIPT_DIR/logs"

# Default configuration (will be overridden by config file)
PROXY_START_PORT=4000
PROXY_END_PORT=4010
MAX_RETRY_ATTEMPTS=3
RESTART_DELAY=2

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
        source "$CONFIG_FILE" 2>/dev/null || true
        log_info "Configuration loaded from $CONFIG_FILE"
    else
        log_warning "Configuration file not found: $CONFIG_FILE"
    fi
}

# Initialize directories
init_directories() {
    mkdir -p "$PID_DIR" "$LOG_DIR"
    log_info "Directories initialized"
}

# Check dependencies
check_dependencies() {
    if ! command -v proxy >/dev/null 2>&1; then
        log_error "GoProxy not found. Please install GoProxy first."
        return 1
    fi
    
    log_success "All dependencies satisfied"
    return 0
}

# Start a single proxy instance
start_proxy_instance() {
    local port=$1
    local pid_file="$PID_DIR/proxy_${port}.pid"
    
    log_info "Starting basic HTTP proxy on port $port"
    
    # Start basic HTTP proxy (free version - no commercial features)
    local attempt=1
    while [[ $attempt -le $MAX_RETRY_ATTEMPTS ]]; do
        log_info "Attempt $attempt/$MAX_RETRY_ATTEMPTS to start proxy on port $port"
        
        # Use only basic parameters that work with free version
        if proxy http -p ":$port" --daemon >/dev/null 2>&1; then
            # Find the PID of the proxy process
            sleep 1
            local proxy_pid=$(pgrep -f "proxy.*:$port" | head -1)
            
            if [[ -n "$proxy_pid" ]]; then
                echo "$proxy_pid" > "$pid_file"
                log_success "Proxy started on port $port (PID: $proxy_pid)"
                return 0
            fi
        fi
        
        log_warning "Failed to start proxy on port $port (attempt $attempt)"
        
        if [[ $attempt -lt $MAX_RETRY_ATTEMPTS ]]; then
            log_info "Retrying in $RESTART_DELAY seconds..."
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
        local pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            log_info "Stopped proxy on port $port (PID: $pid)"
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
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        if start_proxy_instance "$port"; then
            ((started_count++))
        else
            ((failed_count++))
        fi
    done
    
    log_info "Proxy pool startup complete: $started_count started, $failed_count failed"
    
    if [[ $started_count -eq 0 ]]; then
        log_error "No proxy instances started successfully"
        return 1
    fi
    
    return 0
}

# Stop all proxy instances
stop_all_proxies() {
    log_info "Stopping all proxy instances..."
    
    # Stop individual instances
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        stop_proxy_instance "$port"
    done
    
    # Kill any remaining proxy processes
    pkill -f "proxy http" 2>/dev/null || true
    
    # Clean up PID files
    rm -f "$PID_DIR"/proxy_*.pid
    
    log_success "All proxy instances stopped"
}

# Check status of proxy instances
status_proxies() {
    log_info "Checking proxy instance status..."
    
    local running_count=0
    local total_count=$((PROXY_END_PORT - PROXY_START_PORT + 1))
    
    for ((port=PROXY_START_PORT; port<=PROXY_END_PORT; port++)); do
        local pid_file="$PID_DIR/proxy_${port}.pid"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                echo "Port $port: Running (PID: $pid)"
                ((running_count++))
            else
                echo "Port $port: Dead (stale PID file)"
                rm -f "$pid_file"
            fi
        else
            echo "Port $port: Stopped"
        fi
    done
    
    echo "Status: $running_count/$total_count proxy instances running"
    return 0
}

# Main execution
main() {
    case "${1:-}" in
        start)
            load_config
            init_directories
            check_dependencies || exit 1
            start_all_proxies
            ;;
        stop)
            stop_all_proxies
            ;;
        restart)
            load_config
            init_directories
            stop_all_proxies
            sleep 2
            check_dependencies || exit 1
            start_all_proxies
            ;;
        status)
            status_proxies
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status}"
            echo ""
            echo "Free Version Proxy Pool Manager"
            echo "Manages basic HTTP proxy instances without commercial features"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
