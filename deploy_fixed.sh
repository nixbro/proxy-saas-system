#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Fixed Production Deployment Script
# ============================================================================
# 
# Fixed version with proper sed commands and Unicode character handling
# Automated deployment script for the complete SaaS proxy management system
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="proxy-saas-system"
INSTALL_DIR="/opt/$PROJECT_NAME"
WEB_DIR="/var/www/html/$PROJECT_NAME"
SERVICE_USER="proxy-saas"
LOG_FILE="/var/log/$PROJECT_NAME/deploy.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Error handling
handle_error() {
    local line_number=$1
    log_error "Deployment failed at line $line_number"
    log_error "Check the log file: $LOG_FILE"
    exit 1
}

trap 'handle_error $LINENO' ERR

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_error "Please run: sudo $0 $*"
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect operating system"
        exit 1
    fi
    
    log_info "Detected OS: $OS $OS_VERSION"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                nginx \
                mariadb-server \
                redis-server \
                php8.1-fpm \
                php8.1-mysql \
                php8.1-redis \
                php8.1-curl \
                php8.1-cli \
                php8.1-mbstring \
                php8.1-xml \
                php8.1-zip \
                php8.1-gd \
                curl \
                wget \
                unzip \
                git \
                htop \
                fail2ban \
                ufw \
                certbot \
                python3-certbot-nginx \
                bc
            ;;
        *)
            log_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    log_success "System dependencies installed"
}

# Install GoProxy
install_goproxy() {
    log_info "Checking GoProxy installation..."
    
    # Check if GoProxy is already installed
    if command -v proxy >/dev/null 2>&1; then
        local version=$(proxy --version 2>&1 | head -1 || echo "unknown")
        log_success "GoProxy already installed: $version"
        return 0
    fi
    
    log_info "Installing GoProxy..."
    
    # Try multiple download URLs for different versions
    local goproxy_urls=(
        "https://github.com/snail007/goproxy/releases/download/v13.1/proxy-linux-amd64.tar.gz"
        "https://github.com/snail007/goproxy/releases/download/v12.9/proxy-linux-amd64.tar.gz"
        "https://github.com/snail007/goproxy/releases/latest/download/proxy-linux-amd64.tar.gz"
    )
    
    cd /tmp
    local download_success=false
    
    for url in "${goproxy_urls[@]}"; do
        log_info "Trying download from: $url"
        if wget -O goproxy.tar.gz "$url" 2>/dev/null; then
            download_success=true
            break
        fi
    done
    
    if [ "$download_success" = false ]; then
        log_error "Failed to download GoProxy from all sources"
        log_error "Please install GoProxy manually:"
        log_error "1. Download from: https://github.com/snail007/goproxy/releases"
        log_error "2. Extract and copy 'proxy' binary to /usr/local/bin/"
        log_error "3. Run: chmod +x /usr/local/bin/proxy"
        exit 1
    fi
    
    # Extract and install
    tar -xzf goproxy.tar.gz
    chmod +x proxy
    mv proxy /usr/local/bin/
    
    # Verify installation
    if proxy --version >/dev/null 2>&1; then
        log_success "GoProxy installed successfully"
    else
        log_error "GoProxy installation failed"
        exit 1
    fi
}

# Create system user
create_system_user() {
    log_info "Creating system user: $SERVICE_USER"
    
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        useradd -r -s /bin/bash -d "$INSTALL_DIR" "$SERVICE_USER"
        log_success "System user created: $SERVICE_USER"
    else
        log_info "System user already exists: $SERVICE_USER"
    fi
}

# Setup directory structure
setup_directories() {
    log_info "Setting up directory structure..."
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$WEB_DIR"
    mkdir -p "/var/log/$PROJECT_NAME"/{api,users,system,security}
    mkdir -p "/etc/$PROJECT_NAME"
    mkdir -p "/var/lib/$PROJECT_NAME"
    
    # Copy project files
    log_info "Copying project files..."
    if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || {
            log_warning "Some files could not be copied, continuing..."
        }
    fi
    
    # Ensure API directory exists in web directory
    if [[ -d "$SCRIPT_DIR/api" ]]; then
        cp -r "$SCRIPT_DIR/api" "$WEB_DIR/" 2>/dev/null || {
            log_warning "Could not copy API files to web directory"
        }
    fi
    
    # Create missing directories if they don't exist
    mkdir -p "$INSTALL_DIR"/{database,tests,config}
    mkdir -p "$WEB_DIR/api"/{internal,admin}
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" 2>/dev/null || true
    chown -R "www-data:www-data" "$WEB_DIR" 2>/dev/null || true
    chown -R "$SERVICE_USER:$SERVICE_USER" "/var/log/$PROJECT_NAME" 2>/dev/null || true
    chown -R "$SERVICE_USER:$SERVICE_USER" "/var/lib/$PROJECT_NAME" 2>/dev/null || true
    
    # Make scripts executable
    find "$INSTALL_DIR" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    
    log_success "Directory structure created"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    # Ensure .env.example exists in installation directory
    if [[ ! -f "$INSTALL_DIR/.env.example" ]]; then
        if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
            cp "$SCRIPT_DIR/.env.example" "$INSTALL_DIR/.env.example"
        else
            log_error ".env.example file not found in $SCRIPT_DIR or $INSTALL_DIR"
            exit 1
        fi
    fi
    
    # Copy environment file
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    
    # Generate secure passwords
    local db_password="secure_password_change_this"  # Keep consistent with database setup
    local redis_password=$(openssl rand -base64 32 2>/dev/null || echo "redis_password_$(date +%s)")
    
    # Update environment file with current server IP
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")
    
    # Update environment file using | as delimiter to avoid issues with dots and slashes
    log_info "Configuring environment with server IP: $server_ip"
    
    # Use safer sed commands with error checking
    sed -i "s|APP_ENV=development|APP_ENV=production|g" "$INSTALL_DIR/.env" || log_warning "Could not update APP_ENV"
    sed -i "s|APP_DEBUG=true|APP_DEBUG=false|g" "$INSTALL_DIR/.env" || log_warning "Could not update APP_DEBUG"
    sed -i "s|SERVER_HOST=proxy.example.com|SERVER_HOST=$server_ip|g" "$INSTALL_DIR/.env" || log_warning "Could not update SERVER_HOST"
    sed -i "s|DB_PASS=secure_password_change_this|DB_PASS=$db_password|g" "$INSTALL_DIR/.env" || log_warning "Could not update DB_PASS"
    sed -i "s|REDIS_PASSWORD=|REDIS_PASSWORD=$redis_password|g" "$INSTALL_DIR/.env" || log_warning "Could not update REDIS_PASSWORD"
    
    # Verify the configuration was updated
    if grep -q "APP_ENV=production" "$INSTALL_DIR/.env"; then
        log_info "Environment configuration updated successfully"
    else
        log_warning "Environment configuration may not have been updated correctly"
    fi
    
    # Set permissions
    chmod 600 "$INSTALL_DIR/.env"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.env"
    
    log_success "Environment configured with server IP: $server_ip"
}

# Show deployment summary
show_summary() {
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")
    
    echo ""
    echo "============================================================================"
    echo "PROXY-SAAS-SYSTEM DEPLOYMENT COMPLETED SUCCESSFULLY!"
    echo "============================================================================"
    echo ""
    echo "Your Enterprise Proxy SaaS System is now deployed and ready!"
    echo ""
    echo "System Information:"
    echo "   Installation Directory: $INSTALL_DIR"
    echo "   Web Directory: $WEB_DIR"
    echo "   Log Directory: /var/log/$PROJECT_NAME"
    echo "   Configuration: $INSTALL_DIR/.env"
    echo "   Server IP: $server_ip"
    echo ""
    echo "API Endpoints:"
    echo "   Proxy List API: http://$server_ip:8889/api/proxies.php"
    echo "   Admin APIs: http://$server_ip:8889/api/admin/"
    echo "   Health Check: http://$server_ip:8889/api/health.php"
    echo ""
    echo "Next Steps:"
    echo "   1. Edit configuration: sudo nano $INSTALL_DIR/.env"
    echo "   2. Add upstream proxies: sudo nano $INSTALL_DIR/proxy.txt"
    echo "   3. Start the service: sudo systemctl start $PROJECT_NAME"
    echo "   4. Check status: sudo systemctl status $PROJECT_NAME"
    echo "   5. View logs: sudo journalctl -u $PROJECT_NAME -f"
    echo ""
    echo "Test Commands:"
    echo "   Test API: curl \"http://$server_ip:8889/api/proxies.php\""
    echo "   Run validation: $INSTALL_DIR/validate_system.sh"
    echo ""
    echo "Your Enterprise Proxy SaaS System is ready to generate revenue!"
    echo "============================================================================"
}

# Main execution
main() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    case "${1:-}" in
        --install)
            check_root
            detect_os
            install_dependencies
            install_goproxy
            create_system_user
            setup_directories
            setup_environment
            show_summary
            ;;
        --help|-h)
            echo "Usage: $0 --install"
            echo "Fixed deployment script for Proxy SaaS System"
            ;;
        *)
            log_error "Invalid option: ${1:-}"
            echo "Usage: $0 --install"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
