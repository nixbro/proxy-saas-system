#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Production Deployment Script
# ============================================================================
# 
# Automated deployment script for the complete SaaS proxy management system
# Handles: Dependencies, Database setup, Web server, Security, Monitoring
# 
# Usage:
#   ./deploy.sh --install     # Fresh installation
#   ./deploy.sh --update      # Update existing installation
#   ./deploy.sh --test        # Run tests only
#   ./deploy.sh --help        # Show help
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
        centos|rhel|fedora)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release
                dnf install -y \
                    nginx \
                    mariadb-server \
                    redis \
                    php-fpm \
                    php-mysqlnd \
                    php-redis \
                    php-curl \
                    php-json \
                    php-mbstring \
                    php-xml \
                    curl \
                    wget \
                    unzip \
                    git \
                    htop \
                    fail2ban \
                    firewalld \
                    certbot \
                    python3-certbot-nginx
            else
                yum install -y epel-release
                yum install -y \
                    nginx \
                    mariadb-server \
                    redis \
                    php-fpm \
                    php-mysqlnd \
                    php-redis \
                    php-curl \
                    php-json \
                    php-mbstring \
                    php-xml \
                    curl \
                    wget \
                    unzip \
                    git \
                    htop \
                    fail2ban \
                    firewalld \
                    certbot \
                    python3-certbot-nginx
            fi
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
    mkdir -p "/var/log/$PROJECT_NAME"
    mkdir -p "/etc/$PROJECT_NAME"
    mkdir -p "/var/lib/$PROJECT_NAME"
    
    # Copy project files
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/api" "$WEB_DIR/"
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "www-data:www-data" "$WEB_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "/var/log/$PROJECT_NAME"
    chown -R "$SERVICE_USER:$SERVICE_USER" "/var/lib/$PROJECT_NAME"
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR"/*.sh
    chmod +x "$INSTALL_DIR/tests"/*.sh
    
    log_success "Directory structure created"
}

# Configure database
setup_database() {
    log_info "Setting up database..."
    
    # Start MariaDB service
    systemctl start mariadb
    systemctl enable mariadb
    
    # Set MariaDB root password
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'secure_root_password_change_this';" || true
    mysql -u root -p"secure_root_password_change_this" -e "DELETE FROM mysql.user WHERE User='';" || true
    mysql -u root -p"secure_root_password_change_this" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" || true
    mysql -u root -p"secure_root_password_change_this" -e "DROP DATABASE IF EXISTS test;" || true
    mysql -u root -p"secure_root_password_change_this" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" || true
    mysql -u root -p"secure_root_password_change_this" -e "FLUSH PRIVILEGES;" || true
    
    # Create database and user
    mysql -u root -p"secure_root_password_change_this" <<EOF
CREATE DATABASE IF NOT EXISTS proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'proxy_user'@'localhost' IDENTIFIED BY 'secure_password_change_this';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    # Import database schema
    mysql -u proxy_user -p"secure_password_change_this" proxy_saas < "$INSTALL_DIR/database/schema.sql"
    
    log_success "Database configured"
}

# Configure Redis
setup_redis() {
    log_info "Setting up Redis..."
    
    # Configure Redis
    cat > /etc/redis/redis.conf <<EOF
bind 127.0.0.1
port 6379
timeout 0
tcp-keepalive 300
daemonize yes
supervised systemd
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
maxmemory 256mb
maxmemory-policy allkeys-lru
appendonly no
EOF
    
    # Start Redis service
    systemctl start redis-server
    systemctl enable redis-server
    
    log_success "Redis configured"
}

# Configure Nginx
setup_nginx() {
    log_info "Setting up Nginx..."
    
    # Create Nginx configuration
    cat > "/etc/nginx/sites-available/$PROJECT_NAME" <<EOF
server {
    listen 80;
    listen 8889;
    server_name _;
    root $WEB_DIR;
    index index.php index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Block access to internal APIs from external IPs
    location /api/internal/ {
        allow 127.0.0.1;
        allow ::1;
        deny all;
        
        try_files \$uri \$uri/ /index.php?\$query_string;
        
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
    
    # Public API endpoints
    location /api/ {
        try_files \$uri \$uri/ /index.php?\$query_string;
        
        location ~ \.php$ {
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
    
    # Deny access to sensitive files
    location ~ /\. {
        deny all;
    }
    
    location ~ /(config|logs|tests|database)/ {
        deny all;
    }
    
    # PHP processing
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOF
    
    # Enable site
    ln -sf "/etc/nginx/sites-available/$PROJECT_NAME" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and start Nginx
    nginx -t
    systemctl start nginx
    systemctl enable nginx
    
    log_success "Nginx configured"
}

# Configure PHP-FPM
setup_php() {
    log_info "Setting up PHP-FPM..."
    
    # Configure PHP-FPM pool
    cat > "/etc/php/8.1/fpm/pool.d/$PROJECT_NAME.conf" <<EOF
[$PROJECT_NAME]
user = www-data
group = www-data
listen = /var/run/php/php8.1-fpm.sock
listen.owner = www-data
listen.group = www-data
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[error_log] = /var/log/$PROJECT_NAME/php-fpm.log
php_admin_flag[log_errors] = on
php_value[session.save_handler] = files
php_value[session.save_path] = /var/lib/php/sessions
php_value[soap.wsdl_cache_dir] = /var/lib/php/wsdlcache
EOF
    
    # Start PHP-FPM
    systemctl start php8.1-fpm
    systemctl enable php8.1-fpm
    
    log_success "PHP-FPM configured"
}

# Setup environment configuration
setup_environment() {
    log_info "Setting up environment configuration..."
    
    # Copy environment file
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    
    # Generate secure passwords
    local db_password=$(openssl rand -base64 32)
    local redis_password=$(openssl rand -base64 32)
    
    # Update environment file
    sed -i "s/APP_ENV=development/APP_ENV=production/" "$INSTALL_DIR/.env"
    sed -i "s/APP_DEBUG=true/APP_DEBUG=false/" "$INSTALL_DIR/.env"
    sed -i "s/DB_PASS=secure_password_change_this/DB_PASS=$db_password/" "$INSTALL_DIR/.env"
    sed -i "s/REDIS_PASSWORD=/REDIS_PASSWORD=$redis_password/" "$INSTALL_DIR/.env"
    
    # Set permissions
    chmod 600 "$INSTALL_DIR/.env"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.env"
    
    log_success "Environment configured"
}

# Setup systemd service
setup_systemd_service() {
    log_info "Setting up systemd service..."
    
    cat > "/etc/systemd/system/$PROJECT_NAME.service" <<EOF
[Unit]
Description=Proxy SaaS System - Proxy Pool Manager
After=network.target mariadb.service redis-server.service
Wants=mariadb.service redis-server.service

[Service]
Type=forking
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/proxy_pool_manager.sh start
ExecReload=$INSTALL_DIR/proxy_pool_manager.sh reload
ExecStop=$INSTALL_DIR/proxy_pool_manager.sh stop
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "$PROJECT_NAME"
    
    log_success "Systemd service configured"
}

# Configure firewall
setup_firewall() {
    log_info "Setting up firewall..."
    
    case $OS in
        ubuntu|debian)
            # Configure UFW
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow ssh
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw allow 8889/tcp
            ufw allow 4000:4999/tcp
            ufw --force enable
            ;;
        centos|rhel|fedora)
            # Configure firewalld
            systemctl start firewalld
            systemctl enable firewalld
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            firewall-cmd --permanent --add-port=8889/tcp
            firewall-cmd --permanent --add-port=4000-4999/tcp
            firewall-cmd --reload
            ;;
    esac
    
    log_success "Firewall configured"
}

# Setup SSL certificate
setup_ssl() {
    log_info "Setting up SSL certificate..."
    
    local domain=$(grep "SERVER_HOST=" "$INSTALL_DIR/.env" | cut -d'=' -f2)
    
    if [[ "$domain" != "proxy.example.com" ]]; then
        # Request Let's Encrypt certificate
        certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain"
        log_success "SSL certificate configured for $domain"
    else
        log_warning "SSL certificate not configured - update SERVER_HOST in .env file"
    fi
}

# Run tests
run_tests() {
    log_info "Running integration tests..."
    
    # Make test script executable
    chmod +x "$INSTALL_DIR/tests/integration_test.sh"
    
    # Run tests as service user
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/tests/integration_test.sh"
    
    log_success "Tests completed"
}

# Show deployment summary
show_summary() {
    echo ""
    echo "============================================================================"
    echo "DEPLOYMENT COMPLETED SUCCESSFULLY"
    echo "============================================================================"
    echo ""
    echo "🎉 Your Proxy SaaS System is now deployed and ready!"
    echo ""
    echo "📁 Installation Directory: $INSTALL_DIR"
    echo "🌐 Web Directory: $WEB_DIR"
    echo "📋 Log File: $LOG_FILE"
    echo "⚙️  Configuration: $INSTALL_DIR/.env"
    echo ""
    echo "🔗 API Endpoints:"
    echo "   • Proxy List: http://your-domain.com/api/proxies.php"
    echo "   • Admin APIs: http://your-domain.com/api/admin/"
    echo ""
    echo "🚀 Next Steps:"
    echo "   1. Update $INSTALL_DIR/.env with your domain and settings"
    echo "   2. Add your upstream proxies to $INSTALL_DIR/proxy.txt"
    echo "   3. Start the service: systemctl start $PROJECT_NAME"
    echo "   4. Check status: systemctl status $PROJECT_NAME"
    echo "   5. View logs: journalctl -u $PROJECT_NAME -f"
    echo ""
    echo "🔒 Security:"
    echo "   • Change default passwords in .env file"
    echo "   • Configure SSL certificate for your domain"
    echo "   • Review firewall rules"
    echo "   • Set up monitoring and backups"
    echo ""
    echo "📚 Documentation: $INSTALL_DIR/README.md"
    echo "🧪 Run Tests: $INSTALL_DIR/tests/integration_test.sh"
    echo ""
    echo "============================================================================"
}

# Main installation function
install_system() {
    log_info "Starting fresh installation..."
    
    detect_os
    install_dependencies
    install_goproxy
    create_system_user
    setup_directories
    setup_database
    setup_redis
    setup_nginx
    setup_php
    setup_environment
    setup_systemd_service
    setup_firewall
    setup_ssl
    
    log_success "Installation completed successfully"
    show_summary
}

# Update existing installation
update_system() {
    log_info "Starting system update..."
    
    # Stop services
    systemctl stop "$PROJECT_NAME" || true
    systemctl stop nginx || true
    
    # Backup current installation
    local backup_dir="/var/backups/$PROJECT_NAME-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    cp -r "$INSTALL_DIR" "$backup_dir/"
    cp -r "$WEB_DIR" "$backup_dir/"
    
    # Update files
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    cp -r "$SCRIPT_DIR/api" "$WEB_DIR/"
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "www-data:www-data" "$WEB_DIR"
    chmod +x "$INSTALL_DIR"/*.sh
    
    # Restart services
    systemctl start nginx
    systemctl start "$PROJECT_NAME"
    
    log_success "System updated successfully"
    log_info "Backup created at: $backup_dir"
}

# Show help
show_help() {
    cat << EOF
Proxy SaaS System - Deployment Script

Usage: $0 [OPTION]

Options:
    --install     Fresh installation of the complete system
    --update      Update existing installation
    --test        Run integration tests only
    --help        Show this help message

Examples:
    $0 --install     # Install everything from scratch
    $0 --update      # Update existing installation
    $0 --test        # Run tests to verify installation

Requirements:
    - Ubuntu 20.04+ or CentOS 8+
    - Root privileges
    - Internet connection
    - At least 2GB RAM and 10GB disk space

For more information, see the documentation in the project directory.
EOF
}

# Main execution
main() {
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    case "${1:-}" in
        --install)
            check_root
            install_system
            ;;
        --update)
            check_root
            update_system
            ;;
        --test)
            run_tests
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Invalid option: ${1:-}"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
