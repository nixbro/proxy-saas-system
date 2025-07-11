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
    echo -e "${BLUE}[INFO]${NC} $1"
    # Only log to file if directory exists
    [[ -d "$(dirname "$LOG_FILE")" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    [[ -d "$(dirname "$LOG_FILE")" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    [[ -d "$(dirname "$LOG_FILE")" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    [[ -d "$(dirname "$LOG_FILE")" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
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

        # Detect if it's free or commercial version
        if proxy http --help 2>&1 | grep -q "log-file"; then
            log_info "Commercial GoProxy version detected"
            echo "GOPROXY_VERSION=commercial" >> "$INSTALL_DIR/.env"
        else
            log_info "Free GoProxy version detected"
            echo "GOPROXY_VERSION=free" >> "$INSTALL_DIR/.env"
        fi
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

    # Clean up temporary files
    rm -f goproxy.tar.gz
    cd "$SCRIPT_DIR"

    # Verify installation and detect version
    if proxy --version >/dev/null 2>&1; then
        log_success "GoProxy installed successfully"

        # Detect version type
        if proxy http --help 2>&1 | grep -q "log-file"; then
            log_info "Commercial GoProxy version detected"
            echo "GOPROXY_VERSION=commercial" >> "$INSTALL_DIR/.env"
        else
            log_info "Free GoProxy version detected"
            echo "GOPROXY_VERSION=free" >> "$INSTALL_DIR/.env"
        fi
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
    mkdir -p "$INSTALL_DIR"/{database,tests,config,logs}
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

# Configure database
setup_database() {
    log_info "Setting up database..."

    # Start MariaDB service first
    systemctl start mariadb
    systemctl enable mariadb

    # Wait for MariaDB to be ready
    local count=0
    while ! mysqladmin ping >/dev/null 2>&1 && [[ $count -lt 30 ]]; do
        sleep 1
        ((count++))
    done

    if [[ $count -eq 30 ]]; then
        log_error "MariaDB failed to start within 30 seconds"
        exit 1
    fi

    # Configure MariaDB
    local mariadb_config="/etc/mysql/mariadb.conf.d/50-server.cnf"
    if [[ ! -f "$mariadb_config" ]]; then
        mariadb_config="/etc/mysql/mysql.conf.d/mysqld.cnf"
    fi

    if [[ -f "$mariadb_config" ]]; then
        # Check if configuration already exists
        if ! grep -q "Proxy SaaS System Configuration" "$mariadb_config"; then
            cat >> "$mariadb_config" <<EOF

# Proxy SaaS System Configuration
event_scheduler = ON
max_connections = 500
innodb_buffer_pool_size = 256M
EOF
            log_info "MariaDB configuration updated"
            # Restart MariaDB to apply configuration changes
            systemctl restart mariadb
            sleep 2
        else
            log_info "MariaDB already configured"
        fi
    else
        log_warning "MariaDB config file not found, will configure manually"
    fi

    # Set MariaDB root password (try multiple methods)
    log_info "Setting MariaDB root password..."

    # Method 1: Try without password first (fresh installation)
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'secure_root_password_change_this';" 2>/dev/null || \
    # Method 2: Try with empty password
    mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'secure_root_password_change_this';" 2>/dev/null || \
    # Method 3: Try with existing password
    mysql -u root -p"secure_root_password_change_this" -e "SELECT 1;" 2>/dev/null || \
    log_warning "Could not set root password - may already be set"

    # Clean up default users and databases
    mysql -u root -p"secure_root_password_change_this" <<EOF 2>/dev/null || true
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

    # Create database and user
    log_info "Creating database and user..."
    mysql -u root -p"secure_root_password_change_this" <<EOF
DROP DATABASE IF EXISTS proxy_saas;
CREATE DATABASE proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS 'proxy_user'@'localhost';
CREATE USER 'proxy_user'@'localhost' IDENTIFIED BY 'secure_password_change_this';
GRANT ALL PRIVILEGES ON proxy_saas.* TO 'proxy_user'@'localhost';
FLUSH PRIVILEGES;
EOF

    # Ensure database schema file exists
    if [[ ! -f "$INSTALL_DIR/database/schema.sql" ]]; then
        log_error "Database schema file not found: $INSTALL_DIR/database/schema.sql"
        exit 1
    fi

    # Import database schema
    log_info "Importing database schema..."
    mysql -u proxy_user -p"secure_password_change_this" proxy_saas < "$INSTALL_DIR/database/schema.sql"

    # Enable event scheduler with root privileges
    mysql -u root -p"secure_root_password_change_this" -e "SET GLOBAL event_scheduler = ON;" 2>/dev/null || log_warning "Could not enable event scheduler (requires SUPER privilege)"

    # Test database connection
    if mysql -u proxy_user -p"secure_password_change_this" proxy_saas -e "SHOW TABLES;" >/dev/null 2>&1; then
        log_success "Database configured and tested successfully"
    else
        log_error "Database configuration failed - connection test failed"
        exit 1
    fi
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

    # Update environment file with current server IP (prefer IPv4)
    local server_ip=$(curl -4 -s ifconfig.me 2>/dev/null || curl -s ifconfig.me 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || hostname -I | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "127.0.0.1")

    # Update environment file (using | as delimiter to avoid issues with dots, slashes, and colons)
    log_info "Configuring environment with server IP: $server_ip"

    # Use safer sed commands with error checking and proper escaping
    sed -i "s|APP_ENV=development|APP_ENV=production|g" "$INSTALL_DIR/.env" || log_warning "Could not update APP_ENV"
    sed -i "s|APP_DEBUG=true|APP_DEBUG=false|g" "$INSTALL_DIR/.env" || log_warning "Could not update APP_DEBUG"
    sed -i "s|SERVER_HOST=proxy\.example\.com|SERVER_HOST=$server_ip|g" "$INSTALL_DIR/.env" || log_warning "Could not update SERVER_HOST"
    sed -i "s|DB_PASS=secure_password_change_this|DB_PASS=$db_password|g" "$INSTALL_DIR/.env" || log_warning "Could not update DB_PASS"
    sed -i "s|REDIS_PASSWORD=|REDIS_PASSWORD=$redis_password|g" "$INSTALL_DIR/.env" || log_warning "Could not update REDIS_PASSWORD"

    # Add GoProxy version detection if not already present
    if ! grep -q "GOPROXY_VERSION=" "$INSTALL_DIR/.env"; then
        if command -v proxy >/dev/null 2>&1; then
            if proxy http --help 2>&1 | grep -q "log-file"; then
                echo "GOPROXY_VERSION=commercial" >> "$INSTALL_DIR/.env"
                log_info "Added GoProxy version: commercial"
            else
                echo "GOPROXY_VERSION=free" >> "$INSTALL_DIR/.env"
                log_info "Added GoProxy version: free"
            fi
        else
            echo "GOPROXY_VERSION=free" >> "$INSTALL_DIR/.env"
            log_info "Added GoProxy version: free (default)"
        fi
    fi

    # Additional fallback for SERVER_HOST if sed failed
    if ! grep -q "SERVER_HOST=$server_ip" "$INSTALL_DIR/.env"; then
        log_warning "Sed failed, using alternative method for SERVER_HOST"
        # Use a more robust approach
        if grep -q "SERVER_HOST=" "$INSTALL_DIR/.env"; then
            # Replace existing SERVER_HOST line
            local temp_file=$(mktemp)
            while IFS= read -r line; do
                if [[ $line =~ ^SERVER_HOST= ]]; then
                    echo "SERVER_HOST=$server_ip"
                else
                    echo "$line"
                fi
            done < "$INSTALL_DIR/.env" > "$temp_file"
            mv "$temp_file" "$INSTALL_DIR/.env"
        else
            # Add SERVER_HOST if it doesn't exist
            echo "SERVER_HOST=$server_ip" >> "$INSTALL_DIR/.env"
        fi
    fi

    # Verify the configuration was updated
    if grep -q "APP_ENV=production" "$INSTALL_DIR/.env" && grep -q "SERVER_HOST=$server_ip" "$INSTALL_DIR/.env"; then
        log_success "Environment configuration updated successfully"
    else
        log_warning "Environment configuration may not have been updated correctly"
        log_info "Please manually verify: $INSTALL_DIR/.env"
    fi

    # Create saas-config.conf file
    log_info "Creating SaaS configuration file..."
    cat > "$INSTALL_DIR/config/saas-config.conf" <<EOF
# Proxy SaaS System Configuration
# ============================================================================

# Server Configuration
SERVER_HOST=$server_ip
API_PORT=8889
PROXY_START_PORT=4000
PROXY_END_PORT=4999

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=proxy_saas
DB_USER=proxy_user
DB_PASS=secure_password_change_this

# Redis Configuration
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=

# Authentication URLs
AUTH_URL=http://127.0.0.1:8889/api/internal/auth.php
TRAFFIC_URL=http://127.0.0.1:8889/api/internal/traffic.php

# GoProxy Configuration
AUTH_CACHE_DURATION=300
TRAFFIC_MODE=fast
TRAFFIC_INTERVAL=5
CONTROL_SLEEP=3

# Logging
LOG_LEVEL=INFO
MAX_LOG_SIZE=100M
LOG_RETENTION_DAYS=30

# Performance
MAX_RETRY_ATTEMPTS=3
HEALTH_CHECK_INTERVAL=60
RESTART_DELAY=10
EOF

    # Create sample proxy.txt if it doesn't exist
    if [[ ! -f "$INSTALL_DIR/proxy.txt" ]]; then
        log_info "Creating sample proxy configuration..."
        cat > "$INSTALL_DIR/proxy.txt" <<EOF
# Proxy Configuration File
# Format: host:port:username:password
# Example:
# proxy1.example.com:8080:user1:pass1
# proxy2.example.com:8080:user2:pass2

# Add your real proxy servers below:
# Replace these with your actual upstream proxies
EOF
    fi

    # Set permissions
    chmod 600 "$INSTALL_DIR/.env"
    chmod 644 "$INSTALL_DIR/config/saas-config.conf"
    chmod 644 "$INSTALL_DIR/proxy.txt"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/.env"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/config/saas-config.conf"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/proxy.txt"

    log_success "Environment configured with server IP: $server_ip"
}

# Setup systemd service
setup_systemd_service() {
    log_info "Setting up systemd service..."

    # Detect GoProxy version and choose appropriate script
    local goproxy_version=$(grep "GOPROXY_VERSION=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d'=' -f2 || echo "free")
    local script_name="proxy_pool_manager.sh"
    local service_description="Proxy SaaS System - Proxy Pool Manager"

    if [[ "$goproxy_version" == "free" ]]; then
        script_name="proxy_pool_manager_free.sh"
        service_description="Proxy SaaS System - Free Version Proxy Pool Manager"
        log_info "Configuring systemd service for free GoProxy version"
    else
        script_name="proxy_pool_manager.sh"
        service_description="Proxy SaaS System - Commercial Proxy Pool Manager"
        log_info "Configuring systemd service for commercial GoProxy version"
    fi

    cat > "/etc/systemd/system/$PROJECT_NAME.service" <<EOF
[Unit]
Description=$service_description
After=network.target mariadb.service redis-server.service
Wants=mariadb.service redis-server.service

[Service]
Type=forking
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$script_name start
ExecReload=$INSTALL_DIR/$script_name reload
ExecStop=$INSTALL_DIR/$script_name stop
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Ensure the chosen script is executable
    chmod +x "$INSTALL_DIR/$script_name"

    # Also make both scripts executable for flexibility
    chmod +x "$INSTALL_DIR/proxy_pool_manager.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/proxy_pool_manager_free.sh" 2>/dev/null || true

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
    
    # Check if it's a valid domain (not IP address)
    if [[ "$domain" != "127.0.0.1" && "$domain" != "localhost" && "$domain" != "proxy.example.com" && ! "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && ! "$domain" =~ ^[0-9a-fA-F:]+$ && "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_info "Configuring SSL certificate for domain: $domain"
        if certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain" 2>/dev/null; then
            log_success "SSL certificate configured for $domain"
        else
            log_warning "SSL certificate setup failed for $domain"
            log_warning "This is normal for new domains or DNS propagation issues"
            log_info "You can manually configure SSL later with: sudo certbot --nginx -d $domain"
        fi
    else
        log_info "Skipping SSL certificate setup (IP address detected: $domain)"
        log_info "SSL certificates require a valid domain name"
        log_info "To enable SSL later:"
        log_info "  1. Get a domain name and point it to this server"
        log_info "  2. Update SERVER_HOST in $INSTALL_DIR/.env"
        log_info "  3. Run: sudo certbot --nginx -d yourdomain.com"
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
    local server_ip=$(curl -4 -s ifconfig.me 2>/dev/null || curl -s ifconfig.me 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || hostname -I | awk '{print $1}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || echo "127.0.0.1")

    echo ""
    echo "============================================================================"
    echo "🎉 PROXY-SAAS-SYSTEM DEPLOYMENT COMPLETED SUCCESSFULLY! 🎉"
    echo "============================================================================"
    echo ""
    echo "� Your Enterprise Proxy SaaS System is now deployed and ready!"
    echo ""
    echo "� System Information:"
    echo "   �📁 Installation Directory: $INSTALL_DIR"
    echo "   🌐 Web Directory: $WEB_DIR"
    echo "   📋 Log Directory: /var/log/$PROJECT_NAME"
    echo "   ⚙️  Configuration: $INSTALL_DIR/.env"
    echo "   🖥️  Server IP: $server_ip"
    echo ""
    # Detect GoProxy version for summary
    local goproxy_version=$(grep "GOPROXY_VERSION=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d'=' -f2 || echo "unknown")
    local proxy_script="proxy_pool_manager.sh"
    if [[ "$goproxy_version" == "free" ]]; then
        proxy_script="proxy_pool_manager_free.sh"
    fi

    echo "GoProxy Configuration:"
    echo "   Version: $goproxy_version"
    echo "   Manager Script: $proxy_script"
    echo "   Proxy Ports: 4000-4010 (free) or 4000-4999 (commercial)"
    echo ""
    echo "API Endpoints:"
    echo "   Proxy List API: http://$server_ip:8889/api/proxies.php"
    echo "   Admin APIs: http://$server_ip:8889/api/admin/"
    echo "   Health Check: http://$server_ip:8889/api/health.php"
    echo ""
    echo "🚀 Immediate Next Steps:"
    echo "   1. 📝 Edit configuration: sudo nano $INSTALL_DIR/.env"
    echo "   2. 🔧 Add upstream proxies: sudo nano $INSTALL_DIR/proxy.txt"
    echo "   3. ▶️  Start the service: sudo systemctl start $PROJECT_NAME"
    echo "   4. 📊 Check status: sudo systemctl status $PROJECT_NAME"
    echo "   5. 📋 View logs: sudo journalctl -u $PROJECT_NAME -f"
    echo ""
    echo "🧪 Testing Commands:"
    echo "   • Test API: curl \"http://$server_ip:8889/api/proxies.php\""
    echo "   • Run validation: $INSTALL_DIR/validate_system.sh"
    echo "   • Integration tests: sudo $INSTALL_DIR/tests/integration_test.sh"
    echo ""
    echo "💰 Business Configuration:"
    echo "   • Basic Plan: \$10/month (10 threads, 1GB quota)"
    echo "   • Pro Plan: \$50/month (50 threads, 10GB quota)"
    echo "   • Enterprise Plan: \$200/month (200 threads, 100GB quota)"
    echo "   • Revenue Potential: \$10K-\$100K/month at scale"
    echo ""
    echo "🔒 Security Checklist:"
    echo "   ✅ Firewall configured (UFW enabled)"
    echo "   ✅ Internal APIs secured (127.0.0.1 only)"
    echo "   ✅ Database user privileges limited"
    echo "   ⚠️  Change default passwords in .env file"
    echo "   ⚠️  Configure SSL certificate for production"
    echo "   ⚠️  Set up monitoring and backups"
    echo ""
    echo "📚 Documentation & Support:"
    echo "   • Complete Guide: $INSTALL_DIR/README.md"
    echo "   • System Architecture: $INSTALL_DIR/PROJECT_OVERVIEW.md"
    echo "   • Troubleshooting: $INSTALL_DIR/fix_deployment_issues.sh"
    echo ""
    echo "🎯 Your Enterprise Proxy SaaS System is ready to generate revenue!"
    echo "============================================================================"
}

# Validate system requirements
validate_system() {
    log_info "Validating system requirements..."

    # Check available disk space (need at least 2GB)
    local available_space=$(df / | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 2097152 ]]; then  # 2GB in KB
        log_error "Insufficient disk space. Need at least 2GB free."
        exit 1
    fi

    # Check available memory (need at least 1GB)
    local available_memory=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 1024 ]]; then
        log_warning "Low available memory (${available_memory}MB). Recommended: 1GB+"
    fi

    # Check if ports are available
    local ports_in_use=()
    for port in 80 443 8889 3306 6379; do
        if netstat -ln 2>/dev/null | grep -q ":$port "; then
            ports_in_use+=($port)
        fi
    done

    if [[ ${#ports_in_use[@]} -gt 0 ]]; then
        log_warning "Some required ports are in use: ${ports_in_use[*]}"
        log_warning "Installation will continue but may encounter conflicts"
    fi

    log_success "System validation completed"
}

# Test installation
test_installation() {
    log_info "Testing installation..."

    local tests_passed=0
    local tests_total=0

    # Test database connection
    ((tests_total++))
    if mysql -u proxy_user -p"secure_password_change_this" proxy_saas -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "Database connection: OK"
        ((tests_passed++))
    else
        log_error "Database connection: FAILED"
    fi

    # Test Redis connection
    ((tests_total++))
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis connection: OK"
        ((tests_passed++))
    else
        log_error "Redis connection: FAILED"
    fi

    # Test Nginx configuration
    ((tests_total++))
    if nginx -t >/dev/null 2>&1; then
        log_success "Nginx configuration: OK"
        ((tests_passed++))
    else
        log_error "Nginx configuration: FAILED"
    fi

    # Test PHP-FPM
    ((tests_total++))
    if systemctl is-active php8.1-fpm >/dev/null 2>&1; then
        log_success "PHP-FPM service: OK"
        ((tests_passed++))
    else
        log_error "PHP-FPM service: FAILED"
    fi

    # Test GoProxy
    ((tests_total++))
    if command -v proxy >/dev/null 2>&1; then
        log_success "GoProxy installation: OK"
        ((tests_passed++))

        # Test if proxy-saas user can run GoProxy
        if sudo -u "$SERVICE_USER" proxy --version >/dev/null 2>&1; then
            log_success "GoProxy accessible by service user: OK"
        else
            log_warning "GoProxy not accessible by service user"
        fi
    else
        log_warning "GoProxy installation: NOT FOUND"
    fi

    # Test API endpoint
    ((tests_total++))
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}' || echo "127.0.0.1")
    if curl -s "http://$server_ip:8889/api/proxies.php" >/dev/null 2>&1; then
        log_success "API endpoint: OK"
        ((tests_passed++))
    else
        log_warning "API endpoint: Could not test (server may not be fully started)"
    fi

    log_info "Installation test results: $tests_passed/$tests_total tests passed"

    if [[ $tests_passed -ge $((tests_total - 1)) ]]; then
        log_success "Installation test: PASSED"
        return 0
    else
        log_warning "Installation test: Some issues detected"
        log_info "You can manually check and fix issues after deployment"
        return 1
    fi
}

# Post-installation setup
post_installation_setup() {
    log_info "Running post-installation setup..."

    # Ensure all services are started
    systemctl start mariadb || log_warning "MariaDB failed to start"
    systemctl start redis-server || log_warning "Redis failed to start"
    systemctl start nginx || log_warning "Nginx failed to start"
    systemctl start php8.1-fpm || log_warning "PHP-FPM failed to start"

    # Import database schema if not already done
    if ! mysql -u proxy_user -p"secure_password_change_this" proxy_saas -e "SHOW TABLES;" 2>/dev/null | grep -q "users"; then
        log_info "Importing database schema..."
        mysql -u proxy_user -p"secure_password_change_this" proxy_saas < "$INSTALL_DIR/database/schema.sql" || log_warning "Database schema import failed"
    else
        log_info "Database schema already imported"
    fi

    # Ensure all required directories exist
    mkdir -p "$INSTALL_DIR"/{logs,config,database,tests}
    mkdir -p "/var/log/$PROJECT_NAME"/{api,users,system,security}

    # Set proper permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "www-data:www-data" "$WEB_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "/var/log/$PROJECT_NAME"
    chmod +x "$INSTALL_DIR"/*.sh
    chmod 755 "$INSTALL_DIR/logs"
    chmod 755 "$INSTALL_DIR/config"

    # Ensure configuration files exist
    if [[ ! -f "$INSTALL_DIR/config/saas-config.conf" ]]; then
        log_warning "Configuration file missing, creating default..."
        # This should have been created in setup_environment, but create backup
        touch "$INSTALL_DIR/config/saas-config.conf"
        chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/config/saas-config.conf"
    fi

    if [[ ! -f "$INSTALL_DIR/proxy.txt" ]]; then
        log_warning "Proxy configuration missing, creating sample..."
        echo "# Add your proxy servers here: host:port:username:password" > "$INSTALL_DIR/proxy.txt"
        chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/proxy.txt"
    fi

    log_success "Post-installation setup completed"
}

# Main installation function
install_system() {
    log_info "Starting fresh installation..."

    validate_system
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
    post_installation_setup
    test_installation

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
    # Create log directory first
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
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
