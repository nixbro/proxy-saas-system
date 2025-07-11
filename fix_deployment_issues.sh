#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Deployment Issue Fix Script
# ============================================================================
# 
# Fixes common deployment issues and ensures clean installation
# Run this script if deployment fails or encounters database errors
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "============================================================================"
echo "PROXY-SAAS-SYSTEM - Deployment Issue Fixer"
echo "============================================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    log_error "Please run: sudo $0"
    exit 1
fi

# Fix 1: Clean up existing database tables
fix_database_issues() {
    log_info "Fixing database issues..."
    
    local db_user="proxy_user"
    local db_pass="secure_password_change_this"
    local db_name="proxy_saas"
    local root_pass="secure_root_password_change_this"
    
    # Test database connection
    if ! mysql -u root -p"$root_pass" -e "SELECT 1;" >/dev/null 2>&1; then
        log_warning "Cannot connect to database with root password"
        log_info "Attempting to set root password..."
        mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$root_pass';" 2>/dev/null || true
    fi
    
    # Drop and recreate database for clean installation
    log_info "Recreating database for clean installation..."
    mysql -u root -p"$root_pass" <<EOF
DROP DATABASE IF EXISTS $db_name;
CREATE DATABASE $db_name CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
DROP USER IF EXISTS '$db_user'@'localhost';
CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass';
GRANT ALL PRIVILEGES ON $db_name.* TO '$db_user'@'localhost';
FLUSH PRIVILEGES;
EOF
    
    log_success "Database recreated successfully"
}

# Fix 2: Install missing PHP packages
fix_php_packages() {
    log_info "Installing missing PHP packages..."
    
    # Install PHP packages without the problematic php8.1-json
    apt-get update
    apt-get install -y \
        php8.1-fpm \
        php8.1-mysql \
        php8.1-redis \
        php8.1-curl \
        php8.1-cli \
        php8.1-mbstring \
        php8.1-xml \
        php8.1-zip \
        php8.1-gd \
        bc
    
    log_success "PHP packages installed"
}

# Fix 3: Ensure GoProxy is available
fix_goproxy() {
    log_info "Checking GoProxy installation..."
    
    if command -v proxy >/dev/null 2>&1; then
        log_success "GoProxy is already installed"
        proxy --version
    else
        log_warning "GoProxy not found, please install manually"
        log_info "Download from: https://github.com/snail007/goproxy/releases"
    fi
}

# Fix 4: Create necessary directories
fix_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p /opt/proxy-saas-system
    mkdir -p /var/www/html/proxy-saas-system
    mkdir -p /var/log/proxy-saas-system/{api,users,system,security}
    mkdir -p /etc/proxy-saas-system
    
    # Create proxy-saas user if not exists
    if ! id "proxy-saas" >/dev/null 2>&1; then
        useradd -r -s /bin/bash -d /opt/proxy-saas-system proxy-saas
        log_success "Created proxy-saas user"
    fi
    
    log_success "Directories created"
}

# Fix 5: Fix file permissions
fix_permissions() {
    log_info "Fixing file permissions..."
    
    # Make scripts executable
    chmod +x *.sh 2>/dev/null || true
    chmod +x tests/*.sh 2>/dev/null || true
    
    # Set proper ownership
    chown -R proxy-saas:proxy-saas /opt/proxy-saas-system 2>/dev/null || true
    chown -R www-data:www-data /var/www/html/proxy-saas-system 2>/dev/null || true
    chown -R proxy-saas:proxy-saas /var/log/proxy-saas-system 2>/dev/null || true
    
    log_success "Permissions fixed"
}

# Fix 6: Configure MariaDB properly
fix_mariadb_config() {
    log_info "Configuring MariaDB..."
    
    # Find MariaDB config file
    local config_file=""
    if [[ -f "/etc/mysql/mariadb.conf.d/50-server.cnf" ]]; then
        config_file="/etc/mysql/mariadb.conf.d/50-server.cnf"
    elif [[ -f "/etc/mysql/mysql.conf.d/mysqld.cnf" ]]; then
        config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    elif [[ -f "/etc/mysql/my.cnf" ]]; then
        config_file="/etc/mysql/my.cnf"
    fi
    
    if [[ -n "$config_file" ]]; then
        # Add configuration if not already present
        if ! grep -q "Proxy SaaS System Configuration" "$config_file"; then
            cat >> "$config_file" <<EOF

# Proxy SaaS System Configuration
event_scheduler = ON
max_connections = 500
innodb_buffer_pool_size = 256M
EOF
            log_success "MariaDB configuration updated"
        else
            log_info "MariaDB already configured"
        fi
    else
        log_warning "MariaDB config file not found"
    fi
    
    # Restart MariaDB
    systemctl restart mariadb
    systemctl enable mariadb
}

# Fix 7: Import database schema
import_database_schema() {
    log_info "Importing database schema..."
    
    local db_user="proxy_user"
    local db_pass="secure_password_change_this"
    local db_name="proxy_saas"
    local root_pass="secure_root_password_change_this"
    
    if [[ -f "database/schema.sql" ]]; then
        mysql -u "$db_user" -p"$db_pass" "$db_name" < database/schema.sql
        
        # Enable event scheduler with root privileges
        mysql -u root -p"$root_pass" -e "SET GLOBAL event_scheduler = ON;" || log_warning "Could not enable event scheduler"
        
        log_success "Database schema imported"
    else
        log_error "Database schema file not found: database/schema.sql"
        return 1
    fi
}

# Fix 8: Test system components
test_components() {
    log_info "Testing system components..."
    
    # Test database connection
    if mysql -u proxy_user -p"secure_password_change_this" proxy_saas -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "Database connection: OK"
    else
        log_error "Database connection: FAILED"
    fi
    
    # Test Redis connection
    if redis-cli ping | grep -q "PONG"; then
        log_success "Redis connection: OK"
    else
        log_error "Redis connection: FAILED"
    fi
    
    # Test GoProxy
    if command -v proxy >/dev/null 2>&1; then
        log_success "GoProxy: OK"
    else
        log_error "GoProxy: NOT FOUND"
    fi
    
    # Test PHP
    if php --version >/dev/null 2>&1; then
        log_success "PHP: OK"
    else
        log_error "PHP: FAILED"
    fi
}

# Main execution
main() {
    log_info "Starting deployment issue fixes..."
    
    fix_php_packages
    fix_goproxy
    fix_directories
    fix_permissions
    fix_mariadb_config
    fix_database_issues
    import_database_schema
    test_components
    
    echo ""
    log_success "All fixes applied successfully!"
    echo ""
    log_info "You can now run the deployment script:"
    log_info "sudo ./deploy.sh --install"
    echo ""
}

# Run main function
main "$@"
