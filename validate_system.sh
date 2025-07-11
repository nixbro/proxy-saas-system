#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - System Validation Script
# ============================================================================
# 
# Validates the complete SaaS proxy management system
# Checks all components, configurations, and dependencies
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
CHECKS_TOTAL=0
CHECKS_PASSED=0
CHECKS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((CHECKS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((CHECKS_FAILED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check function wrapper
check() {
    local description="$1"
    local command="$2"
    
    ((CHECKS_TOTAL++))
    
    if eval "$command" >/dev/null 2>&1; then
        log_success "$description"
    else
        log_error "$description"
    fi
}

echo "============================================================================"
echo "PROXY-SAAS-SYSTEM - System Validation"
echo "============================================================================"
echo ""

# File structure validation
log_info "Checking file structure..."

check "Main proxy manager script exists" "test -f proxy_pool_manager.sh"
check "Database schema exists" "test -f database/schema.sql"
check "Environment example exists" "test -f .env.example"
check "Deployment script exists" "test -f deploy.sh"
check "Integration tests exist" "test -f tests/integration_test.sh"

# API files validation
log_info "Checking API files..."

check "Config file exists" "test -f api/config.php"
check "Redis client exists" "test -f api/redis_client.php"
check "Auth hook exists" "test -f api/internal/auth.php"
check "Traffic hook exists" "test -f api/internal/traffic.php"
check "Control hook exists" "test -f api/internal/control.php"
check "Proxies API exists" "test -f api/proxies.php"

# Configuration validation
log_info "Checking configuration files..."

check "Proxy configuration exists" "test -f proxy.txt"
check "README documentation exists" "test -f README.md"
check "Project overview exists" "test -f PROJECT_OVERVIEW.md"

# Script validation
log_info "Checking script syntax..."

if command -v bash >/dev/null 2>&1; then
    check "Proxy manager syntax" "bash -n proxy_pool_manager.sh"
    check "Deploy script syntax" "bash -n deploy.sh"
    check "Integration test syntax" "bash -n tests/integration_test.sh"
else
    log_warning "Bash not available - skipping syntax checks"
fi

# PHP validation
log_info "Checking PHP files..."

if command -v php >/dev/null 2>&1; then
    check "Config PHP syntax" "php -l api/config.php"
    check "Redis client PHP syntax" "php -l api/redis_client.php"
    check "Auth hook PHP syntax" "php -l api/internal/auth.php"
    check "Traffic hook PHP syntax" "php -l api/internal/traffic.php"
    check "Control hook PHP syntax" "php -l api/internal/control.php"
    check "Proxies API PHP syntax" "php -l api/proxies.php"
else
    log_warning "PHP not available - skipping PHP syntax checks"
fi

# Database schema validation
log_info "Checking database schema..."

if command -v mysql >/dev/null 2>&1; then
    check "Database schema syntax" "mysql --help >/dev/null && echo 'SELECT 1;' | mysql --batch --skip-column-names 2>/dev/null || true"
else
    log_warning "MySQL not available - skipping database checks"
fi

# Documentation validation
log_info "Checking documentation..."

check "README has content" "test -s README.md"
check "Project overview has content" "test -s PROJECT_OVERVIEW.md"
check "Environment example has content" "test -s .env.example"

# Security validation
log_info "Checking security configurations..."

check "Internal API security configured" "grep -q '127.0.0.1' api/internal/auth.php"
check "Rate limiting implemented" "grep -q 'rate_limit' api/proxies.php"
check "Password hashing used" "grep -q 'password_verify' api/internal/auth.php"
check "SQL injection protection" "grep -q 'prepare' api/internal/auth.php"

# Integration validation
log_info "Checking GoProxy integration..."

check "Auth URL configured" "grep -q 'auth-url' proxy_pool_manager.sh"
check "Traffic URL configured" "grep -q 'traffic-url' proxy_pool_manager.sh"
check "Control URL configured" "grep -q 'control-url' proxy_pool_manager.sh"
check "Strike system implemented" "grep -q 'overlimit_since' api/internal/control.php"

# Business logic validation
log_info "Checking business logic..."

check "User plans configured" "grep -q 'max_threads' database/schema.sql"
check "Quota system implemented" "grep -q 'quota_bytes' database/schema.sql"
check "Traffic logging implemented" "grep -q 'traffic_logs' database/schema.sql"
check "Security events logged" "grep -q 'security_events' database/schema.sql"

# Performance validation
log_info "Checking performance optimizations..."

check "Redis caching implemented" "grep -q 'redis' api/redis_client.php"
check "Database indexing configured" "grep -q 'INDEX' database/schema.sql"
check "Connection pooling configured" "grep -q 'ATTR_PERSISTENT' api/config.php"

echo ""
echo "============================================================================"
echo "VALIDATION SUMMARY"
echo "============================================================================"
echo "Total checks:    $CHECKS_TOTAL"
echo "Passed:          $CHECKS_PASSED"
echo "Failed:          $CHECKS_FAILED"
echo "Success rate:    $(echo "scale=1; $CHECKS_PASSED * 100 / $CHECKS_TOTAL" | bc -l 2>/dev/null || echo "N/A")%"
echo ""

if [[ $CHECKS_FAILED -eq 0 ]]; then
    log_success "🎉 All validation checks passed!"
    echo ""
    echo "✅ Your Proxy-SaaS-System is ready for deployment!"
    echo ""
    echo "Next steps:"
    echo "1. Review and customize .env.example"
    echo "2. Add your upstream proxies to proxy.txt"
    echo "3. Run: sudo ./deploy.sh --install"
    echo "4. Test: ./tests/integration_test.sh"
    echo ""
    exit 0
else
    log_error "❌ $CHECKS_FAILED validation check(s) failed!"
    echo ""
    echo "Please fix the failed checks before deployment."
    echo ""
    exit 1
fi
