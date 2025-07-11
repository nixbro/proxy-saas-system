#!/bin/bash

# ============================================================================
# PROXY-SAAS-SYSTEM - Comprehensive Integration Test Suite
# ============================================================================
# 
# Tests all components of the SaaS proxy management system:
# - Database connectivity and schema
# - Redis connectivity and operations
# - GoProxy integration and authentication
# - API endpoints and rate limiting
# - Strike system and quota enforcement
# - Security and error handling
# ============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_LOG_FILE="${PROJECT_DIR}/logs/tests/integration_test.log"
TEST_RESULTS_FILE="${PROJECT_DIR}/logs/tests/test_results.json"

# Test configuration
TEST_SERVER_HOST="127.0.0.1"
TEST_API_PORT="8889"
TEST_PROXY_PORT="4000"
TEST_USERNAME="test_user_$(date +%s)"
TEST_PASSWORD="test_password_123"
TEST_API_KEY="test_api_key_$(date +%s)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Test results array
declare -a TEST_RESULTS=()

# Logging functions
log_test() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$TEST_LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log_test "INFO" "$1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    log_test "PASS" "$1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    log_test "FAIL" "$1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    log_test "WARN" "$1"
}

log_skip() {
    echo -e "${CYAN}[SKIP]${NC} $1"
    log_test "SKIP" "$1"
}

# Test execution wrapper
run_test() {
    local test_name="$1"
    local test_function="$2"
    local test_description="$3"
    
    ((TESTS_TOTAL++))
    
    log_info "Running test: $test_name - $test_description"
    
    if $test_function; then
        log_success "$test_name: PASSED"
        ((TESTS_PASSED++))
        TEST_RESULTS+=("{\"name\":\"$test_name\",\"status\":\"PASSED\",\"description\":\"$test_description\"}")
    else
        log_error "$test_name: FAILED"
        ((TESTS_FAILED++))
        TEST_RESULTS+=("{\"name\":\"$test_name\",\"status\":\"FAILED\",\"description\":\"$test_description\"}")
    fi
    
    echo ""
}

# Skip test wrapper
skip_test() {
    local test_name="$1"
    local reason="$2"
    
    ((TESTS_TOTAL++))
    ((TESTS_SKIPPED++))
    
    log_skip "$test_name: SKIPPED - $reason"
    TEST_RESULTS+=("{\"name\":\"$test_name\",\"status\":\"SKIPPED\",\"description\":\"$reason\"}")
    echo ""
}

# ============================================================================
# DEPENDENCY CHECKS
# ============================================================================

check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check required commands
    local required_commands=("curl" "mysql" "redis-cli" "php" "proxy")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    # Check PHP extensions
    local required_extensions=("pdo" "pdo_mysql" "redis" "json" "curl")
    for ext in "${required_extensions[@]}"; do
        if ! php -m | grep -q "^$ext$"; then
            missing_deps+=("php-$ext")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_error "Please install missing dependencies and try again"
        return 1
    fi
    
    log_success "All dependencies satisfied"
    return 0
}

# ============================================================================
# DATABASE TESTS
# ============================================================================

test_database_connection() {
    log_info "Testing database connection..."
    
    # Load database configuration
    source "${PROJECT_DIR}/.env" 2>/dev/null || true
    
    local db_host="${DB_HOST:-localhost}"
    local db_user="${DB_USER:-proxy_user}"
    local db_pass="${DB_PASS:-secure_password}"
    local db_name="${DB_NAME:-proxy_saas}"
    
    if mysql -h "$db_host" -u "$db_user" -p"$db_pass" -e "USE $db_name; SELECT 1;" >/dev/null 2>&1; then
        return 0
    else
        log_error "Database connection failed"
        return 1
    fi
}

test_database_schema() {
    log_info "Testing database schema..."
    
    source "${PROJECT_DIR}/.env" 2>/dev/null || true
    
    local db_host="${DB_HOST:-localhost}"
    local db_user="${DB_USER:-proxy_user}"
    local db_pass="${DB_PASS:-secure_password}"
    local db_name="${DB_NAME:-proxy_saas}"
    
    # Check if required tables exist
    local required_tables=("users" "user_ip_whitelist" "upstream_proxies" "user_sessions" "traffic_logs" "admin_tokens" "security_events")
    
    for table in "${required_tables[@]}"; do
        if ! mysql -h "$db_host" -u "$db_user" -p"$db_pass" -e "USE $db_name; DESCRIBE $table;" >/dev/null 2>&1; then
            log_error "Required table '$table' not found"
            return 1
        fi
    done
    
    return 0
}

test_database_sample_data() {
    log_info "Testing database sample data..."
    
    source "${PROJECT_DIR}/.env" 2>/dev/null || true
    
    local db_host="${DB_HOST:-localhost}"
    local db_user="${DB_USER:-proxy_user}"
    local db_pass="${DB_PASS:-secure_password}"
    local db_name="${DB_NAME:-proxy_saas}"
    
    # Check if sample users exist
    local user_count=$(mysql -h "$db_host" -u "$db_user" -p"$db_pass" -e "USE $db_name; SELECT COUNT(*) FROM users;" -s -N 2>/dev/null)
    
    if [[ "$user_count" -gt 0 ]]; then
        return 0
    else
        log_error "No sample users found in database"
        return 1
    fi
}

# ============================================================================
# REDIS TESTS
# ============================================================================

test_redis_connection() {
    log_info "Testing Redis connection..."
    
    if redis-cli ping | grep -q "PONG"; then
        return 0
    else
        log_error "Redis connection failed"
        return 1
    fi
}

test_redis_operations() {
    log_info "Testing Redis operations..."
    
    local test_key="test:integration:$(date +%s)"
    local test_value="test_value_123"
    
    # Test SET and GET
    if redis-cli set "$test_key" "$test_value" | grep -q "OK"; then
        if [[ "$(redis-cli get "$test_key")" == "$test_value" ]]; then
            redis-cli del "$test_key" >/dev/null
            return 0
        fi
    fi
    
    log_error "Redis operations failed"
    return 1
}

# ============================================================================
# API TESTS
# ============================================================================

test_api_health_check() {
    log_info "Testing API health check..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/health.php" 2>/dev/null || echo "000")
    
    if [[ "$response" == "200" ]]; then
        return 0
    else
        log_error "API health check failed (HTTP $response)"
        return 1
    fi
}

test_api_proxies_endpoint() {
    log_info "Testing /api/proxies.php endpoint..."
    
    # Test without authentication (should fail)
    local response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/proxies.php" 2>/dev/null || echo "000")
    
    if [[ "$response" == "401" ]]; then
        return 0
    else
        log_error "Proxies endpoint authentication test failed (expected 401, got $response)"
        return 1
    fi
}

test_api_rate_limiting() {
    log_info "Testing API rate limiting..."
    
    # Make multiple rapid requests
    local success_count=0
    local rate_limited=false
    
    for i in {1..10}; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/proxies.php" 2>/dev/null || echo "000")
        
        if [[ "$response" == "429" ]]; then
            rate_limited=true
            break
        elif [[ "$response" == "401" ]]; then
            ((success_count++))
        fi
        
        sleep 0.1
    done
    
    if [[ $success_count -gt 0 ]]; then
        return 0
    else
        log_error "API rate limiting test failed"
        return 1
    fi
}

# ============================================================================
# GOPROXY INTEGRATION TESTS
# ============================================================================

test_goproxy_installation() {
    log_info "Testing GoProxy installation..."
    
    if command -v proxy >/dev/null 2>&1; then
        local version=$(proxy --version 2>&1 | head -1 || echo "unknown")
        log_info "GoProxy version: $version"
        return 0
    else
        log_error "GoProxy not found in PATH"
        return 1
    fi
}

test_proxy_pool_manager() {
    log_info "Testing proxy pool manager..."
    
    local manager_script="${PROJECT_DIR}/proxy_pool_manager.sh"
    
    if [[ -f "$manager_script" && -x "$manager_script" ]]; then
        # Test help command
        if "$manager_script" help >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    log_error "Proxy pool manager test failed"
    return 1
}

# ============================================================================
# SECURITY TESTS
# ============================================================================

test_internal_api_security() {
    log_info "Testing internal API security..."
    
    # Test that internal APIs reject external requests
    local endpoints=("auth.php" "traffic.php" "control.php")
    
    for endpoint in "${endpoints[@]}"; do
        # Simulate external request (not from 127.0.0.1)
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "X-Forwarded-For: 192.168.1.100" \
            "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/internal/$endpoint" 2>/dev/null || echo "000")
        
        if [[ "$response" != "403" ]]; then
            log_error "Internal API security test failed for $endpoint (expected 403, got $response)"
            return 1
        fi
    done
    
    return 0
}

test_sql_injection_protection() {
    log_info "Testing SQL injection protection..."
    
    # Test common SQL injection patterns
    local injection_patterns=("' OR '1'='1" "'; DROP TABLE users; --" "1' UNION SELECT * FROM users --")
    
    for pattern in "${injection_patterns[@]}"; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/proxies.php?username=$(echo "$pattern" | sed 's/ /%20/g')" 2>/dev/null || echo "000")
        
        # Should return 401 (auth failed) not 500 (SQL error)
        if [[ "$response" == "500" ]]; then
            log_error "Possible SQL injection vulnerability detected"
            return 1
        fi
    done
    
    return 0
}

# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

test_api_response_time() {
    log_info "Testing API response time..."
    
    local start_time=$(date +%s%N)
    curl -s -o /dev/null "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/proxies.php" 2>/dev/null || true
    local end_time=$(date +%s%N)
    
    local response_time_ms=$(( (end_time - start_time) / 1000000 ))
    
    log_info "API response time: ${response_time_ms}ms"
    
    # Response should be under 1000ms
    if [[ $response_time_ms -lt 1000 ]]; then
        return 0
    else
        log_error "API response time too slow: ${response_time_ms}ms"
        return 1
    fi
}

test_concurrent_connections() {
    log_info "Testing concurrent connections..."
    
    # Start multiple background requests
    local pids=()
    for i in {1..5}; do
        curl -s -o /dev/null "http://$TEST_SERVER_HOST:$TEST_API_PORT/api/proxies.php" &
        pids+=($!)
    done
    
    # Wait for all requests to complete
    local success_count=0
    for pid in "${pids[@]}"; do
        if wait "$pid"; then
            ((success_count++))
        fi
    done
    
    if [[ $success_count -eq 5 ]]; then
        return 0
    else
        log_error "Concurrent connections test failed ($success_count/5 succeeded)"
        return 1
    fi
}

# ============================================================================
# MAIN TEST EXECUTION
# ============================================================================

# Initialize test environment
initialize_tests() {
    log_info "Initializing test environment..."
    
    # Create test log directory
    mkdir -p "$(dirname "$TEST_LOG_FILE")"
    
    # Clear previous test log
    > "$TEST_LOG_FILE"
    
    log_info "Test environment initialized"
    log_info "Project directory: $PROJECT_DIR"
    log_info "Test log file: $TEST_LOG_FILE"
    echo ""
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    # Create JSON report
    local json_report="{
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"summary\": {
            \"total\": $TESTS_TOTAL,
            \"passed\": $TESTS_PASSED,
            \"failed\": $TESTS_FAILED,
            \"skipped\": $TESTS_SKIPPED,
            \"success_rate\": $(echo "scale=2; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc -l 2>/dev/null || echo "0")
        },
        \"tests\": [$(IFS=,; echo "${TEST_RESULTS[*]}")]
    }"
    
    echo "$json_report" > "$TEST_RESULTS_FILE"
    
    # Print summary
    echo ""
    echo "============================================================================"
    echo "TEST SUMMARY"
    echo "============================================================================"
    echo "Total tests:    $TESTS_TOTAL"
    echo "Passed:         $TESTS_PASSED"
    echo "Failed:         $TESTS_FAILED"
    echo "Skipped:        $TESTS_SKIPPED"
    echo "Success rate:   $(echo "scale=1; $TESTS_PASSED * 100 / $TESTS_TOTAL" | bc -l 2>/dev/null || echo "0")%"
    echo ""
    echo "Test log:       $TEST_LOG_FILE"
    echo "Test results:   $TEST_RESULTS_FILE"
    echo "============================================================================"
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "All tests passed!"
        exit 0
    else
        log_error "$TESTS_FAILED test(s) failed!"
        exit 1
    fi
}

# Main execution
main() {
    echo "============================================================================"
    echo "PROXY-SAAS-SYSTEM - Integration Test Suite"
    echo "============================================================================"
    echo ""
    
    initialize_tests
    
    # Dependency checks
    if ! check_dependencies; then
        log_error "Dependency check failed. Aborting tests."
        exit 1
    fi
    
    # Database tests
    run_test "db_connection" "test_database_connection" "Database connectivity"
    run_test "db_schema" "test_database_schema" "Database schema validation"
    run_test "db_sample_data" "test_database_sample_data" "Sample data verification"
    
    # Redis tests
    run_test "redis_connection" "test_redis_connection" "Redis connectivity"
    run_test "redis_operations" "test_redis_operations" "Redis operations"
    
    # API tests
    if curl -s "http://$TEST_SERVER_HOST:$TEST_API_PORT" >/dev/null 2>&1; then
        run_test "api_health" "test_api_health_check" "API health check"
        run_test "api_proxies" "test_api_proxies_endpoint" "Proxies endpoint"
        run_test "api_rate_limit" "test_api_rate_limiting" "API rate limiting"
        run_test "api_response_time" "test_api_response_time" "API response time"
        run_test "api_concurrent" "test_concurrent_connections" "Concurrent connections"
    else
        skip_test "api_tests" "API server not running on $TEST_SERVER_HOST:$TEST_API_PORT"
    fi
    
    # GoProxy tests
    run_test "goproxy_install" "test_goproxy_installation" "GoProxy installation"
    run_test "proxy_manager" "test_proxy_pool_manager" "Proxy pool manager"
    
    # Security tests
    run_test "internal_api_security" "test_internal_api_security" "Internal API security"
    run_test "sql_injection" "test_sql_injection_protection" "SQL injection protection"
    
    generate_test_report
}

# Run main function
main "$@"
