-- ============================================================================
-- PROXY-SAAS-SYSTEM - Enterprise Database Schema
-- ============================================================================
-- Complete database structure for GoProxy-based SaaS proxy management
-- Supports: Real-time monitoring, Redis integration, Strike system, Quotas
-- ============================================================================

-- Drop existing database and recreate (for fresh installation)
-- DROP DATABASE IF EXISTS proxy_saas;
-- CREATE DATABASE proxy_saas CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
-- USE proxy_saas;

-- ============================================================================
-- CORE USER MANAGEMENT
-- ============================================================================

-- Users table with comprehensive plan management
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL COMMENT 'bcrypt hashed password',
    email VARCHAR(255) UNIQUE,
    api_key VARCHAR(255) UNIQUE COMMENT 'Customer API key for /api/proxies.php',
    
    -- Plan Configuration
    plan_name VARCHAR(50) DEFAULT 'basic',
    max_threads INT DEFAULT 10 COMMENT 'Maximum simultaneous connections',
    max_qps INT DEFAULT 10 COMMENT 'Requests per second burst limit',
    max_bandwidth_bps BIGINT DEFAULT 1048576 COMMENT 'Bytes per second limit (1MB default)',
    quota_bytes BIGINT DEFAULT 1073741824 COMMENT 'Monthly quota in bytes (1GB default)',
    
    -- Usage Tracking
    bytes_used BIGINT DEFAULT 0 COMMENT 'Current month usage',
    threads_live INT DEFAULT 0 COMMENT 'Current active connections (Redis mirror)',
    last_activity TIMESTAMP NULL,
    
    -- Account Status
    status ENUM('active', 'suspended', 'expired', 'banned') DEFAULT 'active',
    expires_at TIMESTAMP NULL COMMENT 'Plan expiration date',
    is_banned BOOLEAN DEFAULT FALSE,
    ban_reason TEXT NULL,
    ban_until TIMESTAMP NULL,
    
    -- Strike System
    overlimit_since TIMESTAMP NULL COMMENT 'When user first went over thread limit',
    timeout_until TIMESTAMP NULL COMMENT 'Banned until this time (1 hour penalty)',
    strike_count INT DEFAULT 0 COMMENT 'Number of violations',
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_username (username),
    INDEX idx_api_key (api_key),
    INDEX idx_status (status),
    INDEX idx_expires_at (expires_at),
    INDEX idx_timeout_until (timeout_until),
    INDEX idx_last_activity (last_activity)
);

-- ============================================================================
-- IP WHITELIST MANAGEMENT
-- ============================================================================

-- User IP whitelist for authentication
CREATE TABLE user_ip_whitelist (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    username VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NULL COMMENT 'Single IP address',
    ip_range VARCHAR(50) NULL COMMENT 'CIDR notation (e.g., 192.168.1.0/24)',
    description VARCHAR(255) DEFAULT '',
    status ENUM('active', 'inactive') DEFAULT 'active',
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_username (username),
    INDEX idx_ip_address (ip_address),
    INDEX idx_ip_range (ip_range),
    INDEX idx_status_expires (status, expires_at),
    
    -- Ensure either ip_address OR ip_range is set, not both
    CONSTRAINT chk_ip_or_range CHECK (
        (ip_address IS NOT NULL AND ip_range IS NULL) OR 
        (ip_address IS NULL AND ip_range IS NOT NULL)
    )
);

-- ============================================================================
-- PROXY POOL MANAGEMENT
-- ============================================================================

-- Upstream proxy servers
CREATE TABLE upstream_proxies (
    id INT PRIMARY KEY AUTO_INCREMENT,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    username VARCHAR(255),
    password VARCHAR(255),
    protocol ENUM('http', 'https', 'socks4', 'socks5') DEFAULT 'http',
    local_port INT UNIQUE COMMENT 'Local port (4000-4999) this proxy is bound to',
    status ENUM('active', 'inactive', 'failed', 'testing') DEFAULT 'active',
    last_check TIMESTAMP NULL,
    failure_count INT DEFAULT 0,
    response_time_ms INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_proxy (host, port, username),
    INDEX idx_local_port (local_port),
    INDEX idx_status (status),
    INDEX idx_last_check (last_check)
);

-- ============================================================================
-- REAL-TIME SESSION TRACKING
-- ============================================================================

-- Active user sessions (mirrors Redis data)
CREATE TABLE user_sessions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    client_port INT,
    local_port INT NOT NULL COMMENT 'Which proxy port they connected to',
    target_host VARCHAR(255),
    target_port INT,
    
    -- Session tracking
    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP NULL,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    
    -- Authentication method used
    auth_method ENUM('password', 'ip', 'api_key') NOT NULL,
    
    INDEX idx_username (username),
    INDEX idx_client_ip (client_ip),
    INDEX idx_local_port (local_port),
    INDEX idx_connected_at (connected_at),
    INDEX idx_active_sessions (username, disconnected_at),
    
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- ============================================================================
-- TRAFFIC MONITORING & BILLING
-- ============================================================================

-- Traffic logs for billing (inserted every 5 seconds by traffic.php)
CREATE TABLE traffic_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    local_port INT NOT NULL,
    target_host VARCHAR(255),
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    total_bytes BIGINT GENERATED ALWAYS AS (bytes_sent + bytes_received) STORED,
    sniff_domain VARCHAR(255) COMMENT 'Domain extracted by GoProxy',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_username_time (username, created_at),
    INDEX idx_billing (username, created_at, total_bytes),
    INDEX idx_local_port (local_port),
    INDEX idx_domain (sniff_domain),
    
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- ============================================================================
-- ADMIN & SECURITY
-- ============================================================================

-- Admin authentication tokens
CREATE TABLE admin_tokens (
    id INT PRIMARY KEY AUTO_INCREMENT,
    token_hash VARCHAR(64) NOT NULL UNIQUE COMMENT 'SHA-256 hash of token',
    name VARCHAR(100) NOT NULL COMMENT 'Human-readable token name',
    scopes JSON COMMENT 'Array of allowed scopes: ["users", "stats", "logs"]',
    created_by VARCHAR(100),
    expires_at TIMESTAMP NULL,
    last_used TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_token_hash (token_hash),
    INDEX idx_expires_at (expires_at),
    INDEX idx_active (is_active)
);

-- Security events and audit log
CREATE TABLE security_events (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_type VARCHAR(50) NOT NULL,
    username VARCHAR(100),
    client_ip VARCHAR(45),
    user_agent TEXT,
    details JSON,
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_event_type (event_type),
    INDEX idx_username (username),
    INDEX idx_client_ip (client_ip),
    INDEX idx_severity_time (severity, created_at),
    INDEX idx_created_at (created_at)
);

-- Rate limiting for brute force protection
CREATE TABLE auth_rate_limit (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    client_ip VARCHAR(45) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    attempts INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    UNIQUE KEY unique_ip_endpoint (client_ip, endpoint),
    INDEX idx_expires_at (expires_at)
);

-- ============================================================================
-- SYSTEM MONITORING
-- ============================================================================

-- System health and performance metrics
CREATE TABLE system_metrics (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    tags JSON COMMENT 'Additional metadata',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_metric_name_time (metric_name, created_at),
    INDEX idx_created_at (created_at)
);

-- Log file tracking
CREATE TABLE log_files (
    id INT PRIMARY KEY AUTO_INCREMENT,
    file_path VARCHAR(500) NOT NULL,
    file_type ENUM('proxy', 'api', 'security', 'system') NOT NULL,
    local_port INT NULL COMMENT 'For proxy logs',
    file_size BIGINT DEFAULT 0,
    last_rotated TIMESTAMP NULL,
    status ENUM('active', 'rotated', 'archived', 'deleted') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_file_type (file_type),
    INDEX idx_local_port (local_port),
    INDEX idx_status (status)
);

-- ============================================================================
-- SAMPLE DATA FOR TESTING
-- ============================================================================

-- Insert default admin token (token: admin_token_12345)
INSERT INTO admin_tokens (token_hash, name, scopes, created_by) VALUES 
('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Default Admin Token', '["users", "stats", "logs", "admin"]', 'system');

-- Insert sample user plans
INSERT INTO users (username, password, email, api_key, plan_name, max_threads, max_qps, max_bandwidth_bps, quota_bytes, status) VALUES
('demo_basic', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'demo@example.com', 'demo_api_key_basic_123', 'basic', 10, 10, 1048576, 1073741824, 'active'),
('demo_pro', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'pro@example.com', 'demo_api_key_pro_456', 'pro', 50, 50, 10485760, 10737418240, 'active'),
('demo_enterprise', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'enterprise@example.com', 'demo_api_key_enterprise_789', 'enterprise', 200, 200, 104857600, 107374182400, 'active');

-- Insert sample IP whitelist
INSERT INTO user_ip_whitelist (user_id, username, ip_address, description) VALUES
(1, 'demo_basic', '127.0.0.1', 'Localhost testing'),
(2, 'demo_pro', '192.168.1.100', 'Office IP'),
(3, 'demo_enterprise', '203.0.113.0', 'Corporate IP');

-- Insert sample upstream proxies
INSERT INTO upstream_proxies (host, port, username, password, local_port, status) VALUES
('proxy1.example.com', 3128, 'user1', 'pass1', 4000, 'active'),
('proxy2.example.com', 3128, 'user2', 'pass2', 4001, 'active'),
('proxy3.example.com', 3128, 'user3', 'pass3', 4002, 'active');

-- ============================================================================
-- PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Optimize tables for InnoDB
ALTER TABLE traffic_logs ENGINE=InnoDB ROW_FORMAT=COMPRESSED;
ALTER TABLE user_sessions ENGINE=InnoDB ROW_FORMAT=COMPRESSED;
ALTER TABLE security_events ENGINE=InnoDB ROW_FORMAT=COMPRESSED;

-- Set up automatic cleanup procedures
DELIMITER //

-- Cleanup old traffic logs (keep 90 days)
CREATE EVENT cleanup_old_traffic_logs
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM traffic_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY);
END //

-- Cleanup old security events (keep 180 days)
CREATE EVENT cleanup_old_security_events
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    DELETE FROM security_events WHERE created_at < DATE_SUB(NOW(), INTERVAL 180 DAY);
END //

-- Cleanup expired rate limits
CREATE EVENT cleanup_expired_rate_limits
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    DELETE FROM auth_rate_limit WHERE expires_at < NOW();
END //

-- Reset monthly quotas (run on 1st of each month)
CREATE EVENT reset_monthly_quotas
ON SCHEDULE EVERY 1 MONTH STARTS '2024-01-01 00:00:00'
DO
BEGIN
    UPDATE users SET bytes_used = 0 WHERE status = 'active';
    INSERT INTO system_metrics (metric_name, metric_value, tags) 
    VALUES ('monthly_quota_reset', (SELECT COUNT(*) FROM users WHERE status = 'active'), '{"event": "quota_reset"}');
END //

DELIMITER ;

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active users with current usage
CREATE VIEW active_users_stats AS
SELECT 
    u.username,
    u.plan_name,
    u.max_threads,
    u.max_qps,
    u.quota_bytes,
    u.bytes_used,
    ROUND((u.bytes_used / u.quota_bytes) * 100, 2) as quota_usage_percent,
    u.threads_live,
    u.last_activity,
    u.status,
    COUNT(s.id) as active_sessions
FROM users u
LEFT JOIN user_sessions s ON u.username = s.username AND s.disconnected_at IS NULL
WHERE u.status = 'active'
GROUP BY u.id;

-- Traffic summary by user (last 24 hours)
CREATE VIEW traffic_summary_24h AS
SELECT 
    username,
    COUNT(*) as total_requests,
    SUM(total_bytes) as total_bytes,
    AVG(total_bytes) as avg_bytes_per_request,
    COUNT(DISTINCT client_ip) as unique_ips,
    COUNT(DISTINCT sniff_domain) as unique_domains
FROM traffic_logs 
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY username;

-- System health overview
CREATE VIEW system_health AS
SELECT 
    (SELECT COUNT(*) FROM users WHERE status = 'active') as active_users,
    (SELECT COUNT(*) FROM user_sessions WHERE disconnected_at IS NULL) as active_sessions,
    (SELECT COUNT(*) FROM upstream_proxies WHERE status = 'active') as active_proxies,
    (SELECT SUM(bytes_used) FROM users) as total_bytes_used,
    (SELECT COUNT(*) FROM security_events WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) as security_events_1h;

-- ============================================================================
-- REDIS INTEGRATION NOTES
-- ============================================================================

/*
Redis Keys Used by the System:

1. User Counters:
   - threads_live:{username} -> INT (current active connections)
   - bytes_used:{username} -> INT (current month usage)
   - overlimit_since:{username} -> TIMESTAMP (when user went over limit)
   - timeout_until:{username} -> TIMESTAMP (ban expiration)

2. Rate Limiting:
   - rate_limit:{ip}:{endpoint} -> INT (request count)
   - auth_attempts:{ip} -> INT (failed auth attempts)

3. System Metrics:
   - system:active_users -> INT
   - system:active_sessions -> INT
   - system:total_bandwidth -> INT

4. Caching:
   - user_cache:{username} -> JSON (user data cache)
   - ip_whitelist:{username} -> SET (cached IP list)

Redis Configuration:
- maxmemory 256mb
- maxmemory-policy allkeys-lru
- save 900 1 (save every 15 minutes if at least 1 key changed)
- appendonly no (for performance)
*/
