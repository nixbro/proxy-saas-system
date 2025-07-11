<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Internal Authentication Hook
 * ============================================================================
 *
 * Enhanced version of the working reference auth.php with SaaS features
 * Called by GoProxy for every new connection via --auth-url parameter
 *
 * Compatible with reference system format:
 * --auth-url "http://127.0.0.1:8889/api/internal/auth.php?upstream=http://user:pass@host:port"
 *
 * SECURITY: This endpoint should ONLY be accessible from 127.0.0.1
 * Configure Nginx to block external access to /api/internal/*
 *
 * GoProxy Parameters (from reference system):
 * - upstream: Full upstream proxy URL (http://user:pass@host:port)
 * - user: Username for authentication (optional, for SaaS users)
 * - pass: Password for authentication (optional, for SaaS users)
 * - ip: Client IP address (format: IP:port)
 * - local_ip: Local proxy IP (format: IP:port)
 * - target: Target host being accessed
 *
 * Response:
 * - HTTP 204: Authentication successful + rate limiting headers
 * - HTTP 401: Authentication failed
 * - HTTP 403: User banned/suspended
 * - HTTP 429: Rate limited
 * ============================================================================
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../redis_client.php';

// Security: Only allow localhost access
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden: Internal API');
}

// Extract GoProxy parameters (compatible with reference system)
$upstream = $_GET['upstream'] ?? '';       // Reference system format
$username = $_GET['user'] ?? '';           // SaaS user authentication
$password = $_GET['pass'] ?? '';           // SaaS user authentication
$clientAddr = $_GET['ip'] ?? '';           // GoProxy sends 'ip' not 'client_addr'
$localAddr = $_GET['local_ip'] ?? '';      // GoProxy sends 'local_ip' not 'local_addr'
$target = $_GET['target'] ?? '';

// Parse upstream proxy info (from reference system)
$upstreamHost = '';
$upstreamPort = '';
$upstreamUser = '';
$upstreamPass = '';

if (!empty($upstream)) {
    // Parse upstream URL: http://user:pass@host:port
    if (preg_match('/^https?:\/\/([^:]+):([^@]+)@([^:]+):(\d+)$/', $upstream, $matches)) {
        $upstreamUser = urldecode($matches[1]);
        $upstreamPass = urldecode($matches[2]);
        $upstreamHost = $matches[3];
        $upstreamPort = $matches[4];
    } elseif (preg_match('/^https?:\/\/([^:]+):(\d+)$/', $upstream, $matches)) {
        $upstreamHost = $matches[1];
        $upstreamPort = $matches[2];
    }
}

// Parse client IP from format "IP:port"
$clientIp = '';
if (!empty($clientAddr)) {
    $parts = explode(':', $clientAddr);
    $clientIp = $parts[0];
}

// Parse local port from format "IP:port"
$localPort = '';
if (!empty($localAddr)) {
    $parts = explode(':', $localAddr);
    $localPort = $parts[1] ?? '';
}

// Log authentication attempt
logSecurityEvent('auth_attempt', $clientIp, $username, [
    'target' => $target,
    'local_port' => $localPort,
    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
]);

try {
    // Get database and Redis connections
    $pdo = getDbConnection();
    $redis = getRedisConnection();
    
    // Rate limiting check
    if (!checkAuthRateLimit($clientIp, $redis)) {
        logSecurityEvent('auth_rate_limited', $clientIp, $username, ['target' => $target]);
        http_response_code(429);
        header('Retry-After: 3600');
        exit('Rate limited');
    }
    
    // Authenticate user
    $user = authenticateUser($username, $password, $clientIp, $pdo);
    
    if (!$user) {
        logSecurityEvent('auth_failed', $clientIp, $username, ['target' => $target]);
        recordFailedAuth($clientIp, $redis);
        http_response_code(401);
        exit('Authentication failed');
    }
    
    // Check if user is banned or suspended
    if ($user['status'] !== 'active') {
        logSecurityEvent('auth_blocked_status', $clientIp, $username, [
            'status' => $user['status'],
            'target' => $target
        ]);
        http_response_code(403);
        exit('Account ' . $user['status']);
    }
    
    // Check if user is in timeout (strike system)
    $timeoutUntil = $redis->get("timeout_until:{$username}");
    if ($timeoutUntil && time() < $timeoutUntil) {
        logSecurityEvent('auth_timeout', $clientIp, $username, [
            'timeout_until' => date('Y-m-d H:i:s', $timeoutUntil),
            'target' => $target
        ]);
        http_response_code(403);
        header('Retry-After: ' . ($timeoutUntil - time()));
        exit('User in timeout');
    }
    
    // Check plan expiry
    if ($user['expires_at'] && strtotime($user['expires_at']) < time()) {
        logSecurityEvent('auth_expired', $clientIp, $username, [
            'expires_at' => $user['expires_at'],
            'target' => $target
        ]);
        http_response_code(403);
        exit('Plan expired');
    }
    
    // Check monthly quota
    $bytesUsed = $redis->get("bytes_used:{$username}") ?: $user['bytes_used'];
    if ($bytesUsed >= $user['quota_bytes']) {
        logSecurityEvent('auth_quota_exceeded', $clientIp, $username, [
            'bytes_used' => $bytesUsed,
            'quota_bytes' => $user['quota_bytes'],
            'target' => $target
        ]);
        http_response_code(403);
        exit('Quota exceeded');
    }
    
    // Increment live thread counter
    $threadsLive = $redis->incr("threads_live:{$username}");
    
    // Check thread limit
    if ($threadsLive > $user['max_threads']) {
        // Start strike timer if not already started
        $overlimitSince = $redis->get("overlimit_since:{$username}");
        if (!$overlimitSince) {
            $redis->setex("overlimit_since:{$username}", 900, time()); // 15 minutes TTL
            logSecurityEvent('thread_overlimit_start', $clientIp, $username, [
                'threads_live' => $threadsLive,
                'max_threads' => $user['max_threads'],
                'target' => $target
            ]);
        }
        
        // Decrement counter since we're rejecting this connection
        $redis->decr("threads_live:{$username}");
        
        http_response_code(429);
        header('Retry-After: 60');
        exit('Thread limit exceeded');
    }
    
    // Record successful authentication
    recordUserSession($username, $clientIp, $localPort, $target, $pdo);
    logSecurityEvent('auth_success', $clientIp, $username, [
        'target' => $target,
        'local_port' => $localPort,
        'threads_live' => $threadsLive
    ]);
    
    // Calculate rate limiting headers for GoProxy
    $userConnections = min($user['max_threads'], 1000); // Cap at 1000 for stability
    $userQPS = min($user['max_qps'], 1000);
    $userTotalRate = min($user['max_bandwidth_bps'], 1073741824); // Cap at 1GB/s
    
    // Per-IP limits (more restrictive)
    $ipConnections = min(ceil($userConnections / 4), 100); // 25% of user limit, max 100
    $ipRate = min(ceil($userTotalRate / 4), 104857600);    // 25% of user limit, max 100MB/s
    $ipTotalRate = $ipRate;
    
    // Send success response with GoProxy headers
    http_response_code(204);
    header("userconns: $userConnections");
    header("userqps: $userQPS");
    header("userTotalRate: $userTotalRate");
    header("ipconns: $ipConnections");
    header("iprate: $ipRate");
    header("ipTotalRate: $ipTotalRate");
    
    // Optional: Set upstream proxy if using proxy rotation
    // header("upstream: http://upstream-proxy.com:3128");
    
    exit();
    
} catch (Exception $e) {
    logError("Auth error for user $username: " . $e->getMessage());
    logSecurityEvent('auth_error', $clientIp, $username, [
        'error' => $e->getMessage(),
        'target' => $target
    ]);
    
    http_response_code(500);
    exit('Internal error');
}

/**
 * Authenticate user with multiple methods
 */
function authenticateUser($username, $password, $clientIp, $pdo) {
    if (empty($username)) {
        return false;
    }
    
    // Get user data
    $stmt = $pdo->prepare("
        SELECT u.*, 
               CASE WHEN u.expires_at IS NULL OR u.expires_at > NOW() THEN 1 ELSE 0 END as is_active
        FROM users u 
        WHERE u.username = ? AND u.status = 'active'
    ");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    
    if (!$user) {
        return false;
    }
    
    // Method 1: Password authentication
    if (!empty($password) && password_verify($password, $user['password'])) {
        return $user;
    }
    
    // Method 2: IP whitelist authentication
    if (isIpWhitelisted($username, $clientIp, $pdo)) {
        return $user;
    }
    
    return false;
}

/**
 * Check if IP is whitelisted for user
 */
function isIpWhitelisted($username, $clientIp, $pdo) {
    if (empty($clientIp)) {
        return false;
    }
    
    $stmt = $pdo->prepare("
        SELECT ip_address, ip_range 
        FROM user_ip_whitelist 
        WHERE username = ? AND status = 'active' 
        AND (expires_at IS NULL OR expires_at > NOW())
    ");
    $stmt->execute([$username]);
    $whitelist = $stmt->fetchAll();
    
    foreach ($whitelist as $entry) {
        // Check exact IP match
        if ($entry['ip_address'] && $entry['ip_address'] === $clientIp) {
            return true;
        }
        
        // Check CIDR range match
        if ($entry['ip_range'] && cidrMatch($clientIp, $entry['ip_range'])) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check if IP matches CIDR range
 */
function cidrMatch($ip, $cidr) {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    
    list($subnet, $mask) = explode('/', $cidr);
    
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // IPv4
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask_long = -1 << (32 - (int)$mask);
        
        return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // IPv6 - simplified check
        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);
        
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }
        
        $mask_bytes = (int)$mask >> 3;
        $mask_bits = (int)$mask % 8;
        
        // Compare full bytes
        if ($mask_bytes > 0 && substr($ip_bin, 0, $mask_bytes) !== substr($subnet_bin, 0, $mask_bytes)) {
            return false;
        }
        
        // Compare remaining bits
        if ($mask_bits > 0 && $mask_bytes < 16) {
            $ip_byte = ord($ip_bin[$mask_bytes]);
            $subnet_byte = ord($subnet_bin[$mask_bytes]);
            $mask_byte = 0xFF << (8 - $mask_bits);
            
            return ($ip_byte & $mask_byte) === ($subnet_byte & $mask_byte);
        }
        
        return true;
    }
    
    return false;
}

/**
 * Check authentication rate limiting
 */
function checkAuthRateLimit($clientIp, $redis) {
    if (empty($clientIp)) {
        return true;
    }
    
    $key = "auth_rate:{$clientIp}";
    $attempts = $redis->get($key) ?: 0;
    
    if ($attempts >= 100) { // 100 attempts per hour
        return false;
    }
    
    $redis->incr($key);
    $redis->expire($key, 3600); // 1 hour TTL
    
    return true;
}

/**
 * Record failed authentication attempt
 */
function recordFailedAuth($clientIp, $redis) {
    $key = "failed_auth:{$clientIp}";
    $failures = $redis->incr($key);
    $redis->expire($key, 3600);
    
    // Implement progressive delays or bans based on failure count
    if ($failures >= 10) {
        logSecurityEvent('brute_force_detected', $clientIp, '', [
            'failure_count' => $failures
        ]);
    }
}

/**
 * Record user session
 */
function recordUserSession($username, $clientIp, $localPort, $target, $pdo) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO user_sessions (username, client_ip, local_port, target_host, auth_method, connected_at)
            VALUES (?, ?, ?, ?, 'mixed', NOW())
        ");
        $stmt->execute([$username, $clientIp, $localPort, $target]);
    } catch (Exception $e) {
        logError("Failed to record user session: " . $e->getMessage());
    }
}

/**
 * Log security events
 */
function logSecurityEvent($eventType, $clientIp, $username, $details = []) {
    try {
        $pdo = getDbConnection();
        $stmt = $pdo->prepare("
            INSERT INTO security_events (event_type, username, client_ip, user_agent, details, created_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $eventType,
            $username ?: null,
            $clientIp ?: null,
            $_SERVER['HTTP_USER_AGENT'] ?? null,
            json_encode($details)
        ]);
    } catch (Exception $e) {
        error_log("Failed to log security event: " . $e->getMessage());
    }
}
?>
