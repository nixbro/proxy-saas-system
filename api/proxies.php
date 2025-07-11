<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Customer Proxy List API
 * ============================================================================
 * 
 * Public endpoint for customers to get their available proxy ports
 * Returns plain text list of SERVER_IP:PORT or JSON error messages
 * 
 * Authentication: API key or IP whitelist
 * Rate Limiting: Applied per user
 * 
 * Usage Examples:
 * curl "https://proxy.example.com/api/proxies.php?api_key=your_api_key"
 * curl "https://proxy.example.com/api/proxies.php?username=user&password=pass"
 * 
 * Response Formats:
 * 
 * Success (text/plain):
 * proxy.example.com:4000
 * proxy.example.com:4001
 * proxy.example.com:4002
 * 
 * Error (application/json):
 * {"status":"inactive","reason":"expired"}
 * {"status":"inactive","reason":"banned"}
 * {"status":"inactive","reason":"quota_exceeded"}
 * {"status":"inactive","reason":"ip_not_whitelisted"}
 * ============================================================================
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/redis_client.php';

// CORS headers for web applications
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Extract authentication parameters
$apiKey = $_REQUEST['api_key'] ?? '';
$username = $_REQUEST['username'] ?? $_REQUEST['user'] ?? '';
$password = $_REQUEST['password'] ?? $_REQUEST['pass'] ?? '';
$clientIp = getClientIp();

// Log API request
logApiRequest('proxies', $clientIp, $username ?: 'api_key_auth');

try {
    // Get database and Redis connections
    $pdo = getDbConnection();
    $redis = getRedisConnection();
    
    // Rate limiting check
    if (!checkApiRateLimit($clientIp, $redis)) {
        http_response_code(429);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'reason' => 'rate_limited',
            'message' => 'Too many requests. Please try again later.'
        ]);
        exit();
    }
    
    // Authenticate user
    $user = authenticateProxyRequest($apiKey, $username, $password, $clientIp, $pdo);
    
    if (!$user) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'reason' => 'authentication_failed',
            'message' => 'Invalid credentials or IP not whitelisted'
        ]);
        exit();
    }
    
    // Check account status
    $statusCheck = checkAccountStatus($user, $redis);
    if ($statusCheck !== true) {
        http_response_code(403);
        header('Content-Type: application/json');
        echo json_encode($statusCheck);
        exit();
    }
    
    // Get available proxy ports
    $proxyList = getAvailableProxyPorts($user, $pdo);
    
    if (empty($proxyList)) {
        http_response_code(503);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'reason' => 'no_proxies_available',
            'message' => 'No proxy servers are currently available'
        ]);
        exit();
    }
    
    // Update user last activity
    updateUserActivity($user['username'], $pdo);
    
    // Return proxy list as plain text
    header('Content-Type: text/plain');
    echo implode("\n", $proxyList);
    
    // Log successful request
    logSecurityEvent('proxy_list_success', $clientIp, $user['username'], [
        'proxy_count' => count($proxyList),
        'auth_method' => !empty($apiKey) ? 'api_key' : 'password'
    ]);
    
} catch (Exception $e) {
    logError("Proxy list API error: " . $e->getMessage());
    
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'status' => 'error',
        'reason' => 'internal_error',
        'message' => 'Internal server error'
    ]);
}

/**
 * Authenticate proxy request using multiple methods
 */
function authenticateProxyRequest($apiKey, $username, $password, $clientIp, $pdo) {
    // Method 1: API key authentication
    if (!empty($apiKey)) {
        $stmt = $pdo->prepare("
            SELECT * FROM users 
            WHERE api_key = ? AND status = 'active'
        ");
        $stmt->execute([$apiKey]);
        return $stmt->fetch();
    }
    
    // Method 2: Username/password authentication
    if (!empty($username) && !empty($password)) {
        $stmt = $pdo->prepare("
            SELECT * FROM users 
            WHERE username = ? AND status = 'active'
        ");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password'])) {
            return $user;
        }
    }
    
    // Method 3: IP whitelist authentication (try all active users)
    if (!empty($clientIp)) {
        $stmt = $pdo->prepare("
            SELECT u.* FROM users u
            JOIN user_ip_whitelist w ON u.username = w.username
            WHERE w.status = 'active' 
            AND (w.expires_at IS NULL OR w.expires_at > NOW())
            AND u.status = 'active'
            AND (
                w.ip_address = ? OR
                (w.ip_range IS NOT NULL AND ? REGEXP CONCAT('^', REPLACE(REPLACE(w.ip_range, '.', '\\.'), '*', '.*'), '$'))
            )
        ");
        $stmt->execute([$clientIp, $clientIp]);
        
        while ($user = $stmt->fetch()) {
            // Verify CIDR match for IP ranges
            if (isIpInRange($clientIp, $user, $pdo)) {
                return $user;
            }
        }
    }
    
    return false;
}

/**
 * Check if IP is in user's whitelist range
 */
function isIpInRange($clientIp, $user, $pdo) {
    $stmt = $pdo->prepare("
        SELECT ip_address, ip_range 
        FROM user_ip_whitelist 
        WHERE username = ? AND status = 'active'
        AND (expires_at IS NULL OR expires_at > NOW())
    ");
    $stmt->execute([$user['username']]);
    $whitelist = $stmt->fetchAll();
    
    foreach ($whitelist as $entry) {
        // Exact IP match
        if ($entry['ip_address'] && $entry['ip_address'] === $clientIp) {
            return true;
        }
        
        // CIDR range match
        if ($entry['ip_range'] && cidrMatch($clientIp, $entry['ip_range'])) {
            return true;
        }
    }
    
    return false;
}

/**
 * Check account status and return error if inactive
 */
function checkAccountStatus($user, $redis) {
    // Check if banned
    if ($user['status'] === 'banned' || $user['is_banned']) {
        return [
            'status' => 'inactive',
            'reason' => 'banned',
            'message' => 'Account is banned'
        ];
    }
    
    // Check if suspended
    if ($user['status'] === 'suspended') {
        return [
            'status' => 'inactive',
            'reason' => 'suspended',
            'message' => 'Account is suspended'
        ];
    }
    
    // Check plan expiry
    if ($user['expires_at'] && strtotime($user['expires_at']) < time()) {
        return [
            'status' => 'inactive',
            'reason' => 'expired',
            'message' => 'Plan has expired',
            'expires_at' => $user['expires_at']
        ];
    }
    
    // Check if in timeout (strike system)
    $timeoutUntil = getUserTimeoutUntil($user['username']);
    if ($timeoutUntil && time() < $timeoutUntil) {
        return [
            'status' => 'inactive',
            'reason' => 'timeout',
            'message' => 'Account is temporarily suspended',
            'timeout_until' => date('Y-m-d H:i:s', $timeoutUntil)
        ];
    }
    
    // Check quota exceeded
    $bytesUsed = getUserBytesUsed($user['username']);
    if ($bytesUsed >= $user['quota_bytes']) {
        return [
            'status' => 'inactive',
            'reason' => 'quota_exceeded',
            'message' => 'Monthly quota exceeded',
            'bytes_used' => $bytesUsed,
            'quota_bytes' => $user['quota_bytes']
        ];
    }
    
    return true; // Account is active
}

/**
 * Get available proxy ports for user
 */
function getAvailableProxyPorts($user, $pdo) {
    $serverHost = $_ENV['SERVER_HOST'] ?? getenv('SERVER_HOST') ?: 'proxy.example.com';
    
    // Get active proxy ports from database
    $stmt = $pdo->prepare("
        SELECT local_port 
        FROM upstream_proxies 
        WHERE status = 'active' AND local_port IS NOT NULL
        ORDER BY local_port
    ");
    $stmt->execute();
    $ports = $stmt->fetchAll(PDO::FETCH_COLUMN);
    
    // If no database entries, fall back to port range
    if (empty($ports)) {
        $startPort = 4000;
        $endPort = 4999;
        $ports = range($startPort, min($startPort + 999, $endPort)); // Limit to 1000 ports
    }
    
    // Build proxy list
    $proxyList = [];
    foreach ($ports as $port) {
        $proxyList[] = "$serverHost:$port";
    }
    
    return $proxyList;
}

/**
 * Update user last activity
 */
function updateUserActivity($username, $pdo) {
    try {
        $stmt = $pdo->prepare("UPDATE users SET last_activity = NOW() WHERE username = ?");
        $stmt->execute([$username]);
    } catch (Exception $e) {
        logError("Failed to update user activity: " . $e->getMessage());
    }
}

/**
 * Check API rate limiting
 */
function checkApiRateLimit($clientIp, $redis) {
    $key = "api_rate:proxies:$clientIp";
    $limit = 60; // 60 requests per hour
    $window = 3600; // 1 hour
    
    return checkRateLimit($key, $limit, $window);
}

/**
 * Get real client IP address
 */
function getClientIp() {
    $headers = [
        'HTTP_CF_CONNECTING_IP',     // Cloudflare
        'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
        'HTTP_X_FORWARDED',          // Proxy
        'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
        'HTTP_FORWARDED_FOR',        // Proxy
        'HTTP_FORWARDED',            // Proxy
        'REMOTE_ADDR'                // Standard
    ];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
}

/**
 * CIDR matching function
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
    }
    
    return false; // IPv6 not implemented for simplicity
}

/**
 * Log API requests
 */
function logApiRequest($endpoint, $clientIp, $username) {
    try {
        $pdo = getDbConnection();
        $stmt = $pdo->prepare("
            INSERT INTO security_events (event_type, username, client_ip, details, created_at)
            VALUES ('api_request', ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $username ?: null,
            $clientIp,
            json_encode(['endpoint' => $endpoint])
        ]);
    } catch (Exception $e) {
        // Silently fail to avoid disrupting service
    }
}

/**
 * Log security events
 */
function logSecurityEvent($eventType, $clientIp, $username, $details = []) {
    try {
        $pdo = getDbConnection();
        $stmt = $pdo->prepare("
            INSERT INTO security_events (event_type, username, client_ip, details, created_at)
            VALUES (?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $eventType,
            $username ?: null,
            $clientIp ?: null,
            json_encode($details)
        ]);
    } catch (Exception $e) {
        error_log("Failed to log security event: " . $e->getMessage());
    }
}

/**
 * Enhanced logging function
 */
function logError($message) {
    $timestamp = date('Y-m-d H:i:s');
    $logMessage = "[$timestamp] PROXIES API ERROR: $message\n";
    
    // Log to file
    $logFile = __DIR__ . '/../logs/api/proxies.log';
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    
    // Also log to system error log
    error_log($logMessage);
}
?>
