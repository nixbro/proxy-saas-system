<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Internal Traffic Monitoring Hook
 * ============================================================================
 * 
 * Called by GoProxy every 5 seconds via --traffic-url parameter
 * Tracks bandwidth usage for billing and quota enforcement
 * 
 * SECURITY: This endpoint should ONLY be accessible from 127.0.0.1
 * Configure Nginx to block external access to /api/internal/*
 * 
 * GoProxy Parameters:
 * - bytes: Total bytes transferred in this interval
 * - client_addr: Client IP:port
 * - server_addr: Server IP:port  
 * - target_addr: Target host:port
 * - username: Authenticated username (if available)
 * - out_local_addr: Outgoing local address
 * - out_remote_addr: Outgoing remote address
 * - upstream: Upstream proxy used
 * - sniff_domain: Domain extracted by GoProxy
 * 
 * Response:
 * - HTTP 204: Traffic recorded successfully
 * - HTTP 500: Internal error
 * ============================================================================
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../redis_client.php';

// Security: Only allow localhost access
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden: Internal API');
}

// Extract GoProxy traffic parameters
$bytes = (int)($_GET['bytes'] ?? 0);
$clientAddr = $_GET['client_addr'] ?? '';
$serverAddr = $_GET['server_addr'] ?? '';
$targetAddr = $_GET['target_addr'] ?? '';
$username = $_GET['username'] ?? '';
$outLocalAddr = $_GET['out_local_addr'] ?? '';
$outRemoteAddr = $_GET['out_remote_addr'] ?? '';
$upstream = $_GET['upstream'] ?? '';
$sniffDomain = $_GET['sniff_domain'] ?? '';

// Parse addresses
$clientIp = '';
$clientPort = '';
if (!empty($clientAddr)) {
    $parts = explode(':', $clientAddr);
    $clientIp = $parts[0];
    $clientPort = $parts[1] ?? '';
}

$serverPort = '';
if (!empty($serverAddr)) {
    $parts = explode(':', $serverAddr);
    $serverPort = $parts[1] ?? '';
}

$targetHost = '';
$targetPort = '';
if (!empty($targetAddr)) {
    $parts = explode(':', $targetAddr);
    $targetHost = $parts[0];
    $targetPort = $parts[1] ?? '';
}

// Skip if no bytes transferred
if ($bytes <= 0) {
    http_response_code(204);
    exit();
}

try {
    // Get database and Redis connections
    $pdo = getDbConnection();
    $redis = getRedisConnection();
    
    // If no username provided, try to find it from active sessions
    if (empty($username) && !empty($clientIp) && !empty($serverPort)) {
        $username = findUsernameBySession($clientIp, $serverPort, $pdo);
    }
    
    // Record traffic in database for billing
    recordTrafficLog($username, $clientIp, $serverPort, $targetHost, $bytes, $sniffDomain, $pdo);
    
    // Update Redis counters for real-time tracking
    if (!empty($username)) {
        updateUserBytesUsed($username, $bytes, $redis);
        
        // Check if user exceeded quota
        $user = getUserData($username, $pdo);
        if ($user) {
            $totalBytesUsed = getUserBytesUsed($username);
            
            if ($totalBytesUsed >= $user['quota_bytes']) {
                // User exceeded quota - log event
                logSecurityEvent('quota_exceeded', $clientIp, $username, [
                    'bytes_used' => $totalBytesUsed,
                    'quota_bytes' => $user['quota_bytes'],
                    'target' => $targetHost,
                    'domain' => $sniffDomain
                ]);
                
                // Update database
                updateUserQuotaStatus($username, $totalBytesUsed, $pdo);
            }
        }
    }
    
    // Update system metrics
    updateSystemTrafficMetrics($bytes, $redis);
    
    // Log high-bandwidth usage for monitoring
    if ($bytes > 10485760) { // 10MB in single interval
        logSecurityEvent('high_bandwidth_usage', $clientIp, $username, [
            'bytes' => $bytes,
            'target' => $targetHost,
            'domain' => $sniffDomain,
            'interval' => '5s'
        ]);
    }
    
    http_response_code(204);
    exit();
    
} catch (Exception $e) {
    logError("Traffic monitoring error: " . $e->getMessage());
    http_response_code(500);
    exit('Internal error');
}

/**
 * Find username by active session
 */
function findUsernameBySession($clientIp, $localPort, $pdo) {
    try {
        $stmt = $pdo->prepare("
            SELECT username 
            FROM user_sessions 
            WHERE client_ip = ? AND local_port = ? AND disconnected_at IS NULL
            ORDER BY connected_at DESC 
            LIMIT 1
        ");
        $stmt->execute([$clientIp, $localPort]);
        $result = $stmt->fetch();
        
        return $result ? $result['username'] : '';
    } catch (Exception $e) {
        logError("Failed to find username by session: " . $e->getMessage());
        return '';
    }
}

/**
 * Record traffic log for billing
 */
function recordTrafficLog($username, $clientIp, $localPort, $targetHost, $bytes, $sniffDomain, $pdo) {
    try {
        $stmt = $pdo->prepare("
            INSERT INTO traffic_logs (
                username, client_ip, local_port, target_host, 
                bytes_sent, bytes_received, total_bytes, sniff_domain, created_at
            ) VALUES (?, ?, ?, ?, ?, 0, ?, ?, NOW())
        ");
        
        $stmt->execute([
            $username ?: 'unknown',
            $clientIp,
            $localPort,
            $targetHost,
            $bytes,
            $bytes,
            $sniffDomain
        ]);
        
    } catch (Exception $e) {
        logError("Failed to record traffic log: " . $e->getMessage());
    }
}

/**
 * Update user bytes used in Redis and database
 */
function updateUserBytesUsed($username, $bytes, $redis) {
    try {
        // Update Redis counter
        $totalBytes = addUserBytes($username, $bytes);
        
        // Periodically sync to database (every ~100MB)
        if ($totalBytes % 104857600 < $bytes) {
            $pdo = getDbConnection();
            $stmt = $pdo->prepare("UPDATE users SET bytes_used = ? WHERE username = ?");
            $stmt->execute([$totalBytes, $username]);
        }
        
        return $totalBytes;
        
    } catch (Exception $e) {
        logError("Failed to update user bytes: " . $e->getMessage());
        return 0;
    }
}

/**
 * Get user data with caching
 */
function getUserData($username, $pdo) {
    try {
        // Try cache first
        $cached = getCachedUserData($username);
        if ($cached) {
            return $cached;
        }
        
        // Get from database
        $stmt = $pdo->prepare("
            SELECT username, quota_bytes, bytes_used, status, expires_at
            FROM users 
            WHERE username = ?
        ");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user) {
            // Cache for 5 minutes
            cacheUserData($username, $user, 300);
        }
        
        return $user;
        
    } catch (Exception $e) {
        logError("Failed to get user data: " . $e->getMessage());
        return false;
    }
}

/**
 * Update user quota status in database
 */
function updateUserQuotaStatus($username, $bytesUsed, $pdo) {
    try {
        $stmt = $pdo->prepare("
            UPDATE users 
            SET bytes_used = ?, last_activity = NOW()
            WHERE username = ?
        ");
        $stmt->execute([$bytesUsed, $username]);
        
        // Clear cache to force refresh
        $redis = getRedisConnection();
        $redis->del("user_cache:$username");
        
    } catch (Exception $e) {
        logError("Failed to update user quota status: " . $e->getMessage());
    }
}

/**
 * Update system traffic metrics
 */
function updateSystemTrafficMetrics($bytes, $redis) {
    try {
        // Update total system bandwidth
        $redis->incr("system:total_bytes_today", $bytes);
        $redis->expire("system:total_bytes_today", 86400); // 24 hours
        
        // Update bandwidth per minute
        $minute = date('Y-m-d H:i');
        $redis->incr("system:bytes_per_minute:$minute", $bytes);
        $redis->expire("system:bytes_per_minute:$minute", 3600); // 1 hour
        
        // Update active connections count
        $activeConnections = $redis->get("system:active_connections") ?: 0;
        updateSystemMetric('active_connections', $activeConnections);
        
    } catch (Exception $e) {
        logError("Failed to update system metrics: " . $e->getMessage());
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
    $logMessage = "[$timestamp] TRAFFIC ERROR: $message\n";
    
    // Log to file
    $logFile = __DIR__ . '/../../logs/api/traffic.log';
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    
    // Also log to system error log
    error_log($logMessage);
}
?>
