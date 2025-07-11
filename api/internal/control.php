<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Internal Control Hook (Strike System)
 * ============================================================================
 * 
 * Called by GoProxy every 30 seconds via --control-url parameter
 * Implements the strike system: 15 minutes over limit = 1 hour ban
 * Returns JSON list of users/IPs to kick
 * 
 * SECURITY: This endpoint should ONLY be accessible from 127.0.0.1
 * Configure Nginx to block external access to /api/internal/*
 * 
 * GoProxy sends POST data with JSON array of current connections:
 * [
 *   {"user": "username", "ip": "1.2.3.4", "conns": 5},
 *   {"user": "username2", "ip": "5.6.7.8", "conns": 3}
 * ]
 * 
 * Response JSON format:
 * {
 *   "user": "user1,user2",     // Comma-separated users to kick
 *   "ip": "1.1.1.1,2.2.2.2"   // Comma-separated IPs to kick
 * }
 * 
 * Strike System Logic:
 * 1. If threads_live > max_threads: set overlimit_since timer (15 min)
 * 2. If still over limit after 15 min: set timeout_until (1 hour ban)
 * 3. If back under limit: clear overlimit_since timer
 * ============================================================================
 */

require_once __DIR__ . '/../config.php';
require_once __DIR__ . '/../redis_client.php';

// Security: Only allow localhost access
if (!in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
    http_response_code(403);
    exit('Forbidden: Internal API');
}

// Set JSON response header
header('Content-Type: application/json');

try {
    // Get database and Redis connections
    $pdo = getDbConnection();
    $redis = getRedisConnection();
    
    // Get POST data from GoProxy
    $input = file_get_contents('php://input');
    $connections = json_decode($input, true);
    
    if (!is_array($connections)) {
        $connections = [];
    }
    
    // Initialize kick lists
    $usersToKick = [];
    $ipsToKick = [];
    
    // Process each connection report
    foreach ($connections as $conn) {
        $username = $conn['user'] ?? '';
        $clientIp = $conn['ip'] ?? '';
        $currentConns = (int)($conn['conns'] ?? 0);
        
        if (empty($username)) {
            continue;
        }
        
        // Update Redis with current connection count
        $redis->set("threads_live:$username", $currentConns);
        
        // Get user limits
        $user = getUserLimits($username, $pdo);
        if (!$user) {
            continue;
        }
        
        // Check if user is already in timeout
        $timeoutUntil = getUserTimeoutUntil($username);
        if ($timeoutUntil && time() < $timeoutUntil) {
            // User is in timeout - kick them
            $usersToKick[] = $username;
            if (!empty($clientIp)) {
                $ipsToKick[] = $clientIp;
            }
            
            logSecurityEvent('control_timeout_kick', $clientIp, $username, [
                'timeout_until' => date('Y-m-d H:i:s', $timeoutUntil),
                'current_conns' => $currentConns
            ]);
            continue;
        }
        
        // Check quota exceeded
        $bytesUsed = getUserBytesUsed($username);
        if ($bytesUsed >= $user['quota_bytes']) {
            $usersToKick[] = $username;
            if (!empty($clientIp)) {
                $ipsToKick[] = $clientIp;
            }
            
            logSecurityEvent('control_quota_kick', $clientIp, $username, [
                'bytes_used' => $bytesUsed,
                'quota_bytes' => $user['quota_bytes'],
                'current_conns' => $currentConns
            ]);
            continue;
        }
        
        // Check plan expiry
        if ($user['expires_at'] && strtotime($user['expires_at']) < time()) {
            $usersToKick[] = $username;
            if (!empty($clientIp)) {
                $ipsToKick[] = $clientIp;
            }
            
            logSecurityEvent('control_expired_kick', $clientIp, $username, [
                'expires_at' => $user['expires_at'],
                'current_conns' => $currentConns
            ]);
            continue;
        }
        
        // Strike system logic
        if ($currentConns > $user['max_threads']) {
            // User is over thread limit
            $overlimitSince = getUserOverlimitSince($username);
            
            if (!$overlimitSince) {
                // First time over limit - start timer
                setUserOverlimit($username, 900); // 15 minutes
                
                logSecurityEvent('control_overlimit_start', $clientIp, $username, [
                    'current_conns' => $currentConns,
                    'max_threads' => $user['max_threads'],
                    'grace_period' => '15 minutes'
                ]);
                
            } elseif (time() - $overlimitSince >= 900) {
                // Over limit for 15+ minutes - impose 1 hour timeout
                setUserTimeout($username, 3600); // 1 hour
                clearUserOverlimit($username);
                
                // Kick user immediately
                $usersToKick[] = $username;
                if (!empty($clientIp)) {
                    $ipsToKick[] = $clientIp;
                }
                
                logSecurityEvent('control_strike_timeout', $clientIp, $username, [
                    'current_conns' => $currentConns,
                    'max_threads' => $user['max_threads'],
                    'overlimit_duration' => time() - $overlimitSince,
                    'timeout_duration' => '1 hour'
                ]);
                
                // Update database strike count
                incrementUserStrikeCount($username, $pdo);
            }
            
        } else {
            // User is back under limit - clear overlimit timer
            $overlimitSince = getUserOverlimitSince($username);
            if ($overlimitSince) {
                clearUserOverlimit($username);
                
                logSecurityEvent('control_overlimit_cleared', $clientIp, $username, [
                    'current_conns' => $currentConns,
                    'max_threads' => $user['max_threads'],
                    'overlimit_duration' => time() - $overlimitSince
                ]);
            }
        }
    }
    
    // Clean up disconnected sessions
    cleanupDisconnectedSessions($connections, $pdo);
    
    // Update system metrics
    updateSystemConnectionMetrics(count($connections), $redis);
    
    // Return kick list to GoProxy
    $response = [
        'user' => implode(',', array_unique($usersToKick)),
        'ip' => implode(',', array_unique($ipsToKick))
    ];
    
    echo json_encode($response);
    
    // Log control action if any kicks
    if (!empty($usersToKick) || !empty($ipsToKick)) {
        logSecurityEvent('control_kick_action', '', '', [
            'users_kicked' => $usersToKick,
            'ips_kicked' => $ipsToKick,
            'total_connections' => count($connections)
        ]);
    }
    
} catch (Exception $e) {
    logError("Control system error: " . $e->getMessage());
    
    // Return empty response on error to avoid disrupting service
    echo json_encode(['user' => '', 'ip' => '']);
}

/**
 * Get user limits with caching
 */
function getUserLimits($username, $pdo) {
    try {
        // Try cache first
        $cached = getCachedUserData($username);
        if ($cached) {
            return $cached;
        }
        
        // Get from database
        $stmt = $pdo->prepare("
            SELECT username, max_threads, quota_bytes, bytes_used, status, expires_at
            FROM users 
            WHERE username = ? AND status = 'active'
        ");
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user) {
            // Cache for 5 minutes
            cacheUserData($username, $user, 300);
        }
        
        return $user;
        
    } catch (Exception $e) {
        logError("Failed to get user limits: " . $e->getMessage());
        return false;
    }
}

/**
 * Increment user strike count
 */
function incrementUserStrikeCount($username, $pdo) {
    try {
        $stmt = $pdo->prepare("
            UPDATE users 
            SET strike_count = strike_count + 1, timeout_until = DATE_ADD(NOW(), INTERVAL 1 HOUR)
            WHERE username = ?
        ");
        $stmt->execute([$username]);
        
        // Clear user cache
        $redis = getRedisConnection();
        $redis->del("user_cache:$username");
        
    } catch (Exception $e) {
        logError("Failed to increment strike count: " . $e->getMessage());
    }
}

/**
 * Clean up disconnected sessions
 */
function cleanupDisconnectedSessions($activeConnections, $pdo) {
    try {
        // Get list of active usernames and IPs
        $activeUsers = [];
        $activeIps = [];
        
        foreach ($activeConnections as $conn) {
            if (!empty($conn['user'])) {
                $activeUsers[] = $conn['user'];
            }
            if (!empty($conn['ip'])) {
                $activeIps[] = $conn['ip'];
            }
        }
        
        // Mark sessions as disconnected if not in active list
        if (!empty($activeUsers)) {
            $placeholders = str_repeat('?,', count($activeUsers) - 1) . '?';
            $stmt = $pdo->prepare("
                UPDATE user_sessions 
                SET disconnected_at = NOW() 
                WHERE username NOT IN ($placeholders) AND disconnected_at IS NULL
            ");
            $stmt->execute($activeUsers);
        }
        
        // Update Redis thread counts to match reality
        foreach ($activeConnections as $conn) {
            if (!empty($conn['user'])) {
                $redis = getRedisConnection();
                $redis->set("threads_live:{$conn['user']}", $conn['conns'] ?? 0);
            }
        }
        
    } catch (Exception $e) {
        logError("Failed to cleanup disconnected sessions: " . $e->getMessage());
    }
}

/**
 * Update system connection metrics
 */
function updateSystemConnectionMetrics($totalConnections, $redis) {
    try {
        updateSystemMetric('active_connections', $totalConnections);
        updateSystemMetric('last_control_check', time());
        
        // Track peak connections
        $peakConnections = getSystemMetric('peak_connections_today') ?: 0;
        if ($totalConnections > $peakConnections) {
            updateSystemMetric('peak_connections_today', $totalConnections);
        }
        
    } catch (Exception $e) {
        logError("Failed to update connection metrics: " . $e->getMessage());
    }
}

/**
 * Log security events
 */
function logSecurityEvent($eventType, $clientIp, $username, $details = []) {
    try {
        $pdo = getDbConnection();
        $stmt = $pdo->prepare("
            INSERT INTO security_events (event_type, username, client_ip, details, severity, created_at)
            VALUES (?, ?, ?, ?, 'medium', NOW())
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
    $logMessage = "[$timestamp] CONTROL ERROR: $message\n";
    
    // Log to file
    $logFile = __DIR__ . '/../../logs/api/control.log';
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    
    // Also log to system error log
    error_log($logMessage);
}
?>
