<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Redis Client Configuration
 * ============================================================================
 * 
 * Redis integration for real-time counters and caching
 * Supports: Thread counting, quota tracking, rate limiting, strike system
 * ============================================================================
 */

// Redis configuration
define('REDIS_HOST', $_ENV['REDIS_HOST'] ?? getenv('REDIS_HOST') ?: '127.0.0.1');
define('REDIS_PORT', $_ENV['REDIS_PORT'] ?? getenv('REDIS_PORT') ?: 6379);
define('REDIS_PASSWORD', $_ENV['REDIS_PASSWORD'] ?? getenv('REDIS_PASSWORD') ?: '');
define('REDIS_DATABASE', $_ENV['REDIS_DATABASE'] ?? getenv('REDIS_DATABASE') ?: 0);

// Global Redis connection
$redis_connection = null;

/**
 * Get Redis connection (singleton pattern)
 */
function getRedisConnection() {
    global $redis_connection;
    
    if ($redis_connection === null) {
        try {
            $redis_connection = new Redis();
            
            // Connect to Redis
            if (!$redis_connection->connect(REDIS_HOST, REDIS_PORT, 2.0)) {
                throw new Exception("Cannot connect to Redis server");
            }
            
            // Authenticate if password is set
            if (!empty(REDIS_PASSWORD)) {
                if (!$redis_connection->auth(REDIS_PASSWORD)) {
                    throw new Exception("Redis authentication failed");
                }
            }
            
            // Select database
            if (!$redis_connection->select(REDIS_DATABASE)) {
                throw new Exception("Cannot select Redis database");
            }
            
            // Set connection options
            $redis_connection->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_JSON);
            $redis_connection->setOption(Redis::OPT_PREFIX, 'proxy_saas:');
            
        } catch (Exception $e) {
            logError("Redis connection failed: " . $e->getMessage());
            
            // Return mock Redis object for graceful degradation
            return new MockRedis();
        }
    }
    
    return $redis_connection;
}

/**
 * Mock Redis class for graceful degradation when Redis is unavailable
 */
class MockRedis {
    private $data = [];
    
    public function get($key) {
        return $this->data[$key] ?? false;
    }
    
    public function set($key, $value, $ttl = null) {
        $this->data[$key] = $value;
        return true;
    }
    
    public function setex($key, $ttl, $value) {
        $this->data[$key] = $value;
        return true;
    }
    
    public function incr($key) {
        if (!isset($this->data[$key])) {
            $this->data[$key] = 0;
        }
        return ++$this->data[$key];
    }
    
    public function decr($key) {
        if (!isset($this->data[$key])) {
            $this->data[$key] = 0;
        }
        return --$this->data[$key];
    }
    
    public function del($key) {
        unset($this->data[$key]);
        return true;
    }
    
    public function expire($key, $ttl) {
        return true;
    }
    
    public function exists($key) {
        return isset($this->data[$key]);
    }
    
    public function hget($hash, $key) {
        return $this->data[$hash][$key] ?? false;
    }
    
    public function hset($hash, $key, $value) {
        if (!isset($this->data[$hash])) {
            $this->data[$hash] = [];
        }
        $this->data[$hash][$key] = $value;
        return true;
    }
    
    public function hgetall($hash) {
        return $this->data[$hash] ?? [];
    }
    
    public function sadd($set, $member) {
        if (!isset($this->data[$set])) {
            $this->data[$set] = [];
        }
        if (!in_array($member, $this->data[$set])) {
            $this->data[$set][] = $member;
            return 1;
        }
        return 0;
    }
    
    public function srem($set, $member) {
        if (isset($this->data[$set])) {
            $key = array_search($member, $this->data[$set]);
            if ($key !== false) {
                unset($this->data[$set][$key]);
                return 1;
            }
        }
        return 0;
    }
    
    public function smembers($set) {
        return $this->data[$set] ?? [];
    }
    
    public function sismember($set, $member) {
        return isset($this->data[$set]) && in_array($member, $this->data[$set]);
    }
}

/**
 * Redis helper functions for SaaS operations
 */

/**
 * Increment user thread counter
 */
function incrementUserThreads($username) {
    $redis = getRedisConnection();
    return $redis->incr("threads_live:$username");
}

/**
 * Decrement user thread counter
 */
function decrementUserThreads($username) {
    $redis = getRedisConnection();
    $count = $redis->decr("threads_live:$username");
    
    // Don't let it go below 0
    if ($count < 0) {
        $redis->set("threads_live:$username", 0);
        return 0;
    }
    
    return $count;
}

/**
 * Get user thread count
 */
function getUserThreadCount($username) {
    $redis = getRedisConnection();
    return (int)($redis->get("threads_live:$username") ?: 0);
}

/**
 * Add bytes to user quota
 */
function addUserBytes($username, $bytes) {
    $redis = getRedisConnection();
    return $redis->incr("bytes_used:$username", $bytes);
}

/**
 * Get user bytes used
 */
function getUserBytesUsed($username) {
    $redis = getRedisConnection();
    return (int)($redis->get("bytes_used:$username") ?: 0);
}

/**
 * Reset user bytes (monthly reset)
 */
function resetUserBytes($username) {
    $redis = getRedisConnection();
    return $redis->set("bytes_used:$username", 0);
}

/**
 * Set user overlimit timer (strike system)
 */
function setUserOverlimit($username, $duration = 900) {
    $redis = getRedisConnection();
    return $redis->setex("overlimit_since:$username", $duration, time());
}

/**
 * Get user overlimit start time
 */
function getUserOverlimitSince($username) {
    $redis = getRedisConnection();
    return $redis->get("overlimit_since:$username");
}

/**
 * Clear user overlimit timer
 */
function clearUserOverlimit($username) {
    $redis = getRedisConnection();
    return $redis->del("overlimit_since:$username");
}

/**
 * Set user timeout (1 hour ban)
 */
function setUserTimeout($username, $duration = 3600) {
    $redis = getRedisConnection();
    return $redis->setex("timeout_until:$username", $duration, time() + $duration);
}

/**
 * Get user timeout expiration
 */
function getUserTimeoutUntil($username) {
    $redis = getRedisConnection();
    return $redis->get("timeout_until:$username");
}

/**
 * Clear user timeout
 */
function clearUserTimeout($username) {
    $redis = getRedisConnection();
    return $redis->del("timeout_until:$username");
}

/**
 * Cache user data
 */
function cacheUserData($username, $userData, $ttl = 300) {
    $redis = getRedisConnection();
    return $redis->setex("user_cache:$username", $ttl, json_encode($userData));
}

/**
 * Get cached user data
 */
function getCachedUserData($username) {
    $redis = getRedisConnection();
    $data = $redis->get("user_cache:$username");
    return $data ? json_decode($data, true) : false;
}

/**
 * Rate limiting functions
 */
function checkRateLimit($key, $limit, $window = 3600) {
    $redis = getRedisConnection();
    
    $current = $redis->get("rate_limit:$key") ?: 0;
    if ($current >= $limit) {
        return false;
    }
    
    $redis->incr("rate_limit:$key");
    $redis->expire("rate_limit:$key", $window);
    
    return true;
}

/**
 * System metrics functions
 */
function updateSystemMetric($metric, $value) {
    $redis = getRedisConnection();
    return $redis->set("system:$metric", $value);
}

function getSystemMetric($metric) {
    $redis = getRedisConnection();
    return $redis->get("system:$metric");
}

/**
 * IP whitelist caching
 */
function cacheUserIpWhitelist($username, $ipList, $ttl = 600) {
    $redis = getRedisConnection();
    
    // Clear existing set
    $redis->del("ip_whitelist:$username");
    
    // Add IPs to set
    foreach ($ipList as $ip) {
        $redis->sadd("ip_whitelist:$username", $ip);
    }
    
    // Set expiration
    $redis->expire("ip_whitelist:$username", $ttl);
    
    return true;
}

function isIpInCachedWhitelist($username, $ip) {
    $redis = getRedisConnection();
    return $redis->sismember("ip_whitelist:$username", $ip);
}

/**
 * Health check for Redis
 */
function isRedisHealthy() {
    try {
        $redis = getRedisConnection();
        return $redis->ping() === '+PONG';
    } catch (Exception $e) {
        return false;
    }
}

/**
 * Get Redis info
 */
function getRedisInfo() {
    try {
        $redis = getRedisConnection();
        return [
            'connected' => true,
            'info' => $redis->info(),
            'memory_usage' => $redis->info('memory')['used_memory_human'] ?? 'unknown'
        ];
    } catch (Exception $e) {
        return [
            'connected' => false,
            'error' => $e->getMessage()
        ];
    }
}
?>
