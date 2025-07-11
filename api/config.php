<?php
/**
 * ============================================================================
 * PROXY-SAAS-SYSTEM - Configuration File
 * ============================================================================
 * 
 * Central configuration for the entire SaaS proxy management system
 * Handles database connections, environment variables, and global settings
 * ============================================================================
 */

// Prevent direct access
if (!defined('PHP_SAPI') && php_sapi_name() !== 'cli') {
    if (basename($_SERVER['SCRIPT_NAME']) === basename(__FILE__)) {
        http_response_code(403);
        exit('Direct access forbidden');
    }
}

// Error reporting (adjust for production)
error_reporting(E_ALL);
ini_set('display_errors', 0); // Set to 0 in production
ini_set('log_errors', 1);

// Timezone
date_default_timezone_set($_ENV['TIMEZONE'] ?? getenv('TIMEZONE') ?: 'UTC');

// Load environment variables from .env file if it exists
if (file_exists(__DIR__ . '/../.env')) {
    $lines = file(__DIR__ . '/../.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos($line, '=') !== false && strpos($line, '#') !== 0) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value, " \t\n\r\0\x0B\"'");
            if (!getenv($key)) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
            }
        }
    }
}

// ============================================================================
// DATABASE CONFIGURATION
// ============================================================================

define('DB_HOST', $_ENV['DB_HOST'] ?? getenv('DB_HOST') ?: 'localhost');
define('DB_PORT', $_ENV['DB_PORT'] ?? getenv('DB_PORT') ?: 3306);
define('DB_NAME', $_ENV['DB_NAME'] ?? getenv('DB_NAME') ?: 'proxy_saas');
define('DB_USER', $_ENV['DB_USER'] ?? getenv('DB_USER') ?: 'proxy_user');
define('DB_PASS', $_ENV['DB_PASS'] ?? getenv('DB_PASS') ?: 'secure_password');
define('DB_CHARSET', $_ENV['DB_CHARSET'] ?? getenv('DB_CHARSET') ?: 'utf8mb4');

// Database connection options
$db_options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES " . DB_CHARSET,
    PDO::ATTR_TIMEOUT => 5,
    PDO::ATTR_PERSISTENT => false
];

// Global database connection
$db_connection = null;

/**
 * Get database connection (singleton pattern)
 */
function getDbConnection() {
    global $db_connection, $db_options;
    
    if ($db_connection === null) {
        try {
            $dsn = sprintf(
                'mysql:host=%s;port=%d;dbname=%s;charset=%s',
                DB_HOST,
                DB_PORT,
                DB_NAME,
                DB_CHARSET
            );
            
            $db_connection = new PDO($dsn, DB_USER, DB_PASS, $db_options);
            
        } catch (PDOException $e) {
            logError("Database connection failed: " . $e->getMessage());
            
            // In production, you might want to show a generic error
            if (getenv('APP_ENV') === 'production') {
                http_response_code(503);
                exit('Service temporarily unavailable');
            } else {
                throw $e;
            }
        }
    }
    
    return $db_connection;
}

// ============================================================================
// APPLICATION CONFIGURATION
// ============================================================================

// Application settings
define('APP_NAME', $_ENV['APP_NAME'] ?? getenv('APP_NAME') ?: 'Proxy SaaS System');
define('APP_VERSION', $_ENV['APP_VERSION'] ?? getenv('APP_VERSION') ?: '1.0.0');
define('APP_ENV', $_ENV['APP_ENV'] ?? getenv('APP_ENV') ?: 'development');
define('APP_DEBUG', filter_var($_ENV['APP_DEBUG'] ?? getenv('APP_DEBUG') ?: 'false', FILTER_VALIDATE_BOOLEAN));

// Server configuration
define('SERVER_HOST', $_ENV['SERVER_HOST'] ?? getenv('SERVER_HOST') ?: 'proxy.example.com');
define('SERVER_PORT_START', $_ENV['SERVER_PORT_START'] ?? getenv('SERVER_PORT_START') ?: 4000);
define('SERVER_PORT_END', $_ENV['SERVER_PORT_END'] ?? getenv('SERVER_PORT_END') ?: 4999);

// API configuration
define('API_RATE_LIMIT', $_ENV['API_RATE_LIMIT'] ?? getenv('API_RATE_LIMIT') ?: 100);
define('API_RATE_WINDOW', $_ENV['API_RATE_WINDOW'] ?? getenv('API_RATE_WINDOW') ?: 3600);

// Security settings
define('ADMIN_TOKEN_EXPIRY', $_ENV['ADMIN_TOKEN_EXPIRY'] ?? getenv('ADMIN_TOKEN_EXPIRY') ?: 86400);
define('SESSION_TIMEOUT', $_ENV['SESSION_TIMEOUT'] ?? getenv('SESSION_TIMEOUT') ?: 3600);
define('MAX_LOGIN_ATTEMPTS', $_ENV['MAX_LOGIN_ATTEMPTS'] ?? getenv('MAX_LOGIN_ATTEMPTS') ?: 5);

// Strike system configuration
define('OVERLIMIT_GRACE_PERIOD', $_ENV['OVERLIMIT_GRACE_PERIOD'] ?? getenv('OVERLIMIT_GRACE_PERIOD') ?: 900); // 15 minutes
define('TIMEOUT_DURATION', $_ENV['TIMEOUT_DURATION'] ?? getenv('TIMEOUT_DURATION') ?: 3600); // 1 hour

// Logging configuration
define('LOG_LEVEL', $_ENV['LOG_LEVEL'] ?? getenv('LOG_LEVEL') ?: 'INFO');
define('LOG_MAX_SIZE', $_ENV['LOG_MAX_SIZE'] ?? getenv('LOG_MAX_SIZE') ?: 104857600); // 100MB
define('LOG_RETENTION_DAYS', $_ENV['LOG_RETENTION_DAYS'] ?? getenv('LOG_RETENTION_DAYS') ?: 30);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Enhanced logging function
 */
function logError($message, $context = []) {
    $timestamp = date('Y-m-d H:i:s');
    $contextStr = !empty($context) ? ' ' . json_encode($context) : '';
    $logMessage = "[$timestamp] ERROR: $message$contextStr\n";
    
    // Ensure log directory exists
    $logDir = __DIR__ . '/../logs/system';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
    }
    
    // Log to file
    $logFile = $logDir . '/error.log';
    file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    
    // Also log to system error log
    error_log($logMessage);
    
    // Rotate log if too large
    if (file_exists($logFile) && filesize($logFile) > LOG_MAX_SIZE) {
        rotateLogFile($logFile);
    }
}

/**
 * Log info messages
 */
function logInfo($message, $context = []) {
    if (LOG_LEVEL === 'DEBUG' || LOG_LEVEL === 'INFO') {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? ' ' . json_encode($context) : '';
        $logMessage = "[$timestamp] INFO: $message$contextStr\n";
        
        $logDir = __DIR__ . '/../logs/system';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $logFile = $logDir . '/info.log';
        file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }
}

/**
 * Log debug messages
 */
function logDebug($message, $context = []) {
    if (LOG_LEVEL === 'DEBUG') {
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? ' ' . json_encode($context) : '';
        $logMessage = "[$timestamp] DEBUG: $message$contextStr\n";
        
        $logDir = __DIR__ . '/../logs/system';
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $logFile = $logDir . '/debug.log';
        file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }
}

/**
 * Rotate log file when it gets too large
 */
function rotateLogFile($logFile) {
    $rotatedFile = $logFile . '.' . date('Y-m-d-H-i-s');
    rename($logFile, $rotatedFile);
    
    // Compress old log file
    if (function_exists('gzencode')) {
        $content = file_get_contents($rotatedFile);
        file_put_contents($rotatedFile . '.gz', gzencode($content));
        unlink($rotatedFile);
    }
}

/**
 * Generate secure random token
 */
function generateSecureToken($length = 32) {
    if (function_exists('random_bytes')) {
        return bin2hex(random_bytes($length / 2));
    } elseif (function_exists('openssl_random_pseudo_bytes')) {
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    } else {
        // Fallback (less secure)
        return substr(str_shuffle(str_repeat('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', $length)), 0, $length);
    }
}

/**
 * Hash password securely
 */
function hashPassword($password) {
    return password_hash($password, PASSWORD_ARGON2ID, [
        'memory_cost' => 65536, // 64 MB
        'time_cost' => 4,       // 4 iterations
        'threads' => 3          // 3 threads
    ]);
}

/**
 * Verify password
 */
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

/**
 * Sanitize input for database
 */
function sanitizeInput($input) {
    if (is_string($input)) {
        return trim(strip_tags($input));
    }
    return $input;
}

/**
 * Validate email address
 */
function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Validate IP address
 */
function isValidIp($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

/**
 * Check if running in CLI mode
 */
function isCli() {
    return php_sapi_name() === 'cli';
}

/**
 * Get current memory usage
 */
function getMemoryUsage() {
    return [
        'current' => memory_get_usage(true),
        'peak' => memory_get_peak_usage(true),
        'current_formatted' => formatBytes(memory_get_usage(true)),
        'peak_formatted' => formatBytes(memory_get_peak_usage(true))
    ];
}

/**
 * Format bytes to human readable format
 */
function formatBytes($bytes, $precision = 2) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}

/**
 * Get system load average (Linux/Unix only)
 */
function getSystemLoad() {
    if (function_exists('sys_getloadavg')) {
        return sys_getloadavg();
    }
    return [0, 0, 0];
}

/**
 * Check if system is healthy
 */
function isSystemHealthy() {
    $checks = [
        'database' => isDatabaseHealthy(),
        'redis' => isRedisHealthy(),
        'disk_space' => isDiskSpaceHealthy(),
        'memory' => isMemoryHealthy()
    ];
    
    return !in_array(false, $checks, true);
}

/**
 * Check database health
 */
function isDatabaseHealthy() {
    try {
        $pdo = getDbConnection();
        $stmt = $pdo->query('SELECT 1');
        return $stmt !== false;
    } catch (Exception $e) {
        return false;
    }
}

/**
 * Check disk space health
 */
function isDiskSpaceHealthy($threshold = 90) {
    $freeBytes = disk_free_space(__DIR__);
    $totalBytes = disk_total_space(__DIR__);
    
    if ($freeBytes === false || $totalBytes === false) {
        return true; // Can't determine, assume healthy
    }
    
    $usedPercent = (($totalBytes - $freeBytes) / $totalBytes) * 100;
    return $usedPercent < $threshold;
}

/**
 * Check memory health
 */
function isMemoryHealthy($threshold = 90) {
    $memoryLimit = ini_get('memory_limit');
    if ($memoryLimit === '-1') {
        return true; // No limit
    }
    
    $memoryLimitBytes = convertToBytes($memoryLimit);
    $currentUsage = memory_get_usage(true);
    
    $usedPercent = ($currentUsage / $memoryLimitBytes) * 100;
    return $usedPercent < $threshold;
}

/**
 * Convert PHP memory limit to bytes
 */
function convertToBytes($value) {
    $unit = strtolower(substr($value, -1));
    $value = (int)$value;
    
    switch ($unit) {
        case 'g':
            $value *= 1024;
        case 'm':
            $value *= 1024;
        case 'k':
            $value *= 1024;
    }
    
    return $value;
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Create necessary directories
$directories = [
    __DIR__ . '/../logs/system',
    __DIR__ . '/../logs/api',
    __DIR__ . '/../logs/users',
    __DIR__ . '/../logs/security',
    __DIR__ . '/../pids',
    __DIR__ . '/../config'
];

foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// Log system startup
if (!isCli()) {
    logInfo("System initialized", [
        'version' => APP_VERSION,
        'environment' => APP_ENV,
        'memory_limit' => ini_get('memory_limit'),
        'max_execution_time' => ini_get('max_execution_time')
    ]);
}
?>
