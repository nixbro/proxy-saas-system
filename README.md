# 🌐 **Proxy-SaaS-System - Enterprise Proxy Management Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-blue.svg)](https://php.net)
[![GoProxy](https://img.shields.io/badge/GoProxy-13.1%2B-green.svg)](https://github.com/snail007/goproxy)
[![Redis](https://img.shields.io/badge/Redis-6.0%2B-red.svg)](https://redis.io)
[![MariaDB](https://img.shields.io/badge/MariaDB-10.6%2B-orange.svg)](https://mariadb.org)

> **Enterprise-grade SaaS proxy management system with real-time monitoring, sophisticated rate limiting, and comprehensive security features.**

## 🎯 **What This System Does**

Think of it as a **plug-and-play proxy cloud** you host yourself using [GoProxy](https://snail007.host900.com/goproxy/manual/#/) as the core engine:

1. **Feed it ~1,000 upstream proxies** (`user:pass@host:port`)
2. **Binds each to local TCP ports** (4000-4999) using GoProxy
3. **Customers connect** to any of those local ports
4. **SaaS layer monitors everything** in real-time with PHP + Redis + MariaDB
5. **Enforces limits**: threads, QPS, bandwidth, quotas, expiry dates
6. **Strike system**: 15 minutes over limit = 1 hour timeout
7. **Customer API**: `/api/proxies.php` returns available ports
8. **Admin APIs**: Complete management suite with token authentication

## 🏗️ **System Architecture**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           PROXY-SAAS-SYSTEM                                    │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────────┐ │
│  │   Customer      │───▶│   Public APIs    │───▶│      Redis + MariaDB       │ │
│  │   Applications  │    │  (Rate Limited)  │    │    (Real-time Counters)    │ │
│  └─────────────────┘    └──────────────────┘    └─────────────────────────────┘ │
│                                 │                                               │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────────┐ │
│  │  Admin Panel    │───▶│   Admin APIs     │───▶│     Security & Logging      │ │
│  │  & Dashboard    │    │ (Token Secured)  │    │       (Audit Trail)        │ │
│  └─────────────────┘    └──────────────────┘    └─────────────────────────────┘ │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                        GOPROXY CORE ENGINE                                 │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │ │
│  │  │ GoProxy     │  │ GoProxy     │  │ GoProxy     │  │ GoProxy     │      │ │
│  │  │ Port 4000   │  │ Port 4001   │  │ Port 4002   │  │ ... 4999    │      │ │
│  │  │ Upstream 1  │  │ Upstream 2  │  │ Upstream 3  │  │ Upstream N  │      │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘      │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
│                                 │                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────┐ │
│  │                      INTERNAL MONITORING                                   │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │ │
│  │  │  auth.php   │  │traffic.php  │  │control.php  │  │ Strike      │      │ │
│  │  │(127.0.0.1)  │  │(127.0.0.1)  │  │(127.0.0.1)  │  │ System      │      │ │
│  │  │ Validate    │  │ Track       │  │ Enforce     │  │ 15min→1hr   │      │ │
│  │  │ & Count     │  │ Usage       │  │ Limits      │  │ Timeout     │      │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘      │ │
│  └─────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## 🚀 **Quick Start**

### **1. One-Command Installation**

```bash
# Download and install everything
curl -sSL https://raw.githubusercontent.com/your-repo/proxy-saas-system/main/deploy.sh | sudo bash -s -- --install
```

### **2. Manual Installation**

```bash
# Clone repository
git clone https://github.com/your-repo/proxy-saas-system.git
cd proxy-saas-system

# Make deployment script executable
chmod +x deploy.sh

# Run installation
sudo ./deploy.sh --install
```

### **3. Configuration**

```bash
# Edit configuration
sudo nano /opt/proxy-saas-system/.env

# Add your upstream proxies
sudo nano /opt/proxy-saas-system/proxy.txt

# Start the system
sudo systemctl start proxy-saas-system
sudo systemctl status proxy-saas-system
```

## 📋 **System Requirements**

### **Minimum Requirements**
- **OS**: Ubuntu 20.04+ or CentOS 8+
- **RAM**: 2GB minimum, 8GB recommended
- **Storage**: 10GB minimum, 100GB recommended
- **CPU**: 2 cores minimum, 8 cores recommended
- **Network**: 100Mbps minimum, 1Gbps recommended

### **Software Dependencies**
- **GoProxy**: 13.1+ (automatically installed)
- **PHP**: 8.1+ with extensions (pdo, mysql, redis, curl, json)
- **MariaDB**: 10.6+ or MySQL 8.0+
- **Redis**: 6.0+ for real-time counters
- **Nginx**: 1.18+ for web server
- **Certbot**: For SSL certificates

## 🔧 **Core Components**

### **1. Proxy Pool Manager (`proxy_pool_manager.sh`)**
- Reads `proxy.txt` with upstream proxies
- Spawns GoProxy instances on ports 4000-4999
- Handles graceful reload and health monitoring
- Auto-restarts failed processes

### **2. Internal PHP Hooks (127.0.0.1 only)**
- **`auth.php`**: Validates connections, enforces quotas
- **`traffic.php`**: Tracks bandwidth every 5 seconds
- **`control.php`**: Implements strike system, kicks violators

### **3. Public APIs**
- **`/api/proxies.php`**: Returns available ports for customers
- **`/api/admin/*`**: Complete admin management suite
- **`/api/manage_ips.php`**: Customer IP whitelist management

### **4. Real-time Monitoring**
- **Redis**: Live counters for threads, bandwidth, quotas
- **MariaDB**: Persistent storage and billing data
- **Strike System**: 15-minute grace → 1-hour timeout

## 💰 **Business Model Integration**

### **Customer Tiers**
| Plan | Threads | Bandwidth | Quota | Price |
|------|---------|-----------|-------|-------|
| **Basic** | 10 | 1MB/s | 1GB/month | $10/month |
| **Pro** | 50 | 10MB/s | 10GB/month | $50/month |
| **Enterprise** | 200 | 100MB/s | 100GB/month | $200/month |
| **Custom** | Unlimited | Custom | Custom | $500+/month |

### **Revenue Features**
- Real-time usage monitoring
- Automated billing integration
- Overage alerts and upselling
- Customer analytics and insights

## 🔒 **Security Features**

### **Network Security**
- Internal APIs firewalled to `127.0.0.1` only
- Public APIs rate-limited and token-protected
- TLS encryption for all external traffic
- Fail2ban for brute-force protection

### **Authentication Layers**
- Admin token-based authentication (SHA-256)
- Customer IP whitelisting with CIDR support
- Multi-method authentication (password, IP, API key)
- Redis-based rate limiting

### **Data Protection**
- Environment variables for sensitive config
- Encrypted database connections
- Audit trails for all admin actions
- Automatic log rotation and cleanup

## 📊 **Rate Limiting & Quota System**

| Feature | Enforcement | Mechanism |
|---------|-------------|-----------|
| **Threads (simultaneous sockets)** | Redis `threads_live` + GoProxy `userconns` | Hard kicked by `control.php` |
| **QPS burst** | GoProxy `userqps` header | Native GoProxy throttling |
| **Bandwidth (B/s)** | GoProxy `userTotalRate` header | Native GoProxy throttling |
| **Per-IP limits** | GoProxy `ipconns`, `iprate` headers | Native GoProxy throttling |
| **Monthly quota** | Redis `bytes_used` + MariaDB | API blocks + kicks |
| **Plan expiry** | MariaDB `expires_at` | API validation |

## 🧪 **Testing & Quality Assurance**

### **Run Complete Test Suite**
```bash
# Run all integration tests
sudo /opt/proxy-saas-system/tests/integration_test.sh

# Test specific components
sudo /opt/proxy-saas-system/tests/test_database.sh
sudo /opt/proxy-saas-system/tests/test_apis.sh
sudo /opt/proxy-saas-system/tests/test_security.sh
```

### **Load Testing**
```bash
# Test 1000+ concurrent connections
sudo /opt/proxy-saas-system/tests/load_test.sh --users 1000 --duration 300

# Benchmark API performance
sudo /opt/proxy-saas-system/tests/benchmark_apis.sh
```

## 📚 **API Documentation**

### **Customer API**
```bash
# Get available proxy ports
curl "https://proxy.example.com/api/proxies.php?api_key=your_api_key"

# Response (text/plain):
proxy.example.com:4000
proxy.example.com:4001
proxy.example.com:4002
```

### **Admin APIs**
```bash
# Create user
curl -X POST "https://proxy.example.com/api/admin/users.php" \
  -H "Authorization: Bearer admin_token" \
  -d '{"username":"newuser","plan":"pro","quota_gb":10}'

# Get user stats
curl "https://proxy.example.com/api/admin/stats.php?username=user" \
  -H "Authorization: Bearer admin_token"
```

## 🔧 **Configuration**

### **Environment Variables (.env)**
```bash
# Application
APP_ENV=production
SERVER_HOST=proxy.example.com

# Database
DB_HOST=localhost
DB_NAME=proxy_saas
DB_USER=proxy_user
DB_PASS=secure_password

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379

# Strike System
OVERLIMIT_GRACE_PERIOD=900  # 15 minutes
TIMEOUT_DURATION=3600       # 1 hour
```

### **Proxy Configuration (proxy.txt)**
```
# Format: host:port:username:password
proxy1.example.com:8080:user1:pass1
proxy2.example.com:8080:user2:pass2
proxy3.example.com:8080:user3:pass3
```

## 🚀 **Deployment Options**

### **Single Server Deployment**
```bash
# Standard installation
sudo ./deploy.sh --install
```

### **High Availability Deployment**
```bash
# Load balancer + multiple servers
sudo ./deploy.sh --install --ha --nodes 3
```

### **Docker Deployment**
```bash
# Docker Compose
docker-compose up -d
```

### **Kubernetes Deployment**
```bash
# Kubernetes manifests
kubectl apply -f k8s/
```

## 📈 **Monitoring & Alerting**

### **System Health**
```bash
# Check system status
sudo systemctl status proxy-saas-system

# View real-time logs
sudo journalctl -u proxy-saas-system -f

# Monitor performance
sudo /opt/proxy-saas-system/monitor.sh --dashboard
```

### **Metrics & Analytics**
- Real-time connection counts
- Bandwidth usage per user
- API response times
- Error rates and security events
- Revenue and billing metrics

## 🔄 **Maintenance**

### **Updates**
```bash
# Update system
sudo ./deploy.sh --update

# Update GoProxy only
sudo ./update_goproxy.sh
```

### **Backups**
```bash
# Manual backup
sudo /opt/proxy-saas-system/backup.sh

# Automated backups (configured in cron)
sudo crontab -l
```

### **Log Management**
```bash
# Rotate logs
sudo /opt/proxy-saas-system/rotate_logs.sh

# Clean old logs
sudo /opt/proxy-saas-system/cleanup_logs.sh --days 30
```

## 🆘 **Troubleshooting**

### **Common Issues**

**GoProxy not starting:**
```bash
# Check GoProxy installation
proxy --version

# Check port availability
sudo netstat -tulpn | grep :4000

# Check logs
sudo tail -f /opt/proxy-saas-system/logs/users/port_4000.log
```

**Database connection issues:**
```bash
# Test database connection
mysql -u proxy_user -p proxy_saas

# Check database service
sudo systemctl status mariadb
```

**Redis connection issues:**
```bash
# Test Redis connection
redis-cli ping

# Check Redis service
sudo systemctl status redis-server
```

## 📞 **Support**

- **Documentation**: [Full documentation](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-repo/proxy-saas-system/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/proxy-saas-system/discussions)
- **Email**: support@your-domain.com

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- [GoProxy](https://github.com/snail007/goproxy) - Core proxy engine
- [Redis](https://redis.io) - Real-time data store
- [MariaDB](https://mariadb.org) - Database system
- [PHP](https://php.net) - Backend language
- [Nginx](https://nginx.org) - Web server

---

**Built with ❤️ for enterprise proxy management**
