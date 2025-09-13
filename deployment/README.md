# CLAUDE DLS Deployment Guide

This directory contains deployment configurations and scripts for the CLAUDE DLS (Cloud-Linked Agile Unified Diskless Environment) system.

## Overview

CLAUDE DLS supports two primary deployment methods:

1. **FreeBSD Jails** - Native FreeBSD deployment with jail isolation
2. **Docker Containers** - Cross-platform containerized deployment

## Quick Start

### Docker Deployment (Recommended for Development)

```bash
# Clone and build
git clone <repository-url>
cd DLS/deployment

# Quick start (builds and deploys everything)
make quick-start

# Access the system
open http://localhost:8080        # CLAUDE DLS Web UI
open http://localhost:3000        # Grafana (admin/admin123)
open http://localhost:9091        # Prometheus

# Run tests
make test-deployment-docker
```

### FreeBSD Deployment (Production)

```bash
# On FreeBSD 14.x system
git clone <repository-url>
cd DLS/deployment

# Deploy to FreeBSD with jails
make deploy-freebsd

# Or manual deployment
chmod +x scripts/deploy_freebsd.sh
./scripts/deploy_freebsd.sh
```

## Directory Structure

```
deployment/
├── configs/                 # Configuration files
│   ├── production.toml      # Main production configuration
│   ├── postgres/           # PostgreSQL configurations
│   ├── prometheus/         # Prometheus monitoring setup
│   ├── grafana/           # Grafana dashboard configurations
│   └── nginx/             # Reverse proxy configurations
├── containers/            # Docker deployment files
│   ├── Dockerfile         # Multi-stage Docker build
│   └── docker-compose.yml # Complete stack definition
├── freebsd/              # FreeBSD-specific configurations
│   └── jail.conf         # Jail configuration
├── scripts/              # Deployment and utility scripts
│   ├── deploy_freebsd.sh # FreeBSD deployment script
│   └── test_deployment.sh # Comprehensive testing script
├── Makefile              # Deployment automation
└── README.md            # This file
```

## Deployment Methods

### Docker Compose Deployment

**Advantages:**
- Cross-platform compatibility
- Easy development setup
- Isolated services
- Simple scaling

**Services included:**
- CLAUDE DLS Server
- PostgreSQL Database
- Prometheus Monitoring
- Grafana Dashboards
- NGINX Reverse Proxy
- Redis Caching
- Log Aggregation (Loki)

```bash
# Development deployment
make deploy-docker-dev

# Production deployment
make deploy-docker

# View logs
make logs-docker

# Scale services
docker-compose -f containers/docker-compose.yml up -d --scale claude_dls=3
```

### FreeBSD Jail Deployment

**Advantages:**
- Native FreeBSD performance
- ZFS integration
- Production-grade isolation
- Lower overhead than containers

**Jails created:**
- `claude_dls` - Main application (10.0.1.10)
- `claude_db` - PostgreSQL database (10.0.1.11)
- `claude_monitor` - Prometheus/Grafana (10.0.1.12)
- `claude_tftp` - TFTP service (10.0.1.13)
- `claude_dhcp` - DHCP service (10.0.1.14)

```bash
# Deploy to FreeBSD
make deploy-freebsd

# Monitor jails
jls
jexec claude_dls /bin/sh

# View logs
tail -f /var/log/claude_dls/server.log
```

## Configuration

### Environment Variables

Create a `.env` file in the deployment directory:

```bash
# Generate example .env file
make .env

# Edit configuration
vim .env
```

Key variables:
- `POSTGRES_PASSWORD` - Database password
- `JWT_SECRET` - JWT signing secret
- `GRAFANA_PASSWORD` - Grafana admin password
- `RUST_LOG` - Logging level

### Production Configuration

The main configuration file is `configs/production.toml`:

```toml
[server]
bind_address = "0.0.0.0:8080"
worker_threads = 8
max_connections = 1000

[database]
url = "postgresql://claude_dls:password@postgres:5432/claude_dls_production"
max_connections = 100

[storage]
base_path = "/var/lib/claude_dls/images"
zfs_pool = "claude_images"
max_image_size_gb = 100

[monitoring]
metrics_enabled = true
metrics_endpoint = "/metrics"
prometheus_namespace = "claude_dls"
```

## Testing

### Automated Testing

```bash
# Test Docker deployment
make test-deployment-docker

# Test FreeBSD deployment
make test-deployment-freebsd

# Run specific tests
./scripts/test_deployment.sh docker
```

### Manual Testing

```bash
# Check API health
curl http://localhost:8080/health

# View metrics
curl http://localhost:8080/metrics

# Test authentication
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## Monitoring

### Grafana Dashboards

Access Grafana at `http://localhost:3000` (admin/admin123):

- **System Overview** - CPU, memory, disk usage
- **Network Services** - DHCP, TFTP, iSCSI metrics
- **Client Management** - Boot sessions, failures, timing
- **Authentication** - Login attempts, failures, sessions
- **Storage System** - Image operations, ZFS metrics

### Prometheus Metrics

Access Prometheus at `http://localhost:9091`:

- **Network Metrics**: `claude_dls_dhcp_requests_total`, `claude_dls_tftp_requests_total`
- **Client Metrics**: `claude_dls_active_clients`, `claude_dls_boot_time_seconds`
- **Storage Metrics**: `claude_dls_storage_used_bytes`, `claude_dls_disk_images_total`
- **Auth Metrics**: `claude_dls_auth_requests_total`, `claude_dls_active_sessions`

### Log Management

```bash
# Docker logs
docker-compose logs -f claude_dls

# FreeBSD logs
tail -f /var/log/claude_dls/server.log

# Structured JSON logs
jq '.' < /var/log/claude_dls/server.log
```

## Security

### Authentication

- JWT-based authentication with configurable expiration
- Role-based access control (Admin, Operator, Viewer)
- Password hashing with Argon2
- Session management with timeout

### Network Security

```bash
# Enable firewall (FreeBSD)
sysrc firewall_enable="YES"
sysrc firewall_type="workstation"

# Docker network isolation
docker network ls
docker network inspect claude_network
```

### SSL/TLS Configuration

```bash
# Generate SSL certificates
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout configs/ssl/claude.key \
  -out configs/ssl/claude.crt

# Update NGINX configuration
vim configs/nginx/claude.conf
```

## Backup and Recovery

### Automated Backups

```bash
# Create backup
make backup

# Restore backup
make restore BACKUP_FILE=backups/claude-dls-backup-20241213-140000.tar.gz
```

### Database Backups

```bash
# Manual database backup
docker exec claude_postgres pg_dump -U claude_dls claude_dls_production > backup.sql

# Restore database
cat backup.sql | docker exec -i claude_postgres psql -U claude_dls claude_dls_production
```

### ZFS Snapshots (FreeBSD)

```bash
# Create ZFS snapshot
zfs snapshot zpool/claude_dls@backup-$(date +%Y%m%d)

# List snapshots
zfs list -t snapshot

# Rollback to snapshot
zfs rollback zpool/claude_dls@backup-20241213
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check port usage
   netstat -tulpn | grep :8080
   
   # Kill process using port
   lsof -ti:8080 | xargs kill -9
   ```

2. **Database Connection Failed**
   ```bash
   # Check database status
   docker-compose ps postgres
   
   # View database logs
   docker-compose logs postgres
   
   # Test connection
   psql -h localhost -U claude_dls claude_dls_production
   ```

3. **Jail Won't Start (FreeBSD)**
   ```bash
   # Check jail configuration
   jail -f /etc/jail.conf -c claude_dls
   
   # View jail logs
   tail -f /var/log/messages | grep jail
   ```

4. **Metrics Not Available**
   ```bash
   # Check metrics endpoint
   curl -v http://localhost:8080/metrics
   
   # Verify Prometheus target
   curl http://localhost:9091/api/v1/targets
   ```

### Log Analysis

```bash
# View application logs
make logs-docker  # or logs-freebsd

# Search for errors
docker-compose logs claude_dls | grep ERROR

# Monitor real-time logs
tail -f /var/log/claude_dls/server.log | jq 'select(.level == "ERROR")'
```

### Performance Tuning

```bash
# Check system resources
htop
df -h
iostat -x 1

# Tune PostgreSQL
vim configs/postgres/postgresql.conf

# Adjust worker threads
vim configs/production.toml  # server.worker_threads
```

## Development

### Local Development Setup

```bash
# Set up development environment
make dev-setup

# Run with auto-reload
make dev-watch

# Run tests with auto-reload
make dev-test-watch
```

### Custom Configuration

```bash
# Validate configuration
make config-validate

# Generate example config
make config-example

# Edit production config
vim configs/production.toml
```

## Production Deployment

### Pre-deployment Checklist

- [ ] Update configuration files
- [ ] Set secure passwords and secrets
- [ ] Configure SSL certificates
- [ ] Set up monitoring and alerting
- [ ] Plan backup strategy
- [ ] Configure firewall rules
- [ ] Test disaster recovery

### Deployment Process

```bash
# 1. Build release version
make release-build

# 2. Run security scan
make security-scan

# 3. Deploy to staging
make deploy-docker

# 4. Run comprehensive tests
make test-deployment-docker

# 5. Deploy to production
make prod-deploy
```

### Post-deployment

```bash
# Verify deployment
make health

# Monitor system
make monitor

# Check metrics
make metrics

# View status
make status-docker  # or status-freebsd
```

## Support

### Getting Help

1. Check the [main README](../README.md) for general information
2. Review logs for error messages
3. Run deployment tests to identify issues
4. Check system resources and network connectivity

### Contributing

1. Test changes with both deployment methods
2. Update configuration examples
3. Add tests for new features
4. Update documentation

### Version Information

- CLAUDE DLS Version: 0.1.0
- Supported Platforms: FreeBSD 14.x, Linux (Docker)
- Rust Version: 1.80+
- PostgreSQL: 14+
- Docker Compose: 3.8+

---

**Author:** Mario Cho <hephaex@gmail.com>  
**License:** MIT  
**Repository:** https://github.com/hephaex/DLS