#!/bin/sh

# CLAUDE DLS FreeBSD Deployment Script
# Automated deployment script for FreeBSD 14.x production environment

set -e

# Configuration
CLAUDE_VERSION="0.1.0"
JAIL_ROOT="/jails"
ZPOOL_NAME="zpool"
RELEASE="14.1-RELEASE"
ARCH="amd64"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check if running as root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "This script must be run as root"
    fi
}

# Check FreeBSD version
check_freebsd_version() {
    FREEBSD_VERSION=$(freebsd-version | cut -d'-' -f1)
    if [ "$FREEBSD_VERSION" != "14.1" ] && [ "$FREEBSD_VERSION" != "14.0" ]; then
        log_warn "This script is designed for FreeBSD 14.x, detected: $FREEBSD_VERSION"
    fi
}

# Install required packages
install_packages() {
    log_info "Installing required packages..."
    
    # Update package repository
    pkg update -f
    
    # Install system packages
    pkg install -y \
        postgresql14-server \
        postgresql14-contrib \
        prometheus \
        grafana9 \
        nginx \
        git \
        rust \
        llvm \
        cmake \
        pkgconf \
        libpq \
        openssl \
        curl \
        wget \
        htop \
        zsh \
        tmux
    
    # Install Rust cross-compilation tools
    rustup target add x86_64-unknown-freebsd
    
    log_info "Package installation completed"
}

# Setup ZFS datasets
setup_zfs() {
    log_info "Setting up ZFS datasets..."
    
    # Check if zpool exists
    if ! zpool list $ZPOOL_NAME >/dev/null 2>&1; then
        log_error "ZFS pool '$ZPOOL_NAME' not found. Please create the pool first."
    fi
    
    # Create datasets
    zfs create -p $ZPOOL_NAME/jails
    zfs create -p $ZPOOL_NAME/claude_dls
    zfs create -p $ZPOOL_NAME/images
    zfs create -p $ZPOOL_NAME/database
    zfs create -p $ZPOOL_NAME/monitoring
    zfs create -p $ZPOOL_NAME/tftp
    zfs create -p $ZPOOL_NAME/dhcp
    zfs create -p $ZPOOL_NAME/grafana
    
    # Set ZFS properties for production
    zfs set compression=lz4 $ZPOOL_NAME/claude_dls
    zfs set compression=gzip-6 $ZPOOL_NAME/database
    zfs set compression=lz4 $ZPOOL_NAME/images
    zfs set dedup=on $ZPOOL_NAME/images
    
    # Create mount points
    mkdir -p /var/log/claude_dls
    mkdir -p /var/log/postgresql
    
    log_info "ZFS datasets created successfully"
}

# Download and extract FreeBSD base system for jails
setup_jail_base() {
    log_info "Setting up jail base system..."
    
    if [ ! -d "$JAIL_ROOT/base" ]; then
        mkdir -p $JAIL_ROOT
        cd $JAIL_ROOT
        
        # Download base system
        fetch "https://download.freebsd.org/releases/${ARCH}/${RELEASE}/base.txz"
        
        # Extract base system
        mkdir -p base
        tar -xf base.txz -C base/
        rm base.txz
        
        # Update base system
        freebsd-update -b $JAIL_ROOT/base fetch install
        
        log_info "Jail base system setup completed"
    else
        log_info "Jail base system already exists"
    fi
}

# Create individual jails
create_jails() {
    log_info "Creating jails..."
    
    # List of jails to create
    JAILS="claude_dls claude_db claude_monitor claude_tftp claude_dhcp"
    
    for jail in $JAILS; do
        if [ ! -d "$JAIL_ROOT/$jail" ]; then
            log_info "Creating jail: $jail"
            
            # Clone base system
            zfs clone $ZPOOL_NAME/jails/base@clean $ZPOOL_NAME/jails/$jail
            
            # Create jail directory
            mkdir -p $JAIL_ROOT/$jail
            
            # Mount jail filesystem
            mount -t zfs $ZPOOL_NAME/jails/$jail $JAIL_ROOT/$jail
            
            # Copy resolv.conf for network connectivity
            cp /etc/resolv.conf $JAIL_ROOT/$jail/etc/
            
            log_info "Jail $jail created successfully"
        else
            log_info "Jail $jail already exists"
        fi
    done
}

# Configure jail networking
setup_networking() {
    log_info "Setting up jail networking..."
    
    # Enable jail and networking in rc.conf
    sysrc jail_enable="YES"
    sysrc jail_list="claude_dls claude_db claude_monitor claude_tftp claude_dhcp"
    
    # Configure cloned interfaces
    sysrc cloned_interfaces="lo1"
    sysrc ifconfig_lo1="inet 10.0.1.1/24"
    
    # Create lo1 interface
    ifconfig lo1 create 2>/dev/null || true
    ifconfig lo1 inet 10.0.1.1/24
    
    log_info "Networking setup completed"
}

# Build CLAUDE DLS from source
build_claude_dls() {
    log_info "Building CLAUDE DLS from source..."
    
    # Create build directory
    BUILD_DIR="/tmp/claude_dls_build"
    rm -rf $BUILD_DIR
    mkdir -p $BUILD_DIR
    
    # Clone source code (assuming it's already present)
    if [ -f "/usr/src/claude-dls/Cargo.toml" ]; then
        cp -r /usr/src/claude-dls $BUILD_DIR/
        cd $BUILD_DIR/claude-dls
    else
        log_error "CLAUDE DLS source code not found in /usr/src/claude-dls"
    fi
    
    # Build for FreeBSD target
    cargo build --release --target x86_64-unknown-freebsd
    
    # Install binary
    mkdir -p $JAIL_ROOT/claude_dls/usr/local/bin
    cp target/x86_64-unknown-freebsd/release/claude-server $JAIL_ROOT/claude_dls/usr/local/bin/
    cp target/x86_64-unknown-freebsd/release/claude-cli $JAIL_ROOT/claude_dls/usr/local/bin/
    
    # Set permissions
    chmod +x $JAIL_ROOT/claude_dls/usr/local/bin/claude-server
    chmod +x $JAIL_ROOT/claude_dls/usr/local/bin/claude-cli
    
    log_info "CLAUDE DLS build completed"
}

# Setup PostgreSQL database
setup_database() {
    log_info "Setting up PostgreSQL database..."
    
    # Install PostgreSQL in database jail
    jexec claude_db pkg install -y postgresql14-server postgresql14-contrib
    
    # Initialize database
    jexec claude_db su -m postgres -c "initdb -D /var/db/postgres/data14 --locale=C --encoding=UTF8"
    
    # Configure PostgreSQL
    cat > $JAIL_ROOT/claude_db/var/db/postgres/data14/postgresql.conf << 'EOF'
# CLAUDE DLS Production PostgreSQL Configuration
listen_addresses = '10.0.1.11'
port = 5432
max_connections = 200
shared_buffers = 2GB
effective_cache_size = 8GB
work_mem = 16MB
maintenance_work_mem = 512MB
wal_buffers = 64MB
checkpoint_completion_target = 0.9
random_page_cost = 1.1
effective_io_concurrency = 200
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_statement = 'all'
log_duration = on
log_min_duration_statement = 1000
EOF
    
    # Configure authentication
    cat > $JAIL_ROOT/claude_db/var/db/postgres/data14/pg_hba.conf << 'EOF'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     md5
host    claude_dls_production claude_dls  10.0.1.0/24           md5
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
EOF
    
    # Enable PostgreSQL service
    jexec claude_db sysrc postgresql_enable="YES"
    
    log_info "Database setup completed"
}

# Setup monitoring services
setup_monitoring() {
    log_info "Setting up monitoring services..."
    
    # Install monitoring tools in monitoring jail
    jexec claude_monitor pkg install -y prometheus grafana9
    
    # Configure Prometheus
    mkdir -p $JAIL_ROOT/claude_monitor/usr/local/etc/prometheus
    cat > $JAIL_ROOT/claude_monitor/usr/local/etc/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'claude_dls'
    static_configs:
      - targets: ['10.0.1.10:9090']
    scrape_interval: 10s
    metrics_path: /metrics

  - job_name: 'postgres'
    static_configs:
      - targets: ['10.0.1.11:9187']
    scrape_interval: 30s

  - job_name: 'node'
    static_configs:
      - targets: ['10.0.1.10:9100']
    scrape_interval: 30s
EOF
    
    # Configure Grafana
    mkdir -p $JAIL_ROOT/claude_monitor/var/lib/grafana
    chown -R grafana:grafana $JAIL_ROOT/claude_monitor/var/lib/grafana
    
    # Enable monitoring services
    jexec claude_monitor sysrc prometheus_enable="YES"
    jexec claude_monitor sysrc grafana_enable="YES"
    
    log_info "Monitoring setup completed"
}

# Create startup scripts
create_startup_scripts() {
    log_info "Creating startup scripts..."
    
    # CLAUDE DLS startup script
    cat > $JAIL_ROOT/claude_dls/usr/local/bin/claude_dls_start.sh << 'EOF'
#!/bin/sh
cd /opt/claude_dls
export RUST_LOG=info
export CLAUDE_CONFIG_PATH=/opt/claude_dls/config
export CLAUDE_DATA_PATH=/var/lib/claude_dls
/usr/local/bin/claude-server &
echo $! > /var/run/claude_dls.pid
EOF
    
    # CLAUDE DLS stop script
    cat > $JAIL_ROOT/claude_dls/usr/local/bin/claude_dls_stop.sh << 'EOF'
#!/bin/sh
if [ -f /var/run/claude_dls.pid ]; then
    kill $(cat /var/run/claude_dls.pid)
    rm /var/run/claude_dls.pid
fi
EOF
    
    # Make scripts executable
    chmod +x $JAIL_ROOT/claude_dls/usr/local/bin/claude_dls_start.sh
    chmod +x $JAIL_ROOT/claude_dls/usr/local/bin/claude_dls_stop.sh
    
    # Monitoring startup script
    cat > $JAIL_ROOT/claude_monitor/usr/local/bin/monitoring_start.sh << 'EOF'
#!/bin/sh
/usr/local/etc/rc.d/prometheus onestart
/usr/local/etc/rc.d/grafana onestart
EOF
    
    cat > $JAIL_ROOT/claude_monitor/usr/local/bin/monitoring_stop.sh << 'EOF'
#!/bin/sh
/usr/local/etc/rc.d/grafana onestop
/usr/local/etc/rc.d/prometheus onestop
EOF
    
    chmod +x $JAIL_ROOT/claude_monitor/usr/local/bin/monitoring_start.sh
    chmod +x $JAIL_ROOT/claude_monitor/usr/local/bin/monitoring_stop.sh
    
    log_info "Startup scripts created"
}

# Copy jail configuration
install_jail_config() {
    log_info "Installing jail configuration..."
    
    # Copy jail configuration to system
    cp deployment/freebsd/jail.conf /etc/jail.conf
    
    # Enable jail service
    sysrc jail_enable="YES"
    
    log_info "Jail configuration installed"
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Start jails
    service jail start
    
    # Wait for services to start
    sleep 10
    
    # Verify services are running
    jls
    
    log_info "Services started successfully"
}

# Create deployment verification script
create_verification_script() {
    log_info "Creating deployment verification script..."
    
    cat > /usr/local/bin/claude_dls_verify.sh << 'EOF'
#!/bin/sh

echo "CLAUDE DLS Deployment Verification"
echo "================================="

# Check jail status
echo "\n1. Jail Status:"
jls

# Check ZFS datasets
echo "\n2. ZFS Datasets:"
zfs list | grep claude

# Check network connectivity
echo "\n3. Network Connectivity:"
for jail in claude_dls claude_db claude_monitor; do
    echo "  Testing $jail..."
    jexec $jail ping -c 1 10.0.1.1 >/dev/null && echo "    ✓ Network OK" || echo "    ✗ Network FAIL"
done

# Check services
echo "\n4. Service Status:"
jexec claude_dls pgrep claude-server >/dev/null && echo "  ✓ CLAUDE DLS running" || echo "  ✗ CLAUDE DLS not running"
jexec claude_db pgrep postgres >/dev/null && echo "  ✓ PostgreSQL running" || echo "  ✗ PostgreSQL not running"
jexec claude_monitor pgrep prometheus >/dev/null && echo "  ✓ Prometheus running" || echo "  ✗ Prometheus not running"

# Check web interfaces
echo "\n5. Web Interface Check:"
curl -s http://10.0.1.10:8080/health >/dev/null && echo "  ✓ CLAUDE DLS API accessible" || echo "  ✗ CLAUDE DLS API not accessible"
curl -s http://10.0.1.12:3000 >/dev/null && echo "  ✓ Grafana accessible" || echo "  ✗ Grafana not accessible"

echo "\nDeployment verification completed."
EOF
    
    chmod +x /usr/local/bin/claude_dls_verify.sh
    
    log_info "Verification script created at /usr/local/bin/claude_dls_verify.sh"
}

# Main deployment function
main() {
    log_info "Starting CLAUDE DLS FreeBSD deployment..."
    log_info "Version: $CLAUDE_VERSION"
    log_info "Target: FreeBSD $RELEASE"
    
    check_root
    check_freebsd_version
    
    install_packages
    setup_zfs
    setup_jail_base
    create_jails
    setup_networking
    build_claude_dls
    setup_database
    setup_monitoring
    create_startup_scripts
    install_jail_config
    start_services
    create_verification_script
    
    log_info "CLAUDE DLS deployment completed successfully!"
    log_info "Run 'claude_dls_verify.sh' to verify the deployment"
    log_info ""
    log_info "Access points:"
    log_info "  CLAUDE DLS API: http://10.0.1.10:8080"
    log_info "  Grafana:        http://10.0.1.12:3000"
    log_info "  Prometheus:     http://10.0.1.12:9090"
    log_info ""
    log_info "Next steps:"
    log_info "  1. Configure your network to route to 10.0.1.0/24"
    log_info "  2. Set up client PXE boot configuration"
    log_info "  3. Configure monitoring dashboards in Grafana"
    log_info "  4. Import disk images using claude-cli"
}

# Run main function
main "$@"