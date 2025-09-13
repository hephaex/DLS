#!/bin/bash

# CLAUDE DLS Deployment Testing Script
# Comprehensive testing for both FreeBSD and Docker deployments

set -e

# Configuration
CLAUDE_API_URL="http://localhost:8080"
GRAFANA_URL="http://localhost:3000"
PROMETHEUS_URL="http://localhost:9091"
TEST_RESULTS_DIR="./test_results"
DEPLOYMENT_TYPE="${1:-docker}"  # docker or freebsd

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Initialize test environment
init_test_env() {
    log_info "Initializing test environment..."
    
    # Create results directory
    mkdir -p $TEST_RESULTS_DIR
    
    # Clear previous results
    rm -f $TEST_RESULTS_DIR/*
    
    # Set test start time
    TEST_START_TIME=$(date +%s)
    
    log_info "Test environment initialized"
}

# Test function wrapper
run_test() {
    local test_name="$1"
    local test_function="$2"
    
    ((TESTS_TOTAL++))
    log_info "Running test: $test_name"
    
    if $test_function; then
        log_success "$test_name"
        echo "PASS" > "$TEST_RESULTS_DIR/${test_name// /_}.result"
    else
        log_error "$test_name"
        echo "FAIL" > "$TEST_RESULTS_DIR/${test_name// /_}.result"
    fi
}

# API Health Check
test_api_health() {
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$CLAUDE_API_URL/health" || echo "000")
    
    if [ "$response" = "200" ]; then
        return 0
    else
        echo "Expected 200, got $response" >&2
        return 1
    fi
}

# Database Connectivity Test
test_database_connectivity() {
    local response=$(curl -s "$CLAUDE_API_URL/api/v1/status" | jq -r '.database.status' 2>/dev/null || echo "error")
    
    if [ "$response" = "connected" ]; then
        return 0
    else
        echo "Database not connected: $response" >&2
        return 1
    fi
}

# Authentication Test
test_authentication() {
    # Test login endpoint
    local login_response=$(curl -s -X POST "$CLAUDE_API_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"admin","password":"admin123"}' | jq -r '.token' 2>/dev/null || echo "error")
    
    if [ "$login_response" != "error" ] && [ "$login_response" != "null" ]; then
        # Test authenticated endpoint
        local auth_test=$(curl -s -o /dev/null -w "%{http_code}" "$CLAUDE_API_URL/api/v1/users" \
            -H "Authorization: Bearer $login_response" || echo "000")
        
        if [ "$auth_test" = "200" ]; then
            return 0
        else
            echo "Authenticated request failed: $auth_test" >&2
            return 1
        fi
    else
        echo "Login failed: $login_response" >&2
        return 1
    fi
}

# Storage System Test
test_storage_system() {
    local response=$(curl -s "$CLAUDE_API_URL/api/v1/storage/status" | jq -r '.status' 2>/dev/null || echo "error")
    
    if [ "$response" = "available" ]; then
        return 0
    else
        echo "Storage system not available: $response" >&2
        return 1
    fi
}

# Metrics Endpoint Test
test_metrics_endpoint() {
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$CLAUDE_API_URL/metrics" || echo "000")
    
    if [ "$response" = "200" ]; then
        # Check if metrics contain expected data
        local metrics=$(curl -s "$CLAUDE_API_URL/metrics" | grep -c "claude_dls_" || echo "0")
        
        if [ "$metrics" -gt "0" ]; then
            return 0
        else
            echo "No CLAUDE DLS metrics found" >&2
            return 1
        fi
    else
        echo "Metrics endpoint not accessible: $response" >&2
        return 1
    fi
}

# Prometheus Integration Test
test_prometheus_integration() {
    if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$PROMETHEUS_URL/api/v1/targets" || echo "000")
        
        if [ "$response" = "200" ]; then
            # Check if CLAUDE DLS target is being scraped
            local targets=$(curl -s "$PROMETHEUS_URL/api/v1/targets" | jq -r '.data.activeTargets[] | select(.labels.job=="claude_dls") | .health' 2>/dev/null || echo "error")
            
            if [ "$targets" = "up" ]; then
                return 0
            else
                echo "CLAUDE DLS target not healthy in Prometheus: $targets" >&2
                return 1
            fi
        else
            echo "Prometheus not accessible: $response" >&2
            return 1
        fi
    else
        log_warn "Prometheus integration test skipped for FreeBSD deployment"
        return 0
    fi
}

# Grafana Dashboard Test
test_grafana_dashboard() {
    if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
        local response=$(curl -s -o /dev/null -w "%{http_code}" "$GRAFANA_URL/api/health" || echo "000")
        
        if [ "$response" = "200" ]; then
            return 0
        else
            echo "Grafana not accessible: $response" >&2
            return 1
        fi
    else
        log_warn "Grafana dashboard test skipped for FreeBSD deployment"
        return 0
    fi
}

# Network Services Test
test_network_services() {
    # Test DHCP service (if enabled)
    if netstat -ln | grep -q ":67 "; then
        log_info "DHCP service is listening"
    else
        echo "DHCP service not listening on port 67" >&2
        return 1
    fi
    
    # Test TFTP service (if enabled)
    if netstat -ln | grep -q ":69 "; then
        log_info "TFTP service is listening"
    else
        echo "TFTP service not listening on port 69" >&2
        return 1
    fi
    
    # Test iSCSI service (if enabled)
    if netstat -ln | grep -q ":3260 "; then
        log_info "iSCSI service is listening"
        return 0
    else
        echo "iSCSI service not listening on port 3260" >&2
        return 1
    fi
}

# Container Health Test (Docker only)
test_container_health() {
    if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
        local unhealthy_containers=$(docker-compose ps --filter "health=unhealthy" -q | wc -l)
        
        if [ "$unhealthy_containers" -eq "0" ]; then
            return 0
        else
            echo "$unhealthy_containers containers are unhealthy" >&2
            docker-compose ps --filter "health=unhealthy" >&2
            return 1
        fi
    else
        return 0
    fi
}

# Jail Status Test (FreeBSD only)
test_jail_status() {
    if [ "$DEPLOYMENT_TYPE" = "freebsd" ]; then
        if command -v jls >/dev/null 2>&1; then
            local running_jails=$(jls -h | wc -l)
            
            if [ "$running_jails" -gt "1" ]; then  # Header line + actual jails
                return 0
            else
                echo "No jails are running" >&2
                return 1
            fi
        else
            echo "jls command not available (not on FreeBSD?)" >&2
            return 1
        fi
    else
        return 0
    fi
}

# Performance Test
test_performance() {
    log_info "Running performance tests..."
    
    # Test API response time
    local start_time=$(date +%s%N)
    curl -s "$CLAUDE_API_URL/health" >/dev/null
    local end_time=$(date +%s%N)
    local response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    
    echo "API response time: ${response_time}ms" > "$TEST_RESULTS_DIR/performance.log"
    
    if [ "$response_time" -lt "1000" ]; then  # Less than 1 second
        return 0
    else
        echo "API response time too slow: ${response_time}ms" >&2
        return 1
    fi
}

# Load Test
test_load() {
    log_info "Running load test..."
    
    # Simple load test with 10 concurrent requests
    for i in {1..10}; do
        curl -s "$CLAUDE_API_URL/health" >/dev/null &
    done
    
    wait
    
    # Check if service is still responsive
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$CLAUDE_API_URL/health" || echo "000")
    
    if [ "$response" = "200" ]; then
        return 0
    else
        echo "Service not responsive after load test: $response" >&2
        return 1
    fi
}

# Security Test
test_security() {
    # Test unauthenticated access to protected endpoints
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$CLAUDE_API_URL/api/v1/users" || echo "000")
    
    if [ "$response" = "401" ] || [ "$response" = "403" ]; then
        return 0
    else
        echo "Protected endpoint accessible without authentication: $response" >&2
        return 1
    fi
}

# Monitoring Data Test
test_monitoring_data() {
    # Check if metrics are being updated
    local metrics_before=$(curl -s "$CLAUDE_API_URL/metrics" | grep "claude_dls_uptime_seconds" | awk '{print $2}')
    
    sleep 2
    
    local metrics_after=$(curl -s "$CLAUDE_API_URL/metrics" | grep "claude_dls_uptime_seconds" | awk '{print $2}')
    
    if [ "$metrics_after" != "$metrics_before" ]; then
        return 0
    else
        echo "Metrics not being updated" >&2
        return 1
    fi
}

# Configuration Test
test_configuration() {
    local config_response=$(curl -s "$CLAUDE_API_URL/api/v1/config" | jq -r '.version' 2>/dev/null || echo "error")
    
    if [ "$config_response" != "error" ] && [ "$config_response" != "null" ]; then
        return 0
    else
        echo "Configuration endpoint not accessible: $config_response" >&2
        return 1
    fi
}

# Backup System Test
test_backup_system() {
    if [ "$DEPLOYMENT_TYPE" = "docker" ]; then
        # Check if backup service is configured
        if docker-compose ps backup | grep -q "Up"; then
            return 0
        else
            echo "Backup service not running" >&2
            return 1
        fi
    else
        # Check if backup scripts exist
        if [ -f "/usr/local/bin/claude_dls_backup.sh" ]; then
            return 0
        else
            echo "Backup script not found" >&2
            return 1
        fi
    fi
}

# Generate test report
generate_report() {
    local test_end_time=$(date +%s)
    local test_duration=$((test_end_time - TEST_START_TIME))
    
    echo "# CLAUDE DLS Deployment Test Report" > "$TEST_RESULTS_DIR/report.md"
    echo "Generated: $(date)" >> "$TEST_RESULTS_DIR/report.md"
    echo "Deployment Type: $DEPLOYMENT_TYPE" >> "$TEST_RESULTS_DIR/report.md"
    echo "Test Duration: ${test_duration}s" >> "$TEST_RESULTS_DIR/report.md"
    echo "" >> "$TEST_RESULTS_DIR/report.md"
    
    echo "## Summary" >> "$TEST_RESULTS_DIR/report.md"
    echo "- Total Tests: $TESTS_TOTAL" >> "$TEST_RESULTS_DIR/report.md"
    echo "- Passed: $TESTS_PASSED" >> "$TEST_RESULTS_DIR/report.md"
    echo "- Failed: $TESTS_FAILED" >> "$TEST_RESULTS_DIR/report.md"
    echo "- Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%" >> "$TEST_RESULTS_DIR/report.md"
    echo "" >> "$TEST_RESULTS_DIR/report.md"
    
    echo "## Detailed Results" >> "$TEST_RESULTS_DIR/report.md"
    for result_file in "$TEST_RESULTS_DIR"/*.result; do
        if [ -f "$result_file" ]; then
            local test_name=$(basename "$result_file" .result | tr '_' ' ')
            local result=$(cat "$result_file")
            if [ "$result" = "PASS" ]; then
                echo "- ✅ $test_name" >> "$TEST_RESULTS_DIR/report.md"
            else
                echo "- ❌ $test_name" >> "$TEST_RESULTS_DIR/report.md"
            fi
        fi
    done
    
    echo "" >> "$TEST_RESULTS_DIR/report.md"
    echo "## Performance Metrics" >> "$TEST_RESULTS_DIR/report.md"
    if [ -f "$TEST_RESULTS_DIR/performance.log" ]; then
        cat "$TEST_RESULTS_DIR/performance.log" >> "$TEST_RESULTS_DIR/report.md"
    fi
    
    log_info "Test report generated: $TEST_RESULTS_DIR/report.md"
}

# Main test execution
main() {
    log_info "Starting CLAUDE DLS deployment tests..."
    log_info "Deployment type: $DEPLOYMENT_TYPE"
    
    init_test_env
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 10
    
    # Core functionality tests
    run_test "API Health Check" test_api_health
    run_test "Database Connectivity" test_database_connectivity
    run_test "Authentication System" test_authentication
    run_test "Storage System" test_storage_system
    run_test "Metrics Endpoint" test_metrics_endpoint
    run_test "Prometheus Integration" test_prometheus_integration
    run_test "Grafana Dashboard" test_grafana_dashboard
    run_test "Network Services" test_network_services
    
    # Platform-specific tests
    run_test "Container Health" test_container_health
    run_test "Jail Status" test_jail_status
    
    # Performance and security tests
    run_test "Performance Test" test_performance
    run_test "Load Test" test_load
    run_test "Security Test" test_security
    run_test "Monitoring Data" test_monitoring_data
    run_test "Configuration" test_configuration
    run_test "Backup System" test_backup_system
    
    # Generate final report
    generate_report
    
    # Summary
    echo ""
    log_info "================================"
    log_info "Test Summary:"
    log_info "Total Tests: $TESTS_TOTAL"
    log_success "Passed: $TESTS_PASSED"
    log_error "Failed: $TESTS_FAILED"
    log_info "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%"
    log_info "================================"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        log_success "All tests passed! Deployment is ready for production."
        exit 0
    else
        log_error "Some tests failed. Please review the issues before proceeding to production."
        exit 1
    fi
}

# Usage information
usage() {
    echo "Usage: $0 [deployment_type]"
    echo "  deployment_type: docker (default) or freebsd"
    echo ""
    echo "Examples:"
    echo "  $0 docker    # Test Docker deployment"
    echo "  $0 freebsd   # Test FreeBSD jail deployment"
}

# Check arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

# Run main function
main "$@"