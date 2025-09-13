# CLAUDE DLS Deployment Makefile
# Simplified deployment management for both FreeBSD and Docker

.PHONY: help build test clean deploy-docker deploy-freebsd start stop restart logs status

# Configuration
PROJECT_NAME := claude-dls
VERSION := 0.1.0
DOCKER_REGISTRY := localhost:5000
FREEBSD_HOST := freebsd.local

# Default target
help: ## Show this help message
	@echo "CLAUDE DLS Deployment Management"
	@echo "================================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Build targets
build: ## Build the project for all targets
	@echo "Building CLAUDE DLS..."
	cargo build --release
	cargo build --release --target x86_64-unknown-freebsd

build-docker: ## Build Docker images
	@echo "Building Docker images..."
	docker-compose -f containers/docker-compose.yml build
	docker tag $(PROJECT_NAME)_claude_dls $(DOCKER_REGISTRY)/$(PROJECT_NAME):$(VERSION)

build-freebsd: ## Build for FreeBSD target
	@echo "Building for FreeBSD..."
	cargo build --release --target x86_64-unknown-freebsd
	
# Test targets
test: ## Run all tests
	@echo "Running tests..."
	cargo test

test-unit: ## Run unit tests only
	@echo "Running unit tests..."
	cargo test --lib

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	cargo test --test '*'

test-deployment-docker: ## Test Docker deployment
	@echo "Testing Docker deployment..."
	chmod +x scripts/test_deployment.sh
	./scripts/test_deployment.sh docker

test-deployment-freebsd: ## Test FreeBSD deployment
	@echo "Testing FreeBSD deployment..."
	chmod +x scripts/test_deployment.sh
	./scripts/test_deployment.sh freebsd

# Docker deployment targets
deploy-docker: build-docker ## Deploy using Docker Compose
	@echo "Deploying with Docker Compose..."
	docker-compose -f containers/docker-compose.yml up -d
	@echo "Waiting for services to be ready..."
	sleep 30
	@echo "Running deployment tests..."
	$(MAKE) test-deployment-docker

deploy-docker-dev: ## Deploy Docker development environment
	@echo "Deploying development environment..."
	RUST_LOG=debug docker-compose -f containers/docker-compose.yml -f containers/docker-compose.dev.yml up -d

stop-docker: ## Stop Docker services
	@echo "Stopping Docker services..."
	docker-compose -f containers/docker-compose.yml down

restart-docker: stop-docker deploy-docker ## Restart Docker services

logs-docker: ## Show Docker logs
	docker-compose -f containers/docker-compose.yml logs -f

status-docker: ## Show Docker service status
	docker-compose -f containers/docker-compose.yml ps

# FreeBSD deployment targets
deploy-freebsd: build-freebsd ## Deploy to FreeBSD with jails
	@echo "Deploying to FreeBSD..."
	chmod +x scripts/deploy_freebsd.sh
	scp -r ../.. $(FREEBSD_HOST):/usr/src/claude-dls
	ssh $(FREEBSD_HOST) "cd /usr/src/claude-dls/deployment && ./scripts/deploy_freebsd.sh"
	@echo "Running deployment tests..."
	ssh $(FREEBSD_HOST) "cd /usr/src/claude-dls/deployment && ./scripts/test_deployment.sh freebsd"

stop-freebsd: ## Stop FreeBSD services
	@echo "Stopping FreeBSD services..."
	ssh $(FREEBSD_HOST) "service jail stop"

restart-freebsd: ## Restart FreeBSD services
	@echo "Restarting FreeBSD services..."
	ssh $(FREEBSD_HOST) "service jail restart"

logs-freebsd: ## Show FreeBSD logs
	ssh $(FREEBSD_HOST) "tail -f /var/log/claude_dls/*.log"

status-freebsd: ## Show FreeBSD service status
	ssh $(FREEBSD_HOST) "jls && service jail status"

# Development targets
dev-setup: ## Set up development environment
	@echo "Setting up development environment..."
	cargo install cargo-watch
	rustup target add x86_64-unknown-freebsd
	rustup component add clippy rustfmt

dev-watch: ## Run development server with auto-reload
	cargo watch -x 'run --bin claude-server'

dev-test-watch: ## Run tests with auto-reload
	cargo watch -x test

# Production targets
prod-deploy: ## Deploy to production (requires configuration)
	@echo "Deploying to production..."
	@echo "Please ensure production configuration is set up"
	@read -p "Deploy to production? [y/N]: " confirm; \
	if [ "$$confirm" = "y" ] || [ "$$confirm" = "Y" ]; then \
		$(MAKE) deploy-docker; \
	else \
		echo "Production deployment cancelled"; \
	fi

# Maintenance targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	docker system prune -f

backup: ## Create backup of deployment
	@echo "Creating backup..."
	mkdir -p backups
	tar -czf backups/claude-dls-backup-$(shell date +%Y%m%d-%H%M%S).tar.gz \
		--exclude=target \
		--exclude=backups \
		--exclude=.git \
		../..

restore: ## Restore from backup (specify BACKUP_FILE)
	@echo "Restoring from backup..."
	@if [ -z "$(BACKUP_FILE)" ]; then \
		echo "Please specify BACKUP_FILE=path/to/backup.tar.gz"; \
		exit 1; \
	fi
	tar -xzf $(BACKUP_FILE) -C /tmp/
	@echo "Backup restored to /tmp/. Please verify and move to desired location."

# Monitoring targets
monitor: ## Open monitoring dashboard
	@echo "Opening monitoring dashboard..."
	@command -v open >/dev/null 2>&1 && open http://localhost:3000 || echo "Please open http://localhost:3000 manually"

metrics: ## Show current metrics
	@echo "Current metrics:"
	curl -s http://localhost:8080/metrics | grep claude_dls_ | head -20

health: ## Check system health
	@echo "Checking system health..."
	curl -s http://localhost:8080/health | jq '.'

# Security targets
security-scan: ## Run security scan
	@echo "Running security scan..."
	cargo audit
	docker scout cves $(PROJECT_NAME)_claude_dls

update-deps: ## Update dependencies
	@echo "Updating dependencies..."
	cargo update
	cargo audit fix

# Documentation targets
docs: ## Generate documentation
	@echo "Generating documentation..."
	cargo doc --open

docs-deploy: docs ## Deploy documentation
	@echo "Deploying documentation..."
	# Add documentation deployment logic here

# Utility targets
shell-docker: ## Open shell in Docker container
	docker exec -it claude_dls_server /bin/sh

shell-freebsd: ## Open shell in FreeBSD jail
	ssh $(FREEBSD_HOST) "jexec claude_dls /bin/sh"

port-forward: ## Set up port forwarding for local development
	@echo "Setting up port forwarding..."
	@echo "CLAUDE DLS API: http://localhost:8080"
	@echo "Grafana:        http://localhost:3000"
	@echo "Prometheus:     http://localhost:9091"

# Configuration targets
config-validate: ## Validate configuration files
	@echo "Validating configuration files..."
	@for config in configs/*.toml; do \
		echo "Validating $$config..."; \
		cargo run --bin claude-cli -- config validate "$$config"; \
	done

config-example: ## Generate example configuration
	cargo run --bin claude-cli -- config example > configs/example.toml

# Release targets
release-build: ## Build release version
	@echo "Building release version..."
	cargo build --release --target x86_64-unknown-freebsd
	cargo build --release
	strip target/release/claude-server
	strip target/release/claude-cli

release-package: release-build ## Package release for distribution
	@echo "Packaging release..."
	mkdir -p dist
	tar -czf dist/claude-dls-$(VERSION)-freebsd.tar.gz \
		target/x86_64-unknown-freebsd/release/claude-server \
		target/x86_64-unknown-freebsd/release/claude-cli \
		configs/ \
		deployment/scripts/deploy_freebsd.sh \
		README.md
	tar -czf dist/claude-dls-$(VERSION)-linux.tar.gz \
		target/release/claude-server \
		target/release/claude-cli \
		configs/ \
		deployment/containers/ \
		README.md

# Environment variables
.env: ## Create example environment file
	@echo "Creating example .env file..."
	@cat > .env << 'EOF'
# CLAUDE DLS Environment Configuration
POSTGRES_PASSWORD=secure_password_change_me
JWT_SECRET=your_jwt_secret_key_change_me
GRAFANA_PASSWORD=admin123
GRAFANA_SECRET=change_me_secret_key
RUST_LOG=info
EOF
	@echo "Created .env file. Please review and update the values."

# Quick start targets
quick-start: build deploy-docker ## Quick start with Docker
	@echo "CLAUDE DLS is starting up..."
	@echo "This will take about 30 seconds..."
	@sleep 30
	@echo ""
	@echo "🎉 CLAUDE DLS is ready!"
	@echo ""
	@echo "Access points:"
	@echo "  Web UI:         http://localhost:8080"
	@echo "  Grafana:        http://localhost:3000 (admin/admin123)"
	@echo "  Prometheus:     http://localhost:9091"
	@echo "  API Docs:       http://localhost:8080/api/docs"
	@echo ""
	@echo "Run 'make test-deployment-docker' to verify everything is working"

quick-test: ## Quick deployment test
	@echo "Running quick deployment test..."
	$(MAKE) test-deployment-docker

# Default environment setup
ifndef FREEBSD_HOST
FREEBSD_HOST := localhost
endif

# Include custom configuration if available
-include Makefile.local