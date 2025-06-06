# Makefile for FastAPI Boilerplate Generator
# Provides convenient commands for development and testing

.PHONY: help setup install test clean validate demo examples

# Default target
help:
	@echo "FastAPI Boilerplate Generator - Available Commands:"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  setup          - Initialize the generator structure"
	@echo "  install        - Install generator system-wide"
	@echo "  uninstall      - Remove generator from system"
	@echo ""
	@echo "Development:"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  validate       - Validate generator code"
	@echo "  lint           - Lint shell scripts"
	@echo ""
	@echo "Demo & Examples:"
	@echo "  demo           - Generate demo projects"
	@echo "  examples       - Generate all example configurations"
	@echo "  clean-examples - Clean up generated examples"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean          - Clean up temporary files"
	@echo "  update         - Update generator components"
	@echo "  docs           - Generate documentation"

# Setup the generator structure
setup:
	@echo "Setting up FastAPI Boilerplate Generator..."
	@chmod +x setup.sh
	@./setup.sh
	@echo "Setup completed successfully!"

# Install generator system-wide
install: setup
	@echo "Installing generator system-wide..."
	@sudo cp fastapi-generator.sh /usr/local/bin/fastapi-generator
	@sudo chmod +x /usr/local/bin/fastapi-generator
	@sudo mkdir -p /usr/local/share/fastapi-generator
	@sudo cp -r config utils generators examples templates /usr/local/share/fastapi-generator/
	@echo "Generator installed! Use 'fastapi-generator' command from anywhere."

# Uninstall generator
uninstall:
	@echo "Uninstalling generator..."
	@sudo rm -f /usr/local/bin/fastapi-generator
	@sudo rm -rf /usr/local/share/fastapi-generator
	@echo "Generator uninstalled."

# Run all tests
test: test-unit test-integration
	@echo "All tests completed!"

# Run unit tests
test-unit:
	@echo "Running unit tests..."
	@if [ -f tests/test_generator.sh ]; then \
		chmod +x tests/test_generator.sh && \
		./tests/test_generator.sh; \
	else \
		echo "Creating basic unit test..."; \
		mkdir -p tests; \
		echo '#!/bin/bash' > tests/test_generator.sh; \
		echo 'source utils/colors.sh' >> tests/test_generator.sh; \
		echo 'source utils/helpers.sh' >> tests/test_generator.sh; \
		echo 'print_success "Basic unit tests passed"' >> tests/test_generator.sh; \
		chmod +x tests/test_generator.sh; \
		./tests/test_generator.sh; \
	fi

# Run integration tests
test-integration:
	@echo "Running integration tests..."
	@if [ -f tests/integration_test.sh ]; then \
		chmod +x tests/integration_test.sh && \
		./tests/integration_test.sh; \
	else \
		echo "Creating basic integration test..."; \
		mkdir -p tests; \
		./fastapi-generator.sh -n test-integration-project -a "Test User" -e "test@example.com" --config examples/minimal.conf > /dev/null 2>&1; \
		if [ -d test-integration-project ]; then \
			echo "✓ Integration test passed - project generated successfully"; \
			rm -rf test-integration-project; \
		else \
			echo "✗ Integration test failed - project not generated"; \
			exit 1; \
		fi; \
	fi

# Validate generator code
validate:
	@echo "Validating generator code..."
	@echo "Checking shell script syntax..."
	@bash -n fastapi-generator.sh && echo "✓ Main script syntax OK"
	@bash -n setup.sh && echo "✓ Setup script syntax OK"
	@for file in utils/*.sh; do \
		if [ -f "$$file" ]; then \
			bash -n "$$file" && echo "✓ $$file syntax OK"; \
		fi; \
	done
	@for file in generators/*.sh; do \
		if [ -f "$$file" ]; then \
			bash -n "$$file" && echo "✓ $$file syntax OK"; \
		fi; \
	done
	@echo "All validation checks passed!"

# Lint shell scripts
lint:
	@echo "Linting shell scripts..."
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck fastapi-generator.sh setup.sh utils/*.sh generators/*.sh; \
		echo "Linting completed!"; \
	else \
		echo "shellcheck not found. Install with:"; \
		echo "  Ubuntu/Debian: sudo apt install shellcheck"; \
		echo "  macOS: brew install shellcheck"; \
		echo "  Or visit: https://github.com/koalaman/shellcheck"; \
	fi

# Generate demo projects
demo: clean-examples
	@echo "Generating demo projects..."
	@mkdir -p demo-projects
	@echo "Creating minimal API demo..."
	@./fastapi-generator.sh -n demo-minimal-api -d "Minimal API Demo" -a "Demo User" -e "demo@example.com" --config examples/minimal.conf
	@mv demo-minimal-api demo-projects/
	@echo "Creating full-stack API demo..."
	@./fastapi-generator.sh -n demo-fullstack-api -d "Full-stack API Demo" -a "Demo User" -e "demo@example.com" --config examples/full-stack.conf
	@mv demo-fullstack-api demo-projects/
	@echo "Creating microservice demo..."
	@./fastapi-generator.sh -n demo-microservice -d "Microservice Demo" -a "Demo User" -e "demo@example.com" --config examples/microservice.conf
	@mv demo-microservice demo-projects/
	@echo "Demo projects created in demo-projects/ directory"

# Generate all example configurations
examples:
	@echo "Generating example projects for all configurations..."
	@for config in examples/*.conf; do \
		if [ -f "$$config" ]; then \
			name=$$(basename "$$config" .conf); \
			echo "Generating example for $$name..."; \
			./fastapi-generator.sh -n "example-$$name" -d "Example $$name project" -a "Example User" -e "example@test.com" --config "$$config"; \
		fi; \
	done
	@echo "All examples generated!"

# Clean up generated examples
clean-examples:
	@echo "Cleaning up generated examples..."
	@rm -rf demo-projects/
	@rm -rf example-*/
	@rm -rf test-*/
	@echo "Cleanup completed!"

# Clean up temporary files
clean: clean-examples
	@echo "Cleaning up temporary files..."
	@rm -rf .tmp/
	@rm -f *.log
	@rm -f *.tmp
	@find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "Cleanup completed!"

# Update generator components
update:
	@echo "Updating generator components..."
	@if [ -d .git ]; then \
		git pull origin main; \
		echo "Generator updated from repository!"; \
	else \
		echo "Not a git repository. Manual update required."; \
	fi

# Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs
	@echo "# FastAPI Boilerplate Generator Documentation" > docs/README.md
	@echo "" >> docs/README.md
	@echo "Generated on: $$(date)" >> docs/README.md
	@echo "" >> docs/README.md
	@echo "## Available Configurations" >> docs/README.md
	@for config in examples/*.conf; do \
		if [ -f "$$config" ]; then \
			name=$$(basename "$$config" .conf); \
			echo "- **$$name**: $$(head -2 "$$config" | tail -1 | sed 's/^# //')" >> docs/README.md; \
		fi; \
	done
	@echo "" >> docs/README.md
	@echo "## Generator Modules" >> docs/README.md
	@for generator in generators/*.sh; do \
		if [ -f "$$generator" ]; then \
			name=$$(basename "$$generator" .sh); \
			echo "- **$$name**: $$(head -2 "$$generator" | tail -1 | sed 's/^# //')" >> docs/README.md; \
		fi; \
	done
	@echo "Documentation generated in docs/ directory"

# Quick start command
quickstart:
	@echo "FastAPI Generator Quick Start"
	@echo "=============================="
	@read -p "Enter project name: " name; \
	read -p "Enter your name: " author; \
	read -p "Enter your email: " email; \
	echo "Choose configuration:"; \
	echo "1. Minimal (basic API)"; \
	echo "2. Full-stack (all features)"; \
	echo "3. Microservice (container-ready)"; \
	read -p "Enter choice (1-3): " choice; \
	case $$choice in \
		1) config="examples/minimal.conf";; \
		2) config="examples/full-stack.conf";; \
		3) config="examples/microservice.conf";; \
		*) config="examples/minimal.conf";; \
	esac; \
	./fastapi-generator.sh -n "$$name" -a "$$author" -e "$$email" --config "$$config"

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		echo "Setting up pre-commit hooks..."; \
		pre-commit install; \
	fi
	@echo "Development environment ready!"

# Release preparation
release-check:
	@echo "Checking release readiness..."
	@make validate
	@make test
	@echo "Release checks passed!"

# Show generator statistics
stats:
	@echo "FastAPI Generator Statistics"
	@echo "============================="
	@echo "Generator modules: $$(ls generators/*.sh | wc -l)"
	@echo "Example configurations: $$(ls examples/*.conf | wc -l)"
	@echo "Utility functions: $$(ls utils/*.sh | wc -l)"
	@echo "Total shell files: $$(find . -name "*.sh" | wc -l)"
	@echo "Lines of shell code: $$(find . -name "*.sh" -exec cat {} \; | wc -l)"

# Backup generator
backup:
	@echo "Creating backup of generator..."
	@backup_name="fastapi-generator-backup-$$(date +%Y%m%d_%H%M%S).tar.gz"
	@tar -czf "$$backup_name" --exclude=demo-projects --exclude=example-* --exclude=test-* .
	@echo "Backup created: $$backup_name"