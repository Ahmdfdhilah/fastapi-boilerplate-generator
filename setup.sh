#!/bin/bash

# Setup script for FastAPI Boilerplate Generator
# This script creates the modular directory structure

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create directory structure
create_generator_structure() {
    print_status "Creating FastAPI Boilerplate Generator structure..."
    
    # Create directories
    mkdir -p {config,utils,generators,examples,templates}
    
    # Create main files (these would be created by the artifacts above)
    print_status "Generator structure created successfully!"
    print_status "Directory structure:"
    echo "├── fastapi-generator.sh     # Main generator script"
    echo "├── setup.sh                 # This setup script"
    echo "├── config/"
    echo "│   ├── default.conf         # Default configuration"
    echo "│   └── custom.conf.example  # Example custom config"
    echo "├── utils/"
    echo "│   ├── colors.sh            # Color utilities"
    echo "│   └── helpers.sh           # Helper functions"
    echo "├── generators/"
    echo "│   ├── core.sh              # Core file generators"
    echo "│   ├── auth.sh              # Authentication generators"
    echo "│   ├── models.sh            # Model generators"
    echo "│   ├── api.sh               # API endpoint generators"
    echo "│   ├── middleware.sh        # Middleware generators"
    echo "│   ├── utils.sh             # Utility generators"
    echo "│   ├── tests.sh             # Test generators"
    echo "│   ├── docker.sh            # Docker generators"
    echo "│   └── docs.sh              # Documentation generators"
    echo "├── examples/"
    echo "│   ├── minimal.conf         # Minimal configuration"
    echo "│   ├── full-stack.conf      # Full-stack configuration"
    echo "│   └── microservice.conf    # Microservice configuration"
    echo "└── templates/"
    echo "    └── custom/              # Custom template directory"
}

# Create example configuration files
create_example_configs() {
    print_status "Creating example configuration files..."
    
    # Create custom config example
    cat > config/custom.conf.example << 'EOF'
# Custom configuration example
# Copy this file to custom.conf and modify as needed

# Override default project settings
DEFAULT_PROJECT_NAME="my-custom-api"
DEFAULT_PROJECT_DESCRIPTION="Custom FastAPI service with advanced features"

# Enable additional features
INCLUDE_RATE_LIMITING=true
INCLUDE_CELERY=true
INCLUDE_WEBSOCKETS=true

# Custom dependencies
ADDITIONAL_REQUIREMENTS=(
    "slowapi==0.1.7"          # Rate limiting
    "celery==5.3.1"           # Background tasks
    "websockets==11.0.3"      # WebSocket support
    "prometheus-client==0.17.1" # Metrics
)

# Custom directories
CUSTOM_DIRECTORIES=(
    "src/tasks"               # Celery tasks
    "src/websockets"          # WebSocket handlers
    "src/metrics"             # Prometheus metrics
    "monitoring"              # Monitoring configs
)

# Database settings
DEFAULT_DB_TYPE="postgresql"  # or "mysql", "sqlite"
INCLUDE_REDIS=true

# Advanced features
INCLUDE_MONITORING=true
INCLUDE_SWAGGER_UI=true
INCLUDE_ADMIN_PANEL=false
EOF

    # Create minimal config
    cat > examples/minimal.conf << 'EOF'
# Minimal FastAPI configuration
# For simple APIs without complex features

DEFAULT_PROJECT_NAME="simple-api"
DEFAULT_PROJECT_DESCRIPTION="Simple FastAPI service"

# Disable optional features
INCLUDE_REDIS=false
INCLUDE_MIDDLEWARE=false
INCLUDE_TESTS=false
INCLUDE_RATE_LIMITING=false
INCLUDE_CELERY=false
INCLUDE_WEBSOCKETS=false

# Minimal dependencies
ADDITIONAL_REQUIREMENTS=()
CUSTOM_DIRECTORIES=()

USE_DOCKER=false
EOF

    # Create full-stack config
    cat > examples/full-stack.conf << 'EOF'
# Full-stack FastAPI configuration
# Includes all features and integrations

DEFAULT_PROJECT_NAME="fullstack-api"
DEFAULT_PROJECT_DESCRIPTION="Full-stack FastAPI service with all features"

# Enable all features
INCLUDE_AUTH=true
INCLUDE_USER_MANAGEMENT=true
INCLUDE_MIDDLEWARE=true
INCLUDE_LOGGING=true
INCLUDE_TESTS=true
INCLUDE_ALEMBIC=true
INCLUDE_RATE_LIMITING=true
INCLUDE_CELERY=true
INCLUDE_WEBSOCKETS=true
INCLUDE_REDIS=true

# Full-stack dependencies
ADDITIONAL_REQUIREMENTS=(
    "slowapi==0.1.7"
    "celery==5.3.1"
    "websockets==11.0.3"
    "prometheus-client==0.17.1"
    "elasticsearch==8.9.0"
    "boto3==1.28.25"
    "pillow==10.0.0"
    "python-magic==0.4.27"
)

# Additional directories
CUSTOM_DIRECTORIES=(
    "src/tasks"
    "src/websockets"
    "src/metrics"
    "src/storage"
    "src/search"
    "monitoring"
    "static"
    "media"
)

USE_DOCKER=true
EOF

    # Create microservice config
    cat > examples/microservice.conf << 'EOF'
# Microservice configuration
# Optimized for containerized microservices

DEFAULT_PROJECT_NAME="user-service"
DEFAULT_PROJECT_DESCRIPTION="User management microservice"

# Microservice features
INCLUDE_AUTH=true
INCLUDE_USER_MANAGEMENT=true
INCLUDE_MIDDLEWARE=true
INCLUDE_LOGGING=true
INCLUDE_TESTS=true
INCLUDE_RATE_LIMITING=true
INCLUDE_REDIS=true

# Microservice-specific dependencies
ADDITIONAL_REQUIREMENTS=(
    "slowapi==0.1.7"
    "prometheus-client==0.17.1"
    "opentelemetry-api==1.19.0"
    "opentelemetry-sdk==1.19.0"
    "jaeger-client==4.8.0"
)

# Microservice directories
CUSTOM_DIRECTORIES=(
    "src/metrics"
    "src/tracing"
    "src/health"
    "monitoring"
)

USE_DOCKER=true

# Service mesh integration
INCLUDE_HEALTH_CHECKS=true
INCLUDE_METRICS=true
INCLUDE_TRACING=true
EOF
}

# Make scripts executable
make_executable() {
    print_status "Making scripts executable..."
    
    # List of scripts that should be executable
    local scripts=(
        "fastapi-generator.sh"
        "setup.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [[ -f "$script" ]]; then
            chmod +x "$script"
            print_success "Made $script executable"
        else
            print_warning "$script not found, skipping..."
        fi
    done
}

# Create README for the generator itself
create_generator_readme() {
    cat > README.md << 'EOF'
# FastAPI Boilerplate Generator

A modular, customizable FastAPI boilerplate generator that creates production-ready FastAPI applications with JWT authentication, database integration, and modern Python patterns.

## Features

- **Modular Architecture**: Easily customizable generator components
- **Multiple Configurations**: Pre-built configs for different use cases
- **Docker Support**: Optional containerization with docker-compose
- **Production Ready**: Includes logging, error handling, and security best practices
- **Async/Await**: Modern async Python patterns throughout
- **Type Safety**: Full type hints and Pydantic validation
- **Testing**: Comprehensive test setup with pytest
- **Database Migrations**: Alembic integration for schema management

## Quick Start

```bash
# Clone or download the generator
git clone <repository-url>
cd fastapi-boilerplate-generator

# Run setup (creates directory structure)
./setup.sh

# Generate a new FastAPI project
./fastapi-generator.sh -n my-api --docker

# Or use interactive mode
./fastapi-generator.sh
```

## Usage

### Command Line Options

```bash
./fastapi-generator.sh [OPTIONS]

Options:
  -n, --name NAME           Project name
  -d, --description DESC    Project description  
  -a, --author AUTHOR       Author name
  -e, --email EMAIL         Author email
  --docker                  Include Docker configuration
  --no-docker               Skip Docker configuration (default)
  --config FILE             Use custom configuration file
  -h, --help                Show help message
```

### Examples

```bash
# Basic project
./fastapi-generator.sh -n my-api -a "John Doe" -e john@example.com

# With Docker
./fastapi-generator.sh -n my-api --docker

# Using custom configuration
./fastapi-generator.sh --config examples/full-stack.conf

# Minimal project
./fastapi-generator.sh --config examples/minimal.conf -n simple-api
```

## Configuration

### Pre-built Configurations

- **`examples/minimal.conf`**: Simple API without complex features
- **`examples/full-stack.conf`**: Full-featured application with all integrations
- **`examples/microservice.conf`**: Optimized for containerized microservices

### Custom Configuration

1. Copy the example configuration:
   ```bash
   cp config/custom.conf.example config/my-custom.conf
   ```

2. Modify the configuration:
   ```bash
   # Enable additional features
   INCLUDE_RATE_LIMITING=true
   INCLUDE_CELERY=true
   
   # Add custom dependencies
   ADDITIONAL_REQUIREMENTS=(
       "slowapi==0.1.7"
       "celery==5.3.1"
   )
   ```

3. Use your custom configuration:
   ```bash
   ./fastapi-generator.sh --config config/my-custom.conf
   ```

## Generator Structure

```
fastapi-boilerplate-generator/
├── fastapi-generator.sh     # Main generator script
├── setup.sh                 # Setup script
├── config/
│   ├── default.conf         # Default configuration
│   └── custom.conf.example  # Example custom config
├── utils/
│   ├── colors.sh            # Color utilities
│   └── helpers.sh           # Helper functions
├── generators/
│   ├── core.sh              # Core file generators
│   ├── auth.sh              # Authentication generators
│   ├── models.sh            # Model generators
│   ├── api.sh               # API endpoint generators
│   ├── middleware.sh        # Middleware generators
│   ├── utils.sh             # Utility generators
│   ├── tests.sh             # Test generators
│   ├── docker.sh            # Docker generators
│   └── docs.sh              # Documentation generators
└── examples/
    ├── minimal.conf         # Minimal configuration
    ├── full-stack.conf      # Full-stack configuration
    └── microservice.conf    # Microservice configuration
```

## Customization

### Adding New Features

1. **Create a new generator**: Add a new file in `generators/` directory
2. **Update main script**: Source your new generator in `fastapi-generator.sh`
3. **Add configuration options**: Update `config/default.conf` with new settings
4. **Test your changes**: Run the generator with different configurations

### Example: Adding Monitoring

```bash
# generators/monitoring.sh
generate_prometheus_config() {
    cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'fastapi-app'
    static_configs:
      - targets: ['app:8000']
EOF
}
```

## Generated Project Structure

The generator creates a well-organized FastAPI project:

```
my-api/
├── src/
│   ├── api/endpoints/       # API endpoints
│   ├── auth/               # Authentication logic
│   ├── core/               # Core configuration
│   ├── middleware/         # Custom middleware
│   ├── models/             # Database models
│   ├── repositories/       # Data access layer
│   ├── schemas/            # Pydantic schemas
│   ├── services/           # Business logic
│   └── utils/              # Utility functions
├── tests/                  # Test files
├── alembic/               # Database migrations
├── logs/                  # Application logs
├── .env                   # Environment variables
├── main.py                # Application entry point
├── requirements.txt       # Dependencies
└── README.md              # Project documentation
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your changes and tests
4. Submit a pull request

## License

MIT License
EOF
}

# Main setup function
main() {
    print_status "Setting up FastAPI Boilerplate Generator..."
    
    create_generator_structure
    create_example_configs
    make_executable
    create_generator_readme
    
    print_success "Setup completed successfully!"
    echo ""
    print_status "Next steps:"
    echo "1. Review the generated structure and example configurations"
    echo "2. Customize configurations in config/ and examples/ directories"
    echo "3. Run './fastapi-generator.sh' to generate your first FastAPI project"
    echo ""
    print_status "Usage examples:"
    echo "  ./fastapi-generator.sh -n my-api --docker"
    echo "  ./fastapi-generator.sh --config examples/full-stack.conf"
    echo "  ./fastapi-generator.sh --help"
}

# Run main function
main "$@"